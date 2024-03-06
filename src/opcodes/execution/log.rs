use super::*;

use crate::zkevm_opcode_defs::{LogOpcode, Opcode, PrecompileCallABI, FIRST_MESSAGE_FLAG_IDX};
use num::abs;
use zk_evm_abstractions::aux::PubdataCost;
use zk_evm_abstractions::queries::LogQuery;
use zk_evm_abstractions::zkevm_opcode_defs::system_params::{
    MAX_PUBDATA_COST_PER_QUERY, TRANSIENT_STORAGE_AUX_BYTE,
};
use zk_evm_abstractions::zkevm_opcode_defs::{
    FatPointer, OpcodeVariantProps, PrecompileAuxData, VersionedHashHeader,
    VersionedHashNormalizedPreimage,
};

use crate::zkevm_opcode_defs::system_params::{
    EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
};

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn log_opcode_apply<
        S: zk_evm_abstractions::vm::Storage,
        M: zk_evm_abstractions::vm::Memory,
        EV: zk_evm_abstractions::vm::EventSink,
        PP: zk_evm_abstractions::vm::PrecompilesProcessor,
        DP: zk_evm_abstractions::vm::DecommittmentProcessor,
        WT: crate::witness_trace::VmWitnessTracer<N, E>,
    >(
        &self,
        vm_state: &mut VmState<S, M, EV, PP, DP, WT, N, E>,
        prestate: PreState<N, E>,
    ) -> anyhow::Result<()> {
        let PreState {
            src0,
            src1,
            dst0_mem_location,
            new_pc,
            ..
        } = prestate;
        let PrimitiveValue {
            value: src0,
            is_pointer: _,
        } = src0;
        let PrimitiveValue {
            value: src1,
            is_pointer: _,
        } = src1;
        let inner_variant = match self.variant.opcode {
            Opcode::Log(inner) => inner,
            _ => unreachable!(),
        };
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;
        let is_first_message = self.variant.flags[FIRST_MESSAGE_FLAG_IDX];

        // this is the only case where we do extra checking for costs as it's related to pubdata
        // and shard_id

        // We do it as the following:
        // - check if we have enough
        // - if not - just set remaining ergs to 0 (that will cause an exception on the next cycle)
        // - DO NOT set any pending
        // - return

        // ergs exception handling
        let shard_id = vm_state
            .local_state
            .callstack
            .get_current_stack()
            .this_shard_id;
        let ergs_available = vm_state
            .local_state
            .callstack
            .get_current_stack()
            .ergs_remaining;
        let is_rollup = shard_id == 0;

        let timestamp_for_log = vm_state.timestamp_for_first_decommit_or_precompile_read();
        let tx_number_in_block = vm_state.local_state.tx_number_in_block;

        let mut decommit_preimage_format_is_invalid = false;
        // we make formal fat pointer of length of full kernel space "free" heap size,
        // and caller is responsible to truncate it if decommit is succesfull
        let mut preimage_len_in_bytes =
            zkevm_opcode_defs::system_params::NEW_KERNEL_FRAME_MEMORY_STIPEND;
        let mut decommit_header = VersionedHashHeader::default();
        let mut decommit_preimage_normalized = VersionedHashNormalizedPreimage::default();
        let mut buffer = [0u8; 32];

        let extra_cost = match inner_variant {
            LogOpcode::PrecompileCall => {
                let precompile_aux_data = PrecompileAuxData::from_u256(src1);

                precompile_aux_data.extra_ergs_cost
            }
            LogOpcode::Decommit => {
                // extra cost is in src1
                let extra_cost = src1.low_u32();

                // and we check format anyway
                use crate::zkevm_opcode_defs::*;
                src0.to_big_endian(&mut buffer);
                if ContractCodeSha256Format::is_valid(&buffer) {
                    let (header, normalized_preimage) =
                        ContractCodeSha256Format::normalize_for_decommitment(&buffer);
                    decommit_header = header;
                    decommit_preimage_normalized = normalized_preimage;
                } else if BlobSha256Format::is_valid(&buffer) {
                    let (header, normalized_preimage) =
                        BlobSha256Format::normalize_for_decommitment(&buffer);
                    decommit_header = header;
                    decommit_preimage_normalized = normalized_preimage;
                } else {
                    preimage_len_in_bytes = 0;
                    decommit_preimage_format_is_invalid = true;
                };

                extra_cost
            }
            _ => 0,
        };

        let (ergs_remaining, not_enough_power) = ergs_available.overflowing_sub(extra_cost);
        if not_enough_power {
            vm_state
                .local_state
                .callstack
                .get_current_stack_mut()
                .ergs_remaining = 0;
        } else {
            vm_state
                .local_state
                .callstack
                .get_current_stack_mut()
                .ergs_remaining = ergs_remaining;
        }

        let current_context = vm_state.local_state.callstack.get_current_stack();
        let address = current_context.this_address;
        let shard_id = current_context.this_shard_id;

        #[allow(dropping_references)]
        drop(current_context);

        let (pubdata_to_add_to_current_frame, ergs_refund) = match inner_variant {
            variant @ LogOpcode::StorageRead | variant @ LogOpcode::TransientStorageRead => {
                assert!(not_enough_power == false);
                let key = src0;

                let aux_byte = if variant == LogOpcode::StorageRead {
                    STORAGE_AUX_BYTE
                } else if variant == LogOpcode::TransientStorageRead {
                    TRANSIENT_STORAGE_AUX_BYTE
                } else {
                    unreachable!()
                };

                let partial_query = LogQuery {
                    timestamp: timestamp_for_log,
                    tx_number_in_block,
                    aux_byte,
                    shard_id,
                    address,
                    key,
                    read_value: U256::zero(),
                    written_value: U256::zero(),
                    rw_flag: false,
                    rollback: false,
                    is_service: is_first_message,
                };

                let refund = vm_state.refund_for_partial_query(
                    vm_state.local_state.monotonic_cycle_counter,
                    &partial_query,
                );
                let ergs_refund = refund.refund();

                let (query, pubdata_cost) = vm_state
                    .access_storage(vm_state.local_state.monotonic_cycle_counter, partial_query);

                if variant == LogOpcode::TransientStorageRead {
                    assert_eq!(ergs_refund, 0);
                } else {
                    assert!(ergs_refund <= LogOpcode::StorageRead.ergs_price());
                }
                assert_eq!(pubdata_cost.0, 0);

                let result = PrimitiveValue {
                    value: query.read_value,
                    is_pointer: false,
                };
                vm_state.perform_dst0_update(
                    vm_state.local_state.monotonic_cycle_counter,
                    result,
                    dst0_mem_location,
                    self,
                );

                (pubdata_cost, ergs_refund)
            }
            variant @ LogOpcode::StorageWrite | variant @ LogOpcode::TransientStorageWrite => {
                if not_enough_power {
                    // we can return immediatelly and do not need to update regs
                    return Ok(());
                }
                let key = src0;
                let written_value = src1;

                let aux_byte = if variant == LogOpcode::StorageWrite {
                    STORAGE_AUX_BYTE
                } else if variant == LogOpcode::TransientStorageWrite {
                    TRANSIENT_STORAGE_AUX_BYTE
                } else {
                    unreachable!()
                };

                let partial_query = LogQuery {
                    timestamp: timestamp_for_log,
                    tx_number_in_block,
                    aux_byte,
                    shard_id,
                    address,
                    key,
                    read_value: U256::zero(),
                    written_value,
                    rw_flag: true,
                    rollback: false,
                    is_service: is_first_message,
                };

                let refund = vm_state.refund_for_partial_query(
                    vm_state.local_state.monotonic_cycle_counter,
                    &partial_query,
                );
                let ergs_refund = refund.refund();

                let (_query, pubdata_cost) = vm_state
                    .access_storage(vm_state.local_state.monotonic_cycle_counter, partial_query);

                if variant == LogOpcode::TransientStorageWrite {
                    assert_eq!(pubdata_cost.0, 0);
                    assert_eq!(ergs_refund, 0);
                } else {
                    assert!(abs(pubdata_cost.0) <= MAX_PUBDATA_COST_PER_QUERY as i32);
                    assert!(ergs_refund <= LogOpcode::StorageWrite.ergs_price());
                }

                if is_rollup == false {
                    assert_eq!(pubdata_cost.0, 0);
                }

                (pubdata_cost, ergs_refund)
            }
            variant @ LogOpcode::Event | variant @ LogOpcode::ToL1Message => {
                if not_enough_power {
                    assert_eq!(variant, LogOpcode::ToL1Message);
                    // we do not add anything into log and do not need to update
                    // registers
                    return Ok(());
                }
                let key = src0;
                let written_value = src1;

                let aux_byte = if variant == LogOpcode::Event {
                    EVENT_AUX_BYTE
                } else {
                    L1_MESSAGE_AUX_BYTE
                };

                let pubdata_cost = if variant == LogOpcode::Event {
                    PubdataCost(0i32)
                } else {
                    // those messages are reactive and may contain pubdata from different source, so
                    // we do not count them here
                    PubdataCost(0i32)
                };

                let query = LogQuery {
                    timestamp: timestamp_for_log,
                    tx_number_in_block,
                    aux_byte,
                    shard_id,
                    address,
                    key,
                    read_value: U256::zero(),
                    written_value,
                    rw_flag: true,
                    rollback: false,
                    is_service: is_first_message,
                };
                vm_state.emit_event(vm_state.local_state.monotonic_cycle_counter, query);

                (pubdata_cost, 0)
            }
            LogOpcode::PrecompileCall => {
                // add extra information about precompile abi in the "key" field
                if not_enough_power {
                    // we have to update register
                    vm_state.perform_dst0_update(
                        vm_state.local_state.monotonic_cycle_counter,
                        PrimitiveValue::empty(),
                        dst0_mem_location,
                        &self,
                    );

                    (PubdataCost(0), 0)
                } else {
                    let mut precompile_abi = PrecompileCallABI::from_u256(src0);
                    let precompile_aux_data = PrecompileAuxData::from_u256(src1);

                    // normal execution
                    vm_state
                        .local_state
                        .callstack
                        .get_current_stack_mut()
                        .ergs_remaining = ergs_remaining;
                    if precompile_abi.memory_page_to_read == 0 {
                        let memory_page_to_read = CallStackEntry::<N, E>::heap_page_from_base(
                            vm_state
                                .local_state
                                .callstack
                                .get_current_stack()
                                .base_memory_page,
                        );
                        precompile_abi.memory_page_to_read = memory_page_to_read.0;
                    }

                    if precompile_abi.memory_page_to_write == 0 {
                        let memory_page_to_write = CallStackEntry::<N, E>::heap_page_from_base(
                            vm_state
                                .local_state
                                .callstack
                                .get_current_stack()
                                .base_memory_page,
                        );
                        precompile_abi.memory_page_to_write = memory_page_to_write.0;
                    }

                    let timestamp_to_read =
                        vm_state.timestamp_for_first_decommit_or_precompile_read();
                    debug_assert!(timestamp_to_read == timestamp_for_log);
                    let timestamp_to_write =
                        vm_state.timestamp_for_second_decommit_or_precompile_write();
                    debug_assert!(timestamp_to_read.0 + 1 == timestamp_to_write.0);

                    let precompile_abi_encoded = precompile_abi.to_u256();

                    let query = LogQuery {
                        timestamp: timestamp_for_log,
                        tx_number_in_block,
                        aux_byte: PRECOMPILE_AUX_BYTE,
                        shard_id,
                        address,
                        key: precompile_abi_encoded,
                        read_value: U256::zero(),
                        written_value: U256::zero(),
                        rw_flag: false,
                        rollback: false,
                        is_service: is_first_message,
                    };

                    vm_state.call_precompile(vm_state.local_state.monotonic_cycle_counter, query);
                    let result = PrimitiveValue {
                        value: U256::from(1u64),
                        is_pointer: false,
                    };
                    vm_state.perform_dst0_update(
                        vm_state.local_state.monotonic_cycle_counter,
                        result,
                        dst0_mem_location,
                        &self,
                    );

                    let extra_pubdata_cost = precompile_aux_data.extra_pubdata_cost;
                    assert!(extra_pubdata_cost <= i32::MAX as u32);

                    (PubdataCost(extra_pubdata_cost as i32), 0)
                }
            }
            LogOpcode::Decommit => {
                // we take a preimage from src0, check it's format, normalize and add to decommit queue
                let (dst_0_value, (pubdata_cost, refund)) = if decommit_preimage_format_is_invalid
                    || not_enough_power
                {
                    // we have to update register anyway
                    (PrimitiveValue::empty(), (PubdataCost(0), 0))
                } else {
                    // add to decommit queue the normalized image
                    let timestamp_for_decommit =
                        vm_state.timestamp_for_first_decommit_or_precompile_read();
                    let memory_page_candidate_for_decommitment =
                        CallStackEntry::<N, E>::heap_page_from_base(
                            vm_state
                                .local_state
                                .callstack
                                .get_current_stack()
                                .base_memory_page,
                        );
                    assert!(decommit_preimage_normalized.0 != [0u8; 28], "original buffer {:?} lead to zero normalized preimage, but didn't trigger exception", buffer);
                    let prepared_decommittment_query = vm_state.prepare_to_decommit(
                        vm_state.local_state.monotonic_cycle_counter,
                        decommit_header,
                        decommit_preimage_normalized,
                        memory_page_candidate_for_decommitment,
                        timestamp_for_decommit,
                    )?;

                    let refund = if prepared_decommittment_query.is_fresh == false {
                        extra_cost
                    } else {
                        0
                    };

                    vm_state.execute_decommit(
                        vm_state.local_state.monotonic_cycle_counter,
                        prepared_decommittment_query,
                    )?;

                    let output_memory_page = prepared_decommittment_query.memory_page;
                    // form a fat pointer
                    let fat_pointer = FatPointer {
                        offset: 0,
                        memory_page: output_memory_page.0,
                        start: 0,
                        length: preimage_len_in_bytes as u32,
                    };

                    (
                        PrimitiveValue {
                            value: fat_pointer.to_u256(),
                            is_pointer: true,
                        },
                        (PubdataCost(0), refund),
                    )
                };

                // and update register
                vm_state.perform_dst0_update(
                    vm_state.local_state.monotonic_cycle_counter,
                    dst_0_value,
                    dst0_mem_location,
                    &self,
                );

                (pubdata_cost, refund)
            }
        };

        // apply refund
        vm_state
            .local_state
            .callstack
            .get_current_stack_mut()
            .ergs_remaining += ergs_refund;

        vm_state.add_pubdata_cost(pubdata_to_add_to_current_frame);

        Ok(())
    }
}
