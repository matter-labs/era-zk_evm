use super::*;

use zkevm_opcode_defs::{
    LogOpcode, Opcode, PrecompileCallABI, PrecompileCallInnerABI, FIRST_MESSAGE_FLAG_IDX,
};

use zkevm_opcode_defs::system_params::{
    EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
};

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn log_opcode_apply<
        'a,
        S: crate::abstractions::Storage,
        M: crate::abstractions::Memory,
        EV: crate::abstractions::EventSink,
        PP: crate::abstractions::PrecompilesProcessor,
        DP: crate::abstractions::DecommittmentProcessor,
        WT: crate::witness_trace::VmWitnessTracer<N, E>,
    >(
        &self,
        vm_state: &mut VmState<'a, S, M, EV, PP, DP, WT, N, E>,
        prestate: PreState<N, E>,
    ) {
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

        let ergs_on_pubdata = match inner_variant {
            LogOpcode::StorageWrite => {
                let key = src0;
                let written_value = src1;

                let current_context = vm_state.local_state.callstack.get_current_stack();
                let address = current_context.this_address;
                let shard_id = current_context.this_shard_id;
                drop(current_context);

                // we do not need all the values here, but we DO need the written value
                // for oracle to do estimations

                let partial_query = LogQuery {
                    timestamp: Timestamp(0u32),
                    tx_number_in_block: 0u16,
                    aux_byte: STORAGE_AUX_BYTE,
                    shard_id,
                    address,
                    key,
                    read_value: U256::zero(),
                    written_value,
                    rw_flag: true,
                    rollback: false,
                    is_service: false,
                };

                let refund = vm_state.refund_for_partial_query(
                    vm_state.local_state.monotonic_cycle_counter,
                    &partial_query,
                );
                let pubdata_refund = refund.pubdata_refund();

                let net_pubdata = if is_rollup {
                    let (net_cost, uf) =
                        (zkevm_opcode_defs::system_params::INITIAL_STORAGE_WRITE_PUBDATA_BYTES
                            as u32)
                            .overflowing_sub(pubdata_refund);
                    assert!(uf == false, "refund can not be more than net cost itself");

                    net_cost
                } else {
                    assert_eq!(pubdata_refund, 0);

                    0
                };

                vm_state.local_state.current_ergs_per_pubdata_byte * net_pubdata
            }
            LogOpcode::ToL1Message => {
                vm_state.local_state.current_ergs_per_pubdata_byte
                    * zkevm_opcode_defs::system_params::L1_MESSAGE_PUBDATA_BYTES
            }
            _ => 0,
        };

        let extra_cost = match inner_variant {
            LogOpcode::PrecompileCall => src1.low_u32(),
            _ => 0,
        };

        let total_cost = extra_cost + ergs_on_pubdata;

        let (ergs_remaining, not_enough_power) = ergs_available.overflowing_sub(total_cost);
        if not_enough_power {
            vm_state
                .local_state
                .callstack
                .get_current_stack_mut()
                .ergs_remaining = 0;

            vm_state.local_state.spent_pubdata_counter +=
                std::cmp::min(ergs_available, ergs_on_pubdata);
        } else {
            vm_state
                .local_state
                .callstack
                .get_current_stack_mut()
                .ergs_remaining = ergs_remaining;

            vm_state.local_state.spent_pubdata_counter += ergs_on_pubdata;
        }

        let current_context = vm_state.local_state.callstack.get_current_stack();
        let address = current_context.this_address;
        let shard_id = current_context.this_shard_id;
        drop(current_context);
        let tx_number_in_block = vm_state.local_state.tx_number_in_block;
        let timestamp_for_log = vm_state.timestamp_for_first_decommit_or_precompile_read();
        match inner_variant {
            LogOpcode::StorageRead => {
                assert!(not_enough_power == false);
                let key = src0;

                let partial_query = LogQuery {
                    timestamp: timestamp_for_log,
                    tx_number_in_block,
                    aux_byte: STORAGE_AUX_BYTE,
                    shard_id,
                    address,
                    key,
                    read_value: U256::zero(),
                    written_value: U256::zero(),
                    rw_flag: false,
                    rollback: false,
                    is_service: is_first_message,
                };

                // we do not expect refunds for reads yet
                let query = vm_state
                    .access_storage(vm_state.local_state.monotonic_cycle_counter, partial_query);
                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::StorageLogReadOnly,
                    1..4,
                    false,
                );
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
            }
            LogOpcode::StorageWrite => {
                if not_enough_power {
                    // we can return immediatelly and do not need to update regs
                    return;
                }
                let key = src0;
                let written_value = src1;

                let partial_query = LogQuery {
                    timestamp: timestamp_for_log,
                    tx_number_in_block,
                    aux_byte: STORAGE_AUX_BYTE,
                    shard_id,
                    address,
                    key,
                    read_value: U256::zero(),
                    written_value,
                    rw_flag: true,
                    rollback: false,
                    is_service: is_first_message,
                };

                // we still do a formal query to execute write and record witness
                let _query = vm_state
                    .access_storage(vm_state.local_state.monotonic_cycle_counter, partial_query);

                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::StorageLogWrite,
                    1..5,
                    true,
                );
                vm_state.local_state.pending_port.pending_type = Some(PendingType::WriteLog);
            }
            variant @ LogOpcode::Event | variant @ LogOpcode::ToL1Message => {
                if not_enough_power {
                    assert_eq!(variant, LogOpcode::ToL1Message);
                    // we do not add anything into log and do not need to update
                    // registers
                    return;
                }
                let key = src0;
                let written_value = src1;

                let aux_byte = if variant == LogOpcode::Event {
                    EVENT_AUX_BYTE
                } else {
                    L1_MESSAGE_AUX_BYTE
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
                vm_state.local_state.pending_port.pending_type = Some(PendingType::WriteLog);
                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::StorageLogWrite,
                    1..5,
                    true,
                );
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
                    return;
                }

                let precompile_abi = PrecompileCallABI::from_u256(src0);
                let PrecompileCallABI {
                    input_memory_offset,
                    input_memory_length,
                    output_memory_offset,
                    output_memory_length,
                    per_precompile_interpreted,
                } = precompile_abi;

                // normal execution
                vm_state
                    .local_state
                    .callstack
                    .get_current_stack_mut()
                    .ergs_remaining = ergs_remaining;
                let memory_page_to_read = CallStackEntry::<N, E>::heap_page_from_base(
                    vm_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .base_memory_page,
                );
                let memory_page_to_write = CallStackEntry::<N, E>::heap_page_from_base(
                    vm_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .base_memory_page,
                );

                let timestamp_to_read = vm_state.timestamp_for_first_decommit_or_precompile_read();
                let timestamp_to_write =
                    vm_state.timestamp_for_second_decommit_or_precompile_write();
                assert!(timestamp_to_read.0 + 1 == timestamp_to_write.0);

                let precompile_inner_abi = PrecompileCallInnerABI {
                    input_memory_offset,
                    input_memory_length,
                    output_memory_offset,
                    output_memory_length,
                    memory_page_to_read: memory_page_to_read.0,
                    memory_page_to_write: memory_page_to_write.0,
                    precompile_interpreted_data: per_precompile_interpreted,
                };
                let precompile_inner_abi = precompile_inner_abi.to_u256();

                let query = LogQuery {
                    timestamp: timestamp_for_log,
                    tx_number_in_block,
                    aux_byte: PRECOMPILE_AUX_BYTE,
                    shard_id,
                    address,
                    key: precompile_inner_abi,
                    read_value: U256::zero(),
                    written_value: U256::zero(),
                    rw_flag: false,
                    rollback: false,
                    is_service: is_first_message,
                };
                vm_state.call_precompile(vm_state.local_state.monotonic_cycle_counter, query);
                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::StorageLogReadOnly,
                    1..4,
                    false,
                );
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
            }
        }
    }
}
