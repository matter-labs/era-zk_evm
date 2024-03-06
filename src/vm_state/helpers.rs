use crate::opcodes::DecodedOpcode;

use super::*;

use crate::zkevm_opcode_defs::UNMAPPED_PAGE;
use zk_evm_abstractions::aux::{MemoryKey, MemoryLocation, PubdataCost};
use zk_evm_abstractions::queries::{DecommittmentQuery, LogQuery, MemoryQuery};
use zk_evm_abstractions::vm::StorageAccessRefund;
use zk_evm_abstractions::zkevm_opcode_defs::{
    VersionedHashHeader, VersionedHashNormalizedPreimage,
};

pub fn read_code<
    const N: usize,
    E: VmEncodingMode<N>,
    M: zk_evm_abstractions::vm::Memory,
    WT: crate::witness_trace::VmWitnessTracer<N, E>,
>(
    memory: &M,
    witness_tracer: &mut WT,
    monotonic_cycle_counter: u32,
    key: MemoryKey,
) -> MemoryQuery {
    let MemoryKey {
        location,
        timestamp,
    } = key;

    let partial_query = MemoryQuery {
        timestamp,
        location,
        value: U256::zero(),
        value_is_pointer: false,
        rw_flag: false,
    };

    let query = memory.read_code_query(monotonic_cycle_counter, partial_query);

    // also log into the historical sequence
    witness_tracer.add_memory_query(monotonic_cycle_counter, query);

    query
}

impl<
        S: zk_evm_abstractions::vm::Storage,
        M: zk_evm_abstractions::vm::Memory,
        EV: zk_evm_abstractions::vm::EventSink,
        PP: zk_evm_abstractions::vm::PrecompilesProcessor,
        DP: zk_evm_abstractions::vm::DecommittmentProcessor,
        WT: crate::witness_trace::VmWitnessTracer<N, E>,
        const N: usize,
        E: VmEncodingMode<N>,
    > VmState<S, M, EV, PP, DP, WT, N, E>
{
    pub fn read_memory(&mut self, monotonic_cycle_counter: u32, key: MemoryKey) -> MemoryQuery {
        let MemoryKey {
            location,
            timestamp,
        } = key;

        let partial_query = MemoryQuery {
            timestamp,
            location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };

        let query = self
            .memory
            .execute_partial_query(monotonic_cycle_counter, partial_query);

        // also log into the historical sequence
        self.witness_tracer
            .add_memory_query(monotonic_cycle_counter, query);

        query
    }

    pub fn read_code(&mut self, monotonic_cycle_counter: u32, key: MemoryKey) -> MemoryQuery {
        read_code(
            &mut self.memory,
            &mut self.witness_tracer,
            monotonic_cycle_counter,
            key,
        )
    }

    pub fn write_memory(
        &mut self,
        monotonic_cycle_counter: u32,
        key: MemoryKey,
        value: PrimitiveValue,
    ) -> MemoryQuery {
        let MemoryKey {
            location,
            timestamp,
        } = key;

        let PrimitiveValue { value, is_pointer } = value;

        let partial_query = MemoryQuery {
            timestamp,
            location,
            value,
            value_is_pointer: is_pointer,
            rw_flag: true,
        };

        let query = self
            .memory
            .execute_partial_query(monotonic_cycle_counter, partial_query);

        // also log into the historical sequence
        self.witness_tracer
            .add_memory_query(monotonic_cycle_counter, query);

        query
    }

    #[track_caller]
    pub fn refund_for_partial_query(
        &mut self,
        monotonic_cycle_counter: u32,
        partial_query: &LogQuery,
    ) -> StorageAccessRefund {
        let refund = self
            .storage
            .get_access_refund(monotonic_cycle_counter, partial_query);

        self.witness_tracer.record_refund_for_query(
            monotonic_cycle_counter,
            *partial_query,
            refund,
        );

        refund
    }

    #[track_caller]
    pub fn access_storage(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
    ) -> (LogQuery, PubdataCost) {
        // we do not touch pendings here and set them in the opcode only
        // also storage should internally rollback when ret is performed
        let (mut query, pubdata_cost) = self
            .storage
            .execute_partial_query(monotonic_cycle_counter, query);

        if !query.rw_flag {
            // by convension we fill written value with the same value
            query.written_value = query.read_value;
        }

        // tracer takes care of proper placements in the double ended queue
        self.witness_tracer
            .add_log_query(monotonic_cycle_counter, query);
        self.witness_tracer.record_pubdata_cost_for_query(
            monotonic_cycle_counter,
            query,
            pubdata_cost,
        );

        (query, pubdata_cost)
    }

    pub fn emit_event(&mut self, monotonic_cycle_counter: u32, query: LogQuery) {
        self.event_sink
            .add_partial_query(monotonic_cycle_counter, query);
        self.witness_tracer
            .add_log_query(monotonic_cycle_counter, query);
    }

    #[track_caller]
    pub fn prepare_to_decommit(
        &mut self,
        monotonic_cycle_counter: u32,
        header: VersionedHashHeader,
        normalized_preimage: VersionedHashNormalizedPreimage,
        candidate_page: MemoryPage,
        timestamp: Timestamp,
    ) -> anyhow::Result<DecommittmentQuery> {
        let partial_query = DecommittmentQuery {
            header,
            normalized_preimage,
            timestamp,
            memory_page: candidate_page,
            decommitted_length: 0u16,
            is_fresh: false,
        };

        let query = self
            .decommittment_processor
            .prepare_to_decommit(monotonic_cycle_counter, partial_query)?;

        self.witness_tracer
            .prepare_for_decommittment(monotonic_cycle_counter, query);

        Ok(query)
    }

    #[track_caller]
    pub fn execute_decommit(
        &mut self,
        monotonic_cycle_counter: u32,
        query: DecommittmentQuery,
    ) -> anyhow::Result<()> {
        if query.is_fresh == false {
            return Ok(());
        }

        let witness_for_tracer = self.decommittment_processor.decommit_into_memory(
            monotonic_cycle_counter,
            query,
            &mut self.memory,
        )?;

        if let Some(witness_for_tracer) = witness_for_tracer {
            self.witness_tracer.execute_decommittment(
                monotonic_cycle_counter,
                query,
                witness_for_tracer,
            );
        }

        Ok(())
    }

    #[track_caller]
    pub fn call_precompile(&mut self, monotonic_cycle_counter: u32, query: LogQuery) {
        assert!(self
            .local_state
            .callstack
            .get_current_stack()
            .is_kernel_mode());
        assert_eq!(
            query.timestamp,
            self.timestamp_for_first_decommit_or_precompile_read()
        );
        assert_eq!(query.rw_flag, false);
        // add to witness
        self.witness_tracer
            .add_log_query(monotonic_cycle_counter, query);
        // add execution aux data
        if let Some((mem_in, mem_out, round_witness)) = self
            .precompiles_processor
            .execute_precompile::<_>(monotonic_cycle_counter, query, &mut self.memory)
        {
            self.witness_tracer.add_precompile_call_result(
                monotonic_cycle_counter,
                query,
                mem_in,
                mem_out,
                round_witness,
            );
        }
    }

    pub fn start_frame(
        &mut self,
        monotonic_cycle_counter: u32,
        context_entry: CallStackEntry<N, E>,
    ) {
        let timestamp = Timestamp(self.local_state.timestamp);

        self.storage.start_frame(timestamp);
        self.event_sink.start_frame(timestamp);
        self.precompiles_processor.start_frame();
        let previous_context = self.local_state.callstack.get_current_stack();

        self.witness_tracer.start_new_execution_context(
            monotonic_cycle_counter,
            previous_context,
            &context_entry,
        );
        #[allow(dropping_references)]
        drop(previous_context);

        self.local_state.callstack.push_entry(context_entry);
    }

    pub fn add_pubdata_cost(&mut self, pubdata_cost: PubdataCost) {
        // Short logic descriptions:
        // - when we add - we add to both global and local counters
        // - when we start new frame - counter is zero
        // - when frame ends with success we add to parent
        // - when frame rollbacks we adjust global counter
        let pubdata_already_spent = self
            .local_state
            .callstack
            .get_current_stack()
            .total_pubdata_spent
            .0;
        // we can neither overflow nor underflow
        let (new_pubdata_already_spent, of) = pubdata_already_spent.overflowing_add(pubdata_cost.0);
        assert!(of == false);

        self.local_state
            .callstack
            .get_current_stack_mut()
            .total_pubdata_spent = PubdataCost(new_pubdata_already_spent);

        let (new_revert_counter, of) = self
            .local_state
            .pubdata_revert_counter
            .0
            .overflowing_add(pubdata_cost.0);
        assert!(of == false);
        self.local_state.pubdata_revert_counter = PubdataCost(new_revert_counter);
    }

    pub fn finish_frame(
        &mut self,
        monotonic_cycle_counter: u32,
        panicked: bool,
    ) -> CallStackEntry<N, E> {
        let timestamp = Timestamp(self.local_state.timestamp);

        self.storage.finish_frame(timestamp, panicked);
        self.event_sink.finish_frame(panicked, timestamp);
        self.precompiles_processor.finish_frame(panicked);
        self.witness_tracer
            .finish_execution_context(monotonic_cycle_counter, panicked);

        let old_frame = self.local_state.callstack.pop_entry();
        // if we panicked then we should subtract all spent pubdata, and reduce the counter of rollbacks
        let pubdata_spent_in_new_current_frame = self
            .local_state
            .callstack
            .get_current_stack()
            .total_pubdata_spent
            .0;

        // if we revert the frame then all it's pubdata changes must be erased,
        // otherwise - added to the parent

        // we can neither overflow nor underflow
        let (new_pubdata_already_spent, of) = if panicked {
            (pubdata_spent_in_new_current_frame, false)
        } else {
            pubdata_spent_in_new_current_frame.overflowing_add(old_frame.total_pubdata_spent.0)
        };

        assert!(of == false);

        self.local_state
            .callstack
            .get_current_stack_mut()
            .total_pubdata_spent = PubdataCost(new_pubdata_already_spent);

        // same logic - if frame is reverted then it's spendings are "forgotten". In this case
        // we need to subtract from global counter to balance it on panic, otherwise - do nothing
        let (new_revert_counter, of) = if panicked {
            self.local_state
                .pubdata_revert_counter
                .0
                .overflowing_sub(old_frame.total_pubdata_spent.0)
        } else {
            // do nothing
            (self.local_state.pubdata_revert_counter.0, false)
        };
        assert!(of == false);
        self.local_state.pubdata_revert_counter = PubdataCost(new_revert_counter);

        old_frame
    }

    pub fn start_new_tx(&mut self) {
        self.local_state.tx_number_in_block = self.local_state.tx_number_in_block.wrapping_add(1);
        self.storage
            .start_new_tx(Timestamp(self.local_state.timestamp));
    }

    pub fn perform_dst0_update(
        &mut self,
        monotonic_cycle_counter: u32,
        value: PrimitiveValue,
        location: Option<MemoryLocation>,
        opcode: &DecodedOpcode<N, E>,
    ) {
        // memory location is "Some" only if we use proper addressing
        if let Some(location) = location {
            let key = MemoryKey {
                location,
                timestamp: self.timestamp_for_dst_write(),
            };
            let _dst0_query = self.write_memory(monotonic_cycle_counter, key, value);
        } else {
            self.update_register_value(opcode.dst0_reg_idx, value);
        }
    }

    pub fn perform_dst1_update(&mut self, value: PrimitiveValue, mask_u4_value: u8) {
        self.update_register_value(mask_u4_value, value);
    }

    pub fn push_bootloader_context(
        &mut self,
        monotonic_cycle_counter: u32,
        bootloader_context: CallStackEntry<N, E>,
    ) {
        // we have to zero out current ergs and pass all of them further
        let empty_context = self.local_state.callstack.get_current_stack_mut();
        let all_ergs = empty_context.ergs_remaining;
        let (remaining_for_this_frame, uf) =
            all_ergs.overflowing_sub(bootloader_context.ergs_remaining);
        assert!(
            uf == false,
            "trying to create bootloader frame with more ergs than VM has available"
        );
        empty_context.ergs_remaining = remaining_for_this_frame;

        #[allow(dropping_references)]
        drop(empty_context);

        self.start_frame(monotonic_cycle_counter, bootloader_context);
        let base_page = bootloader_context.base_memory_page;
        self.memory.start_global_frame(
            MemoryPage(UNMAPPED_PAGE),
            base_page,
            FatPointer::empty(),
            Timestamp(self.local_state.timestamp),
        );
    }

    pub(crate) fn select_register_value(&self, mask_u4_value: u8) -> PrimitiveValue {
        if mask_u4_value == 0 {
            PrimitiveValue::empty()
        } else {
            self.local_state.registers[(mask_u4_value - 1) as usize]
        }
    }

    pub(crate) fn update_register_value(
        &mut self,
        mask_u4_value: u8,
        value_to_set: PrimitiveValue,
    ) {
        if mask_u4_value > 0 {
            self.local_state.registers[(mask_u4_value - 1) as usize] = value_to_set;
        }
    }

    pub(crate) fn set_shorthand_panic(&mut self) {
        self.local_state.pending_exception = true;
    }
}

use crate::zkevm_opcode_defs::bitflags::bitflags;
use crate::zkevm_opcode_defs::FatPointer;

bitflags! {
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ErrorFlags: u64 {
        const INVALID_OPCODE = 1u64 << 0;
        const NOT_ENOUGH_ERGS = 1u64 << 1;
        const PRIVILAGED_ACCESS_NOT_FROM_KERNEL = 1u64 << 2;
        const WRITE_IN_STATIC_CONTEXT = 1u64 << 3;
        const CALLSTACK_IS_FULL = 1u64 << 4;
    }
}

pub fn address_is_kernel(address: &Address) -> bool {
    // address < 2^16
    let address_bytes = address.as_fixed_bytes();
    address_bytes[0..18].iter().all(|&el| el == 0u8)
}

pub fn get_stipend_and_extra_cost(address: &Address, is_system_call: bool) -> (u32, u32) {
    let address_bytes = address.as_fixed_bytes();
    let is_kernel = address_bytes[0..18].iter().all(|&el| el == 0u8);
    if is_kernel {
        if is_system_call {
            let address = u16::from_be_bytes([address_bytes[18], address_bytes[19]]);
            use crate::zkevm_opcode_defs::STIPENDS_AND_EXTRA_COSTS_TABLE;

            STIPENDS_AND_EXTRA_COSTS_TABLE[address as usize]
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    }
}
