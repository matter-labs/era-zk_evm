use super::*;
use crate::abstractions::RefundType;
use crate::abstractions::SpongeExecutionMarker;
use crate::{
    aux_structures::{
        DecommittmentQuery, LogQuery, MemoryKey, MemoryLocation, MemoryQuery, Timestamp,
    },
    opcodes::parsing::*,
};

use zkevm_opcode_defs::UNMAPPED_PAGE;

pub fn read_code<
    const N: usize,
    E: VmEncodingMode<N>,
    M: crate::abstractions::Memory,
    WT: crate::witness_trace::VmWitnessTracer<N, E>,
>(
    memory: &M,
    witness_tracer: &mut WT,
    monotonic_cycle_counter: u32,
    key: MemoryKey,
    is_pended: bool,
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
        is_pended,
    };

    let query = memory.read_code_query(monotonic_cycle_counter, partial_query);

    // also log into the historical sequence
    witness_tracer.add_memory_query(monotonic_cycle_counter, query);

    query
}

impl<
        'a,
        S: crate::abstractions::Storage,
        M: crate::abstractions::Memory,
        EV: crate::abstractions::EventSink,
        PP: crate::abstractions::PrecompilesProcessor,
        DP: crate::abstractions::DecommittmentProcessor,
        WT: crate::witness_trace::VmWitnessTracer<N, E>,
        const N: usize,
        E: VmEncodingMode<N>,
    > VmState<'a, S, M, EV, PP, DP, WT, N, E>
{
    pub fn read_memory(
        &mut self,
        monotonic_cycle_counter: u32,
        key: MemoryKey,
        is_pended: bool,
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
            is_pended,
        };

        let query = self
            .memory
            .execute_partial_query(monotonic_cycle_counter, partial_query);

        // also log into the historical sequence
        self.witness_tracer
            .add_memory_query(monotonic_cycle_counter, query);

        query
    }

    pub fn read_code(
        &mut self,
        monotonic_cycle_counter: u32,
        key: MemoryKey,
        is_pended: bool,
    ) -> MemoryQuery {
        read_code(
            self.memory,
            self.witness_tracer,
            monotonic_cycle_counter,
            key,
            is_pended,
        )
    }

    pub fn write_memory(
        &mut self,
        monotonic_cycle_counter: u32,
        key: MemoryKey,
        value: PrimitiveValue,
        is_pended: bool,
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
            is_pended,
        };

        let query = self
            .memory
            .execute_partial_query(monotonic_cycle_counter, partial_query);

        // also log into the historical sequence
        self.witness_tracer
            .add_memory_query(monotonic_cycle_counter, query);

        query
    }

    pub fn refund_for_partial_query(
        &mut self,
        monotonic_cycle_counter: u32,
        partial_query: &LogQuery,
    ) -> RefundType {
        assert!(partial_query.rw_flag == true);
        let refund = self
            .storage
            .estimate_refunds_for_write(monotonic_cycle_counter, partial_query);

        self.witness_tracer.record_refund_for_query(
            monotonic_cycle_counter,
            *partial_query,
            refund,
        );

        refund
    }

    pub fn access_storage(&mut self, monotonic_cycle_counter: u32, query: LogQuery) -> LogQuery {
        // we do not touch pendings here and set them in the opcode only
        // also storage should internally rollback when ret is performed
        let mut query = self
            .storage
            .execute_partial_query(monotonic_cycle_counter, query);

        if !query.rw_flag {
            // by convension we fill written value with the same value
            query.written_value = query.read_value;
        }

        // tracer takes care of proper placements in the double ended queue
        self.witness_tracer
            .add_log_query(monotonic_cycle_counter, query);

        query
    }

    pub fn emit_event(&mut self, monotonic_cycle_counter: u32, query: LogQuery) {
        self.event_sink
            .add_partial_query(monotonic_cycle_counter, query);
        self.witness_tracer
            .add_log_query(monotonic_cycle_counter, query);
    }

    pub fn decommit(
        &mut self,
        monotonic_cycle_counter: u32,
        hash: U256,
        candidate_page: MemoryPage,
        timestamp: Timestamp,
    ) -> DecommittmentQuery {
        let partial_query = DecommittmentQuery {
            hash,
            timestamp,
            memory_page: candidate_page,
            decommitted_length: 0u16,
            is_fresh: false,
        };

        let (query, witness_for_tracer) = self.decommittment_processor.decommit_into_memory(
            monotonic_cycle_counter,
            partial_query,
            self.memory,
        );

        if let Some(witness_for_tracer) = witness_for_tracer {
            self.witness_tracer.add_decommittment(
                monotonic_cycle_counter,
                query,
                witness_for_tracer,
            );
        }

        query
    }

    pub fn call_precompile(&mut self, monotonic_cycle_counter: u32, query: LogQuery) {
        debug_assert!(self
            .local_state
            .callstack
            .get_current_stack()
            .is_kernel_mode());
        debug_assert_eq!(
            query.timestamp,
            self.timestamp_for_first_decommit_or_precompile_read()
        );
        debug_assert_eq!(query.rw_flag, false);
        // add to witness
        self.witness_tracer
            .add_log_query(monotonic_cycle_counter, query);
        // add execution aux data
        if let Some((mem_in, mem_out, round_witness)) = self
            .precompiles_processor
            .execute_precompile::<_>(monotonic_cycle_counter, query, self.memory)
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
        drop(previous_context);
        self.local_state.callstack.push_entry(context_entry);
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

        old_frame
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
            let _dst0_query = self.write_memory(
                monotonic_cycle_counter,
                key,
                value,
                /* is_pended */ false,
            ); // no pending on dst0 writes

            self.witness_tracer.add_sponge_marker(
                self.local_state.monotonic_cycle_counter,
                SpongeExecutionMarker::MemoryQuery,
                2..3,
                /* is_pended */ false,
            );
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

use zkevm_opcode_defs::bitflags::bitflags;
use zkevm_opcode_defs::FatPointer;

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
