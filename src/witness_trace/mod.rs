use crate::zkevm_opcode_defs::decoding::VmEncodingMode;
use zk_evm_abstractions::{
    aux::PubdataCost,
    queries::{DecommittmentQuery, LogQuery, MemoryQuery},
    vm::{PrecompileCyclesWitness, StorageAccessRefund},
};

use super::*;
use crate::vm_state::{CallStackEntry, VmLocalState};

#[allow(unused_variables)]
pub trait VmWitnessTracer<const N: usize, E: VmEncodingMode<N>>: Clone + std::fmt::Debug {
    #[inline]
    fn start_new_execution_cycle(&mut self, current_state: &VmLocalState<N, E>) {}

    #[inline]
    fn end_execution_cycle(&mut self, current_state: &VmLocalState<N, E>) {}

    #[inline]
    fn add_memory_query(&mut self, monotonic_cycle_counter: u32, memory_query: MemoryQuery) {}

    #[inline]
    fn record_refund_for_query(
        &mut self,
        monotonic_cycle_counter: u32,
        log_query: LogQuery,
        refund: StorageAccessRefund,
    ) {
    }

    #[inline]
    fn add_log_query(&mut self, monotonic_cycle_counter: u32, log_query: LogQuery) {}

    #[inline]
    fn record_pubdata_cost_for_query(
        &mut self,
        monotonic_cycle_counter: u32,
        log_query: LogQuery,
        pubdata_cost: PubdataCost,
    ) {
    }

    #[inline]
    fn prepare_for_decommittment(
        &mut self,
        monotonic_cycle_counter: u32,
        decommittment_query: DecommittmentQuery,
    ) {
    }

    #[inline]
    fn execute_decommittment(
        &mut self,
        monotonic_cycle_counter: u32,
        decommittment_query: DecommittmentQuery,
        mem_witness: Vec<U256>,
    ) {
    }

    #[inline]
    fn add_precompile_call_result(
        &mut self,
        monotonic_cycle_counter: u32,
        call_params: LogQuery,
        mem_witness_in: Vec<MemoryQuery>,
        memory_witness_out: Vec<MemoryQuery>,
        round_witness: PrecompileCyclesWitness,
    ) {
    }

    #[inline]
    fn add_revertable_precompile_call(
        &mut self,
        monotonic_cycle_counter: u32,
        call_params: LogQuery,
    ) {
    }

    #[inline]
    fn start_new_execution_context(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_context: &CallStackEntry<N, E>,
        new_context: &CallStackEntry<N, E>,
    ) {
    }

    #[inline]
    fn finish_execution_context(&mut self, monotonic_cycle_counter: u32, panicked: bool) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DummyTracer;

impl<const N: usize, E: VmEncodingMode<N>> VmWitnessTracer<N, E> for DummyTracer {}
