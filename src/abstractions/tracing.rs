use zkevm_opcode_defs::decoding::{EncodingModeProduction, VmEncodingMode};

use crate::{
    opcodes::DecodedOpcode,
    vm_state::{ErrorFlags, PrimitiveValue, VmLocalState},
};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VmLocalStateData<'a, const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub vm_local_state: &'a VmLocalState<N, E>,
}

#[derive(Clone, Copy, Debug)]
pub struct AfterDecodingData<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub raw_opcode_unmasked: E::IntegerRepresentation, // what one gets from memory
    pub opcode_masked: DecodedOpcode<N, E>,            // what one gets after exception handling
    pub error_flags_accumulated: ErrorFlags,
    pub resolved_condition: bool,
    pub did_skip_cycle: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct BeforeExecutionData<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub opcode: DecodedOpcode<N, E>,
    pub src0_value: PrimitiveValue,
    pub src1_value: PrimitiveValue,
    pub src0_mem_location: Option<MemoryLocation>,
    pub new_pc: E::PcOrImm,
}

#[derive(Clone, Copy, Debug)]
pub struct AfterExecutionData<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub opcode: DecodedOpcode<N, E>,
    pub dst0_mem_location: Option<MemoryLocation>,
}

impl Memory for () {
    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        _query: MemoryQuery,
    ) -> MemoryQuery {
        unreachable!()
    }

    fn specialized_code_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        _query: MemoryQuery,
    ) -> MemoryQuery {
        unreachable!()
    }

    fn read_code_query(&self, _monotonic_cycle_counter: u32, _query: MemoryQuery) -> MemoryQuery {
        unreachable!()
    }
}

pub trait Tracer<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction>:
    std::fmt::Debug
{
    const CALL_BEFORE_DECODING: bool = false;
    const CALL_AFTER_DECODING: bool = false;
    const CALL_BEFORE_EXECUTION: bool = false;
    const CALL_AFTER_EXECUTION: bool = false;

    type SupportedMemory: Memory;
    fn before_decoding(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        memory: &Self::SupportedMemory,
    );
    fn after_decoding(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        data: AfterDecodingData<N, E>,
        memory: &Self::SupportedMemory,
    );
    fn before_execution(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        data: BeforeExecutionData<N, E>,
        memory: &Self::SupportedMemory,
    );
    fn after_execution(
        &mut self,
        state: VmLocalStateData<'_, N, E>,
        data: AfterExecutionData<N, E>,
        memory: &Self::SupportedMemory,
    );
}
