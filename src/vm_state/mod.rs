use zkevm_opcode_defs::decoding::encoding_mode_production::EncodingModeProduction;
use zkevm_opcode_defs::decoding::VmEncodingMode;
use zkevm_opcode_defs::ISAVersion;

use super::*;
use crate::flags::Flags;
use zk_evm_abstractions::aux::MemoryPage;
use zk_evm_abstractions::aux::Timestamp;
use zkevm_opcode_defs::decoding::AllowedPcOrImm;

pub mod cycle;
pub mod execution_stack;
pub mod helpers;
pub mod mem_ops;
pub mod pending_port;

pub use self::cycle::*;
pub use self::execution_stack::*;
pub use self::helpers::*;
pub use self::mem_ops::*;
pub use self::pending_port::*;

pub const SUPPORTED_ISA_VERSION: ISAVersion = ISAVersion(1);

const _: () = if SUPPORTED_ISA_VERSION.0 != zkevm_opcode_defs::DEFAULT_ISA_VERSION.0 {
    panic!()
} else {
    ()
};

use zkevm_opcode_defs::{STARTING_BASE_PAGE, STARTING_TIMESTAMP};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrimitiveValue {
    pub value: U256,
    pub is_pointer: bool,
}

impl PrimitiveValue {
    pub const fn empty() -> Self {
        Self {
            value: U256::zero(),
            is_pointer: false,
        }
    }

    pub const fn from_value(value: U256) -> Self {
        Self {
            value,
            is_pointer: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VmLocalState<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub previous_code_word: U256,
    pub previous_code_memory_page: MemoryPage,
    pub registers: [PrimitiveValue; zkevm_opcode_defs::REGISTERS_COUNT],
    pub flags: Flags,
    pub timestamp: u32,
    pub monotonic_cycle_counter: u32,
    // A counter for the *ergs* spent on public data for L2 -> L2 messages and storage writes.
    // It is an out-of-circuit only value and it does not (and can not) include ergs spent
    // on the content of long L2->L1 messages as well as well as publishing contract's bytecode.
    pub spent_pubdata_counter: u32,
    pub memory_page_counter: u32,
    pub absolute_execution_step: u32,
    pub current_ergs_per_pubdata_byte: u32,
    pub tx_number_in_block: u16,
    pub pending_exception: bool,
    pub previous_super_pc: E::PcOrImm,
    pub context_u128_register: u128,
    pub callstack: Callstack<N, E>,
}

impl<const N: usize, E: VmEncodingMode<N>> VmLocalState<N, E> {
    pub fn empty_state() -> Self {
        Self {
            previous_code_word: U256::zero(),
            previous_code_memory_page: MemoryPage(0u32),
            registers: [PrimitiveValue::empty(); zkevm_opcode_defs::REGISTERS_COUNT],
            flags: Flags::empty(),
            timestamp: STARTING_TIMESTAMP,
            monotonic_cycle_counter: 0u32,
            spent_pubdata_counter: 0u32,
            memory_page_counter: STARTING_BASE_PAGE,
            absolute_execution_step: 0,
            current_ergs_per_pubdata_byte: 0,
            tx_number_in_block: 0,
            previous_super_pc: E::PcOrImm::from_u64_clipped(0),
            pending_exception: false,
            context_u128_register: 0u128,
            callstack: Callstack::empty(),
        }
    }

    pub fn execution_has_ended(&self) -> bool {
        self.callstack.is_empty()
    }

    pub fn timestamp_for_code_or_src_read(&self) -> Timestamp {
        Timestamp(self.timestamp + 0)
    }

    pub fn callstack_is_full(&self) -> bool {
        self.callstack.is_full()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DelayedLocalStateChanges<
    const N: usize = 8,
    E: VmEncodingMode<N> = EncodingModeProduction,
> {
    pub new_ergs_remaining: Option<u32>,
    pub new_previous_code_word: Option<U256>,
    pub new_previous_super_pc: Option<E::PcOrImm>,
    pub new_pending_exception: Option<bool>,
    pub new_previous_code_memory_page: Option<MemoryPage>,
}

impl<const N: usize, E: VmEncodingMode<N>> Default for DelayedLocalStateChanges<N, E> {
    fn default() -> Self {
        Self {
            new_ergs_remaining: None,
            new_previous_code_word: None,
            new_previous_super_pc: None,
            new_pending_exception: None,
            new_previous_code_memory_page: None,
        }
    }
}

impl<const N: usize, E: VmEncodingMode<N>> DelayedLocalStateChanges<N, E> {
    pub fn apply(self, local_state: &mut VmLocalState<N, E>) {
        if let Some(ergs_remaining) = self.new_ergs_remaining {
            local_state.callstack.get_current_stack_mut().ergs_remaining = ergs_remaining;
        }
        if let Some(previous_code_word) = self.new_previous_code_word {
            local_state.previous_code_word = previous_code_word;
        }

        if let Some(previous_super_pc) = self.new_previous_super_pc {
            local_state.previous_super_pc = previous_super_pc;
        }

        if let Some(new_pending_exception) = self.new_pending_exception {
            local_state.pending_exception = new_pending_exception;
        }

        if let Some(new_previous_code_memory_page) = self.new_previous_code_memory_page {
            local_state.previous_code_memory_page = new_previous_code_memory_page;
        }
    }
}

#[derive(Debug)]
pub struct VmState<
    S: zk_evm_abstractions::vm::Storage,
    M: zk_evm_abstractions::vm::Memory,
    EV: zk_evm_abstractions::vm::EventSink,
    PP: zk_evm_abstractions::vm::PrecompilesProcessor,
    DP: zk_evm_abstractions::vm::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer<N, E>,
    const N: usize = 8,
    E: VmEncodingMode<N> = EncodingModeProduction,
> {
    pub local_state: VmLocalState<N, E>,
    pub block_properties: crate::block_properties::BlockProperties,
    pub storage: S,
    pub memory: M,
    pub event_sink: EV,
    pub precompiles_processor: PP,
    pub decommittment_processor: DP,
    pub witness_tracer: WT,
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
    pub fn empty_state(
        storage: S,
        memory: M,
        event_sink: EV,
        precompiles_processor: PP,
        decommittment_processor: DP,
        witness_tracer: WT,
        block_properties: crate::block_properties::BlockProperties,
    ) -> Self {
        Self {
            local_state: VmLocalState::empty_state(),
            storage,
            memory,
            event_sink,
            precompiles_processor,
            decommittment_processor,
            witness_tracer,
            block_properties,
        }
    }
    pub fn reset_flags(&mut self) {
        self.local_state.flags.reset();
    }
    pub fn callstack_is_full(&self) -> bool {
        self.local_state.callstack_is_full()
    }
    pub fn execution_has_ended(&self) -> bool {
        self.local_state.execution_has_ended()
    }
    pub fn compute_if_should_skip_cycle(&mut self) -> bool {
        self.execution_has_ended()
    }
    pub fn timestamp_for_code_or_src_read(&self) -> Timestamp {
        self.local_state.timestamp_for_code_or_src_read()
    }
    pub fn timestamp_for_first_decommit_or_precompile_read(&self) -> Timestamp {
        Timestamp(self.local_state.timestamp + 1)
    }
    pub fn timestamp_for_second_decommit_or_precompile_write(&self) -> Timestamp {
        Timestamp(self.local_state.timestamp + 2)
    }
    pub fn timestamp_for_dst_write(&self) -> Timestamp {
        Timestamp(self.local_state.timestamp + 3)
    }
    pub fn increment_timestamp_after_cycle(&mut self) {
        self.local_state.timestamp += zkevm_opcode_defs::TIME_DELTA_PER_CYCLE
    }
    pub fn new_base_memory_page_on_call(&self) -> MemoryPage {
        MemoryPage(self.local_state.memory_page_counter)
    }
    pub fn increment_memory_pages_on_call(&mut self) {
        self.local_state.memory_page_counter += zkevm_opcode_defs::NEW_MEMORY_PAGES_PER_FAR_CALL;
    }
}
