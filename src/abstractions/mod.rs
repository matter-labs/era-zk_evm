use zkevm_opcode_defs::FatPointer;

use super::*;
use crate::aux_structures::*;
pub mod tracing;
pub use self::tracing::*;

pub const MEMORY_CELLS_STACK_OR_CODE_PAGE: usize = 1 << 16;
pub const MAX_STACK_PAGE_SIZE_IN_WORDS: usize = 1 << 16;
pub const MAX_CODE_PAGE_SIZE_IN_WORDS: usize = 1 << 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MemoryType {
    Stack,
    Code,
    Heap,
    AuxHeap,
    FatPointer,
}

impl MemoryType {
    pub const fn page_size_limit(&self) -> usize {
        match self {
            MemoryType::Stack | MemoryType::Code => MEMORY_CELLS_STACK_OR_CODE_PAGE,
            MemoryType::Heap | MemoryType::AuxHeap | MemoryType::FatPointer => u32::MAX as usize,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefundedAmounts {
    pub pubdata_bytes: u32,
    pub ergs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefundType {
    None,
    RepeatedRead(RefundedAmounts),
    RepeatedWrite(RefundedAmounts),
    RevertToOriginalInFrame(RefundedAmounts),
}

impl RefundType {
    pub const fn pubdata_refund(&self) -> u32 {
        match self {
            RefundType::None => 0,
            RefundType::RepeatedRead(amounts) => amounts.pubdata_bytes,
            RefundType::RepeatedWrite(amounts) => amounts.pubdata_bytes,
            RefundType::RevertToOriginalInFrame(amounts) => amounts.pubdata_bytes,
        }
    }
}

use crate::precompiles::ecrecover::ECRecoverPrecompile;
use crate::precompiles::keccak256::Keccak256Precompile;
use crate::precompiles::sha256::Sha256Precompile;

// for strong typing we have to enumerate all of the supported precompiles here
pub enum PrecompileCyclesWitness {
    Sha256(Vec<<Sha256Precompile<true> as Precompile>::CycleWitness>),
    Keccak256(Vec<<Keccak256Precompile<true> as Precompile>::CycleWitness>),
    ECRecover(Vec<<ECRecoverPrecompile<true> as Precompile>::CycleWitness>),
}

// ALL traits here are for execution and NOT for witness generation. They can depend on one another, but should
// not have large interconnections.

// Note: We may need to extend them to allow sequencer to easily perform decisions on whether or
// not to accept a transaction (or revert to the previous state) and actually perform "huge" rollbacks on
// on all the corresponding implementors

pub trait Storage: std::fmt::Debug {
    // We can evaluate a query cost (or more precisely - get expected refunds)
    // before actually executing query
    fn estimate_refunds_for_write(
        &mut self, // to avoid any hacks inside, like prefetch
        monotonic_cycle_counter: u32,
        partial_query: &LogQuery,
    ) -> RefundType;

    // Perform a storage read/write access by taking an partially filled query
    // and returning filled query and cold/warm marker for pricing purposes
    fn execute_partial_query(&mut self, monotonic_cycle_counter: u32, query: LogQuery) -> LogQuery;
    // Indicate a start of execution frame for rollback purposes
    fn start_frame(&mut self, timestamp: Timestamp);
    // Indicate that execution frame went out from the scope, so we can
    // log the history and either rollback immediately or keep records to rollback later
    fn finish_frame(&mut self, timestamp: Timestamp, panicked: bool);

    // N.B. We may need to extend frame markers for e.g. special bootloader execution frame
    // such that we can flush all the changes of particular transaction since bootloader doesn't
    // rollback further (at least now)
}

pub trait Memory: std::fmt::Debug {
    // Perform a memory access using a partially filled query and return the result
    fn execute_partial_query(
        &mut self,
        monotonic_cycle_counter: u32,
        query: MemoryQuery,
    ) -> MemoryQuery;

    fn specialized_code_query(
        &mut self,
        monotonic_cycle_counter: u32,
        query: MemoryQuery,
    ) -> MemoryQuery;

    fn read_code_query(&self, monotonic_cycle_counter: u32, query: MemoryQuery) -> MemoryQuery;

    // Notify that a certain page went out of scope and can be discarded
    fn start_global_frame(
        &mut self,
        _current_base_page: MemoryPage,
        _new_base_page: MemoryPage,
        _calldata_fat_pointer: FatPointer,
        _timestamp: Timestamp,
    ) {
    }
    fn finish_global_frame(
        &mut self,
        _page_page: MemoryPage,
        _returndata_fat_pointer: FatPointer,
        _timestamp: Timestamp,
    ) {
    }
}

pub trait EventSink: std::fmt::Debug {
    // Largely the same as storage with exception that events are always "write"-like,
    // so we do not need to return anything
    fn add_partial_query(&mut self, monotonic_cycle_counter: u32, query: LogQuery);
    fn start_frame(&mut self, timestamp: Timestamp);
    fn finish_frame(&mut self, panicked: bool, timestamp: Timestamp);
}

pub trait PrecompilesProcessor: std::fmt::Debug {
    // Precompiles may be write-like (rollbackable, are more like markers),
    // and read-like (pure function calls like sha256, etc). Here we perform an execution
    // and optionally return memory queries performed by the executor that are useful for witness
    // at the end of the block
    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, PrecompileCyclesWitness)>;
    fn start_frame(&mut self);
    fn finish_frame(&mut self, panicked: bool);
}

pub trait DecommittmentProcessor: std::fmt::Debug {
    // For calls to external contract we use storage read + request to decommit a particular hash into some memory page.
    // We also optimize in a way that since code and calldata locations ar read-only we can just give
    // already filled page if we decommit the same hash.
    // We also optinally return a set of memory writes that such decommitment has made (if it's a new page)
    // for witness generation at the end of the block
    fn decommit_into_memory<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        partial_query: DecommittmentQuery,
        memory: &mut M,
    ) -> (DecommittmentQuery, Option<Vec<U256>>);
}

/// Abstraction over precompile implementation. Precompile is usually a closure-forming FSM, so it must output
/// some cycle-like witness
pub trait Precompile: std::fmt::Debug {
    type CycleWitness: Clone + std::fmt::Debug;

    /// execute a precompile by using request and access to memory. May be output
    /// - all memory reads (may be removed later on)
    /// - all memory writes (depending on the implementation we may directly write to `memory` and also remove it)
    /// - FSM cycle witness parameters
    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>;
}

pub enum SpongeExecutionMarker {
    MemoryQuery,
    DecommittmentQuery,
    StorageLogReadOnly,
    StorageLogWrite,
    CallstackPush,
    CallstackPop,
}
