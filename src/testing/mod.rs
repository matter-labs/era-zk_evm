use super::*;
use crate::abstractions::*;
use crate::aux_structures::*;
use std::collections::*;

pub const NUM_SHARDS: usize = 2;

use crate::reference_impls::{decommitter::SimpleDecommitter, event_sink::*, memory::SimpleMemory};
pub mod simple_tracer;
pub mod storage;

use self::storage::InMemoryStorage;
use crate::precompiles::DefaultPrecompilesProcessor;
use crate::witness_trace::DummyTracer;

pub struct BasicTestingTools<const B: bool> {
    pub storage: InMemoryStorage,
    pub memory: SimpleMemory,
    pub event_sink: InMemoryEventSink,
    pub precompiles_processor: DefaultPrecompilesProcessor<B>,
    pub decommittment_processor: SimpleDecommitter<B>,
    pub witness_tracer: DummyTracer,
}

pub fn create_default_testing_tools() -> BasicTestingTools<false> {
    let storage = InMemoryStorage::new();
    let memory = SimpleMemory::new();
    let event_sink = InMemoryEventSink::new();
    let precompiles_processor = DefaultPrecompilesProcessor::<false>;
    let decommittment_processor = SimpleDecommitter::<false>::new();
    let witness_tracer = DummyTracer;

    BasicTestingTools::<false> {
        storage,
        memory,
        event_sink,
        precompiles_processor,
        decommittment_processor,
        witness_tracer,
    }
}

pub fn get_final_net_states<const B: bool>(
    tools: BasicTestingTools<B>,
) -> (
    Vec<LogQuery>,
    [HashMap<Address, HashMap<U256, U256>>; NUM_SHARDS],
    Vec<LogQuery>,
    Vec<EventMessage>,
    Vec<EventMessage>,
    SimpleMemory,
) {
    let BasicTestingTools::<B> {
        storage,
        event_sink,
        memory,
        ..
    } = tools;

    let final_storage_state = storage.inner.clone();
    let (full_storage_access_history, _per_slot_history) = storage.flatten_and_net_history();
    let (events_log_history, events, l1_messages) = event_sink.flatten();

    (
        full_storage_access_history,
        final_storage_state,
        events_log_history,
        events,
        l1_messages,
        memory,
    )
}

#[cfg(test)]
mod tests;
