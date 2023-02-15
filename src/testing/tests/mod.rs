use super::*;

use zkevm_opcode_defs::system_params::BOOTLOADER_FORMAL_ADDRESS;

use crate::precompiles::*;
use crate::vm_state::*;
use crate::{
    block_properties::BlockProperties,
    reference_impls::{event_sink::InMemoryEventSink, memory::SimpleMemory},
    testing::storage::InMemoryStorage,
    vm_state::VmState,
    witness_trace::DummyTracer,
};

pub fn create_default_block_info() -> BlockProperties {
    BlockProperties {
        default_aa_code_hash: U256::zero(),
        zkporter_is_available: true,
    }
}

pub fn create_initial_vm_state_for_basic_testing<'a, const B: bool>(
    tools: &'a mut BasicTestingTools<B>,
    block_properties: &'a BlockProperties,
) -> VmState<
    'a,
    InMemoryStorage,
    SimpleMemory,
    InMemoryEventSink,
    DefaultPrecompilesProcessor<B>,
    SimpleDecommitter<B>,
    DummyTracer,
> {
    let mut vm = VmState::empty_state(
        &mut tools.storage,
        &mut tools.memory,
        &mut tools.event_sink,
        &mut tools.precompiles_processor,
        &mut tools.decommittment_processor,
        &mut tools.witness_tracer,
        block_properties,
    );

    let bootloader_context = CallStackEntry {
        this_address: *BOOTLOADER_FORMAL_ADDRESS,
        msg_sender: Address::zero(),
        code_address: *BOOTLOADER_FORMAL_ADDRESS,
        base_memory_page: MemoryPage(zkevm_opcode_defs::BOOTLOADER_BASE_PAGE),
        code_page: MemoryPage(zkevm_opcode_defs::BOOTLOADER_CODE_PAGE),
        sp: 0u16,
        pc: 0u16,
        exception_handler_location: 0u16,
        ergs_remaining: zkevm_opcode_defs::system_params::VM_INITIAL_FRAME_ERGS,
        this_shard_id: 0u8,
        caller_shard_id: 0u8,
        code_shard_id: 0u8,
        is_static: false,
        is_local_frame: false,
        context_u128_value: 0,
        heap_bound: 0u32,
        aux_heap_bound: 0u32,
    };

    vm.push_bootloader_context(0, bootloader_context);

    vm
}
