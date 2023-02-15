use super::*;

use super::simple_tracer::*;

#[test]
fn run_dummy_log_and_unmapped_noop() {
    let mut tools = create_default_testing_tools();
    let block_properties = create_default_block_info();
    let mut vm = create_initial_vm_state_for_basic_testing(&mut tools, &block_properties);

    let tracing_closure = |state: &VmState<_, _, _, _, _, _>, aux: AuxTracingInformation, cycle_idx: u32| {
        println!("------------------------------------------------------------");
        println!("After the cycle {}", cycle_idx);
        println!("Did skip cycle: {}", aux.skip_cycle);
        println!("Executed opcode: {}", aux.final_masked_opcode);
        println!("Registers:");
        for (i, r) in state.registers.iter().enumerate() {
            println!("r{} = {:x}", i, r);
        }
        println!("Flags = {:?}", state.flags);
        println!("Resolved jump condition = {}", aux.resolved_jump_condition);
        println!("Exceptions: {:?}", aux.error_flags_collection);
        if state.execution_has_ended() {
            println!("Execution has ended");
        } else {
            println!("Execution continues");
        }
        println!("Final context value: {:?}", state.callstack.get_current_stack());
        println!("Pending state: {:?}", state.pending_port);
        println!("Pending cycles left: {:?}", state.pending_cycles_left);
    };

    let mut debug_tracer = ClosureBasedTracer::new(tracing_closure); 

    vm.memory.populate(vec![
        (BOOTLOADER_CODE_PAGE, vec![U256::from_str_radix("10", 10).unwrap()])
    ]);

    vm.cycle(&mut debug_tracer);
    vm.cycle(&mut debug_tracer);
    vm.cycle(&mut debug_tracer);
    vm.cycle(&mut debug_tracer);

    let (full_storage_access_history, storage_pre_shard, events_log_history, events, l1_messages, _) = get_final_net_states!(vm, tools);
    
    println!("------------------------------------------------------");
    println!("Storage log access history:");
    println!("{:?}", full_storage_access_history);
    println!("Event log access history:");
    println!("{:?}", events_log_history);

    println!("------------------------------------------------------");
    println!("Net events:");
    println!("{:?}", events);
    println!("Net L1 messages:");
    println!("{:?}", l1_messages);
}

#[test]
fn check_nop_moves_sp() {
    let mut tools = create_default_testing_tools();
    let block_properties = create_default_block_info();
    let mut vm = create_initial_vm_state_for_basic_testing(&mut tools, &block_properties);

    let default_tracing_tool = DefaultTracingClosure::new();
    let mut debug_tracer = ClosureBasedTracer::new(|a, b, c| default_tracing_tool.trace(a, b, c)); 

    // manually encode LE
    let opcode = "000100005000002000";
    vm.memory.populate(vec![
        (BOOTLOADER_CODE_PAGE, vec![U256::from_little_endian(&hex::decode(opcode).unwrap())])
    ]);

    vm.cycle(&mut debug_tracer);
}
