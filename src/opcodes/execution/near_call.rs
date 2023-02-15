use zkevm_opcode_defs::NearCallABI;

use super::*;

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn near_call_opcode_apply<
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
        let PreState { src0, new_pc, .. } = prestate;
        let PrimitiveValue {
            value: src0,
            is_pointer: _,
        } = src0;
        // reset flags
        vm_state.reset_flags();

        // proceed with call
        let dst = self.imm_0;
        let exception_handler_location = self.imm_1;
        let near_call_abi = NearCallABI::from_u256(src0);

        // resolve passed ergs
        let pass_all_ergs = near_call_abi.ergs_passed == 0;
        let current_callstack_entry = vm_state.local_state.callstack.get_current_stack();
        let remaining_ergs = current_callstack_entry.ergs_remaining;
        let (passed_ergs, remaining_ergs_for_this_context) = if pass_all_ergs {
            (remaining_ergs, 0u32)
        } else {
            let (remaining_for_this_context, uf) =
                remaining_ergs.overflowing_sub(near_call_abi.ergs_passed);
            if uf {
                // pass max(remaining, want to pass)
                (remaining_ergs, 0u32)
            } else {
                (near_call_abi.ergs_passed, remaining_for_this_context)
            }
        };

        // update current ergs and PC
        vm_state
            .local_state
            .callstack
            .get_current_stack_mut()
            .ergs_remaining = remaining_ergs_for_this_context;
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;

        let current_stack = vm_state.local_state.callstack.get_current_stack();
        // we only need to change a PC and formally start a new context

        let mut new_stack = current_stack.clone();
        new_stack.pc = dst;
        new_stack.exception_handler_location = exception_handler_location;
        new_stack.ergs_remaining = passed_ergs;
        new_stack.is_local_frame = true;

        // perform some extra steps to ensure that our rollbacks are properly written and saved
        // both in storage and for witness
        vm_state.start_frame(vm_state.local_state.monotonic_cycle_counter, new_stack);
        vm_state.witness_tracer.add_sponge_marker(
            vm_state.local_state.monotonic_cycle_counter,
            SpongeExecutionMarker::CallstackPush,
            1..4,
            false,
        );
    }
}
