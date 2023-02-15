use super::*;

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn noop_opcode_apply<
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
        let PreState { new_pc, .. } = prestate;
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;
        // IMPORTANT: while we formally do not update the register value here, the NOP operation
        // may still formally address the operand and move SP this way
    }
}
