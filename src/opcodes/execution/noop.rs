use super::*;

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn noop_opcode_apply<
        'a,
        S: zk_evm_abstractions::vm::Storage,
        M: zk_evm_abstractions::vm::Memory,
        EV: zk_evm_abstractions::vm::EventSink,
        PP: zk_evm_abstractions::vm::PrecompilesProcessor,
        DP: zk_evm_abstractions::vm::DecommittmentProcessor,
        WT: crate::witness_trace::VmWitnessTracer<N, E>,
    >(
        &self,
        vm_state: &mut VmState<S, M, EV, PP, DP, WT, N, E>,
        prestate: PreState<N, E>,
    ) {
        let PreState { new_pc, .. } = prestate;
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;
        // IMPORTANT: while we formally do not update the register value here, the NOP operation
        // may still formally address the operand and move SP this way
    }
}
