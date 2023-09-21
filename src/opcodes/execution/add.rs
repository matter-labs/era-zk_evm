use super::*;

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn add_opcode_apply<
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
        let PreState {
            src0,
            src1,
            dst0_mem_location,
            new_pc,
            ..
        } = prestate;
        let PrimitiveValue {
            value: src0,
            is_pointer: _,
        } = src0;
        let PrimitiveValue {
            value: src1,
            is_pointer: _,
        } = src1;

        use zkevm_opcode_defs::SET_FLAGS_FLAG_IDX;
        let set_flags = self.variant.flags[SET_FLAGS_FLAG_IDX];
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;
        let (result, of) = src0.overflowing_add(src1);
        let eq = result.is_zero();
        let gt = !eq && !of;

        if set_flags {
            vm_state.local_state.flags.overflow_or_less_than_flag = of;
            vm_state.local_state.flags.equality_flag = eq;
            vm_state.local_state.flags.greater_than_flag = gt;
        }
        let result = PrimitiveValue {
            value: result,
            is_pointer: false,
        };
        vm_state.perform_dst0_update(
            vm_state.local_state.monotonic_cycle_counter,
            result,
            dst0_mem_location,
            self,
        );
    }
}
