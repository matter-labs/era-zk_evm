use super::*;

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn div_opcode_apply<
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
        let set_flags = self.variant.flags[SET_FLAGS_FLAG_IDX];
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;
        if src1.is_zero() {
            let of = true;
            if set_flags {
                vm_state.reset_flags();
                vm_state.local_state.flags.overflow_or_less_than_flag = of;
            }

            vm_state.perform_dst0_update(
                vm_state.local_state.monotonic_cycle_counter,
                PrimitiveValue::empty(),
                dst0_mem_location,
                self,
            );
            vm_state.perform_dst1_update(PrimitiveValue::empty(), self.dst1_reg_idx);
        } else {
            let (q, r) = src0.div_mod(src1);
            if set_flags {
                let eq = q.is_zero();
                let gt = r.is_zero();

                vm_state.reset_flags();
                vm_state.local_state.flags.equality_flag = eq;
                vm_state.local_state.flags.greater_than_flag = gt;
            }

            let q = PrimitiveValue {
                value: q,
                is_pointer: false,
            };
            vm_state.perform_dst0_update(
                vm_state.local_state.monotonic_cycle_counter,
                q,
                dst0_mem_location,
                self,
            );
            let r = PrimitiveValue {
                value: r,
                is_pointer: false,
            };
            vm_state.perform_dst1_update(r, self.dst1_reg_idx);
        }
    }
}
