use super::*;
use crate::vm_state::{PreState, VmState};

#[derive(Clone, Copy)]
pub struct DecodedOpcode<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub inner: zkevm_opcode_defs::DecodedOpcode<N, E>,
}

impl<const N: usize, E: VmEncodingMode<N>> std::ops::Deref for DecodedOpcode<N, E> {
    type Target = zkevm_opcode_defs::DecodedOpcode<N, E>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize, E: VmEncodingMode<N>> std::ops::DerefMut for DecodedOpcode<N, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<const N: usize, E: VmEncodingMode<N>> std::fmt::Display for DecodedOpcode<N, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<const N: usize, E: VmEncodingMode<N>> std::fmt::Debug for DecodedOpcode<N, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

use zkevm_opcode_defs::decoding::encoding_mode_production::EncodingModeProduction;
use zkevm_opcode_defs::decoding::VmEncodingMode;

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn mask_into_panic(&mut self) {
        self.inner.mask_into_panic();
    }

    pub fn mask_into_nop(&mut self) {
        self.inner.mask_into_nop();
    }

    pub fn apply<
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
        use zkevm_opcode_defs::Opcode;

        match self.inner.variant.opcode {
            Opcode::Nop(_) => self.noop_opcode_apply(vm_state, prestate),
            Opcode::Add(_) => self.add_opcode_apply(vm_state, prestate),
            Opcode::Sub(_) => self.sub_opcode_apply(vm_state, prestate),
            Opcode::Mul(_) => self.mul_opcode_apply(vm_state, prestate),
            Opcode::Div(_) => self.div_opcode_apply(vm_state, prestate),
            Opcode::Jump(_) => self.jump_opcode_apply(vm_state, prestate),
            Opcode::Context(_) => self.context_opcode_apply(vm_state, prestate),
            Opcode::Shift(_) => self.shift_opcode_apply(vm_state, prestate),
            Opcode::Binop(_) => self.binop_opcode_apply(vm_state, prestate),
            Opcode::Ptr(_) => self.ptr_opcode_apply(vm_state, prestate),
            Opcode::Log(_) => self.log_opcode_apply(vm_state, prestate),
            Opcode::NearCall(_) => self.near_call_opcode_apply(vm_state, prestate),
            Opcode::FarCall(_) => self.far_call_opcode_apply(vm_state, prestate),
            Opcode::Ret(_) => self.ret_opcode_apply(vm_state, prestate),
            Opcode::UMA(_) => self.uma_opcode_apply(vm_state, prestate),
            Opcode::Invalid(_) => unreachable!(),
        }
    }
}
