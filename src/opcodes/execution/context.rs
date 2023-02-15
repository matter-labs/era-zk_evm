use super::*;

use zkevm_opcode_defs::{ContextOpcode, Opcode};

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn context_opcode_apply<
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
            new_pc,
            dst0_mem_location,
            ..
        } = prestate;
        let PrimitiveValue {
            value: src0,
            is_pointer: _,
        } = src0;
        let inner_variant = match self.variant.opcode {
            Opcode::Context(inner) => inner,
            _ => unreachable!(),
        };
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;
        let current_context = vm_state.local_state.callstack.get_current_stack();

        // these functions by definition require kernel mode, so we do not need extra checks
        if inner_variant == ContextOpcode::SetContextU128 {
            vm_state.local_state.context_u128_register = src0.low_u128();
            return;
        }

        if inner_variant == ContextOpcode::SetErgsPerPubdataByte {
            vm_state.local_state.current_ergs_per_pubdata_byte = src0.low_u32();
            return;
        }

        if inner_variant == ContextOpcode::IncrementTxNumber {
            vm_state.local_state.tx_number_in_block =
                vm_state.local_state.tx_number_in_block.wrapping_add(1);
            return;
        }

        let value = match inner_variant {
            ContextOpcode::This => {
                let address = &current_context.this_address;
                address_to_u256(address)
            }
            ContextOpcode::Caller => {
                let address = &current_context.msg_sender;
                address_to_u256(address)
            }
            ContextOpcode::CodeAddress => {
                let address = &current_context.code_address;
                address_to_u256(address)
            }
            ContextOpcode::Meta => {
                use zkevm_opcode_defs::VmMetaParameters;

                let meta = VmMetaParameters {
                    ergs_per_pubdata_byte: vm_state.local_state.current_ergs_per_pubdata_byte,
                    this_shard_id: current_context.this_shard_id,
                    caller_shard_id: current_context.caller_shard_id,
                    code_shard_id: current_context.code_shard_id,
                    heap_size: vm_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .heap_bound,
                    aux_heap_size: vm_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .aux_heap_bound,
                };

                meta.to_u256()
            }
            ContextOpcode::ErgsLeft => U256::from(current_context.ergs_remaining as u64),
            ContextOpcode::Sp => U256::from(current_context.sp.as_u64()),
            ContextOpcode::GetContextU128 => U256::from(current_context.context_u128_value),
            ContextOpcode::SetContextU128 => {
                unreachable!()
            }
            ContextOpcode::SetErgsPerPubdataByte => {
                unreachable!()
            }
            ContextOpcode::IncrementTxNumber => {
                unreachable!()
            }
        };

        let result = PrimitiveValue {
            value,
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
