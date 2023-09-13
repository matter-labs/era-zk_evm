use super::*;

use zkevm_opcode_defs::definitions::ret::*;
use zkevm_opcode_defs::FatPointerValidationException;
use zkevm_opcode_defs::{FatPointer, Opcode, RetABI, RetForwardPageType, RetOpcode};

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn ret_opcode_apply<
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
        let PreState { src0, .. } = prestate;
        let mut inner_variant = match self.variant.opcode {
            Opcode::Ret(inner) => inner,
            _ => unreachable!(),
        };
        // ret always resets flags
        vm_state.local_state.flags.reset();

        let PrimitiveValue {
            value: src0,
            is_pointer: src0_is_ptr,
        } = src0;

        let ret_abi = RetABI::from_u256(src0);

        // we want to mark with one that was will become a new current (taken from stack)
        vm_state.witness_tracer.add_sponge_marker(
            vm_state.local_state.monotonic_cycle_counter,
            SpongeExecutionMarker::CallstackPop,
            1..4,
            false,
        );

        let RetABI {
            mut memory_quasi_fat_pointer,
            page_forwarding_mode,
        } = ret_abi;

        let is_to_label = self.variant.flags[RET_TO_LABEL_BIT_IDX];
        let label_pc = self.imm_0;

        let current_callstack = vm_state.local_state.callstack.get_current_stack();

        let mut pointer_validation_exceptions = FatPointerValidationException::empty();

        if current_callstack.is_local_frame == false {
            // if we try to do forwarding then we have to have ptr in src0,
            // otherwise we will panic instead!
            if page_forwarding_mode == RetForwardPageType::ForwardFatPointer {
                if src0_is_ptr == false {
                    inner_variant = RetOpcode::Panic;
                }
                if memory_quasi_fat_pointer.memory_page < current_callstack.base_memory_page.0 {
                    // it's an exotic case when we try to
                    // return-forward our own calldata. To avoid
                    // a sequence of:
                    // - caller makes far call to some contract
                    // - callee does return-forward @calldataptr
                    // - caller modifies calldata corresponding heap region, that leads to modification of returndata
                    // we require that returndata forwarding is unidirectional
                    inner_variant = RetOpcode::Panic;
                }
            }

            // validate that fat pointer (one a future one) we formed is somewhat valid
            let validate_as_fresh = page_forwarding_mode != RetForwardPageType::ForwardFatPointer;

            pointer_validation_exceptions = memory_quasi_fat_pointer.validate(validate_as_fresh);

            if pointer_validation_exceptions.is_empty() == false {
                // pointer is malformed
                inner_variant = RetOpcode::Panic;
            }
            // our formal definition of "in bounds" is strictly "less than", but we want to allow to return
            // "trivial" pointer, like `ret.ok r0`
            // this captures the case of empty slice
            if memory_quasi_fat_pointer.validate_as_slice() == false {
                inner_variant = RetOpcode::Panic;
            }

            if inner_variant == RetOpcode::Panic {
                memory_quasi_fat_pointer = FatPointer::empty();
            }
        }

        let mut ergs_remaining = current_callstack.ergs_remaining;

        // now we are all good to form a new fat pointer for
        let fat_ptr_for_returndata = if current_callstack.is_local_frame == true {
            None
        } else {
            match inner_variant {
                RetOpcode::Ok | RetOpcode::Revert => {
                    match page_forwarding_mode {
                        RetForwardPageType::ForwardFatPointer => {
                            // We can formally shrink the pointer
                            // If it was malformed then we masked and overflows can not happen
                            let new_start = memory_quasi_fat_pointer
                                .start
                                .wrapping_add(memory_quasi_fat_pointer.offset);
                            let new_length = memory_quasi_fat_pointer
                                .length
                                .wrapping_sub(memory_quasi_fat_pointer.offset);

                            memory_quasi_fat_pointer.start = new_start;
                            memory_quasi_fat_pointer.length = new_length;
                            memory_quasi_fat_pointer.offset = 0;
                        }
                        RetForwardPageType::UseHeap => {
                            let owned_page = CallStackEntry::<N, E>::heap_page_from_base(
                                current_callstack.base_memory_page,
                            )
                            .0;

                            memory_quasi_fat_pointer.memory_page = owned_page;
                        }
                        RetForwardPageType::UseAuxHeap => {
                            let owned_page = CallStackEntry::<N, E>::aux_heap_page_from_base(
                                current_callstack.base_memory_page,
                            )
                            .0;

                            memory_quasi_fat_pointer.memory_page = owned_page;
                        }
                    }
                }
                RetOpcode::Panic => {
                    memory_quasi_fat_pointer = FatPointer::empty();
                }
            }

            // potentially pay for memory growth
            let memory_growth_in_bytes = match page_forwarding_mode {
                a @ RetForwardPageType::UseHeap | a @ RetForwardPageType::UseAuxHeap => {
                    // pointer is already validated, so we do not need to check that start + length do not overflow
                    let mut upper_bound =
                        memory_quasi_fat_pointer.start + memory_quasi_fat_pointer.length;

                    let penalize_out_of_bounds_growth = pointer_validation_exceptions
                        .contains(FatPointerValidationException::DEREF_BEYOND_HEAP_RANGE);
                    if penalize_out_of_bounds_growth {
                        upper_bound = u32::MAX;
                    }

                    let current_bound = if a == RetForwardPageType::UseHeap {
                        current_callstack.heap_bound
                    } else if a == RetForwardPageType::UseAuxHeap {
                        current_callstack.aux_heap_bound
                    } else {
                        unreachable!();
                    };
                    let (mut diff, uf) = upper_bound.overflowing_sub(current_bound);
                    if uf {
                        // heap bound is already beyond what we pass
                        diff = 0u32;
                    } else {
                        // we do not need to do anything with the frame that goes out of scope
                    };

                    diff
                }
                RetForwardPageType::ForwardFatPointer => 0u32,
            };

            // MEMORY_GROWTH_ERGS_PER_BYTE is always 1
            let cost_of_memory_growth =
                memory_growth_in_bytes.wrapping_mul(zkevm_opcode_defs::MEMORY_GROWTH_ERGS_PER_BYTE);
            if ergs_remaining >= cost_of_memory_growth {
                ergs_remaining -= cost_of_memory_growth;
            } else {
                ergs_remaining = 0;
                inner_variant = RetOpcode::Panic;
                memory_quasi_fat_pointer = FatPointer::empty();
            };

            // we do nothing with it later on, so just keep returndata page, and set zeroes for other
            Some(memory_quasi_fat_pointer)
        };
        drop(current_callstack);

        // done with exceptions, so we can pop the callstack entry
        let panicked = inner_variant == RetOpcode::Revert || inner_variant == RetOpcode::Panic;

        let finished_callstack =
            vm_state.finish_frame(vm_state.local_state.monotonic_cycle_counter, panicked);

        // we did finish frame, so get_current_stack_mut is one of the original caller's
        let is_to_label = is_to_label & finished_callstack.is_local_frame;

        if finished_callstack.is_local_frame == false {
            let returndata_fat_pointer = fat_ptr_for_returndata.unwrap();

            vm_state.memory.finish_global_frame(
                finished_callstack.base_memory_page,
                returndata_fat_pointer,
                Timestamp(vm_state.local_state.timestamp),
            );

            vm_state.local_state.did_call_or_ret_recently = true;
            vm_state.local_state.registers[RET_IMPLICIT_RETURNDATA_PARAMS_REGISTER as usize] =
                PrimitiveValue {
                    value: returndata_fat_pointer.to_u256(),
                    is_pointer: true,
                };
            vm_state.local_state.registers[RET_RESERVED_REGISTER_0 as usize] =
                PrimitiveValue::empty();
            vm_state.local_state.registers[RET_RESERVED_REGISTER_1 as usize] =
                PrimitiveValue::empty();
            vm_state.local_state.registers[RET_RESERVED_REGISTER_2 as usize] =
                PrimitiveValue::empty();

            // ALL other registers are zeroed out!
            for dst in vm_state
                .local_state
                .registers
                .iter_mut()
                .skip((RET_RESERVED_REGISTER_2 as usize) + 1)
            {
                *dst = PrimitiveValue::empty();
            }

            // clean up context register
            vm_state.local_state.context_u128_register = 0u128;
        } else {
            debug_assert!(fat_ptr_for_returndata.is_none());
        }

        let next_context = vm_state.local_state.callstack.get_current_stack_mut();
        // return ergs
        next_context.ergs_remaining += ergs_remaining;
        // jump properly
        if is_to_label {
            next_context.pc = label_pc;
        } else if panicked {
            next_context.pc = finished_callstack.exception_handler_location;
        } else {
            // just use a saved value
        }

        // and set flag on panic
        if inner_variant == RetOpcode::Panic {
            vm_state.local_state.flags.overflow_or_less_than_flag = true;
        }
    }
}
