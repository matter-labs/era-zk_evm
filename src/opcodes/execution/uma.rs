use crate::abstractions::MemoryType;

use super::*;
use zkevm_opcode_defs::{FatPointer, Opcode, UMAOpcode, UMA_INCREMENT_FLAG_IDX};

const U64_TOP_32_BITS_MASK: u64 = 0xffff_ffff_0000_0000;

use zkevm_opcode_defs::bitflags::bitflags;

bitflags! {
    pub struct UMAExceptionFlags: u64 {
        const INPUT_IS_NOT_POINTER_WHEN_EXPECTED = 1u64 << 0;
        const DEREF_BEYOND_HEAP_RANGE = 1u64 << 1;
        const OVERFLOW_ON_INCREMENT = 1u64 << 2;
        const NOT_ENOUGH_ERGS_TO_GROW_MEMORY = 1u64 << 3;
    }

    pub struct UMASkipMemoryAccessFlags: u64 {
        const FAT_PTR_IS_OUT_OF_BOUNDS = 1u64 << 0;
        const DEREF_BEYOND_HEAP_RANGE = 1u64 << 1;
    }
}

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn uma_opcode_apply<
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
        debug_assert!(
            dst0_mem_location.is_none(),
            "UMA opcode has dst0 not in register"
        );
        let inner_variant = match self.variant.opcode {
            Opcode::UMA(inner) => inner,
            _ => unreachable!(),
        };
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;

        let increment_offset = self.variant.flags[UMA_INCREMENT_FLAG_IDX];

        let PrimitiveValue {
            value: src0_value,
            is_pointer: src0_is_ptr,
        } = src0;
        let PrimitiveValue {
            value: src1,
            is_pointer: _,
        } = src1;
        let mut fat_ptr = FatPointer::from_u256(src0_value);

        let mut exceptions = UMAExceptionFlags::empty();
        let mut skip_memory_access_flags = UMASkipMemoryAccessFlags::empty();

        let is_ptr_read = inner_variant == UMAOpcode::FatPointerRead;

        // heap and aux heap are under full user's control, but fat pointers must be accessed in a valid manner
        if is_ptr_read {
            if src0_is_ptr == false {
                // we are trying to dereference not a pointer
                exceptions.set(UMAExceptionFlags::INPUT_IS_NOT_POINTER_WHEN_EXPECTED, true);
            }
        }

        let memory_type = match inner_variant {
            UMAOpcode::HeapRead | UMAOpcode::HeapWrite => {
                let page = CallStackEntry::<N, E>::heap_page_from_base(
                    vm_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .base_memory_page,
                );

                fat_ptr.memory_page = page.0;

                MemoryType::Heap
            }
            UMAOpcode::AuxHeapRead | UMAOpcode::AuxHeapWrite => {
                let page = CallStackEntry::<N, E>::aux_heap_page_from_base(
                    vm_state
                        .local_state
                        .callstack
                        .get_current_stack()
                        .base_memory_page,
                );

                fat_ptr.memory_page = page.0;

                MemoryType::AuxHeap
            }
            UMAOpcode::FatPointerRead => MemoryType::FatPointer,
        };

        let src_offset = if is_ptr_read {
            if fat_ptr.validate_in_bounds() == false {
                // it's not an exception, but we do not need to access memory,
                // and can just return 0
                skip_memory_access_flags
                    .set(UMASkipMemoryAccessFlags::FAT_PTR_IS_OUT_OF_BOUNDS, true);
            }
            // there can be no overflow over u32 due to how we create fat pointers
            // if we are in bounds, and if we are not - do not care

            fat_ptr.start.wrapping_add(fat_ptr.offset)
        } else {
            // for heaps we offset encodes absolute position
            let offset = fat_ptr.offset;

            // if our register is either not u32, or it's just "too large",
            // then we should also panic
            if src0.value > zkevm_opcode_defs::uma::MAX_OFFSET_TO_DEREF {
                // this is an exception because one tries to address too far into the heap
                exceptions.set(UMAExceptionFlags::DEREF_BEYOND_HEAP_RANGE, true);
                skip_memory_access_flags
                    .set(UMASkipMemoryAccessFlags::DEREF_BEYOND_HEAP_RANGE, true);
            }

            offset
        };

        let (incremented_offset, increment_offset_of) = fat_ptr.offset.overflowing_add(32);

        if increment_offset_of {
            // incremented_offset is an indication of the non-inclusive end of memory region we try
            // to access. So if it overflows we have an exception
            exceptions.set(UMAExceptionFlags::OVERFLOW_ON_INCREMENT, true);
            if is_ptr_read == false {
                // sanity check - it should be caught by comparison above
                assert!(exceptions.contains(UMAExceptionFlags::DEREF_BEYOND_HEAP_RANGE));
            }
        }

        let current_callstack_mut = vm_state.local_state.callstack.get_current_stack_mut();

        // potentially pay for memory growth
        let memory_growth_in_bytes = match inner_variant {
            UMAOpcode::HeapRead
            | UMAOpcode::HeapWrite
            | UMAOpcode::AuxHeapRead
            | UMAOpcode::AuxHeapWrite => {
                let current_bound = match inner_variant {
                    UMAOpcode::HeapRead | UMAOpcode::HeapWrite => current_callstack_mut.heap_bound,
                    UMAOpcode::AuxHeapRead | UMAOpcode::AuxHeapWrite => {
                        current_callstack_mut.aux_heap_bound
                    }
                    _ => {
                        unreachable!()
                    }
                };

                // here do do not care about potential overflow, and later on penalize
                // for it
                let upper_bound = incremented_offset;
                let (mut diff, uf) = upper_bound.overflowing_sub(current_bound);
                if uf {
                    // heap bound is already beyond what we pass
                    diff = 0u32;
                } else {
                    match inner_variant {
                        UMAOpcode::HeapRead | UMAOpcode::HeapWrite => {
                            current_callstack_mut.heap_bound = upper_bound;
                        }
                        UMAOpcode::AuxHeapRead | UMAOpcode::AuxHeapWrite => {
                            current_callstack_mut.aux_heap_bound = upper_bound;
                        }
                        _ => {
                            unreachable!()
                        }
                    };
                };

                diff
            }
            UMAOpcode::FatPointerRead => {
                // cost was paid somewhere, and we if try to go out of bound we will just not read
                0u32
            }
        };

        let mut cost_of_memory_growth =
            memory_growth_in_bytes.wrapping_mul(zkevm_opcode_defs::MEMORY_GROWTH_ERGS_PER_BYTE);

        // if we try to go "too far" in memory that our normal memory growth payment routines
        // are short-circuited, we still account for net cost here

        let penalize_for_out_of_bounds =
            exceptions.contains(UMAExceptionFlags::DEREF_BEYOND_HEAP_RANGE); // offset is not U32

        if penalize_for_out_of_bounds {
            cost_of_memory_growth = u32::MAX;
        }

        let (mut ergs_after_memory_growth, uf) = current_callstack_mut
            .ergs_remaining
            .overflowing_sub(cost_of_memory_growth);
        if uf {
            ergs_after_memory_growth = 0;
            // out of ergs common exception
            exceptions.set(UMAExceptionFlags::NOT_ENOUGH_ERGS_TO_GROW_MEMORY, true);
        }
        current_callstack_mut.ergs_remaining = ergs_after_memory_growth;
        drop(current_callstack_mut);

        // we will set panic if any exception was triggered
        let set_panic = exceptions.is_empty() == false;
        let legitimate_skip_memory_access = skip_memory_access_flags.is_empty() == false;
        // but we may skip memory accesses in practice in some other legitimate cases,
        // like deref fat pointer out of bounds. It's OR with `set_panic` because
        // it will still be not observable as we will not update any registers
        let skip_memory_access = legitimate_skip_memory_access || set_panic;

        // even if src_offset is beyond addressable memory, we are still fine with it as we will eventually NOT do the read.
        // When memory growth payments will be implemented we will be able to remove restriction of 2^24 addressable memory
        let word_0 = src_offset / 32;
        let word_1 = word_0 + 1;
        let unalignment = src_offset % 32;
        let word_0_lowest_bytes = 32 - unalignment;
        let word_1_highest_bytes = unalignment;
        debug_assert!(word_1_highest_bytes != 32);
        let is_unaligned = unalignment != 0;

        let word_0_location = MemoryLocation {
            memory_type,
            page: MemoryPage(fat_ptr.memory_page),
            index: MemoryIndex(word_0),
        };
        let word_1_location = MemoryLocation {
            memory_type,
            page: MemoryPage(fat_ptr.memory_page),
            index: MemoryIndex(word_1),
        };

        let timestamp_to_read = vm_state.timestamp_for_code_or_src_read();
        let timestamp_to_write = vm_state.timestamp_for_dst_write();

        // NOTE: endianess
        // we use naturally LE U256 base type, but in VM it's BE
        // so when we do unaligned read we need LOWEST bits of first word
        // and HIGHEST bits for second word

        // N.B. Reads are NOT pending
        let key_0 = MemoryKey {
            location: word_0_location,
            timestamp: timestamp_to_read,
        };

        let word_0_read_value = if skip_memory_access == false {
            let word_0_query = vm_state.read_memory(
                vm_state.local_state.monotonic_cycle_counter,
                key_0,
                /* is_pended */ false,
            );
            vm_state.witness_tracer.add_sponge_marker(
                vm_state.local_state.monotonic_cycle_counter,
                SpongeExecutionMarker::MemoryQuery,
                1..2,
                /* is_pended */ false,
            );

            let word_0_read_value = word_0_query.value;

            word_0_read_value
        } else {
            U256::zero()
        };

        let word_1_read_value = if is_unaligned && skip_memory_access == false {
            let key_1 = MemoryKey {
                location: word_1_location,
                timestamp: timestamp_to_read,
            };

            let word_1_query = vm_state.read_memory(
                vm_state.local_state.monotonic_cycle_counter,
                key_1,
                /* is_pended */ true,
            );

            vm_state.witness_tracer.add_sponge_marker(
                vm_state.local_state.monotonic_cycle_counter,
                SpongeExecutionMarker::MemoryQuery,
                3..4,
                /* is_pended */ true,
            );

            word_1_query.value
        } else {
            U256::zero()
        };

        match inner_variant {
            a @ UMAOpcode::HeapRead
            | a @ UMAOpcode::AuxHeapRead
            | a @ UMAOpcode::FatPointerRead => {
                // if we do "skip op", then we just write formal 0 into destination,
                // but if "increment" failed, then we skip updates all together

                // read always fits into single VM cycle
                // we want lowest bits of the word0 (if unalignment is 0 then we indeed want it in full)
                let mut result = word_0_read_value << (unalignment * 8);
                // we want highest bits of the word1. If e.g unalignment is X, then we have already
                // observed `32 - unalignment` of bytes from previous word, so we want only
                // `unalignment` bytes of the word1
                result = result | (word_1_read_value >> ((32 - unalignment) * 8));

                if a == UMAOpcode::FatPointerRead {
                    let (mut bytes_beyond_the_bound, uf) =
                        incremented_offset.overflowing_sub(fat_ptr.length);
                    if uf || skip_memory_access {
                        // we either failed some validation above, so we don't care about the result,
                        // or the tail is in bounds too. If `incremented_offset` == `fat_ptr.length` there is no underflow,
                        // but the difference is 0 anyway
                        bytes_beyond_the_bound = 0;
                    }

                    bytes_beyond_the_bound = bytes_beyond_the_bound % 32;

                    // cleanup
                    result >>= bytes_beyond_the_bound * 8;
                    result <<= bytes_beyond_the_bound * 8;
                }

                let result = PrimitiveValue {
                    value: result,
                    is_pointer: false,
                };

                if set_panic == false {
                    vm_state.perform_dst0_update(
                        vm_state.local_state.monotonic_cycle_counter,
                        result,
                        dst0_mem_location,
                        &self,
                    );

                    if increment_offset {
                        let mut updated_value = src0_value;
                        updated_value.0[0] = (updated_value.0[0] & U64_TOP_32_BITS_MASK)
                            + (incremented_offset as u64);
                        let reg_value = PrimitiveValue {
                            value: updated_value,
                            is_pointer: src0_is_ptr,
                        };
                        vm_state.perform_dst1_update(reg_value, self.dst1_reg_idx);
                    }
                } else {
                    vm_state.set_shorthand_panic();
                }
            }
            UMAOpcode::HeapWrite | UMAOpcode::AuxHeapWrite => {
                // we need to keep highest bytes of old word and place highest bytes of src1 into lowest
                // cleanup lowest bytes
                let mut new_word_0_value =
                    (word_0_read_value >> (word_0_lowest_bytes * 8)) << (word_0_lowest_bytes * 8);
                // add highest bytes into lowest for overwriting
                new_word_0_value = new_word_0_value | (src1 >> (unalignment * 8));
                // we need low bytes of old word and place low bytes of src1 into highest
                // cleanup highest bytes
                let mut new_word_1_value =
                    (word_1_read_value << (word_1_highest_bytes * 8)) >> (word_1_highest_bytes * 8);
                // add lowest bytes into highest
                new_word_1_value = new_word_1_value | (src1 << ((32 - word_1_highest_bytes) * 8));

                let key_0 = MemoryKey {
                    location: word_0_location,
                    timestamp: timestamp_to_write,
                };

                let new_word_0_value = PrimitiveValue {
                    value: new_word_0_value,
                    is_pointer: false,
                };

                if skip_memory_access == false {
                    // just write word 0
                    let _word_0_write_query = vm_state.write_memory(
                        vm_state.local_state.monotonic_cycle_counter,
                        key_0,
                        new_word_0_value,
                        /* is_pended */ false,
                    );
                }

                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::MemoryQuery,
                    2..3,
                    /* is_pended */ false,
                );

                // may be write word 1
                if is_unaligned && skip_memory_access == false {
                    let key_1 = MemoryKey {
                        location: word_1_location,
                        timestamp: timestamp_to_write,
                    };

                    // always not a pointer
                    let new_word_1_value = PrimitiveValue {
                        value: new_word_1_value,
                        is_pointer: false,
                    };

                    let _word_1_write_query = vm_state.write_memory(
                        vm_state.local_state.monotonic_cycle_counter,
                        key_1,
                        new_word_1_value,
                        /* is_pended */ true,
                    );

                    vm_state.witness_tracer.add_sponge_marker(
                        vm_state.local_state.monotonic_cycle_counter,
                        SpongeExecutionMarker::MemoryQuery,
                        4..5,
                        /* is_pended */ true,
                    );

                    vm_state.local_state.pending_port.pending_type = Some(PendingType::UMAWrite);
                }

                if set_panic == false {
                    if increment_offset {
                        let mut updated_value = src0_value;
                        updated_value.0[0] = (updated_value.0[0] & U64_TOP_32_BITS_MASK)
                            + (incremented_offset as u64);
                        let result = PrimitiveValue {
                            value: updated_value,
                            is_pointer: false,
                        };
                        debug_assert_eq!(src0_is_ptr, false);

                        vm_state.perform_dst0_update(
                            vm_state.local_state.monotonic_cycle_counter,
                            result,
                            dst0_mem_location,
                            &self,
                        );
                    }
                } else {
                    vm_state.set_shorthand_panic();
                }
            }
        };
    }
}
