use super::*;

use zkevm_opcode_defs::definitions::far_call::*;
use zkevm_opcode_defs::system_params::DEPLOYER_SYSTEM_CONTRACT_ADDRESS;
use zkevm_opcode_defs::system_params::STORAGE_AUX_BYTE;
use zkevm_opcode_defs::FatPointerValidationException;
use zkevm_opcode_defs::{INITIAL_SP_ON_FAR_CALL, UNMAPPED_PAGE};

use zkevm_opcode_defs::bitflags::bitflags;

pub const FORCED_ERGS_FOR_MSG_VALUE_SIMULATOR: bool = false;

bitflags! {
    pub struct FarCallExceptionFlags: u64 {
        const INPUT_IS_NOT_POINTER_WHEN_EXPECTED = 1u64 << 0;
        const INVALID_CODE_HASH_FORMAT = 1u64 << 1;
        const NOT_ENOUGH_ERGS_TO_DECOMMIT = 1u64 << 2;
        const NOT_ENOUGH_ERGS_TO_GROW_MEMORY = 1u64 << 3;
        const MALFORMED_ABI_QUASI_POINTER = 1u64 << 4;
        const CALL_IN_NOW_CONSTRUCTED_SYSTEM_CONTRACT = 1u64 << 5;
        const NOTE_ENOUGH_ERGS_FOR_EXTRA_FAR_CALL_COSTS = 1u64 << 6;
    }
}

use zkevm_opcode_defs::{FarCallABI, FarCallForwardPageType, FarCallOpcode, FatPointer, Opcode};

// Internally FarCall uses all 7 sponges:
// - 1 for decommittment
// - 3 for storage read
// - 3 for callstack manipulation

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn far_call_opcode_apply<
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
            new_pc,
            is_kernel_mode,
            ..
        } = prestate;
        let inner_variant = match self.variant.opcode {
            Opcode::FarCall(inner) => inner,
            _ => unreachable!(),
        };

        let PrimitiveValue {
            value: abi_src,
            is_pointer: abi_src_is_ptr,
        } = src0;
        let PrimitiveValue {
            value: call_destination_value,
            is_pointer: _,
        } = src1;

        // any call resets flags
        vm_state.reset_flags();

        let is_static_call = self.variant.flags[FAR_CALL_STATIC_FLAG_IDX];
        let is_call_shard = self.variant.flags[FAR_CALL_SHARD_FLAG_IDX];

        let exception_handler_location = self.imm_0;
        // binary interface of parameters passing

        let called_address = u256_to_address_unchecked(&call_destination_value);
        let called_address_as_u256 = call_destination_value & *U256_TO_ADDRESS_MASK;
        let dst_is_kernel = CallStackEntry::<N, E>::address_is_kernel(&called_address);

        // ergs, shard_id and calldata
        let mut far_call_abi = FarCallABI::from_u256(abi_src);

        // we ignore extra features if not in kernel
        far_call_abi.constructor_call = far_call_abi.constructor_call & is_kernel_mode;
        far_call_abi.to_system = far_call_abi.to_system & dst_is_kernel;

        let current_stack = vm_state.local_state.callstack.get_current_stack();

        // read for case of delegatecall
        let current_address = current_stack.this_address;
        let current_msg_sender = current_stack.msg_sender;
        let current_base_page = current_stack.base_memory_page;
        let caller_shard_id = current_stack.this_shard_id;
        let remaining_ergs = current_stack.ergs_remaining;
        let current_context_u128 = current_stack.context_u128_value;

        drop(current_stack);

        let timestamp_for_storage_read = vm_state.timestamp_for_first_decommit_or_precompile_read();
        let tx_number_in_block = vm_state.local_state.tx_number_in_block;

        // we read code from some shard ID
        let new_code_shard_id = if is_call_shard {
            far_call_abi.shard_id
        } else {
            caller_shard_id
        };

        // but for contract awareness purposes it may still see an old one (one of the caller)
        let new_this_shard_id = if inner_variant == FarCallOpcode::Delegate {
            caller_shard_id
        } else {
            new_code_shard_id
        };

        let new_base_memory_page = vm_state.new_base_memory_page_on_call();

        // NOTE: our far-call MUST take ergs to cover storage read, but we also have a contribution
        // that depends on the actual code length, so we work with it here
        let (mapped_code_page, ergs_after_code_read_and_exceptions_resolution, stipend_for_callee) = {
            let (code_hash, map_to_trivial) = if new_code_shard_id != 0
                && !vm_state.block_properties.zkporter_is_available
            {
                // we do NOT mask it into default AA here
                // and for now formally jump to the page containing zeroes

                (U256::zero(), true)
            } else {
                let partial_query = LogQuery {
                    timestamp: timestamp_for_storage_read,
                    tx_number_in_block,
                    aux_byte: STORAGE_AUX_BYTE,
                    shard_id: new_code_shard_id,
                    address: *DEPLOYER_SYSTEM_CONTRACT_ADDRESS,
                    key: called_address_as_u256,
                    read_value: U256::zero(),
                    written_value: U256::zero(),
                    rw_flag: false,
                    rollback: false,
                    is_service: false,
                };
                let query = vm_state
                    .access_storage(vm_state.local_state.monotonic_cycle_counter, partial_query);

                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::StorageLogReadOnly,
                    1..4,
                    true,
                );
                let code_hash_from_storage = query.read_value;

                // mask for default AA
                let mask_into_default_aa =
                    code_hash_from_storage.is_zero() && dst_is_kernel == false;
                let code_hash = if mask_into_default_aa {
                    vm_state.block_properties.default_aa_code_hash
                } else {
                    code_hash_from_storage
                };

                (code_hash, false)
            };

            let memory_page_candidate_for_code_decommittment = if map_to_trivial == true {
                MemoryPage(UNMAPPED_PAGE)
            } else {
                CallStackEntry::<N, E>::code_page_candidate_from_base(new_base_memory_page)
            };

            // now we handle potential exceptions

            use zkevm_opcode_defs::{ContractCodeSha256, VersionedHashGeneric};

            let mut buffer = [0u8; 32];
            code_hash.to_big_endian(&mut buffer);

            let mut exceptions = FarCallExceptionFlags::empty();

            // now let's check if code format "makes sense"
            let (code_hash, code_length_in_words) = if let Some(versioned_hash) =
                VersionedHashGeneric::<ContractCodeSha256>::try_create_from_raw(buffer)
            {
                // code is in proper format, let's check other markers

                let layout = versioned_hash.layout_ref();

                let code_marker = layout.extra_marker;

                let code_marker_is_at_rest = code_marker == ContractCodeSha256::CODE_AT_REST_MARKER;
                let code_marker_is_constructed_now =
                    code_marker == ContractCodeSha256::YET_CONSTRUCTED_MARKER;

                let code_marker_is_valid = code_marker_is_at_rest || code_marker_is_constructed_now;

                if code_marker_is_valid == false {
                    // code marker is generally invalid
                    exceptions.set(FarCallExceptionFlags::INVALID_CODE_HASH_FORMAT, true);

                    (U256::zero(), 0u32)
                } else {
                    // it's valid in general, so do the constructor masking work
                    let code_hash_at_storage = versioned_hash
                        .serialize_to_stored()
                        .map(|arr| U256::from_big_endian(&arr))
                        .expect("Failed to serialize a valid hash");

                    let can_call_at_rest = !far_call_abi.constructor_call && code_marker_is_at_rest;
                    let can_call_by_constructor =
                        far_call_abi.constructor_call && code_marker_is_constructed_now;

                    let can_call_code_without_masking = can_call_at_rest || can_call_by_constructor;
                    if can_call_code_without_masking == true {
                        // true values
                        (code_hash_at_storage, layout.code_length_in_words as u32)
                    } else {
                        // calling mode is unknown, so it's most likely a normal
                        // call to contract that is still created
                        if dst_is_kernel == false {
                            // still degrade to default AA
                            let mut buffer = [0u8; 32];
                            vm_state
                                .block_properties
                                .default_aa_code_hash
                                .to_big_endian(&mut buffer);
                            let versioned_hash =
                                VersionedHashGeneric::<ContractCodeSha256>::try_create_from_raw(
                                    buffer,
                                )
                                .expect("default AA code hash must be always valid");
                            let layout = versioned_hash.layout_ref();
                            let code_marker = layout.extra_marker;
                            assert!(
                                code_marker == ContractCodeSha256::CODE_AT_REST_MARKER,
                                "default AA marker is always in storage format"
                            );

                            (
                                vm_state.block_properties.default_aa_code_hash,
                                layout.code_length_in_words as u32,
                            )
                        } else {
                            // we should not decommit 0, so it's an exception
                            exceptions.set(
                                FarCallExceptionFlags::CALL_IN_NOW_CONSTRUCTED_SYSTEM_CONTRACT,
                                true,
                            );
                            (U256::zero(), 0u32)
                        }
                    }
                }
            } else {
                exceptions.set(FarCallExceptionFlags::INVALID_CODE_HASH_FORMAT, true);
                // we still return placeholders
                (U256::zero(), 0u32)
            };

            // we also use code hash as an exception hatch here
            if far_call_abi.forwarding_mode == FarCallForwardPageType::ForwardFatPointer {
                if abi_src_is_ptr == false {
                    exceptions.set(
                        FarCallExceptionFlags::INPUT_IS_NOT_POINTER_WHEN_EXPECTED,
                        true,
                    );
                }
            }

            // validate that fat pointer (one a future one) we formed is somewhat valid
            let validate_as_fresh =
                far_call_abi.forwarding_mode != FarCallForwardPageType::ForwardFatPointer;

            // NOTE: one can not properly address a range [2^32 - 32..2^32] here, but we never care in practice about this case
            // as one can not ever pay to grow memory to such extent

            let pointer_validation_exceptions = far_call_abi
                .memory_quasi_fat_pointer
                .validate(validate_as_fresh);

            if pointer_validation_exceptions.is_empty() == false {
                // pointer is malformed
                exceptions.set(FarCallExceptionFlags::MALFORMED_ABI_QUASI_POINTER, true);
            }
            // this captures the case of empty slice
            if far_call_abi.memory_quasi_fat_pointer.validate_as_slice() == false {
                exceptions.set(FarCallExceptionFlags::MALFORMED_ABI_QUASI_POINTER, true);
            }

            // these modifications we can do already as all pointer formal validity related things are done
            match far_call_abi.forwarding_mode {
                FarCallForwardPageType::ForwardFatPointer => {
                    // We can formally shrink the pointer
                    // If it was malformed then we masked and overflows can not happen
                    let new_start = far_call_abi
                        .memory_quasi_fat_pointer
                        .start
                        .wrapping_add(far_call_abi.memory_quasi_fat_pointer.offset);
                    let new_length = far_call_abi
                        .memory_quasi_fat_pointer
                        .length
                        .wrapping_sub(far_call_abi.memory_quasi_fat_pointer.offset);

                    far_call_abi.memory_quasi_fat_pointer.start = new_start;
                    far_call_abi.memory_quasi_fat_pointer.length = new_length;
                    far_call_abi.memory_quasi_fat_pointer.offset = 0;
                }
                FarCallForwardPageType::UseHeap => {
                    let owned_page =
                        CallStackEntry::<N, E>::heap_page_from_base(current_base_page).0;

                    far_call_abi.memory_quasi_fat_pointer.memory_page = owned_page;
                }
                FarCallForwardPageType::UseAuxHeap => {
                    let owned_page =
                        CallStackEntry::<N, E>::aux_heap_page_from_base(current_base_page).0;

                    far_call_abi.memory_quasi_fat_pointer.memory_page = owned_page;
                }
            };

            if exceptions.is_empty() == false {
                far_call_abi.memory_quasi_fat_pointer = FatPointer::empty();
                // even though we will not pay for memory resize,
                // we do not care
            }

            let current_stack_mut = vm_state.local_state.callstack.get_current_stack_mut();

            // potentially pay for memory growth
            let memory_growth_in_bytes = match far_call_abi.forwarding_mode {
                a @ FarCallForwardPageType::UseHeap | a @ FarCallForwardPageType::UseAuxHeap => {
                    // pointer is already validated, so we do not need to check that start + length do not overflow
                    let mut upper_bound = far_call_abi.memory_quasi_fat_pointer.start
                        + far_call_abi.memory_quasi_fat_pointer.length;

                    let penalize_out_of_bounds_growth = pointer_validation_exceptions
                        .contains(FatPointerValidationException::DEREF_BEYOND_HEAP_RANGE);
                    if penalize_out_of_bounds_growth {
                        upper_bound = u32::MAX;
                    }

                    let current_bound = if a == FarCallForwardPageType::UseHeap {
                        current_stack_mut.heap_bound
                    } else if a == FarCallForwardPageType::UseAuxHeap {
                        current_stack_mut.aux_heap_bound
                    } else {
                        unreachable!();
                    };
                    let (mut diff, uf) = upper_bound.overflowing_sub(current_bound);
                    if uf {
                        // heap bound is already beyond what we pass
                        diff = 0u32;
                    } else {
                        // save new upper bound in context.
                        // Note that we are ok so save even penalizing upper bound because we will burn
                        // all the ergs in this frame anyway, and no further resizes are possible
                        if a == FarCallForwardPageType::UseHeap {
                            current_stack_mut.heap_bound = upper_bound;
                        } else if a == FarCallForwardPageType::UseAuxHeap {
                            current_stack_mut.aux_heap_bound = upper_bound;
                        } else {
                            unreachable!();
                        }
                    }

                    diff
                }
                FarCallForwardPageType::ForwardFatPointer => 0u32,
            };

            drop(current_stack_mut);

            // MEMORY_GROWTH_ERGS_PER_BYTE is always 1
            let cost_of_memory_growth =
                memory_growth_in_bytes.wrapping_mul(zkevm_opcode_defs::MEMORY_GROWTH_ERGS_PER_BYTE);
            let remaining_ergs_after_growth = if remaining_ergs >= cost_of_memory_growth {
                remaining_ergs - cost_of_memory_growth
            } else {
                exceptions.set(FarCallExceptionFlags::NOT_ENOUGH_ERGS_TO_GROW_MEMORY, true);
                // we do not need to mask fat pointer, as we will jump to the page number 0,
                // that can not even read it

                0
            };

            let mut msg_value_stipend = if FORCED_ERGS_FOR_MSG_VALUE_SIMULATOR == false {
                0
            } else {
                if called_address_as_u256 == U256::from(zkevm_opcode_defs::ADDRESS_MSG_VALUE as u64)
                    && far_call_abi.to_system
                {
                    // use that doesn't know what's doing is trying to call "transfer"

                    let pubdata_related = vm_state.local_state.current_ergs_per_pubdata_byte.checked_mul(
                            zkevm_opcode_defs::system_params::MSG_VALUE_SIMULATOR_PUBDATA_BYTES_TO_PREPAY
                        ).expect("must fit into u32");
                    pubdata_related
                        .checked_add(
                            zkevm_opcode_defs::system_params::MSG_VALUE_SIMULATOR_ADDITIVE_COST,
                        )
                        .expect("must not overflow")
                } else {
                    0
                }
            };

            let remaining_ergs_of_caller_frame = if remaining_ergs_after_growth >= msg_value_stipend
            {
                remaining_ergs_after_growth - msg_value_stipend
            } else {
                exceptions.set(
                    FarCallExceptionFlags::NOTE_ENOUGH_ERGS_FOR_EXTRA_FAR_CALL_COSTS,
                    true,
                );
                // if tried to take and failed, but should not add it later on in this case
                msg_value_stipend = 0;

                0
            };

            // we mask instead of branching
            let cost_of_decommittment =
                zkevm_opcode_defs::ERGS_PER_CODE_WORD_DECOMMITTMENT * code_length_in_words;

            let mut remaining_ergs_after_decommittment =
                if remaining_ergs_of_caller_frame >= cost_of_decommittment {
                    remaining_ergs_of_caller_frame - cost_of_decommittment
                } else {
                    exceptions.set(FarCallExceptionFlags::NOT_ENOUGH_ERGS_TO_DECOMMIT, true);

                    remaining_ergs_of_caller_frame // do not burn, as it's irrelevant - we just will not perform a decommittment and call
                };

            let code_memory_page = if exceptions.is_empty() == false {
                vm_state.set_shorthand_panic();

                // we also do not return back cost of decommittment as it wasn't subtracted
                MemoryPage(UNMAPPED_PAGE)
            } else {
                let timestamp_for_decommit =
                    vm_state.timestamp_for_first_decommit_or_precompile_read();
                let processed_decommittment_query = vm_state.decommit(
                    vm_state.local_state.monotonic_cycle_counter,
                    code_hash,
                    memory_page_candidate_for_code_decommittment,
                    timestamp_for_decommit,
                );
                vm_state.witness_tracer.add_sponge_marker(
                    vm_state.local_state.monotonic_cycle_counter,
                    SpongeExecutionMarker::DecommittmentQuery,
                    4..5,
                    true,
                );

                if processed_decommittment_query.is_fresh == false {
                    // refund
                    remaining_ergs_after_decommittment += cost_of_decommittment;
                }

                processed_decommittment_query.memory_page
            };

            (
                code_memory_page,
                remaining_ergs_after_decommittment,
                msg_value_stipend,
            )
        };

        // we have taken everything that we want from caller and now can try to pass to callee

        // resolve passed ergs, by using a value afte decommittment cost is taken
        let remaining_ergs_to_pass = ergs_after_code_read_and_exceptions_resolution;
        let max_passable = (remaining_ergs_to_pass / 64) * 63; // so callee will always have some
        let leftover = remaining_ergs_to_pass - max_passable;
        // for exception handling
        let (passed_ergs, remaining_ergs_for_this_context) = {
            let (remaining_from_max_passable, uf) =
                max_passable.overflowing_sub(far_call_abi.ergs_passed);
            if uf {
                // pass max(passable, want to pass)
                (max_passable, leftover)
            } else {
                (
                    far_call_abi.ergs_passed,
                    leftover + remaining_from_max_passable,
                )
            }
        };

        // can not overflow
        let passed_ergs = passed_ergs.wrapping_add(stipend_for_callee);

        // update current ergs and PC
        vm_state
            .local_state
            .callstack
            .get_current_stack_mut()
            .ergs_remaining = remaining_ergs_for_this_context;
        vm_state.local_state.callstack.get_current_stack_mut().pc = new_pc;

        let current_stack = vm_state.local_state.callstack.get_current_stack();

        // compute if call is static either by modifier or
        let new_context_is_static = current_stack.is_static | is_static_call;

        // no matter if we did execute a query or not, we need to save context at worst
        vm_state.local_state.pending_port.pending_type = Some(PendingType::FarCall);

        vm_state.increment_memory_pages_on_call();

        // read address for mimic_call
        let implicit_reg =
            &vm_state.local_state.registers[CALL_IMPLICIT_PARAMETER_REG_IDX as usize];
        let address_from_implicit_reg = u256_to_address_unchecked(&implicit_reg.value);

        let (address_for_next, msg_sender_for_next) = match inner_variant {
            FarCallOpcode::Normal => {
                // we set that caller of next == this
                (called_address, current_address)
            }
            FarCallOpcode::Delegate => {
                // save current address for context purposes
                (current_address, current_msg_sender)
            }
            FarCallOpcode::Mimic => {
                // we pretent to be calling from some address
                (called_address, address_from_implicit_reg)
            }
        };
        let code_address_for_next = called_address;

        let context_u128_for_next = match inner_variant {
            FarCallOpcode::Normal | FarCallOpcode::Mimic => {
                // we set that caller of next == this
                vm_state.local_state.context_u128_register
            }
            FarCallOpcode::Delegate => {
                // save current address for context purposes
                current_context_u128
            }
        };

        let new_stack = CallStackEntry {
            this_address: address_for_next,
            msg_sender: msg_sender_for_next,
            code_address: code_address_for_next,
            base_memory_page: new_base_memory_page,
            code_page: mapped_code_page,
            sp: E::PcOrImm::from_u64_clipped(INITIAL_SP_ON_FAR_CALL),
            pc: E::PcOrImm::from_u64_clipped(0u64),
            exception_handler_location: exception_handler_location,
            ergs_remaining: passed_ergs,
            this_shard_id: new_this_shard_id,
            caller_shard_id,
            code_shard_id: new_code_shard_id,
            is_static: new_context_is_static,
            is_local_frame: false,
            context_u128_value: context_u128_for_next,
            heap_bound: zkevm_opcode_defs::system_params::NEW_FRAME_MEMORY_STIPEND,
            aux_heap_bound: zkevm_opcode_defs::system_params::NEW_FRAME_MEMORY_STIPEND,
        };

        // zero out the temporary register if it was not trivial
        vm_state.local_state.context_u128_register = 0;

        // perform some extra steps to ensure that our rollbacks are properly written and saved
        // both in storage and for witness
        vm_state.start_frame(vm_state.local_state.monotonic_cycle_counter, new_stack);

        vm_state.memory.start_global_frame(
            current_base_page,
            new_base_memory_page,
            far_call_abi.memory_quasi_fat_pointer,
            Timestamp(vm_state.local_state.timestamp),
        );

        vm_state.witness_tracer.add_sponge_marker(
            vm_state.local_state.monotonic_cycle_counter,
            SpongeExecutionMarker::CallstackPush,
            5..8,
            true,
        );
        // mark the jump to refresh the memory word
        vm_state.local_state.did_call_or_ret_recently = true;

        // write down calldata information

        let r1_value = PrimitiveValue {
            value: far_call_abi.memory_quasi_fat_pointer.to_u256(),
            is_pointer: true,
        };
        vm_state.local_state.registers[CALL_IMPLICIT_CALLDATA_FAT_PTR_REGISTER as usize] = r1_value;

        let mut r2_value = U256::zero();
        if far_call_abi.constructor_call {
            r2_value.0[0] |= 1u64;
        }
        if far_call_abi.to_system {
            r2_value.0[0] |= 1u64 << 1;
        }

        vm_state.local_state.registers[CALL_IMPLICIT_CONSTRUCTOR_MARKER_REGISTER as usize] =
            PrimitiveValue {
                value: r2_value,
                is_pointer: false,
            };

        if far_call_abi.to_system == false {
            for reg_idx in CALL_SYSTEM_ABI_REGISTERS {
                // if it's not a call to the system then we zero out those registers
                vm_state.local_state.registers[reg_idx as usize] = PrimitiveValue::empty();
            }
        } else {
            for reg_idx in CALL_SYSTEM_ABI_REGISTERS {
                // remove "ptr" markers
                vm_state.local_state.registers[reg_idx as usize].is_pointer = false;
            }
        }

        // ALL other registers are zeroed out!
        for reg_idx in CALL_RESERVED_RANGE {
            vm_state.local_state.registers[reg_idx as usize] = PrimitiveValue::empty();
        }
        vm_state.local_state.registers[CALL_IMPLICIT_PARAMETER_REG_IDX as usize] =
            PrimitiveValue::empty();
    }
}
