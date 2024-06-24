use super::*;

use crate::zkevm_opcode_defs::definitions::far_call::*;

use crate::zkevm_opcode_defs::INITIAL_SP_ON_FAR_CALL;
use zk_evm_abstractions::aux::*;
use zk_evm_abstractions::queries::LogQuery;

use crate::zkevm_opcode_defs::bitflags::bitflags;

pub const FORCED_ERGS_FOR_MSG_VALUE_SIMULATOR: bool = false;

bitflags! {
    pub struct FarCallExceptionFlags: u64 {
        const INPUT_IS_NOT_POINTER_WHEN_EXPECTED = 1u64 << 0;
        const INVALID_CODE_HASH_FORMAT = 1u64 << 1;
        const NOT_ENOUGH_ERGS_TO_DECOMMIT = 1u64 << 2;
        const NOT_ENOUGH_ERGS_TO_GROW_MEMORY = 1u64 << 3;
        const MALFORMED_ABI_QUASI_POINTER = 1u64 << 4;
        const CALL_IN_NOW_CONSTRUCTED_SYSTEM_CONTRACT = 1u64 << 5;
        const NOT_ENOUGH_ERGS_FOR_EXTRA_FAR_CALL_COSTS = 1u64 << 6;
        const CALL_TO_UNREACHABLE_ADDRESS = 1u64 << 7;
        const INPUT_IS_POINTER_WHEN_NOT_EXPECTED = 1u64 << 8;
    }
}

use crate::zkevm_opcode_defs::{FarCallABI, FarCallOpcode, Opcode};
use crate::zkevm_opcode_defs::system_params::{DEPLOYER_SYSTEM_CONTRACT_ADDRESS, STORAGE_AUX_BYTE};

impl<const N: usize, E: VmEncodingMode<N>> DecodedOpcode<N, E> {
    pub fn far_call_opcode_apply<
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
    ) -> anyhow::Result<()> {
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
        let dst_is_kernel = address_is_kernel(&called_address);

        // ergs, shard_id and calldata
        let mut far_call_abi = FarCallABI::from_u256(abi_src);

        // convert ergs
        far_call_abi.ergs_passed = if let Some(non_overflowing) =
            far_call_abi.ergs_passed.checked_mul(
                zkevm_opcode_defs::system_params::INTERNAL_ERGS_TO_VISIBLE_ERGS_CONVERSION_CONSTANT,
            ) {
            non_overflowing
        } else {
            u32::MAX
        };

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

        #[allow(dropping_references)]
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

        let call_to_evm_simulator;

        // NOTE: our far-call MUST take ergs to cover storage read, but we also have a contribution
        // that depends on the actual code length, so we work with it here
        let (
            mapped_code_page,
            ergs_after_code_read_and_exceptions_resolution,
            extra_ergs_from_caller_to_callee,
            callee_stipend,
        ) = {
            let (code_hash, call_to_unreachable) = if new_code_shard_id != 0
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
                let (query, _) = vm_state
                    .access_storage(vm_state.local_state.monotonic_cycle_counter, partial_query);

                let code_hash_from_storage = query.read_value;

                (code_hash_from_storage, false)
            };

            let mut exceptions = FarCallExceptionFlags::empty();
            if call_to_unreachable == true {
                exceptions.set(FarCallExceptionFlags::CALL_TO_UNREACHABLE_ADDRESS, true);
            }

            // now we handle potential exceptions

            use crate::zkevm_opcode_defs::*;

            let bytecode_hash_is_empty = code_hash == U256::zero();

            let mut buffer = [0u8; 32];
            code_hash.to_big_endian(&mut buffer);

            let is_valid_as_bytecode_hash = ContractCodeSha256Format::is_valid(&buffer);
            let is_valid_as_blob_hash = BlobSha256Format::is_valid(&buffer);

            let mut mask_to_default_aa = false;

            let can_call_code_without_masking = if is_valid_as_bytecode_hash {
                let is_code_at_rest = ContractCodeSha256Format::is_code_at_rest_if_valid(&buffer);
                let is_constructed = ContractCodeSha256Format::is_in_construction_if_valid(&buffer);

                let can_call_at_rest = !far_call_abi.constructor_call && is_code_at_rest;
                let can_call_by_constructor = far_call_abi.constructor_call && is_constructed;

                let can_call_code_without_masking = can_call_at_rest || can_call_by_constructor;
                if can_call_code_without_masking == true {
                    true
                } else {
                    // calling mode is unknown, so it's most likely a normal
                    // call to contract that is still created
                    if dst_is_kernel == false {
                        mask_to_default_aa = true;
                    } else {
                        exceptions.set(
                            FarCallExceptionFlags::CALL_IN_NOW_CONSTRUCTED_SYSTEM_CONTRACT,
                            true,
                        );
                    }

                    false
                }
            } else {
                false
            };

            let can_call_evm_simulator = if is_valid_as_blob_hash {
                let is_code_at_rest = BlobSha256Format::is_code_at_rest_if_valid(&buffer);
                let is_constructed = BlobSha256Format::is_in_construction_if_valid(&buffer);

                let can_call_at_rest = !far_call_abi.constructor_call && is_code_at_rest;
                let can_call_by_constructor = far_call_abi.constructor_call && is_constructed;

                let can_call_code_without_masking = can_call_at_rest || can_call_by_constructor;
                if can_call_code_without_masking == true {
                    true
                } else {
                    // calling mode is unknown, so it's most likely a normal
                    // call to contract that is still created
                    if dst_is_kernel == false {
                        mask_to_default_aa = true;
                    } else {
                        exceptions.set(FarCallExceptionFlags::INVALID_CODE_HASH_FORMAT, true);
                    }

                    false
                }
            } else {
                false
            };

            call_to_evm_simulator = can_call_evm_simulator;

            if bytecode_hash_is_empty {
                if dst_is_kernel == false {
                    mask_to_default_aa = true;
                } else {
                    exceptions.set(FarCallExceptionFlags::INVALID_CODE_HASH_FORMAT, true);
                }
            }

            assert!(
                (mask_to_default_aa as u64)
                    + (can_call_evm_simulator as u64)
                    + (can_call_code_without_masking as u64)
                    < 2
            );

            let unknown_hash = mask_to_default_aa == false
                && can_call_evm_simulator == false
                && can_call_code_without_masking == false;
            if unknown_hash {
                exceptions.set(FarCallExceptionFlags::INVALID_CODE_HASH_FORMAT, true);
            }

            // now let's check if code format "makes sense"
            let (header, normalized_preimage, code_length_in_words) = {
                if can_call_code_without_masking {
                    // masking is not needed
                } else if can_call_evm_simulator {
                    // overwrite buffer with evm simulator bytecode hash
                    vm_state
                        .block_properties
                        .evm_simulator_code_hash
                        .to_big_endian(&mut buffer);
                } else if mask_to_default_aa {
                    // overwrite buffer with default AA code hash
                    vm_state
                        .block_properties
                        .default_aa_code_hash
                        .to_big_endian(&mut buffer);
                } else {
                    assert!(exceptions.is_empty() == false);
                }

                if exceptions.is_empty() {
                    assert!(
                        can_call_code_without_masking
                            || can_call_evm_simulator
                            || mask_to_default_aa
                    );
                    // true values
                    let length_in_words =
                        ContractCodeSha256Format::code_length_in_bytes32_words(&buffer);
                    let (header, normalized_preimage) =
                        ContractCodeSha256Format::normalize_for_decommitment(&buffer);

                    (header, normalized_preimage, length_in_words)
                } else {
                    (
                        VersionedHashHeader::default(),
                        VersionedHashNormalizedPreimage::default(),
                        0u16,
                    )
                }
            };

            // we also use code hash as an exception hatch here
            if far_call_abi.forwarding_mode == FarCallForwardPageType::ForwardFatPointer {
                if abi_src_is_ptr == false {
                    exceptions.set(
                        FarCallExceptionFlags::INPUT_IS_NOT_POINTER_WHEN_EXPECTED,
                        true,
                    );
                }
            } else {
                if abi_src_is_ptr {
                    // there is no reasonable case to try to re-interpret pointer
                    // as integer here
                    exceptions.set(
                        FarCallExceptionFlags::INPUT_IS_POINTER_WHEN_NOT_EXPECTED,
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
                    let owned_page = heap_page_from_base(current_base_page).0;

                    far_call_abi.memory_quasi_fat_pointer.memory_page = owned_page;
                }
                FarCallForwardPageType::UseAuxHeap => {
                    let owned_page = aux_heap_page_from_base(current_base_page).0;

                    far_call_abi.memory_quasi_fat_pointer.memory_page = owned_page;
                }
            };

            // we mask out fat pointer based on:
            // - invalid code hash format
            // - call yet constructed kernel
            // - not fat pointer when expected
            // - invalid slice structure in ABI
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

            #[allow(dropping_references)]
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

            let (mut callee_stipend, mut extra_ergs_from_caller_to_callee) =
                get_stipend_and_extra_cost(&called_address, far_call_abi.to_system);

            let remaining_ergs_of_caller_frame =
                if remaining_ergs_after_growth >= extra_ergs_from_caller_to_callee {
                    remaining_ergs_after_growth - extra_ergs_from_caller_to_callee
                } else {
                    exceptions.set(
                        FarCallExceptionFlags::NOT_ENOUGH_ERGS_FOR_EXTRA_FAR_CALL_COSTS,
                        true,
                    );
                    // if tried to take and failed, but should not add it later on in this case
                    extra_ergs_from_caller_to_callee = 0;

                    0
                };

            if can_call_evm_simulator {
                assert_eq!(callee_stipend, 0);
                callee_stipend = zkevm_opcode_defs::system_params::EVM_SIMULATOR_STIPEND;
            }

            let (code_memory_page, remaining_ergs_after_decommittment) = if exceptions.is_empty()
                == false
            {
                vm_state.set_shorthand_panic();

                // we also do not return back cost of decommittment as it was subtracted
                (MemoryPage(UNMAPPED_PAGE), remaining_ergs_of_caller_frame)
            } else {
                assert!(normalized_preimage.0 != [0u8; 28], "original buffer {:?} lead to zero normalized preimage, but didn't trigger exception", buffer);

                // we mask instead of branching
                let default_cost_of_decommittment =
                    zkevm_opcode_defs::ERGS_PER_CODE_WORD_DECOMMITTMENT
                        * (code_length_in_words as u32);
                // prepare query
                let timestamp_for_decommit =
                    vm_state.timestamp_for_first_decommit_or_precompile_read();
                let memory_page_candidate_for_code_decommittment =
                    code_page_candidate_from_base(new_base_memory_page);
                let prepared_decommmit_query = vm_state.prepare_to_decommit(
                    vm_state.local_state.monotonic_cycle_counter,
                    header,
                    normalized_preimage,
                    memory_page_candidate_for_code_decommittment,
                    timestamp_for_decommit,
                )?;
                let cost_of_decommittment = if prepared_decommmit_query.is_fresh {
                    default_cost_of_decommittment
                } else {
                    0
                };

                let remaining_ergs_after_decommittment =
                    if remaining_ergs_of_caller_frame >= cost_of_decommittment {
                        remaining_ergs_of_caller_frame - cost_of_decommittment
                    } else {
                        exceptions.set(FarCallExceptionFlags::NOT_ENOUGH_ERGS_TO_DECOMMIT, true);
                        remaining_ergs_of_caller_frame // do not burn, as it's irrelevant - we just will not perform a decommittment and call
                    };

                let memory_page = if exceptions.is_empty() {
                    vm_state.execute_decommit(
                        vm_state.local_state.monotonic_cycle_counter,
                        prepared_decommmit_query,
                    )?;

                    prepared_decommmit_query.memory_page
                } else {
                    vm_state.set_shorthand_panic();
                    MemoryPage(UNMAPPED_PAGE)
                };

                (memory_page, remaining_ergs_after_decommittment)
            };

            (
                code_memory_page,
                remaining_ergs_after_decommittment,
                extra_ergs_from_caller_to_callee,
                callee_stipend,
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
        let passed_ergs = passed_ergs.wrapping_add(extra_ergs_from_caller_to_callee);
        // this one is checked
        let passed_ergs = passed_ergs
            .checked_add(callee_stipend)
            .expect("stipends must never overflow");

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

        let is_static_to_set = if call_to_evm_simulator {
            false
        } else {
            new_context_is_static
        };

        // NOTE: this one decides based on what next frame will be, and not just on the formal
        // call target
        let memory_stipend = if address_is_kernel(&address_for_next) {
            zkevm_opcode_defs::system_params::NEW_KERNEL_FRAME_MEMORY_STIPEND
        } else {
            zkevm_opcode_defs::system_params::NEW_FRAME_MEMORY_STIPEND
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
            is_static: is_static_to_set,
            is_local_frame: false,
            context_u128_value: context_u128_for_next,
            heap_bound: memory_stipend,
            aux_heap_bound: memory_stipend,
            total_pubdata_spent: PubdataCost(0i32),
            stipend: callee_stipend,
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
        if call_to_evm_simulator {
            r2_value.0[0] |= (new_context_is_static as u64) << 2;
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

        Ok(())
    }
}
