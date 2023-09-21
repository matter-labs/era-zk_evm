use super::*;

use crate::opcodes::parsing::*;
use tracing::*;
use zk_evm_abstractions::{aux::*, vm::MemoryType};
use zkevm_opcode_defs::{ImmMemHandlerFlags, NopOpcode, Operand, RegOrImmFlags};

pub struct PreState<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub src0: PrimitiveValue,
    pub src1: PrimitiveValue,
    pub dst0_mem_location: Option<MemoryLocation>,
    pub new_pc: E::PcOrImm,
    pub is_kernel_mode: bool,
}

pub const OPCODES_PER_WORD_LOG_2: usize = 2;
pub const OPCODES_PER_WORD: usize = 1 << OPCODES_PER_WORD_LOG_2;

pub fn read_and_decode<
    const N: usize,
    E: VmEncodingMode<N>,
    M: zk_evm_abstractions::vm::Memory,
    WT: crate::witness_trace::VmWitnessTracer<N, E>,
    DT: crate::tracing::Tracer<N, E, SupportedMemory = M>,
>(
    local_state: &VmLocalState<N, E>,
    memory: &M,
    witness_tracer: &mut WT,
    tracer: &mut DT,
) -> (DecodedOpcode<N, E>, DelayedLocalStateChanges<N, E>, bool) {
    let mut delayed_changes = DelayedLocalStateChanges::default();

    // witness tracing
    witness_tracer.start_new_execution_cycle(local_state);

    // global generic tracing
    if DT::CALL_BEFORE_DECODING {
        let local_state = VmLocalStateData {
            vm_local_state: &local_state,
        };

        tracer.before_decoding(local_state, memory);
    }

    let execution_has_ended = local_state.execution_has_ended();
    let pending_exception = local_state.pending_exception;

    let code_page = local_state.callstack.get_current_stack().code_page;
    delayed_changes.new_previous_code_memory_page = Some(code_page);

    let pc = local_state.callstack.get_current_stack().pc;
    let previous_super_pc = local_state.previous_super_pc;
    let code_pages_are_different = local_state.callstack.get_current_stack().code_page
        != local_state.previous_code_memory_page;
    let (super_pc, sub_pc) = E::split_pc(pc);

    // if we do not skip cycle then we read memory for a new opcode
    let opcode_encoding = if execution_has_ended == false && pending_exception == false {
        let raw_opcode_u64 = match (code_pages_are_different, previous_super_pc == super_pc) {
            (true, _) | (false, false) => {
                // we need to read the code word and select a proper subword
                let code_page = local_state.callstack.get_current_stack().code_page;
                let location = MemoryLocation {
                    memory_type: MemoryType::Code,
                    page: code_page,
                    index: MemoryIndex(super_pc.as_u64() as u32),
                };
                let key = MemoryKey {
                    timestamp: local_state.timestamp_for_code_or_src_read(),
                    location,
                };

                delayed_changes.new_previous_code_memory_page = Some(code_page);

                // code read is never pending
                let code_query = read_code(
                    memory,
                    witness_tracer,
                    local_state.monotonic_cycle_counter,
                    key,
                );
                let u256_word = code_query.value;
                delayed_changes.new_previous_code_word = Some(u256_word);
                delayed_changes.new_previous_super_pc = Some(super_pc);

                // our memory is a set of words in storage, and those are only re-interpreted
                // as bytes in UMA. But natural storage for code is still bytes.

                // to ensure consistency with the future if we allow deployment of raw bytecode
                // then for our BE machine we should consider that "first" bytes, that will be
                // our integer's "highest" bytes, so to follow bytearray-like enumeration we
                // have to use inverse order here
                let u256_word = u256_word;
                E::integer_representaiton_from_u256(u256_word, sub_pc)
            }
            (false, true) => {
                // use a saved one
                let u256_word = local_state.previous_code_word;
                E::integer_representaiton_from_u256(u256_word, sub_pc)
            }
        };

        raw_opcode_u64
    } else if pending_exception {
        // there are no cases that set pending exception and
        // simultaneously finish the execution
        assert!(execution_has_ended == false);

        // so we can just remove the marker as soon as we are no longer pending
        delayed_changes.new_pending_exception = Some(false);

        // anyway update super PC
        delayed_changes.new_previous_super_pc = Some(super_pc);

        E::exception_revert_encoding()
    } else {
        // we are skipping cycle for some reason, so we do nothing,
        // and do not touch any flags

        // This only happens at the end of execution

        if local_state.execution_has_ended() {
            assert!(pending_exception == false);
        }

        E::nop_encoding()
    };

    let skip_cycle = execution_has_ended;

    // now we have some candidate for opcode. If it's noop we are not expecting to have any problems,
    // so check for other meaningful exceptions

    let mut error_flags = ErrorFlags::empty();
    let (partially_decoded_inner, opcode_raw_variant_idx) =
        E::parse_preliminary_variant_and_absolute_number(opcode_encoding);

    let mut partially_decoded = DecodedOpcode {
        inner: partially_decoded_inner,
    };

    if partially_decoded.variant.is_explicit_panic() {
        error_flags.set(ErrorFlags::INVALID_OPCODE, true);
    }

    // now try to get ergs price (unmodified for hard cases), that will also allow us to catch invalid opcode
    let mut ergs_cost =
        zkevm_opcode_defs::OPCODES_PRICES[opcode_raw_variant_idx.into_usize()] as u32;
    if skip_cycle {
        // we have already paid for it
        ergs_cost = 0;
    }
    let (mut ergs_remaining, not_enough_power) = local_state
        .callstack
        .get_current_stack()
        .ergs_remaining
        .overflowing_sub(ergs_cost);
    if not_enough_power {
        ergs_remaining = 0;
        error_flags.set(ErrorFlags::NOT_ENOUGH_ERGS, true);
    }

    delayed_changes.new_ergs_remaining = Some(ergs_remaining);

    // we have only 3 exceptions that we check before execution
    // - opcode requires kernel mode, but we are not in one
    // - opcode requires non-static context, but we are in one
    // - callstack is full because we have just called some other context

    let is_kernel = local_state.callstack.get_current_stack().is_kernel_mode();
    let is_static_execution = local_state.callstack.get_current_stack().is_static;
    let callstack_is_full = local_state.callstack_is_full();

    if partially_decoded.variant.requires_kernel_mode() && !is_kernel {
        error_flags.set(ErrorFlags::PRIVILAGED_ACCESS_NOT_FROM_KERNEL, true);
    }

    if !partially_decoded.variant.can_be_used_in_static_context() && is_static_execution {
        error_flags.set(ErrorFlags::WRITE_IN_STATIC_CONTEXT, true);
    }

    if callstack_is_full {
        error_flags.set(ErrorFlags::CALLSTACK_IS_FULL, true);
    }

    // now we have enough information to decide whether to mask the opcode into "panic" or not
    let mask_into_panic_due_to_exception = error_flags.is_empty() == false;
    if mask_into_panic_due_to_exception {
        partially_decoded.mask_into_panic();
    };

    // resolve condition once
    let resolved_condition = {
        use zkevm_opcode_defs::Condition;
        match partially_decoded.condition {
            Condition::Always => true,
            Condition::Gt => local_state.flags.greater_than_flag,
            Condition::Lt => local_state.flags.overflow_or_less_than_flag,
            Condition::Eq => local_state.flags.equality_flag,
            Condition::Ge => local_state.flags.greater_than_flag | local_state.flags.equality_flag,
            Condition::Le => {
                local_state.flags.overflow_or_less_than_flag | local_state.flags.equality_flag
            }
            Condition::Ne => local_state.flags.equality_flag == false,
            Condition::GtOrLt => {
                local_state.flags.greater_than_flag | local_state.flags.overflow_or_less_than_flag
            }
        }
    };

    // mask into NOP if condition doesn't match. Note that encoding for PANIC has "always" condition
    if resolved_condition == false {
        // we self-protect against double-masking
        if mask_into_panic_due_to_exception == false {
            partially_decoded.mask_into_nop();
        }
    }

    if DT::CALL_AFTER_DECODING {
        let local_state = VmLocalStateData {
            vm_local_state: local_state,
        };

        let data = AfterDecodingData {
            raw_opcode_unmasked: opcode_encoding,
            opcode_masked: partially_decoded,
            error_flags_accumulated: error_flags,
            resolved_condition,
            did_skip_cycle: false,
        };

        tracer.after_decoding(local_state, data, memory);
    }

    (partially_decoded, delayed_changes, skip_cycle)
}

impl<
        'a,
        S: zk_evm_abstractions::vm::Storage,
        M: zk_evm_abstractions::vm::Memory,
        EV: zk_evm_abstractions::vm::EventSink,
        PP: zk_evm_abstractions::vm::PrecompilesProcessor,
        DP: zk_evm_abstractions::vm::DecommittmentProcessor,
        WT: crate::witness_trace::VmWitnessTracer<N, E>,
        const N: usize,
        E: VmEncodingMode<N>,
    > VmState<S, M, EV, PP, DP, WT, N, E>
{
    #[inline]
    pub fn super_and_sub_pc_from_pc(pc: u16) -> (u16, u8) {
        (
            (pc >> OPCODES_PER_WORD_LOG_2),
            (pc & (OPCODES_PER_WORD as u16 - 1)) as u8,
        )
    }

    pub fn cycle<DT: tracing::Tracer<N, E, SupportedMemory = M>>(
        &mut self,
        tracer: &mut DT,
    ) -> anyhow::Result<()> {
        let (after_masking_decoded, delayed_changes, skip_cycle) = read_and_decode(
            &self.local_state,
            &mut self.memory,
            &mut self.witness_tracer,
            tracer,
        );
        delayed_changes.apply(&mut self.local_state);

        // now we are exception-less!

        // Now we can try to access the memory, but should keep in mind that if we did encounter an error here
        // then in addition to (later on) masking the opcode to be panicing Ret we also have to avoid
        // memory reads here and later on also avoid writes (this will happen automatically inside of opcode processing itself)

        let mut mem_processor = MemOpsProcessor::<N, E> {
            sp: self.local_state.callstack.get_current_stack().sp,
        };
        let (src0_reg_value, mut src0_mem_location) = mem_processor
            .compute_addresses_and_select_operands(
                self,
                after_masking_decoded.src0_reg_idx,
                after_masking_decoded.imm_0,
                after_masking_decoded.variant.src0_operand_type,
                false,
            );

        let (_, dst0_mem_location) = mem_processor.compute_addresses_and_select_operands(
            self,
            after_masking_decoded.dst0_reg_idx,
            after_masking_decoded.imm_1,
            after_masking_decoded.variant.dst0_operand_type,
            true,
        );

        // here we can either execute NOP r0, r0, r0, r0 after masking, or RET (that doesn't manipulate SP),
        // so we can still set ergs and SP and be happy
        self.local_state.callstack.get_current_stack_mut().sp = mem_processor.sp;
        if after_masking_decoded.variant.opcode == zkevm_opcode_defs::Opcode::Nop(NopOpcode) {
            // special rule for NOP - we do NOT read
            src0_mem_location = None;
        }

        // so we do read here
        let src0_mem_value = if let Some(src0_mem_location) = src0_mem_location {
            let key = MemoryKey {
                timestamp: self.timestamp_for_code_or_src_read(),
                location: src0_mem_location,
            };
            // src read is never pending, but to keep consistent memory implementation we
            // need to branch here for a case of loading constants from code space
            let src0_query = if src0_mem_location.memory_type == MemoryType::Code {
                self.read_code(self.local_state.monotonic_cycle_counter, key)
            } else {
                self.read_memory(self.local_state.monotonic_cycle_counter, key)
            };
            let u256_word = src0_query.value;
            let is_pointer = src0_query.value_is_pointer;

            PrimitiveValue {
                value: u256_word,
                is_pointer,
            }
        } else {
            PrimitiveValue::empty()
        };

        let src0 = match after_masking_decoded.variant.src0_operand_type {
            Operand::RegOnly
            | Operand::Full(ImmMemHandlerFlags::UseRegOnly)
            | Operand::RegOrImm(RegOrImmFlags::UseRegOnly) => src0_reg_value,
            Operand::Full(ImmMemHandlerFlags::UseImm16Only)
            | Operand::RegOrImm(RegOrImmFlags::UseImm16Only) => PrimitiveValue {
                value: U256::from(after_masking_decoded.imm_0.as_u64()),
                is_pointer: false,
            },
            _ => src0_mem_value,
        };

        let src1 = self.select_register_value(after_masking_decoded.src1_reg_idx);

        let (src0, src1) = if after_masking_decoded.variant.swap_operands() {
            (src1, src0)
        } else {
            (src0, src1)
        };

        let mut new_pc = self.local_state.callstack.get_current_stack().pc;
        if !skip_cycle {
            new_pc = new_pc.wrapping_add(E::PcOrImm::from_u64_clipped(1u64));
        }

        if DT::CALL_BEFORE_EXECUTION {
            let local_state = VmLocalStateData {
                vm_local_state: &self.local_state,
            };

            let data = BeforeExecutionData {
                opcode: after_masking_decoded,
                src0_value: src0,
                src1_value: src1,
                src0_mem_location,
                new_pc,
            };

            tracer.before_execution(local_state, data, &mut self.memory);
        }

        let is_kernel_mode = self
            .local_state
            .callstack
            .get_current_stack()
            .is_kernel_mode();

        let prestate = PreState {
            src0,
            src1,
            dst0_mem_location,
            new_pc,
            is_kernel_mode,
        };

        after_masking_decoded.apply(self, prestate)?;

        if !skip_cycle {
            self.increment_timestamp_after_cycle();
        }
        self.local_state.monotonic_cycle_counter += 1;

        self.witness_tracer.end_execution_cycle(&self.local_state);

        if DT::CALL_AFTER_EXECUTION {
            let local_state = VmLocalStateData {
                vm_local_state: &self.local_state,
            };

            let data = AfterExecutionData {
                opcode: after_masking_decoded,
                dst0_mem_location,
            };

            tracer.after_execution(local_state, data, &mut self.memory);
        }

        Ok(())
    }
}
