#![allow(clippy::bool_assert_comparison)] // There are a lot of bool checks, direct comparison is more declarative.

mod assembly;

use crate::vm::VmExecutionContext;
use crate::vm_runner::{run_vm_multi_contracts, set_account_type, RawInMemoryStorage};
use crate::{run_vm, VmExecutionResult, VmInstance, VmLaunchOption, VmSnapshot};
use std::collections::HashMap;
use zkevm_assembly::*;
use zksync_types::AccountTreeId::Rollup;
use zksync_types::{
    utils::{address_to_h256, h256_to_u256},
    Address, BlockNumber, VmEvent, H160, H256, U256,
};
use zksync_types::{AccountTreeId, AccountType, StorageKey};

const NULL: RegisterOperand = RegisterOperand::Null;
const RG0: RegisterOperand = RegisterOperand::Register(0);
const RG1: RegisterOperand = RegisterOperand::Register(1);
const RG2: RegisterOperand = RegisterOperand::Register(2);
const RG3: RegisterOperand = RegisterOperand::Register(3);
const RG4: RegisterOperand = RegisterOperand::Register(4);
const RG5: RegisterOperand = RegisterOperand::Register(5);

const RF0: FullOperand = FullOperand::Register(RG0);
const RF1: FullOperand = FullOperand::Register(RG1);
const RF2: FullOperand = FullOperand::Register(RG2);

const OP_RETURN: Instruction =
    Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false });

#[test]
fn test_calldata_allocation() {
    let storage = &mut dummy_storage();
    let mut calldata_word_2_bytes = [0u8; 32];
    U256::from(42424242).to_little_endian(&mut calldata_word_2_bytes);
    let mut calldata = vec![0x0; 32];
    calldata.extend_from_slice(&calldata_word_2_bytes);
    let mut vm = VmInstance::new(
        storage,
        &calldata,
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();

    vm.dispatch_opcode(Instruction::Memory(MemoryInstruction {
        address: MemoryOperand {
            r#type: MemoryType::SharedParent,
            offset: 0,
            register: NULL,
        },
        operation: DataOperation::Read { destination: RG0 },
    }))
    .unwrap();

    vm.dispatch_opcode(Instruction::Memory(MemoryInstruction {
        address: MemoryOperand {
            r#type: MemoryType::SharedParent,
            offset: 1,
            register: NULL,
        },
        operation: DataOperation::Read { destination: RG1 },
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG0), U256::zero());
    assert_eq!(vm.read_reg(RG1), U256::from(42424242));
}

#[test]
fn test_add_execution() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::from(1));
    vm.write_reg(RG1, U256::from(2));

    vm.dispatch_opcode(Instruction::Add(AddInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG2,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), U256::from(3));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
}

#[test]
fn test_bitwise_xor() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::from(0b01011011));
    vm.write_reg(RG1, U256::from(0b10000001));

    vm.dispatch_opcode(Instruction::Bitwise(BitwiseInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG2,
        op_type: BitwiseOpType::Xor,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), U256::from(0b11011010));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
}

#[test]
fn test_bitwise_shift() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::from(3 + (17 << 8))); // only first 8 bytes must be considered
    vm.write_reg(RG1, U256::from(0b010111011011) + (U256::one() << 255));

    vm.dispatch_opcode(Instruction::Shift(ShiftInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG2,
        is_cyclic: false,
        is_right: false,
    }))
    .unwrap();

    vm.dispatch_opcode(Instruction::Shift(ShiftInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG3,
        is_cyclic: false,
        is_right: true,
    }))
    .unwrap();

    vm.dispatch_opcode(Instruction::Shift(ShiftInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG4,
        is_cyclic: true,
        is_right: false,
    }))
    .unwrap();

    vm.dispatch_opcode(Instruction::Shift(ShiftInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG5,
        is_cyclic: true,
        is_right: true,
    }))
    .unwrap();
    assert_eq!(vm.read_reg(RG2), U256::from(0b010111011011000));
    assert_eq!(
        vm.read_reg(RG3),
        U256::from(0b010111011) + (U256::one() << 252)
    );
    assert_eq!(vm.read_reg(RG4), U256::from(0b010111011011100));
    assert_eq!(
        vm.read_reg(RG5),
        U256::from(0b010111011) + (U256::from(0b111) << 252)
    );
}

#[test]
fn test_add_execution_overflow() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::max_value());
    vm.write_reg(RG1, U256::from(44));

    vm.dispatch_opcode(Instruction::Add(AddInstruction {
        source_1: RF0,
        source_2: RG1,
        destination: RG2,
    }))
    .unwrap();
    assert_eq!(vm.read_reg(RG2), U256::from(43));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, true);
}

#[test]
fn test_mul_execution() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::from(1000));
    vm.write_reg(RG1, U256::from(43));

    vm.dispatch_opcode(Instruction::Mul(MulInstruction {
        source_1: RF0,
        source_2: RG1,
        destination_1: RG2,
        destination_2: RG3,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), U256::from(43000));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, true);
    assert_eq!(vm.flags.greater_than_flag, false);
}

#[test]
fn test_mul_execution_overflow() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, (U256::max_value() - 1) / 2);
    vm.write_reg(RG1, U256::from(3));

    vm.dispatch_opcode(Instruction::Mul(MulInstruction {
        source_1: RF0,
        source_2: RG1,
        destination_1: RG2,
        destination_2: RG3,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), (U256::max_value() - 4) / 2);
    assert_eq!(vm.read_reg(RG3), U256::one());
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
    assert_eq!(vm.flags.greater_than_flag, true);
}

#[test]
fn test_div_execution() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::from(43));
    vm.write_reg(RG1, U256::from(10));

    vm.dispatch_opcode(Instruction::Div(DivInstruction {
        source_1: RF0,
        source_2: RG1,
        quotient_destination: RG2,
        remainder_destination: RG3,
        swap_operands: false,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), U256::from(4));
    assert_eq!(vm.read_reg(RG3), U256::from(3));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
    assert_eq!(vm.flags.equality_flag, false);
    assert_eq!(vm.flags.greater_than_flag, true);
}

#[test]
fn test_div_execution_zero() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();

    vm.write_reg(RG0, U256::from(43));
    vm.write_reg(RG1, U256::from(0));

    vm.dispatch_opcode(Instruction::Div(DivInstruction {
        source_1: RF0,
        source_2: RG1,
        quotient_destination: RG2,
        remainder_destination: RG3,
        swap_operands: false,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), U256::from(0));
    assert_eq!(vm.read_reg(RG3), U256::from(0));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
    assert_eq!(vm.flags.equality_flag, true);
    assert_eq!(vm.flags.greater_than_flag, true);
}

#[test]
fn test_div_execution_both_zero() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG0, U256::from(0));
    vm.write_reg(RG1, U256::from(0));

    vm.dispatch_opcode(Instruction::Div(DivInstruction {
        source_1: RF0,
        source_2: RG1,
        quotient_destination: RG2,
        remainder_destination: RG3,
        swap_operands: false,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG2), U256::from(0));
    assert_eq!(vm.read_reg(RG3), U256::from(0));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
    assert_eq!(vm.flags.equality_flag, true);
    assert_eq!(vm.flags.greater_than_flag, false);
}

#[test]
fn test_shuffle_lowest() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.dispatch_opcode(Instruction::Shuffle(ShuffleInstruction {
        source_1: FullOperand::Immediate(43),
        source_2: NULL,
        destination: RG3,
        load_in_low: true,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG3), U256::from(43));
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
    assert_eq!(vm.flags.equality_flag, false);
    assert_eq!(vm.flags.greater_than_flag, false);
}

#[test]
fn test_immediate_highest() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.dispatch_opcode(Instruction::Shuffle(ShuffleInstruction {
        source_1: FullOperand::Immediate(43),
        source_2: NULL,
        destination: RG3,
        load_in_low: false,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG3), (U256::from(u128::MAX) + 1) * 43);
    assert_eq!(vm.flags.error_overflow_or_less_than_flag, false);
    assert_eq!(vm.flags.equality_flag, false);
    assert_eq!(vm.flags.greater_than_flag, false);
}

#[test]
fn test_hash_zero() {
    let storage = &mut dummy_storage();
    let mut vm = VmInstance::new(
        storage,
        &Vec::new(),
        dummy_context(),
        usize::MAX,
        Default::default(),
    )
    .unwrap();
    vm.write_reg(RG1, U256::from(123));

    vm.dispatch_opcode(Instruction::HashOutput(HashOutputInstruction {
        destination: RG1,
    }))
    .unwrap();

    assert_eq!(vm.read_reg(RG1), U256::zero());
}

#[test]
fn test_hash_reset() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::HashAbsorb(HashAbsorbInstruction {
                source: RF1,
                reset: false,
            }),
            Instruction::HashAbsorb(HashAbsorbInstruction {
                source: RF2,
                reset: true,
            }),
            Instruction::HashOutput(HashOutputInstruction { destination: RG3 }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::zero(), U256::from(123), U256::zero()],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(
        registers[3],
        U256::from_dec_str(
            "5862139083026206628832301127335791535962889136620943667582563443715053309945"
        )
        .unwrap()
    );
}

#[test]
fn test_hash() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::HashAbsorb(HashAbsorbInstruction {
                source: RF1,
                reset: false,
            }),
            Instruction::HashAbsorb(HashAbsorbInstruction {
                source: RF2,
                reset: false,
            }),
            Instruction::HashOutput(HashOutputInstruction { destination: RG3 }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::zero(), U256::from(123), U256::from(125)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(
        registers[3],
        U256::from_dec_str(
            "9683768255054160865462551840877242526106853161404912121878200381733926296023"
        )
        .unwrap()
    );
}

#[test]
fn test_jump() {
    // the second instruction will be skipped
    let assembly = Assembly {
        instructions: vec![
            Instruction::Jump(JumpInstruction {
                source: FullOperand::Register(NULL),
                flags: vec![JumpFlag::Unconditional],
                destination_true: 2,
                destination_false: 1,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(17),
                source_2: NULL,
                destination: RG0,
                load_in_low: true,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(42),
                source_2: NULL,
                destination: RG2,
                load_in_low: true,
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::zero(), U256::from(123), U256::from(125)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], U256::from(42));
    assert_eq!(registers[0], U256::from(0));
}

#[test]
fn test_jump_source_zero() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Jump(JumpInstruction {
                source: RF0,
                flags: vec![],
                // should jump here
                destination_true: 2,
                destination_false: 1,
            }),
            // this instruction should be skipped
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(17),
                source_2: NULL,
                destination: RG2,
                load_in_low: true,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(42),
                source_2: NULL,
                destination: RG3,
                load_in_low: true,
            }),
            Instruction::Jump(JumpInstruction {
                source: RF1,
                flags: vec![],
                destination_true: 5,
                // should jump here - no skipped instructions
                destination_false: 4,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(17),
                source_2: NULL,
                destination: RG4,
                load_in_low: true,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(42),
                source_2: NULL,
                destination: RG5,
                load_in_low: true,
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        // first register: first two bytes are not zero, flag evaluates to true
        // second register: first two bytes are zero, flag evaluates to false
        Vec::new(),
        HashMap::new(),
        vec![U256::from(1 << 15), U256::from(1 << 17)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], U256::from(0));
    assert_eq!(registers[3], U256::from(42));
    assert_eq!(registers[4], U256::from(17));
    assert_eq!(registers[5], U256::from(42));
}

#[test]
fn test_mul_memory_stack() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG0 },
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(20),
                source_2: NULL,
                destination: RG1,
                load_in_low: true,
            }),
            Instruction::Mul(MulInstruction {
                source_1: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0, // pop one element - the one added in the preceding memory op (= 7)
                    register: RegisterOperand::Null,
                }),
                source_2: RG1, // = 20
                destination_1: RG2,
                destination_2: RG3,
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),

        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot {
        registers,
        first_contract_stack,
        ..
    } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(7)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], U256::from(140));
    // make sure stack pop clears the poped element
    assert_eq!(first_contract_stack.read(0).unwrap(), U256::zero());
}

#[test]
fn test_mul_memory_local() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 5,
                    register: RG0, // = 3
                },
                operation: DataOperation::Write { source: RG1 }, // = 5
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(20),
                source_2: NULL,
                destination: RG1,
                load_in_low: true,
            }),
            Instruction::Mul(MulInstruction {
                source_1: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 8,
                    register: RegisterOperand::Null,
                }), // = 5
                source_2: RG1, // = 20
                destination_1: RG2,
                destination_2: RG3,
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),

        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot {
        registers,
        first_contract_local_memory,
        ..
    } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(3), U256::from(5)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], U256::from(100));
    assert_eq!(first_contract_local_memory.read(8).unwrap(), U256::from(5));
}

#[test]
fn test_jump_lesser_than() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Sub(SubInstruction {
                source_1: RF0,
                source_2: RG1,
                destination: NULL, // we only need it to set flags
                swap_operands: false,
            }),
            Instruction::Jump(JumpInstruction {
                source: FullOperand::Register(NULL),
                flags: vec![JumpFlag::LesserThan],
                // should jump here
                destination_true: 3,
                destination_false: 2,
            }),
            // this instruction should be skipped
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(17),
                source_2: NULL,
                destination: RG2,
                load_in_low: true,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(42),
                source_2: NULL,
                destination: RG3,
                load_in_low: true,
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),

        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(5), U256::from(7)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], U256::zero());
    assert_eq!(registers[3], U256::from(42));
}

#[test]
fn test_memory_stack_push_pop() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG0 },
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 1, // pushes two elements: zero and RG1
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG1 },
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG2 },
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: RG3, // RG3 == 1:  raw_mem_offset = 1. POP two elements.
                },
                operation: DataOperation::Read { destination: RG3 },
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: RG4, // RG4 == 0: raw_mem_offset = 1.
                },
                operation: DataOperation::Read { destination: RG4 },
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: RG4, // RG4 == 0: raw_mem_offset = 1.
                },
                operation: DataOperation::Read { destination: RG5 },
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![
            U256::from(201),
            U256::from(202),
            U256::from(203),
            U256::from(1),
        ],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[3], U256::from(202));
    assert_eq!(registers[4], U256::from(0));
    assert_eq!(registers[5], U256::from(201));
}

#[test]
fn test_memory_push_pop() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Memory(MemoryInstruction {
                // bump sp to 1
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG0 },
            }),
            Instruction::Memory(MemoryInstruction {
                // bump sp to 3
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 1,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG1 },
            }),
            Instruction::Memory(MemoryInstruction {
                // bump sp to 5
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 1,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG2 },
            }),
            Instruction::Memory(MemoryInstruction {
                // sp is down to 2
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 2,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG3 }, // value of RG1 goes here
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    // sp is down to 1
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG4 }, // NULL goes here
            }),
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    // sp is down to 0
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG5 }, //value of RG0 goes here
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot {
        registers,
        first_contract_stack,
        ..
    } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(10), U256::from(20)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(first_contract_stack.read(0).unwrap(), U256::default());
    assert_eq!(first_contract_stack.read(1).unwrap(), U256::default());
    assert_eq!(first_contract_stack.read(2).unwrap(), U256::default());
    assert_eq!(first_contract_stack.read(3).unwrap(), U256::default());
    assert_eq!(first_contract_stack.read(4).unwrap(), U256::default());
    assert_eq!(registers[3], U256::from(20));
    assert_eq!(registers[4], U256::from(0));
    assert_eq!(registers[5], U256::from(10));
}

#[test]
fn test_storage() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::Storage {
                storage_key: RF0,
                operation: DataOperation::Write { source: RG1 },
                is_external_storage_access: false,
            }),
            Instruction::Storage(StorageInstruction::Storage {
                storage_key: RF0,
                operation: DataOperation::Read { destination: RG2 },
                is_external_storage_access: false,
            }),
            OP_RETURN,
        ],
        labels: HashMap::new(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let address1 = Address::random();
    let address2 = Address::random();

    let address_to_u256 = |addr| h256_to_u256(address_to_h256(&addr));

    let mut storage = HashMap::new();
    set_account_type(&mut storage, &Address::zero(), &AccountType::ZkRollup);

    let VmSnapshot {
        registers, storage, ..
    } = run_vm(
        assembly,
        Vec::new(),
        storage,
        vec![address_to_u256(address1), address_to_u256(address2)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], address_to_u256(address2));
    assert_eq!(
        storage.get(&StorageKey::UserKey(
            AccountTreeId::Rollup(Address::zero()),
            AccountTreeId::Rollup(Address::zero()),
            address_to_h256(&address1)
        )),
        Some(&address_to_h256(&address2))
    );
}

#[test]
fn test_limit_cycles() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Context(ContextInstruction {
                destination: RG0,
                field: ContextField::RemainingCycles,
            }),
            Instruction::Sub(SubInstruction {
                source_1: FullOperand::Immediate(100),
                source_2: RG0,
                destination: NULL,
                swap_operands: false,
            }), // use this to compare current cycles to 100. It's more than 100 *before* the jump, and it's less *after*.
            Instruction::Jump(JumpInstruction {
                source: FullOperand::Register(NULL),
                flags: vec![JumpFlag::LesserThan],
                destination_true: 3,
                destination_false: 5,
            }),
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    operand: FullOperand::Immediate(10 << 16), // bytes 2..4 represent `num_passed_cycles`
                    is_delegate: false,
                },
            }),
            Instruction::Context(ContextInstruction {
                destination: RG1,
                field: ContextField::RemainingCycles,
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let res_reg: [U256; 6] = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    )
    .registers;

    assert_eq!(res_reg[0], U256::from(9));
    assert_eq!(res_reg[1], U256::from(usize::MAX - 11));
}

#[test]
fn test_rollback_multiple_contracts_explicit_error() {
    let callee_1_contract_address = H160::from_low_u64_le(366);
    let mut contract_1_address_bytes = callee_1_contract_address.as_bytes().to_vec();
    contract_1_address_bytes.reverse();
    let callee_2_contract_address = H160::from_low_u64_le(239);
    let mut contract_2_address_bytes = callee_2_contract_address.as_bytes().to_vec();
    contract_2_address_bytes.reverse();
    let mut function_jump_calldata_bytes = vec![0u8; 32];
    function_jump_calldata_bytes.splice(4..24, contract_1_address_bytes);
    let callee_1_calldata = U256::from_little_endian(&function_jump_calldata_bytes);
    function_jump_calldata_bytes.splice(4..24, contract_2_address_bytes);
    let callee_2_calldata = U256::from_little_endian(&function_jump_calldata_bytes);

    let main_contract = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::Storage {
                storage_key: FullOperand::Immediate(42),
                operation: DataOperation::Write { source: RG0 },
                is_external_storage_access: false,
            }),
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    operand: FullOperand::Register(RG2),
                    is_delegate: false,
                },
            }),
            Instruction::Storage(StorageInstruction::Storage {
                storage_key: FullOperand::Immediate(34),
                operation: DataOperation::Write { source: RG0 },
                is_external_storage_access: false,
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let callee_contract_1 = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::Storage {
                storage_key: FullOperand::Immediate(44),
                operation: DataOperation::Write { source: RG0 },
                is_external_storage_access: false,
            }),
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    operand: FullOperand::Register(RG3),
                    is_delegate: false,
                },
            }),
            // we return with an explicit error. This contract and the callee contract will be reverted.
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: true }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let callee_contract_2 = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::Storage {
                storage_key: FullOperand::Immediate(50),
                operation: DataOperation::Write { source: RG0 },
                is_external_storage_access: false,
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let mut loaded_contracts: HashMap<Address, Assembly> = HashMap::new();
    loaded_contracts.insert(Address::default(), main_contract);
    loaded_contracts.insert(callee_1_contract_address, callee_contract_1);
    loaded_contracts.insert(callee_2_contract_address, callee_contract_2);

    let mut storage = HashMap::new();
    set_account_type(&mut storage, &Address::default(), &AccountType::ZkRollup);
    set_account_type(
        &mut storage,
        &callee_1_contract_address,
        &AccountType::ZkRollup,
    );
    set_account_type(
        &mut storage,
        &callee_2_contract_address,
        &AccountType::ZkRollup,
    );

    let VmSnapshot { storage, .. } = run_vm_multi_contracts(
        loaded_contracts,
        Vec::new(),
        storage,
        vec![
            U256::from(10),
            U256::from(12),
            callee_1_calldata,
            callee_2_calldata,
        ],
        Address::default(),
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );
    assert_eq!(
        storage.get(&StorageKey::new_user(
            Rollup(Address::default()),
            Rollup(Address::default()),
            H256::from_low_u64_be(42)
        )),
        Some(&H256::from_low_u64_be(10))
    ); // the storage write from the entry contract shouldn't be rollback
    assert_eq!(
        storage.get(&StorageKey::new_user(
            Rollup(Address::default()),
            Rollup(Address::default()),
            H256::from_low_u64_be(34)
        )),
        Some(&H256::from_low_u64_be(10))
    ); // the storage write from the entry contract shouldn't be rollback
    assert_eq!(
        storage.get(&StorageKey::new_user(
            Rollup(callee_1_contract_address),
            Rollup(callee_1_contract_address),
            H256::from_low_u64_be(44)
        )),
        Some(&H256::zero())
    ); // callee storages must be reverted
    assert_eq!(
        storage.get(&StorageKey::new_user(
            Rollup(callee_2_contract_address),
            Rollup(callee_2_contract_address),
            H256::from_low_u64_be(50)
        )),
        Some(&H256::zero())
    ); // callee storages must be reverted
}

#[test]
fn test_local_call_memory_sharing() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 239,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG1 },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::Local {
                    address: 4, // pc
                    operand: FullOperand::Immediate(0),
                },
            }),
            // read from stack - callee contract wrote there
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG2 },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
            // local jump goes here
            // read value saved by calling contract
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 239,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG3 },
            }),
            // write to stack - calling contract should be able to pop it
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG0 },
            }),
            // return back to the entry frame
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: true }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(366), U256::from(30)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );
    assert_eq!(registers[2], U256::from(366));
    assert_eq!(registers[3], U256::from(30));
}

#[test]
fn test_delegate_call_memory_sharing() {
    let callee_contract_address = H160::from_low_u64_le(366);
    let mut function_jump_calldata_bytes = vec![0u8; 32];
    let mut contract_address_bytes = callee_contract_address.as_bytes().to_vec();
    contract_address_bytes.reverse();
    function_jump_calldata_bytes.splice(4..24, contract_address_bytes);
    let callee_calldata = U256::from_little_endian(&function_jump_calldata_bytes);

    let assembly_main = Assembly {
        instructions: vec![
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 239,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG1 },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    is_delegate: true,
                    operand: FullOperand::Register(RG2),
                },
            }),
            // read from stack - callee contract wrote there
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG2 },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let assembly_callee = Assembly {
        instructions: vec![
            // read value saved by calling contract
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 239,
                    register: NULL,
                },
                operation: DataOperation::Read { destination: RG3 },
            }),
            // write to stack - calling contract should be able to pop it
            Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0,
                    register: NULL,
                },
                operation: DataOperation::Write { source: RG0 },
            }),
            // return back to the entry frame
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: true }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let mut loaded_contracts: HashMap<Address, Assembly> = HashMap::new();
    loaded_contracts.insert(Address::default(), assembly_main);
    loaded_contracts.insert(callee_contract_address, assembly_callee);

    let VmSnapshot { registers, .. } = run_vm_multi_contracts(
        loaded_contracts,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(366), U256::from(30), callee_calldata],
        Address::default(),
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[2], U256::from(366));
    assert_eq!(registers[3], U256::from(30));
}

#[test]
fn test_limit_cycles_exception() {
    let assembly = Assembly {
        instructions: vec![
            Instruction::Context(ContextInstruction {
                destination: RG0,
                field: ContextField::RemainingCycles,
            }),
            Instruction::Context(ContextInstruction {
                destination: RG1,
                field: ContextField::RemainingCycles,
            }),
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    operand: FullOperand::Immediate(1 << 16), // bytes 2..4 represent `num_passed_cycles`. Only pass one cycle.
                    is_delegate: false,
                },
            }),
            Instruction::Jump(JumpInstruction {
                source: FullOperand::Register(NULL),
                //make sure the Lesser flag is set (== exception flag)
                flags: vec![JumpFlag::LesserThan],
                destination_true: 5,
                destination_false: 6,
            }),
            Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Immediate(42),
                source_2: NULL,
                destination: RG2,
                load_in_low: true,
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let VmSnapshot {
        registers,
        execution_result,
        ..
    } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(
        execution_result.internal_errors,
        vec![(Address::default(), "Ran out of cycles.".to_owned())]
    );
    assert_eq!(registers[0], U256::from(0));
    assert_eq!(registers[1], U256::from(usize::MAX - 2)); // make sure the second operation (Instruction::Cycles(CyclesInstruction { destination: RG1 })) only ran once
    assert_eq!(registers[2], U256::from(42));
}

#[test]
fn test_events_multi_contract() {
    let callee_contract_address = H160::from_low_u64_le(366);
    let mut function_jump_calldata_bytes = vec![0u8; 32];
    let mut contract_address_bytes = callee_contract_address.as_bytes().to_vec();
    contract_address_bytes.reverse();
    function_jump_calldata_bytes.splice(4..24, contract_address_bytes);
    let callee_calldata = U256::from_little_endian(&function_jump_calldata_bytes);

    let assembly_main = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::LogInit {
                packed_lengths: packed_log_lengths(2, 32),
                first_topic_or_chunk: RG2, // 533
            }),
            Instruction::Storage(StorageInstruction::Log(FullOperand::Immediate(777), RG3)), //366366366
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    // call `assembly_callee`
                    operand: FullOperand::Register(RG1),
                    is_delegate: false,
                },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let assembly_callee = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::LogInit {
                packed_lengths: packed_log_lengths(1, 32),
                first_topic_or_chunk: RG2, // 533
            }),
            Instruction::Storage(StorageInstruction::Log(
                FullOperand::Immediate(239239239),
                NULL,
            )),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let mut loaded_contracts: HashMap<Address, Assembly> = HashMap::new();
    loaded_contracts.insert(Address::default(), assembly_main);
    loaded_contracts.insert(callee_contract_address, assembly_callee);

    let VmSnapshot {
        execution_result: VmExecutionResult { events, .. },
        ..
    } = run_vm_multi_contracts(
        loaded_contracts,
        Vec::new(),
        HashMap::new(),
        vec![
            U256::from(32),
            callee_calldata,
            U256::from(533),
            U256::from(366366366),
        ],
        Address::default(),
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    let mut value1_bytes = [0u8; 32];
    let mut value2_bytes = [0u8; 32];

    U256::from(366366366).to_big_endian(&mut value1_bytes);
    U256::from(239239239).to_big_endian(&mut value2_bytes);

    // only one event should be emitted -
    // the event in the callee contract is rolled back due to exception
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        VmEvent {
            address: Address::default(),
            location: (BlockNumber(0), 0),
            indexed_topics: vec!(H256::from_low_u64_be(533), H256::from_low_u64_be(777)),
            value: value1_bytes.to_vec()
        }
    );
    assert_eq!(
        events[1],
        VmEvent {
            address: callee_contract_address,
            location: (BlockNumber(0), 0),
            indexed_topics: vec!(H256::from_low_u64_be(533)),
            value: value2_bytes.to_vec()
        }
    );
}

#[test]
fn test_events_multi_contract_exception() {
    let callee_contract_address = H160::from_low_u64_le(366);
    let mut function_jump_calldata_bytes = vec![0u8; 32];
    let mut contract_address_bytes = callee_contract_address.as_bytes().to_vec();
    contract_address_bytes.reverse();
    function_jump_calldata_bytes.splice(4..24, contract_address_bytes);
    let callee_calldata = U256::from_little_endian(&function_jump_calldata_bytes);

    let assembly_main = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::LogInit {
                packed_lengths: packed_log_lengths(1, 59),
                first_topic_or_chunk: RG2, //533
            }),
            Instruction::Storage(StorageInstruction::Log(
                FullOperand::Immediate(366366366),
                RG3, //544544544
            )),
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    // call `assembly_callee`
                    operand: FullOperand::Register(RG1),
                    is_delegate: false,
                },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let assembly_callee = Assembly {
        instructions: vec![
            Instruction::Storage(StorageInstruction::LogInit {
                packed_lengths: packed_log_lengths(1, 59),
                first_topic_or_chunk: RG2,
            }),
            Instruction::Storage(StorageInstruction::Log(
                FullOperand::Immediate(544544544),
                NULL,
            )),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: true }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let mut loaded_contracts: HashMap<Address, Assembly> = HashMap::new();
    loaded_contracts.insert(Address::default(), assembly_main);
    loaded_contracts.insert(callee_contract_address, assembly_callee);

    let VmSnapshot {
        execution_result:
            VmExecutionResult {
                events,
                internal_errors,
                ..
            },
        ..
    } = run_vm_multi_contracts(
        loaded_contracts,
        Vec::new(),
        HashMap::new(),
        vec![
            U256::from(59),
            callee_calldata,
            U256::from(533),
            U256::from(544544544),
        ], // 32  + 27 bytes
        Address::default(),
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    let mut topic_bytes = [0u8; 32];
    let mut value_bytes = [0u8; 64];

    U256::from(533).to_little_endian(&mut topic_bytes);
    U256::from(366366366).to_big_endian(&mut value_bytes[0..32]);
    U256::from(544544544).to_big_endian(&mut value_bytes[32..64]);
    assert_eq!(
        internal_errors,
        vec![(
            callee_contract_address,
            "Contract execution resulted in a revert".to_owned()
        )]
    );
    // only one event should be emitted -
    // the event in the callee contract is rolled back due to exception
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0],
        VmEvent {
            address: Address::default(),
            location: (BlockNumber(0), 0),
            indexed_topics: vec!(H256::from_low_u64_be(533)),
            value: value_bytes[0..59].to_vec()
        }
    );
}

#[test]
fn test_context_contract_addresses() {
    let contract_address = H160::from_low_u64_le(366);
    let assembly = Assembly {
        instructions: vec![
            Instruction::Context(ContextInstruction {
                destination: RG0,
                field: ContextField::CurrentAddress,
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let mut loaded_contracts: HashMap<Address, Assembly> = HashMap::new();
    loaded_contracts.insert(contract_address, assembly);

    let VmSnapshot { registers, .. } = run_vm_multi_contracts(
        loaded_contracts,
        Vec::new(),
        HashMap::new(),
        vec![],
        contract_address,
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(
        registers[0],
        h256_to_u256(address_to_h256(&contract_address))
    );
}

#[test]
fn test_context_msg_sender() {
    let callee_contract_address = H160::from_low_u64_le(366);
    let mut function_jump_calldata_bytes = vec![0u8; 32];
    let mut contract_address_bytes = callee_contract_address.as_bytes().to_vec();
    contract_address_bytes.reverse();
    function_jump_calldata_bytes.splice(4..24, contract_address_bytes);
    let callee_calldata = U256::from_little_endian(&function_jump_calldata_bytes);

    let assembly_main = Assembly {
        instructions: vec![
            Instruction::Context(ContextInstruction {
                destination: RG1,
                field: ContextField::MsgSender,
            }),
            Instruction::SwitchContext,
            Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: FunctionJumpLocation::External {
                    // call `assembly_callee`
                    operand: FullOperand::Register(RG0),
                    is_delegate: false,
                },
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let assembly_callee = Assembly {
        instructions: vec![
            Instruction::Context(ContextInstruction {
                destination: RG2,
                field: ContextField::MsgSender,
            }),
            Instruction::FunctionJump(FunctionJumpInstruction::Return { error: true }),
        ],
        labels: Default::default(),
        assembly_code: "".to_string(),
        pc_line_mapping: Default::default(),
    };

    let mut loaded_contracts: HashMap<Address, Assembly> = HashMap::new();
    loaded_contracts.insert(H160::from_low_u64_be(777), assembly_main);
    loaded_contracts.insert(callee_contract_address, assembly_callee);

    let VmSnapshot { registers, .. } = run_vm_multi_contracts(
        loaded_contracts,
        Vec::new(),
        HashMap::new(),
        vec![callee_calldata], // 32  + 27 bytes
        H160::from_low_u64_be(777),
        Some(VmExecutionContext {
            msg_sender: H160::from_low_u64_be(223),
            block_number: BlockNumber(0),
            transaction_index: 0,
            block_timestamp: 0,
            entry_address: H160::from_low_u64_be(777),
        }),
        VmLaunchOption::Default,
        usize::MAX,
    );
    assert_eq!(registers[1], U256::from(223));
    assert_eq!(registers[2], U256::from(777));
}

fn packed_log_lengths(topics: u128, data_bytes: u128) -> FullOperand {
    FullOperand::Immediate(topics + (data_bytes << 32))
}

fn dummy_storage() -> RawInMemoryStorage {
    let mut contracts = HashMap::new();

    contracts.insert(
        Address::default(),
        Assembly {
            instructions: vec![OP_RETURN],
            labels: HashMap::new(),

            assembly_code: "".to_string(),
            pc_line_mapping: Default::default(),
        },
    );
    RawInMemoryStorage {
        values: Default::default(),
        contracts,
    }
}

fn dummy_context() -> VmExecutionContext {
    VmExecutionContext {
        msg_sender: Default::default(),
        block_number: BlockNumber(0),
        transaction_index: 0,
        block_timestamp: 0,
        entry_address: Address::default(),
    }
}
