use crate::tests::set_account_type;
use crate::vm_runner::{run_vm, VmLaunchOption, VmSnapshot};
use crate::VmExecutionResult;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

#[test]
fn factorial_5() {
    let assembly =
        zkevm_assembly::Assembly::try_from(PathBuf::from("examples/factorial.sasm")).unwrap();
    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(5)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[0], U256::from(120)); //5! = 120
}

#[test]
fn errors_in_contract() {
    // You can find the exact contract code in etc/contracts-test-data/error-contract/SimpleRequire.sol
    let assembly =
        zkevm_assembly::Assembly::try_from(PathBuf::from("examples/require.zasm")).unwrap();
    let short_calldata = decode_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e6136e38").unwrap();
    let long_calldata = decode_hex("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b5fa981").unwrap();
    let new_error_calldata = decode_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058f822ca").unwrap();

    let mut storage = HashMap::new();
    let storage_key = StorageKey::UserKey(
        AccountTreeId::Rollup(Address::default()),
        AccountTreeId::Rollup(Address::default()),
        H256::from_str("0xc49821d8653c58e43c7c6b0f17e15eb7f774bf3333419e9bedb01be51ae97e7c")
            .unwrap(),
    );
    storage.insert(storage_key, u32_to_h256(1));
    set_account_type(&mut storage, &Address::default(), &AccountType::ZkRollup);
    let VmSnapshot {
        execution_result: VmExecutionResult { revert_reason, .. },
        ..
    } = run_vm(
        assembly.clone(),
        short_calldata,
        storage.clone(),
        vec![],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );
    let revert_reason = revert_reason.unwrap();
    assert_eq!(revert_reason.require_msg().unwrap(), "short");
    assert_eq!(hex::encode(revert_reason.complete_byte_message()),"08c379a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000573686f7274000000000000000000000000000000000000000000000000000000");
    let VmSnapshot {
        execution_result: VmExecutionResult { revert_reason, .. },
        ..
    } = run_vm(
        assembly.clone(),
        long_calldata,
        storage.clone(),
        vec![],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );
    assert_eq!(revert_reason.unwrap().require_msg().unwrap(), "llonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextblonglonglongtextbonglonglongtextb");
    let VmSnapshot {
        execution_result: VmExecutionResult { revert_reason, .. },
        ..
    } = run_vm(
        assembly.clone(),
        new_error_calldata,
        storage.clone(),
        vec![],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );
    //Correct error encoded with abi
    assert_eq!(hex::encode(revert_reason.unwrap().msg), "000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000046461746100000000000000000000000000000000000000000000000000000000");
}

#[test]
fn factorial_rec_5() {
    let assembly =
        zkevm_assembly::Assembly::try_from(PathBuf::from("examples/factorial_rec.sasm")).unwrap();

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(5)],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );

    assert_eq!(registers[0], U256::from(120)); //5! = 120
}

#[test]
#[ignore] // ignore because fibonacci.sasm is generated with compiler with old sp handling
fn fibonacci_23() {
    vlog::init();
    let assembly =
        zkevm_assembly::Assembly::try_from(PathBuf::from("examples/fibonacci.sasm")).unwrap();

    let VmSnapshot { registers, .. } = run_vm(
        assembly,
        Vec::new(),
        HashMap::new(),
        vec![U256::from(5)],
        None,
        VmLaunchOption::Label(String::from("three")),
        usize::MAX,
    );

    assert_eq!(registers[0], U256::from(63245986)); //23th fibonacci number = 17711
}

#[test]
#[ignore]
fn test_increase_storage() {
    vlog::init();
    let asm_text = r#"
          .text
    .file    "main"
    .type    reverse,@function
reverse:
    push    #33, r0
    add    r1, r0, r4
    sfll    #0, r5, r5
    sflh    #0, r5, r5
    sfll    #320, r3, r3
    sflh    #0, r3, r3
    sfll    #736, r0, r1
    add    r1, r3, r3
    mov    r3, 22(sp)
    sfll    #288, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 7(sp)
    sfll    #224, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 9(sp)
    sfll    #192, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 8(sp)
    sfll    #160, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 6(sp)
    sfll    #128, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 5(sp)
    sfll    #96, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 4(sp)
    sfll    #64, r3, r3
    sflh    #0, r3, r3
    add    r1, r3, r3
    mov    r3, 3(sp)
    sfll    #32, r6, r6
    sflh    #0, r6, r6
    div    r2, r6, r3, r0
    mov    r6, 23(sp)
    add    r1, r6, r2
    mov    r2, 2(sp)
    sfll    #256, r6, r6
    sflh    #0, r6, r6
    add    r1, r6, r1
    mov    r1, 1(sp)
    add    1088, r4, r1
    mov    r1, 11(sp)
    mov    35(sp-r3), r2
    mov    36(sp-r3), r1
    mov    r1, 13(sp)
    mov    37(sp-r3), r1
    mov    r1, 20(sp)
    mov    38(sp-r3), r1
    mov    r1, 19(sp)
    mov    39(sp-r3), r1
    mov    r1, 18(sp)
    mov    40(sp-r3), r1
    mov    r1, 17(sp)
    mov    41(sp-r3), r1
    mov    r1, 16(sp)
    mov    42(sp-r3), r1
    mov    r1, 15(sp)
    mov    43(sp-r3), r1
    mov    r1, 14(sp)
    mov    44(sp-r3), r1
    mov    45(sp-r3), r4
    mov    r4, 34(sp)
    div    r4, r6, r0, r3
    mov    r3, 10(sp)
    mov    r1, 12(sp)
    mov    r1, 33(sp)
    mov    14(sp), r1
    mov    r1, 32(sp)
    mov    15(sp), r1
    mov    r1, 31(sp)
    mov    16(sp), r1
    mov    r1, 30(sp)
    mov    17(sp), r1
    mov    r1, 29(sp)
    mov    18(sp), r1
    mov    r1, 28(sp)
    mov    19(sp), r1
    mov    r1, 27(sp)
    mov    20(sp), r1
    mov    r1, 26(sp)
    mov    13(sp), r1
    mov    r1, 25(sp)
    mov    r2, 24(sp)
    sfll    #2, r3, r3
    sflh    #0, r3, r3
    mov    r3, 21(sp)
    mov    10(sp), r1
    sub    r1, r3, r0
    jlt    .LBB0_4, .LBB0_1
.LBB0_1: 
    sub    r0, r5, r3
    sfll    #340282366920938463463374607431768211455, r1, r1
    sflh    #340282366920938463463374607431768211455, r1, r1
    add    r3, r1, r1
    add    r4, r1, r3
    div    r3, r6, r0, r3
    mov    24(sp-r3), r3
    div    r3, r6, r0, r3
    div    r5, r6, r0, r4
    mov    r3, 24(sp-r4)
    mov    23(sp), r3
    mov    22(sp), r4
    div    r4, r3, r3, r0
    mov    1(sp-r3), r4
    add    r4, r1, r1
    div    r2, r6, r0, r2
    div    r1, r6, r0, r1
    mov    r2, 24(sp-r1)
    sfll    #1, r1, r1
    sflh    #0, r1, r1
    add    r5, r1, r5
    mov    1(sp-r3), r4
    div    r4, r6, r0, r1
    mov    21(sp), r2
    div    r1, r2, r1, r0
    div    r5, r6, r0, r2
    sub    r2, r1, r0
    jge    .LBB0_3, .LBB0_2
.LBB0_2: 
    mov    24(sp-r2), r1
    div    r1, r6, r0, r2
    j    .LBB0_1, .LBB0_1
.LBB0_3: 
    mov    23(sp), r1
    mov    1(sp), r2
    div    r2, r1, r2, r0
    mov    r2, 19(sp)
    mov    7(sp), r2
    div    r2, r1, r6, r0
    mov    2(sp), r2
    div    r2, r1, r2, r0
    mov    r2, 22(sp)
    mov    3(sp), r2
    div    r2, r1, r2, r0
    mov    r2, 21(sp)
    mov    4(sp), r2
    div    r2, r1, r2, r0
    mov    r2, 20(sp)
    mov    5(sp), r2
    div    r2, r1, r2, r0
    mov    r2, 18(sp)
    mov    6(sp), r2
    div    r2, r1, r5, r0
    mov    8(sp), r2
    div    r2, r1, r3, r0
    mov    9(sp), r2
    div    r2, r1, r1, r0
    mov    24(sp), r2
    mov    1(sp-r6), r6
    mov    r6, 12(sp)
    mov    19(sp), r6
    mov    1(sp-r6), r6
    mov    r6, 14(sp)
    mov    1(sp-r1), r1
    mov    r1, 15(sp)
    mov    1(sp-r3), r1
    mov    r1, 16(sp)
    mov    1(sp-r5), r1
    mov    r1, 17(sp)
    mov    18(sp), r1
    mov    1(sp-r1), r1
    mov    r1, 18(sp)
    mov    20(sp), r1
    mov    1(sp-r1), r1
    mov    r1, 19(sp)
    mov    21(sp), r1
    mov    1(sp-r1), r1
    mov    r1, 20(sp)
    mov    22(sp), r1
    mov    1(sp-r1), r1
    mov    r1, 13(sp)
.LBB0_4: 
    mov    11(sp), r1
    mov    23(sp), r3
    div    r1, r3, r3, r0
    mov    r4, 11(sp-r3)
    mov    12(sp), r4
    mov    r4, 10(sp-r3)
    mov    14(sp), r4
    mov    r4, 9(sp-r3)
    mov    15(sp), r4
    mov    r4, 8(sp-r3)
    mov    16(sp), r4
    mov    r4, 7(sp-r3)
    mov    17(sp), r4
    mov    r4, 6(sp-r3)
    mov    18(sp), r4
    mov    r4, 5(sp-r3)
    mov    19(sp), r4
    mov    r4, 4(sp-r3)
    mov    20(sp), r4
    mov    r4, 3(sp-r3)
    mov    13(sp), r4
    mov    r4, 2(sp-r3)
    mov    r2, 1(sp-r3)
    pop    #33, r0
    ret
reverse_test: 
    push    #26, r0
    sfll    #9, r1, r1
    sflh    #0, r1, r1
    mov    r1, 25(sp)
    sfll    #4, r1, r1
    sflh    #0, r1, r1
    mov    r1, 24(sp)
    sfll    #5, r1, r1
    sflh    #0, r1, r1
    mov    r1, 23(sp)
    sfll    #10, r1, r1
    sflh    #0, r1, r1
    mov    r1, 27(sp)
    mov    r1, 21(sp)
    sfll    #8, r1, r1
    sflh    #0, r1, r1
    mov    r1, 20(sp)
    sfll    #6, r1, r1
    sflh    #0, r1, r1
    mov    r1, 4(sp)
    mov    r1, 26(sp)
    sfll    #3, r1, r1
    sflh    #0, r1, r1
    mov    r1, 2(sp)
    mov    r1, 22(sp)
    sfll    #1, r1, r1
    sflh    #0, r1, r1
    mov    r1, 1(sp)
    mov    r1, 19(sp)
    sfll    #2, r1, r1
    sflh    #0, r1, r1
    mov    r1, 5(sp)
    mov    r1, 18(sp)
    sfll    #7, r1, r1
    sflh    #0, r1, r1
    mov    r1, 3(sp)
    mov    r1, 17(sp)
    sfll    #160, r0, r1
    sfll    #512, r0, r2
    call    reverse
    mov    1(sp), r5
    sfll    #0, r2, r2
    sflh    #0, r2, r2
    mov    10(sp), r3
    add    r5, r0, r1
    mov    2(sp), r4
    sub    r3, r4, r0
    je    .LBB1_2, .LBB1_1
.LBB1_1: 
    add    r2, r0, r1
.LBB1_2: 
    mov    15(sp), r4
    add    r5, r0, r3
    mov    3(sp), r6
    sub    r4, r6, r0
    je    .LBB1_4, .LBB1_3
.LBB1_3: 
    add    r2, r0, r3
.LBB1_4: 
    mov    6(sp), r4
    mov    4(sp), r6
    sub    r4, r6, r0
    je    .LBB1_6, .LBB1_5
.LBB1_5: 
    add    r2, r0, r5
.LBB1_6: 
    mul    r5, r3, r2, r0
    mul    r1, r2, r1, r0
    mov    5(sp), r2
    div    r1, r2, r0, r1
    pop    #26, r0
    ret
.Lfunc_end1:
    .size    reverse_test, .Lfunc_end1-reverse_test

    .section    ".note.GNU-stack","",@progbits
    "#;

    let assembly = zkevm_assembly::Assembly::try_from(asm_text.to_owned()).unwrap();
    let calldata = r#"
        0100 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0100 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 7bfc 6c64
        0500 0000 0000 0000 0000 0000 0000 0000
        0000 0000 0000 0000 0000 0000 0000 0000

    "#
    .replace(|c: char| c.is_whitespace(), "");

    let decoded_calldata = decode_hex(&calldata).expect("Decoding failed");
    let storage_key = UserKey(
        Rollup(H160::zero()),
        Rollup(H160::zero()),
        H256::from_low_u64_be(1),
    );
    let mut initial_storage: HashMap<StorageKey, H256> = HashMap::new();
    initial_storage.insert(storage_key.clone(), H256::from_low_u64_be(43));
    let VmSnapshot { storage, .. } = run_vm(
        assembly,
        decoded_calldata,
        initial_storage,
        vec![],
        None,
        VmLaunchOption::Default,
        usize::MAX,
    );
    assert_eq!(storage.get(&storage_key), Some(&H256::from_low_u64_be(48))) // 43 + 5 = 48
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
