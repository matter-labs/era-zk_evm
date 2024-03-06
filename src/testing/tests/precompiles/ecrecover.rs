use super::*;
use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zkevm_opcode_defs::system_params::*;
use zkevm_opcode_defs::PrecompileCallABI;

fn fill_memory<M: Memory>(
    hash: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    v: bool,
    page: u32,
    memory: &mut M,
) -> u16 {
    let mut location = MemoryLocation {
        page: MemoryPage(page),
        index: MemoryIndex(0),
        memory_type: MemoryType::Heap,
    };
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&hash),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(0, query);

    location.index.0 += 1;
    let mut buffer = [0u8; 32];
    if v {
        buffer[31] = 1;
    }
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&buffer),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(1, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&r),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(2, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&s),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(3, query);

    4 as u16
}

fn ecrecover_test_inner(
    hash: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    v: bool,
    expect_ok: bool,
    expected_address: [u8; 20],
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;
    let page_number = 4u32;
    // create heap page
    memory.heaps.push((
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ));

    // fill the memory
    let num_words_used = fill_memory(hash, r, s, v, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 2,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS as u64);

    let precompile_query = LogQuery {
        timestamp: Timestamp(1u32),
        tx_number_in_block: 0,
        shard_id: 0,
        aux_byte: PRECOMPILE_AUX_BYTE,
        address,
        key: precompile_call_params_encoded,
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let _ = precompiles_processor.execute_precompile(4, precompile_query, &mut memory);

    let range = 0u32..(num_words_used as u32 + 2);
    let content = memory.dump_page_content(page_number, range.clone());
    let content_len = content.len();
    let expected_output = content[content_len - 1];
    let ok_or_error_marker = content[content_len - 2];

    if expect_ok {
        let mut buffer = [0u8; 32];
        U256::one().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&expected_output[12..], &expected_address);
    } else {
        let mut buffer = [0u8; 32];
        U256::zero().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&expected_output[..], &[0u8; 32]);
    }

    (content, range)
}

fn ecrecover_test_inner_from_raw(
    raw_input: &str,
    raw_address: &str,
    expect_ok: bool,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let input_bytes = hex::decode(raw_input).unwrap();
    let hash: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let v_padded: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let r: [u8; 32] = input_bytes[64..96].try_into().unwrap();
    let s: [u8; 32] = input_bytes[96..128].try_into().unwrap();

    let address = hex::decode(raw_address).unwrap();
    let offset = address.len() - 20;
    let expected_address: [u8; 20] = address[offset..].try_into().unwrap();

    let v = if v_padded[31] == 1 {
        true
    } else if v_padded[31] == 0 {
        false
    } else if v_padded[31] == 28 {
        true
    } else if v_padded[31] == 27 {
        false
    } else {
        panic!("v = {}", v_padded[31]);
    };

    ecrecover_test_inner(hash, r, s, v, expect_ok, expected_address)
}

#[test]
fn test_valid() {
    let raw_input = "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e789d1dd423d25f0772d2748d60f7e4b81bb14d086eba8e8e8efb6dcff8a4ae02";
    let raw_address = "000000000000000000000000ceaccac640adf55b2028469bd36ba501f28b699d";
    let (content, range) = ecrecover_test_inner_from_raw(raw_input, raw_address, true);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_valid_2() {
    let hash: [u8; 32] =
        hex::decode("5ae8317d34d1e595e3fa7247db80c0af4320cce1116de187f8f7e2e099c0d8d0")
            .unwrap()
            .try_into()
            .unwrap();
    let v = true;
    let r: [u8; 32] =
        hex::decode("45c0b7f8c09a9e1f1cea0c25785594427b6bf8f9f878a8af0b1abbb48e16d092")
            .unwrap()
            .try_into()
            .unwrap();
    let s: [u8; 32] =
        hex::decode("0d8becd0c220f67c51217eecfd7184ef0732481c843857e6bc7fc095c4f6b788")
            .unwrap()
            .try_into()
            .unwrap();

    let expected_address: [u8; 20] = hex::decode("0624bd72497747be77b2cba25140fcab61ae4fea")
        .unwrap()
        .try_into()
        .unwrap();

    let (content, range) = ecrecover_test_inner(hash, r, s, v, true, expected_address);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_valid_3() {
    let hash: [u8; 32] =
        hex::decode("14431339128bd25f2c7f93baa611e367472048757f4ad67f6d71a5ca0da550f5")
            .unwrap()
            .try_into()
            .unwrap();
    let v = true;
    let r: [u8; 32] =
        hex::decode("51e4dbbbcebade695a3f0fdf10beb8b5f83fda161e1a3105a14c41168bf3dce0")
            .unwrap()
            .try_into()
            .unwrap();
    let s: [u8; 32] =
        hex::decode("46eabf35680328e26ef4579caf8aeb2cf9ece05dbf67a4f3d1f28c7b1d0e3546")
            .unwrap()
            .try_into()
            .unwrap();

    let expected_address: [u8; 20] = hex::decode("7f8b3b04bf34618f4a1723fba96b5db211279a2b")
        .unwrap()
        .try_into()
        .unwrap();

    let (content, range) = ecrecover_test_inner(hash, r, s, v, true, expected_address);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_valid_large_s() {
    let raw_input = "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
    let raw_address = hex::encode(&vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 198, 174, 93, 17, 93, 119, 163, 216, 169, 239, 54,
        214, 164, 45, 35, 105, 43, 170, 127,
    ]);
    let (content, range) = ecrecover_test_inner_from_raw(raw_input, &raw_address, true);
    pretty_print_memory_dump(&content, range);
}
