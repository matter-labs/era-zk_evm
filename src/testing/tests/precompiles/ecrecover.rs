use super::*;

fn fill_memory<M: Memory>(hash: [u8; 32], r: [u8; 32], s: [u8; 32], v: bool, page: u32, memory: &mut M) -> u16 {
    let mut location = MemoryLocation {page: MemoryPage(page), index: MemoryIndex(0)};
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&hash),
        rw_flag: true
    };
    let _ = memory.execute_partial_query(query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&r),
        rw_flag: true
    };
    let _ = memory.execute_partial_query(query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&s),
        rw_flag: true
    };
    let _ = memory.execute_partial_query(query);

    location.index.0 += 1;
    let mut buffer = [0u8; 32];
    if v {
        buffer[31] = 1;
    }
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&buffer),
        rw_flag: true
    };
    let _ = memory.execute_partial_query(query);


    4 as u16
}

fn ecrecover_test_inner(hash: [u8; 32], r: [u8; 32], s: [u8; 32], v: bool, expect_ok: bool, expected_address: [u8; 20]) -> (Vec<[u8; 32]>, std::ops::Range<u16>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;

    // fill the memory
    let num_words_used = fill_memory(hash, r, s, v, 0u32, &mut memory);

    let precompile_call_params = PrecompileCallParams {
        input_location: MemoryLocation {page: MemoryPage(0u32), index: MemoryIndex(0u16)},
        output_location: MemoryLocation {page: MemoryPage(0u32), index: MemoryIndex(num_words_used)},
        timestamp_for_input_read: Timestamp(1u32),
        timestamp_for_output_write: Timestamp(2u32),
    };

    let address = Address::from_low_u64_be(ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS as u64);

    let precompile_query = LogQuery {
        timestamp: precompile_call_params.timestamp_for_input_read,
        tx_number_in_block: 0,
        shard_id: 0,
        aux_byte: PRECOMPILE_AUX_BYTE,
        address,
        key: U256::zero(),
        read_value: precompile_call_params.encode_into_log_value(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let _ = precompiles_processor.execute_precompile(precompile_query, &mut memory);

    let range = 0u16..(num_words_used + 2);
    let content = memory.dump_page_content(0u32, range.clone());
    let content_len = content.len();
    let expected_output = content[content_len-1];
    let ok_or_error_marker = content[content_len-2];

    if expect_ok {
        let mut buffer = [0u8; 32];
        U256::one().to_big_endian(&mut buffer);
        assert!(ok_or_error_marker == buffer);
        assert_eq!(&expected_output[12..], &expected_address);
    } else {
        let mut buffer = [0u8; 32];
        U256::zero().to_big_endian(&mut buffer);
        assert!(ok_or_error_marker == buffer);
        assert_eq!(&expected_output[..], &[0u8; 32]);
    }

    (content, range)
}

fn ecrecover_test_inner_from_raw(raw_input: &str, raw_address: &str, expect_ok: bool) -> (Vec<[u8; 32]>, std::ops::Range<u16>) {
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
fn test_valid_large_s() {
    let raw_input = "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e000000000000000000000000000000000000000000000000000000000000001b38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
    let raw_address = hex::encode(&vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 198, 174, 93, 17, 93, 119, 163, 216, 169, 239,
        54, 214, 164, 45, 35, 105, 43, 170, 127,
    ]);
    let (content, range) = ecrecover_test_inner_from_raw(raw_input, &raw_address, true);
    pretty_print_memory_dump(&content, range);
}