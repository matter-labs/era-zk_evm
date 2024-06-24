use super::*;
use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zkevm_opcode_defs::system_params::*;
use zkevm_opcode_defs::PrecompileCallABI;

fn fill_memory<M: Memory>(
    b_size: [u8; 32],
    e_size: [u8; 32],
    m_size: [u8; 32],
    b: [u8; 32],
    e: [u8; 32],
    m: [u8; 32],
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
        value: U256::from_big_endian(&b_size),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(0, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&e_size),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(1, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&m_size),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(2, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&b),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(3, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&e),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(4, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&m),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(5, query);

    6 as u16
}

fn modexp_test_inner(
    b_size: [u8; 32],
    e_size: [u8; 32],
    m_size: [u8; 32],
    b: [u8; 32],
    e: [u8; 32],
    m: [u8; 32],
    expect_ok: bool,
    expected_result: [u8; 32],
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;
    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    // fill the memory
    let num_words_used = fill_memory(b_size, e_size, m_size, b, e, m, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 1,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(MODEXP_INNER_FUNCTION_PRECOMPILE_ADDRESS as u64);

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
    let ok_or_error_marker = content[content_len - 2];
    let output = content[content_len - 1];

    if expect_ok {
        let mut buffer = [0u8; 32];
        U256::one().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&output, &expected_result);
    } else {
        let mut buffer = [0u8; 32];
        U256::zero().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&output[..], &[0u8; 32]);
    }

    (content, range)
}

fn modexp_test_inner_from_raw(
    raw_input: &str,
    raw_output: &str,
    expect_ok: bool,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let input_bytes = hex::decode(raw_input).unwrap();
    let b_size: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let e_size: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let m_size: [u8; 32] = input_bytes[64..96].try_into().unwrap();
    let b: [u8; 32] = input_bytes[96..128].try_into().unwrap();
    let e: [u8; 32] = input_bytes[128..160].try_into().unwrap();
    let m: [u8; 32] = input_bytes[160..192].try_into().unwrap();

    let expected_result: [u8; 32] = hex::decode(raw_output).unwrap().try_into().unwrap();

    modexp_test_inner(b_size, e_size, m_size, b, e, m, expect_ok, expected_result)
}

#[cfg(test)]
pub mod test {
    /// Tests the modexp correctness based on the valid input.
    #[test]
    fn test_valid() {
        use super::*;
        
        let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f333213268023a7d3d40ea760d0e1c00d5fe99710e379193fc5973e7ad09370039d71831130091794534336679323390f4408be38cb89963ec41f4a90d6bf63ec6f05ec20e4c25420f9d6bc6800f9544ecabf5dbea80d11e0fb12c7f0517f5b";
        let raw_output = "2779a7e4d2b26461c6557a12eb86285eeeb9cf5a40155305177854b15b4ed3df";
        let (content, range) = modexp_test_inner_from_raw(raw_input, raw_output, true);
        pretty_print_memory_dump(&content, range);
    }
}
