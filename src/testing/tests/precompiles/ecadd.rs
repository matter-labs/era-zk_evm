use super::*;
use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zkevm_opcode_defs::system_params::*;
use zkevm_opcode_defs::PrecompileCallABI;

fn fill_memory<M: Memory>(
    x1: [u8; 32],
    y1: [u8; 32],
    x2: [u8; 32],
    y2: [u8; 32],
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
        value: U256::from_big_endian(&x1),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(0, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&y1),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(1, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&x2),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(2, query);

    location.index.0 += 1;
    let query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: U256::from_big_endian(&y2),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(3, query);

    4 as u16
}

fn ecadd_test_inner(
    x1: [u8; 32],
    y1: [u8; 32],
    x2: [u8; 32],
    y2: [u8; 32],
    expect_ok: bool,
    expected_x: [u8; 32],
    expected_y: [u8; 32],
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
    let num_words_used = fill_memory(x1, y1, x2, y2, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 3,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECADD_INNER_FUNCTION_PRECOMPILE_ADDRESS as u64);

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

    let range = 0u32..(num_words_used as u32 + 3);
    let content = memory.dump_page_content(page_number, range.clone());
    let content_len = content.len();
    let ok_or_error_marker = content[content_len - 3];
    let output_x = content[content_len - 2];
    let output_y = content[content_len - 1];

    if expect_ok {
        let mut buffer = [0u8; 32];
        U256::one().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&output_x, &expected_x);
        assert_eq!(&output_y, &expected_y);
    } else {
        let mut buffer = [0u8; 32];
        U256::zero().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&output_x[..], &[0u8; 32]);
        assert_eq!(&output_y[..], &[0u8; 32]);
    }

    (content, range)
}

fn ecadd_test_inner_from_raw(
    raw_input: &str,
    raw_x: &str,
    raw_y: &str,
    expect_ok: bool,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let input_bytes = hex::decode(raw_input).unwrap();
    let x1: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let y1: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let x2: [u8; 32] = input_bytes[64..96].try_into().unwrap();
    let y2: [u8; 32] = input_bytes[96..128].try_into().unwrap();

    let x: [u8; 32] = hex::decode(raw_x).unwrap().try_into().unwrap();
    let y: [u8; 32] = hex::decode(raw_y).unwrap().try_into().unwrap();

    ecadd_test_inner(x1, y1, x2, y2, expect_ok, x, y)
}

#[cfg(test)]
pub mod test {
    /// Tests whether the operation `P+Q=R` holds correctly for the given `P`,`Q`,`R`.
    #[test]
    fn test_valid() {
        use super::*;

        let raw_input = "099c07c9dd1107b9c9b0836da7ecfb7202d10bea1b8d1e88bc51ca476f23d91d28351e12f9219537fc8d6cac7c6444bd7980390d0d3e203fe0d8c1b0d811995021e177a985c3db8ef1d670629972c007ae90c78fb16e3011de1d08f5a44cb6550bd68a7caa07f6adbecbf06fb1f09d32b7bed1369a2a58058d1521bebd8272ac";
        let raw_x = "25beba7ab903d641d77e5801ca4d69a7a581359959c5d2621301dddafb145044";
        let raw_y = "19ee7a5ce8338bbcf4f74c3d3ec79d3635e837cb723ee6a0fa99269e3c6d7e23";
        let (content, range) = ecadd_test_inner_from_raw(raw_input, raw_x, raw_y, true);
        pretty_print_memory_dump(&content, range);
    }

    /// Tests whether the operation `P+Q=R` fails if either of P or Q is incorrect.
    #[test]
    fn test_invalid() {
        use super::*;

        // We "twist" one of the points from `test_valid` by a couple of bytes
        let raw_input = "099c08c9dd1107b9c9b0836da7ecfb7202d10bea1b8d1e88cc51ca476f23d91d28351e12f9219537fc8d6cac7c6444bd7980390d0d3e203fe0d8c1b0d811995021e177a985c3db8ef1d670629972c007ae90c78fb16e3011de1d08f5a44cb6550bd68a7caa07f6adbecbf06fb1f09d32b7bed1369a2a58058d1521bebd8272ac";
        let raw_x = "0000000000000000000000000000000000000000000000000000000000000000";
        let raw_y = "0000000000000000000000000000000000000000000000000000000000000000";
        let (content, range) = ecadd_test_inner_from_raw(raw_input, raw_x, raw_y, false);
        pretty_print_memory_dump(&content, range);
    }
}

