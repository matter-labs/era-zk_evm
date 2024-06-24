use super::*;
use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zkevm_opcode_defs::system_params::*;
use zkevm_opcode_defs::PrecompileCallABI;

fn fill_memory<M: Memory>(
    x1: [u8; 32],
    y1: [u8; 32],
    s: [u8; 32],
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
        value: U256::from_big_endian(&s),
        rw_flag: true,
        value_is_pointer: false,
    };
    let _ = memory.execute_partial_query(2, query);

    3 as u16
}

fn ecmul_test_inner(
    x1: [u8; 32],
    y1: [u8; 32],
    s: [u8; 32],
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
    let num_words_used = fill_memory(x1, y1, s, page_number, &mut memory);

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

    let address = Address::from_low_u64_be(ECMUL_INNER_FUNCTION_PRECOMPILE_ADDRESS as u64);

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

fn ecmul_test_inner_from_raw(
    raw_input: &str,
    raw_x: &str,
    raw_y: &str,
    expect_ok: bool,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let input_bytes = hex::decode(raw_input).unwrap();
    let x1: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let y1: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let s: [u8; 32] = input_bytes[64..96].try_into().unwrap();

    let x: [u8; 32] = hex::decode(raw_x).unwrap().try_into().unwrap();
    let y: [u8; 32] = hex::decode(raw_y).unwrap().try_into().unwrap();

    ecmul_test_inner(x1, y1, s, expect_ok, x, y)
}

#[cfg(test)]
pub mod test {
    /// Test for the ecmul precompile correctness. 
    /// Given a valid scalar `k` and point `P`, verifies that `[k]P` is calculated correctly.
    #[test]
    fn test_valid() {
        use super::*;

        let raw_input = "1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad0bac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d15f0e77d431a6c4d21df6a71cdcb0b2eeba21fc1192bd9801b8cd8b7c763e115";
        let raw_x = "15fac9de17d074fc56d9d679d5c011e90688d953b04edd1f82c469fc07a07648";
        let raw_y = "13de0f379fa2120d2caed4e79c43d67104e091783118c4a04d0250a317183c26";
        let (content, range) = ecmul_test_inner_from_raw(raw_input, raw_x, raw_y, true);
        pretty_print_memory_dump(&content, range);
    }

    /// Test that when provided with the wrong point `P`, the precompile returns an error.
    #[test]
    fn test_invalid() {
        use super::*;

        // We "twist" the point from `test_valid` by a couple of bytes to make it outside the curve.
        let raw_input = "1148f79e5364458dd22f5071480ae679d0b9df89d69e881f611e8381384ed1ad0bac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d15f0e77d431a6c4d21df6a71cdcb0b2eeba21fc1192bd9801b8cd8b7c763e115";
        let raw_x = "0000000000000000000000000000000000000000000000000000000000000000";
        let raw_y = "0000000000000000000000000000000000000000000000000000000000000000";
        let (content, range) = ecmul_test_inner_from_raw(raw_input, raw_x, raw_y, false);
        pretty_print_memory_dump(&content, range);
    }
}