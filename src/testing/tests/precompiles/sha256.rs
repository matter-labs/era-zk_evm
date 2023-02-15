use super::*;

use crate::precompiles::sha256::*;

fn pad_and_fill_memory<M: Memory>(input: &[u8], page: u32, memory: &mut M) -> u16 {
    let mut padded = vec![];
    padded.extend_from_slice(input);

    let block_size = 64;

    let message_bitlen = (padded.len() * 8) as u64;
    let last_block_size = padded.len() % block_size;

    let (num_of_zero_bytes, _pad_overflowed) = if last_block_size <= (64 - 1 - 8) {
        (64 - 1 - 8 - last_block_size, false)
    }
    else {
        (128 - 1 - 8 - last_block_size, true)
    };
    
    padded.push(1u8 << 7);
    padded.extend(std::iter::repeat(0u8).take(num_of_zero_bytes));

    // represent L as big integer number:
    let repr = message_bitlen.to_be_bytes();
    padded.extend(repr.into_iter());
    assert_eq!(padded.len() % block_size, 0);

    // number of words to put the data
    let num_words = padded.len() / 32;

    // number of rounds of invocation
    let num_rounds = padded.len() / block_size;

    let mut num_rounds_u256 = U256::zero();
    num_rounds_u256.0[0] = num_rounds as u64;
    println!("Num rounds = {}", num_rounds_u256);
    let mut location = MemoryLocation {page: MemoryPage(page), index: MemoryIndex(0)};
    let num_rounds_query = MemoryQuery {
        timestamp: Timestamp(0u32),
        location,
        value: num_rounds_u256,
        rw_flag: true
    };

    let _ = memory.execute_partial_query(num_rounds_query);

    let mut chunk_iter = padded.chunks_exact(32);
    assert_eq!(chunk_iter.len(), num_words);

    for word_bytes in &mut chunk_iter {
        location.index.0 += 1;
        let value = U256::from_big_endian(word_bytes);
        let data_query = MemoryQuery {
            timestamp: Timestamp(0u32),
            location,
            value,
            rw_flag: true
        };

        let _ = memory.execute_partial_query(data_query);
    }

    assert!(chunk_iter.remainder().len() == 0);

    (1 + num_words) as u16
}

use sha2::*;

fn run_sha256_test_inner(input: &[u8]) -> (Vec<[u8; 32]>, std::ops::Range<u16>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;

    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize();
    let bytes: &[u8] = result.as_ref();
    println!("{}", hex::encode(bytes));

    // fill the memory
    let num_words_used = pad_and_fill_memory(input, 0u32, &mut memory);

    let precompile_call_params = PrecompileCallParams {
        input_location: MemoryLocation {page: MemoryPage(0u32), index: MemoryIndex(0u16)},
        output_location: MemoryLocation {page: MemoryPage(0u32), index: MemoryIndex(num_words_used)},
        timestamp_for_input_read: Timestamp(1u32),
        timestamp_for_output_write: Timestamp(2u32),
    };

    let address = Address::from_low_u64_be(SHA256_ROUND_FUNCTION_PRECOMPILE_ADDRESS as u64);

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

    let range = 0u16..(num_words_used + 1);
    let content = memory.dump_page_content(0u32, range.clone());
    let expected_output = content.last().copied().unwrap();

    assert_eq!(&expected_output[..], bytes);

    (content, range)
}

#[test]
fn test_empty_sha256() {
    let (content, range) = run_sha256_test_inner(&[]);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_few_rounds_of_sha256() {
    let data = vec![255u8; 256];
    let (content, range) = run_sha256_test_inner(&data);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_very_long_sha256() {
    let data = vec![255u8; 10_000];
    let (content, range) = run_sha256_test_inner(&data);
    pretty_print_memory_dump(&content, range);
}