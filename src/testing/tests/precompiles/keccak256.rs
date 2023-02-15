use super::*;

use crate::precompiles::keccak256::*;

fn pad_and_fill_memory<M: Memory>(input: &[u8], page: u32, memory: &mut M) -> u16 {
    let mut padded = vec![];
    padded.extend_from_slice(input);

    let block_size = KECCAK_RATE_IN_U64_WORDS * 8;
    let last_block_size = padded.len() % block_size;
    let padlen = block_size - last_block_size;
    if padlen == 1 {
        padded.push(0x81);
    } else {
        padded.push(0x01);
        padded.extend(std::iter::repeat(0u8).take(padlen - 2));
        padded.push(0x80);
    }
   
    assert_eq!(padded.len() % block_size, 0);

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

    let total_len_as_u64_words = padded.len() / 8;
    let mut num_words = total_len_as_u64_words / 4;
    if total_len_as_u64_words % 4 != 0 {
        num_words += 1;
    }

    let mut chunk_iter = padded.chunks_exact(8);

    for _word in 0..num_words {
        location.index.0 += 1;
        let mut value = U256::zero();
        for i in (0..4).rev() {
            if let Some(chunk) = chunk_iter.next() {
                let as_u64 = u64::from_be_bytes(chunk.try_into().unwrap());
                value.0[i] = as_u64;
            }
        }

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

use sha3::Digest;
use sha3::Keccak256;

fn run_keccak256_test_inner(input: &[u8]) -> (Vec<[u8; 32]>, std::ops::Range<u16>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;

    let mut hasher = Keccak256::default();
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

    let address = Address::from_low_u64_be(KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS as u64);

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
fn test_empty_keccak256() {
    let (content, range) = run_keccak256_test_inner(&[]);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_few_rounds_of_keccak256() {
    let data = vec![255u8; 256];
    let (content, range) = run_keccak256_test_inner(&data);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_very_long_keccak256() {
    let data = vec![255u8; 10_000];
    let (content, range) = run_keccak256_test_inner(&data);
    pretty_print_memory_dump(&content, range);
}