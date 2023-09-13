use super::*;

use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::MemoryQuery;
use zk_evm_abstractions::vm::Memory;
use zk_evm_abstractions::vm::MemoryType;
use zk_evm_abstractions::vm::PrecompilesProcessor;
use zkevm_opcode_defs::PrecompileCallABI;

fn bytes_to_u256_words(input: Vec<u8>, unalignement: usize) -> Vec<U256> {
    let mut result = vec![];
    let mut it = std::iter::repeat(0xffu8)
        .take(unalignement)
        .chain(input.into_iter());
    'outer: loop {
        let mut done = false;
        let mut buffer = [0u8; 32];
        for (idx, dst) in buffer.iter_mut().enumerate() {
            if let Some(src) = it.next() {
                *dst = src;
            } else {
                done = true;
                if idx == 0 {
                    break 'outer;
                }
                break;
            }
        }
        let el = U256::from_big_endian(&buffer);
        result.push(el);
        if done {
            break 'outer;
        }
    }

    result
}

fn pad_and_fill_memory<M: Memory>(
    input: &[u8],
    page: u32,
    memory: &mut M,
    unalignment: u32,
) -> u32 {
    let input = input.to_vec();
    let words = bytes_to_u256_words(input, unalignment as usize);
    let mut index = 0u32;
    let num_words = words.len() as u32;

    for word in words.into_iter() {
        let location = MemoryLocation {
            page: MemoryPage(page),
            index: MemoryIndex(index),
            memory_type: MemoryType::Heap,
        };
        let num_rounds_query = MemoryQuery {
            timestamp: Timestamp(0u32),
            location,
            value: word,
            value_is_pointer: false,
            rw_flag: true,
        };

        let _ = memory.execute_partial_query(1, num_rounds_query);
        index += 1;
    }

    num_words
}

use sha3::Digest;
use sha3::Keccak256;

fn run_keccak256_test_inner(
    input: &[u8],
    unalignment: u32,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let mut memory = SimpleMemory::new();

    let input_memory_page = 4u32;
    let output_memory_page = 4u32;

    memory.heaps.push((
        (input_memory_page, vec![U256::zero(); 1 << 10]),
        (0, vec![U256::zero(); 0]),
    ));
    memory.page_numbers_indirections.insert(
        input_memory_page,
        reference_impls::memory::Indirection::Heap(1),
    );
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;

    let mut hasher = Keccak256::default();
    hasher.update(input);
    let result = hasher.finalize();
    let expected_output: &[u8] = result.as_ref();

    // fill the memory
    let num_words_used = pad_and_fill_memory(input, input_memory_page, &mut memory, unalignment);
    let input_byte_offset = unalignment;
    let input_length = input.len();

    let precompile_abi = PrecompileCallABI {
        input_memory_offset: input_byte_offset,
        input_memory_length: input_length as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 0,
        memory_page_to_read: input_memory_page,
        memory_page_to_write: output_memory_page,
        precompile_interpreted_data: 0,
    };

    let address =
        *zkevm_opcode_defs::system_params::KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS;

    let precompile_query = LogQuery {
        timestamp: Timestamp(1),
        tx_number_in_block: 0,
        shard_id: 0,
        aux_byte: zkevm_opcode_defs::system_params::PRECOMPILE_AUX_BYTE,
        address,
        key: precompile_abi.to_u256(),
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let _ = precompiles_processor.execute_precompile(4, precompile_query, &mut memory);

    let range = 0u32..(num_words_used + 1);
    let content = memory.dump_page_content(output_memory_page, range.clone());
    let output = content.last().copied().unwrap();

    dbg!(hex::encode(&expected_output));
    dbg!(hex::encode(&output));

    assert_eq!(&expected_output[..], &output[..]);

    (content, range)
}

#[test]
fn test_empty_keccak256() {
    let (content, range) = run_keccak256_test_inner(&[], 0);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_empty_keccak256_unaligned() {
    let (content, range) = run_keccak256_test_inner(&[], 31);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_one_round_of_keccak256() {
    let data = vec![123u8; 50];
    let (content, range) = run_keccak256_test_inner(&data, 0);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_one_round_of_keccak256_unaligned() {
    let data = vec![123u8; 50];
    let (content, range) = run_keccak256_test_inner(&data, 31);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_one_round_of_keccak256_with_full_paddings() {
    let data = vec![123u8; 136];
    let (content, range) = run_keccak256_test_inner(&data, 0);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_one_round_of_keccak256_with_full_paddings_unaligned() {
    let data = vec![123u8; 136];
    let (content, range) = run_keccak256_test_inner(&data, 31);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_two_rounds_of_keccak256() {
    let data = vec![123u8; 200];
    let (content, range) = run_keccak256_test_inner(&data, 0);
    pretty_print_memory_dump(&content, range);
}

#[test]
fn test_two_rounds_of_keccak256_unaligned() {
    let data = vec![123u8; 200];
    let (content, range) = run_keccak256_test_inner(&data, 31);
    pretty_print_memory_dump(&content, range);
}
