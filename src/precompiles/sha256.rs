use super::*;

// for sha256 we do not need complicated buffering as it uses 64 bytes per round, and this is divisible
// by our 32 byte per query

pub const MEMORY_READS_PER_CYCLE: usize = 2;
pub const MEMORY_WRITES_PER_CYCLE: usize = 1;

pub use sha2::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sha256RoundWitness {
    pub new_request: Option<LogQuery>,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: Option<[MemoryQuery; MEMORY_WRITES_PER_CYCLE]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sha256Precompile<const B: bool>;

impl<const B: bool> crate::abstractions::Precompile for Sha256Precompile<B> {
    type CycleWitness = Sha256RoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)> {
        let precompile_call_params = query;
        let params = precompile_abi_in_log(precompile_call_params);
        let timestamp_to_read = precompile_call_params.timestamp;
        let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1); // our default timestamping agreement

        let num_rounds = params.precompile_interpreted_data as usize;
        let source_memory_page = params.memory_page_to_read;
        let destination_memory_page = params.memory_page_to_write;
        let mut current_read_offset = params.input_memory_offset;
        let write_offset = params.output_memory_offset;

        let mut read_queries = if B {
            Vec::with_capacity(MEMORY_READS_PER_CYCLE * num_rounds)
        } else {
            vec![]
        };

        let mut write_queries = if B {
            Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
        } else {
            vec![]
        };

        let mut witness = if B {
            Vec::with_capacity(num_rounds)
        } else {
            vec![]
        };

        let mut internal_state = Sha256::default();
        for round in 0..num_rounds {
            let mut block = [0u8; 64];

            let mut reads = [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE];
            for query_index in 0..MEMORY_READS_PER_CYCLE {
                let query = MemoryQuery {
                    timestamp: timestamp_to_read,
                    location: MemoryLocation {
                        memory_type: MemoryType::Heap,
                        page: MemoryPage(source_memory_page),
                        index: MemoryIndex(current_read_offset),
                    },
                    value: U256::zero(),
                    value_is_pointer: false,
                    rw_flag: false,
                    is_pended: false,
                };

                let query = memory.execute_partial_query(monotonic_cycle_counter, query);
                current_read_offset += 1;
                if B {
                    read_queries.push(query);
                }

                reads[query_index] = query;
                let data = query.value;
                data.to_big_endian(&mut block[(query_index * 32)..(query_index * 32 + 32)]);
            }

            // run round function
            internal_state.update(&block);

            let is_last = round == num_rounds - 1;

            let mut round_witness = Sha256RoundWitness {
                new_request: None,
                reads,
                writes: None,
            };

            if round == 0 {
                round_witness.new_request = Some(precompile_call_params);
            }

            if is_last {
                // let state_inner = transmute_state(internal_state.clone()).inner;
                let state_inner = transmute_state(internal_state.clone());
                // take hash and properly set endianess for the output word
                let mut hash_as_bytes32 = [0u8; 32];
                for (chunk, state_word) in
                    hash_as_bytes32.chunks_mut(4).zip(state_inner.into_iter())
                {
                    chunk.copy_from_slice(&state_word.to_be_bytes());
                }
                let as_u256 = U256::from_big_endian(&hash_as_bytes32);

                let write_location = MemoryLocation {
                    memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                    page: MemoryPage(destination_memory_page),
                    index: MemoryIndex(write_offset),
                };

                let result_query = MemoryQuery {
                    timestamp: timestamp_to_write,
                    location: write_location,
                    value: as_u256,
                    value_is_pointer: false,
                    rw_flag: true,
                    is_pended: false,
                };
                let result_query =
                    memory.execute_partial_query(monotonic_cycle_counter, result_query);
                round_witness.writes = Some([result_query]);

                if B {
                    write_queries.push(result_query);
                }
            }

            if B {
                witness.push(round_witness);
            }
        }

        if B {
            Some((read_queries, write_queries, witness))
        } else {
            None
        }
    }
}

pub fn sha256_rounds_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Sha256RoundWitness>)> {
    let mut processor = Sha256Precompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

pub type Sha256InnerState = [u32; 8];

struct BlockBuffer {
    _buffer: [u8; 64],
    _pos: u8,
}

struct CoreWrapper {
    core: Sha256VarCore,
    _buffer: BlockBuffer,
}

struct Sha256VarCore {
    state: Sha256InnerState,
    _block_len: u64,
}

static_assertions::assert_eq_size!(Sha256, CoreWrapper);

pub fn transmute_state(reference_state: Sha256) -> Sha256InnerState {
    // we use a trick that size of both structures is the same, and even though we do not know a stable field layout,
    // we can replicate it
    let our_wrapper: CoreWrapper = unsafe { std::mem::transmute(reference_state) };

    our_wrapper.core.state
}
