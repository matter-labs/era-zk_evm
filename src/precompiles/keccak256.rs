use super::*;

pub const KECCAK_RATE_IN_U64_WORDS: usize = 17;
pub const MEMORY_READS_PER_CYCLE: usize = 5;
pub const MEMORY_WRITES_PER_CYCLE: usize = 1;
pub const NUM_WORDS_PER_QUERY: usize = 4;
pub const NEW_WORDS_PER_CYCLE: usize = NUM_WORDS_PER_QUERY * MEMORY_READS_PER_CYCLE;

// we need a buffer such that if we can not fill it in this block eventually it should
// also contain enough data to run another round function this time
pub const BUFFER_SIZE: usize = NEW_WORDS_PER_CYCLE + KECCAK_RATE_IN_U64_WORDS - 1;

// since NEW_WORDS_PER_CYCLE and KECCAK_RATE_IN_U64_WORDS are co-prime we will have remainders in a buffer like
// 0 - 3 - 6 - 9 - .... - 18 (here we can actually absorb), so there is no good trick to other than check
// if we skip or not memory reads at this cycle

// static_assertions::const_assert!(BUFFER_SIZE - NEW_WORDS_PER_CYCLE >= KECCAK_RATE_IN_U64_WORDS);

pub use sha3::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Keccak256RoundWitness {
    pub new_request: Option<LogQuery>,
    pub reads: Option<[MemoryQuery; MEMORY_READS_PER_CYCLE]>,
    pub writes: Option<[MemoryQuery; MEMORY_WRITES_PER_CYCLE]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Keccak256Precompile<const B: bool>;

impl<const B: bool> crate::abstractions::Precompile for Keccak256Precompile<B> {
    type CycleWitness = Keccak256RoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)> {
        let precompile_call_params = query;
        // read the parameters
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

        let mut input_buffer = Buffer::new();
        let mut words_buffer = [0u64; NEW_WORDS_PER_CYCLE];

        let mut internal_state = Keccak256::default();

        for round in 0..num_rounds {
            let mut round_witness = Keccak256RoundWitness {
                new_request: None,
                reads: None,
                writes: None,
            };

            if B && round == 0 {
                round_witness.new_request = Some(precompile_call_params);
            }

            // fill the buffer if we can
            if input_buffer.can_read_into() {
                let mut reads = [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE];

                for query_index in 0..MEMORY_READS_PER_CYCLE {
                    let data_query = MemoryQuery {
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
                    let data_query =
                        memory.execute_partial_query(monotonic_cycle_counter, data_query);
                    let data = data_query.value;
                    if B {
                        reads[query_index] = data_query;
                        read_queries.push(data_query);
                    }
                    let mut bytes32_buffer = [0u8; 32];
                    data.to_big_endian(&mut bytes32_buffer[..]);
                    // revert endianess and push
                    for (i, chunk) in bytes32_buffer.chunks(8).enumerate() {
                        let as_u64 = u64::from_le_bytes(chunk.try_into().unwrap());
                        words_buffer[query_index * NUM_WORDS_PER_QUERY + i] = as_u64;
                    }

                    current_read_offset += 1;
                }

                if B {
                    round_witness.reads = Some(reads);
                }

                input_buffer.append(&words_buffer);
            }

            // always consume rate and run keccak round function
            let words = input_buffer.consume_rate();
            let mut block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];

            for (i, word) in words.into_iter().enumerate() {
                block[(i * 8)..(i * 8 + 8)].copy_from_slice(&word.to_le_bytes());
            }
            internal_state.update(&block);

            let is_last = round == num_rounds - 1;

            if is_last {
                let state_inner = transmute_state(internal_state.clone());

                // take hash and properly set endianess for the output word
                let mut hash_as_bytes32 = [0u8; 32];
                hash_as_bytes32[0..8].copy_from_slice(&state_inner[0].to_le_bytes());
                hash_as_bytes32[8..16].copy_from_slice(&state_inner[1].to_le_bytes());
                hash_as_bytes32[16..24].copy_from_slice(&state_inner[2].to_le_bytes());
                hash_as_bytes32[24..32].copy_from_slice(&state_inner[3].to_le_bytes());
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

                if B {
                    round_witness.writes = Some([result_query]);
                    write_queries.push(result_query);
                }
            }

            witness.push(round_witness);
        }

        if B {
            Some((read_queries, write_queries, witness))
        } else {
            None
        }
    }
}

pub struct Buffer {
    pub words: [u64; BUFFER_SIZE],
    pub filled: usize,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            words: [0u64; BUFFER_SIZE],
            filled: 0,
        }
    }

    pub fn reset(&mut self) {
        self.words = [0u64; BUFFER_SIZE];
        self.filled = 0;
    }

    pub fn can_read_into(&self) -> bool {
        self.filled <= BUFFER_SIZE - NEW_WORDS_PER_CYCLE
    }

    pub fn append(&mut self, data: &[u64; NEW_WORDS_PER_CYCLE]) {
        debug_assert!(
            self.filled <= BUFFER_SIZE - NEW_WORDS_PER_CYCLE,
            "have {} words filled, but the limit is {}",
            self.filled,
            BUFFER_SIZE - NEW_WORDS_PER_CYCLE
        );
        self.words[self.filled..(self.filled + NEW_WORDS_PER_CYCLE)].copy_from_slice(&data[..]);
        self.filled += NEW_WORDS_PER_CYCLE;
    }

    pub fn consume_rate(&mut self) -> [u64; KECCAK_RATE_IN_U64_WORDS] {
        debug_assert!(self.filled >= KECCAK_RATE_IN_U64_WORDS);
        let taken = self.words[..KECCAK_RATE_IN_U64_WORDS].try_into().unwrap();
        self.filled -= KECCAK_RATE_IN_U64_WORDS;
        let mut tmp = [0u64; BUFFER_SIZE];
        tmp[..(BUFFER_SIZE - KECCAK_RATE_IN_U64_WORDS)]
            .copy_from_slice(&self.words[KECCAK_RATE_IN_U64_WORDS..]);
        self.words = tmp;

        taken
    }
}

pub fn keccak256_rounds_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> Option<(
    Vec<MemoryQuery>,
    Vec<MemoryQuery>,
    Vec<Keccak256RoundWitness>,
)> {
    let mut processor = Keccak256Precompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

pub type Keccak256InnerState = [u64; 25];

struct BlockBuffer {
    _buffer: [u8; 136],
    _pos: u8,
}

struct CoreWrapper {
    core: Keccak256VarCore,
    _buffer: BlockBuffer,
}

struct Keccak256VarCore {
    state: Keccak256InnerState,
}

static_assertions::assert_eq_size!(Keccak256, CoreWrapper);

pub fn transmute_state(reference_state: Keccak256) -> Keccak256InnerState {
    // we use a trick that size of both structures is the same, and even though we do not know a stable field layout,
    // we can replicate it
    let our_wrapper: CoreWrapper = unsafe { std::mem::transmute(reference_state) };

    our_wrapper.core.state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        let mut hasher = Keccak256::new();
        hasher.update(&[]);
        let result = hasher.finalize();
        println!("Empty string hash = {}", hex::encode(result.as_slice()));

        let mut our_hasher = Keccak256::default();
        let mut block = [0u8; 136];
        block[0] = 0x01;
        block[135] = 0x80;
        our_hasher.update(&block);
        let state_inner = transmute_state(our_hasher);
        for (idx, el) in state_inner.iter().enumerate() {
            println!("Element {} = 0x{:016x}", idx, el);
        }
    }
}
