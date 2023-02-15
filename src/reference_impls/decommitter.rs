use super::*;

pub const MEMORY_CELLS_PER_PAGE: usize = (1 << 16) - 1;

#[derive(Debug)]
pub struct SimpleDecommitter<const B: bool> {
    known_hashes: HashMap<U256, Vec<U256>>,
    history: HashMap<U256, (u32, u16)>,
}

impl<const B: bool> SimpleDecommitter<B> {
    pub fn new() -> Self {
        Self {
            known_hashes: HashMap::default(),
            history: HashMap::default(),
        }
    }

    pub fn populate(&mut self, elements: Vec<(U256, Vec<U256>)>) {
        for (hash, values) in elements.into_iter() {
            assert!(!self.known_hashes.contains_key(&hash));
            self.known_hashes.insert(hash, values);
        }
    }
}

impl<const B: bool> DecommittmentProcessor for SimpleDecommitter<B> {
    fn decommit_into_memory<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        mut partial_query: DecommittmentQuery,
        memory: &mut M,
    ) -> (DecommittmentQuery, Option<Vec<U256>>) {
        if let Some((old_page, old_len)) = self.history.get(&partial_query.hash).copied() {
            partial_query.is_fresh = false;
            partial_query.memory_page = MemoryPage(old_page);
            partial_query.decommitted_length = old_len;

            if B {
                (partial_query, Some(vec![])) // empty extra data
            } else {
                (partial_query, None)
            }
        } else {
            // fresh one
            let values = self
                .known_hashes
                .get(&partial_query.hash)
                .cloned()
                .expect(&format!(
                    "Code hash {:?} must be known",
                    &partial_query.hash
                ));
            let page_to_use = partial_query.memory_page;
            let timestamp = partial_query.timestamp;
            partial_query.decommitted_length = values.len() as u16;
            partial_query.is_fresh = true;
            // write into memory
            let mut tmp_q = MemoryQuery {
                timestamp,
                location: MemoryLocation {
                    memory_type: MemoryType::Code,
                    page: page_to_use,
                    index: MemoryIndex(0),
                },
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: true,
                is_pended: false,
            };

            self.history.insert(
                partial_query.hash,
                (
                    partial_query.memory_page.0,
                    partial_query.decommitted_length,
                ),
            );
            if B {
                for (i, value) in values.iter().enumerate() {
                    tmp_q.location.index = MemoryIndex(i as u32);
                    tmp_q.value = *value;
                    memory.specialized_code_query(monotonic_cycle_counter, tmp_q);
                }

                (partial_query, Some(values))
            } else {
                for (i, value) in values.into_iter().enumerate() {
                    tmp_q.location.index = MemoryIndex(i as u32);
                    tmp_q.value = value;
                    memory.specialized_code_query(monotonic_cycle_counter, tmp_q);
                }

                (partial_query, None)
            }
        }
    }
}
