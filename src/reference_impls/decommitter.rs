use zk_evm_abstractions::aux::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zk_evm_abstractions::zkevm_opcode_defs::BlobSha256Format;
use zk_evm_abstractions::zkevm_opcode_defs::ContractCodeSha256Format;
use zk_evm_abstractions::zkevm_opcode_defs::VersionedHashLen32;
use zk_evm_abstractions::zkevm_opcode_defs::VersionedHashNormalizedPreimage;

use super::*;

pub const MEMORY_CELLS_PER_PAGE: usize = (1 << 16) - 1;

#[derive(Debug)]
pub struct SimpleDecommitter<const B: bool> {
    known_hashes: HashMap<VersionedHashNormalizedPreimage, Vec<U256>>,
    history: HashMap<VersionedHashNormalizedPreimage, (u32, u16)>,
}

impl<const B: bool> SimpleDecommitter<B> {
    pub fn new() -> Self {
        Self {
            known_hashes: HashMap::default(),
            history: HashMap::default(),
        }
    }

    pub fn populate(&mut self, elements: Vec<(U256, Vec<U256>)>) {
        let mut buffer = [0u8; 32];
        for (hash, values) in elements.into_iter() {
            hash.to_big_endian(&mut buffer);
            let normalized = if ContractCodeSha256Format::is_valid(&buffer) {
                let (_, normalized) = ContractCodeSha256Format::normalize_for_decommitment(&buffer);
                normalized
            } else if BlobSha256Format::is_valid(&buffer) {
                let (_, normalized) = BlobSha256Format::normalize_for_decommitment(&buffer);
                normalized
            } else {
                panic!("Unknown versioned hash format {:?}", hash);
            };
            assert!(!self.known_hashes.contains_key(&normalized));
            self.known_hashes.insert(normalized, values);
        }
    }
}

impl<const B: bool> DecommittmentProcessor for SimpleDecommitter<B> {
    #[track_caller]
    fn prepare_to_decommit(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut partial_query: DecommittmentQuery,
    ) -> anyhow::Result<DecommittmentQuery> {
        if let Some((old_page, old_len)) = self
            .history
            .get(&partial_query.normalized_preimage)
            .copied()
        {
            partial_query.is_fresh = false;
            partial_query.memory_page = MemoryPage(old_page);
            partial_query.decommitted_length = old_len;

            Ok(partial_query)
        } else {
            // fresh one
            let values = self
                .known_hashes
                .get(&partial_query.normalized_preimage)
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Code hash {:?} must be known",
                        &partial_query.normalized_preimage
                    )
                })?;
            partial_query.decommitted_length = values.len() as u16;
            partial_query.is_fresh = true;

            Ok(partial_query)
        }
    }

    #[track_caller]
    fn decommit_into_memory<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        partial_query: DecommittmentQuery,
        memory: &mut M,
    ) -> anyhow::Result<Option<Vec<U256>>> {
        assert!(partial_query.is_fresh);
        // fresh one
        let values = self
            .known_hashes
            .get(&partial_query.normalized_preimage)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Code hash {:?} must be known",
                    &partial_query.normalized_preimage
                )
            })?;
        assert_eq!(partial_query.decommitted_length, values.len() as u16);
        let page_to_use = partial_query.memory_page;
        let timestamp = partial_query.timestamp;
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
        };

        // update history
        let existing = self.history.insert(
            partial_query.normalized_preimage,
            (
                partial_query.memory_page.0,
                partial_query.decommitted_length,
            ),
        );
        assert!(existing.is_none());

        if B {
            for (i, value) in values.iter().enumerate() {
                tmp_q.location.index = MemoryIndex(i as u32);
                tmp_q.value = *value;
                memory.specialized_code_query(monotonic_cycle_counter, tmp_q);
            }

            Ok(Some(values))
        } else {
            for (i, value) in values.into_iter().enumerate() {
                tmp_q.location.index = MemoryIndex(i as u32);
                tmp_q.value = value;
                memory.specialized_code_query(monotonic_cycle_counter, tmp_q);
            }

            Ok(None)
        }
    }
}
