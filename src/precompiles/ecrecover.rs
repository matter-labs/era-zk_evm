use super::*;

// we need hash, r, s, v
pub const MEMORY_READS_PER_CYCLE: usize = 4;
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

use k256::ecdsa::*;
use sha2::Digest;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECRecoverRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECRecoverPrecompile<const B: bool>;

impl<const B: bool> crate::abstractions::Precompile for ECRecoverPrecompile<B> {
    type CycleWitness = ECRecoverRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)> {
        // read the parameters
        let precompile_call_params = query;
        let params = precompile_abi_in_log(precompile_call_params);
        let timestamp_to_read = precompile_call_params.timestamp;
        let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1); // our default timestamping agreement

        let mut current_read_location = MemoryLocation {
            memory_type: MemoryType::Heap, // we default for some value, here it's not that important
            page: MemoryPage(params.memory_page_to_read),
            index: MemoryIndex(params.input_memory_offset),
        };

        // we assume that we have
        // - hash of the message
        // - r
        // - s
        // - v as a single byte

        // we do 6 queries per precompile
        let mut read_history = if B {
            Vec::with_capacity(MEMORY_READS_PER_CYCLE)
        } else {
            vec![]
        };
        let mut write_history = if B {
            Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
        } else {
            vec![]
        };

        let mut round_witness = ECRecoverRoundWitness {
            new_request: precompile_call_params,
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            writes: [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE],
        };

        let mut read_idx = 0;

        let hash_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
            is_pended: false,
        };
        let hash_query = memory.execute_partial_query(monotonic_cycle_counter, hash_query);
        let hash_value = hash_query.value;
        if B {
            round_witness.reads[read_idx] = hash_query;
            read_idx += 1;
            read_history.push(hash_query);
        }

        current_read_location.index.0 += 1;
        let v_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
            is_pended: false,
        };
        let v_query = memory.execute_partial_query(monotonic_cycle_counter, v_query);
        let v_value = v_query.value;
        if B {
            round_witness.reads[read_idx] = v_query;
            read_idx += 1;
            read_history.push(v_query);
        }

        current_read_location.index.0 += 1;
        let r_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
            is_pended: false,
        };
        let r_query = memory.execute_partial_query(monotonic_cycle_counter, r_query);
        let r_value = r_query.value;
        if B {
            round_witness.reads[read_idx] = r_query;
            read_idx += 1;
            read_history.push(r_query);
        }

        current_read_location.index.0 += 1;
        let s_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
            is_pended: false,
        };
        let s_query = memory.execute_partial_query(monotonic_cycle_counter, s_query);
        let s_value = s_query.value;
        if B {
            round_witness.reads[read_idx] = s_query;
            read_history.push(s_query);
        }
        // read everything as bytes for ecrecover purposes

        let mut buffer = [0u8; 32];
        hash_value.to_big_endian(&mut buffer[..]);
        let hash = buffer;

        r_value.to_big_endian(&mut buffer[..]);
        let r_bytes = buffer;

        s_value.to_big_endian(&mut buffer[..]);
        let s_bytes = buffer;

        v_value.to_big_endian(&mut buffer[..]);
        let v = buffer[31];
        assert!(v == 0 || v == 1);

        let mut serialized = Vec::with_capacity(65);
        serialized.extend(r_bytes);
        serialized.extend(s_bytes);
        serialized.push(v);

        let pk = ecrecover_inner(hash, serialized);

        // here it may be possible to have non-recoverable k*G point, so can fail
        if let Ok(recovered_pubkey) = pk {
            let pk = k256::PublicKey::from(&recovered_pubkey);
            let affine_point = pk.as_affine().clone();
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let pk_bytes = affine_point.to_encoded_point(false);
            let pk_bytes_ref: &[u8] = pk_bytes.as_ref();
            assert_eq!(pk_bytes_ref.len(), 65);
            debug_assert_eq!(pk_bytes_ref[0], 0x04);
            let address_hash = sha3::Keccak256::digest(&pk_bytes_ref[1..]);

            let mut address = [0u8; 32];
            let hash_ref: &[u8] = address_hash.as_ref();
            address[12..].copy_from_slice(&hash_ref[12..]);

            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            let ok_marker = U256::one();
            let ok_or_err_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: ok_marker,
                value_is_pointer: false,
                rw_flag: true,
                is_pended: false,
            };
            let ok_or_err_query =
                memory.execute_partial_query(monotonic_cycle_counter, ok_or_err_query);

            write_location.index.0 += 1;
            let result = U256::from_big_endian(&address);
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: result,
                value_is_pointer: false,
                rw_flag: true,
                is_pended: false,
            };
            let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = result_query;
                write_history.push(ok_or_err_query);
                write_history.push(result_query);
            }
        } else {
            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            let err_marker = U256::zero();
            let ok_or_err_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: err_marker,
                value_is_pointer: false,
                rw_flag: true,
                is_pended: false,
            };
            let ok_or_err_query =
                memory.execute_partial_query(monotonic_cycle_counter, ok_or_err_query);

            write_location.index.0 += 1;
            let empty_result = U256::zero();
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: empty_result,
                value_is_pointer: false,
                rw_flag: true,
                is_pended: false,
            };
            let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = result_query;
                write_history.push(ok_or_err_query);
                write_history.push(result_query);
            }
        }

        if B {
            Some((read_history, write_history, vec![round_witness]))
        } else {
            None
        }
    }
}

pub fn ecrecover_inner(
    digest: [u8; 32],
    serialized_signature: Vec<u8>,
) -> Result<VerifyingKey, ()> {
    if digest.iter().all(|el| *el == 0) {
        // zero hash is not supported by our convension
        return Err(());
    }
    // we expect pre-validation, so this check always works
    let sig =
        k256::ecdsa::recoverable::Signature::try_from(&serialized_signature[..]).map_err(|_| ())?;
    let mut hash_array = k256::FieldBytes::default();
    let hash_array_mut_ref: &mut [u8] = hash_array.as_mut();
    hash_array_mut_ref.copy_from_slice(&digest);

    sig.recover_verifying_key_from_digest_bytes(&hash_array)
        .map_err(|_| ())
}

pub fn ecrecover_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> Option<(
    Vec<MemoryQuery>,
    Vec<MemoryQuery>,
    Vec<ECRecoverRoundWitness>,
)> {
    let mut processor = ECRecoverPrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}
