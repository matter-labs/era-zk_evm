use super::ApplicationData;
use super::*;

#[derive(Debug, Clone)]
pub struct InMemoryStorage {
    pub inner: [HashMap<Address, HashMap<U256, U256>>; NUM_SHARDS],
    pub cold_warm_markers: [HashMap<Address, HashSet<U256>>; NUM_SHARDS],
    pub frames_stack: Vec<ApplicationData<LogQuery>>,
}

// as usual, if we rollback the current frame then we apply changes to storage immediately,
// otherwise we carry rollbacks to the parent's frames

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            inner: [(); NUM_SHARDS].map(|_| HashMap::default()),
            cold_warm_markers: [(); NUM_SHARDS].map(|_| HashMap::default()),
            frames_stack: vec![ApplicationData::empty()],
        }
    }

    pub fn populate(&mut self, elements: Vec<(u8, Address, U256, U256)>) {
        for (shard_id, address, key, value) in elements.into_iter() {
            let shard_level_map = &mut self.inner[shard_id as usize];
            let address_level_map = shard_level_map.entry(address).or_default();
            address_level_map.insert(key, value);
        }
    }

    pub fn flatten_and_net_history(
        mut self,
    ) -> (Vec<LogQuery>, HashMap<(u8, Address, U256), Vec<LogQuery>>) {
        assert_eq!(
            self.frames_stack.len(),
            1,
            "there must exist an initial keeper frame"
        );
        let full_history = self.frames_stack.pop().unwrap();
        // we forget rollbacks as we have finished the execution and can just apply them
        let ApplicationData {
            forward,
            rollbacks: _,
        } = full_history;
        let history = forward.clone();
        // we want to have net queries for every storage slot
        let mut tmp = HashMap::<(u8, Address, U256), Vec<LogQuery>>::with_capacity(forward.len());

        // note that we only use "forward" part and discard the rollbacks at the end,
        // since if rollbacks of parents were not appended anywhere we just still keep them
        for el in forward.into_iter() {
            let LogQuery {
                timestamp,
                shard_id,
                address,
                key,
                rollback,
                ..
            } = &el;

            let entry = tmp.entry((*shard_id, *address, *key)).or_insert(vec![]);
            if let Some(last) = entry.last() {
                // forward application always has monotonic time
                if !rollback {
                    assert!(timestamp.0 > last.timestamp.0);
                }
            }

            entry.push(el);
        }

        (history, tmp)
    }
}

impl Storage for InMemoryStorage {
    fn estimate_refunds_for_write(
        &mut self,
        _monotonic_cycle_counter: u32,
        _partial_query: &LogQuery,
    ) -> RefundType {
        RefundType::None
    }

    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut query: LogQuery,
    ) -> LogQuery {
        let shard_level_map = &mut self.inner[query.shard_id as usize];
        let shard_level_warm_map = &mut self.cold_warm_markers[query.shard_id as usize];
        let frame_data = self.frames_stack.last_mut().expect("frame must be started");

        assert!(!query.rollback);
        if query.rw_flag {
            // write, also append rollback
            let address_level_map = shard_level_map.entry(query.address).or_default();
            let current_value = address_level_map
                .get(&query.key)
                .copied()
                .unwrap_or(U256::zero());
            address_level_map.insert(query.key, query.written_value);

            // mark as warm, and return
            let address_level_warm_map = shard_level_warm_map.entry(query.address).or_default();
            let warm = address_level_warm_map.contains(&query.key);
            if !warm {
                address_level_warm_map.insert(query.key);
            }
            query.read_value = current_value;

            frame_data.forward.push(query);
            query.rollback = true;
            frame_data.rollbacks.push(query);
            query.rollback = false;

            query
        } else {
            // read, do not append to rollback
            let address_level_map = shard_level_map.entry(query.address).or_default();
            let current_value = address_level_map
                .get(&query.key)
                .copied()
                .unwrap_or(U256::zero());
            // mark as warm, and return
            let address_level_warm_map = shard_level_warm_map.entry(query.address).or_default();
            let warm = address_level_warm_map.contains(&query.key);
            if !warm {
                address_level_warm_map.insert(query.key);
            }
            query.read_value = current_value;
            frame_data.forward.push(query);

            query
        }
    }
    fn start_frame(&mut self, _timestamp: Timestamp) {
        let new = ApplicationData::empty();
        self.frames_stack.push(new);
    }
    fn finish_frame(&mut self, _timestamp: Timestamp, panicked: bool) {
        // if we panic then we append forward and rollbacks to the forward of parent,
        // otherwise we place rollbacks of child before rollbacks of the parent
        let current_frame = self
            .frames_stack
            .pop()
            .expect("frame must be started before finishing");
        let ApplicationData { forward, rollbacks } = current_frame;
        let parent_data = self
            .frames_stack
            .last_mut()
            .expect("parent_frame_must_exist");
        if panicked {
            // perform actual rollback
            for query in rollbacks.iter().rev() {
                let LogQuery {
                    shard_id,
                    address,
                    key,
                    read_value,
                    written_value,
                    ..
                } = *query;
                let shard_level_map = &mut self.inner[shard_id as usize];
                let address_level_map = shard_level_map
                    .get_mut(&address)
                    .expect("must always exist on rollback");
                let current_value_ref = address_level_map
                    .get_mut(&key)
                    .expect("must always exist on rollback");
                assert_eq!(*current_value_ref, written_value); // compare current value
                *current_value_ref = read_value; // write back an old value
            }

            parent_data.forward.extend(forward);
            // add to forward part, but in reverse order
            parent_data.forward.extend(rollbacks.into_iter().rev());
        } else {
            parent_data.forward.extend(forward);
            // we need to prepend rollbacks. No reverse here, as we do not care yet!
            parent_data.rollbacks.extend(rollbacks);
        }
    }
}
