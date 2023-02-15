use super::*;

use zkevm_opcode_defs::system_params::{EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE};

#[derive(Clone, Copy)]
pub struct EventMessage {
    pub shard_id: u8,
    pub is_first: bool,
    pub tx_number_in_block: u16,
    pub address: Address,
    pub key: U256,
    pub value: U256,
}

impl std::fmt::Debug for EventMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventMessage")
            .field("shard_id", &self.shard_id)
            .field("is_first", &self.is_first)
            .field("tx_number_in_block", &self.tx_number_in_block)
            .field("address", &self.address)
            .field("key", &format_args!("{:#064x}", &self.key))
            .field("value", &format_args!("{:#064x}", &self.value))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApplicationData<T> {
    pub forward: Vec<T>,
    pub rollbacks: Vec<T>,
}

impl<T> Default for ApplicationData<T> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T> ApplicationData<T> {
    pub fn empty() -> Self {
        Self {
            forward: vec![],
            rollbacks: vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub struct InMemoryEventSink {
    pub frames_stack: Vec<ApplicationData<LogQuery>>,
}

// as usual, if we rollback the current frame then we apply changes to storage immediately,
// otherwise we carry rollbacks to the parent's frames

impl InMemoryEventSink {
    pub fn new() -> Self {
        Self {
            // we add single frame that will serve as a last one
            frames_stack: vec![ApplicationData::empty()],
        }
    }

    pub fn flatten(mut self) -> (Vec<LogQuery>, Vec<EventMessage>, Vec<EventMessage>) {
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
        let mut tmp = HashMap::<u32, LogQuery>::with_capacity(forward.len());

        // note that we only use "forward" part and discard the rollbacks at the end,
        // since if rollbacks of parents were not appended anywhere we just still keep them
        for el in forward.into_iter() {
            // we are time ordered here in terms of rollbacks
            if tmp.get(&el.timestamp.0).is_some() {
                assert!(el.rollback);
                tmp.remove(&el.timestamp.0);
            } else {
                assert!(!el.rollback);
                tmp.insert(el.timestamp.0, el);
            }
        }

        // naturally sorted by timestamp
        let mut keys: Vec<_> = tmp.keys().into_iter().cloned().collect();
        keys.sort();

        let mut events = vec![];
        let mut l1_messages = vec![];

        for k in keys.into_iter() {
            let el = tmp.remove(&k).unwrap();
            let LogQuery {
                shard_id,
                is_service,
                tx_number_in_block,
                address,
                key,
                written_value,
                aux_byte,
                ..
            } = el;

            let event = EventMessage {
                shard_id,
                is_first: is_service,
                tx_number_in_block,
                address,
                key,
                value: written_value,
            };

            if aux_byte == EVENT_AUX_BYTE {
                events.push(event);
            } else {
                l1_messages.push(event);
            }
        }

        (history, events, l1_messages)
    }
}

impl EventSink for InMemoryEventSink {
    // when we enter a new frame we should remember all our current applications and rollbacks
    // when we exit the current frame then if we did panic we should concatenate all current
    // forward and rollback cases

    fn add_partial_query(&mut self, _monotonic_cycle_counter: u32, mut query: LogQuery) {
        assert!(query.rw_flag);
        assert!(query.aux_byte == EVENT_AUX_BYTE || query.aux_byte == L1_MESSAGE_AUX_BYTE);
        assert!(!query.rollback);
        // just append to rollbacks and a full history
        let frame_data = self.frames_stack.last_mut().expect("frame must be started");
        frame_data.forward.push(query);
        // we do not need it explicitly here, but let's be consistent with circuit counterpart
        query.rollback = true;
        frame_data.rollbacks.push(query);
    }
    fn start_frame(&mut self, _timestamp: Timestamp) {
        let new = ApplicationData::empty();
        self.frames_stack.push(new);
    }
    fn finish_frame(&mut self, panicked: bool, _timestamp: Timestamp) {
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
