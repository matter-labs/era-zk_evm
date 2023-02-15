use super::*;
use crate::aux_structures::*;

use zkevm_opcode_defs::{INITIAL_SP_ON_FAR_CALL, UNMAPPED_PAGE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CallStackEntry<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub this_address: Address,
    pub msg_sender: Address,
    pub code_address: Address,
    pub base_memory_page: MemoryPage,
    pub code_page: MemoryPage,
    pub sp: E::PcOrImm,
    pub pc: E::PcOrImm,
    pub exception_handler_location: E::PcOrImm,
    pub ergs_remaining: u32,
    pub this_shard_id: u8,
    pub caller_shard_id: u8,
    pub code_shard_id: u8,
    pub is_static: bool,
    pub is_local_frame: bool,
    pub context_u128_value: u128,
    pub heap_bound: u32,
    pub aux_heap_bound: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Callstack<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    pub current: CallStackEntry<N, E>,
    pub inner: Vec<CallStackEntry<N, E>>,
}

impl<const N: usize, E: VmEncodingMode<N>> CallStackEntry<N, E> {
    // this is a context before bootloader actually starts. Necessary
    // to continue no-oping
    pub fn empty_context() -> Self {
        Self {
            this_address: Address::zero(),
            msg_sender: Address::zero(),
            code_address: Address::zero(),
            base_memory_page: MemoryPage(UNMAPPED_PAGE),
            code_page: MemoryPage(UNMAPPED_PAGE),
            sp: E::PcOrImm::from_u64_clipped(INITIAL_SP_ON_FAR_CALL),
            pc: E::PcOrImm::from_u64_clipped(0u64),
            exception_handler_location: E::PcOrImm::from_u64_clipped(0u64),
            ergs_remaining: zkevm_opcode_defs::system_params::VM_INITIAL_FRAME_ERGS,
            this_shard_id: 0u8,
            caller_shard_id: 0u8,
            code_shard_id: 0u8,
            is_static: false,
            is_local_frame: false,
            context_u128_value: 0u128,
            heap_bound: 0u32,
            aux_heap_bound: 0u32,
        }
    }
    pub fn is_kernel_mode(&self) -> bool {
        Self::address_is_kernel(&self.this_address)
    }

    pub const fn get_address_low(&self) -> u16 {
        let address_bytes = self.this_address.as_fixed_bytes();
        let address_u16 = u16::from_le_bytes([address_bytes[19], address_bytes[18]]);

        address_u16
    }

    pub const fn code_page_candidate_from_base(base: MemoryPage) -> MemoryPage {
        MemoryPage(base.0)
    }

    pub const fn stack_page_from_base(base: MemoryPage) -> MemoryPage {
        MemoryPage(base.0 + 1)
    }

    pub const fn heap_page_from_base(base: MemoryPage) -> MemoryPage {
        MemoryPage(base.0 + 2)
    }

    pub const fn aux_heap_page_from_base(base: MemoryPage) -> MemoryPage {
        MemoryPage(base.0 + 3)
    }

    pub fn address_is_kernel(address: &Address) -> bool {
        // address < 2^16
        let address_bytes = address.as_fixed_bytes();
        address_bytes[0..18].iter().all(|&el| el == 0u8)
    }
}

impl<const N: usize, E: VmEncodingMode<N>> Callstack<N, E> {
    pub fn empty() -> Self {
        let new = Self {
            current: CallStackEntry::empty_context(),
            inner: Vec::with_capacity(1 << 12),
        };
        debug_assert_eq!(new.depth(), 0);
        debug_assert!(new.is_empty());

        new
    }

    #[track_caller]
    pub fn push_entry(&mut self, entry: CallStackEntry<N, E>) {
        let old = std::mem::replace(&mut self.current, entry);
        self.inner.push(old);
        debug_assert!(
            self.depth() <= zkevm_opcode_defs::system_params::VM_MAX_STACK_DEPTH as usize
        );
    }

    #[track_caller]
    pub fn pop_entry(&mut self) -> CallStackEntry<N, E> {
        let previous = self.inner.pop().unwrap();
        let old = std::mem::replace(&mut self.current, previous);

        old
    }

    pub fn is_full(&self) -> bool {
        self.depth() == zkevm_opcode_defs::system_params::VM_MAX_STACK_DEPTH as usize
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.inner.len()
    }

    #[track_caller]
    pub fn get_current_stack(&self) -> &CallStackEntry<N, E> {
        &self.current
    }

    #[track_caller]
    pub fn get_current_stack_mut(&mut self) -> &mut CallStackEntry<N, E> {
        &mut self.current
    }
}
