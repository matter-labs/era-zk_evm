use std::collections::hash_map::RandomState;
use std::{collections::HashSet, hash::BuildHasher};

use crate::vm_state::CallStackEntry;
use crate::vm_state::PrimitiveValue;
use zkevm_opcode_defs::{FatPointer, BOOTLOADER_CALLDATA_PAGE};

use super::*;

const MAX_HEAP_PAGE_SIZE_IN_WORDS: usize = (u16::MAX as usize) / 32;

pub struct ReusablePool<
    T: Sized,
    InitFn: Fn() -> T,
    OnPullFn: Fn(&mut T) -> (),
    OnReturnFn: Fn(&mut T) -> (),
> {
    pool: Vec<T>,
    init_fn: InitFn,
    on_pull_fn: OnPullFn,
    on_return_fn: OnReturnFn,
}

impl<T: Sized, InitFn: Fn() -> T, OnPullFn: Fn(&mut T) -> (), OnReturnFn: Fn(&mut T) -> ()>
    ReusablePool<T, InitFn, OnPullFn, OnReturnFn>
{
    pub fn new_with_capacity(
        capacity: usize,
        init_fn: InitFn,
        on_pull_fn: OnPullFn,
        on_return_fn: OnReturnFn,
    ) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let el = init_fn();
            pool.push(el);
        }

        Self {
            pool,
            init_fn,
            on_pull_fn,
            on_return_fn,
        }
    }

    pub fn pull(&mut self) -> T {
        if let Some(mut existing) = self.pool.pop() {
            (self.on_pull_fn)(&mut existing);

            existing
        } else {
            let mut new = (self.init_fn)();
            (self.on_pull_fn)(&mut new);

            new
        }
    }

    pub fn return_element(&mut self, mut el: T) {
        (self.on_return_fn)(&mut el);
        self.pool.push(el);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Indirection {
    Heap(usize),
    AuxHeap(usize),
    ReturndataExtendedLifetime,
    Empty,
}

// unfortunately we have to name it

#[derive(Debug)]
pub struct HeapPagesReusablePool {
    pool: Vec<Vec<U256>>,
}

impl HeapPagesReusablePool {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let el = heap_init();
            pool.push(el);
        }

        Self { pool }
    }

    pub fn pull(&mut self) -> Vec<U256> {
        if let Some(mut existing) = self.pool.pop() {
            heap_on_pull(&mut existing);

            existing
        } else {
            let mut new = heap_init();
            heap_on_pull(&mut new);

            new
        }
    }

    pub fn return_element(&mut self, mut el: Vec<U256>) {
        heap_on_return(&mut el);
        self.pool.push(el);
    }
}

#[derive(Debug)]
pub struct StackPagesReusablePool {
    pool: Vec<Vec<PrimitiveValue>>,
}

impl StackPagesReusablePool {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let el = stack_init();
            pool.push(el);
        }

        Self { pool }
    }

    pub fn pull(&mut self) -> Vec<PrimitiveValue> {
        if let Some(mut existing) = self.pool.pop() {
            stack_on_pull(&mut existing);

            existing
        } else {
            let mut new = stack_init();
            stack_on_pull(&mut new);

            new
        }
    }

    pub fn return_element(&mut self, mut el: Vec<PrimitiveValue>) {
        stack_on_return(&mut el);
        self.pool.push(el);
    }
}

#[derive(Debug)]
pub struct SimpleMemory<S: BuildHasher + Default = RandomState> {
    pub stack_pages: Vec<(u32, Vec<PrimitiveValue>)>, // easy to purge
    pub heaps: Vec<((u32, Vec<U256>), (u32, Vec<U256>))>, // potentially easier to purge
    pub code_pages: HashMap<u32, Vec<U256>, S>,       // live as long as VM is alive
    // each frame can get calldata forwarded to it,
    // and returndata too. We should keep in mind that
    // - calldata ptr CAN be used as returndata
    // - returndata ptr CAN be used for calldata
    // so we should maintain something like a simple graph for it,
    // based on the assumption that even though calldata originates from some HEAP
    // it can end up being a returndata, so when we:
    // - perform far call we are ok to just keep calldata ptr as indirection
    // - but when we return we should check that our returndata ptr doesn't force us to later on
    // extend a lifetime of calldataptr indirection
    pub pages_with_extended_lifetime: HashMap<u32, Vec<U256>, S>,
    pub page_numbers_indirections: HashMap<u32, Indirection, S>,
    pub indirections_to_cleanup_on_return: Vec<HashSet<u32, S>>,

    // we do not need a pool for code pages as those are extended lifetime always
    pub heaps_pool: HeapPagesReusablePool,
    pub stacks_pool: StackPagesReusablePool,
}

fn heap_init() -> Vec<U256> {
    vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS]
}

fn stack_init() -> Vec<PrimitiveValue> {
    vec![PrimitiveValue::empty(); MAX_STACK_PAGE_SIZE_IN_WORDS]
}

fn heap_on_pull(_el: &mut Vec<U256>) -> () {}

fn stack_on_pull(_el: &mut Vec<PrimitiveValue>) -> () {}

fn heap_on_return(el: &mut Vec<U256>) -> () {
    assert_eq!(el.len(), MAX_HEAP_PAGE_SIZE_IN_WORDS);
    el.fill(U256::zero());
}

fn stack_on_return(el: &mut Vec<PrimitiveValue>) -> () {
    assert_eq!(el.len(), MAX_STACK_PAGE_SIZE_IN_WORDS);
    el.fill(PrimitiveValue::empty());
}

// as usual, if we rollback the current frame then we apply changes to storage immediately,
// otherwise we carry rollbacks to the parent's frames

pub fn new_reference_memory_impl() -> ReusablePool<
    Vec<U256>,
    impl Fn() -> Vec<U256>,
    impl Fn(&mut Vec<U256>) -> (),
    impl Fn(&mut Vec<U256>) -> (),
> {
    ReusablePool::new_with_capacity(1 << 10, heap_init, heap_on_pull, heap_on_return)
}

impl<S: BuildHasher + Default> SimpleMemory<S> {
    pub fn new() -> Self {
        let mut new = Self {
            stack_pages: Vec::with_capacity(1024), // we do not need stack or heaps for root frame as it's never accessible
            heaps: Vec::with_capacity(1024),
            code_pages: HashMap::with_capacity_and_hasher(1 << 12, S::default()),
            pages_with_extended_lifetime: HashMap::with_capacity_and_hasher(64, S::default()),
            page_numbers_indirections: HashMap::with_capacity_and_hasher(64, S::default()),
            indirections_to_cleanup_on_return: Vec::with_capacity(1024),
            heaps_pool: HeapPagesReusablePool::new_with_capacity(1 << 12),
            stacks_pool: StackPagesReusablePool::new_with_capacity(1 << 11),
        };

        // this one virtually exists always
        new.code_pages
            .insert(0u32, vec![U256::zero(); MAX_CODE_PAGE_SIZE_IN_WORDS]);
        new.pages_with_extended_lifetime.insert(
            BOOTLOADER_CALLDATA_PAGE,
            vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS],
        );
        new.page_numbers_indirections.insert(0, Indirection::Empty); // quicker lookup
        new.indirections_to_cleanup_on_return
            .push(HashSet::with_capacity_and_hasher(4, S::default()));
        new.heaps.push((
            (0u32, vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS]),
            (0u32, vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS]),
        )); // formally, so we can access "last"

        new
    }

    pub fn new_without_preallocations() -> Self {
        let mut new = Self {
            stack_pages: Vec::with_capacity(1024), // we do not need stack or heaps for root frame as it's never accessible
            heaps: Vec::with_capacity(1024),
            code_pages: HashMap::with_capacity_and_hasher(1 << 12, S::default()),
            pages_with_extended_lifetime: HashMap::with_capacity_and_hasher(64, S::default()),
            page_numbers_indirections: HashMap::with_capacity_and_hasher(64, S::default()),
            indirections_to_cleanup_on_return: Vec::with_capacity(1024),
            heaps_pool: HeapPagesReusablePool::new_with_capacity(2),
            stacks_pool: StackPagesReusablePool::new_with_capacity(2),
        };

        // this one virtually exists always
        new.code_pages
            .insert(0u32, vec![U256::zero(); MAX_CODE_PAGE_SIZE_IN_WORDS]);
        new.pages_with_extended_lifetime.insert(
            BOOTLOADER_CALLDATA_PAGE,
            vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS],
        );
        new.page_numbers_indirections.insert(0, Indirection::Empty); // quicker lookup
        new.indirections_to_cleanup_on_return
            .push(HashSet::with_capacity_and_hasher(4, S::default()));
        new.heaps.push((
            (0u32, vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS]),
            (0u32, vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS]),
        )); // formally, so we can access "last"

        new
    }
}

impl<S: BuildHasher + Default> SimpleMemory<S> {
    // Can populate code pages only
    pub fn populate_code(&mut self, elements: Vec<(u32, Vec<U256>)>) -> Vec<(u32, usize)> {
        let mut results = vec![];
        for (page, values) in elements.into_iter() {
            assert!(!self.code_pages.contains_key(&page));
            let len = values.len();
            assert!(len <= MAX_CODE_PAGE_SIZE_IN_WORDS);
            let mut values = values;
            values.resize(MAX_CODE_PAGE_SIZE_IN_WORDS, U256::zero());
            self.code_pages.insert(page, values);
            results.push((page, len));
        }

        results
    }

    // Can never populate stack or aux heap
    pub fn populate_heap(&mut self, values: Vec<U256>) {
        let heaps_data = self.heaps.last_mut().unwrap();
        let len = values.len();
        assert!(len <= MAX_HEAP_PAGE_SIZE_IN_WORDS);
        let mut values = values;
        values.resize(MAX_HEAP_PAGE_SIZE_IN_WORDS, U256::zero());

        heaps_data.0 .1 = values;
    }

    pub fn polulate_bootloaders_calldata(&mut self, values: Vec<U256>) {
        let len = values.len();
        assert!(len <= MAX_HEAP_PAGE_SIZE_IN_WORDS);
        let mut values = values;
        values.resize(MAX_HEAP_PAGE_SIZE_IN_WORDS, U256::zero());

        *self
            .pages_with_extended_lifetime
            .get_mut(&BOOTLOADER_CALLDATA_PAGE)
            .unwrap() = values;
    }

    pub fn dump_page_content(
        &self,
        page_number: u32,
        range: std::ops::Range<u32>,
    ) -> Vec<[u8; 32]> {
        let u256_words = self.dump_page_content_as_u256_words(page_number, range);
        let mut buffer = [0u8; 32];
        let mut result = Vec::with_capacity(u256_words.len());
        for el in u256_words.into_iter() {
            el.to_big_endian(&mut buffer);
            result.push(buffer);
        }

        result
    }

    pub fn dump_page_content_as_u256_words(
        &self,
        page_number: u32,
        range: std::ops::Range<u32>,
    ) -> Vec<U256> {
        if let Some(page) = self.code_pages.get(&page_number) {
            let mut result = vec![];
            for i in range {
                if let Some(word) = page.get(i as usize) {
                    result.push(*word);
                } else {
                    result.push(U256::zero());
                }
            }

            return result;
        } else {
            if let Some(content) = self.pages_with_extended_lifetime.get(&page_number) {
                let mut result = vec![];
                for i in range {
                    if let Some(word) = content.get(i as usize) {
                        result.push(*word);
                    } else {
                        result.push(U256::zero());
                    }
                }

                return result;
            }

            for (page_idx, content) in self.stack_pages.iter().rev() {
                if *page_idx == page_number {
                    let mut result = vec![];
                    for i in range {
                        if let Some(word) = content.get(i as usize) {
                            result.push(word.value);
                        } else {
                            result.push(U256::zero());
                        }
                    }

                    return result;
                } else {
                    continue;
                }
            }

            for (heap_data, aux_heap_data) in self.heaps.iter().rev() {
                if heap_data.0 == page_number {
                    let content = &heap_data.1;
                    let mut result = vec![];
                    for i in range {
                        if let Some(word) = content.get(i as usize) {
                            result.push(*word);
                        } else {
                            result.push(U256::zero());
                        }
                    }

                    return result;
                } else if aux_heap_data.0 == page_number {
                    let content = &aux_heap_data.1;
                    let mut result = vec![];
                    for i in range {
                        if let Some(word) = content.get(i as usize) {
                            result.push(*word);
                        } else {
                            result.push(U256::zero());
                        }
                    }

                    return result;
                } else {
                    continue;
                }
            }
        }

        vec![U256::zero(); range.len()]
    }

    pub fn dump_full_page(&self, page_number: u32) -> Vec<[u8; 32]> {
        let upper_bound = MAX_HEAP_PAGE_SIZE_IN_WORDS as u32;
        self.dump_page_content(page_number, 0..upper_bound)
    }
}

impl Memory for SimpleMemory {
    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut query: MemoryQuery,
    ) -> MemoryQuery {
        // we assume that all pages were pre-created, and use a hint here
        let page_number = query.location.page.0;
        match query.location.memory_type {
            MemoryType::Stack => {
                if query.rw_flag {
                    let (idx, page) = self.stack_pages.last_mut().unwrap();
                    assert_eq!(*idx, page_number);
                    let primitive = PrimitiveValue {
                        value: query.value,
                        is_pointer: query.value_is_pointer,
                    };
                    page[query.location.index.0 as usize] = primitive
                } else {
                    let (idx, page) = self.stack_pages.last().unwrap();
                    assert_eq!(*idx, page_number);
                    let primitive = page[query.location.index.0 as usize];
                    query.value = primitive.value;
                    query.value_is_pointer = primitive.is_pointer;
                }
            }
            a @ MemoryType::Heap | a @ MemoryType::AuxHeap => {
                assert!(query.value_is_pointer == false);
                if query.rw_flag {
                    let (
                        (current_heap_page, current_heap_content),
                        (current_aux_heap_page, current_aux_heap_content),
                    ) = self.heaps.last_mut().unwrap();
                    if a == MemoryType::Heap {
                        debug_assert_eq!(*current_heap_page, query.location.page.0);
                        current_heap_content[query.location.index.0 as usize] = query.value;
                    } else if a == MemoryType::AuxHeap {
                        debug_assert_eq!(*current_aux_heap_page, query.location.page.0);
                        current_aux_heap_content[query.location.index.0 as usize] = query.value;
                    } else {
                        unreachable!()
                    }
                } else {
                    let (
                        (current_heap_page, current_heap_content),
                        (current_aux_heap_page, current_aux_heap_content),
                    ) = self.heaps.last().unwrap();
                    if a == MemoryType::Heap {
                        debug_assert_eq!(*current_heap_page, query.location.page.0);
                        query.value = current_heap_content[query.location.index.0 as usize];
                    } else if a == MemoryType::AuxHeap {
                        debug_assert_eq!(*current_aux_heap_page, query.location.page.0);
                        query.value = current_aux_heap_content[query.location.index.0 as usize];
                    } else {
                        unreachable!()
                    }
                }
            }
            MemoryType::FatPointer => {
                assert!(query.rw_flag == false);
                assert!(query.value_is_pointer == false);
                let indirection = self
                    .page_numbers_indirections
                    .get(&page_number)
                    .expect("fat pointer only points to reachable memory");

                match indirection {
                    Indirection::Heap(index) => {
                        let forwarded_heap_data = &self.heaps[*index];
                        assert_eq!(forwarded_heap_data.0 .0, query.location.page.0);
                        query.value = forwarded_heap_data.0 .1[query.location.index.0 as usize];
                    }
                    Indirection::AuxHeap(index) => {
                        let forwarded_heap_data = &self.heaps[*index];
                        assert_eq!(forwarded_heap_data.1 .0, query.location.page.0);
                        query.value = forwarded_heap_data.1 .1[query.location.index.0 as usize];
                    }
                    Indirection::ReturndataExtendedLifetime => {
                        let page = self
                            .pages_with_extended_lifetime
                            .get(&page_number)
                            .expect("indirection target must exist");
                        query.value = page[query.location.index.0 as usize];
                    }
                    Indirection::Empty => {
                        query.value = U256::zero();
                    }
                }
            }
            MemoryType::Code => {
                unreachable!("code should be through specialized query");
            }
        }

        query
    }

    fn specialized_code_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        query: MemoryQuery,
    ) -> MemoryQuery {
        assert_eq!(query.location.memory_type, MemoryType::Code);
        let page = query.location.page.0;

        let idx = query.location.index.0 as usize;
        let mut query = query;
        if query.rw_flag {
            if self.code_pages.contains_key(&page) == false {
                self.code_pages
                    .insert(page, vec![U256::zero(); MAX_CODE_PAGE_SIZE_IN_WORDS]);
            }
            let page_content = self.code_pages.get_mut(&page).unwrap();
            page_content[idx] = query.value;
        } else {
            debug_assert!(query.value_is_pointer == false);
            let page_content = self.code_pages.get(&page).unwrap();
            query.value = page_content[idx];
        }

        query
    }

    fn read_code_query(&self, _monotonic_cycle_counter: u32, query: MemoryQuery) -> MemoryQuery {
        assert_eq!(query.location.memory_type, MemoryType::Code);
        assert!(!query.rw_flag);
        let page = query.location.page.0;

        let idx = query.location.index.0 as usize;
        let mut query = query;

        debug_assert!(query.value_is_pointer == false);
        let page_content = self.code_pages.get(&page).unwrap();
        query.value = page_content[idx];

        query
    }

    // Notify that we start a new global frame. `calldata_fat_pointer` can not leak in a sense
    // that it's already alive somewhere
    fn start_global_frame(
        &mut self,
        _current_base_page: MemoryPage,
        new_base_page: MemoryPage,
        calldata_fat_pointer: FatPointer,
        _timestamp: Timestamp,
    ) {
        use zkevm_opcode_defs::decoding::EncodingModeProduction;

        // we can prepare and preallocate, and then deallocate the number of pages that we want
        let stack_page =
            CallStackEntry::<8, EncodingModeProduction>::stack_page_from_base(new_base_page);
        let stack_page_from_pool = self.stacks_pool.pull();
        self.stack_pages.push((stack_page.0, stack_page_from_pool));
        // self.stack_pages.push((stack_page.0, vec![PrimitiveValue::empty(); MAX_STACK_PAGE_SIZE_IN_WORDS]));

        let heap_page =
            CallStackEntry::<8, EncodingModeProduction>::heap_page_from_base(new_base_page);

        let aux_heap_page =
            CallStackEntry::<8, EncodingModeProduction>::aux_heap_page_from_base(new_base_page);

        let current_heaps_data = self.heaps.last().unwrap();
        let current_heap_page = current_heaps_data.0 .0;
        let current_aux_heap_page = current_heaps_data.1 .0;

        let idx_to_use_for_calldata_ptrs = self.heaps.len() - 1;

        let heap_page_from_pool = self.heaps_pool.pull();
        let aux_heap_page_from_pool = self.heaps_pool.pull();

        self.heaps.push((
            (heap_page.0, heap_page_from_pool),
            (aux_heap_page.0, aux_heap_page_from_pool),
        ));

        // self.heaps.push(
        //     (
        //         (heap_page.0, vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS]),
        //         (aux_heap_page.0, vec![U256::zero(); MAX_HEAP_PAGE_SIZE_IN_WORDS])
        //     )
        // );
        // we may want to later on cleanup indirections
        self.indirections_to_cleanup_on_return
            .push(HashSet::with_capacity(4));

        if calldata_fat_pointer.memory_page == 0 {
            // no need to do anything
        } else if calldata_fat_pointer.memory_page == current_heap_page {
            self.page_numbers_indirections.insert(
                current_heap_page,
                Indirection::Heap(idx_to_use_for_calldata_ptrs),
            );
            // if we will return from here and returndata page will not "leak" calldata page via forwarding, then we can cleanup the indirection
            self.indirections_to_cleanup_on_return
                .last_mut()
                .unwrap()
                .insert(current_heap_page);
        } else if calldata_fat_pointer.memory_page == current_aux_heap_page {
            self.page_numbers_indirections.insert(
                current_aux_heap_page,
                Indirection::AuxHeap(idx_to_use_for_calldata_ptrs),
            );
            self.indirections_to_cleanup_on_return
                .last_mut()
                .unwrap()
                .insert(current_aux_heap_page);
        } else {
            // calldata is unidirectional, so we check that it's already an indirection
            let existing_indirection = self
                .page_numbers_indirections
                .get(&calldata_fat_pointer.memory_page)
                .expect("fat pointer must only point to reachable memory");
            match existing_indirection {
                Indirection::Heap(..) | Indirection::AuxHeap(..) => {}
                a @ _ => {
                    panic!("calldata forwaring using pointer {:?} should already have a heap/aux heap indirection, but has {:?}. All indirections:\n {:?}",
                        &calldata_fat_pointer,
                        a,
                        &self.page_numbers_indirections
                    );
                }
            }
        }
    }

    // here we potentially want to do some cleanup
    fn finish_global_frame(
        &mut self,
        base_page: MemoryPage,
        returndata_fat_pointer: FatPointer,
        _timestamp: Timestamp,
    ) {
        use zkevm_opcode_defs::decoding::EncodingModeProduction;

        // stack always goes out of scope
        let stack_page =
            CallStackEntry::<8, EncodingModeProduction>::stack_page_from_base(base_page);

        let (stack_page_number, stack_page_to_reuse) = self.stack_pages.pop().unwrap();
        assert_eq!(stack_page_number, stack_page.0);
        self.stacks_pool.return_element(stack_page_to_reuse);

        let returndata_page = returndata_fat_pointer.memory_page;

        // we can cleanup all the heap pages that derive from base, if one of those is not in returndata
        let heap_page = CallStackEntry::<8, EncodingModeProduction>::heap_page_from_base(base_page);
        let aux_heap_page =
            CallStackEntry::<8, EncodingModeProduction>::aux_heap_page_from_base(base_page);

        // when we finish the global frame then ALL indirections go out of scope except
        // one that becomes returndata itself (if returndata is not taken from heap or aux heap)

        let (
            (current_heap_page, current_heap_content),
            (current_aux_heap_page, current_aux_heap_content),
        ) = self.heaps.pop().unwrap();
        assert_eq!(heap_page.0, current_heap_page);
        assert_eq!(aux_heap_page.0, current_aux_heap_page);

        let mut current_frame_indirections_to_cleanup = self
            .indirections_to_cleanup_on_return
            .pop()
            .expect("indirections must exist");
        let previous_frame_indirections_to_cleanup = self
            .indirections_to_cleanup_on_return
            .last_mut()
            .expect("previous page indirections must exist");

        if returndata_page == current_heap_page {
            // we add indirection and move to extended lifetime
            let existing = self
                .pages_with_extended_lifetime
                .insert(current_heap_page, current_heap_content);
            assert!(existing.is_none());
            self.page_numbers_indirections
                .insert(current_heap_page, Indirection::ReturndataExtendedLifetime);
            previous_frame_indirections_to_cleanup.insert(current_heap_page);

            // and we can reuse another page
            self.heaps_pool.return_element(current_aux_heap_content);
        } else if returndata_page == current_aux_heap_page {
            // we add indirection and move to extended lifetime
            let existing = self
                .pages_with_extended_lifetime
                .insert(current_aux_heap_page, current_aux_heap_content);
            assert!(existing.is_none());
            self.page_numbers_indirections.insert(
                current_aux_heap_page,
                Indirection::ReturndataExtendedLifetime,
            );
            previous_frame_indirections_to_cleanup.insert(current_aux_heap_page);

            // and we can reuse another page
            self.heaps_pool.return_element(current_heap_content);
        } else {
            // this means "forwarding" of some form,
            // so we carry indirection forward

            // so it's not masked ret panic page
            if returndata_page != 0 {
                assert!(self
                    .page_numbers_indirections
                    .contains_key(&returndata_page),
                    "expected that indirections contain page {}. Heap page = {}, aux heap page = {}, full set = {:?}",
                    returndata_page,
                    current_heap_page,
                    current_aux_heap_page,
                    &self.page_numbers_indirections
                );
                current_frame_indirections_to_cleanup.remove(&returndata_page); // otherwise it'll be lost
                previous_frame_indirections_to_cleanup.insert(returndata_page);
            }

            // and we can reuse all pages
            self.heaps_pool.return_element(current_heap_content);
            self.heaps_pool.return_element(current_aux_heap_content);
        }

        // now it's safe to cleanup all the indirections we have encountered at this page

        for el in current_frame_indirections_to_cleanup.into_iter() {
            let existing = self.page_numbers_indirections.remove(&el);
            assert!(existing.is_some(), "double free in indirection");
        }
    }
}
