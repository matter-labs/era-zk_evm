use crate::vm_state::VmState;
use crate::vm_state::cycle::AuxTracingInformation;

use super::*;

pub struct NoopTracer<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer
> {
    _marker: std::marker::PhantomData<VmState<'a, S, M, EV, PP, DP, WT>>
}

impl<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer
> std::fmt::Debug for NoopTracer<'a, S, M, EV, PP, DP, WT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopTracer")
            .finish()
    }
}

impl<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer
> NoopTracer<'a, S, M, EV, PP, DP, WT> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData
        }
    }
}

impl<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer
> DebugTracer<VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, ()> for NoopTracer<'a, S, M, EV, PP, DP, WT> {
    #[inline]
    fn perform_before_execution(&mut self, _main: &VmState<'a, S, M, EV, PP, DP, WT>, _aux: AuxTracingInformation) {

    }

    #[inline]
    fn perform_after_execution(&mut self, _main: &VmState<'a, S, M, EV, PP, DP, WT>, _aux: ()) {

    }
}

pub struct ClosureBasedTracer<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
    F: FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, u32, ) -> ()
> {
    closure: F,
    cycle_number: u32,
    _marker: std::marker::PhantomData<VmState<'a, S, M, EV, PP, DP, WT>>
}

impl<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
    F: FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, u32, ) -> ()
> std::fmt::Debug for ClosureBasedTracer<'a, S, M, EV, PP, DP, WT, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClosureBasedTracer")
            .finish()
    }
}

impl<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
    F: FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, u32, ) -> ()
> ClosureBasedTracer<'a, S, M, EV, PP, DP, WT, F> {
    pub fn new(closure: F) -> Self {
        Self {
            closure,
            cycle_number: 0u32,
            _marker: std::marker::PhantomData
        }
    }
}

impl<
    'a, 
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
    F: FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, u32, ) -> ()
> DebugTracer<VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, ()> for ClosureBasedTracer<'a, S, M, EV, PP, DP, WT, F> {
    fn perform_before_execution(&mut self, main: &VmState<'a, S, M, EV, PP, DP, WT>, aux: AuxTracingInformation) {
        (self.closure)(main, aux, self.cycle_number);
    }

    fn perform_after_execution(&mut self, _main: &VmState<'a, S, M, EV, PP, DP, WT>, _aux: ()) {
        self.cycle_number += 1;
    }
}


pub struct DynTracer<
    'a,
    'b,
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
> {
    // pub before_closure: Option<Box<dyn FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, u32, ) -> () + 'a>>,
    // pub after_closure: Option<Box<dyn FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, (), u32, ) -> () + 'a>>,
    pub before_closure: Option<&'b mut dyn FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, u32, ) -> ()>,
    pub after_closure: Option<&'b mut dyn FnMut(&VmState<'a, S, M, EV, PP, DP, WT>, (), u32, ) -> ()>,
    cycle_number: u32,
    _marker: std::marker::PhantomData<VmState<'a, S, M, EV, PP, DP, WT>>
}

impl<
    'a, 
    'b,
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
> std::fmt::Debug for DynTracer<'a, 'b, S, M, EV, PP, DP, WT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynTracer")
            .finish()
    }
}

impl<
    'a, 
    'b,
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
> DynTracer<'a, 'b, S, M, EV, PP, DP, WT> {
    pub fn new() -> Self {
        Self {
            before_closure: None,
            after_closure: None,
            cycle_number: 0u32,
            _marker: std::marker::PhantomData
        }
    }
}

impl<
    'a, 
    'b,
    S: crate::abstractions::Storage, 
    M: crate::abstractions::Memory, 
    EV: crate::abstractions::EventSink,
    PP: crate::abstractions::PrecompilesProcessor,
    DP: crate::abstractions::DecommittmentProcessor,
    WT: crate::witness_trace::VmWitnessTracer,
> DebugTracer<VmState<'a, S, M, EV, PP, DP, WT>, AuxTracingInformation, ()> for DynTracer<'a, 'b, S, M, EV, PP, DP, WT> {
    fn perform_before_execution(&mut self, main: &VmState<'a, S, M, EV, PP, DP, WT>, aux: AuxTracingInformation) {
        if let Some(closure) = self.before_closure.as_deref_mut() {
            (closure)(main, aux, self.cycle_number);
        }
    }

    fn perform_after_execution(&mut self, main: &VmState<'a, S, M, EV, PP, DP, WT>, aux: ()) {
        if let Some(closure) = self.after_closure.as_deref_mut() {
            (closure)(main, aux, self.cycle_number);
        }
        self.cycle_number += 1;
    }
}