use crate::abstractions::Tracer;
use crate::testing::{
    AfterDecodingData, AfterExecutionData, BeforeExecutionData, VmLocalStateData,
};

#[derive(Debug, Clone, Copy)]
pub struct NoopTracer;

impl Tracer for NoopTracer {
    type SupportedMemory = ();
    #[inline]
    fn before_decoding(&mut self, _state: VmLocalStateData<'_>, _memory: &Self::SupportedMemory) {}
    #[inline]
    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: AfterDecodingData,
        _memory: &Self::SupportedMemory,
    ) {
    }
    #[inline]
    fn before_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: BeforeExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
    }
    #[inline]
    fn after_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: AfterExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
    }
}

// pub struct ClosureBasedTracer<
//     I,
//     F0: FnMut(&mut I, VmLocalStateData<'_>, &dyn Memory) -> (),
//     F1: FnMut(&mut I, VmLocalStateData<'_>, AfterDecodingData, &dyn Memory) -> (),
//     F2: FnMut(&mut I, VmLocalStateData<'_>, BeforeExecutionData, &dyn Memory) -> (),
//     F3: FnMut(&mut I, VmLocalStateData<'_>, AfterExecutionData, &dyn Memory) -> (),
//     const BEFORE_DECODING: bool,
//     const AFTER_DECODING: bool,
//     const BEFORE_EXECUTION: bool,
//     const AFTER_EXECUTION: bool,
// > {
//     pub inner_state: I,
//     pub before_decoding: Option<F0>,
//     pub after_decoding: Option<F1>,
//     pub before_execution: Option<F2>,
//     pub after_execution: Option<F3>,
// }

// impl<
//     I: 'static,
//     F0: FnMut(&mut I, VmLocalStateData<'_>, &dyn Memory) -> () + 'static,
//     F1: FnMut(&mut I, VmLocalStateData<'_>, AfterDecodingData, &dyn Memory) -> () + 'static,
//     F2: FnMut(&mut I, VmLocalStateData<'_>, BeforeExecutionData, &dyn Memory) -> () + 'static,
//     F3: FnMut(&mut I, VmLocalStateData<'_>, AfterExecutionData, &dyn Memory) -> () + 'static,
//     const BEFORE_DECODING: bool,
//     const AFTER_DECODING: bool,
//     const BEFORE_EXECUTION: bool,
//     const AFTER_EXECUTION: bool,
// > Tracer for ClosureBasedTracer<I, F0, F1, F2, F3, BEFORE_DECODING, AFTER_DECODING, BEFORE_EXECUTION, AFTER_EXECUTION> {
//     const CALL_BEFORE_DECODING: bool = BEFORE_DECODING;
//     const CALL_AFTER_DECODING: bool = AFTER_DECODING;
//     const CALL_BEFORE_EXECUTION: bool = BEFORE_EXECUTION;
//     const CALL_AFTER_EXECUTION: bool = AFTER_EXECUTION;

//     fn before_decoding(&mut self, state: VmLocalStateData<'_>, memory: &dyn Memory) {
//         if let Some(c) = self.before_decoding.as_mut() {
//             (c)(&mut self.inner_state, state, memory)
//         }
//     }
//     fn after_decoding(&mut self, state: VmLocalStateData<'_>, data: AfterDecodingData, memory: &dyn Memory) {
//         if let Some(c) = self.after_decoding.as_mut() {
//             c(&mut self.inner_state, state, data, memory)
//         }
//     }
//     fn before_execution(&mut self, state: VmLocalStateData<'_>, data: BeforeExecutionData, memory: &dyn Memory) {
//         if let Some(c) = self.before_execution.as_mut() {
//             c(&mut self.inner_state, state, data, memory)
//         }
//     }
//     fn after_execution(&mut self, state: VmLocalStateData<'_>, data: AfterExecutionData, memory: &dyn Memory) {
//         if let Some(c) = self.after_execution.as_mut() {
//             c(&mut self.inner_state, state, data, memory)
//         }
//     }
// }

// impl<
//     I,
//     F0: FnMut(&mut I, VmLocalStateData<'_>, &dyn Memory) -> (),
//     F1: FnMut(&mut I, VmLocalStateData<'_>, AfterDecodingData, &dyn Memory) -> (),
//     F2: FnMut(&mut I, VmLocalStateData<'_>, BeforeExecutionData, &dyn Memory) -> (),
//     F3: FnMut(&mut I, VmLocalStateData<'_>, AfterExecutionData, &dyn Memory) -> (),
//     const BEFORE_DECODING: bool,
//     const AFTER_DECODING: bool,
//     const BEFORE_EXECUTION: bool,
//     const AFTER_EXECUTION: bool,
// > std::fmt::Debug for ClosureBasedTracer<I, F0, F1, F2, F3, BEFORE_DECODING, AFTER_DECODING, BEFORE_EXECUTION, AFTER_EXECUTION> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct(&"ClosureBasedTracer")
//             .finish()
//     }
// }
