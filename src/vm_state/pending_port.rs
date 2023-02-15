#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PendingType {
    FarCall,
    Ret,
    WriteLog,
    UMAWrite,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpongePendingPort {
    pub pending_type: Option<PendingType>,
}

impl SpongePendingPort {
    pub const fn empty() -> Self {
        Self { pending_type: None }
    }

    pub const fn is_any_pending(&self) -> bool {
        self.pending_type.is_some()
    }

    pub fn reset(&mut self) {
        self.pending_type = None;
    }
}
