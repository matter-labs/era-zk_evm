use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockProperties {
    pub default_aa_code_hash: U256,
    pub zkporter_is_available: bool,
}
