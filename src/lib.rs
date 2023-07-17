pub mod block_properties;
pub mod errors;
pub mod flags;
pub mod opcodes;
pub mod reference_impls;
pub mod testing;
pub mod tracing;
pub mod utils;
pub mod vm_state;
pub mod witness_trace;

pub use self::utils::*;

pub use zkevm_opcode_defs::{bitflags, ethereum_types};

use self::ethereum_types::{Address, U256};

pub use zkevm_opcode_defs;

pub use zk_evm_abstractions;
pub use zkevm_opcode_defs::blake2;
pub use zkevm_opcode_defs::k256;
pub use zkevm_opcode_defs::sha2;
pub use zkevm_opcode_defs::sha3;

// Re-export abstractions.
pub mod abstractions {
    pub use zk_evm_abstractions::vm::*;
}
pub mod aux_structures {
    pub use zk_evm_abstractions::aux::*;
    pub use zk_evm_abstractions::queries::*;
}
