#[derive(Clone, Copy, Debug)]
pub enum OpcodeDecodingError {
    UnknownOpcode,
    EncodingIsTooLong,
}

impl std::fmt::Display for OpcodeDecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for OpcodeDecodingError {}
