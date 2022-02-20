use crate::error::IoError;

/// Provides IO error as an associated type.
///
/// Must be implemented for all types that also implement at least one of the following traits: `Read`, `Write`,
/// `Seek`.
pub trait IoBase {
    /// Type of errors returned by input/output operations.
    type Error: IoError;
}
