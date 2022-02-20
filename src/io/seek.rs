use super::base::IoBase;

/// Enumeration of possible methods to seek within an I/O object.
///
/// It is based on the `std::io::SeekFrom` enum.
pub enum SeekFrom {
    /// Sets the offset to the provided number of bytes.
    Start(u64),
    /// Sets the offset to the size of this object plus the specified number of bytes.
    End(i64),
    /// Sets the offset to the current position plus the specified number of bytes.
    Current(i64),
}

/// The `Seek` trait provides a cursor which can be moved within a stream of bytes.
///
/// It is based on the `std::io::Seek` trait.
#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
pub trait Seek: IoBase {
    /// Seek to an offset, in bytes, in a stream.
    ///
    /// A seek beyond the end of a stream or to a negative position is not allowed.
    ///
    /// If the seek operation completed successfully, this method returns the new position from the start of the
    /// stream. That position can be used later with `SeekFrom::Start`.
    ///
    /// # Errors
    /// Seeking to a negative offset is considered an error.
    async fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error>;
}
