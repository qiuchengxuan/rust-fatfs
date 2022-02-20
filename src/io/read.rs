use crate::error::IoError;

use super::base::IoBase;

/// The `Read` trait allows for reading bytes from a source.
///
/// It is based on the `std::io::Read` trait.
#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
pub trait Read: IoBase {
    /// Pull some bytes from this source into the specified buffer, returning how many bytes were read.
    ///
    /// This function does not provide any guarantees about whether it blocks waiting for data, but if an object needs
    /// to block for a read and cannot, it will typically signal this via an Err return value.
    ///
    /// If the return value of this method is `Ok(n)`, then it must be guaranteed that `0 <= n <= buf.len()`. A nonzero
    /// `n` value indicates that the buffer buf has been filled in with n bytes of data from this source. If `n` is
    /// `0`, then it can indicate one of two scenarios:
    ///
    /// 1. This reader has reached its "end of file" and will likely no longer be able to produce bytes. Note that this
    ///    does not mean that the reader will always no longer be able to produce bytes.
    /// 2. The buffer specified was 0 bytes in length.
    ///
    /// It is not an error if the returned value `n` is smaller than the buffer size, even when the reader is not at
    /// the end of the stream yet. This may happen for example because fewer bytes are actually available right now
    /// (e. g. being close to end-of-file) or because read() was interrupted by a signal.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O or other error, an error will be returned. If an error is returned
    /// then it must be guaranteed that no bytes were read.
    /// An error for which `IoError::is_interrupted` returns true is non-fatal and the read operation should be retried
    /// if there is nothing else to do.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Read the exact number of bytes required to fill `buf`.
    ///
    /// This function reads as many bytes as necessary to completely fill the specified buffer `buf`.
    ///
    /// # Errors
    ///
    /// If this function encounters an error for which `IoError::is_interrupted` returns true then the error is ignored
    /// and the operation will continue.
    ///
    /// If this function encounters an end of file before completely filling the buffer, it returns an error
    /// instantiated by a call to `IoError::new_unexpected_eof_error`. The contents of `buf` are unspecified in this
    /// case.
    ///
    /// If this function returns an error, it is unspecified how many bytes it has read, but it will never read more
    /// than would be necessary to completely fill the buffer.
    async fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            match self.read(buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(ref e) if e.is_interrupted() => {}
                Err(e) => return Err(e),
            }
        }
        if buf.is_empty() {
            Ok(())
        } else {
            debug!("failed to fill whole buffer in read_exact");
            Err(Self::Error::new_unexpected_eof_error())
        }
    }
}
