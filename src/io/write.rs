use crate::error::IoError;

use super::base::IoBase;

/// The `Write` trait allows for writing bytes into the sink.
///
/// It is based on the `std::io::Write` trait.
#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
pub trait Write: IoBase {
    /// Write a buffer into this writer, returning how many bytes were written.
    ///
    /// # Errors
    ///
    /// Each call to write may generate an I/O error indicating that the operation could not be completed. If an error
    /// is returned then no bytes in the buffer were written to this writer.
    /// It is not considered an error if the entire buffer could not be written to this writer.
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error>;

    /// Attempts to write an entire buffer into this writer.
    ///
    /// This method will continuously call `write` until there is no more data to be written or an error is returned.
    /// Errors for which `IoError::is_interrupted` method returns true are being skipped. This method will not return
    /// until the entire buffer has been successfully written or such an error occurs.
    /// If `write` returns 0 before the entire buffer has been written this method will return an error instantiated by
    /// a call to `IoError::new_write_zero_error`.
    ///
    /// # Errors
    ///
    /// This function will return the first error for which `IoError::is_interrupted` method returns false that `write`
    /// returns.
    async fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            match self.write(buf).await {
                Ok(0) => {
                    debug!("failed to write whole buffer in write_all");
                    return Err(Self::Error::new_write_zero_error());
                }
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.is_interrupted() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    ///
    /// # Errors
    ///
    /// It is considered an error if not all bytes could be written due to I/O errors or EOF being reached.
    async fn flush(&mut self) -> Result<(), Self::Error>;
}
