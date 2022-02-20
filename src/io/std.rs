use super::{
    base::IoBase,
    read::Read,
    seek::{Seek, SeekFrom},
    write::Write,
};

impl From<SeekFrom> for std::io::SeekFrom {
    fn from(from: SeekFrom) -> Self {
        match from {
            SeekFrom::Start(n) => std::io::SeekFrom::Start(n),
            SeekFrom::End(n) => std::io::SeekFrom::End(n),
            SeekFrom::Current(n) => std::io::SeekFrom::Current(n),
        }
    }
}

impl From<std::io::SeekFrom> for SeekFrom {
    fn from(from: std::io::SeekFrom) -> Self {
        match from {
            std::io::SeekFrom::Start(n) => SeekFrom::Start(n),
            std::io::SeekFrom::End(n) => SeekFrom::End(n),
            std::io::SeekFrom::Current(n) => SeekFrom::Current(n),
        }
    }
}

/// A wrapper struct for types that have implementations for `std::io` traits.
///
/// `Read`, `Write`, `Seek` traits from this crate are implemented for this type if
/// corresponding types from `std::io` are implemented by the inner instance.
pub struct StdIoWrapper<T> {
    inner: T,
}

impl<T> StdIoWrapper<T> {
    /// Creates a new `StdIoWrapper` instance that wraps the provided `inner` instance.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Returns inner struct
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> IoBase for StdIoWrapper<T> {
    type Error = std::io::Error;
}

impl<T: std::io::Read> Read for StdIoWrapper<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.inner.read(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.read_exact(buf)
    }
}

impl<T: std::io::Write> Write for StdIoWrapper<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.inner.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.inner.write_all(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

impl<T: std::io::Seek> Seek for StdIoWrapper<T> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.inner.seek(pos.into())
    }
}

impl<T> From<T> for StdIoWrapper<T> {
    fn from(from: T) -> Self {
        Self::new(from)
    }
}
