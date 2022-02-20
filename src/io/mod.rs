mod base;
mod read;
mod seek;
#[cfg(all(not(feature = "async"), any(test, feature = "std")))]
pub mod std;
mod write;

pub use base::IoBase;
pub use read::Read;
pub use seek::{Seek, SeekFrom};
pub use write::Write;

#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
pub(crate) trait ReadLeExt {
    type Error;

    async fn read_u8(&mut self) -> Result<u8, Self::Error>;
    async fn read_u16_le(&mut self) -> Result<u16, Self::Error>;
    async fn read_u32_le(&mut self) -> Result<u32, Self::Error>;
}

#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
impl<T: Read> ReadLeExt for T {
    type Error = <Self as IoBase>::Error;

    async fn read_u8(&mut self) -> Result<u8, Self::Error> {
        let mut buf = [0_u8; 1];
        self.read_exact(&mut buf).await?;
        Ok(buf[0])
    }

    async fn read_u16_le(&mut self) -> Result<u16, Self::Error> {
        let mut buf = [0_u8; 2];
        self.read_exact(&mut buf).await?;
        Ok(u16::from_le_bytes(buf))
    }

    async fn read_u32_le(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0_u8; 4];
        self.read_exact(&mut buf).await?;
        Ok(u32::from_le_bytes(buf))
    }
}

#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
pub(crate) trait WriteLeExt {
    type Error;

    async fn write_u8(&mut self, n: u8) -> Result<(), Self::Error>;
    async fn write_u16_le(&mut self, n: u16) -> Result<(), Self::Error>;
    async fn write_u32_le(&mut self, n: u32) -> Result<(), Self::Error>;
}

#[cfg_attr(feature = "async", async_trait)]
#[deasync::deasync]
impl<T: Write> WriteLeExt for T {
    type Error = <Self as IoBase>::Error;

    async fn write_u8(&mut self, n: u8) -> Result<(), Self::Error> {
        self.write_all(&[n]).await
    }

    async fn write_u16_le(&mut self, n: u16) -> Result<(), Self::Error> {
        self.write_all(&n.to_le_bytes()).await
    }

    async fn write_u32_le(&mut self, n: u32) -> Result<(), Self::Error> {
        self.write_all(&n.to_le_bytes()).await
    }
}
