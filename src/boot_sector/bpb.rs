use crate::{
    dir_entry::DIR_ENTRY_SIZE,
    error::{Error, IoError},
    fs::{FatType, FsStatusFlags},
    io::{Read, ReadLeExt, Write, WriteLeExt},
    table::RESERVED_FAT_ENTRIES,
};

#[derive(Default, Debug, Clone)]
#[repr(C)]
pub(crate) struct BiosParameterBlock {
    pub(crate) bytes_per_sector: u16,
    pub(crate) sectors_per_cluster: u8,
    pub(crate) reserved_sectors: u16,
    pub(crate) fats: u8,
    pub(crate) root_entries: u16,
    pub(crate) total_sectors_16: u16,
    pub(crate) media: u8,
    pub(crate) sectors_per_fat_16: u16,
    pub(crate) sectors_per_track: u16,
    pub(crate) heads: u16,
    pub(crate) hidden_sectors: u32,
    pub(crate) total_sectors_32: u32,

    // Extended BIOS Parameter Block
    pub(crate) sectors_per_fat_32: u32,
    pub(crate) extended_flags: u16,
    pub(crate) fs_version: u16,
    pub(crate) root_dir_first_cluster: u32,
    pub(crate) fs_info_sector: u16,
    pub(crate) backup_boot_sector: u16,
    pub(crate) reserved_0: [u8; 12],
    pub(crate) drive_num: u8,
    pub(crate) reserved_1: u8,
    pub(crate) ext_sig: u8,
    pub(crate) volume_id: u32,
    pub(crate) volume_label: [u8; 11],
    pub(crate) fs_type_label: [u8; 8],
}

impl BiosParameterBlock {
    pub(crate) fn deserialize<R: Read>(rdr: &mut R) -> Result<Self, R::Error> {
        let mut bpb = Self {
            bytes_per_sector: rdr.read_u16_le()?,
            sectors_per_cluster: rdr.read_u8()?,
            reserved_sectors: rdr.read_u16_le()?,
            fats: rdr.read_u8()?,
            root_entries: rdr.read_u16_le()?,
            total_sectors_16: rdr.read_u16_le()?,
            media: rdr.read_u8()?,
            sectors_per_fat_16: rdr.read_u16_le()?,
            sectors_per_track: rdr.read_u16_le()?,
            heads: rdr.read_u16_le()?,
            hidden_sectors: rdr.read_u32_le()?,
            total_sectors_32: rdr.read_u32_le()?,
            ..Self::default()
        };

        if bpb.is_fat32() {
            bpb.sectors_per_fat_32 = rdr.read_u32_le()?;
            bpb.extended_flags = rdr.read_u16_le()?;
            bpb.fs_version = rdr.read_u16_le()?;
            bpb.root_dir_first_cluster = rdr.read_u32_le()?;
            bpb.fs_info_sector = rdr.read_u16_le()?;
            bpb.backup_boot_sector = rdr.read_u16_le()?;
            rdr.read_exact(&mut bpb.reserved_0)?;
        }

        bpb.drive_num = rdr.read_u8()?;
        bpb.reserved_1 = rdr.read_u8()?;
        bpb.ext_sig = rdr.read_u8()?; // 0x29
        bpb.volume_id = rdr.read_u32_le()?;
        rdr.read_exact(&mut bpb.volume_label)?;
        rdr.read_exact(&mut bpb.fs_type_label)?;

        // when the extended boot signature is anything other than 0x29, the fields are invalid
        if bpb.ext_sig != 0x29 {
            // fields after ext_sig are not used - clean them
            bpb.volume_id = 0;
            bpb.volume_label = [0; 11];
            bpb.fs_type_label = [0; 8];
        }

        Ok(bpb)
    }

    pub(crate) fn serialize<W: Write>(&self, wrt: &mut W) -> Result<(), W::Error> {
        wrt.write_u16_le(self.bytes_per_sector)?;
        wrt.write_u8(self.sectors_per_cluster)?;
        wrt.write_u16_le(self.reserved_sectors)?;
        wrt.write_u8(self.fats)?;
        wrt.write_u16_le(self.root_entries)?;
        wrt.write_u16_le(self.total_sectors_16)?;
        wrt.write_u8(self.media)?;
        wrt.write_u16_le(self.sectors_per_fat_16)?;
        wrt.write_u16_le(self.sectors_per_track)?;
        wrt.write_u16_le(self.heads)?;
        wrt.write_u32_le(self.hidden_sectors)?;
        wrt.write_u32_le(self.total_sectors_32)?;

        if self.is_fat32() {
            wrt.write_u32_le(self.sectors_per_fat_32)?;
            wrt.write_u16_le(self.extended_flags)?;
            wrt.write_u16_le(self.fs_version)?;
            wrt.write_u32_le(self.root_dir_first_cluster)?;
            wrt.write_u16_le(self.fs_info_sector)?;
            wrt.write_u16_le(self.backup_boot_sector)?;
            wrt.write_all(&self.reserved_0)?;
        }

        wrt.write_u8(self.drive_num)?;
        wrt.write_u8(self.reserved_1)?;
        wrt.write_u8(self.ext_sig)?; // 0x29
        wrt.write_u32_le(self.volume_id)?;
        wrt.write_all(&self.volume_label)?;
        wrt.write_all(&self.fs_type_label)?;
        Ok(())
    }

    fn validate_bytes_per_sector<E: IoError>(&self) -> Result<(), Error<E>> {
        if !self.bytes_per_sector.is_power_of_two() {
            error!(
                "invalid bytes_per_sector value in BPB: expected a power of two but got {}",
                self.bytes_per_sector
            );
            return Err(Error::CorruptedFileSystem);
        }

        if !(512..=4096).contains(&self.bytes_per_sector) {
            error!(
                "invalid bytes_per_sector value in BPB: expected value in range [512, 4096] but got {}",
                self.bytes_per_sector
            );
            return Err(Error::CorruptedFileSystem);
        }
        Ok(())
    }

    fn validate_sectors_per_cluster<E: IoError>(&self) -> Result<(), Error<E>> {
        if !self.sectors_per_cluster.is_power_of_two() {
            error!(
                "invalid sectors_per_cluster value in BPB: expected a power of two but got {}",
                self.sectors_per_cluster
            );
            return Err(Error::CorruptedFileSystem);
        }
        if !(1..=128).contains(&self.sectors_per_cluster) {
            error!(
                "invalid sectors_per_cluster value in BPB: expected value in range [1, 128] but got {}",
                self.sectors_per_cluster
            );
            return Err(Error::CorruptedFileSystem);
        }

        // bytes per sector is u16, sectors per cluster is u8, so guaranteed no overflow in multiplication
        let bytes_per_cluster =
            u32::from(self.bytes_per_sector) * u32::from(self.sectors_per_cluster);
        let maximum_compatibility_bytes_per_cluster: u32 = 32 * 1024;

        if bytes_per_cluster > maximum_compatibility_bytes_per_cluster {
            // 32k is the largest value to maintain greatest compatibility
            // Many implementations appear to support 64k per cluster, and some may support 128k or larger
            // However, >32k is not as thoroughly tested...
            warn!(
                "fs compatibility: bytes_per_cluster value '{}' in BPB exceeds '{}', and thus may be incompatible with some implementations",
                bytes_per_cluster, maximum_compatibility_bytes_per_cluster
            );
        }
        Ok(())
    }

    fn validate_reserved_sectors<E: IoError>(&self) -> Result<(), Error<E>> {
        if self.reserved_sectors < 1 {
            error!("invalid reserved_sectors value in BPB: {}", self.reserved_sectors);
            return Err(Error::CorruptedFileSystem);
        }
        let is_fat32 = self.is_fat32();
        if !is_fat32 && self.reserved_sectors != 1 {
            // Microsoft document indicates fat12 and fat16 code exists that presume this value is 1
            warn!(
                "fs compatibility: reserved_sectors value '{}' in BPB is not '1', and thus is incompatible with some implementations",
                self.reserved_sectors
            );
        }
        if is_fat32 && self.backup_boot_sector >= self.reserved_sectors {
            error!(
                "Invalid BPB: expected backup boot-sector to be in the reserved region (sector < {}) but got sector {}",
                self.reserved_sectors, self.backup_boot_sector
            );
            return Err(Error::CorruptedFileSystem);
        }
        if is_fat32 && self.fs_info_sector >= self.reserved_sectors {
            error!(
                "Invalid BPB: expected FSInfo sector to be in the reserved region (sector < {}) but got sector {}",
                self.reserved_sectors, self.fs_info_sector
            );
            return Err(Error::CorruptedFileSystem);
        }
        Ok(())
    }

    fn validate_fats<E: IoError>(&self) -> Result<(), Error<E>> {
        if self.fats == 0 {
            error!("invalid fats value in BPB: {}", self.fats);
            return Err(Error::CorruptedFileSystem);
        }
        if self.fats > 2 {
            // Microsoft document indicates that few implementations support any values other than 1 or 2
            warn!(
                "fs compatibility: numbers of FATs '{}' in BPB is greater than '2', and thus is incompatible with some implementations",
                self.fats
            );
        }
        Ok(())
    }

    fn validate_root_entries<E: IoError>(&self) -> Result<(), Error<E>> {
        let is_fat32 = self.is_fat32();
        if is_fat32 && self.root_entries != 0 {
            error!(
                "Invalid root_entries value in FAT32 BPB: expected 0 but got {}",
                self.root_entries
            );
            return Err(Error::CorruptedFileSystem);
        }
        if !is_fat32 && self.root_entries == 0 {
            error!(
                "Invalid root_entries value in FAT12/FAT16 BPB: expected non-zero value but got {}",
                self.root_entries
            );
            return Err(Error::CorruptedFileSystem);
        }
        if (u32::from(self.root_entries) * DIR_ENTRY_SIZE) % u32::from(self.bytes_per_sector) != 0 {
            warn!("Root entries should fill sectors fully");
        }
        Ok(())
    }

    fn validate_total_sectors<E: IoError>(&self) -> Result<(), Error<E>> {
        let is_fat32 = self.is_fat32();
        if is_fat32 && self.total_sectors_16 != 0 {
            error!(
                "Invalid total_sectors_16 value in FAT32 BPB: expected 0 but got {}",
                self.total_sectors_16
            );
            return Err(Error::CorruptedFileSystem);
        }
        if (self.total_sectors_16 == 0) == (self.total_sectors_32 == 0) {
            error!("Invalid BPB (total_sectors_16 or total_sectors_32 should be non-zero)");
            return Err(Error::CorruptedFileSystem);
        }
        let total_sectors = self.total_sectors();
        let first_data_sector = self.first_data_sector();
        if total_sectors <= first_data_sector {
            error!(
                "Invalid total_sectors value in BPB: expected value > {} but got {}",
                first_data_sector, total_sectors
            );
            return Err(Error::CorruptedFileSystem);
        }
        Ok(())
    }

    fn validate_sectors_per_fat<E: IoError>(&self) -> Result<(), Error<E>> {
        let is_fat32 = self.is_fat32();
        if is_fat32 && self.sectors_per_fat_32 == 0 {
            error!(
                "Invalid sectors_per_fat_32 value in FAT32 BPB: expected non-zero value but got {}",
                self.sectors_per_fat_32
            );
            return Err(Error::CorruptedFileSystem);
        }
        Ok(())
    }

    fn validate_total_clusters<E: IoError>(&self) -> Result<(), Error<E>> {
        let is_fat32 = self.is_fat32();
        let total_clusters = self.total_clusters();
        let fat_type = FatType::from_clusters(total_clusters);
        if is_fat32 != (fat_type == FatType::Fat32) {
            error!(
                "Invalid BPB: result of FAT32 determination from total number of clusters and sectors_per_fat_16 field differs"
            );
            return Err(Error::CorruptedFileSystem);
        }
        if fat_type == FatType::Fat32 && total_clusters > 0x0FFF_FFFF {
            error!("Invalid BPB: too many clusters {}", total_clusters);
            return Err(Error::CorruptedFileSystem);
        }

        let bits_per_fat_entry = fat_type.bits_per_fat_entry();
        let total_fat_entries =
            self.sectors_per_fat() * u32::from(self.bytes_per_sector) * 8 / bits_per_fat_entry;
        let usable_fat_entries = total_fat_entries - RESERVED_FAT_ENTRIES;
        if usable_fat_entries < total_clusters {
            warn!(
                "FAT is too small (allows allocation of {} clusters) compared to the total number of clusters ({})",
                usable_fat_entries, total_clusters
            );
        }
        Ok(())
    }

    pub(crate) fn validate<E: IoError>(&self) -> Result<(), Error<E>> {
        if self.fs_version != 0 {
            error!("Unsupported filesystem version: expected 0 but got {}", self.fs_version);
            return Err(Error::CorruptedFileSystem);
        }
        self.validate_bytes_per_sector()?;
        self.validate_sectors_per_cluster()?;
        self.validate_reserved_sectors()?;
        self.validate_fats()?;
        self.validate_root_entries()?;
        self.validate_total_sectors()?;
        self.validate_sectors_per_fat()?;
        self.validate_total_clusters()?;
        Ok(())
    }

    pub(crate) fn mirroring_enabled(&self) -> bool {
        self.extended_flags & 0x80 == 0
    }

    pub(crate) fn active_fat(&self) -> u16 {
        // The zero-based number of the active FAT is only valid if mirroring is disabled.
        if self.mirroring_enabled() {
            0
        } else {
            self.extended_flags & 0x0F
        }
    }

    pub(crate) fn status_flags(&self) -> FsStatusFlags {
        FsStatusFlags::decode(self.reserved_1)
    }

    pub(crate) fn is_fat32(&self) -> bool {
        // because this field must be zero on FAT32, and
        // because it must be non-zero on FAT12/FAT16,
        // this provides a simple way to detect FAT32
        self.sectors_per_fat_16 == 0
    }

    pub(crate) fn sectors_per_fat(&self) -> u32 {
        if self.is_fat32() {
            self.sectors_per_fat_32
        } else {
            u32::from(self.sectors_per_fat_16)
        }
    }

    pub(crate) fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 == 0 {
            self.total_sectors_32
        } else {
            u32::from(self.total_sectors_16)
        }
    }

    pub(crate) fn reserved_sectors(&self) -> u32 {
        u32::from(self.reserved_sectors)
    }

    pub(crate) fn root_dir_sectors(&self) -> u32 {
        let root_dir_bytes = u32::from(self.root_entries) * DIR_ENTRY_SIZE;
        (root_dir_bytes + u32::from(self.bytes_per_sector) - 1) / u32::from(self.bytes_per_sector)
    }

    pub(crate) fn sectors_per_all_fats(&self) -> u32 {
        u32::from(self.fats) * self.sectors_per_fat()
    }

    pub(crate) fn first_data_sector(&self) -> u32 {
        let root_dir_sectors = self.root_dir_sectors();
        let fat_sectors = self.sectors_per_all_fats();
        self.reserved_sectors() + fat_sectors + root_dir_sectors
    }

    pub(crate) fn total_clusters(&self) -> u32 {
        let total_sectors = self.total_sectors();
        let first_data_sector = self.first_data_sector();
        let data_sectors = total_sectors - first_data_sector;
        data_sectors / u32::from(self.sectors_per_cluster)
    }

    pub(crate) fn bytes_from_sectors(&self, sectors: u32) -> u64 {
        // Note: total number of sectors is a 32 bit number so offsets have to be 64 bit
        u64::from(sectors) * u64::from(self.bytes_per_sector)
    }

    pub(crate) fn sectors_from_clusters(&self, clusters: u32) -> u32 {
        // Note: total number of sectors is a 32 bit number so it should not overflow
        clusters * u32::from(self.sectors_per_cluster)
    }

    pub(crate) fn cluster_size(&self) -> u32 {
        u32::from(self.sectors_per_cluster) * u32::from(self.bytes_per_sector)
    }

    pub(crate) fn clusters_from_bytes(&self, bytes: u64) -> u32 {
        let cluster_size = u64::from(self.cluster_size());
        ((bytes + cluster_size - 1) / cluster_size) as u32
    }

    pub(crate) fn fs_info_sector(&self) -> u32 {
        u32::from(self.fs_info_sector)
    }

    pub(crate) fn backup_boot_sector(&self) -> u32 {
        u32::from(self.backup_boot_sector)
    }
}
