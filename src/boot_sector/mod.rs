use core::cmp;

use hex_literal::hex;

use crate::{
    dir_entry::DIR_ENTRY_SIZE,
    error::{Error, IoError},
    fs::{FatType, FormatVolumeOptions},
    io::{Read, Write},
};

pub(crate) mod bpb;

const BITS_PER_BYTE: u32 = 8;
const KB_32: u32 = 1024;
const KB_64: u64 = 1024;
const MB_64: u64 = KB_64 * 1024;
const GB_64: u64 = MB_64 * 1024;

pub(crate) struct BootSector {
    bootjmp: [u8; 3],
    oem_name: [u8; 8],
    pub(crate) bpb: bpb::BiosParameterBlock,
    boot_code: [u8; 448],
    boot_sig: [u8; 2],
}

impl BootSector {
    pub(crate) fn deserialize<R: Read>(rdr: &mut R) -> Result<Self, R::Error> {
        let mut boot = Self::default();
        rdr.read_exact(&mut boot.bootjmp)?;
        rdr.read_exact(&mut boot.oem_name)?;
        boot.bpb = bpb::BiosParameterBlock::deserialize(rdr)?;

        if boot.bpb.is_fat32() {
            rdr.read_exact(&mut boot.boot_code[0..420])?;
        } else {
            rdr.read_exact(&mut boot.boot_code[0..448])?;
        }
        rdr.read_exact(&mut boot.boot_sig)?;
        Ok(boot)
    }

    pub(crate) fn serialize<W: Write>(&self, wrt: &mut W) -> Result<(), W::Error> {
        wrt.write_all(&self.bootjmp)?;
        wrt.write_all(&self.oem_name)?;
        self.bpb.serialize(&mut *wrt)?;

        if self.bpb.is_fat32() {
            wrt.write_all(&self.boot_code[0..420])?;
        } else {
            wrt.write_all(&self.boot_code[0..448])?;
        }
        wrt.write_all(&self.boot_sig)?;
        Ok(())
    }

    pub(crate) fn validate<E: IoError>(&self) -> Result<(), Error<E>> {
        if self.boot_sig != [0x55, 0xAA] {
            error!(
                "Invalid boot sector signature: expected [0x55, 0xAA] but got {:?}",
                self.boot_sig
            );
            return Err(Error::CorruptedFileSystem);
        }
        if self.bootjmp[0] != 0xEB && self.bootjmp[0] != 0xE9 {
            warn!("Unknown opcode {:x} in bootjmp boot sector field", self.bootjmp[0]);
        }
        self.bpb.validate()?;
        Ok(())
    }
}

impl Default for BootSector {
    fn default() -> Self {
        Self {
            bootjmp: Default::default(),
            oem_name: Default::default(),
            bpb: bpb::BiosParameterBlock::default(),
            boot_code: [0; 448],
            boot_sig: Default::default(),
        }
    }
}

pub(crate) fn estimate_fat_type(total_bytes: u64) -> FatType {
    // Used only to select cluster size if FAT type has not been overriden in options
    if total_bytes < 4 * MB_64 {
        FatType::Fat12
    } else if total_bytes < 512 * MB_64 {
        FatType::Fat16
    } else {
        FatType::Fat32
    }
}

fn determine_bytes_per_cluster(
    total_bytes: u64,
    bytes_per_sector: u16,
    fat_type: Option<FatType>,
) -> u32 {
    const MAX_CLUSTER_SIZE: u32 = 32 * KB_32;

    let fat_type = fat_type.unwrap_or_else(|| estimate_fat_type(total_bytes));
    let bytes_per_cluster = match fat_type {
        FatType::Fat12 => (total_bytes.next_power_of_two() / MB_64 * 512) as u32,
        FatType::Fat16 => {
            if total_bytes <= 16 * MB_64 {
                KB_32
            } else if total_bytes <= 128 * MB_64 {
                2 * KB_32
            } else {
                ((total_bytes.next_power_of_two() / (64 * MB_64)) as u32) * KB_32
            }
        }
        FatType::Fat32 => {
            if total_bytes <= 260 * MB_64 {
                512
            } else if total_bytes <= 8 * GB_64 {
                4 * KB_32
            } else {
                ((total_bytes.next_power_of_two() / (2 * GB_64)) as u32) * KB_32
            }
        }
    };
    let bytes_per_cluster_clamped =
        cmp::min(cmp::max(bytes_per_cluster, u32::from(bytes_per_sector)), MAX_CLUSTER_SIZE);
    debug_assert!(bytes_per_cluster_clamped.is_power_of_two());
    bytes_per_cluster_clamped
}

fn determine_sectors_per_fat(
    total_sectors: u32,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    fat_type: FatType,
    reserved_sectors: u16,
    root_dir_sectors: u32,
    fats: u8,
) -> u32 {
    //
    // FAT size formula transformations:
    //
    // Initial basic formula:
    // size of FAT in bits >= (total number of clusters + 2) * bits per FAT entry
    //
    // Note: when computing number of clusters from number of sectors rounding down is used because partial clusters
    // are not allowed
    // Note: in those transformations '/' is a floating-point division (not a rounding towards zero division)
    //
    // data_sectors = total_sectors - reserved_sectors - fats * sectors_per_fat - root_dir_sectors
    // total_clusters = floor(data_sectors / sectors_per_cluster)
    // bits_per_sector = bytes_per_sector * 8
    // sectors_per_fat * bits_per_sector >= (total_clusters + 2) * bits_per_fat_entry
    // sectors_per_fat * bits_per_sector >= (floor(data_sectors / sectors_per_cluster) + 2) * bits_per_fat_entry
    //
    // Note: omitting the floor function can cause the FAT to be bigger by 1 entry - negligible
    //
    // sectors_per_fat * bits_per_sector >= (data_sectors / sectors_per_cluster + 2) * bits_per_fat_entry
    // t0 = total_sectors - reserved_sectors - root_dir_sectors
    // sectors_per_fat * bits_per_sector >= ((t0 - fats * sectors_per_fat) / sectors_per_cluster + 2) * bits_per_fat_entry
    // sectors_per_fat * bits_per_sector / bits_per_fat_entry >= (t0 - fats * sectors_per_fat) / sectors_per_cluster + 2
    // sectors_per_fat * bits_per_sector / bits_per_fat_entry >= t0 / sectors_per_cluster + 2 - fats * sectors_per_fat / sectors_per_cluster
    // sectors_per_fat * bits_per_sector / bits_per_fat_entry + fats * sectors_per_fat / sectors_per_cluster >= t0 / sectors_per_cluster + 2
    // sectors_per_fat * (bits_per_sector / bits_per_fat_entry + fats / sectors_per_cluster) >= t0 / sectors_per_cluster + 2
    // sectors_per_fat >= (t0 / sectors_per_cluster + 2) / (bits_per_sector / bits_per_fat_entry + fats / sectors_per_cluster)
    //
    // Note: MS specification omits the constant 2 in calculations. This library is taking a better approach...
    //
    // sectors_per_fat >= ((t0 + 2 * sectors_per_cluster) / sectors_per_cluster) / (bits_per_sector / bits_per_fat_entry + fats / sectors_per_cluster)
    // sectors_per_fat >= (t0 + 2 * sectors_per_cluster) / (sectors_per_cluster * bits_per_sector / bits_per_fat_entry + fats)
    //
    // Note: compared to MS formula this one can suffer from an overflow problem if u32 type is used
    //
    // When converting formula to integer types round towards a bigger FAT:
    // * first division towards infinity
    // * second division towards zero (it is in a denominator of the first division)

    let t0: u32 = total_sectors - u32::from(reserved_sectors) - root_dir_sectors;
    let t1: u64 = u64::from(t0) + u64::from(2 * u32::from(sectors_per_cluster));
    let bits_per_cluster =
        u32::from(sectors_per_cluster) * u32::from(bytes_per_sector) * BITS_PER_BYTE;
    let t2 = u64::from(bits_per_cluster / fat_type.bits_per_fat_entry() + u32::from(fats));
    let sectors_per_fat = (t1 + t2 - 1) / t2;
    // Note: casting is safe here because number of sectors per FAT cannot be bigger than total sectors number
    sectors_per_fat as u32
}

fn try_fs_geometry(
    total_sectors: u32,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    fat_type: FatType,
    root_dir_sectors: u32,
    fats: u8,
) -> Result<(u16, u32), Error<()>> {
    // Note: most of implementations use 32 reserved sectors for FAT32 but it's wasting of space
    // This implementation uses only 8. This is enough to fit in two boot sectors (main and backup) with additional
    // bootstrap code and one FSInfo sector. It also makes FAT alligned to 4096 which is a nice number.
    let reserved_sectors: u16 = if fat_type == FatType::Fat32 { 8 } else { 1 };

    // Check if volume has enough space to accomodate reserved sectors, FAT, root directory and some data space
    // Having less than 8 sectors for FAT and data would make a little sense
    if total_sectors <= u32::from(reserved_sectors) + root_dir_sectors + 8 {
        error!("Volume is too small");
        return Err(Error::InvalidInput);
    }

    // calculate File Allocation Table size
    let sectors_per_fat = determine_sectors_per_fat(
        total_sectors,
        bytes_per_sector,
        sectors_per_cluster,
        fat_type,
        reserved_sectors,
        root_dir_sectors,
        fats,
    );

    let data_sectors = total_sectors
        - u32::from(reserved_sectors)
        - root_dir_sectors
        - sectors_per_fat * u32::from(fats);
    let total_clusters = data_sectors / u32::from(sectors_per_cluster);
    if fat_type != FatType::from_clusters(total_clusters) {
        error!("Invalid FAT type");
        return Err(Error::InvalidInput);
    }
    debug_assert!(total_clusters >= fat_type.min_clusters());
    if total_clusters > fat_type.max_clusters() {
        // Note: it can happen for FAT32
        error!("Too many clusters");
        return Err(Error::InvalidInput);
    }

    Ok((reserved_sectors, sectors_per_fat))
}

fn determine_root_dir_sectors(
    root_dir_entries: u16,
    bytes_per_sector: u16,
    fat_type: FatType,
) -> u32 {
    if fat_type == FatType::Fat32 {
        0
    } else {
        let root_dir_bytes = u32::from(root_dir_entries) * DIR_ENTRY_SIZE as u32;
        (root_dir_bytes + u32::from(bytes_per_sector) - 1) / u32::from(bytes_per_sector)
    }
}

fn determine_fs_geometry<E: IoError>(
    total_sectors: u32,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    root_dir_entries: u16,
    fats: u8,
) -> Result<(FatType, u16, u32), Error<E>> {
    for &fat_type in &[FatType::Fat32, FatType::Fat16, FatType::Fat12] {
        let root_dir_sectors =
            determine_root_dir_sectors(root_dir_entries, bytes_per_sector, fat_type);
        let result = try_fs_geometry(
            total_sectors,
            bytes_per_sector,
            sectors_per_cluster,
            fat_type,
            root_dir_sectors,
            fats,
        );
        if let Ok((reserved_sectors, sectors_per_fat)) = result {
            return Ok((fat_type, reserved_sectors, sectors_per_fat));
        }
    }

    error!("Cannot select FAT type - unfortunate storage size");
    Err(Error::InvalidInput)
}

fn format_bpb<E: IoError>(
    options: &FormatVolumeOptions,
    total_sectors: u32,
    bytes_per_sector: u16,
) -> Result<(bpb::BiosParameterBlock, FatType), Error<E>> {
    let bytes_per_cluster = options.bytes_per_cluster.unwrap_or_else(|| {
        let total_bytes = u64::from(total_sectors) * u64::from(bytes_per_sector);
        determine_bytes_per_cluster(total_bytes, bytes_per_sector, options.fat_type)
    });

    let sectors_per_cluster = bytes_per_cluster / u32::from(bytes_per_sector);
    assert!(sectors_per_cluster <= u32::from(u8::MAX));
    let sectors_per_cluster = sectors_per_cluster as u8;

    let fats = options.fats.unwrap_or(2_u8);
    let root_dir_entries = options.max_root_dir_entries.unwrap_or(512);
    let (fat_type, reserved_sectors, sectors_per_fat) = determine_fs_geometry(
        total_sectors,
        bytes_per_sector,
        sectors_per_cluster,
        root_dir_entries,
        fats,
    )?;

    // drive_num should be 0 for floppy disks and 0x80 for hard disks - determine it using FAT type
    let drive_num =
        options.drive_num.unwrap_or_else(|| if fat_type == FatType::Fat12 { 0 } else { 0x80 });

    // reserved_0 is always zero
    let reserved_0 = [0_u8; 12];

    // setup volume label
    let mut volume_label = [0_u8; 11];
    if let Some(volume_label_from_opts) = options.volume_label {
        volume_label.copy_from_slice(&volume_label_from_opts);
    } else {
        volume_label.copy_from_slice(b"NO NAME    ");
    }

    // setup fs_type_label field
    let mut fs_type_label = [0_u8; 8];
    let fs_type_label_str = match fat_type {
        FatType::Fat12 => b"FAT12   ",
        FatType::Fat16 => b"FAT16   ",
        FatType::Fat32 => b"FAT32   ",
    };
    fs_type_label.copy_from_slice(fs_type_label_str);

    // create Bios Parameter Block struct
    let is_fat32 = fat_type == FatType::Fat32;
    let sectors_per_fat_16 = if is_fat32 {
        0
    } else {
        debug_assert!(sectors_per_fat <= u32::from(u16::MAX));
        sectors_per_fat as u16
    };
    let bpb = bpb::BiosParameterBlock {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fats,
        root_entries: if is_fat32 { 0 } else { root_dir_entries },
        total_sectors_16: if total_sectors < 0x10000 { total_sectors as u16 } else { 0 },
        media: options.media.unwrap_or(0xF8),
        sectors_per_fat_16,
        sectors_per_track: options.sectors_per_track.unwrap_or(0x20),
        heads: options.heads.unwrap_or(0x40),
        hidden_sectors: 0,
        total_sectors_32: if total_sectors >= 0x10000 { total_sectors } else { 0 },
        // FAT32 fields start
        sectors_per_fat_32: if is_fat32 { sectors_per_fat } else { 0 },
        extended_flags: 0, // mirroring enabled
        fs_version: 0,
        root_dir_first_cluster: if is_fat32 { 2 } else { 0 },
        fs_info_sector: if is_fat32 { 1 } else { 0 },
        backup_boot_sector: if is_fat32 { 6 } else { 0 },
        reserved_0,
        // FAT32 fields end
        drive_num,
        reserved_1: 0,
        ext_sig: 0x29,
        volume_id: options.volume_id.unwrap_or(0x1234_5678),
        volume_label,
        fs_type_label,
    };

    // Check if number of clusters is proper for used FAT type
    if FatType::from_clusters(bpb.total_clusters()) != fat_type {
        error!(
            "Total number of clusters and FAT type does not match, please try a different volume size"
        );
        return Err(Error::InvalidInput);
    }

    Ok((bpb, fat_type))
}

pub(crate) fn format_boot_sector<E: IoError>(
    options: &FormatVolumeOptions,
    total_sectors: u32,
    bytes_per_sector: u16,
) -> Result<(BootSector, FatType), Error<E>> {
    let mut boot = BootSector::default();
    let (bpb, fat_type) = format_bpb(options, total_sectors, bytes_per_sector)?;
    boot.bpb = bpb;
    boot.oem_name.copy_from_slice(b"MSWIN4.1");
    // Boot code copied from FAT32 boot sector initialized by mkfs.fat
    boot.bootjmp = [0xEB, 0x58, 0x90];
    let boot_code: [u8; 129] = hex!(
        "
        0E 1F BE 77 7C AC 22 C0 74 0B 56 B4 0E BB 07 00 CD 10
        5E EB F0 32 E4 CD 16 CD 19 EB FE 54 68 69 73 20 69 73
        20 6E 6F 74 20 61 20 62 6F 6F 74 61 62 6C 65 20 64 69
        73 6B 2E 20 20 50 6C 65 61 73 65 20 69 6E 73 65 72 74
        20 61 20 62 6F 6F 74 61 62 6C 65 20 66 6C 6F 70 70 79
        20 61 6E 64 0D 0A 70 72 65 73 73 20 61 6E 79 20 6B 65
        79 20 74 6F 20 74 72 79 20 61 67 61 69 6E 20 2E 2E 2E
        20 0D 0A"
    );
    boot.boot_code[..boot_code.len()].copy_from_slice(&boot_code);
    boot.boot_sig = [0x55, 0xAA];

    // fix offsets in bootjmp and boot code for non-FAT32 filesystems (bootcode is on a different offset)
    if fat_type != FatType::Fat32 {
        // offset of boot code
        const BOOT_CODE_OFFSET: u8 = 0x36 + 8;
        // offset of message
        const MESSAGE_OFFSET: u16 = 29;
        boot.bootjmp[1] = BOOT_CODE_OFFSET - 2;
        let message_offset_in_sector = u16::from(BOOT_CODE_OFFSET) + MESSAGE_OFFSET + 0x7c00;
        boot.boot_code[3] = (message_offset_in_sector & 0xff) as u8;
        boot.boot_code[4] = (message_offset_in_sector >> 8) as u8;
    }

    Ok((boot, fat_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::u32;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_estimate_fat_type() {
        assert_eq!(estimate_fat_type(3 * MB_64), FatType::Fat12);
        assert_eq!(estimate_fat_type(4 * MB_64), FatType::Fat16);
        assert_eq!(estimate_fat_type(511 * MB_64), FatType::Fat16);
        assert_eq!(estimate_fat_type(512 * MB_64), FatType::Fat32);
    }

    #[test]
    fn test_determine_bytes_per_cluster_fat12() {
        assert_eq!(determine_bytes_per_cluster(128 * KB_64, 512, Some(FatType::Fat12)), 512);
        assert_eq!(determine_bytes_per_cluster(MB_64, 512, Some(FatType::Fat12)), 512);
        assert_eq!(determine_bytes_per_cluster(MB_64 + 1, 512, Some(FatType::Fat12)), 1024);
        assert_eq!(determine_bytes_per_cluster(MB_64, 4096, Some(FatType::Fat12)), 4096);
    }

    #[test]
    #[rustfmt::skip]
    fn test_determine_bytes_per_cluster_fat16() {
        assert_eq!(determine_bytes_per_cluster(MB_64,            512, Some(FatType::Fat16)), KB_32);
        assert_eq!(determine_bytes_per_cluster(MB_64,            4096, Some(FatType::Fat16)), 4 * KB_32);
        assert_eq!(determine_bytes_per_cluster(16 * MB_64,       512, Some(FatType::Fat16)), KB_32);
        assert_eq!(determine_bytes_per_cluster(16 * MB_64 + 1,   512, Some(FatType::Fat16)), 2 * KB_32);
        assert_eq!(determine_bytes_per_cluster(128 * MB_64,      512, Some(FatType::Fat16)), 2 * KB_32);
        assert_eq!(determine_bytes_per_cluster(128 * MB_64 + 1,  512, Some(FatType::Fat16)), 4 * KB_32);
        assert_eq!(determine_bytes_per_cluster(256 * MB_64,      512, Some(FatType::Fat16)), 4 * KB_32);
        assert_eq!(determine_bytes_per_cluster(256 * MB_64 + 1,  512, Some(FatType::Fat16)), 8 * KB_32);
        assert_eq!(determine_bytes_per_cluster(512 * MB_64,      512, Some(FatType::Fat16)), 8 * KB_32);
        assert_eq!(determine_bytes_per_cluster(512 * MB_64 + 1,  512, Some(FatType::Fat16)), 16 * KB_32);
        assert_eq!(determine_bytes_per_cluster(1024 * MB_64,     512, Some(FatType::Fat16)), 16 * KB_32);
        assert_eq!(determine_bytes_per_cluster(1024 * MB_64 + 1, 512, Some(FatType::Fat16)), 32 * KB_32);
        assert_eq!(determine_bytes_per_cluster(99999 * MB_64,    512, Some(FatType::Fat16)), 32 * KB_32);
    }

    #[test]
    #[rustfmt::skip]
    fn test_determine_bytes_per_cluster_fat32() {
        assert_eq!(determine_bytes_per_cluster(260 * MB_64,     512, Some(FatType::Fat32)), 512);
        assert_eq!(determine_bytes_per_cluster(260 * MB_64,     4096, Some(FatType::Fat32)), 4 * KB_32);
        assert_eq!(determine_bytes_per_cluster(260 * MB_64 + 1, 512, Some(FatType::Fat32)), 4 * KB_32);
        assert_eq!(determine_bytes_per_cluster(8   * GB_64,     512, Some(FatType::Fat32)), 4 * KB_32);
        assert_eq!(determine_bytes_per_cluster(8   * GB_64 + 1, 512, Some(FatType::Fat32)), 8 * KB_32);
        assert_eq!(determine_bytes_per_cluster(16  * GB_64,     512, Some(FatType::Fat32)), 8 * KB_32);
        assert_eq!(determine_bytes_per_cluster(16  * GB_64 + 1, 512, Some(FatType::Fat32)), 16 * KB_32);
        assert_eq!(determine_bytes_per_cluster(32  * GB_64,     512, Some(FatType::Fat32)), 16 * KB_32);
        assert_eq!(determine_bytes_per_cluster(32  * GB_64 + 1, 512, Some(FatType::Fat32)), 32 * KB_32);
        assert_eq!(determine_bytes_per_cluster(999 * GB_64,     512, Some(FatType::Fat32)), 32 * KB_32);
    }

    fn test_determine_sectors_per_fat_single(
        total_bytes: u64,
        bytes_per_sector: u16,
        bytes_per_cluster: u32,
        fat_type: FatType,
        reserved_sectors: u16,
        fats: u8,
        root_dir_entries: u32,
    ) {
        let total_sectors = total_bytes / u64::from(bytes_per_sector);
        debug_assert!(total_sectors <= u64::from(u32::MAX), "{:x}", total_sectors);
        let total_sectors = total_sectors as u32;

        let sectors_per_cluster = (bytes_per_cluster / u32::from(bytes_per_sector)) as u8;
        let root_dir_size = root_dir_entries * DIR_ENTRY_SIZE as u32;
        let root_dir_sectors =
            (root_dir_size + u32::from(bytes_per_sector) - 1) / u32::from(bytes_per_sector);
        let sectors_per_fat = determine_sectors_per_fat(
            total_sectors,
            bytes_per_sector,
            sectors_per_cluster,
            fat_type,
            reserved_sectors,
            root_dir_sectors,
            fats,
        );

        let sectors_per_all_fats = u32::from(fats) * sectors_per_fat;
        let total_data_sectors =
            total_sectors - u32::from(reserved_sectors) - sectors_per_all_fats - root_dir_sectors;
        let total_clusters = total_data_sectors / u32::from(sectors_per_cluster);
        if FatType::from_clusters(total_clusters) != fat_type {
            // Skip impossible FAT configurations
            return;
        }
        let bits_per_sector = u32::from(bytes_per_sector) * BITS_PER_BYTE;
        let bits_per_fat = u64::from(sectors_per_fat) * u64::from(bits_per_sector);
        let total_fat_entries = (bits_per_fat / u64::from(fat_type.bits_per_fat_entry())) as u32;
        let fat_clusters = total_fat_entries - RESERVED_FAT_ENTRIES;
        // Note: fat_entries_per_sector is rounded down for FAT12
        let fat_entries_per_sector = bits_per_sector / fat_type.bits_per_fat_entry();
        let desc = format!(
            "total_clusters {}, fat_clusters {}, total_sectors {}, bytes/sector {}, sectors/cluster {}, fat_type {:?}, reserved_sectors {}, root_dir_sectors {}, sectors_per_fat {}",
            total_clusters,
            fat_clusters,
            total_sectors,
            bytes_per_sector,
            sectors_per_cluster,
            fat_type,
            reserved_sectors,
            root_dir_sectors,
            sectors_per_fat
        );
        assert!(fat_clusters >= total_clusters, "Too small FAT: {}", desc);
        let expected_max_fat_clusters = total_clusters + 2 * fat_entries_per_sector;
        assert!(fat_clusters <= expected_max_fat_clusters, "Too big FAT: {}", desc);
    }

    fn test_determine_sectors_per_fat_for_multiple_sizes(
        bytes_per_sector: u16,
        fat_type: FatType,
        reserved_sectors: u16,
        fats: u8,
        root_dir_entries: u32,
    ) {
        let mut bytes_per_cluster = u32::from(bytes_per_sector);
        while bytes_per_cluster <= 64 * KB_32 {
            let mut size: u64 = MB_64;
            while size < 2048 * GB_64 {
                test_determine_sectors_per_fat_single(
                    size,
                    bytes_per_sector,
                    bytes_per_cluster,
                    fat_type,
                    reserved_sectors,
                    fats,
                    root_dir_entries,
                );
                size = size + size / 7;
            }
            size = 2048 * GB_64 - 1;
            test_determine_sectors_per_fat_single(
                size,
                bytes_per_sector,
                bytes_per_cluster,
                fat_type,
                reserved_sectors,
                fats,
                root_dir_entries,
            );
            bytes_per_cluster *= 2;
        }
    }

    #[test]
    fn test_determine_sectors_per_fat() {
        init();

        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat12, 1, 2, 512);
        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat12, 1, 1, 512);
        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat12, 1, 2, 8192);
        test_determine_sectors_per_fat_for_multiple_sizes(4096, FatType::Fat12, 1, 2, 512);

        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat16, 1, 2, 512);
        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat16, 1, 1, 512);
        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat16, 1, 2, 8192);
        test_determine_sectors_per_fat_for_multiple_sizes(4096, FatType::Fat16, 1, 2, 512);

        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat32, 32, 2, 0);
        test_determine_sectors_per_fat_for_multiple_sizes(512, FatType::Fat32, 32, 1, 0);
        test_determine_sectors_per_fat_for_multiple_sizes(4096, FatType::Fat32, 32, 2, 0);
    }

    #[test]
    fn test_format_boot_sector() {
        init();

        let bytes_per_sector = 512_u16;
        // test all partition sizes from 1MB to 2TB (u32::MAX sectors is 2TB - 1 for 512 byte sectors)
        let mut total_sectors_vec = Vec::new();
        let mut size = MB_64;
        while size < 2048 * GB_64 {
            total_sectors_vec.push((size / u64::from(bytes_per_sector)) as u32);
            size = size + size / 7;
        }
        total_sectors_vec.push(u32::MAX);
        for total_sectors in total_sectors_vec {
            let (boot, _) = format_boot_sector::<()>(
                &FormatVolumeOptions::new(),
                total_sectors,
                bytes_per_sector,
            )
            .expect("format_boot_sector");
            boot.validate::<()>().expect("validate");
        }
    }
}
