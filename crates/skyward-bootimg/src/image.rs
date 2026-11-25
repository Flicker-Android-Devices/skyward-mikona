use abootimg_oxide::binrw::{io::Cursor, BinRead, BinWrite};
use abootimg_oxide::{Header, HeaderV3, VendorHeader};
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::fs;
use std::path::Path;

const PAGE: usize = 4096;
const VENDOR_MAGIC: &[u8] = b"VNDRBOOT";

/// A boot image with header version 3 or 4 (`boot`, `init_boot`, `recovery`)
/// split into its header, kernel and ramdisk.
pub struct BootImage {
    pub header: HeaderV3,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
}

/// A vendor boot image (`vendor_boot`) split into its header, vendor
/// ramdisk, DTB and optional v4 sections.
pub struct VendorBootImage {
    pub header: VendorHeader,
    pub ramdisk: Vec<u8>,
    pub dtb: Vec<u8>,
    pub ramdisk_table: Vec<u8>,
    pub bootconfig: Vec<u8>,
}

/// Either a standard boot/recovery image (`ANDROID!`) or a vendor boot image
/// (`VNDRBOOT`).
pub enum Image {
    Boot(BootImage),
    Vendor(VendorBootImage),
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = match Header::parse(&mut Cursor::new(bytes)).context("header")? {
            Header::V3(h) => h,
            Header::V0(h) => bail!("header version {} predates the ramdisk-only layout", h.header_version()),
        };
        let kernel = section(bytes, HeaderV3::kernel_position(), header.kernel_size, "kernel")?;
        let ramdisk = section(bytes, header.ramdisk_position(), header.ramdisk_size, "ramdisk")?;
        Ok(BootImage { header, kernel, ramdisk })
    }

    /// The image with sizes taken from its parts. A version 4 header keeps its
    /// version but carries no boot signature; unlocked bootloaders do not ask
    /// for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
        header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
        header.v4_signature_size = header.v4_signature_size.map(|_| 0);
        let mut out = Vec::new();
        Header::V3(header).write(&mut out).context("write header")?;
        pad(&mut out, PAGE);
        out.extend_from_slice(&self.kernel);
        pad(&mut out, PAGE);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, PAGE);
        Ok(out)
    }
}

impl VendorBootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        VendorBootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = VendorHeader::read(&mut Cursor::new(bytes)).context("vendor_boot header")?;
        ensure!(header.page_size > 0, "vendor_boot page size is 0");
        let ramdisk = section(bytes, header.ramdisk_position(), header.vendor_ramdisk_size, "vendor_ramdisk")?;
        let dtb = section(bytes, header.dtb_position(), header.dtb_size, "dtb")?;
        let (ramdisk_table, bootconfig) = match &header.v4 {
            Some(v4) => {
                let table = section(bytes, header.ramdisk_table_position(), v4.vendor_ramdisk_table_size, "vendor_ramdisk_table")?;
                let pos = header.bootconfig_position().expect("v4 has bootconfig position");
                let config = section(bytes, pos, v4.bootconfig_size, "bootconfig")?;
                (table, config)
            }
            None => (Vec::new(), Vec::new()),
        };
        Ok(VendorBootImage { header, ramdisk, dtb, ramdisk_table, bootconfig })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        let page = usize::try_from(header.page_size).context("page size")?;
        ensure!(page > 0, "vendor_boot page size is 0");
        let ramdisk_size = u32::try_from(self.ramdisk.len()).context("vendor_ramdisk size")?;
        header.vendor_ramdisk_size = ramdisk_size;
        header.dtb_size = u32::try_from(self.dtb.len()).context("dtb size")?;
        let mut table = self.ramdisk_table.clone();
        if let Some(v4) = &mut header.v4 {
            ensure!(v4.vendor_ramdisk_table_entry_num <= 1, "vendor_boot v4 with {} ramdisk entries is not supported for repacking", v4.vendor_ramdisk_table_entry_num);
            if v4.vendor_ramdisk_table_entry_num == 1 {
                ensure!(table.len() >= 8, "vendor_ramdisk_table is too short");
                table[0..4].copy_from_slice(&ramdisk_size.to_le_bytes());
                table[4..8].copy_from_slice(&0u32.to_le_bytes());
            }
            v4.vendor_ramdisk_table_size = u32::try_from(table.len()).context("vendor_ramdisk_table size")?;
            v4.bootconfig_size = u32::try_from(self.bootconfig.len()).context("bootconfig size")?;
        }
        let mut out = Vec::new();
        header.write(&mut Cursor::new(&mut out)).context("write vendor_boot header")?;
        pad(&mut out, page);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, page);
        out.extend_from_slice(&self.dtb);
        pad(&mut out, page);
        if header.v4.is_some() {
            out.extend_from_slice(&table);
            pad(&mut out, page);
            out.extend_from_slice(&self.bootconfig);
            pad(&mut out, page);
        }
        Ok(out)
    }
}

impl Image {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Image::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(VENDOR_MAGIC) {
            Ok(Image::Vendor(VendorBootImage::parse(bytes)?))
        } else {
            Ok(Image::Boot(BootImage::parse(bytes)?))
        }
    }

    pub fn header_version(&self) -> u32 {
        match self {
            Image::Boot(b) => b.header.header_version(),
            Image::Vendor(v) => v.header.header_version(),
        }
    }

    pub fn kernel_len(&self) -> usize {
        match self {
            Image::Boot(b) => b.kernel.len(),
            Image::Vendor(_) => 0,
        }
    }

    pub fn ramdisk(&self) -> &[u8] {
        match self {
            Image::Boot(b) => &b.ramdisk,
            Image::Vendor(v) => &v.ramdisk,
        }
    }

    pub fn set_ramdisk(&mut self, ramdisk: Vec<u8>) {
        match self {
            Image::Boot(b) => b.ramdisk = ramdisk,
            Image::Vendor(v) => v.ramdisk = ramdisk,
        }
    }

    pub fn partition_name(&self) -> &'static str {
        match self {
            Image::Boot(_) => "recovery",
            Image::Vendor(_) => "vendor_boot",
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Image::Boot(b) => b.to_bytes(),
            Image::Vendor(v) => v.to_bytes(),
        }
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abootimg_oxide::VendorHeaderV4;

    #[test]
    fn vendor_boot_v3_round_trip_keeps_dtb_and_updates_sizes() {
        let header = VendorHeader {
            page_size: 4096,
            kernel_addr: 0x0000_8000,
            ramdisk_addr: 0x0100_0000,
            vendor_ramdisk_size: 0,
            cmdline: Box::new([0; 2048]),
            tags_addr: 0x0000_0100,
            board_name: *b"thyme\0\0\0\0\0\0\0\0\0\0\0",
            dtb_size: 0,
            dtb_addr: 0x01f0_0000,
            v4: None,
        };
        let img = VendorBootImage {
            header,
            ramdisk: b"new-ramdisk".to_vec(),
            dtb: b"fake-dtb".to_vec(),
            ramdisk_table: Vec::new(),
            bootconfig: Vec::new(),
        };
        let bytes = img.to_bytes().unwrap();
        let back = VendorBootImage::parse(&bytes).unwrap();
        assert_eq!(back.header.header_version(), 3);
        assert_eq!(back.ramdisk, b"new-ramdisk");
        assert_eq!(back.dtb, b"fake-dtb");
        assert!(matches!(Image::parse(&bytes).unwrap(), Image::Vendor(_)));
    }

    #[test]
    fn vendor_boot_v4_single_entry_updates_table_size() {
        let header = VendorHeader {
            page_size: 4096,
            kernel_addr: 0,
            ramdisk_addr: 0,
            vendor_ramdisk_size: 0,
            cmdline: Box::new([0; 2048]),
            tags_addr: 0,
            board_name: [0; 16],
            dtb_size: 0,
            dtb_addr: 0,
            v4: Some(VendorHeaderV4 {
                vendor_ramdisk_table_size: 108,
                vendor_ramdisk_table_entry_num: 1,
                vendor_ramdisk_table_entry_size: 108,
                bootconfig_size: 0,
            }),
        };
        let img = VendorBootImage {
            header,
            ramdisk: b"abcde".to_vec(),
            dtb: b"dtb".to_vec(),
            ramdisk_table: vec![0u8; 108],
            bootconfig: b"a=1\n".to_vec(),
        };
        let bytes = img.to_bytes().unwrap();
        let back = VendorBootImage::parse(&bytes).unwrap();
        assert_eq!(u32::from_le_bytes(back.ramdisk_table[0..4].try_into().unwrap()), 5);
        assert_eq!(back.bootconfig, b"a=1\n");
    }
}
