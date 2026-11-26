//! Persisting the running Skyward recovery into the device's `vendor_boot`
//! partition(s), keeping each slot's own header, DTB, bootconfig, `init`,
//! and `first_stage_ramdisk` untouched while injecting Skyward's runtime files
//! and re-creating the unsigned AVB footer.

use crate::image;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use skyward_bootimg::{avb, lz4_legacy, prop, sepolicy, Ramdisk, VendorBootImage};
use skyward_config::{ramdisk as paths, RecoveryPartition};
use skyward_vab::Slot;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// Skyward's own recovery payload extracted from the running rootfs, excluding
/// `init` and stock `vendor_boot` resources so normal Android boot stays intact.
#[derive(Clone)]
pub struct Payload {
    pub recovery: Vec<u8>,
    pub system_init: Vec<u8>,
    pub config: Vec<u8>,
    pub font: Vec<u8>,
    pub mono: Vec<u8>,
    pub mono_license: Vec<u8>,
    pub mtp_rc: Vec<u8>,
    pub task_profiles: Option<Vec<u8>>,
}

impl Payload {
    /// Collect Skyward's runtime recovery files from `root` (normally `/`).
    pub fn from_root(root: &Path) -> Result<Self> {
        let read = |rel: &str| -> Result<Vec<u8>> {
            let p = root.join(rel);
            fs::read(&p).with_context(|| format!("read {}", p.display()))
        };
        let task_profiles = match fs::read(root.join(paths::TASK_PROFILES)) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("read {}", root.join(paths::TASK_PROFILES).display())),
        };
        Ok(Self {
            recovery: read(paths::RECOVERY)?,
            system_init: read(paths::SYSTEM_INIT)?,
            config: read(paths::CONFIG)?,
            font: read(paths::FONT)?,
            mono: read(paths::MONO)?,
            mono_license: read(paths::MONO_LICENSE)?,
            mtp_rc: read(paths::MTP_RC)?,
            task_profiles,
        })
    }
}

/// Progress reported while persisting Skyward into `vendor_boot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Preparing,
    Writing { done: u64, total: u64 },
}

/// Outcome of [`install`], distinguishing failures before any partition was
/// modified from failures after writing started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Installed(Vec<Slot>),
    NotWritten(String),
    WriteFailed(Vec<Slot>, String),
}

/// Inject `payload` into a stock (or already-persisted) `vendor_boot` partition
/// image `raw_partition` of `partition_size` bytes, leaving `init`,
/// `first_stage_ramdisk`, `dtb`, and `bootconfig` intact and finishing with an
/// unsigned AVB footer.
pub fn patch_vendor_boot(raw_partition: &[u8], partition_size: usize, payload: &Payload) -> Result<Vec<u8>> {
    let mut img = VendorBootImage::parse(raw_partition).context("parse vendor_boot image")?;
    let mut rd = Ramdisk::decode(&img.ramdisk).context("decode vendor_boot ramdisk")?;

    rd.upsert(paths::RECOVERY, 0o755, payload.recovery.clone())?;
    let (_, recovery_name) = paths::RECOVERY.rsplit_once('/').expect("recovery path has /");
    for command in paths::COMMANDS {
        rd.link(command, recovery_name)?;
    }
    rd.upsert(paths::SYSTEM_INIT, 0o755, payload.system_init.clone())?;
    rd.upsert(paths::CONFIG, 0o644, payload.config.clone())?;
    rd.upsert(paths::FONT, 0o644, payload.font.clone())?;
    rd.upsert(paths::MONO, 0o644, payload.mono.clone())?;
    rd.upsert(paths::MONO_LICENSE, 0o644, payload.mono_license.clone())?;
    rd.upsert(paths::MTP_RC, 0o644, payload.mtp_rc.clone())?;
    if rd.find(paths::TASK_PROFILES).is_none()
        && let Some(profiles) = &payload.task_profiles
    {
        rd.add(paths::TASK_PROFILES, 0o644, profiles.clone())?;
    }

    let stock_props = &rd
        .find(paths::PROP_DEFAULT)
        .with_context(|| format!("{} is not in vendor_boot ramdisk", paths::PROP_DEFAULT))?
        .data;
    rd.replace(paths::PROP_DEFAULT, prop::patch_default(stock_props))?;

    if let Some(policy) = rd.find(paths::SEPOLICY) {
        let patched = sepolicy::make_permissive(&policy.data, &["kernel"])?;
        rd.replace(paths::SEPOLICY, patched)?;
    }

    img.ramdisk = lz4_legacy(&rd.archive()?);
    let bytes = img.to_bytes()?;
    avb::footed(&bytes, RecoveryPartition::VendorBoot.partition(), partition_size, &Sha256::digest(&bytes))
}

/// Merge `payload` into each selected `vendor_boot` slot under `dir`, verify
/// every image fits before writing anything, then flash and read back each slot.
pub fn install(dir: &Path, partition: RecoveryPartition, payload: &Payload, slots: &[Slot], progress: &mut dyn FnMut(Stage)) -> Outcome {
    if partition != RecoveryPartition::VendorBoot {
        return Outcome::NotWritten("only vendor_boot recovery persistence is supported".into());
    }
    if slots.is_empty() {
        return Outcome::NotWritten("no slots selected".into());
    }
    progress(Stage::Preparing);

    let name = partition.partition();
    let mut prepared: Vec<(Slot, PathBuf, Vec<u8>)> = Vec::with_capacity(slots.len());
    for &slot in slots {
        let path = image::device(dir, name, slot);
        let built = (|| -> Result<Vec<u8>> {
            let mut file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
            image::drop_cache(&file).with_context(|| format!("drop cached pages of {}", path.display()))?;
            let mut raw = Vec::new();
            file.read_to_end(&mut raw).with_context(|| format!("read {}", path.display()))?;
            patch_vendor_boot(&raw, raw.len(), payload)
        })();
        match built {
            Ok(bytes) => prepared.push((slot, path, bytes)),
            Err(e) => return Outcome::NotWritten(format!("{e:#}")),
        }
    }

    let total: u64 = prepared.iter().map(|(_, _, bytes)| 2 * bytes.len() as u64).sum();
    let mut done_so_far = 0u64;
    let mut written = Vec::with_capacity(prepared.len());
    for (slot, path, bytes) in &prepared {
        progress(Stage::Writing { done: done_so_far, total });
        if let Err(e) = image::flash(&mut Cursor::new(bytes), bytes.len() as u64, std::slice::from_ref(path), &mut |done, _| {
            progress(Stage::Writing { done: done_so_far + done, total });
        }) {
            return Outcome::WriteFailed(written, format!("{e:#}"));
        }
        written.push(*slot);
        done_so_far += 2 * bytes.len() as u64;
    }
    Outcome::Installed(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(config: &[u8]) -> Payload {
        Payload {
            recovery: b"skyward-bin".to_vec(),
            system_init: b"sys-init".to_vec(),
            config: config.to_vec(),
            font: b"font".to_vec(),
            mono: b"mono".to_vec(),
            mono_license: b"ofl".to_vec(),
            mtp_rc: b"mtp".to_vec(),
            task_profiles: Some(b"{}".to_vec()),
        }
    }

    fn stock_vendor_boot(partition_size: usize, dtb: &[u8], stock_tag: &[u8]) -> Vec<u8> {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.add("first_stage_ramdisk/fstab.qcom", 0o644, stock_tag.to_vec()).unwrap();
        rd.add("system/bin/init", 0o755, b"force_normal_boot_stock".to_vec()).unwrap();
        rd.link("init", "/system/bin/init").unwrap();
        rd.add(paths::RECOVERY, 0o755, b"stock-recovery".to_vec()).unwrap();
        rd.add(paths::PROP_DEFAULT, 0o644, b"ro.build.version.release=13\nro.adb.secure=1\n".to_vec()).unwrap();

        let vboot = VendorBootImage {
            header: abootimg_oxide::VendorHeader {
                page_size: 4096,
                kernel_addr: 0,
                ramdisk_addr: 0,
                vendor_ramdisk_size: 0,
                cmdline: Box::new([0; 2048]),
                tags_addr: 0,
                board_name: [0; 16],
                dtb_size: 0,
                dtb_addr: 0,
                v4: None,
            },
            ramdisk: lz4_legacy(&rd.archive().unwrap()),
            dtb: dtb.to_vec(),
            ramdisk_table: Vec::new(),
            bootconfig: Vec::new(),
        };
        let raw = vboot.to_bytes().unwrap();
        avb::footed(&raw, "vendor_boot", partition_size, &Sha256::digest(&raw)).unwrap()
    }

    #[test]
    fn patch_preserves_stock_init_dtb_first_stage_and_adds_avb_footer() {
        let stock = stock_vendor_boot(131_072, b"dtb-a", b"fstab-a");
        let payload = sample_payload(b"[device]\ncodename = \"thyme\"\n");
        let patched = patch_vendor_boot(&stock, stock.len(), &payload).unwrap();

        assert_eq!(patched.len(), 131_072);
        assert_eq!(&patched[patched.len() - 64..patched.len() - 60], b"AVBf");
        let img = VendorBootImage::parse(&patched).unwrap();
        assert_eq!(img.dtb, b"dtb-a");
        let rd = Ramdisk::decode(&img.ramdisk).unwrap();
        assert_eq!(rd.find("system/bin/init").unwrap().data, b"force_normal_boot_stock", "never copies force_norma1_boot init");
        assert_eq!(rd.find("first_stage_ramdisk/fstab.qcom").unwrap().data, b"fstab-a");
        assert_eq!(rd.find(paths::RECOVERY).unwrap().data, b"skyward-bin");
        assert_eq!(rd.find(paths::CONFIG).unwrap().data, b"[device]\ncodename = \"thyme\"\n");
        for cmd in paths::COMMANDS {
            assert_eq!(rd.find(cmd).unwrap().data, b"recovery");
        }
        let props = std::str::from_utf8(&rd.find(paths::PROP_DEFAULT).unwrap().data).unwrap();
        assert!(!props.contains("ro.build.version.release="));
        assert!(props.contains("ro.adb.secure=0"));

        // Running patch_vendor_boot a second time is idempotent.
        let again = patch_vendor_boot(&patched, patched.len(), &payload).unwrap();
        assert_eq!(again, patched);
    }

    #[test]
    fn install_keeps_each_slots_own_dtb_and_fails_cleanly_if_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let size = 131_072;
        std::fs::write(dir.path().join("vendor_boot_a"), stock_vendor_boot(size, b"dtb-a", b"fstab-a")).unwrap();
        std::fs::write(dir.path().join("vendor_boot_b"), stock_vendor_boot(size, b"dtb-b", b"fstab-b")).unwrap();
        let payload = sample_payload(b"[device]\ncodename = \"thyme\"\n");

        let mut stages = Vec::new();
        let out = install(dir.path(), RecoveryPartition::VendorBoot, &payload, &[Slot::A, Slot::B], &mut |s| stages.push(s));
        assert_eq!(out, Outcome::Installed(vec![Slot::A, Slot::B]));
        assert!(matches!(stages.first(), Some(Stage::Preparing)));
        assert!(matches!(stages.last(), Some(Stage::Writing { done, total }) if done == total && *total > 0));

        let img_a = VendorBootImage::parse(&std::fs::read(dir.path().join("vendor_boot_a")).unwrap()).unwrap();
        let img_b = VendorBootImage::parse(&std::fs::read(dir.path().join("vendor_boot_b")).unwrap()).unwrap();
        assert_eq!(img_a.dtb, b"dtb-a");
        assert_eq!(img_b.dtb, b"dtb-b");
        assert_eq!(Ramdisk::decode(&img_a.ramdisk).unwrap().find("first_stage_ramdisk/fstab.qcom").unwrap().data, b"fstab-a");
        assert_eq!(Ramdisk::decode(&img_b.ramdisk).unwrap().find("first_stage_ramdisk/fstab.qcom").unwrap().data, b"fstab-b");

        // Oversized payload aborts before modifying any partition.
        let mut huge = sample_payload(b"x");
        huge.font = (0..200_000u32).map(|i| ((i.wrapping_mul(2654435761) >> 24) ^ (i >> 8)) as u8).collect();
        let before_a = std::fs::read(dir.path().join("vendor_boot_a")).unwrap();
        let err = install(dir.path(), RecoveryPartition::VendorBoot, &huge, &[Slot::A], &mut |_| {});
        assert!(matches!(err, Outcome::NotWritten(_)));
        assert_eq!(std::fs::read(dir.path().join("vendor_boot_a")).unwrap(), before_a);
    }
}
