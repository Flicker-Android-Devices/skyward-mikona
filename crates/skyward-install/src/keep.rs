//! Keeping this recovery in the recovery partitions an install writes
//! over: this recovery as its partition holds it, what each slot's
//! partition held before the install, and which slots get it back after.

use crate::image;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use skyward_bootimg::{lz4_legacy, Ramdisk, VendorBootImage};
use skyward_config::RecoveryPartition;
use skyward_vab::Slot;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

/// What a slot's recovery partition holds: a digest of all of it, and
/// whether that is Skyward, any build of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub digest: [u8; 32],
    pub skyward: bool,
}

/// This recovery, held from the current slot's recovery partition before
/// an install, and what each slot's partition held then, slot A first.
pub struct Kept {
    dir: PathBuf,
    partition: RecoveryPartition,
    image: Vec<u8>,
    own: [u8; 32],
    before: [Held; 2],
}

impl Kept {
    /// Hold this recovery from the recovery partitions among the links in
    /// `dir`, before an install; none when the partition of the `current`
    /// slot does not hold Skyward, as when it was started without being
    /// flashed.
    pub fn hold(dir: &Path, partition: RecoveryPartition, current: Slot) -> Result<Option<Kept>> {
        let name = partition.partition();
        let (a, image_a) = read(&image::device(dir, name, Slot::A))?;
        let (b, image_b) = read(&image::device(dir, name, Slot::B))?;
        let (held, image) = match current {
            Slot::A => (a, image_a),
            Slot::B => (b, image_b),
        };
        Ok(held.skyward.then(|| Kept { dir: dir.to_path_buf(), partition, image, own: held.digest, before: [a, b] }))
    }

    /// The slots whose recovery partition gets this recovery back, by what
    /// the partitions hold once the install is done; `next` is the slot
    /// that starts next.
    pub fn wanted(&self, next: Slot) -> Result<Vec<Slot>> {
        let name = self.partition.partition();
        let (a, _) = read(&image::device(&self.dir, name, Slot::A))?;
        let (b, _) = read(&image::device(&self.dir, name, Slot::B))?;
        Ok(restore(self.before, [a, b], self.own, next))
    }

    /// Write this recovery into the recovery partitions of `slots` and read
    /// each back; `progress` hears the bytes so far, of all.
    pub fn write(&self, slots: &[Slot], progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        let name = self.partition.partition();
        if self.partition == RecoveryPartition::Recovery {
            let devices: Vec<PathBuf> = slots.iter().map(|&slot| image::device(&self.dir, name, slot)).collect();
            return image::flash(&mut Cursor::new(&self.image), self.image.len() as u64, &devices, progress);
        }
        let mut payloads = Vec::with_capacity(slots.len());
        for &slot in slots {
            let path = image::device(&self.dir, name, slot);
            let merged = match std::fs::read(&path) {
                Ok(target) => merge_vendor_boot(&self.image, &target).unwrap_or_else(|_| self.image.clone()),
                Err(_) => self.image.clone(),
            };
            payloads.push((path, merged));
        }
        let total_work: u64 = payloads.iter().map(|(_, bytes)| 2 * bytes.len() as u64).sum();
        let mut done_so_far = 0u64;
        for (path, bytes) in &payloads {
            image::flash(&mut Cursor::new(bytes), bytes.len() as u64, std::slice::from_ref(path), &mut |done, _| {
                progress(done_so_far + done, total_work);
            })?;
            done_so_far += 2 * bytes.len() as u64;
        }
        Ok(())
    }
}

fn is_first_stage(name: &str) -> bool {
    name == "first_stage_ramdisk" || name.starts_with("first_stage_ramdisk/")
}

/// Transplant Skyward's recovery entries (everything outside `first_stage_ramdisk`)
/// from `kept_image` onto `target_image`, keeping the newly installed image's
/// header, DTB, bootconfig, and `first_stage_ramdisk`.
fn merge_vendor_boot(kept_image: &[u8], target_image: &[u8]) -> Result<Vec<u8>> {
    let kept = VendorBootImage::parse(kept_image)?;
    let kept_rd = Ramdisk::decode(&kept.ramdisk)?;
    let mut target = VendorBootImage::parse(target_image)?;
    let mut target_rd = Ramdisk::decode(&target.ramdisk)?;
    target_rd.entries.retain(|e| is_first_stage(&e.name));
    for entry in kept_rd.entries {
        if !is_first_stage(&entry.name) {
            target_rd.entries.push(entry);
        }
    }
    target.ramdisk = lz4_legacy(&target_rd.archive()?);
    target.to_bytes()
}

/// What the partition at `path` holds, read past any pages cached of it,
/// and all of it.
fn read(path: &Path) -> Result<(Held, Vec<u8>)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    image::drop_cache(&file).with_context(|| format!("drop the cached pages of {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).with_context(|| format!("read {}", path.display()))?;
    let skyward = image::is_skyward(&mut Cursor::new(&bytes)).with_context(|| format!("look into {}", path.display()))?;
    Ok((Held { digest: Sha256::digest(&bytes).into(), skyward }, bytes))
}

/// The slots whose recovery partition gets this recovery back once an
/// install is done, by what each held `before` and `after` it, slot A
/// first: the slot that starts next, `next`, unless it holds this build,
/// whose digest is `own`; and any other the install wrote over with
/// something that is not Skyward.
pub fn restore(before: [Held; 2], after: [Held; 2], own: [u8; 32], next: Slot) -> Vec<Slot> {
    [Slot::A, Slot::B]
        .into_iter()
        .filter(|&slot| {
            let k = slot.number() as usize;
            match slot == next {
                true => after[k].digest != own,
                false => after[k].digest != before[k].digest && !after[k].skyward,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::samples::recovery;

    const SKYWARD: Held = Held { digest: [1; 32], skyward: true };
    const OWN: [u8; 32] = SKYWARD.digest;
    /// Another build of Skyward.
    const OTHER_BUILD: Held = Held { digest: [4; 32], skyward: true };
    const STOCK: Held = Held { digest: [2; 32], skyward: false };
    const OLD: Held = Held { digest: [3; 32], skyward: false };

    #[test]
    fn the_slot_that_starts_next_gets_this_build() {
        assert_eq!(restore([SKYWARD, OLD], [SKYWARD, STOCK], OWN, Slot::B), [Slot::B], "an update or a package that went to slot B");
        assert_eq!(restore([SKYWARD, OLD], [SKYWARD, OLD], OWN, Slot::B), [Slot::B], "an older recovery there, left alone by the install");
        assert_eq!(restore([SKYWARD, OTHER_BUILD], [SKYWARD, OTHER_BUILD], OWN, Slot::B), [Slot::B], "another build of Skyward there");
        assert!(restore([SKYWARD, SKYWARD], [SKYWARD, SKYWARD], OWN, Slot::A).is_empty(), "this recovery is there already");
    }

    #[test]
    fn elsewhere_it_goes_back_only_where_the_install_wrote_something_else() {
        assert!(restore([SKYWARD, OLD], [SKYWARD, OLD], OWN, Slot::A).is_empty(), "a package that left recovery alone, such as a root installer");
        assert_eq!(restore([SKYWARD, OLD], [SKYWARD, STOCK], OWN, Slot::A), [Slot::B]);
        assert_eq!(restore([SKYWARD, OLD], [STOCK, STOCK], OWN, Slot::A), [Slot::A, Slot::B]);
        assert!(restore([SKYWARD, OLD], [SKYWARD, OTHER_BUILD], OWN, Slot::A).is_empty(), "a package that put another build of Skyward in");
    }

    /// Recovery partitions of `size` bytes holding `a` and `b`.
    fn partitions(a: &[u8], b: &[u8], size: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, image) in [("recovery_a", a), ("recovery_b", b)] {
            let mut bytes = image.to_vec();
            bytes.resize(size, 0);
            std::fs::write(dir.path().join(name), bytes).unwrap();
        }
        dir
    }

    #[test]
    fn this_recovery_goes_back_where_an_install_wrote_over_it() {
        let (skyward, stock) = (recovery(true), recovery(false));
        let size = skyward.len().max(stock.len()) + 4096;
        let dir = partitions(&skyward, &stock, size);
        let kept = Kept::hold(dir.path(), RecoveryPartition::Recovery, Slot::A)
            .unwrap()
            .expect("slot A's partition holds Skyward");
        assert!(kept.wanted(Slot::A).unwrap().is_empty(), "nothing written over");
        // A package puts the stock recovery in both slots.
        let mut written = stock.clone();
        written.resize(size, 0);
        std::fs::write(dir.path().join("recovery_a"), &written).unwrap();
        assert_eq!(kept.wanted(Slot::A).unwrap(), [Slot::A], "slot B held the stock recovery already");
        let mut told = Vec::new();
        kept.write(&[Slot::A], &mut |done, total| told.push((done, total))).unwrap();
        assert_eq!(told.last(), Some(&(2 * size as u64, 2 * size as u64)), "written and read back");
        let mut whole = skyward.clone();
        whole.resize(size, 0);
        assert_eq!(std::fs::read(dir.path().join("recovery_a")).unwrap(), whole);
        assert!(kept.wanted(Slot::A).unwrap().is_empty());
        assert_eq!(kept.wanted(Slot::B).unwrap(), [Slot::B], "an install that has slot B start next");
    }

    #[test]
    fn nothing_is_kept_when_this_recovery_was_started_without_being_flashed() {
        let dir = partitions(&recovery(false), &recovery(false), 1 << 20);
        assert!(Kept::hold(dir.path(), RecoveryPartition::Recovery, Slot::B).unwrap().is_none());
        let erased = partitions(&recovery(true), &[], 1 << 20);
        assert!(Kept::hold(erased.path(), RecoveryPartition::Recovery, Slot::B).unwrap().is_none(), "an erased partition");
        assert!(Kept::hold(erased.path(), RecoveryPartition::Recovery, Slot::A).unwrap().is_some());
    }

    #[test]
    fn vendor_boot_keep_preserves_targets_dtb_and_first_stage_ramdisk() {
        let make_vboot = |dtb: &[u8], fstab: &[u8], recovery_cfg: Option<&[u8]>| {
            let mut rd = Ramdisk { entries: Vec::new() };
            rd.add("first_stage_ramdisk/fstab", 0o644, fstab.to_vec()).unwrap();
            if let Some(cfg) = recovery_cfg {
                rd.add(skyward_config::ramdisk::CONFIG, 0o644, cfg.to_vec()).unwrap();
            } else {
                rd.add("system/bin/recovery", 0o755, b"stock-rec".to_vec()).unwrap();
            }
            let mut raw = vec![0u8; 4096];
            let ramdisk = lz4_legacy(&rd.archive().unwrap());
            raw[0..8].copy_from_slice(b"VNDRBOOT");
            raw[8..12].copy_from_slice(&3u32.to_le_bytes());
            raw[12..16].copy_from_slice(&4096u32.to_le_bytes());
            raw[24..28].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
            raw[2096..2100].copy_from_slice(&2112u32.to_le_bytes());
            raw[2100..2104].copy_from_slice(&(dtb.len() as u32).to_le_bytes());
            raw.extend_from_slice(&ramdisk);
            raw.resize(raw.len().div_ceil(4096) * 4096, 0);
            raw.extend_from_slice(dtb);
            raw.resize(raw.len().div_ceil(4096) * 4096, 0);
            raw
        };

        let old_skyward = make_vboot(b"old-dtb", b"old-fstab", Some(b"[device]\ncodename = \"thyme\"\n"));
        let new_stock = make_vboot(b"new-dtb", b"new-fstab", None);
        let size = old_skyward.len().max(new_stock.len()) + 65536;

        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [("vendor_boot_a", &old_skyward), ("vendor_boot_b", &new_stock)] {
            let mut buf = bytes.clone();
            buf.resize(size, 0);
            std::fs::write(dir.path().join(name), buf).unwrap();
        }
        let kept = Kept::hold(dir.path(), RecoveryPartition::VendorBoot, Slot::A).unwrap().unwrap();
        let wanted = kept.wanted(Slot::B).unwrap();
        assert_eq!(wanted, [Slot::B]);
        kept.write(&wanted, &mut |_, _| {}).unwrap();

        let flashed = std::fs::read(dir.path().join("vendor_boot_b")).unwrap();
        let parsed = VendorBootImage::parse(&flashed).unwrap();
        assert_eq!(parsed.dtb, b"new-dtb", "target's updated DTB is kept");
        let rd = Ramdisk::decode(&parsed.ramdisk).unwrap();
        assert_eq!(rd.find("first_stage_ramdisk/fstab").unwrap().data, b"new-fstab");
        assert!(rd.find(skyward_config::ramdisk::CONFIG).is_some());
        assert!(rd.find("system/bin/recovery").is_none(), "stock recovery replaced by kept Skyward entries");
    }
}
