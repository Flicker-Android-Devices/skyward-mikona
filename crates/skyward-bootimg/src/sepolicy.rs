//! Marks SELinux domains permissive in a binary kernel `sepolicy` image.
//!
//! Even userdebug stock recoveries keep `kernel` enforcing without
//! `recovery:fd use`, which blocks Linux 4.19 loopback threads (`vfs_iter_read`
//! in `kernel`) from reading `.apex` files opened by `recovery`. Setting
//! `kernel` directly in `permissive_map` leaves the rest of the policy stream
//! untouched and never affects normal Android boot, which loads the split
//! CIL/precompiled policy instead of `/sepolicy`.

use anyhow::{bail, ensure, Context, Result};
use std::collections::BTreeMap;

const POLICYDB_MAGIC: u32 = 0xf97c_ff8c;
const POLICYDB_VERSION_VALIDATETRANS: u32 = 19;
const POLICYDB_VERSION_POLCAP: u32 = 22;
const POLICYDB_VERSION_PERMISSIVE: u32 = 23;
const POLICYDB_VERSION_BOUNDARY: u32 = 24;
const POLICYDB_VERSION_NEW_OBJECT_DEFAULTS: u32 = 27;
const POLICYDB_VERSION_DEFAULT_TYPE: u32 = 28;
const POLICYDB_VERSION_CONSTRAINT_NAMES: u32 = 29;
const POLICYDB_VERSION_MAX: u32 = 35;

const SYM_TYPES_INDEX: usize = 3;
const CEXPR_NAMES: u32 = 5;
const EBITMAP_MAPSIZE: u32 = 64;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).context("policy offset overflow")?;
        let slice = self.data.get(self.pos..end).context("unexpected end of binary sepolicy")?;
        self.pos = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64> {
        let b: [u8; 8] = self.take(8)?.try_into().expect("eight bytes");
        Ok(u64::from_le_bytes(b))
    }

    fn str_bytes(&mut self, len: u32) -> Result<&'a [u8]> {
        self.take(usize::try_from(len).context("string length")?)
    }
}

/// Extensible bitmap storing sparse 64-bit chunks keyed by aligned `startbit`.
#[derive(Debug, Default, PartialEq, Eq)]
struct Ebitmap {
    nodes: BTreeMap<u32, u64>,
}

impl Ebitmap {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let mapsize = r.u32()?;
        ensure!(mapsize == EBITMAP_MAPSIZE, "unsupported ebitmap mapsize {mapsize}");
        let highbit = r.u32()?;
        let count = r.u32()?;
        ensure!(highbit % EBITMAP_MAPSIZE == 0, "unaligned ebitmap highbit {highbit}");
        ensure!(highbit == 0 || count > 0, "non-zero ebitmap highbit with zero nodes");
        let mut nodes = BTreeMap::new();
        for _ in 0..count {
            let startbit = r.u32()?;
            let map = r.u64()?;
            ensure!(startbit % EBITMAP_MAPSIZE == 0, "unaligned ebitmap startbit {startbit}");
            ensure!(map != 0, "empty ebitmap node at {startbit}");
            nodes.insert(startbit, map);
        }
        Ok(Self { nodes })
    }

    fn set(&mut self, bit: u32) {
        let startbit = bit & !(EBITMAP_MAPSIZE - 1);
        let mask = 1u64 << (bit - startbit);
        *self.nodes.entry(startbit).or_default() |= mask;
    }

    fn encode(&self) -> Vec<u8> {
        let highbit = self.nodes.keys().next_back().map_or(0, |s| s + EBITMAP_MAPSIZE);
        let count = u32::try_from(self.nodes.len()).expect("ebitmap node count");
        let mut out = Vec::with_capacity(12 + self.nodes.len() * 12);
        out.extend_from_slice(&EBITMAP_MAPSIZE.to_le_bytes());
        out.extend_from_slice(&highbit.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for (&startbit, &map) in &self.nodes {
            out.extend_from_slice(&startbit.to_le_bytes());
            out.extend_from_slice(&map.to_le_bytes());
        }
        out
    }
}

fn skip_perms(r: &mut Reader<'_>, count: u32) -> Result<()> {
    for _ in 0..count {
        let len = r.u32()?;
        let _value = r.u32()?;
        r.str_bytes(len)?;
    }
    Ok(())
}

fn skip_constraints(r: &mut Reader<'_>, vers: u32, ncons: u32) -> Result<()> {
    for _ in 0..ncons {
        let _perms = r.u32()?;
        let nexpr = r.u32()?;
        for _ in 0..nexpr {
            let expr_type = r.u32()?;
            let _attr = r.u32()?;
            let _op = r.u32()?;
            if expr_type == CEXPR_NAMES {
                Ebitmap::read(r)?;
                if vers >= POLICYDB_VERSION_CONSTRAINT_NAMES {
                    Ebitmap::read(r)?;
                    Ebitmap::read(r)?;
                    let _flags = r.u32()?;
                }
            }
        }
    }
    Ok(())
}

fn skip_commons(r: &mut Reader<'_>) -> Result<()> {
    let _nprim = r.u32()?;
    let nel = r.u32()?;
    for _ in 0..nel {
        let len = r.u32()?;
        let _val = r.u32()?;
        let _perm_nprim = r.u32()?;
        let perm_nel = r.u32()?;
        r.str_bytes(len)?;
        skip_perms(r, perm_nel)?;
    }
    Ok(())
}

fn skip_classes(r: &mut Reader<'_>, vers: u32) -> Result<()> {
    let _nprim = r.u32()?;
    let nel = r.u32()?;
    for _ in 0..nel {
        let len = r.u32()?;
        let len2 = r.u32()?;
        let _val = r.u32()?;
        let _perm_nprim = r.u32()?;
        let perm_nel = r.u32()?;
        let ncons = r.u32()?;
        r.str_bytes(len)?;
        r.str_bytes(len2)?;
        skip_perms(r, perm_nel)?;
        skip_constraints(r, vers, ncons)?;
        if vers >= POLICYDB_VERSION_VALIDATETRANS {
            let vt_ncons = r.u32()?;
            skip_constraints(r, vers, vt_ncons)?;
        }
        if vers >= POLICYDB_VERSION_NEW_OBJECT_DEFAULTS {
            let _ = (r.u32()?, r.u32()?, r.u32()?);
        }
        if vers >= POLICYDB_VERSION_DEFAULT_TYPE {
            let _ = r.u32()?;
        }
    }
    Ok(())
}

fn skip_roles(r: &mut Reader<'_>, vers: u32) -> Result<()> {
    let _nprim = r.u32()?;
    let nel = r.u32()?;
    for _ in 0..nel {
        let len = r.u32()?;
        let _val = r.u32()?;
        if vers >= POLICYDB_VERSION_BOUNDARY {
            let _bounds = r.u32()?;
        }
        r.str_bytes(len)?;
        Ebitmap::read(r)?;
        Ebitmap::read(r)?;
    }
    Ok(())
}

fn find_types(r: &mut Reader<'_>, vers: u32, targets: &[&str]) -> Result<Vec<(String, u32)>> {
    let _nprim = r.u32()?;
    let nel = r.u32()?;
    let mut found = Vec::new();
    for _ in 0..nel {
        let len = r.u32()?;
        let val = r.u32()?;
        let _ = r.u32()?;
        if vers >= POLICYDB_VERSION_BOUNDARY {
            let _bounds = r.u32()?;
        }
        let name = r.str_bytes(len)?;
        if let Ok(text) = std::str::from_utf8(name)
            && targets.contains(&text)
        {
            found.push((text.to_string(), val));
        }
    }
    Ok(found)
}

/// Returns a copy of `policy` with every domain in `domains` added to
/// `permissive_map`.
pub fn make_permissive(policy: &[u8], domains: &[&str]) -> Result<Vec<u8>> {
    let mut r = Reader::new(policy);
    let magic = r.u32()?;
    ensure!(magic == POLICYDB_MAGIC, "not a binary kernel sepolicy (magic {magic:#x})");
    let target_len = r.u32()?;
    r.str_bytes(target_len)?;
    let vers = r.u32()?;
    ensure!(
        (POLICYDB_VERSION_PERMISSIVE..=POLICYDB_VERSION_MAX).contains(&vers),
        "unsupported sepolicy version {vers}"
    );
    let _config = r.u32()?;
    let sym_num = r.u32()?;
    let _ocon_num = r.u32()?;
    ensure!(sym_num > SYM_TYPES_INDEX as u32, "sepolicy has only {sym_num} symbol tables");
    if vers >= POLICYDB_VERSION_POLCAP {
        Ebitmap::read(&mut r)?;
    }

    let pm_start = r.pos;
    let mut permissive = Ebitmap::read(&mut r)?;
    let pm_end = r.pos;

    skip_commons(&mut r)?;
    skip_classes(&mut r, vers)?;
    skip_roles(&mut r, vers)?;
    let found = find_types(&mut r, vers, domains)?;
    for &domain in domains {
        let Some((_, id)) = found.iter().find(|(name, _)| name == domain) else {
            bail!("sepolicy defines no {domain} domain");
        };
        permissive.set(*id);
    }

    let encoded = permissive.encode();
    let mut out = Vec::with_capacity(policy.len() - (pm_end - pm_start) + encoded.len());
    out.extend_from_slice(&policy[..pm_start]);
    out.extend_from_slice(&encoded);
    out.extend_from_slice(&policy[pm_end..]);
    Ok(out)
}

const REQUIRED_RECOVERY_DOMAINS: &[&str] = &["kernel", "recovery"];
const OPTIONAL_RECOVERY_DOMAINS: &[&str] =
    &["vendor_init", "fastbootd", "adbd", "shell", "ueventd"];

/// Marks recovery-mode SELinux domains permissive in a ramdisk `sepolicy`.
///
/// Requires `kernel` (for Linux 4.19 loopback reads on `.apex` files) and
/// `recovery` (which is enforcing on `user`-build `vendor_boot` images,
/// blocking Skyward from writing `/skyward/run` or partitions), and also
/// marks common recovery daemons permissive when defined in the policy.
pub fn make_recovery_permissive(policy: &[u8]) -> Result<Vec<u8>> {
    let mut patched = make_permissive(policy, REQUIRED_RECOVERY_DOMAINS)?;
    for &domain in OPTIONAL_RECOVERY_DOMAINS {
        match make_permissive(&patched, &[domain]) {
            Ok(next) => patched = next,
            Err(err) if err.to_string().contains("defines no") => {}
            Err(err) => return Err(err),
        }
    }
    Ok(patched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_str(out: &mut Vec<u8>, val: u32, name: &[u8]) {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
        out.extend_from_slice(name);
    }

    fn minimal_policy() -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&POLICYDB_MAGIC.to_le_bytes());
        let target = b"SE Linux";
        p.extend_from_slice(&(target.len() as u32).to_le_bytes());
        p.extend_from_slice(target);
        p.extend_from_slice(&33u32.to_le_bytes()); // policyvers
        p.extend_from_slice(&1u32.to_le_bytes()); // config (MLS)
        p.extend_from_slice(&8u32.to_le_bytes()); // sym_num
        p.extend_from_slice(&7u32.to_le_bytes()); // ocon_num
        // policycaps (empty) + permissive_map (empty)
        p.extend_from_slice(&Ebitmap::default().encode());
        p.extend_from_slice(&Ebitmap::default().encode());
        // SYM_COMMONS: empty
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        // SYM_CLASSES: 1 class with 1 perm & defaults
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&4u32.to_le_bytes()); // len("file")
        p.extend_from_slice(&0u32.to_le_bytes()); // len2
        p.extend_from_slice(&1u32.to_le_bytes()); // value
        p.extend_from_slice(&1u32.to_le_bytes()); // perm nprim
        p.extend_from_slice(&1u32.to_le_bytes()); // perm nel
        p.extend_from_slice(&0u32.to_le_bytes()); // ncons
        p.extend_from_slice(b"file");
        push_str(&mut p, 1, b"read");
        p.extend_from_slice(&0u32.to_le_bytes()); // validatetrans ncons
        p.extend_from_slice(&[0u8; 16]); // default_user/role/range/type
        // SYM_ROLES: 1 role
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes()); // len("r")
        p.extend_from_slice(&1u32.to_le_bytes()); // value
        p.extend_from_slice(&0u32.to_le_bytes()); // bounds
        p.extend_from_slice(b"r");
        p.extend_from_slice(&Ebitmap::default().encode());
        p.extend_from_slice(&Ebitmap::default().encode());
        // SYM_TYPES: kernel=1, recovery=70 (tests cross-word ebitmap nodes)
        p.extend_from_slice(&70u32.to_le_bytes());
        p.extend_from_slice(&2u32.to_le_bytes());
        for (name, val) in [(b"kernel".as_slice(), 1u32), (b"recovery".as_slice(), 70u32)] {
            p.extend_from_slice(&(name.len() as u32).to_le_bytes());
            p.extend_from_slice(&val.to_le_bytes());
            p.extend_from_slice(&1u32.to_le_bytes()); // properties
            p.extend_from_slice(&0u32.to_le_bytes()); // bounds
            p.extend_from_slice(name);
        }
        p.extend_from_slice(b"TRAILING_BYTES");
        p
    }

    fn read_permissive(policy: &[u8]) -> Ebitmap {
        let mut r = Reader::new(policy);
        let _ = r.u32().unwrap();
        let l = r.u32().unwrap();
        r.str_bytes(l).unwrap();
        let _ = (r.u32().unwrap(), r.u32().unwrap(), r.u32().unwrap(), r.u32().unwrap());
        Ebitmap::read(&mut r).unwrap(); // policycaps
        Ebitmap::read(&mut r).unwrap()
    }

    #[test]
    fn marks_multiple_domains_permissive_and_keeps_trailing_bytes() {
        let orig = minimal_policy();
        let patched = make_permissive(&orig, &["recovery", "kernel"]).unwrap();
        assert!(patched.ends_with(b"TRAILING_BYTES"));

        let perm = read_permissive(&patched);
        assert_eq!(perm.nodes.get(&0), Some(&(1u64 << 1)));
        assert_eq!(perm.nodes.get(&64), Some(&(1u64 << (70 - 64))));
    }

    #[test]
    fn refuses_missing_domain() {
        let orig = minimal_policy();
        let err = make_permissive(&orig, &["nonexistent"]).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn recovery_permissive_sets_required_and_skips_missing_optional() {
        let orig = minimal_policy();
        let patched = make_recovery_permissive(&orig).unwrap();

        let perm = read_permissive(&patched);
        assert_eq!(perm.nodes.get(&0), Some(&(1u64 << 1)));
        assert_eq!(perm.nodes.get(&64), Some(&(1u64 << (70 - 64))));
    }
}
