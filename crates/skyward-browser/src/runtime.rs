//! Downloading, verifying, caching, and unpacking the AERA WPE browser runtime.

use anyhow::{bail, ensure, Context, Result};
use liblzma::read::XzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skyward_net::download::{self, Progress, Sum};
use skyward_net::http::{self, Servers};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const MANIFEST_URL: &str =
    "https://gh-proxy.org/https://raw.githubusercontent.com/AERA-Plugins/browser/main/plugin.json";
const GH_PROXY: &str = "https://gh-proxy.org/";
pub const FALLBACK_COMPRESSED_SHA256: &str =
    "009a7c1391d0af9bc15082545c6dd0269ea47fc476f5e672bb7680cd63fb0a29";
pub const FALLBACK_COMPRESSED_SIZE: u64 = 40_963_812;
pub const FALLBACK_EXPANDED_SHA256: &str =
    "dca7711d64a7ed34634afffa00395fd7b2436b5492f81879fe72c0cabbbae974";
pub const FALLBACK_EXPANDED_SIZE: u64 = 210_809_085;
pub const FALLBACK_MEMBER_COUNT: u32 = 445;

const ARCHIVE_MAGIC: &[u8; 8] = b"AERAWEB1";
const MAX_MEMBER_BYTES: u64 = 100 * 1024 * 1024;
const MAX_EXPANDED_CAP: u64 = 256 * 1024 * 1024;
const DOWNLOAD_RETRIES: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareStage {
    CheckingCache,
    Downloading { done: u64, total: u64 },
    Unpacking { done: u64, total: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeManifest {
    pub version: String,
    pub payload_url: String,
    pub payload_size: u64,
    pub payload_sha256: String,
    pub expanded_size: u64,
    pub expanded_sha256: String,
    pub member_count: u32,
}

impl RuntimeManifest {
    pub fn fallback_v156() -> Self {
        Self {
            version: "1.5.6".into(),
            payload_url: format!("{GH_PROXY}https://github.com/AERA-Plugins/browser/releases/download/v1.5.6/runtime.xz"),
            payload_size: FALLBACK_COMPRESSED_SIZE,
            payload_sha256: FALLBACK_COMPRESSED_SHA256.into(),
            expanded_size: FALLBACK_EXPANDED_SIZE,
            expanded_sha256: FALLBACK_EXPANDED_SHA256.into(),
            member_count: FALLBACK_MEMBER_COUNT,
        }
    }

    pub fn spec(&self) -> RuntimeSpec {
        RuntimeSpec {
            compressed_size: self.payload_size,
            compressed_sha256: self.payload_sha256.to_ascii_lowercase(),
            expanded_size: self.expanded_size,
            expanded_sha256: self.expanded_sha256.to_ascii_lowercase(),
            member_count: self.member_count,
        }
    }

    pub fn proxied_url(&self) -> Result<String> {
        ensure!(self.payload_url.starts_with("https://"), "runtime URL must use HTTPS");
        if self.payload_url.starts_with(GH_PROXY) {
            Ok(self.payload_url.clone())
        } else if self.payload_url.starts_with("https://github.com/") {
            Ok(format!("{GH_PROXY}{}", self.payload_url))
        } else {
            Ok(self.payload_url.clone())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSpec {
    pub compressed_size: u64,
    pub compressed_sha256: String,
    pub expanded_size: u64,
    pub expanded_sha256: String,
    pub member_count: u32,
}

/// Fetch the latest `plugin.json` manifest from GitHub via `gh-proxy.org`.
pub fn fetch_latest_manifest(servers: &Servers) -> Result<RuntimeManifest> {
    let agent = http::agent(servers.clone());
    let mut resp = agent.get(MANIFEST_URL).call().context("fetch browser runtime manifest")?;
    ensure!(resp.status().as_u16() == 200, "manifest server returned {}", resp.status().as_u16());
    let text = resp.body_mut().read_to_string().context("read browser manifest body")?;
    let m: RuntimeManifest = serde_json::from_str(&text).context("parse browser plugin.json")?;
    ensure!(m.expanded_size > 12 && m.expanded_size <= MAX_EXPANDED_CAP, "invalid expanded size {}", m.expanded_size);
    ensure!(m.member_count > 0 && m.member_count <= 4096, "invalid member count {}", m.member_count);
    ensure!(m.payload_sha256.len() == 64 && m.expanded_sha256.len() == 64, "invalid manifest SHA-256");
    let _ = m.proxied_url()?;
    Ok(m)
}

fn manifest_cache_path(xz_cache: &Path) -> PathBuf {
    xz_cache.with_file_name("plugin.json")
}

/// Returns true when `path` exists and matches the expected compressed size and SHA-256.
pub fn cached_runtime_valid(path: &Path, spec: &RuntimeSpec, stop: &AtomicBool) -> Result<bool> {
    let Ok(meta) = fs::metadata(path) else {
        return Ok(false);
    };
    if !meta.is_file() || meta.len() != spec.compressed_size {
        return Ok(false);
    }
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        if stop.load(Ordering::Relaxed) {
            bail!("cancelled");
        }
        let n = file.read(&mut buf).with_context(|| format!("read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()) == spec.compressed_sha256)
}

fn rootfs_stamp(spec: &RuntimeSpec) -> String {
    format!("{}:{}:{}", spec.expanded_sha256, spec.expanded_size, spec.member_count)
}

fn valid_stamp_format(stamp: &str) -> bool {
    let mut parts = stamp.trim().split(':');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(sha), Some(sz), Some(cnt), None)
            if sha.len() == 64 && sz.parse::<u64>().is_ok() && cnt.parse::<u32>().is_ok()
    )
}

/// Return `work_dir/rootfs` if a previously completed unpack passes stamp and binary checks.
fn cached_rootfs_path(work_dir: &Path, expected: Option<&RuntimeSpec>) -> Option<PathBuf> {
    let rootfs = work_dir.join("rootfs");
    if !rootfs.join("usr/bin/aera-browser-worker").is_file() {
        return None;
    }
    let stamp = fs::read_to_string(work_dir.join(".rootfs.ready")).ok()?;
    let trimmed = stamp.trim();
    let ok = match expected {
        Some(spec) => trimmed == rootfs_stamp(spec),
        None => valid_stamp_format(trimmed),
    };
    ok.then_some(rootfs)
}

/// Resolve the latest upstream manifest (or a valid offline cached copy) and unpack into `work_dir/rootfs`.
pub fn prepare_runtime(
    cache_path: Option<&Path>,
    work_dir: &Path,
    servers: Servers,
    stop: &AtomicBool,
    on_stage: &mut dyn FnMut(PrepareStage),
) -> Result<PathBuf> {
    fs::create_dir_all(work_dir).with_context(|| format!("make {}", work_dir.display()))?;

    on_stage(PrepareStage::CheckingCache);
    // Reuse a rootfs already unpacked in this boot unless a cached plugin.json specifies a newer build.
    let cached_expected = cache_path
        .and_then(|p| fs::read_to_string(manifest_cache_path(p)).ok())
        .and_then(|s| serde_json::from_str::<RuntimeManifest>(&s).ok())
        .map(|m| m.spec());
    if let Some(rootfs) = cached_rootfs_path(work_dir, cached_expected.as_ref()) {
        return Ok(rootfs);
    }

    let (xz_path, temporary_xz) = match cache_path {
        Some(path) => (path.to_path_buf(), false),
        None => (work_dir.join("runtime.xz"), true),
    };

    let latest = fetch_latest_manifest(&servers);
    let manifest = match (latest, cache_path) {
        (Ok(m), _) => m,
        (Err(online_err), Some(xz_cache)) => {
            // Allow offline launch from an already-verified cached `runtime.xz` beside `plugin.json` (or v1.5.6 fallback).
            let cached_meta = fs::read_to_string(manifest_cache_path(xz_cache))
                .ok()
                .and_then(|s| serde_json::from_str::<RuntimeManifest>(&s).ok());
            if let Some(m) = cached_meta && cached_runtime_valid(xz_cache, &m.spec(), stop)? {
                m
            } else {
                let fb = RuntimeManifest::fallback_v156();
                if cached_runtime_valid(xz_cache, &fb.spec(), stop)? {
                    fb
                } else {
                    return Err(online_err);
                }
            }
        }
        (Err(online_err), None) => return Err(online_err),
    };

    let spec = manifest.spec();
    if let Some(rootfs) = cached_rootfs_path(work_dir, Some(&spec)) {
        return Ok(rootfs);
    }

    let already_valid = cached_runtime_valid(&xz_path, &spec, stop)?;
    if !already_valid {
        if xz_path.exists() {
            let _ = fs::remove_file(&xz_path);
        }
        let url = manifest.proxied_url()?;
        fetch_with_retries(&servers, &url, &xz_path, &spec.compressed_sha256, stop, on_stage)?;
        if let Some(xz_cache) = cache_path
            && let Ok(json) = serde_json::to_string_pretty(&manifest)
        {
            let _ = fs::write(manifest_cache_path(xz_cache), json);
        }
    }

    let rootfs = work_dir.join("rootfs");
    let stamp_path = work_dir.join(".rootfs.ready");
    let _ = fs::remove_file(&stamp_path);
    if rootfs.exists() {
        fs::remove_dir_all(&rootfs).with_context(|| format!("clean {}", rootfs.display()))?;
    }
    let unpack_res = unpack_xz_archive(&xz_path, &rootfs, &spec, stop, &mut |done| {
        on_stage(PrepareStage::Unpacking { done, total: spec.expanded_size });
    });
    if temporary_xz {
        let _ = fs::remove_file(&xz_path);
    }
    unpack_res?;
    fs::write(&stamp_path, rootfs_stamp(&spec)).with_context(|| format!("write {}", stamp_path.display()))?;
    Ok(rootfs)
}

fn fetch_with_retries(
    servers: &Servers,
    url: &str,
    dest: &Path,
    sha256: &str,
    stop: &AtomicBool,
    on_stage: &mut dyn FnMut(PrepareStage),
) -> Result<()> {
    let sum = Sum::Sha256(sha256.to_string());
    let mut attempt = 0;
    loop {
        attempt += 1;
        let agent = http::agent(servers.clone());
        let res = download::fetch(&agent, url, dest, &sum, stop, &mut |p| match p {
            Progress::Checking { done, total } | Progress::Downloading { done, total } => {
                on_stage(PrepareStage::Downloading { done, total });
            }
        });
        match res {
            Ok(()) => return Ok(()),
            Err(err) if stop.load(Ordering::Relaxed) || attempt >= DOWNLOAD_RETRIES => {
                return Err(err);
            }
            Err(_) => std::thread::sleep(Duration::from_secs(2)),
        }
    }
}

struct CountingHashReader<R> {
    inner: R,
    hash: Sha256,
    total: u64,
}

impl<R: Read> CountingHashReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, hash: Sha256::new(), total: 0 }
    }
}

impl<R: Read> Read for CountingHashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hash.update(&buf[..n]);
            self.total += n as u64;
        }
        Ok(n)
    }
}

/// Unpack a verified `AERAWEB1` `.xz` stream into `dst_root`, rolling back on failure.
pub fn unpack_xz_archive(
    xz_path: &Path,
    dst_root: &Path,
    spec: &RuntimeSpec,
    stop: &AtomicBool,
    on_progress: &mut dyn FnMut(u64),
) -> Result<()> {
    let res = unpack_inner(xz_path, dst_root, spec, stop, on_progress);
    if res.is_err() {
        let _ = fs::remove_dir_all(dst_root);
    }
    res
}

fn unpack_inner(
    xz_path: &Path,
    dst_root: &Path,
    spec: &RuntimeSpec,
    stop: &AtomicBool,
    on_progress: &mut dyn FnMut(u64),
) -> Result<()> {
    let file = File::open(xz_path).with_context(|| format!("open {}", xz_path.display()))?;
    let xz = XzDecoder::new(BufReader::new(file));
    let mut reader = CountingHashReader::new(xz);

    let mut header = [0u8; 12];
    reader.read_exact(&mut header).context("read AERAWEB1 archive header")?;
    ensure!(&header[..8] == ARCHIVE_MAGIC, "invalid browser runtime archive magic");
    let count = u32::from_le_bytes(header[8..12].try_into().expect("four bytes"));
    ensure!(count == spec.member_count, "unexpected browser member count {count} != {}", spec.member_count);

    ensure_open_dir(dst_root, dst_root, &mut HashSet::new())?;
    let mut created_dirs: HashSet<PathBuf> = HashSet::from([dst_root.to_path_buf()]);
    let mut symlinks: Vec<(PathBuf, String)> = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];

    for _ in 0..count {
        if stop.load(Ordering::Relaxed) {
            bail!("cancelled");
        }
        let mut rec = [0u8; 12];
        reader.read_exact(&mut rec).context("read archive entry header")?;
        let name_len = u16::from_le_bytes(rec[0..2].try_into().expect("two bytes")) as usize;
        let mode = u16::from_le_bytes(rec[2..4].try_into().expect("two bytes"));
        let data_len = u64::from_le_bytes(rec[4..12].try_into().expect("eight bytes"));

        ensure!(name_len > 0 && name_len < 240, "invalid archive entry name length {name_len}");
        ensure!(data_len <= MAX_MEMBER_BYTES, "oversize archive entry ({data_len} bytes)");
        ensure!(
            reader.total + data_len <= spec.expanded_size,
            "browser archive exceeds expected expanded size"
        );

        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes).context("read archive entry path")?;
        let name = std::str::from_utf8(&name_bytes).context("archive entry path is not UTF-8")?;
        ensure!(is_safe_rel_path(name), "unsafe archive entry path: {name}");

        let pad = (4 - (reader.total % 4)) % 4;
        if pad > 0 {
            let mut junk = [0u8; 4];
            reader.read_exact(&mut junk[..pad as usize]).context("read alignment padding")?;
        }

        let out_path = dst_root.join(name);
        if let Some(parent) = out_path.parent() {
            ensure_open_dir(parent, dst_root, &mut created_dirs)?;
        }

        if mode == 0 {
            ensure!(data_len < 512, "overlong symlink target");
            let mut target_bytes = vec![0u8; data_len as usize];
            reader.read_exact(&mut target_bytes).context("read symlink target")?;
            let target = String::from_utf8(target_bytes).context("symlink target is not UTF-8")?;
            ensure!(is_safe_rel_path(&target), "unsafe symlink target: {target}");
            symlinks.push((out_path, target));
        } else {
            ensure!(mode == 0o644 || mode == 0o755, "unexpected file mode {mode:#o} for {name}");
            let mut out = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?;
            let mut left = data_len;
            while left > 0 {
                if stop.load(Ordering::Relaxed) {
                    bail!("cancelled");
                }
                let want = (left as usize).min(buf.len());
                reader.read_exact(&mut buf[..want]).with_context(|| format!("read {name}"))?;
                out.write_all(&buf[..want]).with_context(|| format!("write {}", out_path.display()))?;
                left -= want as u64;
                on_progress(reader.total);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&out_path, fs::Permissions::from_mode(u32::from(mode)))
                    .with_context(|| format!("chmod {}", out_path.display()))?;
            }
        }
        on_progress(reader.total);
    }

    // Drain any trailing stream EOF and ensure no extra bytes follow.
    let mut extra = [0u8; 1];
    ensure!(reader.read(&mut extra)? == 0, "unexpected trailing bytes in browser runtime");
    ensure!(
        reader.total == spec.expanded_size,
        "browser runtime expanded size {} != {}",
        reader.total,
        spec.expanded_size
    );
    let expanded_hash = hex::encode(reader.hash.finalize());
    ensure!(
        expanded_hash == spec.expanded_sha256,
        "browser runtime SHA-256 mismatch: {expanded_hash} != {}",
        spec.expanded_sha256
    );

    let root_canon = fs::canonicalize(dst_root).context("canonicalize rootfs")?;
    for (link_path, target_rel) in symlinks {
        let abs_target = dst_root.join(&target_rel);
        let canon_target = fs::canonicalize(&abs_target).with_context(|| format!("resolve {target_rel}"))?;
        ensure!(canon_target.starts_with(&root_canon), "symlink escapes rootfs: {target_rel}");
        #[cfg(unix)]
        {
            let link_dir = link_path.parent().context("symlink has parent")?;
            let link_dir_canon = fs::canonicalize(link_dir)?;
            let rel_target = relative_path(&link_dir_canon, &canon_target);
            std::os::unix::fs::symlink(&rel_target, &link_path)
                .with_context(|| format!("symlink {} -> {}", link_path.display(), rel_target.display()))?;
        }
        #[cfg(not(unix))]
        let _ = link_path;
    }

    Ok(())
}

fn ensure_open_dir(dir: &Path, root: &Path, seen: &mut HashSet<PathBuf>) -> Result<()> {
    if seen.contains(dir) {
        return Ok(());
    }
    fs::create_dir_all(dir).with_context(|| format!("make {}", dir.display()))?;
    // Recovery runs under umask 0077; explicitly open unpacked dirs so uid 99090 can traverse the jail.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut cur = dir.to_path_buf();
        loop {
            if seen.insert(cur.clone()) {
                fs::set_permissions(&cur, fs::Permissions::from_mode(0o755))
                    .with_context(|| format!("chmod {}", cur.display()))?;
            }
            if cur == root {
                break;
            }
            let Some(parent) = cur.parent() else {
                break;
            };
            cur = parent.to_path_buf();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        seen.insert(dir.to_path_buf());
    }
    Ok(())
}

fn is_safe_rel_path(path: &str) -> bool {
    if path.is_empty() || path.len() >= 240 || path.starts_with('/') {
        return false;
    }
    Path::new(path).components().all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(unix)]
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let a: Vec<_> = from.components().collect();
    let b: Vec<_> = to.components().collect();
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut rel = PathBuf::new();
    for _ in common..a.len() {
        rel.push("..");
    }
    for comp in &b[common..] {
        rel.push(comp.as_os_str());
    }
    rel
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblzma::write::XzEncoder;

    fn build_test_xz(entries: &[(&str, u16, &[u8])]) -> (Vec<u8>, RuntimeSpec) {
        let mut raw = Vec::new();
        raw.extend_from_slice(ARCHIVE_MAGIC);
        raw.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for &(name, mode, data) in entries {
            raw.extend_from_slice(&(name.len() as u16).to_le_bytes());
            raw.extend_from_slice(&mode.to_le_bytes());
            raw.extend_from_slice(&(data.len() as u64).to_le_bytes());
            raw.extend_from_slice(name.as_bytes());
            while !raw.len().is_multiple_of(4) {
                raw.push(0);
            }
            raw.extend_from_slice(data);
        }
        let expanded_sha = hex::encode(Sha256::digest(&raw));
        let expanded_size = raw.len() as u64;

        let mut enc = XzEncoder::new(Vec::new(), 1);
        enc.write_all(&raw).unwrap();
        let xz = enc.finish().unwrap();
        let compressed_sha = hex::encode(Sha256::digest(&xz));
        let spec = RuntimeSpec {
            compressed_size: xz.len() as u64,
            compressed_sha256: compressed_sha,
            expanded_size,
            expanded_sha256: expanded_sha,
            member_count: entries.len() as u32,
        };
        (xz, spec)
    }

    #[test]
    fn unpacks_verified_archive_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let (xz, spec) = build_test_xz(&[
            ("lib/ld-musl.so", 0o755, b"elf-loader"),
            ("usr/lib/libc.so", 0, b"lib/ld-musl.so"),
            ("etc/fonts.conf", 0o644, b"<fontconfig/>"),
        ]);
        let xz_path = dir.path().join("runtime.xz");
        fs::write(&xz_path, &xz).unwrap();
        let stop = AtomicBool::new(false);
        assert!(cached_runtime_valid(&xz_path, &spec, &stop).unwrap());

        let out = dir.path().join("rootfs");
        unpack_xz_archive(&xz_path, &out, &spec, &stop, &mut |_| {}).unwrap();
        assert_eq!(fs::read(out.join("lib/ld-musl.so")).unwrap(), b"elf-loader");
        assert_eq!(fs::read(out.join("usr/lib/libc.so")).unwrap(), b"elf-loader");
        assert_eq!(fs::read(out.join("etc/fonts.conf")).unwrap(), b"<fontconfig/>");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [&out, &out.join("usr"), &out.join("usr/lib"), &out.join("etc")] {
                assert_eq!(fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o755);
            }
        }
    }

    #[test]
    fn rejects_escaping_paths_and_bad_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let (xz, mut spec) = build_test_xz(&[("../escape", 0o644, b"bad")]);
        let xz_path = dir.path().join("bad.xz");
        fs::write(&xz_path, &xz).unwrap();
        let stop = AtomicBool::new(false);
        let out = dir.path().join("rootfs");
        assert!(unpack_xz_archive(&xz_path, &out, &spec, &stop, &mut |_| {}).is_err());
        assert!(!out.exists());

        let (xz2, good_spec) = build_test_xz(&[("a/b", 0o644, b"ok")]);
        let xz2_path = dir.path().join("corrupt.xz");
        fs::write(&xz2_path, &xz2).unwrap();
        spec = good_spec;
        spec.expanded_sha256 = "0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(unpack_xz_archive(&xz2_path, &out, &spec, &stop, &mut |_| {}).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn manifest_wraps_github_url_with_gh_proxy() {
        let m = RuntimeManifest {
            version: "1.6.0".into(),
            payload_url: "https://github.com/AERA-Plugins/browser/releases/download/v1.6.0/runtime.xz".into(),
            payload_size: 100,
            payload_sha256: "a".repeat(64),
            expanded_size: 200,
            expanded_sha256: "b".repeat(64),
            member_count: 1,
        };
        assert_eq!(
            m.proxied_url().unwrap(),
            "https://gh-proxy.org/https://github.com/AERA-Plugins/browser/releases/download/v1.6.0/runtime.xz"
        );
    }

    #[test]
    fn cached_rootfs_requires_worker_binary_and_matching_stamp() {
        let dir = tempfile::tempdir().unwrap();
        let (xz, spec) = build_test_xz(&[("usr/bin/aera-browser-worker", 0o755, b"bin")]);
        let xz_path = dir.path().join("runtime.xz");
        fs::write(&xz_path, &xz).unwrap();
        let stop = AtomicBool::new(false);
        let rootfs = dir.path().join("rootfs");
        unpack_xz_archive(&xz_path, &rootfs, &spec, &stop, &mut |_| {}).unwrap();

        assert!(cached_rootfs_path(dir.path(), None).is_none());
        fs::write(dir.path().join(".rootfs.ready"), rootfs_stamp(&spec)).unwrap();
        assert_eq!(cached_rootfs_path(dir.path(), None).as_deref(), Some(rootfs.as_path()));
        assert_eq!(cached_rootfs_path(dir.path(), Some(&spec)).as_deref(), Some(rootfs.as_path()));

        let mut other = spec.clone();
        other.member_count += 1;
        assert!(cached_rootfs_path(dir.path(), Some(&other)).is_none());

        fs::remove_file(rootfs.join("usr/bin/aera-browser-worker")).unwrap();
        assert!(cached_rootfs_path(dir.path(), None).is_none());
    }
}
