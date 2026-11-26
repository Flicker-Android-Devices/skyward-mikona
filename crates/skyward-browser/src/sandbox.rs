//! Sandboxed launcher and IPC bridge for `aera-browser-worker` on Android.

use crate::protocol::{Kind, Message, SHARED_BYTES};
use anyhow::{bail, Context, Result};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr;

const BROWSER_UID: libc::uid_t = 99090;
const BROWSER_GID: libc::gid_t = 99090;
const AID_INET: libc::gid_t = 3003;
const STDERR_CAP: usize = 4096;
const RAMDISK_FONT: &str = "/skyward/MiSansVF.ttf";
#[cfg(target_arch = "aarch64")]
const WPE_HOOK_SO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libskyward_wpe_hook.so"));

pub struct LaunchConfig {
    pub rootfs: PathBuf,
    pub work_dir: PathBuf,
    pub downloads_dir: Option<PathBuf>,
    pub profile_dir: Option<PathBuf>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub struct BrowserSession {
    child: libc::pid_t,
    sock: OwnedFd,
    stderr_fd: OwnedFd,
    stderr_buf: String,
    _memfd: OwnedFd,
    shm: *mut u8,
}

struct ChildMounts {
    rootfs: CString,
    jail: CString,
    jail_tmp: CString,
    jail_downloads: CString,
    jail_profile: CString,
    jail_resolv: CString,
    resolv_src: CString,
    dl_src: Option<CString>,
    prof_src: Option<CString>,
    font_bind: Option<(&'static CStr, CString)>,
    dev_binds: [(&'static CStr, CString); 5],
}

impl ChildMounts {
    fn prepare(jail: &Path, cfg: &LaunchConfig) -> Result<Self> {
        let font_bind = Path::new(RAMDISK_FONT)
            .exists()
            .then(|| cstr(&jail.join("usr/share/fonts/skyward/MiSansVF.ttf")).map(|dst| (c"/skyward/MiSansVF.ttf", dst)))
            .transpose()?;
        Ok(Self {
            rootfs: cstr(&cfg.rootfs)?,
            jail: cstr(jail)?,
            jail_tmp: cstr(&jail.join("tmp"))?,
            jail_downloads: cstr(&jail.join("downloads"))?,
            jail_profile: cstr(&jail.join("profile"))?,
            jail_resolv: cstr(&jail.join("etc/resolv.conf"))?,
            resolv_src: cstr(&cfg.work_dir.join("resolv.conf"))?,
            dl_src: cfg.downloads_dir.as_ref().map(|p| cstr(p)).transpose()?,
            prof_src: cfg.profile_dir.as_ref().map(|p| cstr(p)).transpose()?,
            font_bind,
            dev_binds: [
                (c"/dev/null", cstr(&jail.join("dev/null"))?),
                (c"/dev/urandom", cstr(&jail.join("dev/urandom"))?),
                (c"/dev/zero", cstr(&jail.join("dev/zero"))?),
                (c"/dev/kgsl-3d0", cstr(&jail.join("dev/kgsl-3d0"))?),
                (c"/dev/ion", cstr(&jail.join("dev/ion"))?),
            ],
        })
    }
}

// SAFETY: `shm` points to an `OwnedFd`-backed `memfd` mapping kept alive until `Drop` (`munmap`),
// and is only accessed by the single `BrowserSession` owner.
unsafe impl Send for BrowserSession {}

impl BrowserSession {
    /// Launch `aera-browser-worker` in a minimal read-only namespace jail.
    pub fn spawn(cfg: &LaunchConfig) -> Result<Self> {
        prepare_jail_stubs(&cfg.rootfs, &cfg.work_dir, &cfg.dns_servers)?;
        let jail = cfg.work_dir.join("jail");
        fs::create_dir_all(&jail).with_context(|| format!("make {}", jail.display()))?;

        let memfd = create_shared_memfd()?;
        let shm = unsafe {
            libc::mmap(
                ptr::null_mut(),
                SHARED_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                memfd.as_raw_fd(),
                0,
            )
        };
        if shm == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("mmap browser shared memfd");
        }

        let mut sv = [-1i32; 2];
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
            unsafe { libc::munmap(shm, SHARED_BYTES) };
            return Err(std::io::Error::last_os_error()).context("socketpair for browser IPC");
        }
        // SAFETY: `socketpair` returned two valid file descriptors on success.
        let parent_sock = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let child_sock = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        let mut err_pipe = [-1i32; 2];
        if unsafe { libc::pipe2(err_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            unsafe { libc::munmap(shm, SHARED_BYTES) };
            return Err(std::io::Error::last_os_error()).context("pipe for browser stderr");
        }
        // SAFETY: `pipe2` returned two valid pipe descriptors on success.
        let stderr_rd = unsafe { OwnedFd::from_raw_fd(err_pipe[0]) };
        let stderr_wr = unsafe { OwnedFd::from_raw_fd(err_pipe[1]) };

        set_nonblocking(parent_sock.as_raw_fd(), "browser IPC socket")?;
        set_nonblocking(stderr_rd.as_raw_fd(), "browser stderr pipe")?;

        // Prepare all C strings before `fork` so the child performs zero heap allocations.
        let mounts = ChildMounts::prepare(&jail, cfg)?;

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe { libc::munmap(shm, SHARED_BYTES) };
            return Err(std::io::Error::last_os_error()).context("fork browser launcher");
        }
        if pid == 0 {
            drop(parent_sock);
            drop(stderr_rd);
            unsafe { libc::munmap(shm, SHARED_BYTES) };
            child_exec(&mounts, memfd.as_raw_fd(), child_sock.as_raw_fd(), stderr_wr.as_raw_fd());
        }

        drop(child_sock);
        drop(stderr_wr);
        Ok(Self { child: pid, sock: parent_sock, stderr_fd: stderr_rd, stderr_buf: String::new(), _memfd: memfd, shm: shm.cast() })
    }

    pub fn fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    pub fn send(&self, msg: &Message) -> Result<()> {
        let bytes = msg.as_bytes();
        let rc = unsafe { libc::send(self.sock.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
        if rc != bytes.len() as isize {
            return Err(std::io::Error::last_os_error()).context("send browser IPC message");
        }
        Ok(())
    }

    pub fn try_recv(&mut self) -> Result<Option<Message>> {
        let mut buf = [0u8; std::mem::size_of::<Message>()];
        let rc = unsafe {
            libc::recv(
                self.sock.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err).context("receive browser IPC message");
        }
        if rc == 0 {
            let status = self.wait_brief_exit();
            let log = self.take_stderr();
            match (status, log.is_empty()) {
                (Some(code), false) => bail!("browser worker exited ({code}): {log}"),
                (Some(code), true) => bail!("browser worker closed IPC socket (exit={code})"),
                (None, false) => bail!("browser worker closed IPC socket: {log}"),
                (None, true) => bail!("browser worker closed IPC socket"),
            }
        }
        let msg = Message::from_bytes(&buf[..rc as usize]).context("invalid browser IPC packet")?;
        Ok(Some(msg))
    }

    pub fn drain_stderr(&mut self) {
        let mut chunk = [0u8; 1024];
        loop {
            let n = unsafe { libc::read(self.stderr_fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
            if n <= 0 {
                break;
            }
            // Keep draining the pipe even after `STDERR_CAP` so child writes never block.
            if self.stderr_buf.len() < STDERR_CAP {
                let text = String::from_utf8_lossy(&chunk[..n as usize]);
                for ch in text.chars() {
                    if self.stderr_buf.len() + ch.len_utf8() > STDERR_CAP {
                        break;
                    }
                    self.stderr_buf.push(ch);
                }
            }
        }
    }

    pub fn take_stderr(&mut self) -> String {
        self.drain_stderr();
        self.stderr_buf.trim().replace('\n', " | ")
    }

    fn wait_brief_exit(&mut self) -> Option<i32> {
        for _ in 0..10 {
            if let Some(code) = self.poll_exit() {
                return Some(code);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        None
    }

    /// Copy and swizzle frame `slot` (`0` or `1`) into an `RGBA8` byte buffer (`FRAME_BYTES`).
    pub fn copy_frame_rgba(&self, slot: u32, dst: &mut [u8]) {
        let idx = (slot as usize) % crate::protocol::FRAME_SLOTS;
        let offset = idx * crate::protocol::FRAME_BYTES;
        // SAFETY: `self.shm` maps `SHARED_BYTES = 2 * FRAME_BYTES`, and worker pauses writes to `slot` until `kAck`.
        let src = unsafe { std::slice::from_raw_parts(self.shm.add(offset), crate::protocol::FRAME_BYTES) };
        crate::protocol::bgra_to_rgba(src, dst);
    }

    pub fn poll_exit(&mut self) -> Option<i32> {
        if self.child <= 0 {
            return None;
        }
        let mut status = 0;
        let waited = unsafe { libc::waitpid(self.child, &mut status, libc::WNOHANG) };
        if waited == self.child {
            self.child = 0;
            return Some(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                -libc::WTERMSIG(status)
            } else {
                -1
            });
        }
        None
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        let _ = self.send(&Message::new(Kind::Close));
        unsafe {
            libc::munmap(self.shm.cast(), SHARED_BYTES);
        }
        if self.child > 0 {
            for _ in 0..20 {
                if self.poll_exit().is_some() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            unsafe {
                libc::kill(self.child, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(self.child, &mut status, 0);
            }
            self.child = 0;
        }
    }
}

fn prepare_jail_stubs(rootfs: &Path, work_dir: &Path, dns_servers: &[Ipv4Addr]) -> Result<()> {
    for rel in ["tmp", "downloads", "profile", "dev", "etc"] {
        let dir = rootfs.join(rel);
        fs::create_dir_all(&dir).with_context(|| format!("create stub {rel}"))?;
        // Recovery runs under umask 0077; `/dev` and `/etc` must be traversable by uid 99090.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod stub {}", dir.display()))?;
    }
    for dev_stub in ["dev/null", "dev/urandom", "dev/zero", "dev/kgsl-3d0", "dev/ion"] {
        let p = rootfs.join(dev_stub);
        if !p.exists() {
            File::create(&p).with_context(|| format!("create stub {}", p.display()))?;
        }
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644))?;
    }
    let etc_resolv = rootfs.join("etc/resolv.conf");
    if !etc_resolv.exists() {
        File::create(&etc_resolv)?;
    }
    fs::set_permissions(&etc_resolv, fs::Permissions::from_mode(0o644))?;

    if Path::new(RAMDISK_FONT).exists() {
        let font_dir = rootfs.join("usr/share/fonts/skyward");
        fs::create_dir_all(&font_dir).with_context(|| format!("create stub {}", font_dir.display()))?;
        fs::set_permissions(&font_dir, fs::Permissions::from_mode(0o755))?;
        let font_stub = font_dir.join("MiSansVF.ttf");
        if !font_stub.exists() {
            File::create(&font_stub).with_context(|| format!("create stub {}", font_stub.display()))?;
        }
        fs::set_permissions(&font_stub, fs::Permissions::from_mode(0o644))?;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let hook_path = rootfs.join("usr/lib/libskyward_wpe_hook.so");
        fs::write(&hook_path, WPE_HOOK_SO).with_context(|| format!("write {}", hook_path.display()))?;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))?;
    }

    let mut resolv = String::new();
    for ip in dns_servers {
        resolv.push_str(&format!("nameserver {ip}\n"));
    }
    if resolv.is_empty() {
        resolv.push_str("nameserver 223.5.5.5\nnameserver 8.8.8.8\n");
    }
    let work_resolv = work_dir.join("resolv.conf");
    fs::write(&work_resolv, resolv).with_context(|| format!("write {}", work_resolv.display()))?;
    fs::set_permissions(&work_resolv, fs::Permissions::from_mode(0o644))?;

    fs::set_permissions(rootfs, fs::Permissions::from_mode(0o755))?;
    chown(rootfs, Some(0), Some(0))?;
    Ok(())
}

fn create_shared_memfd() -> Result<OwnedFd> {
    let name = CString::new("aera-browser").expect("literal has no NUL");
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("memfd_create");
    }
    // SAFETY: `memfd_create` succeeded and returned a new fd.
    let owned = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    if unsafe { libc::ftruncate(owned.as_raw_fd(), SHARED_BYTES as libc::off_t) } != 0 {
        return Err(std::io::Error::last_os_error()).context("ftruncate browser memfd");
    }
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    let _ = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    Ok(owned)
}

fn set_nonblocking(fd: RawFd, what: &str) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("set {what} nonblocking"));
    }
    Ok(())
}

fn cstr(path: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).with_context(|| format!("invalid path {}", path.display()))
}

unsafe fn fail_child(msg: &[u8], code: i32) -> ! {
    unsafe {
        let mut errno = *libc::__errno();
        let trimmed = msg.strip_suffix(b"\n").unwrap_or(msg);
        let mut buf = [0u8; 128];
        let mut n = trimmed.len().min(buf.len() - 24);
        buf[..n].copy_from_slice(&trimmed[..n]);
        let tag = b" (errno=";
        buf[n..n + tag.len()].copy_from_slice(tag);
        n += tag.len();
        if errno <= 0 {
            buf[n] = b'0';
            n += 1;
        } else {
            let mut rev = [0u8; 12];
            let mut k = 0;
            while errno > 0 && k < rev.len() {
                rev[k] = b'0' + (errno % 10) as u8;
                errno /= 10;
                k += 1;
            }
            while k > 0 {
                k -= 1;
                buf[n] = rev[k];
                n += 1;
            }
        }
        buf[n] = b')';
        buf[n + 1] = b'\n';
        n += 2;
        let _ = libc::write(2, buf.as_ptr().cast(), n);
        libc::_exit(code);
    }
}

unsafe fn move_fd_above(fd: RawFd, min_fd: RawFd) -> RawFd {
    if fd >= min_fd {
        return fd;
    }
    let moved = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min_fd) };
    if moved < 0 {
        unsafe { fail_child(b"dupfd above failed\n", 100) };
    }
    moved
}

unsafe fn mount_rw_tmpfs(target: *const libc::c_char) {
    let opts = c"mode=0755,uid=99090,gid=99090,size=64m";
    if unsafe { libc::mount(c"tmpfs".as_ptr(), target, c"tmpfs".as_ptr(), libc::MS_NOSUID | libc::MS_NODEV, opts.as_ptr().cast()) } != 0 {
        unsafe { fail_child(b"mount tmpfs inside jail failed\n", 94) };
    }
}

fn child_exec(mounts: &ChildMounts, memfd: RawFd, sock: RawFd, stderr_wr: RawFd) -> ! {
    unsafe {
        let err_fd = move_fd_above(stderr_wr, 5);
        let memfd = move_fd_above(memfd, 5);
        let sock = move_fd_above(sock, 5);
        if libc::dup2(err_fd, 1) != 1 || libc::dup2(err_fd, 2) != 2 {
            libc::_exit(100);
        }
        if err_fd > 4 {
            libc::close(err_fd);
        }

        if libc::unshare(libc::CLONE_NEWNS) != 0 {
            fail_child(b"unshare(CLONE_NEWNS) failed\n", 91);
        }
        let root_slash = c"/";
        if libc::mount(ptr::null(), root_slash.as_ptr(), ptr::null(), libc::MS_REC | libc::MS_PRIVATE, ptr::null()) != 0 {
            fail_child(b"mount MS_PRIVATE failed\n", 92);
        }
        // Bind `rootfs` onto `jail` (zero-copy) so `/data`, `/sys`, `/proc/1` disappear after `chroot`.
        if libc::mount(mounts.rootfs.as_ptr(), mounts.jail.as_ptr(), ptr::null(), libc::MS_BIND, ptr::null()) != 0 {
            fail_child(b"bind rootfs onto jail failed\n", 93);
        }

        mount_rw_tmpfs(mounts.jail_tmp.as_ptr());
        if let Some(dl) = &mounts.dl_src {
            if libc::mount(dl.as_ptr(), mounts.jail_downloads.as_ptr(), ptr::null(), libc::MS_BIND, ptr::null()) != 0 {
                fail_child(b"bind downloads failed\n", 94);
            }
        } else {
            mount_rw_tmpfs(mounts.jail_downloads.as_ptr());
        }
        if let Some(prof) = &mounts.prof_src {
            if libc::mount(prof.as_ptr(), mounts.jail_profile.as_ptr(), ptr::null(), libc::MS_BIND, ptr::null()) != 0 {
                fail_child(b"bind profile failed\n", 94);
            }
        } else {
            mount_rw_tmpfs(mounts.jail_profile.as_ptr());
        }

        if libc::mount(mounts.resolv_src.as_ptr(), mounts.jail_resolv.as_ptr(), ptr::null(), libc::MS_BIND, ptr::null()) != 0 {
            fail_child(b"bind resolv.conf failed\n", 94);
        }
        for (src, dst) in &mounts.dev_binds {
            let _ = libc::mount(src.as_ptr(), dst.as_ptr(), ptr::null(), libc::MS_BIND, ptr::null());
        }
        if let Some((src, dst)) = &mounts.font_bind {
            let _ = libc::mount(src.as_ptr(), dst.as_ptr(), ptr::null(), libc::MS_BIND, ptr::null());
        }

        if libc::mount(ptr::null(), mounts.jail.as_ptr(), ptr::null(), libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY, ptr::null()) != 0 {
            fail_child(b"remount jail ro failed\n", 95);
        }
        if libc::chdir(mounts.jail.as_ptr()) != 0 || libc::chroot(mounts.jail.as_ptr()) != 0 || libc::chdir(root_slash.as_ptr()) != 0 {
            fail_child(b"chroot jail failed\n", 96);
        }

        for cap in 0..=40 {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && *libc::__errno() != libc::EINVAL {
                fail_child(b"drop capbset failed\n", 97);
            }
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail_child(b"PR_SET_NO_NEW_PRIVS failed\n", 98);
        }
        install_seccomp();

        let inet_group = AID_INET;
        if libc::setgroups(1, &inet_group) != 0 || libc::setresgid(BROWSER_GID, BROWSER_GID, BROWSER_GID) != 0 || libc::setresuid(BROWSER_UID, BROWSER_UID, BROWSER_UID) != 0 {
            fail_child(b"setgroups/setresgid/setresuid failed\n", 99);
        }

        if libc::dup2(memfd, 3) != 3 || libc::dup2(sock, 4) != 4 {
            fail_child(b"dup2(3/4) failed\n", 100);
        }
        libc::close(memfd);
        libc::close(sock);
        // Clear CLOEXEC on fd 3 and fd 4 after dup2.
        let _ = libc::fcntl(3, libc::F_SETFD, 0);
        let _ = libc::fcntl(4, libc::F_SETFD, 0);
        // Restore standard 0022 umask in the worker so downloaded files are readable after reboot.
        libc::umask(0o022);

        let prog = c"/usr/bin/aera-browser-worker";
        let arg1 = c"--isolated-ipc-v1";
        let argv = [prog.as_ptr(), arg1.as_ptr(), ptr::null()];
        let envp = [
            c"HOME=/profile".as_ptr(),
            c"TMPDIR=/tmp".as_ptr(),
            c"XDG_RUNTIME_DIR=/tmp".as_ptr(),
            c"XDG_CACHE_HOME=/tmp".as_ptr(),
            c"XDG_DATA_HOME=/profile".as_ptr(),
            c"XDG_CONFIG_HOME=/profile".as_ptr(),
            c"FONTCONFIG_PATH=/etc/fonts".as_ptr(),
            c"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt".as_ptr(),
            c"VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/freedreno_icd.json".as_ptr(),
            c"LIBGL_DRIVERS_PATH=/usr/lib/dri".as_ptr(),
            c"MESA_LOADER_DRIVER_OVERRIDE=zink".as_ptr(),
            #[cfg(target_arch = "aarch64")]
            c"LD_PRELOAD=/usr/lib/libskyward_wpe_hook.so".as_ptr(),
            ptr::null(),
        ];
        libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
        fail_child(b"execve aera-browser-worker failed\n", 101);
    }
}

unsafe fn install_seccomp() {
    const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K from <linux/bpf_common.h>
    let mut filter = [libc::sock_filter { code: BPF_RET_K, jt: 0, jf: 0, k: libc::SECCOMP_RET_ALLOW }];
    let prog = libc::sock_fprog { len: 1, filter: filter.as_mut_ptr() };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog, 0, 0) } != 0 {
        unsafe { fail_child(b"PR_SET_SECCOMP failed\n", 102) };
    }
}

/// Ensure cache/download directory `/sdcard/Download/Skyward` and private profile directory exist
/// with permissions usable by the unprivileged `99090` worker without risking cache tampering.
pub fn ensure_storage_dirs(download_dir: &Path, profile_dir: &Path) -> Result<()> {
    fs::create_dir_all(download_dir).with_context(|| format!("make {}", download_dir.display()))?;
    // Sticky bit + world-writable lets uid 99090 create downloaded files while protecting root-owned `runtime.xz`.
    fs::set_permissions(download_dir, fs::Permissions::from_mode(0o1777))?;
    let cached = download_dir.join("runtime.xz");
    if cached.exists() {
        fs::set_permissions(cached, fs::Permissions::from_mode(0o644))?;
    }
    fs::create_dir_all(profile_dir).with_context(|| format!("make {}", profile_dir.display()))?;
    chown(profile_dir, Some(BROWSER_UID), Some(BROWSER_GID))?;
    fs::set_permissions(profile_dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
