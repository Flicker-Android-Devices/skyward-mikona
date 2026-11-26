//! Background worker bridging the sandboxed WebKit browser with Skyward's UI loop.

use anyhow::{Context, Result};
use skyward_browser::protocol::{normalize_address, Kind, Message, FRAME_BYTES};
use skyward_browser::runtime::{self, PrepareStage};
use skyward_browser::sandbox::{self, BrowserSession, LaunchConfig};
use skyward_net::http::Servers;
use skyward_sys::worker;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

const SDCARD_BROWSER_DIR: &str = "Download/Skyward";
const PROFILE_DIR: &str = "/data/skyward/browser/profile";
const DEFAULT_HOME_URL: &str = "https://www.bing.com";
const FRAME_POOL_CAP: usize = 3;

type FramePool = Arc<Mutex<Vec<Vec<u8>>>>;

pub enum Event {
    Phase(skyward_ui::app::BrowserPhase),
    Status { progress: u8, can_back: bool, can_forward: bool, uri: String, error: Option<String> },
    Frame(Arc<Vec<u8>>),
    Keyboard(bool),
    DownloadStarted { id: u32, name: String },
    DownloadProgress { id: u32, name: String, percent: u8, received_kib: u64, total_kib: u64 },
    DownloadFinished { id: u32, name: String },
    DownloadFailed { id: u32, error: String },
    DownloadCancelled { id: u32, name: String },
    Failed(String),
}

pub struct Worker {
    stop: Arc<AtomicBool>,
    cmds: mpsc::Sender<skyward_ui::app::BrowserCmd>,
    cmd_wake: OwnedFd,
    pool: FramePool,
    worker: worker::Worker<Event>,
}

impl Worker {
    pub fn start(data_open: bool, servers: Servers) -> Result<Self> {
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if efd < 0 {
            return Err(std::io::Error::last_os_error()).context("create browser command eventfd");
        }
        // SAFETY: `eventfd` returned a valid descriptor owned by this struct.
        let cmd_wake = unsafe { OwnedFd::from_raw_fd(efd) };
        let wake_rd = cmd_wake.as_raw_fd();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = stop.clone();
        let pool: FramePool = Arc::new(Mutex::new(Vec::with_capacity(FRAME_POOL_CAP)));
        let pool_bg = pool.clone();
        let (tx, rx) = mpsc::channel();

        let worker = worker::Worker::start("browser", move |tell| {
            let work_dir = Path::new(skyward_sys::RUN).join("browser");
            if let Err(err) = run_worker(data_open, &work_dir, servers, &stop_bg, &tell, wake_rd, rx, &pool_bg) && !stop_bg.load(Ordering::Relaxed) {
                tell.tell(Event::Failed(format!("{err:#}")));
            }
        })?;

        Ok(Self { stop, cmds: tx, cmd_wake, pool, worker })
    }

    pub fn fd(&self) -> RawFd {
        self.worker.fd()
    }

    pub fn events(&self) -> Vec<Event> {
        self.worker.events()
    }

    pub fn recycle(&self, arc: Arc<Vec<u8>>) {
        if let Ok(buf) = Arc::try_unwrap(arc)
            && buf.len() == FRAME_BYTES
        {
            let mut pool = self.pool.lock().expect("frame pool lock not poisoned");
            if pool.len() < FRAME_POOL_CAP {
                pool.push(buf);
            }
        }
    }

    pub fn send(&self, cmd: skyward_ui::app::BrowserCmd) {
        if self.cmds.send(cmd).is_ok() {
            let one: u64 = 1;
            unsafe { libc::write(self.cmd_wake.as_raw_fd(), (&one as *const u64).cast(), std::mem::size_of::<u64>()) };
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let one: u64 = 1;
        unsafe { libc::write(self.cmd_wake.as_raw_fd(), (&one as *const u64).cast(), std::mem::size_of::<u64>()) };
    }
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    data_open: bool,
    work_dir: &Path,
    servers: Servers,
    stop: &AtomicBool,
    tell: &worker::Teller<Event>,
    wake_fd: RawFd,
    rx: mpsc::Receiver<skyward_ui::app::BrowserCmd>,
    pool: &FramePool,
) -> Result<()> {
    let (cache_path, downloads_dir, profile_dir) = if data_open {
        let dl = Path::new(skyward_crypto::data::SDCARD).join(SDCARD_BROWSER_DIR);
        let prof = PathBuf::from(PROFILE_DIR);
        sandbox::ensure_storage_dirs(&dl, &prof)?;
        let cache = dl.join("runtime.xz");
        (Some(cache), Some(dl), Some(prof))
    } else {
        (None, None, None)
    };

    let rootfs = runtime::prepare_runtime(cache_path.as_deref(), work_dir, servers.clone(), stop, &mut |stage| {
        let phase = match stage {
            PrepareStage::CheckingCache => skyward_ui::app::BrowserPhase::Checking,
            PrepareStage::Downloading { done, total } => skyward_ui::app::BrowserPhase::Downloading { done, total },
            PrepareStage::Unpacking { done, total } => skyward_ui::app::BrowserPhase::Unpacking { done, total },
        };
        tell.tell(Event::Phase(phase));
    })?;

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }
    tell.tell(Event::Phase(skyward_ui::app::BrowserPhase::Starting));

    let dns_servers = servers.lock().expect("DNS servers lock not poisoned").clone();
    let mut session = BrowserSession::spawn(&LaunchConfig {
        rootfs,
        work_dir: work_dir.to_path_buf(),
        downloads_dir,
        profile_dir,
        dns_servers,
    })?;
    session.send(&Message::with_text(Kind::Open, DEFAULT_HOME_URL)?)?;

    let mut fds = [
        libc::pollfd { fd: session.fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: wake_fd, events: libc::POLLIN, revents: 0 },
    ];

    while !stop.load(Ordering::Relaxed) {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 500) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("poll browser IPC");
        }

        if fds[1].revents & libc::POLLIN != 0 {
            let mut val: u64 = 0;
            while unsafe { libc::read(wake_fd, (&mut val as *mut u64).cast(), std::mem::size_of::<u64>()) } > 0 {}
            let mut pending_move: Option<(i32, i32)> = None;
            for cmd in rx.try_iter() {
                if let skyward_ui::app::BrowserCmd::TouchMove(x, y) = cmd {
                    pending_move = Some((x, y));
                } else {
                    if let Some((mx, my)) = pending_move.take() {
                        dispatch_cmd(&session, skyward_ui::app::BrowserCmd::TouchMove(mx, my), tell)?;
                    }
                    dispatch_cmd(&session, cmd, tell)?;
                }
            }
            if let Some((mx, my)) = pending_move {
                dispatch_cmd(&session, skyward_ui::app::BrowserCmd::TouchMove(mx, my), tell)?;
            }
        }

        if fds[0].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            let mut latest_frame: Option<u32> = None;
            while let Some(msg) = session.try_recv()? {
                if matches!(msg.kind(), Some(Kind::Frame)) {
                    if let Some(prev) = latest_frame.replace(msg.sequence) {
                        let mut ack = Message::new(Kind::Ack);
                        ack.sequence = prev;
                        session.send(&ack)?;
                    }
                } else {
                    handle_worker_msg(&msg, tell)?;
                }
            }
            if let Some(seq) = latest_frame {
                let mut rgba = pool
                    .lock()
                    .expect("frame pool lock not poisoned")
                    .pop()
                    .unwrap_or_else(|| vec![0u8; FRAME_BYTES]);
                session.copy_frame_rgba(seq, &mut rgba);
                let mut ack = Message::new(Kind::Ack);
                ack.sequence = seq;
                session.send(&ack)?;
                tell.tell(Event::Frame(Arc::new(rgba)));
            }
        }

        session.drain_stderr();

        if let Some(code) = session.poll_exit() {
            if !stop.load(Ordering::Relaxed) {
                let log = session.take_stderr();
                if log.is_empty() {
                    anyhow::bail!("browser worker exited ({code})");
                }
                anyhow::bail!("browser worker exited ({code}): {log}");
            }
            break;
        }
    }
    Ok(())
}

fn dispatch_cmd(session: &BrowserSession, cmd: skyward_ui::app::BrowserCmd, tell: &worker::Teller<Event>) -> Result<()> {
    use skyward_ui::app::BrowserCmd;
    let msg = match cmd {
        BrowserCmd::Open(raw) => {
            let Some(url) = normalize_address(&raw) else {
                tell.tell(Event::Status {
                    progress: 0,
                    can_back: false,
                    can_forward: false,
                    uri: raw,
                    error: Some("Only HTTP and HTTPS addresses are supported.".into()),
                });
                return Ok(());
            };
            Message::with_text(Kind::Open, &url)?
        }
        BrowserCmd::Back => Message::new(Kind::Back),
        BrowserCmd::Forward => Message::new(Kind::Forward),
        BrowserCmd::Reload => Message::new(Kind::Reload),
        BrowserCmd::Stop => Message::new(Kind::Stop),
        BrowserCmd::TouchDown(x, y) => {
            let mut m = Message::new(Kind::TouchDown);
            m.x = x;
            m.y = y;
            m
        }
        BrowserCmd::TouchMove(x, y) => {
            let mut m = Message::new(Kind::TouchMove);
            m.x = x;
            m.y = y;
            m
        }
        BrowserCmd::TouchUp(x, y) => {
            let mut m = Message::new(Kind::TouchUp);
            m.x = x;
            m.y = y;
            m
        }
        BrowserCmd::Key(code) => {
            let mut m = Message::new(Kind::Key);
            m.value = code;
            m
        }
        BrowserCmd::CancelDownload(id) => {
            let mut m = Message::new(Kind::DownloadCancel);
            m.sequence = id;
            m
        }
    };
    session.send(&msg)
}

fn handle_worker_msg(msg: &Message, tell: &worker::Teller<Event>) -> Result<()> {
    match msg.kind() {
        Some(Kind::Status) => {
            tell.tell(Event::Status {
                progress: msg.value.min(100) as u8,
                can_back: msg.x != 0,
                can_forward: msg.y != 0,
                uri: msg.text_str().to_string(),
                error: None,
            });
        }
        Some(Kind::Error) => {
            let err = msg.text_str();
            // WebKit emits "Frame load interrupted" when handing a link response to the download manager.
            if err != "Frame load interrupted" {
                tell.tell(Event::Status {
                    progress: 0,
                    can_back: false,
                    can_forward: false,
                    uri: String::new(),
                    error: Some(err.to_string()),
                });
            }
        }
        Some(Kind::KeyboardShow) => {
            tell.tell(Event::Keyboard(msg.value > 0));
        }
        Some(Kind::KeyboardHide) => {
            tell.tell(Event::Keyboard(false));
        }
        Some(Kind::DownloadStarted) => {
            tell.tell(Event::DownloadStarted {
                id: msg.sequence,
                name: msg.text_str().to_string(),
            });
        }
        Some(Kind::DownloadProgress) => {
            tell.tell(Event::DownloadProgress {
                id: msg.sequence,
                name: msg.text_str().to_string(),
                percent: msg.x.clamp(0, 100) as u8,
                received_kib: u64::from(msg.value),
                total_kib: msg.y.max(0) as u64,
            });
        }
        Some(Kind::DownloadFinished) => {
            tell.tell(Event::DownloadFinished {
                id: msg.sequence,
                name: msg.text_str().to_string(),
            });
        }
        Some(Kind::DownloadFailed) => {
            tell.tell(Event::DownloadFailed {
                id: msg.sequence,
                error: msg.text_str().to_string(),
            });
        }
        Some(Kind::DownloadCancelled) => {
            tell.tell(Event::DownloadCancelled {
                id: msg.sequence,
                name: msg.text_str().to_string(),
            });
        }
        _ => {}
    }
    Ok(())
}
