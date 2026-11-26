//! The browser page: runtime preparation state, URL input, touch forwarding, and frame updates.

use super::*;
use std::sync::Arc;

pub const VIEW_WIDTH: i32 = 360;
pub const VIEW_HEIGHT: i32 = 700;
pub const FRAME_WIDTH: u32 = 1080;
pub const FRAME_HEIGHT: u32 = 2100;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum BrowserPhase {
    #[default]
    Idle,
    Checking,
    Downloading { done: u64, total: u64 },
    Unpacking { done: u64, total: u64 },
    Starting,
    Ready,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserCmd {
    Open(String),
    Back,
    Forward,
    Reload,
    Stop,
    TouchDown(i32, i32),
    TouchMove(i32, i32),
    TouchUp(i32, i32),
    Key(u32),
    CancelDownload(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserDownloadStatus {
    Downloading,
    Finished,
    Failed(String),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserDownload {
    pub id: u32,
    pub name: String,
    pub percent: u8,
    pub received_kib: u64,
    pub total_kib: u64,
    pub status: BrowserDownloadStatus,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct BrowserState {
    pub phase: BrowserPhase,
    pub url: String,
    pub url_draft: String,
    pub editing_url: bool,
    pub web_keyboard: bool,
    pub progress: u8,
    pub can_back: bool,
    pub can_forward: bool,
    pub error: Option<String>,
    pub frame: Option<Arc<Vec<u8>>>,
    pub downloads: Vec<BrowserDownload>,
}

impl BrowserState {
    pub fn reset_session(&mut self) {
        self.phase = BrowserPhase::Idle;
        self.url.clear();
        self.url_draft.clear();
        self.editing_url = false;
        self.web_keyboard = false;
        self.progress = 0;
        self.can_back = false;
        self.can_forward = false;
        self.error = None;
        self.frame = None;
        for d in &mut self.downloads {
            if matches!(d.status, BrowserDownloadStatus::Downloading) {
                d.status = BrowserDownloadStatus::Cancelled;
            }
        }
    }

    pub fn active_downloads(&self) -> usize {
        self.downloads.iter().filter(|d| matches!(d.status, BrowserDownloadStatus::Downloading)).count()
    }

    pub fn has_clearable_downloads(&self) -> bool {
        self.downloads.iter().any(|d| !matches!(d.status, BrowserDownloadStatus::Downloading))
    }

    pub fn keyboard_open(&self) -> bool {
        self.editing_url || self.web_keyboard
    }
}

/// Map a screen pixel `(x, y)` inside the browser viewport `rect` (whose full unclipped
/// height for a 1080:2100 page is `full_h`) to WPE logical `(0..360, 0..700)`.
pub(super) fn map_viewport_point(rect: Rect, full_h: f32, x: f32, y: f32) -> (i32, i32) {
    let nx = ((x - rect.x) / rect.w.max(1.0)).clamp(0.0, 0.999);
    let ny = ((y - rect.y) / full_h.max(1.0)).clamp(0.0, 0.999);
    ((nx * VIEW_WIDTH as f32) as i32, (ny * VIEW_HEIGHT as f32) as i32)
}

impl App {
    pub fn browser_phase(&mut self, phase: BrowserPhase) {
        self.state.browser.phase = phase;
        if self.screen() == Screen::Browser {
            self.refresh();
        }
    }

    pub fn browser_status(&mut self, progress: u8, can_back: bool, can_forward: bool, uri: String, error: Option<String>) {
        let b = &mut self.state.browser;
        b.phase = BrowserPhase::Ready;
        if error.is_none() {
            b.progress = progress;
            b.can_back = can_back;
            b.can_forward = can_forward;
        }
        if !uri.is_empty() {
            b.url = uri;
            if !b.editing_url {
                b.url_draft = b.url.clone();
            }
        }
        b.error = error;
        if self.screen() == Screen::Browser {
            self.refresh();
        }
    }

    pub fn browser_frame(&mut self, rgba: Arc<Vec<u8>>) -> Option<Arc<Vec<u8>>> {
        let b = &mut self.state.browser;
        let was_ready = matches!(b.phase, BrowserPhase::Ready) && b.frame.is_some();
        let kb_open = b.keyboard_open();
        b.phase = BrowserPhase::Ready;
        let old = b.frame.replace(rgba);
        if self.screen() == Screen::Browser {
            if was_ready && !kb_open && self.frame.is_some() {
                let t = self.theme();
                let view_y = crate::pages::browser_view_y(&t) as u32;
                let full_h = (t.m.w as f32 * FRAME_HEIGHT as f32 / FRAME_WIDTH as f32).round() as u32;
                let end = (view_y + full_h).min(self.h);
                if end > view_y {
                    self.refresh_rows(view_y, end);
                } else {
                    self.refresh();
                }
            } else {
                self.refresh();
            }
        }
        old
    }

    pub fn browser_keyboard(&mut self, show: bool) {
        self.state.browser.web_keyboard = show;
        if show {
            self.state.browser.editing_url = false;
            self.state.layer = Layer::Letters;
        }
        if self.screen() == Screen::Browser {
            self.refresh();
        }
    }

    pub fn browser_failed(&mut self, why: String) {
        self.state.browser.phase = BrowserPhase::Failed(why);
        if self.screen() == Screen::Browser {
            self.refresh();
        }
    }

    fn refresh_download_views(&mut self) {
        match self.screen() {
            Screen::BrowserDownloads => self.refresh(),
            Screen::Browser if self.frame.is_some() => {
                let t = self.theme();
                let top_end = (crate::pages::browser_view_y(&t) as u32).min(self.h);
                self.refresh_rows(0, top_end);
            }
            Screen::Browser => self.refresh(),
            _ => {}
        }
    }

    fn upsert_download(&mut self, id: u32, fallback_name: &str) -> &mut BrowserDownload {
        if let Some(pos) = self.state.browser.downloads.iter().position(|d| d.id == id) {
            let item = &mut self.state.browser.downloads[pos];
            if !fallback_name.is_empty() && (item.name.is_empty() || item.name == fallback_name) {
                item.name = fallback_name.to_string();
            }
            return &mut self.state.browser.downloads[pos];
        }
        self.state.browser.downloads.insert(
            0,
            BrowserDownload {
                id,
                name: fallback_name.to_string(),
                percent: 0,
                received_kib: 0,
                total_kib: 0,
                status: BrowserDownloadStatus::Downloading,
            },
        );
        &mut self.state.browser.downloads[0]
    }

    pub fn browser_download_started(&mut self, id: u32, name: &str, now: u64) {
        let entry = self.upsert_download(id, name);
        entry.name = name.to_string();
        entry.percent = 0;
        entry.received_kib = 0;
        entry.total_kib = 0;
        entry.status = BrowserDownloadStatus::Downloading;
        self.refresh_download_views();
        self.say(&texts::browser::download_started(self.state.lang, name), now);
    }

    pub fn browser_download_progress(&mut self, id: u32, name: &str, percent: u8, received_kib: u64, total_kib: u64) {
        let entry = self.upsert_download(id, name);
        let pct = percent.min(100);
        entry.percent = pct;
        entry.received_kib = received_kib;
        entry.total_kib = total_kib;
        if !name.is_empty() && entry.name.is_empty() {
            entry.name = name.to_string();
        }
        if self.screen() == Screen::BrowserDownloads {
            self.refresh();
        }
    }

    pub fn browser_download_finished(&mut self, id: u32, name: &str, now: u64) {
        let display = {
            let entry = self.upsert_download(id, name);
            if !name.is_empty() {
                entry.name = name.to_string();
            }
            entry.percent = 100;
            if entry.total_kib == 0 {
                entry.total_kib = entry.received_kib;
            }
            entry.status = BrowserDownloadStatus::Finished;
            entry.name.clone()
        };
        self.refresh_download_views();
        self.say(&texts::browser::download_finished(self.state.lang, &display), now);
    }

    pub fn browser_download_failed(&mut self, id: u32, error: &str, now: u64) {
        let entry = self.upsert_download(id, "");
        entry.status = BrowserDownloadStatus::Failed(error.to_string());
        self.refresh_download_views();
        self.say(&texts::browser::download_failed(self.state.lang, error), now);
    }

    pub fn browser_download_cancelled(&mut self, id: u32, name: &str, now: u64) {
        let display = {
            let entry = self.upsert_download(id, name);
            if !name.is_empty() && entry.name.is_empty() {
                entry.name = name.to_string();
            }
            entry.status = BrowserDownloadStatus::Cancelled;
            entry.name.clone()
        };
        self.refresh_download_views();
        self.say(&texts::browser::download_cancelled(self.state.lang, &display), now);
    }

    pub(super) fn browser_typed(&mut self, cap: Cap) -> Vec<Effect> {
        match cap {
            Cap::Shift => self.state.layer = if self.state.layer == Layer::Shifted { Layer::Letters } else { Layer::Shifted },
            Cap::Show(layer) => self.state.layer = layer,
            _ => {}
        }
        let shifted = self.state.layer == Layer::Shifted;
        if shifted && matches!(cap, Cap::Char(_)) {
            self.state.layer = Layer::Letters;
        }
        if self.state.browser.editing_url {
            match cap {
                Cap::Char(ch) => {
                    self.state.browser.url_draft.push(ch);
                    self.refresh();
                }
                Cap::Backspace => {
                    self.state.browser.url_draft.pop();
                    self.refresh();
                }
                Cap::Enter => {
                    let typed = self.state.browser.url_draft.trim().to_string();
                    self.state.browser.editing_url = false;
                    self.refresh();
                    if !typed.is_empty() {
                        return vec![Effect::Browser(BrowserCmd::Open(typed))];
                    }
                }
                _ => self.refresh(),
            }
            return Vec::new();
        }
        self.refresh();
        if !self.state.browser.web_keyboard {
            return Vec::new();
        }
        let code = match cap {
            Cap::Char(ch) => Some(ch as u32),
            Cap::Backspace => Some(8),
            Cap::Enter => Some(13),
            _ => None,
        };
        code.map(|k| vec![Effect::Browser(BrowserCmd::Key(k))]).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testing::*;

    #[test]
    fn browser_opens_from_home_below_wlan_and_forwards_url_and_keys() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Home, W, H, PPD);
        app.state.wlan = Some(Wlan::default());

        let fr = app.whole_frame(&f, &i);
        let pos_wlan = fr.hits.iter().position(|h| h.action == Action::Open(Screen::Wlan)).unwrap();
        let pos_browser = fr.hits.iter().position(|h| h.action == Action::Open(Screen::Browser)).unwrap();
        assert_eq!(pos_browser, pos_wlan + 1, "Browser entry sits directly below WLAN on Home");

        assert_eq!(tap(&mut app, &f, &i, Action::Open(Screen::Browser)), vec![Effect::StartBrowser]);
        assert_eq!(app.screen(), Screen::Browser);

        assert!(tap(&mut app, &f, &i, Action::BrowserEditUrl).is_empty());
        assert!(app.state.browser.editing_url);
        for ch in "example.com".chars() {
            assert!(tap(&mut app, &f, &i, Action::Type(Cap::Char(ch))).is_empty());
        }
        assert_eq!(
            tap(&mut app, &f, &i, Action::Type(Cap::Enter)),
            vec![Effect::Browser(BrowserCmd::Open("example.com".into()))]
        );
        assert!(!app.state.browser.editing_url);

        assert!(tap(&mut app, &f, &i, Action::BrowserKeyboard).is_empty());
        assert_eq!(
            tap(&mut app, &f, &i, Action::Type(Cap::Char('a'))),
            vec![Effect::Browser(BrowserCmd::Key('a' as u32))]
        );

        assert_eq!(tap(&mut app, &f, &i, Action::Back), vec![Effect::StopBrowser]);
        assert_eq!(app.screen(), Screen::Home);
    }

    #[test]
    fn viewport_touch_maps_linearly_to_wpe_logical_coords() {
        let rect = Rect::new(0.0, 200.0, 1080.0, 1800.0);
        let full_h = 2100.0;
        assert_eq!(map_viewport_point(rect, full_h, 0.0, 200.0), (0, 0));
        assert_eq!(map_viewport_point(rect, full_h, 540.0, 1250.0), (180, 350));
    }

    #[test]
    fn subsequent_browser_frames_refresh_viewport_band_only_and_recycle_previous() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Browser, W, H, PPD);
        let frame1 = Arc::new(vec![0x11u8; (FRAME_WIDTH * FRAME_HEIGHT * 4) as usize]);
        assert!(app.browser_frame(frame1.clone()).is_none());
        let mut screen = Canvas::new(W, H);
        app.compose(&mut screen, &f, &i, "12:00", 0);

        let frame2 = Arc::new(vec![0x42u8; (FRAME_WIDTH * FRAME_HEIGHT * 4) as usize]);
        let prev = app.browser_frame(frame2).expect("returns replaced frame");
        assert!(Arc::ptr_eq(&prev, &frame1));
        assert!(app.frame.is_some(), "keeps toolbar cached in existing frame");
        assert!(!app.stale.is_empty(), "marks only viewport band stale");

        app.compose(&mut screen, &f, &i, "12:00", 16);
        let t = app.theme();
        let vy = crate::pages::browser_view_y(&t) as u32;
        assert_eq!(screen.data[((vy + 10) * W * 4) as usize], 0x42);
    }

    #[test]
    fn browser_downloads_tracks_progress_cancel_clear_and_keeps_session_alive() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Home, W, H, PPD);
        app.state.wlan = Some(Wlan::default());
        assert_eq!(tap(&mut app, &f, &i, Action::Open(Screen::Browser)), vec![Effect::StartBrowser]);

        app.browser_download_started(7, "rom.zip", 10);
        app.browser_download_progress(7, "rom.zip", 42, 420, 1000);
        assert_eq!(app.state.browser.active_downloads(), 1);
        assert_eq!(app.state.browser.downloads[0].percent, 42);

        // Opening Download Manager from Browser leaves the browser running in the background.
        assert!(tap(&mut app, &f, &i, Action::Open(Screen::BrowserDownloads)).is_empty());
        assert_eq!(app.screen(), Screen::BrowserDownloads);

        let fr = app.whole_frame(&f, &i);
        assert!(fr.hits.iter().any(|h| h.action == Action::BrowserCancelDownload(7)));
        assert_eq!(
            tap(&mut app, &f, &i, Action::BrowserCancelDownload(7)),
            vec![Effect::Browser(BrowserCmd::CancelDownload(7))]
        );
        app.browser_download_cancelled(7, "rom.zip", 20);
        assert_eq!(app.state.browser.active_downloads(), 0);
        assert_eq!(app.state.browser.downloads[0].status, BrowserDownloadStatus::Cancelled);

        app.browser_download_started(8, "boot.img", 30);
        app.browser_download_finished(8, "boot.img", 40);
        app.browser_download_started(9, "active.bin", 50);
        assert!(app.state.browser.has_clearable_downloads());
        assert!(tap(&mut app, &f, &i, Action::BrowserClearDownloads).is_empty());
        assert_eq!(app.state.browser.downloads.len(), 1);
        assert_eq!(app.state.browser.downloads[0].id, 9);

        // Back from BrowserDownloads returns to Browser without resetting its state.
        app.state.browser.phase = BrowserPhase::Ready;
        tap_back(&mut app, &f, &i, 60);
        assert_eq!(app.screen(), Screen::Browser);
        assert_eq!(app.state.browser.phase, BrowserPhase::Ready);
    }
}
