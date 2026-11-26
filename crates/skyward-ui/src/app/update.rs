//! The update page: asking the phone maker's server for the newest system
//! and downloading its full package.

use super::*;

/// Where an update package comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageKind {
    Ota,
    Official,
    Rom,
    Firmware,
}

/// One downloadable package shown on the update page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePackage {
    pub kind: PackageKind,
    /// Relative folder/branch label (e.g. `"sixteen / qpr2 / PixelOS"`).
    pub channel: String,
    pub release: Release,
    pub have: Have,
}

/// All packages gathered from configured OTA, official, ROM, and firmware sources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateCatalog {
    pub packages: Vec<UpdatePackage>,
    /// Non-fatal error from a subset of sources when others succeeded.
    pub warning: Option<String>,
}

/// How far asking the update server for the newest system has come.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Check {
    #[default]
    Idle,
    Asking,
    Failed(Unanswered),
    /// The newest system the server knows; none when it knows of none for
    /// the installed one.
    Answered(Option<Release>),
    /// Catalog of OTA, official, ROM, and firmware packages.
    Catalog(UpdateCatalog),
}

/// What internal storage holds of the newest system's full package.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Have {
    #[default]
    Nothing,
    /// Part of it, this many bytes, from a download stopped before its end.
    Part(u64),
    /// All of it, checked, this many bytes.
    Whole(u64),
}

/// Downloading the newest system's full package, as the update page shows
/// it: how far it has come, how fast, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadJob {
    /// None until the download has begun.
    pub progress: Option<Progress>,
    /// Bytes a second.
    pub rate: u64,
    pub outcome: Option<DownloadEnd>,
    /// Stopping was asked for and is under way.
    pub stopping: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadEnd {
    Downloaded,
    Stopped,
    Failed(Failure),
}

/// Where the full packages downloaded go, from the top of internal
/// storage: the folder the stock updater keeps them in.
pub const DOWNLOADS: &str = "downloaded_rom";

impl App {
    /// What the update server answered, and what internal storage holds of
    /// the full package of the newest system it told of.
    pub fn update_checked(&mut self, answer: Result<Option<Release>, Unanswered>, have: Have) {
        self.state.check = match answer {
            Ok(newest) => Check::Answered(newest),
            Err(why) => Check::Failed(why),
        };
        self.state.have = have;
        if matches!(self.screen(), Screen::Update) {
            self.refresh();
        }
    }

    /// Packages gathered from configured update, ROM, and firmware sources.
    pub fn catalog_checked(&mut self, answer: Result<UpdateCatalog, Unanswered>) {
        self.state.check = match answer {
            Ok(cat) => {
                if self.state.picked_package.is_some_and(|i| i >= cat.packages.len()) {
                    self.state.picked_package = None;
                }
                Check::Catalog(cat)
            }
            Err(why) => Check::Failed(why),
        };
        if matches!(self.screen(), Screen::Update | Screen::UpdatePackage) {
            self.refresh();
        }
    }

    /// Refreshes what internal storage holds of each package in the catalog.
    pub fn catalog_have(&mut self, haves: Vec<Have>) {
        if let Check::Catalog(cat) = &mut self.state.check {
            for (pkg, have) in cat.packages.iter_mut().zip(haves) {
                pkg.have = have;
            }
            if matches!(self.screen(), Screen::Update | Screen::UpdatePackage) {
                self.refresh();
            }
        }
    }

    /// How far downloading the full package has come, and how fast it goes,
    /// in bytes a second.
    pub fn download_progress(&mut self, progress: Progress, rate: u64) {
        let job = self.state.download.as_mut().expect("only a download under way moves on");
        job.progress = Some(progress);
        job.rate = rate;
        if matches!(self.screen(), Screen::Update | Screen::UpdatePackage) {
            self.refresh();
        }
    }

    /// Downloading the full package has ended, leaving `have` of it: the
    /// update page says how, lit for the user to read.
    pub fn download_ended(&mut self, end: DownloadEnd, have: Have, now: u64) {
        let job = self.state.download.as_mut().expect("only a download under way ends");
        job.stopping = false;
        job.outcome = Some(end);
        self.state.have = have;
        if let (Check::Catalog(cat), Some(name)) = (&mut self.state.check, &self.state.downloading_package) {
            for pkg in &mut cat.packages {
                if &pkg.release.name == name {
                    pkg.have = have;
                }
            }
        }
        self.wake(now);
        self.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testing::*;

    fn newest() -> Release {
        Release {
            version: "OS3.0.310.0.WMACNXM".into(),
            name: "ishtar-ota_full-OS3.0.310.0.WMACNXM-user-16.0-0123456789.zip".into(),
            urls: vec!["https://ultimateota.d.miui.com/OS3.0.310.0.WMACNXM/ishtar-ota_full.zip".into()],
            md5: "0123456789abcdef0123456789abcdef".into(),
            size: "7.1G".into(),
            length: Some(7_572_375_802),
        }
    }

    #[test]
    fn the_update_page_asks_for_the_newest_system_and_downloads_its_full_package_to_install() {
        let f = fonts();
        let i = DeviceInfo { os_version: Some("OS3.0.308.0.WMACNXM".into()), ..info() };
        let mut app = App::new(Screen::Install, W, H, PPD);
        app.state.update_server = true;
        app.state.wlan = Some(Wlan::default());
        app.refresh();
        assert_eq!(tap(&mut app, &f, &i, Action::Open(Screen::Update)), vec![Effect::ReadUpdate], "nothing is asked without a network");
        assert!(tap(&mut app, &f, &i, Action::CheckUpdate).is_empty());
        assert_eq!(app.screen(), Screen::Wlan, "asking takes a network, which the WLAN page joins");
        app.key(Key::Back, 0);
        app.set_wlan(connected("Skyward"));
        assert_eq!(tap(&mut app, &f, &i, Action::CheckUpdate), vec![Effect::CheckUpdate]);
        assert_eq!(app.state.check, Check::Asking);
        app.update_checked(Ok(Some(newest())), Have::Nothing);
        app.state.data = Data::Locked { user: 0, keys: Keys::Digits, checking: false };
        app.refresh();
        assert!(tap(&mut app, &f, &i, Action::Download).is_empty());
        assert_eq!(app.screen(), Screen::Decrypt, "the package goes to internal storage, which opens with the owner's files");
        app.state.data = Data::Open;
        app.act(Action::Skip, 0);
        assert_eq!(app.screen(), Screen::Update);
        assert_eq!(tap(&mut app, &f, &i, Action::Download), vec![Effect::Download(newest())]);
        app.download_progress(Progress::Checking { done: 0, total: 7_572_375_802 }, 0);
        app.download_progress(Progress::Downloading { done: 1_000_000_000, total: 7_572_375_802 }, 12_000_000);
        assert!(app.state.downloading());
        assert_eq!(tap(&mut app, &f, &i, Action::StopDownload), vec![Effect::StopDownload]);
        assert!(!app.frame(&f, &i).hits.iter().any(|h| h.action == Action::StopDownload), "stopping, it is not asked again");
        // An end lights the panel, and a touch just after only keeps it lit.
        app.download_ended(DownloadEnd::Stopped, Have::Part(1_000_000_000), 0);
        assert_eq!(tap_at(&mut app, &f, &i, Action::Download, 2000), vec![Effect::Download(newest())], "a download stopped carries on");
        let damaged = skyward_net::download::Failure::Damaged;
        app.download_ended(DownloadEnd::Failed(damaged.clone()), Have::Nothing, 3000);
        assert_eq!(fmt::download_failure(Lang::Hans, &damaged), "完整更新包校验失败，已删除，请重新下载。");
        assert_eq!(tap_at(&mut app, &f, &i, Action::Download, 5000), vec![Effect::Download(newest())]);
        app.download_ended(DownloadEnd::Downloaded, Have::Whole(7_572_375_802), 6000);
        let fx = tap_at(&mut app, &f, &i, Action::InstallDownloaded, 8000);
        assert_eq!(fx, vec![Effect::InstallFile(Place::Storage, format!("downloaded_rom/{}", newest().name))]);
        assert_eq!(app.screen(), Screen::Installing);
    }

    #[test]
    fn the_update_page_asks_the_server_as_it_opens_once_a_network_is_joined() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Install, W, H, PPD);
        app.state.wlan = Some(connected("Skyward"));
        assert_eq!(tap(&mut app, &f, &i, Action::Open(Screen::Update)), vec![Effect::ReadUpdate], "a phone whose server is not known asks nothing");
        app.key(Key::Back, 0);
        app.state.update_server = true;
        assert_eq!(tap(&mut app, &f, &i, Action::Open(Screen::Update)), vec![Effect::ReadUpdate, Effect::CheckUpdate]);
        app.update_checked(Err(Unanswered::Failed("update.miui.com did not answer".into())), Have::Nothing);
        app.key(Key::Back, 0);
        assert_eq!(tap(&mut app, &f, &i, Action::Open(Screen::Update)), vec![Effect::ReadUpdate, Effect::CheckUpdate], "a failed check is tried again");
    }

    #[test]
    fn a_catalog_offers_roms_and_firmware_to_pick_download_and_install() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Update, W, H, PPD);
        app.state.update_server = true;
        app.state.wlan = Some(connected("Skyward"));
        app.state.data = Data::Open;
        let rom = Release {
            version: "PixelOS_thyme-16.2-20260624-1725".into(),
            name: "PixelOS_thyme-16.2-20260624-1725.zip".into(),
            urls: vec!["https://sourceforge.net/projects/flickerdev/files/ROM/sixteen/thyme/qpr2/PixelOS/20260625/PixelOS_thyme-16.2-20260624-1725.zip/download".into()],
            md5: "f6b3e3cb34a5048166a3ac9dc2e25105".into(),
            size: String::new(),
            length: Some(2_611_868_200),
        };
        let fw = Release {
            version: "fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0".into(),
            name: "fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip".into(),
            urls: vec!["https://sourceforge.net/projects/flickerdev/files/Firmware/thyme/fw_thyme_miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip/download".into()],
            md5: "40b214ab288395ed0823c3ce9d085268".into(),
            size: String::new(),
            length: Some(152_005_860),
        };
        app.catalog_checked(Ok(UpdateCatalog {
            packages: vec![
                UpdatePackage { kind: PackageKind::Rom, channel: "sixteen / qpr2 / PixelOS".into(), release: rom.clone(), have: Have::Nothing },
                UpdatePackage { kind: PackageKind::Firmware, channel: String::new(), release: fw.clone(), have: Have::Whole(152_005_860) },
            ],
            warning: None,
        }));
        assert_eq!(tap(&mut app, &f, &i, Action::PickUpdatePackage(0)), vec![Effect::ReadUpdate]);
        assert_eq!(app.screen(), Screen::UpdatePackage);
        assert_eq!(tap(&mut app, &f, &i, Action::Download), vec![Effect::Download(rom.clone())]);
        app.download_ended(DownloadEnd::Downloaded, Have::Whole(2_611_868_200), 1000);
        assert_eq!(
            tap_at(&mut app, &f, &i, Action::InstallDownloaded, 3000),
            vec![Effect::InstallFile(Place::Storage, format!("{DOWNLOADS}/{}", rom.name))]
        );
        app.state.install = Install::Idle;
        app.key(Key::Back, 4000);
        app.key(Key::Back, 4500);
        assert_eq!(app.screen(), Screen::Update);
        assert_eq!(tap_at(&mut app, &f, &i, Action::PickUpdatePackage(1), 5000), vec![Effect::ReadUpdate]);
        assert_eq!(
            tap_at(&mut app, &f, &i, Action::InstallDownloaded, 5500),
            vec![Effect::InstallFile(Place::Storage, format!("{DOWNLOADS}/{}", fw.name))]
        );
    }

    #[test]
    fn a_full_thyme_catalog_composes_cleanly_at_thyme_density() {
        let f = fonts();
        let i = DeviceInfo { os_version: Some("PixelOS_thyme-17.0-20261125-1008".into()), ..info() };
        let mut app = App::new(Screen::Update, 1080, 2340, 440.0 / 160.0);
        app.state.update_server = true;
        app.state.wlan = Some(connected("Skyward"));
        let mut packages = vec![UpdatePackage {
            kind: PackageKind::Official,
            channel: String::new(),
            release: Release {
                version: "OS1.0.4.0.TGACNXM".into(),
                name: "miui_THYME_OS1.0.4.0.TGACNXM_80dbab1cd4_13.0.zip".into(),
                urls: vec!["https://cdnorg.d.miui.com/a.zip".into()],
                md5: "80dbab1cd4".into(),
                size: String::new(),
                length: Some(4_155_617_504),
            },
            have: Have::Nothing,
        }];
        for k in 0..10 {
            packages.push(UpdatePackage {
                kind: PackageKind::Rom,
                channel: "sixteen / qpr2 / PixelOS / 20260625".into(),
                release: Release {
                    version: format!("PixelOS_thyme-16.2-2026062{k}-1725"),
                    name: format!("PixelOS_thyme-16.2-2026062{k}-1725.zip"),
                    urls: vec!["https://sourceforge.net/projects/flickerdev/files/a.zip/download".into()],
                    md5: "f6b3e3cb34a5048166a3ac9dc2e25105".into(),
                    size: String::new(),
                    length: Some(2_611_868_200),
                },
                have: Have::Nothing,
            });
        }
        for k in 0..2 {
            packages.push(UpdatePackage {
                kind: PackageKind::Firmware,
                channel: String::new(),
                release: Release {
                    version: format!("fw_thyme_miui_THYME_OS1.0.{k}.0.TGACNXM_80dbab1cd4_13.0"),
                    name: format!("fw_thyme_miui_THYME_OS1.0.{k}.0.TGACNXM_80dbab1cd4_13.0.zip"),
                    urls: vec!["https://sourceforge.net/projects/flickerdev/files/fw.zip/download".into()],
                    md5: "40b214ab288395ed0823c3ce9d085268".into(),
                    size: String::new(),
                    length: Some(152_005_860),
                },
                have: Have::Nothing,
            });
        }
        app.catalog_checked(Ok(UpdateCatalog { packages, warning: None }));
        let mut screen = Canvas::new(1080, 2340);
        app.compose(&mut screen, &f, &i, "08:40", 0);
        // Scroll the bottom refresh row into view and tap it while row press tracking is active.
        let mut now = 100u64;
        for _ in 0..8 {
            app.touch(Touch::Down(540.0, 1800.0), &f, now);
            for step in 1..=6 {
                now += 16;
                app.touch(Touch::Move(540.0, 1800.0 - step as f32 * 200.0), &f, now);
                app.tick(now);
                app.compose(&mut screen, &f, &i, "08:40", now);
            }
            now += 16;
            app.touch(Touch::Up, &f, now);
            for _ in 0..30 {
                now += 16;
                app.tick(now);
                app.compose(&mut screen, &f, &i, "08:40", now);
            }
        }
        for _ in 0..5 {
            now += 2000;
            app.tick(now);
            app.compose(&mut screen, &f, &i, "08:40", now);
        }
        let (x, y) = spot(&mut app, &f, &i, Action::CheckUpdate);
        app.touch(Touch::Down(x, y), &f, now + 100);
        for dt in 1..=8 {
            app.tick(now + 100 + dt * 20);
            app.compose(&mut screen, &f, &i, "08:40", now + 100 + dt * 20);
        }
        let fx = app.touch(Touch::Up, &f, now + 280);
        assert_eq!(fx, vec![Effect::CheckUpdate]);
        app.compose(&mut screen, &f, &i, "08:40", now + 300);
    }
}
