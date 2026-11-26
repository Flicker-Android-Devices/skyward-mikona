//! Persisting the running Skyward recovery into the device's `vendor_boot`
//! partition(s) from the Advanced page.

use super::*;

/// Persisting the running Skyward recovery, as its page shows it: reading and
/// merging target `vendor_boot`, writing and verifying, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistJob {
    pub stage: Option<PersistStage>,
    pub outcome: Option<PersistEnd>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistStage {
    Preparing,
    Writing { done: u64, total: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersistEnd {
    Installed(Vec<Slot>),
    NotWritten(String),
    WriteFailed(Vec<Slot>, String),
}

impl App {
    /// Persisting Skyward into `vendor_boot` has started.
    pub fn persist_started(&mut self) {
        self.state.persist_job = Some(PersistJob { stage: Some(PersistStage::Preparing), outcome: None });
        self.refresh();
    }

    /// How far persisting Skyward into `vendor_boot` has come.
    pub fn persist_progress(&mut self, stage: PersistStage) {
        let job = self.state.persist_job.as_mut().expect("only persistence under way moves on");
        job.stage = Some(stage);
        if self.screen() == Screen::InstallSkyward {
            self.refresh();
        }
    }

    /// Persisting Skyward into `vendor_boot` has ended.
    pub fn persist_ended(&mut self, end: PersistEnd, now: u64) {
        let job = self.state.persist_job.as_mut().expect("only persistence under way ends");
        job.outcome = Some(end);
        self.wake(now);
        self.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testing::*;

    #[test]
    fn install_skyward_to_vendor_boot_is_offered_on_vendor_boot_devices_and_runs_to_completion() {
        let (f, i) = (fonts(), info());
        let mut app = App::new(Screen::Advanced, W, H, PPD);
        app.refresh();
        assert!(!app.frame(&f, &i).hits.iter().any(|h| h.action == Action::Open(Screen::InstallSkyward)));

        app.state.persist_vendor_boot = true;
        app.refresh();
        assert!(app.frame(&f, &i).hits.iter().any(|h| h.action == Action::Open(Screen::InstallSkyward)));

        tap(&mut app, &f, &i, Action::Open(Screen::InstallSkyward));
        assert_eq!(app.screen(), Screen::InstallSkyward);
        assert_eq!(app.state.persist_pick, Pick::Current);

        tap(&mut app, &f, &i, Action::PersistSlots(Pick::Both));
        assert_eq!(app.state.persist_pick, Pick::Both);

        app.state.install = Install::Waiting;
        assert!(swipe(&mut app, &f, &i, Confirm::InstallSkyward).is_empty(), "blocked while installer is busy");
        app.state.install = Install::Idle;
        assert_eq!(swipe(&mut app, &f, &i, Confirm::InstallSkyward), vec![Effect::PersistSkyward(Pick::Both)]);

        app.persist_started();
        assert!(!app.frame(&f, &i).back, "no going back while writing vendor_boot");
        app.key(Key::Back, 0);
        assert_eq!(app.screen(), Screen::InstallSkyward);

        app.persist_progress(PersistStage::Writing { done: 1 << 20, total: 4 << 20 });
        app.persist_ended(PersistEnd::Installed(vec![Slot::A, Slot::B]), 1000);
        assert!(app.frame(&f, &i).back);
        assert_eq!(tap_at(&mut app, &f, &i, Action::RebootTo(Target::Recovery), 2000), vec![Effect::Reboot(Target::Recovery)]);

        tap_at(&mut app, &f, &i, Action::Back, 3000);
        assert_eq!(app.screen(), Screen::Advanced);
        assert_eq!(app.state.persist_job, None);
        assert_eq!(app.state.persist_pick, Pick::Current);
    }
}
