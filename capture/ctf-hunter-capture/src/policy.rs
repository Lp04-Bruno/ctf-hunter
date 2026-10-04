use std::collections::HashSet;

use ctf_hunter_common::JobKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Capture,
    UnselectedTty,
    BackgroundJob,
    InitialJob,
    ReadTainted,
    FailClosed,
}

#[derive(Debug)]
pub struct PrivacyPolicy {
    selected_devices: HashSet<u32>,
    initialized_ttys: HashSet<u64>,
    tainted_jobs: HashSet<(u64, u64)>,
    taint_capacity: usize,
    failed: bool,
}

impl PrivacyPolicy {
    #[must_use]
    pub fn new(selected_devices: impl IntoIterator<Item = u32>, taint_capacity: usize) -> Self {
        Self {
            selected_devices: selected_devices.into_iter().collect(),
            initialized_ttys: HashSet::new(),
            tainted_jobs: HashSet::new(),
            taint_capacity,
            failed: false,
        }
    }

    pub fn observe_read(&mut self, device: u32, key: JobKey) {
        if self.failed || !self.selected_devices.contains(&device) {
            return;
        }
        self.taint(key);
    }

    pub fn evaluate_write(
        &mut self,
        device: u32,
        key: JobKey,
        foreground_group: u64,
    ) -> PolicyDecision {
        if self.failed {
            return PolicyDecision::FailClosed;
        }
        if !self.selected_devices.contains(&device) {
            return PolicyDecision::UnselectedTty;
        }
        if key.process_group != foreground_group {
            return PolicyDecision::BackgroundJob;
        }
        if self.initialized_ttys.insert(key.tty) {
            self.taint(key);
            return if self.failed {
                PolicyDecision::FailClosed
            } else {
                PolicyDecision::InitialJob
            };
        }
        if self.tainted_jobs.contains(&(key.tty, key.process_group)) {
            PolicyDecision::ReadTainted
        } else {
            PolicyDecision::Capture
        }
    }

    fn taint(&mut self, key: JobKey) {
        let value = (key.tty, key.process_group);
        if self.tainted_jobs.contains(&value) {
            return;
        }
        if self.tainted_jobs.len() >= self.taint_capacity {
            self.failed = true;
            return;
        }
        self.tainted_jobs.insert(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: u32 = 17;
    const TTY: u64 = 0x1000;

    fn job(process_group: u64) -> JobKey {
        JobKey {
            tty: TTY,
            process_group,
        }
    }

    fn initialized_policy() -> PrivacyPolicy {
        let mut policy = PrivacyPolicy::new([DEVICE], 8);
        assert_eq!(
            policy.evaluate_write(DEVICE, job(10), 10),
            PolicyDecision::InitialJob
        );
        policy
    }

    #[test]
    fn suppresses_the_preexisting_foreground_job() {
        let mut policy = PrivacyPolicy::new([DEVICE], 8);
        assert_eq!(
            policy.evaluate_write(DEVICE, job(10), 10),
            PolicyDecision::InitialJob
        );
        assert_eq!(
            policy.evaluate_write(DEVICE, job(10), 10),
            PolicyDecision::ReadTainted
        );
    }

    #[test]
    fn captures_a_new_foreground_job_that_never_reads() {
        let mut policy = initialized_policy();
        assert_eq!(
            policy.evaluate_write(DEVICE, job(20), 20),
            PolicyDecision::Capture
        );
    }

    #[test]
    fn a_read_taints_the_entire_process_group_before_output() {
        let mut policy = initialized_policy();
        policy.observe_read(DEVICE, job(20));
        assert_eq!(
            policy.evaluate_write(DEVICE, job(20), 20),
            PolicyDecision::ReadTainted
        );
    }

    #[test]
    fn rejects_background_and_unselected_writers() {
        let mut policy = initialized_policy();
        assert_eq!(
            policy.evaluate_write(DEVICE, job(20), 30),
            PolicyDecision::BackgroundJob
        );
        assert_eq!(
            policy.evaluate_write(99, job(20), 20),
            PolicyDecision::UnselectedTty
        );
    }

    #[test]
    fn map_saturation_permanently_fails_closed() {
        let mut policy = PrivacyPolicy::new([DEVICE], 1);
        assert_eq!(
            policy.evaluate_write(DEVICE, job(10), 10),
            PolicyDecision::InitialJob
        );
        policy.observe_read(DEVICE, job(20));
        assert_eq!(
            policy.evaluate_write(DEVICE, job(30), 30),
            PolicyDecision::FailClosed
        );
    }

    #[test]
    fn taint_is_scoped_to_a_tty_and_process_group_pair() {
        let mut policy = initialized_policy();
        policy.observe_read(DEVICE, job(20));
        assert_eq!(
            policy.evaluate_write(DEVICE, job(21), 21),
            PolicyDecision::Capture
        );
    }
}
