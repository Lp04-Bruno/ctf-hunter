use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use notify_rust::Notification;

pub const DEFAULT_NOTIFICATION_QUEUE_CAPACITY: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingNotification {
    pub session: String,
    pub value: String,
}

#[derive(Default)]
struct Counters {
    depth: AtomicUsize,
    delivered: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
}

#[derive(Clone)]
pub struct NotificationControl {
    sender: SyncSender<FindingNotification>,
    counters: Arc<Counters>,
    capacity: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotificationMetrics {
    pub capacity: usize,
    pub depth: usize,
    pub delivered: u64,
    pub dropped: u64,
    pub errors: u64,
}

impl NotificationControl {
    pub fn try_send(&self, message: FindingNotification) {
        self.counters.depth.fetch_add(1, Ordering::Relaxed);
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.sender.try_send(message)
        {
            self.counters.depth.fetch_sub(1, Ordering::Relaxed);
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn metrics(&self) -> NotificationMetrics {
        NotificationMetrics {
            capacity: self.capacity,
            depth: self.counters.depth.load(Ordering::Relaxed),
            delivered: self.counters.delivered.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            errors: self.counters.errors.load(Ordering::Relaxed),
        }
    }
}

pub struct NotificationDispatcher {
    control: NotificationControl,
    worker: JoinHandle<()>,
}

impl NotificationDispatcher {
    pub fn start(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<FindingNotification>(capacity);
        let counters = Arc::new(Counters::default());
        let worker_counters = Arc::clone(&counters);
        let worker = thread::spawn(move || {
            while let Ok(message) = receiver.recv() {
                worker_counters.depth.fetch_sub(1, Ordering::Relaxed);
                let body = format!(
                    "{}\nSession: {}",
                    escape_markup(&message.value),
                    escape_markup(&message.session)
                );
                let shown = Notification::new()
                    .appname("CTF Hunter")
                    .summary("Flag candidate found")
                    .body(&body)
                    .icon("dialog-information")
                    .timeout(Duration::from_secs(8))
                    .show();
                if shown.is_ok() {
                    worker_counters.delivered.fetch_add(1, Ordering::Relaxed);
                } else {
                    worker_counters.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        Self {
            control: NotificationControl {
                sender,
                counters,
                capacity,
            },
            worker,
        }
    }

    #[must_use]
    pub fn control(&self) -> NotificationControl {
        self.control.clone()
    }

    pub fn shutdown(self) {
        drop(self.control);
        let _ = self.worker.join();
    }
}

fn escape_markup(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_markup_is_escaped() {
        assert_eq!(escape_markup("FLAG{<a&b>}"), "FLAG{&lt;a&amp;b&gt;}");
    }

    #[test]
    fn queue_submission_never_waits_for_desktop_delivery() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let control = NotificationControl {
            sender,
            counters: Arc::new(Counters::default()),
            capacity: 1,
        };
        let message = FindingNotification {
            session: "test".to_owned(),
            value: "FLAG{test}".to_owned(),
        };
        control.try_send(message.clone());
        let start = std::time::Instant::now();
        control.try_send(message);
        assert!(start.elapsed() < Duration::from_millis(25));
        assert_eq!(control.metrics().dropped, 1);
    }
}
