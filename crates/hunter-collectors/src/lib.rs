use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, Read as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use hunter_types::{MAX_EVENT_PAYLOAD_BYTES, SessionId};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};
use thiserror::Error;

pub const DEFAULT_MAX_FILE_BYTES: usize = MAX_EVENT_PAYLOAD_BYTES;
pub const DEFAULT_MAX_READ_BYTES_PER_SECOND: u64 = 4 * 1024 * 1024;
pub const DEFAULT_MAX_REGISTRATIONS: usize = 256;
pub const DEFAULT_MAX_TRACKED_PATHS: usize = 2_048;
pub const DEFAULT_COMMAND_CAPACITY: usize = 64;
pub const DEFAULT_SETTLE_DELAY: Duration = Duration::from_millis(100);
pub const DEFAULT_DEDUPLICATION_WINDOW: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const EVENT_BUFFER_BYTES: usize = 16 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct FileCollectorConfig {
    pub max_file_bytes: usize,
    pub max_read_bytes_per_second: u64,
    pub max_registrations: usize,
    pub max_tracked_paths: usize,
    pub command_capacity: usize,
    pub settle_delay: Duration,
    pub deduplication_window: Duration,
}

impl Default for FileCollectorConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_read_bytes_per_second: DEFAULT_MAX_READ_BYTES_PER_SECOND,
            max_registrations: DEFAULT_MAX_REGISTRATIONS,
            max_tracked_paths: DEFAULT_MAX_TRACKED_PATHS,
            command_capacity: DEFAULT_COMMAND_CAPACITY,
            settle_delay: DEFAULT_SETTLE_DELAY,
            deduplication_window: DEFAULT_DEDUPLICATION_WINDOW,
        }
    }
}

impl FileCollectorConfig {
    pub fn validate(&self) -> Result<(), FileCollectorError> {
        if self.max_file_bytes == 0 || self.max_file_bytes > MAX_EVENT_PAYLOAD_BYTES {
            return Err(FileCollectorError::InvalidConfiguration(
                "max file bytes must be between 1 and the event payload limit",
            ));
        }
        if self.max_read_bytes_per_second == 0
            || self.max_registrations == 0
            || self.max_tracked_paths == 0
            || self.command_capacity == 0
        {
            return Err(FileCollectorError::InvalidConfiguration(
                "collector limits must be greater than zero",
            ));
        }
        if self.max_read_bytes_per_second < self.max_file_bytes as u64 {
            return Err(FileCollectorError::InvalidConfiguration(
                "read-rate limit must allow one maximum-sized file per second",
            ));
        }
        if self.settle_delay.is_zero() || self.deduplication_window.is_zero() {
            return Err(FileCollectorError::InvalidConfiguration(
                "collector timing windows must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WatchRegistration {
    pub session_id: SessionId,
    pub directory: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectedFile {
    pub session_id: SessionId,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CollectorAction {
    Register(WatchRegistration),
    Unregister(WatchRegistration),
    SetSessionActive { session_id: SessionId, active: bool },
}

struct CollectorCommand {
    action: CollectorAction,
    acknowledgement: SyncSender<Result<(), String>>,
}

#[derive(Clone)]
pub struct FileCollectorControl {
    commands: SyncSender<CollectorCommand>,
}

impl FileCollectorControl {
    pub fn register(&self, registration: WatchRegistration) -> Result<(), CollectorControlError> {
        self.execute(CollectorAction::Register(registration))
    }

    pub fn unregister(&self, registration: WatchRegistration) -> Result<(), CollectorControlError> {
        self.execute(CollectorAction::Unregister(registration))
    }

    pub fn set_session_active(
        &self,
        session_id: SessionId,
        active: bool,
    ) -> Result<(), CollectorControlError> {
        self.execute(CollectorAction::SetSessionActive { session_id, active })
    }

    fn execute(&self, action: CollectorAction) -> Result<(), CollectorControlError> {
        let (acknowledgement, result) = mpsc::sync_channel(1);
        let command = CollectorCommand {
            action,
            acknowledgement,
        };
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(CollectorControlError::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(CollectorControlError::Stopped),
        }
        result
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|_| CollectorControlError::TimedOut)?
            .map_err(CollectorControlError::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileCollectorStatistics {
    pub events_received: u64,
    pub files_read: u64,
    pub duplicate_events: u64,
    pub oversized_files: u64,
    pub rate_limited_files: u64,
    pub dropped_events: u64,
    pub read_errors: u64,
    pub queue_overflows: u64,
    pub invalidated_watches: u64,
}

#[derive(Default)]
struct Statistics {
    events_received: AtomicU64,
    files_read: AtomicU64,
    duplicate_events: AtomicU64,
    oversized_files: AtomicU64,
    rate_limited_files: AtomicU64,
    dropped_events: AtomicU64,
    read_errors: AtomicU64,
    queue_overflows: AtomicU64,
    invalidated_watches: AtomicU64,
}

impl Statistics {
    fn snapshot(&self) -> FileCollectorStatistics {
        FileCollectorStatistics {
            events_received: self.events_received.load(Ordering::Relaxed),
            files_read: self.files_read.load(Ordering::Relaxed),
            duplicate_events: self.duplicate_events.load(Ordering::Relaxed),
            oversized_files: self.oversized_files.load(Ordering::Relaxed),
            rate_limited_files: self.rate_limited_files.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            queue_overflows: self.queue_overflows.load(Ordering::Relaxed),
            invalidated_watches: self.invalidated_watches.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Error)]
pub enum FileCollectorError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid file collector configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("watch registration limit reached")]
    RegistrationLimit,
    #[error("watch path must be an absolute directory: {0}")]
    InvalidWatchPath(PathBuf),
    #[error("file collector thread panicked")]
    ThreadPanicked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CollectorControlError {
    #[error("file collector command queue is full")]
    Busy,
    #[error("file collector is stopped")]
    Stopped,
    #[error("file collector rejected the command: {0}")]
    Rejected(String),
    #[error("file collector command timed out")]
    TimedOut,
}

pub struct FileCollector {
    control: FileCollectorControl,
    metrics: FileCollectorMetrics,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), FileCollectorError>>>,
}

#[derive(Clone)]
pub struct FileCollectorMetrics(Arc<Statistics>);

impl FileCollectorMetrics {
    #[must_use]
    pub fn snapshot(&self) -> FileCollectorStatistics {
        self.0.snapshot()
    }
}

impl FileCollector {
    pub fn start<F>(
        config: FileCollectorConfig,
        registrations: impl IntoIterator<Item = WatchRegistration>,
        active_sessions: impl IntoIterator<Item = SessionId>,
        sink: F,
    ) -> Result<Self, FileCollectorError>
    where
        F: FnMut(CollectedFile) -> bool + Send + 'static,
    {
        config.validate()?;
        let mut runtime = Runtime::new(config.clone(), sink)?;
        for registration in registrations {
            runtime.register(registration)?;
        }
        runtime.active_sessions.extend(active_sessions);

        let (commands, receiver) = mpsc::sync_channel(config.command_capacity);
        let metrics = FileCollectorMetrics(Arc::clone(&runtime.statistics));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || runtime.run(receiver, worker_stopping));
        Ok(Self {
            control: FileCollectorControl { commands },
            metrics,
            stopping,
            thread: Some(thread),
        })
    }

    #[must_use]
    pub fn control(&self) -> FileCollectorControl {
        self.control.clone()
    }

    #[must_use]
    pub fn statistics(&self) -> FileCollectorStatistics {
        self.metrics.snapshot()
    }

    #[must_use]
    pub fn metrics(&self) -> FileCollectorMetrics {
        self.metrics.clone()
    }

    pub fn shutdown(mut self) -> Result<FileCollectorStatistics, FileCollectorError> {
        self.stopping.store(true, Ordering::Relaxed);
        let result = self
            .thread
            .take()
            .expect("collector thread is present")
            .join()
            .map_err(|_| FileCollectorError::ThreadPanicked)?;
        result?;
        Ok(self.metrics.snapshot())
    }
}

impl Drop for FileCollector {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
    }
}

struct Runtime<F> {
    config: FileCollectorConfig,
    inotify: Inotify,
    registrations: HashMap<PathBuf, HashSet<SessionId>>,
    watch_by_path: HashMap<PathBuf, WatchDescriptor>,
    path_by_watch: HashMap<WatchDescriptor, PathBuf>,
    active_sessions: HashSet<SessionId>,
    pending: HashMap<PathBuf, Instant>,
    open_paths: HashMap<PathBuf, usize>,
    fingerprints: HashMap<PathBuf, ([u8; 32], Instant)>,
    rate_limiter: RateLimiter,
    statistics: Arc<Statistics>,
    sink: F,
}

impl<F> Runtime<F>
where
    F: FnMut(CollectedFile) -> bool,
{
    fn new(config: FileCollectorConfig, sink: F) -> Result<Self, FileCollectorError> {
        Ok(Self {
            rate_limiter: RateLimiter::new(config.max_read_bytes_per_second),
            config,
            inotify: Inotify::init()?,
            registrations: HashMap::new(),
            watch_by_path: HashMap::new(),
            path_by_watch: HashMap::new(),
            active_sessions: HashSet::new(),
            pending: HashMap::new(),
            open_paths: HashMap::new(),
            fingerprints: HashMap::new(),
            statistics: Arc::new(Statistics::default()),
            sink,
        })
    }

    fn run(
        &mut self,
        commands: Receiver<CollectorCommand>,
        stopping: Arc<AtomicBool>,
    ) -> Result<(), FileCollectorError> {
        let mut buffer = vec![0_u8; EVENT_BUFFER_BYTES];
        while !stopping.load(Ordering::Relaxed) {
            self.process_commands(&commands);
            self.process_events(&mut buffer)?;
            self.process_pending();
            thread::sleep(POLL_INTERVAL);
        }
        Ok(())
    }

    fn process_commands(&mut self, commands: &Receiver<CollectorCommand>) {
        loop {
            match commands.try_recv() {
                Ok(command) => {
                    let result = match command.action {
                        CollectorAction::Register(registration) => self.register(registration),
                        CollectorAction::Unregister(registration) => self.unregister(&registration),
                        CollectorAction::SetSessionActive { session_id, active } => {
                            if active {
                                self.active_sessions.insert(session_id);
                            } else {
                                self.active_sessions.remove(&session_id);
                            }
                            Ok(())
                        }
                    }
                    .map_err(|error| error.to_string());
                    let _ = command.acknowledgement.try_send(result);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    fn register(&mut self, registration: WatchRegistration) -> Result<(), FileCollectorError> {
        if !is_watch_directory(&registration.directory) {
            return Err(FileCollectorError::InvalidWatchPath(registration.directory));
        }
        let registration_count: usize = self.registrations.values().map(HashSet::len).sum();
        let is_new = !self
            .registrations
            .get(&registration.directory)
            .is_some_and(|sessions| sessions.contains(&registration.session_id));
        if is_new && registration_count >= self.config.max_registrations {
            return Err(FileCollectorError::RegistrationLimit);
        }
        if !self.watch_by_path.contains_key(&registration.directory) {
            let descriptor = self.inotify.watches().add(
                &registration.directory,
                WatchMask::CREATE
                    | WatchMask::MODIFY
                    | WatchMask::OPEN
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::CLOSE_NOWRITE
                    | WatchMask::MOVED_FROM
                    | WatchMask::MOVED_TO
                    | WatchMask::DELETE
                    | WatchMask::DELETE_SELF
                    | WatchMask::MOVE_SELF
                    | WatchMask::ONLYDIR
                    | WatchMask::DONT_FOLLOW
                    | WatchMask::EXCL_UNLINK,
            )?;
            self.path_by_watch
                .insert(descriptor.clone(), registration.directory.clone());
            self.watch_by_path
                .insert(registration.directory.clone(), descriptor);
        }
        self.registrations
            .entry(registration.directory)
            .or_default()
            .insert(registration.session_id);
        Ok(())
    }

    fn unregister(&mut self, registration: &WatchRegistration) -> Result<(), FileCollectorError> {
        let remove_watch =
            if let Some(sessions) = self.registrations.get_mut(&registration.directory) {
                sessions.remove(&registration.session_id);
                sessions.is_empty()
            } else {
                false
            };
        if remove_watch {
            self.registrations.remove(&registration.directory);
            if let Some(descriptor) = self.watch_by_path.remove(&registration.directory) {
                self.path_by_watch.remove(&descriptor);
                let _ = self.inotify.watches().remove(descriptor);
            }
            self.pending
                .retain(|path, _| path.parent() != Some(registration.directory.as_path()));
            self.open_paths
                .retain(|path, _| path.parent() != Some(registration.directory.as_path()));
            self.fingerprints
                .retain(|path, _| path.parent() != Some(registration.directory.as_path()));
        }
        Ok(())
    }

    fn process_events(&mut self, buffer: &mut [u8]) -> Result<(), FileCollectorError> {
        let events = match self.inotify.read_events(buffer) {
            Ok(events) => events
                .map(|event| {
                    (
                        event.wd.clone(),
                        event.mask,
                        event.name.map(std::ffi::OsStr::to_os_string),
                    )
                })
                .collect::<Vec<_>>(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for (descriptor, mask, name) in events {
            self.statistics
                .events_received
                .fetch_add(1, Ordering::Relaxed);
            if mask.contains(EventMask::Q_OVERFLOW) {
                self.statistics
                    .queue_overflows
                    .fetch_add(1, Ordering::Relaxed);
                self.schedule_rescan();
                continue;
            }
            if mask.contains(EventMask::IGNORED) {
                if let Some(directory) = self.path_by_watch.remove(&descriptor) {
                    self.watch_by_path.remove(&directory);
                }
                continue;
            }
            if mask.intersects(EventMask::DELETE_SELF | EventMask::MOVE_SELF | EventMask::UNMOUNT) {
                self.invalidate_watch(&descriptor);
                continue;
            }
            if mask.contains(EventMask::ISDIR) {
                continue;
            }
            let (Some(directory), Some(name)) = (self.path_by_watch.get(&descriptor), name) else {
                continue;
            };
            let path = directory.join(name);
            if mask.intersects(EventMask::DELETE | EventMask::MOVED_FROM) {
                self.pending.remove(&path);
                self.open_paths.remove(&path);
                self.fingerprints.remove(&path);
                continue;
            }
            if mask.contains(EventMask::OPEN) {
                if let Some(open_count) = self.open_paths.get_mut(&path) {
                    *open_count = open_count.saturating_add(1);
                } else if self.open_paths.len() < self.config.max_tracked_paths {
                    self.open_paths.insert(path, 1);
                } else {
                    self.statistics
                        .dropped_events
                        .fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
            if mask.intersects(EventMask::CLOSE_WRITE | EventMask::CLOSE_NOWRITE) {
                if let Some(open_count) = self.open_paths.get_mut(&path) {
                    *open_count = open_count.saturating_sub(1);
                    if *open_count == 0 {
                        self.open_paths.remove(&path);
                    }
                }
                if mask.contains(EventMask::CLOSE_WRITE) {
                    self.schedule(path, Instant::now());
                }
                continue;
            }
            if mask.intersects(EventMask::CREATE | EventMask::MODIFY | EventMask::MOVED_TO) {
                self.schedule(path, Instant::now() + self.config.settle_delay);
            }
        }
        Ok(())
    }

    fn invalidate_watch(&mut self, descriptor: &WatchDescriptor) {
        if let Some(directory) = self.path_by_watch.remove(descriptor) {
            self.watch_by_path.remove(&directory);
            self.pending
                .retain(|path, _| path.parent() != Some(directory.as_path()));
            self.open_paths
                .retain(|path, _| path.parent() != Some(directory.as_path()));
            self.fingerprints
                .retain(|path, _| path.parent() != Some(directory.as_path()));
            self.statistics
                .invalidated_watches
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn schedule(&mut self, path: PathBuf, due: Instant) {
        if self.pending.contains_key(&path) || self.pending.len() < self.config.max_tracked_paths {
            self.pending.insert(path, due);
        } else {
            self.statistics
                .dropped_events
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn schedule_rescan(&mut self) {
        let directories = self.registrations.keys().cloned().collect::<Vec<_>>();
        for directory in directories {
            let entries = match directory.read_dir() {
                Ok(entries) => entries,
                Err(_) => {
                    self.statistics.read_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            for entry in entries.flatten() {
                self.schedule(entry.path(), Instant::now() + self.config.settle_delay);
                if self.pending.len() >= self.config.max_tracked_paths {
                    break;
                }
            }
        }
    }

    fn process_pending(&mut self) {
        let now = Instant::now();
        let ready = self
            .pending
            .iter()
            .filter_map(|(path, due)| (*due <= now).then_some(path.clone()))
            .collect::<Vec<_>>();
        for path in ready {
            if self.open_paths.contains_key(&path) {
                self.pending.insert(path, now + self.config.settle_delay);
                continue;
            }
            self.pending.remove(&path);
            self.process_file(path, now);
        }
        if self.fingerprints.len() > self.config.max_tracked_paths {
            self.fingerprints.retain(|_, (_, observed)| {
                now.duration_since(*observed) <= self.config.deduplication_window
            });
        }
    }

    fn process_file(&mut self, path: PathBuf, now: Instant) {
        let Some(directory) = path.parent() else {
            return;
        };
        let sessions = self
            .registrations
            .get(directory)
            .into_iter()
            .flatten()
            .filter(|session| self.active_sessions.contains(session))
            .copied()
            .collect::<Vec<_>>();
        if sessions.is_empty() {
            return;
        }
        let outcome = read_regular_file(
            &path,
            self.config.max_file_bytes,
            &mut self.rate_limiter,
            now,
        );
        let bytes = match outcome {
            ReadOutcome::Data(bytes) => bytes,
            ReadOutcome::EmptyOrNotRegular => return,
            ReadOutcome::Oversized => {
                self.statistics
                    .oversized_files
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            ReadOutcome::RateLimited(retry_at) => {
                self.statistics
                    .rate_limited_files
                    .fetch_add(1, Ordering::Relaxed);
                self.schedule(path, retry_at);
                return;
            }
            ReadOutcome::Error => {
                self.statistics.read_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let fingerprint = *blake3::hash(&bytes).as_bytes();
        if self.fingerprints.get(&path).is_some_and(|(previous, at)| {
            *previous == fingerprint && now.duration_since(*at) <= self.config.deduplication_window
        }) {
            self.statistics
                .duplicate_events
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.fingerprints.len() >= self.config.max_tracked_paths
            && !self.fingerprints.contains_key(&path)
            && let Some(oldest) = self
                .fingerprints
                .iter()
                .min_by_key(|(_, (_, observed))| *observed)
                .map(|(path, _)| path.clone())
        {
            self.fingerprints.remove(&oldest);
        }
        self.fingerprints.insert(path.clone(), (fingerprint, now));
        self.statistics.files_read.fetch_add(1, Ordering::Relaxed);
        for session_id in sessions {
            if !(self.sink)(CollectedFile {
                session_id,
                path: path.clone(),
                bytes: bytes.clone(),
            }) {
                self.statistics
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn is_watch_directory(path: &Path) -> bool {
    path.is_absolute()
        && fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

struct RateLimiter {
    max_bytes: u64,
    used_bytes: u64,
    window_started: Instant,
}

impl RateLimiter {
    fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
            window_started: Instant::now(),
        }
    }

    fn reserve(&mut self, bytes: u64, now: Instant) -> Result<(), Instant> {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.used_bytes = 0;
        }
        if bytes > self.max_bytes || self.used_bytes.saturating_add(bytes) > self.max_bytes {
            return Err(self.window_started + Duration::from_secs(1));
        }
        self.used_bytes += bytes;
        Ok(())
    }
}

enum ReadOutcome {
    Data(Vec<u8>),
    EmptyOrNotRegular,
    Oversized,
    RateLimited(Instant),
    Error,
}

fn read_regular_file(
    path: &Path,
    max_file_bytes: usize,
    rate_limiter: &mut RateLimiter,
    now: Instant,
) -> ReadOutcome {
    let descriptor = match open(
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(_) => return ReadOutcome::Error,
    };
    let mut file = File::from(descriptor);
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return ReadOutcome::Error,
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return ReadOutcome::EmptyOrNotRegular;
    }
    if metadata.len() > max_file_bytes as u64 {
        return ReadOutcome::Oversized;
    }
    if let Err(retry_at) = rate_limiter.reserve(metadata.len(), now) {
        return ReadOutcome::RateLimited(retry_at);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if file
        .by_ref()
        .take(max_file_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return ReadOutcome::Error;
    }
    if bytes.len() > max_file_bytes {
        ReadOutcome::Oversized
    } else if bytes.is_empty() {
        ReadOutcome::EmptyOrNotRegular
    } else {
        ReadOutcome::Data(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write as _,
        os::unix::fs::symlink,
        sync::mpsc,
        time::{Duration, Instant},
    };

    use tempfile::tempdir;

    use super::*;

    fn config() -> FileCollectorConfig {
        FileCollectorConfig {
            settle_delay: Duration::from_millis(20),
            deduplication_window: Duration::from_millis(250),
            ..FileCollectorConfig::default()
        }
    }

    fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        predicate()
    }

    #[test]
    fn rejects_invalid_limits() {
        let invalid = FileCollectorConfig {
            max_file_bytes: 0,
            ..FileCollectorConfig::default()
        };
        assert!(matches!(
            invalid.validate(),
            Err(FileCollectorError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn rejects_a_symbolic_link_as_the_watch_root() {
        let parent = tempdir().expect("parent");
        let target = parent.path().join("target");
        let linked = parent.path().join("linked");
        fs::create_dir(&target).expect("target");
        symlink(target, &linked).expect("symlink");
        let error = match FileCollector::start(
            config(),
            [WatchRegistration {
                session_id: SessionId::generate(),
                directory: linked.clone(),
            }],
            [],
            |_| true,
        ) {
            Ok(_) => panic!("symbolic link watch root was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            FileCollectorError::InvalidWatchPath(path) if path == linked
        ));
    }

    #[test]
    fn collects_regular_files_by_bytes_and_deduplicates_kernel_events() {
        let directory = tempdir().expect("tempdir");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: directory.path().to_path_buf(),
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector =
            FileCollector::start(config(), [registration], [session_id], move |event| {
                sender.try_send(event).is_ok()
            })
            .expect("collector");

        let path = directory.path().join("payload.unknown");
        fs::write(&path, b"RkxBR3tmaWxlfQ==").expect("write");
        let event = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("file event");
        assert_eq!(event.session_id, session_id);
        assert_eq!(event.path, path);
        assert_eq!(event.bytes, b"RkxBR3tmaWxlfQ==");
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());

        let statistics = collector.shutdown().expect("shutdown");
        assert_eq!(statistics.files_read, 1);
        assert!(statistics.events_received >= 1);
    }

    #[test]
    fn collects_files_moved_into_a_watched_directory() {
        let watched = tempdir().expect("watched");
        let staging = tempdir().expect("staging");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: watched.path().to_path_buf(),
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector =
            FileCollector::start(config(), [registration], [session_id], move |event| {
                sender.try_send(event).is_ok()
            })
            .expect("collector");

        let source = staging.path().join("response.bin");
        let destination = watched.path().join("response.bin");
        fs::write(&source, b"FLAG{renamed}").expect("write");
        fs::rename(source, &destination).expect("rename");
        let event = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("file event");
        assert_eq!(event.path, destination);
        assert_eq!(event.bytes, b"FLAG{renamed}");
        collector.shutdown().expect("shutdown");
    }

    #[test]
    fn waits_for_partial_writes_to_close() {
        let directory = tempdir().expect("tempdir");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: directory.path().to_path_buf(),
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector =
            FileCollector::start(config(), [registration], [session_id], move |event| {
                sender.try_send(event).is_ok()
            })
            .expect("collector");

        let path = directory.path().join("partial.dat");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("open");
        file.write_all(b"RkxBR3twYXJ0").expect("first write");
        file.flush().expect("flush");
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
        file.write_all(b"aWFsfQ==").expect("second write");
        drop(file);

        let event = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("complete file event");
        assert_eq!(event.bytes, b"RkxBR3twYXJ0aWFsfQ==");
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
        collector.shutdown().expect("shutdown");
    }

    #[test]
    fn skips_oversized_files_and_inactive_sessions() {
        let directory = tempdir().expect("tempdir");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: directory.path().to_path_buf(),
        };
        let limited = FileCollectorConfig {
            max_file_bytes: 8,
            ..config()
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector = FileCollector::start(limited, [registration], [], move |event| {
            sender.try_send(event).is_ok()
        })
        .expect("collector");

        let path = directory.path().join("payload.bin");
        fs::write(&path, b"too large for this test").expect("write inactive");
        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
        collector
            .control()
            .set_session_active(session_id, true)
            .expect("activate");
        fs::write(&path, b"still too large").expect("write oversized");
        assert!(receiver.recv_timeout(Duration::from_millis(300)).is_err());

        let statistics = collector.shutdown().expect("shutdown");
        assert!(statistics.oversized_files >= 1);
    }

    #[test]
    fn rate_limits_reads_without_losing_the_deferred_file() {
        let directory = tempdir().expect("tempdir");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: directory.path().to_path_buf(),
        };
        let limited = FileCollectorConfig {
            max_file_bytes: 8,
            max_read_bytes_per_second: 8,
            ..config()
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector = FileCollector::start(limited, [registration], [session_id], move |event| {
            sender.try_send(event).is_ok()
        })
        .expect("collector");

        fs::write(directory.path().join("first.bin"), b"12345678").expect("first file");
        fs::write(directory.path().join("second.bin"), b"abcdefgh").expect("second file");
        let mut payloads = [
            receiver
                .recv_timeout(Duration::from_secs(3))
                .expect("first event")
                .bytes,
            receiver
                .recv_timeout(Duration::from_secs(3))
                .expect("deferred event")
                .bytes,
        ];
        payloads.sort();
        assert_eq!(payloads, [b"12345678".to_vec(), b"abcdefgh".to_vec()]);

        let statistics = collector.shutdown().expect("shutdown");
        assert!(statistics.rate_limited_files >= 1);
        assert_eq!(statistics.files_read, 2);
    }

    #[test]
    fn refuses_symbolic_links() {
        let directory = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        let target = outside.path().join("target.bin");
        fs::write(&target, b"FLAG{outside}").expect("target");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: directory.path().to_path_buf(),
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector =
            FileCollector::start(config(), [registration], [session_id], move |event| {
                sender.try_send(event).is_ok()
            })
            .expect("collector");

        symlink(target, directory.path().join("linked.bin")).expect("symlink");
        assert!(wait_until(Duration::from_secs(2), || {
            collector.statistics().read_errors >= 1
        }));
        assert!(receiver.try_recv().is_err());

        let statistics = collector.shutdown().expect("shutdown");
        assert_eq!(statistics.files_read, 0);
    }

    #[test]
    fn invalidates_a_watch_when_its_root_moves() {
        let parent = tempdir().expect("parent");
        let watched = parent.path().join("watched");
        let moved = parent.path().join("moved");
        fs::create_dir(&watched).expect("watched directory");
        let session_id = SessionId::generate();
        let registration = WatchRegistration {
            session_id,
            directory: watched.clone(),
        };
        let (sender, receiver) = mpsc::sync_channel(8);
        let collector =
            FileCollector::start(config(), [registration], [session_id], move |event| {
                sender.try_send(event).is_ok()
            })
            .expect("collector");

        fs::rename(&watched, moved).expect("move watched root");
        assert!(wait_until(Duration::from_secs(2), || {
            collector.statistics().invalidated_watches >= 1
        }));
        fs::create_dir(&watched).expect("replacement directory");
        fs::write(watched.join("payload.bin"), b"FLAG{replacement}").expect("replacement file");
        assert!(receiver.recv_timeout(Duration::from_millis(300)).is_err());

        let statistics = collector.shutdown().expect("shutdown");
        assert_eq!(statistics.invalidated_watches, 1);
        assert_eq!(statistics.files_read, 0);
    }
}
