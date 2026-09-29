mod notifications;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs, io,
    os::unix::{
        fs::FileTypeExt as _, fs::MetadataExt as _, fs::PermissionsExt as _, net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use hunter_capture_client::{
    CaptureClient, CaptureClientConfig, CaptureClientMetrics, CaptureClientStatistics,
    CaptureControlError, CaptureRegistration, CollectedTerminalOutput,
};
use hunter_collectors::{
    CollectedFile, CollectorControlError, FileCollector, FileCollectorConfig, FileCollectorMetrics,
    FileCollectorStatistics, WatchRegistration,
};
use hunter_core::{AnalysisConfig, Analyzer};
use hunter_database::Database;
use hunter_decoder::DecoderSet;
use hunter_flags::FlagPattern;
use hunter_ipc::{
    AnalysisPreview, AnalysisStatus, CaptureStatus, DaemonStatus, ErrorCode, FileCollectorStatus,
    FindingDetail, FindingOccurrence, FindingSummary, FrameError, IO_TIMEOUT, MAX_LIST_LIMIT,
    NotificationStatus, PROTOCOL_VERSION, PreviewDetection, PreviewFinding, PreviewStatistics,
    PreviewTransformation, Request, RequestEnvelope, Response, ResponseEnvelope,
    TransformationStep, read_frame, write_frame,
};
use hunter_types::{
    CaptureEvent, EventId, EventPayload, FileSource, NotificationSettings, Session, SessionId,
    SessionStatus, SourceMetadata, SourcePath, TerminalSource, Timestamp,
};
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::geteuid,
};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use thiserror::Error;

use notifications::{
    DEFAULT_NOTIFICATION_QUEUE_CAPACITY, FindingNotification, NotificationControl,
    NotificationDispatcher,
};

pub const DEFAULT_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_WORKER_COUNT: usize = 4;
pub const DEFAULT_WORK_BATCH_SIZE: usize = 16;
pub const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub const DEFAULT_CAPTURE_SOCKET: &str = "/run/ctf-hunter/capture.sock";
const MAX_PREVIEW_TRANSFORMATIONS: usize = 12;
const MAX_PREVIEW_FINDINGS: usize = 16;
const MAX_PREVIEW_TEXT_CHARS: usize = 2_048;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub database_path: PathBuf,
    pub socket_path: PathBuf,
    pub queue_capacity: usize,
    pub worker_count: usize,
    pub work_batch_size: usize,
    pub file_collector: FileCollectorConfig,
    pub capture_client: CaptureClientConfig,
}

impl DaemonConfig {
    #[must_use]
    pub fn new(database_path: impl Into<PathBuf>, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            database_path: database_path.into(),
            socket_path: socket_path.into(),
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            worker_count: DEFAULT_WORKER_COUNT,
            work_batch_size: DEFAULT_WORK_BATCH_SIZE,
            file_collector: FileCollectorConfig::default(),
            capture_client: CaptureClientConfig::new(DEFAULT_CAPTURE_SOCKET),
        }
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Database(#[from] hunter_database::DatabaseError),
    #[error(transparent)]
    FileCollector(#[from] hunter_collectors::FileCollectorError),
    #[error(transparent)]
    CaptureClient(#[from] hunter_capture_client::CaptureClientError),
    #[error("queue capacity must be greater than zero")]
    InvalidQueueCapacity,
    #[error("worker count must be greater than zero")]
    InvalidWorkerCount,
    #[error("work batch size must be greater than zero")]
    InvalidWorkBatchSize,
    #[error("runtime directory is not owned by the current user")]
    RuntimeDirectoryOwner,
    #[error("refusing to replace a non-socket path: {0}")]
    UnsafeSocketPath(PathBuf),
    #[error("another daemon is already listening on {0}")]
    AlreadyRunning(PathBuf),
    #[error("daemon worker stopped unexpectedly")]
    WorkerStopped,
    #[error("daemon worker panicked")]
    WorkerPanicked,
}

#[derive(Default)]
struct Statistics {
    queue_depth: AtomicUsize,
    accepted_connections: AtomicU64,
    rejected_connections: AtomicU64,
    completed_requests: AtomicU64,
    failed_requests: AtomicU64,
    analyzed_files: AtomicU64,
    file_analysis_errors: AtomicU64,
    analyzed_terminal_events: AtomicU64,
    terminal_analysis_errors: AtomicU64,
    analyzed_events: AtomicU64,
    extracted_candidates: AtomicU64,
    decoded_candidates: AtomicU64,
    findings_detected: AtomicU64,
    duplicate_events: AtomicU64,
}

impl Statistics {
    fn snapshot(
        &self,
        schema_version: usize,
        worker_count: usize,
        queue_capacity: usize,
        collector: FileCollectorStatistics,
        capture: CaptureClientStatistics,
        notifications: notifications::NotificationMetrics,
    ) -> DaemonStatus {
        DaemonStatus {
            schema_version,
            worker_count,
            queue_capacity,
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            completed_requests: self.completed_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            file_collector: FileCollectorStatus {
                events_received: collector.events_received,
                files_read: collector.files_read,
                duplicate_events: collector.duplicate_events,
                oversized_files: collector.oversized_files,
                rate_limited_files: collector.rate_limited_files,
                dropped_events: collector.dropped_events,
                read_errors: collector.read_errors,
                queue_overflows: collector.queue_overflows,
                invalidated_watches: collector.invalidated_watches,
                analyzed_files: self.analyzed_files.load(Ordering::Relaxed),
                analysis_errors: self.file_analysis_errors.load(Ordering::Relaxed),
            },
            capture: CaptureStatus {
                configured_sources: capture.configured_sources,
                active_sources: capture.active_sources,
                connected_sources: capture.connected_sources,
                connection_attempts: capture.connection_attempts,
                reconnects: capture.reconnects,
                events_received: capture.events_received,
                events_analyzed: self.analyzed_terminal_events.load(Ordering::Relaxed),
                analysis_errors: self.terminal_analysis_errors.load(Ordering::Relaxed),
                dropped_events: capture.dropped_events,
                protocol_errors: capture.protocol_errors,
                helper_errors: capture.helper_errors,
                ring_dropped: capture.ring_dropped,
                read_failed: capture.read_failed,
                fail_closed: capture.fail_closed,
            },
            analysis: AnalysisStatus {
                events_analyzed: self.analyzed_events.load(Ordering::Relaxed),
                candidates_extracted: self.extracted_candidates.load(Ordering::Relaxed),
                candidates_decoded: self.decoded_candidates.load(Ordering::Relaxed),
                findings_detected: self.findings_detected.load(Ordering::Relaxed),
                duplicate_events: self.duplicate_events.load(Ordering::Relaxed),
            },
            notifications: NotificationStatus {
                queue_capacity: notifications.capacity,
                queue_depth: notifications.depth,
                delivered: notifications.delivered,
                dropped: notifications.dropped,
                errors: notifications.errors,
            },
        }
    }
}

pub fn termination_flag() -> Result<Arc<AtomicBool>, io::Error> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&flag))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&flag))?;
    Ok(flag)
}

pub fn run(config: DaemonConfig, terminating: Arc<AtomicBool>) -> Result<(), DaemonError> {
    if config.queue_capacity == 0 {
        return Err(DaemonError::InvalidQueueCapacity);
    }
    if config.worker_count == 0 {
        return Err(DaemonError::InvalidWorkerCount);
    }
    if config.work_batch_size == 0 {
        return Err(DaemonError::InvalidWorkBatchSize);
    }
    let database_directory = config.database_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "database path has no parent")
    })?;
    secure_private_directory(database_directory)?;
    let database = Database::open(&config.database_path)?;
    let schema_version = database.schema_version()?;
    let stored_watches = database.all_watch_directories()?;
    let stored_terminals = database.all_terminals()?;
    let notification_settings = Arc::new(RwLock::new(database.notification_settings()?));
    fs::set_permissions(&config.database_path, fs::Permissions::from_mode(0o600))?;
    drop(database);
    let listener = bind_secure_socket(&config.socket_path)?;
    let _socket_guard = SocketGuard(config.socket_path.clone());
    listener.set_nonblocking(true)?;

    let statistics = Arc::new(Statistics::default());
    let notification_dispatcher =
        NotificationDispatcher::start(DEFAULT_NOTIFICATION_QUEUE_CAPACITY);
    let notification_control = notification_dispatcher.control();
    let recent_events = Arc::new(Mutex::new(RecentEvents::default()));
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
    let collector_sender = sender.clone();
    let collector_statistics = Arc::clone(&statistics);
    let registrations = stored_watches
        .iter()
        .filter(|watch| is_restorable_watch_directory(&watch.directory))
        .map(|watch| WatchRegistration {
            session_id: watch.session_id,
            directory: watch.directory.clone(),
        })
        .collect::<Vec<_>>();
    let active_sessions = stored_watches
        .iter()
        .filter(|watch| watch.active)
        .map(|watch| watch.session_id)
        .collect::<HashSet<_>>();
    let collector = FileCollector::start(
        config.file_collector.clone(),
        registrations,
        active_sessions,
        move |file| enqueue_file(&collector_sender, file, &collector_statistics),
    )?;
    let collector_control = collector.control();
    let collector_metrics = collector.metrics();
    let capture_registrations = stored_terminals
        .iter()
        .map(|terminal| CaptureRegistration {
            session_id: terminal.session_id,
            terminal: terminal.terminal.clone(),
        })
        .collect::<Vec<_>>();
    let capture_active_sessions = stored_terminals
        .iter()
        .filter(|terminal| terminal.active)
        .map(|terminal| terminal.session_id)
        .collect::<HashSet<_>>();
    let capture_sender = sender.clone();
    let capture_statistics = Arc::clone(&statistics);
    let capture = CaptureClient::start(
        config.capture_client.clone(),
        capture_registrations,
        capture_active_sessions,
        move |event| enqueue_terminal(&capture_sender, event, &capture_statistics),
    )?;
    let capture_control = capture.control();
    let capture_metrics = capture.metrics();
    let receiver = Arc::new(Mutex::new(receiver));
    let session_state_lock = Arc::new(Mutex::new(()));
    let queue_capacity = config.queue_capacity;
    let worker_count = config.worker_count;
    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let worker_database_path = config.database_path.clone();
        let context = WorkerContext {
            receiver: Arc::clone(&receiver),
            statistics: Arc::clone(&statistics),
            terminating: Arc::clone(&terminating),
            session_state_lock: Arc::clone(&session_state_lock),
            collector_control: collector_control.clone(),
            collector_metrics: collector_metrics.clone(),
            capture_control: capture_control.clone(),
            capture_metrics: capture_metrics.clone(),
            schema_version,
            worker_count,
            queue_capacity,
            work_batch_size: config.work_batch_size,
            notification_settings: Arc::clone(&notification_settings),
            notification_control: notification_control.clone(),
            recent_events: Arc::clone(&recent_events),
        };
        workers.push(thread::spawn(move || {
            worker_loop(Database::open(worker_database_path)?, context)
        }));
    }

    let current_uid = geteuid().as_raw();
    while !terminating.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                statistics
                    .accepted_connections
                    .fetch_add(1, Ordering::Relaxed);
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                let credentials = getsockopt(&stream, PeerCredentials)
                    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                if credentials.uid() != current_uid {
                    statistics
                        .rejected_connections
                        .fetch_add(1, Ordering::Relaxed);
                    let mut stream = stream;
                    let _ = write_frame(
                        &mut stream,
                        &ResponseEnvelope::error(
                            0,
                            ErrorCode::PermissionDenied,
                            "peer UID does not match daemon UID",
                        ),
                    );
                    continue;
                }
                enqueue_client(&sender, stream, &statistics)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
    collector.shutdown()?;
    capture.shutdown()?;
    drop(sender);
    for worker in workers {
        worker.join().map_err(|_| DaemonError::WorkerPanicked)??;
    }
    drop(notification_control);
    notification_dispatcher.shutdown();
    Ok(())
}

enum Work {
    Client(std::os::unix::net::UnixStream),
    File(CollectedFile),
    Terminal(CollectedTerminalOutput),
}

const RECENT_EVENT_CAPACITY: usize = 4_096;
const RECENT_EVENT_TTL: Duration = Duration::from_secs(5);

#[derive(Default)]
struct RecentEvents {
    entries: HashMap<[u8; 32], Instant>,
    order: VecDeque<([u8; 32], Instant)>,
}

impl RecentEvents {
    fn is_duplicate(&mut self, event: &CaptureEvent, now: Instant) -> bool {
        while self
            .order
            .front()
            .is_some_and(|(_, inserted)| now.duration_since(*inserted) >= RECENT_EVENT_TTL)
        {
            if let Some((key, inserted)) = self.order.pop_front()
                && self.entries.get(&key) == Some(&inserted)
            {
                self.entries.remove(&key);
            }
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(event.session_id().to_string().as_bytes());
        hasher.update(&serde_json::to_vec(event.source()).unwrap_or_default());
        hasher.update(event.payload().as_bytes());
        let key = *hasher.finalize().as_bytes();
        if self.entries.contains_key(&key) {
            return true;
        }
        self.entries.insert(key, now);
        self.order.push_back((key, now));
        while self.order.len() > RECENT_EVENT_CAPACITY {
            if let Some((key, inserted)) = self.order.pop_front()
                && self.entries.get(&key) == Some(&inserted)
            {
                self.entries.remove(&key);
            }
        }
        false
    }
}

fn enqueue_client(
    sender: &SyncSender<Work>,
    stream: std::os::unix::net::UnixStream,
    statistics: &Statistics,
) -> Result<(), DaemonError> {
    statistics.queue_depth.fetch_add(1, Ordering::Relaxed);
    match sender.try_send(Work::Client(stream)) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(Work::Client(mut stream))) => {
            statistics.queue_depth.fetch_sub(1, Ordering::Relaxed);
            statistics
                .rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            if write_frame(
                &mut stream,
                &ResponseEnvelope::error(0, ErrorCode::Busy, "request queue is full"),
            )
            .is_err()
            {
                statistics.failed_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Ok(())
        }
        Err(TrySendError::Full(Work::File(_) | Work::Terminal(_))) => {
            unreachable!("client work changed variant")
        }
        Err(TrySendError::Disconnected(_)) => {
            statistics.queue_depth.fetch_sub(1, Ordering::Relaxed);
            Err(DaemonError::WorkerStopped)
        }
    }
}

fn enqueue_file(sender: &SyncSender<Work>, file: CollectedFile, statistics: &Statistics) -> bool {
    statistics.queue_depth.fetch_add(1, Ordering::Relaxed);
    match sender.try_send(Work::File(file)) {
        Ok(()) => true,
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            statistics.queue_depth.fetch_sub(1, Ordering::Relaxed);
            false
        }
    }
}

fn enqueue_terminal(
    sender: &SyncSender<Work>,
    event: CollectedTerminalOutput,
    statistics: &Statistics,
) -> bool {
    statistics.queue_depth.fetch_add(1, Ordering::Relaxed);
    match sender.try_send(Work::Terminal(event)) {
        Ok(()) => true,
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            statistics.queue_depth.fetch_sub(1, Ordering::Relaxed);
            false
        }
    }
}

struct WorkerContext {
    receiver: Arc<Mutex<Receiver<Work>>>,
    statistics: Arc<Statistics>,
    terminating: Arc<AtomicBool>,
    session_state_lock: Arc<Mutex<()>>,
    collector_control: hunter_collectors::FileCollectorControl,
    collector_metrics: FileCollectorMetrics,
    capture_control: hunter_capture_client::CaptureClientControl,
    capture_metrics: CaptureClientMetrics,
    schema_version: usize,
    worker_count: usize,
    queue_capacity: usize,
    work_batch_size: usize,
    notification_settings: Arc<RwLock<NotificationSettings>>,
    notification_control: NotificationControl,
    recent_events: Arc<Mutex<RecentEvents>>,
}

fn worker_loop(database: Database, context: WorkerContext) -> Result<(), DaemonError> {
    let mut service = Service {
        database,
        statistics: Arc::clone(&context.statistics),
        terminating: Arc::clone(&context.terminating),
        session_state_lock: Arc::clone(&context.session_state_lock),
        collector_control: context.collector_control,
        collector_metrics: context.collector_metrics,
        capture_control: context.capture_control,
        capture_metrics: context.capture_metrics,
        schema_version: context.schema_version,
        worker_count: context.worker_count,
        queue_capacity: context.queue_capacity,
        notification_settings: context.notification_settings,
        notification_control: context.notification_control,
        recent_events: context.recent_events,
    };
    loop {
        let mut batch = Vec::with_capacity(context.work_batch_size);
        let disconnected = {
            let receiver = context
                .receiver
                .lock()
                .map_err(|_| DaemonError::WorkerStopped)?;
            match receiver.recv() {
                Ok(work) => {
                    batch.push(work);
                    while batch.len() < context.work_batch_size {
                        match receiver.try_recv() {
                            Ok(work) => batch.push(work),
                            Err(_) => break,
                        }
                    }
                    false
                }
                Err(_) => true,
            }
        };
        if disconnected {
            break;
        }
        context
            .statistics
            .queue_depth
            .fetch_sub(batch.len(), Ordering::Relaxed);
        for work in batch {
            match work {
                Work::Client(mut stream) => service.handle_connection(&mut stream),
                Work::File(file) => match service.handle_file(file) {
                    Ok(true) => {
                        context
                            .statistics
                            .analyzed_files
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(false) => {}
                    Err(_) => {
                        context
                            .statistics
                            .file_analysis_errors
                            .fetch_add(1, Ordering::Relaxed);
                    }
                },
                Work::Terminal(event) => match service.handle_terminal(event) {
                    Ok(true) => {
                        context
                            .statistics
                            .analyzed_terminal_events
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(false) => {}
                    Err(_) => {
                        context
                            .statistics
                            .terminal_analysis_errors
                            .fetch_add(1, Ordering::Relaxed);
                    }
                },
            }
        }
    }
    Ok(())
}

struct Service {
    database: Database,
    statistics: Arc<Statistics>,
    terminating: Arc<AtomicBool>,
    session_state_lock: Arc<Mutex<()>>,
    collector_control: hunter_collectors::FileCollectorControl,
    collector_metrics: FileCollectorMetrics,
    capture_control: hunter_capture_client::CaptureClientControl,
    capture_metrics: CaptureClientMetrics,
    schema_version: usize,
    worker_count: usize,
    queue_capacity: usize,
    notification_settings: Arc<RwLock<NotificationSettings>>,
    notification_control: NotificationControl,
    recent_events: Arc<Mutex<RecentEvents>>,
}

impl Service {
    fn handle_connection(&mut self, stream: &mut std::os::unix::net::UnixStream) {
        let request = match read_frame::<RequestEnvelope>(stream) {
            Ok(request) => request,
            Err(error) => {
                self.statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                let _ = write_frame(
                    stream,
                    &ResponseEnvelope::error(0, ErrorCode::InvalidFrame, error.to_string()),
                );
                return;
            }
        };
        let request_id = request.request_id;
        let response = if request.version != PROTOCOL_VERSION {
            ResponseEnvelope::error(
                request_id,
                ErrorCode::UnsupportedVersion,
                format!("supported protocol version is {PROTOCOL_VERSION}"),
            )
        } else {
            ResponseEnvelope::new(request_id, self.handle_request(request.request))
        };
        let response_is_error = matches!(response.response, Response::Error { .. });
        let write_failed = match write_frame(stream, &response) {
            Ok(()) => false,
            Err(FrameError::Oversized) => {
                let fallback = ResponseEnvelope::error(
                    request_id,
                    ErrorCode::Internal,
                    "response exceeds the protocol frame limit",
                );
                let _ = write_frame(stream, &fallback);
                true
            }
            Err(_) => true,
        };
        if write_failed || response_is_error {
            self.statistics
                .failed_requests
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.statistics
                .completed_requests
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn handle_request(&mut self, request: Request) -> Response {
        match self.try_handle_request(request) {
            Ok(response) => response,
            Err((code, message)) => Response::Error { code, message },
        }
    }

    fn try_handle_request(&mut self, request: Request) -> Result<Response, (ErrorCode, String)> {
        match request {
            Request::GetStatus => Ok(Response::Status(self.statistics.snapshot(
                self.schema_version,
                self.worker_count,
                self.queue_capacity,
                self.collector_metrics.snapshot(),
                self.capture_metrics.snapshot(),
                self.notification_control.metrics(),
            ))),
            Request::GetNotificationSettings => {
                let settings = *self
                    .notification_settings
                    .read()
                    .map_err(|_| state_lock_error())?;
                Ok(Response::NotificationSettings(settings))
            }
            Request::UpdateNotificationSettings { settings } => {
                self.database
                    .save_notification_settings(settings)
                    .map_err(internal_error)?;
                *self
                    .notification_settings
                    .write()
                    .map_err(|_| state_lock_error())? = settings;
                Ok(Response::NotificationSettings(settings))
            }
            Request::ListSessions => Ok(Response::Sessions {
                sessions: self.database.list_sessions().map_err(internal_error)?,
            }),
            Request::CreateSession {
                name,
                flag_patterns,
            } => {
                let mut session = Session::new(SessionId::generate(), name, Timestamp::now())
                    .map_err(invalid_request)?;
                session
                    .set_flag_patterns(flag_patterns)
                    .map_err(invalid_request)?;
                self.database
                    .save_session(&session)
                    .map_err(internal_error)?;
                Ok(Response::Session(session))
            }
            Request::UpdateSession {
                session_id,
                name,
                flag_patterns,
            } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                if !matches!(
                    session.status(),
                    SessionStatus::Inactive | SessionStatus::Paused
                ) {
                    return Err((
                        ErrorCode::InvalidState,
                        "only inactive or paused sessions can be edited".to_owned(),
                    ));
                }
                session.set_name(name).map_err(invalid_request)?;
                session
                    .set_flag_patterns(flag_patterns)
                    .map_err(invalid_request)?;
                self.database
                    .save_session(&session)
                    .map_err(internal_error)?;
                Ok(Response::Session(session))
            }
            Request::StartSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                let previous = session.clone();
                session.start(Timestamp::now()).map_err(invalid_state)?;
                self.save_session_activity(&previous, &session, true)?;
                Ok(Response::Session(session))
            }
            Request::PauseSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                let previous = session.clone();
                session.pause().map_err(invalid_state)?;
                self.save_session_activity(&previous, &session, false)?;
                Ok(Response::Session(session))
            }
            Request::ResumeSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                let previous = session.clone();
                session.resume().map_err(invalid_state)?;
                self.save_session_activity(&previous, &session, true)?;
                Ok(Response::Session(session))
            }
            Request::StopSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                let previous = session.clone();
                session.finish(Timestamp::now()).map_err(invalid_state)?;
                self.save_session_activity(&previous, &session, false)?;
                Ok(Response::Session(session))
            }
            Request::AddWatchDirectory {
                session_id,
                directory,
            } => self.add_watch_directory(session_id, directory),
            Request::RemoveWatchDirectory {
                session_id,
                directory,
            } => self.remove_watch_directory(session_id, directory),
            Request::ListWatchDirectories { session_id } => {
                self.require_session(session_id)?;
                self.watch_directories_response(session_id)
            }
            Request::AddTerminal {
                session_id,
                terminal,
            } => self.add_terminal(session_id, terminal),
            Request::RemoveTerminal {
                session_id,
                terminal,
            } => self.remove_terminal(session_id, terminal),
            Request::ListTerminals { session_id } => {
                self.require_session(session_id)?;
                self.terminals_response(session_id)
            }
            Request::SubmitText { session_id, text } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                self.submit_text(session_id, text)
            }
            Request::PreviewText { session_id, text } => self.preview_text(session_id, text),
            Request::ListFindings {
                session_id,
                offset,
                limit,
            } => {
                if limit > MAX_LIST_LIMIT {
                    return Err(invalid_request(format!(
                        "list limit must not exceed {MAX_LIST_LIMIT}"
                    )));
                }
                self.require_session(session_id)?;
                let findings = self
                    .database
                    .list_findings(session_id, offset, limit)
                    .map_err(internal_error)?
                    .into_iter()
                    .map(summary_from_database)
                    .collect();
                Ok(Response::Findings { findings })
            }
            Request::GetFinding { finding_id } => {
                let finding = self
                    .database
                    .get_finding(finding_id)
                    .map_err(internal_error)?
                    .map(detail_from_database);
                Ok(Response::Finding { finding })
            }
            Request::Shutdown => {
                self.terminating.store(true, Ordering::Relaxed);
                Ok(Response::Acknowledged)
            }
        }
    }

    fn require_session(&self, session_id: SessionId) -> Result<Session, (ErrorCode, String)> {
        self.database
            .get_session(session_id)
            .map_err(internal_error)?
            .ok_or_else(|| (ErrorCode::NotFound, "session not found".to_owned()))
    }

    fn save_session_activity(
        &mut self,
        previous: &Session,
        session: &Session,
        active: bool,
    ) -> Result<(), (ErrorCode, String)> {
        self.database
            .save_session(session)
            .map_err(internal_error)?;
        if let Err(error) = self
            .collector_control
            .set_session_active(session.id(), active)
        {
            self.database
                .save_session(previous)
                .map_err(internal_error)?;
            return Err(collector_control_error(error));
        }
        if let Err(error) = self
            .capture_control
            .set_session_active(session.id(), active)
        {
            let previous_active = previous.status() == SessionStatus::Monitoring;
            let _ = self
                .collector_control
                .set_session_active(session.id(), previous_active);
            self.database
                .save_session(previous)
                .map_err(internal_error)?;
            return Err(capture_control_error(error));
        }
        Ok(())
    }

    fn add_watch_directory(
        &mut self,
        session_id: SessionId,
        directory: String,
    ) -> Result<Response, (ErrorCode, String)> {
        let lock = Arc::clone(&self.session_state_lock);
        let _guard = lock.lock().map_err(|_| state_lock_error())?;
        let session = self.require_session(session_id)?;
        if session.status() == SessionStatus::Finished {
            return Err((
                ErrorCode::InvalidState,
                "watch directories cannot be changed for a finished session".to_owned(),
            ));
        }
        let directory = canonical_watch_directory(&directory)?;
        let inserted = self
            .database
            .add_watch_directory(session_id, &directory)
            .map_err(internal_error)?;
        let registration = WatchRegistration {
            session_id,
            directory: directory.clone(),
        };
        if let Err(error) = self.collector_control.register(registration.clone()) {
            if inserted {
                self.database
                    .remove_watch_directory(session_id, &directory)
                    .map_err(internal_error)?;
            }
            return Err(collector_control_error(error));
        }
        if session.status() == SessionStatus::Monitoring
            && let Err(error) = self.collector_control.set_session_active(session_id, true)
        {
            let _ = self.collector_control.unregister(registration);
            if inserted {
                self.database
                    .remove_watch_directory(session_id, &directory)
                    .map_err(internal_error)?;
            }
            return Err(collector_control_error(error));
        }
        self.watch_directories_response(session_id)
    }

    fn remove_watch_directory(
        &mut self,
        session_id: SessionId,
        directory: String,
    ) -> Result<Response, (ErrorCode, String)> {
        let lock = Arc::clone(&self.session_state_lock);
        let _guard = lock.lock().map_err(|_| state_lock_error())?;
        let session = self.require_session(session_id)?;
        if session.status() == SessionStatus::Finished {
            return Err((
                ErrorCode::InvalidState,
                "watch directories cannot be changed for a finished session".to_owned(),
            ));
        }
        let directory = removable_watch_directory(&directory)?;
        let removed = self
            .database
            .remove_watch_directory(session_id, &directory)
            .map_err(internal_error)?;
        if removed {
            let registration = WatchRegistration {
                session_id,
                directory: directory.clone(),
            };
            if let Err(error) = self.collector_control.unregister(registration) {
                self.database
                    .add_watch_directory(session_id, &directory)
                    .map_err(internal_error)?;
                return Err(collector_control_error(error));
            }
        }
        self.watch_directories_response(session_id)
    }

    fn watch_directories_response(
        &self,
        session_id: SessionId,
    ) -> Result<Response, (ErrorCode, String)> {
        let directories = self
            .database
            .list_watch_directories(session_id)
            .map_err(internal_error)?
            .into_iter()
            .map(|directory| {
                directory
                    .into_os_string()
                    .into_string()
                    .map_err(|_| internal_error("stored watch directory is not valid UTF-8"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::WatchDirectories {
            session_id,
            directories,
        })
    }

    fn add_terminal(
        &mut self,
        session_id: SessionId,
        terminal: String,
    ) -> Result<Response, (ErrorCode, String)> {
        let lock = Arc::clone(&self.session_state_lock);
        let _guard = lock.lock().map_err(|_| state_lock_error())?;
        let session = self.require_session(session_id)?;
        if session.status() == SessionStatus::Finished {
            return Err((
                ErrorCode::InvalidState,
                "terminal sources cannot be changed for a finished session".to_owned(),
            ));
        }
        let terminal = canonical_terminal(&terminal)?;
        let inserted = self
            .database
            .add_terminal(session_id, &terminal)
            .map_err(internal_error)?;
        let registration = CaptureRegistration {
            session_id,
            terminal: terminal.clone(),
        };
        if let Err(error) = self.capture_control.register(registration) {
            if inserted {
                self.database
                    .remove_terminal(session_id, &terminal)
                    .map_err(internal_error)?;
            }
            return Err(capture_control_error(error));
        }
        self.terminals_response(session_id)
    }

    fn remove_terminal(
        &mut self,
        session_id: SessionId,
        terminal: String,
    ) -> Result<Response, (ErrorCode, String)> {
        let lock = Arc::clone(&self.session_state_lock);
        let _guard = lock.lock().map_err(|_| state_lock_error())?;
        let session = self.require_session(session_id)?;
        if session.status() == SessionStatus::Finished {
            return Err((
                ErrorCode::InvalidState,
                "terminal sources cannot be changed for a finished session".to_owned(),
            ));
        }
        let terminal = removable_terminal(&terminal)?;
        let removed = self
            .database
            .remove_terminal(session_id, &terminal)
            .map_err(internal_error)?;
        if removed {
            let registration = CaptureRegistration {
                session_id,
                terminal: terminal.clone(),
            };
            if let Err(error) = self.capture_control.unregister(registration) {
                self.database
                    .add_terminal(session_id, &terminal)
                    .map_err(internal_error)?;
                return Err(capture_control_error(error));
            }
        }
        self.terminals_response(session_id)
    }

    fn terminals_response(&self, session_id: SessionId) -> Result<Response, (ErrorCode, String)> {
        let terminals = self
            .database
            .list_terminals(session_id)
            .map_err(internal_error)?
            .into_iter()
            .map(|terminal| {
                terminal
                    .into_os_string()
                    .into_string()
                    .map_err(|_| internal_error("stored terminal path is not valid UTF-8"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::Terminals {
            session_id,
            terminals,
        })
    }

    fn handle_file(&mut self, file: CollectedFile) -> Result<bool, (ErrorCode, String)> {
        let lock = Arc::clone(&self.session_state_lock);
        let session = {
            let _guard = lock.lock().map_err(|_| state_lock_error())?;
            self.require_session(file.session_id)?
        };
        if session.status() != SessionStatus::Monitoring {
            return Ok(false);
        }
        let payload = EventPayload::new(file.bytes).map_err(invalid_request)?;
        let source_path = SourcePath::new(file.path).map_err(invalid_request)?;
        let event = CaptureEvent::new(
            EventId::generate(),
            file.session_id,
            Timestamp::now(),
            SourceMetadata::File(FileSource::new(source_path)),
            payload,
        );
        self.analyze_event(&session, &event)?;
        Ok(true)
    }

    fn handle_terminal(
        &mut self,
        output: CollectedTerminalOutput,
    ) -> Result<bool, (ErrorCode, String)> {
        let lock = Arc::clone(&self.session_state_lock);
        let session = {
            let _guard = lock.lock().map_err(|_| state_lock_error())?;
            self.require_session(output.session_id)?
        };
        if session.status() != SessionStatus::Monitoring {
            return Ok(false);
        }
        if output.uid != geteuid().as_raw() {
            return Err((
                ErrorCode::PermissionDenied,
                "capture event UID does not match daemon UID".to_owned(),
            ));
        }
        let payload = EventPayload::new(output.payload).map_err(invalid_request)?;
        let tty = SourcePath::new(output.terminal).map_err(invalid_request)?;
        let source =
            TerminalSource::new(output.pid, output.uid, None, output.process_name, None, tty)
                .map_err(invalid_request)?;
        let event = CaptureEvent::new(
            EventId::generate(),
            output.session_id,
            Timestamp::now(),
            SourceMetadata::Terminal(source),
            payload,
        );
        self.analyze_event(&session, &event)?;
        Ok(true)
    }

    fn submit_text(
        &mut self,
        session_id: SessionId,
        text: String,
    ) -> Result<Response, (ErrorCode, String)> {
        let session = self.require_session(session_id)?;
        if session.status() != SessionStatus::Monitoring {
            return Err((
                ErrorCode::InvalidState,
                "session must be monitoring before input is submitted".to_owned(),
            ));
        }
        let payload = EventPayload::new(text.into_bytes()).map_err(invalid_request)?;
        let event = CaptureEvent::new(
            EventId::generate(),
            session_id,
            Timestamp::now(),
            SourceMetadata::Manual,
            payload,
        );
        let finding_ids = self.analyze_event(&session, &event)?;
        Ok(Response::Submission {
            event_id: event.id(),
            finding_ids,
        })
    }

    fn preview_text(
        &self,
        session_id: SessionId,
        text: String,
    ) -> Result<Response, (ErrorCode, String)> {
        let session = self.require_session(session_id)?;
        let payload = EventPayload::new(text.into_bytes()).map_err(invalid_request)?;
        let detections = DecoderSet::new()
            .detect(payload.as_bytes())
            .into_iter()
            .map(|detection| PreviewDetection {
                format: detection.kind().id().to_owned(),
                confidence: detection.score().value(),
            })
            .collect();
        let event = CaptureEvent::new(
            EventId::generate(),
            session_id,
            Timestamp::now(),
            SourceMetadata::Manual,
            payload,
        );
        let patterns = session
            .flag_patterns()
            .iter()
            .cloned()
            .map(FlagPattern::simple);
        let analyzer =
            Analyzer::new(AnalysisConfig::default(), patterns).map_err(internal_error)?;
        let report = analyzer.analyze(&event).map_err(internal_error)?;
        let candidate_text = report
            .candidates()
            .iter()
            .map(|candidate| {
                (
                    candidate.id(),
                    preview_text_value(candidate.data().as_bytes()),
                )
            })
            .collect::<HashMap<_, _>>();
        let transformations = report
            .transformations()
            .iter()
            .take(MAX_PREVIEW_TRANSFORMATIONS)
            .map(|transformation| PreviewTransformation {
                name: transformation.name().as_str().to_owned(),
                input: candidate_text
                    .get(&transformation.input_candidate_id())
                    .cloned()
                    .unwrap_or_default(),
                output: candidate_text
                    .get(&transformation.output_candidate_id())
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect();
        let findings = report
            .findings()
            .iter()
            .take(MAX_PREVIEW_FINDINGS)
            .map(|finding| PreviewFinding {
                value: preview_string(finding.value().as_str()),
                confidence: finding.confidence(),
                path: finding.path().clone(),
            })
            .collect();
        let statistics = report.statistics();
        Ok(Response::AnalysisPreview(AnalysisPreview {
            normalized: preview_text_value(report.normalized()),
            detections,
            transformations,
            findings,
            statistics: PreviewStatistics {
                extracted_occurrences: statistics.extracted_occurrences,
                candidate_count: report.candidates().len(),
                decoded_candidates: statistics.decoded_candidates,
                decoder_attempts: statistics.decoder_attempts,
            },
        }))
    }

    fn analyze_event(
        &mut self,
        session: &Session,
        event: &CaptureEvent,
    ) -> Result<Vec<hunter_types::FindingId>, (ErrorCode, String)> {
        if self
            .recent_events
            .lock()
            .map_err(|_| state_lock_error())?
            .is_duplicate(event, Instant::now())
        {
            self.statistics
                .duplicate_events
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Vec::new());
        }
        let patterns = session
            .flag_patterns()
            .iter()
            .cloned()
            .map(FlagPattern::simple);
        let analyzer =
            Analyzer::new(AnalysisConfig::default(), patterns).map_err(internal_error)?;
        let report = analyzer.analyze(event).map_err(internal_error)?;
        let analysis_statistics = report.statistics();
        let finding_count = report.findings().len();
        let stored_findings = self
            .database
            .persist_analysis_with_outcomes(event, &report)
            .map_err(internal_error)?;
        let settings = *self
            .notification_settings
            .read()
            .map_err(|_| state_lock_error())?;
        for (finding, stored) in report.findings().iter().zip(&stored_findings) {
            if stored.created && settings.accepts(finding.confidence()) {
                self.notification_control.try_send(FindingNotification {
                    session: session.name().to_owned(),
                    value: finding.value().as_str().to_owned(),
                });
            }
        }
        self.statistics
            .analyzed_events
            .fetch_add(1, Ordering::Relaxed);
        self.statistics.extracted_candidates.fetch_add(
            usize_to_u64(analysis_statistics.extracted_occurrences),
            Ordering::Relaxed,
        );
        self.statistics.decoded_candidates.fetch_add(
            usize_to_u64(analysis_statistics.decoded_candidates),
            Ordering::Relaxed,
        );
        self.statistics
            .findings_detected
            .fetch_add(usize_to_u64(finding_count), Ordering::Relaxed);
        Ok(stored_findings
            .into_iter()
            .map(|finding| finding.id)
            .collect())
    }
}

fn preview_text_value(value: &[u8]) -> String {
    preview_string(&String::from_utf8_lossy(value))
}

fn preview_string(value: &str) -> String {
    let mut preview = value
        .chars()
        .take(MAX_PREVIEW_TEXT_CHARS)
        .collect::<String>();
    if value.chars().count() > MAX_PREVIEW_TEXT_CHARS {
        preview.push('…');
    }
    preview
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn bind_secure_socket(path: &Path) -> Result<UnixListener, DaemonError> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"))?;
    secure_private_directory(directory)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
            return Err(DaemonError::UnsafeSocketPath(path.to_owned()));
        }
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => return Err(DaemonError::AlreadyRunning(path.to_owned())),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn secure_private_directory(path: &Path) -> Result<(), DaemonError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(DaemonError::UnsafeSocketPath(path.to_owned()));
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(DaemonError::RuntimeDirectoryOwner);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn invalid_request(error: impl std::fmt::Display) -> (ErrorCode, String) {
    (ErrorCode::InvalidRequest, error.to_string())
}

fn invalid_state(error: impl std::fmt::Display) -> (ErrorCode, String) {
    (ErrorCode::InvalidState, error.to_string())
}

fn internal_error(error: impl std::fmt::Display) -> (ErrorCode, String) {
    (ErrorCode::Internal, error.to_string())
}

fn state_lock_error() -> (ErrorCode, String) {
    internal_error("session state lock is poisoned")
}

fn collector_control_error(error: CollectorControlError) -> (ErrorCode, String) {
    match error {
        CollectorControlError::Busy => (ErrorCode::Busy, CollectorControlError::Busy.to_string()),
        other => internal_error(other),
    }
}

fn capture_control_error(error: CaptureControlError) -> (ErrorCode, String) {
    match error {
        CaptureControlError::Busy => (ErrorCode::Busy, CaptureControlError::Busy.to_string()),
        other => internal_error(other),
    }
}

fn canonical_watch_directory(value: &str) -> Result<PathBuf, (ErrorCode, String)> {
    let directory = fs::canonicalize(value).map_err(invalid_request)?;
    if !directory.is_absolute() || !directory.is_dir() {
        return Err(invalid_request(
            "watch path must resolve to an existing directory",
        ));
    }
    directory
        .to_str()
        .ok_or_else(|| invalid_request("watch directory must be valid UTF-8"))?;
    Ok(directory)
}

fn is_restorable_watch_directory(path: &Path) -> bool {
    path.is_absolute()
        && fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

fn removable_watch_directory(value: &str) -> Result<PathBuf, (ErrorCode, String)> {
    if let Ok(directory) = fs::canonicalize(value) {
        return Ok(directory);
    }
    let directory = PathBuf::from(value);
    if !directory.is_absolute()
        || directory.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || directory.to_str().is_none()
    {
        return Err(invalid_request(
            "missing watch directory must be an absolute normalized UTF-8 path",
        ));
    }
    Ok(directory)
}

fn canonical_terminal(value: &str) -> Result<PathBuf, (ErrorCode, String)> {
    let terminal = fs::canonicalize(value).map_err(invalid_request)?;
    if !terminal.is_absolute() || !is_supported_terminal_path(&terminal) {
        return Err(invalid_request(
            "terminal must resolve to /dev/pts/N or /dev/ttyN",
        ));
    }
    let metadata = fs::metadata(&terminal).map_err(invalid_request)?;
    if !metadata.file_type().is_char_device() || metadata.uid() != geteuid().as_raw() {
        return Err((
            ErrorCode::PermissionDenied,
            "terminal must be a character device owned by the daemon UID".to_owned(),
        ));
    }
    terminal
        .to_str()
        .ok_or_else(|| invalid_request("terminal path must be valid UTF-8"))?;
    Ok(terminal)
}

fn removable_terminal(value: &str) -> Result<PathBuf, (ErrorCode, String)> {
    if let Ok(terminal) = fs::canonicalize(value)
        && is_supported_terminal_path(&terminal)
    {
        return Ok(terminal);
    }
    let terminal = PathBuf::from(value);
    if !terminal.is_absolute()
        || !is_supported_terminal_path(&terminal)
        || terminal.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || terminal.to_str().is_none()
    {
        return Err(invalid_request(
            "missing terminal must be a normalized /dev/pts/N or /dev/ttyN path",
        ));
    }
    Ok(terminal)
}

fn is_supported_terminal_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    value.strip_prefix("/dev/pts/").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    }) || value.strip_prefix("/dev/tty").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn summary_from_database(value: hunter_database::FindingSummary) -> FindingSummary {
    FindingSummary {
        id: value.id,
        session_id: value.session_id,
        value: value.value,
        confidence: value.confidence,
        discovered_at: value.discovered_at,
        occurrences: value.occurrences,
        source: value.source,
    }
}

fn detail_from_database(value: hunter_database::FindingDetail) -> FindingDetail {
    FindingDetail {
        summary: summary_from_database(value.summary),
        occurrences_truncated: value.occurrences_truncated,
        occurrences: value
            .occurrences
            .into_iter()
            .map(|occurrence| FindingOccurrence {
                source_event_id: occurrence.source_event_id,
                candidate_id: occurrence.candidate_id,
                path: occurrence.path,
                observed_at: occurrence.observed_at,
                count: occurrence.count,
                source: occurrence.source,
                candidate_text: occurrence.candidate_text,
                candidate_original_length: occurrence.candidate_original_length,
                candidate_truncated: occurrence.candidate_truncated,
                transformations: occurrence
                    .transformations
                    .into_iter()
                    .map(|step| TransformationStep {
                        id: step.id,
                        input_candidate_id: step.input_candidate_id,
                        output_candidate_id: step.output_candidate_id,
                        name: step.name,
                        applied_at: step.applied_at,
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_backpressure_statistics() {
        let statistics = Statistics::default();
        statistics.queue_depth.store(7, Ordering::Relaxed);
        statistics.rejected_connections.store(3, Ordering::Relaxed);

        let snapshot = statistics.snapshot(
            3,
            4,
            64,
            FileCollectorStatistics::default(),
            CaptureClientStatistics::default(),
            notifications::NotificationMetrics::default(),
        );

        assert_eq!(snapshot.schema_version, 3);
        assert_eq!(snapshot.queue_depth, 7);
        assert_eq!(snapshot.rejected_connections, 3);
        assert_eq!(snapshot.worker_count, 4);
        assert_eq!(snapshot.queue_capacity, 64);
    }

    #[test]
    fn recent_event_cache_deduplicates_and_remains_bounded() {
        let session_id = SessionId::generate();
        let event = CaptureEvent::new(
            EventId::generate(),
            session_id,
            Timestamp::now(),
            SourceMetadata::Manual,
            EventPayload::new(b"FLAG{duplicate}".to_vec()).expect("payload"),
        );
        let now = Instant::now();
        let mut cache = RecentEvents::default();
        assert!(!cache.is_duplicate(&event, now));
        assert!(cache.is_duplicate(&event, now));
        for index in 0..RECENT_EVENT_CAPACITY + 64 {
            let event = CaptureEvent::new(
                EventId::generate(),
                session_id,
                Timestamp::now(),
                SourceMetadata::Manual,
                EventPayload::new(index.to_string().into_bytes()).expect("payload"),
            );
            cache.is_duplicate(&event, now);
        }
        assert!(cache.entries.len() <= RECENT_EVENT_CAPACITY);
        assert!(cache.order.len() <= RECENT_EVENT_CAPACITY);
        assert!(!cache.is_duplicate(&event, now + Duration::from_secs(3 * 60 * 60)));
    }

    #[test]
    fn saturated_capture_queue_drops_immediately_instead_of_blocking_writer() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let statistics = Statistics::default();
        let output = CollectedTerminalOutput {
            session_id: SessionId::generate(),
            terminal: PathBuf::from("/dev/pts/1"),
            pid: 42,
            uid: 1_000,
            requested_len: 4,
            truncated: false,
            process_name: "test".to_owned(),
            payload: b"test".to_vec(),
        };
        assert!(enqueue_terminal(&sender, output.clone(), &statistics));
        let start = Instant::now();
        assert!(!enqueue_terminal(&sender, output, &statistics));
        assert!(start.elapsed() < Duration::from_millis(25));
        assert_eq!(statistics.queue_depth.load(Ordering::Relaxed), 1);
    }
}
