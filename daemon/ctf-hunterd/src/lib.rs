use std::{
    fs, io,
    os::unix::{
        fs::FileTypeExt as _, fs::MetadataExt as _, fs::PermissionsExt as _, net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use hunter_core::{AnalysisConfig, Analyzer};
use hunter_database::Database;
use hunter_flags::FlagPattern;
use hunter_ipc::{
    DaemonStatus, ErrorCode, FindingDetail, FindingOccurrence, FindingSummary, FrameError,
    IO_TIMEOUT, MAX_LIST_LIMIT, PROTOCOL_VERSION, Request, RequestEnvelope, Response,
    ResponseEnvelope, TransformationStep, read_frame, write_frame,
};
use hunter_types::{
    CaptureEvent, EventId, EventPayload, Session, SessionId, SessionStatus, SourceMetadata,
    Timestamp,
};
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::geteuid,
};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use thiserror::Error;

pub const DEFAULT_QUEUE_CAPACITY: usize = 64;
pub const DEFAULT_WORKER_COUNT: usize = 4;
pub const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub database_path: PathBuf,
    pub socket_path: PathBuf,
    pub queue_capacity: usize,
    pub worker_count: usize,
}

impl DaemonConfig {
    #[must_use]
    pub fn new(database_path: impl Into<PathBuf>, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            database_path: database_path.into(),
            socket_path: socket_path.into(),
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            worker_count: DEFAULT_WORKER_COUNT,
        }
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Database(#[from] hunter_database::DatabaseError),
    #[error("queue capacity must be greater than zero")]
    InvalidQueueCapacity,
    #[error("worker count must be greater than zero")]
    InvalidWorkerCount,
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
}

impl Statistics {
    fn snapshot(
        &self,
        schema_version: usize,
        worker_count: usize,
        queue_capacity: usize,
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
    let database_directory = config.database_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "database path has no parent")
    })?;
    secure_private_directory(database_directory)?;
    let database = Database::open(&config.database_path)?;
    let schema_version = database.schema_version()?;
    fs::set_permissions(&config.database_path, fs::Permissions::from_mode(0o600))?;
    drop(database);
    let listener = bind_secure_socket(&config.socket_path)?;
    let _socket_guard = SocketGuard(config.socket_path.clone());
    listener.set_nonblocking(true)?;

    let statistics = Arc::new(Statistics::default());
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
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
            schema_version,
            worker_count,
            queue_capacity,
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
                enqueue(&sender, stream, &statistics)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
    drop(sender);
    for worker in workers {
        worker.join().map_err(|_| DaemonError::WorkerPanicked)??;
    }
    Ok(())
}

fn enqueue(
    sender: &SyncSender<std::os::unix::net::UnixStream>,
    stream: std::os::unix::net::UnixStream,
    statistics: &Statistics,
) -> Result<(), DaemonError> {
    statistics.queue_depth.fetch_add(1, Ordering::Relaxed);
    match sender.try_send(stream) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(mut stream)) => {
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
        Err(TrySendError::Disconnected(_)) => {
            statistics.queue_depth.fetch_sub(1, Ordering::Relaxed);
            Err(DaemonError::WorkerStopped)
        }
    }
}

struct WorkerContext {
    receiver: Arc<Mutex<Receiver<std::os::unix::net::UnixStream>>>,
    statistics: Arc<Statistics>,
    terminating: Arc<AtomicBool>,
    session_state_lock: Arc<Mutex<()>>,
    schema_version: usize,
    worker_count: usize,
    queue_capacity: usize,
}

fn worker_loop(database: Database, context: WorkerContext) -> Result<(), DaemonError> {
    let mut service = Service {
        database,
        statistics: Arc::clone(&context.statistics),
        terminating: Arc::clone(&context.terminating),
        session_state_lock: Arc::clone(&context.session_state_lock),
        schema_version: context.schema_version,
        worker_count: context.worker_count,
        queue_capacity: context.queue_capacity,
    };
    loop {
        let received = context
            .receiver
            .lock()
            .map_err(|_| DaemonError::WorkerStopped)?
            .recv();
        let Ok(mut stream) = received else {
            break;
        };
        context
            .statistics
            .queue_depth
            .fetch_sub(1, Ordering::Relaxed);
        service.handle_connection(&mut stream);
    }
    Ok(())
}

struct Service {
    database: Database,
    statistics: Arc<Statistics>,
    terminating: Arc<AtomicBool>,
    session_state_lock: Arc<Mutex<()>>,
    schema_version: usize,
    worker_count: usize,
    queue_capacity: usize,
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
            ))),
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
            Request::StartSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                session.start(Timestamp::now()).map_err(invalid_state)?;
                self.database
                    .save_session(&session)
                    .map_err(internal_error)?;
                Ok(Response::Session(session))
            }
            Request::PauseSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                session.pause().map_err(invalid_state)?;
                self.database
                    .save_session(&session)
                    .map_err(internal_error)?;
                Ok(Response::Session(session))
            }
            Request::ResumeSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                session.resume().map_err(invalid_state)?;
                self.database
                    .save_session(&session)
                    .map_err(internal_error)?;
                Ok(Response::Session(session))
            }
            Request::StopSession { session_id } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                let mut session = self.require_session(session_id)?;
                session.finish(Timestamp::now()).map_err(invalid_state)?;
                self.database
                    .save_session(&session)
                    .map_err(internal_error)?;
                Ok(Response::Session(session))
            }
            Request::SubmitText { session_id, text } => {
                let lock = Arc::clone(&self.session_state_lock);
                let _guard = lock.lock().map_err(|_| state_lock_error())?;
                self.submit_text(session_id, text)
            }
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
        let patterns = session
            .flag_patterns()
            .iter()
            .cloned()
            .map(FlagPattern::simple);
        let analyzer =
            Analyzer::new(AnalysisConfig::default(), patterns).map_err(internal_error)?;
        let report = analyzer.analyze(&event).map_err(internal_error)?;
        let finding_ids = self
            .database
            .persist_analysis(&event, &report)
            .map_err(internal_error)?;
        Ok(Response::Submission {
            event_id: event.id(),
            finding_ids,
        })
    }
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

fn summary_from_database(value: hunter_database::FindingSummary) -> FindingSummary {
    FindingSummary {
        id: value.id,
        session_id: value.session_id,
        value: value.value,
        confidence: value.confidence,
        discovered_at: value.discovered_at,
        occurrences: value.occurrences,
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

        let snapshot = statistics.snapshot(1, 4, 64);

        assert_eq!(snapshot.queue_depth, 7);
        assert_eq!(snapshot.rejected_connections, 3);
        assert_eq!(snapshot.worker_count, 4);
        assert_eq!(snapshot.queue_capacity, 64);
    }
}
