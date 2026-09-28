use std::{
    collections::{HashMap, HashSet},
    io,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use hunter_capture_protocol::{
    CaptureHealth, ClientMessage, ProtocolError, ServerMessage, read_server, write_client,
};
use hunter_types::SessionId;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use thiserror::Error;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_MAX_REGISTRATIONS: usize = 256;
pub const DEFAULT_COMMAND_CAPACITY: usize = 64;
pub const DEFAULT_RECONNECT_DELAY: Duration = Duration::from_millis(250);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub struct CaptureClientConfig {
    pub socket_path: PathBuf,
    pub max_registrations: usize,
    pub command_capacity: usize,
    pub reconnect_delay: Duration,
    pub io_timeout: Duration,
    pub expected_helper_uid: u32,
}

impl CaptureClientConfig {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_registrations: DEFAULT_MAX_REGISTRATIONS,
            command_capacity: DEFAULT_COMMAND_CAPACITY,
            reconnect_delay: DEFAULT_RECONNECT_DELAY,
            io_timeout: DEFAULT_IO_TIMEOUT,
            expected_helper_uid: 0,
        }
    }

    fn validate(&self) -> Result<(), CaptureClientError> {
        if !self.socket_path.is_absolute() {
            return Err(CaptureClientError::InvalidConfiguration(
                "capture helper socket path must be absolute",
            ));
        }
        if self.max_registrations == 0 || self.command_capacity == 0 {
            return Err(CaptureClientError::InvalidConfiguration(
                "capture client limits must be greater than zero",
            ));
        }
        if self.reconnect_delay.is_zero() || self.io_timeout.is_zero() {
            return Err(CaptureClientError::InvalidConfiguration(
                "capture client timing values must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CaptureRegistration {
    pub session_id: SessionId,
    pub terminal: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectedTerminalOutput {
    pub session_id: SessionId,
    pub terminal: PathBuf,
    pub pid: u32,
    pub uid: u32,
    pub requested_len: u32,
    pub truncated: bool,
    pub process_name: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureClientStatistics {
    pub configured_sources: usize,
    pub active_sources: usize,
    pub connected_sources: usize,
    pub connection_attempts: u64,
    pub reconnects: u64,
    pub events_received: u64,
    pub dropped_events: u64,
    pub protocol_errors: u64,
    pub helper_errors: u64,
    pub ring_dropped: u64,
    pub read_failed: u64,
    pub fail_closed: u64,
}

#[derive(Default)]
struct Statistics {
    configured_sources: AtomicUsize,
    active_sources: AtomicUsize,
    connected_sources: AtomicUsize,
    connection_attempts: AtomicU64,
    reconnects: AtomicU64,
    events_received: AtomicU64,
    dropped_events: AtomicU64,
    protocol_errors: AtomicU64,
    helper_errors: AtomicU64,
    ring_dropped: AtomicU64,
    read_failed: AtomicU64,
    fail_closed: AtomicU64,
}

impl Statistics {
    fn snapshot(&self) -> CaptureClientStatistics {
        CaptureClientStatistics {
            configured_sources: self.configured_sources.load(Ordering::Relaxed),
            active_sources: self.active_sources.load(Ordering::Relaxed),
            connected_sources: self.connected_sources.load(Ordering::Relaxed),
            connection_attempts: self.connection_attempts.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            events_received: self.events_received.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
            helper_errors: self.helper_errors.load(Ordering::Relaxed),
            ring_dropped: self.ring_dropped.load(Ordering::Relaxed),
            read_failed: self.read_failed.load(Ordering::Relaxed),
            fail_closed: self.fail_closed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Error)]
pub enum CaptureClientError {
    #[error("invalid capture client configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("capture source registration limit reached")]
    RegistrationLimit,
    #[error("capture terminal path must be absolute: {0}")]
    InvalidTerminal(PathBuf),
    #[error("capture client manager panicked")]
    ThreadPanicked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CaptureControlError {
    #[error("capture client command queue is full")]
    Busy,
    #[error("capture client is stopped")]
    Stopped,
    #[error("capture client rejected the command: {0}")]
    Rejected(String),
    #[error("capture client command timed out")]
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    Register(CaptureRegistration),
    Unregister(CaptureRegistration),
    SetSessionActive { session_id: SessionId, active: bool },
}

struct Command {
    action: Action,
    acknowledgement: SyncSender<Result<(), String>>,
}

#[derive(Clone)]
pub struct CaptureClientControl {
    commands: SyncSender<Command>,
}

impl CaptureClientControl {
    pub fn register(&self, registration: CaptureRegistration) -> Result<(), CaptureControlError> {
        self.execute(Action::Register(registration))
    }

    pub fn unregister(&self, registration: CaptureRegistration) -> Result<(), CaptureControlError> {
        self.execute(Action::Unregister(registration))
    }

    pub fn set_session_active(
        &self,
        session_id: SessionId,
        active: bool,
    ) -> Result<(), CaptureControlError> {
        self.execute(Action::SetSessionActive { session_id, active })
    }

    fn execute(&self, action: Action) -> Result<(), CaptureControlError> {
        let (acknowledgement, result) = mpsc::sync_channel(1);
        match self.commands.try_send(Command {
            action,
            acknowledgement,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return Err(CaptureControlError::Busy),
            Err(TrySendError::Disconnected(_)) => return Err(CaptureControlError::Stopped),
        }
        result
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|_| CaptureControlError::TimedOut)?
            .map_err(CaptureControlError::Rejected)
    }
}

#[derive(Clone)]
pub struct CaptureClientMetrics(Arc<Statistics>);

impl CaptureClientMetrics {
    #[must_use]
    pub fn snapshot(&self) -> CaptureClientStatistics {
        self.0.snapshot()
    }
}

pub struct CaptureClient {
    control: CaptureClientControl,
    metrics: CaptureClientMetrics,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), CaptureClientError>>>,
}

impl CaptureClient {
    pub fn start<F>(
        config: CaptureClientConfig,
        registrations: impl IntoIterator<Item = CaptureRegistration>,
        active_sessions: impl IntoIterator<Item = SessionId>,
        sink: F,
    ) -> Result<Self, CaptureClientError>
    where
        F: Fn(CollectedTerminalOutput) -> bool + Send + Sync + 'static,
    {
        config.validate()?;
        let statistics = Arc::new(Statistics::default());
        let sink = Arc::new(sink);
        let mut runtime = Runtime {
            config: config.clone(),
            registrations: HashSet::new(),
            active_sessions: active_sessions.into_iter().collect(),
            workers: HashMap::new(),
            statistics: Arc::clone(&statistics),
            sink,
        };
        for registration in registrations {
            runtime.register(registration)?;
        }
        runtime.reconcile();

        let (commands, receiver) = mpsc::sync_channel(config.command_capacity);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || runtime.run(receiver, worker_stopping));
        Ok(Self {
            control: CaptureClientControl { commands },
            metrics: CaptureClientMetrics(statistics),
            stopping,
            thread: Some(thread),
        })
    }

    #[must_use]
    pub fn control(&self) -> CaptureClientControl {
        self.control.clone()
    }

    #[must_use]
    pub fn metrics(&self) -> CaptureClientMetrics {
        self.metrics.clone()
    }

    pub fn shutdown(mut self) -> Result<CaptureClientStatistics, CaptureClientError> {
        self.stopping.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .expect("capture manager thread is present")
            .join()
            .map_err(|_| CaptureClientError::ThreadPanicked)??;
        Ok(self.metrics.snapshot())
    }
}

impl Drop for CaptureClient {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
    }
}

struct Runtime<F> {
    config: CaptureClientConfig,
    registrations: HashSet<CaptureRegistration>,
    active_sessions: HashSet<SessionId>,
    workers: HashMap<CaptureRegistration, SourceWorker>,
    statistics: Arc<Statistics>,
    sink: Arc<F>,
}

impl<F> Runtime<F>
where
    F: Fn(CollectedTerminalOutput) -> bool + Send + Sync + 'static,
{
    fn run(
        &mut self,
        commands: Receiver<Command>,
        stopping: Arc<AtomicBool>,
    ) -> Result<(), CaptureClientError> {
        while !stopping.load(Ordering::Relaxed) {
            match commands.recv_timeout(Duration::from_millis(20)) {
                Ok(command) => self.process(command),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            self.remove_finished();
        }
        self.stop_all();
        Ok(())
    }

    fn process(&mut self, command: Command) {
        let result = match command.action {
            Action::Register(registration) => self.register(registration),
            Action::Unregister(registration) => {
                self.registrations.remove(&registration);
                self.reconcile();
                Ok(())
            }
            Action::SetSessionActive { session_id, active } => {
                if active {
                    self.active_sessions.insert(session_id);
                } else {
                    self.active_sessions.remove(&session_id);
                }
                self.reconcile();
                Ok(())
            }
        }
        .map_err(|error| error.to_string());
        let _ = command.acknowledgement.try_send(result);
    }

    fn register(&mut self, registration: CaptureRegistration) -> Result<(), CaptureClientError> {
        if !registration.terminal.is_absolute() {
            return Err(CaptureClientError::InvalidTerminal(registration.terminal));
        }
        if !self.registrations.contains(&registration)
            && self.registrations.len() >= self.config.max_registrations
        {
            return Err(CaptureClientError::RegistrationLimit);
        }
        self.registrations.insert(registration);
        self.reconcile();
        Ok(())
    }

    fn reconcile(&mut self) {
        let desired = self
            .registrations
            .iter()
            .filter(|registration| self.active_sessions.contains(&registration.session_id))
            .cloned()
            .collect::<HashSet<_>>();
        let obsolete = self
            .workers
            .keys()
            .filter(|registration| !desired.contains(*registration))
            .cloned()
            .collect::<Vec<_>>();
        for registration in obsolete {
            if let Some(worker) = self.workers.remove(&registration) {
                worker.stop();
            }
        }
        let missing = desired
            .iter()
            .filter(|item| !self.workers.contains_key(*item))
            .cloned()
            .collect::<Vec<_>>();
        for registration in missing {
            self.workers.insert(
                registration.clone(),
                SourceWorker::start(
                    self.config.clone(),
                    registration.clone(),
                    Arc::clone(&self.statistics),
                    Arc::clone(&self.sink),
                ),
            );
        }
        self.statistics
            .configured_sources
            .store(self.registrations.len(), Ordering::Relaxed);
        self.statistics
            .active_sources
            .store(desired.len(), Ordering::Relaxed);
    }

    fn remove_finished(&mut self) {
        let finished = self
            .workers
            .iter()
            .filter(|(_, worker)| worker.thread.is_finished())
            .map(|(registration, _)| registration.clone())
            .collect::<Vec<_>>();
        for registration in finished {
            if let Some(worker) = self.workers.remove(&registration) {
                worker.stop();
            }
        }
        if !self.workers.is_empty() || !self.active_sessions.is_empty() {
            self.reconcile();
        }
    }

    fn stop_all(&mut self) {
        for (_, worker) in self.workers.drain() {
            worker.stop();
        }
        self.statistics.active_sources.store(0, Ordering::Relaxed);
    }
}

struct SourceWorker {
    running: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl SourceWorker {
    fn start<F>(
        config: CaptureClientConfig,
        registration: CaptureRegistration,
        statistics: Arc<Statistics>,
        sink: Arc<F>,
    ) -> Self
    where
        F: Fn(CollectedTerminalOutput) -> bool + Send + Sync + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let thread = thread::spawn(move || {
            source_loop(config, registration, statistics, sink, worker_running)
        });
        Self { running, thread }
    }

    fn stop(self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

fn source_loop<F>(
    config: CaptureClientConfig,
    registration: CaptureRegistration,
    statistics: Arc<Statistics>,
    sink: Arc<F>,
    running: Arc<AtomicBool>,
) where
    F: Fn(CollectedTerminalOutput) -> bool + Send + Sync + 'static,
{
    let mut has_been_ready = false;
    while running.load(Ordering::Relaxed) {
        statistics
            .connection_attempts
            .fetch_add(1, Ordering::Relaxed);
        let Ok(mut stream) = UnixStream::connect(&config.socket_path) else {
            interruptible_wait(&running, config.reconnect_delay);
            continue;
        };
        let authenticated = getsockopt(&stream, PeerCredentials)
            .is_ok_and(|credentials| credentials.uid() == config.expected_helper_uid);
        if !authenticated {
            statistics.helper_errors.fetch_add(1, Ordering::Relaxed);
            interruptible_wait(&running, config.reconnect_delay);
            continue;
        }
        if stream.set_read_timeout(Some(config.io_timeout)).is_err()
            || stream.set_write_timeout(Some(config.io_timeout)).is_err()
            || write_client(
                &mut stream,
                &ClientMessage::Start {
                    terminal: registration.terminal.to_string_lossy().into_owned(),
                },
            )
            .is_err()
        {
            interruptible_wait(&running, config.reconnect_delay);
            continue;
        }
        let mut previous_health = CaptureHealth::default();
        let mut ready = false;
        let mut connected = None;
        while running.load(Ordering::Relaxed) {
            match read_server(&mut stream) {
                Ok(ServerMessage::Ready) if !ready => {
                    if has_been_ready {
                        statistics.reconnects.fetch_add(1, Ordering::Relaxed);
                    }
                    has_been_ready = true;
                    ready = true;
                    connected = Some(ConnectedGuard::new(Arc::clone(&statistics)));
                }
                Ok(ServerMessage::Event(event)) if ready => {
                    statistics.events_received.fetch_add(1, Ordering::Relaxed);
                    let collected = CollectedTerminalOutput {
                        session_id: registration.session_id,
                        terminal: registration.terminal.clone(),
                        pid: event.pid,
                        uid: event.uid,
                        requested_len: event.requested_len,
                        truncated: event.truncated,
                        process_name: event.process_name,
                        payload: event.payload,
                    };
                    if !(sink)(collected) {
                        statistics.dropped_events.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(ServerMessage::Health(health)) if ready => {
                    add_delta(
                        &statistics.ring_dropped,
                        health.ring_dropped,
                        previous_health.ring_dropped,
                    );
                    add_delta(
                        &statistics.read_failed,
                        health.read_failed,
                        previous_health.read_failed,
                    );
                    add_delta(
                        &statistics.fail_closed,
                        health.fail_closed,
                        previous_health.fail_closed,
                    );
                    previous_health = health;
                }
                Ok(ServerMessage::Error { .. }) => {
                    statistics.helper_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Ok(_) => {
                    statistics.protocol_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(ProtocolError::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(ProtocolError::Io(_)) => break,
                Err(_) => {
                    statistics.protocol_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        if !running.load(Ordering::Relaxed) {
            let _ = write_client(&mut stream, &ClientMessage::Stop);
        }
        drop(connected);
        interruptible_wait(&running, config.reconnect_delay);
    }
}

fn add_delta(target: &AtomicU64, current: u64, previous: u64) {
    target.fetch_add(current.saturating_sub(previous), Ordering::Relaxed);
}

fn interruptible_wait(running: &AtomicBool, duration: Duration) {
    let slices = 10_u32;
    let slice = duration / slices;
    for _ in 0..slices {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        thread::sleep(slice);
    }
}

struct ConnectedGuard(Arc<Statistics>);

impl ConnectedGuard {
    fn new(statistics: Arc<Statistics>) -> Self {
        statistics.connected_sources.fetch_add(1, Ordering::Relaxed);
        Self(statistics)
    }
}

impl Drop for ConnectedGuard {
    fn drop(&mut self) {
        self.0.connected_sources.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixListener, sync::mpsc, time::Instant};

    use hunter_capture_protocol::{CapturedOutput, ServerMessage, read_client, write_server};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn receives_bounded_events_and_health_from_a_helper() {
        let directory = tempdir().expect("tempdir");
        let socket = directory.path().join("capture.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        let helper = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            assert!(matches!(
                read_client(&mut stream).expect("start"),
                ClientMessage::Start { terminal } if terminal == "/dev/pts/7"
            ));
            write_server(&mut stream, &ServerMessage::Ready).expect("ready");
            write_server(
                &mut stream,
                &ServerMessage::Event(CapturedOutput {
                    pid: 42,
                    uid: 1_000,
                    requested_len: 10,
                    truncated: false,
                    process_name: "printf".to_owned(),
                    payload: b"FLAG{ok}\n".to_vec(),
                }),
            )
            .expect("event");
            write_server(
                &mut stream,
                &ServerMessage::Health(CaptureHealth {
                    ring_dropped: 2,
                    ..CaptureHealth::default()
                }),
            )
            .expect("health");
            let _ = read_client(&mut stream);
        });

        let (events, received) = mpsc::sync_channel(1);
        let session_id = SessionId::generate();
        let registration = CaptureRegistration {
            session_id,
            terminal: PathBuf::from("/dev/pts/7"),
        };
        let mut config = CaptureClientConfig::new(&socket);
        config.expected_helper_uid = nix::unistd::geteuid().as_raw();
        let client = CaptureClient::start(config, [registration], [session_id], move |event| {
            events.try_send(event).is_ok()
        })
        .expect("client");
        let event = received
            .recv_timeout(Duration::from_secs(2))
            .expect("captured event");
        assert_eq!(event.payload, b"FLAG{ok}\n");
        assert_eq!(client.metrics().snapshot().connected_sources, 1);
        let deadline = Instant::now() + Duration::from_secs(2);
        while client.metrics().snapshot().ring_dropped != 2 {
            assert!(Instant::now() < deadline, "health was not received");
            thread::sleep(Duration::from_millis(10));
        }
        let statistics = client.shutdown().expect("shutdown");
        assert_eq!(statistics.events_received, 1);
        assert_eq!(statistics.ring_dropped, 2);
        helper.join().expect("helper");
    }

    #[test]
    fn reconnects_only_after_an_authenticated_ready_connection() {
        let directory = tempdir().expect("tempdir");
        let socket = directory.path().join("capture.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        let helper = thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                assert!(matches!(
                    read_client(&mut stream).expect("start"),
                    ClientMessage::Start { terminal } if terminal == "/dev/pts/8"
                ));
                write_server(&mut stream, &ServerMessage::Ready).expect("ready");
                if attempt == 1 {
                    write_server(
                        &mut stream,
                        &ServerMessage::Event(CapturedOutput {
                            pid: 43,
                            uid: 1_000,
                            requested_len: 9,
                            truncated: false,
                            process_name: "printf".to_owned(),
                            payload: b"FLAG{re}\n".to_vec(),
                        }),
                    )
                    .expect("event");
                    let _ = read_client(&mut stream);
                }
            }
        });

        let (events, received) = mpsc::sync_channel(1);
        let session_id = SessionId::generate();
        let mut config = CaptureClientConfig::new(&socket);
        config.expected_helper_uid = nix::unistd::geteuid().as_raw();
        config.reconnect_delay = Duration::from_millis(10);
        let client = CaptureClient::start(
            config,
            [CaptureRegistration {
                session_id,
                terminal: PathBuf::from("/dev/pts/8"),
            }],
            [session_id],
            move |event| events.try_send(event).is_ok(),
        )
        .expect("client");
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(2))
                .expect("reconnected event")
                .payload,
            b"FLAG{re}\n"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while client.metrics().snapshot().reconnects != 1 {
            assert!(Instant::now() < deadline, "reconnect was not recorded");
            thread::sleep(Duration::from_millis(10));
        }
        let statistics = client.shutdown().expect("shutdown");
        assert_eq!(statistics.connected_sources, 0);
        assert_eq!(statistics.reconnects, 1);
        helper.join().expect("helper");
    }

    #[test]
    fn rejects_relative_terminal_registrations() {
        let directory = tempdir().expect("tempdir");
        let client = CaptureClient::start(
            CaptureClientConfig::new(directory.path().join("capture.sock")),
            [],
            [],
            |_| true,
        )
        .expect("client");
        let error = client
            .control()
            .register(CaptureRegistration {
                session_id: SessionId::generate(),
                terminal: PathBuf::from("pts/7"),
            })
            .expect_err("relative terminal");
        assert!(matches!(error, CaptureControlError::Rejected(_)));
        client.shutdown().expect("shutdown");
    }

    #[test]
    fn rejects_a_helper_with_the_wrong_peer_uid() {
        let directory = tempdir().expect("tempdir");
        let socket = directory.path().join("capture.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        let helper = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
            assert!(read_client(&mut stream).is_err());
        });

        let session_id = SessionId::generate();
        let mut config = CaptureClientConfig::new(&socket);
        config.expected_helper_uid = nix::unistd::geteuid().as_raw().saturating_add(1);
        let client = CaptureClient::start(
            config,
            [CaptureRegistration {
                session_id,
                terminal: PathBuf::from("/dev/pts/9"),
            }],
            [session_id],
            |_| true,
        )
        .expect("client");
        let deadline = Instant::now() + Duration::from_secs(2);
        while client.metrics().snapshot().helper_errors == 0 {
            assert!(
                Instant::now() < deadline,
                "wrong helper UID was not rejected"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let statistics = client.shutdown().expect("shutdown");
        assert_eq!(statistics.events_received, 0);
        assert!(statistics.helper_errors >= 1);
        helper.join().expect("helper");
    }
}
