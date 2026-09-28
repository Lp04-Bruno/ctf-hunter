use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use ctf_hunter_common::{
    FLAG_TRUNCATED, STAT_BACKGROUND_FILTERED, STAT_EMITTED, STAT_FAIL_CLOSED,
    STAT_INITIAL_FILTERED, STAT_MAP_FAILED, STAT_PROCESS_FILTERED, STAT_READ_FAILED,
    STAT_READ_MARKED, STAT_RING_DROPPED, STAT_SEEN, STAT_STRUCTURE_FAILED, STAT_TAINT_FILTERED,
    STAT_TRUNCATED, STAT_TTY_FILTERED, STAT_UID_FILTERED,
};
use hunter_capture_protocol::{
    CaptureHealth, CapturedOutput, ClientMessage, ErrorCode, ProtocolError, ServerMessage,
    read_client, write_server,
};
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::geteuid,
};

use crate::{CaptureConfig, CaptureRuntime, CaptureStatistics, is_terminal_path, process_name};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const CONTROL_TIMEOUT: Duration = Duration::from_millis(250);
const HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_CONNECTIONS: usize = 32;

#[derive(Clone, Debug)]
pub struct CaptureServiceConfig {
    pub socket_path: PathBuf,
    pub max_connections: usize,
}

impl CaptureServiceConfig {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

pub fn serve(config: CaptureServiceConfig, terminating: Arc<AtomicBool>) -> Result<()> {
    if config.max_connections == 0 {
        bail!("maximum connection count must be greater than zero");
    }
    let listener = bind_socket(&config.socket_path)?;
    let _socket_guard = SocketGuard(config.socket_path.clone());
    listener.set_nonblocking(true)?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();

    while !terminating.load(Ordering::Relaxed) {
        reap_workers(&mut workers)?;
        match listener.accept() {
            Ok((mut stream, _)) => {
                if active.load(Ordering::Relaxed) >= config.max_connections {
                    let _ = write_server(
                        &mut stream,
                        &ServerMessage::Error {
                            code: ErrorCode::Busy,
                            message: "capture service connection limit reached".to_owned(),
                        },
                    );
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let active = Arc::clone(&active);
                let terminating = Arc::clone(&terminating);
                workers.push(thread::spawn(move || {
                    let _guard = ConnectionGuard(active);
                    if let Err(error) = handle_client(stream, terminating) {
                        eprintln!("capture client stopped: {error:#}");
                    }
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }

    for worker in workers {
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("capture worker panicked"))?;
    }
    Ok(())
}

fn reap_workers(workers: &mut Vec<thread::JoinHandle<()>>) -> Result<()> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            workers
                .swap_remove(index)
                .join()
                .map_err(|_| anyhow::anyhow!("capture worker panicked"))?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream, terminating: Arc<AtomicBool>) -> Result<()> {
    let credentials = getsockopt(&stream, PeerCredentials)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let peer_uid = credentials.uid();
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let terminal = match read_client(&mut stream) {
        Ok(ClientMessage::Start { terminal }) => terminal,
        Ok(ClientMessage::Stop) => {
            return send_error(
                &mut stream,
                ErrorCode::InvalidRequest,
                "first message must start capture",
            );
        }
        Err(error) => {
            return send_error(&mut stream, ErrorCode::InvalidRequest, &error.to_string());
        }
    };
    let terminal = validate_terminal(&terminal, peer_uid).inspect_err(|error| {
        let _ = send_error(&mut stream, ErrorCode::PermissionDenied, &error.to_string());
    })?;

    let mut runtime = match CaptureRuntime::load(&CaptureConfig {
        uid: peer_uid,
        terminals: vec![terminal],
    }) {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = send_error(
                &mut stream,
                ErrorCode::KernelUnsupported,
                &format!("capture initialization failed: {error:#}"),
            );
            return Err(error);
        }
    };

    write_server(&mut stream, &ServerMessage::Ready)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let control_stop = Arc::clone(&stopped);
    let mut control = stream.try_clone()?;
    control.set_read_timeout(Some(CONTROL_TIMEOUT))?;
    let control_thread = thread::spawn(move || control_loop(&mut control, &control_stop));
    let mut forwarded = 0_u64;
    let mut next_health = Instant::now() + HEALTH_INTERVAL;

    while !terminating.load(Ordering::Relaxed) && !stopped.load(Ordering::Relaxed) {
        let drained = runtime.drain(|event| {
            let message = ServerMessage::Event(CapturedOutput {
                pid: event.pid,
                uid: event.uid,
                requested_len: event.requested_len,
                truncated: event.flags & FLAG_TRUNCATED != 0,
                process_name: process_name(&event.comm).to_owned(),
                payload: event.payload().to_vec(),
            });
            write_server(&mut stream, &message)?;
            forwarded = forwarded.saturating_add(1);
            Ok::<_, ProtocolError>(())
        })?;
        if Instant::now() >= next_health {
            let health = health(runtime.statistics()?, forwarded);
            write_server(&mut stream, &ServerMessage::Health(health))?;
            next_health = Instant::now() + HEALTH_INTERVAL;
        }
        if drained == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }

    stopped.store(true, Ordering::Relaxed);
    control_thread
        .join()
        .map_err(|_| anyhow::anyhow!("capture control reader panicked"))?;
    let final_health = health(runtime.statistics()?, forwarded);
    let _ = write_server(&mut stream, &ServerMessage::Health(final_health));
    Ok(())
}

fn control_loop(stream: &mut UnixStream, stopped: &AtomicBool) {
    while !stopped.load(Ordering::Relaxed) {
        match read_client(stream) {
            Ok(ClientMessage::Stop) => {
                stopped.store(true, Ordering::Relaxed);
                return;
            }
            Ok(ClientMessage::Start { .. }) => {
                stopped.store(true, Ordering::Relaxed);
                return;
            }
            Err(ProtocolError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {
                stopped.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
}

fn validate_terminal(value: &str, peer_uid: u32) -> Result<PathBuf> {
    let path = fs::canonicalize(value).context("resolve selected terminal")?;
    if !is_terminal_path(&path) {
        bail!("selected path is not a supported terminal");
    }
    let metadata = fs::metadata(&path).context("inspect selected terminal")?;
    if !metadata.file_type().is_char_device() {
        bail!("selected path is not a character device");
    }
    if metadata.uid() != peer_uid {
        bail!("selected terminal is not owned by the requesting UID");
    }
    Ok(path)
}

fn health(statistics: CaptureStatistics, forwarded: u64) -> CaptureHealth {
    let counters = statistics.counters;
    CaptureHealth {
        seen: counters[STAT_SEEN as usize],
        emitted: counters[STAT_EMITTED as usize],
        forwarded,
        read_marked: counters[STAT_READ_MARKED as usize],
        taint_filtered: counters[STAT_TAINT_FILTERED as usize],
        initial_filtered: counters[STAT_INITIAL_FILTERED as usize],
        background_filtered: counters[STAT_BACKGROUND_FILTERED as usize],
        tty_filtered: counters[STAT_TTY_FILTERED as usize],
        uid_filtered: counters[STAT_UID_FILTERED as usize],
        process_filtered: counters[STAT_PROCESS_FILTERED as usize],
        structure_failed: counters[STAT_STRUCTURE_FAILED as usize],
        map_failed: counters[STAT_MAP_FAILED as usize],
        fail_closed: counters[STAT_FAIL_CLOSED as usize],
        ring_dropped: counters[STAT_RING_DROPPED as usize],
        read_failed: counters[STAT_READ_FAILED as usize],
        truncated: counters[STAT_TRUNCATED as usize],
        failure_reason: statistics.failure_reason,
    }
}

fn send_error(stream: &mut UnixStream, code: ErrorCode, message: &str) -> Result<()> {
    write_server(
        stream,
        &ServerMessage::Error {
            code,
            message: message.to_owned(),
        },
    )?;
    Ok(())
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    let directory = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("capture socket path has no parent"))?;
    fs::create_dir_all(directory).context("create capture runtime directory")?;
    let directory_metadata =
        fs::symlink_metadata(directory).context("inspect capture runtime directory")?;
    if !directory_metadata.is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.uid() != geteuid().as_raw()
    {
        bail!("capture runtime directory is unsafe");
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750))
        .context("restrict capture runtime directory")?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
            bail!("refusing to replace unsafe capture socket path");
        }
        match UnixStream::connect(path) {
            Ok(_) => bail!("capture service is already running"),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(path).context("remove stale capture socket")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let listener = UnixListener::bind(path).context("bind capture socket")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .context("restrict capture socket")?;
    Ok(listener)
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn rejects_non_terminal_capture_targets() {
        let error = validate_terminal("/dev/null", geteuid().as_raw()).expect_err("not a tty");
        assert!(error.to_string().contains("supported terminal"));
    }

    #[test]
    fn maps_health_counters_without_payload_data() {
        let mut counters = [0; ctf_hunter_common::STAT_COUNT as usize];
        counters[STAT_EMITTED as usize] = 3;
        counters[STAT_RING_DROPPED as usize] = 2;
        let health = health(
            CaptureStatistics {
                accepted: 3,
                counters,
                failure_reason: 7,
            },
            3,
        );
        assert_eq!(health.emitted, 3);
        assert_eq!(health.forwarded, 3);
        assert_eq!(health.ring_dropped, 2);
        assert_eq!(health.failure_reason, 7);
    }

    #[test]
    fn creates_a_restricted_socket_and_refuses_regular_files() {
        let directory = tempdir().expect("tempdir");
        let socket = directory.path().join("capture.sock");
        let listener = bind_socket(&socket).expect("bind socket");
        assert_eq!(
            fs::metadata(&socket)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        drop(listener);
        fs::remove_file(&socket).expect("remove socket");
        fs::write(&socket, b"do not replace").expect("regular file");
        assert!(bind_socket(&socket).is_err());
        assert_eq!(
            fs::read(&socket).expect("preserved file"),
            b"do not replace"
        );
    }
}
