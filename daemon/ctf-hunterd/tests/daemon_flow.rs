use std::{
    fs,
    io::Write as _,
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    sync::{Arc, Barrier, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use ctf_hunterd::{DaemonConfig, run};
use hunter_capture_client::CaptureClientConfig;
use hunter_capture_protocol::{
    CaptureHealth, CapturedOutput, ClientMessage, ServerMessage, read_client, write_server,
};
use hunter_database::Database;
use hunter_ipc::{
    ErrorCode, IpcClient, MAX_FRAME_BYTES, PROTOCOL_VERSION, Request, RequestEnvelope, Response,
    ResponseEnvelope, read_frame,
};
use hunter_types::{Session, SessionId, SourceMetadata, Timestamp};
use tempfile::tempdir;

fn start(config: DaemonConfig) -> thread::JoinHandle<Result<(), ctf_hunterd::DaemonError>> {
    let socket = config.socket_path.clone();
    let handle = thread::spawn(move || run(config, Arc::new(AtomicBool::new(false))));
    let deadline = Instant::now() + Duration::from_secs(15);
    while !socket.exists() {
        if handle.is_finished() {
            let result = handle.join().expect("daemon thread");
            panic!("daemon exited before creating its socket: {result:?}");
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not create its socket"
        );
        thread::sleep(Duration::from_millis(10));
    }
    handle
}

fn request(config: &DaemonConfig, request_id: u64, request: Request) -> Response {
    let response = IpcClient::request(
        &config.socket_path,
        &RequestEnvelope::new(request_id, request),
    )
    .expect("IPC response");
    assert_eq!(response.version, PROTOCOL_VERSION);
    assert_eq!(response.request_id, request_id);
    response.response
}

fn shutdown(
    config: &DaemonConfig,
    handle: thread::JoinHandle<Result<(), ctf_hunterd::DaemonError>>,
) {
    assert_eq!(
        request(config, 999, Request::Shutdown),
        Response::Acknowledged
    );
    handle.join().expect("daemon thread").expect("daemon exit");
    assert!(!config.socket_path.exists());
}

fn wait_for_findings(config: &DaemonConfig, session_id: hunter_types::SessionId, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = request(
            config,
            800,
            Request::ListFindings {
                session_id,
                offset: 0,
                limit: 20,
            },
        );
        if matches!(response, Response::Findings { ref findings } if findings.len() == count) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "finding count did not reach {count}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn analyzes_queries_and_recovers_findings_after_restart() {
    let directory = tempdir().expect("tempdir");
    let config = DaemonConfig::new(
        directory.path().join("data/hunter.db"),
        directory.path().join("runtime/daemon.sock"),
    );
    let handle = start(config.clone());

    assert_eq!(
        fs::metadata(config.socket_path.parent().expect("parent"))
            .expect("runtime metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&config.socket_path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&config.database_path)
            .expect("database metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let session = match request(
        &config,
        1,
        Request::CreateSession {
            name: "Restart test".to_owned(),
            flag_patterns: vec!["FLAG{*}".to_owned()],
        },
    ) {
        Response::Session(session) => session,
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(matches!(
        request(
            &config,
            2,
            Request::SubmitText {
                session_id: session.id(),
                text: "FLAG{too_early}".to_owned(),
            }
        ),
        Response::Error {
            code: ErrorCode::InvalidState,
            ..
        }
    ));
    assert!(matches!(
        request(
            &config,
            3,
            Request::StartSession {
                session_id: session.id()
            }
        ),
        Response::Session(_)
    ));
    let finding_id = match request(
        &config,
        4,
        Request::SubmitText {
            session_id: session.id(),
            text: r#"{"profile":{"payload":"RkxBR3twZXJzaXN0ZWR9"}}"#.to_owned(),
        },
    ) {
        Response::Submission { finding_ids, .. } => {
            assert_eq!(finding_ids.len(), 1);
            finding_ids[0]
        }
        other => panic!("unexpected response: {other:?}"),
    };
    match request(&config, 5, Request::GetFinding { finding_id }) {
        Response::Finding {
            finding: Some(finding),
        } => {
            assert_eq!(finding.summary.value, "FLAG{persisted}");
            assert_eq!(finding.occurrences[0].path.to_string(), "profile.payload");
            assert_eq!(finding.occurrences[0].transformations[0].name, "base64");
        }
        other => panic!("unexpected response: {other:?}"),
    }
    match request(&config, 6, Request::GetStatus) {
        Response::Status(status) => {
            assert_eq!(status.schema_version, 3);
            assert_eq!(status.worker_count, 4);
            assert_eq!(status.queue_capacity, 64);
            assert!(status.completed_requests >= 3);
            assert!(status.failed_requests >= 1);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown(&config, handle);

    let restarted = start(config.clone());
    match request(
        &config,
        7,
        Request::ListFindings {
            session_id: session.id(),
            offset: 0,
            limit: 10,
        },
    ) {
        Response::Findings { findings } => {
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, finding_id);
            assert_eq!(findings[0].value, "FLAG{persisted}");
        }
        other => panic!("unexpected response: {other:?}"),
    }
    shutdown(&config, restarted);
}

#[test]
fn watches_files_by_content_and_restores_watches_after_restart() {
    let directory = tempdir().expect("tempdir");
    let watched = directory.path().join("watched");
    fs::create_dir(&watched).expect("watch directory");
    let config = DaemonConfig::new(
        directory.path().join("data/hunter.db"),
        directory.path().join("runtime/daemon.sock"),
    );
    let daemon = start(config.clone());
    let session = match request(
        &config,
        100,
        Request::CreateSession {
            name: "File watch test".to_owned(),
            flag_patterns: vec!["FLAG{*}".to_owned()],
        },
    ) {
        Response::Session(session) => session,
        other => panic!("unexpected response: {other:?}"),
    };
    let watched_text = watched.to_str().expect("UTF-8 path").to_owned();
    assert_eq!(
        request(
            &config,
            101,
            Request::AddWatchDirectory {
                session_id: session.id(),
                directory: watched_text.clone(),
            },
        ),
        Response::WatchDirectories {
            session_id: session.id(),
            directories: vec![watched_text.clone()],
        }
    );
    assert!(matches!(
        request(
            &config,
            102,
            Request::StartSession {
                session_id: session.id(),
            },
        ),
        Response::Session(_)
    ));

    let first_path = watched.join("response.unknown");
    fs::write(
        &first_path,
        br#"{"profile":{"payload":"RkxBR3tmaWxlX3dhdGNoZWR9"}}"#,
    )
    .expect("write first file");
    wait_for_findings(&config, session.id(), 1);
    thread::sleep(Duration::from_millis(250));
    wait_for_findings(&config, session.id(), 1);
    shutdown(&config, daemon);

    let restarted = start(config.clone());
    assert_eq!(
        request(
            &config,
            103,
            Request::ListWatchDirectories {
                session_id: session.id(),
            },
        ),
        Response::WatchDirectories {
            session_id: session.id(),
            directories: vec![watched_text.clone()],
        }
    );
    let second_path = watched.join("renamed.bin");
    let staged = directory.path().join("staged.bin");
    fs::write(&staged, b"RkxBR3thZnRlcl9yZXN1bWV9").expect("stage file");
    fs::rename(staged, &second_path).expect("move file into watch");
    wait_for_findings(&config, session.id(), 2);

    let findings = match request(
        &config,
        104,
        Request::ListFindings {
            session_id: session.id(),
            offset: 0,
            limit: 20,
        },
    ) {
        Response::Findings { findings } => findings,
        other => panic!("unexpected response: {other:?}"),
    };
    let finding = findings
        .iter()
        .find(|finding| finding.value == "FLAG{after_resume}")
        .expect("file finding");
    match request(
        &config,
        105,
        Request::GetFinding {
            finding_id: finding.id,
        },
    ) {
        Response::Finding {
            finding: Some(detail),
        } => match &detail.occurrences[0].source {
            SourceMetadata::File(source) => assert_eq!(source.path(), second_path),
            other => panic!("unexpected source: {other:?}"),
        },
        other => panic!("unexpected response: {other:?}"),
    }
    match request(&config, 106, Request::GetStatus) {
        Response::Status(status) => {
            assert!(status.file_collector.files_read >= 1);
            assert!(status.file_collector.analyzed_files >= 1);
            assert_eq!(status.file_collector.analysis_errors, 0);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    assert_eq!(
        request(
            &config,
            107,
            Request::RemoveWatchDirectory {
                session_id: session.id(),
                directory: watched_text,
            },
        ),
        Response::WatchDirectories {
            session_id: session.id(),
            directories: Vec::new(),
        }
    );
    fs::write(watched.join("ignored.txt"), b"FLAG{ignored}").expect("write ignored file");
    thread::sleep(Duration::from_millis(250));
    wait_for_findings(&config, session.id(), 2);
    shutdown(&config, restarted);
}

#[test]
fn activates_a_watch_added_to_a_restored_monitoring_session() {
    let directory = tempdir().expect("tempdir");
    let watched = directory.path().join("watched");
    fs::create_dir(&watched).expect("watch directory");
    let config = DaemonConfig::new(
        directory.path().join("data/hunter.db"),
        directory.path().join("runtime/daemon.sock"),
    );
    let daemon = start(config.clone());
    let session = match request(
        &config,
        150,
        Request::CreateSession {
            name: "Late watch test".to_owned(),
            flag_patterns: vec!["FLAG{*}".to_owned()],
        },
    ) {
        Response::Session(session) => session,
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(matches!(
        request(
            &config,
            151,
            Request::StartSession {
                session_id: session.id(),
            },
        ),
        Response::Session(_)
    ));
    shutdown(&config, daemon);

    let restarted = start(config.clone());
    assert!(matches!(
        request(
            &config,
            152,
            Request::AddWatchDirectory {
                session_id: session.id(),
                directory: watched.to_str().expect("UTF-8 path").to_owned(),
            },
        ),
        Response::WatchDirectories { .. }
    ));
    fs::write(watched.join("late.bin"), b"FLAG{late_watch}").expect("watched file");
    wait_for_findings(&config, session.id(), 1);
    shutdown(&config, restarted);
}

#[test]
fn analyzes_capture_events_from_the_privileged_helper_channel() {
    let directory = tempdir().expect("tempdir");
    let capture_socket = directory.path().join("capture.sock");
    let listener = UnixListener::bind(&capture_socket).expect("capture listener");
    let helper = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("capture connection");
        assert!(matches!(
            read_client(&mut stream).expect("capture start"),
            ClientMessage::Start { terminal } if terminal == "/dev/pts/7"
        ));
        write_server(&mut stream, &ServerMessage::Ready).expect("ready");
        write_server(
            &mut stream,
            &ServerMessage::Event(CapturedOutput {
                pid: 4242,
                uid: nix::unistd::geteuid().as_raw(),
                requested_len: 24,
                truncated: false,
                process_name: "challenge".to_owned(),
                payload: b"RkxBR3t0ZXJtaW5hbF9pcGN9".to_vec(),
            }),
        )
        .expect("event");
        write_server(
            &mut stream,
            &ServerMessage::Health(CaptureHealth::default()),
        )
        .expect("health");
        assert_eq!(read_client(&mut stream).expect("stop"), ClientMessage::Stop);
    });

    let database_path = directory.path().join("data/hunter.db");
    fs::create_dir_all(database_path.parent().expect("database parent"))
        .expect("database directory");
    let session_id = SessionId::generate();
    let mut session = Session::new(session_id, "Terminal IPC", Timestamp::now()).expect("session");
    session
        .set_flag_patterns(vec!["FLAG{*}".to_owned()])
        .expect("patterns");
    session.start(Timestamp::now()).expect("start");
    {
        let mut database = Database::open(&database_path).expect("database");
        database.save_session(&session).expect("save session");
        database
            .add_terminal(session_id, std::path::Path::new("/dev/pts/7"))
            .expect("terminal registration");
    }

    let mut config =
        DaemonConfig::new(&database_path, directory.path().join("runtime/daemon.sock"));
    config.capture_client = CaptureClientConfig::new(&capture_socket);
    config.capture_client.expected_helper_uid = nix::unistd::geteuid().as_raw();
    let daemon = start(config.clone());
    wait_for_findings(&config, session_id, 1);

    let findings = match request(
        &config,
        901,
        Request::ListFindings {
            session_id,
            offset: 0,
            limit: 10,
        },
    ) {
        Response::Findings { findings } => findings,
        other => panic!("unexpected response: {other:?}"),
    };
    assert_eq!(findings[0].value, "FLAG{terminal_ipc}");
    match request(
        &config,
        902,
        Request::GetFinding {
            finding_id: findings[0].id,
        },
    ) {
        Response::Finding {
            finding: Some(detail),
        } => match &detail.occurrences[0].source {
            SourceMetadata::Terminal(source) => {
                assert_eq!(source.process_id(), 4242);
                assert_eq!(source.process_name(), "challenge");
                assert_eq!(source.file_descriptor(), None);
                assert_eq!(source.tty(), std::path::Path::new("/dev/pts/7"));
            }
            other => panic!("unexpected source: {other:?}"),
        },
        other => panic!("unexpected response: {other:?}"),
    }
    match request(&config, 903, Request::GetStatus) {
        Response::Status(status) => {
            assert_eq!(status.capture.configured_sources, 1);
            assert_eq!(status.capture.active_sources, 1);
            assert_eq!(status.capture.events_received, 1);
            assert_eq!(status.capture.events_analyzed, 1);
            assert_eq!(status.capture.analysis_errors, 0);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    assert_eq!(
        request(&config, 904, Request::ListTerminals { session_id },),
        Response::Terminals {
            session_id,
            terminals: vec!["/dev/pts/7".to_owned()],
        }
    );
    assert!(matches!(
        request(&config, 905, Request::PauseSession { session_id }),
        Response::Session(_)
    ));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match request(&config, 906, Request::GetStatus) {
            Response::Status(status)
                if status.capture.active_sources == 0 && status.capture.connected_sources == 0 =>
            {
                break;
            }
            Response::Status(_) => {}
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(Instant::now() < deadline, "capture source did not stop");
        thread::sleep(Duration::from_millis(10));
    }
    helper.join().expect("helper");
    shutdown(&config, daemon);
}

#[test]
fn rejects_malformed_oversized_and_unsupported_requests_without_stopping() {
    let directory = tempdir().expect("tempdir");
    let config = DaemonConfig::new(
        directory.path().join("data/hunter.db"),
        directory.path().join("runtime/daemon.sock"),
    );
    let handle = start(config.clone());

    let mut malformed = UnixStream::connect(&config.socket_path).expect("connect");
    malformed.write_all(&1_u32.to_be_bytes()).expect("header");
    malformed.write_all(b"{").expect("payload");
    assert!(matches!(
        read_frame::<ResponseEnvelope>(&mut malformed)
            .expect("response")
            .response,
        Response::Error {
            code: ErrorCode::InvalidFrame,
            ..
        }
    ));

    let mut oversized = UnixStream::connect(&config.socket_path).expect("connect");
    oversized
        .write_all(
            &u32::try_from(MAX_FRAME_BYTES + 1)
                .expect("length")
                .to_be_bytes(),
        )
        .expect("header");
    assert!(matches!(
        read_frame::<ResponseEnvelope>(&mut oversized)
            .expect("response")
            .response,
        Response::Error {
            code: ErrorCode::InvalidFrame,
            ..
        }
    ));

    let mut wrong_version = RequestEnvelope::new(77, Request::GetStatus);
    wrong_version.version += 1;
    assert!(matches!(
        IpcClient::request(&config.socket_path, &wrong_version)
            .expect("response")
            .response,
        Response::Error {
            code: ErrorCode::UnsupportedVersion,
            ..
        }
    ));
    assert!(matches!(
        request(&config, 78, Request::GetStatus),
        Response::Status(_)
    ));
    shutdown(&config, handle);
}

#[test]
fn serializes_conflicting_session_transitions() {
    let directory = tempdir().expect("tempdir");
    let config = DaemonConfig::new(
        directory.path().join("data/hunter.db"),
        directory.path().join("runtime/daemon.sock"),
    );
    let daemon = start(config.clone());
    let session = match request(
        &config,
        1,
        Request::CreateSession {
            name: "Concurrency test".to_owned(),
            flag_patterns: vec!["FLAG{*}".to_owned()],
        },
    ) {
        Response::Session(session) => session,
        other => panic!("unexpected response: {other:?}"),
    };

    let session_id = session.id();
    let barrier = Arc::new(Barrier::new(3));
    let requests = [2, 3].map(|request_id| {
        let config = config.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            request(&config, request_id, Request::StartSession { session_id })
        })
    });
    barrier.wait();
    let responses = requests.map(|thread| thread.join().expect("request thread"));

    assert_eq!(
        responses
            .iter()
            .filter(|response| matches!(response, Response::Session(_)))
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| matches!(
                response,
                Response::Error {
                    code: ErrorCode::InvalidState,
                    ..
                }
            ))
            .count(),
        1
    );
    shutdown(&config, daemon);
}
