use std::{
    env, fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use hunter_ipc::{
    AnalysisPreview, DaemonStatus, FindingDetail, FindingSummary, IpcClient, Request,
    RequestEnvelope, Response,
};
use hunter_types::{EventId, FindingId, NotificationSettings, Session, SessionId};
use nix::unistd::{Group, User, getegid, geteuid, getgroups};
use serde::Serialize;
use tauri::State;

const CAPTURE_GROUP: &str = "ctf-hunter";
const CAPTURE_HELPER: &str = "/usr/libexec/ctf-hunter-capture";
const CAPTURE_SETUP_HELPER: &str = "/usr/libexec/ctf-hunter-enable-capture";
const CAPTURE_UNIT: &str = "ctf-hunter-capture.service";
const DAEMON_BINARY: &str = "/usr/bin/ctf-hunterd";
const DAEMON_UNIT_FILE: &str = "/usr/lib/systemd/user/ctf-hunterd.service";
const DAEMON_UNIT: &str = "ctf-hunterd.service";
const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";
const PKEXEC: &str = "/usr/bin/pkexec";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

struct AppState {
    socket_path: PathBuf,
    next_request_id: AtomicU64,
}

impl AppState {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            next_request_id: AtomicU64::new(1),
        }
    }
}

#[derive(Serialize)]
struct Sources {
    directories: Vec<String>,
    terminals: Vec<String>,
}

#[derive(Serialize)]
struct Submission {
    event_id: EventId,
    finding_ids: Vec<FindingId>,
}

#[derive(Debug, Serialize)]
struct HealthCheck {
    status: &'static str,
    title: &'static str,
    detail: String,
    recovery_command: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct RuntimeDiagnostics {
    user_daemon: HealthCheck,
    capture_service: HealthCheck,
    kernel_btf: HealthCheck,
    terminal_access: HealthCheck,
    group_exists: bool,
    account_in_group: bool,
    session_has_group: bool,
    requires_new_login: bool,
    setup_available: bool,
    terminal_capture_ready: bool,
}

async fn send(state: &AppState, request: Request) -> Result<Response, String> {
    let socket_path = state.socket_path.clone();
    let request_id = state.next_request_id.fetch_add(1, Ordering::Relaxed);
    tauri::async_runtime::spawn_blocking(move || {
        let envelope = RequestEnvelope::new(request_id, request);
        let response =
            IpcClient::request(socket_path, &envelope).map_err(|error| error.to_string())?;
        if response.request_id != request_id {
            return Err("daemon returned a mismatched request identifier".to_owned());
        }
        match response.response {
            Response::Error { message, .. } => Err(message),
            response => Ok(response),
        }
    })
    .await
    .map_err(|error| format!("IPC task failed: {error}"))?
}

#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatus, String> {
    match send(&state, Request::GetStatus).await? {
        Response::Status(status) => Ok(status),
        _ => Err("daemon returned an unexpected status response".to_owned()),
    }
}

#[tauri::command]
async fn notification_settings(state: State<'_, AppState>) -> Result<NotificationSettings, String> {
    match send(&state, Request::GetNotificationSettings).await? {
        Response::NotificationSettings(settings) => Ok(settings),
        _ => Err("daemon returned an unexpected notification-settings response".to_owned()),
    }
}

#[tauri::command]
async fn update_notification_settings(
    state: State<'_, AppState>,
    settings: NotificationSettings,
) -> Result<NotificationSettings, String> {
    match send(&state, Request::UpdateNotificationSettings { settings }).await? {
        Response::NotificationSettings(settings) => Ok(settings),
        _ => Err("daemon returned an unexpected notification-settings response".to_owned()),
    }
}

#[tauri::command]
async fn list_sessions(state: State<'_, AppState>) -> Result<Vec<Session>, String> {
    match send(&state, Request::ListSessions).await? {
        Response::Sessions { sessions } => Ok(sessions),
        _ => Err("daemon returned an unexpected session list response".to_owned()),
    }
}

#[tauri::command]
async fn create_session(
    state: State<'_, AppState>,
    name: String,
    flag_patterns: Vec<String>,
) -> Result<Session, String> {
    match send(
        &state,
        Request::CreateSession {
            name,
            flag_patterns,
        },
    )
    .await?
    {
        Response::Session(session) => Ok(session),
        _ => Err("daemon returned an unexpected create-session response".to_owned()),
    }
}

#[tauri::command]
async fn update_session(
    state: State<'_, AppState>,
    session_id: SessionId,
    name: String,
    flag_patterns: Vec<String>,
) -> Result<Session, String> {
    match send(
        &state,
        Request::UpdateSession {
            session_id,
            name,
            flag_patterns,
        },
    )
    .await?
    {
        Response::Session(session) => Ok(session),
        _ => Err("daemon returned an unexpected update-session response".to_owned()),
    }
}

#[tauri::command]
async fn transition_session(
    state: State<'_, AppState>,
    session_id: SessionId,
    action: String,
) -> Result<Session, String> {
    let request = match action.as_str() {
        "start" => Request::StartSession { session_id },
        "pause" => Request::PauseSession { session_id },
        "resume" => Request::ResumeSession { session_id },
        "stop" => Request::StopSession { session_id },
        _ => return Err("unsupported session action".to_owned()),
    };
    match send(&state, request).await? {
        Response::Session(session) => Ok(session),
        _ => Err("daemon returned an unexpected session transition response".to_owned()),
    }
}

#[tauri::command]
async fn list_sources(
    state: State<'_, AppState>,
    session_id: SessionId,
) -> Result<Sources, String> {
    let directories = match send(&state, Request::ListWatchDirectories { session_id }).await? {
        Response::WatchDirectories { directories, .. } => directories,
        _ => return Err("daemon returned an unexpected directory response".to_owned()),
    };
    let terminals = match send(&state, Request::ListTerminals { session_id }).await? {
        Response::Terminals { terminals, .. } => terminals,
        _ => return Err("daemon returned an unexpected terminal response".to_owned()),
    };
    Ok(Sources {
        directories,
        terminals,
    })
}

#[tauri::command]
async fn add_source(
    state: State<'_, AppState>,
    session_id: SessionId,
    kind: String,
    path: String,
) -> Result<Vec<String>, String> {
    let request = match kind.as_str() {
        "directory" => Request::AddWatchDirectory {
            session_id,
            directory: path,
        },
        "terminal" => Request::AddTerminal {
            session_id,
            terminal: path,
        },
        _ => return Err("unsupported source kind".to_owned()),
    };
    match send(&state, request).await? {
        Response::WatchDirectories { directories, .. } => Ok(directories),
        Response::Terminals { terminals, .. } => Ok(terminals),
        _ => Err("daemon returned an unexpected add-source response".to_owned()),
    }
}

#[tauri::command]
async fn remove_source(
    state: State<'_, AppState>,
    session_id: SessionId,
    kind: String,
    path: String,
) -> Result<Vec<String>, String> {
    let request = match kind.as_str() {
        "directory" => Request::RemoveWatchDirectory {
            session_id,
            directory: path,
        },
        "terminal" => Request::RemoveTerminal {
            session_id,
            terminal: path,
        },
        _ => return Err("unsupported source kind".to_owned()),
    };
    match send(&state, request).await? {
        Response::WatchDirectories { directories, .. } => Ok(directories),
        Response::Terminals { terminals, .. } => Ok(terminals),
        _ => Err("daemon returned an unexpected remove-source response".to_owned()),
    }
}

#[tauri::command]
async fn list_findings(
    state: State<'_, AppState>,
    session_id: SessionId,
    offset: usize,
    limit: usize,
) -> Result<Vec<FindingSummary>, String> {
    match send(
        &state,
        Request::ListFindings {
            session_id,
            offset,
            limit,
        },
    )
    .await?
    {
        Response::Findings { findings } => Ok(findings),
        _ => Err("daemon returned an unexpected findings response".to_owned()),
    }
}

#[tauri::command]
async fn get_finding(
    state: State<'_, AppState>,
    finding_id: FindingId,
) -> Result<Option<FindingDetail>, String> {
    match send(&state, Request::GetFinding { finding_id }).await? {
        Response::Finding { finding } => Ok(finding),
        _ => Err("daemon returned an unexpected finding response".to_owned()),
    }
}

#[tauri::command]
async fn preview_text(
    state: State<'_, AppState>,
    session_id: SessionId,
    text: String,
) -> Result<AnalysisPreview, String> {
    match send(&state, Request::PreviewText { session_id, text }).await? {
        Response::AnalysisPreview(preview) => Ok(preview),
        _ => Err("daemon returned an unexpected decoder response".to_owned()),
    }
}

#[tauri::command]
async fn submit_text(
    state: State<'_, AppState>,
    session_id: SessionId,
    text: String,
) -> Result<Submission, String> {
    match send(&state, Request::SubmitText { session_id, text }).await? {
        Response::Submission {
            event_id,
            finding_ids,
        } => Ok(Submission {
            event_id,
            finding_ids,
        }),
        _ => Err("daemon returned an unexpected submission response".to_owned()),
    }
}

fn command_output(program: &str, arguments: &[&str]) -> Option<Output> {
    Command::new(program).args(arguments).output().ok()
}

fn command_succeeds(program: &str, arguments: &[&str]) -> bool {
    command_output(program, arguments).is_some_and(|output| output.status.success())
}

fn installed_executable(path: &str) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn socket_exists(path: &std::path::Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

fn current_group_access() -> (bool, bool, bool) {
    let group = Group::from_name(CAPTURE_GROUP).ok().flatten();
    let Some(group) = group else {
        return (false, false, false);
    };

    let uid = geteuid();
    let user = User::from_uid(uid).ok().flatten();
    let account_in_group = user
        .as_ref()
        .is_some_and(|user| user.gid == group.gid || group.mem.contains(&user.name));
    let session_has_group =
        getegid() == group.gid || getgroups().is_ok_and(|groups| groups.contains(&group.gid));
    (true, account_in_group, session_has_group)
}

fn abbreviated_error(output: &Output) -> String {
    let message = String::from_utf8_lossy(&output.stderr);
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if message.is_empty() {
        format!("exited with {}", output.status)
    } else {
        message.chars().take(240).collect()
    }
}

fn collect_diagnostics(socket_path: &std::path::Path) -> RuntimeDiagnostics {
    let daemon_socket_ready = socket_exists(socket_path);
    let daemon_active =
        command_succeeds(SYSTEMCTL, &["--user", "is-active", "--quiet", DAEMON_UNIT]);
    let user_daemon = if daemon_socket_ready {
        HealthCheck {
            status: "ready",
            title: "Analysis daemon",
            detail: "The private per-user socket is available.".to_owned(),
            recovery_command: None,
        }
    } else if daemon_active {
        HealthCheck {
            status: "attention",
            title: "Analysis daemon",
            detail: "The user service is active, but its socket is not available yet.".to_owned(),
            recovery_command: Some("systemctl --user restart ctf-hunterd.service"),
        }
    } else {
        HealthCheck {
            status: "unavailable",
            title: "Analysis daemon",
            detail: "The per-user service is not running. Stored findings remain untouched."
                .to_owned(),
            recovery_command: Some("systemctl --user enable --now ctf-hunterd.service"),
        }
    };

    let helper_installed = installed_executable(CAPTURE_HELPER);
    let capture_active = command_succeeds(SYSTEMCTL, &["is-active", "--quiet", CAPTURE_UNIT]);
    let capture_service = if helper_installed && capture_active {
        HealthCheck {
            status: "ready",
            title: "Capture helper",
            detail: "The hardened system service is active with its limited capabilities."
                .to_owned(),
            recovery_command: None,
        }
    } else if !helper_installed {
        HealthCheck {
            status: "unavailable",
            title: "Capture helper",
            detail: "The privileged helper is not installed at the expected package path."
                .to_owned(),
            recovery_command: Some("sudo apt install --reinstall ctf-hunter"),
        }
    } else {
        HealthCheck {
            status: "unavailable",
            title: "Capture helper",
            detail: "The privileged system service is installed but not active.".to_owned(),
            recovery_command: Some("sudo systemctl enable --now ctf-hunter-capture.service"),
        }
    };

    let btf_path = std::path::Path::new(KERNEL_BTF);
    let kernel_btf = if !btf_path.is_file() {
        HealthCheck {
            status: "unavailable",
            title: "Kernel compatibility",
            detail: "The running kernel does not expose /sys/kernel/btf/vmlinux. File and manual analysis still work.".to_owned(),
            recovery_command: None,
        }
    } else if !helper_installed {
        HealthCheck {
            status: "attention",
            title: "Kernel compatibility",
            detail: "Kernel BTF exists, but compatibility cannot be checked until the helper is installed."
                .to_owned(),
            recovery_command: Some("sudo apt install --reinstall ctf-hunter"),
        }
    } else {
        match command_output(CAPTURE_HELPER, &["preflight"]) {
            Some(output) if output.status.success() => HealthCheck {
                status: "ready",
                title: "Kernel compatibility",
                detail: "Kernel BTF and required terminal hooks are compatible.".to_owned(),
                recovery_command: None,
            },
            Some(output) => HealthCheck {
                status: "unavailable",
                title: "Kernel compatibility",
                detail: format!(
                    "The capture preflight rejected this kernel: {}",
                    abbreviated_error(&output)
                ),
                recovery_command: None,
            },
            None => HealthCheck {
                status: "unavailable",
                title: "Kernel compatibility",
                detail: "The installed capture preflight could not be started.".to_owned(),
                recovery_command: Some("sudo apt install --reinstall ctf-hunter"),
            },
        }
    };

    let (group_exists, account_in_group, session_has_group) = current_group_access();
    let requires_new_login = account_in_group && !session_has_group;
    let terminal_access = if session_has_group {
        HealthCheck {
            status: "ready",
            title: "Terminal access",
            detail: "This login session can access the capture service.".to_owned(),
            recovery_command: None,
        }
    } else if requires_new_login {
        HealthCheck {
            status: "pending",
            title: "Terminal access",
            detail: "Access is enabled for your account. Sign out completely and sign back in once to activate it."
                .to_owned(),
            recovery_command: None,
        }
    } else if group_exists {
        HealthCheck {
            status: "attention",
            title: "Terminal access",
            detail: "Terminal capture is off for this account. Enabling it requires one administrator confirmation."
                .to_owned(),
            recovery_command: Some("sudo usermod -aG ctf-hunter \"$USER\""),
        }
    } else {
        HealthCheck {
            status: "unavailable",
            title: "Terminal access",
            detail: "The package-created ctf-hunter group is missing.".to_owned(),
            recovery_command: Some("sudo apt install --reinstall ctf-hunter"),
        }
    };

    let setup_available = group_exists
        && !account_in_group
        && !session_has_group
        && installed_executable(CAPTURE_SETUP_HELPER)
        && installed_executable(PKEXEC);
    let terminal_capture_ready =
        session_has_group && helper_installed && capture_active && kernel_btf.status == "ready";

    RuntimeDiagnostics {
        user_daemon,
        capture_service,
        kernel_btf,
        terminal_access,
        group_exists,
        account_in_group,
        session_has_group,
        requires_new_login,
        setup_available,
        terminal_capture_ready,
    }
}

fn start_packaged_user_daemon(socket_path: &std::path::Path) {
    if env::var_os("CTF_HUNTER_SOCKET").is_some()
        || socket_exists(socket_path)
        || !std::path::Path::new(DAEMON_UNIT_FILE).is_file()
        || !installed_executable(DAEMON_BINARY)
    {
        return;
    }

    if !command_succeeds(SYSTEMCTL, &["--user", "start", DAEMON_UNIT]) {
        let _ = command_succeeds(SYSTEMCTL, &["--user", "daemon-reload"]);
        let _ = command_succeeds(SYSTEMCTL, &["--user", "start", DAEMON_UNIT]);
    }
    for _ in 0..10 {
        if socket_exists(socket_path) {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[tauri::command]
async fn bootstrap_runtime(state: State<'_, AppState>) -> Result<RuntimeDiagnostics, String> {
    let socket_path = state.socket_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        start_packaged_user_daemon(&socket_path);
        collect_diagnostics(&socket_path)
    })
    .await
    .map_err(|error| format!("runtime diagnostic task failed: {error}"))
}

#[tauri::command]
async fn runtime_diagnostics(state: State<'_, AppState>) -> Result<RuntimeDiagnostics, String> {
    let socket_path = state.socket_path.clone();
    tauri::async_runtime::spawn_blocking(move || collect_diagnostics(&socket_path))
        .await
        .map_err(|error| format!("runtime diagnostic task failed: {error}"))
}

#[tauri::command]
async fn enable_terminal_capture(state: State<'_, AppState>) -> Result<RuntimeDiagnostics, String> {
    let socket_path = state.socket_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if !installed_executable(PKEXEC) || !installed_executable(CAPTURE_SETUP_HELPER) {
            return Err(
                "The guided setup helper is unavailable. Use the recovery command shown in Settings."
                    .to_owned(),
            );
        }
        let output = command_output(PKEXEC, &[CAPTURE_SETUP_HELPER])
            .ok_or_else(|| "could not open the administrator authorization dialog".to_owned())?;
        if !output.status.success() {
            return Err(if matches!(output.status.code(), Some(126 | 127)) {
                "Administrator authorization was cancelled or denied.".to_owned()
            } else {
                format!("Terminal capture setup failed: {}", abbreviated_error(&output))
            });
        }
        Ok(collect_diagnostics(&socket_path))
    })
    .await
    .map_err(|error| format!("terminal setup task failed: {error}"))?
}

fn default_socket_path() -> PathBuf {
    if let Some(path) = env::var_os("CTF_HUNTER_SOCKET") {
        return PathBuf::from(path);
    }
    env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", geteuid().as_raw())))
        .join("ctf-hunter/daemon.sock")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::new(default_socket_path()))
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            notification_settings,
            update_notification_settings,
            list_sessions,
            create_session,
            update_session,
            transition_session,
            list_sources,
            add_source,
            remove_source,
            list_findings,
            get_finding,
            preview_text,
            submit_text,
            bootstrap_runtime,
            runtime_diagnostics,
            enable_terminal_capture,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run CTF Hunter desktop application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_is_absolute_and_scoped() {
        // Environment mutation is avoided here; the fallback shape is the security property.
        let fallback = default_socket_path();
        assert!(fallback.ends_with("ctf-hunter/daemon.sock"));
        assert!(fallback.is_absolute());
    }

    #[test]
    fn installed_executable_rejects_missing_paths() {
        assert!(!installed_executable(
            "/definitely/missing/ctf-hunter-test-helper"
        ));
    }

    #[test]
    fn abbreviated_errors_are_bounded_and_single_line() {
        let output = Command::new("/bin/sh")
            .args(["-c", "printf 'first\\nsecond\\n' >&2; exit 1"])
            .output()
            .unwrap();
        assert_eq!(abbreviated_error(&output), "first second");
    }
}
