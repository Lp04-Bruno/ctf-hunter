use std::{
    env,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use hunter_ipc::{
    AnalysisPreview, DaemonStatus, FindingDetail, FindingSummary, IpcClient, Request,
    RequestEnvelope, Response,
};
use hunter_types::{EventId, FindingId, Session, SessionId};
use nix::unistd::geteuid;
use serde::Serialize;
use tauri::State;

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
}
