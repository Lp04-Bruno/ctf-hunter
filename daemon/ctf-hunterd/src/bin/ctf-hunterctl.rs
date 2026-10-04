use std::{path::PathBuf, str::FromStr as _};

use hunter_ipc::{IpcClient, Request, RequestEnvelope};
use hunter_types::{FindingId, SessionId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (socket, request) = parse_args().map_err(|error| format!("{error}\n{}", usage()))?;
    let response = IpcClient::request(socket, &RequestEnvelope::new(1, request))?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn parse_args() -> Result<(PathBuf, Request), String> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--socket") {
        return Err("--socket must be the first argument".to_owned());
    }
    let socket = PathBuf::from(next(&mut args, "socket path")?);
    let command = next(&mut args, "command")?;
    let request = match command.as_str() {
        "status" => Request::GetStatus,
        "sessions" => Request::ListSessions,
        "create" => {
            let name = next(&mut args, "session name")?;
            let flag_patterns = args.collect();
            Request::CreateSession {
                name,
                flag_patterns,
            }
        }
        "update" => {
            let session_id = session_id(&mut args)?;
            let name = next(&mut args, "session name")?;
            let flag_patterns = args.collect();
            Request::UpdateSession {
                session_id,
                name,
                flag_patterns,
            }
        }
        "start" => Request::StartSession {
            session_id: session_id(&mut args)?,
        },
        "pause" => Request::PauseSession {
            session_id: session_id(&mut args)?,
        },
        "resume" => Request::ResumeSession {
            session_id: session_id(&mut args)?,
        },
        "stop" => Request::StopSession {
            session_id: session_id(&mut args)?,
        },
        "add-watch" => Request::AddWatchDirectory {
            session_id: session_id(&mut args)?,
            directory: next(&mut args, "directory")?,
        },
        "remove-watch" => Request::RemoveWatchDirectory {
            session_id: session_id(&mut args)?,
            directory: next(&mut args, "directory")?,
        },
        "watches" => Request::ListWatchDirectories {
            session_id: session_id(&mut args)?,
        },
        "add-terminal" => Request::AddTerminal {
            session_id: session_id(&mut args)?,
            terminal: next(&mut args, "terminal")?,
        },
        "remove-terminal" => Request::RemoveTerminal {
            session_id: session_id(&mut args)?,
            terminal: next(&mut args, "terminal")?,
        },
        "terminals" => Request::ListTerminals {
            session_id: session_id(&mut args)?,
        },
        "submit" => Request::SubmitText {
            session_id: session_id(&mut args)?,
            text: next(&mut args, "text")?,
        },
        "preview" => Request::PreviewText {
            session_id: session_id(&mut args)?,
            text: next(&mut args, "text")?,
        },
        "list" => Request::ListFindings {
            session_id: session_id(&mut args)?,
            offset: 0,
            limit: args
                .next()
                .map(|value| value.parse().map_err(|_| "invalid limit".to_owned()))
                .transpose()?
                .unwrap_or(50),
        },
        "finding" => Request::GetFinding {
            finding_id: FindingId::from_str(&next(&mut args, "finding ID")?)
                .map_err(|_| "invalid finding ID".to_owned())?,
        },
        "shutdown" => Request::Shutdown,
        _ => return Err(format!("unknown command: {command}")),
    };
    Ok((socket, request))
}

fn session_id(args: &mut impl Iterator<Item = String>) -> Result<SessionId, String> {
    SessionId::from_str(&next(args, "session ID")?).map_err(|_| "invalid session ID".to_owned())
}

fn next(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("missing {name}"))
}

const fn usage() -> &'static str {
    "usage: ctf-hunterctl --socket PATH <status|sessions|create NAME [PATTERN...]|update ID NAME [PATTERN...]|start ID|pause ID|resume ID|stop ID|add-watch ID DIR|remove-watch ID DIR|watches ID|add-terminal ID TTY|remove-terminal ID TTY|terminals ID|submit ID TEXT|preview ID TEXT|list ID [LIMIT]|finding ID|shutdown>"
}
