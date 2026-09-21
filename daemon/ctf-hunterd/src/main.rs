use std::{env, path::PathBuf};

use ctf_hunterd::{DaemonConfig, run, termination_flag};
use nix::unistd::geteuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (database_path, socket_path) = paths_from_args()?;
    run(
        DaemonConfig::new(database_path, socket_path),
        termination_flag()?,
    )?;
    Ok(())
}

fn paths_from_args() -> Result<(PathBuf, PathBuf), String> {
    let mut database = None;
    let mut socket = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--database" => database = Some(PathBuf::from(require_value(&mut args, "--database")?)),
            "--socket" => socket = Some(PathBuf::from(require_value(&mut args, "--socket")?)),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((
        database.unwrap_or_else(default_database_path),
        socket.unwrap_or_else(default_socket_path),
    ))
}

fn require_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn default_database_path() -> PathBuf {
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("ctf-hunter/hunter.db");
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/ctf-hunter/hunter.db")
}

fn default_socket_path() -> PathBuf {
    env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", geteuid().as_raw())))
        .join("ctf-hunter/daemon.sock")
}
