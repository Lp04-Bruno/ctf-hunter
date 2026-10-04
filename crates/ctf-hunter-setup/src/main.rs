use std::{env, process::Command};

use nix::unistd::{Group, Uid, User, geteuid};

const CAPTURE_GROUP: &str = "ctf-hunter";
const USERMOD: &str = "/usr/sbin/usermod";

fn invoking_uid(value: Option<&str>) -> Result<Uid, String> {
    let value = value.ok_or_else(|| "this helper must be started through pkexec".to_owned())?;
    let raw = value
        .parse::<u32>()
        .map_err(|_| "pkexec supplied an invalid caller UID".to_owned())?;
    if raw == 0 {
        return Err("terminal capture setup is not required for root".to_owned());
    }
    Ok(Uid::from_raw(raw))
}

fn run() -> Result<(), String> {
    if env::args_os().nth(1).is_some() {
        return Err("this helper does not accept arguments".to_owned());
    }
    if !geteuid().is_root() {
        return Err("terminal capture setup requires administrator authorization".to_owned());
    }

    let uid = invoking_uid(env::var("PKEXEC_UID").ok().as_deref())?;
    let user = User::from_uid(uid)
        .map_err(|error| format!("cannot resolve the requesting account: {error}"))?
        .ok_or_else(|| "the requesting account no longer exists".to_owned())?;
    let group = Group::from_name(CAPTURE_GROUP)
        .map_err(|error| format!("cannot resolve the capture group: {error}"))?
        .ok_or_else(|| "the ctf-hunter group is missing; reinstall the package".to_owned())?;

    if user.gid == group.gid || group.mem.contains(&user.name) {
        return Ok(());
    }

    let status = Command::new(USERMOD)
        .args(["--append", "--groups", CAPTURE_GROUP, "--", &user.name])
        .status()
        .map_err(|error| format!("cannot start usermod: {error}"))?;
    if !status.success() {
        return Err(format!("usermod failed with {status}"));
    }

    let updated = Group::from_name(CAPTURE_GROUP)
        .map_err(|error| format!("cannot verify the capture group: {error}"))?
        .ok_or_else(|| "the ctf-hunter group disappeared during setup".to_owned())?;
    if !updated.mem.contains(&user.name) {
        return Err("the account was not added to the ctf-hunter group".to_owned());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ctf-hunter-enable-capture: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_uid_requires_pkexec_metadata() {
        assert!(invoking_uid(None).is_err());
        assert!(invoking_uid(Some("not-a-uid")).is_err());
    }

    #[test]
    fn caller_uid_rejects_root() {
        assert!(invoking_uid(Some("0")).is_err());
    }

    #[test]
    fn caller_uid_accepts_an_unprivileged_uid() {
        assert_eq!(invoking_uid(Some("1000")).unwrap().as_raw(), 1000);
    }
}
