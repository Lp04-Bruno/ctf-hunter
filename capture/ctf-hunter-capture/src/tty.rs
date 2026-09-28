use std::{
    fs, io,
    os::unix::{fs::FileTypeExt as _, fs::MetadataExt as _},
    path::Path,
};

pub fn terminal_device_key(path: &Path) -> io::Result<u32> {
    let canonical = fs::canonicalize(path)?;
    if !is_terminal_path(&canonical) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a supported terminal path", path.display()),
        ));
    }
    let metadata = fs::metadata(&canonical)?;
    if !metadata.file_type().is_char_device() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a character device", path.display()),
        ));
    }
    let device = metadata.rdev();
    let major = ((device & 0x0000_0000_000f_ff00) >> 8) | ((device & 0xffff_f000_0000_0000) >> 32);
    let minor = (device & 0xff) | ((device & 0x0000_0fff_fff0_0000) >> 12);
    if major >= (1 << 12) || minor >= (1 << 20) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has an unsupported device identifier", path.display()),
        ));
    }
    Ok(((major as u32) << 20) | minor as u32)
}

#[must_use]
pub fn is_terminal_path(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    value.strip_prefix("/dev/pts/").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    }) || value.strip_prefix("/dev/tty").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_supported_terminal_paths() {
        for path in ["/dev/pts/0", "/dev/tty2"] {
            assert!(is_terminal_path(Path::new(path)), "{path}");
        }
        for path in [
            "/tmp/output",
            "/dev/null",
            "/dev/pts/x",
            "/dev/tty",
            "/dev/console",
            "/dev/ttyUSB0",
        ] {
            assert!(!is_terminal_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn rejects_non_terminal_devices() {
        let error = terminal_device_key(Path::new("/dev/null")).expect_err("not a terminal");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
