use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FdClassification {
    Terminal(PathBuf),
    NonTerminal,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FdKey {
    pid: u32,
    fd: i32,
}

#[derive(Clone, Debug)]
struct CachedFd {
    classification: FdClassification,
    observed_at: Instant,
}

#[derive(Debug)]
pub struct TtyFdCache {
    entries: HashMap<FdKey, CachedFd>,
    capacity: usize,
    ttl: Duration,
}

impl TtyFdCache {
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
            ttl,
        }
    }

    pub fn classify(&mut self, pid: u32, fd: i32) -> io::Result<FdClassification> {
        let key = FdKey { pid, fd };
        let now = Instant::now();
        if let Some(cached) = self.entries.get(&key)
            && now.duration_since(cached.observed_at) <= self.ttl
        {
            return Ok(cached.classification.clone());
        }

        let link = PathBuf::from(format!("/proc/{pid}/fd/{fd}"));
        let classification = match std::fs::read_link(link) {
            Ok(path) if is_terminal_path(&path) => FdClassification::Terminal(path),
            Ok(_) => FdClassification::NonTerminal,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                FdClassification::Unavailable
            }
            Err(error) => return Err(error),
        };
        if self.capacity > 0 {
            self.remove_expired_or_oldest(now);
            self.entries.insert(
                key,
                CachedFd {
                    classification: classification.clone(),
                    observed_at: now,
                },
            );
        }
        Ok(classification)
    }

    fn remove_expired_or_oldest(&mut self, now: Instant) {
        self.entries
            .retain(|_, value| now.duration_since(value.observed_at) <= self.ttl);
        if self.entries.len() < self.capacity {
            return;
        }
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, value)| value.observed_at)
            .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest);
        }
    }
}

#[must_use]
pub fn is_terminal_path(path: &Path) -> bool {
    if path == Path::new("/dev/tty") || path == Path::new("/dev/console") {
        return true;
    }
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
    fn recognizes_only_terminal_device_paths() {
        for path in ["/dev/pts/0", "/dev/tty", "/dev/tty2", "/dev/console"] {
            assert!(is_terminal_path(Path::new(path)), "{path}");
        }
        for path in ["/tmp/output", "/dev/null", "/dev/pts/x", "/dev/ttyUSB0"] {
            assert!(!is_terminal_path(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn bounds_cache_capacity() {
        let mut cache = TtyFdCache::new(1, Duration::from_secs(1));
        let _ = cache.classify(u32::MAX, 1).expect("classification");
        let _ = cache.classify(u32::MAX - 1, 1).expect("classification");
        assert!(cache.entries.len() <= 1);
    }
}
