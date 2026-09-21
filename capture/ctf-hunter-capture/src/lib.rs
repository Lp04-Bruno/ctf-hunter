mod gate;
mod tracepoint;
mod tty;

pub use gate::{GateAssessment, GateStatus, PrivacyRisk, assess_privacy_gate};
pub use tracepoint::{ExpectedField, TracepointField, verify_tracepoint_format};
pub use tty::{FdClassification, TtyFdCache, is_terminal_path};

#[must_use]
pub fn process_name(comm: &[u8; 16]) -> &str {
    let end = comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(comm.len());
    std::str::from_utf8(&comm[..end]).unwrap_or("<invalid>")
}

#[must_use]
pub fn escaped_payload(payload: &[u8]) -> String {
    payload
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_non_ascii_bytes() {
        assert_eq!(escaped_payload(b"ok\n\xff"), "ok\\n\\xff");
    }

    #[test]
    fn extracts_a_bounded_process_name() {
        let mut comm = [0; 16];
        comm[..4].copy_from_slice(b"curl");
        assert_eq!(process_name(&comm), "curl");
    }
}
