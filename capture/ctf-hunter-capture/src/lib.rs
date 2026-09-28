mod gate;
mod kernel_layout;
mod policy;
mod tty;

pub use gate::{GateAssessment, GateStatus, PrivacyControl, assess_privacy_gate};
pub use kernel_layout::KernelLayout;
pub use policy::{PolicyDecision, PrivacyPolicy};
pub use tty::{is_terminal_path, terminal_device_key};

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

    const EBPF_SOURCE: &str = include_str!("../../ctf-hunter-ebpf/src/main.rs");

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

    #[test]
    fn tty_read_hook_never_accesses_input_arguments_or_payload_helpers() {
        let read_hook = EBPF_SOURCE
            .split("#[fentry(function = \"n_tty_read\")]")
            .nth(1)
            .and_then(|tail| tail.split("#[fentry(function = \"n_tty_write\")]").next())
            .expect("read hook source");

        assert!(read_hook.contains("ctx.arg(0)"));
        for forbidden in [
            "ctx.arg(1)",
            "ctx.arg(2)",
            "ctx.arg(3)",
            "ctx.arg(4)",
            "ctx.arg(5)",
            "bpf_probe_read_user",
            "CaptureEvent",
            "EVENTS.reserve",
        ] {
            assert!(!read_hook.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn ebpf_helpers_use_single_register_return_values() {
        assert!(!EBPF_SOURCE.contains("Result<u64"));
    }

    #[test]
    fn tty_output_uses_the_kernel_write_buffer() {
        assert!(!EBPF_SOURCE.contains("bpf_probe_read_user"));
        assert!(EBPF_SOURCE.contains("bpf_probe_read_kernel"));
    }
}
