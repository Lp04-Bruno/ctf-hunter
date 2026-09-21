#![no_std]

pub const CAPTURE_BYTES: usize = 256;
pub const EVENT_WIRE_SIZE: usize = core::mem::size_of::<CaptureEvent>();
pub const MAX_WRITEV_SEGMENTS: usize = 4;
pub const RING_BYTES: u32 = 1 << 20;

pub const FLAG_TRUNCATED: u8 = 1;
pub const FLAG_CONTINUATION: u8 = 1 << 1;

pub const STAT_SEEN: u32 = 0;
pub const STAT_UID_FILTERED: u32 = 1;
pub const STAT_PROCESS_FILTERED: u32 = 2;
pub const STAT_EMITTED: u32 = 3;
pub const STAT_RING_DROPPED: u32 = 4;
pub const STAT_READ_FAILED: u32 = 5;
pub const STAT_TRUNCATED: u32 = 6;
pub const STAT_WRITE: u32 = 7;
pub const STAT_WRITEV: u32 = 8;
pub const STAT_COUNT: u32 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SyscallKind {
    Write = 1,
    WriteV = 2,
}

impl SyscallKind {
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Write),
            2 => Some(Self::WriteV),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct CaptureEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub fd: i32,
    pub requested_len: u32,
    pub captured_len: u16,
    pub syscall: u8,
    pub flags: u8,
    pub comm: [u8; 16],
    pub data: [u8; CAPTURE_BYTES],
    pub reserved: [u8; 4],
}

impl CaptureEvent {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            uid: 0,
            fd: 0,
            requested_len: 0,
            captured_len: 0,
            syscall: 0,
            flags: 0,
            comm: [0; 16],
            data: [0; CAPTURE_BYTES],
            reserved: [0; 4],
        }
    }

    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != EVENT_WIRE_SIZE {
            return None;
        }
        let mut event = Self::empty();
        event.timestamp_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
        event.pid = u32::from_ne_bytes(bytes[8..12].try_into().ok()?);
        event.uid = u32::from_ne_bytes(bytes[12..16].try_into().ok()?);
        event.fd = i32::from_ne_bytes(bytes[16..20].try_into().ok()?);
        event.requested_len = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
        event.captured_len = u16::from_ne_bytes(bytes[24..26].try_into().ok()?);
        event.syscall = bytes[26];
        event.flags = bytes[27];
        event.comm.copy_from_slice(&bytes[28..44]);
        event.data.copy_from_slice(&bytes[44..44 + CAPTURE_BYTES]);
        event.reserved.copy_from_slice(&bytes[300..304]);
        SyscallKind::from_u8(event.syscall)?;
        if usize::from(event.captured_len) > CAPTURE_BYTES {
            return None;
        }
        Some(event)
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.data[..usize::from(self.captured_len)]
    }
}

#[must_use]
pub const fn process_name_hash(name: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < name.len() && index < 15 {
        hash ^= name[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

#[must_use]
pub fn comm_hash(comm: &[u8; 16]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < 15 && comm[index] != 0 {
        hash ^= u64::from(comm[index]);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

#[must_use]
pub fn is_blocked_comm(comm: &[u8; 16]) -> bool {
    matches!(
        comm_hash(comm),
        h if h == process_name_hash(b"bash")
            || h == process_name_hash(b"zsh")
            || h == process_name_hash(b"fish")
            || h == process_name_hash(b"dash")
            || h == process_name_hash(b"sh")
            || h == process_name_hash(b"ksh")
            || h == process_name_hash(b"tcsh")
            || h == process_name_hash(b"csh")
            || h == process_name_hash(b"sudo")
            || h == process_name_hash(b"su")
            || h == process_name_hash(b"ssh")
            || h == process_name_hash(b"vim")
            || h == process_name_hash(b"nvim")
            || h == process_name_hash(b"vi")
            || h == process_name_hash(b"nano")
            || h == process_name_hash(b"emacs")
            || h == process_name_hash(b"less")
            || h == process_name_hash(b"more")
            || h == process_name_hash(b"man")
            || h == process_name_hash(b"tmux")
            || h == process_name_hash(b"screen")
            || h == process_name_hash(b"python")
            || h == process_name_hash(b"python3")
            || h == process_name_hash(b"ipython")
            || h == process_name_hash(b"node")
            || h == process_name_hash(b"irb")
            || h == process_name_hash(b"ghci")
            || h == process_name_hash(b"lua")
            || h == process_name_hash(b"mysql")
            || h == process_name_hash(b"psql")
            || h == process_name_hash(b"sqlite3")
            || h == process_name_hash(b"gdb")
            || h == process_name_hash(b"lldb")
            || h == process_name_hash(b"xterm")
            || h == process_name_hash(b"kitty")
            || h == process_name_hash(b"konsole")
            || h == process_name_hash(b"gnome-terminal-")
            || h == process_name_hash(b"alacritty")
            || h == process_name_hash(b"wezterm")
            || h == process_name_hash(b"foot")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comm(name: &str) -> [u8; 16] {
        let mut output = [0; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        output[..len].copy_from_slice(&bytes[..len]);
        output
    }

    #[test]
    fn blocks_interactive_process_classes() {
        for name in ["bash", "zsh", "ssh", "sudo", "nvim", "python3", "tmux"] {
            assert!(is_blocked_comm(&comm(name)), "{name}");
        }
        assert!(!is_blocked_comm(&comm("curl")));
    }

    #[test]
    fn parses_the_fixed_wire_layout() {
        let mut bytes = [0_u8; EVENT_WIRE_SIZE];
        bytes[0..8].copy_from_slice(&42_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&1_000_u32.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1_i32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&4_u32.to_ne_bytes());
        bytes[24..26].copy_from_slice(&4_u16.to_ne_bytes());
        bytes[26] = SyscallKind::Write as u8;
        bytes[28..32].copy_from_slice(b"echo");
        bytes[44..48].copy_from_slice(b"test");

        let event = CaptureEvent::from_wire(&bytes).expect("valid event");
        assert_eq!(event.pid, 7);
        assert_eq!(event.payload(), b"test");
    }

    #[test]
    fn rejects_invalid_wire_events() {
        assert!(CaptureEvent::from_wire(&[0; 16]).is_none());
        let mut bytes = [0_u8; EVENT_WIRE_SIZE];
        bytes[24..26].copy_from_slice(&257_u16.to_ne_bytes());
        bytes[26] = SyscallKind::Write as u8;
        assert!(CaptureEvent::from_wire(&bytes).is_none());
    }
}
