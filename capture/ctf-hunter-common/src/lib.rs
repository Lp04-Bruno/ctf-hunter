#![no_std]

pub const CAPTURE_BYTES: usize = 256;
pub const EVENT_WIRE_SIZE: usize = core::mem::size_of::<CaptureEvent>();
pub const RING_BYTES: u32 = 1 << 20;
pub const MAX_SELECTED_TTYS: u32 = 32;
pub const MAX_TAINTED_JOBS: u32 = 4_096;

pub const FLAG_TRUNCATED: u8 = 1;

pub const STAT_SEEN: u32 = 0;
pub const STAT_UID_FILTERED: u32 = 1;
pub const STAT_PROCESS_FILTERED: u32 = 2;
pub const STAT_TTY_FILTERED: u32 = 3;
pub const STAT_BACKGROUND_FILTERED: u32 = 4;
pub const STAT_READ_MARKED: u32 = 5;
pub const STAT_TAINT_FILTERED: u32 = 6;
pub const STAT_INITIAL_FILTERED: u32 = 7;
pub const STAT_STRUCTURE_FAILED: u32 = 8;
pub const STAT_MAP_FAILED: u32 = 9;
pub const STAT_FAIL_CLOSED: u32 = 10;
pub const STAT_EMITTED: u32 = 11;
pub const STAT_RING_DROPPED: u32 = 12;
pub const STAT_READ_FAILED: u32 = 13;
pub const STAT_TRUNCATED: u32 = 14;
pub const STAT_COUNT: u32 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CaptureKind {
    TtyWrite = 3,
}

impl CaptureKind {
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::TtyWrite),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct JobKey {
    pub tty: u64,
    pub process_group: u64,
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
    pub capture_kind: u8,
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
            capture_kind: 0,
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
        event.capture_kind = bytes[26];
        event.flags = bytes[27];
        event.comm.copy_from_slice(&bytes[28..44]);
        event.data.copy_from_slice(&bytes[44..44 + CAPTURE_BYTES]);
        event.reserved.copy_from_slice(&bytes[300..304]);
        CaptureKind::from_u8(event.capture_kind)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_fixed_wire_layout() {
        let mut bytes = [0_u8; EVENT_WIRE_SIZE];
        bytes[0..8].copy_from_slice(&42_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&1_000_u32.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1_i32.to_ne_bytes());
        bytes[20..24].copy_from_slice(&4_u32.to_ne_bytes());
        bytes[24..26].copy_from_slice(&4_u16.to_ne_bytes());
        bytes[26] = CaptureKind::TtyWrite as u8;
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
        bytes[26] = CaptureKind::TtyWrite as u8;
        assert!(CaptureEvent::from_wire(&bytes).is_none());
    }
}
