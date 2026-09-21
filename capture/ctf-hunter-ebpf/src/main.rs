#![no_main]
#![no_std]

use aya_ebpf::{
    Global,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ctf_hunter_common::{
    CAPTURE_BYTES, CaptureEvent, FLAG_CONTINUATION, FLAG_TRUNCATED, MAX_WRITEV_SEGMENTS,
    RING_BYTES, STAT_COUNT, STAT_EMITTED, STAT_PROCESS_FILTERED, STAT_READ_FAILED,
    STAT_RING_DROPPED, STAT_SEEN, STAT_TRUNCATED, STAT_UID_FILTERED, STAT_WRITE, STAT_WRITEV,
    SyscallKind, is_blocked_comm,
};

const ARG0_OFFSET: usize = 16;
const ARG1_OFFSET: usize = 24;
const ARG2_OFFSET: usize = 32;

#[unsafe(no_mangle)]
static TARGET_UID: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static SELF_PID: Global<u32> = Global::new(0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_COUNT, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: *const u8,
    len: usize,
}

#[tracepoint]
pub fn observe_write(ctx: TracePointContext) -> u32 {
    let _ = try_observe_write(ctx);
    0
}

fn try_observe_write(ctx: TracePointContext) -> Result<(), i32> {
    let Some(metadata) = metadata(SyscallKind::Write) else {
        return Ok(());
    };
    let fd: i64 = unsafe { ctx.read_at(ARG0_OFFSET)? };
    let buffer: *const u8 = unsafe { ctx.read_at(ARG1_OFFSET)? };
    let count: u64 = unsafe { ctx.read_at(ARG2_OFFSET)? };
    capture(metadata, fd as i32, buffer, count, 0)
}

#[tracepoint]
pub fn observe_writev(ctx: TracePointContext) -> u32 {
    let _ = try_observe_writev(ctx);
    0
}

fn try_observe_writev(ctx: TracePointContext) -> Result<(), i32> {
    let Some(metadata) = metadata(SyscallKind::WriteV) else {
        return Ok(());
    };
    let fd: i64 = unsafe { ctx.read_at(ARG0_OFFSET)? };
    let vectors: *const IoVec = unsafe { ctx.read_at(ARG1_OFFSET)? };
    let count: u64 = unsafe { ctx.read_at(ARG2_OFFSET)? };
    if count == 0 || vectors.is_null() {
        return Ok(());
    }

    if count > 0 {
        capture_vector(metadata, fd as i32, vectors, 0, count)?;
    }
    if count > 1 {
        capture_vector(metadata, fd as i32, vectors, 1, count)?;
    }
    if count > 2 {
        capture_vector(metadata, fd as i32, vectors, 2, count)?;
    }
    if count > 3 {
        capture_vector(metadata, fd as i32, vectors, 3, count)?;
    }
    if count > MAX_WRITEV_SEGMENTS as u64 {
        increment(STAT_TRUNCATED);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Metadata {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    syscall: SyscallKind,
}

fn metadata(syscall: SyscallKind) -> Option<Metadata> {
    increment(STAT_SEEN);
    match syscall {
        SyscallKind::Write => increment(STAT_WRITE),
        SyscallKind::WriteV => increment(STAT_WRITEV),
    }
    let uid = bpf_get_current_uid_gid() as u32;
    if uid != TARGET_UID.load() {
        increment(STAT_UID_FILTERED);
        return None;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid == SELF_PID.load() {
        increment(STAT_PROCESS_FILTERED);
        return None;
    }
    let comm = bpf_get_current_comm().ok()?;
    if is_blocked_comm(&comm) {
        increment(STAT_PROCESS_FILTERED);
        return None;
    }
    Some(Metadata {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid,
        uid,
        comm,
        syscall,
    })
}

fn capture_vector(
    metadata: Metadata,
    fd: i32,
    vectors: *const IoVec,
    index: usize,
    count: u64,
) -> Result<(), i32> {
    let vector = unsafe { bpf_probe_read_user(vectors.add(index))? };
    let mut flags = if index == 0 { 0 } else { FLAG_CONTINUATION };
    if count > MAX_WRITEV_SEGMENTS as u64 {
        flags |= FLAG_TRUNCATED;
    }
    capture(metadata, fd, vector.base, vector.len as u64, flags)
}

fn capture(
    metadata: Metadata,
    fd: i32,
    source: *const u8,
    requested: u64,
    mut flags: u8,
) -> Result<(), i32> {
    if fd < 0 || requested == 0 || source.is_null() {
        return Ok(());
    }
    let captured = if requested > CAPTURE_BYTES as u64 {
        flags |= FLAG_TRUNCATED;
        increment(STAT_TRUNCATED);
        CAPTURE_BYTES
    } else {
        requested as usize
    };
    let Some(mut entry) = EVENTS.reserve::<CaptureEvent>(0) else {
        increment(STAT_RING_DROPPED);
        return Ok(());
    };
    let event = entry.write(CaptureEvent::empty());
    event.timestamp_ns = metadata.timestamp_ns;
    event.pid = metadata.pid;
    event.uid = metadata.uid;
    event.fd = fd;
    event.requested_len = requested.min(u32::MAX as u64) as u32;
    event.captured_len = captured as u16;
    event.syscall = metadata.syscall as u8;
    event.flags = flags;
    event.comm = metadata.comm;
    if unsafe {
        aya_ebpf::helpers::generated::bpf_probe_read_user(
            event.data.as_mut_ptr().cast(),
            captured as u32,
            source.cast(),
        )
    } != 0
    {
        increment(STAT_READ_FAILED);
        entry.discard(0);
        return Ok(());
    }
    entry.submit(0);
    increment(STAT_EMITTED);
    Ok(())
}

fn increment(index: u32) {
    if let Some(value) = STATS.get_ptr_mut(index) {
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
