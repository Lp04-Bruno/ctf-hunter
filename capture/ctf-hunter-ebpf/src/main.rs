#![no_main]
#![no_std]

use aya_ebpf::{
    Global,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel,
    },
    macros::{fentry, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::FEntryContext,
};
use ctf_hunter_common::{
    CAPTURE_BYTES, CaptureEvent, CaptureKind, FLAG_TRUNCATED, FailureReason, JobKey,
    MAX_SELECTED_TTYS, MAX_TAINTED_JOBS, RING_BYTES, STAT_BACKGROUND_FILTERED, STAT_COUNT,
    STAT_EMITTED, STAT_FAIL_CLOSED, STAT_INITIAL_FILTERED, STAT_MAP_FAILED, STAT_PROCESS_FILTERED,
    STAT_READ_FAILED, STAT_READ_MARKED, STAT_RING_DROPPED, STAT_SEEN, STAT_STRUCTURE_FAILED,
    STAT_TAINT_FILTERED, STAT_TRUNCATED, STAT_TTY_FILTERED, STAT_UID_FILTERED,
};

#[unsafe(no_mangle)]
static TARGET_UID: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static SELF_PID: Global<u32> = Global::new(0);

#[unsafe(no_mangle)]
static TASK_SIGNAL_OFFSET: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static SIGNAL_PGID_OFFSET: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static TTY_PGRP_OFFSET: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static TTY_INDEX_OFFSET: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static TTY_DRIVER_OFFSET: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static DRIVER_MAJOR_OFFSET: Global<u32> = Global::new(u32::MAX);

#[unsafe(no_mangle)]
static DRIVER_MINOR_START_OFFSET: Global<u32> = Global::new(u32::MAX);

#[map]
static SELECTED_TTYS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_SELECTED_TTYS, 0);

#[map]
static TAINTED_JOBS: HashMap<JobKey, u8> = HashMap::with_max_entries(MAX_TAINTED_JOBS, 0);

#[map]
static INITIALIZED_TTYS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_SELECTED_TTYS, 0);

#[map]
static FAIL_STATE: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_COUNT, 0);

#[fentry(function = "n_tty_read")]
pub fn mark_tty_read(ctx: FEntryContext) -> u32 {
    let tty: *const u8 = ctx.arg(0);
    let _ = try_mark_tty_read(tty);
    0
}

fn try_mark_tty_read(tty: *const u8) -> Result<(), i32> {
    if fail_closed() || !selected_tty(tty)? {
        return Ok(());
    }
    let process_group = current_process_group();
    if process_group == u64::MAX {
        return Err(-1);
    }
    mark_tainted(JobKey {
        tty: tty as u64,
        process_group,
    })?;
    increment(STAT_READ_MARKED);
    Ok(())
}

#[fentry(function = "n_tty_write")]
pub fn observe_tty_write(ctx: FEntryContext) -> u32 {
    let tty: *const u8 = ctx.arg(0);
    let buffer: *const u8 = ctx.arg(2);
    let count: usize = ctx.arg(3);
    let _ = try_observe_tty_write(tty, buffer, count);
    0
}

fn try_observe_tty_write(tty: *const u8, buffer: *const u8, count: usize) -> Result<(), i32> {
    increment(STAT_SEEN);
    if fail_closed() || !eligible_process() || !selected_tty(tty)? {
        return Ok(());
    }

    let process_group = current_process_group();
    if process_group == u64::MAX {
        return Err(-1);
    }
    let foreground_group = tty_foreground_group(tty);
    if foreground_group == u64::MAX {
        return Err(-1);
    }
    if process_group != foreground_group {
        increment(STAT_BACKGROUND_FILTERED);
        return Ok(());
    }

    let key = JobKey {
        tty: tty as u64,
        process_group,
    };
    if !tty_initialized(tty as u64, key)? {
        increment(STAT_INITIAL_FILTERED);
        return Ok(());
    }
    if TAINTED_JOBS.get_ptr(&key).is_some() {
        increment(STAT_TAINT_FILTERED);
        return Ok(());
    }

    capture(buffer, count)
}

fn eligible_process() -> bool {
    let uid = bpf_get_current_uid_gid() as u32;
    if uid != TARGET_UID.load() {
        increment(STAT_UID_FILTERED);
        return false;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid == SELF_PID.load() {
        increment(STAT_PROCESS_FILTERED);
        return false;
    }
    true
}

fn selected_tty(tty: *const u8) -> Result<bool, i32> {
    if tty.is_null() {
        structure_failure(FailureReason::TtyArgument);
        return Err(-1);
    }
    let index = read_kernel_u32(tty, TTY_INDEX_OFFSET.load(), FailureReason::TtyIndex);
    if index == u32::MAX {
        return Err(-1);
    }
    let driver = read_kernel_u64(
        tty,
        TTY_DRIVER_OFFSET.load(),
        FailureReason::TtyDriverPointer,
    );
    if driver == u64::MAX {
        return Err(-1);
    }
    if driver == 0 {
        structure_failure(FailureReason::TtyDriverPointer);
        return Err(-1);
    }
    let major = read_kernel_u32(
        driver as *const u8,
        DRIVER_MAJOR_OFFSET.load(),
        FailureReason::TtyDriverNumber,
    );
    let minor_start = read_kernel_u32(
        driver as *const u8,
        DRIVER_MINOR_START_OFFSET.load(),
        FailureReason::TtyDriverNumber,
    );
    if major == u32::MAX || minor_start == u32::MAX {
        return Err(-1);
    }
    const MAX_MAJOR: u32 = 1 << 12;
    const MAX_MINOR: u32 = 1 << 20;
    if major >= MAX_MAJOR
        || minor_start >= MAX_MINOR
        || index >= MAX_MINOR
        || minor_start > (MAX_MINOR - 1) - index
    {
        structure_failure(FailureReason::TtyDriverNumber);
        return Err(-1);
    }
    let devt = (major << 20) | (minor_start + index);
    if SELECTED_TTYS.get_ptr(&devt).is_none() {
        increment(STAT_TTY_FILTERED);
        return Ok(false);
    }
    Ok(true)
}

fn current_process_group() -> u64 {
    let task = unsafe { aya_ebpf::helpers::generated::bpf_get_current_task() } as *const u8;
    let signal = read_kernel_u64(
        task,
        TASK_SIGNAL_OFFSET.load(),
        FailureReason::TaskSignalPointer,
    );
    if signal == u64::MAX {
        return u64::MAX;
    }
    if signal == 0 {
        structure_failure(FailureReason::TaskSignalPointer);
        return u64::MAX;
    }
    let process_group = read_kernel_u64(
        signal as *const u8,
        SIGNAL_PGID_OFFSET.load(),
        FailureReason::ProcessGroupPointer,
    );
    if process_group == u64::MAX {
        return u64::MAX;
    }
    if process_group == 0 {
        structure_failure(FailureReason::ProcessGroupPointer);
        return u64::MAX;
    }
    process_group
}

fn tty_foreground_group(tty: *const u8) -> u64 {
    let process_group = read_kernel_u64(
        tty,
        TTY_PGRP_OFFSET.load(),
        FailureReason::ForegroundProcessGroup,
    );
    if process_group == u64::MAX {
        return u64::MAX;
    }
    if process_group == 0 {
        structure_failure(FailureReason::ForegroundProcessGroup);
        return u64::MAX;
    }
    process_group
}

fn read_kernel_u64(base: *const u8, offset: u32, reason: FailureReason) -> u64 {
    if base.is_null() || offset == u32::MAX {
        structure_failure(reason);
        return u64::MAX;
    }
    match unsafe { bpf_probe_read_kernel(base.add(offset as usize).cast::<u64>()) } {
        Ok(value) => value,
        Err(_) => {
            structure_failure(reason);
            u64::MAX
        }
    }
}

fn read_kernel_u32(base: *const u8, offset: u32, reason: FailureReason) -> u32 {
    if base.is_null() || offset == u32::MAX {
        structure_failure(reason);
        return u32::MAX;
    }
    match unsafe { bpf_probe_read_kernel(base.add(offset as usize).cast::<u32>()) } {
        Ok(value) => value,
        Err(_) => {
            structure_failure(reason);
            u32::MAX
        }
    }
}

fn tty_initialized(tty: u64, key: JobKey) -> Result<bool, i32> {
    if INITIALIZED_TTYS.get_ptr(&tty).is_some() {
        return Ok(true);
    }
    if INITIALIZED_TTYS.insert(&tty, &1, 0).is_err() && INITIALIZED_TTYS.get_ptr(&tty).is_none() {
        map_failure();
        return Err(-1);
    }
    mark_tainted(key)?;
    Ok(false)
}

fn mark_tainted(key: JobKey) -> Result<(), i32> {
    if TAINTED_JOBS.get_ptr(&key).is_some() {
        return Ok(());
    }
    if TAINTED_JOBS.insert(&key, &1, 0).is_err() && TAINTED_JOBS.get_ptr(&key).is_none() {
        map_failure();
        return Err(-1);
    }
    Ok(())
}

fn capture(source: *const u8, requested: usize) -> Result<(), i32> {
    if requested == 0 || source.is_null() {
        return Ok(());
    }
    let mut flags = 0;
    let captured = if requested > CAPTURE_BYTES {
        flags |= FLAG_TRUNCATED;
        increment(STAT_TRUNCATED);
        CAPTURE_BYTES
    } else {
        requested
    };
    let Some(mut entry) = EVENTS.reserve::<CaptureEvent>(0) else {
        increment(STAT_RING_DROPPED);
        return Ok(());
    };
    let event = entry.write(CaptureEvent::empty());
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    event.uid = bpf_get_current_uid_gid() as u32;
    event.fd = -1;
    event.requested_len = requested.min(u32::MAX as usize) as u32;
    event.captured_len = captured as u16;
    event.capture_kind = CaptureKind::TtyWrite as u8;
    event.flags = flags;
    event.comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if unsafe {
        aya_ebpf::helpers::generated::bpf_probe_read_kernel(
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

fn structure_failure(reason: FailureReason) {
    increment(STAT_STRUCTURE_FAILED);
    set_fail_closed(reason);
}

fn map_failure() {
    increment(STAT_MAP_FAILED);
    set_fail_closed(FailureReason::MapMutation);
}

fn fail_closed() -> bool {
    FAIL_STATE.get(0).is_none_or(|value| *value != 0)
}

fn set_fail_closed(reason: FailureReason) {
    if let Some(value) = FAIL_STATE.get_ptr_mut(0) {
        unsafe {
            if *value == 0 {
                *value = reason as u32;
            }
        };
    }
    increment(STAT_FAIL_CLOSED);
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
