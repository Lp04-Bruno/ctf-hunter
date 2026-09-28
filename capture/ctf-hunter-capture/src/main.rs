use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use aya::Btf;
use ctf_hunter_capture::{
    CaptureConfig, CaptureRuntime, CaptureServiceConfig, GateStatus, KernelLayout,
    assess_privacy_gate, escaped_payload, process_name, serve,
};
use ctf_hunter_common::{
    FailureReason, MAX_SELECTED_TTYS, STAT_BACKGROUND_FILTERED, STAT_EMITTED, STAT_FAIL_CLOSED,
    STAT_INITIAL_FILTERED, STAT_MAP_FAILED, STAT_PROCESS_FILTERED, STAT_READ_FAILED,
    STAT_READ_MARKED, STAT_RING_DROPPED, STAT_SEEN, STAT_STRUCTURE_FAILED, STAT_TAINT_FILTERED,
    STAT_TRUNCATED, STAT_TTY_FILTERED, STAT_UID_FILTERED,
};
use signal_hook::consts::signal::{SIGINT, SIGTERM};

const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

fn main() -> Result<()> {
    match parse_args()? {
        Command::Preflight => preflight().map(|_| ()),
        Command::Gate => print_gate(),
        Command::Run(options) => run(options),
        Command::Serve(config) => {
            let terminating = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(SIGINT, Arc::clone(&terminating))?;
            signal_hook::flag::register(SIGTERM, Arc::clone(&terminating))?;
            serve(config, terminating)
        }
    }
}

#[derive(Clone, Debug)]
struct RunOptions {
    uid: u32,
    terminals: Vec<PathBuf>,
    duration: Duration,
    show_payload: bool,
}

#[derive(Clone, Debug)]
enum Command {
    Preflight,
    Gate,
    Run(RunOptions),
    Serve(CaptureServiceConfig),
}

fn parse_args() -> Result<Command> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("preflight") if args.next().is_none() => Ok(Command::Preflight),
        Some("gate") if args.next().is_none() => Ok(Command::Gate),
        Some("run") => {
            let mut uid = None;
            let mut terminals = Vec::new();
            let mut duration = Duration::from_secs(5);
            let mut show_payload = false;
            while let Some(argument) = args.next() {
                match argument.as_str() {
                    "--uid" => {
                        uid = Some(
                            args.next()
                                .context("--uid requires a value")?
                                .parse()
                                .context("invalid UID")?,
                        );
                    }
                    "--tty" => {
                        terminals.push(PathBuf::from(args.next().context("--tty requires a path")?))
                    }
                    "--duration-seconds" => {
                        duration = Duration::from_secs(
                            args.next()
                                .context("--duration-seconds requires a value")?
                                .parse()
                                .context("invalid duration")?,
                        );
                    }
                    "--show-payload" => show_payload = true,
                    _ => bail!("unknown argument: {argument}"),
                }
            }
            let uid = uid.context("run requires --uid")?;
            if terminals.is_empty() {
                bail!("run requires at least one --tty path");
            }
            if terminals.len() > MAX_SELECTED_TTYS as usize {
                bail!("at most {MAX_SELECTED_TTYS} terminals may be selected");
            }
            if duration.is_zero() {
                bail!("duration must be greater than zero");
            }
            Ok(Command::Run(RunOptions {
                uid,
                terminals,
                duration,
                show_payload,
            }))
        }
        Some("serve") => {
            let mut socket = None;
            let mut max_connections = None;
            while let Some(argument) = args.next() {
                match argument.as_str() {
                    "--socket" => {
                        socket = Some(PathBuf::from(
                            args.next().context("--socket requires a value")?,
                        ));
                    }
                    "--max-connections" => {
                        max_connections = Some(
                            args.next()
                                .context("--max-connections requires a value")?
                                .parse()
                                .context("invalid maximum connection count")?,
                        );
                    }
                    _ => bail!("unknown argument: {argument}"),
                }
            }
            let mut config = CaptureServiceConfig::new(socket.context("serve requires --socket")?);
            if let Some(max_connections) = max_connections {
                config.max_connections = max_connections;
            }
            Ok(Command::Serve(config))
        }
        _ => bail!(
            "usage: ctf-hunter-capture <preflight|gate|run --uid UID --tty PATH [--tty PATH ...] [--duration-seconds N] [--show-payload]|serve --socket PATH [--max-connections N]>"
        ),
    }
}

fn preflight() -> Result<KernelLayout> {
    if !cfg!(target_arch = "x86_64") {
        bail!("the capture prototype currently supports x86_64 only");
    }
    Btf::from_sys_fs().context("load kernel BTF from /sys/kernel/btf/vmlinux")?;
    let layout = KernelLayout::from_path(Path::new(KERNEL_BTF)).map_err(anyhow::Error::msg)?;
    println!(
        "kernel BTF: compatible task_signal={} signal_pgid={} tty_pgrp={} tty_index={} tty_driver={} driver_major={} driver_minor_start={}",
        layout.task_signal,
        layout.signal_pgid,
        layout.tty_pgrp,
        layout.tty_index,
        layout.tty_driver,
        layout.driver_major,
        layout.driver_minor_start,
    );
    Ok(layout)
}

fn print_gate() -> Result<()> {
    let assessment = assess_privacy_gate();
    println!("privacy gate: {:?}", assessment.status());
    for control in assessment.controls() {
        println!("control: {control:?}");
    }
    if assessment.status() != GateStatus::Pass {
        bail!("terminal capture is not approved for integration");
    }
    Ok(())
}

fn run(options: RunOptions) -> Result<()> {
    preflight()?;
    let mut runtime = CaptureRuntime::load(&CaptureConfig {
        uid: options.uid,
        terminals: options.terminals,
    })?;
    println!("capture ready");
    io::stdout().flush().context("flush readiness signal")?;
    let deadline = Instant::now() + options.duration;

    while Instant::now() < deadline {
        let drained = runtime.drain(|event| {
            if options.show_payload {
                println!(
                    "pid={} comm={} data={}",
                    event.pid,
                    process_name(&event.comm),
                    escaped_payload(event.payload())
                );
            }
            Ok::<_, std::convert::Infallible>(())
        });
        if drained.expect("infallible event consumer") == 0 {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let statistics = runtime.statistics()?;
    let counters = statistics.counters;
    println!(
        "summary accepted={} seen={} emitted={} read_marked={} taint_filtered={} initial_filtered={} background_filtered={} tty_filtered={} uid_filtered={} process_filtered={} structure_failed={} map_failed={} fail_closed={} failure_reason={} ring_dropped={} read_failed={} truncated={}",
        statistics.accepted,
        counters[STAT_SEEN as usize],
        counters[STAT_EMITTED as usize],
        counters[STAT_READ_MARKED as usize],
        counters[STAT_TAINT_FILTERED as usize],
        counters[STAT_INITIAL_FILTERED as usize],
        counters[STAT_BACKGROUND_FILTERED as usize],
        counters[STAT_TTY_FILTERED as usize],
        counters[STAT_UID_FILTERED as usize],
        counters[STAT_PROCESS_FILTERED as usize],
        counters[STAT_STRUCTURE_FAILED as usize],
        counters[STAT_MAP_FAILED as usize],
        counters[STAT_FAIL_CLOSED as usize],
        failure_reason_name(statistics.failure_reason),
        counters[STAT_RING_DROPPED as usize],
        counters[STAT_READ_FAILED as usize],
        counters[STAT_TRUNCATED as usize],
    );
    Ok(())
}

fn failure_reason_name(value: u32) -> &'static str {
    match FailureReason::from_u32(value) {
        Some(FailureReason::None) => "none",
        Some(FailureReason::TtyArgument) => "tty_argument",
        Some(FailureReason::TtyIndex) => "tty_index",
        Some(FailureReason::TtyDriverPointer) => "tty_driver_pointer",
        Some(FailureReason::TtyDriverNumber) => "tty_driver_number",
        Some(FailureReason::TaskSignalPointer) => "task_signal_pointer",
        Some(FailureReason::ProcessGroupPointer) => "process_group_pointer",
        Some(FailureReason::ForegroundProcessGroup) => "foreground_process_group",
        Some(FailureReason::MapMutation) => "map_mutation",
        None => "unknown",
    }
}
