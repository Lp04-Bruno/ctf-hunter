use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use aya::{
    Btf, EbpfLoader,
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::FEntry,
};
use ctf_hunter_capture::{
    GateStatus, KernelLayout, assess_privacy_gate, escaped_payload, process_name,
    terminal_device_key,
};
use ctf_hunter_common::{
    CaptureEvent, MAX_SELECTED_TTYS, STAT_BACKGROUND_FILTERED, STAT_COUNT, STAT_EMITTED,
    STAT_FAIL_CLOSED, STAT_INITIAL_FILTERED, STAT_MAP_FAILED, STAT_PROCESS_FILTERED,
    STAT_READ_FAILED, STAT_READ_MARKED, STAT_RING_DROPPED, STAT_SEEN, STAT_STRUCTURE_FAILED,
    STAT_TAINT_FILTERED, STAT_TRUNCATED, STAT_TTY_FILTERED, STAT_UID_FILTERED,
};

const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

fn main() -> Result<()> {
    match parse_args()? {
        Command::Preflight => preflight().map(|_| ()),
        Command::Gate => print_gate(),
        Command::Run(options) => run(options),
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
        _ => bail!(
            "usage: ctf-hunter-capture <preflight|gate|run --uid UID --tty PATH [--tty PATH ...] [--duration-seconds N] [--show-payload]>"
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
        "kernel BTF: compatible task_signal={} signal_pgid={} tty_pgrp={} tty_device={} device_devt={}",
        layout.task_signal,
        layout.signal_pgid,
        layout.tty_pgrp,
        layout.tty_device,
        layout.device_devt,
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
    if assess_privacy_gate().status() != GateStatus::Pass {
        bail!("privacy gate failed");
    }
    let layout = preflight()?;
    let devices = selected_devices(&options.terminals)?;
    let kernel_btf = Btf::from_sys_fs().context("load kernel BTF")?;
    let self_pid = std::process::id();
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ctf-hunter-ebpf"));
    let mut ebpf = EbpfLoader::new()
        .override_global("TARGET_UID", &options.uid, true)
        .override_global("SELF_PID", &self_pid, true)
        .override_global("TASK_SIGNAL_OFFSET", &layout.task_signal, true)
        .override_global("SIGNAL_PGID_OFFSET", &layout.signal_pgid, true)
        .override_global("TTY_PGRP_OFFSET", &layout.tty_pgrp, true)
        .override_global("TTY_DEVICE_OFFSET", &layout.tty_device, true)
        .override_global("DEVICE_DEVT_OFFSET", &layout.device_devt, true)
        .load(bytes)
        .context("load eBPF object")?;

    {
        let map = ebpf
            .map_mut("SELECTED_TTYS")
            .context("SELECTED_TTYS map missing")?;
        let mut selected: HashMap<_, u32, u8> =
            HashMap::try_from(map).context("open SELECTED_TTYS map")?;
        for device in &devices {
            selected
                .insert(*device, 1, 0)
                .with_context(|| format!("select terminal device {device}"))?;
        }
    }

    attach(&mut ebpf, "mark_tty_read", "n_tty_read", &kernel_btf)?;
    attach(&mut ebpf, "observe_tty_write", "n_tty_write", &kernel_btf)?;

    let events = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let stats = ebpf.take_map("STATS").context("STATS map missing")?;
    let mut ring = RingBuf::try_from(events).context("open EVENTS ring buffer")?;
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(stats).context("open STATS map")?;
    let deadline = Instant::now() + options.duration;
    let mut accepted = 0_u64;

    while Instant::now() < deadline {
        let mut drained = false;
        while let Some(item) = ring.next() {
            drained = true;
            let Some(event) = CaptureEvent::from_wire(&item) else {
                continue;
            };
            accepted += 1;
            if options.show_payload {
                println!(
                    "pid={} comm={} data={}",
                    event.pid,
                    process_name(&event.comm),
                    escaped_payload(event.payload())
                );
            }
        }
        if !drained {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let counters = read_counters(&stats)?;
    println!(
        "summary accepted={accepted} seen={} emitted={} read_marked={} taint_filtered={} initial_filtered={} background_filtered={} tty_filtered={} uid_filtered={} process_filtered={} structure_failed={} map_failed={} fail_closed={} ring_dropped={} read_failed={} truncated={}",
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
        counters[STAT_RING_DROPPED as usize],
        counters[STAT_READ_FAILED as usize],
        counters[STAT_TRUNCATED as usize],
    );
    Ok(())
}

fn selected_devices(paths: &[PathBuf]) -> Result<BTreeSet<u32>> {
    let mut devices = BTreeSet::new();
    for path in paths {
        let device = terminal_device_key(path)
            .with_context(|| format!("inspect terminal {}", path.display()))?;
        devices.insert(device);
    }
    Ok(devices)
}

fn attach(ebpf: &mut aya::Ebpf, program_name: &str, function: &str, btf: &Btf) -> Result<()> {
    let program: &mut FEntry = ebpf
        .program_mut(program_name)
        .with_context(|| format!("program {program_name} missing"))?
        .try_into()?;
    program.load(function, btf)?;
    program.attach()?;
    Ok(())
}

fn read_counters(stats: &PerCpuArray<aya::maps::MapData, u64>) -> Result<Vec<u64>> {
    let mut output = Vec::with_capacity(STAT_COUNT as usize);
    for index in 0..STAT_COUNT {
        let values = stats.get(&index, 0)?;
        output.push(values.iter().copied().sum());
    }
    Ok(output)
}
