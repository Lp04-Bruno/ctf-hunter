use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use aya::{
    Btf, EbpfLoader,
    maps::{PerCpuArray, RingBuf},
    programs::TracePoint,
};
use ctf_hunter_capture::{
    FdClassification, GateStatus, TtyFdCache, assess_privacy_gate, escaped_payload, process_name,
    verify_tracepoint_format,
};
use ctf_hunter_common::{
    CaptureEvent, STAT_COUNT, STAT_EMITTED, STAT_PROCESS_FILTERED, STAT_READ_FAILED,
    STAT_RING_DROPPED, STAT_SEEN, STAT_TRUNCATED, STAT_UID_FILTERED, STAT_WRITE, STAT_WRITEV,
};

const TRACE_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

fn main() -> Result<()> {
    match parse_args()? {
        Command::Preflight => preflight(),
        Command::Gate => print_gate(),
        Command::Run(options) => run(options),
    }
}

#[derive(Clone, Copy, Debug)]
struct RunOptions {
    uid: u32,
    duration: Duration,
    show_payload: bool,
    acknowledge_privacy_risk: bool,
}

#[derive(Clone, Copy, Debug)]
enum Command {
    Preflight,
    Gate,
    Run(RunOptions),
}

fn parse_args() -> Result<Command> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("preflight") => Ok(Command::Preflight),
        Some("gate") => Ok(Command::Gate),
        Some("run") => {
            let mut uid = None;
            let mut duration = Duration::from_secs(5);
            let mut show_payload = false;
            let mut acknowledge_privacy_risk = false;
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
                    "--duration-seconds" => {
                        duration = Duration::from_secs(
                            args.next()
                                .context("--duration-seconds requires a value")?
                                .parse()
                                .context("invalid duration")?,
                        );
                    }
                    "--show-payload" => show_payload = true,
                    "--acknowledge-privacy-risk" => acknowledge_privacy_risk = true,
                    _ => bail!("unknown argument: {argument}"),
                }
            }
            let uid = uid.context("run requires --uid")?;
            if duration.is_zero() {
                bail!("duration must be greater than zero");
            }
            Ok(Command::Run(RunOptions {
                uid,
                duration,
                show_payload,
                acknowledge_privacy_risk,
            }))
        }
        _ => bail!(
            "usage: ctf-hunter-capture <preflight|gate|run --uid UID --acknowledge-privacy-risk [--duration-seconds N] [--show-payload]>"
        ),
    }
}

fn preflight() -> Result<()> {
    if !cfg!(target_arch = "x86_64") {
        bail!("the prototype tracepoint layout is supported only on x86_64");
    }
    Btf::from_sys_fs().context("load kernel BTF from /sys/kernel/btf/vmlinux")?;
    println!("kernel BTF: compatible");
    let root = TRACE_ROOTS
        .iter()
        .map(Path::new)
        .find(|path| {
            path.join("events/syscalls/sys_enter_write/format")
                .is_file()
        })
        .context("tracefs syscall formats are unavailable; run with the required privileges")?;
    verify_format(
        root,
        "sys_enter_write",
        &[("fd", 16, 8), ("buf", 24, 8), ("count", 32, 8)],
    )?;
    verify_format(
        root,
        "sys_enter_writev",
        &[("fd", 16, 8), ("vec", 24, 8), ("vlen", 32, 8)],
    )?;
    println!("kernel BTF and syscall tracepoint layouts are compatible");
    Ok(())
}

fn verify_format(root: &Path, event: &str, expected: &[(&str, usize, usize)]) -> Result<()> {
    let path = root.join(format!("events/syscalls/{event}/format"));
    let format = std::fs::read_to_string(&path)
        .with_context(|| format!("read tracepoint format {}", path.display()))?;
    let expected: Vec<_> = expected
        .iter()
        .map(|(name, offset, size)| ctf_hunter_capture::ExpectedField {
            name,
            offset: *offset,
            size: *size,
        })
        .collect();
    verify_tracepoint_format(&format, &expected).map_err(anyhow::Error::msg)?;
    Ok(())
}

fn print_gate() -> Result<()> {
    let assessment = assess_privacy_gate();
    println!("privacy gate: {:?}", assessment.status());
    for risk in assessment.unresolved() {
        println!("unresolved: {risk:?}");
    }
    if assessment.status() == GateStatus::Fail {
        bail!("terminal capture is not approved for integration");
    }
    Ok(())
}

fn run(options: RunOptions) -> Result<()> {
    if assess_privacy_gate().status() == GateStatus::Fail && !options.acknowledge_privacy_risk {
        bail!("run requires --acknowledge-privacy-risk because the privacy gate failed");
    }
    preflight()?;
    let self_pid = std::process::id();
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ctf-hunter-ebpf"));
    let mut ebpf = EbpfLoader::new()
        .override_global("TARGET_UID", &options.uid, true)
        .override_global("SELF_PID", &self_pid, true)
        .load(bytes)
        .context("load eBPF object")?;
    attach(&mut ebpf, "observe_write", "sys_enter_write")?;
    attach(&mut ebpf, "observe_writev", "sys_enter_writev")?;

    let events = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
    let stats = ebpf.take_map("STATS").context("STATS map missing")?;
    let mut ring = RingBuf::try_from(events).context("open EVENTS ring buffer")?;
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(stats).context("open STATS map")?;
    let mut tty_cache = TtyFdCache::new(4_096, Duration::from_secs(1));
    let deadline = Instant::now() + options.duration;
    let mut accepted = 0_u64;
    let mut non_terminal = 0_u64;
    let mut unavailable = 0_u64;

    while Instant::now() < deadline {
        let mut drained = false;
        while let Some(item) = ring.next() {
            drained = true;
            let Some(event) = CaptureEvent::from_wire(&item) else {
                continue;
            };
            match tty_cache.classify(event.pid, event.fd)? {
                FdClassification::Terminal(path) => {
                    accepted += 1;
                    if options.show_payload {
                        println!(
                            "pid={} comm={} tty={} data={}",
                            event.pid,
                            process_name(&event.comm),
                            path.display(),
                            escaped_payload(event.payload())
                        );
                    }
                }
                FdClassification::NonTerminal => non_terminal += 1,
                FdClassification::Unavailable => unavailable += 1,
            }
        }
        if !drained {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let counters = read_counters(&stats)?;
    println!(
        "summary accepted={accepted} non_terminal={non_terminal} unavailable={unavailable} seen={} emitted={} ring_dropped={} read_failed={} truncated={} uid_filtered={} process_filtered={} write={} writev={}",
        counters[STAT_SEEN as usize],
        counters[STAT_EMITTED as usize],
        counters[STAT_RING_DROPPED as usize],
        counters[STAT_READ_FAILED as usize],
        counters[STAT_TRUNCATED as usize],
        counters[STAT_UID_FILTERED as usize],
        counters[STAT_PROCESS_FILTERED as usize],
        counters[STAT_WRITE as usize],
        counters[STAT_WRITEV as usize],
    );
    Ok(())
}

fn attach(ebpf: &mut aya::Ebpf, program_name: &str, tracepoint: &str) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("program {program_name} missing"))?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", tracepoint)?;
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
