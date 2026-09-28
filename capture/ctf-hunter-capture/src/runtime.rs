use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::{Array, HashMap, MapData, PerCpuArray, RingBuf},
    programs::FEntry,
};
use ctf_hunter_common::{CaptureEvent, MAX_SELECTED_TTYS, STAT_COUNT};

use crate::{GateStatus, KernelLayout, assess_privacy_gate, terminal_device_key};

const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

#[derive(Clone, Debug)]
pub struct CaptureConfig {
    pub uid: u32,
    pub terminals: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureStatistics {
    pub accepted: u64,
    pub counters: [u64; STAT_COUNT as usize],
    pub failure_reason: u32,
}

pub struct CaptureRuntime {
    _ebpf: Ebpf,
    ring: RingBuf<MapData>,
    stats: PerCpuArray<MapData, u64>,
    fail_state: Array<MapData, u32>,
    accepted: u64,
}

impl CaptureRuntime {
    pub fn load(config: &CaptureConfig) -> Result<Self> {
        if assess_privacy_gate().status() != GateStatus::Pass {
            bail!("privacy gate failed");
        }
        if !cfg!(target_arch = "x86_64") {
            bail!("terminal capture currently supports x86_64 only");
        }
        if config.terminals.is_empty() {
            bail!("at least one terminal must be selected");
        }
        if config.terminals.len() > MAX_SELECTED_TTYS as usize {
            bail!("at most {MAX_SELECTED_TTYS} terminals may be selected");
        }

        let layout = KernelLayout::from_path(std::path::Path::new(KERNEL_BTF))
            .map_err(anyhow::Error::msg)?;
        let devices = selected_devices(&config.terminals)?;
        let kernel_btf = Btf::from_sys_fs().context("load kernel BTF")?;
        let self_pid = std::process::id();
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ctf-hunter-ebpf"));
        let mut ebpf = EbpfLoader::new()
            .override_global("TARGET_UID", &config.uid, true)
            .override_global("SELF_PID", &self_pid, true)
            .override_global("TASK_SIGNAL_OFFSET", &layout.task_signal, true)
            .override_global("SIGNAL_PGID_OFFSET", &layout.signal_pgid, true)
            .override_global("TTY_PGRP_OFFSET", &layout.tty_pgrp, true)
            .override_global("TTY_INDEX_OFFSET", &layout.tty_index, true)
            .override_global("TTY_DRIVER_OFFSET", &layout.tty_driver, true)
            .override_global("DRIVER_MAJOR_OFFSET", &layout.driver_major, true)
            .override_global(
                "DRIVER_MINOR_START_OFFSET",
                &layout.driver_minor_start,
                true,
            )
            .load(bytes)
            .context("load eBPF object")?;

        {
            let map = ebpf
                .map_mut("SELECTED_TTYS")
                .context("SELECTED_TTYS map missing")?;
            let mut selected: HashMap<_, u32, u8> =
                HashMap::try_from(map).context("open SELECTED_TTYS map")?;
            for device in devices {
                selected
                    .insert(device, 1, 0)
                    .with_context(|| format!("select terminal device {device}"))?;
            }
        }

        attach(&mut ebpf, "mark_tty_read", "n_tty_read", &kernel_btf)?;
        attach(&mut ebpf, "observe_tty_write", "n_tty_write", &kernel_btf)?;

        let events = ebpf.take_map("EVENTS").context("EVENTS map missing")?;
        let stats = ebpf.take_map("STATS").context("STATS map missing")?;
        let fail_state = ebpf
            .take_map("FAIL_STATE")
            .context("FAIL_STATE map missing")?;
        Ok(Self {
            _ebpf: ebpf,
            ring: RingBuf::try_from(events).context("open EVENTS ring buffer")?,
            stats: PerCpuArray::try_from(stats).context("open STATS map")?,
            fail_state: Array::try_from(fail_state).context("open FAIL_STATE map")?,
            accepted: 0,
        })
    }

    pub fn drain<E>(
        &mut self,
        mut consume: impl FnMut(CaptureEvent) -> Result<(), E>,
    ) -> Result<usize, E> {
        let mut drained = 0;
        while let Some(item) = self.ring.next() {
            let Some(event) = CaptureEvent::from_wire(&item) else {
                continue;
            };
            consume(event)?;
            self.accepted = self.accepted.saturating_add(1);
            drained += 1;
        }
        Ok(drained)
    }

    pub fn statistics(&self) -> Result<CaptureStatistics> {
        let mut counters = [0_u64; STAT_COUNT as usize];
        for index in 0..STAT_COUNT {
            let values = self.stats.get(&index, 0)?;
            counters[index as usize] = values.iter().copied().sum();
        }
        Ok(CaptureStatistics {
            accepted: self.accepted,
            counters,
            failure_reason: self.fail_state.get(&0, 0)?,
        })
    }
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

fn attach(ebpf: &mut Ebpf, program_name: &str, function: &str, btf: &Btf) -> Result<()> {
    let program: &mut FEntry = ebpf
        .program_mut(program_name)
        .with_context(|| format!("program {program_name} missing"))?
        .try_into()?;
    program.load(function, btf)?;
    program.attach()?;
    Ok(())
}
