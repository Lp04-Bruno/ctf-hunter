use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("read workspace metadata")?;
    let package = packages
        .into_iter()
        .find(|package| package.name.as_str() == "ctf-hunter-ebpf")
        .ok_or_else(|| anyhow!("ctf-hunter-ebpf package not found"))?;
    let root_dir = package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("eBPF manifest has no parent"))?;
    aya_build::build_ebpf(
        [aya_build::Package {
            name: package.name.as_str(),
            root_dir: root_dir.as_str(),
            ..Default::default()
        }],
        Toolchain::default(),
    )
}
