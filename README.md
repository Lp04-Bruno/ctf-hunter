# CTF Hunter

CTF Hunter is a Linux-first application for passively finding CTF flags in terminal output, watched files, and manually submitted data.

The project is in active development. The current implementation provides foundational domain types and a bounded analysis engine with structured parsing, classified recursive decoding, compressed payload support, numerical finding scoring, candidate deduplication, and transformation provenance. The terminal-capture feasibility prototype is intentionally not approved for integration because syscall observation cannot reliably distinguish program output from text redrawn by unknown interactive applications. Collection, persistence, and UI components will be added incrementally.

## Requirements

- Linux
- Rust 1.98 or newer
- Rust nightly with `rust-src`
- `bpf-linker` 0.11 or newer

## Development

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --exclude ctf-hunter-ebpf --all-targets --all-features -- -D warnings
cargo build --package ctf-hunter-capture
```

Development follows Git Flow: feature branches merge into `develop`, while `master` remains releasable.
