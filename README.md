# CTF Hunter

CTF Hunter is a Linux-first application for passively finding CTF flags in terminal output, watched files, and manually submitted data.

The project is in active development. The current implementation provides the foundational Rust domain types; collection, analysis, persistence, and UI components will be added incrementally.

## Requirements

- Linux
- Rust 1.98 or newer

## Development

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Development follows Git Flow: feature branches merge into `develop`, while `master` remains releasable.
