# CTF Hunter

CTF Hunter is a Linux-first application for passively finding CTF flags in terminal output, watched files, and manually submitted data.

The project is in active development. The current implementation provides foundational domain types and a bounded analysis engine with structured parsing, classified recursive decoding, compressed payload support, numerical finding scoring, candidate deduplication, and transformation provenance. Collection, persistence, and UI components will be added incrementally.

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
