# CTF Hunter

CTF Hunter is a Linux-first application for passively finding CTF flags in terminal output, watched files, and manually submitted data.

The project is in active development. The current implementation provides a bounded analysis engine, SQLite persistence, an unprivileged per-user daemon with versioned Unix-socket IPC, and inotify-backed file collection. The terminal-capture feasibility prototype is intentionally not approved for integration because syscall observation cannot reliably distinguish program output from text redrawn by unknown interactive applications. UI components will be added incrementally.

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

## Daemon

```bash
cargo run --package ctf-hunterd --bin ctf-hunterd
cargo run --package ctf-hunterd --bin ctf-hunterctl -- --socket "$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock" status
cargo run --package ctf-hunterd --bin ctf-hunterctl -- --socket "$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock" add-watch SESSION_ID DIRECTORY
```

The daemon stores its database below the user data directory and creates a mode `0600` socket below the user runtime directory. File watches inspect direct child regular files by content, do not follow symbolic links, and default to a 64 KiB per-file limit.
