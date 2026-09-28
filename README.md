# CTF Hunter

CTF Hunter is a Linux-first application for passively finding CTF flags in terminal output, watched files, and manually submitted data.

The project is in active development. The current implementation provides a bounded analysis engine, SQLite persistence, an unprivileged per-user daemon with versioned Unix-socket IPC, inotify-backed file collection, and integrated read-tainted foreground-TTY capture. The capture service runs beside ordinary terminals without wrapping commands and forwards only kernel-filtered, bounded output to the daemon. UI components will be added incrementally.

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
cargo run --package ctf-hunterd --bin ctf-hunterctl -- --socket "$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock" add-terminal SESSION_ID "$(tty)"
```

The daemon stores its database below the user data directory and creates a mode `0600` socket below the user runtime directory. File watches inspect direct child regular files by content, do not follow symbolic links, and default to a 64 KiB per-file limit.

## Terminal capture

The privileged helper has no parser, decoder, database, shell execution, or network capability. It derives the target UID from Unix peer credentials, accepts only a terminal owned by that UID, and streams at most 256 bytes per accepted kernel event over a bounded local protocol. Interactive jobs that read from the terminal, the initial foreground job, background jobs, other users, and other terminals are filtered before userspace.

For local development, start the helper and daemon in separate terminals:

```bash
sudo -g "$(id -gn)" target/debug/ctf-hunter-capture serve --socket /run/ctf-hunter/capture.sock
target/debug/ctf-hunterd --capture-socket /run/ctf-hunter/capture.sock
```

The production units are in `packaging/systemd/`. The system helper is restricted to `CAP_BPF`, `CAP_PERFMON`, Unix sockets, and a hardened filesystem view. The per-user daemon remains unprivileged. Membership in the package-created `ctf-hunter` group grants access to the helper socket; add the intended desktop user to that group during installation and start a new login session before enabling capture. The helper still limits each client to terminals owned by its authenticated UID.
