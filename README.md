# CTF Hunter

CTF Hunter is a Linux-first application for passively finding CTF flags in terminal output, watched files, and manually submitted data.

The project is in active development. The current implementation provides a bounded analysis engine, SQLite persistence, an unprivileged per-user daemon with versioned Unix-socket IPC, inotify-backed file collection, integrated read-tainted foreground-TTY capture, and a native Tauri and Svelte desktop interface. The capture service runs beside ordinary terminals without wrapping commands and forwards only kernel-filtered, bounded output to the daemon.

## Requirements

- Linux
- Rust 1.98 or newer
- Rust nightly with `rust-src`
- `bpf-linker` 0.11 or newer
- Node.js 24 and npm 11 for UI development

## Development

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --exclude ctf-hunter-ebpf --all-targets --all-features -- -D warnings
cargo build --package ctf-hunter-capture
cd ui && npm ci && npm run check && npm test && npm run build
```

Development follows Git Flow: feature branches merge into `develop`, while `master` remains releasable.

## Debian installation

Install a downloaded package with APT so normal repository dependencies are resolved:

```bash
sudo apt install ./ctf-hunter_0.1.0-1_amd64.deb
```

The desktop application, decoder, file collection, database, and per-user daemon
are available immediately. The application starts its packaged user service on
first launch when necessary. Terminal capture is an explicit one-time opt-in
because it connects to the capability-bound system helper. Open **Settings →
System readiness**, select **Enable terminal capture**, approve the administrator
dialog, then sign out of the Linux desktop and sign back in once.

The equivalent recovery command is:

```bash
sudo usermod -aG ctf-hunter "$USER"
```

Package installation never guesses a `$SUDO_USER` or silently changes account
memberships. Removing or purging the package never deletes data below
`~/.local/share/ctf-hunter`.

Release compatibility, versioning, and data-retention guarantees are documented in
[`docs/release-policy.md`](docs/release-policy.md). Release metadata is validated with:

```bash
python3 scripts/check-release-metadata.py
```

## Daemon

```bash
cargo run --package ctf-hunterd --bin ctf-hunterd
cargo run --package ctf-hunterd --bin ctf-hunterctl -- --socket "$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock" status
cargo run --package ctf-hunterd --bin ctf-hunterctl -- --socket "$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock" add-watch SESSION_ID DIRECTORY
cargo run --package ctf-hunterd --bin ctf-hunterctl -- --socket "$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock" add-terminal SESSION_ID "$(tty)"
```

The daemon stores its database below the user data directory and creates a mode `0600` socket below the user runtime directory. File watches inspect direct child regular files by content, do not follow symbolic links, and default to a 64 KiB per-file limit.

## Desktop UI

Start the unprivileged daemon, then launch the native application:

```bash
cargo run --package ctf-hunterd --bin ctf-hunterd
cd ui
npm ci
npm run tauri dev
```

The Tauri Rust layer is the only UI component that connects to the daemon socket. Frontend JavaScript uses a narrow set of typed commands and cannot request daemon shutdown, so closing the window does not stop monitoring. The socket defaults to `$XDG_RUNTIME_DIR/ctf-hunter/daemon.sock`; set `CTF_HUNTER_SOCKET` before launching the UI to use a different path.

Running `npm run dev` opens a clearly labelled browser preview with local sample data for visual development. It does not connect to the daemon. The native application exposes live overview metrics, session and pattern management, finding inspection, transformation paths, decoder previews, source management, capture health, and appearance settings.

## Terminal capture

The privileged helper has no parser, decoder, database, shell execution, or network capability. It derives the target UID from Unix peer credentials, accepts only a terminal owned by that UID, and streams at most 256 bytes per accepted kernel event over a bounded local protocol. Interactive jobs that read from the terminal, the initial foreground job, background jobs, other users, and other terminals are filtered before userspace.

For local development, start the helper and daemon in separate terminals:

```bash
sudo -g "$(id -gn)" target/debug/ctf-hunter-capture serve --socket /run/ctf-hunter/capture.sock
target/debug/ctf-hunterd --capture-socket /run/ctf-hunter/capture.sock
```

The production units are in `packaging/systemd/`. The system helper is restricted to `CAP_BPF`, `CAP_PERFMON`, Unix sockets, and a hardened filesystem view. The per-user daemon remains unprivileged. Membership in the package-created `ctf-hunter` group grants access to the helper socket; the guided Settings action adds only the authenticated desktop account after explicit administrator approval. A new login session activates the membership. The helper still limits each client to terminals owned by its authenticated UID.

## License

Copyright 2026 Lp04-Bruno.

CTF Hunter is licensed under either the Apache License, Version 2.0 or the MIT License,
at your option. See [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
