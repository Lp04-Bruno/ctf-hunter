#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/release/build-environment.env"

cd "$project_root"
export CTF_HUNTER_EBPF_TOOLCHAIN=$RUST_NIGHTLY

python3 scripts/check-build-toolchain.py
python3 scripts/check-release-metadata.py
python3 scripts/verify-service-lifecycle.py
python3 scripts/verify-workflows.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'

cargo fmt --all -- --check

npm --prefix ui ci
npm --prefix ui run check
npm --prefix ui test
npm --prefix ui run build

cargo test --workspace --exclude ctf-hunter-ebpf --locked
cargo clippy --workspace --exclude ctf-hunter-ebpf \
    --all-targets --all-features --locked -- -D warnings
cargo build --release --workspace --exclude ctf-hunter-ebpf --locked \
    --features ctf-hunter-ui/custom-protocol

echo "PASS: source, frontend, native release, service, and workflow gates"
