#!/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

test -f "$project_root/Cargo.toml"
test -f "$project_root/ui/package-lock.json"

managed_paths=(
    "$project_root/target"
    "$project_root/ui/node_modules"
    "$project_root/ui/dist"
    "$project_root/ui/.svelte-kit"
)

echo "Disk usage before reclaiming source-gate artifacts:"
df -h "$project_root"

for path in "${managed_paths[@]}"; do
    case "$path" in
        "$project_root/target"|\
        "$project_root/ui/node_modules"|\
        "$project_root/ui/dist"|\
        "$project_root/ui/.svelte-kit")
            rm -rf -- "$path"
            ;;
        *)
            echo "Refusing to remove unmanaged path: $path" >&2
            exit 1
            ;;
    esac
done

echo "Disk usage after reclaiming source-gate artifacts:"
df -h "$project_root"
