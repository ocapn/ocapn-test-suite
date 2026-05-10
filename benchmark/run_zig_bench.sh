#!/usr/bin/env bash
# Run the zig-syrup benchmark (vendor/zig-syrup) and print results.
#
# Requirements:
#   - zig >= 0.15.0  (on macOS, requires macOS 14 or earlier, OR zig nightly
#                    built against macOS 26 SDK; zig 0.15.2 is broken on macOS 26)
#   - The submodule must be initialised:
#       git submodule update --init vendor/zig-syrup
#
# Usage (from repo root):
#   bash benchmark/run_zig_bench.sh
#   ZIG=/path/to/zig bash benchmark/run_zig_bench.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIG_SYRUP="$REPO_ROOT/vendor/zig-syrup"
if [ -z "${ZIG:-}" ]; then
    if [ -x /opt/homebrew/bin/zig ]; then
        ZIG=/opt/homebrew/bin/zig
    else
        ZIG=zig
    fi
fi

if [ ! -f "$ZIG_SYRUP/src/syrup.zig" ]; then
    echo "error: vendor/zig-syrup not initialised. Run:" >&2
    echo "  git submodule update --init vendor/zig-syrup" >&2
    exit 1
fi

if ! command -v "$ZIG" &>/dev/null; then
    echo "error: zig not found in PATH. Set ZIG=/path/to/zig or install zig >= 0.15." >&2
    exit 1
fi

ZIG_VERSION=$("$ZIG" version)
echo "=== zig-syrup benchmark (zig $ZIG_VERSION) ===" >&2

# Build the bench-zig executable with ReleaseFast optimisation.
cd "$ZIG_SYRUP"
"$ZIG" build bench -Doptimize=ReleaseFast 2>&1
BENCH_BIN=$(find "$ZIG_SYRUP/zig-out/bin" -name 'bench-zig' -type f 2>/dev/null | head -1)
if [ -z "$BENCH_BIN" ]; then
    echo "error: bench-zig binary not found after build" >&2
    exit 1
fi

exec "$BENCH_BIN"
