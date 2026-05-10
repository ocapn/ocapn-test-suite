# Benchmark Follow-Up Items

This file tracks review items that should be evaluated with upstream project maintainers before larger behavioral changes are made.

## CapTP abort latency semantics

- **Current state:** `benchmark/captp_benchmark.py` measures local `op:abort` send plus local connection close.
- **Question for upstream:** Should the benchmark instead wait for a remote EOF / remote-side close event?
- **Why defer:** The current session API does not clearly expose a portable, reliable “remote observed abort and closed” measurement path. Changing this could make the benchmark transport- or implementation-specific.

## JavaScript dictionary representation

- **Current state:** `benchmark/syrup_bench_node.mjs` decodes dictionaries into plain objects and now rejects non-string keys.
- **Question for upstream:** Should the benchmark support full Syrup dictionary key semantics using `Map` instead of plain objects?
- **Why defer:** Switching to `Map` is more spec-complete, but it changes benchmark ergonomics and any downstream expectations around decoded dictionary shape.

## Cross-implementation benchmark payload alignment

- **Current state:** The benchmark suite compares useful but not perfectly identical payloads across Python, Node.js, Haskell, Go, and Zig.
- **Question for upstream:** Should all implementations use one shared corpus of encoded fixtures and benchmark cases?
- **Why defer:** A shared fixture corpus would be better for long-term interop, but it is broader than the minimal review fixes and may require agreeing on supported Syrup value coverage across implementations.
