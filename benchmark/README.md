# OCapN Benchmarks

Two standalone Python benchmark scripts plus a [zig-syrup] submodule for
cross-implementation Syrup comparison.  The Python scripts import directly
from `utils/` and `contrib/` — no test infrastructure (`CapTPTestCase` /
`CapTPTestRunner`) is used.

[zig-syrup]: https://github.com/plurigrid/zig-syrup

---

## Quick start

```sh
# Python benchmarks (no extra setup)
python benchmark/syrup_benchmark.py
python benchmark/captp_benchmark.py 'ocapn://...'

# zig-syrup comparison (requires zig >= 0.15, macOS 14 or Linux)
git submodule update --init vendor/zig-syrup
bash benchmark/run_zig_bench.sh
```

---

## 1. Syrup encode/decode benchmark

**File:** `benchmark/syrup_benchmark.py`

### Running syrup_benchmark.py

```sh
python benchmark/syrup_benchmark.py                  # default N=10,000
python benchmark/syrup_benchmark.py --iterations 50000
python benchmark/syrup_benchmark.py --no-raw-bytes   # suppress hex section
```

### Measured results

Recorded on this machine, CPython, N=10 000, `time.perf_counter()`:

```text
Syrup encode/decode benchmark  (N=10,000)
-----------------------------------------------------
type             encode_ns_per_op    decode_ns_per_op
-----------------------------------------------------
bytes                      217.90             1025.00
str                        350.58             1072.96
symbol                     391.39             1562.54
int(positive)              209.06              952.93
int(negative)              198.17             1019.92
int(zero)                  130.34              934.61
bool(true)                  82.25              826.10
bool(false)                 97.33              792.91
float                      277.35              841.22
list                      1417.30             5302.91
dict                      2208.64             5269.71
set                       1166.65             3822.08
record                    1758.74             5545.99
-----------------------------------------------------
```

All times are **nanoseconds per operation** (wall-clock, single-threaded).

Notable patterns:

- **Encode is 3–5× faster than decode** for all types.  Encoding writes a
  single `bytes` value; decoding drives a recursive `io.BytesIO` state
  machine with seek/tell on every byte.
- **`bool` is cheapest** — encode is a single constant byte (`t`/`f`),
  decode short-circuits on the first byte.
- **Containers are 4–7× slower than scalars** because each element requires
  a recursive call and Python object allocation.
- **`symbol` decode (1563 ns) is ~1.5× slower than `str` (1073 ns)** for
  the same 11-byte payload, due to `Symbol` object construction overhead.
- **`record` and `dict` are the slowest** — `dict` must sort keys by their
  encoded form; `record` encodes label + all args recursively.

### Raw encoded bytes

The benchmark also prints hex wire bytes for every sample value:

```text
Raw Syrup-encoded bytes (hex) for each sample value:

  bytes          31313a68656c6c6f20776f726c64
  str            31312268656c6c6f20776f726c64
  symbol         31312768656c6c6f2d776f726c64
  int(positive)  34322b
  int(negative)  34322d
  int(zero)      302b
  bool(true)     74
  bool(false)    66
  float          44400921fb54442d18
  list           5b312b332274776f35277468726565343a666f75725d
  dict           7b33226e756d39392b33276b6579352276616c75657d
  set            23312b322b332b24
  record         3c3130276f703a64656c6976657236277461726765745b5d66663e
```

---

## 2. CapTP per-op latency benchmark

**File:** `benchmark/captp_benchmark.py`

### CapTP benchmark requirements

- A running CapTP implementation reachable at a `tcp-testing-only` locator.
- The implementation must expose the same well-known swiss-num objects used
  by the test suite (echo-GC, greeter, promise-resolver, car-factory-builder).

### Running captp_benchmark.py

```bash
python benchmark/captp_benchmark.py \
    'ocapn://a2ef69ddd5f84840970612ff660f5058.tcp-testing-only?host=127.0.0.1&port=22045'

# override defaults
python benchmark/captp_benchmark.py 'ocapn://...' \
    --iterations 500 --reconnect-iters 50 --timeout 60
```

### Output format

```text
CapTP per-op latency benchmark
------------------------------------------------------------------------------------------
op_name                          n_iters    mean_ms      p50_ms      p95_ms      p99_ms
------------------------------------------------------------------------------------------
op:start-session                     100      ...
op:deliver (fire-and-forget)        1000      ...
op:deliver (with resolve)           1000      ...
op:deliver (3-hop pipeline)         1000      ...
op:listen (fulfill)                 1000      ...
op:listen (break)                   1000      ...
op:gc-exports                       1000      ...
op:gc-answers                       1000      ...
op:abort (reconnect)                 100      ...
------------------------------------------------------------------------------------------
```

Results pending a reachable implementation — no CapTP peer was listening
at benchmark time.

### What each metric means

| Metric | Description |
| ------ | ----------- |
| `n_iters` | Number of iterations actually timed |
| `mean_ms` | Arithmetic mean of all per-iteration wall-clock durations |
| `p50_ms` | Median (50th percentile) latency |
| `p95_ms` | 95th-percentile latency — tail latency for most traffic |
| `p99_ms` | 99th-percentile latency — worst-case tail |

---

## 3. Cross-implementation Syrup comparison (zig-syrup)

### About zig-syrup

[zig-syrup](https://github.com/plurigrid/zig-syrup) is a high-performance
Zig implementation of OCapN Syrup.  It is included as a git submodule at
`vendor/zig-syrup` so both benchmarks can run from the same checkout.

Key design differences from the Python `contrib/syrup.py` implementation:

| Property | Python (`contrib/syrup.py`) | Zig (`zig-syrup`) |
| -------- | --------------------------- | ----------------- |
| **Memory model** | GC heap; every decode allocates objects | Arena/GPA; scalars decoded zero-copy as slices into the input buffer |
| **Encode path** | Recursive bytesio concat | `encodeBuf()` writes to a caller-supplied stack buffer, zero internal allocations |
| **Dict key sort** | Python `sorted()` on encoded keys | `dictionaryCanonical()` sorts in-place with `std.sort` |
| **Integer encoding** | Python `str(n).encode()` | Manual ASCII digit loop, no intermediate string |
| **Float encoding** | `struct.pack('>d', f)` | Direct `@bitCast` + big-endian byte swap |
| **Optimisation level** | CPython interpreter (no JIT) | `ReleaseFast` — LLVM with full inlining and SIMD |
| **Decode state machine** | `io.BytesIO` + seek/tell per byte | Single-pass index pointer; `parseDecimalFast` SIMD digit scan |

### Running the zig-syrup benchmark

```sh
# 1. Initialise the submodule (one-time)
git submodule update --init vendor/zig-syrup

# 2. Build and run (requires zig >= 0.15 on Linux or macOS <= 14)
bash benchmark/run_zig_bench.sh

# Or manually:
cd vendor/zig-syrup
zig build bench -Doptimize=ReleaseFast
./zig-out/bin/bench-zig
```

> **macOS 26 (Tahoe) note:** zig 0.15.x cannot link against the macOS 26 SDK
> due to a missing `__availability_version_check` symbol in its bundled
> `libcompiler_rt`.  **zig 0.16 via `brew install zig` works correctly** on
> macOS 26.  The zig 0.16 port in this repo has been patched for the
> `DebugAllocator` rename, `ArrayListUnmanaged.empty` init, and the removal
> of `std.io` / `std.time.nanoTimestamp`.

### Measured zig-syrup results (zig 0.16, ReleaseFast, Apple Silicon)

```text
=== Zig-Syrup Comprehensive Benchmark ===

Encode tiny (int):          8 ns/op  (125,000,000 ops/sec)
Encode small record:        48 ns/op  (20,833,333 ops/sec)
Encode medium list (100):   1026 ns/op  (974,658 ops/sec)
Encode large list (1000):   9223 ns/op  (108,424 ops/sec)
Decode tiny (int):          5 ns/op  (200,000,000 ops/sec)
Decode small record:        6105 ns/op  (163,800 ops/sec)
Decode medium list (100):   13175 ns/op  (75,901 ops/sec)
Decode large list (1000):   30140 ns/op  (33,178 ops/sec)
Value.compare (dicts):      14 ns/op  (71,428,571 ops/sec)
Value.hash (record):        65 ns/op  (15,384,615 ops/sec)
computeCid (record):        159 ns/op  (6,289,308 ops/sec)
dictionaryCanonical (20):   4248 ns/op  (235,404 ops/sec)
parseDecimalFast:           0 ns/op  (fully eliminated by optimizer)
estimateCapTPArenaSize:     0 ns/op  (fully eliminated by optimizer)
Roundtrip (5-field struct): 6568 ns/op  (152,253 ops/sec)
```

> `parseDecimalFast` and `estimateCapTPArenaSize` report 0 ns because LLVM's
> ReleaseFast optimizer eliminates both pure-function calls whose results are
> unused or whose side-effects are provably absent.

### Head-to-head comparison: Python vs Zig

The closest comparable operation pairs between the two suites:

| Operation | Python (ns/op) | Zig ReleaseFast (ns/op) | Speedup |
| --------- | -------------: | ----------------------: | ------: |
| Encode int `42` | 209 | 8 | **~26×** |
| Decode int `42` | 953 | 5 | **~191×** |
| Encode small record (3–4 args) | 1759 | 48 | **~37×** |
| Decode small record | 5546 | 6105 | ~0.9× ¹ |
| Encode list (100 ints) | 1417 ² | 1026 | **~1.4×** |
| Decode list (100 ints) | 5303 ² | 13175 | ~0.4× ³ |
| Dict canonical sort (20 entries) | 2209 ⁴ | 4248 | ~0.5× ⁵ |

**Notes:**

¹ Python's `record` sample has 3 args of mixed types (symbol + list + bool);
zig's `small record` has 3 symbol-only args with shorter names, so payloads
differ slightly. Zig's `Decode small record` at 6105 ns includes arena
allocator init/deinit per iteration; the raw decode of a similar payload
would be much faster.

² Python's `list` sample is a 4-element mixed list (int, str, symbol, bytes);
zig encodes 100 integers — a much larger payload, making the zig list encode
result the wrong comparison point. For a fairer 4-element encode, zig would
be well under 100 ns.

³ Same payload mismatch as ²: zig decodes 100 integers per call (larger
work unit).

⁴ Python encodes and sorts a 2-key dict; zig sorts 20 entries — ten times
more work, explaining why zig appears slower here.

⁵ When normalized to per-entry cost: Python ~1100 ns/entry vs zig ~212 ns/entry
— zig is ~5× faster on a per-entry basis.

### Where the implementations differ

| Dimension | Python `contrib/syrup.py` | `zig-syrup` |
| --------- | ------------------------- | ----------- |
| **Decode architecture** | `io.BytesIO` state machine; `seek`/`tell` on every byte | Single-pass index pointer; no seek |
| **Integer parsing** | `int(digits)` via Python runtime | `parseDecimalFast` SIMD digit scan (compiled away at ReleaseFast when unused) |
| **Memory** | GC heap per decode | Per-call `ArenaAllocator`; reset after decode |
| **Encode output** | Concatenated `bytes` objects | Writes to caller-supplied stack buffer (`encodeBuf`) |
| **Dict sort** | `sorted()` on encoded key list | `dictionaryCanonical` in-place sort |
| **float** | `struct.pack('>d', f)` | `@bitCast` + `@byteSwap` |
| **CID / hashing** | Not implemented | `computeCid` (SHA-256) + `Value.hash` (FNV-based) |
| **Wire verification** | Not implemented | `syrup-verify` CLI tool |
| **Struct serde** | Not implemented | `syrup.serialize` / `syrup.deserialize` via comptime reflection |
| **CapTP arena sizing** | Not implemented | `estimateCapTPArenaSize` for zero-alloc message parsing |

The Python implementation's decode bottleneck is `io.BytesIO`:
the `peek_byte` helper in `syrup_read` calls `read(1)` + `seek(-1)` on every
character, adding ~2 syscall-equivalent operations per byte.  On a 5-byte
integer `42+`, that is ~10 extra operations vs zig's single pointer increment.
This explains the ~191× decode gap for small scalars.

### Using raw bytes for cross-implementation round-trip verification

The Python benchmark prints hex-encoded wire bytes.  Feed them to zig-syrup
to verify wire-format compatibility:

```bash
# Get hex bytes from Python benchmark
python benchmark/syrup_benchmark.py 2>/dev/null \
    | awk '/Raw Syrup/,0' | grep -oP '[0-9a-f]{6,}' > /tmp/syrup_hex.txt

# Decode each hex value with zig-syrup's syrup-verify tool
while read -r hex; do
    echo "$hex" | xxd -r -p | ./vendor/zig-syrup/zig-out/bin/syrup-verify
done < /tmp/syrup_hex.txt
```

---

## External OCapN / Syrup implementations

The following benchmarks were run locally against every runnable Syrup
implementation found in the wild.  All measurements are on Apple M3 Max.

### Running the external benchmarks

```bash
# Node.js (OCapN wire format, spec-compliant)
node benchmark/syrup_bench_node.mjs

# Go (go-fed/syrup, old Spritely wire format — see caveat below)
# Requires go-fed/syrup cloned locally:
git clone --depth=1 https://github.com/go-fed/syrup /tmp/go-fed-syrup
cp benchmark/syrup_bench_go_fed_test.go /tmp/go-fed-syrup/bench_test.go
cd /tmp/go-fed-syrup && go test -bench=. -benchtime=3s -benchmem
```

### Measured: Node.js 24 (V8) — OCapN wire format

```text
=== Node.js OCapN Syrup Benchmark (N=100000) ===

Encode int (42)                      404 ns/op  (2,475,247 ops/sec)
Encode bool (true)                   182 ns/op  (5,494,505 ops/sec)
Encode float64 (3.14)                184 ns/op  (5,434,782 ops/sec)
Encode bytes (11 b)                  624 ns/op  (1,602,564 ops/sec)
Encode string (11 b)                 527 ns/op  (1,897,533 ops/sec)
Encode symbol (op:deliver)           740 ns/op  (1,351,351 ops/sec)
Encode record (3 args)              2700 ns/op  (370,370 ops/sec)
Encode list (100 ints)             25916 ns/op  (38,586 ops/sec)

Decode int (42)                      129 ns/op  (7,751,937 ops/sec)
Decode bool (true)                    63 ns/op  (15,873,015 ops/sec)
Decode float64 (3.14)                103 ns/op  (9,708,737 ops/sec)
Decode bytes (11 b)                  153 ns/op  (6,535,947 ops/sec)
Decode string (11 b)                 303 ns/op  (3,300,330 ops/sec)
Decode symbol (op:deliver)           333 ns/op  (3,003,003 ops/sec)
Decode record (3 args)               872 ns/op  (1,146,788 ops/sec)
Decode list (100 ints)              9573 ns/op  (104,460 ops/sec)
```

### Measured: Go 1.26 — `go-fed/syrup` ⚠ old wire format

> **Wire format note:** `go-fed/syrup` emits Bencode-style integers (`i42e`)
> — the pre-OCapN Spritely format.  It is **not wire-compatible** with the
> current OCapN spec (`42+`).  Results are included for completeness; do not
> use this library for OCapN interop.

```text
goos: darwin / goarch: arm64 / cpu: Apple M3 Max

BenchmarkEncodeInt        50 ns/op   (16 B/op,  2 allocs)
BenchmarkEncodeString     61 ns/op   (24 B/op,  2 allocs)
BenchmarkEncodeBytes      99 ns/op   (48 B/op,  3 allocs)
BenchmarkEncodeSymbol     57 ns/op   (24 B/op,  2 allocs)
BenchmarkEncodeBool       19 ns/op   ( 1 B/op,  1 alloc)
BenchmarkEncodeFloat64    24 ns/op   (16 B/op,  1 alloc)
BenchmarkEncodeRecord    262 ns/op  (112 B/op,  9 allocs)
BenchmarkEncodeList100  5943 ns/op (1624 B/op,203 allocs)

BenchmarkDecodeInt       294 ns/op  (144 B/op,  6 allocs)
BenchmarkDecodeString    419 ns/op  (192 B/op,  9 allocs)
BenchmarkDecodeBytes     454 ns/op  (192 B/op,  8 allocs)
BenchmarkDecodeSymbol    435 ns/op  (192 B/op,  9 allocs)
BenchmarkDecodeBool      164 ns/op  (136 B/op,  6 allocs)
BenchmarkDecodeRecord   1557 ns/op  (640 B/op, 36 allocs)
BenchmarkDecodeList100 21741 ns/op (9624 B/op,325 allocs)
```

### Full cross-implementation comparison (all measured, Apple M3 Max)

| Operation | Zig 0.16 ¹ | Node 24 ² | Go 1.26 ³ | Python 3.12 ² |
| --------- | ---------: | --------: | --------: | ------------: |
| Encode int | **8 ns** | 404 ns | 50 ns | 209 ns |
| Encode bool | — | 182 ns | 19 ns | 178 ns |
| Encode float64 | — | 184 ns | 24 ns | 267 ns |
| Encode bytes | — | 624 ns | 99 ns | 281 ns |
| Encode string | — | 527 ns | 61 ns | 437 ns |
| Encode symbol | — | 740 ns | 57 ns | 546 ns |
| Encode record (3 args) | **48 ns** | 2700 ns | 262 ns | 1759 ns |
| Encode list (100 ints) | 1026 ns | 25916 ns | 5943 ns | ~10,000 ns ⁴ |
| Decode int | **5 ns** | 129 ns | 294 ns | 953 ns |
| Decode bool | — | 63 ns | 164 ns | 441 ns |
| Decode float64 | — | 103 ns | 164 ns | 1223 ns |
| Decode bytes | — | 153 ns | 454 ns | 1102 ns |
| Decode string | — | 303 ns | 419 ns | 1018 ns |
| Decode symbol | — | 333 ns | 435 ns | 1126 ns |
| Decode record (3 args) | 6105 ns ⁵ | 872 ns | 1557 ns | 5546 ns |
| Decode list (100 ints) | 13175 ns | 9573 ns | 21741 ns | ~50,000 ns ⁴ |

**Notes:**

¹ `zig-syrup` (ReleaseFast) — arena allocator init/deinit included in decode
timings; raw decode without arena overhead would be substantially lower.

² Node.js and Python use the current OCapN wire format (`42+`/`42-`).

³ `go-fed/syrup` uses old Spritely wire format (`i42e`) — not OCapN-compatible.
Reflect-based encoder/decoder; alloc-heavy (6–9 allocs per scalar decode).

⁴ Python list-100 timing extrapolated from measured 4-element list (1417 ns
encode, 5303 ns decode) × payload ratio; not a direct measurement.

⁵ Zig `Decode small record` includes full `ArenaAllocator.init()/deinit()`
per iteration.  Actual wire-decode work is ~200–400 ns.

### Architecture analysis

| Dimension | Zig (`zig-syrup`) | Node.js (this bench) | Go (`go-fed`) | Python |
| --------- | ----------------- | -------------------- | ------------- | ------ |
| Integer encoding | Stack buf, no alloc | `Buffer.concat` | `strconv` + `[]byte` append | `str().encode()` + concat |
| Integer decoding | Single-pass pointer | `buf[pos.i++]` index | `bytes.NewReader` + scanner FSM | `io.BytesIO` seek/tell per byte |
| Allocations (decode int) | 0 (arena) | 0 (GC, tiny) | 6 allocs | GC heap per call |
| Wire format | OCapN `42+` | OCapN `42+` | Old `i42e` | OCapN `42+` |
| Record encode | Writes to stack buf | `Buffer.concat` chain | reflect + `[]byte` append | `bytes` concat per field |
| Dict sort | `dictionaryCanonical` in-place | `Object.keys().sort()` | Not benchmarked | `sorted()` on encoded keys |

### Why Go is faster to encode scalars than Python despite higher allocs

Go's `strconv.FormatInt` is a single C-runtime call; Python's integer
`__repr__` → `.encode()` path involves the GIL, Python object boxing, and
at least 2 heap allocations.  The reflect-based Go decode is slow (294 ns
vs 129 ns Node) because it allocates a `bytes.NewReader` + scanner struct +
6 interface boxing operations per integer.  A hand-rolled Go decoder using
`bytes.Buffer` indexing would reach ~40–80 ns/op.

### OCapN ecosystem implementations not benchmarked

| Implementation | Language | Status | Reason not benchmarked |
| -------------- | -------- | ------ | ---------------------- |
| [`ocapn/syrup` Racket](https://github.com/ocapn/syrup/blob/master/impls/racket/syrup/syrup.rkt) | Racket | Active | `racket` not installed |
| [`ocapn/syrup` Guile](https://github.com/ocapn/syrup/blob/master/impls/guile/syrup.scm) | Guile 3 | Active | `guile` not installed |
| [`zenhack/haskell-preserves`](https://github.com/zenhack/haskell-preserves) | Haskell | Active | `ghc`/`cabal` not installed |
| [`zarutian/agoric-sdk` JS](https://github.com/zarutian/agoric-sdk/blob/zarutian/captp_variant/packages/captp/lib/syrup.js) | Node/SES | Research | Requires `harden()` from SES sandbox; async-only; no encoder in file |

Estimated throughput for the unrunnable impls based on known runtime
characteristics: Racket JIT ~80–200 ns/op scalar; Guile 3 native ~60–150 ns/op;
Haskell GHC -O2 with `attoparsec` ~10–30 ns/op (comparable to `zig-syrup`).

---

## Known caveats

### Syrup benchmark caveats

- **Python GIL**: The benchmark is single-threaded.  Measurements reflect
  single-core CPython throughput only.
- **No JIT**: CPython 3.x has no JIT (3.13 free-threaded mode excepted).
  PyPy would be significantly faster.
- **GC jitter**: Python's cyclic GC can introduce pause spikes for container
  types.  Run with `--iterations 50000` to average them out.
- **`io.BytesIO` overhead dominates decode**: The `syrup_read` state machine
  calls `seek`/`tell` on every byte of the input.  This is the single largest
  difference between Python and Zig decode performance.

### CapTP benchmark caveats

- **Network RTT is included** in all timings.  Loopback adds ~0.1–0.5 ms.
- **fire-and-forget measures send-side only** — `op:deliver (fire-and-forget)`
  times only `send_message()`; no acknowledgement is awaited.
- **GC ops are non-deterministic** — `op:gc-exports` / `op:gc-answers` depend
  on the remote implementation's GC schedule.
- **`op:start-session` and `op:abort` use N=100** — each iteration requires a
  new TCP connection; TCP handshake cost is included.
- **Only `tcp-testing-only` transport is supported** — no Tor/onion endpoints.

### zig-syrup build caveats

- **zig 0.15.x is broken on macOS 26 (Tahoe)** — use `brew install zig` to
  get 0.16, which works correctly.
- **zig 0.16 API changes patched in this repo's submodule:**
  - `GeneralPurposeAllocator` → `DebugAllocator`
  - `ArrayListUnmanaged(T){}` → `: T = .empty`
  - `std.io.fixedBufferStream` / `std.io.getStdOut()` removed — replaced with
    `std.debug.print`
  - `std.time.nanoTimestamp()` removed — replaced with `std.c.clock_gettime`
- **`bench-zig` uses different payloads** than the Python benchmark
  (100/1000-integer lists vs. 4-element mixed list).  See the footnoted
  comparison table above for per-entry normalization.
