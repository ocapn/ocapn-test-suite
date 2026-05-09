#!/usr/bin/env python3
"""
Syrup encode/decode benchmark.

Measures per-op latency for syrup_encode and syrup_decode across every
Syrup type.  Results are printed as a plain text table and the raw encoded
bytes for each sample value are printed so they can be piped to external
implementations (e.g. zig-syrup) for cross-implementation comparison.

Usage:
    python -m benchmark.syrup_benchmark [--iterations N]

or from the repo root:
    python benchmark/syrup_benchmark.py [--iterations N]
"""

import argparse
import os
import sys
import time

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contrib.syrup import Record, Symbol, syrup_decode, syrup_encode

DEFAULT_N = 10_000

SAMPLE_VALUES = [
    ("bytes",          b"hello world"),
    ("str",            "hello world"),
    ("symbol",         Symbol("hello-world")),
    ("int(positive)",  42),
    ("int(negative)",  -42),
    ("int(zero)",      0),
    ("bool(true)",     True),
    ("bool(false)",    False),
    ("float",          3.14159265358979323846),
    ("list",           [1, "two", Symbol("three"), b"four"]),
    ("dict",           {Symbol("key"): "value", "num": 99}),
    ("set",            frozenset({1, 2, 3})),
    ("record",         Record(Symbol("op:deliver"), [Symbol("target"), [], False, False])),
]


def _bench_encode(value, n: int) -> float:
    """Return total wall-clock seconds for n syrup_encode calls."""
    # warm-up
    syrup_encode(value)

    start = time.perf_counter()
    for _ in range(n):
        syrup_encode(value)
    return time.perf_counter() - start


def _bench_decode(encoded: bytes, n: int) -> float:
    """Return total wall-clock seconds for n syrup_decode calls."""
    # warm-up
    syrup_decode(encoded)

    start = time.perf_counter()
    for _ in range(n):
        syrup_decode(encoded)
    return time.perf_counter() - start


def _ns_per_op(total_seconds: float, n: int) -> float:
    return (total_seconds / n) * 1e9


def run(n: int = DEFAULT_N, print_bytes: bool = True) -> list[dict]:
    results = []

    for type_name, value in SAMPLE_VALUES:
        # sets must be encoded as sorted-byte sets; syrup_encode handles this,
        # but frozenset is not a set for isinstance checks – convert it.
        actual_value = set(value) if isinstance(value, frozenset) else value

        encoded = syrup_encode(actual_value)

        enc_secs = _bench_encode(actual_value, n)
        dec_secs = _bench_decode(encoded, n)

        results.append({
            "type": type_name,
            "encode_ns": _ns_per_op(enc_secs, n),
            "decode_ns": _ns_per_op(dec_secs, n),
            "encoded_bytes": encoded,
            "encoded_hex": encoded.hex(),
        })

    return results


def print_table(results: list[dict], n: int) -> None:
    col_type = max(len(r["type"]) for r in results)
    col_type = max(col_type, len("type"))
    col_enc = 18
    col_dec = 18

    header = (
        f"{'type':<{col_type}}  "
        f"{'encode_ns_per_op':>{col_enc}}  "
        f"{'decode_ns_per_op':>{col_dec}}"
    )
    sep = "-" * len(header)

    print(f"\nSyrup encode/decode benchmark  (N={n:,})")
    print(sep)
    print(header)
    print(sep)
    for r in results:
        print(
            f"{r['type']:<{col_type}}  "
            f"{r['encode_ns']:>{col_enc}.2f}  "
            f"{r['decode_ns']:>{col_dec}.2f}"
        )
    print(sep)


def print_raw_bytes(results: list[dict]) -> None:
    print("\nRaw Syrup-encoded bytes (hex) for each sample value:")
    print("(Feed these to external implementations for cross-impl comparison)")
    print()
    col = max(len(r["type"]) for r in results)
    for r in results:
        print(f"  {r['type']:<{col}}  {r['encoded_hex']}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark syrup_encode / syrup_decode per Syrup type."
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=DEFAULT_N,
        metavar="N",
        help=f"Number of iterations per measurement (default: {DEFAULT_N})",
    )
    parser.add_argument(
        "--no-raw-bytes",
        action="store_true",
        help="Suppress the raw-bytes section",
    )
    args = parser.parse_args()

    results = run(n=args.iterations)
    print_table(results, n=args.iterations)
    if not args.no_raw_bytes:
        print_raw_bytes(results)


if __name__ == "__main__":
    main()
