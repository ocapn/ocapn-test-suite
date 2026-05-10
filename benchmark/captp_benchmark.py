#!/usr/bin/env python3
"""
CapTP per-op latency benchmark.

Establishes a single CapTP session (or reconnects only when required) and
measures round-trip latency for each CapTP op.

Usage (from repo root):
    python benchmark/captp_benchmark.py 'ocapn://...<locator>...'

Example:
    python benchmark/captp_benchmark.py \\
        'ocapn://a2ef69ddd5f84840970612ff660f5058.tcp-testing-only?host=127.0.0.1&port=22045'

Options:
    --iterations N        Iterations for low-reconnect ops  (default 1000)
    --reconnect-iters N   Iterations for ops that need reconnect (default 100)
    --captp-version VER   CapTP version string sent in op:start-session (default "1.0")
    --timeout SECS        Per-message timeout in seconds (default 30)
"""

import argparse
import os
import statistics
import sys
import time

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contrib.syrup import Symbol
from netlayers.testing_only_tcp import TestingOnlyTCPNetlayer
from utils.captp_types import (
    OpAbort,
    OpDeliver,
    OpGcAnswers,
    OpGcExports,
    OpListen,
)
from utils.ocapn_uris import OCapNPeer

DEFAULT_N = 1000
DEFAULT_N_RECONNECT = 100
DEFAULT_CAPTP_VERSION = "1.0"
DEFAULT_TIMEOUT = 30

SWISS_ECHO = b"IO58l1laTyhcrgDKbEzFOO32MDd6zE5w"
SWISS_GREETER = b"VMDDd1voKWarCe2GvgLbxbVFysNzRPzx"
SWISS_PROMISE_RESOLVER = b"IokCxYmMj04nos2JN1TDoY1bT8dXh6Lr"
SWISS_CAR_FACTORY_BUILDER = b"JadQ0++RzsD4M+40uLxTWVaVqM10DcBJ"


def _new_session(netlayer, ocapn_peer, captp_version):
    session = netlayer.connect(ocapn_peer)
    session.setup_session(captp_version)
    return session


def _ms(secs):
    return secs * 1000.0


def _stats(samples_secs):
    samples_ms = [_ms(s) for s in samples_secs]
    return {
        "mean": statistics.mean(samples_ms),
        "p50": statistics.median(samples_ms),
        "p95": sorted(samples_ms)[int(len(samples_ms) * 0.95)],
        "p99": sorted(samples_ms)[int(len(samples_ms) * 0.99)],
    }


# ---------------------------------------------------------------------------
# Individual benchmark functions
# Each returns a list of per-iteration wall-clock durations in seconds.
# ---------------------------------------------------------------------------

def bench_start_session(netlayer, ocapn_peer, captp_version, n, timeout):
    """op:start-session — measure time to complete a full session handshake."""
    samples = []
    for _ in range(n):
        raw_sock = netlayer.connect(ocapn_peer)
        t0 = time.perf_counter()
        raw_sock.setup_session(captp_version)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
        try:
            raw_sock.close()
        except Exception:
            pass
    return samples


def bench_deliver_no_answer(session, echo_ref, n, timeout):
    """op:deliver (fire-and-forget) — deliver with no answer_position and no resolve_me_desc."""
    samples = []
    for _ in range(n):
        op = OpDeliver(
            to=echo_ref,
            args=["ping"],
            answer_position=False,
            resolve_me_desc=False,
        )
        t0 = time.perf_counter()
        session.send_message(op)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def bench_deliver_with_resolve(session, echo_ref, n, timeout):
    """op:deliver (with resolve_me_desc) — measure full round-trip until resolution."""
    samples = []
    for _ in range(n):
        resolve_me = session.next_import_object
        op = OpDeliver(
            to=echo_ref,
            args=["ping"],
            answer_position=False,
            resolve_me_desc=resolve_me,
        )
        t0 = time.perf_counter()
        session.send_message(op)
        session.expect_promise_resolution(op.exported_resolve_me_desc, timeout=timeout)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def bench_deliver_pipeline(session, car_factory_builder_ref_pipelined, n, timeout):
    """op:deliver with 3-hop promise pipeline — car-factory-builder → factory → car → drive."""
    samples = []
    for _ in range(n):
        factory_op = OpDeliver(
            to=car_factory_builder_ref_pipelined,
            args=[],
            answer_position=session.next_answer.position,
            resolve_me_desc=session.next_import_object,
        )
        session.send_message(factory_op)

        car_op = OpDeliver(
            to=factory_op.vow,
            args=[[Symbol("red"), Symbol("zoomracer")]],
            answer_position=session.next_answer.position,
            resolve_me_desc=session.next_import_object,
        )
        session.send_message(car_op)

        drive_op = OpDeliver(
            to=car_op.vow,
            args=[],
            answer_position=False,
            resolve_me_desc=session.next_import_object,
        )
        t0 = time.perf_counter()
        session.send_message(drive_op)
        session.expect_promise_resolution(drive_op.exported_resolve_me_desc, timeout=timeout)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def bench_listen_fulfill(session, promise_resolver_ref, n, timeout):
    """op:listen (fulfill path) — get promise/resolver pair, listen, then fulfill."""
    samples = []
    for _ in range(n):
        get_pair_op = OpDeliver(
            to=promise_resolver_ref,
            args=[],
            answer_position=False,
            resolve_me_desc=session.next_import_object,
        )
        session.send_message(get_pair_op)
        resp = session.expect_promise_resolution(get_pair_op.exported_resolve_me_desc, timeout=timeout)
        vow, resolver = resp.args[1]

        listen_op = OpListen(
            to=vow.to_desc_export(),
            resolve_me_desc=session.next_import_object,
            wants_partial=False,
        )
        session.send_message(listen_op)

        resolve_msg = OpDeliver(
            to=resolver.to_desc_export(),
            args=[Symbol("fulfill"), Symbol("ok")],
            answer_position=False,
            resolve_me_desc=False,
        )
        t0 = time.perf_counter()
        session.send_message(resolve_msg)
        session.expect_promise_resolution(listen_op.exported_resolve_me_desc, timeout=timeout)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def bench_listen_break(session, promise_resolver_ref, n, timeout):
    """op:listen (break path) — get promise/resolver pair, listen, then break."""
    samples = []
    for _ in range(n):
        get_pair_op = OpDeliver(
            to=promise_resolver_ref,
            args=[],
            answer_position=False,
            resolve_me_desc=session.next_import_object,
        )
        session.send_message(get_pair_op)
        resp = session.expect_promise_resolution(get_pair_op.exported_resolve_me_desc, timeout=timeout)
        vow, resolver = resp.args[1]

        listen_op = OpListen(
            to=vow.to_desc_export(),
            resolve_me_desc=session.next_import_object,
            wants_partial=False,
        )
        session.send_message(listen_op)

        break_msg = OpDeliver(
            to=resolver.to_desc_export(),
            args=[Symbol("break"), Symbol("oh-no")],
            answer_position=False,
            resolve_me_desc=False,
        )
        t0 = time.perf_counter()
        session.send_message(break_msg)
        session.expect_promise_resolution(listen_op.exported_resolve_me_desc, timeout=timeout)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def bench_gc_exports(session, echo_ref, n, timeout):
    """op:gc-exports — deliver a local object ref and wait for the GC message."""
    samples = []
    for _ in range(n):
        local_obj = session.next_import_object
        deliver_op = OpDeliver(echo_ref, [local_obj], False, False)

        t0 = time.perf_counter()
        session.send_message(deliver_op)
        _wait_for_gc_export(session, local_obj.position, timeout=timeout)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def _wait_for_gc_export(session, position, timeout):
    """Drain messages until op:gc-exports for *position* is received."""
    gc_totals = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        msg = session.receive_message(timeout=remaining)
        if isinstance(msg, OpGcExports):
            for pos, delta in zip(msg.export_positions, msg.wire_deltas):
                gc_totals[pos] = gc_totals.get(pos, 0) + delta
            if gc_totals.get(position, 0) >= 1:
                return
    raise TimeoutError(f"op:gc-exports for position {position} not received within {timeout}s")


def bench_gc_answers(session, greeter_ref, n, timeout):
    """op:gc-answers — deliver a message that causes the remote to GC an answer position."""
    samples = []
    for _ in range(n):
        object_to_greet = session.next_import_object
        deliver_op = OpDeliver(greeter_ref, [object_to_greet], False, False)
        session.send_message(deliver_op)

        greeting_op = session.expect_message_to(object_to_greet.to_desc_export(), timeout=timeout)

        reply = OpDeliver(
            to=greeting_op.exported_resolve_me_desc,
            args=[Symbol("fulfill"), "Hello"],
            answer_position=False,
            resolve_me_desc=False,
        )
        t0 = time.perf_counter()
        session.send_message(reply)
        _wait_for_gc_answer(session, greeting_op.answer_position, timeout=timeout)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


def _wait_for_gc_answer(session, answer_position, timeout):
    """Drain messages until op:gc-answers containing *answer_position* is received."""
    gc_answers = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        msg = session.receive_message(timeout=remaining)
        if isinstance(msg, OpGcAnswers):
            gc_answers.update(msg.answer_positions)
            if answer_position in gc_answers:
                return
    raise TimeoutError(
        f"op:gc-answers for answer_position {answer_position} not received within {timeout}s"
    )


def bench_abort(netlayer, ocapn_peer, captp_version, n, timeout):
    """op:abort — connect, set up session, send op:abort, then close locally."""
    samples = []
    for _ in range(n):
        session = _new_session(netlayer, ocapn_peer, captp_version)
        abort_op = OpAbort("benchmark-abort")
        t0 = time.perf_counter()
        session.send_message(abort_op)
        try:
            session.connection.close()
        except Exception:
            pass
        t1 = time.perf_counter()
        samples.append(t1 - t0)
    return samples


# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------

def print_results(rows):
    col_op = max(len(r["op"]) for r in rows)
    col_op = max(col_op, len("op_name"))
    header = (
        f"{'op_name':<{col_op}}  "
        f"{'n_iters':>8}  "
        f"{'mean_ms':>10}  "
        f"{'p50_ms':>10}  "
        f"{'p95_ms':>10}  "
        f"{'p99_ms':>10}"
    )
    sep = "-" * len(header)
    print("\nCapTP per-op latency benchmark")
    print(sep)
    print(header)
    print(sep)
    for r in rows:
        s = r["stats"]
        print(
            f"{r['op']:<{col_op}}  "
            f"{r['n']:>8}  "
            f"{s['mean']:>10.3f}  "
            f"{s['p50']:>10.3f}  "
            f"{s['p95']:>10.3f}  "
            f"{s['p99']:>10.3f}"
        )
    print(sep)


def _run_bench(label, func, n, *args, **kwargs):
    print(f"  Running {label} (n={n})...", flush=True)
    samples = func(*args, n=n, **kwargs)
    return {"op": label, "n": len(samples), "stats": _stats(samples)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark CapTP op round-trip latency."
    )
    parser.add_argument("locator", help="OCapN peer locator URI")
    parser.add_argument("--iterations", "-n", type=int, default=DEFAULT_N, metavar="N")
    parser.add_argument(
        "--reconnect-iters", type=int, default=DEFAULT_N_RECONNECT, metavar="N",
        help="Iterations for ops that require reconnect (default: 100)",
    )
    parser.add_argument("--captp-version", default=DEFAULT_CAPTP_VERSION, metavar="VER")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SECS")
    args = parser.parse_args()

    ocapn_peer = OCapNPeer.from_uri(args.locator)
    n = args.iterations
    nr = args.reconnect_iters
    captp_version = args.captp_version
    timeout = args.timeout

    if ocapn_peer.transport != Symbol("tcp-testing-only"):
        print(f"ERROR: Only tcp-testing-only transport is supported, got: {ocapn_peer.transport}")
        sys.exit(1)

    netlayer = TestingOnlyTCPNetlayer(
        listen_address=ocapn_peer.hints.get("host", "127.0.0.1")
    )

    print(f"Connecting to {args.locator}")
    session = _new_session(netlayer, ocapn_peer, captp_version)
    print("Session established. Pre-fetching object references...")

    echo_ref = session.fetch_object(SWISS_ECHO)
    greeter_ref = session.fetch_object(SWISS_GREETER)
    promise_resolver_ref = session.fetch_object(SWISS_PROMISE_RESOLVER)
    car_factory_builder_ref = session.fetch_object(SWISS_CAR_FACTORY_BUILDER, pipeline=True)

    print("Starting benchmarks...\n")
    rows = []

    rows.append(_run_bench(
        "op:start-session", bench_start_session, nr,
        netlayer, ocapn_peer, captp_version, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:deliver (fire-and-forget)", bench_deliver_no_answer, n,
        session, echo_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:deliver (with resolve)", bench_deliver_with_resolve, n,
        session, echo_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:deliver (3-hop pipeline)", bench_deliver_pipeline, n,
        session, car_factory_builder_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:listen (fulfill)", bench_listen_fulfill, n,
        session, promise_resolver_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:listen (break)", bench_listen_break, n,
        session, promise_resolver_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:gc-exports", bench_gc_exports, n,
        session, echo_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:gc-answers", bench_gc_answers, n,
        session, greeter_ref, timeout=timeout,
    ))

    rows.append(_run_bench(
        "op:abort (reconnect)", bench_abort, nr,
        netlayer, ocapn_peer, captp_version, timeout=timeout,
    ))

    try:
        session.close()
    except Exception:
        pass

    print_results(rows)


if __name__ == "__main__":
    main()
