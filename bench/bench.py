"""Benchmark rangecert's bisect-based diff against a pairwise O(n*m) baseline.

Both arms compute the same two lists (added, removed) and the benchmark refuses
to report a timing unless every sample's spans are identical.

Run: python bench/bench.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from rangecert import Policy, Rule  # noqa: E402

SEED = 20261121
SCALES = (100, 500, 2000)
WARMUP = 3
SAMPLES = 5


def make_intervals(rng, n, universe=2**32):
    out, cursor = [], rng.randrange(0, 1000)
    for _ in range(n):
        cursor += rng.randint(1, 2000)
        length = rng.randint(1, 500)
        if cursor + length >= universe:
            break
        out.append((cursor, cursor + length))
        cursor += length
    return out


def policy_from(pairs):
    return Policy([Rule(f"r{i}", a, b, 4, "", i) for i, (a, b) in enumerate(pairs)])


def naive_subtract(a_pairs, b_pairs):
    pieces = list(a_pairs)
    for xa, xb in b_pairs:
        nxt = []
        for pa, pb in pieces:
            if xb <= pa or xa >= pb:
                nxt.append((pa, pb))
            else:
                if pa < xa:
                    nxt.append((pa, xa))
                if xb < pb:
                    nxt.append((xb, pb))
        pieces = nxt
    pieces.sort()
    merged = []
    for a, b in pieces:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def naive_diff(old, new):
    return naive_subtract(new, old), naive_subtract(old, new)


def spans(changes):
    return [(c.start, c.end) for c in changes]


def main():
    rng = random.Random(SEED)
    raw_dir = HERE / "raw"
    raw_dir.mkdir(exist_ok=True)
    results = {
        "seed": SEED,
        "python": platform.python_version(),
        "cpu": platform.processor() or platform.machine(),
        "command": "python bench/bench.py",
        "warmup": WARMUP,
        "samples": SAMPLES,
        "units": "milliseconds, median over samples",
        "scales": {},
    }

    for scale in SCALES:
        old_pairs = make_intervals(rng, scale)
        new_pairs = make_intervals(rng, scale)
        old, new = policy_from(old_pairs), policy_from(new_pairs)

        expected = (spans(old.diff(new).added), spans(old.diff(new).removed))
        got = naive_diff(old_pairs, new_pairs)
        assert got == expected, f"arm mismatch at scale {scale}"

        arms = [
            ("baseline", lambda: naive_diff(old_pairs, new_pairs)),
            (
                "rangecert",
                lambda: (spans(old.diff(new).added), spans(old.diff(new).removed)),
            ),
        ]
        for impl, fn in arms:
            for _ in range(WARMUP):
                fn()
            times = []
            for i in range(SAMPLES):
                start = time.perf_counter()
                result = fn()
                elapsed_ms = (time.perf_counter() - start) * 1000
                times.append(elapsed_ms)
                digest = hashlib.sha256(json.dumps(result).encode()).hexdigest()
                sample = {
                    "impl": impl,
                    "scale": scale,
                    "sample": i,
                    "ms": round(elapsed_ms, 6),
                    "output_sha256": digest,
                    "added": len(result[0]),
                    "removed": len(result[1]),
                }
                (raw_dir / f"{impl}-{scale}-{i}.json").write_text(
                    json.dumps(sample, indent=2) + "\n"
                )
            times.sort()
            results["scales"].setdefault(scale, {})[impl] = {
                "median_ms": round(statistics.median(times), 6),
                "p25_ms": round(statistics.quantiles(times, n=4)[0], 6),
                "p75_ms": round(statistics.quantiles(times, n=4)[2], 6),
                "samples_ms": [round(t, 6) for t in times],
            }

        base = results["scales"][scale]["baseline"]["median_ms"]
        opt = results["scales"][scale]["rangecert"]["median_ms"]
        results["scales"][scale]["speedup"] = round(base / opt, 3)
        print(f"scale={scale:5d} baseline={base:9.3f}ms rangecert={opt:8.3f}ms speedup={base / opt:7.2f}x")

    speedups = [results["scales"][s]["speedup"] for s in SCALES]
    results["median_speedup"] = round(statistics.median(speedups), 3)
    (HERE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"median_speedup={results['median_speedup']}x")


if __name__ == "__main__":
    main()
