#!/usr/bin/env python3
"""Backfill captured Prometheus metrics into a replay Prometheus TSDB.

Converts a captured `query_range` JSON response (matrix result) into OpenMetrics
text, then runs `promtool tsdb create-blocks-from openmetrics` to write TSDB
blocks the replay Prometheus serves directly — bypassing the out-of-order
ingestion window so historical samples load cleanly.

    prom_backfill.py <captured metrics.json> <output prometheus data dir>

Requires `promtool` on PATH.
"""
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict


def esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, out = sys.argv[1], sys.argv[2]
    with open(src) as f:
        data = json.load(f)
    result = data.get("data", {}).get("result", [])
    if not result:
        print("no series in capture — nothing to backfill")
        return 0

    # Group samples by metric family so OpenMetrics families aren't interleaved.
    families = defaultdict(list)
    for series in result:
        metric = series.get("metric", {})
        name = metric.get("__name__")
        if not name:
            continue
        labels = {k: v for k, v in metric.items() if k != "__name__"}
        labelstr = ",".join(f'{k}="{esc(str(v))}"' for k, v in sorted(labels.items()))
        sel = f"{name}{{{labelstr}}}" if labelstr else name
        for ts, val in series.get("values", []):
            try:
                fval = float(val)
            except (TypeError, ValueError):
                continue
            families[name].append((sel, fval, float(ts)))

    lines = []
    for name, samples in families.items():
        lines.append(f"# TYPE {name} gauge")
        for sel, fval, ts in samples:
            lines.append(f"{sel} {fval} {ts}")
    lines.append("# EOF")

    os.makedirs(out, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".openmetrics", delete=False) as tf:
        tf.write("\n".join(lines) + "\n")
        ompath = tf.name

    subprocess.run(
        ["promtool", "tsdb", "create-blocks-from", "openmetrics", ompath, out],
        check=True,
    )
    os.unlink(ompath)
    print(f"backfilled {len(families)} metric families into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
