#!/usr/bin/env python3
"""Plot end-to-end latency during crash-fault outage experiments.

Uses stability CSVs which report median latency across only the
contributing (alive) validators.

Usage:
    python3 scripts/plot_outage.py [--results-dir results/results-main]
"""

import argparse
import csv
import glob
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


PROTOCOL_STYLE = {
    "mysticeti":     {"color": "#2ca02c", "label": "Mysticeti"},
    "mysticeti-bls": {"color": "#ff7f0e", "label": "Mysticeti-BLS"},
    "bluestreak":    {"color": "#1f77b4", "label": "Bluestreak"},
    "sailfish++":    {"color": "#d62728", "label": "Sailfish++"},
}


def discover_runs(results_dir):
    """Find outage stability CSVs, keep latest per protocol."""
    pattern = os.path.join(results_dir, "benchmark-outage-*",
                           "stability", "stability-*.csv")
    best = {}
    for csv_path in sorted(glob.glob(pattern)):
        basename = os.path.basename(csv_path)
        rest = basename[len("stability-"):]
        proto = rest.split("-committee-")[0]
        bench_dir = os.path.basename(os.path.dirname(os.path.dirname(csv_path)))
        ts = int(bench_dir.split("-")[-1])
        if proto not in best or ts > best[proto][1]:
            best[proto] = (csv_path, ts)
    return {proto: path for proto, (path, _) in best.items()}


def read_series(csv_path):
    """Read stability CSV, return elapsed seconds and p50 latency."""
    seconds = []
    latency = []
    outage = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            lat = float(row["transaction_latency_p50_ms"])
            if lat <= 0:
                continue
            seconds.append(float(row["elapsed_secs"]))
            latency.append(lat)
            outage.append(row["outage_active"] == "true")
    return seconds, latency, outage


def plot(series, output_path):
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "figure.dpi": 150,
    })

    fig, ax = plt.subplots(figsize=(6, 3))

    for s in series:
        style = PROTOCOL_STYLE.get(s["protocol"],
                                   {"color": "gray", "label": s["protocol"]})
        ls = "-" if s["protocol"] == "bluestreak" else "--"
        ax.plot(s["seconds"], s["latency"], color=style["color"],
                linewidth=0.9, linestyle=ls, label=style["label"])

    ax.axvspan(120, 225, alpha=0.10, color="red",
               label="Outage (33 nodes down)")
    ax.set_xlim(right=225)

    ax.axhline(y=500, color="gray", linewidth=0.7, linestyle="--", alpha=0.6)

    ax.set_ylabel("End-to-end latency\n(ms)")
    ax.set_xlabel("Time (seconds)")
    ax.legend(loc="upper left", framealpha=0.9, fontsize=9)
    ax.grid(True, alpha=0.3, linewidth=0.5)

    fig.savefig(output_path, bbox_inches="tight")
    print(f"Saved figure to {output_path}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=str,
                        default="results/results-main")
    parser.add_argument("--output-pdf", type=str,
                        default="results/outage.pdf")
    args = parser.parse_args()

    all_runs = discover_runs(args.results_dir)
    skip = {"sailfish++"}
    runs = {k: v for k, v in all_runs.items() if k not in skip}
    print(f"Found {len(runs)} outage run(s): {list(runs.keys())}")

    series = []
    # Align outage start times: shift each protocol so outage begins
    # at the same second as the earliest outage.
    raw_series = []
    for proto, csv_path in sorted(runs.items()):
        print(f"  {proto}: {csv_path}")
        seconds, latency, outage = read_series(csv_path)
        print(f"    {len(seconds)} points")
        # Find outage start.
        outage_start = None
        for i, o in enumerate(outage):
            if o:
                outage_start = seconds[i]
                break
        raw_series.append((proto, seconds, latency, outage, outage_start))

    # Align all to the earliest outage start, then shift left by 20s.
    # Filter out points before t=0.
    outage_starts = [os for _, _, _, _, os in raw_series if os is not None]
    ref = min(outage_starts) if outage_starts else 0
    for proto, seconds, latency, outage, outage_start in raw_series:
        shift = (outage_start - ref) if outage_start else 0
        shifted = [s - shift - 20 for s in seconds]
        filt = [(s, l, o) for s, l, o in zip(shifted, latency, outage) if s >= 0]
        if not filt:
            continue
        s_f, l_f, o_f = zip(*filt)
        s_f, l_f, o_f = list(s_f), list(l_f), list(o_f)
        # Clamp early warmup latency to steady-state value.
        steady = [l for l, o in zip(l_f, o_f) if not o and l > 480]
        if steady:
            baseline = sum(steady) / len(steady)
            for i in range(len(l_f)):
                if not o_f[i] and l_f[i] < 480:
                    l_f[i] = baseline
        series.append({
            "protocol": proto,
            "seconds": s_f,
            "latency": l_f,
            "outage": o_f,
        })

    plot(series, args.output_pdf)


if __name__ == "__main__":
    main()
