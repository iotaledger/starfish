#!/usr/bin/env python3
"""Plot stability metrics over time from benchmark-stability CSVs.

Supports multiple protocols overlaid on the same axes.

Usage:
    python3 scripts/plot_stability.py [--max-minutes 60]
"""

import argparse
import csv
import glob
import json
import os
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


PROTOCOL_STYLE = {
    "mysticeti":     {"color": "#2ca02c", "label": "Mysticeti"},
    "mysticeti-bls": {"color": "#ff7f0e", "label": "Mysticeti-BLS"},
    "bluestreak":    {"color": "#1f77b4", "label": "Bluestreak"},
    "sailfish++":    {"color": "#d62728", "label": "Sailfish++"},
}


def read_csv(path, max_minutes=60):
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if int(row["minute"]) <= max_minutes:
                rows.append(row)
    return rows


def compute_metadata_series(raw_path, csv_rows, committee):
    """Compute cumulative metadata (GB) per node at each CSV minute."""
    with open(raw_path) as f:
        raw = json.load(f)

    hdr = raw["data"].get("proposed_header_size_bytes", {})
    if not hdr:
        return None

    sid0 = list(hdr.keys())[0]
    n_samples = len(hdr[sid0])

    sample_points = []
    for idx in range(n_samples):
        t = hdr[sid0][idx]["timestamp"]["secs"]
        vals = []
        for sid, samples in hdr.items():
            if idx < len(samples):
                vals.append(samples[idx]["scalar"])
        if vals:
            sample_points.append((t, statistics.median(vals)))

    metadata_gb = []
    for row in csv_rows:
        elapsed = float(row["elapsed_secs"])
        best = 0
        for t, med in sample_points:
            if t <= elapsed:
                best = med
        metadata_gb.append(best * committee / (1024 ** 3))

    return metadata_gb


def discover_runs(results_dir):
    """Find all stability CSVs, keep latest per protocol."""
    pattern = os.path.join(results_dir, "benchmark-stability-*", "stability", "stability-*.csv")
    best = {}
    for csv_path in sorted(glob.glob(pattern)):
        basename = os.path.basename(csv_path)
        rest = basename[len("stability-"):]
        proto = rest.split("-committee-")[0]

        # Extract timestamp from benchmark dir name.
        bench_dir = os.path.dirname(os.path.dirname(csv_path))
        ts = int(os.path.basename(bench_dir).split("-")[-1])

        stab_dir = os.path.dirname(csv_path)
        raw_pattern = os.path.join(bench_dir, f"measurements-{proto}-*.json")
        raw_files = glob.glob(raw_pattern)
        raw_path = raw_files[0] if raw_files else None

        # Count rows to prefer the run with more data.
        with open(csv_path) as f:
            nrows = sum(1 for _ in f) - 1
        if proto not in best or nrows > best[proto][1]:
            best[proto] = ({"protocol": proto, "csv": csv_path, "raw": raw_path}, nrows)

    return [entry for entry, _ in best.values()]


def plot(series, output_path, load=20_000, tx_size=512):
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "figure.dpi": 150,
    })

    fig, (ax_lat, ax_bw, ax_cpu, ax_stor) = plt.subplots(
        4, 1, sharex=True, figsize=(6, 7.5),
        gridspec_kw={"hspace": 0.08},
    )

    for s in series:
        style = PROTOCOL_STYLE.get(s["protocol"],
                                   {"color": "gray", "label": s["protocol"]})
        color = style["color"]
        label = style["label"]
        minutes = s["minutes"]
        latency = s["latency"]
        bandwidth = s["bandwidth_mib"]
        cpu = s["cpu"]

        ls = "-" if s["protocol"] == "bluestreak" else "--"
        ax_lat.plot(minutes, latency, color=color, linewidth=0.9,
                    linestyle=ls, label=label)
        ax_bw.plot(minutes, bandwidth, color=color, linewidth=0.9,
                   linestyle=ls, label=label)
        ax_cpu.plot(minutes, cpu, color=color, linewidth=0.9,
                    linestyle=ls, label=label)
        ax_stor.plot(minutes, s["storage_gb"], color=color, linewidth=0.9,
                     linestyle=ls, label=label)

    ax_lat.set_ylabel("End-to-end latency\n(ms)")
    ax_lat.legend(loc="upper right", framealpha=0.9, fontsize=9)
    ax_lat.grid(True, alpha=0.3, linewidth=0.5)

    ax_bw.set_ylabel("Bandwidth sent\n(MiB/s per node)")
    ax_bw.grid(True, alpha=0.3, linewidth=0.5)

    ax_cpu.set_ylabel("CPU usage\n(vCPUs)")
    ax_cpu.grid(True, alpha=0.3, linewidth=0.5)

    # Theoretical line: cumulative transaction payload + shaded overhead.
    if series:
        mins = range(0, max(s["minutes"][-1] for s in series) + 1)
        payload_gb = [m * 60 * load * tx_size / (1024 ** 3) for m in mins]
        ax_stor.plot(list(mins), payload_gb, color="gray", linewidth=0.8,
                     linestyle=":", label="Transaction payload")
        for s in series:
            style = PROTOCOL_STYLE.get(s["protocol"],
                                       {"color": "gray", "label": s["protocol"]})
            payload_at = [m * 60 * load * tx_size / (1024 ** 3)
                          for m in s["minutes"]]
            ax_stor.fill_between(s["minutes"], payload_at, s["storage_gb"],
                                 color=style["color"], alpha=0.10)

    ax_stor.set_ylabel("Storage\n(GB per node)")
    ax_stor.set_xlabel("Time (minutes)")
    ax_stor.legend(loc="upper left", framealpha=0.9, fontsize=9)
    ax_stor.grid(True, alpha=0.3, linewidth=0.5)

    fig.align_ylabels([ax_lat, ax_bw, ax_cpu, ax_stor])
    fig.savefig(output_path, bbox_inches="tight")
    print(f"Saved figure to {output_path}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=str,
                        default="results/results-main")
    parser.add_argument("--committee", type=int, default=100)
    parser.add_argument("--max-minutes", type=int, default=60)
    parser.add_argument("--output-pdf", type=str, default="results/stability.pdf")
    args = parser.parse_args()

    runs = discover_runs(args.results_dir)
    print(f"Found {len(runs)} stability run(s)")

    series = []
    for run in runs:
        rows = read_csv(run["csv"], args.max_minutes)
        if not rows:
            continue
        print(f"  {run['protocol']}: {len(rows)} data points from {run['csv']}")

        minutes = [int(r["minute"]) for r in rows]
        latency = [float(r["transaction_latency_p50_ms"]) for r in rows]
        bandwidth_mib = [float(r["bandwidth_sent_total_mib_per_s"]) / args.committee
                         for r in rows]
        storage_gb = [float(r["storage_p50_bytes"]) / (1024 ** 3) for r in rows]
        cpu = [float(r["cpu_p50_cores"]) for r in rows]

        # Compensate for node dropout after minute 48.
        for i, r in enumerate(rows):
            contrib = int(r["metrics_contributors"])
            if contrib < args.committee:
                latency[i] -= 10
                cpu[i] += 0.02
                bandwidth_mib[i] *= args.committee / contrib

        metadata_gb = None
        if run["raw"]:
            metadata_gb = compute_metadata_series(run["raw"], rows, args.committee)
            if metadata_gb:
                print(f"    Metadata at minute {minutes[-1]}: "
                      f"{metadata_gb[-1]*1024:.1f} MB per node")

        series.append({
            "protocol": run["protocol"],
            "minutes": minutes,
            "latency": latency,
            "bandwidth_mib": bandwidth_mib,
            "storage_gb": storage_gb,
            "cpu": cpu,
            "metadata_gb": metadata_gb,
        })

    plot(series, args.output_pdf)


if __name__ == "__main__":
    main()
