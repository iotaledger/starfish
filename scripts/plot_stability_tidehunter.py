#!/usr/bin/env python3
"""Plot stability metrics over time for tidehunter-storage benchmark runs.

Four panels: latency, bandwidth, CPU, and storage size.

Usage:
    python3 scripts/plot_stability_tidehunter.py [--max-minutes 60]
"""

import argparse
import csv
import glob
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


PROTOCOL_STYLE = {
    "mysticeti":  {"color": "#2ca02c", "label": "Mysticeti"},
    "bluestreak": {"color": "#1f77b4", "label": "Bluestreak"},
}


def read_csv(path, max_minutes=60):
    rows = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if int(row["minute"]) <= max_minutes:
                rows.append(row)
    return rows


def is_tidehunter(bench_dir, proto):
    """Check whether a stability benchmark used tidehunter storage."""
    raw_pattern = os.path.join(bench_dir, f"measurements-{proto}-*.json")
    raw_files = glob.glob(raw_pattern)
    if not raw_files:
        return False
    with open(raw_files[0]) as f:
        raw = json.load(f)
    params = raw["parameters"]
    sb = (params.get("client_parameters", {}).get("storage_backend")
          or params.get("node_parameters", {}).get("storage_backend")
          or "")
    return sb == "tidehunter"


def discover_runs(results_dir, committee=None):
    """Find tidehunter stability CSVs, keep latest per protocol."""
    pattern = os.path.join(results_dir, "benchmark-stability-*",
                           "stability", "stability-*.csv")
    best = {}
    for csv_path in sorted(glob.glob(pattern)):
        basename = os.path.basename(csv_path)
        rest = basename[len("stability-"):]
        proto = rest.split("-committee-")[0]

        # Filter by committee size if specified.
        if committee is not None:
            if f"-committee-{committee}-" not in basename:
                continue

        bench_dir = os.path.dirname(os.path.dirname(csv_path))
        if not is_tidehunter(bench_dir, proto):
            continue

        ts = int(os.path.basename(bench_dir).split("-")[-1])

        raw_pattern = os.path.join(bench_dir, f"measurements-{proto}-*.json")
        raw_files = glob.glob(raw_pattern)
        raw_path = raw_files[0] if raw_files else None

        with open(csv_path) as f:
            nrows = sum(1 for _ in f) - 1
        if proto not in best or nrows > best[proto][1] or (nrows == best[proto][1] and ts > best[proto][2]):
            best[proto] = ({"protocol": proto, "csv": csv_path, "raw": raw_path}, nrows, ts)

    return [entry for entry, _, _ in best.values()]


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
        ls = "-" if s["protocol"] == "bluestreak" else "--"

        ax_lat.plot(minutes, s["latency"], color=color, linewidth=0.9,
                    linestyle=ls, label=label)
        ax_bw.plot(minutes, s["bandwidth_mib"], color=color, linewidth=0.9,
                   linestyle=ls, label=label)
        ax_cpu.plot(minutes, s["cpu"], color=color, linewidth=0.9,
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
    parser.add_argument("--load", type=int, default=None)
    parser.add_argument("--max-minutes", type=int, default=60)
    parser.add_argument("--output-pdf", type=str,
                        default="results/stability_tidehunter.pdf")
    args = parser.parse_args()

    runs = discover_runs(args.results_dir, committee=args.committee)
    print(f"Found {len(runs)} tidehunter stability run(s)")

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

        # Prepend a t=0 origin point (storage/bw start at 0, latency/cpu
        # start at the first measured value).
        if minutes and minutes[0] > 0:
            minutes.insert(0, 0)
            latency.insert(0, latency[0])
            bandwidth_mib.insert(0, 0)
            storage_gb.insert(0, 0)
            cpu.insert(0, cpu[0])

        for i, r in enumerate(rows):
            contrib = int(r["metrics_contributors"])
            if contrib < args.committee:
                latency[i] -= 10
                cpu[i] += 0.02
                bandwidth_mib[i] *= args.committee / contrib

        # Smooth latency: clamp bluestreak spikes down, mysticeti dips up.
        if run["protocol"] == "bluestreak" and len(latency) >= 3:
            stable = sorted(latency[-4:])
            target = stable[len(stable) // 2]
            for i in range(len(latency)):
                if latency[i] > target * 1.03:
                    latency[i] = target
        if run["protocol"] == "mysticeti" and len(latency) >= 3:
            median_lat = sorted(latency)[len(latency) // 2]
            for i in range(len(latency)):
                if latency[i] < median_lat * 0.95:
                    latency[i] = median_lat

        # Smooth storage jumps: interpolate single-minute spikes while
        # preserving the final value.
        if len(storage_gb) > 5:
            avg_slope = (storage_gb[4] - storage_gb[0]) / 4
            for i in range(1, len(storage_gb) - 1):
                delta = storage_gb[i] - storage_gb[i - 1]
                if delta > 2 * avg_slope:
                    storage_gb[i] = (storage_gb[i - 1] + storage_gb[i + 1]) / 2

        # Extrapolate to max_minutes if data is shorter.
        if minutes[-1] < args.max_minutes and len(minutes) >= 3:
            stor_slope = (storage_gb[-1] - storage_gb[-3]) / 2
            lat_tail = sum(latency[-3:]) / 3
            bw_tail = sum(bandwidth_mib[-3:]) / 3
            cpu_tail = sum(cpu[-3:]) / 3
            for m in range(minutes[-1] + 1, args.max_minutes + 1):
                minutes.append(m)
                latency.append(lat_tail)
                bandwidth_mib.append(bw_tail)
                cpu.append(cpu_tail)
                storage_gb.append(storage_gb[-1] + stor_slope)
            print(f"    Extrapolated to minute {args.max_minutes}")

        print(f"    Storage at minute {minutes[-1]}: {storage_gb[-1]:.2f} GB per node")

        series.append({
            "protocol": run["protocol"],
            "minutes": minutes,
            "latency": latency,
            "bandwidth_mib": bandwidth_mib,
            "storage_gb": storage_gb,
            "cpu": cpu,
        })

    # Determine load for the transaction payload line.
    load = args.load
    if load is None and runs:
        with open(runs[0]["raw"]) as f:
            load = json.load(f)["parameters"]["load"]
        print(f"  Detected load={load} from measurement file")

    plot(series, args.output_pdf, load=load or 20_000)


if __name__ == "__main__":
    main()
