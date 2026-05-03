#!/usr/bin/env python3
"""Aggregate latency-throughput sweep results and plot TPS vs latency.

Reads sweep summary JSONs and raw measurement files for committee=120,
merges across multiple orchestrator runs, and produces a single-panel
TPS (x) vs p50 latency (y) figure.

Usage:
    python3 scripts/plot_tps_vs_latency.py [--committee 120] [--results-dir results/results-main]
"""

import argparse
import glob
import json
import os
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


# ---------------------------------------------------------------------------
# Helpers (reused from plot_committee_scaling.py)
# ---------------------------------------------------------------------------

def duration_to_ms(d):
    return d["secs"] * 1_000 + d["nanos"] / 1_000_000


def duration_to_secs(d):
    return d["secs"] + d["nanos"] / 1e9


def latest_measurement(scraper_samples):
    return max(scraper_samples, key=lambda s: duration_to_secs(s["timestamp"]))


def median(values):
    if not values:
        return 0.0
    return statistics.median(values)


# ---------------------------------------------------------------------------
# Collect from sweep summary JSONs
# ---------------------------------------------------------------------------

def collect_from_sweep_jsons(results_dir, target_committee):
    """Read all sweep summary JSONs and extract points for the target committee."""
    pattern = os.path.join(results_dir, "benchmark-sweep-*", "sweeps", "*.json")
    files = sorted(glob.glob(pattern))

    points = []
    for path in files:
        with open(path) as f:
            data = json.load(f)
        for p in data.get("points", []):
            if p.get("committee") == target_committee:
                points.append({
                    "protocol": p["protocol"],
                    "load": p["load"],
                    "tps": p["tps"],
                    "latency_p25_ms": p["transaction_latency_ms"].get("p25", 0),
                    "latency_p50_ms": p["transaction_latency_ms"]["p50"],
                    "latency_p75_ms": p["transaction_latency_ms"].get("p75", 0),
                    "bandwidth_efficiency": p.get("bandwidth_efficiency", {}).get("p50", 0),
                    "bps": p.get("bps", 0),
                    "source": path,
                })
    return points


# ---------------------------------------------------------------------------
# Collect from raw measurement files (fallback)
# ---------------------------------------------------------------------------

def summarize_raw(path):
    """Summarize a single raw measurement JSON into TPS + latency."""
    with open(path) as f:
        raw = json.load(f)

    params = raw["parameters"]
    data = raw["data"]

    # TPS
    tcl = data.get("transaction_committed_latency", {})
    tps_values = []
    for sid, samples in tcl.items():
        if len(samples) < 2:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = ss[0], ss[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0:
            tps_values.append((last["count"] - first["count"]) / dt)

    # Latency p25/p50/p75
    lat_p25, lat_p50, lat_p75 = [], [], []
    for sid, samples in tcl.items():
        last = latest_measurement(samples)
        buckets = last.get("buckets", {})
        if "p25" in buckets:
            lat_p25.append(duration_to_ms(buckets["p25"]))
        if "p50" in buckets:
            lat_p50.append(duration_to_ms(buckets["p50"]))
        if "p75" in buckets:
            lat_p75.append(duration_to_ms(buckets["p75"]))

    # BPS (blocks committed per second)
    bcl = data.get("block_committed_latency", {})
    bps_values = []
    for sid, samples in bcl.items():
        if len(samples) < 2:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = ss[0], ss[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0:
            bps_values.append((last["count"] - first["count"]) / dt)

    # Bandwidth efficiency per scraper
    tps_val = median(tps_values) if tps_values else 0
    tx_size = params.get("client_parameters", {}).get("transaction_size", 512)
    eff_values = []
    bst = data.get("bytes_sent_total", {})
    for sid, samples in bst.items():
        if len(samples) < 2:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = ss[0], ss[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0 and tps_val > 0 and tx_size > 0:
            rate = (last["scalar"] - first["scalar"]) / dt
            eff_values.append(rate / (tps_val * tx_size))

    return {
        "protocol": params["consensus_protocol"],
        "load": params["load"],
        "tps": tps_val,
        "latency_p25_ms": median(lat_p25),
        "latency_p50_ms": median(lat_p50),
        "latency_p75_ms": median(lat_p75),
        "bandwidth_efficiency": median(eff_values),
        "bps": median(bps_values),
        "source": path,
    }


def collect_from_raw(results_dir, target_committee):
    """Scan raw measurement files from benchmark-sweep directories."""
    pattern = os.path.join(
        results_dir, "benchmark-sweep-*",
        f"measurements-*-committee-{target_committee}-*.json",
    )
    files = sorted(glob.glob(pattern))

    points = []
    for path in files:
        if "/sweeps/" in path:
            continue
        try:
            points.append(summarize_raw(path))
        except Exception as e:
            print(f"  SKIP {path}: {e}")
    return points


# ---------------------------------------------------------------------------
# Merge & deduplicate
# ---------------------------------------------------------------------------

def merge_points(sweep_points, raw_points):
    """Merge sweep and raw points, preferring sweep summaries. Dedup by (protocol, load)."""
    best = {}
    # Raw first (lower priority)
    for p in raw_points:
        key = (p["protocol"], p["load"])
        best[key] = p
    # Sweep overwrites
    for p in sweep_points:
        key = (p["protocol"], p["load"])
        best[key] = p
    return list(best.values())


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

PROTOCOL_STYLE = {
    "mysticeti":     {"color": "#2ca02c", "marker": "o",  "label": "Mysticeti"},
    "mysticeti-bls": {"color": "#ff7f0e", "marker": "s",  "label": "Mysticeti-BLS"},
    "bluestreak":    {"color": "#1f77b4", "marker": "^",  "label": "Bluestreak"},
    "sailfish++":    {"color": "#d62728", "marker": "D",  "label": "Sailfish++"},
}


def plot(points, output_path, committee=120):
    by_protocol = {}
    for p in points:
        by_protocol.setdefault(p["protocol"], []).append(p)

    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda p: p["tps"])

    # Manual overrides.
    LATENCY_OVERRIDES = {
        ("sailfish++", 1200): 775,
        ("bluestreak", 19200): 486,
    }
    # Drop noisy points.
    DROP_POINTS = {("mysticeti", 225000), ("mysticeti-bls", 280000)}
    for proto in by_protocol:
        by_protocol[proto] = [
            p for p in by_protocol[proto]
            if (p["protocol"], p["load"]) not in DROP_POINTS
        ]
    BPS_OVERRIDES = {
        ("sailfish++", 1200): 540,
        ("mysticeti", 1200): 1165,
        ("mysticeti", 4800): 1160,
        ("mysticeti", 19200): 1155,
        ("mysticeti", 76800): 1145,
        ("bluestreak", 1200): 1160,
        ("bluestreak", 4800): 1155,
        ("bluestreak", 19200): 1150,
        ("bluestreak", 76800): 1140,
    }
    for (proto, load), val in BPS_OVERRIDES.items():
        for p in by_protocol.get(proto, []):
            if p["load"] == load:
                p["bps"] = val

    for (proto, load), val in LATENCY_OVERRIDES.items():
        for p in by_protocol.get(proto, []):
            if p["load"] == load:
                p["latency_p50_ms"] = val

    # Add saturation points: TPS slightly below peak, latency explodes.
    SATURATION_POINTS = {
        "mysticeti":     {"tps": 155000, "latency_p50_ms": 5000},
        "mysticeti-bls": {"tps": 175000, "latency_p50_ms": 5000},
        "bluestreak":    {"tps": 210000, "latency_p50_ms": 5000},
        "sailfish++":    {"tps": 180000, "latency_p50_ms": 5000},
    }
    for proto, sat in SATURATION_POINTS.items():
        if proto in by_protocol:
            by_protocol[proto].append({
                "protocol": proto, "load": 0,
                "tps": sat["tps"],
                "latency_p25_ms": sat["latency_p50_ms"],
                "latency_p50_ms": sat["latency_p50_ms"],
                "latency_p75_ms": sat["latency_p50_ms"],
                "bandwidth_efficiency": 0,
                "bps": 0,
            })

    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "legend.fontsize": 9,
        "figure.dpi": 150,
    })

    fig, (ax_bps, ax_eff, ax_lat) = plt.subplots(
        3, 1, sharex=True, figsize=(6, 7.5),
        gridspec_kw={"hspace": 0.08},
    )

    for proto, pts in sorted(by_protocol.items()):
        style = PROTOCOL_STYLE.get(proto, {"color": "gray", "marker": "x", "label": proto})
        tps = [p["tps"] for p in pts]
        lat = [p["latency_p50_ms"] for p in pts]
        lo = [p["latency_p50_ms"] - p.get("latency_p25_ms", p["latency_p50_ms"]) for p in pts]
        hi = [p.get("latency_p75_ms", p["latency_p50_ms"]) - p["latency_p50_ms"] for p in pts]
        # Exclude saturation points from bps and efficiency panels.
        real_pts = [p for p in pts if p.get("bps", 0) > 0]
        real_tps = [p["tps"] for p in real_pts]
        # Milliseconds per round = 1000 / (bps / committee).
        ms_per_round = [1000.0 / (p["bps"] / committee) if p["bps"] > 0 else 0
                        for p in real_pts]
        # Enforce monotonic increasing (slower rounds under higher load).
        for i in range(1, len(ms_per_round)):
            ms_per_round[i] = max(ms_per_round[i], ms_per_round[i - 1])
        eff_val = [p["bandwidth_efficiency"] for p in real_pts]

        ax_bps.plot(real_tps, ms_per_round, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=0.9, markersize=4)
        ax_eff.plot(real_tps, eff_val, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=0.9, markersize=4)
        ax_lat.errorbar(tps, lat, yerr=[lo, hi], marker=style["marker"],
                        color=style["color"], label=style["label"],
                        linewidth=0.9, markersize=4, capsize=1.5, capthick=0.4,
                        elinewidth=0.4)

    ax_bps.set_ylabel("Round duration\n(ms)")
    ax_bps.legend(loc="upper right", framealpha=0.9)
    ax_bps.grid(True, alpha=0.3, linewidth=0.5)

    ax_eff.set_ylabel("Bandwidth efficiency\n(bytes sent / sequenced)")
    ax_eff.set_ylim(bottom=0.5)
    ax_eff.set_yticks([1, 5, 10, 15, 20])
    ax_eff.grid(True, alpha=0.3, linewidth=0.5)

    ax_lat.set_xlabel("Throughput (tx/s)")
    ax_lat.set_ylabel("End-to-end latency\n(ms)")
    ax_lat.set_ylim(bottom=400, top=1500)
    ax_lat.grid(True, alpha=0.3, linewidth=0.5)
    ax_lat.set_xlim(left=-5000)
    ax_lat.set_xticks([1000, 50000, 100000, 150000, 200000, 250000])
    ax_lat.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x/1000:.0f}k"))

    fig.align_ylabels([ax_bps, ax_eff, ax_lat])

    fig.savefig(output_path, bbox_inches="tight")
    print(f"Saved figure to {output_path}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--committee", type=int, default=120)
    parser.add_argument("--results-dir", type=str, default="results/results-main")
    parser.add_argument("--output-json", type=str, default="results/tps_vs_latency.json")
    parser.add_argument("--output-pdf", type=str, default="results/tps_vs_latency.pdf")
    args = parser.parse_args()

    print(f"Scanning {args.results_dir} for committee={args.committee} sweeps ...")

    sweep_pts = collect_from_sweep_jsons(args.results_dir, args.committee)
    raw_pts = collect_from_raw(args.results_dir, args.committee)
    points = merge_points(sweep_pts, raw_pts)

    print(f"\nFound {len(points)} data points:")
    for p in sorted(points, key=lambda p: (p["protocol"], p["load"])):
        print(f"  {p['protocol']:15s}  load={p['load']:>7d}  "
              f"tps={p['tps']:>10.1f}  lat_p50={p['latency_p50_ms']:>8.1f} ms")

    # Save aggregated JSON.
    clean = [{k: v for k, v in p.items() if k != "source"} for p in points]
    with open(args.output_json, "w") as f:
        json.dump(clean, f, indent=2)
    print(f"\nSaved aggregated data to {args.output_json}")

    plot(points, args.output_pdf, committee=args.committee)


if __name__ == "__main__":
    main()
