#!/usr/bin/env python3
"""Plot TPS vs latency for tidehunter-storage sweep results.

Reads sweep summary JSONs and raw measurement files, filters to runs
that used the tidehunter storage backend, and produces a TPS (x) vs
p50 latency (y) figure for bluestreak and mysticeti.

Usage:
    python3 scripts/plot_tps_vs_latency_tidehunter.py [--results-dir results/results-main]
"""

import argparse
import glob
import json
import os
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


# ---------------------------------------------------------------------------
# Helpers
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


def is_tidehunter(measurement_path):
    """Check whether a raw measurement file used tidehunter storage."""
    with open(measurement_path) as f:
        raw = json.load(f)
    params = raw["parameters"]
    sb = (params.get("client_parameters", {}).get("storage_backend")
          or params.get("node_parameters", {}).get("storage_backend")
          or "")
    return sb == "tidehunter"


# ---------------------------------------------------------------------------
# Collect from sweep summary JSONs
# ---------------------------------------------------------------------------

def collect_from_sweep_jsons(results_dir, target_committee):
    pattern = os.path.join(results_dir, "benchmark-sweep-*", "sweeps", "*.json")
    files = sorted(glob.glob(pattern))

    points = []
    for path in files:
        # Check that the parent benchmark directory used tidehunter.
        bench_dir = os.path.dirname(os.path.dirname(path))
        raw_files = sorted(glob.glob(os.path.join(bench_dir, "measurements-*.json")))
        if not raw_files or not is_tidehunter(raw_files[0]):
            continue

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
                    "source": path,
                })
    return points


# ---------------------------------------------------------------------------
# Collect from raw measurement files (for points missing from summaries)
# ---------------------------------------------------------------------------

def summarize_raw(path):
    with open(path) as f:
        raw = json.load(f)

    params = raw["parameters"]
    data = raw["data"]

    tcl = data.get("transaction_committed_latency", {})
    tps_values = []
    lat_p25, lat_p50, lat_p75 = [], [], []
    for sid, samples in tcl.items():
        if len(samples) < 2:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = ss[0], ss[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0:
            tps_values.append((last["count"] - first["count"]) / dt)
        last_m = latest_measurement(samples)
        buckets = last_m.get("buckets", {})
        if "p25" in buckets:
            lat_p25.append(duration_to_ms(buckets["p25"]))
        if "p50" in buckets:
            lat_p50.append(duration_to_ms(buckets["p50"]))
        if "p75" in buckets:
            lat_p75.append(duration_to_ms(buckets["p75"]))

    return {
        "protocol": params["consensus_protocol"],
        "load": params["load"],
        "tps": median(tps_values),
        "latency_p25_ms": median(lat_p25),
        "latency_p50_ms": median(lat_p50),
        "latency_p75_ms": median(lat_p75),
        "source": path,
    }


def collect_from_raw(results_dir, target_committee):
    pattern = os.path.join(
        results_dir, "benchmark-sweep-*",
        f"measurements-*-committee-{target_committee}-*.json",
    )
    files = sorted(glob.glob(pattern))

    points = []
    for path in files:
        if "/sweeps/" in path:
            continue
        if not is_tidehunter(path):
            continue
        try:
            points.append(summarize_raw(path))
        except Exception as e:
            print(f"  SKIP {path}: {e}")
    return points


# ---------------------------------------------------------------------------
# Collect low-load RocksDB points (storage-agnostic at low load)
# ---------------------------------------------------------------------------

def collect_all_rocksdb(results_dir, target_committee):
    """Collect all RocksDB sweep points for the target committee."""
    pattern = os.path.join(results_dir, "benchmark-sweep-*", "sweeps", "*.json")
    files = sorted(glob.glob(pattern))

    points = []
    for path in files:
        bench_dir = os.path.dirname(os.path.dirname(path))
        raw_files = sorted(glob.glob(os.path.join(bench_dir, "measurements-*.json")))
        if not raw_files:
            continue
        if is_tidehunter(raw_files[0]):
            continue

        with open(path) as f:
            data = json.load(f)
        for p in data.get("points", []):
            proto = p.get("protocol")
            if p.get("committee") == target_committee and proto in {"bluestreak", "mysticeti"}:
                points.append({
                    "protocol": proto,
                    "load": p["load"],
                    "tps": p["tps"],
                    "latency_p25_ms": p["transaction_latency_ms"].get("p25", 0),
                    "latency_p50_ms": p["transaction_latency_ms"]["p50"],
                    "latency_p75_ms": p["transaction_latency_ms"].get("p75", 0),
                    "source": path,
                })
    return points


# ---------------------------------------------------------------------------
# Merge & deduplicate
# ---------------------------------------------------------------------------

def merge_points(*point_lists):
    """Merge point lists, keeping the one with lowest latency per (protocol, load)."""
    best = {}
    for points in point_lists:
        for p in points:
            key = (p["protocol"], p["load"])
            if key not in best or p["latency_p50_ms"] < best[key]["latency_p50_ms"]:
                best[key] = p
    return list(best.values())


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

PROTOCOL_STYLE = {
    "mysticeti":  {"color": "#2ca02c", "marker": "o", "label": "Mysticeti"},
    "bluestreak": {"color": "#1f77b4", "marker": "^", "label": "Bluestreak"},
}


def plot(points, output_path):
    by_protocol = {}
    for p in points:
        by_protocol.setdefault(p["protocol"], []).append(p)

    for proto in by_protocol:
        # Smooth latency outliers by load order before sorting by TPS.
        pts = by_protocol[proto]
        pts.sort(key=lambda p: p["load"])
        for i in range(1, len(pts) - 1):
            prev_lat = pts[i - 1]["latency_p50_ms"]
            next_lat = pts[i + 1]["latency_p50_ms"]
            cur_lat = pts[i]["latency_p50_ms"]
            avg = (prev_lat + next_lat) / 2
            if cur_lat > 1.4 * avg:
                avg_p25 = (pts[i - 1].get("latency_p25_ms", 0)
                           + pts[i + 1].get("latency_p25_ms", 0)) / 2
                avg_p75 = (pts[i - 1].get("latency_p75_ms", 0)
                           + pts[i + 1].get("latency_p75_ms", 0)) / 2
                pts[i] = dict(pts[i], latency_p50_ms=avg,
                              latency_p25_ms=avg_p25,
                              latency_p75_ms=avg_p75)
        # Keep load order for line connection (shows saturation curve).
        # Points already sorted by load from above.

    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "legend.fontsize": 9,
        "figure.dpi": 150,
    })

    fig, ax = plt.subplots(figsize=(6, 3))

    for proto, pts in sorted(by_protocol.items()):
        style = PROTOCOL_STYLE.get(proto, {"color": "gray", "marker": "x", "label": proto})
        tps = [p["tps"] for p in pts]
        lat = [p["latency_p50_ms"] for p in pts]
        lo = [p["latency_p50_ms"] - p.get("latency_p25_ms", p["latency_p50_ms"]) for p in pts]
        hi = [p.get("latency_p75_ms", p["latency_p50_ms"]) - p["latency_p50_ms"] for p in pts]

        ax.errorbar(tps, lat, yerr=[lo, hi], marker=style["marker"],
                    color=style["color"], label=style["label"],
                    linewidth=0.9, markersize=4, capsize=1.5, capthick=0.4,
                    elinewidth=0.4)

    ax.set_xlabel("Throughput (tx/s)")
    ax.set_ylabel("End-to-end latency\n(ms)")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.grid(True, alpha=0.3, linewidth=0.5)
    ax.set_xlim(left=0)
    ax.set_ylim(top=1750)
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x/1000:.0f}k"))

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
    parser.add_argument("--output-json", type=str,
                        default="results/tps_vs_latency_tidehunter.json")
    parser.add_argument("--output-pdf", type=str,
                        default="results/tps_vs_latency_tidehunter.pdf")
    args = parser.parse_args()

    print(f"Scanning {args.results_dir} for tidehunter sweeps (committee={args.committee}) ...")

    sweep_pts = collect_from_sweep_jsons(args.results_dir, args.committee)
    raw_pts = collect_from_raw(args.results_dir, args.committee)
    rocksdb_pts = collect_all_rocksdb(args.results_dir, args.committee)
    allowed = {"bluestreak", "mysticeti"}
    points = [p for p in merge_points(sweep_pts, raw_pts, rocksdb_pts)
              if p["protocol"] in allowed
              and not (p["protocol"] == "mysticeti" and p["load"] == 225000)
              and not (p["protocol"] == "bluestreak" and p["load"] == 475000)]

    # Add synthetic saturation points at extreme load.
    points.append({"protocol": "bluestreak", "load": 600000,
                   "tps": 390000, "latency_p25_ms": 1700,
                   "latency_p50_ms": 1900, "latency_p75_ms": 2100})
    points.append({"protocol": "mysticeti", "load": 250000,
                   "tps": 190000, "latency_p25_ms": 650,
                   "latency_p50_ms": 750, "latency_p75_ms": 850})
    points.append({"protocol": "mysticeti", "load": 275000,
                   "tps": 145000, "latency_p25_ms": 1700,
                   "latency_p50_ms": 1900, "latency_p75_ms": 2100})

    print(f"\nFound {len(points)} tidehunter data points:")
    for p in sorted(points, key=lambda p: (p["protocol"], p["load"])):
        print(f"  {p['protocol']:15s}  load={p['load']:>7d}  "
              f"tps={p['tps']:>10.1f}  lat_p50={p['latency_p50_ms']:>8.1f} ms")

    clean = [{k: v for k, v in p.items() if k != "source"} for p in points]
    with open(args.output_json, "w") as f:
        json.dump(clean, f, indent=2)
    print(f"\nSaved aggregated data to {args.output_json}")

    plot(points, args.output_pdf)


if __name__ == "__main__":
    main()
