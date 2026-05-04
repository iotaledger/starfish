#!/usr/bin/env python3
"""Aggregate committee-scaling benchmark results and plot latency + efficiency.

Reads raw MeasurementsCollection JSON files produced by the orchestrator,
computes per-protocol summaries, saves an aggregated JSON, and generates
a two-panel PDF figure suitable for papers.

Usage:
    python3 scripts/plot_committee_scaling.py [--load 4000] [--results-dir results/results-main]
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
from matplotlib.ticker import MaxNLocator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def duration_to_us(d):
    """Convert a serialized Rust Duration {secs, nanos} to microseconds."""
    return d["secs"] * 1_000_000 + d["nanos"] / 1000


def duration_to_ms(d):
    """Convert a serialized Rust Duration {secs, nanos} to milliseconds."""
    return d["secs"] * 1_000 + d["nanos"] / 1_000_000


def duration_to_secs(d):
    return d["secs"] + d["nanos"] / 1e9


def latest_measurement(scraper_samples):
    """Return the sample with the highest timestamp from a list of samples."""
    return max(scraper_samples, key=lambda s: duration_to_secs(s["timestamp"]))


def median(values):
    if not values:
        return 0.0
    return statistics.median(values)


# ---------------------------------------------------------------------------
# Per-file aggregation (mirrors Rust MeasurementsCollection logic)
# ---------------------------------------------------------------------------

def summarize_measurement(path):
    """Read a single measurement JSON and return a summary dict."""
    with open(path) as f:
        raw = json.load(f)

    params = raw["parameters"]
    data = raw["data"]
    protocol = params["consensus_protocol"]
    committee = params["nodes"]
    load = params["load"]
    tx_size = params.get("client_parameters", {}).get("transaction_size", 512)

    # --- Transaction latency p50 (median across scrapers) ---
    tx_latency_p50_values = []
    tcl = data.get("transaction_committed_latency", {})
    for scraper_id, samples in tcl.items():
        last = latest_measurement(samples)
        buckets = last.get("buckets", {})
        if "p50" in buckets:
            tx_latency_p50_values.append(duration_to_ms(buckets["p50"]))

    # --- Transaction latency p25/p75 ---
    tx_latency_p25_values = []
    tx_latency_p75_values = []
    for scraper_id, samples in tcl.items():
        last = latest_measurement(samples)
        buckets = last.get("buckets", {})
        if "p25" in buckets:
            tx_latency_p25_values.append(duration_to_ms(buckets["p25"]))
        if "p75" in buckets:
            tx_latency_p75_values.append(duration_to_ms(buckets["p75"]))

    # --- Block latency p50 ---
    block_latency_p50_values = []
    bcl = data.get("block_committed_latency", {})
    for scraper_id, samples in bcl.items():
        last = latest_measurement(samples)
        buckets = last.get("buckets", {})
        if "p50" in buckets:
            block_latency_p50_values.append(duration_to_ms(buckets["p50"]))

    # --- TPS (transaction rate) per scraper ---
    tps_values = []
    for scraper_id, samples in tcl.items():
        if len(samples) < 2:
            continue
        samples_sorted = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = samples_sorted[0], samples_sorted[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0:
            rate = (last["count"] - first["count"]) / dt
            tps_values.append(rate)

    tps = median(tps_values) if tps_values else 0.0

    # --- Bandwidth efficiency per scraper ---
    efficiency_values = []
    bst = data.get("bytes_sent_total", {})
    for scraper_id, samples in bst.items():
        if len(samples) < 2:
            continue
        samples_sorted = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = samples_sorted[0], samples_sorted[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0 and tps > 0 and tx_size > 0:
            bytes_rate = (last["scalar"] - first["scalar"]) / dt
            eff = bytes_rate / (tps * tx_size)
            efficiency_values.append(eff)

    # --- Block header average size ---
    header_values = []
    hdr = data.get("proposed_header_size_bytes", {})
    for scraper_id, samples in hdr.items():
        last = latest_measurement(samples)
        if last["count"] > 0:
            header_values.append(last["scalar"] / last["count"])

    # --- Per-validator vCPU usage (rate of process_cpu_seconds_total) ---
    cpu_values = []
    cpu = data.get("process_cpu_seconds_total", {})
    for scraper_id, samples in cpu.items():
        if len(samples) < 2:
            continue
        samples_sorted = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        first, last = samples_sorted[0], samples_sorted[-1]
        dt = duration_to_secs(last["timestamp"]) - duration_to_secs(first["timestamp"])
        if dt > 0:
            cpu_rate = (last["scalar"] - first["scalar"]) / dt
            cpu_values.append(cpu_rate)

    return {
        "protocol": protocol,
        "committee": committee,
        "load": load,
        "transaction_size_bytes": tx_size,
        "tps": tps,
        "transaction_latency_ms": {
            "p25": median(tx_latency_p25_values),
            "p50": median(tx_latency_p50_values),
            "p75": median(tx_latency_p75_values),
        },
        "block_latency_ms": {
            "p50": median(block_latency_p50_values),
        },
        "bandwidth_efficiency": {
            "p50": median(efficiency_values),
        },
        "block_header_size_bytes": median(header_values),
        "vcpu_per_validator": median(cpu_values),
        "source_file": str(path),
    }


# ---------------------------------------------------------------------------
# Discovery & deduplication
# ---------------------------------------------------------------------------

def extract_timestamp_from_dir(path):
    """Extract the numeric timestamp from a benchmark-committee-sweep-XXXXX dir."""
    dirname = Path(path).parent.name
    parts = dirname.split("-")
    try:
        return int(parts[-1])
    except (ValueError, IndexError):
        return 0


# Canonical alias map. The orchestrator has produced two CLI spellings for
# the same protocol over time; normalize before filtering / plotting so a
# sweep that mixes runs is still consistent.
PROTOCOL_ALIASES = {
    "sailfish-pp":   "sailfish++",
    "starfish-s":    "starfish-speed",
}


def canonical_protocol(name):
    return PROTOCOL_ALIASES.get(name, name)


def collect_summaries(results_dir, target_load, allowed_protocols=None):
    """Walk result directories, aggregate, and deduplicate by (protocol, committee)."""
    pattern = os.path.join(results_dir, "benchmark-committee-sweep-*", "measurements-*.json")
    files = sorted(glob.glob(pattern))

    summaries = []
    for path in files:
        try:
            s = summarize_measurement(path)
        except Exception as e:
            print(f"  SKIP {path}: {e}")
            continue
        if s["load"] != target_load:
            continue
        s["protocol"] = canonical_protocol(s["protocol"])
        if allowed_protocols is not None and s["protocol"] not in allowed_protocols:
            continue
        summaries.append(s)

    # Deduplicate: keep latest run per (protocol, committee).
    best = {}
    for s in summaries:
        key = (s["protocol"], s["committee"])
        ts = extract_timestamp_from_dir(s["source_file"])
        if key not in best or ts > extract_timestamp_from_dir(best[key]["source_file"]):
            best[key] = s

    return list(best.values())


# ---------------------------------------------------------------------------
# Plotting
# ---------------------------------------------------------------------------

PROTOCOL_STYLE = {
    "starfish":      {"color": "#9467bd", "marker": "P",  "label": "Starfish"},
    "starfish-bls":  {"color": "#8c564b", "marker": "X",  "label": "Starfish-BLS"},
    "mysticeti":     {"color": "#2ca02c", "marker": "o",  "label": "Mysticeti"},
    "mysticeti-bls": {"color": "#ff7f0e", "marker": "s",  "label": "Mysticeti-BLS"},
    "bluestreak":    {"color": "#1f77b4", "marker": "^",  "label": "Bluestreak"},
    "sailfish++":    {"color": "#d62728", "marker": "D",  "label": "Sailfish++"},
}


def plot(summaries, output_path):
    # Group by protocol.
    by_protocol = {}
    for s in summaries:
        by_protocol.setdefault(s["protocol"], []).append(s)

    # Sort each protocol's points by committee size.
    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda s: s["committee"])


    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "legend.fontsize": 9,
        "figure.dpi": 150,
    })

    fig, (ax_lat, ax_eff, ax_hdr, ax_cpu) = plt.subplots(
        4, 1, sharex=True, figsize=(6, 9.5),
        gridspec_kw={"hspace": 0.08},
    )

    for proto, points in sorted(by_protocol.items()):
        style = PROTOCOL_STYLE.get(proto, {"color": "gray", "marker": "x", "label": proto})
        committees = [p["committee"] for p in points]
        lat_p50 = [p["transaction_latency_ms"]["p50"] for p in points]
        eff_p50 = [p["bandwidth_efficiency"]["p50"] for p in points]
        hdr_size = [p["block_header_size_bytes"] / 1000 for p in points]  # KB
        cpu_p50 = [p.get("vcpu_per_validator", 0.0) for p in points]

        ax_lat.plot(committees, lat_p50, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=0.9, markersize=4)
        ax_eff.plot(committees, eff_p50, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=0.9, markersize=4)
        ax_hdr.plot(committees, hdr_size, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=0.9, markersize=4)
        ax_cpu.plot(committees, cpu_p50, marker=style["marker"], color=style["color"],
                    label=style["label"], linewidth=0.9, markersize=4)

    ax_lat.set_ylabel("End-to-end latency\n(ms)")
    ax_lat.set_ylim(bottom=400)
    ax_lat.set_yticks([500, 700, 900, 1100, 1300, 1500])
    ax_lat.grid(True, alpha=0.3, linewidth=0.5)

    ax_eff.set_ylabel("Bandwidth efficiency\n(bytes sent / sequenced)")
    ax_eff.set_yscale("log")
    ax_eff.set_yticks([1, 2, 3, 5, 10, 20, 30])
    ax_eff.set_yticklabels(["1", "2", "3", "5", "10", "20", "30"])
    ax_eff.set_ylim(bottom=0.9)
    ax_eff.grid(True, which="both", alpha=0.3, linewidth=0.5)

    ax_hdr.set_ylabel("Block metadata\n(KB)")
    ax_hdr.grid(True, alpha=0.3, linewidth=0.5)

    ax_cpu.set_ylabel("vCPUs per validator")
    ax_cpu.set_ylim(bottom=0)
    ax_cpu.legend(loc="upper left", framealpha=0.9)
    ax_cpu.set_xlabel("Committee size")
    ax_cpu.grid(True, alpha=0.3, linewidth=0.5)
    # Auto-fit x range to the actual measured committee sizes.
    all_committees = sorted({c for proto, pts in by_protocol.items() for c in (p["committee"] for p in pts)})
    if all_committees:
        ax_cpu.set_xticks(all_committees)
        cmin, cmax = min(all_committees), max(all_committees)
        pad = max(2, (cmax - cmin) * 0.05)
        ax_cpu.set_xlim(cmin - pad, cmax + pad)

    fig.align_ylabels([ax_lat, ax_eff, ax_hdr, ax_cpu])
    fig.savefig(output_path, bbox_inches="tight")
    print(f"Saved figure to {output_path}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--load", type=int, default=4000,
                        help="Filter results to this load value (default: 4000)")
    parser.add_argument("--results-dir", type=str,
                        default="results/results-main",
                        help="Base results directory")
    parser.add_argument("--output-json", type=str,
                        default="results/committee_scaling_aggregated.json")
    parser.add_argument("--output-pdf", type=str,
                        default="results/committee_scaling.pdf")
    parser.add_argument(
        "--protocols", type=str, nargs="+",
        default=["starfish", "starfish-bls", "mysticeti", "mysticeti-bls", "sailfish++"],
        help="Restrict plot to these (canonical) protocol names",
    )
    args = parser.parse_args()

    allowed = set(canonical_protocol(p) for p in args.protocols)
    print(f"Scanning {args.results_dir} for load={args.load}, protocols={sorted(allowed)} ...")
    summaries = collect_summaries(args.results_dir, args.load, allowed_protocols=allowed)

    # Print what we found.
    print(f"\nFound {len(summaries)} data points:")
    for s in sorted(summaries, key=lambda s: (s["protocol"], s["committee"])):
        print(f"  {s['protocol']:15s}  committee={s['committee']:>4d}  "
              f"latency_p50={s['transaction_latency_ms']['p50']:8.1f} ms  "
              f"efficiency={s['bandwidth_efficiency']['p50']:.2f}  "
              f"tps={s['tps']:.0f}  "
              f"vcpu={s.get('vcpu_per_validator', 0.0):.2f}")

    # Save aggregated JSON.
    clean = [{k: v for k, v in s.items() if k != "source_file"} for s in summaries]
    with open(args.output_json, "w") as f:
        json.dump(clean, f, indent=2)
    print(f"\nSaved aggregated data to {args.output_json}")

    # Plot.
    plot(summaries, args.output_pdf)


if __name__ == "__main__":
    main()
