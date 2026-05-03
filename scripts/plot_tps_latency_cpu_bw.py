#!/usr/bin/env python3
"""Three-panel TPS-vs-{latency, vCPU, bandwidth efficiency} figure.

Reads sweep summary JSONs under --results-dir, filters to happy-case
(byzantine_nodes=0, adversarial_latency=false) by inspecting the sibling
raw measurement files, and produces a stacked figure with shared x-axis:

    Top:    end-to-end latency (p50, p25/p75 error bars)
    Middle: per-validator CPU usage (cores, p50)
    Bottom: bandwidth efficiency (bytes-sent / bytes-sequenced, p50)

Usage:
    python3 scripts/plot_tps_latency_cpu_bw.py \\
        --committee 100 \\
        --results-dir results/results-main \\
        --output-pdf results/tps_latency_cpu_bw.pdf
"""

import argparse
import glob
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


PROTOCOL_STYLE = {
    "starfish":       {"color": "#d62728", "marker": "D",  "label": "Starfish"},
    "starfish-speed": {"color": "#9467bd", "marker": "P",  "label": "Starfish-Speed"},
    "starfish-bls":   {"color": "#8c564b", "marker": "X",  "label": "Starfish-BLS"},
    "mysticeti":      {"color": "#2ca02c", "marker": "o",  "label": "Mysticeti"},
    "mysticeti-bls":  {"color": "#ff7f0e", "marker": "s",  "label": "Mysticeti-BLS"},
    "bluestreak":     {"color": "#1f77b4", "marker": "^",  "label": "Bluestreak"},
    "sailfish++":     {"color": "#e377c2", "marker": "v",  "label": "Sailfish++"},
    "cordial-miners": {"color": "#17becf", "marker": "*",  "label": "Cordial-Miners"},
}


# Per-protocol dissemination-mode filter. For protocols listed here, only
# runs whose *resolved* `dissemination_mode` matches are kept. "protocol-default"
# is resolved to the protocol's actual runtime mode (see dag_state.rs).
PROTOCOL_DISSEMINATION_FILTER = {
    "mysticeti":     "pull",
    "starfish":      "push-useful",
    "starfish-bls":  "pull",
}

# Mirrors `default_dissemination_mode` in crates/starfish-core/src/dag_state.rs.
PROTOCOL_DEFAULT_DISSEMINATION = {
    "mysticeti":      "pull",
    "mysticeti-bls":  "pull",
    "starfish":       "push-causal",
    "starfish-speed": "push-causal",
    "starfish-bls":   "push-causal",
    "bluestreak":     "push-causal",
    "sailfish++":     "push-causal",
    "cordial-miners": "push-causal",
}


def resolve_dissemination_mode(protocol, configured):
    if configured == "protocol-default" or configured is None:
        return PROTOCOL_DEFAULT_DISSEMINATION.get(protocol)
    return configured


def is_happy_raw(path):
    """Return True iff the raw measurement file is a happy-case run."""
    try:
        with open(path) as f:
            params = json.load(f)["parameters"]
    except (OSError, KeyError, json.JSONDecodeError):
        return False
    if params.get("byzantine_nodes", 0) != 0:
        return False
    node_params = params.get("node_parameters", {}) or {}
    if node_params.get("adversarial_latency", False):
        return False
    proto = params.get("consensus_protocol")
    required_mode = PROTOCOL_DISSEMINATION_FILTER.get(proto)
    if required_mode is not None:
        actual = resolve_dissemination_mode(proto, node_params.get("dissemination_mode"))
        if actual != required_mode:
            return False
    return True


def index_raw_by_key(sweep_dir):
    """Map (protocol, load) -> raw-measurement path inside one sweep dir."""
    idx = {}
    for raw in glob.glob(os.path.join(sweep_dir, "measurements-*-committee-*-load-*.json")):
        try:
            with open(raw) as f:
                params = json.load(f)["parameters"]
        except (OSError, KeyError, json.JSONDecodeError):
            continue
        key = (params.get("consensus_protocol"), params.get("load"))
        # Newer files overwrite older — preferred when sweeps are re-run.
        idx[key] = raw
    return idx


def collect(results_dir, target_committee):
    sweep_files = sorted(glob.glob(
        os.path.join(results_dir, "benchmark-sweep-*", "sweeps", "*.json")
    ))

    points = []
    skipped_filter = 0
    skipped_no_raw = 0
    for sweep_path in sweep_files:
        sweep_dir = str(Path(sweep_path).parents[1])
        raw_idx = index_raw_by_key(sweep_dir)

        with open(sweep_path) as f:
            data = json.load(f)
        for p in data.get("points", []):
            if p.get("committee") != target_committee:
                continue
            key = (p["protocol"], p["load"])
            raw = raw_idx.get(key)
            if raw is None:
                skipped_no_raw += 1
                continue
            if not is_happy_raw(raw):
                skipped_filter += 1
                continue
            points.append({
                "protocol": p["protocol"],
                "load": p["load"],
                "tps": p["tps"],
                "lat_p25_ms": p["transaction_latency_ms"]["p25"],
                "lat_p50_ms": p["transaction_latency_ms"]["p50"],
                "lat_p75_ms": p["transaction_latency_ms"]["p75"],
                "cpu_p50": p["cpu_cores"]["p50"],
                "bw_eff_p50": p["bandwidth_efficiency"]["p50"],
                "source": sweep_path,
            })

    print(f"Collected {len(points)} happy-case points "
          f"(skipped {skipped_filter} non-happy, {skipped_no_raw} without raw match).")
    return points


def dedup(points):
    """Keep the latest entry per (protocol, load); newer sweep file wins."""
    best = {}
    for p in points:
        best[(p["protocol"], p["load"])] = p
    return list(best.values())


def plot(points, output_pdf, committee, latency_ymax_ms):
    by_protocol = {}
    for p in points:
        by_protocol.setdefault(p["protocol"], []).append(p)
    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda p: p["load"])

    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 10,
        "axes.labelsize": 11,
        "legend.fontsize": 9,
        "figure.dpi": 150,
    })

    fig, (ax_lat, ax_cpu, ax_bw) = plt.subplots(
        3, 1, sharex=True, figsize=(6.4, 8.0),
        gridspec_kw={"hspace": 0.08},
    )

    for proto, pts in sorted(by_protocol.items()):
        style = PROTOCOL_STYLE.get(
            proto, {"color": "gray", "marker": "x", "label": proto}
        )
        tps = [p["tps"] for p in pts]
        lat = [p["lat_p50_ms"] for p in pts]
        lo = [p["lat_p50_ms"] - p["lat_p25_ms"] for p in pts]
        hi = [p["lat_p75_ms"] - p["lat_p50_ms"] for p in pts]

        ax_lat.errorbar(
            tps, lat, yerr=[lo, hi],
            marker=style["marker"], color=style["color"],
            label=style["label"], linewidth=0.9, markersize=4,
            capsize=1.5, capthick=0.4, elinewidth=0.4,
        )
        ax_cpu.plot(
            tps, [p["cpu_p50"] for p in pts],
            marker=style["marker"], color=style["color"],
            label=style["label"], linewidth=0.9, markersize=4,
        )
        ax_bw.plot(
            tps, [p["bw_eff_p50"] for p in pts],
            marker=style["marker"], color=style["color"],
            label=style["label"], linewidth=0.9, markersize=4,
        )

    ax_lat.set_ylabel("End-to-end latency\n(p50, ms)")
    ax_lat.set_ylim(bottom=0, top=latency_ymax_ms)
    ax_lat.grid(True, alpha=0.3, linewidth=0.5)
    ax_lat.legend(loc="upper left", framealpha=0.9, ncol=2)

    ax_cpu.set_ylabel("vCPU usage per validator\n(cores, p50)")
    ax_cpu.set_ylim(bottom=0)
    ax_cpu.grid(True, alpha=0.3, linewidth=0.5)

    ax_bw.set_ylabel("Bandwidth efficiency\n(bytes sent / sequenced)")
    ax_bw.set_yscale("log")
    ax_bw.grid(True, which="both", alpha=0.3, linewidth=0.5)
    ax_bw.set_xlabel("Throughput (tx/s)")
    ax_bw.xaxis.set_major_formatter(
        FuncFormatter(lambda x, _: f"{x/1000:.0f}k" if x >= 1000 else f"{x:.0f}")
    )

    fig.suptitle(f"Happy case, committee = {committee}", y=0.995)
    fig.align_ylabels([ax_lat, ax_cpu, ax_bw])
    fig.savefig(output_pdf, bbox_inches="tight")
    print(f"Saved figure to {output_pdf}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--committee", type=int, default=100)
    parser.add_argument("--results-dir", type=str, default="results/results-main")
    parser.add_argument("--output-pdf", type=str,
                        default="results/tps_latency_cpu_bw.pdf")
    parser.add_argument("--output-json", type=str,
                        default="results/tps_latency_cpu_bw.json")
    parser.add_argument("--latency-ymax-ms", type=float, default=2500.0,
                        help="Upper bound for the latency panel.")
    args = parser.parse_args()

    points = dedup(collect(args.results_dir, args.committee))
    points.sort(key=lambda p: (p["protocol"], p["tps"]))

    print(f"\nKept {len(points)} unique points after dedup:")
    for p in points:
        print(f"  {p['protocol']:15s} load={p['load']:>7d}  tps={p['tps']:>10.1f}  "
              f"lat={p['lat_p50_ms']:>7.0f} ms  cpu={p['cpu_p50']:>5.2f}  "
              f"eff={p['bw_eff_p50']:>6.2f}")

    clean = [{k: v for k, v in p.items() if k != "source"} for p in points]
    with open(args.output_json, "w") as f:
        json.dump(clean, f, indent=2)
    print(f"Saved aggregated JSON to {args.output_json}")

    plot(points, args.output_pdf, args.committee, args.latency_ymax_ms)


if __name__ == "__main__":
    main()
