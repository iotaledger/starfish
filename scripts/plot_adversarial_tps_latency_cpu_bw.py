#!/usr/bin/env python3
"""Three-panel TPS-vs-{latency, vCPU, bandwidth efficiency} figure for
adversarial-latency runs.

Mirrors plot_tps_latency_cpu_bw.py but keeps *only* points whose raw
measurement file has node_parameters.adversarial_latency = true.

Unlike the happy-case script, this one collects directly from raw
measurement files (not the sweep summaries), because adversarial-latency
campaigns are usually run as benchmark (fixed loads) rather than
benchmark-sweep, so they live under benchmark-* directories that have
no sweeps/ subdirectory.

Top panel uses a wider y-range than the happy-case plot because under
adversarial latency every protocol's p50 sits in the multi-second range.

Usage:
    python3 scripts/plot_adversarial_tps_latency_cpu_bw.py \\
        --committee 100 \\
        --results-dir results/results-main \\
        --output-pdf results/tps_latency_cpu_bw_adv.pdf
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


# Per-protocol dissemination-mode filter. Mode is the *resolved* mode
# (protocol-default expanded). Drop any run whose configured mode does
# not resolve to the required value.
PROTOCOL_DISSEMINATION_FILTER = {
    "mysticeti":     "pull",
    "starfish":      "push-useful",
    "starfish-bls":  "pull",
}

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


def duration_to_secs(d):
    return d["secs"] + d["nanos"] / 1e9


def duration_to_ms(d):
    return d["secs"] * 1_000 + d["nanos"] / 1_000_000


def median(values):
    return statistics.median(values) if values else 0.0


def matches_filter(params, target_committee):
    if params.get("nodes") != target_committee:
        return False
    if params.get("byzantine_nodes", 0) != 0:
        return False
    node_params = params.get("node_parameters", {}) or {}
    if not node_params.get("adversarial_latency", False):
        return False
    proto = params.get("consensus_protocol")
    required_mode = PROTOCOL_DISSEMINATION_FILTER.get(proto)
    if required_mode is not None:
        actual = resolve_dissemination_mode(proto, node_params.get("dissemination_mode"))
        if actual != required_mode:
            return False
    return True


def summarize_raw(path):
    """Compute TPS / latency / CPU / bandwidth-efficiency from a raw
    measurement file using the same conventions as the orchestrator's
    summary code (median across validators, last-scrape histogram values
    for latency)."""
    with open(path) as f:
        raw = json.load(f)
    params = raw["parameters"]
    data = raw["data"]

    # TPS = (last cumulative count - first) / elapsed, median across validators.
    tcl = data.get("transaction_committed_latency", {})
    tps_values = []
    for samples in tcl.values():
        if len(samples) < 2:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        dt = duration_to_secs(ss[-1]["timestamp"]) - duration_to_secs(ss[0]["timestamp"])
        if dt > 0:
            tps_values.append((ss[-1]["count"] - ss[0]["count"]) / dt)
    tps = median(tps_values)

    # Latency: median across validators of each validator's last-scrape p25/p50/p75.
    lat_p25, lat_p50, lat_p75 = [], [], []
    for samples in tcl.values():
        if not samples:
            continue
        last = max(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        buckets = last.get("buckets", {})
        if "p25" in buckets:
            lat_p25.append(duration_to_ms(buckets["p25"]))
        if "p50" in buckets:
            lat_p50.append(duration_to_ms(buckets["p50"]))
        if "p75" in buckets:
            lat_p75.append(duration_to_ms(buckets["p75"]))

    # CPU usage in cores per validator: (delta cpu_seconds) / (delta wall).
    cpu_values = []
    pcs = data.get("process_cpu_seconds_total", {})
    for samples in pcs.values():
        if len(samples) < 2:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        dt = duration_to_secs(ss[-1]["timestamp"]) - duration_to_secs(ss[0]["timestamp"])
        if dt > 0:
            cpu_values.append((ss[-1]["scalar"] - ss[0]["scalar"]) / dt)

    # Bandwidth efficiency = bytes-sent rate / (tps * tx_size), median across validators.
    eff_values = []
    bst = data.get("bytes_sent_total", {})
    tx_size = (params.get("client_parameters", {}) or {}).get("transaction_size", 512)
    for samples in bst.values():
        if len(samples) < 2 or tps <= 0 or tx_size <= 0:
            continue
        ss = sorted(samples, key=lambda s: duration_to_secs(s["timestamp"]))
        dt = duration_to_secs(ss[-1]["timestamp"]) - duration_to_secs(ss[0]["timestamp"])
        if dt > 0:
            rate = (ss[-1]["scalar"] - ss[0]["scalar"]) / dt
            eff_values.append(rate / (tps * tx_size))

    return {
        "protocol": params["consensus_protocol"],
        "load": params["load"],
        "tps": tps,
        "lat_p25_ms": median(lat_p25),
        "lat_p50_ms": median(lat_p50),
        "lat_p75_ms": median(lat_p75),
        "cpu_p50": median(cpu_values),
        "bw_eff_p50": median(eff_values),
        "source": path,
    }


def collect(results_dir, target_committee):
    pattern = os.path.join(results_dir, "**", "measurements-*-committee-*-load-*.json")
    files = sorted(glob.glob(pattern, recursive=True))

    points = []
    skipped_filter = 0
    skipped_error = 0
    for path in files:
        if "/sweeps/" in path:
            continue
        try:
            with open(path) as f:
                params = json.load(f)["parameters"]
        except (OSError, KeyError, json.JSONDecodeError):
            skipped_error += 1
            continue
        if not matches_filter(params, target_committee):
            skipped_filter += 1
            continue
        try:
            points.append(summarize_raw(path))
        except Exception as exc:
            print(f"  SKIP {path}: {exc}")
            skipped_error += 1

    print(f"Collected {len(points)} adversarial-latency points "
          f"(skipped {skipped_filter} non-matching, {skipped_error} unreadable).")
    return points


def dedup(points):
    """Keep the latest entry per (protocol, load); newer source file wins."""
    points.sort(key=lambda p: p["source"])
    best = {}
    for p in points:
        best[(p["protocol"], p["load"])] = p
    return list(best.values())


def plot(points, output_pdf, committee, latency_ymax_ms):
    if not points:
        print("No adversarial-latency points found. Skipping figure generation.")
        return

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

    fig.suptitle(
        f"Adversarial latency (10 s overlay on f far peers), committee = {committee}",
        y=0.995,
    )
    fig.align_ylabels([ax_lat, ax_cpu, ax_bw])
    fig.savefig(output_pdf, bbox_inches="tight")
    print(f"Saved figure to {output_pdf}")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--committee", type=int, default=100)
    parser.add_argument("--results-dir", type=str, default="results/results-main")
    parser.add_argument("--output-pdf", type=str,
                        default="results/tps_latency_cpu_bw_adv.pdf")
    parser.add_argument("--output-json", type=str,
                        default="results/tps_latency_cpu_bw_adv.json")
    parser.add_argument("--latency-ymax-ms", type=float, default=15000.0,
                        help="Upper bound for the latency panel. Adversarial "
                             "runs sit in the multi-second range; default "
                             "15s lets the knee be visible.")
    args = parser.parse_args()

    points = dedup(collect(args.results_dir, args.committee))
    points.sort(key=lambda p: (p["protocol"], p["load"]))

    print(f"\nKept {len(points)} unique points after dedup:")
    for p in points:
        print(f"  {p['protocol']:15s} load={p['load']:>7d}  tps={p['tps']:>10.1f}  "
              f"lat={p['lat_p50_ms']:>7.0f} ms  cpu={p['cpu_p50']:>5.2f}  "
              f"eff={p['bw_eff_p50']:>6.2f}")

    if points:
        clean = [{k: v for k, v in p.items() if k != "source"} for p in points]
        with open(args.output_json, "w") as f:
            json.dump(clean, f, indent=2)
        print(f"Saved aggregated JSON to {args.output_json}")

    plot(points, args.output_pdf, args.committee, args.latency_ymax_ms)


if __name__ == "__main__":
    main()
