#!/usr/bin/env python3
"""Generate a multi-page PDF report from benchmark-sweep CSV files.

Usage:
    python3 scripts/sweep_report.py results/results-main/sweeps/
    python3 scripts/sweep_report.py a.csv b.csv --output report.pdf
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.backends.backend_pdf import PdfPages

# One color per protocol, easily extensible.
COLORS = [
    "#1f77b4",
    "#ff7f0e",
    "#2ca02c",
    "#d62728",
    "#9467bd",
    "#8c564b",
    "#e377c2",
    "#7f7f7f",
]

METRIC_GROUPS = [
    {
        "title": "Transaction Latency vs Throughput",
        "p25": "transaction_latency_p25_ms",
        "p50": "transaction_latency_p50_ms",
        "p75": "transaction_latency_p75_ms",
        "ylabel": "Transaction Latency (ms)",
    },
    {
        "title": "Block Latency vs Throughput",
        "p25": "block_latency_p25_ms",
        "p50": "block_latency_p50_ms",
        "p75": "block_latency_p75_ms",
        "ylabel": "Block Latency (ms)",
    },
    {
        "title": "Bandwidth Efficiency vs Throughput",
        "p25": "bandwidth_efficiency_p25",
        "p50": "bandwidth_efficiency_p50",
        "p75": "bandwidth_efficiency_p75",
        "ylabel": "Bandwidth Efficiency",
    },
    {
        "title": "Bandwidth per Round vs Throughput",
        "p25": "bandwidth_per_round_p25_bytes",
        "p50": "bandwidth_per_round_p50_bytes",
        "p75": "bandwidth_per_round_p75_bytes",
        "ylabel": "bandwidth_per_round",  # sentinel — auto-scaled below
    },
    {
        "title": "CPU Usage vs Throughput",
        "p25": "cpu_p25_cores",
        "p50": "cpu_p50_cores",
        "p75": "cpu_p75_cores",
        "ylabel": "CPU (cores)",
    },
]


def load_csvs(paths: list[Path]) -> pd.DataFrame:
    frames = []
    for p in paths:
        df = pd.read_csv(p, skipinitialspace=True)
        df.columns = df.columns.str.strip()
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def auto_scale_bandwidth(df: pd.DataFrame, group: dict) -> tuple[pd.DataFrame, str]:
    """Scale bandwidth_per_round columns to KB or MB and return updated df + label."""
    max_val = df[group["p75"]].max()
    if max_val >= 1e6:
        scale, unit = 1e6, "MB"
    elif max_val >= 1e3:
        scale, unit = 1e3, "KB"
    else:
        scale, unit = 1, "B"
    df = df.copy()
    for key in ("p25", "p50", "p75"):
        df[group[key]] = df[group[key]] / scale
    return df, f"Bandwidth per Round ({unit})"


def render_title_page(pdf: PdfPages, df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(8.5, 11))
    ax.axis("off")

    protocols = sorted(df["protocol"].unique())
    committees = sorted(df["committee"].unique())
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = [
        "Starfish Benchmark Sweep Report",
        "",
        f"Generated: {date_str}",
        f"Committee size(s): {', '.join(str(c) for c in committees)}",
        f"Protocols: {', '.join(protocols)}",
        f"Data points: {len(df)}",
    ]
    ax.text(
        0.5,
        0.55,
        "\n".join(lines),
        transform=ax.transAxes,
        ha="center",
        va="center",
        fontsize=14,
        family="monospace",
        linespacing=1.8,
    )
    pdf.savefig(fig)
    plt.close(fig)


def render_metric_page(pdf: PdfPages, df: pd.DataFrame, group: dict) -> None:
    ylabel = group["ylabel"]

    # Auto-scale bandwidth columns.
    if ylabel == "bandwidth_per_round":
        df, ylabel = auto_scale_bandwidth(df, group)

    fig, ax = plt.subplots(figsize=(10, 6))
    protocols = sorted(df["protocol"].unique())

    for i, proto in enumerate(protocols):
        color = COLORS[i % len(COLORS)]
        sub = df[df["protocol"] == proto].sort_values("tps")
        x = sub["tps"]
        ax.fill_between(
            x, sub[group["p25"]], sub[group["p75"]], alpha=0.2, color=color
        )
        ax.plot(x, sub[group["p50"]], color=color, linewidth=2, label=proto)

    ax.set_xlabel("Throughput (tps)")
    ax.set_ylabel(ylabel)
    ax.set_title(group["title"])
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    pdf.savefig(fig)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sweep-result PDF report")
    parser.add_argument(
        "inputs",
        nargs="+",
        help="CSV files or a directory containing them",
    )
    parser.add_argument("--output", "-o", type=Path, default=None)
    args = parser.parse_args()

    # Resolve input paths.
    csv_paths: list[Path] = []
    for raw in args.inputs:
        p = Path(raw)
        if p.is_dir():
            csv_paths.extend(sorted(p.glob("*.csv")))
        elif p.is_file():
            csv_paths.append(p)
        else:
            sys.exit(f"Not found: {p}")

    if not csv_paths:
        sys.exit("No CSV files found.")

    df = load_csvs(csv_paths)

    # Determine output path.
    out = args.output
    if out is None:
        first_input = Path(args.inputs[0])
        parent = first_input if first_input.is_dir() else first_input.parent
        out = parent / "sweep_report.pdf"

    with PdfPages(out) as pdf:
        render_title_page(pdf, df)
        for group in METRIC_GROUPS:
            render_metric_page(pdf, df, group)

    print(f"Report written to {out}")


if __name__ == "__main__":
    main()
