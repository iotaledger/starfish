#!/usr/bin/env python3

import subprocess
import csv
import sys
import argparse
import os
import time
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt


class BenchmarkOrchestrator:
    def __init__(self, start_latency=20, end_latency=200, step_latency=20,
                 committee_size=20, duration_secs=300, protocols="starfish,mysticeti",
                 output_file="latency_benchmark_results.csv"):
        self.start_latency = start_latency
        self.end_latency = end_latency
        self.step_latency = step_latency
        self.committee_size = committee_size
        self.duration_secs = duration_secs
        self.protocols = [p.strip() for p in protocols.split(",")]
        self.output_file = output_file
        self.results = []

    def print_header(self):
        print("\n" + "╔" + "═" * 58 + "╗")
        print("║" + " " * 12 + "LATENCY BENCHMARKING SUITE" + " " * 20 + "║")
        print("╚" + "═" * 58 + "╝\n")

    def print_config(self):
        print("Configuration:")
        print(f"  • Start Latency: {self.start_latency} ms")
        print(f"  • End Latency: {self.end_latency} ms")
        print(f"  • Step: {self.step_latency} ms")
        print(f"  • Committee Size: {self.committee_size} validators")
        print(f"  • Duration per run: {self.duration_secs} seconds")
        print(f"  • Protocols: {', '.join(self.protocols)}")
        print(f"  • Output file: {self.output_file}\n")

    def calculate_plan(self):
        latencies = list(range(self.start_latency, self.end_latency + 1, self.step_latency))
        num_latencies = len(latencies)
        num_protocols = len(self.protocols)
        total = num_latencies * num_protocols
        total_time = total * self.duration_secs // 60

        print("Experiment Plan:")
        print(f"  • Number of latencies: {num_latencies}")
        print(f"  • Number of protocols: {num_protocols}")
        print(f"  • Total experiments: {total}")
        print(f"  • Estimated time: ~{total_time} minutes\n")

        return latencies

    def build_project(self):
        print("Building Rust binary...")
        try:
            subprocess.run(
                ["cargo", "build", "--release", "--bin", "starfish"],
                capture_output=True,
                check=True,
                cwd=str(Path(__file__).resolve().parent.parent)
            )
            print("✓ Build complete\n")
        except subprocess.CalledProcessError as e:
            print(f"✗ Build failed: {e}\n")
            sys.exit(1)

    def create_output_file(self):
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "protocol", "network_latency_ms", "num_validators", "duration_secs",
                "p50_consensus_latency_ms", "p50_tx_latency_ms", "avg_tps", "avg_bps",
                "avg_bytes_sent", "avg_bytes_received"
            ])

    def extract_metrics(self, output):
        """Extract metrics from benchmark stdout"""
        metrics = {}

        for line in output.split('\n'):
            if "Average block latency:" in line:
                try:
                    metrics['block_latency'] = float(line.split()[-2])
                except (ValueError, IndexError):
                    metrics['block_latency'] = 0

            elif "Average e2e latency:" in line:
                try:
                    metrics['tx_latency'] = float(line.split()[-2])
                except (ValueError, IndexError):
                    metrics['tx_latency'] = 0

            elif "Average TPS:" in line:
                try:
                    metrics['tps'] = float(line.split()[-2])
                except (ValueError, IndexError):
                    metrics['tps'] = 0

            elif "Average BPS:" in line:
                try:
                    metrics['bps'] = float(line.split()[-2])
                except (ValueError, IndexError):
                    metrics['bps'] = 0

            elif "Average bandwidth out:" in line:
                try:
                    bw_out = float(line.split()[-2])
                    metrics['bytes_sent'] = int(bw_out * self.duration_secs * 1024 * 1024)
                except (ValueError, IndexError):
                    metrics['bytes_sent'] = 0

            elif "Average bandwidth in:" in line:
                try:
                    bw_in = float(line.split()[-2])
                    metrics['bytes_received'] = int(bw_in * self.duration_secs * 1024 * 1024)
                except (ValueError, IndexError):
                    metrics['bytes_received'] = 0

        return metrics

    def run_benchmark(self, protocol, latency_ms):
        """Run a single benchmark experiment"""
        sys.stdout.write(f"  Running {protocol} @ {latency_ms}ms latency... ")
        sys.stdout.flush()

        try:
            result = subprocess.run(
                [
                    "cargo", "run", "--release", "--bin", "starfish", "--",
                    "local-benchmark",
                    "--committee-size", str(self.committee_size),
                    "--load", "0",
                    "--uniform-latency-ms", str(float(latency_ms)),
                    "--consensus", protocol,
                    "--duration-secs", str(self.duration_secs),
                ],
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).resolve().parent.parent),
                timeout=self.duration_secs + 120
            )

            if result.returncode == 0:
                print("✓")
                metrics = self.extract_metrics(result.stdout)

                return {
                    "protocol": protocol,
                    "network_latency_ms": latency_ms,
                    "num_validators": self.committee_size,
                    "duration_secs": self.duration_secs,
                    "p50_consensus_latency_ms": metrics.get('block_latency', 0),
                    "p50_tx_latency_ms": metrics.get('tx_latency', 0),
                    "avg_tps": metrics.get('tps', 0),
                    "avg_bps": metrics.get('bps', 0),
                    "avg_bytes_sent": metrics.get('bytes_sent', 0),
                    "avg_bytes_received": metrics.get('bytes_received', 0),
                }
            else:
                print("✗")
                return None

        except subprocess.TimeoutExpired:
            print("✗ (timeout)")
            return None
        except Exception as e:
            print(f"✗ ({e})")
            return None

    def save_results(self, results):
        """Save results to CSV file"""
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "protocol", "network_latency_ms", "num_validators", "duration_secs",
                "p50_consensus_latency_ms", "p50_tx_latency_ms", "avg_tps", "avg_bps",
                "avg_bytes_sent", "avg_bytes_received"
            ])
            for result in results:
                if result:
                    writer.writerow(result)

    def calculate_theoretical_latency(self, protocol, latency_ms):
        """Calculate theoretical latency bounds"""
        if protocol == "starfish":
            return (latency_ms * 5.0, latency_ms * 7.0)
        elif protocol == "mysticeti":
            return (latency_ms * 4.0, latency_ms * 16.0 / 3.0)
        else:
            return (0.0, 0.0)

    def generate_visualization(self):
        """Generate plots and summary from CSV results"""
        print("Generating visualization...")

        try:
            df = pd.read_csv(self.output_file)

            # Create figure
            fig, ax = plt.subplots(figsize=(12, 7))

            # Color scheme
            colors = {
                'starfish_measured': '#1f77b4',      # blue
                'starfish_theory': '#aec7e8',        # light blue
                'mysticeti_measured': '#ff7f0e',    # orange
                'mysticeti_theory': '#ffbb78',      # light orange
            }

            # Plot for each protocol
            protocols = df['protocol'].unique()
            for protocol in protocols:
                protocol_data = df[df['protocol'] == protocol].sort_values('network_latency_ms')

                # Measured latency
                marker = 'o' if protocol == 'starfish' else 's'
                color = colors[f'{protocol}_measured']
                ax.plot(
                    protocol_data['network_latency_ms'],
                    protocol_data['p50_consensus_latency_ms'],
                    marker=marker,
                    linewidth=2.5,
                    markersize=9,
                    label=f'{protocol.capitalize()} (measured)',
                    color=color,
                    zorder=3,
                )

                # Theoretical bounds
                bounds = [self.calculate_theoretical_latency(protocol, lat)
                         for lat in protocol_data['network_latency_ms']]
                lower_bounds = [b[0] for b in bounds]
                upper_bounds = [b[1] for b in bounds]

                color_theory = colors[f'{protocol}_theory']

                # Lower bound
                ax.plot(
                    protocol_data['network_latency_ms'],
                    lower_bounds,
                    linestyle='--',
                    linewidth=2,
                    alpha=0.6,
                    label=f'{protocol.capitalize()} (lower bound)',
                    color=color_theory,
                    zorder=2,
                )

                # Upper bound
                ax.plot(
                    protocol_data['network_latency_ms'],
                    upper_bounds,
                    linestyle=':',
                    linewidth=2,
                    alpha=0.6,
                    label=f'{protocol.capitalize()} (upper bound)',
                    color=color_theory,
                    zorder=2,
                )

                # Shade the region between bounds
                ax.fill_between(
                    protocol_data['network_latency_ms'],
                    lower_bounds,
                    upper_bounds,
                    alpha=0.1,
                    color=color_theory,
                    zorder=1,
                )

            # Formatting
            ax.set_xlabel('Network Latency Δ (ms)', fontsize=13, fontweight='bold')
            ax.set_ylabel('Consensus Latency (ms)', fontsize=13, fontweight='bold')
            ax.set_title('Consensus Latency vs Network Latency\nStarfish: 5Δ - 7Δ, Mysticeti: 4Δ - 5⅓Δ',
                        fontsize=15, fontweight='bold')
            ax.legend(fontsize=11, loc='upper left', framealpha=0.95)
            ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
            ax.set_axisbelow(True)

            # Set reasonable limits
            all_latencies = df['p50_consensus_latency_ms'].tolist()
            max_lat = max(all_latencies) if all_latencies else 1000
            ax.set_ylim(bottom=0, top=max_lat * 1.1)

            # Improve tick labels
            ax.tick_params(axis='both', labelsize=11)

            # Tight layout
            plt.tight_layout()

            # Save plots
            plot_dir = Path(self.output_file).parent / "plots"
            plot_dir.mkdir(parents=True, exist_ok=True)

            suffix = f"_{self.start_latency}-{self.end_latency}ms_step{self.step_latency}_n{self.committee_size}_dur{self.duration_secs}s"
            png_path = plot_dir / f'latency_comparison{suffix}.png'
            pdf_path = plot_dir / f'latency_comparison{suffix}.pdf'

            fig.savefig(png_path, dpi=300, bbox_inches='tight')
            fig.savefig(pdf_path, bbox_inches='tight')
            plt.close()

            print(f"✓ Plots saved to {plot_dir}")
            print(f"  • {png_path} (300 DPI)")
            print(f"  • {pdf_path}")

            # Print summary
            self.print_summary(df)

        except Exception as e:
            print(f"⚠ Visualization failed: {e}")

    def print_summary(self, df):
        """Print benchmark summary with bounds checking"""
        print("\n" + "=" * 70)
        print("BENCHMARK SUMMARY")
        print("=" * 70)

        for protocol in df['protocol'].unique():
            protocol_data = df[df['protocol'] == protocol]
            min_lat = protocol_data['p50_consensus_latency_ms'].min()
            max_lat = protocol_data['p50_consensus_latency_ms'].max()
            avg_lat = protocol_data['p50_consensus_latency_ms'].mean()

            print(f"\n{protocol.upper()}:")
            print(f"  Min consensus latency: {min_lat:.2f} ms")
            print(f"  Max consensus latency: {max_lat:.2f} ms")
            print(f"  Avg consensus latency: {avg_lat:.2f} ms")

            # Compare with theory
            if protocol == "starfish":
                print(f"\n  Comparison with theoretical bounds (5Δ - 7Δ):")
            else:
                print(f"\n  Comparison with theoretical bounds (4Δ - 5⅓Δ):")

            for _, row in protocol_data.iterrows():
                net_lat = row['network_latency_ms']
                measured = row['p50_consensus_latency_ms']
                lower, upper = self.calculate_theoretical_latency(protocol, net_lat)
                in_bounds = "✓" if lower <= measured <= upper else "✗"
                print(f"    {net_lat:>5.0f}ms → Measured: {measured:7.2f}ms, Bounds: [{lower:7.2f}ms, {upper:7.2f}ms] {in_bounds}")

        print("\n" + "=" * 70)

    def run(self):
        """Run the full benchmarking suite"""
        self.print_header()
        self.print_config()
        latencies = self.calculate_plan()

        self.build_project()
        print("Waiting 10 seconds before starting benchmarks...")
        time.sleep(10)
        self.create_output_file()

        completed = 0
        total = len(latencies) * len(self.protocols)

        for protocol in self.protocols:
            print(f"Protocol: {protocol}")

            batch_results = []
            for latency_ms in latencies:
                result = self.run_benchmark(protocol, latency_ms)
                if result:
                    batch_results.append(result)
                    completed += 1
                else:
                    batch_results.append(None)
                    completed += 1

            self.save_results(batch_results)
            print()

        # Print completion summary
        print("╔" + "═" * 58 + "╗")
        print("║" + " " * 18 + "BENCHMARKS COMPLETE" + " " * 21 + "║")
        print("╚" + "═" * 58 + "╝")
        print(f"\nResults saved to: {self.output_file}")
        print(f"Experiments completed: {completed}/{total}\n")

        # Generate visualization
        self.generate_visualization()

        print(f"\n✓ Done!\n")


def main():
    parser = argparse.ArgumentParser(
        description="Latency benchmarking for consensus protocols",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default configuration (20-200ms in 20ms steps, 300s duration)
  python3 benchmark.py

  # Quick test (10-100ms in 10ms steps, 60s duration)
  python3 benchmark.py --start 10 --end 100 --step 10 --duration 60

  # Single protocol
  python3 benchmark.py --protocols starfish --output results.csv

  # High resolution
  python3 benchmark.py --start 20 --end 200 --step 5 --duration 600
        """
    )

    parser.add_argument("--start", type=int, default=20,
                       help="Starting latency in ms (default: 20)")
    parser.add_argument("--end", type=int, default=200,
                       help="Ending latency in ms (default: 200)")
    parser.add_argument("--step", type=int, default=20,
                       help="Step size for latency (default: 20)")
    parser.add_argument("--committee-size", type=int, default=20,
                       help="Number of validators (default: 20)")
    parser.add_argument("--duration", type=int, default=300,
                       help="Duration per benchmark in seconds (default: 300)")
    parser.add_argument("--protocols", type=str, default="starfish,mysticeti",
                       help="Comma-separated protocols (default: starfish,mysticeti)")
    parser.add_argument("--output", type=str, default="latency_benchmark_results.csv",
                       help="Output CSV file (default: latency_benchmark_results.csv)")

    args = parser.parse_args()

    orchestrator = BenchmarkOrchestrator(
        start_latency=args.start,
        end_latency=args.end,
        step_latency=args.step,
        committee_size=args.committee_size,
        duration_secs=args.duration,
        protocols=args.protocols,
        output_file=args.output
    )

    orchestrator.run()


if __name__ == "__main__":
    main()
