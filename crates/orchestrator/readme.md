# Orchestrator

The Orchestrator crate provides facilities for quickly deploying and benchmarking
this codebase in a geo-distributed environment.
Please note that it is not intended for production deployments
or as an indicator of production engineering best practices.
Its purpose is to facilitate research projects by allowing benchmarking
of (variants of) the codebase and analyzing performance.

This guide provides a step-by-step explanation of how to run geo-distributed benchmarks on [Amazon Web Services (AWS)](http://aws.amazon.com).

## Step 1. Set up cloud provider credentials

To enable programmatic access to your cloud provider account from your local machine,
you need to set up your cloud provider credentials.
These credentials authorize your machine to create, delete,
and edit instances programmatically on your account.

### Setting up AWS credentials

1. Find your 'access key id' and 'secret access key'
([link](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-creds)).
2. Create a file `~/.aws/credentials` with the following content:

```text
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
```

Do not specify any AWS region in that file, as the scripts need to handle multiple regions programmatically.

## Step 2. Specify the testbed configuration

Create a file called `settings.yml` that contains all the configuration parameters
for the testbed deployment.
You can find an example file at `./assets/settings-template.yml`.

The documentation of the `Settings` struct in `./src/settings.rs` provides
detailed information about each field and indicates which ones are optional.
If you're working with a private GitHub repository, you can include a
[private access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
in the repository URL. The repository URL should be formatted as follows:

```yml
repository:
  - url: http://YOUR_ACCESS_TOKEN@github.com/iotaledger/starfish.git
  - commit: main
```

### Pre-built binary (optional)

By default the orchestrator clones the repository and builds from source on each
remote machine. To skip compilation, set `pre_built_binary` in `settings.yml`:

```yml
# Download from URL (each remote machine fetches via curl):
pre_built_binary: "https://github.com/iotaledger/starfish/releases/download/nightly/starfish-linux-amd64"

# Or SCP a local binary to all machines:
pre_built_binary: "./target/release/starfish"
```

Nightly builds are published automatically from `main` and can be used as the
URL source. See [Releases](https://github.com/iotaledger/starfish/releases/tag/nightly).

### Spot Instances (optional)

To use EC2 Spot Instances instead of On-Demand, add `spot: true` to
`settings.yml`:

```yml
spot: true
```

Spot instances use spare EC2 capacity at a significant discount (typically
40-60% cheaper) but may be interrupted with 2 minutes notice. This is
acceptable for benchmark workloads since experiments can simply be restarted.
The orchestrator requests one-time spot instances that are not automatically
re-provisioned after interruption.

**Tips for running 100+ spot instances:**
- `us-east-2` (Ohio) and `us-west-2` (Oregon) tend to have the deepest spare
  capacity and lowest spot prices for `m5d` instances.
- AWS spot vCPU limits are per-region. Verify your limit covers your needs
  (e.g., 100 × `m5d.4xlarge` = 1600 vCPUs). Request a limit increase via the
  AWS Service Quotas console if needed.

## Step 3. Create a testbed

The `orchestrator` binary provides various functionalities for creating,
starting, stopping, and destroying instances.
You can use the following command to boot 2 instances per region
(if the settings file specifies 10 regions, as shown in the example above,
a total of 20 instances will be created):

```bash
cargo run --bin orchestrator -- testbed deploy --instances 2
```

Note that one instance is used for collecting metrics and representing them
in Grafana (unless an [external monitoring server](#external-monitoring-server-optional)
is configured). This means that for a committee of 10 validators
one needs to run 11 instances (or 10 with an external monitoring server).

To check the current status of the testbed instances, use the following command:

```bash
cargo run --bin orchestrator -- testbed status
```

Instances listed with a green number are available and ready for use, while instances listed with a red number are stopped.

## Step 4. Running benchmarks

Running benchmarks involves installing the specified version of the codebase
on the remote machines and running one validator per instance.
One dedicated instance will take care of processing incoming metrics,
so make sure that `committee_size`<`number_instances`.
For example, the following command benchmarks a committee of `10` validators
running `Starfish` consensus protocol under a constant load of 1000 tx/s:

```bash
cargo run --bin orchestrator -- benchmark --consensus starfish --committee 10 --loads 1000
```

In a network of 10 validators, each with a corresponding load generator,
each load generator submits a fixed load of 100 tx/s
or more precisely 10 tx every 100ms.
Performance measurements are collected by regularly scraping
the Prometheus metrics exposed by the load generators.
There are 5 options for consensus protocols: `starfish`, `starfish-speed`, `starfish-bls`, `mysticeti`, and `cordial-miners`.

To run with Byzantine validators:

```bash
cargo run --bin orchestrator -- benchmark --consensus mysticeti --committee 4 --loads 200 --byzantine-nodes 1 --byzantine-strategy chain-bomb
```

In a network of 4 validators, each with a corresponding load generator,
each load generator submits a fixed load of 50 tx/s.
One node is Byzantine and follows `Chain-Bomb` Byzantine strategies.
The available options for Byzantine strategies are
`chain-bomb`, `equivocating-chains`, `equivocating-two-chains`, `equivocating-chains-bomb`, `timeout-leader`, `leader-withholding`, `random-drop`.

In case of running in a single region AWS VPC, it's possible to use
internal IP addresses to avoid unnecessary costs for data transfer
between validators. This option can be enabled by adding
the `--use-internal-ip-addresses` flag to the `benchmark` command.
In addition, since the latencies within one region are very small,
one can _mimic_ extra latencies matching some geo-distributed setup
using the flag `--mimic-extra-latency`. So, the command could be

```bash
cargo run --bin orchestrator -- benchmark --consensus starfish --committee 10 --loads 20000 --byzantine-nodes 1 --byzantine-strategy equivocating-chains-bomb --mimic-extra-latency --use-internal-ip-addresses
```

Additional benchmark flags:

| Flag | Default | Description |
|---|---|---|
| `--dissemination-mode` | _(protocol default)_ | `protocol-default`, `pull`, `push-causal`, `push-useful` |
| `--storage-backend` | _(unset)_ | `rocksdb` or `tidehunter` |
| `--transaction-mode` | _(unset)_ | `all_zero` or `random` |
| `--protocols` | _(unset)_ | Run multiple protocols in sequence |
| `--enable-tracing` | false | Enable detailed log traces |
| `--adversarial-latency` | false | Overlay 10s latency on f farthest peers |
| `--skip-testbed-update` | false | Skip pulling latest code on remotes |
| `--skip-testbed-configuration` | false | Skip reconfiguring nodes |
| `--destroy-testbed-after` | false | Destroy testbed after benchmark |

## Step 5. Benchmark sweeps

The `benchmark-sweep` subcommand performs adaptive
latency-throughput characterization. It works in two phases:
a coarse phase that multiplies load aggressively to find the
throughput region, then a fine phase that narrows in with smaller
increments. The sweep stops when p50 latency exceeds
`--sweep-latency-goal-ms` or `--sweep-max-points` measurements
are collected.

```bash
cargo run --bin orchestrator -- benchmark-sweep \
    --consensus starfish --committee 10
```

Use `--protocols` to sweep multiple protocols in one run:

```bash
cargo run --bin orchestrator -- benchmark-sweep \
    --protocols starfish starfish-speed starfish-bls \
    --committee 10
```

Sweep-specific flags:

| Flag | Default | Description |
|---|---|---|
| `--sweep-initial-load` | 2000 | Starting load (tx/s) |
| `--sweep-latency-goal-ms` | 2000 | Stop when p50 exceeds this (ms) |
| `--sweep-refine-latency-ms` | 1000 | Switch to fine phase above this (ms) |
| `--sweep-coarse-multiplier` | 4.0 | Coarse-phase load multiplier |
| `--sweep-fine-multiplier` | 1.25 | Fine-phase load multiplier |
| `--sweep-max-points` | 12 | Max measurements per protocol |

All common benchmark flags (`--mimic-extra-latency`,
`--adversarial-latency`, `--dissemination-mode`, etc.) are also
accepted.

## Step 6. Summarize results

The `summarize` subcommand prints a summary table from a saved
benchmark results file:

```bash
cargo run --bin orchestrator -- summarize --path results.json
```

## Step 7. Monitoring

The orchestrator provides facilities to monitor metrics on clients and nodes.
It deploys a [Prometheus](https://prometheus.io) instance and
a [Grafana](https://grafana.com) instance on a dedicated remote machine.
Grafana is then available on the address printed on stdout
(e.g., `http://3.83.97.12:3000`) with the default username and password
both set to `admin`. You can either create a
[new dashboard](https://grafana.com/docs/grafana/latest/getting-started/build-first-dashboard/)
or [import](https://grafana.com/docs/grafana/latest/dashboards/manage-dashboards/#import-a-dashboard)
the example dashboard located in the `monitoring/grafana/` folder.

### External monitoring server (optional)

By default the orchestrator allocates one cloud instance for monitoring,
which means a committee of 10 validators requires 11 instances. To use a
pre-existing server instead, set `monitoring_server` in `settings.yml`:

```yml
monitoring_server: root@monitor.example.com
```

The value accepts `[user@]host` format. When set, the orchestrator:

- Installs Prometheus and Grafana on the server during setup.
- Does **not** consume a cloud instance for monitoring (10 validators = 10 instances).
- Uses the specified SSH user (or falls back to the cloud instance user).
- Never destroys the external server on `testbed destroy`.

The server must be reachable via SSH with the same private key configured in
`ssh_private_key_file`. Hostnames are resolved via DNS. When running with
`--use-internal-ip-addresses`, the server must be able to reach the validators'
private IPs (e.g., it should be in the same VPC).

### Collecting monitoring data locally

After a benchmark completes, the remote monitoring instance keeps running
(and costing money). The `collect-monitoring` command downloads the Prometheus
TSDB data, starts a local monitoring stack via Docker Compose, and destroys the
remote monitoring instance so that all historical metrics remain accessible
locally.

```bash
cargo run --bin orchestrator -- collect-monitoring
```

This will:

1. Stop any conflicting local monitoring stacks (previous `collect-monitoring`
   runs or a dry-run stack on the same ports).
2. Kill all remote processes (validators and clients) via `tmux kill-server`.
3. Download Prometheus TSDB data from the remote monitoring instance.
4. Generate a local `docker-compose.yml` and `prometheus.yml` under
   `./monitoring-data/<timestamp>/`.
5. Start Prometheus and Grafana containers locally.
6. Print the local Grafana (`http://localhost:3000`) and Prometheus
   (`http://localhost:9090`) URLs.
7. Destroy the remote monitoring instance.

**Prerequisites**: Docker must be installed and running on the local machine,
and `monitoring` must be enabled in `settings.yml`.

#### Collecting monitoring data during testbed destruction

The `testbed destroy` command accepts an optional `--collect-monitoring` flag
that downloads monitoring data in parallel with destroying the validator
instances, then destroys the monitoring instance last:

```bash
cargo run --bin orchestrator -- testbed destroy --collect-monitoring
```

This is useful when you want to tear down the entire testbed while preserving
monitoring data in a single command.
