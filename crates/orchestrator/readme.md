# Orchestrator

The Orchestrator crate provides facilities for quickly deploying and benchmarking this codebase in a geo-distributed environment. Please note that it is not intended for production deployments or as an indicator of production engineering best practices. Its purpose is to facilitate research projects by allowing benchmarking of (variants of) the codebase and analyzing performance.

This guide provides a step-by-step explanation of how to run geo-distributed benchmarks on either [Vultr](http://vultr.com) or [Amazon Web Services (AWS)](http://aws.amazon.com).

## Step 1. Set up cloud provider credentials

To enable programmatic access to your cloud provider account from your local machine, you need to set up your cloud provider credentials. These credentials authorize your machine to create, delete, and edit instances programmatically on your account.


### Setting up AWS credentials

1. Find your ['access key id' and 'secret access key'](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-creds).
2. Create a file `~/.aws/credentials` with the following content:

```text
[default]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
```

Do not specify any AWS region in that file, as the scripts need to handle multiple regions programmatically.

## Step 2. Specify the testbed configuration

Create a file called `settings.yml` that contains all the configuration parameters for the testbed deployment. You can find an example file at `./assets/settings-template.yml`.

The documentation of the `Settings` struct in `./src/settings.rs` provides detailed information about each field and indicates which ones are optional. If you're working with a private GitHub repository, you can include a [private access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) in the repository URL. For example, if your access token is `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`, the repository URL should be formatted as follows:

```yml
repository:
  - url: http://YOUR_ACCESS_TOKEN@github.com/asonino/-mysticeti.git
  - commit: main
```

## Step 3. Create a testbed

The `orchestrator` binary provides various functionalities for creating, starting, stopping, and destroying instances. You can use the following command to boot 2 instances per region (if the settings file specifies 10 regions, as shown in the example above, a total of 20 instances will be created):

```bash
cargo run --bin orchestrator -- testbed deploy --instances 2
```

Note that one instance is used for collecting metrics and representing them in Grafana. This means that for a committee of 10 validators one needs to run 11 instances. 

To check the current status of the testbed instances, use the following command:

```bash
cargo run --bin orchestrator testbed status
```

Instances listed with a green number are available and ready for use, while instances listed with a red number are stopped.

## Step 4. Running benchmarks

Running benchmarks involves installing the specified version of the codebase on the remote machines and running one validator per instance. One dedicated instance will take care of processing incoming metrics, so make sure that `committee_size`<`number_instances`. For example, the following command benchmarks a committee of `10` validators running `Starfish-Pull` consensus protocol under a constant load of 1000 tx/s:

```bash
cargo run --bin orchestrator -- benchmark --consensus starfish-pull --committee 10 --loads 1000
```

In a network of 10 validators, each with a corresponding load generator, each load generator submits a fixed load of 100 tx/s or more precisely 10 tx every 100ms. Performance measurements are collected by regularly scraping the Prometheus metrics exposed by the load generators.
There are 4 options for consensus protocols: `starfish`, `starfish-pull`, `mysticeti`, and `cordial-miners`.

To run with Byzantine validators:
```bash
cargo run --bin orchestrator -- benchmark --consensus mysticeti --committee 4 --loads 200 --byzantine-nodes 1 --byzantine-strategy chain-bomb 
```
In a network of 4 validators, each with a corresponding load generator, each load generator submits a fixed load of 50 tx/s. One node is Byzantine and follows `Chain-Bomb` Byzantine strategies. The available options for Byzantine strategies are
`chain-bomb`, `equivocating-two-chains`, `equivocating-chains-bomb`, `timeout-leader`, `leader-withholding`, `equivocating-two-chains`.

In case of running in a single region AWS VPC, it's possible to use internal IP addresses to avoid unnecessary costs for data transfer between validators. This option can be enabled by adding the `--use-internal-ip-addresses` flag to the `benchmark` command. In addition,
since the latencies within one region are very small, one can _mimic_ extra latencies matching some geo-distributed setup using the flag `--mimic-extra-latency`. So, the command could be

```bash
cargo run --bin orchestrator -- benchmark --consensus starfish --committee 10 --loads 20000 --byzantine-nodes 1 --byzantine-strategy equivocating-chains-bomb --mimic-extra-latency --use-internal-ip-addresses 
```


## Step 5. Monitoring

The orchestrator provides facilities to monitor metrics on clients and nodes. It deploys a [Prometheus](https://prometheus.io) instance and a [Grafana](https://grafana.com) instance on a dedicated remote machine. Grafana is then available on the address printed on stdout (e.g., `http://3.83.97.12:3000`) with the default username and password both set to `admin`. You can either create a [new dashboard](https://grafana.com/docs/grafana/latest/getting-started/build-first-dashboard/) or [import](https://grafana.com/docs/grafana/latest/dashboards/manage-dashboards/#import-a-dashboard) the example dashboard located in the `./assets` folder.
