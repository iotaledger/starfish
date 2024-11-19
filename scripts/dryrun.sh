#!/bin/bash

# Cleanup step: Remove all .ansi files and directories with the prefix "dryrun-validator"
echo "Cleaning up .ansi files and dryrun-validator directories..."

# Remove all .ansi files in the current directory and subdirectories, suppress output
find . -type f -name "*.ansi" -exec rm {} \; > /dev/null 2>&1

# Remove directories with prefix "dryrun-validator", suppress output
find . -type d -name "dryrun-validator*" -exec rm -r {} + > /dev/null 2>&1

# Get the number of validators from the user
NUM_VALIDATORS=${1:-7}
echo "Number of validators: $NUM_VALIDATORS"

echo "Updating prometheus.yaml for $NUM_VALIDATORS validators..."

# File path to prometheus.yaml
PROMETHEUS_CONFIG="monitoring/prometheus.yaml"

# Header for prometheus.yaml
cat <<EOL > $PROMETHEUS_CONFIG
global:
  scrape_interval: 1s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['prometheus:9090']

  - job_name: 'mysticeti-metrics'
    static_configs:
      - targets:
EOL

# Generate the target list for mysticeti-metrics
for ((i=0; i<NUM_VALIDATORS; i++)); do
  PORT=$((1500 + NUM_VALIDATORS+ i))
  echo "          - 'host.docker.internal:$PORT'" >> $PROMETHEUS_CONFIG
done

echo "Updated prometheus.yaml successfully!"

# Check if any containers are running in the monitoring directory
if (cd monitoring && docker compose ps -q | grep -q .); then
    echo "Monitoring services are already running. Stopping and removing them..."
    (cd monitoring && docker compose down)
    if [ $? -eq 0 ]; then
        echo "Monitoring services stopped successfully!"
    else
        echo "Failed to stop monitoring services."
        exit 1
    fi
else
    echo "No monitoring services are currently running."
fi


# Start Docker Compose to bring up monitoring services
echo "Starting monitoring services..."
(cd monitoring && docker compose up -d)

# Environment setup
export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG

# Kill any running tmux sessions
tmux kill-server || true

# Start tmux sessions for each validator
for ((i=0; i<NUM_VALIDATORS; i++)); do
    SESSION_NAME="v$i"
    LOG_FILE="v${i}.log.ansi"
    echo "Starting validator $i in tmux session $SESSION_NAME..."
    tmux new -d -s "$SESSION_NAME" "cargo run --bin mysticeti -- dry-run --committee-size $NUM_VALIDATORS --mimic-extra-latency 1 --authority $i > $LOG_FILE"
done

LONG_URL="http://localhost:3000/d/bdd54ee7-84de-4018-8bb7-92af2defc041/mysticeti?from=now-30m&to=now&refresh=5s"
SHORT_URL=$(curl -s "http://tinyurl.com/api-create.php?url=$LONG_URL")

echo "Grafana monitoring is available at $SHORT_URL"

# Wait for the validators to run (e.g., 600 seconds)
sleep 600

# Kill all tmux sessions
tmux kill-server