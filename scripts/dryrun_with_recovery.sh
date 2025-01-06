#!/bin/bash
# Parameters
NUM_VALIDATORS=${NUM_VALIDATORS:-10} #With N physical cores, it is recommended to have less than N validators
KILL_VALIDATORS=${KILL_VALIDATORS:-2} #Kill first validators after 1 minute
BOOT_VALIDATORS=${BOOT_VALIDATORS:-1} #Boot last validators after 1 minute
DESIRED_TPS=${DESIRED_TPS:-100000}
REMOVE_VOLUMES=0 # remove Grafana and Prometheus data volumes "0" | "1"

# Perform the division of DESIRED_TPS by NUM_VALIDATORS
TPS_PER_VALIDATOR=$(echo "$DESIRED_TPS / $NUM_VALIDATORS" | bc)

# Colors using tput
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)


# Output Validators
echo -e "${GREEN}Number of validators: ${YELLOW}$NUM_VALIDATORS${RESET}"

# Cleanup
echo -e "${CYAN}Cleaning up .ansi files and dryrun-validator directories...${RESET}"
find . -type f -name "*.ansi" -exec rm {} \; > /dev/null 2>&1
find . -type d -name "dryrun-validator*" -exec rm -r {} + > /dev/null 2>&1


# Prometheus Update
PROMETHEUS_CONFIG="monitoring/prometheus.yaml"
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

for ((i=0; i<NUM_VALIDATORS; i++)); do
  PORT=$((1500 + NUM_VALIDATORS + i))
  echo "          - 'host.docker.internal:$PORT'" >> $PROMETHEUS_CONFIG
done

echo -e "${GREEN}Updated prometheus.yaml successfully!${RESET}"


# Calculate port to look for committed leaders
PORT=$((1500 + NUM_VALIDATORS + KILL_VALIDATORS + 1))

# Define the file path
FILE="monitoring/grafana/grafana-dashboard.json"

# Replace the line in the file
sed -i '' -E "s/(host\.docker\.internal:)[0-9]{4}/\1$PORT/" "$FILE"

echo -e "${GREEN}Updated grafana-dashboard.json successfully!${RESET}"


# Docker Compose Down
(cd monitoring && docker compose down)


if [ "$REMOVE_VOLUMES" = 1 ]; then
    echo "Removing Grafana and Prometheus data volumes..."
    docker volume rm monitoring_grafana_data || echo "Grafana data volume not found or could not be removed."
    docker volume rm monitoring_prometheus_data || echo "Prometheus data volume not found or could not be removed."
else
    echo "Skipping removal of Grafana and Prometheus data volumes."
fi


# Docker Compose Up
(cd monitoring && docker compose up -d)
if [ $? -ne 0 ]; then
  echo "Error: Failed to start Docker Compose in the 'monitoring' directory."
  exit 1
fi

# Start Validators
tmux kill-server || true
for ((i=0; i<NUM_VALIDATORS - BOOT_VALIDATORS; i++)); do
  export RUST_BACKTRACE=1 RUST_LOG=warn,mysticeti_core::block_manager=trace,mysticeti_core::types=trace,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG,mysticeti_core::synchronizer=DEBUG,mysticeti_core::block_handler=DEBUG,mysticeti_core::transactions_generator=DEBUG,mysticeti_core::validator=trace,mysticeti_core::network=trace
  SESSION_NAME="validator_$i"
  LOG_FILE="validator_${i}.log.ansi"
  echo -e "${GREEN}Starting honest validator ${YELLOW}$i${RESET} with load $TPS_PER_VALIDATOR..."
  tmux new -d -s "$SESSION_NAME" "cargo run --release --bin mysticeti -- dry-run --committee-size $NUM_VALIDATORS --load $TPS_PER_VALIDATOR --mimic-extra-latency --authority $i 2>&1 | tee $LOG_FILE"
done

SHORT_URL=$(curl -s "http://tinyurl.com/api-create.php?url=http://localhost:3000/d/bdd54ee7-84de-4018-8bb7-92af2defc041/mysticeti?from=now-30m&to=now&refresh=5s")
echo -e "${CYAN}Grafana monitoring is available at: ${GREEN}$SHORT_URL${RESET}; user/password = admin"

# Kill first validators after 1 minute
sleep 60

for ((i=0; i<KILL_VALIDATORS; i++)); do
   SESSION_NAME="validator_$i"
   echo -e "${RED}Killing first validator ${YELLOW}$i${RESET}..."
   tmux kill-session -t "$SESSION_NAME"
done

# Start last validators
for ((i=NUM_VALIDATORS - BOOT_VALIDATORS; i<NUM_VALIDATORS; i++)); do
   SESSION_NAME="validator_$i"
   echo -e "${GREEN}Starting honest validator ${YELLOW}$i${RESET} with load $TPS_PER_VALIDATOR..."
   LOG_FILE="validator_${i}.log.ansi"
   tmux new -d -s "$SESSION_NAME" "cargo run --release --bin mysticeti -- dry-run --committee-size $NUM_VALIDATORS --load $TPS_PER_VALIDATOR --mimic-extra-latency --authority $i 2>&1 | tee $LOG_FILE"
done

# Wait for the validators to run (e.g., 600 seconds)
sleep 600

# Kill all tmux sessions
echo -e "${RED}Killing all tmux sessions...${RESET}"
tmux kill-server