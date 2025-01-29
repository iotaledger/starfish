#!/bin/bash

#------------------------------------------------------------------------------
# Configuration Parameters
#------------------------------------------------------------------------------
NUM_VALIDATORS=${NUM_VALIDATORS:-10}     # Default: 5 validators (recommend < number of physical cores)
DESIRED_TPS=${DESIRED_TPS:-10000}       # Target transactions per second
CONSENSUS=${CONSENSUS:-starfish}         # Options: mysticeti, starfish, cordial-miners, starfish-push
NUM_BYZANTINE_NODES=${NUM_BYZANTINE_NODES:-0}  # Must be < NUM_VALIDATORS / 3
BYZANTINE_STRATEGY=${BYZANTINE_STRATEGY:-equivocating-chains-bomb} #| "timeout-leader"          | "leader-withholding" | "chain-bomb"              |
                                                      #| "equivocating-two-chains" |"equivocating-chains" | "equivocating-chains-bomb"|
TEST_TIME=${TEST_TIME:-600}               # Total test duration in seconds
REMOVE_VOLUMES=0                       # Set to 1 to clear Grafana/Prometheus volumes

# Calculate TPS per validator
TPS_PER_VALIDATOR=$(echo "$DESIRED_TPS / $NUM_VALIDATORS" | bc)

#------------------------------------------------------------------------------
# Terminal Colors
#------------------------------------------------------------------------------
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)

#------------------------------------------------------------------------------
# Cleanup Previous Run
#------------------------------------------------------------------------------
tmux kill-server || true
echo -e "${GREEN}Number of validators: ${YELLOW}$NUM_VALIDATORS${RESET}"

# Remove old logs and validator directories
echo -e "${CYAN}Cleaning up previous run data...${RESET}"
find . -type f -name "*.ansi" -exec rm {} \; > /dev/null 2>&1
find . -type d -name "dryrun-validator*" -exec rm -r {} + > /dev/null 2>&1

#------------------------------------------------------------------------------
# Monitoring Setup
#------------------------------------------------------------------------------
# Update Prometheus configuration
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

# Add validator endpoints
for ((i=0; i<NUM_VALIDATORS; i++)); do
  PORT=$((1500 + NUM_VALIDATORS + i))
  echo "          - 'host.docker.internal:$PORT'" >> $PROMETHEUS_CONFIG
done

# Update Grafana dashboard port
PORT=$((1500 + NUM_VALIDATORS + 2))
FILE="monitoring/grafana/grafana-dashboard.json"
sed -i '' -E "s/(host\.docker\.internal:)[0-9]{4}/\1$PORT/" "$FILE"

echo -e "${GREEN}Monitoring configuration updated${RESET}"

#------------------------------------------------------------------------------
# Docker Services
#------------------------------------------------------------------------------
(cd monitoring && docker compose down)

# Handle volume cleanup if requested
if [ "$REMOVE_VOLUMES" = 1 ]; then
    echo "Removing monitoring volumes..."
    docker volume rm monitoring_grafana_data monitoring_prometheus_data 2>/dev/null || true
fi

# Start monitoring services
(cd monitoring && docker compose up -d) || {
    echo "${RED}Failed to start monitoring services${RESET}"
    exit 1
}

#------------------------------------------------------------------------------
# Launch Validators
#------------------------------------------------------------------------------
echo "${CYAN}Deploying consensus protocol: ${GREEN}$CONSENSUS${RESET}"

# Environment variables for logging
export RUST_BACKTRACE=1
export RUST_LOG=warn,mysticeti_core::block_manager=trace,mysticeti_core::block_handler=trace,\
mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG,\
mysticeti_core::synchronizer=DEBUG,mysticeti_core::transactions_generator=DEBUG,\
mysticeti_core::validator=trace,mysticeti_core::network=trace,mysticeti_core::block_store=trace,\
mysticeti_core::threshold_core=trace,mysticeti_core::syncer=trace,

BYZANTINE_COUNT=0
for ((i=0; i<NUM_VALIDATORS; i++)); do
  SESSION_NAME="validator_$i"
  LOG_FILE="validator_${i}.log.ansi"

  # Determine if this validator should be Byzantine
  if (( i % 3 == 0 && BYZANTINE_COUNT < NUM_BYZANTINE_NODES )); then
      LOAD=0
      TYPE="${YELLOW}$BYZANTINE_STRATEGY${RESET}"
      ((BYZANTINE_COUNT++))
      EXTRA_FLAGS="--byzantine-strategy $BYZANTINE_STRATEGY"
  else
      LOAD=$TPS_PER_VALIDATOR
      TYPE="honest"
      EXTRA_FLAGS=""
  fi

  echo -e "${GREEN}Starting $TYPE validator ${YELLOW}$i${RESET} with load $LOAD..."
  tmux new -d -s "$SESSION_NAME" "cargo run --release --bin mysticeti -- \
    dry-run \
    --committee-size $NUM_VALIDATORS \
    --load $LOAD \
    --mimic-extra-latency \
    --authority $i \
    --consensus $CONSENSUS \
    $EXTRA_FLAGS \
    2>&1 | tee $LOG_FILE"
done

#------------------------------------------------------------------------------
# Monitoring Dashboard
#------------------------------------------------------------------------------
DASHBOARD_URL="http://localhost:3000/d/bdd54ee7-84de-4018-8bb7-92af2defc041/mysticeti?from=now-30m&to=now&refresh=5s"
echo -e "${CYAN}Grafana dashboard: ${GREEN}$DASHBOARD_URL${RESET}"
echo -e "${CYAN}Credentials: admin/supers3cret${RESET}"


sleep "$TEST_TIME"

# Cleanup
echo -e "${RED}Terminating experiment...${RESET}"
tmux kill-server