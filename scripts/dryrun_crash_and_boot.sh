#!/bin/bash

# Parameters
NUM_VALIDATORS=${NUM_VALIDATORS:-10}      # Total number of validators (recommend < number of physical cores)
KILL_VALIDATORS=${KILL_VALIDATORS:-2}     # Number of first validators to kill after CRASH_TIME
BOOT_VALIDATORS=${BOOT_VALIDATORS:-1}     # Number of last validators to boot after CRASH_TIME
DESIRED_TPS=${DESIRED_TPS:-20000}        # Target total transactions per second
TEST_TIME=${TEST_TIME:-600}               # Total test duration in seconds
CRASH_TIME=${CRASH_TIME:-300}             # When to crash first nodes and start the last one
REMOVE_VOLUMES=${REMOVE_VOLUMES:-1}        # Whether to remove Grafana/Prometheus volumes (1=yes, 0=no)
CONSENSUS=${CONSENSUS:-starfish-push}           # Consensus protocol: starfish, starfish, cordial-miners, starfish-push
BYZANTINE_STRATEGY=${BYZANTINE_STRATEGY:-equivocating-chains-bomb}  # Byzantine strategies: timeout-leader, leader-withholding,
                                                                   # equivocating-chains, equivocating-two-chains,
                                                                   # chain-bomb, equivocating-chains-bomb


TPS_PER_VALIDATOR=$(echo "$DESIRED_TPS / $NUM_VALIDATORS" | bc)

# Colors
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)

# Cleanup
tmux kill-server || true
find . -type f -name "*.ansi" -exec rm {} \; > /dev/null 2>&1
find . -type d -name "dryrun-validator*" -exec rm -r {} + > /dev/null 2>&1

# Update monitoring configs
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
  echo "          - 'host.docker.internal:$((1500 + NUM_VALIDATORS + i))'" >> $PROMETHEUS_CONFIG
done

# Reset and start monitoring
(cd monitoring && docker compose down)
if [ "$REMOVE_VOLUMES" = 1 ]; then
    docker volume rm monitoring_grafana_data monitoring_prometheus_data 2>/dev/null || true
fi
(cd monitoring && docker compose up -d)

# Start initial validators
export RUST_BACKTRACE=1 RUST_LOG=warn,mysticeti_core=trace
for ((i=0; i<NUM_VALIDATORS - BOOT_VALIDATORS; i++)); do
  SESSION_NAME="validator_$i"
  LOG_FILE="validator_${i}.log.ansi"
  echo -e "${GREEN}Starting validator ${YELLOW}$i${RESET} with load $TPS_PER_VALIDATOR..."
  tmux new -d -s "$SESSION_NAME" "cargo run --release --bin starfish -- \
    dry-run \
    --committee-size $NUM_VALIDATORS \
    --load $TPS_PER_VALIDATOR \
    --mimic-extra-latency \
    --authority $i \
    --consensus $CONSENSUS \
    2>&1 | tee $LOG_FILE"
done


#------------------------------------------------------------------------------
# Monitoring Dashboard
#------------------------------------------------------------------------------
DASHBOARD_URL="http://localhost:3000/d/bdd54ee7-84de-4018-8bb7-92af2defc041/mysticeti?from=now-5m&to=now&refresh=5s"
echo -e "${CYAN}Grafana dashboard: ${GREEN}$DASHBOARD_URL${RESET}"
echo -e "${CYAN}Credentials: admin/supers3cret${RESET}"

# Kill and boot sequence
sleep "$CRASH_TIME"
for ((i=0; i<KILL_VALIDATORS; i++)); do
  echo -e "${RED}Crashing validator ${YELLOW}$i${RESET}..."
   tmux kill-session -t "validator_$i"
done

for ((i=NUM_VALIDATORS - BOOT_VALIDATORS; i<NUM_VALIDATORS; i++)); do
   SESSION_NAME="validator_$i"
   LOG_FILE="validator_${i}.log.ansi"
   echo -e "${GREEN}Starting validator ${YELLOW}$i${RESET} with load $TPS_PER_VALIDATOR..."
   tmux new -d -s "$SESSION_NAME" "cargo run --release --bin starfish -- \
    dry-run \
    --committee-size $NUM_VALIDATORS \
    --load $TPS_PER_VALIDATOR \
    --mimic-extra-latency \
    --authority $i \
    --consensus $CONSENSUS \
    2>&1 | tee $LOG_FILE"
done

sleep "$TEST_TIME"
tmux kill-server