#!/bin/bash
# Parameters
NUM_VALIDATORS=${NUM_VALIDATORS:-4}
SEED_FOR_EXTRA_LATENCY=${SEED_FOR_EXTRA_LATENCY:-2}
BYZANTINE_STRATEGY=${BYZANTINE_STRATEGY:-honest} #possible "honest" | "delayed" | "equivocate" | "timeout"



# Colors using tput
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)


# Output Validators
echo -e "${GREEN}Number of validators: ${YELLOW}$NUM_VALIDATORS${RESET}"
# Output Seed for latency
echo -e "${GREEN}Seed for extra latency: ${YELLOW}$SEED_FOR_EXTRA_LATENCY${RESET}"
# Output Byzantine strategy
echo -e "${GREEN}Byzantine strategy: ${YELLOW}$BYZANTINE_STRATEGY${RESET}"

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


# Docker Compose Down
(cd monitoring && docker compose down)


# Remove the Grafana and Prometheus data volumes
docker volume rm monitoring_grafana_data || echo "Grafana data volume not found or could not be removed."
docker volume rm monitoring_prometheus_data || echo "Prometheus data volume not found or could not be removed."


# Docker Compose Up
(cd monitoring && docker compose up -d)


# Start Validators
tmux kill-server || true
for ((i=0; i<NUM_VALIDATORS; i++)); do
  SESSION_NAME="validator_$i"
  LOG_FILE="validator_${i}.log.ansi"
  if [[ $i -eq 0 ]]; then
    echo -e "${GREEN}Starting ${YELLOW}$BYZANTINE_STRATEGY ${GREEN}validator ${YELLOW}$i${RESET}..."
    tmux new -d -s "$SESSION_NAME" "cargo run --bin mysticeti -- dry-run --committee-size $NUM_VALIDATORS --mimic-extra-latency $SEED_FOR_EXTRA_LATENCY --byzantine-strategy $BYZANTINE_STRATEGY --authority $i > $LOG_FILE"
  else
    echo -e "${GREEN}Starting honest validator ${YELLOW}$i${RESET}..."
    tmux new -d -s "$SESSION_NAME" "cargo run --bin mysticeti -- dry-run --committee-size $NUM_VALIDATORS --mimic-extra-latency $SEED_FOR_EXTRA_LATENCY --authority $i > $LOG_FILE"
  fi
done

SHORT_URL=$(curl -s "http://tinyurl.com/api-create.php?url=http://localhost:3000/d/bdd54ee7-84de-4018-8bb7-92af2defc041/mysticeti?from=now-30m&to=now&refresh=5s")
echo -e "${CYAN}Grafana monitoring is available at: ${GREEN}$SHORT_URL${RESET}"

# Wait for the validators to run (e.g., 600 seconds)
sleep 600

# Kill all tmux sessions
echo -e "${RED}Killing all tmux sessions...${RESET}"
tmux kill-server