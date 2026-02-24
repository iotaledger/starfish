#!/bin/bash

#------------------------------------------------------------------------------
# Configuration Parameters
#------------------------------------------------------------------------------
NUM_VALIDATORS=${NUM_VALIDATORS:-10}     # Recommend < number of physical cores. The hard limit is 128
DESIRED_TPS=${DESIRED_TPS:-10000}       # Target transactions per second
CONSENSUS=${CONSENSUS:-starfish-s}       # Options: starfish, starfish-s, starfish-pull, cordial-miners, mysticeti
NUM_BYZANTINE_NODES=${NUM_BYZANTINE_NODES:-0}  # Must be < NUM_VALIDATORS / 3
BYZANTINE_STRATEGY=${BYZANTINE_STRATEGY:-equivocating-chains-bomb}
TEST_TIME=${TEST_TIME:-300}               # Total test duration in seconds
# UNIFORM_LATENCY_MS=100              # Optional: set to use uniform latency (ms) instead of AWS RTT table
DATA_DIR="scripts/data"
COMPOSE_FILE="$DATA_DIR/docker-compose.yml"
REMOVE_VOLUMES=${REMOVE_VOLUMES:-1}

# Docker network
BASE_IP="172.28.0.10"
SUBNET="172.28.0.0/24"

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
# Signal Handling
#------------------------------------------------------------------------------
cleanup() {
    echo -e "\n${RED}Terminating experiment...${RESET}"
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
}

cleanup_interrupt() {
    cleanup
    rm -f "$DATA_DIR"/*.log
    exit 1
}

trap cleanup_interrupt INT

#------------------------------------------------------------------------------
# Cleanup Previous Run
#------------------------------------------------------------------------------
if [ -f "$COMPOSE_FILE" ]; then
    if [ "$REMOVE_VOLUMES" = 1 ]; then
        docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    else
        docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    fi
fi
echo -e "${CYAN}Cleaning up previous run data...${RESET}"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

#------------------------------------------------------------------------------
# Build Docker Image
#------------------------------------------------------------------------------
echo -e "${CYAN}Building starfish Docker image...${RESET}"
docker build -t starfish . || {
    echo -e "${RED}Docker build failed${RESET}"
    exit 1
}

#------------------------------------------------------------------------------
# Generate Prometheus Configuration
#------------------------------------------------------------------------------
PROMETHEUS_CONFIG="$DATA_DIR/prometheus.yaml"
{
  cat <<'EOH'
global:
  scrape_interval: 1s
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['prometheus:9090']
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
  - job_name: 'starfish-metrics'
    static_configs:
      - targets:
EOH
  for ((i=0; i<NUM_VALIDATORS; i++)); do
    LAST_OCTET=$((${BASE_IP##*.} + i))
    METRICS_PORT=$((1500 + NUM_VALIDATORS + i))
    echo "          - '172.28.0.$LAST_OCTET:$METRICS_PORT'"
  done
} > "$PROMETHEUS_CONFIG"

#------------------------------------------------------------------------------
# Generate Docker Compose File
#------------------------------------------------------------------------------
echo -e "${CYAN}Generating docker-compose.yml for $NUM_VALIDATORS validators...${RESET}"

RUST_LOG="warn,starfish_core::block_manager=trace,starfish_core::block_handler=trace,\
starfish_core::consensus=trace,starfish_core::net_sync=DEBUG,starfish_core::core=DEBUG,\
starfish_core::synchronizer=DEBUG,starfish_core::transactions_generator=DEBUG,\
starfish_core::validator=trace,starfish_core::network=trace,starfish_core::block_store=trace,\
starfish_core::threshold_core=trace,starfish_core::syncer=trace"

{
  # Header: networks and volumes
  cat <<EOH
networks:
  starfish-net:
    driver: bridge
    ipam:
      config:
        - subnet: $SUBNET

volumes:
  prometheus_data:
  grafana_data:
EOH

  # Infrastructure services
  cat <<'EOH'

services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yaml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    networks:
      starfish-net:
        ipv4_address: 172.28.0.2
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
    user: "472"
    volumes:
      - grafana_data:/var/lib/grafana
      - ../../monitoring/grafana/datasource.yaml:/etc/grafana/provisioning/datasources/main.yaml:ro
      - ../../monitoring/grafana/dashboard.yaml:/etc/grafana/provisioning/dashboards/main.yaml:ro
      - ../../monitoring/grafana/grafana-dashboard.json:/var/lib/grafana/dashboards/grafana-dashboard.json:ro
    networks:
      starfish-net:
        ipv4_address: 172.28.0.3
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    pid: "host"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--collector.filesystem.ignored-mount-points=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      starfish-net:
        ipv4_address: 172.28.0.4
    restart: unless-stopped
EOH

  # Validator services
  BYZANTINE_COUNT=0
  for ((i=0; i<NUM_VALIDATORS; i++)); do
    LAST_OCTET=$((${BASE_IP##*.} + i))
    VALIDATOR_IP="172.28.0.$LAST_OCTET"

    if (( i % 3 == 0 && BYZANTINE_COUNT < NUM_BYZANTINE_NODES )); then
        LOAD=0
        ((BYZANTINE_COUNT++))
        EXTRA_FLAGS="--byzantine-strategy $BYZANTINE_STRATEGY"
    else
        LOAD=$TPS_PER_VALIDATOR
        EXTRA_FLAGS=""
    fi

    LATENCY_FLAGS="--mimic-extra-latency"
    if [ -n "${UNIFORM_LATENCY_MS:-}" ]; then
        LATENCY_FLAGS="$LATENCY_FLAGS --uniform-latency-ms $UNIFORM_LATENCY_MS"
    fi

    cat <<EOV

  validator-$i:
    image: starfish
    command: >
      dry-run
      --authority $i
      --committee-size $NUM_VALIDATORS
      --load $LOAD
      --base-ip $BASE_IP
      --consensus $CONSENSUS
      --data-dir /data
      $LATENCY_FLAGS
      $EXTRA_FLAGS
    environment:
      - RUST_BACKTRACE=1
      - RUST_LOG=$RUST_LOG
    networks:
      starfish-net:
        ipv4_address: $VALIDATOR_IP
    restart: unless-stopped
EOV
  done
} > "$COMPOSE_FILE"

#------------------------------------------------------------------------------
# Launch
#------------------------------------------------------------------------------
echo -e "${GREEN}Run dryrun for: ${YELLOW}$TEST_TIME${RESET} seconds"
echo -e "${GREEN}Number of validators: ${YELLOW}$NUM_VALIDATORS${RESET}"
echo -e "${CYAN}Deploying consensus protocol: ${YELLOW}$CONSENSUS${RESET}"

docker compose -f "$COMPOSE_FILE" up -d || {
    echo -e "${RED}Failed to start services${RESET}"
    exit 1
}

#------------------------------------------------------------------------------
# Monitoring Dashboard
#------------------------------------------------------------------------------
DASHBOARD_URL="http://localhost:3000/d/bdd54ee7-84de-4018-8bb7-92af2defc041/mysticeti?from=now-5m&to=now&refresh=5s"
echo -e "${CYAN}Grafana dashboard: ${GREEN}$DASHBOARD_URL${RESET}"
echo -e "${CYAN}Credentials: admin/admin${RESET}"

sleep "$TEST_TIME"

# Save logs before cleanup
echo -e "${CYAN}Saving validator logs...${RESET}"
for ((i=0; i<NUM_VALIDATORS; i++)); do
  docker compose -f "$COMPOSE_FILE" logs "validator-$i" > "$DATA_DIR/validator_${i}.log" 2>&1
done

cleanup
