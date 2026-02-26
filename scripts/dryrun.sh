#!/bin/bash

#----------------------------------------------------------------------
# Configuration Parameters
#----------------------------------------------------------------------
# Recommend < physical cores. Hard limit is 128
NUM_VALIDATORS=${NUM_VALIDATORS:-10}
DESIRED_TPS=${DESIRED_TPS:-100}
# Options: starfish, starfish-s, starfish-pull,
#          cordial-miners, mysticeti
CONSENSUS=${CONSENSUS:-starfish}
NUM_BYZANTINE_NODES=${NUM_BYZANTINE_NODES:-2}
# Options: timeout-leader, leader-withholding,
#   equivocating-chains, equivocating-two-chains,
#   chain-bomb, equivocating-chains-bomb, random-drop
BYZANTINE_STRATEGY=${BYZANTINE_STRATEGY:-random-drop}
TEST_TIME=${TEST_TIME:-300}
# Optional: set to use uniform latency (ms)
# instead of AWS RTT table
# UNIFORM_LATENCY_MS=100
DATA_DIR="scripts/data"
COMPOSE_FILE="$DATA_DIR/docker-compose.yml"
REMOVE_VOLUMES=${REMOVE_VOLUMES:-1}
# Set to 1 to wipe Prometheus/Grafana data
CLEAN_MONITORING=${CLEAN_MONITORING:-1}
# Host ports for monitoring (offset from orchestrator's 9090/3000)
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9091}
GRAFANA_PORT=${GRAFANA_PORT:-3001}

# Docker network
BASE_IP="172.28.0.10"
SUBNET="172.28.0.0/24"

TPS_PER_VALIDATOR=$(echo "$DESIRED_TPS / $NUM_VALIDATORS" | bc)

#----------------------------------------------------------------------
# Terminal Colors
#----------------------------------------------------------------------
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
RESET=$(tput sgr0)

if (( NUM_BYZANTINE_NODES > 0 )); then
    case "$BYZANTINE_STRATEGY" in
        timeout-leader \
        |leader-withholding \
        |equivocating-chains \
        |equivocating-two-chains \
        |chain-bomb \
        |equivocating-chains-bomb \
        |random-drop) ;;
        *)
            echo -e \
                "${RED}Invalid BYZANTINE_STRATEGY:" \
                "${BYZANTINE_STRATEGY}${RESET}"
            echo -e \
                "${YELLOW}Supported:" \
                "timeout-leader," \
                "leader-withholding," \
                "equivocating-chains," \
                "equivocating-two-chains," \
                "chain-bomb," \
                "equivocating-chains-bomb," \
                "random-drop${RESET}"
            exit 1
            ;;
    esac
fi

#----------------------------------------------------------------------
# Signal Handling
#----------------------------------------------------------------------
cleanup() {
    echo -e "\n${RED}Terminating validators...${RESET}"
    # Build validator service names list
    local validators=""
    for ((i=0; i<NUM_VALIDATORS; i++)); do
        validators="$validators validator-$i"
    done
    # Stop all validators at once with short timeout
    docker compose -f "$COMPOSE_FILE" \
        stop -t 1 $validators 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" \
        rm -f $validators 2>/dev/null || true
    echo -e \
        "${GREEN}Monitoring still running at:" \
        "${CYAN}http://localhost:${GRAFANA_PORT}${RESET}"
    echo -e \
        "${YELLOW}To stop everything:" \
        "docker compose -f $COMPOSE_FILE down${RESET}"
}

cleanup_interrupt() {
    cleanup
    rm -f "$DATA_DIR"/*.log
    exit 1
}

trap cleanup_interrupt INT

#----------------------------------------------------------------------
# Cleanup Previous Run
#----------------------------------------------------------------------
if [ -f "$COMPOSE_FILE" ]; then
    if [ "$REMOVE_VOLUMES" = 1 ]; then
        docker compose -f "$COMPOSE_FILE" down -v \
            2>/dev/null || true
    else
        docker compose -f "$COMPOSE_FILE" down \
            2>/dev/null || true
    fi
fi

#----------------------------------------------------------------------
# Persistent Monitoring Volumes
#----------------------------------------------------------------------
if [ "$CLEAN_MONITORING" = 1 ]; then
    echo -e "${YELLOW}Wiping monitoring data...${RESET}"
    docker volume rm prometheus_data grafana_data \
        2>/dev/null || true
fi
docker volume create prometheus_data 2>/dev/null || true
docker volume create grafana_data 2>/dev/null || true
echo -e "${CYAN}Cleaning up previous run data...${RESET}"
rm -f "$DATA_DIR"/*.log \
    "$DATA_DIR"/docker-compose.yml \
    "$DATA_DIR"/prometheus.yaml
mkdir -p "$DATA_DIR"

#----------------------------------------------------------------------
# Build Docker Image
#----------------------------------------------------------------------
echo -e "${CYAN}Building starfish Docker image...${RESET}"
docker build -t starfish . || {
    echo -e "${RED}Docker build failed${RESET}"
    exit 1
}

#----------------------------------------------------------------------
# Generate Prometheus Configuration
#----------------------------------------------------------------------
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
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
  - job_name: 'starfish-metrics'
    static_configs:
EOH
    for ((i=0; i<NUM_VALIDATORS; i++)); do
        LAST_OCTET=$((${BASE_IP##*.} + i))
        METRICS_PORT=$((1500 + NUM_VALIDATORS + i))
        VALIDATOR_NAME="validator-$i"
        cat <<EOT
      - targets: ['172.28.0.$LAST_OCTET:$METRICS_PORT']
        labels:
          validator: '$VALIDATOR_NAME'
EOT
    done
} > "$PROMETHEUS_CONFIG"

#----------------------------------------------------------------------
# Generate Docker Compose File
#----------------------------------------------------------------------
echo -e \
    "${CYAN}Generating docker-compose.yml for" \
    "$NUM_VALIDATORS validators...${RESET}"

RUST_LOG="warn"
RUST_LOG+=",starfish_core::block_manager=trace"
RUST_LOG+=",starfish_core::block_handler=trace"
RUST_LOG+=",starfish_core::consensus=trace"
RUST_LOG+=",starfish_core::net_sync=DEBUG"
RUST_LOG+=",starfish_core::core=DEBUG"
RUST_LOG+=",starfish_core::synchronizer=DEBUG"
RUST_LOG+=",starfish_core::transactions_generator=DEBUG"
RUST_LOG+=",starfish_core::validator=trace"
RUST_LOG+=",starfish_core::network=trace"
RUST_LOG+=",starfish_core::block_store=trace"
RUST_LOG+=",starfish_core::threshold_core=trace"
RUST_LOG+=",starfish_core::syncer=trace"

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
    external: true
  grafana_data:
    external: true
EOH

    # Infrastructure services
    GD="../../monitoring/grafana"
    cat <<EOH

services:
  prometheus:
    image: prom/prometheus
    ports:
      - "$PROMETHEUS_PORT:9090"
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
      - "$GRAFANA_PORT:3000"
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
      - ${GD}/datasource.yaml:/etc/grafana/provisioning/datasources/main.yaml:ro
      - ${GD}/dashboard.yaml:/etc/grafana/provisioning/dashboards/main.yaml:ro
      - ${GD}/grafana-dashboard.json:/var/lib/grafana/dashboards/grafana-dashboard.json:ro
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

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    networks:
      starfish-net:
        ipv4_address: 172.28.0.5
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
            LATENCY_FLAGS+=" --uniform-latency-ms"
            LATENCY_FLAGS+=" $UNIFORM_LATENCY_MS"
        fi

        cat <<EOV

  validator-$i:
    container_name: validator-$i
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

#----------------------------------------------------------------------
# Launch
#----------------------------------------------------------------------
echo -e \
    "${GREEN}Run dryrun for:" \
    "${YELLOW}$TEST_TIME${RESET} seconds"
echo -e \
    "${GREEN}Number of validators:" \
    "${YELLOW}$NUM_VALIDATORS${RESET}"
echo -e \
    "${CYAN}Deploying consensus protocol:" \
    "${YELLOW}$CONSENSUS${RESET}"

docker compose -f "$COMPOSE_FILE" up -d || {
    echo -e "${RED}Failed to start services${RESET}"
    exit 1
}

#----------------------------------------------------------------------
# Monitoring Dashboard
#----------------------------------------------------------------------
DASH_ID="bdd54ee7-84de-4018-8bb7-92af2defc041"
DASH_PATH="d/$DASH_ID/consensus"
DASH_QUERY="from=now-5m&to=now&refresh=5s"
DASHBOARD_URL="http://localhost:${GRAFANA_PORT}/${DASH_PATH}?${DASH_QUERY}"
echo -e \
    "${CYAN}Grafana dashboard:" \
    "${GREEN}$DASHBOARD_URL${RESET}"
echo -e "${CYAN}Credentials: admin/admin${RESET}"

sleep "$TEST_TIME"

# Save logs before cleanup
echo -e "${CYAN}Saving validator logs...${RESET}"
for ((i=0; i<NUM_VALIDATORS; i++)); do
    docker compose -f "$COMPOSE_FILE" \
        logs "validator-$i" \
        > "$DATA_DIR/validator_${i}.log" 2>&1
done

cleanup
