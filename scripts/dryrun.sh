#!/bin/bash

#----------------------------------------------------------------------
# Configuration Parameters
#----------------------------------------------------------------------
# Recommend < physical cores. Hard limit is 128
NUM_NODES=${NUM_NODES:-10}
DESIRED_TPS=${DESIRED_TPS:-1000}
# Options: starfish, starfish-speed, starfish-bls,
#          sailfish-pp, cordial-miners, mysticeti
CONSENSUS=${CONSENSUS:-sailfish-pp}
NUM_BYZANTINE_NODES=${NUM_BYZANTINE_NODES:-0}
# Options: timeout-leader, leader-withholding,
#   equivocating-chains, equivocating-two-chains,
#   chain-bomb, equivocating-chains-bomb, random-drop
BYZANTINE_STRATEGY=${BYZANTINE_STRATEGY:-random-drop}
TEST_TIME=${TEST_TIME:-3000}
# Optional: set to use uniform latency (ms)
# instead of AWS RTT table
# UNIFORM_LATENCY_MS=100
# Storage backend: rocksdb (default) | tidehunter
STORAGE_BACKEND=${STORAGE_BACKEND:-rocksdb}
# Transaction payload mode: all_zero | random (default)
TRANSACTION_MODE=${TRANSACTION_MODE:-random}
# Dissemination mode: protocol-default (default) | pull |
#   push-causal | push-useful
#DISSEMINATION_MODE=${DISSEMINATION_MODE:-}
# Enable lz4 network compression.
# Auto-enabled for random transaction mode.
# Set COMPRESS_NETWORK=1 or =0 to override.
if [ -z "${COMPRESS_NETWORK+x}" ]; then
    if [ "$TRANSACTION_MODE" = "random" ]; then
        COMPRESS_NETWORK=1
    else
        COMPRESS_NETWORK=0
    fi
fi
# Set to 1 to overlay 10s latency on the f farthest peers
#ADVERSARIAL_LATENCY=1
DATA_DIR="scripts/data"
COMPOSE_FILE="$DATA_DIR/docker-compose.yml"
REMOVE_VOLUMES=${REMOVE_VOLUMES:-1}
# Set to 1 to wipe Prometheus/Grafana data
CLEAN_MONITORING=${CLEAN_MONITORING:-0}
# Host ports for monitoring (offset from orchestrator's 9090/3000)
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9091}
GRAFANA_PORT=${GRAFANA_PORT:-3001}

# Docker network
BASE_IP="172.28.0.10"
SUBNET="172.28.0.0/24"

TPS_PER_NODE=$(echo "$DESIRED_TPS / $NUM_NODES" | bc)

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
    echo -e "\n${RED}Terminating nodes...${RESET}"
    # Build node service names list
    local nodes=""
    for ((i=0; i<NUM_NODES; i++)); do
        nodes="$nodes node-$i"
    done
    # Stop all nodes at once with short timeout
    docker compose -f "$COMPOSE_FILE" \
        stop -t 1 $nodes 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" \
        rm -f $nodes 2>/dev/null || true
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
            --remove-orphans 2>/dev/null || true
    else
        docker compose -f "$COMPOSE_FILE" down \
            --remove-orphans 2>/dev/null || true
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
docker volume create prometheus_data >/dev/null 2>&1 || true
docker volume create grafana_data >/dev/null 2>&1 || true
rm -f "$DATA_DIR"/*.log \
    "$DATA_DIR"/docker-compose.yml
rm -rf "$DATA_DIR"/prometheus.yaml
mkdir -p "$DATA_DIR"

#----------------------------------------------------------------------
# Build Docker Image
#----------------------------------------------------------------------
echo -ne "${CYAN}Building starfish Docker image... ${RESET}"
BUILD_LOG=$(mktemp)
BUILD_START=$SECONDS
docker build -t starfish . > "$BUILD_LOG" 2>&1 &
BUILD_PID=$!
while kill -0 "$BUILD_PID" 2>/dev/null; do
    ELAPSED=$(( SECONDS - BUILD_START ))
    printf "\r${CYAN}Building starfish Docker image... ${YELLOW}%dm%02ds${RESET}" \
        $(( ELAPSED / 60 )) $(( ELAPSED % 60 ))
    sleep 1
done
wait "$BUILD_PID"
BUILD_RC=$?
ELAPSED=$(( SECONDS - BUILD_START ))
if [ $BUILD_RC -eq 0 ]; then
    printf "\r${GREEN}Build OK in %dm%02ds${RESET}%20s\n" \
        $(( ELAPSED / 60 )) $(( ELAPSED % 60 )) ""
else
    printf "\r${RED}Docker build failed after %dm%02ds. Last 30 lines:${RESET}\n" \
        $(( ELAPSED / 60 )) $(( ELAPSED % 60 ))
    tail -30 "$BUILD_LOG"
    rm -f "$BUILD_LOG"
    exit 1
fi
rm -f "$BUILD_LOG"

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
    for ((i=0; i<NUM_NODES; i++)); do
        LAST_OCTET=$((${BASE_IP##*.} + i))
        METRICS_PORT=$((1500 + NUM_NODES + i))
        NODE_NAME="node-$i"
        cat <<EOT
      - targets: ['172.28.0.$LAST_OCTET:$METRICS_PORT']
        labels:
          node: '$NODE_NAME'
EOT
    done
} > "$PROMETHEUS_CONFIG"

#----------------------------------------------------------------------
# Generate Docker Compose File
#----------------------------------------------------------------------
RUST_LOG="debug"

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

    # Node services
    BYZANTINE_COUNT=0
    for ((i=0; i<NUM_NODES; i++)); do
        LAST_OCTET=$((${BASE_IP##*.} + i))
        NODE_IP="172.28.0.$LAST_OCTET"

        if (( i % 3 == 0 && BYZANTINE_COUNT < NUM_BYZANTINE_NODES )); then
            ((BYZANTINE_COUNT++))
            EXTRA_FLAGS="--byzantine-strategy $BYZANTINE_STRATEGY"
            # Equivocating strategies create multiple blocks per round;
            # encoding transactions for each is too expensive.
            case "$BYZANTINE_STRATEGY" in
                equivocating-chains|equivocating-two-chains|equivocating-chains-bomb)
                    LOAD=0 ;;
                *)
                    LOAD=$TPS_PER_NODE ;;
            esac
        else
            LOAD=$TPS_PER_NODE
            EXTRA_FLAGS=""
        fi

        LATENCY_FLAGS="--mimic-extra-latency"
        if [ -n "${UNIFORM_LATENCY_MS:-}" ]; then
            LATENCY_FLAGS+=" --uniform-latency-ms"
            LATENCY_FLAGS+=" $UNIFORM_LATENCY_MS"
        fi
        if [ "${ADVERSARIAL_LATENCY:-0}" = 1 ]; then
            LATENCY_FLAGS+=" --adversarial-latency"
        fi

        PARAM_FLAGS=""
        if [ -n "${STORAGE_BACKEND:-}" ]; then
            PARAM_FLAGS+=" --storage-backend $STORAGE_BACKEND"
        fi
        if [ -n "${TRANSACTION_MODE:-}" ]; then
            PARAM_FLAGS+=" --transaction-mode $TRANSACTION_MODE"
        fi
        if [ -n "${DISSEMINATION_MODE:-}" ]; then
            PARAM_FLAGS+=" --dissemination-mode"
            PARAM_FLAGS+=" $DISSEMINATION_MODE"
        fi
        if [ "${COMPRESS_NETWORK:-0}" = 1 ]; then
            PARAM_FLAGS+=" --compress-network"
        fi

        cat <<EOV

  node-$i:
    container_name: node-$i
    image: starfish
    command: >
      dry-run
      --authority $i
      --committee-size $NUM_NODES
      --load $LOAD
      --base-ip $BASE_IP
      --consensus $CONSENSUS
      --data-dir /data
      $LATENCY_FLAGS
      $EXTRA_FLAGS
      $PARAM_FLAGS
    environment:
      - RUST_BACKTRACE=1
      - RUST_LOG=$RUST_LOG
    networks:
      starfish-net:
        ipv4_address: $NODE_IP
    restart: unless-stopped
EOV
    done
} > "$COMPOSE_FILE"

#----------------------------------------------------------------------
# Launch
#----------------------------------------------------------------------
echo -e "${CYAN}Started at: $(date)${RESET}"
echo -e "${GREEN}─── Configuration ───────────────────${RESET}"
printf "  %-18s ${YELLOW}%s${RESET}\n" \
    "Nodes:" "$NUM_NODES" \
    "Consensus:" "$CONSENSUS" \
    "Dissemination:" "$DISSEMINATION_MODE" \
    "Target TPS:" "$DESIRED_TPS ($TPS_PER_NODE/node)" \
    "Storage:" "$STORAGE_BACKEND" \
    "Tx mode:" "$TRANSACTION_MODE" \
    "Compression:" "$([ "$COMPRESS_NETWORK" = 1 ] && echo enabled || echo disabled)" \
    "Byzantine:" "$NUM_BYZANTINE_NODES" \
    "Test duration:" "${TEST_TIME}s"
if [ -n "${UNIFORM_LATENCY_MS:-}" ]; then
    printf "  %-18s ${YELLOW}%s${RESET}\n" \
        "Uniform latency:" "${UNIFORM_LATENCY_MS}ms"
fi
if [ "${ADVERSARIAL_LATENCY:-0}" = 1 ]; then
    printf "  %-18s ${YELLOW}%s${RESET}\n" \
        "Adversarial lat.:" "enabled"
fi
if (( NUM_BYZANTINE_NODES > 0 )); then
    printf "  %-18s ${YELLOW}%s${RESET}\n" \
        "Byzantine strat.:" "$BYZANTINE_STRATEGY"
fi
echo -e "${GREEN}─────────────────────────────────────${RESET}"

docker compose -f "$COMPOSE_FILE" up -d || {
    echo -e "${RED}Failed to start services${RESET}"
    exit 1
}

#----------------------------------------------------------------------
# Monitoring Dashboard
#----------------------------------------------------------------------
DASH_ID="bdd54ee7-84de-4018-8bb7-92af2defc041"
DASH_PATH="d/$DASH_ID/consensus"
DASH_QUERY="from=now-5m&to=now&refresh=5s&kiosk"
DASHBOARD_URL="http://localhost:${GRAFANA_PORT}/${DASH_PATH}?${DASH_QUERY}"
echo -e \
    "${CYAN}Grafana dashboard:" \
    "${GREEN}$DASHBOARD_URL${RESET}"
echo -e "${CYAN}Credentials: admin/admin${RESET}"

sleep "$TEST_TIME"

# Save logs before cleanup
echo -e "${CYAN}Saving node logs...${RESET}"
for ((i=0; i<NUM_NODES; i++)); do
    docker compose -f "$COMPOSE_FILE" \
        logs "node-$i" \
        > "$DATA_DIR/node_${i}.log" 2>&1
done

cleanup
