#!/bin/bash
COMMITTEE_SIZE=22
LOAD=2000
DURATION_SECS=120

# Strategy-specific byzantine nodes configuration
declare -A BYZANTINE_NODES
BYZANTINE_NODES["random-drop"]=7
BYZANTINE_NODES["timeout-leader"]=7
BYZANTINE_NODES["leader-withholding"]=7
BYZANTINE_NODES["chain-bomb"]=7
BYZANTINE_NODES["equivocating-two-chains"]=7
BYZANTINE_NODES["equivocating-chains"]=7
BYZANTINE_NODES["equivocating-chains-bomb"]=1

STRATEGIES=(
    "random-drop"
    "timeout-leader"
    "leader-withholding"
    "chain-bomb"
    "equivocating-two-chains"
    "equivocating-chains"
    "equivocating-chains-bomb"
)

CONSENSUS_PROTOCOLS=(
    "mysticeti"
    "starfish-push"
)

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="benchmark_results_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"
LOG_FILE="${RESULTS_DIR}/benchmark_log.txt"

run_benchmark() {
    local strategy=$1
    local consensus=$2
    local byzantine_nodes=${BYZANTINE_NODES[$strategy]}
    local output_file="${RESULTS_DIR}/benchmark_c${COMMITTEE_SIZE}_l${LOAD}_${strategy}_${consensus}_b${byzantine_nodes}.txt"

    cargo run --release --bin starfish -- local-benchmark \
        --committee-size "$COMMITTEE_SIZE" \
        --load "$LOAD" \
        --consensus "$consensus" \
        --num-byzantine-nodes "$byzantine_nodes" \
        --byzantine-strategy "$strategy" \
        --mimic-extra-latency \
        --duration-secs "$DURATION_SECS" \
        2>&1 | tee -a "$output_file"

    echo "----------------------------------------" >> "$LOG_FILE"
    echo "Completed run: Strategy=$strategy Consensus=$consensus Byzantine=$byzantine_nodes" >> "$LOG_FILE"
    echo "Output file: $output_file" >> "$LOG_FILE"
    echo "----------------------------------------" >> "$LOG_FILE"

    sleep 10
}

echo "Starting benchmark suite at $(date)" >> "$LOG_FILE"
for consensus in "${CONSENSUS_PROTOCOLS[@]}"; do
    for strategy in "${STRATEGIES[@]}"; do
        run_benchmark "$strategy" "$consensus"
    done
done

echo "Benchmark suite completed at $(date)" >> "$LOG_FILE"
echo "Results are in directory: $RESULTS_DIR"