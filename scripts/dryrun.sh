# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# bash run.sh

export RUST_LOG=warn,mysticeti_core::consensus=trace,mysticeti_core::net_sync=DEBUG,mysticeti_core::core=DEBUG

tmux kill-server || true

tmux new -d -s "v0" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 0 > v0.log.ansi"
tmux new -d -s "v1" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 1 > v1.log.ansi"
tmux new -d -s "v2" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 2 > v2.log.ansi"
tmux new -d -s "v3" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 3 > v3.log.ansi"
tmux new -d -s "v4" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 4 > v4.log.ansi"
tmux new -d -s "v5" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 5 > v5.log.ansi"
tmux new -d -s "v6" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 6 > v6.log.ansi"
tmux new -d -s "v7" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 7 > v7.log.ansi"
tmux new -d -s "v8" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 8 > v8.log.ansi"
tmux new -d -s "v9" "cargo run --bin mysticeti -- dry-run --committee-size 10 --authority 9 > v9.log.ansi"

sleep 1000
tmux kill-server
