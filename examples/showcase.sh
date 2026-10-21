#!/usr/bin/env bash
#
# CAGE showcase: builds the broker and runs the broker demo.
#
#   broker_demo.py   "the agent holds tokens, never the key"
#       a rogue agent in its own process signs within budget, is refused
#       every escalation, and never receives the key. A memory dump of the
#       broker finds no plaintext.
#
# Usage:  examples/showcase.sh
#
set -euo pipefail

# Run from the repo root no matter where this is invoked from.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bar() { printf '\n\033[1m========================================================================\n%s\n========================================================================\033[0m\n\n' "$1"; }

bar "BUILD: cage-broker"
cargo build -p cage-broker

bar "DEMO: the agent holds tokens, never the key"
uv run python examples/broker_demo.py target/debug/cage-broker

bar "DONE"
