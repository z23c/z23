#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Compose the established seven-daemon DHT/Noise acceptance with the
# attestation-flight hook. The hook assigns two of those independent daemons
# the verifier-publisher and fresh-receiver roles and flies one REALLY SIGNED
# ZCLATT attestation between them over the frozen package swarm codec; the
# remaining five keep the sparse Kademlia topology nontrivial.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export DHT_PACKAGEHOST=1
export DHT_AFTER_SPARSE_HOOK="$SCRIPT_DIR/attestation_flight_hook.sh"

exec bash "$SCRIPT_DIR/zcode_dht_acceptance.sh"
