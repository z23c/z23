#!/usr/bin/env bash
# check_wallet_raw_prepare_log — RATCHET gate (shrink-only).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-wallet-raw-prepare-log "$@"
