#!/usr/bin/env bash
# Lint gate E6 — one-write-path (RATCHET).
#
# There is one consensus writer: the reducer advances durable cursors and
# authors UTXO deltas. The legacy chain-state write surfaces this gate used
# to ratchet down have already been deleted (the baseline is intentionally
# empty — see tools/scripts/one_write_path_baseline.txt), so this gate now
# guards against regression: any NEW production file/line that writes chain
# state outside the recorded baseline fails the build.
#
# Baseline format:
#   <file>:<line>: <matched source>
#
# Do not add lines to the baseline without an ADR; growing it means a new
# chain writer appeared outside the reducer's single write path.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-one-write-path "$@"
