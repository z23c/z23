#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Compatibility entry: the native pool runs both probes on every invocation.
# The legacy cache directory now holds diagnostics, never a reusable PASS.
set -eu
ROOT="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
ZCL_LINT_TIMING_DIR="${ZCL_BUILD_EPOCH_CACHE_DIR:-$ROOT/.cache/build-epoch-integrity}/probes"
export ZCL_LINT_TIMING_DIR
exec "$ROOT/build/bin/z23-lint" epoch-probes
