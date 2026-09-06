#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Lint gate — OFFLINE-ONLY FENCE for the FAST-MINT crypto pass-through.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-mint-skip-crypto-offline-only "$@"
