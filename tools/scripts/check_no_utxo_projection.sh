#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-utxo-projection "$@"
