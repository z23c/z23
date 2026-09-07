#!/usr/bin/env bash
# Ported to z23-lint check-model-validation; see gate_call_presence_fences.c.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-model-validation "$@"
