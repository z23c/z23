#!/usr/bin/env bash
# Ported to z23-lint check-lag-slo-observable; see gate_call_presence_fences.c.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-lag-slo-observable "$@"
