#!/usr/bin/env bash
# Structural boot-order gate: outbound onion work must pre-warm while the
exec "$(dirname "$0")/../../build/bin/z23-lint" check-tor-dial-prewarm "$@"
