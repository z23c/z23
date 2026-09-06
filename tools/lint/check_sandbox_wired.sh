#!/usr/bin/env bash
# Gate: sandbox wired (HARD) — ported to the C23 lint runtime (z23-lint).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-sandbox-wired "$@"
