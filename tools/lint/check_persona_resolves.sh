#!/usr/bin/env bash
# Gate: every authored persona still points at things that exist (HARD).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-persona-resolves "$@"
