#!/usr/bin/env bash
# Gate: every prompt template names a real section, and every kind can be
# selected (HARD).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-prompt-templates "$@"
