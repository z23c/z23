#!/usr/bin/env bash
# Lint gate — blocker remedy totality (docs/work/tenacity-roadmap.md "Hold-class doctrine").
exec "$(dirname "$0")/../../build/bin/z23-lint" check-blocker-remedy "$@"
