#!/bin/sh
# Lint gate — blocker remedy totality (docs/TENACITY.md "Hold-class doctrine").
exec "$(dirname "$0")/../../build/bin/z23-lint" check-blocker-remedy "$@"
