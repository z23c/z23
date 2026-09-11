#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
exec "${ZCL_LINT_BIN_DIR:-$(dirname "$0")/../../build/bin}/z23-lint" check-describe-budget "$@"
