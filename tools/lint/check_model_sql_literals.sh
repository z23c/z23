#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_model_sql_literals.sh — literal SQL in the models layer, a
# shrink-only ratchet against tools/lint/model_sql_literal_baseline.txt. A
# model file must not carry a hand-written SQL statement: reads and writes
# go through the typed query builder,
# engine/models/include/models/query_builder.h. See
# tools/lint/lintc/gate_model_sql_literals.c for the check itself.
#
# Usage:
#   tools/lint/check_model_sql_literals.sh
#   tools/lint/check_model_sql_literals.sh --selftest
#
# Env: ZCL_LINT_MODE (FAIL default | WARN | UPDATE), ZCL_MODEL_SQL_BASELINE,
#      ZCL_MODEL_SQL_FILE_FLOOR, ZCL_MODEL_SQL_SCAN_ROOT.
# Exit: 0 clean, 1 on an unbaselined/stale row (FAIL mode), 2 on a hollow scan.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-model-sql-literals "$@"
