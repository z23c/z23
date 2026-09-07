#!/usr/bin/env bash
# Lint gate — service-shape SHRINKING-FLOOR ratchet for legacy bool exports
# (Phase 3 of the framework refactor; sibling to E2 check_one_result_type.sh).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-service-result-convergence "$@"
