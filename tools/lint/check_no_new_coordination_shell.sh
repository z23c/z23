#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — no NEW coordination shell (the project goal: no shell on the
# coordination path). Every tracked top-level tools/dev/<name>.sh and
# tools/scripts/<name>.sh, plus tools/agent_test_runner.sh,
# tools/agent_fast_ci.sh and tools/deploy_guard.sh, must be listed in
# tools/lint/coordination_shell_baseline.txt. The list is hand-edited and can
# only lose lines. A new script is written in C23 as a native command instead.
#
# This wrapper lives under tools/lint/, which is NOT on the coordination path.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-new-coordination-shell "$@"
