#!/usr/bin/env bash
# Lint gate E3 — shape source files include their shape header (HARD).
#
# The framework places each app/.c file in a shape folder (Gate #18). That
# is a PATH-only claim: a file under engine/conditions/src/ is "a Condition"
# by virtue of where it sits, even if it never touches the Condition shape
# contract. This gate closes that mislabel hole — a shape file must include
# the header that defines its shape's contract:
#
#   engine/conditions/src/*.c   -> "framework/condition.h"  (the Condition
#                               shape contract) OR a "conditions/" header.
#   engine/models/src/*.c       -> a "models/" header (each model header pulls
#                               in models/activerecord.h, the AR lifecycle).
#   engine/supervisors/src/*.c  -> a "supervisors/" header OR "util/supervisor.h"
#                               (the supervisor liveness contract).
#
# engine/jobs/ is intentionally skipped: its job.h shape header does not exist
# yet. The tree fully satisfies this gate today, so it runs HARD — any new
# off-shape file (e.g. a Service mislabeled as a Condition because it lacks
# the contract include) fails immediately.
#
# Override: a shape file that legitimately cannot include the shape header
# (a pure registry/aggregator) may carry `// shape-include-ok:<tag>`
# (no space after the colon, non-empty tag) anywhere in the file.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-shape-includes-header "$@"
