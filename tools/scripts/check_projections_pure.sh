#!/usr/bin/env bash
# Lint gate E4 — projections are pure folds over the event log (HARD).
#
# A projection (engine/modules/storage/src/*_projection.c) rebuilds a read-optimized
# view by folding the event/storage log into its OWN table(s). It must NOT
# reach upward into the app layer or mutate state through the model write
# path. Concretely, a projection must NOT:
#
#   1. #include anything from engine/services/ or engine/controllers/ — that
#      inverts the dependency arrow (storage is the foundation; services
#      and controllers are upstream consumers) and turns a pure fold into
#      a side-effecting coordinator.
#   2. write through the ActiveRecord model save path (AR_ADHOC_SAVE /
#      AR_CACHED_SAVE / AR_BEGIN_SAVE) — a projection owns raw projection
#      SQL over its own tables; routing a write through a Model save fires
#      that model's before/after hooks and creates a cross-shape write.
#
# The current projection set fully complies, so this gate runs HARD: any
# new include of a service/controller header, or any AR model save inside a
# projection, fails immediately.
#
# Override: a legitimate cache write (e.g. memoizing a derived value back
# into the projection's own table outside the strict fold) may carry
# `// projection-cache-ok:<tag>` (no space after the colon, non-empty tag)
# on the offending line.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-projections-pure "$@"
