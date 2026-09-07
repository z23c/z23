#!/usr/bin/env bash
# check_model_validation.sh — gate #11
#
# Every engine/models/src/*.c must either invoke at least one validates_*
# macro from engine/models/include/models/activerecord.h, or carry a
# deliberate `ar-validate-skip:<reason>` marker explaining why the AR
# validation lifecycle does not apply (e.g. infrastructure wrappers,
# registries, helper-only modules).
#
# Marker syntax (matches the obs-ok / raw-*-ok family):
#   ar-validate-skip:<short-tag>
# No space after the colon. The tag must be non-empty.
#
# Exit 0 on clean, 1 on any model file that satisfies neither rule.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-model-validation "$@"
