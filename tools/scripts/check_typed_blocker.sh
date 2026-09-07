#!/usr/bin/env bash
# Lint gate #16 — typed blocker primitive adoption.
#
# Goal: every "this is blocked" signal in the codebase is a typed
# blocker_record routed through `blocker_set()` (platform/modules/util/blocker.h),
# not a raw `char *_blocker[N]` string field or a bare `state == "blocked"`
# bool. The typed primitive is the only path with rate-limiting,
# escape dispatch, retry budget, and class-aware policy.
#
# Why: 2026-05-21 — the live node ran 4.3 days with
# `activation_blocker = "activation-no-progress"` re-firing ~5/sec
# because there was no de-duplication at the recorder. Round 6 C1
# shipped the typed primitive; C2/C3/C4/C5 wired it into the mirror
# consensus, source scoring, BLOCK_FAILED model, and native diagnostics. This gate
# is the ratchet that drives the rest of the codebase to opt in.
#
# A file is a "raw blocker site" if it contains one of:
#   - char[[:space:]]+[a-z_]*_blocker(_code)?\[   (raw blocker char[N] field)
#   - lms_set_blocker\(                            (legacy mirror string setter)
#   - g_[a-z_]*\.last_blocker_code\b             (legacy blocker_code mutation)
#
# Such a file must EITHER:
#   - call `blocker_set(` (uses the typed primitive somewhere); OR
#   - carry a per-file override marker `// blocker-ok:<tag>` on a line
#     in the file (explain WHY this site intentionally uses the string
#     surface — usually because it predates the typed primitive and is
#     scheduled for migration); OR
#   - appear in `tools/scripts/typed_blocker_baseline.txt`.
#
# To clean up debt: pick a baseline entry, migrate it to blocker_set()
# (see engine/services/src/block_source_policy_runtime.c
# classify_mirror_blocker_class() + score_source for the typed pattern),
# delete the baseline line, re-run `make lint`.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-typed-blocker "$@"
