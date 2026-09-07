#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_json_value_init.sh — a `struct json_value` local must be zeroed
# (`= {0}`) or json_init()ed before any json_set_*() / json_free() touches it.
#
# WHY THIS GATE EXISTS. json_set_object()/json_set_array()/json_set_str() and
# friends all call json_free(v) FIRST, to release what the value held before
# (platform/modules/json/src/json.c). On an uninitialised stack local that "release" reads
# garbage type/num_children/children and frees or walks it. The contract is
# already stated in platform/modules/json/include/json/json.h ("Stack values must be
# zero-initialized or passed through json_init()") — this gate is what makes
# the statement true.
#
# It was written after zid_domain_dump_state_json() did exactly this and
# segfaulted a serving node every ~15 minutes:
#     json_free+0x43 <- zid_domain_dump_state_json+0x1b9 <- debug_bundle_write
# Whether it faults depends on what the previous frame left behind, so the
# same binary can look fine for hours and then kill a node mid-sync.
#
# SCOPE — the unambiguous, purely local pattern only:
#     struct json_value NAME;      <- no initialiser
#     ... first mention of NAME is json_set_*(&NAME) or json_free(&NAME)
# Indirection through a helper that takes &NAME is NOT flagged; helpers own
# their out-param (see core/math/src/core_io.c, which json_init()s first).
# Every file under the repo is scanned, tests included — the UB is identical
# there and a test that corrupts its own stack is not a passing test.
#
# ZERO baseline on purpose: the class was empty when this gate landed, so
# there is nothing to grandfather and no allowlist to erode.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-json-value-init "$@"
