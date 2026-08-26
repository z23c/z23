# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# source_identity_lib.sh — the ONE reader for a build's baked source
# identity ("source_id_sha256"), and the ONE sha256-string validator.
#
# TWO QUESTIONS, ONE KEY NAME — read this before adding a caller.
#
# The string `source_id_sha256` answers two DIFFERENT questions in this tree,
# and every reporting surface spells both of them with that same key:
#
#   Q1. "What source tree was this BINARY built from?"
#       A property of the executable. Baked in at compile time by
#       -DZCL_BUILD_SOURCE_ID (Makefile BUILD_IDENTITY_CPPFLAGS, scoped to the
#       single TU lib/util/src/clientversion.c) and returned by
#       zcl_build_source_id_sha256(). CONSTANT wherever you run the binary
#       from: it does not read the filesystem, the cwd, or any environment.
#
#   Q2. "What source tree is in THIS DIRECTORY right now?"
#       A property of a working tree. Computed by tools/dev/source-identity.sh
#       over the files under the current repository root and surfaced as
#       $(BUILD_SOURCE_ID), as `make agent-plan`'s green_input_cache
#       .source_id_sha256, and inside the background-quality lane status
#       files. It VARIES BY DIRECTORY, by design.
#
# Both are useful and neither is wrong. Reporting one under the other's name
# is the defect. A freshness check — "is the running daemon the build I
# expect?" — must read Q1, because a cwd-derived answer can pass a stale
# daemon (its own tree looks current) or fail a fresh one (checked out
# somewhere else). Q2 belongs only to questions about a checkout.
#
# THIS LIBRARY ANSWERS Q1 ONLY. There is deliberately no Q2 reader here, so a
# caller cannot pick the wrong one out of the same namespace by accident; if
# you want Q2, run tools/dev/source-identity.sh against the tree you mean and
# name the variable after the tree, not after "the source id".
#
# WHY THIS EXISTS — read before touching any function below.
#
# `z23 agentbuild` emits the key `source_id_sha256` SEVERAL times on a
# SINGLE line (8 on one build measured 2026-07-30 — the exact count is build-
# and lane-state-dependent, so treat it as "more than one," not a fixed
# number): once at the top level (the source this binary was actually
# compiled from) and again inside nested runtime blocks describing the dev
# lane as it exists right now. Because the payload is one line, a naive
# extraction of the form
#     sed 's/.*"source_id_sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
# is GREEDY — the leading `.*` consumes as much as possible, so it returns
# the LAST occurrence (a runtime value), not the first (the baked identity).
# Piping through `head -1` does not help: sed emits at most one line per
# input line, so `head -1` is a no-op on single-line JSON. This is not
# hypothetical — it produced a false "the live daemon and the dev build have
# identical identities" on 2026-07-28, exactly the false positive a drift
# check must never produce. The fix is to anchor on the FIRST match instead:
# `grep -oE` (or `grep -o`) followed by `head -1`, where `grep -o` prints
# each match as its own line and `-oE`'s NON-greedy-per-match scanning finds
# the first occurrence first. Every function below uses that form, and nine
# copies of a subtly different version of it are exactly the defect
# tools/lint/check_identity_parser_single.sh exists to stop from growing
# back — see that gate for the anti-rot enforcement, and dev_lib.sh's
# baked_source_id() (predates this library, deliberately left as the
# tools/dev/ in-tree reference and NOT migrated here — see the lane's
# handoff notes) for the sibling implementation this library generalizes.
#
# FIRST-MATCH IS A HEURISTIC, NOT AN ADMISSION RULE. "The first occurrence"
# only lands on the Q1 value while the Q1 value happens to be printed first;
# it is one key-ordering change away from silently returning a Q2 value under
# a Q1 caller's variable name — the same class of failure as the greedy sed,
# just with a longer fuse. So the readers that feed a freshness DECISION do
# not use it:
#   * agentbuild payloads  -> zcl_agentbuild_v2_top_source_id(), which binds
#     schema, api_version, status, field position and the following field, so
#     only the canonical top-level value can ever be returned.
#   * healthcheck payloads -> zcl_healthcheck_v1_running_source_id(), which
#     binds the schema and then requires UNANIMITY: if the document offers two
#     different values under this key, it refuses instead of guessing which
#     question the document was answering.
# zcl_json_first_string()/zcl_json_first_sha256() remain for display and for
# non-identity keys. Do not introduce a new freshness caller on top of them.
#
# Sourcing contract: THE CALLER resolves this file's own path before sourcing
# it — this library does not locate itself. That is deliberate, not an
# oversight: `deploy_verify.sh` runs under `sh` (dash), which has no
# `${BASH_SOURCE[0]}`, so a self-locating library would need a bash-only
# mechanism the plainest caller can't use — the caller-resolves form is the
# one shape that works identically under both shells. Each of the four
# callers uses the one-line form appropriate to how it already finds its own
# directory:
#   sh (deploy_verify.sh):    . "$SCRIPT_DIR/scripts/source_identity_lib.sh"
#   bash (ship.sh, lane_health.sh — both already compute $REPO_ROOT):
#                             . "$REPO_ROOT/tools/scripts/source_identity_lib.sh"
#   bash (proof_server_pin.sh, sourced by its own dirname):
#                             . "$SELF_DIR/source_identity_lib.sh"
# Otherwise: side-effect-free (defines functions only), and idempotent (safe
# to source twice — a second source is a no-op). All functions are prefixed
# `zcl_` to avoid colliding with a caller's own locals.

if [ -n "${ZCL_SOURCE_IDENTITY_LIB_SOURCED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
ZCL_SOURCE_IDENTITY_LIB_SOURCED=1

# zcl_is_sha256 <string> — true iff exactly 64 lowercase hex characters.
# Pure: no output, status only.
zcl_is_sha256() {
    case "${1:-}" in
        "") return 1 ;;
    esac
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
    esac
    [ "${#1}" -eq 64 ]
}

# zcl_json_first_string <json-text> <key> — the FIRST string value of "key"
# in <json-text>. Anchored first-occurrence extraction (see header): a
# `grep -o` pass isolates the first "key":"value" token, then a `sed`
# anchored on that isolated token (not on the original text) pulls out the
# value. Empty output, success status, when the key is absent or malformed
# — an absent key is a normal answer for a caller, not an error.
zcl_json_first_string() {
    local body="${1:-}" key="${2:?zcl_json_first_string: key required}" token
    token="$(printf '%s\n' "$body" |
        grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" 2>/dev/null |
        head -1 || true)"
    [ -n "$token" ] || return 0
    printf '%s\n' "$token" |
        sed -n "s/^\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"\$/\1/p"
}

# zcl_json_first_sha256 <json-text> <key> — as zcl_json_first_string, but
# only ever returns a well-formed 64-lowercase-hex value: the first
# occurrence of "key" whose value is NOT 64 hex characters yields empty
# output rather than a truncated or garbage string. This is the semantic
# every source_id_sha256 reader in this tree actually wants, and is
# equivalent to dev_lib.sh's baked_source_id() rule (anchor first, require
# 64 hex).
zcl_json_first_sha256() {
    local body="${1:-}" key="${2:?zcl_json_first_sha256: key required}"
    printf '%s\n' "$body" |
        grep -oE "\"${key}\"[[:space:]]*:[[:space:]]*\"[0-9a-f]{64}\"" 2>/dev/null |
        head -1 |
        grep -oE '[0-9a-f]{64}' || true
}

# zcl_json_all_sha256 <json-text> <key> — every well-formed 64-lowercase-hex
# value carried by "key", one per line, in document order. Zero matches is a
# normal answer (empty output, success status). This is the raw material for
# an ambiguity check; it is NOT an identity reader — never pick a line out of
# it by position.
zcl_json_all_sha256() {
    local body="${1:-}" key="${2:?zcl_json_all_sha256: key required}"
    printf '%s\n' "$body" |
        grep -oE "\"${key}\"[[:space:]]*:[[:space:]]*\"[0-9a-f]{64}\"" 2>/dev/null |
        grep -oE '[0-9a-f]{64}' || true
}

# zcl_json_sha256_is_ambiguous <json-text> <key> — TRUE when "key" carries two
# or more DIFFERENT 64-hex values in one document, i.e. the document answers
# two different questions under one name and no positional rule can say which
# one a caller meant. Repeats of the SAME value are not ambiguous. Status
# only, no output; callers turn a true here into a fail-closed diagnostic.
zcl_json_sha256_is_ambiguous() {
    local body="${1:-}" key="${2:?zcl_json_sha256_is_ambiguous: key required}"
    local values distinct
    values="$(zcl_json_all_sha256 "$body" "$key")"
    [ -n "$values" ] || return 1
    distinct="$(printf '%s\n' "$values" | sort -u | wc -l | tr -d ' ')"
    [ "$distinct" -gt 1 ]
}

# zcl_json_unanimous_sha256 <json-text> <key> — the value of "key" when the
# document is unanimous about it, and NOTHING when it is absent, malformed, or
# ambiguous. Refusal is deliberate: a freshness authority that guesses between
# two candidate answers is exactly the check that passes a stale deploy.
zcl_json_unanimous_sha256() {
    local body="${1:-}" key="${2:?zcl_json_unanimous_sha256: key required}"
    local values
    values="$(zcl_json_all_sha256 "$body" "$key")"
    [ -n "$values" ] || return 0
    if zcl_json_sha256_is_ambiguous "$body" "$key"; then
        return 0
    fi
    printf '%s\n' "$values" | head -1
}

# zcl_healthcheck_v1_running_source_id <json-text> — the Q1 identity of the
# process that answered a `healthcheck` RPC: the source tree ITS OWN
# executable was built from (app/controllers/src/event_healthcheck_controller.c
# publishes zcl_build_source_id_sha256() at the top level of both the bounded
# and the full payload; the nested `agent` block repeats the same value, and
# the nested `runtime_build` block deliberately uses the distinct names
# running_source_id_sha256/expected_source_id_sha256 so it cannot collide).
#
# Admission binds the schema and then requires unanimity — a payload that ever
# grows a nested `source_id_sha256` describing a WORKING TREE (Q2) rather than
# this executable makes the answer ambiguous, and this returns nothing so the
# caller refuses instead of comparing the wrong value. Invalid/refused input
# yields empty output and success; the caller applies its own diagnostic.
#
# The schema bind is a CONTAINS, not the exact leading prefix the agentbuild
# reader above uses. That is deliberate: a caller may hand over the raw
# JSON-RPC envelope (`{"result":{...},"error":null,...}`) rather than the
# unwrapped result, and an over-tight prefix would refuse a perfectly good
# deploy — a freshness check that fails a FRESH binary is its own outage.
# Unanimity, not field position, is what does the work here.
#
# `grep -c` rather than `grep -q`: under `set -o pipefail` a quiet grep in a
# pipeline reports a MATCH as 141, which inverts the decision. Callers of this
# library do run with pipefail.
zcl_healthcheck_v1_running_source_id() {
    local body="${1:-}" schema_hits
    schema_hits="$(printf '%s\n' "$body" |
        grep -cE '"schema"[[:space:]]*:[[:space:]]*"zcl\.healthcheck\.v1"' \
        2>/dev/null || true)"
    case "${schema_hits:-0}" in
        ''|0) return 0 ;;
    esac
    zcl_json_unanimous_sha256 "$body" source_id_sha256
}

# zcl_agentbuild_v2_top_source_id <json-text> — admit only the canonical
# top-level prefix of a successful v1 agentbuild response. This is stronger
# than zcl_json_first_sha256(): nested runtime objects legitimately reuse the
# source_id_sha256 key, so admission must also bind schema, API, status, field
# position, and the exact top-level value. Invalid/refused input yields empty
# output and success so callers can apply their own fail-closed diagnostic.
zcl_agentbuild_v2_top_source_id() {
    local body="${1:-}" prefix rest source_id suffix
    prefix='{"schema":"zcl.agent_build.v2","api_version":"v1","status":"ok","source_id_sha256":"'
    case "$body" in
        "$prefix"*) ;;
        *) return 0 ;;
    esac
    rest="${body#"$prefix"}"
    source_id="${rest%%\"*}"
    zcl_is_sha256 "$source_id" || return 0
    suffix="${rest#"$source_id"}"
    case "$suffix" in
        '","build_commit":"'*) ;;
        *) return 0 ;;
    esac
    printf '%s\n' "$source_id"
}

# zcl_agentbuild_v2_top_build_commit <json-text> — display-only commit paired
# with the same admitted top-level source identity. The caller still applies
# its own character allowlist before exporting it.
zcl_agentbuild_v2_top_build_commit() {
    local body="${1:-}" source_id prefix rest
    source_id="$(zcl_agentbuild_v2_top_source_id "$body")"
    [ -n "$source_id" ] || return 0
    prefix='{"schema":"zcl.agent_build.v2","api_version":"v1","status":"ok","source_id_sha256":"'"$source_id"'","build_commit":"'
    case "$body" in
        "$prefix"*) ;;
        *) return 0 ;;
    esac
    rest="${body#"$prefix"}"
    case "$rest" in
        *\"*) ;;
        *) return 0 ;;
    esac
    printf '%s\n' "${rest%%\"*}"
}

# zcl_binary_source_id <path-to-binary> — Q1 ONLY: the source tree THAT
# BINARY was compiled from, read out of the binary itself by running
# `<path> agentbuild` and admitting the canonical top-level identity through
# zcl_agentbuild_v2_top_source_id(). The answer is a property of the file at
# <path> and is therefore the same from every working directory; nothing here
# consults the cwd, and the schema-anchored admission means a nested runtime
# (Q2) value can never be returned in its place even if the payload's key
# order changes. Pass /proc/<pid>/exe to ask it of a running process.
#
# It used to admit via zcl_json_first_sha256() — the positional heuristic.
# That returned the right value only for as long as the baked identity stayed
# the first `source_id_sha256` in the document; the strict reader removes the
# ordering dependency entirely.
#
# Preserves dev_lib.sh's baked_source_id() control flow exactly: a
# non-executable (or missing) path is a normal "nothing to report" case, not a
# failure — it returns SUCCESS with empty output, so a caller doing
# `id="$(zcl_binary_source_id "$bin")"` never has to fork error handling for
# "binary absent" vs. "binary present but silent". A binary whose agentbuild
# output is not a canonical successful zcl.agent_build.v2 reads the same way:
# empty, i.e. "this binary did not state its identity", never a guess.
zcl_binary_source_id() {
    local bin="${1:-}"
    [ -x "$bin" ] || return 0
    zcl_agentbuild_v2_top_source_id "$(timeout 20 "$bin" agentbuild 2>/dev/null)"
}
