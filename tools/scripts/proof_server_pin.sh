#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# proof_server_pin.sh — records, and later checks, which commit the
# immutable proof server ($ZCL_SHIP_REMOTE — operator-local, not committed)
# is actually
# running.
#
# WHY THIS EXISTS: tools/ship.sh's proof-server guard used to say the box
# "runs one tagged candidate" and told the operator to "re-tag the candidate
# afterwards so the tag still names what runs." Nothing ever performed that
# re-tag — `git tag -l 'proof-server/*'` was empty — so the prose described a
# binding that no code produced. The running binary answers `agentbuild` with
# `"build_commit":"external"` and a source_id that cannot be reverse-mapped to
# a commit, because tools/dev/source-identity.sh hashes host-local build
# inputs (vendor archives, generated headers) that are not checked in. Today
# nobody can answer "what source is that box running?" This script makes the
# binding self-recording at the one moment ship.sh provably holds it: right
# after it has verified the RUNNING daemon reports the candidate's source id.
#
# Three modes:
#
#   record <commit-sha> <source_id> <artifact_sha256> <host>
#       Creates a LOCAL annotated tag
#       proof-server/<UTC timestamp>-<short commit>-<short source_id>
#       (falling back to a numeric suffix on an exact-name collision)
#       pointing at <commit-sha>, with a machine-greppable key=value message.
#       Validates every argument before writing anything — a failed
#       validation leaves no tag behind. Never overwrites or reuses an
#       existing tag — these are evidence records. Never pushes (publish
#       policy: origin holds only main; these are local evidence tags, same
#       as the operator's tag namespace for other things this repo does not
#       push).
#
#   check [host]
#       Finds the newest proof-server/* tag, dials the host READ-ONLY with
#       exactly two ssh calls, and reports whether the box still runs the
#       pinned source_id. If no pin tag exists at all, this prints that
#       honestly and exits 2 — that is the repository's actual state today,
#       not a bug in this script. This mode writes nothing, locally or
#       remotely, ever.
#
#   --self-test
#       Hermetic. Builds a throwaway git repository under ${TMPDIR:-/tmp},
#       exercises `record` and the no-pin path of `check` INSIDE that repo
#       (this repository's own tags are never touched), and asserts the
#       refusals actually refuse. Touches no network and no proof server.
#
# THE TAG IS NO LONGER THE AUTHORITY. A local annotated tag is exactly as
# trustworthy as one mutable ref on one disk: it is never pushed (origin holds
# only main), `git tag -d`/`-f` rewrites it with no trace, and nothing signs or
# chains it. The authoritative record of a promotion is now the signed,
# hash-chained, TRACKED ledger deploy/promotion-receipts.jsonl, written by
# tools/scripts/promotion_receipt.sh (also called from tools/ship.sh's promotion
# path) and verifiable offline by a third party. That ledger ships with zero
# records: its genesis is minted once by the owner under a signing key the owner
# chooses (docs/PROMOTION_RECEIPTS.md, "Owner setup"). The tag below stays as a
# convenience index — it makes a promotion visible in `git log --decorate` —
# and it proves nothing on its own.
#
# Deliberately NOT done here: nothing re-derives a pin for whatever is
# running on the proof server right now. Its commit is unknown (the
# source-identity hash does not resolve), and fabricating a tag for it would
# be a false record — the honest state is "unpinned," and `check` says so.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$SELF_DIR/$(basename "${BASH_SOURCE[0]}")"

# shellcheck source=tools/scripts/source_identity_lib.sh
. "$SELF_DIR/source_identity_lib.sh"  # zcl_is_sha256, zcl_json_first_sha256

# choose_tag_name — pick a proof-server/* tag name that does not exist yet.
#
# The timestamp alone (second granularity) is not a unique key: two
# promotions inside the same wall-clock second would otherwise collide on
# `git tag -a`, and evidence tags must NEVER be silently overwritten or
# reused. So the base name also carries the short commit and short source_id
# — two promotions of genuinely different values almost never collide even
# within the same second — and if the exact base still exists (e.g. a
# byte-for-byte re-promotion, or two calls with identical commit+source_id
# in the same second), a numeric suffix is appended until a free name is
# found, bounded so this can never loop forever.
choose_tag_name() {
    local ts="$1" commit="$2" source_id="$3"
    local base="proof-server/${ts}-${commit:0:8}-${source_id:0:8}"
    local tagname="$base" n=0
    while git rev-parse -q --verify "refs/tags/${tagname}" >/dev/null 2>&1; do
        n=$((n + 1))
        if [ "$n" -gt 99 ]; then
            return 1
        fi
        tagname="${base}-${n}"
    done
    printf '%s\n' "$tagname"
    return 0
}

# ── record ───────────────────────────────────────────────────────────────
cmd_record() {
    if [ "$#" -ne 4 ]; then
        echo "proof_server_pin: record requires exactly 4 args: <commit-sha> <source_id> <artifact_sha256> <host>" >&2
        return 2
    fi
    local commit="$1" source_id="$2" artifact_sha="$3" host="$4"

    if ! resolved_commit="$(git rev-parse --verify -q "${commit}^{commit}" 2>/dev/null)"; then
        echo "proof_server_pin: refuse — '$commit' does not resolve to a commit in this repo" >&2
        return 1
    fi
    if ! zcl_is_sha256 "$source_id"; then
        echo "proof_server_pin: refuse — source_id '$source_id' is not 64 lowercase hex characters" >&2
        return 1
    fi
    if ! zcl_is_sha256 "$artifact_sha"; then
        echo "proof_server_pin: refuse — artifact_sha256 '$artifact_sha' is not 64 lowercase hex characters" >&2
        return 1
    fi
    if [ -z "$host" ]; then
        echo "proof_server_pin: refuse — host must be non-empty" >&2
        return 1
    fi

    local ts tagname msg
    ts="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
    if ! tagname="$(choose_tag_name "$ts" "$resolved_commit" "$source_id")"; then
        echo "proof_server_pin: refuse — could not find a free proof-server/* tag name after 99 attempts (timestamp ${ts}, commit ${resolved_commit:0:8}, source_id ${source_id:0:8})" >&2
        return 1
    fi
    msg="proof server pin — source_id is the authority (what the running
binary reports of itself); commit is the source it was built from.

host=${host}
commit=${resolved_commit}
source_id=${source_id}
artifact_sha256=${artifact_sha}
recorded_utc=${ts}"

    if ! git tag -a "$tagname" "$resolved_commit" -m "$msg" 2>/dev/null; then
        echo "proof_server_pin: refuse — could not create tag $tagname" >&2
        return 1
    fi
    echo "proof_server_pin: recorded ${tagname} -> commit ${resolved_commit:0:12} source_id ${source_id:0:16}... host ${host} (local tag only, not pushed)"
    return 0
}

# ── check ────────────────────────────────────────────────────────────────
cmd_check() {
    local host="${1:-${ZCL_SHIP_REMOTE:-}}"
    if [ -z "$host" ]; then
        echo "set ZCL_SHIP_REMOTE=<host> locally; fleet endpoints are operator-local and not committed" >&2
        return 2
    fi

    local tag
    tag="$(git for-each-ref --sort=-creatordate --format='%(refname:short)' 'refs/tags/proof-server/*' 2>/dev/null | head -1)"
    if [ -z "$tag" ]; then
        cat >&2 <<EOF
proof_server_pin: NO PROMOTION RECORDED — no proof-server/* tag exists.
  Nobody has ever completed a tools/ship.sh promotion that records one, so
  whatever ${host} is currently running cannot be tied to a reviewed commit.
  This is the repository's honest current state, not a script defect.
EOF
        return 2
    fi

    local contents pinned_commit pinned_source pinned_host
    contents="$(git for-each-ref --format='%(contents)' "refs/tags/${tag}" 2>/dev/null)"
    pinned_commit="$(printf '%s\n' "$contents" | sed -n 's/^commit=//p' | head -1)"
    pinned_source="$(printf '%s\n' "$contents" | sed -n 's/^source_id=//p' | head -1)"
    pinned_host="$(printf '%s\n' "$contents" | sed -n 's/^host=//p' | head -1)"

    if [ -z "$pinned_commit" ] || ! zcl_is_sha256 "$pinned_source"; then
        echo "proof_server_pin: refuse — tag ${tag} is malformed (missing/bad commit= or source_id= line)" >&2
        return 3
    fi

    echo "proof_server_pin: newest pin  ${tag}"
    echo "  pinned commit      ${pinned_commit}"
    echo "  pinned source_id   ${pinned_source}"
    echo "  pinned host        ${pinned_host}"

    local svc_bin
    svc_bin="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" \
        'systemctl --user show zclassic23 -p ExecStart --value | tr " " "\n" | sed -n "s/^path=//p" | head -1' 2>/dev/null || true)"
    case "$svc_bin" in
        /*) ;;
        *)
            echo "proof_server_pin: UNREACHABLE — could not get an absolute ExecStart path from ${host}" >&2
            return 3
            ;;
    esac

    local running_source
    running_source="$(zcl_json_first_sha256 "$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" \
        "timeout 20 '${svc_bin}' agentbuild" 2>/dev/null)" source_id_sha256)"

    if ! zcl_is_sha256 "$running_source"; then
        echo "proof_server_pin: UNREACHABLE — ${host} did not report a usable source_id_sha256" >&2
        return 3
    fi
    echo "  running source_id  ${running_source}"

    if [ "$running_source" = "$pinned_source" ]; then
        echo "proof_server_pin: MATCH — ${host} is running the pinned commit ${pinned_commit:0:12} (${tag})"
        return 0
    fi
    echo "proof_server_pin: MISMATCH — ${host} is running source_id ${running_source}, pinned was ${pinned_source} (${tag}, commit ${pinned_commit:0:12})" >&2
    return 1
}

# ── self-test ────────────────────────────────────────────────────────────
selftest_git() {
    env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
        GIT_AUTHOR_NAME=selftest GIT_AUTHOR_EMAIL=selftest@invalid \
        GIT_COMMITTER_NAME=selftest GIT_COMMITTER_EMAIL=selftest@invalid \
        git "$@"
}

selftest_run() {
    # $1 = repo dir, remaining = args to proof_server_pin.sh. Runs with cwd
    # set to $1 so `record`/`check` operate on the throwaway repo, never on
    # this checkout. Echoes the exit status; never aborts the caller.
    local repo="$1"; shift
    local rc=0
    ( cd "$repo" && \
      env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
          GIT_AUTHOR_NAME=selftest GIT_AUTHOR_EMAIL=selftest@invalid \
          GIT_COMMITTER_NAME=selftest GIT_COMMITTER_EMAIL=selftest@invalid \
          "$SELF" "$@" >"$repo/.selftest_out" 2>"$repo/.selftest_err" ) || rc=$?
    echo "$rc"
}

selftest_tag_count() {
    selftest_git -C "$1" tag -l 'proof-server/*' 2>/dev/null | grep -c . || true
}

selftest_fail=0
selftest_note() {
    echo "proof_server_pin: SELF-TEST FAIL — $1" >&2
    selftest_fail=$((selftest_fail + 1))
}

run_self_test() {
    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl_proof_pin_selftest.XXXXXX" 2>/dev/null || true)"
    if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
        echo "proof_server_pin: SELF-TEST SKIPPED — no writable temp dir" >&2
        return 0
    fi
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM

    selftest_git init -q "$tmp" >/dev/null 2>&1 || {
        echo "proof_server_pin: SELF-TEST SKIPPED — cannot build a fixture git repo here" >&2
        return 0
    }
    echo "fixture" > "$tmp/f.txt"
    selftest_git -C "$tmp" add -A >/dev/null 2>&1
    selftest_git -C "$tmp" -c commit.gpgsign=false commit -qm fixture >/dev/null 2>&1
    local commit
    commit="$(selftest_git -C "$tmp" rev-parse HEAD)"

    # (1) check's no-pin path: no proof-server/* tag exists yet in this
    #     fixture, so `check` must refuse before dialling anything and exit
    #     2. This is the ONLY check() case self-test exercises, by design —
    #     the pin-found path requires ssh, which self-test must never touch.
    local rc
    rc="$(selftest_run "$tmp" check some.unreachable.invalid.example)"
    [ "$rc" = "2" ] || selftest_note "check with no pin tag should exit 2 (got $rc)"
    grep -q 'NO PROMOTION RECORDED' "$tmp/.selftest_err" 2>/dev/null || \
        selftest_note "check with no pin tag should print an honest NO PROMOTION RECORDED message"

    # (2) record, valid args -> tag exists, annotated, points at the right
    #     commit, message carries all five keys with the exact values given.
    local src="1111111111111111111111111111111111111111111111111111111111111111"
    src="${src:0:64}"
    local art="2222222222222222222222222222222222222222222222222222222222222222"
    art="${art:0:64}"
    rc="$(selftest_run "$tmp" record "$commit" "$src" "$art" "example-host")"
    [ "$rc" = "0" ] || selftest_note "record with valid args should exit 0 (got $rc; stderr: $(cat "$tmp/.selftest_err" 2>/dev/null))"

    local newtag
    newtag="$(selftest_git -C "$tmp" tag -l 'proof-server/*' | head -1)"
    if [ -z "$newtag" ]; then
        selftest_note "record did not create a proof-server/* tag"
    else
        local objtype
        objtype="$(selftest_git -C "$tmp" cat-file -t "$newtag" 2>/dev/null || true)"
        [ "$objtype" = "tag" ] || selftest_note "$newtag is not an annotated tag object (type='$objtype')"

        local points_at
        points_at="$(selftest_git -C "$tmp" rev-parse "${newtag}^{commit}" 2>/dev/null || true)"
        [ "$points_at" = "$commit" ] || selftest_note "$newtag points at '$points_at', expected '$commit'"

        local body
        body="$(selftest_git -C "$tmp" for-each-ref --format='%(contents)' "refs/tags/${newtag}")"
        printf '%s\n' "$body" | grep -qx "host=example-host"        || selftest_note "tag message missing exact host= line"
        printf '%s\n' "$body" | grep -qx "commit=${commit}"         || selftest_note "tag message missing exact commit= line"
        printf '%s\n' "$body" | grep -qx "source_id=${src}"         || selftest_note "tag message missing exact source_id= line"
        printf '%s\n' "$body" | grep -qx "artifact_sha256=${art}"   || selftest_note "tag message missing exact artifact_sha256= line"
        printf '%s\n' "$body" | grep -qE '^recorded_utc=[0-9TZ-]+$' || selftest_note "tag message missing a well-formed recorded_utc= line"
    fi

    # (3) refusals: each must exit non-zero, leave no new tag behind, AND
    #     print EXACTLY the one expected refusal message — not merely
    #     "contains" it. Exit-code-plus-tag-count alone is too weak: a
    #     disabled validator that happens to fail for an UNRELATED reason
    #     downstream (e.g. `git tag` itself refusing a bad ref) still trips
    #     "non-zero" and "no new tag," so it would pass a weaker check while
    #     the actual validation never ran. An exact stderr match catches
    #     that: if the specific refusal echo does not fire (or something
    #     else prints alongside it), the comparison fails.
    local before after stderr_got stderr_want

    before="$(selftest_tag_count "$tmp")"
    rc="$(selftest_run "$tmp" record "$commit" "not-64-hex" "$art" "example-host")"
    after="$(selftest_tag_count "$tmp")"
    stderr_got="$(cat "$tmp/.selftest_err" 2>/dev/null)"
    stderr_want="proof_server_pin: refuse — source_id 'not-64-hex' is not 64 lowercase hex characters"
    [ "$rc" != "0" ] || selftest_note "record with a malformed source_id should refuse (got exit 0)"
    [ "$before" = "$after" ] || selftest_note "record with a malformed source_id left a tag behind ($before -> $after)"
    [ "$stderr_got" = "$stderr_want" ] || selftest_note "record with a malformed source_id: stderr was '$stderr_got', expected exactly '$stderr_want' — the source_id validator may not actually be running"

    before="$(selftest_tag_count "$tmp")"
    rc="$(selftest_run "$tmp" record "0000000000000000000000000000000000000000" "$src" "$art" "example-host")"
    after="$(selftest_tag_count "$tmp")"
    stderr_got="$(cat "$tmp/.selftest_err" 2>/dev/null)"
    stderr_want="proof_server_pin: refuse — '0000000000000000000000000000000000000000' does not resolve to a commit in this repo"
    [ "$rc" != "0" ] || selftest_note "record with a non-existent commit should refuse (got exit 0)"
    [ "$before" = "$after" ] || selftest_note "record with a non-existent commit left a tag behind ($before -> $after)"
    [ "$stderr_got" = "$stderr_want" ] || selftest_note "record with a non-existent commit: stderr was '$stderr_got', expected exactly '$stderr_want' — the commit validator may not actually be running"

    before="$(selftest_tag_count "$tmp")"
    rc="$(selftest_run "$tmp" record "$commit" "$src" "$art" "")"
    after="$(selftest_tag_count "$tmp")"
    stderr_got="$(cat "$tmp/.selftest_err" 2>/dev/null)"
    stderr_want="proof_server_pin: refuse — host must be non-empty"
    [ "$rc" != "0" ] || selftest_note "record with an empty host should refuse (got exit 0)"
    [ "$before" = "$after" ] || selftest_note "record with an empty host left a tag behind ($before -> $after)"
    [ "$stderr_got" = "$stderr_want" ] || selftest_note "record with an empty host: stderr was '$stderr_got', expected exactly '$stderr_want' — the host validator may not actually be running"

    # (4) same-second collision: two `record` calls with DIFFERENT valid
    #     values, issued back to back (in practice landing in the same
    #     wall-clock second — a fresh shell invocation is well under a
    #     second), must both succeed and produce TWO DISTINCT tags. This is
    #     the regression proof for choose_tag_name()'s discriminator: with
    #     only a second-granularity timestamp, the second call would collide
    #     on `git tag -a` and fail (this was the original bug — see the
    #     header of this script's commit history).
    local src2="3333333333333333333333333333333333333333333333333333333333333333"
    src2="${src2:0:64}"
    local art2="4444444444444444444444444444444444444444444444444444444444444444"
    art2="${art2:0:64}"
    local src3="5555555555555555555555555555555555555555555555555555555555555555"
    src3="${src3:0:64}"
    local art3="6666666666666666666666666666666666666666666666666666666666666666"
    art3="${art3:0:64}"

    before="$(selftest_tag_count "$tmp")"
    local rc_a rc_b
    rc_a="$(selftest_run "$tmp" record "$commit" "$src3" "$art3" "example-host")"
    rc_b="$(selftest_run "$tmp" record "$commit" "$src2" "$art2" "example-host")"
    after="$(selftest_tag_count "$tmp")"
    [ "$rc_a" = "0" ] || selftest_note "same-second collision case: first record should succeed (got exit $rc_a)"
    [ "$rc_b" = "0" ] || selftest_note "same-second collision case: second record (different source_id) should succeed (got exit $rc_b; stderr: $(cat "$tmp/.selftest_err" 2>/dev/null))"
    [ "$after" -ge "$((before + 2))" ] || selftest_note "same-second collision case: expected at least 2 new tags, got $((after - before))"

    rm -rf "$tmp"
    trap - EXIT HUP INT TERM

    if [ "$selftest_fail" -ne 0 ]; then
        echo "PROOF SERVER PIN SELF-TEST: FAIL ($selftest_fail assertion(s))" >&2
        return 1
    fi
    echo "PROOF SERVER PIN SELF-TEST: PASS"
    return 0
}

# ── dispatch ─────────────────────────────────────────────────────────────
case "${1-}" in
    record)
        shift
        cmd_record "$@"
        exit $?
        ;;
    check)
        shift
        cmd_check "$@"
        exit $?
        ;;
    --self-test)
        run_self_test
        exit $?
        ;;
    *)
        cat >&2 <<EOF
usage:
  proof_server_pin.sh record <commit-sha> <source_id> <artifact_sha256> <host>
  proof_server_pin.sh check [host]
  proof_server_pin.sh --self-test
EOF
        exit 2
        ;;
esac
