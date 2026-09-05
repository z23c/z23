#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# check-tor-full-default — real Tor is the default link, and a stub cannot be
# packaged.
#
# WHAT WENT WRONG, so nobody re-derives it. The node link selected real Tor
# when four archives happened to exist and fell back to libtor_stub.a when
# they did not. Nothing failed: the build compiled, linked, and passed the
# whole suite. The only symptom was a node whose -tor is inert — blind to the
# onion network this project is built on. Every fresh worktree hit it, because
# a git worktree does not populate submodules. The portable Linux release hit
# it ON PURPOSE, passing TOR_FULL= to make.
#
# A defect whose only symptom is silence needs a gate, because a test can only
# check the build it was compiled into. Three things must stay true:
#
#   (i)   a build that links a node ESTABLISHES the Tor archives first — the
#         default goal cannot quietly proceed without them;
#   (ii)  the stub is reachable only by naming it, ZCL_TOR=stub, and the knob
#         rejects any other value rather than guessing;
#   (iii) every step that packages a binary refuses a tor=stub one with the
#         SAME sentence, so an operator who hits it once can grep for it.
#
# This gate reads text, deliberately. It cannot run a Tor build, and a runtime
# test cannot see the ninety-nine builds that were configured differently.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="check-tor-full-default"

# The one refusal sentence. Kept here as a literal on purpose: this gate's job
# is to notice when a copy of it drifts, and a gate that read the sentence
# from the file it is checking would agree with every rewording.
REFUSAL='refusing to package a tor=stub binary: it cannot reach the onion network; rebuild with make tor-full'

# Files that must carry the sentence verbatim. tor_stamp_lib.sh defines it;
# install_z23.sh must run standalone on a box with no checkout, so it carries
# its own copy, and this gate is the only thing keeping the two identical.
REFUSAL_FILES=(
    tools/scripts/tor_stamp_lib.sh
    tools/scripts/install_z23.sh
)
# Files that must REACH the refusal (by the shared variable or the literal).
REFUSAL_USERS=(
    tools/ship.sh
    tools/scripts/build_c23_portable_release.sh
)

fail=0
note() { printf '%s: FAIL — %s\n' "$GATE" "$1" >&2; fail=1; }

# Makefile assignments wrap across backslash-continued lines, so every
# multi-line assertion below reads a JOINED copy. Grepping the raw file would
# make this gate pass or fail on where somebody put a line break.
mk_joined() { sed -e :a -e '/\\$/{N;s/\\\n//;ta}' "$1"; }

check_root() {
    local root="$1" mk="$1/Makefile" f joined
    [ -f "$mk" ] || { note "no Makefile under $root"; return 1; }
    joined="$(mk_joined "$mk")"

    # (i) A link establishes the archives. The bootstrap include is what makes
    #     the default goal depend on them: remaking an included makefile
    #     restarts Make, and the second parse's wildcard sees them.
    grep -qF -- '-include $(TOR_BOOTSTRAP_MK)' "$mk" \
        || note "the Makefile never includes \$(TOR_BOOTSTRAP_MK), so a plain \`make\` does not establish the Tor archives and links the stub"
    grep -qE '^\$\(TOR_BOOTSTRAP_MK\):[[:space:]]*tor-ready' "$mk" \
        || note "\$(TOR_BOOTSTRAP_MK) has no 'tor-ready' prerequisite, so the include cannot build anything"

    # The goal filter must be a SKIP list. An allow list means every goal
    # nobody thought about silently keeps the stub — the exact default-permit
    # shape this change deleted.
    grep -qE 'ZCL_TOR_LINK_REQUESTED[[:space:]]*:?=.*filter-out[[:space:]]+\$\(ZCL_TOR_SKIP_GOALS\)' <<<"$joined" \
        || note "ZCL_TOR_LINK_REQUESTED is not computed as filter-out of a skip list; an allow list would let any unlisted goal link the stub"

    # (ii) The stub needs the knob, and the knob rejects anything else.
    grep -qE '^ZCL_TOR[[:space:]]*\?=[[:space:]]*full$' "$mk" \
        || note "ZCL_TOR does not default to 'full'"
    grep -qE '\$\(error ZCL_TOR must be' "$mk" \
        || note "an unrecognised ZCL_TOR value is not refused; the Makefile would guess"
    grep -qE '^TOR_FULL[[:space:]]*=.*filter[[:space:]]+stub,\$\(ZCL_TOR\)' "$mk" \
        || note "TOR_FULL is not emptied by ZCL_TOR=stub, so the stub is not selected by the knob"
    grep -qF 'ZCL_TOR=stub - LINKING THE OFFLINE TOR STUB' "$mk" \
        || note "selecting the stub prints no loud line"

    # (iii) The refusal sentence, byte for byte, in every carrier.
    for f in "${REFUSAL_FILES[@]}"; do
        [ -f "$root/$f" ] || { note "$f is missing"; continue; }
        grep -qF -- "$REFUSAL" "$root/$f" \
            || note "$f does not carry the exact tor=stub refusal sentence"
    done
    for f in "${REFUSAL_USERS[@]}"; do
        [ -f "$root/$f" ] || { note "$f is missing"; continue; }
        grep -qE -- 'ZCL_TOR_STUB_REFUSAL|zcl_tor_require_full' "$root/$f" \
            || note "$f packages a binary but never reaches the tor=stub refusal"
    done

    # The forced-stub release path must stay deleted. It is one assignment,
    # and it silently un-does everything above. Comment lines are exempt:
    # build_c23_portable_release.sh now explains in prose why it used to pass
    # TOR_FULL=, and deleting that explanation would cost more than it saves.
    local forced
    forced="$(grep -rnE 'TOR_FULL=([[:space:]]|$)' "$root/tools" "$mk" 2>/dev/null |
        grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' |
        grep -v '/check_tor_full_default\.sh:' || true)"
    if [ -n "$forced" ]; then
        note "something still forces TOR_FULL empty; that is how the portable release shipped a stub"
        printf '%s\n' "$forced" >&2
    fi

    return $fail
}

# --selftest plants one defect at a time in a throwaway copy and asserts this
# gate rejects it. A gate nobody has seen fail is a gate nobody should trust.
run_selftest() {
    local tmp rc bad
    tmp="$(mktemp -d "$ROOT/build/scratch/zcl-tor-gate.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT HUP INT TERM

    seed() {
        local d="$1"
        rm -rf "$d"; mkdir -p "$d/tools/scripts"
        cp "$ROOT/Makefile" "$d/Makefile"
        cp "$ROOT/tools/ship.sh" "$d/tools/ship.sh"
        cp "$ROOT/tools/scripts/tor_stamp_lib.sh" "$d/tools/scripts/"
        cp "$ROOT/tools/scripts/install_z23.sh" "$d/tools/scripts/"
        cp "$ROOT/tools/scripts/build_c23_portable_release.sh" "$d/tools/scripts/"
    }
    expect() {
        local want="$1" d="$2" label="$3"
        fail=0
        rc=0
        check_root "$d" >/dev/null 2>&1 || rc=$?
        if [ "$want" = accept ] && [ "$rc" -ne 0 ]; then
            printf '%s selftest: FAILED — rejected the good fixture (%s)\n' "$GATE" "$label" >&2
            exit 1
        fi
        if [ "$want" = reject ] && [ "$rc" -eq 0 ]; then
            printf '%s selftest: FAILED — accepted a fixture with %s\n' "$GATE" "$label" >&2
            exit 1
        fi
    }

    bad="$tmp/fixture"

    seed "$bad"
    expect accept "$bad" "unmodified tree"

    # 1. The refusal sentence drifts in the standalone installer copy.
    seed "$bad"
    sed -i 's/refusing to package a tor=stub binary/refusing to install a stub binary/' \
        "$bad/tools/scripts/install_z23.sh"
    expect reject "$bad" "a reworded refusal sentence in install_z23.sh"

    # 2. The bootstrap include is dropped, so a plain make links the stub.
    seed "$bad"
    sed -i 's@^-include \$(TOR_BOOTSTRAP_MK)$@# removed@' "$bad/Makefile"
    expect reject "$bad" "no \$(TOR_BOOTSTRAP_MK) include"

    # 3. ZCL_TOR stops defaulting to full.
    seed "$bad"
    sed -i 's@^ZCL_TOR ?= full$@ZCL_TOR ?= stub@' "$bad/Makefile"
    expect reject "$bad" "ZCL_TOR defaulting to something other than full"

    # 4. The forced-stub release path comes back.
    seed "$bad"
    sed -i 's%ZCL_C23_PORTABLE_RELEASE=1 %ZCL_C23_PORTABLE_RELEASE=1 TOR_FULL= %' \
        "$bad/tools/scripts/build_c23_portable_release.sh"
    expect reject "$bad" "TOR_FULL= forced empty again"

    # 5. ship.sh loses its reach to the refusal.
    seed "$bad"
    sed -i 's/ZCL_TOR_STUB_REFUSAL/SOME_OTHER_MESSAGE/g; s/zcl_tor_require_full/some_other_check/g' \
        "$bad/tools/ship.sh"
    expect reject "$bad" "ship.sh no longer reaching the tor=stub refusal"

    rm -rf "$tmp"
    trap - EXIT HUP INT TERM
    printf '%s selftest: OK\n' "$GATE"
}

main() {
    case "${1:-}" in
        --selftest) run_selftest; exit $? ;;
        "") ;;
        *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
    esac
    if check_root "$ROOT"; then
        printf '%s: PASS — the default build establishes real Tor, the stub needs ZCL_TOR=stub, and %s packaging step(s) carry the exact refusal\n' \
            "$GATE" "$(( ${#REFUSAL_FILES[@]} + ${#REFUSAL_USERS[@]} ))"
        exit 0
    fi
    exit 1
}

main "$@"
