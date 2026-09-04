#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_macos_acceptance.sh — run the STATIC half of the macOS acceptance
# script under `make lint`, and say UNOBSERVED, in that word, about the half
# that needs an Apple host.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# tools/scripts/macos_acceptance.sh has existed since the macOS port landed and
# nothing ran it. Its only reference in the whole tree was the recipe of the
# `macos-acceptance` Make target, which is a target a Linux box never invokes
# because its --run mode refuses on a non-Darwin host. It was in none of the
# four places a lint gate has to be wired (the gate_command() case table in
# tools/lint/run_lint.sh, LINT_GATES + a recipe + .PHONY in Makefile, the
# LINT-GATES block in docs/DEFENSIVE_CODING.md, and tools/lint/lint_cache.sh),
# so `make lint` never touched it. A script nobody runs is a script that is
# already wrong and has not been told.
#
# ── WHAT IS ACTUALLY CHECKED HERE, AND WHAT IS NOT ──────────────────────────
# The script has two modes and only one of them needs an Apple machine:
#
#   --check   Pure text. It reads engine/composition/platform/macos_capabilities.def and
#             asserts: the capability SET has not drifted from the validator's
#             closed list; every row carries one of the three legal states
#             (available / degraded / unavailable); every row carries a typed
#             reason code; and every evidence group a row names is a group
#             REGISTERED in tools/dev/test_group_catalog.def. Nothing here
#             touches Darwin, an SDK, or a compiler. It goes red on this box
#             the moment somebody adds a capability without evidence, points a
#             row at a test group that was renamed or deleted, or quietly
#             promotes an `unavailable` row to `available` while renaming it.
#             THAT is the gate, and it is a real one.
#
#   --run     Builds and executes the exact test groups the matrix derives,
#             then cuts, audits, checksums, and executes the node-free guide
#             from the real temporary darwin-arm64 runtime package. It refuses
#             unless `uname -s` is Darwin and `uname -m` is arm64. It cannot
#             run here and this gate does not pretend to.
#
# So this gate runs --check for real and reports --run as UNOBSERVED. It never
# prints a pass for the native leg. A gate that always passes is worse than no
# gate: it manufactures confidence. The honest deliverable on a Linux box is
# "the matrix is well-formed and every claim in it is backed by a registered
# test group; nobody here has watched those tests run on a Mac", and that is
# what it prints.
#
# ── WHY NOT RUN --run WHEN THE HOST *IS* DARWIN ─────────────────────────────
# Deliberate. --run builds and executes the derived test groups; `make lint` is the
# static pass and must stay seconds, not minutes. On an Apple host the native
# leg is `make macos-acceptance`, and this gate names that command in its
# UNOBSERVED line rather than silently doing something a lint run should not.
#
# Usage:
#   tools/lint/check_macos_acceptance.sh             # the gate
#   tools/lint/check_macos_acceptance.sh --self-test # prove it can go red
#
# Exit: 0 clean (the --check leg really ran); 1 on a malformed/unbacked
# capability matrix; 2 when the script, the matrix or the catalog is missing.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# str_contains / str_lacks: `printf | grep -q` under pipefail returns 141 on a
# MATCH once the payload exceeds the pipe buffer, inverting the decision.
# shellcheck source=tools/scripts/sh_str.sh
. tools/scripts/sh_str.sh

GATE="check-macos-acceptance"
ACCEPT="tools/scripts/macos_acceptance.sh"
MATRIX="engine/composition/platform/macos_capabilities.def"
CATALOG="tools/dev/test_group_catalog.def"
RELEASE_CUTTER="platform/packaging/release/build_release.sh"
# The union is a closed acceptance contract: 33 capability-evidence groups
# plus eight required platform-baseline groups.  A floor would miss deletions.
EXPECTED_GROUPS=41

macos_make_target_reachable() {
    local makefile="${1:-Makefile}"
    awk '
        /^macos-acceptance:[[:space:]]+z23[[:space:]]+zclassic23-package-verify[[:space:]]+zclassic23-acme[[:space:]]*$/ {
            in_target = 1
            next
        }
        in_target && /^\t@?\.\/tools\/scripts\/macos_acceptance\.sh --run[[:space:]]*$/ {
            found = 1
            next
        }
        in_target && /^[^[:space:]#][^:]*:/ { in_target = 0 }
        END { exit(found ? 0 : 1) }
    ' "$makefile"
}

macos_runtime_package_reachable() {
    local accept="${1:-$ACCEPT}"
    grep -Fq '"$REPO_ROOT/platform/packaging/release/build_release.sh" --bin "$REPO_ROOT/build/bin" --out "$package_root/runtime" --platform darwin-arm64' "$accept" &&
        grep -Fq '"$package_root/runtime/z23" code guide >"$package_root/code-guide.json"' "$accept"
}

check_root() {
    local out rc groups group_n

    for f in "$ACCEPT" "$MATRIX" "$CATALOG" "$RELEASE_CUTTER"; do
        if [ ! -f "$f" ]; then
            echo "$GATE: FATAL — missing $f." >&2
            echo "  This gate is a thin driver over $ACCEPT;" >&2
            echo "  with any of its four inputs gone there is nothing to check and" >&2
            echo "  a silent pass would be a lie." >&2
            return 2
        fi
    done
    if [ ! -x "$ACCEPT" ]; then
        echo "$GATE: FATAL — $ACCEPT is not executable." >&2
        return 2
    fi

    # ── Leg 1: the static matrix check. This is the part that can go red. ──
    out="$("$ACCEPT" --check 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "  $GATE: FAIL — the macOS capability matrix does not validate:" >&2
        printf '%s\n' "$out" | sed 's/^/    /' >&2
        echo "" >&2
        echo "  $MATRIX is the closed, declarative truth about what this product" >&2
        echo "  does and does not do on darwin-arm64. Every row must name a legal" >&2
        echo "  state, a typed reason code, and at least one REGISTERED test group" >&2
        echo "  that proves the claim (an 'unavailable' row proves its refusal" >&2
        echo "  path; that still counts as evidence). Fix the row, or register" >&2
        echo "  the group in $CATALOG — do not delete the evidence field." >&2
        return 1
    fi

    # ── Leg 1b: the derived evidence union is exact, not merely nonempty. ──
    groups="$("$ACCEPT" --groups 2>/dev/null)"
    group_n="$(printf '%s' "$groups" | tr ',' '\n' | grep -c . || true)"
    if [ "${group_n:-0}" -ne "$EXPECTED_GROUPS" ]; then
        echo "  $GATE: FAIL — expected $EXPECTED_GROUPS exact macOS groups; derived ${group_n:-0}." >&2
        echo "  The capability evidence and required platform baseline form a" >&2
        echo "  closed union; deletion must not degrade into a smaller pass." >&2
        return 1
    fi

    # ── Leg 1c: the Make target must still reach the script. ───────────────
    # The whole reason this gate exists is that the script had exactly one
    # reference in the tree. If the recipe stops naming it, the native leg is
    # unreachable again and only this line would notice.
    if ! macos_make_target_reachable Makefile; then
        echo "  $GATE: FAIL — macos-acceptance does not depend on the complete" >&2
        echo "  darwin-arm64 runtime member set" >&2
        echo "  whose recipe invokes $ACCEPT --run." >&2
        echo "  The native (Darwin) leg is then unreachable from any command a" >&2
        echo "  person would type. Restore the exact 'macos-acceptance: z23" >&2
        echo "  zclassic23-package-verify zclassic23-acme' target and its tabbed" >&2
        echo "  acceptance recipe." >&2
        return 1
    fi
    if ! grep -Fq 'ONLY="$groups" EXACT_ONLY_MATCHED="$groups"' "$ACCEPT"; then
        echo "  $GATE: FAIL — $ACCEPT does not bind its derived union equally" >&2
        echo "  to t-fast-exact's parse guard and exact selector; the native" >&2
        echo "  target could validate 38 groups while executing an empty set." >&2
        return 1
    fi
    if ! macos_runtime_package_reachable "$ACCEPT"; then
        echo "  $GATE: FAIL — $ACCEPT does not cut and execute the real" >&2
        echo "  temporary darwin-arm64 runtime after its exact test verdict." >&2
        echo "  Restore the canonical build_release.sh invocation and packaged" >&2
        echo "  'z23 code guide' execution; source-test binaries alone do not" >&2
        echo "  prove that the bytes a Mac user receives are acceptable." >&2
        return 1
    fi

    printf '%s\n' "$out" | sed 's/^/  /'
    echo "  $GATE: OK — capability matrix validates; ${group_n} evidence group(s), every one registered."

    # ── Leg 2: the native run. Never claimed, always named. ────────────────
    local host_os host_arch
    host_os="$(uname -s 2>/dev/null || echo unknown)"
    host_arch="$(uname -m 2>/dev/null || echo unknown)"
    echo "  $GATE: UNOBSERVED — the native leg (${group_n} exact groups plus an"
    echo "  audited/checksummed temporary runtime cut and packaged-node execution on"
    echo "  darwin-arm64) did NOT run here; this host is ${host_os}/${host_arch}."
    if [ "$host_os" = "Darwin" ] && [ "$host_arch" = "arm64" ]; then
        echo "  This host CAN run it, and lint deliberately does not: it builds and"
        echo "  executes the derived test groups. Run 'make macos-acceptance'."
    else
        echo "  UNOBSERVED is not a pass. It is a leg no machine in this run could"
        echo "  observe. Run 'make macos-acceptance' on a darwin-arm64 host to"
        echo "  close it."
    fi
    return 0
}

# ── Self-test ───────────────────────────────────────────────────────────────
# Every case plants a throwaway capability matrix OUTSIDE the repo and points
# the real script at it through ZCL_MACOS_CAPABILITY_MATRIX, so the code under
# test is the shipped script and not a mock of it.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

expect_reject() {
    local label="$1" needle="$2" fixture="$3" out rc
    out="$(ZCL_MACOS_CAPABILITY_MATRIX="$fixture" "$ACCEPT" --check 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $label — expected rejection, got a PASS."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if str_lacks "$out" "$needle"; then
        echo "SELFTEST FAIL: $label — rejected, but never named '$needle'."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

expect_accept() {
    local label="$1" fixture="$2" out rc
    out="$(ZCL_MACOS_CAPABILITY_MATRIX="$fixture" "$ACCEPT" --check 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "SELFTEST FAIL: $label — expected a PASS, got rejection."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

expect_make_reject() {
    local label="$1" fixture="$2"
    if macos_make_target_reachable "$fixture"; then
        echo "SELFTEST FAIL: $label — malformed Make target was accepted."
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

expect_package_reject() {
    local label="$1" fixture="$2"
    if macos_runtime_package_reachable "$fixture"; then
        echo "SELFTEST FAIL: $label — incomplete package acceptance was accepted."
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

run_selftest() {
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zcl-macos-acceptance-selftest.XXXXXX")" || return 2
    trap selftest_cleanup EXIT
    local rc=0

    echo "══ $GATE selftest ══"

    # Positive control first: a byte copy of the real matrix must PASS, so
    # none of the rejections below can be an unconditional failure.
    cp "$MATRIX" "$FIXTURE_ROOT/clean.def"
    expect_accept "0: a copy of the real matrix passes (positive control)" \
                  "$FIXTURE_ROOT/clean.def" || rc=1

    # A. An illegal state.
    sed 's/^ZCL_MACOS_CAPABILITY(tor, available,/ZCL_MACOS_CAPABILITY(tor, probably,/' \
        "$MATRIX" > "$FIXTURE_ROOT/state.def"
    expect_reject "A: an illegal capability state is caught" \
                  "invalid state" "$FIXTURE_ROOT/state.def" || rc=1

    # B. Evidence that names a group nobody registered — the shape a rename or
    #    deletion of a test group leaves behind.
    sed 's/test_tor)/test_tor_group_that_does_not_exist)/' \
        "$MATRIX" > "$FIXTURE_ROOT/group.def"
    expect_reject "B: a capability naming an unregistered test group is caught" \
                  "unregistered group" "$FIXTURE_ROOT/group.def" || rc=1

    # B2. The same defect in a NON-last position. B alone would pass even with
    #     the trailing-newline bug this gate's first run found in the script
    #     (the loop dropped the LAST group of every row); together the two
    #     cases pin both ends of the evidence list.
    sed 's/test_noise_nk_handshake,/test_noise_group_that_does_not_exist,/' \
        "$MATRIX" > "$FIXTURE_ROOT/group_first.def"
    expect_reject "B2: an unregistered group in a non-last position is caught" \
                  "unregistered group" "$FIXTURE_ROOT/group_first.def" || rc=1

    # C. A capability with no typed reason code.
    sed 's/^ZCL_MACOS_CAPABILITY(tor, available, embedded_full_tor_when_archive_present,/ZCL_MACOS_CAPABILITY(tor, available, ,/' \
        "$MATRIX" > "$FIXTURE_ROOT/reason.def"
    expect_reject "C: a capability with no typed reason is caught" \
                  "no typed reason" "$FIXTURE_ROOT/reason.def" || rc=1

    # D. The closed capability set drifting — a row silently renamed.
    sed 's/^ZCL_MACOS_CAPABILITY(tor,/ZCL_MACOS_CAPABILITY(onion,/' \
        "$MATRIX" > "$FIXTURE_ROOT/drift.def"
    expect_reject "D: drift in the closed capability set is caught" \
                  "capability set drift" "$FIXTURE_ROOT/drift.def" || rc=1

    # E. An empty matrix must REFUSE, never pass vacuously. This is the
    #    direction that matters most: a gate that can see nothing must not
    #    report clean.
    printf '/* no rows */\n' > "$FIXTURE_ROOT/empty.def"
    expect_reject "E: an empty capability matrix fails closed" \
                  "no rows" "$FIXTURE_ROOT/empty.def" || rc=1

    # F. A missing matrix file must REFUSE.
    expect_reject "F: a missing capability matrix fails closed" \
                  "missing capability matrix" "$FIXTURE_ROOT/not_here.def" || rc=1

    # G. Removing one of the eight required baseline groups must fail even
    #    though every remaining group is registered and the capability rows
    #    are otherwise untouched.
    sed '/^ZCL_MACOS_REQUIRED_TEST(test_crypto)$/d' \
        "$MATRIX" > "$FIXTURE_ROOT/required_deleted.def"
    expect_reject "G: deletion from the required baseline is caught" \
                  "required test set drift" "$FIXTURE_ROOT/required_deleted.def" || rc=1

    # H. The required set is subject to the same registration authority as
    #    capability evidence.
    sed 's/^ZCL_MACOS_REQUIRED_TEST(test_crypto)$/ZCL_MACOS_REQUIRED_TEST(test_macos_group_that_does_not_exist)/' \
        "$MATRIX" > "$FIXTURE_ROOT/required_unknown.def"
    expect_reject "H: an unknown required group is caught" \
                  "unregistered group" "$FIXTURE_ROOT/required_unknown.def" || rc=1

    # I. Count equality is insufficient: replacing a required group with a
    #    different, registered group must still violate the exact set.
    sed 's/^ZCL_MACOS_REQUIRED_TEST(test_crypto)$/ZCL_MACOS_REQUIRED_TEST(test_json)/' \
        "$MATRIX" > "$FIXTURE_ROOT/required_exact_set.def"
    expect_reject "I: a same-size registered mutation violates the exact set" \
                  "required test set drift" "$FIXTURE_ROOT/required_exact_set.def" || rc=1

    # J. The capability-evidence half of the union is exact too. Replacing Tor
    #    evidence with an unrelated but registered group preserves the count;
    #    only a full-set comparison catches the weakened claim.
    sed 's/test_tor)/test_json)/' \
        "$MATRIX" > "$FIXTURE_ROOT/capability_exact_set.def"
    expect_reject "J: same-size registered capability evidence drift is caught" \
                  "exact evidence set drift" "$FIXTURE_ROOT/capability_exact_set.def" || rc=1

    # K/L. Legal state words and nonempty reason codes are not sufficient for
    # the two confinement rows: the public matrix must preserve qualified
    # Seatbelt package execution without promoting resident-node confinement.
    sed 's/^ZCL_MACOS_CAPABILITY(package_execution, available,/ZCL_MACOS_CAPABILITY(package_execution, degraded,/' \
        "$MATRIX" > "$FIXTURE_ROOT/package_state.def"
    expect_reject "K: a legal Seatbelt package downgrade is caught" \
                  "package_execution contract drift" "$FIXTURE_ROOT/package_state.def" || rc=1
    sed 's/^ZCL_MACOS_CAPABILITY(resident_confinement, unavailable,/ZCL_MACOS_CAPABILITY(resident_confinement, available,/' \
        "$MATRIX" > "$FIXTURE_ROOT/resident_state.def"
    expect_reject "L: Seatbelt cannot promote resident confinement" \
                  "resident_confinement contract drift" "$FIXTURE_ROOT/resident_state.def" || rc=1

    # M/N. Reassigning registered evidence while preserving the global union
    # must not sever a claim from the tests that actually prove it.
    sed -e 's/test_boot_shutdown_marker_persistence,test_net,test_rpc/test_boot_shutdown_marker_persistence,test_platform_toolchain,test_rpc/' \
        -e 's/test_os_sandbox,test_platform_toolchain,test_sandbox_process_budget,test_zcode_verify/test_os_sandbox,test_net,test_sandbox_process_budget,test_zcode_verify/' \
        "$MATRIX" > "$FIXTURE_ROOT/package_groups.def"
    expect_reject "M: package evidence reassignment is caught" \
                  "package_execution contract drift" "$FIXTURE_ROOT/package_groups.def" || rc=1
    sed -e 's/test_boot_shutdown_marker_persistence,test_net,test_rpc/test_boot_shutdown_marker_persistence,test_net,test_confine/' \
        -e 's/test_os_sandbox,test_confine)/test_os_sandbox,test_rpc)/' \
        "$MATRIX" > "$FIXTURE_ROOT/resident_groups.def"
    expect_reject "N: resident evidence reassignment is caught" \
                  "resident_confinement contract drift" "$FIXTURE_ROOT/resident_groups.def" || rc=1

    # O/P. A comment mentioning the script must not keep the reachability
    # check green after either the real recipe or its public-binary dependency
    # disappears.
    sed '\#^[[:space:]]*@\./tools/scripts/macos_acceptance\.sh --run[[:space:]]*$#d' \
        Makefile > "$FIXTURE_ROOT/make_no_recipe"
    expect_make_reject "O: deleting the native recipe is caught" \
                       "$FIXTURE_ROOT/make_no_recipe" || rc=1
    sed 's/^macos-acceptance: z23 zclassic23-package-verify zclassic23-acme$/macos-acceptance: z23/' \
        Makefile > "$FIXTURE_ROOT/make_no_z23"
    expect_make_reject "P: deleting release-member prerequisites is caught" \
                       "$FIXTURE_ROOT/make_no_z23" || rc=1

    # Q/R. Passing source tests is insufficient when either the canonical
    # runtime cut or execution of its stripped node can silently disappear.
    grep -Fv 'build_release.sh" --bin' "$ACCEPT" > "$FIXTURE_ROOT/no_package_cut.sh"
    expect_package_reject "Q: deleting the canonical runtime cut is caught" \
                          "$FIXTURE_ROOT/no_package_cut.sh" || rc=1
    grep -Fv 'runtime/z23" code guide' "$ACCEPT" > "$FIXTURE_ROOT/no_package_exec.sh"
    expect_package_reject "R: deleting packaged-node execution is caught" \
                          "$FIXTURE_ROOT/no_package_exec.sh" || rc=1

    if [ "$rc" -eq 0 ]; then
        echo "══ selftest: PASS (20/20) ══"
    else
        echo "══ selftest: FAIL ══"
    fi
    return "$rc"
}

case "${1:-}" in
    --self-test) run_selftest; exit $? ;;
    "")          echo "══ LINT: macOS acceptance (capability matrix + evidence registration) ══"
                 check_root; exit $? ;;
    *)           echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
