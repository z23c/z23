#!/usr/bin/env bash
# check-standalone-tools-link: every standalone tool binary the Makefile knows
# how to build must actually BUILD.
#
# Why this gate exists. `make lint`, `make test-parallel` and `make ci` between
# them build the node, the test runners, the fuzzers and two lint helpers —
# and nothing else. Every other `$(BIN_DIR)/<tool>` rule in the Makefile was
# unreachable from any gate, so those rules rotted silently: a tool kept
# compiling in the author's head and in no CI anywhere. When lib/base absorbed
# logging and allocation behind forwarding headers, SIX standalone rules broke
# at once (missing -I paths, missing lib/base/src/log_level.c,
# missing lib/platform/src/clock.c) and every gate stayed green for it. That is
# the class this gate closes.
#
# Mechanism: the tool list is DERIVED from the Makefile, never hand-written, so
# a newly added tool is covered the day it lands. Anything the Makefile can
# build and that is not explicitly exempted below must link. The exempt set is
# small, closed, and carries a reason per entry; an unknown tool is NOT
# exempt — this gate is fail-closed by construction.
#
# Cost: the covered tools are single-translation-unit builds. ~6 s warm,
# ~70 s cold, and a no-op once built (make decides).
#
# NOTE — this is the only lint gate that EXECUTES `make`, and that is
# deliberate: a rule's -I paths and object list are only proven by actually
# compiling and linking it, which is exactly what rotted here. Three things
# make the nesting safe under the parallel lint runner: (1) the targets below
# are disjoint from the two binaries `lint:` builds as its own prerequisites
# (core_seal, check_observability_pairing), so nothing is built twice; (2) the
# node, the test runners and the fuzzers are all exempt, so no whole-program
# link is ever triggered from in here; and (3) the gen_templates step that runs
# at Makefile-parse time is content-idempotent (it writes nothing when the
# generated header is unchanged). Keep -j modest — the lint runner is already
# running its own jobs alongside this one.
#
# Mode: WARN | FAIL (controlled by ZCL_LINT_MODE; default FAIL).
set -euo pipefail

MODE="${ZCL_LINT_MODE:-FAIL}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

# ── Exempt set ───────────────────────────────────────────────────────────
# A tool belongs here ONLY if an existing gate already builds it, or building
# it needs something outside the base toolchain. Reason is mandatory.
declare -A EXEMPT=(
    # Already built by `make lint`.
    [gen_templates]="built by every build (TMPL_GEN prerequisite)"
    [core_seal]="built by make lint (check-core-sealed)"
    [check_observability_pairing]="built by make lint (check-observability-pairing)"
    # Already built by `make ci`.
    [fuzz_block]="built by make ci (fuzz-ci)"
    [fuzz_script]="built by make ci (fuzz-ci)"
    [fuzz_p2p]="built by make ci (fuzz-ci)"
    [fuzz_http]="built by make ci (fuzz-ci)"
    [fuzz_compactblock]="built by make ci (fuzz-ci)"
    [fuzz_snapshot]="built by make ci (fuzz-ci)"
    [fuzz_tx_bundle]="built by make ci (fuzz-ci)"
    [fuzz_rom_manifest]="built by make ci (fuzz-ci)"
    # Was MISSING from this list while its eight siblings were exempt, so this
    # gate linked a full libFuzzer+ASan binary on every `make lint` — inside
    # the gate that is already 93% of the umbrella's wall time. It is in
    # FUZZ_TARGETS like the rest, so make ci already builds it.
    [fuzz_overlay]="built by make ci (fuzz-ci)"
    [fuzz_ecdsa]="built by make ci (fuzz-ci)"
    [crash_recovery_test]="built by make ci (test-crash)"
    [zcl-rpc]="built by make ci (test-crash)"
    # The node and the test runners: whole-program relinks, and each is
    # already the direct product of make zclassic23 / test-parallel / ci.
    # The canonical node binary is build/bin/z23 (the zclassic23 symlink
    # exists for compatibility), so both spellings are exempt.
    [zclassic23]="built by make ci and make test-parallel"
    [z23]="built by make ci and make test-parallel (canonical node name)"
    [zclassic23-dev]="dev-profile whole-node relink (make dev)"
    [zclassic23-dev-asan]="sanitizer whole-node relink (make dev-asan)"
    [zclassic23-dev-tsan]="sanitizer whole-node relink (make dev-tsan)"
    [z23-dev]="dev-profile whole-node relink (make dev)"
    [z23-dev-asan]="sanitizer whole-node relink (make dev-asan)"
    [z23-dev-tsan]="sanitizer whole-node relink (make dev-tsan)"
    [test_zcl]="whole-test relink (make test-parallel)"
    [zclassic23-package-verify]="node-profile verifier relink (built by product and CI targets)"
    [zclassic23-package-verify-dev]="dev companion links the whole dev object graph"
    [test_parallel]="built by make test-parallel"
    [test_parallel_fast]="built by make t-fast"
    [test-asan]="sanitizer whole-test relink (make test-asan)"
    [test-tsan]="sanitizer whole-test relink (make test-tsan)"
    [test_zcl_cov]="coverage whole-test relink (make coverage, in make ci)"
    # Too expensive to relink inside a lint gate.
    [session]="whole-node relink over \$(ALL_SRCS) — minutes, not seconds"
    [bot]="whole-node relink over \$(ALL_SRCS) — minutes, not seconds"
    # Outside the base toolchain.
    [zcl-blog]="needs webkit2gtk-4.1 via pkg-config (not a base toolchain dep)"
    [arena_view]="optional raylib GUI; needs raylib via pkg-config (not a base toolchain dep)"
)

# ── Host-bound exemptions (consulted only when building on THAT host) ────
# A tool belongs here when the kernel or runtime primitive underneath it
# simply does not exist here — code-level porting cannot fix a missing OS
# facility. Reason is mandatory and names the missing primitive. On every
# other host the tool keeps being built exactly as before.
declare -A DARWIN_EXEMPT=(
    [zcl-portfwd]="event loop sits on sys/epoll.h (Linux kernel API)"
    [z23-headless-run.exe]="Win32 PE launcher; #include <windows.h> + -municode, and its rule is inside ifeq (\$(ZCL_HOST_WINDOWS),1) so it does not exist on this host"
    [native_ui_driver]="X11 UI transport; links -Wl,-l:libX11.so.6"
    [fuzz_zcode_commons]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_zcode_dht]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_zcode_science]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
)

# ── Windows-only tools (exempt on every host that is NOT Windows) ────────
# The mirror of DARWIN_EXEMPT, and a different mechanism: not "this host is
# missing the primitive underneath the tool", but "on this host the Makefile
# has NO RULE for the target at all". A tool belongs here only when its
# $(BIN_DIR)/<name> rule is written entirely inside
# `ifeq ($(ZCL_HOST_WINDOWS),1)`, whose else arm defines only phony goals that
# print a refusal and fail — so `make build/bin/<name>` on a POSIX host dies
# with "No rule to make target", which is not a rotted rule and cannot be
# fixed by an -I path. Reason is mandatory and must name that guard.
#
# ⛔ AN EXEMPTION WITH NO REPLACEMENT CHECK IS EXACTLY THE ROT THIS GATE
# EXISTS TO STOP. So this table is not a pass on its own: each entry also
# names, in COVER below, the source file that some OTHER gate must still
# compile on THIS host, and the exemption is refused (exit 2, not a quiet
# skip) the moment that coverage stops being real. The exemption and its
# replacement stand or fall together.
declare -A WINDOWS_ONLY_EXEMPT=(
    [z23-headless-run.exe]="rule body lives only inside ifeq (\$(ZCL_HOST_WINDOWS),1); the else arm defines no \$(BIN_DIR) target, so make has no rule for it on a POSIX host — covered instead by check-windows-acceptance, which mingw-cross-links the source (see COVER)"
)

# tool name -> "<catalog row name> <source path>": the windows-acceptance row
# that must still cross-compile the tool's source on this host, so
# `make check-windows-acceptance` keeps proving what the native Makefile rule
# cannot prove here. Verified below against the catalog file itself.
declare -A WINDOWS_ONLY_COVER=(
    [z23-headless-run.exe]="headless_run tools/dev/windows_headless_run.c"
)
WINDOWS_ACCEPTANCE_CATALOG="lib/platform/tests/windows_acceptance.mk"

# Is <src> still cross-compiled by catalog row <row>? BOTH halves are checked,
# because either one alone can be true while nothing gets compiled:
#   - a ZCL_WINDOWS_ACCEPTANCE_<row>_SOURCES row whose name is missing from
#     ZCL_WINDOWS_ACCEPTANCE_TESTS generates no make rule at all, so the row is
#     inert and the source is read by nothing;
#   - a name in TESTS whose row no longer lists <src> compiles something else
#     and still reports PASS.
#
# ⛔ COMMENT LINES ARE STRIPPED FIRST, and that is not tidiness. The catalog
# documents this very coupling in prose that spells out the exact path being
# searched for. A plain substring match over the whole file therefore reported
# "replacement check CONFIRMED" off its own documentation, with the real
# SOURCES row pointed at a different file — observed while building this
# check. Only assignment lines count.
windows_acceptance_covers() {
    local catalog="$1" row="$2" src="$3" listed sources
    local nl=$'\n'
    local awk_collect='
        /^[ \t]*#/ { next }
        {
            line = $0
            if ($0 ~ start) { inrow = 1; sub(/^[^:]*:=/, "", line) }
            else if (!inrow) { next }
            cont = (line ~ /\\[ \t]*$/)
            gsub(/\\[ \t]*$/, "", line)
            n = split(line, p, /[ \t]+/)
            for (i = 1; i <= n; i++) if (p[i] != "") print p[i]
            if (!cont) inrow = 0
        }'
    listed="$(LC_ALL=C awk -v start='^ZCL_WINDOWS_ACCEPTANCE_TESTS[ \t]*:=' \
                  "$awk_collect" "$catalog")"
    sources="$(LC_ALL=C awk \
                  -v start="^ZCL_WINDOWS_ACCEPTANCE_${row}_SOURCES[ \t]*:=" \
                  "$awk_collect" "$catalog")"
    # Pipeline-free membership (never `printf | grep -q`: grep -q exits at the
    # first match, printf takes SIGPIPE, and pipefail then reports 141 — a HIT
    # reading as a MISS. Same rule as tools/scripts/sh_str.sh).
    case "${nl}${listed}${nl}" in *"${nl}${row}${nl}"*) ;; *) return 1 ;; esac
    case "${nl}${sources}${nl}" in *"${nl}${src}${nl}"*) ;; *) return 2 ;; esac
    return 0
}

# ── Derive the tool list from the Makefile ───────────────────────────────
# Two rule spellings carry a standalone tool:
#   $(BIN_DIR)/<name>:  ...
#   $(SOME_BIN):        ...   where  SOME_BIN = $(BIN_DIR)/<name>
declare -A TOOLS=()

while IFS= read -r name; do
    [[ -n "$name" ]] && TOOLS["$name"]=1
done < <(gate_grep -oE '^\$\(BIN_DIR\)/[a-zA-Z_0-9.-]+:' Makefile \
         | sed 's|^\$(BIN_DIR)/||; s|:$||' || true)

while IFS= read -r var; do
    [[ -n "$var" ]] || continue
    # Resolve `VAR = $(BIN_DIR)/<name>` (first definition wins).
    resolved=$(gate_grep -m1 -E "^${var}[[:space:]]*=[[:space:]]*\\\$\(BIN_DIR\)/" Makefile \
               | sed 's|.*\$(BIN_DIR)/||; s|[[:space:]]*$||' || true)
    [[ -n "$resolved" ]] || continue
    # Skip per-epoch CANDIDATE paths: they carry an unexpanded $(...) epoch
    # hash and a subdirectory, and are staging outputs of the promoted
    # binaries above, not separately-authored tools.
    [[ "$resolved" == *'$('* || "$resolved" == */* ]] && continue
    TOOLS["$resolved"]=1
done < <(gate_grep -oE '^\$\([A-Z_0-9]+\):' Makefile | sed 's|^\$(||; s|):$||' || true)

gate_require_scanned "${#TOOLS[@]}" 20 check-standalone-tools-link \
    "no \$(BIN_DIR)/<tool> rules found in Makefile — did the rule spelling change?"

# ── Partition into covered vs must-build ─────────────────────────────────
GATE_HOST_OS="$(uname -s 2>/dev/null)"
targets=()
for name in $(printf '%s\n' "${!TOOLS[@]}" | sort); do
    # A bare non-windows exemption used to sit here. It skipped the tool on
    # sight, with no check that anything still compiled the source — the exact
    # fail-open this gate exists to prevent. The WINDOWS_ONLY_EXEMPT block
    # below does the same skip, but only after confirming the replacement
    # check is real, and refuses outright when it is not.
    if [[ "$GATE_HOST_OS" == Darwin && -n "${DARWIN_EXEMPT[$name]:-}" ]]; then
        echo "[check_standalone_tools_link] darwin-exempt $name: ${DARWIN_EXEMPT[$name]}" >&2
        continue
    fi
    # Windows-only tools: skipped everywhere the Makefile writes no rule for
    # them, i.e. every host that is not MSYS/MinGW (Makefile line 28 spells
    # ZCL_HOST_WINDOWS as `filter MINGW% MSYS%` over uname -s, and this must
    # agree with it — on a real Windows host the rule EXISTS and the tool is
    # built like any other, no exemption).
    if [[ -n "${WINDOWS_ONLY_EXEMPT[$name]:-}" \
          && "$GATE_HOST_OS" != MINGW* && "$GATE_HOST_OS" != MSYS* ]]; then
        cover="${WINDOWS_ONLY_COVER[$name]:-}"
        cover_row="${cover%% *}"
        cover_src="${cover##* }"
        # Fail-closed, both ways. No COVER entry, no catalog on disk, or a
        # catalog that has stopped naming the source = the replacement check
        # is gone and the exemption is now pure rot. That is exit 2 (a broken
        # gate), never a skip, and never a silent build attempt either.
        if [[ -z "$cover" || "$cover_row" == "$cover_src" ]]; then
            echo "check-standalone-tools-link: FATAL — $name is in" >&2
            echo "  WINDOWS_ONLY_EXEMPT with no usable WINDOWS_ONLY_COVER" >&2
            echo "  entry (expected \"<catalog row> <source path>\")." >&2
            echo "  An exemption with no named replacement check is the rot" >&2
            echo "  this gate exists to stop. Name the source another gate" >&2
            echo "  still compiles, or delete the exemption." >&2
            exit 2
        fi
        if [[ ! -f "$WINDOWS_ACCEPTANCE_CATALOG" ]]; then
            echo "check-standalone-tools-link: FATAL — the windows acceptance" >&2
            echo "  catalog $WINDOWS_ACCEPTANCE_CATALOG is missing, so the" >&2
            echo "  replacement check backing the $name exemption cannot be" >&2
            echo "  confirmed to exist. Refusing to skip on an unproven claim." >&2
            exit 2
        fi
        windows_acceptance_covers \
            "$WINDOWS_ACCEPTANCE_CATALOG" "$cover_row" "$cover_src" || cover_rc=$?
        cover_rc="${cover_rc:-0}"
        if (( cover_rc != 0 )); then
            echo "check-standalone-tools-link: FATAL — $name is exempt here" >&2
            echo "  because $WINDOWS_ACCEPTANCE_CATALOG was supposed to keep" >&2
            echo "  cross-compiling $cover_src for Windows as row" >&2
            echo "  '$cover_row', and it no longer does:" >&2
            if (( cover_rc == 1 )); then
                echo "    '$cover_row' is not in ZCL_WINDOWS_ACCEPTANCE_TESTS," >&2
                echo "    so no make rule is generated and the SOURCES row is" >&2
                echo "    inert — nothing compiles it." >&2
            else
                echo "    ZCL_WINDOWS_ACCEPTANCE_${cover_row}_SOURCES does not" >&2
                echo "    name $cover_src (comment mentions do not count)." >&2
            fi
            echo "  The exemption has outlived its replacement check: nothing" >&2
            echo "  on this host compiles that source any more, which is the" >&2
            echo "  silent rot this gate exists to stop. Restore the catalog" >&2
            echo "  row, or drop the exemption and give the tool a rule make" >&2
            echo "  can build here." >&2
            exit 2
        fi
        unset cover_rc
        echo "[check_standalone_tools_link] windows-only-exempt $name:" \
             "${WINDOWS_ONLY_EXEMPT[$name]}" >&2
        echo "[check_standalone_tools_link]   replacement check CONFIRMED:" \
             "$WINDOWS_ACCEPTANCE_CATALOG row '$cover_row' cross-compiles" \
             "$cover_src (make check-windows-acceptance)" >&2
        continue
    fi
    targets+=("build/bin/$name")
done

# Floor well above 1: the failure mode this guards is the exempt set quietly
# growing until the gate builds almost nothing while still reporting clean.
# 18 tools are covered today; anything under 10 means exemptions have eaten it.
gate_require_scanned "${#targets[@]}" 10 check-standalone-tools-link \
    "the exempt set has swallowed the gate — it is no longer proving anything"

echo "[check_standalone_tools_link] ${#TOOLS[@]} tool rule(s) in Makefile;" \
     "${#EXEMPT[@]} exempt; building ${#targets[@]}"

# ── Build them ───────────────────────────────────────────────────────────
# Each target is its own single-TU link; make no-ops the already-built ones.
violations=0
failed=()
build_log=$(mktemp)
trap 'rm -f "$build_log"' EXIT

# Parallelism. MEASURED, not guessed: this one gate was 191 s of a 199 s lint
# wall on a 32-core host (the other 136 gates finished inside its shadow), and
# it is cold on every push that touches the Makefile or a shared lib source.
# The targets are independent single-TU links, so the work scales with -j. Half
# the host, capped, leaves room for the lint driver's own workers running
# alongside. Override with ZCL_TOOLS_LINK_JOBS=<n>.
tl_nproc="$(nproc 2>/dev/null || echo 4)"
tl_jobs="${ZCL_TOOLS_LINK_JOBS:-$(( tl_nproc / 2 ))}"
if [ "$tl_jobs" -lt 4 ];  then tl_jobs=4;  fi
if [ "$tl_jobs" -gt 16 ]; then tl_jobs=16; fi

if ! make -j"$tl_jobs" --no-print-directory "${targets[@]}" >"$build_log" 2>&1; then
    # Re-probe serially so the report names every broken tool, not just the
    # one that happened to lose the race to fail first.
    for t in "${targets[@]}"; do
        if ! make --no-print-directory "$t" >/dev/null 2>&1; then
            failed+=("$t")
            violations=$((violations + 1))
        fi
    done
fi

if (( violations > 0 )); then
    echo "[check_standalone_tools_link] BUILD OUTPUT (first failure):"
    tail -n 30 "$build_log" | sed 's/^/    /'
    echo "[check_standalone_tools_link] tool target(s) that do not build:"
    for t in "${failed[@]}"; do echo "    $t"; done
fi

echo "[check_standalone_tools_link] $violations violation(s) found (mode: $MODE)"
echo "[check_standalone_tools_link] a Makefile tool rule that nothing else"
echo "[check_standalone_tools_link] builds rots silently — fix the rule's -I"
echo "[check_standalone_tools_link] paths / object list, or add the tool to the"
echo "[check_standalone_tools_link] EXEMPT set in this script WITH a reason."

if (( violations > 0 )) && [[ "$MODE" == "FAIL" ]]; then
    exit 1
fi
exit 0
