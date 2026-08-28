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
    [native_ui_driver]="X11 UI transport; links -Wl,-l:libX11.so.6"
    [fuzz_zcode_commons]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_zcode_dht]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_zcode_science]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
)

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
    [[ -n "${EXEMPT[$name]:-}" ]] && continue
    if [[ "$GATE_HOST_OS" == Darwin && -n "${DARWIN_EXEMPT[$name]:-}" ]]; then
        echo "[check_standalone_tools_link] darwin-exempt $name: ${DARWIN_EXEMPT[$name]}" >&2
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
