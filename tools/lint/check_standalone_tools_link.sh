#!/usr/bin/env bash
# check-standalone-tools-link: every standalone tool binary the Makefile knows
# how to build must actually BUILD.
#
# Why this gate exists. `make lint`, `make test-parallel` and `make ci` between
# them build the node, the test runners, the fuzzers and two lint helpers —
# and nothing else. Every other `$(BIN_DIR)/<tool>` rule in the Makefile was
# unreachable from any gate, so those rules rotted silently: a tool kept
# compiling in the author's head and in no CI anywhere. When platform/modules/base absorbed
# logging and allocation behind forwarding headers, SIX standalone rules broke
# at once (missing -I paths, missing platform/modules/base/src/log_level.c,
# missing platform/modules/platform/src/clock.c) and every gate stayed green for it. That is
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

# --build-only: link every covered tool and stop — no verdict, no self-test,
# no prose. A landing proof runs this before it forks its lint and test
# dimensions, because this gate's nested `make` is the one thing in the lint
# dimension that relinks binaries the test dimension is reading. Deriving the
# tool list twice is how the two would drift, so the pre-build calls the gate
# that owns the derivation and asks it for the build alone; the gate still
# adjudicates, in full, inside the lint dimension where it belongs.
BUILD_ONLY=0
LIST_TARGETS=0
if [ "$#" -gt 0 ]; then
    for arg in "$@"; do
        case "$arg" in
            --build-only) BUILD_ONLY=1 ;;
            --list-targets) LIST_TARGETS=1 ;;
            *)
                echo "check-standalone-tools-link: unknown argument '$arg'" >&2
                exit 2
                ;;
        esac
    done
fi
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
    [zclassic23-dev-asan]="sanitizer whole-node relink (make dev-asan)"
    [zclassic23-dev-tsan]="sanitizer whole-node relink (make dev-tsan)"
    [z23-dev-asan]="sanitizer whole-node relink (make dev-asan)"
    [z23-dev-tsan]="sanitizer whole-node relink (make dev-tsan)"
    [test_zcl]="whole-test relink (make test-parallel)"
    [z23-package-verify]="node-profile verifier relink (built by product and CI targets)"
    [z23-package-verify-dev]="dev companion links the whole dev object graph"
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
    [z23-clang-manifest]="optional semantic sensor; needs libclang's C API (libclang-NN-dev, not a base toolchain dep)"
)

# ── Host-bound exemptions (consulted only when building on THAT host) ────
# A tool belongs here when the kernel or runtime primitive underneath it
# simply does not exist here — code-level porting cannot fix a missing OS
# facility. Reason is mandatory and names the missing primitive. On every
# other host the tool keeps being built exactly as before.
declare -A DARWIN_EXEMPT=(
    [tunnel-static]="Linux ELF static-PIE artifact; native Mach-O tunnel remains required"
    [zcl-portfwd]="event loop sits on sys/epoll.h (Linux kernel API)"
    [z23-headless-run.exe]="Win32 PE launcher; #include <windows.h> + -municode, and its rule is inside ifeq (\$(ZCL_HOST_WINDOWS),1) so it does not exist on this host"
    [native_ui_driver]="X11 UI transport; links -Wl,-l:libX11.so.6"
    [fuzz_zcode_commons]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_zcode_dht]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_zcode_science]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_mesh_status_proto]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
    [fuzz_semantic_manifest]="host lacks libclang_rt.fuzzer_osx.a (standalone CLT ships no libFuzzer runtime)"
)

# A missing X11 runtime can excuse only the link, never the strict compile.
# Derive the command from the actual Make rule so compiler wrappers, command
# line overrides, platform flags and future rule changes cannot silently drift.
# Status: 0 = linkable, 1 = confirmed absent with strict object coverage,
# 2 = unproven (temporary storage, compiler, recipe or other linker failure).
x11_runtime_linkable() (
    local dir recipe flags missing=0 line
    dir="$(mktemp -d "${TMPDIR:-/tmp}/zcl-x11-probe.XXXXXX")" || return 2
    trap 'rm -rf -- "$dir"' EXIT
    recipe="$(awk '
        /^\$\(NATIVE_UI_DRIVER_BIN\):/ { rule=1; next }
        rule && /^\t/ {
            if ($0 ~ /^\t\$\(CC\)/) command=1
            if (command) { sub(/^\t[ \t]*/, ""); print }
            next
        }
        rule { exit }
    ' Makefile)" || return 2
    # Refuse unfamiliar recipes instead of approximating their strictness.
    recipe="${recipe//$'\\\n'/ }"
    [[ "$recipe" == '$(CC) '* &&
       "$recipe" == *' -o $@ $< -Wl,-l:libX11.so.6' ]] || return 2
    flags="${recipe%' -o $@ $< -Wl,-l:libX11.so.6'}"
    # Native execution validates the selected compiler's target as well as
    # its ability to compile and link without X11. DISPLAY is never consulted.
    printf '#ifndef __linux__\n#error native Linux compiler required\n#endif\nint main(void){return 0;}\n' > "$dir/probe.c" || return 2
    {
        printf '.PHONY: zcl-x11-baseline zcl-x11-cover\n'
        printf 'zcl-x11-baseline:\n'
        printf '\t%s -o "$$z23_x11_probe_dir/probe" "$$z23_x11_probe_dir/probe.c" && printf ok >"$$z23_x11_probe_dir/compiled" || exit 1\n' "$flags"
        printf '\t"$$z23_x11_probe_dir/probe" && printf ok >"$$z23_x11_probe_dir/ran" || exit 1\n'
        printf '\t@if %s -o "$$z23_x11_probe_dir/x11" "$$z23_x11_probe_dir/probe.c" -Wl,-l:libX11.so.6 >"$$z23_x11_probe_dir/link.log" 2>&1; then printf present >"$$z23_x11_probe_dir/state"; else printf failed >"$$z23_x11_probe_dir/state"; fi\n' "$flags"
        printf 'zcl-x11-cover:\n'
        printf '\t%s -c tools/native_ui_driver.c -o "$$z23_x11_probe_dir/native_ui_driver.o" && printf ok >"$$z23_x11_probe_dir/covered" || exit 1\n' "$flags"
    } > "$dir/probe.mk" || return 2
    export z23_x11_probe_dir="$dir"
    if ! LC_ALL=C make --no-print-directory -s -f Makefile -f "$dir/probe.mk" zcl-x11-baseline >&2; then
        return 2
    fi
    # Make may inherit -i/--ignore-errors (also through GNUMAKEFLAGS), or
    # a non-execution mode. Require success recorded by each actual shell
    # command, independently of Make's status and any partial compiler output.
    # Retain Make's legitimate CC/wrapper/platform overrides unchanged.
    [[ -s "$dir/probe" && -s "$dir/state" &&
       -s "$dir/compiled" && -s "$dir/ran" ]] || return 2
    [[ "$(cat "$dir/state")" != present ]] || return 0
    # Only the named SONAME's absence is an exemption. A second diagnostic,
    # wrong architecture, missing compiler or generic link error is unproven.
    while IFS= read -r line; do
        case "$line" in
            *'ld: cannot find -l:libX11.so.6: No such file or directory' | *'ld.bfd: cannot find -l:libX11.so.6: No such file or directory' | \
            *'ld.lld: error: unable to find library -l:libX11.so.6')
                missing=$((missing + 1)) ;;
            'collect2: error: ld returned 1 exit status' | \
            'clang: error: linker command failed with exit code 1 (use -v to see invocation)') ;;
            *) cat "$dir/link.log" >&2; return 2 ;;
        esac
    done < "$dir/link.log"
    (( missing == 1 )) || { cat "$dir/link.log" >&2; return 2; }
    [[ -s vendor/x11/include/X11/Xlib.h &&
       -s vendor/x11/include/X11/Xutil.h &&
       -s vendor/x11/include/X11/keysym.h ]] || return 2
    if ! LC_ALL=C make --no-print-directory -s -f Makefile -f "$dir/probe.mk" zcl-x11-cover >&2; then
        return 2
    fi
    [[ -s "$dir/native_ui_driver.o" && -s "$dir/covered" ]] || return 2
    return 1
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
WINDOWS_ACCEPTANCE_CATALOG="platform/modules/platform/tests/windows_acceptance.mk"

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
fuzz_target_line="$(gate_grep -m1 '^FUZZ_TARGETS = ' Makefile || true)"
fuzz_target_assignments="$(gate_grep -E '^FUZZ_TARGETS[[:space:]]*[:+?]?=' Makefile || true)"
# This fast literal reader is a coverage gate, not a Make interpreter. Refuse
# comments or a second assignment rather than treating dead text as fuzz-ci.
if [[ "$GATE_HOST_OS" == Darwin &&
      ( -z "$fuzz_target_line" || "$fuzz_target_assignments" != "$fuzz_target_line" ||
        "$fuzz_target_line" == *'#'* || "$fuzz_target_line" == *'\'* ) ]]; then
    echo "check-standalone-tools-link: FATAL — FUZZ_TARGETS is not one literal uncommented assignment" >&2
    exit 2
fi
read -r -a fuzz_target_tokens <<< "$fuzz_target_line"
declare -A FUZZ_CI_TARGETS=()
for token in "${fuzz_target_tokens[@]}"; do
    [[ "$token" == '$(BIN_DIR)/fuzz_'* ]] || continue
    FUZZ_CI_TARGETS["${token#'$(BIN_DIR)/'}"]=1
done
targets=()
for name in $(printf '%s\n' "${!TOOLS[@]}" | sort); do
    # A new fuzzer belongs to the fuzz-ci corpus. On Darwin's base CLT,
    # linking it here fails only after a costly whole-program compile because
    # libclang_rt.fuzzer_osx.a is absent. Require an explicit host decision
    # before the proof's prefork build schedules that work.
    if [[ "$GATE_HOST_OS" == Darwin && "$name" == fuzz_* ]]; then
        if [[ -z "${FUZZ_CI_TARGETS[$name]:-}" ]]; then
            echo "check-standalone-tools-link: FATAL — $name has no fuzz-ci target" >&2
            exit 2
        fi
        if [[ -z "${EXEMPT[$name]:-}" && -z "${DARWIN_EXEMPT[$name]:-}" ]]; then
            echo "check-standalone-tools-link: FATAL — unclassified Darwin fuzz target $name" >&2
            echo "  Declare its fuzz-ci coverage and host-runtime policy before prefork." >&2
            exit 2
        fi
    fi
    [[ -n "${EXEMPT[$name]:-}" ]] && continue
    # A bare non-windows exemption used to sit here. It skipped the tool on
    # sight, with no check that anything still compiled the source — the exact
    # fail-open this gate exists to prevent. The WINDOWS_ONLY_EXEMPT block
    # below does the same skip, but only after confirming the replacement
    # check is real, and refuses outright when it is not.
    if [[ "$GATE_HOST_OS" == Darwin && -n "${DARWIN_EXEMPT[$name]:-}" ]]; then
        echo "[check_standalone_tools_link] darwin-exempt $name: ${DARWIN_EXEMPT[$name]}" >&2
        continue
    fi
    # Probe only this Linux tool. Inherited X11_PROBE_DONE/X11_RUNTIME_OK
    # variables cannot qualify or manufacture an exemption.
    if [[ "$GATE_HOST_OS" == Linux && "$name" == native_ui_driver ]]; then
        if x11_runtime_linkable; then
            : # The normal target still links the actual driver.
        else
            x11_rc=$?
            if (( x11_rc != 1 )); then
                echo "check-standalone-tools-link: FATAL - X11 runtime qualification failed" >&2
                exit 2
            fi
            echo "[check_standalone_tools_link] no-x11-runtime-exempt $name: SONAME absent; canonical strict object compiled" >&2
            continue
        fi
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
# Anything under 10 means exemptions have eaten it. No count is written here:
# the gate prints the live one on its summary line below, and a number typed
# into prose goes stale without anything noticing.
gate_require_scanned "${#targets[@]}" 10 check-standalone-tools-link \
    "the exempt set has swallowed the gate — it is no longer proving anything"

if [ "$LIST_TARGETS" -eq 1 ]; then
    [ "$BUILD_ONLY" -eq 0 ] || exit 2
    printf '%s\n' "${targets[@]}"
    exit 0
fi

echo "[check_standalone_tools_link] ${#TOOLS[@]} tool rule(s) in Makefile;" \
     "${#EXEMPT[@]} exempt; building ${#targets[@]}"

# ── Build them ───────────────────────────────────────────────────────────
# Each target is its own single-TU link; make no-ops the already-built ones.
violations=0; failed=()
build_log=$(mktemp)

# The receipt wrapper owns a fast private build path for agent_sha3 so a direct
# invocation does not pay a Makefile parse. Prove that ACTUAL path from an
# absent output, not only the sibling `make agent-sha3` rule: the two source
# lists once drifted, leaving every Makefile tool gate green while a fresh
# `make gate-receipt` failed before its child gate could start.
if [ "$BUILD_ONLY" -eq 1 ]; then
    echo "[check_standalone_tools_link] build-only: skipping the gate-receipt helper"
    echo "[check_standalone_tools_link] self-test — that is a verdict, and the gate"
    echo "[check_standalone_tools_link] still runs it in the lint dimension."
elif helper_selftest="$(tools/agent/gate-receipt.sh --selftest-helper 2>&1)"; then
    echo "[check_standalone_tools_link] $helper_selftest"
else
    echo "[check_standalone_tools_link] gate-receipt helper selftest failed:" >&2
    printf '    %s\n' "$helper_selftest" >&2
    printf '%s\n' "$helper_selftest" >>"$build_log"
    failed+=("gate-receipt fresh agent_sha3 helper")
    violations=$((violations + 1))
fi

# The helper selftest above skips the X11 exemption: run its hermetic failure
# regressions BESIDE the build; a missing or failed child is a violation. Skip
# stamp (written only after a PASS): the selftest reads just the files hashed
# here; any hash failure leaves the key empty, which always runs it. The trap
# reaps the child on an early exit.
x11_pid=""; x11_log=$(mktemp); x11_stamp=build/lint-stamps/standalone-x11.sha256; x11_key=""
trap '[[ -z "$x11_pid" ]] || { kill "$x11_pid" 2>/dev/null; wait "$x11_pid" 2>/dev/null; }; rm -f "$build_log" "$x11_log"' EXIT
if [[ "$BUILD_ONLY" == 0 && "$GATE_HOST_OS" == Linux ]]; then
    x11_key=$(set -o pipefail; { sha256sum tools/lint/selftest_standalone_tools_x11.sh "$0" tools/lint/gate_lib.sh &&
      find vendor/x11/include -type f | LC_ALL=C sort | xargs sha256sum && cc --version &&
      awk '/^NATIVE_UI_DRIVER_BIN = /{a=1} a{if(/^# Crash recovery/)exit;print}' Makefile; } | sha256sum | cut -c1-64) 2>/dev/null || x11_key=""
    if [[ -n "$x11_key" && "$(cat "$x11_stamp" 2>/dev/null)" == "$x11_key" ]]; then
        echo "[check_standalone_tools_link] X11 selftest inputs unchanged since last pass; skipped"
    else tools/lint/selftest_standalone_tools_x11.sh >"$x11_log" 2>&1 & x11_pid=$!; fi
fi

# Parallelism: half the grant (ZCL_HOST_JOBS, else CPUs), clamped 4..16; override ZCL_TOOLS_LINK_JOBS=<n>.
tl_nproc="${ZCL_HOST_JOBS:-$(nproc 2>/dev/null || echo 4)}"
tl_jobs="${ZCL_TOOLS_LINK_JOBS:-$(( tl_nproc / 2 ))}"
if [ "$tl_jobs" -lt 4 ];  then tl_jobs=4;  fi
if [ "$tl_jobs" -gt 16 ]; then tl_jobs=16; fi

if ! make -k -j"$tl_jobs" --no-print-directory "${targets[@]}" >"$build_log" 2>&1; then
    # One -k parse keeps the original failure context; serial re-probes lose it.
    if grep -Fq "exact source capture failed" "$build_log"; then
        sed 's/^/    /' "$build_log" >&2
        echo "[check_standalone_tools_link] source-identity capture refused, so make could" \
             "not parse. This is NOT a broken tool rule; re-run on a settled tree." >&2
        exit 2
    fi
    failed+=("standalone tool build batch (see build output)")
    violations=$((violations + 1))
fi

# --build-only stops here. A tool that would not link is still a hard failure —
# fail-closed, exactly as the gate is — but the exempt-set prose and the gate's
# own verdict belong to the run inside `make lint`, not to a pre-build.
if [ "$BUILD_ONLY" -eq 1 ]; then
    if (( violations > 0 )); then
        echo "[check_standalone_tools_link] build-only: BUILD OUTPUT:" >&2
        sed 's/^/    /' "$build_log" >&2
        for t in "${failed[@]}"; do echo "    $t" >&2; done
        echo "check-standalone-tools-link --build-only: ${violations} check(s) failed" >&2
        exit 1
    fi
    echo "[check_standalone_tools_link] build-only: ${#targets[@]} tool target(s) built"
    exit 0
fi

if [[ -n "$x11_pid" ]]; then
    if wait "$x11_pid"; then
        cat "$x11_log"
        [[ -z "$x11_key" ]] || { mkdir -p "${x11_stamp%/*}" && printf '%s' "$x11_key" >"$x11_stamp"; } 2>/dev/null || true
    else
        cat "$x11_log" >&2
        failed+=("X11 runtime qualification selftest")
        violations=$((violations + 1))
    fi
    x11_pid=""
fi

if (( violations > 0 )); then
    echo "[check_standalone_tools_link] BUILD OUTPUT:"
    sed 's/^/    /' "$build_log"
    echo "[check_standalone_tools_link] failed check(s):"
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
