#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# doctor.sh — `make doctor`. Answers one question: what does THIS host still
# need before the build works, and what is the exact command to install it.
#
# It replaces three prose prerequisite lists that disagreed with each other
# and with the script they described. The authority is
# tools/scripts/vendor_prereqs.tsv, and this script refuses to report a clean
# bill of health if that table has fallen behind build_vendor.sh: every
# `need <tool>` call there must have a row. A doctor that can silently miss a
# prerequisite is worse than no doctor.
#
# Read-only. Installs nothing, writes nothing.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TSV="${ZCL_DOCTOR_TSV:-$ROOT/tools/scripts/vendor_prereqs.tsv}"
VENDOR_SH="$ROOT/tools/scripts/build_vendor.sh"

MODE="${1:-report}"

die() { printf 'doctor: FATAL — %s\n' "$*" >&2; exit 2; }

[ -f "$TSV" ]       || die "missing prerequisite table: $TSV"
[ -f "$VENDOR_SH" ] || die "missing vendor build script: $VENDOR_SH"

# --------------------------------------------------------------------------
# Coverage: every `need <tool>` in build_vendor.sh must have a row here.
# Literal `need foo` and `need "$VAR"` both count; a variable resolves to the
# script's own default (VENDOR_CC=cc, VENDOR_AR=ar).
# --------------------------------------------------------------------------
tsv_tools() { awk -F'\t' '!/^#/ && NF>1 && $1!="tool" {print $1}' "$TSV"; }

needed_tools() {
    # Comment lines are prose ("we do not need to install them") and would
    # otherwise contribute English words as fake tool names.
    grep -v '^[[:space:]]*#' "$VENDOR_SH" |
        grep -oE '\bneed[[:space:]]+("?\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?"?)' |
        awk '{print $2}' |
        tr -d '"${}' |
        while read -r t; do
            case "$t" in
                VENDOR_CC) echo cc ;;
                VENDOR_AR) echo ar ;;
                *)         echo "$t" ;;
            esac
        done | sort -u
}

check_coverage() {
    local missing=() t
    while read -r t; do
        [ -n "$t" ] || continue
        grep -qx "$t" <<<"$(tsv_tools)" || missing+=("$t")
    done <<<"$(needed_tools)"

    if [ "${#missing[@]}" -gt 0 ]; then
        printf 'doctor: FAIL — build_vendor.sh requires tools with no row in %s:\n' \
            "${TSV#"$ROOT"/}" >&2
        printf '    %s\n' "${missing[@]}" >&2
        printf '  Add a row (tool/class/apt/dnf/why) so `make doctor` can report it.\n' >&2
        return 1
    fi
    return 0
}

# make setup arms native hooks at <checkout>/build/githooks. The older
# spelling was <checkout>/tools/githooks. Either is armed; anything else
# is not.
doctor_hooks_shape() {
    case "$1" in
        */build/githooks|*/tools/githooks) printf 'ok\n' ;;
        *)                                 printf 'no\n' ;;
    esac
}

if [ "$MODE" = "--prereq-coverage" ]; then
    check_coverage || exit 1
    echo "doctor: prereq table covers every 'need' in build_vendor.sh ($(needed_tools | grep -c .) tools)"
    exit 0
fi

if [ "$MODE" = "--self-test" ]; then
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-doctor.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT HUP INT TERM
    self="${BASH_SOURCE[0]}"

    # (1) The real table passes coverage.
    check_coverage >/dev/null 2>&1 ||
        { echo "doctor selftest: FAIL — real table must pass coverage" >&2; exit 1; }

    # (2) The coverage assertion can actually FAIL. Drop the perl row — perl
    #     is a real `need` in build_vendor.sh — and require a nonzero exit.
    grep -v $'^perl\t' "$TSV" > "$tmp/noperl.tsv"
    if ZCL_DOCTOR_TSV="$tmp/noperl.tsv" bash "$self" --prereq-coverage >/dev/null 2>&1; then
        echo "doctor selftest: FAIL — coverage passed with the perl row removed" >&2
        exit 1
    fi

    # (3) A missing prerequisite produces an install line naming ONLY its
    #     package. Uses a tool name that cannot exist on any host.
    cp "$TSV" "$tmp/bogus.tsv"
    printf 'zcl-absent-tool-fixture\trequired\tzcl-fixture-pkg\tzcl-fixture-pkg\tfixture\n' \
        >> "$tmp/bogus.tsv"
    out="$(ZCL_DOCTOR_TSV="$tmp/bogus.tsv" bash "$self" 2>&1)"
    grep -Fq 'zcl-fixture-pkg' <<<"$out" ||
        { echo "doctor selftest: FAIL — missing tool produced no install line: $out" >&2; exit 1; }
    grep -Eq 'Install the [0-9]+ missing prerequisite' <<<"$out" ||
        { echo "doctor selftest: FAIL — missing tool not counted: $out" >&2; exit 1; }

    # (4) On a host where nothing is missing the doctor says so, and does NOT
    #     print an install line. This is the "never surprise the reader" half.
    out="$(bash "$self" 2>&1)"
    if grep -Fq 'zcl-fixture-pkg' <<<"$out"; then
        echo "doctor selftest: FAIL — fixture leaked into the real report" >&2; exit 1
    fi

    # (5) After `make setup`, hooks live at build/githooks. A shape check
    #     that only accepts tools/githooks reports "not armed" on a green
    #     setup. Born-red: a path that is neither is refused.
    [ "$(doctor_hooks_shape /checkout/build/githooks)" = ok ] ||
        { echo "doctor selftest: FAIL — native build/githooks path not armed" >&2; exit 1; }
    [ "$(doctor_hooks_shape /checkout/tools/githooks)" = ok ] ||
        { echo "doctor selftest: FAIL — legacy tools/githooks path not armed" >&2; exit 1; }
    [ "$(doctor_hooks_shape /checkout/elsewhere)" = no ] ||
        { echo "doctor selftest: FAIL — unknown hooks path was accepted" >&2; exit 1; }

    echo "doctor selftest: PASS"
    exit 0
fi

# --------------------------------------------------------------------------
# Probe the host.
# --------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

missing_apt=(); missing_dnf=(); either_present=0; either_seen=0
missing_opt_apt=(); missing_opt_dnf=(); missing_opt_n=0
present_n=0; missing_n=0
rows_required=(); rows_vendor=(); rows_optional=()

while IFS=$'\t' read -r tool class apt dnf why; do
    case "$tool" in ''|'#'*|tool) continue ;; esac
    if have "$tool"; then
        status="ok"; present_n=$((present_n + 1))
    else
        status="MISSING"
    fi
    [ "$class" = "vendor-either" ] && {
        either_seen=1
        [ "$status" = "ok" ] && either_present=1
    }
    line="$(printf '  %-8s %-16s %s' "$status" "$tool" "$why")"
    case "$class" in
        required)                 rows_required+=("$line") ;;
        vendor|vendor-either)     rows_vendor+=("$line") ;;
        vendor-optional)          rows_optional+=("$line") ;;
    esac
    # vendor-optional is counted SEPARATELY: absent means a slower path or one
    # named capability off, never a build that cannot proceed. Folding it into
    # the blocking count is what made `make doctor` demand a Rust toolchain on
    # a host that does not need one.
    if [ "$status" = "MISSING" ]; then
        case "$class" in
            vendor-either) ;;
            vendor-optional)
                missing_opt_n=$((missing_opt_n + 1))
                missing_opt_apt+=("$apt"); missing_opt_dnf+=("$dnf") ;;
            *)
                missing_n=$((missing_n + 1))
                missing_apt+=("$apt"); missing_dnf+=("$dnf") ;;
        esac
    fi
done < "$TSV"

echo "══ doctor: build prerequisites on $(uname -n) ══"
echo
echo "Required for any build:"
printf '%s\n' "${rows_required[@]}"
echo
echo "Required for 'make vendor' (one-time vendored-archive build):"
printf '%s\n' "${rows_vendor[@]}"
echo
echo "Optional — the build completes without these (slower path, or one"
echo "named capability off; see the reason on each line):"
printf '%s\n' "${rows_optional[@]}"
echo

# vendor-either: only a failure when EVERY member is absent.
if [ "$either_seen" = 1 ] && [ "$either_present" = 0 ]; then
    missing_n=$((missing_n + 1))
    missing_apt+=("curl"); missing_dnf+=("curl")
    echo "  MISSING  a downloader — build_vendor needs curl OR wget"
    echo
fi

# --------------------------------------------------------------------------
# Compiler capability, not just presence: -std=c23 is the actual requirement.
# --------------------------------------------------------------------------
c23_probe=""
if have cc; then
    probe="$(mktemp "${TMPDIR:-/tmp}/zcl-c23-XXXXXX.c")"
    printf '[[nodiscard]] static int f(void){return 0;}\nint main(void){return f();}\n' > "$probe"
    if cc -std=c23 -fsyntax-only "$probe" >/dev/null 2>&1; then
        c23_probe="ok"
    else
        c23_probe="fail"
    fi
    rm -f "$probe"
fi
case "$c23_probe" in
    ok)   echo "  ok       cc -std=c23   accepts C23 and the [[nodiscard]] attribute" ;;
    fail) echo "  MISSING  cc -std=c23   present but rejects C23 — need gcc 14+ or a newer clang"
          missing_n=$((missing_n + 1))
          missing_apt+=("gcc"); missing_dnf+=("gcc") ;;
    *)    ;;
esac

# --------------------------------------------------------------------------
# Repository-side setup that is not a package.
# --------------------------------------------------------------------------
echo
echo "Repository setup:"
# core.hooksPath lives in the SHARED config, so a linked worktree legitimately
# sees an absolute spelling pointing at another checkout's hooks. The
# substance is "setup's armed hooks are the armed hooks", not the spelling.
hooks="$(git -C "$ROOT" config --get core.hooksPath 2>/dev/null || true)"
hooks_abs="$(realpath -m -- "${hooks:-/nonexistent}" 2>/dev/null || echo /nonexistent)"
hooks_shape="$(doctor_hooks_shape "$hooks_abs")"
if [ "$hooks_shape" = ok ] && [ -x "$hooks_abs/pre-push" ]; then
    echo "  ok       git hooks       core.hooksPath -> $hooks"
else
    echo "  ACTION   git hooks       not armed — run: make setup"
fi
if [ -e "$ROOT/vendor/lib/libcrypto.a" ]; then
    echo "  ok       vendor/lib      vendored archives present"
else
    echo "  ACTION   vendor/lib      archives absent — run: make vendor"
fi
if [ -f "$ROOT/compile_commands.json" ]; then
    echo "  ok       compile db      compile_commands.json present (clangd/LSP)"
else
    echo "  ACTION   compile db      absent — run: make setup"
fi

# --------------------------------------------------------------------------
# The payoff: one install line per manager, listing ONLY what is missing.
# --------------------------------------------------------------------------
echo
if [ "$missing_n" -eq 0 ]; then
    echo "No missing prerequisites on this host."
    if [ "$missing_opt_n" -gt 0 ]; then
        echo
        echo "Everything required is present. $missing_opt_n OPTIONAL tool(s) are absent —"
        echo "the build works without them; each line above says what you give up."
        if have apt-get || have apt; then
            printf '  sudo apt-get install -y %s\n' \
                "$(printf '%s\n' "${missing_opt_apt[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
        fi
        if have dnf; then
            printf '  sudo dnf install -y %s\n' \
                "$(printf '%s\n' "${missing_opt_dnf[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
        fi
    fi
else
    echo "Install the $missing_n missing prerequisite(s):"
    if have apt-get || have apt; then
        printf '  sudo apt-get install -y %s\n' \
            "$(printf '%s\n' "${missing_apt[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
    fi
    if have dnf; then
        printf '  sudo dnf install -y %s\n' \
            "$(printf '%s\n' "${missing_dnf[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
    fi
    if ! have apt-get && ! have apt && ! have dnf; then
        echo "  (no apt or dnf on this host — package names by distro:)"
        printf '  apt: %s\n' "$(printf '%s\n' "${missing_apt[@]}" | sort -u | tr '\n' ' ')"
        printf '  dnf: %s\n' "$(printf '%s\n' "${missing_dnf[@]}" | sort -u | tr '\n' ' ')"
    fi
fi

echo
echo "Build SPEED (ccache, mold/lld/gold, clang, ...) is a different question:"
echo "  make doctor-build"
echo "Where the wall time actually goes on this host:"
echo "  make timings"

# A stale prerequisite table is a defect in the doctor itself, so it is
# reported last and it fails the command.
echo
check_coverage || exit 1
echo "doctor: prerequisite table is in sync with build_vendor.sh"
exit 0
