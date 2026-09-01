#!/usr/bin/env bash
# pr_security_scan.sh — automated security review of a pull request / diff.
#
# Runs on every PR (via .github/workflows/pr-security-review.yml) and is
# runnable by hand or by an agent reviewing an outside contribution. It is
# the "fast customer-service" gate: catch the dangerous classes immediately,
# tell the contributor clearly, and keep our tree safe before anything merges.
#
# It scans the ADDED lines of a diff for:
#   - consensus divergence from zclassicd (the parity guard, E13 token class)
#   - supply-chain execution (fetch-and-run, base64|sh, eval, new submodules,
#     CI steps running remote code)
#   - secrets (private keys, cloud credentials)
#   - dangerous C (system/popen/exec, unbounded str ops, dlopen)
# and runs the static security lint gates against the resulting tree.
#
# Usage:
#   tools/scripts/pr_security_scan.sh                 # origin/main...HEAD
#   tools/scripts/pr_security_scan.sh <BASE> <HEAD>   # explicit range
#   tools/scripts/pr_security_scan.sh --pr <N>        # fetch PR N (needs gh)
#   tools/scripts/pr_security_scan.sh ... --fix       # apply safe auto-fixes
#
# Exit: 0 = clean (no HIGH findings), 1 = HIGH findings (block the PR).
set -uo pipefail
cd "$(dirname "$0")/../.."

REPO="${PR_SCAN_REPO:-z23c/z23}"
FIX=0
BASE=""; HEAD=""
PR=""
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --fix) FIX=1 ;;
        --pr) PR="$2"; shift ;;
        *) args+=("$1") ;;
    esac
    shift
done
[ "${#args[@]}" -ge 1 ] && BASE="${args[0]}"
[ "${#args[@]}" -ge 2 ] && HEAD="${args[1]}"

if [ -n "$PR" ]; then
    command -v gh >/dev/null || { echo "FAIL: --pr needs the gh CLI"; exit 1; }
    gh pr checkout "$PR" --repo "$REPO" >/dev/null 2>&1 || { echo "FAIL: gh pr checkout $PR"; exit 1; }
    BASE="$(gh pr view "$PR" --repo "$REPO" --json baseRefName -q .baseRefName 2>/dev/null || echo main)"
    HEAD="HEAD"
fi
BASE="${BASE:-origin/main}"
HEAD="${HEAD:-HEAD}"

# Merge-base diff of ADDED lines only (new content the PR introduces).
DIFF="$(git diff "$BASE...$HEAD" 2>/dev/null)"
if [ -z "$DIFF" ]; then
    echo "pr_security_scan: empty diff for $BASE...$HEAD — nothing to review"
    exit 0
fi
# Added lines tagged with their file (for location-aware checks).
ADDED_TAGGED="$(printf '%s\n' "$DIFF" | awk '
    /^\+\+\+ b\// { f=substr($0,7); next }
    /^\+/ && !/^\+\+\+/ { print f "\t" substr($0,2) }')"
# The security tooling + docs LEGITIMATELY name these dangerous tokens (to
# describe/forbid them). Exclude them from the naming-sensitive checks so the
# scanner never flags itself or the doctrine. Genuine code/secret risks are
# still scanned everywhere else.
SELF_RE='^(docs/|tools/scripts/pr_security_scan\.sh|tools/scripts/check_consensus_parity\.sh|tests/harness/src/test_consensus_parity\.c)'
ADDED_SCAN="$(printf '%s\n' "$ADDED_TAGGED" | grep -vE "$SELF_RE")"
ADDED="$(printf '%s\n' "$ADDED_SCAN" | cut -f2-)"

HIGH=0; MED=0
report=""
add() { # severity message
    local sev="$1"; shift
    report+="- **[$sev]** $*"$'\n'
    [ "$sev" = "HIGH" ] && HIGH=$((HIGH+1))
    [ "$sev" = "MED"  ] && MED=$((MED+1))
}
show() { # pattern over ADDED_SCAN, print up to 4 hits
    printf '%s\n' "$ADDED_SCAN" | grep -nE "$1" 2>/dev/null | head -4 \
        | sed 's/^/      /'
}

echo "══ PR security scan: $BASE...$HEAD ══"

# 1) Consensus parity — the forbidden mechanism class (E13), scoped to the
#    consensus SOURCE surface only (so docs/tests/tooling naming the tokens
#    are never flagged) and to added lines so the report is contributor-actionable.
PARITY_TOK='versionbits|VersionBitsState|ComputeBlockVersion|ehUpgrade|eh_upgrade|nSignalBit|vbits_|equihash_n_at|equihash_k_at|BIP9|BIP8'
PARITY_PATHS='^(core/params|core/chainparams|lib/validation|lib/chain|lib/mining|app/jobs|core/consensus)/'
PARITY_HITS="$(printf '%s\n' "$ADDED_SCAN" | grep -E "$PARITY_PATHS" | grep -E "$PARITY_TOK")"
if [ -n "$PARITY_HITS" ]; then
    add HIGH "Consensus divergence from zclassicd: a versionbits/miner-signaled/dynamic-Equihash-override mechanism is introduced in the consensus path. zclassic23 must stay bit-for-bit with zclassicd (docs/CONSENSUS_PARITY_DOCTRINE.md)."
    report+="$(printf '%s\n' "$PARITY_HITS" | head -4 | sed 's/^/      /')"$'\n'
fi

# Every match test below feeds grep with a HERE-STRING, never `printf ... | grep -q`.
# This script runs under `set -o pipefail` (above), and in a pipeline `grep -q`
# exits at the FIRST match, so printf takes SIGPIPE and pipefail reports its 141
# instead of grep's 0 -- turning a FOUND SECRET into a clean verdict. Measured:
# a 400 KB diff with a matching AKIA key on line 1 reported CLEAN at status 141,
# while the same key in a short diff reported correctly. That is the worst
# possible direction for a security gate and it fails only on large diffs, so it
# hides on small test inputs. Keep these pipeline-free. See tools/scripts/sh_str.sh.
# 2) Supply-chain execution.
SUPPLY='(curl|wget|fetch)[^|]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba)?sh|\beval[[:space:]]|\bdlopen[[:space:]]*\(|pip[[:space:]]+install|npm[[:space:]]+install|go[[:space:]]+get'
if grep -qE "$SUPPLY" <<<"$ADDED_SCAN"; then
    add HIGH "Possible supply-chain execution (fetch-and-run / decode-and-run / dynamic load / remote package install). Review every hit before merge."
    report+="$(show "$SUPPLY")"$'\n'
fi
if grep -qE '^\+\+\+ b/\.gitmodules|^\+\+\+ b/\.github/workflows/' <<<"$DIFF"; then
    add HIGH "Touches .gitmodules or .github/workflows (CI/supply-chain surface) — verify no new submodule or workflow step runs untrusted code."
fi

# 3) Secrets.
# NOTE: pattern begins with '-', so every grep uses `-- "$SECRET"`.
SECRET='-----BEGIN ([A-Z ]*)?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|aws_secret_access_key|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{30,}|(password|passwd|secret|api_?key)[[:space:]]*[:=][[:space:]]*["'\''][^"'\'' ]{6,}'
if grep -qiE -- "$SECRET" <<<"$ADDED"; then
    add HIGH "Possible committed secret (private key / cloud credential / hardcoded password / token). Never merge a real secret; rotate immediately if exposed."
fi

# 4) Dangerous C (review-worthy, not auto-block).
DANGER='\bsystem[[:space:]]*\(|\bpopen[[:space:]]*\(|\bexec[lv]p?e?[[:space:]]*\(|\bgets[[:space:]]*\(|\bstrcpy[[:space:]]*\(|\bstrcat[[:space:]]*\(|\bsprintf[[:space:]]*\('
if grep -qE "$DANGER" <<<"$ADDED_SCAN"; then
    add MED "Dangerous C call introduced (system/popen/exec, or unbounded gets/strcpy/strcat/sprintf). Prefer zcl_* safe helpers / bounded variants; confirm inputs are trusted."
    report+="$(show "$DANGER")"$'\n'
fi

# 5) Static security lint gates against the resulting tree.
GATE_FAIL=""
for g in check_consensus_parity.sh check_no_secret_printf.sh; do
    if [ -x "tools/scripts/$g" ]; then
        if ! out="$(./tools/scripts/$g 2>&1)"; then
            GATE_FAIL+="$g"$'\n'"$out"$'\n'
        fi
    fi
done
if [ -n "$GATE_FAIL" ]; then
    add HIGH "A static security gate failed against the merged tree:"
    report+="$(printf '%s\n' "$GATE_FAIL" | head -8 | sed 's/^/      /')"$'\n'
fi

# Optional safe auto-fix pass.
if [ "$FIX" = 1 ]; then
    echo "── --fix: applying safe normalizations + re-running gates ──"
    # Safe, idempotent fixes only. Consensus/secret findings are deliberately
    # NOT auto-rewritten (auto-editing security-sensitive code is itself a
    # risk) — they are surfaced for a human decision.
    if command -v clang-format >/dev/null 2>&1 && [ -f .clang-format ]; then
        printf '%s\n' "$ADDED_TAGGED" | awk -F'\t' '{print $1}' | sort -u \
            | grep -E '\.(c|h)$' | while read -r f; do
                [ -f "$f" ] && clang-format -i "$f" 2>/dev/null || true
            done
        echo "  applied clang-format to changed C sources"
    else
        echo "  (no clang-format/.clang-format — no auto-format applied)"
    fi
    echo "  security findings above are surfaced for human review, not auto-rewritten"
fi

echo ""
echo "════════════ VERDICT ════════════"
if [ "$HIGH" -gt 0 ]; then
    printf '%s\n' "$report"
    echo "RESULT: BLOCK — $HIGH high-severity, $MED medium finding(s). Resolve HIGH before merge."
    exit 1
elif [ "$MED" -gt 0 ]; then
    printf '%s\n' "$report"
    echo "RESULT: REVIEW — 0 high, $MED medium finding(s). Human review recommended; not a hard block."
    exit 0
else
    echo "RESULT: CLEAN — no consensus-parity, supply-chain, secret, or dangerous-call findings in the diff."
    exit 0
fi
