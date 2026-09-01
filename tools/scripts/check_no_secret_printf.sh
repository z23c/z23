#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_no_secret_printf.sh — static audit for obvious private-key leaks.
#
# The single most embarrassing bug we could ship is logging a private key,
# seed phrase, or wallet secret to stdout / stderr / a file. This script
# greps the tree for common printf-family calls that name a variable with
# a secret-shaped word ("priv", "secret", "seed", "mnemonic", "wif") in
# their argument list.
#
# The heuristic isn't perfect — some of these are false positives (e.g.
# key_to_pub_seed() is benign) — but failing CI on a literal
# printf("...%s...", priv_hex) catches the class of mistake the audit is
# built to prevent. Benign matches get added to the ALLOWLIST below after
# a human has reviewed them.
#
# Usage: tools/scripts/check_no_secret_printf.sh
# Exit code: 0 on clean, 1 on any flagged match.

set -uo pipefail

# Find the repo root regardless of where the script was invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# Directories to scan — the five source authorities plus tools, excluding vendor,
# tests, and the audit corpus itself (which contains "priv" by design).
# Overridable via ZCL_SECRET_PRINTF_SCAN_DIRS (space-separated) so the
# lint-gate self-test can point the gate at an EMPTY dir and prove the
# non-empty-floor preflight fires (exit 2).
read -r -a SCAN_DIRS <<< "${ZCL_SECRET_PRINTF_SCAN_DIRS:-core engine contexts cognition platform tools}"
EXCLUDE_PATHS=(
    "tests/harness"
    "tools/scripts/check_no_secret_printf.sh"
    "vendor"
)

EXCLUDE_EXPR=""
for p in "${EXCLUDE_PATHS[@]}"; do
    EXCLUDE_EXPR="$EXCLUDE_EXPR --exclude-dir=$p"
done

# Pattern: a printf-family call that references a token whose identifier
# name strongly implies it holds sensitive key material. We match on the
# portion AFTER the format string so we don't flag English "private" or
# "seed" inside comments or format literals.
#
# Matched token patterns (must be bare identifiers, not inside a "..."
# literal):
#   priv_key / privkey / privateKey
#   spending_key / sk_data / sk_bytes
#   mnemonic (any suffix)
#   wif (as a complete token) / wif_str / wif_data
#   seed_phrase / seed_words
#   viewing_key (raw material — public FVKs handled separately)
#   extfvk / extspk / xprv / xpriv
#
# The pattern anchors to the " that closes a format string, then matches
# a comma and the identifier, so `printf("private: %f", amount)` doesn't
# trigger but `printf("%s", priv_key)` does.
PATTERN='[fs]?n?printf\s*\([^"]*"[^"]*"\s*,[^)]*\b(priv_?key|privateKey|spending_?key|sk_data|sk_bytes|mnemonic[a-z_]*|wif|wif_str|wif_data|seed_phrase|seed_words|viewing_?key|extfvk|extspk|xpr[iv]v?)\b[^)]*\)'

# Allowlist: lines that match the pattern but are known-safe. Each entry
# is a regex checked with egrep — if any entry matches the full file:line
# output, the hit is suppressed. Keep this list small and annotated.
ALLOWLIST_RE=(
    # tools/wallet_dump.c — dedicated key-export utility; printing keys is
    # its entire purpose, behind an explicit operator-run gate.
    'tools/wallet_dump\.c'
)

# Fail-loud preflight: the .c/.h file set across SCAN_DIRS must be non-empty.
# A renamed/moved scan dir would empty the surface; combined with the old
# `2>/dev/null || true` masking grep's exit, the gate would print "clean"
# exit 0 over zero files — a hollow pass. Assert a floor first.
mapfile -t scan_files < <(find "${SCAN_DIRS[@]}" -type f \( -name '*.c' -o -name '*.h' \) "${LINT_FIND_PRUNE_ARGS[@]}" 2>/dev/null)
gate_require_scanned "${#scan_files[@]}" 1 check_no_secret_printf \
    "no *.c/*.h under: ${SCAN_DIRS[*]}"

# Run the scan and check grep's exit EXPLICITLY: 0=match, 1=no-match,
# >=2=real error (e.g. busybox grep rejecting --exclude-dir / a bad regex).
# The old `2>/dev/null || true` masked >=2 as an empty result → "clean"
# exit 0, a fail-silent hole. (gate_grep's own exit-2 can't propagate out of
# a `$(...)` subshell, so we inline the explicit check here.)
matches=$(grep -rEn $EXCLUDE_EXPR \
    --include='*.c' --include='*.h' \
    "$PATTERN" "${SCAN_DIRS[@]}" "${LINT_GREP_EXCLUDE_ARGS[@]}")
grc=$?
if [ "$grc" -ge 2 ]; then
    echo "check_no_secret_printf: FATAL — scan grep failed (exit $grc); a grep" >&2
    echo "  error (bad flag on a non-GNU grep, unreadable file) was about to be" >&2
    echo "  masked as 'no secrets found'. Refusing to pass off a broken scan." >&2
    exit 2
fi

if [[ -z "$matches" ]]; then
    echo "check_no_secret_printf: clean — no suspicious printf calls found"
    exit 0
fi

# Filter out allowlisted lines.
filtered=""
while IFS= read -r line; do
    allowed=0
    for re in "${ALLOWLIST_RE[@]}"; do
        if echo "$line" | grep -qE "$re"; then
            allowed=1
            break
        fi
    done
    if [[ "$allowed" -eq 0 ]]; then
        filtered+="$line"$'\n'
    fi
done <<< "$matches"

# Trim trailing newline.
filtered="${filtered%$'\n'}"

if [[ -z "$filtered" ]]; then
    echo "check_no_secret_printf: clean (all matches allowlisted)"
    exit 0
fi

echo "check_no_secret_printf: SUSPICIOUS PRINTF CALLS FOUND"
echo
echo "$filtered"
echo
echo "If any of these are false positives, add a regex to ALLOWLIST_RE in"
echo "tools/scripts/check_no_secret_printf.sh (with a justification)."
echo "If they're real leaks, fix the call and run the script again."
exit 1
