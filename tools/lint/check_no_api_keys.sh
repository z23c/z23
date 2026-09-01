#!/usr/bin/env bash
# check-no-api-keys: no API credential is committed to this tree.
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
# tools/engine_unit.c dispatches work to a paid API, which means this tree now
# has a reason to hold an API key near it. A key that lands in a tracked file
# is spent: it is in the history, on every clone, and on every mirror, and
# rotating it is the only remedy. The rule that a key lives in the environment
# or in a 0600 file OUTSIDE the repository is enforced in code
# (engine/modules/engine/src/engine_secret.c), and this gate is the second half — the one
# that notices when somebody pastes one in anyway.
#
# ── WHAT IS MATCHED ─────────────────────────────────────────────────────────
# Vendor-prefixed tokens (sk-, sk-ant-, xai-, gsk_, ghp_, glpat-, AKIA), a
# Bearer header carrying a long opaque token, and the two-part <32+ hex>.<16+
# alnum> shape Z.ai and JWT-ish credentials use. These are SHAPES, not a list
# of known keys: a gate that only catches keys somebody already told it about
# catches nothing.
#
# ── WHAT IS DELIBERATELY NOT MATCHED ────────────────────────────────────────
# A bare long hex run. Git object ids, SHA3 digests, seeds, test vectors and
# consensus constants are all long hex, and this tree is full of them; a rule
# that fires on those would be turned off within a week, and a gate that is
# turned off protects nothing. The two-part shape is required precisely
# because it does not collide with a digest.
#
# Binary fixtures are also out of scope — vendor/, images, archives, and the
# generated `.bin`/`.dat` corpora under tests/harness/fuzz_seeds/. A fuzz seed is
# random bytes, and random bytes reliably contain every shape; scanning them
# produced a false positive on the first run of this gate. Nobody pastes a
# credential into a generated corpus, and the cost of pretending otherwise is
# a gate that cries wolf.
#
# Vendor prefixes are assembled from fragments below rather than written out,
# so this script does not trip on its own patterns.
#
# ── PROVING IT WORKS ────────────────────────────────────────────────────────
# A gate nobody has seen fail is a gate nobody has tested.
# tests/harness/src/test_engine.c case_key_gate() plants a key in a fixture tree,
# points ZCL_API_KEY_SCAN_FILES at it, and requires a NON-ZERO exit — and
# requires a clean fixture to pass, so the failure is attributable.
#
# Env:
#   ZCL_API_KEY_SCAN_FILES  space-separated paths to scan instead of the
#                           tracked tree. Test isolation only; unset in
#                           production, where the scan set is `git ls-files`.
#
# Mode: FAIL always. There is no WARN tier and no baseline. A committed
# credential is not a thing to ratchet down over time.
#
# Exit: 0 clean, 1 on any match, 2 on a broken scan.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

# Assembled so this file is not its own violation.
P_SK="s""k-"
P_XAI="x""ai-"
P_GSK="g""sk_"
P_GHP="g""hp_"
P_GLPAT="g""lpat-"
P_AKIA="A""KIA"

PATTERNS=(
    "\\b${P_SK}[A-Za-z0-9_-]{20,}"
    "\\b${P_XAI}[A-Za-z0-9_-]{20,}"
    "\\b${P_GSK}[A-Za-z0-9_-]{20,}"
    "\\b${P_GHP}[A-Za-z0-9_-]{20,}"
    "\\b${P_GLPAT}[A-Za-z0-9_-]{20,}"
    "\\b${P_AKIA}[A-Z0-9]{16}"
    "Bearer[[:space:]]+[A-Za-z0-9._-]{24,}"
    "[0-9a-f]{32,}\.[A-Za-z0-9]{16,}"
)
ALTERNATION="$(IFS='|'; printf '%s' "${PATTERNS[*]}")"

if [[ -n "${ZCL_API_KEY_SCAN_FILES:-}" ]]; then
    read -r -a files <<< "$ZCL_API_KEY_SCAN_FILES"
    floor=1
else
    mapfile -t files < <(git ls-files \
        ':!:vendor/**' ':!:tools/lint/check_no_api_keys.sh' \
        ':!:**/*.png' ':!:**/*.jpg' ':!:**/*.gz' ':!:**/*.xz' \
        ":!:**/*.zip" ":!:**/*.pdf" ":!:**/*.ico" \
        ":!:**/*.bin" ":!:**/*.dat" ":!:tests/harness/fuzz_seeds/**")
    floor=1000
fi

if (( ${#files[@]} < floor )); then
    echo "check_no_api_keys: FATAL — scanned ${#files[@]} files (floor $floor)." >&2
    echo "check_no_api_keys: a broken scan is never reported as clean." >&2
    exit 2
fi

# `grep -a` because a tracked file can carry a NUL and a binary-mode grep would
# report a FALSE clean on it (see the tree's log-grep note). -I would do the
# same thing, and is why it is not used.
matches="$(printf '%s\n' "${files[@]}" \
    | xargs -r -d '\n' grep -a -n -E -H "$ALTERNATION" -- 2>/dev/null \
    | grep -a -v "api-key-example-ok" \
    | tr -d '\000' \
    || true)"

if [[ -n "$matches" ]]; then
    echo "[check_no_api_keys] a credential-shaped string is in a tracked file:"
    printf '%s\n' "$matches" | head -20
    echo "[check_no_api_keys] a key in this tree is SPENT — it is in the history,"
    echo "[check_no_api_keys] on every clone, and on every mirror. Rotate it, then"
    echo "[check_no_api_keys] keep the replacement in the environment or in a 0600"
    echo "[check_no_api_keys] file outside the repository (see engine/engine_secret.h)."
    echo "[check_no_api_keys] For a documented non-credential, append the marker"
    echo "[check_no_api_keys] api-key-example-ok to the line."
    exit 1
fi

echo "[check_no_api_keys] 0 violation(s) across ${#files[@]} file(s) (mode: FAIL)"
exit 0
