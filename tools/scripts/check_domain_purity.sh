#!/usr/bin/env bash
# Lint gate #45 — domain/ source purity (HARD).
#
# domain/ is the innermost layer: pure consensus/validation logic with no
# upstream or sideways dependencies. A domain/ file may ONLY #include:
#
#   (1) its own domain headers   — #include "domain/<sub>/<x>.h"
#   (2) C / POSIX system headers — #include <...>
#   (3) a domain-LOCAL sibling file reached without a path prefix — any quoted
#       include with NO slash (e.g. a bare "foo.h" or "table.inc" that sits in
#       the same src/ dir) is a bare sibling and is allowed. (The consensus
#       predicates and their siblings "reject_out.h" /
#       "oversize_grandfather_table.inc" moved to the sealed core/consensus/ in
#       the Wave 1.1 split; that tree is governed by check-core-include-boundary.)
#   (4) a fixed set of 12 lib/ subsystem prefixes, each of which resolves to
#       lib/<x>/include/<x>/... :
#         bloom chain coins consensus core crypto keys primitives
#         script support util validation
#
# This gate FORBIDS, with no baseline / ratchet (the tree is already clean):
#   (a) any include from the app/ shapes —
#         "controllers/..." "models/..." "services/..." "views/..."
#       (domain leaking UP into an application shape), and
#   (b) any quoted slash-include whose top-level prefix is NOT in the allow
#       set {domain + the 12 lib subsystems above} — e.g. "app/...",
#       "platform/ports/...", "tools/...", or an outer lib subsystem not on the list
#       (domain leaking SIDEWAYS into an unlisted module).
#
# The allow set is implemented positively: any quoted slash-include whose
# top-level prefix is not "domain" and not one of the 12 lib subsystems is a
# violation. This inherently catches controllers/models/services/views/app and
# anything else. Bare (no-slash) quoted includes are siblings and are skipped.
# System <...> includes are never scanned (only quoted includes are checked).
#
# (Supersedes the note in check_lib_layering.sh that the domain/ source-purity
# ratchet "does not exist as a script yet" — this is that gate.)
#
# Override on a specific line (preferred when you understand the trade-off and
# want to keep the include): add `// domain-purity-ok:<tag>` after the include
# directive. Use sparingly — every override is a debt marker.
#
# To clean up debt: remove the include from domain/ code (move the symbol into
# domain/, depend on one of the 12 allowed lib subsystems, or push the logic up
# into the app/ layer that should own it).
set -euo pipefail

# Run from the repo root regardless of the caller's CWD.
cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh
# shellcheck source=tools/lint/repo_shape.sh
source tools/lint/repo_shape.sh

# The allow set: domain self-includes + the 12 lib subsystem prefixes. Any
# quoted slash-include whose first path component is not in this set is a
# violation (this is what makes the gate catch app/ + platform/ports/ + unlisted lib/).
declare -A allow
for p in domain bloom chain coins consensus core crypto keys \
         primitives script support util validation; do
    allow["$p"]=1
done

fail=0
violations=()

while IFS= read -r f; do
    # Scan only quoted includes that contain a slash (so bare-sibling includes
    # like "reject_out.h" / "oversize_grandfather_table.inc" are ignored).
    while IFS= read -r match; do
        lineno="${match%%:*}"
        line_content="${match#*:}"

        # Per-line override marker: skip immediately.
        if echo "$line_content" | grep -qE '//[[:space:]]*domain-purity-ok:[A-Za-z][A-Za-z0-9_-]*'; then
            continue
        fi

        # Extract the included path (between the first pair of double quotes).
        hdr=$(echo "$line_content" | sed -E 's@^[^"]*"@@; s@".*$@@')
        # First path component (top-level prefix).
        prefix="${hdr%%/*}"

        if [ -n "${allow[$prefix]+x}" ]; then
            continue
        fi

        violations+=("$f:$lineno domain may not include $hdr")
        fail=1
    done < <(grep -nE '^[[:space:]]*#include[[:space:]]+"[^"]+/' "$f" || true)
done < <(
    while IFS= read -r domain_dir; do
        find "$domain_dir" -type f \( -name '*.c' -o -name '*.h' \) \
            ! -path '*/test/*' "${LINT_FIND_PRUNE_ARGS[@]}"
    done < <(repo_shape_dirs domain)
)

if [ "$fail" = "0" ]; then
    echo "check_domain_purity: clean — domain/ has no app/lib includes"
    exit 0
fi

echo ""
echo "check_domain_purity: ${#violations[@]} forbidden include(s) in domain/"
echo ""
for v in "${violations[@]}"; do
    echo "FAIL: $v"
done
echo ""
echo "domain/ is the innermost layer. A domain/ file may only include:"
echo "  - its own domain headers   #include \"domain/<sub>/<x>.h\""
echo "  - C / POSIX system headers #include <...>"
echo "  - bare domain-local siblings (a quoted include with no slash)"
echo "  - one of the 12 allowed lib subsystems:"
echo "      bloom chain coins consensus core crypto keys"
echo "      primitives script support util validation"
echo ""
echo "Fix options (this is a HARD gate — there is no baseline):"
echo "  1. Delete the include if it's unused."
echo "  2. Move the needed symbol down into domain/ (or one of the 12 libs)."
echo "  3. Push the logic up into the app/ layer that should own it."
echo "  4. As a deliberate, reviewed exception only, add an override marker"
echo "     '// domain-purity-ok:<tag>' to the include line."
exit 1
