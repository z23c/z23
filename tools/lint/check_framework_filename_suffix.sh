#!/usr/bin/env bash
# Lint gate #22 — framework filename suffix: no foreign-shape suffix (HARD).
#
# "The folder is the type; the filename is the entity" (FRAMEWORK.md Law 1).
# A file whose name ends in ANOTHER shape's suffix — e.g. a *_controller.c
# living in engine/services/src/ — lies about its shape and re-introduces the
# exact naming drift the S1 service renames removed. This gate locks that
# in: it is the recurrence guard for "filename matches folder".
#
# Rule (NEGATIVE, not positive): a file in shape folder F may not end with
# the distinctive suffix of a DIFFERENT shape. The seven physical-folder
# shape suffixes are
#   controller service model view job supervisor condition
# (the eighth shape, Event, has no app/ folder — see FRAMEWORK.md §3 row 7 —
# so it carries no suffix to guard here). A file may freely use its OWN
# shape's suffix (services/foo_service.c) or
# a bare entity name (models/block.c, jobs/validate_headers_stage.c) — only
# a FOREIGN-shape suffix is rejected. A positive "must end in _service"
# rule would reject ~190 legitimately entity-named files; this does not.
# Note: _store / _repository name no shape, so they are not foreign
# suffixes (models/mmb_leaf_store.c is a storage entity, not a violation).
#
# Override: a file whose entity name legitimately ends in a shape word —
# e.g. models/file_service.c, where the entity is a "file service" offer,
# a Model, not the Service shape — may carry a top-of-file marker
# '// suffix-ok:<tag>' (no space after the colon, non-empty tag).
set -euo pipefail

cd "$(dirname "$0")/../.."

# folder basename -> this folder's own shape suffix (the one it may keep)
declare -A OWN=(
    [controllers]=controller
    [services]=service
    [models]=model
    [views]=view
    [jobs]=job
    [supervisors]=supervisor
    [conditions]=condition
)
ALL_SHAPES="controller service model view job supervisor condition"

# The singular suffix for each shape is hand-knowledge (services -> service,
# but also conditions -> condition and views -> view; no rule derives it), so
# the map above stays hand-written. What IS derivable is whether the map is
# COMPLETE: assert it covers exactly the shapes the Makefile declares, so a new
# shape cannot be silently unchecked by this gate.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"
for _shape in "${ZCL_APP_SHAPES[@]}"; do
    if [ -z "${OWN[$_shape]:-}" ]; then
        echo "check_framework_filename_suffix: FATAL — Makefile APP_DIRS has" >&2
        echo "  '$_shape' but the OWN[] suffix map has no entry for it." >&2
        echo "  Add its singular suffix; leaving it out silently exempts the" >&2
        echo "  whole app/$_shape/ tree from this gate." >&2
        exit 2
    fi
done
for _shape in "${!OWN[@]}"; do
    _hit=0
    for _s in "${ZCL_APP_SHAPES[@]}"; do [ "$_shape" = "$_s" ] && _hit=1 && break; done
    if [ "$_hit" -eq 0 ]; then
        echo "check_framework_filename_suffix: FATAL — OWN[] has '$_shape'" >&2
        echo "  but the Makefile's APP_DIRS does not declare it." >&2
        exit 2
    fi
done
unset _shape _s _hit

fail=0
violations=()

for folder in "${!OWN[@]}"; do
    own="${OWN[$folder]}"
    while IFS= read -r d; do
        while IFS= read -r f; do
            [ -e "$f" ] || continue
            b="$(basename "$f" .c)"
            # Override marker anywhere in the file: skip.
            if grep -qE '//[[:space:]]*suffix-ok:[A-Za-z0-9][A-Za-z0-9_-]*' "$f" 2>/dev/null; then
                continue
            fi
            for shape in $ALL_SHAPES; do
                [ "$shape" = "$own" ] && continue
                case "$b" in
                    *_"$shape")
                        violations+=("$f ends in foreign-shape suffix _$shape (this folder's shape: $own)")
                        fail=1
                        break ;;
                esac
            done
        done < <(find "$d/src" -maxdepth 1 -type f -name '*.c' 2>/dev/null | sort)
    done < <(repo_shape_room_dirs "$folder")
done

if [ "$fail" = "0" ]; then
    echo "check_framework_filename_suffix: clean — no shape file carries a foreign-shape filename suffix"
    exit 0
fi

echo ""
echo "check_framework_filename_suffix: ${#violations[@]} foreign-shape filename suffix violation(s)"
echo ""
for v in "${violations[@]}"; do
    echo "  $v"
done
echo ""
echo "Fix options:"
echo "  1. Rename the file to its own shape's suffix or a bare entity name."
echo "  2. Move it to the folder whose shape its suffix names."
echo "  3. If the entity name legitimately ends in that shape word, add a"
echo "     top-of-file marker '// suffix-ok:<tag>' explaining why."
exit 1
