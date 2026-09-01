# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# The one shell view of Z23's physical architecture. Consumers source this
# file instead of restating roots, contexts, shapes, or module locations.

_repo_shape_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/lint/gate_lib.sh
. "$_repo_shape_dir/gate_lib.sh"

ZCL_REPO_SHAPE_ROOT="${ZCL_REPO_SHAPE_ROOT:-$_repo_shape_dir/../..}"
ZCL_REPO_SHAPE_MAKEFILE="${ZCL_REPO_SHAPE_MAKEFILE:-$ZCL_REPO_SHAPE_ROOT/Makefile}"
ZCL_REPO_SHAPE_MODULE_DEF="${ZCL_REPO_SHAPE_MODULE_DEF:-$ZCL_REPO_SHAPE_ROOT/engine/composition/lib_module_order.def}"

if [ ! -r "$ZCL_REPO_SHAPE_MAKEFILE" ] ||
   [ ! -r "$ZCL_REPO_SHAPE_MODULE_DEF" ]; then
    echo "repo-shape: FATAL — architecture declarations are unreadable" >&2
    exit 2
fi

_repo_shape_make_list() {
    local variable="$1"
    awk -v wanted="$variable" '
        function emit(line,   n, item, values) {
            sub(/#.*/, "", line); gsub(/\\/, " ", line)
            n = split(line, values, /[ \t]+/)
            for (item = 1; item <= n; item++)
                if (values[item] != "") print values[item]
        }
        $0 ~ "^" wanted "[ \t]*=" {
            line=$0; sub(/^[^=]*=/, "", line)
            while ($0 ~ /\\[ \t]*$/) {
                if (getline <= 0) exit 2
                line=line " " $0
            }
            emit(line); exit
        }
    ' "$ZCL_REPO_SHAPE_MAKEFILE"
}

# shellcheck disable=SC2034
mapfile -t ZCL_PRODUCT_CONTEXTS < <(_repo_shape_make_list PRODUCT_CONTEXTS)
# shellcheck disable=SC2034
mapfile -t ZCL_APP_SHAPES < <(_repo_shape_make_list APP_DIRS)
# shellcheck disable=SC2034
mapfile -t ZCL_LIB_MODULES < <(sed -n 's/^[[:space:]]*LIB_MODULE("\([A-Za-z0-9_]*\)").*/\1/p' \
    "$ZCL_REPO_SHAPE_MODULE_DEF" | LC_ALL=C sort -u)

gate_require_scanned "${#ZCL_PRODUCT_CONTEXTS[@]}" 1 repo-shape \
    "PRODUCT_CONTEXTS parse came back empty"
gate_require_scanned "${#ZCL_APP_SHAPES[@]}" 1 repo-shape \
    "APP_DIRS parse came back empty"
gate_require_scanned "${#ZCL_LIB_MODULES[@]}" 1 repo-shape \
    "module declaration parse came back empty"

# These are the only source authorities visible at repository root. Tests and
# tools are navigable support roots, not production authorities.
# shellcheck disable=SC2034
ZCL_SOURCE_AUTHORITIES=(core engine contexts cognition platform)
# shellcheck disable=SC2034
ZCL_REPO_TOPS=(core engine contexts cognition platform tools tests)

# Physical directories are discovered beneath fixed authorities. The declared
# module names are checked against these directories by the Makefile and by
# check_architecture_tree.sh; this reader never guesses their owners.
mapfile -t ZCL_MODULE_DIRS < <(
    find "$ZCL_REPO_SHAPE_ROOT/core" "$ZCL_REPO_SHAPE_ROOT/engine" \
         "$ZCL_REPO_SHAPE_ROOT/cognition" "$ZCL_REPO_SHAPE_ROOT/platform" \
         "$ZCL_REPO_SHAPE_ROOT/contexts" \
         -type d -path '*/modules/*' -mindepth 2 -maxdepth 4 2>/dev/null |
    awk -v root="$ZCL_REPO_SHAPE_ROOT/" '
        { sub("^" root, ""); if ($0 ~ /\/modules\/[^/]+$/) print }
    ' | LC_ALL=C sort -u
)
gate_require_scanned "${#ZCL_MODULE_DIRS[@]}" "${#ZCL_LIB_MODULES[@]}" repo-shape \
    "physical module directory set is incomplete"

ZCL_APP_AUTHORITY_DIRS=(engine cognition)
for _repo_context in "${ZCL_PRODUCT_CONTEXTS[@]}"; do
    ZCL_APP_AUTHORITY_DIRS+=("contexts/$_repo_context")
done
unset _repo_context

ZCL_DOMAIN_DIRS=(contexts/wallet/domain platform/domain/encoding)

# Compatibility query used by lint consumers. `app` means every physical
# authority/shape room, `lib` means every physical module, and `domain` means
# each pure domain room. Output includes only paths that actually exist.
repo_shape_dirs() {
    local family="$1" leaf="${2:-}" base name path
    local -a candidates=()
    case "$family" in
        app)
            for base in "${ZCL_APP_AUTHORITY_DIRS[@]}"; do
                for name in "${ZCL_APP_SHAPES[@]}"; do
                    candidates+=("$base/$name")
                done
            done
            ;;
        lib) candidates=("${ZCL_MODULE_DIRS[@]}") ;;
        domain) candidates=("${ZCL_DOMAIN_DIRS[@]}") ;;
        *)
            echo "repo_shape_dirs: FATAL — unknown family '$family'" >&2
            exit 2
            ;;
    esac
    for base in "${candidates[@]}"; do
        path="$base${leaf:+/$leaf}"
        [ -d "$ZCL_REPO_SHAPE_ROOT/$path" ] && printf '%s\n' "$path"
    done
    return 0
}

# Emit one named product shape across all authorities. This is distinct from
# repo_shape_dirs app <leaf>, which appends a leaf below every existing shape.
repo_shape_room_dirs() {
    local shape="$1" base path count=0
    for base in "${ZCL_APP_AUTHORITY_DIRS[@]}"; do
        path="$base/$shape"
        if [ -d "$ZCL_REPO_SHAPE_ROOT/$path" ]; then
            printf '%s\n' "$path"
            count=$((count + 1))
        fi
    done
    if (( count == 0 )); then
        echo "repo_shape_room_dirs: FATAL — no '$shape' room exists" >&2
        exit 2
    fi
    return 0
}
