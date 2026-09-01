#!/usr/bin/env bash
# check_model_ar_lifecycle.sh
#
# Model saves must not hand-run the ActiveRecord callback internals. Use
# AR_BEGIN_SAVE / AR_ADHOC_SAVE / AR_FINISH_SAVE so validation, callbacks,
# logging, and future lifecycle hooks stay mechanically consistent.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/scan_exclusions.sh
source "$ROOT/tools/lint/scan_exclusions.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$ROOT/tools/lint/repo_shape.sh"

shopt -s nullglob
mapfile -t model_dirs < <(repo_shape_room_dirs models)
files=()
for model_dir in "${model_dirs[@]}"; do
    for model_file in "$model_dir"/src/*.c; do files+=("$model_file"); done
done
if [[ "${ZCL_LINT_PRODUCTION_SCAN:-0}" == "1" ]]; then
    kept=()
    for f in "${files[@]}"; do
        lint_path_is_excluded "$f" || kept+=("$f")
    done
    files=("${kept[@]}")
fi
if (( ${#files[@]} < 20 )); then
    echo "FAIL: check_model_ar_lifecycle scanned only ${#files[@]} model file(s)"
    echo "      expected physical */models/src/*.c rooms; gate would be hollow"
    exit 2
fi

violations=()
for f in "${files[@]}"; do
    while IFS= read -r line; do
        trimmed="${line#*:}"
        trimmed="${trimmed#*:}"
        trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
        case "$trimmed" in
            '/*'*|'*'*|'//'*) continue ;;
        esac
        if printf '%s\n' "$line" | grep -qE 'ar-lifecycle-ok:[A-Za-z][A-Za-z0-9_-]*'; then
            continue
        fi
        violations+=("$line")
    done < <(grep -nHE '\bar_run_(before|after)_save[[:space:]]*\(' "$f" || true)
done

set +e
save_scan=$(awk '
function reset_fn() {
    in_fn = 0
    saw_open = 0
    depth = 0
    fn_name = ""
    fn_body = ""
    fn_line = 0
}

function brace_delta(s, tmp, opens, closes) {
    tmp = s
    opens = gsub(/\{/, "{", tmp)
    tmp = s
    closes = gsub(/\}/, "}", tmp)
    return opens - closes
}

function finish_fn(   key) {
    key = FILENAME SUBSEP fn_line SUBSEP fn_name
    keys[++key_count] = key
    names[key] = fn_name
    paths[key] = FILENAME
    lines[key] = fn_line
    bodies[key] = fn_body
    if (fn_body ~ /AR_BEGIN_SAVE|AR_ADHOC_SAVE|AR_CACHED_SAVE|ar-lifecycle-ok:/)
        ar_reached[FILENAME SUBSEP fn_name] = 1
    if (fn_name ~ /^db_[A-Za-z0-9_]+_save$/)
        targets[++target_count] = key
    reset_fn()
}

function calls_ar_helper(body, path,   i, key, name, needle) {
    for (i = 1; i <= key_count; i++) {
        key = keys[i]
        if (paths[key] != path)
            continue
        name = names[key]
        if (!ar_reached[path SUBSEP name])
            continue
        needle = "(^|[^A-Za-z0-9_])" name "[[:space:]]*\\("
        if (body ~ needle)
            return 1
    }
    return 0
}

BEGIN { reset_fn() }

!in_fn &&
/^[[:space:]]*(static[[:space:]]+)?bool[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(/ {
    line = $0
    sub(/^.*bool[[:space:]]+/, "", line)
    sub(/[[:space:]]*\(.*/, "", line)
    fn_name = line
    fn_line = FNR
    in_fn = 1
}

in_fn {
    fn_body = fn_body $0 "\n"
    if ($0 ~ /\{/)
        saw_open = 1
    if (saw_open)
        depth += brace_delta($0)
    if (saw_open && depth == 0)
        finish_fn()
}

ENDFILE {
    if (in_fn) {
        printf("FATAL: unmatched function braces in %s at line %d\n",
               FILENAME, fn_line) > "/dev/stderr"
        exit 2
    }
    reset_fn()
}

END {
    for (i = 1; i <= target_count; i++) {
        key = targets[i]
        body = bodies[key]
        if (body ~ /AR_BEGIN_SAVE|AR_ADHOC_SAVE|AR_CACHED_SAVE|ar-lifecycle-ok:/)
            continue
        if (calls_ar_helper(body, paths[key]))
            continue
        printf("%s:%d: %s does not reach AR_BEGIN_SAVE / AR_ADHOC_SAVE / AR_CACHED_SAVE\n",
               paths[key], lines[key], names[key])
    }
}
' "${files[@]}"
)
save_rc=$?
set -e
if (( save_rc >= 2 )); then
    exit "$save_rc"
fi
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    violations+=("$line")
done <<< "$save_scan"

if (( ${#violations[@]} == 0 )); then
    echo "check_model_ar_lifecycle: clean — model saves use AR lifecycle macros"
    exit 0
fi

echo "FAIL: model sources call AR save callbacks directly:"
printf '  %s\n' "${violations[@]}"
echo ""
echo "Use AR_BEGIN_SAVE / AR_ADHOC_SAVE / AR_FINISH_SAVE so validation and"
echo "before/after-save hooks remain in one defensive lifecycle."
exit 1
