#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Generate compile_commands.json from the real non-LTO dev-object recipes.
#
# The Makefile remains the authority for source discovery, generated-header
# prerequisites, compiler wrappers, and target-specific DEV_HOT_CFLAGS.  This
# script asks make for DEV_OBJS, forces a dry-run of those exact targets, and
# converts only the emitted compile recipes into a compilation database.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/dev/dev_lib.sh
. "$SCRIPT_DIR/dev_lib.sh"  # is_true (fail() below satisfies its contract)
ROOT="${ZCL_AGENT_INDEX_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OUTPUT="${ZCL_AGENT_COMPDB_PATH:-$ROOT/compile_commands.json}"
STATE_DIR="${ZCL_AGENT_INDEX_STATE_DIR:-$ROOT/.cache/zcl-agent-index}"
STATUS_FILE="${ZCL_AGENT_INDEX_STATUS_PATH:-$STATE_DIR/status.json}"
CLANGD_CHECK="${ZCL_AGENT_INDEX_CLANGD_CHECK:-0}"
MAKE_BIN="${MAKE:-make}"

TMP_DIR=""
TMP_PATHS=()

log()
{
    printf '[agent-index] %s\n' "$*"
}

fail()
{
    printf '[agent-index] FATAL: %s\n' "$*" >&2
    exit 2
}

usage()
{
    printf '%s\n' \
        'Usage: tools/dev/generate-compdb.sh [--status|--clangd-check|--no-clangd-check]' \
        '' \
        'Generates root compile_commands.json from exact forced dry-runs of DEV_OBJS.' \
        'clangd is optional; --clangd-check validates one representative TU.' \
        '' \
        'Environment:' \
        '  ZCL_AGENT_COMPDB_PATH          output database path' \
        '  ZCL_AGENT_INDEX_STATE_DIR      metadata/cache directory' \
        '  ZCL_AGENT_INDEX_STATUS_PATH    metadata JSON path' \
        '  ZCL_AGENT_INDEX_CLANGD_CHECK   0 (default) or 1' \
        '  ZCL_AGENT_INDEX_CHECK_FILE     representative TU for clangd --check'
}

json_escape()
{
    printf '%s' "$1" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e ':a;N;$!ba;s/\n/\\n/g'
}

hash_file()
{
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        fail 'sha256sum or shasum is required to record index freshness'
    fi
}

write_json_word_array()
{
    local sep="" word
    printf '['
    for word in "$@"; do
        [ -n "$word" ] || continue
        printf '%s"%s"' "$sep" "$(json_escape "$word")"
        sep=','
    done
    printf ']'
}

cleanup()
{
    local path
    for path in "${TMP_PATHS[@]}"; do
        [ -n "$path" ] && rm -f "$path"
    done
    [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}

query_make_graph()
{
    local destination="$1"
    "$MAKE_BIN" -s --no-print-directory -f Makefile -f - \
        ZCL_COMPDB_GRAPH_PATH="$destination" zcl-compdb-vars <<'MAKE_EOF'
.PHONY: zcl-compdb-vars
zcl-compdb-vars:
	@$(file >$(ZCL_COMPDB_GRAPH_PATH),VIEW_GEN_HEADERS=$(VIEW_GEN_HEADERS))
	@$(foreach obj,$(DEV_OBJS),$(file >>$(ZCL_COMPDB_GRAPH_PATH),DEV_OBJ=$(obj)))
	@true
MAKE_EOF
}

write_input_manifest()
{
    local output="$1"
    (
        cd "$ROOT"
        for path in Makefile tools/dev/generate-compdb.sh; do
            if [ -f "$path" ]; then
                stat -c '%n\t%s\t%Y' "$path"
            fi
        done
        find core engine contexts cognition platform tools vendor/include \
            -type f \
            \( -name '*.c' -o -name '*.h' -o -name '*.def' -o \
               -name '*.inc' -o -name '*.mk' -o -name '*.tmpl' -o \
               -name '*.css' \) \
            -printf '%p\t%s\t%T@\n' 2>/dev/null
    ) | LC_ALL=C sort -u > "$output"
}

json_string_field()
{
    local path="$1" key="$2"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
        "$path" | sed -n '1p'
}

json_uint_field()
{
    local path="$1" key="$2"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" \
        "$path" | sed -n '1p'
}

emit_runtime_status()
{
    local database="$OUTPUT" metadata_present=false database_present=false
    local metadata_valid=false recorded_hash="" actual_hash="" entry_count=0
    local generated_at="" clangd_available=false clangd_status="unknown"
    local source_newer=false newer_path="" freshness="missing"
    local database_size=0 database_mtime=0 hash_matches=false

    if [ -r "$STATUS_FILE" ]; then
        metadata_present=true
        if grep -q '"schema":"zcl.agent_index_status.v1"' "$STATUS_FILE"; then
            metadata_valid=true
        fi
        database="$(json_string_field "$STATUS_FILE" compilation_database)"
        [ -n "$database" ] || database="$OUTPUT"
        recorded_hash="$(json_string_field "$STATUS_FILE" compdb_sha256)"
        entry_count="$(json_uint_field "$STATUS_FILE" entry_count)"
        [ -n "$entry_count" ] || entry_count=0
        generated_at="$(json_string_field "$STATUS_FILE" generated_at_utc)"
        clangd_status="$(json_string_field "$STATUS_FILE" clangd_check_status)"
        grep -q '"clangd_available":true' "$STATUS_FILE" &&
            clangd_available=true
    fi
    if [ -r "$database" ]; then
        database_present=true
        database_size="$(stat -c '%s' "$database" 2>/dev/null || printf 0)"
        database_mtime="$(stat -c '%Y' "$database" 2>/dev/null || printf 0)"
        actual_hash="$(hash_file "$database")"
        if [ -n "$recorded_hash" ] && [ "$recorded_hash" = "$actual_hash" ]; then
            hash_matches=true
        fi
        newer_path="$({
            [ "$ROOT/Makefile" -nt "$database" ] && printf '%s\n' Makefile
            [ "$ROOT/tools/dev/generate-compdb.sh" -nt "$database" ] &&
                printf '%s\n' tools/dev/generate-compdb.sh
            find "$ROOT/core" "$ROOT/engine" "$ROOT/contexts" \
                "$ROOT/cognition" "$ROOT/platform" "$ROOT/tools" \
                "$ROOT/vendor/include" -type f \
                \( -name '*.c' -o -name '*.h' -o -name '*.def' -o \
                   -name '*.inc' -o -name '*.mk' -o -name '*.tmpl' -o \
                   -name '*.css' \) -newer "$database" -print -quit 2>/dev/null
        } | sed -n '1p')"
        [ -n "$newer_path" ] && source_newer=true
        if [ "$metadata_valid" != true ]; then
            freshness="metadata_missing_or_invalid"
        elif [ "$hash_matches" != true ]; then
            freshness="content_hash_mismatch"
        elif [ "$source_newer" = true ]; then
            freshness="stale_source_inputs"
        else
            freshness="fresh"
        fi
    fi
    printf '{'
    printf '"schema":"zcl.agent_index_runtime.v1",'
    printf '"status":"%s",' "$([ "$freshness" = fresh ] && printf ok || printf attention)"
    printf '"command":"make agent-index","generator":"tools/dev/generate-compdb.sh",'
    printf '"compilation_database":"%s",' "$(json_escape "$database")"
    printf '"database_present":%s,"database_size_bytes":%s,"database_mtime_epoch":%s,' \
        "$database_present" "$database_size" "$database_mtime"
    printf '"metadata":"%s","metadata_present":%s,"metadata_valid":%s,' \
        "$(json_escape "$STATUS_FILE")" "$metadata_present" "$metadata_valid"
    printf '"entry_count":%s,"recorded_sha256":"%s","actual_sha256":"%s",' \
        "$entry_count" "$recorded_hash" "$actual_hash"
    printf '"content_hash_matches":%s,"source_inputs_newer":%s,' \
        "$hash_matches" "$source_newer"
    printf '"newer_input":"%s","fresh":%s,"freshness":"%s",' \
        "$(json_escape "$newer_path")" \
        "$([ "$freshness" = fresh ] && printf true || printf false)" "$freshness"
    printf '"generated_at_utc":"%s","clangd_optional":true,' \
        "$(json_escape "$generated_at")"
    printf '"clangd_available":%s,"clangd_check_status":"%s",' \
        "$clangd_available" "$(json_escape "$clangd_status")"
    printf '"agent_next_action":"%s"' \
        "$([ "$freshness" = fresh ] && printf 'use the fresh compilation database' || printf 'run make agent-index')"
    printf '}\n'
}

emit_compdb()
{
    local rows="$1" destination="$2" first=1
    local source object command

    printf '[\n' > "$destination"
    while IFS=$'\t' read -r source object command; do
        [ -n "$source" ] || continue
        if [ "$first" -eq 0 ]; then
            printf ',\n' >> "$destination"
        fi
        first=0
        printf '  {"directory":"%s","file":"%s","output":"%s","command":"%s"}' \
            "$(json_escape "$ROOT")" \
            "$(json_escape "$source")" \
            "$(json_escape "$object")" \
            "$(json_escape "$command")" >> "$destination"
    done < "$rows"
    printf '\n]\n' >> "$destination"
}

main()
{
    local graph headers_line raw rows compdb_tmp status_tmp
    local object_count entry_count generated_at generated_epoch
    local compdb_hash compdb_size compdb_mtime input_hash latest_input
    local clangd_available=false clangd_version="" clangd_status="not_requested"
    local clangd_log="$STATE_DIR/clangd-check.log" check_file
    local -a dev_objects=() generated_headers=()

    case "${1:-}" in
        --help|-h) usage; return 0 ;;
        --status) emit_runtime_status; return 0 ;;
        --clangd-check) CLANGD_CHECK=1 ;;
        --no-clangd-check|"") ;;
        *) usage >&2; return 2 ;;
    esac

    [ -f "$ROOT/Makefile" ] || fail "Makefile not found below $ROOT"
    mkdir -p "$(dirname "$OUTPUT")" "$STATE_DIR" \
             "$(dirname "$STATUS_FILE")"
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zcl-agent-index.XXXXXX")" ||
        fail 'could not create temporary workspace'
    trap cleanup EXIT

    cd "$ROOT"
    graph="$TMP_DIR/make-graph.txt"
    query_make_graph "$graph"
    headers_line="$(sed -n 's/^VIEW_GEN_HEADERS=//p' "$graph")"
    mapfile -t dev_objects < <(sed -n 's/^DEV_OBJ=//p' "$graph" |
        sed '/^$/d')
    mapfile -t generated_headers < <(
        printf '%s\n' "$headers_line" | tr ' ' '\n' | sed '/^$/d')
    object_count="${#dev_objects[@]}"
    [ "$object_count" -gt 0 ] || fail 'no dev objects parsed from Makefile'

    raw="$TMP_DIR/make-dry-run.txt"
    rows="$TMP_DIR/compile-rows.tsv"
    log "dry-running $object_count real dev-object targets"
    ZCL_COMPDB_FORCE=1 "$MAKE_BIN" --no-print-directory -n \
        "${dev_objects[@]}" > "$raw"

    awk '
        {
            if (sub(/\\$/, "")) {
                continued = continued $0 " "
                next
            }
            print continued $0
            continued = ""
        }
        END { if (continued != "") print continued }
    ' "$raw" | awk '
        index($0, "compile-epoch-object.sh dep ") {
            n = split($0, words, /[[:space:]]+/)
            source = ""
            object = ""
            separator = 0
            for (i = 1; i <= n; i++) {
                if (words[i] ~ /compile-epoch-object[.]sh$/ &&
                    i + 3 <= n && words[i + 1] == "dep") {
                    object = words[i + 2]
                    source = words[i + 3]
                }
                if (words[i] == "--")
                    separator = i
            }
            gsub(/^"|"$/, "", object)
            gsub(/^"|"$/, "", source)
            command = ""
            if (separator > 0) {
                for (i = separator + 1; i <= n; i++)
                    command = command (command == "" ? "" : " ") words[i]
                dep = object
                sub(/[.]o$/, ".d", dep)
                command = command " -MMD -MP -MF " dep " -MT " object \
                          " -c -o " object " " source
            }
            if (source ~ /[.]c$/ &&
                object ~ /^build\/dev-obj\/epochs\/[0-9a-f]+\/.*[.]o$/ &&
                separator > 0)
                print source "\t" object "\t" command
        }
    ' | LC_ALL=C sort -t $'\t' -k1,1 -u > "$rows"

    entry_count="$(sed '/^$/d' "$rows" | wc -l | tr -d ' ')"
    if [ "$entry_count" -ne "$object_count" ]; then
        fail "parsed $entry_count compile commands for $object_count dev objects"
    fi

    compdb_tmp="$(mktemp "$(dirname "$OUTPUT")/.compile_commands.json.XXXXXX")" ||
        fail 'could not create atomic compilation-database staging file'
    TMP_PATHS+=("$compdb_tmp")
    emit_compdb "$rows" "$compdb_tmp"
    mv -f "$compdb_tmp" "$OUTPUT"

    generated_at="$(date -u +%FT%TZ)"
    generated_epoch="$(date +%s)"
    compdb_hash="$(hash_file "$OUTPUT")"
    compdb_size="$(stat -c '%s' "$OUTPUT")"
    compdb_mtime="$(stat -c '%Y' "$OUTPUT")"
    write_input_manifest "$TMP_DIR/inputs.manifest"
    input_hash="$(hash_file "$TMP_DIR/inputs.manifest")"
    latest_input="$(sort -t $'\t' -k3,3nr "$TMP_DIR/inputs.manifest" |
        sed -n '1p' | cut -f1 || true)"

    if command -v clangd >/dev/null 2>&1; then
        clangd_available=true
        clangd_version="$(clangd --version 2>/dev/null | sed -n '1p' || true)"
    fi
    if is_true "$CLANGD_CHECK"; then
        if [ "$clangd_available" != true ]; then
            clangd_status="unavailable"
        else
            check_file="${ZCL_AGENT_INDEX_CHECK_FILE:-cognition/controllers/src/agent_controller.c}"
            if clangd --compile-commands-dir="$ROOT" \
                    --check="$ROOT/$check_file" --log=error \
                    > "$clangd_log" 2>&1; then
                clangd_status="passed"
            else
                clangd_status="failed"
            fi
        fi
    fi

    status_tmp="$(mktemp "$(dirname "$STATUS_FILE")/.status.json.XXXXXX")" ||
        fail 'could not create atomic index-status staging file'
    TMP_PATHS+=("$status_tmp")
    {
        printf '{\n'
        printf '  "schema":"zcl.agent_index_status.v1",\n'
        printf '  "status":"ok",\n'
        printf '  "generated_at_utc":"%s",\n' "$(json_escape "$generated_at")"
        printf '  "generated_at_epoch":%s,\n' "$generated_epoch"
        printf '  "repo_root":"%s",\n' "$(json_escape "$ROOT")"
        printf '  "compilation_database":"%s",\n' "$(json_escape "$OUTPUT")"
        printf '  "entry_count":%s,\n' "$entry_count"
        printf '  "dev_object_count":%s,\n' "$object_count"
        printf '  "compdb_sha256":"%s",\n' "$compdb_hash"
        printf '  "compdb_size_bytes":%s,\n' "$compdb_size"
        printf '  "compdb_mtime_epoch":%s,\n' "$compdb_mtime"
        printf '  "input_manifest_sha256":"%s",\n' "$input_hash"
        printf '  "latest_input_path":"%s",\n' "$(json_escape "$latest_input")"
        printf '  "make_derivation":"ZCL_COMPDB_FORCE=1 make --no-print-directory -n <DEV_OBJS>",\n'
        printf '  "generated_headers":'
        write_json_word_array "${generated_headers[@]}"
        printf ',\n'
        printf '  "clangd_available":%s,\n' "$clangd_available"
        printf '  "clangd_version":"%s",\n' "$(json_escape "$clangd_version")"
        printf '  "clangd_check_requested":%s,\n' \
            "$(is_true "$CLANGD_CHECK" && printf true || printf false)"
        printf '  "clangd_check_status":"%s",\n' "$clangd_status"
        printf '  "clangd_check_log":"%s",\n' "$(json_escape "$clangd_log")"
        printf '  "agent_next_action":"%s"\n' \
            "$(if [ "$clangd_status" = failed ]; then printf 'inspect %s' "$clangd_log"; else printf 'use compile_commands.json with any C23 indexer'; fi)"
        printf '}\n'
    } > "$status_tmp"
    mv -f "$status_tmp" "$STATUS_FILE"

    log "wrote $entry_count exact dev compile commands to $OUTPUT"
    log "status=$STATUS_FILE clangd=$clangd_status"
    [ "$clangd_status" != failed ]
}

main "$@"
