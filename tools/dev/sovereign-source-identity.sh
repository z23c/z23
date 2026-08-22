#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Git-free Make adapter for an externally authorized ZVCS source root.

set -euo pipefail

MODE="${1:-capture}"
EXPECTED="${2:-}"
EXPECTED_COMPLETE="${3:-}"
EXPECTED_MUTATION="${4:-}"
AUTHORITY="${ZCL_SOVEREIGN_SOURCE_ROOT:-}"
VERIFY_BIN="${ZCL_SOVEREIGN_VERIFY_BIN:-}"
SOURCE="$(pwd -P)"
ZCL_SOURCE_IDENTITY_SESSION="${ZCL_SOURCE_IDENTITY_SESSION:-}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-sovereign-identity.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
METADATA_SEQ=0

fail()
{
    echo "sovereign-source-identity: $*" >&2
    exit 3
}

[[ "$AUTHORITY" =~ ^[0-9a-f]{64}$ ]] ||
    fail "ZCL_SOVEREIGN_SOURCE_ROOT must be one lowercase 64-hex ZVCS root"
[ -n "$VERIFY_BIN" ] ||
    fail "ZCL_SOVEREIGN_VERIFY_BIN must name the trusted bootstrap binary"
VERIFY_BIN="$(realpath "$VERIFY_BIN" 2>/dev/null)" ||
    fail "bootstrap verifier does not resolve"
[ -f "$VERIFY_BIN" ] && [ -x "$VERIFY_BIN" ] ||
    fail "bootstrap verifier must be an executable regular file"
case "$SOURCE" in
    *'"'*|*'\'*|*$'\n'*|*$'\r'*)
        fail "source path cannot be represented by the native JSON input"
        ;;
esac

capture_authority()
{
    local output roots actual
    output="$("$VERIFY_BIN" zcode workspace source capture \
        --input="{\"workspace\":\"$SOURCE\"}")" ||
        fail "bootstrap verifier refused the source capture"
    [[ "$output" == *'"ok":true'* ]] ||
        fail "bootstrap verifier did not return a successful native result"
    roots="$(printf '%s\n' "$output" |
        grep -oE '"source_root":"[0-9a-f]{64}"' || true)"
    [ "$(printf '%s\n' "$roots" | sed '/^$/d' | wc -l)" -eq 1 ] ||
        fail "bootstrap verifier returned an ambiguous source root"
    actual="${roots#*:\"}"
    actual="${actual%\"}"
    [ "$actual" = "$AUTHORITY" ] ||
        fail "source authority mismatch: expected=$AUTHORITY actual=$actual"
    printf '%s\n' "$actual"
}

append_metadata()
{
    local root="$1" path relative seq batch_start batch_size=128
    local -a paths=() metadata=() batch=()
    [ -e "$root" ] || return 0
    seq="$METADATA_SEQ"
    METADATA_SEQ=$((METADATA_SEQ + 1))
    # Persistent build records bind actual compiler inputs, not parent
    # directory epochs. Several existing generators safely create and remove
    # temp files beside unchanged generated headers; binding those directory
    # mtimes would make an unchanged source root falsely supersede itself.
    # Every verify path independently recaptures the complete ZVCS root, so a
    # newly persistent file is still refused before an artifact is published.
    find "$root" -name .git -prune -o -name .zvcs -prune -o \
        \( -type f -o -type l \) -print0 \
        > "$WORK/paths.$seq" || fail "source inventory failed: $root"
    LC_ALL=C sort -z "$WORK/paths.$seq" > "$WORK/paths.$seq.sorted" ||
        fail "source inventory sort failed: $root"
    mapfile -d '' -t paths < "$WORK/paths.$seq.sorted"
    : > "$WORK/metadata.$seq"
    for ((batch_start = 0; batch_start < ${#paths[@]};
          batch_start += batch_size)); do
        batch=("${paths[@]:batch_start:batch_size}")
        stat --printf='%d:%i:%s:%f:%y:%z\0' -- "${batch[@]}" \
            >> "$WORK/metadata.$seq" ||
            fail "source metadata changed during capture: $root"
    done
    mapfile -d '' -t metadata < "$WORK/metadata.$seq"
    [ "${#paths[@]}" -eq "${#metadata[@]}" ] ||
        fail "source metadata batch was incomplete: $root"
    for ((batch_start = 0; batch_start < ${#paths[@]}; batch_start++)); do
        path="${paths[$batch_start]}"
        relative="${path#"$SOURCE"/}"
        printf 'P\0%s\0%s\0' "$relative" "${metadata[$batch_start]}"
    done
}

mutation_token()
{
    local root
    {
        printf 'zcl.sovereign_source_mutation.v1\0%s\0' "$AUTHORITY"
        for root in adapters app application config core domain lib ports src \
                    tools vendor/include vendor/lib vendor/tor; do
            append_metadata "$SOURCE/$root"
        done
        for root in Makefile LICENSE .ignore; do
            append_metadata "$SOURCE/$root"
        done
    } > "$WORK/mutation"
    sha256sum "$WORK/mutation" | awk '{print $1}'
}

capture_record()
{
    local before after actual
    actual="$(capture_authority)"
    before="$(mutation_token)"
    after="$(mutation_token)"
    [ "$before" = "$after" ] || fail "source mutated during record capture"
    printf '%s 1 %s\n' "$actual" "$after"
}

session_cache_path()
{
    local token="$1"
    [[ "$token" =~ ^[1-9][0-9]*:[0-9]+$ ]] || return 1
    printf '%s/build/identity/.session-cache/sovereign.%s.record' \
        "$SOURCE" "${token/:/.}"
}

prune_session_cache()
{
    local dir="$1" f base token pid start actual
    [ -d "$dir" ] || return 0
    for f in "$dir"/sovereign.*.record; do
        [ -e "$f" ] || continue
        base="$(basename -- "$f")"
        token="${base#sovereign.}"
        token="${token%.record}"
        pid="${token%%.*}"
        start="${token#*.}"
        actual=""
        if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ "$start" =~ ^[0-9]+$ ]]; then
            actual="$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)" ||
                actual=""
        fi
        [ -n "$actual" ] && [ "$actual" = "$start" ] && continue
        rm -f -- "$f" 2>/dev/null || true
    done
}

capture_record_cached()
{
    local cache tmp record
    cache="$(session_cache_path "$ZCL_SOURCE_IDENTITY_SESSION")" || {
        capture_record
        return
    }
    if [ -f "$cache" ]; then
        cat -- "$cache"
        return
    fi
    record="$(capture_record)" || return $?
    if mkdir -p "$(dirname -- "$cache")" 2>/dev/null; then
        prune_session_cache "$(dirname -- "$cache")"
        tmp="$(mktemp "$(dirname -- "$cache")/.tmp.XXXXXX" 2>/dev/null)" ||
            tmp=""
        if [ -n "$tmp" ]; then
            printf '%s\n' "$record" > "$tmp" && mv -f -- "$tmp" "$cache" ||
                rm -f -- "$tmp"
        fi
    fi
    printf '%s\n' "$record"
}

case "$MODE" in
    paths) ;;
    capture) capture_authority ;;
    capture-record) capture_record_cached ;;
    session-cache-drop)
        # Same parse/restart-boundary contract as source-identity.sh: a
        # bootstrap include that establishes build inputs invalidates this
        # session's pre-boundary cached record. Best-effort; verify stays
        # fail-closed even when there is nothing to drop.
        if cache="$(session_cache_path "$ZCL_SOURCE_IDENTITY_SESSION")"; then
            rm -f -- "$cache" ||
                echo "sovereign-source-identity: could not drop session cache: $cache" >&2
        fi
        exit 0
        ;;
    verify)
        [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify requires a 64-hex expected identity"
        actual="$(capture_authority)"
        [ "${actual,,}" = "${EXPECTED,,}" ] ||
            fail "source identity superseded"
        printf '%s\n' "$actual"
        ;;
    verify-record)
        [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] &&
            [ "$EXPECTED_COMPLETE" = 1 ] &&
            [[ "$EXPECTED_MUTATION" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify-record requires identity, completeness bit 1, and mutation"
        record="$(capture_record_cached)"
        read -r actual complete mutation <<< "$record"
        [ "${actual,,}" = "${EXPECTED,,}" ] &&
            [ "$complete" = 1 ] &&
            [ "${mutation,,}" = "${EXPECTED_MUTATION,,}" ] ||
            fail "source build superseded"
        printf '%s\n' "$record"
        ;;
    verify-mutation)
        [[ "$EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] ||
            fail "verify-mutation requires a 64-hex mutation token"
        capture_authority >/dev/null
        mutation="$(mutation_token)"
        [ "${mutation,,}" = "${EXPECTED,,}" ] ||
            fail "source mutation superseded"
        printf '%s\n' "$mutation"
        ;;
    *)
        echo "usage: tools/dev/source-identity.sh paths|capture|capture-record|session-cache-drop|verify EXPECTED|verify-record EXPECTED COMPLETE MUTATION|verify-mutation MUTATION" >&2
        exit 2
        ;;
esac
