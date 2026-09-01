#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Pure service-island confinement. Build-free and fail-loud: the C23 compiler
# remains the only compiler authority; this gate only narrows what an island
# may import or own.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
. tools/lint/gate_lib.sh

MANIFEST="${ZCL_HOTSWAP_SERVICE_MANIFEST:-engine/composition/hotswap_services.def}"
PROBE_CASES="${ZCL_HOTSWAP_PROBE_CASES:-engine/composition/hotswap_probe_cases.def}"
SHADOW_OWNERS="${ZCL_HOTSWAP_SHADOW_OWNERS:-engine/composition/hotswap_shadow_owners.def}"
FIXTURE_MODE="${ZCL_HOTSWAP_SERVICE_FIXTURE:-0}"
echo "══ LINT: pure hot-swap service islands ══"
if [ ! -r "$MANIFEST" ]; then
    echo "check_hotswap_service_islands: FATAL — manifest '$MANIFEST' missing" >&2
    exit 2
fi
if [ ! -r "$PROBE_CASES" ]; then
    echo "check_hotswap_service_islands: FATAL — probe cases '$PROBE_CASES' missing" >&2
    exit 2
fi
if [ ! -r "$SHADOW_OWNERS" ]; then
    echo "check_hotswap_service_islands: FATAL — manifest '$SHADOW_OWNERS' missing" >&2
    exit 2
fi

MACRO_AWK='
{ buf = buf $0 "\n" }
END {
  n=length(buf); tok="HOTSWAP_SERVICE("; L=length(tok); i=1
  while (i<=n) {
    if (substr(buf,i,L)!=tok || (i>1 && substr(buf,i-1,1)!="\n")) { i++; continue }
    j=i+L; depth=1; ins=0; esc=0; spec=""
    while (j<=n && depth>0) {
      c=substr(buf,j,1)
      if (ins) { if (esc) esc=0; else if (c=="\\") esc=1; else if (c=="\"") ins=0 }
      else { if (c=="\"") ins=1; else if (c=="(") depth++; else if (c==")") depth-- }
      if (depth>0) spec=spec c; j++
    }
    out=""; rest=spec
    for (k=0;k<10;k++) {
      v=""; if (match(rest,/"[^"]*"/)) { v=substr(rest,RSTART+1,RLENGTH-2); rest=substr(rest,RSTART+RLENGTH) }
      out=out (k?"\t":"") v
    }
    print out; i=j
  }
}'

mapfile -t ROWS < <(awk "$MACRO_AWK" "$MANIFEST")
gate_require_scanned "${#ROWS[@]}" 1 check_hotswap_service_islands \
    "no HOTSWAP_SERVICE rows parsed from $MANIFEST"

violations=""
scanned=0
forbidden='(^|[^A-Za-z0-9_])(sqlite3_[A-Za-z0-9_]*|fopen|freopen|open|openat|close|read|write|pread|pwrite|stat|lstat|fstat|opendir|readdir|unlink|rename|mkdir|socket|connect|bind|listen|accept|send|recv|clock_gettime|gettimeofday|time|rand|random|getrandom|fork|vfork|exec[A-Za-z0-9_]*|system|popen|posix_spawn)[[:space:]]*\('
declare -A seen_ids=() seen_sources=()
for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r id source headers contract_headers imports abi schema wire kat probe <<<"$row"
    scanned=$((scanned + 1))
    if [ -z "$id" ] || [ -n "${seen_ids[$id]:-}" ]; then
        violations+="  $id (empty or duplicate service id)"$'\n'
    fi
    seen_ids[$id]=1
    if [ -n "${seen_sources[$source]:-}" ]; then
        violations+="  $source (translation unit belongs to two services)"$'\n'
    fi
    seen_sources[$source]=1
    if [[ ! "$source" =~ ^(engine|cognition|contexts/[^/]+)/services/src/.+\.c$ ]] &&
       { [ "$FIXTURE_MODE" != 1 ] || [[ ! "$source" =~ ^tests/harness/fixtures/.+\.c$ ]]; }; then
        violations+="  $source (service TU must live under a physical service room)"$'\n'
        continue
    fi
    if [ ! -f "$source" ]; then
        violations+="  $source (missing source)"$'\n'; continue
    fi
    scan_files=("$source")
    for h in $headers; do
        [ "$h" = "-" ] && continue
        if [ ! -f "$h" ]; then
            violations+="  $source -> $h (missing private/public header)"$'\n'
        else
            scan_files+=("$h")
        fi
    done
    contract_files=()
    for h in $contract_headers; do
        [ "$h" = "-" ] && continue
        if [ ! -f "$h" ]; then
            violations+="  $source -> $h (missing service contract header)"$'\n'
        else
            contract_files+=("$h")
        fi
    done
    for stamped in "abi:$abi" "schema:$schema" "wire:$wire" "kat:$kat"; do
        label="${stamped%%:*}"
        stamp="${stamped#*:}"
        if [ -z "$stamp" ]; then
            violations+="  $source (empty frozen $label fingerprint)"$'\n'
            continue
        fi
        matches=0
        for h in "${contract_files[@]}"; do
            if grep -Fq "\"$stamp\"" "$h"; then
                matches=$((matches + 1))
            fi
        done
        if [ "$matches" -ne 1 ]; then
            violations+="  $source ($label fingerprint '$stamp' resolves to $matches contract headers, expected exactly one)"$'\n'
        fi
    done
    if [ -z "$probe" ]; then
        violations+="  $source (empty resident-owned probe leaf)"$'\n'
    else
        case_count="$(grep -Fc "\"$probe\"," "$PROBE_CASES" || true)"
        if [ "$case_count" -ne 1 ]; then
            violations+="  $source (probe '$probe' resolves to $case_count resident cases, expected exactly one)"$'\n'
        fi
    fi

    # Ownership/state constructs that would create a second mutable world.
    hits="$(awk '
      /hotswap-service-static-ok:/ { next }
      /_Thread_local|__thread/ { print FILENAME ":" FNR ": TLS: " $0; next }
      /__attribute__[[:space:]]*\(\([^)]*(constructor|destructor)/ { print FILENAME ":" FNR ": lifecycle: " $0; next }
      /^[[:space:]]*static[[:space:]]/ {
        if ($0 ~ /const/ || $0 ~ /\(/) next
        if ($0 ~ /=/ || $0 ~ /\[/ || $0 ~ /\{[[:space:]]*$/) print FILENAME ":" FNR ": mutable: " $0
      }
      /^[[:space:]]*extern[[:space:]]/ { print FILENAME ":" FNR ": extern: " $0 }
    ' "${scan_files[@]}")"
    if [ -n "$hits" ]; then violations+="$hits"$'\n'; fi

    # Calls that imply effects/ambient authority. Match call tokens, not prose.
    bad_calls="$(grep -nE "$forbidden" "${scan_files[@]}" || true)"
    if [ -n "$bad_calls" ]; then violations+="$source:$bad_calls"$'\n'; fi
    bad_includes="$(grep -nE '^#[[:space:]]*include[[:space:]]*[<"]([^>"]*/)?(wallet|storage|consensus|validation|net|coins|chain|mining|rpc)/' "${scan_files[@]}" || true)"
    if [ -n "$bad_includes" ]; then violations+="$source:$bad_includes"$'\n'; fi

    # Every project-prefixed call must be an explicitly declared stable host
    # import or a function defined inside this TU. C23 rejects undeclared calls;
    # rejecting `extern` above closes the manual-declaration escape hatch.
    mapfile -t project_calls < <(grep -oE '\b(vcs_|zcl_)[A-Za-z0-9_]*[[:space:]]*\(' "$source" | sed -E 's/[[:space:]]*\($//' | sort -u)
    for call in "${project_calls[@]}"; do
        case " $imports " in
            *" $call "*) ;;
            *) violations+="  $source -> $call (host symbol absent from stable-import list)"$'\n' ;;
        esac
    done
done

# Static authority shells may route feedback to exactly one already-admitted
# pure service. They remain ordinary whole-program sources: this mapping never
# admits the shell to dlopen or runtime activation.
declare -A seen_shadow_owners=()
while IFS=$'\t' read -r owner service; do
    [ -n "$owner" ] && [ -n "$service" ] || continue
    scanned=$((scanned + 1))
    if [ -n "${seen_shadow_owners[$owner]:-}" ]; then
        violations+="  $owner (duplicate HOTSHADOW_OWNER)"$'\n'
    fi
    seen_shadow_owners[$owner]=1
    case "$owner" in
        tools/command/*.c|tools/dev/*.c|engine/controllers/src/*.c|engine/services/src/*.c|cognition/controllers/src/*.c|cognition/services/src/*.c|contexts/*/controllers/src/*.c|contexts/*/services/src/*.c|contexts/commons/modules/vcs/src/vcs_devloop.c) ;;
        *) violations+="  $owner (shadow shell is outside admitted static-shell roots)"$'\n';;
    esac
    [ -f "$owner" ] || violations+="  $owner (missing static authority shell)"$'\n'
    if [ -z "${seen_sources[$service]:-}" ]; then
        violations+="  $owner -> $service (target is not one pure service row)"$'\n'
    fi
    if [ "$owner" = "$service" ]; then
        violations+="  $owner (service cannot be its own static shell)"$'\n'
    fi
done < <(awk '
  /^HOTSHADOW_OWNER\(/ { active=1; count=0 }
  active {
    rest=$0
    while (match(rest,/"[^"]+"/)) {
      value=substr(rest,RSTART+1,RLENGTH-2)
      if (count==0) owner=value; else if (count==1) service=value
      count++; rest=substr(rest,RSTART+RLENGTH)
    }
    if (active && count>=2) { print owner "\t" service; active=0 }
  }
' "$SHADOW_OWNERS")

while IFS=$'\t' read -r service members; do
    [ -n "$service" ] && [ -n "$members" ] || continue
    if [ -z "${seen_sources[$service]:-}" ]; then
        violations+="  $service (HOTSHADOW_SERVICE_MEMBERS target is not a pure service)"$'\n'
    fi
    for member in $members; do
        scanned=$((scanned + 1))
        case "$member" in
            platform/modules/base/src/*.c|platform/modules/codec/src/*.c|platform/modules/json/src/*.c|contexts/commons/modules/vcs/src/*.c) ;;
            *) violations+="  $member (HOT_EXECUTE member is outside pure library roots)"$'\n';;
        esac
        if [ ! -f "$member" ]; then
            violations+="  $member (missing HOT_EXECUTE member)"$'\n'
            continue
        fi
        member_state="$(awk '
          /hotswap-service-static-ok:/ { next }
          /_Thread_local|__thread/ { print FILENAME ":" FNR ": TLS: " $0; next }
          /__attribute__[[:space:]]*\(\([^)]*(constructor|destructor)/ { print FILENAME ":" FNR ": lifecycle: " $0; next }
          /^[[:space:]]*static[[:space:]]/ {
            if ($0 ~ /const/ || $0 ~ /\(/) next
            if ($0 ~ /=/ || $0 ~ /\[/ || $0 ~ /\{[[:space:]]*$/) print FILENAME ":" FNR ": mutable: " $0
          }
          /^[[:space:]]*extern[[:space:]]/ { print FILENAME ":" FNR ": extern: " $0 }
        ' "$member")"
        [ -z "$member_state" ] || violations+="$member_state"$'\n'
        member_effects="$(grep -nE "$forbidden" "$member" || true)"
        [ -z "$member_effects" ] || violations+="$member:$member_effects"$'\n'
        member_includes="$(grep -nE '^#[[:space:]]*include[[:space:]]*[<"]([^>"]*/)?(wallet|storage|consensus|validation|net|coins|chain|mining|rpc)/' "$member" || true)"
        [ -z "$member_includes" ] || violations+="$member:$member_includes"$'\n'
    done
done < <(awk '
  /^HOTSHADOW_SERVICE_MEMBERS\(/ { active=1; count=0 }
  active {
    rest=$0
    while (match(rest,/"[^"]+"/)) {
      value=substr(rest,RSTART+1,RLENGTH-2)
      if (count==0) service=value; else if (count==1) members=value
      count++; rest=substr(rest,RSTART+RLENGTH)
    }
    if (active && count>=2) { print service "\t" members; active=0 }
  }
' "$SHADOW_OWNERS")

gate_require_scanned "$scanned" 1 check_hotswap_service_islands \
    "service scan population is empty"
if [ -n "${violations//[[:space:]]/}" ]; then
    printf '%s' "$violations"
    echo "FAIL: a pure hot-swap service island owns state, effects, or an undeclared import."
    exit 1
fi
echo "  OK: $scanned admitted service/shadow row(s), frozen contracts and stable imports only"
