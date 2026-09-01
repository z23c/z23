#!/usr/bin/env bash
# symbolize_crash.sh — turn a zclassic23 crash_log.txt backtrace into a
# file:line stack walk, using the build-id-matched binary (+ its
# .gnu_debuglink split-debug sidecar, written next to it by the link rule).
#
# The node's fatal-signal handler (platform/modules/util/src/signal_handler.c) appends
# glibc backtrace_symbols_fd() lines to $datadir/crash_log.txt:
#
#   [fatal-signal] sig=11 code=1 addr=0x0 pid=123 tid=456 time=1721...
#   ./build/bin/zclassic23(fatal_handler+0x1a2) [0x55f1c2c34f12]
#   /lib/x86_64-linux-gnu/libc.so.6(+0x42520) [0x7f2a1b442520]
#   [fatal-signal] end
#
# The bracketed address is ASLR'd (PIE) and useless on its own; the
# (sym+0xoff) / (+0xoff) part is the module-relative address, which is
# what the resolver wants. Resolution per frame:
#   sym+0xoff → symbol value (nm, .dynsym first, sidecar symtab second)
#               + off → module-relative address
#   +0xoff    → already module-relative
#
# RESOLUTION ENGINE: gdb batch mode (`info line *ADDR`). binutils
# addr2line is NOT usable as the primary engine on this binary: measured
# 2026-07-18, it resolves only ~8/300 code addresses on the whole-program
# LTO build (the .debug_aranges GCC emits for the LTO partitions do not
# cover most of .text, and addr2line gives up instead of scanning CUs),
# while gdb resolves ~300/300 of the same addresses because it builds its
# own CU map. addr2line is kept as the fallback when gdb is absent.
#
# Usage:
#   tools/scripts/symbolize_crash.sh [CRASH_LOG] [BINARY]
#
# Defaults:
#   CRASH_LOG  newest crash_log.txt under ~/.zclassic-c23*/ (datadir default)
#   BINARY     <repo>/build/bin/zclassic23
#
# Exit codes: 0 — walked at least one frame; 2 — missing prerequisites.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

crash_log="${1:-}"
bin="${2:-$REPO_DIR/build/bin/zclassic23}"

if [[ -z "$crash_log" ]]; then
    crash_log="$(ls -t "$HOME"/.zclassic-c23*/crash_log.txt 2>/dev/null | head -n1 || true)"
fi
if [[ -z "$crash_log" || ! -r "$crash_log" ]]; then
    echo "error: no readable crash log (pass path as arg 1)" >&2
    exit 2
fi
if [[ ! -r "$bin" ]]; then
    echo "error: binary not readable: $bin" >&2
    exit 2
fi
command -v nm >/dev/null 2>&1 || { echo "error: required tool not found: nm" >&2; exit 2; }

engine=""
if command -v gdb >/dev/null 2>&1; then
    engine="gdb"
elif command -v addr2line >/dev/null 2>&1; then
    engine="addr2line"
else
    echo "error: neither gdb nor addr2line found" >&2
    exit 2
fi

echo "crash log : $crash_log"
echo "binary    : $bin"
echo "engine    : $engine$( [[ "$engine" == addr2line ]] && echo ' (degraded on LTO builds — install gdb for file:line)' || true)"
if command -v readelf >/dev/null 2>&1; then
    bid="$(readelf -n "$bin" 2>/dev/null | awk '/Build ID:/{print $3; exit}')"
    echo "build-id  : ${bid:-<none>} (must equal the crashed process's binary)"
fi
echo

bin_base="$(basename "$bin")"

# Keep these in variables: inline [[ =~ ]] parsing chokes on the parens.
re_frame='^(.+)\(([^+)]*)\+0x([0-9a-fA-F]+)\)[[:space:]]*\[0x[0-9a-fA-F]+\]'
re_unmapped='\[0x[0-9a-fA-F]+\]'

# ── Pass 1: parse the log into per-entry records ─────────────────────
declare -a e_kind e_obj e_addr e_sym e_raw
n_entries=0

while IFS= read -r line; do
    if [[ "$line" =~ ^\[fatal-signal\] ]]; then
        e_kind[n_entries]="marker"; e_raw[n_entries]="$line"
        e_obj[n_entries]=""; e_addr[n_entries]=""; e_sym[n_entries]=""
        n_entries=$((n_entries + 1))
    elif [[ "$line" =~ $re_frame ]]; then
        module="${BASH_REMATCH[1]}"
        sym="${BASH_REMATCH[2]}"
        off="${BASH_REMATCH[3]}"
        # Pick the object file: our binary when the module basename matches
        # (the log's path is relative to the crashed process's cwd), else the
        # module path itself when readable (libc, ld-linux, ...).
        obj="$module"
        [[ "$(basename "$module")" == "$bin_base" ]] && obj="$bin"
        [[ -r "$obj" ]] || obj="$bin"
        # A stripped binary has no static symbols; the split-debug sidecar
        # ($obj.debug) has the full table. Prefer it for nm lookups.
        dbg_obj="$obj"
        [[ -r "$obj.debug" ]] && dbg_obj="$obj.debug"
        if [[ -n "$sym" ]]; then
            # sym+0xoff: value of sym + offset = module-relative address.
            # Strip ELF version suffixes (libc exports "foo@@GLIBC_2.34").
            # No early-exit in awk: closing the pipe early would SIGPIPE nm
            # on the large sidecar symbol table (pipefail + set -e abort).
            base="$(nm -D --defined-only "$dbg_obj" 2>/dev/null | awk -v s="$sym" '{n=$3; sub(/@.*/,"",n)} n==s && !f {print $1; f=1}')"
            [[ -n "$base" ]] || base="$(nm --defined-only "$dbg_obj" 2>/dev/null | awk -v s="$sym" '{n=$3; sub(/@.*/,"",n)} n==s && !f {print $1; f=1}')"
            if [[ -n "$base" ]]; then
                e_kind[n_entries]="frame"
                e_addr[n_entries]="$(printf '%x' $((0x$base + 0x$off)))"
                e_sym[n_entries]=""
            else
                e_kind[n_entries]="nosym"
                e_addr[n_entries]=""
                e_sym[n_entries]="$sym"
            fi
        else
            # (+0xoff): already the module-relative address.
            e_kind[n_entries]="frame"
            e_addr[n_entries]="$off"
            e_sym[n_entries]=""
        fi
        e_obj[n_entries]="$obj"
        e_raw[n_entries]="$line"
        n_entries=$((n_entries + 1))
    elif [[ "$line" =~ $re_unmapped ]]; then
        # dladdr found no module for this address: unmapped/garbage frame.
        e_kind[n_entries]="unmapped"; e_raw[n_entries]="$line"
        e_obj[n_entries]=""; e_addr[n_entries]=""; e_sym[n_entries]=""
        n_entries=$((n_entries + 1))
    else
        e_kind[n_entries]="raw"; e_raw[n_entries]="$line"
        e_obj[n_entries]=""; e_addr[n_entries]=""; e_sym[n_entries]=""
        n_entries=$((n_entries + 1))
    fi
done < "$crash_log"

# ── Pass 2: resolve frame addresses to func + file:line ──────────────
# resolved["$obj|$addr"] = "func<TAB>file:line"
declare -A resolved

resolve_with_gdb() {
    # $1=obj; rest=addrs. One gdb process per object: builds its own CU map
    # once, then each `info line` is cheap. Echo markers keep output aligned.
    local obj="$1"; shift
    local -a ex_args
    local a
    for a in "$@"; do
        ex_args+=(-ex "echo @@$a@@\\n" -ex "info line *0x$a")
    done
    local out cur fn loc
    out="$(gdb -batch -nx -ex "file $obj" "${ex_args[@]}" 2>/dev/null || true)"
    while IFS= read -r ol; do
        if [[ "$ol" =~ ^@@([0-9a-fA-F]+)@@$ ]]; then
            cur="${BASH_REMATCH[1]}"
        elif [[ -n "${cur:-}" ]]; then
            if [[ "$ol" =~ ^Line\ ([0-9]+)\ of\ \"(.+)\"\ starts\ at\ address.*\<([^\ \>]+) ]]; then
                loc="${BASH_REMATCH[2]}:${BASH_REMATCH[1]}"
                fn="${BASH_REMATCH[3]}"
                fn="${fn%%+*}"  # strip +offset
                resolved["$obj|$cur"]="$fn"$'\t'"$loc"
            elif [[ "$ol" =~ \<([^\ \>]+)\> ]]; then
                # symbol known, no line info ("No line number information ...")
                fn="${BASH_REMATCH[1]}"
                fn="${fn%%+*}"
                resolved["$obj|$cur"]="$fn"$'\t'"?"
            else
                resolved["$obj|$cur"]="?"$'\t'"?"
            fi
            cur=""
        fi
    done <<< "$out"
}

resolve_with_addr2line() {
    # $1=obj; rest=addrs.
    local obj="$1"; shift
    local dbg_obj="$obj"
    [[ -r "$obj.debug" ]] && dbg_obj="$obj.debug"
    local a out fn loc
    for a in "$@"; do
        out="$(addr2line -f -C -e "$dbg_obj" "0x$a" 2>/dev/null || true)"
        fn="$(printf '%s\n' "$out" | sed -n '1p')"
        loc="$(printf '%s\n' "$out" | sed -n '2p')"
        resolved["$obj|$a"]="${fn:-?}"$'\t'"${loc:-?}"
    done
}

# Group frame addresses per object.
declare -A obj_addrs
for ((i = 0; i < n_entries; i++)); do
    [[ "${e_kind[i]}" == "frame" ]] || continue
    obj_addrs["${e_obj[i]}"]+="${e_addr[i]} "
done

for obj in "${!obj_addrs[@]}"; do
    # shellcheck disable=SC2086
    if [[ "$engine" == "gdb" ]]; then
        resolve_with_gdb "$obj" ${obj_addrs[$obj]}
    else
        resolve_with_addr2line "$obj" ${obj_addrs[$obj]}
    fi
done

# ── Pass 3: print the walk ────────────────────────────────────────────
frame_no=0
frames=0
for ((i = 0; i < n_entries; i++)); do
    kind="${e_kind[i]}"
    raw="${e_raw[i]}"
    case "$kind" in
        marker)
            [[ "$raw" == *"sig="* ]] && frame_no=0
            printf '%s\n' "$raw"
            ;;
        raw)
            printf '%s\n' "$raw"
            ;;
        unmapped)
            printf '#%-3d <unmapped frame> %s\n' "$frame_no" "$raw"
            frame_no=$((frame_no + 1)); frames=$((frames + 1))
            ;;
        nosym)
            printf '#%-3d <symbol %s not found>\n' "$frame_no" "${e_sym[i]}"
            printf '      %s\n' "$raw"
            frame_no=$((frame_no + 1)); frames=$((frames + 1))
            ;;
        frame)
            key="${e_obj[i]}|${e_addr[i]}"
            if [[ -v "resolved[$key]" ]]; then
                r="${resolved[$key]}"
            else
                r="?"$'\t'"?"
            fi
            fn="${r%%$'\t'*}"
            loc="${r#*$'\t'}"
            printf '#%-3d %s  %s\n' "$frame_no" "$fn" "$loc"
            printf '      %s\n' "$raw"
            frame_no=$((frame_no + 1)); frames=$((frames + 1))
            ;;
    esac
done

echo
echo "symbolized $frames frame(s) from $crash_log"
[[ "$frames" -gt 0 ]]
