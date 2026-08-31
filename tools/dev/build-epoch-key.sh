#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Produce the fail-closed compiler/profile keys used by Make's cached object
# epochs.  The portable source authority remains independent of mtimes and Git
# history.  The epoch namespace binds ONLY inputs that change object bytes
# without changing any tracked TU: compiler/tool bytes, profile name,
# effective compile/link flags, and the build-system fingerprint
# (build-system-id mode: the root Makefile, which holds every flag variable
# and per-object override, plus the four epoch driver scripts).  Source edits
# deliberately do NOT re-key the epoch: make's own timestamp+depfile
# incrementality recompiles exactly the affected TUs inside the stable epoch,
# and the identity stamp (BUILD_IDENTITY_STAMP) rebuilds clientversion.o and
# relinks whenever the source identity moves.  Artifact publication remains
# source-bound: every publish path re-verifies the exact source record, so a
# build that raced an edit still fails closed at publish time.

set -euo pipefail

WORK=""
cleanup()
{
    [ -z "$WORK" ] || rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 2' HUP INT TERM

fail()
{
    printf 'build-epoch-key: %s\n' "$*" >&2
    exit 2
}

sha256_file()
{
    sha256sum < "$1" | awk '{print $1}'
}

is_sha256()
{
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

MODE="${1:-}"
shift || true

case "$MODE" in
compiler-id)
    CC_COMMAND="${1:-}"
    CXX_COMMAND="${2:-${1:-}}"
    [ -n "$CC_COMMAND" ] || fail 'compiler-id requires the effective CC command'

    # Make's compiler commands are a whitespace-separated argv (normally
    # `cc`, `ccache cc`, or `sccache cc`).  Accept only tokens whose shell
    # interpretation is identical to `read -a`: quotes, escapes, expansions,
    # comments, globs, redirects, assignments in argv[0], and control syntax
    # all fail closed instead of being fingerprinted differently from Make.
    safe_command()
    {
        local label="$1" command="$2"
        [[ "$command" =~ ^[[:space:]]*[A-Za-z0-9_./:+,=%-]+([[:space:]]+[A-Za-z0-9_./:+,=%-]+)*[[:space:]]*$ ]] ||
            fail "$label contains unsupported shell syntax"
    }
    safe_command CC "$CC_COMMAND"
    safe_command CXX "$CXX_COMMAND"
    read -r -a CC_ARGV <<< "$CC_COMMAND"
    read -r -a CXX_ARGV <<< "$CXX_COMMAND"
    [ "${#CC_ARGV[@]}" -gt 0 ] || fail 'CC parsed to an empty argv'
    [ "${#CXX_ARGV[@]}" -gt 0 ] || fail 'CXX parsed to an empty argv'
    case "${CC_ARGV[0]}" in -*|*=*) fail 'CC argv[0] is not an executable token' ;; esac
    case "${CXX_ARGV[0]}" in -*|*=*) fail 'CXX argv[0] is not an executable token' ;; esac
    command -v "${CC_ARGV[0]}" >/dev/null 2>&1 ||
        fail "compiler command not found: ${CC_ARGV[0]}"
    command -v "${CXX_ARGV[0]}" >/dev/null 2>&1 ||
        fail "C++ compiler command not found: ${CXX_ARGV[0]}"

    # GNU Make exports scheduling/control state to recipes but not uniformly to
    # parse-time $(shell ...). GCC -v echoes MAKEFLAGS even though it does not
    # affect generated code. Normalize those orchestration-only variables so a
    # -j change cannot impersonate a toolchain replacement.
    unset MAKEFLAGS MFLAGS MAKELEVEL

    WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-build-compiler.XXXXXX")" ||
        fail 'could not create compiler fingerprint workspace'
    PREIMAGE="$WORK/compiler.preimage"
    : > "$PREIMAGE"
    printf 'zcl.build_compiler_identity.v2\0cc_command\0%s\0cxx_command\0%s\0' \
        "$CC_COMMAND" "$CXX_COMMAND" \
        >> "$PREIMAGE"

    # These variables can redirect headers, compiler subprograms, libraries,
    # or an SDK without changing argv.  Bind unset-vs-set and the exact value.
    for env_name in CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH COMPILER_PATH \
            GCC_EXEC_PREFIX LIBRARY_PATH SDKROOT LD_LIBRARY_PATH \
            SOURCE_DATE_EPOCH; do
        if [[ -v "$env_name" ]]; then
            printf 'environment\0%s\0set\0%s\0' "$env_name" "${!env_name}" \
                >> "$PREIMAGE"
        else
            printf 'environment\0%s\0unset\0' "$env_name" >> "$PREIMAGE"
        fi
    done
    while IFS= read -r env_name; do
        case "$env_name" in CCACHE_*|SCCACHE_*)
            printf 'environment\0%s\0set\0%s\0' "$env_name" "${!env_name}" \
                >> "$PREIMAGE"
            ;;
        esac
    done < <(compgen -e | LC_ALL=C sort -u)

    declare -A SEEN_TOOL=()
    fingerprint_tool()
    {
        local label="$1" requested="$2" resolved digest metadata
        [ -n "$requested" ] || return 0
        if [[ "$requested" == */* ]]; then
            resolved="$(readlink -f -- "$requested" 2>/dev/null || true)"
        else
            resolved="$(command -v -- "$requested" 2>/dev/null || true)"
            [ -n "$resolved" ] &&
                resolved="$(readlink -f -- "$resolved" 2>/dev/null || true)"
        fi
        [ -n "$resolved" ] && [ -f "$resolved" ] || return 0
        case "${SEEN_TOOL[$resolved]+seen}" in seen) return 0 ;; esac
        SEEN_TOOL["$resolved"]=1
        digest="$(sha256_file "$resolved")" ||
            fail "could not hash compiler tool: $resolved"
        metadata="$(stat -Lc '%d:%i:%s:%Y:%Z:%y:%z' "$resolved" 2>/dev/null)" ||
            fail "could not stat compiler tool: $resolved"
        printf 'tool\0%s\0%s\0%s\0%s\0' \
            "$label" "$resolved" "$digest" "$metadata" \
            >> "$PREIMAGE"
    }

    # Fingerprint wrappers and explicit compiler argv programs.
    for token in "${CC_ARGV[@]}"; do
        case "$token" in -*) continue ;; esac
        fingerprint_tool argv "$token"
    done
    for token in "${CXX_ARGV[@]}"; do
        case "$token" in -*) continue ;; esac
        fingerprint_tool cxx-argv "$token"
    done

    probe()
    {
        local label="$1" output rc
        shift
        set +e
        output="$("${CC_ARGV[@]}" "$@" </dev/null 2>&1)"
        rc=$?
        set -e
        printf 'probe\0%s\0%d\0%s\0' "$label" "$rc" "$output" \
            >> "$PREIMAGE"
    }

    probe version --version
    probe machine -dumpmachine
    probe compiler-version -dumpfullversion -dumpversion
    probe search-dirs -print-search-dirs
    probe c-include-search -E -x c -v -
    probe c-builtins -dM -E -x c -

    wrapper_base="$(basename -- "${CC_ARGV[0]}")"
    case "$wrapper_base" in
        ccache)
            set +e
            wrapper_config="$("${CC_ARGV[0]}" --show-config 2>&1)"
            rc=$?
            set -e
            printf 'wrapper-config\0ccache\0%d\0%s\0' "$rc" "$wrapper_config" \
                >> "$PREIMAGE"
            ;;
        sccache)
            # sccache has no stable show-config command; its admitted SCCACHE_*
            # environment is bound above and its conventional config file is
            # hashed below. Never bind live cache statistics/counters.
            printf 'wrapper-config\0sccache\0environment-plus-file\0' >> "$PREIMAGE"
            ;;
    esac
    for wrapper_config_path in \
            "${CCACHE_CONFIGPATH:-}" \
            "${HOME:-}/.config/ccache/ccache.conf" \
            "${HOME:-}/.ccache/ccache.conf" \
            "${SCCACHE_CONF:-}" \
            "${HOME:-}/.config/sccache/config"; do
        [ -n "$wrapper_config_path" ] || continue
        [ -f "$wrapper_config_path" ] &&
            fingerprint_tool wrapper-config-file "$wrapper_config_path"
    done

    probe_cxx()
    {
        local label="$1" output rc
        shift
        set +e
        output="$("${CXX_ARGV[@]}" "$@" </dev/null 2>&1)"
        rc=$?
        set -e
        printf 'cxx-probe\0%s\0%d\0%s\0' "$label" "$rc" "$output" \
            >> "$PREIMAGE"
    }
    probe_cxx version --version
    probe_cxx machine -dumpmachine
    probe_cxx include-search -E -x c++ -v -
    probe_cxx builtins -dM -E -x c++ -

    # GCC/Clang drivers dispatch to these programs. Hash the resolved bytes,
    # not just a marketing version line, so an in-place toolchain replacement
    # cannot silently reuse old cached objects.
    for program in cc1 cc1plus collect2 lto1 as ld; do
        set +e
        resolved="$("${CC_ARGV[@]}" "-print-prog-name=$program" 2>/dev/null)"
        rc=$?
        set -e
        [ "$rc" -eq 0 ] || continue
        fingerprint_tool "driver-$program" "$resolved"
    done

    # Bind every linker implementation the Make profile may auto-select and
    # the runtime/startup archives selected by the drivers.
    for program in ld ld.lld mold; do
        resolved="$(command -v -- "$program" 2>/dev/null || true)"
        [ -n "$resolved" ] && fingerprint_tool "linker-$program" "$resolved"
    done
    # GCC accepts arbitrary -fuse-ld=<name> values and searches for ld.<name>
    # in its program path. Fingerprint every available linker-shaped executable
    # in the admitted driver/PATH search, not only today's bfd/lld/mold names.
    program_dirs="$("${CC_ARGV[@]}" -print-search-dirs 2>/dev/null |
        sed -n 's/^programs: *=//p')"
    IFS=: read -r -a linker_dirs <<< "${program_dirs}:${PATH:-}"
    for linker_dir in "${linker_dirs[@]}"; do
        [ -n "$linker_dir" ] || linker_dir=.
        [ -d "$linker_dir" ] || continue
        while IFS= read -r -d '' resolved; do
            [ -x "$resolved" ] && fingerprint_tool arbitrary-linker "$resolved"
        done < <(find "$linker_dir" -maxdepth 1 \( -type f -o -type l \) \
            -name 'ld*' -print0 2>/dev/null | LC_ALL=C sort -z)
    done
    for asset in libgcc.a libgcc_s.so libgcc_s.so.1 libstdc++.a libstdc++.so \
            libc.so libm.so libpthread.so libdl.so Scrt1.o crt1.o crti.o \
            crtn.o crtbegin.o crtbeginS.o crtend.o crtendS.o; do
        set +e
        resolved="$("${CXX_ARGV[@]}" "-print-file-name=$asset" 2>/dev/null)"
        rc=$?
        set -e
        [ "$rc" -eq 0 ] || continue
        fingerprint_tool "driver-asset-$asset" "$resolved"
    done

    # Header/search-root bytes are too expensive to hash on every Make parse,
    # but their complete host metadata inventory is cheap and ABA-sensitive:
    # an edit/revert changes ctime even when bytes and mtime are restored.  The
    # include-search probes above bind order and compiler preprocessing state.
    : > "$WORK/search-roots"
    collect_search_roots()
    {
        local -n argv_ref="$1"
        local output in_list=0 line root
        output="$("${argv_ref[@]}" -E -x c -v - </dev/null 2>&1 || true)"
        while IFS= read -r line; do
            case "$line" in
                '#include <...> search starts here:') in_list=1; continue ;;
                'End of search list.') in_list=0; continue ;;
            esac
            [ "$in_list" -eq 1 ] || continue
            root="${line# }"
            root="${root% (framework directory)}"
            [ -d "$root" ] && printf '%s\0' "$root" >> "$WORK/search-roots"
        done <<< "$output"
    }
    collect_search_roots CC_ARGV
    collect_search_roots CXX_ARGV
    for env_name in CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH COMPILER_PATH \
            LIBRARY_PATH SDKROOT; do
        [[ -v "$env_name" ]] || continue
        IFS=: read -r -a env_roots <<< "${!env_name}"
        for root in "${env_roots[@]}"; do
            [ -n "$root" ] || root=.
            [ -d "$root" ] && printf '%s\0' "$root" >> "$WORK/search-roots"
        done
    done
    LC_ALL=C sort -zu "$WORK/search-roots" -o "$WORK/search-roots"
    while IFS= read -r -d '' root; do
        resolved="$(readlink -f -- "$root" 2>/dev/null || true)"
        [ -n "$resolved" ] && [ -d "$resolved" ] || continue
        printf 'search-root\0%s\0%s\0' "$root" "$resolved" >> "$PREIMAGE"
        find_error="$WORK/search-root-find.error"
        : > "$find_error"
        set +e
        LC_ALL=C find -L "$resolved" \( -type f -o -type l \) \
            -printf '%P\0%D:%i:%s:%T@:%C@:%m:%y:%l\0' \
            2> "$find_error" |
            LC_ALL=C sort -z >> "$PREIMAGE"
        pipeline_rc=("${PIPESTATUS[@]}")
        set -e
        [ "${pipeline_rc[1]}" -eq 0 ] ||
            fail "could not sort compiler search root inventory: $resolved"
        if [ "${pipeline_rc[0]}" -ne 0 ]; then
            # GNU find returns 1 after pruning a link that re-enters an
            # ancestor. That ancestor is already fully inventoried, and the
            # link is bound below. Every other incomplete walk still fails.
            [ "${pipeline_rc[0]}" -eq 1 ] && [ -s "$find_error" ] &&
                ! LC_ALL=C grep -v \
                    '^find: File system loop detected;.*$' "$find_error" |
                    grep -q . ||
                fail "could not inventory compiler search root: $resolved"
        fi
        while IFS= read -r -d '' linked; do
            target="$(readlink -f -- "$linked" 2>/dev/null || true)"
            [ -f "$target" ] && fingerprint_tool search-symlink-target "$target"
        done < <(find "$resolved" -type l -print0 2>/dev/null)
        printf '\0search-root-end\0' >> "$PREIMAGE"
    done < "$WORK/search-roots"

    sha256_file "$PREIMAGE"
    ;;

key)
    COMPILER_ID="${1:-}"
    PROFILE="${2:-}"
    COMPILE_FLAGS="${3:-}"
    LINK_FLAGS="${4:-}"
    BUILD_SYSTEM="${5:-}"
    is_sha256 "$COMPILER_ID" || fail 'key requires a compiler fingerprint'
    [ -n "$PROFILE" ] || fail 'key requires a nonempty profile name'
    case "$PROFILE" in *$'\n'*|*$'\r'*) fail 'profile contains a control line' ;; esac
    case "$COMPILE_FLAGS $LINK_FLAGS" in
        *@*) fail 'response-file syntax is forbidden in compile/link flags' ;;
    esac

    # -MMD deliberately leaves system headers out of each TU depfile. Their
    # authority therefore comes from compiler-id's probed search roots and
    # metadata inventory. A compile-only flag that redirects those roots, or
    # loads an indirect specs/plugin program, would sit outside that inventory.
    # Refuse it here rather than minting an epoch with an incomplete authority.
    read -r -a COMPILE_ARGV <<< "$COMPILE_FLAGS"
    for flag in "${COMPILE_ARGV[@]}"; do
        case "$flag" in
            -isystem|-isystem*|*=-isystem*| \
            -idirafter|-idirafter*|*=-idirafter*| \
            --sysroot|--sysroot=*|*=--sysroot*| \
            -isysroot|-isysroot*|*=-isysroot*| \
            -iframework|-iframework*|*=-iframework*| \
            -F|-F*|*=-F*| \
            -nostdinc|-nostdinc++|*=-nostdinc|*=-nostdinc++| \
            -iprefix|-iprefix*|*=-iprefix*| \
            -iwithprefix|-iwithprefix*|*=-iwithprefix*| \
            -iwithprefixbefore|-iwithprefixbefore*|*=-iwithprefixbefore*| \
            -B|-B*|*=-B*| \
            -resource-dir|-resource-dir=*|*=-resource-dir=*| \
            --gcc-toolchain|--gcc-toolchain=*|*=--gcc-toolchain=*| \
            -gcc-toolchain|-gcc-toolchain=*|*=-gcc-toolchain=*| \
            -specs|--specs|-specs=*|--specs=*|*=-specs=*|*=--specs=*| \
            -fplugin|-fplugin=*|-fpass-plugin=*|*=-fplugin=*|*=-fpass-plugin=*| \
            -load|-load=*|-plugin|-plugin=*|-wrapper|-wrapper=*| \
            -include-pch|-include-pch*|-include-pth|-include-pth*| \
            -fmodule*|-fprebuilt-module-path=*|-fmodules-cache-path=*| \
            -Xclang|-Xpreprocessor|-Xassembler|-Wp,*|-Wa,*| \
            *=-load*|*=-plugin*|*=-wrapper*|*=-include-pch*| \
            *=-include-pth*|*=-fmodule*|*=-Xclang|*=-Xpreprocessor| \
            *=-Xassembler|*=-Wp,*|*=-Wa,*)
                fail "compile flags contain un-inventoried search/tool modifier: $flag"
                ;;
        esac
    done
    is_sha256 "$BUILD_SYSTEM" || fail 'key requires a build-system fingerprint'

    WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-build-epoch.XXXXXX")" ||
        fail 'could not create build epoch workspace'
    {
        printf 'zcl.build_compile_epoch.v2\0'
        printf 'compiler_id_sha256\0%s\0' "$COMPILER_ID"
        printf 'profile\0%s\0' "$PROFILE"
        printf 'compile_flags\0%s\0' "$COMPILE_FLAGS"
        printf 'link_flags\0%s\0' "$LINK_FLAGS"
        printf 'build_system_sha256\0%s\0' "$BUILD_SYSTEM"
    } > "$WORK/epoch.preimage"
    sha256_file "$WORK/epoch.preimage"
    ;;

build-system-id)
    # Canonical fingerprint of every build-system input that can change
    # compile/link semantics WITHOUT changing a tracked TU's bytes: the root
    # Makefile (all flag variables and every per-object/per-pattern flag
    # override), zcc's bootstrap flags and complete compiled authority inputs,
    # and the epoch driver scripts (this key tool's algorithm, the legacy
    # per-object oracle, the session/lease/GC authority, and the candidate
    # publisher). Editing any of them must re-key every compile epoch; a stale
    # object must never survive a flags or driver edit. This is the single
    # source of truth for the list; Make and build-epoch-session.sh both call
    # this mode.
    SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ROOT="$(cd "$SELF_DIR/../.." && pwd)"
    ZCC_BOOTSTRAP_CATALOG="$SELF_DIR/zcc-bootstrap-inputs.list"
    BUILD_SYSTEM_FILES=(
        "$ROOT/Makefile"
        "$SELF_DIR/build-epoch-key.sh"
        "$SELF_DIR/compile-epoch-object.sh"
        "$SELF_DIR/build-epoch-session.sh"
        "$SELF_DIR/publish-build-alias.sh"
    )
    while IFS= read -r input || [ -n "$input" ]; do
        case "$input" in
            license=*) ;;
            *) [[ "$input" =~ ^[A-Za-z0-9_./-]+$ ]] ||
                   fail 'zcc bootstrap input catalog is malformed'
               BUILD_SYSTEM_FILES+=("$ROOT/$input") ;;
        esac
    done < "$ZCC_BOOTSTRAP_CATALOG"
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-build-system.XXXXXX")" ||
        fail 'could not create build-system fingerprint workspace'
    : > "$WORK/build-system.preimage"
    printf 'zcl.build_system_id.v1\0' >> "$WORK/build-system.preimage"
    for f in "${BUILD_SYSTEM_FILES[@]}"; do
        [ -f "$f" ] || fail "build-system input is missing: $f"
        printf 'file\0%s\0%s\0' "${f#"$ROOT"/}" "$(sha256_file "$f")" \
            >> "$WORK/build-system.preimage"
    done
    sha256_file "$WORK/build-system.preimage"
    ;;

*)
    fail 'usage: build-epoch-key.sh compiler-id CC [CXX] | key COMPILER PROFILE COMPILE_FLAGS LINK_FLAGS BUILD_SYSTEM_ID | build-system-id'
    ;;
esac
