#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Fail closed unless the shipped node has only the glibc runtime family as a
# dynamic dependency. Before glibc 2.34, pthread and dl are separate DSOs;
# newer glibc merges them into libc. Every project/third-party dependency must
# still be linked from a pinned static archive; GUI and C++ runtimes belong to
# separate developer tools.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${1:-build/bin/zclassic23}"
test -x "$bin" || { echo "c23-node: missing executable: $bin" >&2; exit 1; }

# Which audit to run is a property of the BINARY, not of this machine. A
# Windows release is now cross-linked on Linux (make ZCL_TARGET=windows-x86_64
# release), so a host-keyed choice would hand a PE executable to the ELF
# branch: readelf finds no shared-library entries, the "forbidden dynamic
# dependency" loop never runs, and every DLL import ships ungraded behind a
# PASS line. Ask objdump what the file is instead. GNU objdump on Linux reads
# pei-x86-64; where it cannot (Mach-O on most Linux binutils) the probe is
# simply empty and the host-keyed Darwin branch below still applies.
bin_format=""
if command -v objdump >/dev/null 2>&1; then
    # Apple LLVM objdump recognizes Mach-O and prints its format, but exits 1
    # after doing so.  This probe is only a cross-format hint; Darwin still
    # grades the artifact below with otool and nm.  Preserve any emitted
    # format while preventing that tool quirk from aborting under pipefail.
    bin_format="$(objdump -f "$bin" 2>/dev/null |
        sed -n 's/^.*file format //p' | head -1 || true)"
fi

if [[ "$(uname -s 2>/dev/null)" == Darwin && "$bin_format" != pei-* ]]; then
    command -v otool >/dev/null 2>&1 || {
        echo "c23-node: otool is required for the Mach-O dependency audit" >&2
        exit 1
    }
    command -v nm >/dev/null 2>&1 || {
        echo "c23-node: nm is required for the Mach-O symbol audit" >&2
        exit 1
    }

    bad=0
    while IFS= read -r dep; do
        case "$dep" in
            /usr/lib/*|/System/Library/Frameworks/*) ;;
            *) echo "c23-node: forbidden dynamic dependency: $dep" >&2; bad=1 ;;
        esac
    done < <(otool -L "$bin" | tail -n +2 | sed 's/^[[:space:]]*//; s/[[:space:]].*$//')

    # The permitted set is the Makefile's OWN weak-undefined list, parsed here
    # rather than restated. The two must agree by construction: the Makefile
    # hands these names to the linker on a Darwin stub link and this gate
    # grades the result. A restated copy already drifted -- the Makefile
    # carried 17 names while this gate allowed 14, so three symbols the stub
    # link is designed to leave weak would have been reported as forbidden on
    # the first macOS build that referenced them. That is the same failure the
    # Windows API floor comment in the Makefile describes: two sides that must
    # agree, and a disagreement that is invisible because both sides compile.
    #
    # Anti-hollow: assert a floor on the parse. An unparsed or renamed variable
    # would yield an empty set, and an empty set grades every binary against no
    # rule at all -- a pass that checked nothing. Fail loudly instead.
    weak_names="$(sed -n \
        '/^ZCL_DARWIN_TOR_WEAK_UNDEFS[[:space:]]*=/,/[^\\]$/p' \
        "$repo_root/Makefile" \
        | grep -oE '\-Wl,-U,_[A-Za-z0-9_]+' | sed 's/^-Wl,-U,_//' | sort -u)"
    weak_count="$(printf '%s\n' "$weak_names" | grep -c . || true)"
    if [ "$weak_count" -lt 14 ]; then
        echo "c23-node: could not read ZCL_DARWIN_TOR_WEAK_UNDEFS from" \
             "$repo_root/Makefile (parsed $weak_count name(s), expected at" \
             "least 14) -- refusing to grade against an empty rule" >&2
        exit 1
    fi
    allowed_weak="^_($(printf '%s\n' "$weak_names" | paste -sd'|' -))\$"
    while IFS= read -r symbol; do
        if ! grep -Eq "$allowed_weak" <<<"$symbol"; then
            echo "c23-node: forbidden dynamically looked-up symbol: $symbol" >&2
            bad=1
        fi
    done < <(nm -m "$bin" 2>/dev/null |
        sed -n 's/.*(undefined) weak external \([^ ]*\) (dynamically looked up).*/\1/p')

    if nm -u "$bin" 2>/dev/null | grep -E \
            '(__gxx_personality_v0|__cxa_(throw|rethrow|begin_catch|end_catch|allocate_exception|free_exception|pure_virtual|guard_)|__Z(nw|dl|da|na))' \
            >/dev/null; then
        echo "c23-node: C++ runtime symbol found in node executable" >&2
        bad=1
    fi

    test "$bad" -eq 0 || exit 1
    echo "c23-node: PASS (C23 sources; pinned static project dependencies; Apple system runtimes only)"
    exit 0
fi

# Selected by the artifact (see bin_format above), so a PE is graded as a PE
# whether it was linked on Windows or cross-linked for Windows.
case "$bin_format:$(uname -s 2>/dev/null)" in
    pei-*:*|*:MINGW*|*:MSYS*)
        command -v objdump >/dev/null 2>&1 || {
            echo "c23-node: objdump is required for the PE dependency audit" >&2
            exit 1
        }
        [[ "$bin_format" == pei-x86-64 ]] || {
            echo "c23-node: expected x86-64 PE, found ${bin_format:-unknown}" >&2
            exit 1
        }
        bad=0
        while IFS= read -r dep; do
            folded="${dep,,}"
            case "$folded" in
                advapi32.dll|bcrypt.dll|crypt32.dll|gdi32.dll|iphlpapi.dll|\
                kernel32.dll|msvcrt.dll|ole32.dll|psapi.dll|shell32.dll|\
                user32.dll|userenv.dll|ws2_32.dll|api-ms-win-*.dll) ;;
                *) echo "c23-node: forbidden dynamic dependency: $dep" >&2; bad=1 ;;
            esac
        done < <(objdump -p "$bin" | sed -n 's/^[[:space:]]*DLL Name: //p')
        test "$bad" -eq 0 || exit 1
        echo "c23-node: PASS (x86-64 PE; pinned static project dependencies; Windows system DLLs only)"
        exit 0
        ;;
esac

command -v readelf >/dev/null 2>&1 || {
    echo "c23-node: readelf is required for the release dependency audit" >&2
    exit 1
}
command -v objdump >/dev/null 2>&1 || {
    echo "c23-node: objdump is required for the release ABI audit" >&2
    exit 1
}

# Ubuntu 22.04's glibc 2.35 is older than this ceiling, while the project's
# established portable-release contract permits symbols through GLIBC_2.38.
# The ceiling is about symbols the executable REQUIRES, not the libc version
# installed on the build machine.  A developer may build on a newer distro,
# but publication must fail if that silently raises the deploy ABI.  Override
# only for an explicit cross-platform audit; the release recipe uses the
# fail-closed default.
max_glibc_allowed="${ZCL_C23_MAX_GLIBC:-GLIBC_2.38}"
case "$max_glibc_allowed" in
    GLIBC_[0-9]*.[0-9]*) ;;
    *) echo "c23-node: invalid ZCL_C23_MAX_GLIBC: $max_glibc_allowed" >&2; exit 1 ;;
esac

bad=0
while IFS= read -r dep; do
    case "$dep" in
        libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2) ;;
        *) echo "c23-node: forbidden dynamic dependency: $dep" >&2; bad=1 ;;
    esac
done < <(readelf -d "$bin" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p')

# __cxa_finalize and __cxa_atexit are ordinary libc startup/teardown symbols
# emitted for C PIE executables too. Reject the C++ exception/guard/personality
# surface, operator new/delete manglings, and versioned C++ ABIs instead. Do
# not use grep -q here: under pipefail its early close SIGPIPEs readelf, making
# the answer depend on whether readelf filled the pipe buffer (large binaries
# used to false-pass while small binaries failed on __cxa_finalize).
if readelf -Ws "$bin" | grep -E \
        'GLIBCXX_|CXXABI_|__gxx_personality_v0|__cxa_(throw|rethrow|begin_catch|end_catch|allocate_exception|free_exception|pure_virtual|guard_)|_Z(nw|dl|da|na)' \
        >/dev/null; then
    echo "c23-node: C++ runtime symbol found in node executable" >&2
    bad=1
fi

max_glibc="$(objdump -T "$bin" 2>/dev/null |
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sort -V | tail -1 || true)"
if [[ -z "$max_glibc" ]]; then
    echo "c23-node: no required GLIBC symbol versions found (unparseable artifact)" >&2
    bad=1
elif [[ "$(printf '%s\n%s\n' "$max_glibc" "$max_glibc_allowed" |
        sort -V | tail -1)" != "$max_glibc_allowed" ]]; then
    echo "c23-node: required ABI $max_glibc exceeds supported ceiling $max_glibc_allowed" >&2
    echo "c23-node: build the release on the oldest supported toolchain/sysroot" >&2
    bad=1
fi

test "$bad" -eq 0 || exit 1
echo "c23-node: PASS (C23 sources; pinned static project dependencies; glibc runtime ABI only; max $max_glibc)"
