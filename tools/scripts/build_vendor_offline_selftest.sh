#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove offline vendor mode refuses a cache miss before invoking a downloader.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-vendor-offline-selftest.XXXXXX")"
real_make="$(command -v make)"
lock_pid=
beside=
wait_lock_selftest()
{
    [ -n "$lock_pid" ] || return 0
    local status=0
    wait "$lock_pid" || status=$?
    lock_pid=
    cat "$lock_log"
    return "$status"
}

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    wait_lock_selftest || :
    [ -z "$beside" ] || rm -rf "$beside"
    rm -rf "$SANDBOX"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# A populated shared vendor archive cache would satisfy the archive these cases
# delete. Every case below sees an empty private one unless it opts in.
export VENDOR_ARCHIVE_CACHE="$SANDBOX/vendor-archive-cache"
mkdir -p "$VENDOR_ARCHIVE_CACHE"

fail()
{
    wait_lock_selftest || :
    printf 'build_vendor_offline_selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

lock_log="$SANDBOX/vendor-lock-selftest.log"
bash "$ROOT/tools/scripts/vendor_lock_selftest.sh" >"$lock_log" 2>&1 &
lock_pid=$!

mkdir -p "$SANDBOX/tools/scripts" "$SANDBOX/tools/dev" "$SANDBOX/vendor/.cache" \
    "$SANDBOX/vendor/lib" "$SANDBOX/vendor/include" "$SANDBOX/bin"
cp "$ROOT/tools/scripts/build_vendor.sh" \
    "$ROOT/tools/scripts/vendor_provenance_lib.sh" \
    "$ROOT/tools/scripts/source_identity_lib.sh" "$SANDBOX/tools/scripts/"
for dependency in platform/modules/platform/src/clock.c \
    platform/modules/platform/include/platform/clock.h \
    platform/modules/util/include/util/log_macros.h \
    platform/modules/base/include/base/log_macros.h \
    platform/modules/base/include/base/format_attribute.h \
    platform/modules/base/include/base/log_level.h \
    platform/modules/platform/src/private_acl_internal.c \
    platform/modules/platform/src/private_acl_internal.h \
    platform/modules/base/src/safe_alloc.c \
    platform/modules/base/include/base/safe_alloc.h; do
    mkdir -p "$SANDBOX/$(dirname "$dependency")"
    cp "$ROOT/$dependency" "$SANDBOX/$dependency"
done
cp "$ROOT/tools/vendor_lock.c" "$SANDBOX/tools/"
cp "$ROOT/tools/dev/build-epoch-key.sh" "$SANDBOX/tools/dev/build-epoch-key-real.sh"
export VENDOR_LOCK_KEY_TRACE="$SANDBOX/vendor-key.trace"
cat > "$SANDBOX/tools/dev/build-epoch-key.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\${1:-}" >> "$VENDOR_LOCK_KEY_TRACE"
exec "$SANDBOX/tools/dev/build-epoch-key-real.sh" "\$@"
EOF
chmod +x "$SANDBOX/tools/dev/build-epoch-key.sh"
: > "$VENDOR_LOCK_KEY_TRACE"

for tool in curl wget; do
    printf '%s\n' '#!/usr/bin/env bash' \
        'printf "%s\\n" "$0 $*" >>"$DOWNLOADER_CONTACT_LOG"' \
        'exit 97' > "$SANDBOX/bin/$tool"
    chmod +x "$SANDBOX/bin/$tool"
done

contact_log="$SANDBOX/downloader-contact.log"
: > "$contact_log"
if output="$(cd "$SANDBOX" && \
        DOWNLOADER_CONTACT_LOG="$contact_log" \
        PATH="$SANDBOX/bin:$PATH" ZCL_VENDOR_OFFLINE=1 \
        tools/scripts/build_vendor.sh libz.a 2>&1)"; then
    fail 'missing archive unexpectedly built in offline mode'
fi
[[ "$output" == *'offline cache miss or checksum failure: zlib-1.3.1.tar.gz'* ]] ||
    fail 'cache-miss refusal did not name the missing pinned archive'
[ ! -s "$contact_log" ] || fail 'offline mode invoked a downloader'
[[ "$(awk '{ n++ } END { print n + 0 }' "$VENDOR_LOCK_KEY_TRACE")" == 1 ]] ||
    fail 'lock handoff repeated compiler identity derivation'

# The compiler driver grounds slash-containing relative tools at the source
# root. Compilation must use that same executable from a different cwd.
mkdir -p "$SANDBOX/elsewhere/tools"
# Freeze the qualified driver before the relative fixture overrides HOSTCC.
# Match the production token grammar; never evaluate a compiler command.
fixture_host_cc="${HOSTCC:-${HOST_CC:-cc}}"
case "$(uname -s 2>/dev/null)" in
    MSYS*|MINGW*|CYGWIN*) fixture_host_cc="${HOSTCC:-${HOST_CC:-${ZCL_BOOTSTRAP_CC:-/usr/bin/cc}}}" ;;
esac
[[ "$fixture_host_cc" =~ ^[A-Za-z0-9_./:+,=%-]+([[:space:]]+[A-Za-z0-9_./:+,=%-]+)*$ ]] ||
    fail 'fixture HOSTCC contains unsupported shell syntax'
read -r -a fixture_host_argv <<<"$fixture_host_cc"
case "${fixture_host_argv[0]}" in
    /*) ;;
    */*) fixture_host_argv[0]="$ROOT/${fixture_host_argv[0]}" ;;
    *) fixture_host_argv[0]="$(command -v -- "${fixture_host_argv[0]}")" ||
           fail 'fixture host compiler unavailable' ;;
esac
[[ "${fixture_host_argv[0]}" == /* && -f "${fixture_host_argv[0]}" &&
   -x "${fixture_host_argv[0]}" ]] || fail 'fixture host compiler unavailable'
{
    printf '%s\n' '#!/usr/bin/env bash'
    printf 'exec'
    printf ' %q' "${fixture_host_argv[@]}"
    printf ' "$@"\n'
} > "$SANDBOX/tools/native-cc"
printf '%s\n' '#!/usr/bin/env bash' 'exit 97' > "$SANDBOX/elsewhere/tools/native-cc"
chmod +x "$SANDBOX/tools/native-cc" "$SANDBOX/elsewhere/tools/native-cc"
fixture_machine="$("${fixture_host_argv[@]}" -dumpmachine)"
ln -s "$(command -v ar)" "$SANDBOX/bin/$fixture_machine-ar"
# Exercise the actual vendor-ready invocation with no usable default cc.
printf '%s\n' '#!/bin/sh' 'exit 97' > "$SANDBOX/bin/cc"
chmod +x "$SANDBOX/bin/cc"
{
    printf 'HOST_CC ?= cc\nvendor-ready:\n'
    sed -n '/^vendor-ready: /{n;p;}' "$ROOT/Makefile"
} > "$SANDBOX/host-selector.mk"
mkdir -p "$SANDBOX/env-check/tools/scripts"
cp "$SANDBOX/host-selector.mk" "$SANDBOX/env-check/Makefile"
printf '%s\n' '#!/bin/sh' 'test "${HOST_CC+x}" != x' > "$SANDBOX/env-check/tools/scripts/build_vendor.sh"
chmod +x "$SANDBOX/env-check/tools/scripts/build_vendor.sh"
(cd "$SANDBOX/env-check" && env -u HOST_CC -u HOSTCC make vendor-ready) ||
    fail 'implicit Make HOST_CC default was exported to the vendor script'
if output="$(cd "$SANDBOX" && env -u HOSTCC PATH="$SANDBOX/bin:$PATH" \
    VENDOR_CC="$SANDBOX/tools/native-cc" VENDOR_AR="$fixture_machine-ar" ZCL_VENDOR_OFFLINE=1 \
    make -f host-selector.mk HOST_CC="$SANDBOX/tools/native-cc" vendor-ready 2>&1)"; then
    fail 'host compiler fixture unexpectedly built missing archive'
fi
[[ "$output" == *'vendor/tor_stub.c missing (tracked source expected)'* ]] ||
    fail "vendor-ready ignored the selected host compiler: $output"
if output="$(cd "$SANDBOX" && HOSTCC="$SANDBOX/tools/native-cc" \
    PATH="$SANDBOX/bin:$PATH" VENDOR_CC="$SANDBOX/tools/native-cc" VENDOR_AR="$fixture_machine-ar" ZCL_VENDOR_OFFLINE=1 \
    make -f host-selector.mk HOST_CC=cc vendor-ready 2>&1)"; then
    fail 'host override fixture unexpectedly built missing archive'
fi
[[ "$output" == *'vendor/tor_stub.c missing (tracked source expected)'* ]] ||
    fail 'explicit HOSTCC did not override HOST_CC'
printf '%s\n' '#!/bin/sh' '[ "$1" = -dumpmachine ] && { echo aarch64-apple-darwin; exit 0; }' \
    'exec "$(dirname "$0")/native-cc" "$@"' > "$SANDBOX/tools/target-cc"
chmod +x "$SANDBOX/tools/target-cc"
ln -s "$(command -v ar)" "$SANDBOX/bin/aarch64-apple-darwin-ar"
if output="$(cd "$SANDBOX" && env -u HOSTCC PATH="$SANDBOX/bin:$PATH" \
    VENDOR_CC="$SANDBOX/tools/target-cc" VENDOR_AR=aarch64-apple-darwin-ar ZCL_VENDOR_OFFLINE=1 \
    make -f host-selector.mk HOST_CC="$SANDBOX/tools/native-cc" \
    ZCL_CROSS_TRIPLE=aarch64-apple-darwin vendor-ready 2>&1)"; then
    fail 'cross compiler fixture unexpectedly built missing archive'
fi
[[ "$output" == *'vendor/tor_stub.c missing (tracked source expected)'* ]] ||
    fail "cross target did not retain the selected host compiler: $output"
rm "$SANDBOX/bin/cc"
if output="$(cd "$SANDBOX/elsewhere" && HOSTCC=tools/native-cc \
    ZCL_VENDOR_OFFLINE=1 "$SANDBOX/tools/scripts/build_vendor.sh" libz.a 2>&1)"; then
    fail 'root-scoped compiler fixture unexpectedly built missing archive'
fi
[[ "$output" == *'offline cache miss or checksum failure: zlib-1.3.1.tar.gz'* ]] ||
    fail 'bootstrap compiled with a different executable than its compiler identity'

# A compiler named by a path under the checkout, the build scratch or HOME is
# used by its plain name, its directory first on PATH: OpenSSL records the
# literal compiler command in libcrypto.a, and the provenance identity hashes
# the command as written, so one spelling must survive every host. Any other
# path stays as given. The wrapper records how it was invoked and its PATH.
# HOME is a temporary directory in every case, so the build user's own home
# is never a root.
beside="$(mktemp -d "$(dirname "$SANDBOX")/zcl-vendor-beside.XXXXXX")"
mkdir -p "$beside/bin"
printf '%s\n' '#!/usr/bin/env bash' \
    "printf '%s\\n' \"\$VENDOR_CC\" \"\$PATH\" > '$SANDBOX/tools/path.log'" \
    "exec '$SANDBOX/tools/native-cc' \"\$@\"" > "$SANDBOX/tools/path-cc"
cp "$SANDBOX/tools/path-cc" "$beside/bin/path-cc"
chmod +x "$SANDBOX/tools/path-cc" "$beside/bin/path-cc"
expect_path_cc()      # HOME  VENDOR_CC  expected invocation  expected PATH head
{
    local home="$1" cc="$2" name="$3" head="$4" invoked path
    : > "$SANDBOX/tools/path.log"
    (cd "$SANDBOX" && HOME="$home" PATH="$SANDBOX/bin:/usr/bin:/bin" VENDOR_CC="$cc" \
        VENDOR_AR="$fixture_machine-ar" ZCL_VENDOR_OFFLINE=1 \
        tools/scripts/build_vendor.sh --check-provenance libz.a >/dev/null 2>&1) || true
    [ -s "$SANDBOX/tools/path.log" ] || fail "compiler fixture $cc was not invoked"
    { read -r invoked; read -r path; } < "$SANDBOX/tools/path.log"
    [[ "$invoked" == "$name" && "${path%%:*}" == "$head" ]] ||
        fail "compiler $cc under HOME $home: invoked as '$invoked' with PATH head '${path%%:*}', expected '$name' and '$head'"
}
expect_path_cc "$beside" "$SANDBOX/tools/path-cc" path-cc "$SANDBOX/tools"
expect_path_cc "$beside" "$beside/bin/path-cc" path-cc "$beside/bin"
expect_path_cc "$SANDBOX" "$beside/bin/path-cc" "$beside/bin/path-cc" "$SANDBOX/bin"
rm "$SANDBOX/tools/path-cc"

# One machine can be spelled three ways by one host: Debian's GCC says
# x86_64-linux-gnu, Clang says x86_64-unknown-linux-gnu and Red Hat's
# compilers say x86_64-redhat-linux. Compare the machine, not the vendor
# spelling, or a native Clang beside llvm-ar is refused as a cross compiler.
# A cross compiler stays one.
machine_cc()      # name  -dumpmachine answer
{
    printf '%s\n' '#!/usr/bin/env bash' \
        "case \"\${1:-}\" in -dumpmachine) printf '%s\\n' '$2'; exit 0;; esac" \
        "exec '$SANDBOX/tools/native-cc' \"\$@\"" > "$SANDBOX/tools/$1"
    chmod +x "$SANDBOX/tools/$1"
}
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$SANDBOX/bin/llvm-ar"
chmod +x "$SANDBOX/bin/llvm-ar"
for host_machine in x86_64-linux-gnu x86_64-redhat-linux; do
    machine_cc cc "$host_machine"
    machine_cc native-clang x86_64-unknown-linux-gnu
    if output="$(cd "$SANDBOX" && PATH="$SANDBOX/tools:$SANDBOX/bin:/usr/bin:/bin" \
        VENDOR_CC="$SANDBOX/tools/native-clang" VENDOR_AR=llvm-ar ZCL_VENDOR_OFFLINE=1 \
        tools/scripts/build_vendor.sh libtor_stub.a 2>&1)"; then
        fail 'native Clang fixture unexpectedly built missing archive'
    fi
    [[ "$output" == *'vendor/tor_stub.c missing (tracked source expected)'* ]] ||
        fail "a native Clang machine was treated as a cross compiler beside a host cc that says $host_machine: $output"
done
machine_cc native-clang aarch64-unknown-linux-gnu
if output="$(cd "$SANDBOX" && PATH="$SANDBOX/tools:$SANDBOX/bin:/usr/bin:/bin" \
    VENDOR_CC="$SANDBOX/tools/native-clang" VENDOR_AR=llvm-ar ZCL_VENDOR_OFFLINE=1 \
    tools/scripts/build_vendor.sh libtor_stub.a 2>&1)"; then
    fail 'cross Clang fixture unexpectedly built missing archive'
fi
[[ "$output" == *'llvm-ar cross exception requires Android'* ]] ||
    fail "a cross Clang was accepted as native beside a host cc that says x86_64-redhat-linux: $output"
rm "$SANDBOX/tools/cc" "$SANDBOX/tools/native-clang"

# Each row lists machine spellings, then their one key (see vendor_machine_key).
eval "$(sed -n '/^vendor_machine_key()/,/^}/p' "$ROOT/tools/scripts/build_vendor.sh")"
while read -r row; do
    want="${row##* }"
    for spelling in ${row% *}; do
        [ "$(vendor_machine_key "$spelling")" = "$want" ] ||
            fail "machine key of $spelling is '$(vendor_machine_key "$spelling")', not '$want'"
    done
done <<'MACHINES'
x86_64-unknown-linux-gnu x86_64-pc-linux-gnu x86_64-linux-gnu x86_64-redhat-linux x86_64-suse-linux x86_64-linux
aarch64-unknown-linux-android24 aarch64-linux-android24
aarch64-linux-android aarch64-linux-android
arm-none-eabi arm-eabi
aarch64-apple-darwin aarch64-darwin
x86_64-w64-mingw32 x86_64-mingw32
x86_64-linux-gnux32 x86_64-linux-gnux32
riscv64-elf riscv64-unknown-elf riscv64-elf
MACHINES

# A C driver with no C++ front end installed is an ordinary host shape (cc is
# one GCC major, g++ another). The lock helper is C only, so its identity
# must still be observable there instead of refusing every vendor build.
if command -v c++ >/dev/null 2>&1; then
    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'previous=""'
        printf '%s\n' 'for argument in "$@"; do'
        printf '%s\n' '    if [[ "$previous" == -x && "$argument" == c++ ]]; then'
        printf '%s\n' "        printf '%s\\n' \"cc: fatal error: cannot execute 'cc1plus': posix_spawnp: No such file or directory\" >&2"
        printf '%s\n' '        exit 1'
        printf '%s\n' '    fi'
        printf '%s\n' '    previous="$argument"'
        printf '%s\n' 'done'
        printf 'exec %q "$@"\n' "$SANDBOX/tools/native-cc"
    } > "$SANDBOX/tools/c-only-cc"
    chmod +x "$SANDBOX/tools/c-only-cc"
    if output="$(cd "$SANDBOX" && HOSTCC=tools/c-only-cc \
        ZCL_VENDOR_OFFLINE=1 tools/scripts/build_vendor.sh libz.a 2>&1)"; then
        fail 'C-only compiler fixture unexpectedly built missing archive'
    fi
    [[ "$output" == *'offline cache miss or checksum failure: zlib-1.3.1.tar.gz'* ]] ||
        fail 'a C driver without a C++ front end could not identify the lock helper compiler'
fi

"${HOST_CC:-cc}" -std=c23 -Wall -Wextra -Werror -pedantic \
    "$ROOT/tools/dev/vendor_compiler_selftest.c" -o "$SANDBOX/vendor-compiler-selftest"
"$SANDBOX/vendor-compiler-selftest" "$SANDBOX" "$fixture_machine"

wait_lock_selftest || fail 'vendor lock selftest failed'


if ZCL_VENDOR_OFFLINE=invalid "$ROOT/tools/scripts/build_vendor.sh" \
        --check-provenance >/dev/null 2>&1; then
    fail 'invalid offline policy value was accepted'
fi

# Exercise the production Make include boundaries with missing vendor inputs.
# A fresh directory per invocation has no marker or archives. Replace only
# the vendor builder with a contact marker: no compiler, network, or checkout
# build state is needed to observe whether Make attempts vendor bootstrap.
probe_mk="$SANDBOX/bootstrap.mk"
{
    printf '%s\n' 'VENDOR_LIBS := vendor/lib/missing.a' 'BIN_DIR := build/bin'
    awk '/^ZCL_TOR_PROVENANCE_GOALS :=/ { copying=1 }
         copying { print }
         /^ZCL_HOTSWAP_LOOP_ONLY :=/ { copying=0 }' "$ROOT/Makefile"
    awk '/^VENDOR_BOOTSTRAP_MK :=/ { copying=1 }
         /^# Generated view headers/ { copying=0 }
         copying { print }' "$ROOT/Makefile"
    printf '%s\n' 'ZCL_TOR := full' 'TOR_MISSING_ARCHIVES := vendor/tor/libtor.a'
    awk '/^ZCL_TOR_SKIP_GOALS :=/ { copying=1 }
         /^# The stub is reachable/ { copying=0 }
         copying { print }' "$ROOT/Makefile"
    cat <<'MAKE'
.DEFAULT_GOAL := z23
.PHONY: z23 windows-headless-run windows-headless-run-selftest
z23 audit dep-audit build/bin/dep_audit print-node-c23-srcs help doctor doctor-build timings agent-dev-status \
print-CFLAGS print-DEV-CFLAGS print-LDFLAGS print-DEV-LDFLAGS print-build-flags \
windows-headless-run windows-headless-run-selftest build/bin/z23-headless-run.exe $(ZCL_TOR_PROVENANCE_GOALS):
	@printf 'lean=%s\n' '$(ZCL_HOTSWAP_LOOP_ONLY)'
$(VENDOR_BOOTSTRAP_MK):
	@mkdir -p build/identity
	@printf '%s\n' contacted > vendor-contact
	@printf '%s\n' '# vendor boundary established' > $@
$(TOR_BOOTSTRAP_MK):
	@mkdir -p build/identity
	@printf '%s\n' contacted > tor-contact
	@printf '%s\n' '# Tor boundary established' > $@
MAKE
} > "$probe_mk"

probe_number=0
probe_bootstrap()
{
    local expected="$1"
    shift
    probe_number=$((probe_number + 1))
    local fixture="$SANDBOX/bootstrap-$probe_number"
    mkdir -p "$fixture"
    if ! make --no-print-directory -C "$fixture" -f "$probe_mk" "$@" \
            > "$fixture/output" 2>&1; then
        cat "$fixture/output" >&2
        fail "bootstrap selection probe failed: $*"
    fi
    if [ "$expected" = skip ]; then
        grep -q '^lean=1$' "$fixture/output" ||
            fail "bootstrap helper entered authoritative node parse: $*"
    elif grep -q '^lean=1$' "$fixture/output"; then
        fail "$expected goal entered lean helper parse: $*"
    fi
    for service in vendor tor; do
        if [ "$expected" = require ]; then
            [ -s "$fixture/$service-contact" ] ||
                fail "node goals skipped $service bootstrap: $*"
        else
            [ ! -e "$fixture/$service-contact" ] ||
                fail "nonlink goals invoked $service bootstrap: $*"
        fi
    done
}

for goal in windows-headless-run windows-headless-run-selftest \
        build/bin/z23-headless-run.exe build/bin/z23-tor-provenance \
        tools/tor-provenance z23-tor-provenance dep-audit build/bin/dep_audit; do
    probe_bootstrap skip "$goal"
    probe_bootstrap require "$goal" z23
done
for goal in print-node-c23-srcs help doctor doctor-build timings agent-dev-status \
    print-CFLAGS print-DEV-CFLAGS print-LDFLAGS print-DEV-LDFLAGS print-build-flags; do
    probe_bootstrap query "$goal"
    probe_bootstrap require "$goal" z23
done
probe_bootstrap skip windows-headless-run windows-headless-run-selftest
probe_bootstrap skip windows-headless-run-selftest dep-audit
probe_bootstrap require BIN_DIR=custom-bin build/bin/dep_audit
probe_bootstrap require audit
probe_bootstrap require dep-audit audit
probe_bootstrap require z23
probe_bootstrap require

# The selected target's REQUIRED closure is checked before named provenance.
mkdir -p "$SANDBOX/fake-ndk/build/cmake"
: > "$SANDBOX/fake-ndk/build/cmake/android.toolchain.cmake"
cat > "$SANDBOX/bin/fake-android-cc" <<'COMPILER'
#!/usr/bin/env bash
case "${1:-}" in
    -dumpmachine) printf '%s\n' aarch64-linux-android24 ;;
    --version) printf '%s\n' 'fixture Android compiler' ;;
    *) cat >/dev/null ;;
esac
COMPILER
chmod +x "$SANDBOX/bin/fake-android-cc"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$SANDBOX/bin/llvm-ar"
chmod +x "$SANDBOX/bin/llvm-ar"

identity_calls="$(awk '{ n++ } END { print n + 0 }' "$VENDOR_LOCK_KEY_TRACE")"
for archive in libsecp256k1.a libsecp256k1-darwin.a libsecp256k1-android.a; do
    if [ "$archive" = libsecp256k1-android.a ]; then
        [[ "$(awk '{ n++ } END { print n + 0 }' "$VENDOR_LOCK_KEY_TRACE")" == "$identity_calls" ]] ||
            fail 'out-of-target provenance refusal derived a lock compiler identity'
        expected='vendor provenance verification failed'
    else
        expected='archive is not required for this target'
    fi
    if output="$(cd "$SANDBOX" && VENDOR_TARGET=aarch64-linux-android24 \
        PATH="$SANDBOX/bin:$PATH" ANDROID_NDK_ROOT="$SANDBOX/fake-ndk" VENDOR_CC="$SANDBOX/bin/fake-android-cc" \
        VENDOR_AR=llvm-ar ZCL_VENDOR_OFFLINE=1 tools/scripts/build_vendor.sh \
        --check-provenance "$archive" 2>&1)"; then
        fail "cross provenance unexpectedly accepted $archive"
    fi
    [[ "$output" == *"$expected"* ]] || fail "provenance refusal for $archive did not report $expected"
done

# A populated archive cache restores in offline mode without a downloader, and
# the restored archive still passes the stamp check. The first run builds libz
# from the already-downloaded pinned tarball and saves the bundle; the second
# run has neither archive, stamp nor tarball, so only the cache can supply it.
zlib_tarball="$ROOT/vendor/.cache/zlib-1.3.1.tar.gz"
if [ -f "$zlib_tarball" ]; then
    rm -rf "$VENDOR_ARCHIVE_CACHE"; mkdir -p "$VENDOR_ARCHIVE_CACHE"
    cp "$zlib_tarball" "$SANDBOX/vendor/.cache/"
    (cd "$SANDBOX" && DOWNLOADER_CONTACT_LOG="$contact_log" \
        PATH="$SANDBOX/bin:$PATH" ZCL_VENDOR_OFFLINE=1 \
        tools/scripts/build_vendor.sh libz.a >/dev/null 2>&1) ||
        fail 'offline build from the cached tarball failed'
    [ -n "$(find "$VENDOR_ARCHIVE_CACHE/zlib" -name bundle.tar 2>/dev/null)" ] ||
        fail 'a verified build did not populate the archive cache'
    rm -rf "$SANDBOX/vendor/lib/libz.a" "$SANDBOX/vendor/lib/.provenance" \
        "$SANDBOX/vendor/.cache/zlib-1.3.1.tar.gz" "$SANDBOX/vendor/include/zlib.h"
    output="$(cd "$SANDBOX" && DOWNLOADER_CONTACT_LOG="$contact_log" \
        PATH="$SANDBOX/bin:$PATH" ZCL_VENDOR_OFFLINE=1 \
        tools/scripts/build_vendor.sh libz.a 2>&1)" ||
        fail 'populated cache did not restore in offline mode'
    [[ "$output" == *'restored libz.a (vendor archive cache)'* ]] ||
        fail 'offline restore was not served from the archive cache'
    [ -f "$SANDBOX/vendor/lib/libz.a" ] || fail 'restore left no archive'
    [ ! -s "$contact_log" ] || fail 'offline cache restore invoked a downloader'
    (cd "$SANDBOX" && ZCL_VENDOR_OFFLINE=1 tools/scripts/build_vendor.sh \
        --check-provenance libz.a >/dev/null 2>&1) ||
        fail 'restored archive failed the provenance stamp check'
    # Tamper: a corrupt bundle must fall back to the (absent) download path.
    rm -rf "$SANDBOX/vendor/lib/libz.a" "$SANDBOX/vendor/lib/.provenance"
    for b in "$VENDOR_ARCHIVE_CACHE"/zlib/*/bundle.tar; do printf x >>"$b"; done
    if (cd "$SANDBOX" && ZCL_VENDOR_OFFLINE=1 \
        tools/scripts/build_vendor.sh libz.a >/dev/null 2>&1); then
        fail 'corrupt cache bundle was accepted'
    fi
    # A parent make's command line reaches every sub-make through MAKEFLAGS,
    # where it outranks the environment, and a builder launched in a parallel
    # group runs with a share of the job count. From a parent make that names
    # another compiler and four jobs on its command line, the vendor compiler
    # alone builds zlib and its sub-make inherits no flag and takes two jobs.
    leak="$SANDBOX/leak"
    mkdir -p "$leak"
    rm -rf "$VENDOR_ARCHIVE_CACHE"
    cp "$zlib_tarball" "$SANDBOX/vendor/.cache/"
    cp "$ROOT"/vendor/.cache/sqlite-amalgamation-*.zip "$SANDBOX/vendor/.cache/" 2>/dev/null || :
    printf '%s\n' '#!/usr/bin/env bash' "printf '%s\\n' \"\$*\" >> '$leak/vendor-cc.log'" \
        "exec '$(command -v cc)' \"\$@\"" > "$leak/vendor-cc"
    printf '%s\n' '#!/usr/bin/env bash' "printf '%s\\n' \"\$*\" >> '$leak/foreign-cc.log'" \
        'exit 97' > "$leak/foreign-cc"
    printf '%s\n' '#!/usr/bin/env bash' \
        "printf 'MAKEFLAGS=[%s] args=[%s]\\n' \"\${MAKEFLAGS-<unset>}\" \"\$*\" >> '$leak/make.log'" \
        "exec '$real_make' \"\$@\"" > "$SANDBOX/bin/make"
    chmod +x "$leak/vendor-cc" "$leak/foreign-cc" "$SANDBOX/bin/make"
    printf '%s\n' 'probe:' '	VENDOR_MAX_PARALLEL=2 tools/scripts/build_vendor.sh libz.a libsqlite3.a' \
        > "$SANDBOX/parent.mk"
    (cd "$SANDBOX" && PATH="$SANDBOX/bin:$PATH" make --no-print-directory -f parent.mk -j4 JOBS=4 \
        CC="$leak/foreign-cc" VENDOR_CC="$leak/vendor-cc" ZCL_VENDOR_OFFLINE=1 probe > "$leak/vendor.log" 2>&1) || :
    rm "$SANDBOX/bin/make"
    submake="$(awk '/ libz\.a\]$/ { print; exit }' "$leak/make.log" 2>/dev/null || true)"
    [ ! -s "$leak/foreign-cc.log" ] ||
        fail "a parent make's command-line compiler reached a vendor sub-make: $(head -n 1 "$leak/foreign-cc.log")"
    [ -s "$leak/vendor-cc.log" ] && [[ "$submake" == 'MAKEFLAGS=[] args=[-j2 '* ]] ||
        fail "the vendor compiler did not build zlib alone with its share of the jobs: sub-make '${submake:-not run}'; build_vendor.sh said: $(tail -n 3 "$leak/vendor.log" | tr '\n' ' ')"
fi

# Run each fixture in its own job-control process group so orphaned workers
# remain observable after the driver exits, without inspecting other processes.
run_failed_vendor_group() (
    set -m || return 1
    [[ $- == *m* ]] || return 1
    cd "$SANDBOX" || return 1
    local driver= status=0
    trap 'if [ -n "$driver" ] && kill -0 -- "-$driver" 2>/dev/null; then
        kill -KILL -- "-$driver" 2>/dev/null || :
        for _ in {1..100}; do
            kill -0 -- "-$driver" 2>/dev/null || break
            sleep 0.01
        done
        if kill -0 -- "-$driver" 2>/dev/null; then
            echo "fixture worker group did not terminate" >&2
            exit 1
        fi
    fi' EXIT
    VENDOR_FORCE=1 ZCL_VENDOR_OFFLINE=1 VENDOR_MAX_PARALLEL="$1" \
        "$SANDBOX/tools/scripts/build_vendor.sh" libcrypto.a libevent.a libz.a \
        >"$2" 2>&1 &
    driver=$!
    wait "$driver" || status=$?
    if kill -0 -- "-$driver" 2>/dev/null; then
        printf '%s\n' "vendor worker remained active after failure" >&2
        return 1
    fi
    driver=
    [ "$status" -ne 0 ]
)
# An OpenSSL failure must not release dependent libevent work, and all
# independent workers must be reaped before the driver reports failure.
rm -rf "$SANDBOX/vendor/.cache" "$VENDOR_ARCHIVE_CACHE"
mkdir -p "$SANDBOX/vendor/.cache" "$VENDOR_ARCHIVE_CACHE"
for mode in parallel serial; do
    if [ "$mode" = parallel ]; then workers=3; else workers=1; fi
    log="$SANDBOX/$mode-failure.log"
    run_failed_vendor_group "$workers" "$log" ||
        fail "offline $mode driver succeeded or left a worker active"
    grep -q 'offline cache miss or checksum failure: openssl' "$log" ||
        fail "$mode driver did not report the OpenSSL cache miss"
    ! grep -q 'libevent 2.1.12' "$log" ||
        fail "$mode libevent started after its OpenSSL dependency failed"
done

# A failed build step exits non-zero, prints no "built" line, keeps archive and stamp.
cp "$ROOT/vendor/tor_stub.c" "$SANDBOX/vendor/"
printf '%s\n' '#!/usr/bin/env bash' 'case " $* " in *" -c "*) echo "stub-cc: boom" >&2; exit 1;; esac' 'exec cc "$@"' > "$SANDBOX/bin/failcc"; chmod +x "$SANDBOX/bin/failcc"
build_tor() { (cd "$SANDBOX" && env "$@" tools/scripts/build_vendor.sh libtor_stub.a 2>&1); }
state() { cksum "$SANDBOX/vendor/lib/.provenance/libtor_stub.a.stamp" "$SANDBOX/vendor/lib/libtor_stub.a"; }
good="$(build_tor VENDOR_FORCE=1)" && [[ "$good" == *'built   libtor_stub.a'* ]] || fail 'host tor_stub build failed'
before="$(state)"
bad="$(build_tor VENDOR_FORCE=1 VENDOR_CC="$SANDBOX/bin/failcc")" && fail 'failing compiler exited 0'
[[ "$bad" == *'stub-cc: boom'* && "$bad" == *'FAILED build_tor_stub libtor_stub.a'* && "$bad" == *'full log: '*'log.build_tor_stub'* && "$bad" == *'step failed: '* && "$bad" != *'built   libtor_stub.a'* && "$(state)" == "$before" ]] ||
    fail 'failed build printed built, hid the step error, or touched archive/stamp'
printf '%s\n' \
    'build_vendor_offline_selftest: PASS downloader_contacted=false cache_miss_refused=true launcher_vendor_and_tor_skipped=true source_query_vendor_and_tor_skipped=true mixed_goals_bootstrap=true'
