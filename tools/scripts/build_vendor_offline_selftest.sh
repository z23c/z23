#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove offline vendor mode refuses a cache miss before invoking a downloader.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bash "$ROOT/tools/scripts/vendor_lock_selftest.sh"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-vendor-offline-selftest.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT HUP INT TERM
# A populated shared vendor archive cache would satisfy the archive these cases
# delete. Every case below sees an empty private one unless it opts in.
export VENDOR_ARCHIVE_CACHE="$SANDBOX/vendor-archive-cache"
mkdir -p "$VENDOR_ARCHIVE_CACHE"

fail()
{
    printf 'build_vendor_offline_selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

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
cp "$ROOT/tools/dev/build-epoch-key.sh" "$SANDBOX/tools/dev/"

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

# The compiler driver grounds slash-containing relative tools at the source
# root. Compilation must use that same executable from a different cwd.
mkdir -p "$SANDBOX/elsewhere/tools"
# Freeze the qualified driver before the relative fixture overrides HOSTCC.
# Match the production token grammar; never evaluate a compiler command.
fixture_host_cc="${HOSTCC:-cc}"
case "$(uname -s 2>/dev/null)" in
    MSYS*|MINGW*|CYGWIN*) fixture_host_cc="${HOSTCC:-${ZCL_BOOTSTRAP_CC:-/usr/bin/cc}}" ;;
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
if output="$(cd "$SANDBOX/elsewhere" && HOSTCC=tools/native-cc \
    ZCL_VENDOR_OFFLINE=1 "$SANDBOX/tools/scripts/build_vendor.sh" libz.a 2>&1)"; then
    fail 'root-scoped compiler fixture unexpectedly built missing archive'
fi
[[ "$output" == *'offline cache miss or checksum failure: zlib-1.3.1.tar.gz'* ]] ||
    fail 'bootstrap compiled with a different executable than its compiler identity'

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
        printf 'exec'
        printf ' %q' "${fixture_host_argv[@]}"
        printf ' "$@"\n'
    } > "$SANDBOX/tools/c-only-cc"
    chmod +x "$SANDBOX/tools/c-only-cc"
    if output="$(cd "$SANDBOX" && HOSTCC=tools/c-only-cc \
        ZCL_VENDOR_OFFLINE=1 tools/scripts/build_vendor.sh libz.a 2>&1)"; then
        fail 'C-only compiler fixture unexpectedly built missing archive'
    fi
    [[ "$output" == *'offline cache miss or checksum failure: zlib-1.3.1.tar.gz'* ]] ||
        fail 'a C driver without a C++ front end could not identify the lock helper compiler'
fi

# Bad bootstrap identities must refuse before touching an existing helper.
cp -R "$SANDBOX/build/bin/vendor-lock" "$SANDBOX/helper-cache-before"
cp "$SANDBOX/tools/dev/build-epoch-key.sh" "$SANDBOX/key-driver-before"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$SANDBOX/tools/dev/build-epoch-key.sh"
if output="$(ZCL_VENDOR_OFFLINE=1 "$SANDBOX/tools/scripts/build_vendor.sh" libz.a 2>&1)"; then
    fail 'empty compiler identity admitted'
fi
[[ "$output" == *'vendor lock compiler identity invalid'* ]] || fail 'compiler identity refusal unnamed'
cp "$SANDBOX/key-driver-before" "$SANDBOX/tools/dev/build-epoch-key.sh"
cp "$SANDBOX/tools/scripts/vendor_provenance_lib.sh" "$SANDBOX/provenance-before"
for hash_behavior in 'return 1' 'return 0'; do
    cp "$SANDBOX/provenance-before" "$SANDBOX/tools/scripts/vendor_provenance_lib.sh"
    printf '\nvp_sha256_file() { %s; }\n' "$hash_behavior" >> "$SANDBOX/tools/scripts/vendor_provenance_lib.sh"
    if output="$(ZCL_VENDOR_OFFLINE=1 "$SANDBOX/tools/scripts/build_vendor.sh" libz.a 2>&1)"; then
        fail 'failed or empty source hash admitted'
    fi
    [[ "$output" == *'vendor lock source hash'* ]] || fail 'source hash refusal unnamed'
done
cp "$SANDBOX/provenance-before" "$SANDBOX/tools/scripts/vendor_provenance_lib.sh"
diff -r "$SANDBOX/helper-cache-before" "$SANDBOX/build/bin/vendor-lock" >/dev/null ||
    fail 'identity refusal modified cached helper bytes'
mkdir "$SANDBOX/unknown-legacy.lock"
if output="$(VENDOR_LOCK_HELD=1 VENDOR_LOCK_DIR="$SANDBOX/unknown-legacy.lock" \
    ZCL_VENDOR_OFFLINE=1 "$SANDBOX/tools/scripts/build_vendor.sh" libz.a 2>&1)"; then
    fail 'forged environment bypassed unknown legacy lock'
fi
[[ "$output" == *vendor_lock_legacy_directory_refused* ]] || fail 'legacy refusal unnamed'
[[ -d "$SANDBOX/unknown-legacy.lock" ]] || fail 'unknown legacy owner removed'

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
    printf '%s\n' 'VENDOR_LIBS := vendor/lib/missing.a'
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
z23 print-node-c23-srcs help doctor doctor-build timings agent-dev-status \
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
    if [ "$expected" = skip ] || [ "$expected" = query ]; then
        if [ "$expected" = skip ]; then
            grep -q '^lean=1$' "$fixture/output" ||
                fail "bootstrap helper entered authoritative node parse: $*"
        elif grep -q '^lean=1$' "$fixture/output"; then
            fail "source query skipped the full node source declarations: $*"
        fi
        [ ! -e "$fixture/vendor-contact" ] ||
            fail "nonlink goals invoked vendor bootstrap: $*"
        [ ! -e "$fixture/tor-contact" ] ||
            fail "nonlink goals invoked Tor bootstrap: $*"
    else
        if grep -q '^lean=1$' "$fixture/output"; then
            fail "node goals entered lean helper parse: $*"
        fi
        [ -s "$fixture/vendor-contact" ] ||
            fail "node goals skipped vendor bootstrap: $*"
        [ -s "$fixture/tor-contact" ] ||
            fail "node goals skipped Tor bootstrap: $*"
    fi
}

for goal in windows-headless-run windows-headless-run-selftest \
        build/bin/z23-headless-run.exe build/bin/z23-tor-provenance \
        tools/tor-provenance z23-tor-provenance; do
    probe_bootstrap skip "$goal"
    probe_bootstrap require "$goal" z23
done
for goal in print-node-c23-srcs help doctor doctor-build timings agent-dev-status \
    print-CFLAGS print-DEV-CFLAGS print-LDFLAGS print-DEV-LDFLAGS print-build-flags; do
    probe_bootstrap query "$goal"
    probe_bootstrap require "$goal" z23
done
probe_bootstrap skip windows-headless-run windows-headless-run-selftest
probe_bootstrap require z23
probe_bootstrap require

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
fi

printf '%s\n' \
    'build_vendor_offline_selftest: PASS downloader_contacted=false cache_miss_refused=true launcher_vendor_and_tor_skipped=true source_query_vendor_and_tor_skipped=true mixed_goals_bootstrap=true'
