#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove offline vendor mode refuses a cache miss before invoking a downloader.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-vendor-offline-selftest.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT HUP INT TERM

fail()
{
    printf 'build_vendor_offline_selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

mkdir -p "$SANDBOX/tools/scripts" "$SANDBOX/vendor/.cache" \
    "$SANDBOX/vendor/lib" "$SANDBOX/vendor/include" "$SANDBOX/bin"
cp "$ROOT/tools/scripts/build_vendor.sh" \
    "$ROOT/tools/scripts/vendor_provenance_lib.sh" "$SANDBOX/tools/scripts/"

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
z23 windows-headless-run windows-headless-run-selftest build/bin/z23-headless-run.exe $(ZCL_TOR_PROVENANCE_GOALS):
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
        [ ! -e "$fixture/vendor-contact" ] ||
            fail "launcher-only goals invoked vendor bootstrap: $*"
        [ ! -e "$fixture/tor-contact" ] ||
            fail "launcher-only goals invoked Tor bootstrap: $*"
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
probe_bootstrap skip windows-headless-run windows-headless-run-selftest
probe_bootstrap require z23
probe_bootstrap require

printf '%s\n' \
    'build_vendor_offline_selftest: PASS downloader_contacted=false cache_miss_refused=true launcher_vendor_and_tor_skipped=true mixed_goals_bootstrap=true'
