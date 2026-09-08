#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Deterministic service-discovery fixtures; never contact a host supervisor.
set -euo pipefail
SELF_DIR="$(cd "${BASH_SOURCE[0]%/*}" && pwd)"
source "$SELF_DIR/lib/service_args.sh"
fixture_domain_case=''
systemctl() { return 1; }
zcl_service_launchd_label() { printf 'org.z23.fixture\n'; }
launchctl() {
    [ "$1" = print ] || return 2
    case "$fixture_domain_case:$2" in
        gui:gui/*|both:gui/*) printf 'state = running\npid = 123\n' ;;
        background:user/*|both:user/*) printf 'state = running\npid = 456\n' ;;
        *) return 1 ;;
    esac
}
fail() { printf 'service-args selftest: FAIL: %s\n' "$*" >&2; exit 1; }
fixture_domain_case=gui
[ "$(zcl_service_pid fixture fixture.plist)" = 123 ] || fail 'GUI job not discovered'
[ "$(zcl_service_active_state fixture fixture.plist)" = active ] || fail 'GUI state lost'
fixture_domain_case=background
[ "$(zcl_service_pid fixture fixture.plist)" = 456 ] || fail 'Background job not discovered'
[ "$(zcl_service_active_state fixture fixture.plist)" = active ] || fail 'Background state lost'
for fixture_domain_case in both missing; do
    if zcl_service_pid fixture fixture.plist >/dev/null 2>&1; then
        fail "$fixture_domain_case job produced a PID"
    fi
    if zcl_service_active_state fixture fixture.plist >/dev/null 2>&1; then
        fail "$fixture_domain_case job produced an active state"
    fi
done
printf 'service-args selftest: PASS gui=true background=true ambiguity_refused=true absent_refused=true\n'
