#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install.sh — the front door served at the project domain.
#
# THIS IS NOT THE INSTALLER. It is the smallest honest thing that can stand
# in front of one:
#   1. refuse a machine we publish no runtime for, naming the ones we do;
#   2. compare the release pin carried by THREE consistency channels — baked
#      in below, a DNS TXT record, and the source repository — refusing unless
#      all reachable ones agree;
#   3. verify the served installer against that pin BEFORE a line of it runs;
#   4. hand off, passing every attestation through so the installer judges the
#      same evidence itself.
#
# This file is already executing when these checks run. A curl-to-shell user
# trusts the z23.sh TLS origin for these first-stage bytes; a compromised origin
# can replace both this program and its checks. The pin protects only fetched
# second-stage and release bytes after an honestly obtained front door starts.
# An independently verified bootstrap must download this file and verify it
# against an anchor obtained outside z23.sh before executing it.
#
# POSIX sh, because the future convenience bootstrap ends in `sh` and that is
# often dash: no bashisms, no [[ ]], no `set -o pipefail` (not POSIX). Every
# status-carrying test here is pipeline-free, so none can invert on SIGPIPE.
# No prompt and no terminal is required — this runs under a coding agent as
# often as a person, and every refusal names the thing it protects, never the
# shape of the caller.
#
# No public bootstrap is currently published: the baked pin is the all-zero
# sentinel and this scaffold refuses. See docs/work/BOOTSTRAP_PLAN.md.
# --print-pin resolves the consistency channels and installs nothing.
set -euf
# build_release.sh produces x86_64-linux only today, so that is the whole
# published set. Refusing a machine we do not publish for, by name, beats
# installing a binary that cannot run on it.
PUBLISHED_PLATFORMS=" linux-x86_64 "
ORIGIN="${Z23_INSTALL_TEST_ORIGIN:-https://z23.sh}"
PIN_DNS_NAME="${Z23_INSTALL_TEST_PIN_DNS:-_z23-pin.z23.sh}"
PIN_REPO_URL="${Z23_INSTALL_TEST_PIN_REPO_URL:-https://raw.githubusercontent.com/ZclassiC23/zclassic/main/packaging/install/RELEASE_PIN}"
# Channel 1 of 3: baked into these bytes, rewritten by the release cutter.
# It is not an external trust anchor for a copy of this file fetched from the
# same origin. The all-zero sentinel means NO RELEASE IS PINNED YET.
PIN_ZERO=0000000000000000000000000000000000000000000000000000000000000000
PIN_BAKED="z23-pin-v1:$PIN_ZERO:$PIN_ZERO"
# Harness hook, not an install knob: anyone who can set your environment
# already owns this process. It exists so the refusals below are proved.
[ -z "${Z23_INSTALL_TEST_BAKED_PIN:-}" ] || PIN_BAKED="$Z23_INSTALL_TEST_BAKED_PIN"
die() { printf 'z23-install: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'z23-install: %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
is_sha256() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}
# z23-pin-v1:<64 hex manifest>:<64 hex installer> — no spaces, so a pin is one
# argv element and one TXT string, needing no quoting anywhere.
pin_parse() {
    case "$1" in "z23-pin-v1:$PIN_ZERO:$PIN_ZERO") return 1 ;; esac
    pin_rest="${1#z23-pin-v1:}"
    [ "$pin_rest" != "$1" ] || return 1
    PIN_MANIFEST="${pin_rest%%:*}"
    [ "$PIN_MANIFEST" != "$pin_rest" ] || return 1
    PIN_INSTALLER="${pin_rest#*:}"
    case "$PIN_INSTALLER" in *:*) return 1 ;; esac
    is_sha256 "$PIN_MANIFEST" && is_sha256 "$PIN_INSTALLER"
}
sha256_file() {
    if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
    elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
    elif have openssl; then openssl dgst -sha256 "$1" | sed 's/.*= *//'
    else return 1
    fi
}
fetch() { # url dest max-bytes max-seconds
    curl --connect-timeout 10 --max-time "$4" --max-filesize "$3" -fsSL "$1" -o "$2"
}

# Source 2 of 3. dig, host and nslookup are all absent from a genuinely
# minimal container, so each is checked for and the honest answer otherwise is
# no-dns-tool. No DNS-over-HTTPS fallback: trusting an unnamed third-party
# resolver is a worse dependency than the one it replaces. Losing DNS costs
# one vote; the quorum rule decides the rest.
dns_pin() {
    DNS_PIN=""; DNS_WHY=""
    if have dig; then
        dns_raw="$(dig +short +time=5 +tries=2 TXT "$PIN_DNS_NAME" 2>/dev/null || true)"
    elif have host; then
        dns_raw="$(host -t TXT "$PIN_DNS_NAME" 2>/dev/null || true)"
    elif have nslookup; then
        dns_raw="$(nslookup -type=TXT "$PIN_DNS_NAME" 2>/dev/null || true)"
    else
        DNS_WHY=no-dns-tool; return 0
    fi
    if [ -z "$dns_raw" ]; then DNS_WHY=no-answer; return 0; fi
    dns_txt="$(printf '%s\n' "$dns_raw" \
        | sed -n 's/.*"\(z23-pin-v1:[^"]*\)".*/\1/p' | sed -n 1p)"
    # A captive portal answers with something that is not a pin at all: that
    # is UNREACHABLE, not disagreement — it must not trip our loudest refusal.
    if [ -z "$dns_txt" ] || ! pin_parse "$dns_txt"; then
        DNS_WHY=malformed-answer; return 0
    fi
    DNS_PIN="$dns_txt"
}
repo_pin() { # Source 3 of 3.
    REPO_PIN=""; REPO_WHY=""
    if ! fetch "$PIN_REPO_URL" "$WORK/repo.pin" 512 20; then
        REPO_WHY=fetch-failed; return 0
    fi
    repo_txt="$(sed -n 's/^\(z23-pin-v1:[0-9a-f:]*\)$/\1/p' "$WORK/repo.pin" | sed -n 1p)"
    if [ -z "$repo_txt" ] || ! pin_parse "$repo_txt"; then
        REPO_WHY=malformed-answer; return 0
    fi
    REPO_PIN="$repo_txt"
}

# The consistency judgement. Two answered pins that differ REFUSE — never a majority
# vote: disagreement means a rollback, a half-finished publish or a
# compromise, and installing the winner would hide it. Fewer than two answered
# also REFUSE — one source is not corroboration. Exactly two agreeing proceed,
# loudly. This protects later fetches only after this exact program has begun;
# it does not authenticate the first-stage program itself. Demanding all three
# would hand a veto to any resolver that drops TXT.
consider() { # origin pin unreachable-reason
    if [ -n "$2" ]; then
        ANSWERED=$((ANSWERED + 1))
        if [ -z "$AGREED_PIN" ]; then
            AGREED_PIN="$2"; AGREED_ORIGIN="$1"
        elif [ "$2" != "$AGREED_PIN" ]; then
            say "attested pin $AGREED_ORIGIN=$AGREED_PIN"
            say "attested pin $1=$2"
            die "release pin disagreement between $AGREED_ORIGIN and $1 — refusing to install either"
        fi
    else
        UNREACHABLE="$UNREACHABLE${UNREACHABLE:+, }$1=$3"
    fi
}
attest_arg() { # origin pin unreachable-reason
    if [ -n "$2" ]; then printf -- '--attest=%s=%s' "$1" "$2"
    else printf -- '--attest-unreachable=%s=%s' "$1" "$3"
    fi
}
PRINT_PIN=0
case "${1:-}" in
    '') ;;
    --print-pin) PRINT_PIN=1 ;;
    *) die "unknown argument: $1" ;;
esac

case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) os="$(uname -s)" ;; esac
case "$(uname -m)" in
    x86_64|amd64) cpu=x86_64 ;;
    aarch64|arm64) cpu=aarch64 ;;
    *) cpu="$(uname -m)" ;;
esac
PLATFORM="$os-$cpu"
if [ "$PRINT_PIN" -eq 0 ]; then
    case "$PUBLISHED_PLATFORMS" in
        *" $PLATFORM "*) ;;
        *) die "no Z23 runtime is published for $PLATFORM; published:${PUBLISHED_PLATFORMS% }" ;;
    esac
    have bash || die "the Z23 installer is a bash script and bash was not found"
    have sha256sum || have shasum || have openssl \
        || die "no SHA-256 tool (sha256sum, shasum or openssl) — nothing here could be verified"
fi
have curl || die "curl is required to reach the release pin and the installer"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/z23-install.XXXXXX")" || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
BAKED_PIN=""; BAKED_WHY=no-release-pinned
if [ "$PIN_BAKED" != "z23-pin-v1:$PIN_ZERO:$PIN_ZERO" ]; then
    if pin_parse "$PIN_BAKED"; then BAKED_PIN="$PIN_BAKED"; else BAKED_WHY=malformed-answer; fi
fi
dns_pin
repo_pin

ANSWERED=0; AGREED_PIN=""; AGREED_ORIGIN=""; UNREACHABLE=""
consider baked "$BAKED_PIN" "$BAKED_WHY"
consider dns "$DNS_PIN" "$DNS_WHY"
consider repo "$REPO_PIN" "$REPO_WHY"
[ "$ANSWERED" -ge 2 ] \
    || die "release pin quorum: $ANSWERED of 3 sources answered, two independent sources are required for pin consistency; this does not authenticate the first-stage script (unreachable: ${UNREACHABLE:-none})"
[ "$ANSWERED" -ge 3 ] \
    || say "release pin agreed by $ANSWERED of 3 sources (unreachable: $UNREACHABLE)"
pin_parse "$AGREED_PIN" || die "agreed pin is not a z23-pin-v1 record"
if [ "$PRINT_PIN" -eq 1 ]; then printf '%s\n' "$AGREED_PIN"; exit 0; fi

fetch "$ORIGIN/install_z23.sh" "$WORK/install_z23.sh" 262144 60 \
    || die "could not fetch $ORIGIN/install_z23.sh"
GOT_INSTALLER="$(sha256_file "$WORK/install_z23.sh")" || die "could not hash the fetched installer"
[ "$GOT_INSTALLER" = "$PIN_INSTALLER" ] \
    || die "installer digest mismatch — $ORIGIN served bytes the agreed release pin does not name"

# The current convenience default is the same domain. An operator may select
# any mirror with Z23_RELEASE_SOURCE, but automatic decentralized discovery and
# failover do not exist yet.
set -- "--source=${Z23_RELEASE_SOURCE:-$ORIGIN/release/$PLATFORM}" \
    "--manifest-sha256=$PIN_MANIFEST" \
    "$(attest_arg baked "$BAKED_PIN" "$BAKED_WHY")" \
    "$(attest_arg dns "$DNS_PIN" "$DNS_WHY")" \
    "$(attest_arg repo "$REPO_PIN" "$REPO_WHY")"
bash "$WORK/install_z23.sh" "$@"
