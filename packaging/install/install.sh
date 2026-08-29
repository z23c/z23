#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install.sh — the front door served at the project domain.
#
# THIS IS NOT THE INSTALLER, AND IT IS NO LONGER THE CHECKS EITHER. Every line
# below is already executing when it runs: a `curl https://z23.sh | sh` user
# trusts the TLS origin for these first-stage bytes, and a compromised origin
# can replace both this program and its checks. So logic that lives HERE is
# logic an attacker gets to rewrite for free — and this file used to hold 206
# lines of it, with a hand-maintained 322-line PowerShell twin that had to
# make every one of the same decisions the same way.
#
# It now does four things and stops:
#   1. name this machine;
#   2. fetch ONE small C23 bootstrap binary published for it;
#   3. check its SHA-256 against the digest baked in below;
#   4. run it, forwarding every argument.
#
# The release-pin channels, their agreement rule, the platform refusal, the
# installer verification and the handoff all moved into that binary
# (tools/install/z23_bootstrap.c over lib/install). They are written once, in
# C23, for every platform, and they execute only after a digest check.
#
# This shell line is irreducible: a bare machine has no compiler. What is
# reducible is how much it decides, and that is now one digest comparison.
#
# The all-zero digest below is the SENTINEL: NO BOOTSTRAP IS PUBLISHED YET,
# and this scaffold refuses rather than fetching something it cannot name.
# See docs/work/BOOTSTRAP_PLAN.md.
#
# PUBLISHED, not BUILT. packaging/release/build_release.sh packages a
# windows-x86_64 runtime as well as a linux-x86_64 one — a real x86-64 PE,
# cross-linked here, with its own exact closed SHA-256 manifest — and Windows
# is still absent from the table below, for reasons about the user's machine
# rather than ours:
#   1. no bootstrap exists for it. tools/install/z23_bootstrap.c is POSIX —
#      uname(2), a UDP socket, fork/exec — so nothing here can serve
#      bootstrap/windows-x86_64/z23-bootstrap.exe, because nothing here
#      builds one.
#   2. there is no Windows second stage either: a Windows bootstrap would
#      fetch install_z23.ps1, which does not exist.
#   3. the Windows runtime has never been EXECUTED. This host has no Windows
#      machine and no Wine, so the evidence stops at "links, and imports only
#      Windows system DLLs".
# macOS is absent for a different reason: no Linux host may produce a Mach-O
# (the SDK is not redistributable), so there is no runtime to publish at all.
# Adding a name below is therefore a separate act from making a release, and
# tools/lint/check_published_platforms.sh refuses any name the release cutter
# cannot actually produce a bootstrap for. Refusing a machine we do not
# publish for, by name, beats installing a binary that cannot run on it.
#
# POSIX sh, because the convenience bootstrap ends in `sh` and that is often
# dash: no bashisms, no [[ ]], no `set -o pipefail` (not POSIX). Every
# status-carrying test here is pipeline-free, so none can invert on SIGPIPE.
set -euf
# The claim, and the table that makes it good: PUBLISHED_PLATFORMS is what a
# refusal names, and the BOOT_* digests are what a fetch is checked against.
# check_published_platforms.sh keeps the two in step with each other, with
# install.ps1, and with what the release cutter can actually produce.
PUBLISHED_PLATFORMS=" linux-x86_64 "
BOOT_ZERO=0000000000000000000000000000000000000000000000000000000000000000
BOOT_LINUX_X86_64="$BOOT_ZERO"
ORIGIN="${Z23_INSTALL_TEST_ORIGIN:-https://z23.sh}"
[ -z "${Z23_INSTALL_TEST_BOOT_SHA256:-}" ] || BOOT_LINUX_X86_64="$Z23_INSTALL_TEST_BOOT_SHA256"
die() { printf 'z23-install: REFUSE: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) os="$(uname -s)" ;; esac
case "$(uname -m)" in x86_64|amd64) cpu=x86_64 ;; aarch64|arm64) cpu=aarch64 ;; *) cpu="$(uname -m)" ;; esac
PLATFORM="$os-$cpu"
case "$PLATFORM" in
    linux-x86_64) WANT="$BOOT_LINUX_X86_64" ;;
    *) die "no Z23 bootstrap is published for $PLATFORM; published:${PUBLISHED_PLATFORMS% }" ;;
esac
[ "$WANT" != "$BOOT_ZERO" ] || die "no Z23 bootstrap is pinned into this script yet — nothing was downloaded"
have curl || die "curl is required to fetch the Z23 bootstrap"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/z23-install.XXXXXX")" || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
curl --connect-timeout 10 --max-time 120 --max-filesize 33554432 -fsSL \
    "$ORIGIN/bootstrap/$PLATFORM/z23-bootstrap" -o "$WORK/z23-bootstrap" \
    || die "could not fetch $ORIGIN/bootstrap/$PLATFORM/z23-bootstrap"
if have sha256sum; then GOT="$(sha256sum "$WORK/z23-bootstrap" | cut -d' ' -f1)"
elif have shasum; then GOT="$(shasum -a 256 "$WORK/z23-bootstrap" | cut -d' ' -f1)"
elif have openssl; then GOT="$(openssl dgst -sha256 "$WORK/z23-bootstrap" | sed 's/.*= *//')"
else die "no SHA-256 tool (sha256sum, shasum or openssl) — nothing here could be verified"
fi
[ "$GOT" = "$WANT" ] || die "bootstrap digest mismatch — $ORIGIN served bytes this front door does not name"
chmod 755 "$WORK/z23-bootstrap"
"$WORK/z23-bootstrap" "$@"
