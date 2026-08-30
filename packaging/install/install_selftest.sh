#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_selftest.sh — mutation tests for the install front door.
#
# The front door is now TWO programs, and this harness drives both end to end:
#
#   packaging/install/install.sh   the ~30-line shim served at the domain. It
#                                  names the machine, fetches ONE bootstrap
#                                  binary, checks its SHA-256 against a baked
#                                  digest, and runs it.
#   build/bin/z23-bootstrap        the C23 program that shim fetches, which
#                                  makes every decision the shim used to make:
#                                  the three pin channels, their agreement
#                                  rule, the platform refusal, the installer
#                                  verification and the handoff.
#
# It lives OUT of install.sh on purpose: that script is served at the domain
# and has to stay short enough that a careful person reads it before handing
# it to a shell, so no test code ships in the bytes a stranger reads.
#
# Every verification either program performs is exercised in BOTH directions:
# the agreeing case installs, and each way of breaking agreement refuses
# without the fetched installer ever being executed. Run from
# `tools/scripts/install_z23.sh --selftest`, which the check-z23-release-install
# lint gate already runs.
#
# The pure judgement inside the bootstrap — pin parsing, the agreement rule,
# the platform triple, the DNS TXT wire format — is ALSO proved by the
# z23_front_door test group (lib/test/src/test_z23_front_door.c), which can
# feed it hostile datagrams byte by byte. This file proves the same decisions
# survive a real process, a real fork/exec and a real handoff.
#
# Status-carrying matches use `grep -q PATTERN FILE` (a file argument, not a
# pipeline), so nothing here can invert on SIGPIPE under pipefail. Negative
# matches are written `if grep -q ...; then die; fi` and never `! grep -q ...`,
# because `! cmd` is exempt from `set -e` and an assertion that cannot fail is
# not an assertion.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FRONT_DOOR="$SCRIPT_DIR/install.sh"
BOOTSTRAP="${Z23_BOOTSTRAP_BIN:-$REPO_ROOT/build/bin/z23-bootstrap}"

die() { printf 'install_selftest: FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf 'install_selftest: %s\n' "$*" >&2; }

ROOT=""
cleanup() { [ -z "$ROOT" ] || rm -rf "$ROOT"; }

MANIFEST_SHA=1234567812345678123456781234567812345678123456781234567812345678
OTHER_SHA=fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98
ZERO_SHA="$(printf '0%.0s' {1..64})"

prepare() {
    ROOT="$(mktemp -d "${TMPDIR:-/tmp}/z23-front-door-selftest.XXXXXX")" \
        || die "mktemp failed"
    trap cleanup EXIT
    mkdir -p "$ROOT/http/front" "$ROOT/http/repo" "$ROOT/http/boot" \
        "$ROOT/minbin" "$ROOT/unamebin" "$ROOT/dns" "$ROOT/resolv" "$ROOT/tmp"

    # The real installer is never run here: a stub records the argv it was
    # handed, which is how the handoff (source, manifest digest, and one
    # attestation record per source) is proved.
    cat >"$ROOT/http/front/install_z23.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$Z23_FD_TEST_ARGV_LOG"
STUB
    INSTALLER_SHA="$(sha256sum "$ROOT/http/front/install_z23.sh" | cut -d' ' -f1)"
    GOOD_PIN="z23-pin-v1:$MANIFEST_SHA:$INSTALLER_SHA"
    OTHER_PIN="z23-pin-v1:$OTHER_SHA:$INSTALLER_SHA"
    ZERO_PIN="z23-pin-v1:$ZERO_SHA:$ZERO_SHA"

    printf '#!/bin/sh\ntouch "$Z23_FD_TEST_ARGV_LOG"\n' \
        >"$ROOT/http/front/tampered.sh"

    printf '%s\n' "$GOOD_PIN" >"$ROOT/http/repo/RELEASE_PIN"
    printf '%s\n' "$OTHER_PIN" >"$ROOT/http/repo/RELEASE_PIN.other"
    printf '<html>404</html>\n' >"$ROOT/http/repo/RELEASE_PIN.html"
    printf '%s\n' "$ZERO_PIN" >"$ROOT/http/repo/RELEASE_PIN.unset"
    printf '"%s"\n' "$GOOD_PIN" >"$ROOT/dns/good"
    printf '"%s"\n' "$OTHER_PIN" >"$ROOT/dns/other"
    printf '"this-domain-is-parked"\n' >"$ROOT/dns/portal"
    : >"$ROOT/dns/silent"
    # A container with no resolver configured at all. Nothing is mocked here:
    # the bootstrap reads this file with the same code that reads
    # /etc/resolv.conf and finds no nameserver in it.
    : >"$ROOT/resolv/empty.conf"

    # The bootstrap the shim is supposed to fetch. A stub, because what the
    # shim must prove is the digest gate and the argv forwarding, not what the
    # real bootstrap then decides — that is proved directly, below.
    cat >"$ROOT/http/boot/z23-bootstrap" <<'BOOTSTUB'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$Z23_FD_TEST_ARGV_LOG"
BOOTSTUB
    BOOT_SHA="$(sha256sum "$ROOT/http/boot/z23-bootstrap" | cut -d' ' -f1)"
    # case_cut_shim_installs replaces the served bootstrap with the one a real
    # release cut produced; this is the copy it puts back afterwards, so the
    # cases that follow it see the same fixture the cases before it saw.
    cp -f -- "$ROOT/http/boot/z23-bootstrap" "$ROOT/http/boot/z23-bootstrap.orig"
    printf '#!/usr/bin/env bash\ntouch "$Z23_FD_TEST_ARGV_LOG"\n' \
        >"$ROOT/http/boot/tampered"

    # A deliberately minimal PATH: exactly the commands install.sh may use on
    # a bare machine. Nothing else is reachable, so a missing tool is a real
    # condition here and not a mocked one.
    local tool
    for tool in sh bash uname mktemp rm cp cat sed cut wc chmod sha256sum; do
        ln -sf "$(command -v "$tool")" "$ROOT/minbin/$tool"
    done

    cat >"$ROOT/minbin/curl" <<'MOCKCURL'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 10 ] || exit 2
[ "$1" = --connect-timeout ] && [ "$3" = --max-time ] || exit 2
[ "$5" = --max-filesize ] && [ "$7" = -fsSL ] && [ "$9" = -o ] || exit 2
max_bytes="$6"; url="$8"; dest="${10}"
printf '%s max-bytes=%s\n' "$url" "$max_bytes" >>"$Z23_FD_TEST_CURL_LOG"
case "$url" in
    https://front.invalid/bootstrap/*/z23-bootstrap)
        path="$Z23_FD_TEST_HTTP/boot/${Z23_FD_TEST_BOOTSTRAP:-z23-bootstrap}" ;;
    *) exit 22 ;;
esac
[ -f "$path" ] || exit 22
[ "$(wc -c <"$path")" -le "$max_bytes" ] || exit 63
cp -- "$path" "$dest"
MOCKCURL
    chmod 755 "$ROOT/minbin/curl"

    cat >"$ROOT/unamebin/uname" <<'MOCKUNAME'
#!/usr/bin/env bash
case "${1:-}" in
    -s) echo "${Z23_FD_TEST_UNAME_S:-Linux}" ;;
    -m) echo "${Z23_FD_TEST_UNAME_M:-x86_64}" ;;
    *) echo "${Z23_FD_TEST_UNAME_S:-Linux}" ;;
esac
MOCKUNAME
    chmod 755 "$ROOT/unamebin/uname"

    [ -x "$BOOTSTRAP" ] \
        || die "the C23 bootstrap is missing at $BOOTSTRAP — run \`make z23-bootstrap\`"
}

# ══ Part 1: the shim served at the domain ════════════════════════════════
# run_shim <case> <path-prefix> [env assignments...]
RC=0
run_shim() {
    local name="$1" path_prefix="$2"
    shift 2
    OUT="$ROOT/$name.out"; ERR="$ROOT/$name.err"
    ARGV="$ROOT/$name.argv"; CURL="$ROOT/$name.curl"
    rm -f "$ARGV"
    : >"$CURL"
    RC=0
    env -i PATH="$path_prefix$ROOT/unamebin:$ROOT/minbin" \
        HOME="$ROOT" TMPDIR="$ROOT" \
        Z23_FD_TEST_HTTP="$ROOT/http" \
        Z23_FD_TEST_ARGV_LOG="$ARGV" \
        Z23_FD_TEST_CURL_LOG="$CURL" \
        Z23_INSTALL_TEST_ORIGIN=https://front.invalid \
        "$@" \
        sh "$FRONT_DOOR" --print-pin >"$OUT" 2>"$ERR" || RC=$?
}

# The sentinel is the whole reason this scaffold is safe to serve today: no
# bootstrap is published, so the shim must refuse before it touches a network.
case_shim_sentinel() {
    # Exercise the one currently published platform even when this self-test
    # runs natively on an unpublished Mac. Platform refusal is a separate
    # case below; it must not hide the all-zero sentinel branch here.
    run_shim shim-sentinel "$ROOT/unamebin:" \
        Z23_FD_TEST_UNAME_S=Linux Z23_FD_TEST_UNAME_M=x86_64
    [ "$RC" -eq 1 ] || die "the all-zero bootstrap digest must refuse (rc=$RC)"
    grep -q 'no Z23 bootstrap is pinned into this script yet' "$ERR" \
        || die "the sentinel refusal must say nothing is pinned"
    if [ -s "$CURL" ]; then
        die "the sentinel refusal still made a request"
    fi
    say "PASS the all-zero bootstrap digest refuses before any request"
}

case_shim_platform() {
    run_shim shim-platform "$ROOT/unamebin:" \
        Z23_FD_TEST_UNAME_S=Darwin Z23_FD_TEST_UNAME_M=arm64 \
        Z23_INSTALL_TEST_BOOT_SHA256="$BOOT_SHA"
    [ "$RC" -eq 1 ] || die "an unpublished platform must refuse (rc=$RC)"
    grep -q 'no Z23 bootstrap is published for darwin-aarch64' "$ERR" \
        || die "the refusal must name this machine"
    grep -q 'published: linux-x86_64' "$ERR" \
        || die "the refusal must name what we do publish"
    if [ -s "$CURL" ]; then
        die "an unpublished platform still made a request"
    fi
    say "PASS the shim refuses an unpublished platform by name, before any request"
}

case_shim_digest() {
    run_shim shim-tampered "" \
        Z23_INSTALL_TEST_BOOT_SHA256="$BOOT_SHA" \
        Z23_FD_TEST_BOOTSTRAP=tampered
    [ "$RC" -eq 1 ] || die "a swapped bootstrap must refuse (rc=$RC)"
    grep -q 'bootstrap digest mismatch' "$ERR" \
        || die "a swapped bootstrap must name the digest mismatch"
    [ ! -f "$ARGV" ] || die "a swapped bootstrap was executed anyway"

    run_shim shim-handoff "" Z23_INSTALL_TEST_BOOT_SHA256="$BOOT_SHA"
    [ "$RC" -eq 0 ] || die "a matching bootstrap must run (rc=$RC): $(cat "$ERR")"
    [ -f "$ARGV" ] || die "a matching bootstrap never ran"
    grep -qx -- '--print-pin' "$ARGV" \
        || die "the shim must forward its argv to the bootstrap"
    grep -q 'z23-bootstrap max-bytes=33554432' "$CURL" \
        || die "the bootstrap fetch was not bounded"
    say "PASS the fetched bootstrap is digest-verified before it runs, and gets our argv"
}

# ── The release cut and the shim have to agree about the digest ───────────
# Every case above hands the shim its digest through
# Z23_INSTALL_TEST_BOOT_SHA256, which proves the comparison but says nothing
# about where a real digest comes from. It comes from
# `build_release.sh --front-door`, which packages the bootstrap and stamps its
# SHA-256 into a COPY of this shim. If the stamp and the packaged bytes ever
# disagreed, every install would refuse with "digest mismatch" and the pair
# would still each look correct on their own. So run the real cut and then run
# the shim it produced, with no override at all.
case_cut_shim_installs() {
    local cut="$ROOT/cut" cutbin="$ROOT/cutbin" saved="$FRONT_DOOR" truebin=""
    mkdir -p "$cutbin"
    # A real ELF, because the only currently published front-door bootstrap is
    # linux-x86_64 and the cutter correctly refuses to relabel a native Mach-O
    # as ELF. true(1) also ignores argv and exits 0, which is all the handoff
    # needs here; argv forwarding is proved by case_shim_digest above.
    # `command -v true` is the SHELL BUILTIN and is not a path, so the real
    # file is looked for by name.
    local candidate
    for candidate in /usr/bin/true /bin/true; do
        [ -x "$candidate" ] && { truebin="$candidate"; break; }
    done
    [ -n "$truebin" ] || die "no true(1) binary to stand in for a bootstrap"
    case "$(file -b "$truebin" 2>/dev/null)" in
        *ELF*) ;;
        *)
            say "UNOBSERVED Linux front-door cut: host true(1) is not ELF"
            return 0 ;;
    esac
    cp -f -- "$truebin" "$cutbin/z23-bootstrap"
    chmod 755 "$cutbin/z23-bootstrap"
    bash "$REPO_ROOT/packaging/release/build_release.sh" --front-door \
        --bin "$cutbin" --out "$cut" >/dev/null 2>"$ROOT/cut.err" \
        || die "the front-door cut refused a complete input: $(cat "$ROOT/cut.err")"

    if grep -q '^BOOT_LINUX_X86_64="\$BOOT_ZERO"$' "$cut/install.sh"; then
        die "the cut shim still carries the sentinel"
    fi
    cp -f -- "$cut/bootstrap/linux-x86_64/z23-bootstrap" "$ROOT/http/boot/z23-bootstrap"

    FRONT_DOOR="$cut/install.sh"
    run_shim cut-handoff ""
    [ "$RC" -eq 0 ] \
        || die "the cut shim refused the bytes the same cut packaged (rc=$RC): $(cat "$ERR")"

    # ...and the stamp is a real check, not a formality: one changed byte in
    # the served bootstrap and the same cut shim refuses.
    cp -f -- "$ROOT/http/boot/tampered" "$ROOT/http/boot/z23-bootstrap"
    run_shim cut-tampered ""
    [ "$RC" -eq 1 ] || die "the cut shim accepted bytes it did not name (rc=$RC)"
    grep -q 'bootstrap digest mismatch' "$ERR" \
        || die "the cut shim must name the digest mismatch"

    FRONT_DOOR="$saved"
    cp -f -- "$ROOT/http/boot/z23-bootstrap.orig" "$ROOT/http/boot/z23-bootstrap"
    say "PASS a real release cut stamps a digest the shim then accepts, and only that one"
}

# ══ Part 2: the C23 bootstrap, end to end ════════════════════════════════
# run_boot <case> [env assignments...] — a real process, real files, a real
# fork/exec of the verified installer.
run_boot() {
    local name="$1"
    shift
    OUT="$ROOT/$name.out"; ERR="$ROOT/$name.err"; ARGV="$ROOT/$name.argv"
    rm -f "$ARGV"
    rm -rf "$ROOT/tmp/$name"
    mkdir -p "$ROOT/tmp/$name"
    BOOTTMP="$ROOT/tmp/$name"
    RC=0
    env -i PATH="$ROOT/minbin" HOME="$ROOT" TMPDIR="$BOOTTMP" \
        Z23_FD_TEST_ARGV_LOG="$ARGV" \
        Z23_INSTALL_TEST_ORIGIN="file://$ROOT/http/front" \
        Z23_INSTALL_TEST_PIN_REPO_URL="file://$ROOT/http/repo/RELEASE_PIN" \
        Z23_INSTALL_TEST_RESOLV_CONF="$ROOT/resolv/empty.conf" \
        Z23_INSTALL_TEST_UNAME_S=Linux \
        Z23_INSTALL_TEST_UNAME_M=x86_64 \
        "$@" \
        "$BOOTSTRAP" >"$OUT" 2>"$ERR" || RC=$?
}

# ── Direction 1: everything agrees, and the handoff carries the evidence ──
case_boot_all_agree() {
    run_boot boot-all-agree \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good"
    [ "$RC" -eq 0 ] || die "three agreeing sources must install (rc=$RC): $(cat "$ERR")"
    [ -f "$ARGV" ] || die "three agreeing sources never reached the installer"
    grep -qx -- "--manifest-sha256=$MANIFEST_SHA" "$ARGV" \
        || die "the agreed manifest digest was not handed to the installer"
    grep -qx -- "--source=file://$ROOT/http/front/release/linux-x86_64" "$ARGV" \
        || die "the release source was not handed to the installer"
    local origin
    for origin in baked dns repo; do
        grep -qx -- "--attest=$origin=$GOOD_PIN" "$ARGV" \
            || die "attestation for $origin was not passed through"
    done
    if grep -q 'agreed by' "$ERR"; then
        die "a full quorum must not announce a degraded one"
    fi
    say "PASS all three sources agree -> installs, evidence passed through"
}

case_boot_print_pin() {
    # --print-pin is forwarded through the shim, so the bootstrap owns it.
    BOOTTMP="$ROOT/tmp/boot-print-pin"
    mkdir -p "$BOOTTMP"
    RC=0
    env -i PATH="$ROOT/minbin" HOME="$ROOT" TMPDIR="$BOOTTMP" \
        Z23_INSTALL_TEST_ORIGIN="file://$ROOT/http/front" \
        Z23_INSTALL_TEST_PIN_REPO_URL="file://$ROOT/http/repo/RELEASE_PIN" \
        Z23_INSTALL_TEST_RESOLV_CONF="$ROOT/resolv/empty.conf" \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good" \
        "$BOOTSTRAP" --print-pin >"$ROOT/printpin.out" 2>"$ROOT/printpin.err" || RC=$?
    [ "$RC" -eq 0 ] || die "--print-pin must resolve the channels (rc=$RC)"
    grep -qx -- "$GOOD_PIN" "$ROOT/printpin.out" \
        || die "--print-pin must print the agreed pin and nothing else"

    RC=0
    env -i PATH="$ROOT/minbin" HOME="$ROOT" TMPDIR="$BOOTTMP" \
        "$BOOTSTRAP" --wat >"$ROOT/badarg.out" 2>"$ROOT/badarg.err" || RC=$?
    [ "$RC" -eq 1 ] || die "an unknown argument must refuse (rc=$RC)"
    grep -q 'unknown argument: --wat' "$ROOT/badarg.err" \
        || die "an unknown argument must be named"
    say "PASS --print-pin resolves the channels and installs nothing"
}

# ── Direction 2: one source disagrees. Never a majority vote. ─────────────
case_boot_disagreement() {
    run_boot boot-dns-split \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/other"
    [ "$RC" -eq 1 ] || die "a disagreeing DNS record must refuse (rc=$RC)"
    grep -q 'release pin disagreement between baked and dns' "$ERR" \
        || die "the disagreement must name both origins"
    grep -q "attested pin baked=$GOOD_PIN" "$ERR" \
        || die "the disagreement must print the pin each origin attested"
    grep -q "attested pin dns=$OTHER_PIN" "$ERR" \
        || die "the disagreement must print the dissenting pin"
    [ ! -f "$ARGV" ] || die "a disagreement still ran the installer"

    run_boot boot-repo-split \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good" \
        Z23_INSTALL_TEST_PIN_REPO_URL="file://$ROOT/http/repo/RELEASE_PIN.other"
    [ "$RC" -eq 1 ] || die "a disagreeing repository pin must refuse (rc=$RC)"
    grep -q 'release pin disagreement between baked and repo' "$ERR" \
        || die "the repository disagreement must name both origins"
    [ ! -f "$ARGV" ] || die "a repository disagreement still ran the installer"
    say "PASS one dissenting source -> refuses, 2-against-1 never wins"
}

# ── Unreachable is not disagreement, and two is the floor ─────────────────
case_boot_unreachable() {
    # No resolver configured at all. Baked + repository still carry a quorum,
    # and the refusal-free path says out loud what was missing.
    run_boot boot-no-resolver Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN"
    [ "$RC" -eq 0 ] || die "two agreeing sources must install (rc=$RC): $(cat "$ERR")"
    grep -q 'agreed by 2 of 3 sources (unreachable: dns=no-resolver)' "$ERR" \
        || die "a degraded quorum must be announced"
    grep -qx -- '--attest-unreachable=dns=no-resolver' "$ARGV" \
        || die "the unreachable source must be declared to the installer"

    # A resolver that answers with nothing at all.
    run_boot boot-dns-silent \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/silent"
    [ "$RC" -eq 0 ] || die "an empty DNS answer must not break a real quorum"
    grep -q 'unreachable: dns=no-answer' "$ERR" \
        || die "an empty TXT answer must be reported as no-answer"

    # A captive portal answers with something that is not a pin. That is
    # unreachable, NOT a disagreement.
    run_boot boot-portal \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/portal"
    [ "$RC" -eq 0 ] || die "a portal TXT answer must not break a real quorum"
    grep -q 'unreachable: dns=malformed-answer' "$ERR" \
        || die "a non-pin TXT answer must be reported as malformed"
    if grep -q 'disagreement' "$ERR"; then
        die "a non-pin TXT answer was reported as a disagreement"
    fi

    # An HTML error page from the repository host is the same class.
    run_boot boot-repo-html \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_PIN_REPO_URL="file://$ROOT/http/repo/RELEASE_PIN.html"
    [ "$RC" -eq 1 ] || die "baked alone must not install (rc=$RC)"
    grep -q 'release pin quorum: 1 of 3 sources answered' "$ERR" \
        || die "a single answering source must be refused by count"
    grep -q 'repo=malformed-answer' "$ERR" \
        || die "an HTML answer must be reported as malformed"

    # Nothing reachable but the baked value: still a refusal, never a silent
    # degradation to one source.
    run_boot boot-alone \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_PIN_REPO_URL="file://$ROOT/http/repo/MISSING"
    [ "$RC" -eq 1 ] || die "one source must never be enough (rc=$RC)"
    grep -q 'two independent sources are required' "$ERR" \
        || die "the quorum refusal must state the requirement"
    grep -q 'repo=fetch-failed' "$ERR" \
        || die "an unreachable repository must be named with its reason"
    [ ! -f "$ARGV" ] || die "a failed quorum still ran the installer"

    # No release pinned into the bootstrap at all: the sentinel is a missing
    # source, not a pin, and DNS + repository carry the quorum without it.
    run_boot boot-unpinned \
        Z23_INSTALL_TEST_BAKED_PIN="$ZERO_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good"
    [ "$RC" -eq 0 ] || die "dns+repo must carry a quorum without a baked pin"
    grep -q 'unreachable: baked=no-release-pinned' "$ERR" \
        || die "an unpinned bootstrap must say so"

    # Before the first release is cut, the repository file carries the unset
    # sentinel. That is "nothing is pinned here", not a dissenting pin.
    run_boot boot-repo-unset \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good" \
        Z23_INSTALL_TEST_PIN_REPO_URL="file://$ROOT/http/repo/RELEASE_PIN.unset"
    [ "$RC" -eq 0 ] || die "an unset repository pin must not break a real quorum"
    grep -q 'unreachable: repo=malformed-answer' "$ERR" \
        || die "the unset sentinel must be reported as no pin"
    if grep -q 'disagreement' "$ERR"; then
        die "the unset sentinel was reported as a disagreement"
    fi

    # The checked-in repository pin must always be a well-formed pin record,
    # sentinel or real, or source 3 is dead the moment a release lands.
    grep -qxE 'z23-pin-v1:[0-9a-f]{64}:[0-9a-f]{64}' "$SCRIPT_DIR/RELEASE_PIN" \
        || die "packaging/install/RELEASE_PIN is not a z23-pin-v1 record"
    say "PASS unreachable is counted, named, and never called disagreement"
}

# ── The installer's own bytes are pinned too ──────────────────────────────
case_boot_installer_digest() {
    run_boot boot-tampered \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good" \
        Z23_INSTALL_TEST_ORIGIN="file://$ROOT/http/front-tampered"
    [ "$RC" -eq 1 ] || die "an unfetchable installer must refuse (rc=$RC)"
    grep -q 'could not fetch' "$ERR" \
        || die "an unfetchable installer must say so"

    mkdir -p "$ROOT/http/swap"
    cp "$ROOT/http/front/tampered.sh" "$ROOT/http/swap/install_z23.sh"
    run_boot boot-swapped \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good" \
        Z23_INSTALL_TEST_ORIGIN="file://$ROOT/http/swap"
    [ "$RC" -eq 1 ] || die "a swapped installer must refuse (rc=$RC)"
    grep -q 'installer digest mismatch' "$ERR" \
        || die "a swapped installer must name the digest mismatch"
    [ ! -f "$ARGV" ] || die "a swapped installer was executed anyway"
    say "PASS the served installer is verified before it runs"
}

# ── A machine we publish no runtime for is told so, by name ───────────────
case_boot_platform() {
    run_boot boot-unpublished \
        Z23_INSTALL_TEST_BAKED_PIN="$GOOD_PIN" \
        Z23_INSTALL_TEST_DNS="$ROOT/dns/good" \
        Z23_INSTALL_TEST_UNAME_S=Darwin \
        Z23_INSTALL_TEST_UNAME_M=arm64
    [ "$RC" -eq 1 ] || die "an unpublished platform must refuse (rc=$RC)"
    grep -q 'no Z23 runtime is published for darwin-aarch64' "$ERR" \
        || die "the refusal must name this machine"
    grep -q 'published: linux-x86_64' "$ERR" \
        || die "the refusal must name what we do publish"
    # Nothing was consulted and nothing was created: the scratch directory is
    # made only after this refusal can no longer happen, so an empty TMPDIR is
    # proof that no channel was read and no byte was written.
    if grep -q 'release pin' "$ERR"; then
        die "an unpublished platform still consulted the pin channels"
    fi
    [ -z "$(ls -A "$BOOTTMP")" ] \
        || die "an unpublished platform still created scratch state"
    say "PASS an unpublished platform is refused by name, before any request"
}

prepare
case_shim_sentinel
case_shim_platform
case_shim_digest
case_cut_shim_installs
case_boot_all_agree
case_boot_print_pin
case_boot_disagreement
case_boot_unreachable
case_boot_installer_digest
case_boot_platform
say "front door selftest PASS"
