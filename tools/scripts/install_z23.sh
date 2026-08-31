#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# install_z23.sh — fetch a packaged Z23 runtime set, verify SHA256SUMS
# fail-closed, install to ~/.local, install the native user service, and print
# ONE next command. Linux uses systemd --user. macOS uses launchd with
# immutable release generations and automatic rollback on failed readiness.
#
# Artifact source is taken from the first argument or Z23_RELEASE_SOURCE
# (a node URL or a local directory). Never hardcoded: any node that serves
# z23, zclassic23, zclassic23-package-verify, zclassic23-acme, and
# SHA256SUMS is a valid source. There is no registry.
#
# Checksum mismatch is a loud refusal. Nothing is copied to the destination
# until SHA256SUMS --strict passes.
#
# The expected SHA256SUMS digest may instead be learned from three
# independent systems (see "Release pin" below): pass one --attest= or
# --attest-unreachable= record per source and this script decides.
#
# Usage:
#   install_z23.sh --source=<url> --manifest-sha256=<sha256-of-SHA256SUMS>
#   install_z23.sh --source=<url> --attest=baked=<pin> --attest=dns=<pin> \
#                  --attest-unreachable=repo=<reason>
#   install_z23.sh --source=<local-dir>
#   install_z23.sh <url> --manifest-sha256=<sha256-of-SHA256SUMS>
#   install_z23.sh <local-dir>
#   Z23_RELEASE_SOURCE=<url> Z23_RELEASE_MANIFEST_SHA256=<sha256> install_z23.sh
#   Z23_RELEASE_SOURCE=<local-dir> install_z23.sh
#   install_z23.sh --selftest
#
# Env:
#   Z23_RELEASE_MANIFEST_SHA256
#                        expected SHA-256 of a remote SHA256SUMS (required
#                        for http(s); obtain independently of the mirror)
#   Z23_INSTALL_PREFIX   default $HOME/.local
#   Z23_UNIT_DIR         default $HOME/.config/systemd/user
#   Z23_LAUNCHD_DIR      default $HOME/Library/LaunchAgents
#   Z23_DATADIR          default $HOME/.zclassic-c23
#   Z23_SKIP_SYSTEMD=1   skip all service installation (tests/archives)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { printf 'install_z23: REFUSE: %s\n' "$*" >&2; exit 1; }
say() { printf 'install_z23: %s\n' "$*" >&2; }

NEXT_COMMAND="z23 status"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "no SHA-256 tool (sha256sum or shasum) is available"
    fi
}

sha256_check_manifest() {
    local manifest="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$(dirname "$manifest")" && sha256sum -c --strict "$(basename "$manifest")")
    elif command -v shasum >/dev/null 2>&1; then
        # validate_manifest_contract already proves the exact strict grammar
        # and closed member set before this is reached. Stock macOS shasum
        # has no GNU --strict switch, so it only has to check the bytes here.
        (cd "$(dirname "$manifest")" && shasum -a 256 -c "$(basename "$manifest")")
    else
        die "no SHA-256 tool (sha256sum or shasum) is available"
    fi
}

# Public fetch ceilings. The manifest has exactly five short checksum rows;
# 1 KiB leaves ample format headroom. Node aliases are currently below 32 MiB,
# the confined verifier below 96 MiB, and the certificate worker (a small
# static-ish TLS client, currently ~5 MB) below 32 MiB; these limits allow
# growth without permitting an untrusted mirror to stream without bound.
# Deadlines apply to every HTTP transaction independently.
REMOTE_MANIFEST_MAX_BYTES=1024
REMOTE_NODE_MAX_BYTES=$((64 * 1024 * 1024))
REMOTE_VERIFIER_MAX_BYTES=$((128 * 1024 * 1024))
REMOTE_ACME_MAX_BYTES=$((32 * 1024 * 1024))
REMOTE_CONNECT_TIMEOUT_SECONDS=10
REMOTE_MANIFEST_MAX_TIME_SECONDS=30
REMOTE_PAYLOAD_MAX_TIME_SECONDS=300
CURL_MINIMUM_VERSION="8.4.0"

# ── Release pin: three independent sources, or no install ──────────────────
# A mirror is never the authority for its own checksum manifest. The expected
# digest of SHA256SUMS is learned from three INDEPENDENT systems — a value
# baked into the front-door script, a DNS TXT record on the domain, and the
# source repository — and reaches this script as attestation records:
#
#   --attest=<origin>=z23-pin-v1:<manifest-sha256>:<installer-sha256>
#   --attest-unreachable=<origin>=<reason>
#
# The GATHERER is the C23 front door (tools/install/z23_bootstrap.c over
# lib/install), which packaging/install/install.sh fetches and digest-checks
# before running. It classifies each source as answered-with-a-pin or
# unreachable-for-<reason>. This script is the JUDGE. Judging here as well as
# in the front door is deliberate duplication, not an oversight: this file is
# fetched and run ALONE, so it cannot link lib/install, and it must be able to
# refuse on its own evidence rather than on the gatherer's word.
#
# POLICY, stated plainly so it can be argued with:
#   * ANY two answered pins that differ -> REFUSE. We never majority-vote.
#     A disagreement means a rollback, a half-finished publish, or a
#     compromise; installing the "winner" would hide exactly the event this
#     mechanism exists to surface.
#   * FEWER THAN TWO answered pins -> REFUSE. One source is not corroboration,
#     and quietly degrading to it hands back the whole property being bought.
#   * EXACTLY TWO answered and agreeing -> PROCEED, and say on stderr which
#     source was unreachable and why. Two independent systems still means
#     taking over the web server alone does not change what a stranger
#     installs. Demanding all three would give a veto to any corporate
#     resolver that drops TXT or any network that blocks the repository host,
#     and an installer that fails for honest strangers is not safer — it just
#     pushes them onto a worse install path.
#   * UNREACHABLE IS NOT DISAGREEMENT, and is never reported as one. A source
#     that answers with something that is not a pin at all (a captive portal,
#     an HTML error page) is recorded by the gatherer as unreachable with a
#     reason. It cannot lower the quorum bar, and calling it a disagreement
#     would teach people to click past the loudest refusal we have.
ATTEST_ORIGINS_KNOWN=" baked dns repo "
ATTEST_PIN_UNSET=0000000000000000000000000000000000000000000000000000000000000000
ATTEST_SEEN=" "
ATTEST_OK=""
ATTEST_OK_COUNT=0
ATTEST_DOWN=""
ATTESTED_MANIFEST_SHA256=""

# The one 64-lowercase-hex validator in this file; every hex check goes
# through it (the pin halves above, and the --manifest-sha256 argument in
# fetch_into below).
# zcl-identity-parser-allow: this script ships ALONE — the C23 front door
# fetches just this file into a mktemp dir and runs it there, so there is no
# tools/scripts/source_identity_lib.sh beside it to source, and a second
# shipped file would break the two-digest z23-pin-v1 release pin.
attest_is_sha256() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

# z23-pin-v1:<64 hex>:<64 hex> — no spaces, so a pin is one argv element and
# one DNS TXT string, and needs no quoting anywhere in this pipeline.
attest_valid_pin() {
    local rest manifest installer
    # The unset sentinel is a declaration that nothing is pinned, not a pin.
    # A gatherer must report it as an unreachable source, never attest it.
    case "$1" in
        "z23-pin-v1:$ATTEST_PIN_UNSET:$ATTEST_PIN_UNSET") return 1 ;;
    esac
    rest="${1#z23-pin-v1:}"
    [ "$rest" != "$1" ] || return 1
    manifest="${rest%%:*}"
    [ "$manifest" != "$rest" ] || return 1
    installer="${rest#*:}"
    case "$installer" in *:*) return 1 ;; esac
    # Both pins are exactly 64 lowercase hex chars. Checked inline rather than
    # through a shared helper: this script is fetched and run standalone, so
    # it cannot source tools/scripts/source_identity_lib.sh (zcl_is_sha256).
    [ "${#manifest}" -eq 64 ] && [ "${#installer}" -eq 64 ] || return 1
    case "$manifest" in *[!0-9a-f]*) return 1 ;; esac
    case "$installer" in *[!0-9a-f]*) return 1 ;; esac
    return 0
}

attest_claim_origin() {
    case "$ATTEST_ORIGINS_KNOWN" in
        *" $1 "*) ;;
        *) die "unknown attestation origin: $1" ;;
    esac
    case "$ATTEST_SEEN" in
        *" $1 "*) die "attestation origin named twice: $1" ;;
    esac
    ATTEST_SEEN="$ATTEST_SEEN$1 "
}

attest_record() {
    attest_claim_origin "$1"
    attest_valid_pin "$2" \
        || die "attestation from $1 is not a z23-pin-v1:<sha256>:<sha256> record"
    ATTEST_OK="$ATTEST_OK$1 $2"$'\n'
    ATTEST_OK_COUNT=$((ATTEST_OK_COUNT + 1))
}

attest_record_unreachable() {
    attest_claim_origin "$1"
    # The reason is text from a source we do not trust; keep it to a token so
    # it cannot dress itself up as another line of our own output.
    case "$2" in
        ''|*[!a-z0-9-]*) die "unreachable reason for $1 must be lowercase-dash text" ;;
    esac
    ATTEST_DOWN="$ATTEST_DOWN$1 $2"$'\n'
}

# Sets ATTESTED_MANIFEST_SHA256, or dies. Deliberately not a subshell that
# echoes a value: die() inside $(...) would exit only the subshell and leave
# the caller carrying an empty digest.
attest_resolve_manifest() {
    local origin pin reason first_origin="" first_pin="" unreachable="" rest
    while read -r origin reason; do
        [ -n "$origin" ] || continue
        unreachable="$unreachable${unreachable:+, }$origin=$reason"
    done <<<"$ATTEST_DOWN"
    while read -r origin pin; do
        [ -n "$origin" ] || continue
        if [ -z "$first_pin" ]; then
            first_origin="$origin"
            first_pin="$pin"
            continue
        fi
        [ "$pin" = "$first_pin" ] && continue
        say "attested pin $first_origin=$first_pin"
        say "attested pin $origin=$pin"
        die "release pin disagreement between $first_origin and $origin — refusing to install either"
    done <<<"$ATTEST_OK"
    if [ "$ATTEST_OK_COUNT" -lt 2 ]; then
        die "release pin quorum: $ATTEST_OK_COUNT of 3 sources answered, two independent sources are required (unreachable: ${unreachable:-none})"
    fi
    [ "$ATTEST_OK_COUNT" -ge 3 ] \
        || say "release pin agreed by $ATTEST_OK_COUNT of 3 sources (unreachable: ${unreachable:-none})"
    rest="${first_pin#z23-pin-v1:}"
    ATTESTED_MANIFEST_SHA256="${rest%%:*}"
}

INSTALL_STAGE=""
INSTALL_STAGE_PARENT=""

cleanup_install_stage() {
    if [ -n "${MACOS_INCOMING:-}" ]; then
        case "$MACOS_INCOMING" in
            "${MACOS_GENERATIONS:-/invalid}"/.incoming.??????)
                chmod u+w "$MACOS_INCOMING" 2>/dev/null || true
                find "$MACOS_INCOMING" -xdev -depth -delete
                ;;
            *)
                printf 'install_z23: REFUSE: internal macOS generation cleanup path escaped its parent\n' >&2
                return 1
                ;;
        esac
        MACOS_INCOMING=""
    fi
    [ -n "$INSTALL_STAGE" ] || return 0
    case "$INSTALL_STAGE" in
        "$INSTALL_STAGE_PARENT"/zcl-install-z23.??????) ;;
        *)
            printf 'install_z23: REFUSE: internal cleanup path escaped the install staging directory\n' >&2
            return 1
            ;;
    esac
    [ ! -e "$INSTALL_STAGE" ] \
        || find "$INSTALL_STAGE" -xdev -depth -delete
    INSTALL_STAGE=""
}

# The release is an EXACT CLOSED SET of five names. AGENT_CARD.md is in it
# and is not "just documentation": its whole job is to tell a coding agent
# which commands to run, so a tampered card is instruction injection into
# whatever assistant installs the node. zclassic23-acme is in it because a
# node that can obtain a certificate but never installs the one binary that
# can renew it is a node that goes dark the day the certificate expires —
# see write_cert_renew_units below. A release that claims everything is
# verified does not get to ship one unverified file. The set stays exact —
# never a wildcard — because "any file the manifest names" is how an
# attacker adds a sixth.
RELEASE_MEMBERS="AGENT_CARD.md z23 zclassic23 zclassic23-package-verify zclassic23-acme"
REMOTE_CARD_MAX_BYTES=$((64 * 1024))

payload_max_bytes() {
    case "$1" in
        z23|zclassic23) printf '%s\n' "$REMOTE_NODE_MAX_BYTES" ;;
        zclassic23-package-verify) printf '%s\n' "$REMOTE_VERIFIER_MAX_BYTES" ;;
        zclassic23-acme) printf '%s\n' "$REMOTE_ACME_MAX_BYTES" ;;
        AGENT_CARD.md) printf '%s\n' "$REMOTE_CARD_MAX_BYTES" ;;
        *) return 1 ;;
    esac
}

validate_manifest_contract() {
    local manifest="$1" bytes lines matching names z23_digest alias_digest
    [ -f "$manifest" ] || die "SHA256SUMS missing after fetch"
    bytes="$(wc -c <"$manifest" | tr -d ' ')"
    [ "$bytes" -le "$REMOTE_MANIFEST_MAX_BYTES" ] \
        || die "SHA256SUMS exceeds $REMOTE_MANIFEST_MAX_BYTES bytes"
    lines="$(wc -l <"$manifest" | tr -d ' ')"
    matching="$(LC_ALL=C grep -Ec \
        '^[0-9a-f]{64}  (AGENT_CARD\.md|z23|zclassic23|zclassic23-package-verify|zclassic23-acme)$' \
        "$manifest" || true)"
    [ "$lines" -eq 5 ] && [ "$matching" -eq 5 ] \
        || die "SHA256SUMS must contain exactly five strict lowercase SHA-256 rows"
    names="$(awk '{print $2}' "$manifest" | LC_ALL=C sort)"
    [ "$names" = $'AGENT_CARD.md\nz23\nzclassic23\nzclassic23-acme\nzclassic23-package-verify' ] \
        || die "SHA256SUMS must name each required release member exactly once"
    # z23 and zclassic23 are one program under two names, and the release
    # says so with one digest in two rows. If they ever differ this is not a
    # release we understand: refuse rather than guess which name is the node.
    z23_digest="$(manifest_digest_of "$(dirname "$manifest")" z23)"
    alias_digest="$(manifest_digest_of "$(dirname "$manifest")" zclassic23)"
    [ "$z23_digest" = "$alias_digest" ] \
        || die "SHA256SUMS gives z23 and zclassic23 different digests — refusing to guess which one is the node"
}

validate_payload_sizes() {
    local dir="$1" name bytes maximum
    for name in $RELEASE_MEMBERS; do
        [ -f "$dir/$name" ] || die "verified payload missing $name"
        maximum="$(payload_max_bytes "$name")"
        bytes="$(wc -c <"$dir/$name" | tr -d ' ')"
        [ "$bytes" -le "$maximum" ] \
            || die "$name exceeds its $maximum-byte release ceiling"
    done
}

manifest_digest_of() {
    awk -v want="$2" '$2 == want { print $1; exit }' "$1/SHA256SUMS"
}

# ── The duplicate third of the download ────────────────────────────────────
# z23 and zclassic23 are one program under two names: build_release.sh emits
# the same bytes twice (measured 2026-08-29: 27.8 MB each of a 79.9 MB set),
# and validate_manifest_contract has already REFUSED any release where the
# two rows disagree. A hard link in the release directory does not help the
# stranger — a file server streams the full body per URL however the origin
# stores it — so the second GET is skipped here instead, and the alias is
# materialised locally from the bytes just verified.
#
# Nothing is verified less. The digest demanded of zclassic23 is the digest
# that was checked against actually-transferred bytes for z23, SHA256SUMS
# keeps both rows, and `sha256sum -c --strict` below still hashes every name
# present on disk — including this one, through the link.
materialize_alias() {
    local dir="$1" name="$2" source_name="$3"
    [ -f "$dir/$source_name" ] \
        || die "release members are out of order: $name precedes $source_name"
    ln -f -- "$dir/$source_name" "$dir/$name" 2>/dev/null \
        || cp -f -- "$dir/$source_name" "$dir/$name" \
        || die "could not materialize $name from the identical $source_name"
}

curl_bounded() {
    local url="$1" dest="$2" maximum_bytes="$3" maximum_seconds="$4"
    curl --connect-timeout "$REMOTE_CONNECT_TIMEOUT_SECONDS" \
        --max-time "$maximum_seconds" --max-filesize "$maximum_bytes" \
        -fsSL "$url" -o "$dest"
}

require_bounded_curl() {
    local first version major minor
    first="$(curl --version 2>/dev/null | sed -n '1p')" \
        || die "curl $CURL_MINIMUM_VERSION or newer is required for bounded remote fetches"
    version="${first#curl }"
    [ "$version" != "$first" ] || die "could not parse curl version; $CURL_MINIMUM_VERSION or newer is required"
    version="${version%% *}"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || die "could not parse curl version '$version'; $CURL_MINIMUM_VERSION or newer is required"
    IFS=. read -r major minor _ <<<"$version"
    if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -lt 4 ]; }; then
        die "curl $version is too old; $CURL_MINIMUM_VERSION or newer is required for bounded remote fetches"
    fi
}

fetch_into() {
    local src="$1" dest="$2" expected_manifest_sha256="$3"
    mkdir -p "$dest"
    case "$src" in
        http://*|https://*)
            # Same 64-lowercase-hex rule as the release pin, so there is one
            # validator in this file and not two that can drift apart.
            attest_is_sha256 "$expected_manifest_sha256" \
                || die "remote source requires --manifest-sha256=<64 lowercase hex>, obtained independently of the mirror"
            command -v curl >/dev/null 2>&1 || die "curl is required to fetch $src"
            require_bounded_curl
            curl_bounded "$src/SHA256SUMS" "$dest/SHA256SUMS" \
                "$REMOTE_MANIFEST_MAX_BYTES" \
                "$REMOTE_MANIFEST_MAX_TIME_SECONDS" \
                || die "could not fetch $src/SHA256SUMS"
            [ -s "$dest/SHA256SUMS" ] || die "empty SHA256SUMS from $src"
            local got_manifest_sha256 name
            got_manifest_sha256="$(sha256_file "$dest/SHA256SUMS")"
            [ "$got_manifest_sha256" = "$expected_manifest_sha256" ] \
                || die "remote SHA256SUMS digest mismatch — refusing to fetch payloads"
            validate_manifest_contract "$dest/SHA256SUMS"

            while read -r _ name; do
                if [ "$name" = zclassic23 ]; then
                    materialize_alias "$dest" zclassic23 z23
                    continue
                fi
                curl_bounded "$src/$name" "$dest/$name" \
                    "$(payload_max_bytes "$name")" \
                    "$REMOTE_PAYLOAD_MAX_TIME_SECONDS" \
                    || die "could not fetch $src/$name"
            done <"$dest/SHA256SUMS"
            ;;
        *)
            [ -d "$src" ] || die "source is not a directory or http(s) URL: $src"
            [ -f "$src/SHA256SUMS" ] || die "SHA256SUMS missing in $src"
            cp -f -- "$src/SHA256SUMS" "$dest/SHA256SUMS"
            validate_manifest_contract "$dest/SHA256SUMS"
            # An independently obtained digest binds a local directory too:
            # a staging tree on disk is no more authoritative about itself
            # than a mirror is. Only checked when one was supplied, so the
            # ssh bootstrap path (which transfers and re-verifies bytes it
            # produced) is unaffected.
            if [ -n "$expected_manifest_sha256" ]; then
                local got_local_sha256
                got_local_sha256="$(sha256_file "$dest/SHA256SUMS")"
                [ "$got_local_sha256" = "$expected_manifest_sha256" ] \
                    || die "SHA256SUMS digest mismatch in $src — refusing to install"
            fi
            local name
            while read -r _ name; do
                if [ "$name" = zclassic23 ]; then
                    materialize_alias "$dest" zclassic23 z23
                    continue
                fi
                [ -f "$src/$name" ] || die "listed file missing: $src/$name"
                cp -f -- "$src/$name" "$dest/$name"
            done <"$dest/SHA256SUMS"
            ;;
    esac
}

verify_strict() {
    local dir="$1"
    validate_payload_sizes "$dir"
    sha256_check_manifest "$dir/SHA256SUMS" >/dev/null \
        || die "SHA256SUMS mismatch — refusing to install"
}

atomic_relative_link() {
    local target="$1" link="$2" tmp="$2.new.$$"
    rm -f -- "$tmp"
    ln -s "$target" "$tmp" || return 1
    # GNU mv follows a destination symlink to a directory unless -T is used;
    # BSD/macOS mv spells the same no-follow contract -h. Try both native
    # dialects so `current` is replaced, never treated as a destination dir.
    if mv -fT -- "$tmp" "$link" 2>/dev/null; then
        return 0
    fi
    mv -fh -- "$tmp" "$link"
}

macos_generation_matches() {
    local stage="$1" generation="$2" name
    for name in z23 zclassic23-package-verify zclassic23-acme AGENT_CARD.md; do
        cmp -s "$stage/$name" "$generation/$name" || return 1
    done
    [ -L "$generation/zclassic23" ] \
        && [ "$(readlink "$generation/zclassic23")" = z23 ]
}

MACOS_GENERATION=""
MACOS_GENERATION_ID=""
MACOS_GENERATIONS=""
MACOS_INCOMING=""
MACOS_PREVIOUS_TARGET=""
MACOS_PLIST=""
MACOS_ACTIVE_PREFIX=""
MACOS_ACTIVATION_PENDING=0

install_payload_macos_generation() {
    local stage="$1" prefix="$2" root generations name
    root="$prefix/lib/z23"
    generations="$root/generations"
    MACOS_GENERATIONS="$generations"
    MACOS_GENERATION_ID="$(sha256_file "$stage/SHA256SUMS")"
    MACOS_GENERATION="$generations/$MACOS_GENERATION_ID"
    mkdir -p "$generations" "$prefix/bin" "$prefix/share/z23"

    if [ -e "$MACOS_GENERATION" ]; then
        [ -d "$MACOS_GENERATION" ] \
            || die "macOS generation path is not a directory: $MACOS_GENERATION"
        macos_generation_matches "$stage" "$MACOS_GENERATION" \
            || die "macOS generation $MACOS_GENERATION_ID does not match its verified manifest"
    else
        MACOS_INCOMING="$(mktemp -d "$generations/.incoming.XXXXXX")" \
            || die "could not stage macOS release generation"
        for name in z23 zclassic23-package-verify zclassic23-acme; do
            install -m 555 "$stage/$name" "$MACOS_INCOMING/$name"
        done
        install -m 444 "$stage/AGENT_CARD.md" "$MACOS_INCOMING/AGENT_CARD.md"
        ln -s z23 "$MACOS_INCOMING/zclassic23" \
            || die "could not create the macOS generation node alias"
        # APFS refuses to rename the generation after its owner-write bit is
        # removed. Commit its final name first, then make the directory inert.
        mv -- "$MACOS_INCOMING" "$MACOS_GENERATION" \
            || die "could not commit macOS release generation"
        MACOS_INCOMING=""
        chmod 555 "$MACOS_GENERATION"
    fi

    # These stable public names never contain release bytes. Each resolves
    # through the one atomically replaced `current` link below.
    atomic_relative_link ../lib/z23/current/z23 "$prefix/bin/z23" \
        || die "could not link the current macOS z23 generation"
    atomic_relative_link z23 "$prefix/bin/zclassic23" \
        || die "could not link the current macOS node alias"
    atomic_relative_link ../lib/z23/current/zclassic23-package-verify \
        "$prefix/bin/zclassic23-package-verify" \
        || die "could not link the current macOS package verifier"
    atomic_relative_link ../lib/z23/current/zclassic23-acme \
        "$prefix/bin/zclassic23-acme" \
        || die "could not link the current macOS certificate worker"
    atomic_relative_link ../../lib/z23/current/AGENT_CARD.md \
        "$prefix/share/z23/AGENT_CARD.md" \
        || die "could not link the current verified agent card"
}

install_payload() {
    local stage="$1" prefix="$2" name
    local bindir="$prefix/bin" carddir="$prefix/share/z23"
    mkdir -p "$bindir" "$carddir"
    for name in $RELEASE_MEMBERS; do
        [ -f "$stage/$name" ] || die "verified payload missing $name"
    done
    install -m 755 "$stage/z23" "$bindir/z23"
    # Same bytes, two names: install the alias as a RELATIVE symlink rather
    # than a second 27.8 MB copy. A symlink and not a hard link on purpose —
    # a later upgrade replaces the z23 inode, and a hard link would silently
    # keep serving the old program under the old name. Nothing dispatches on
    # argv[0]; /proc/self/exe resolves through the link to identical bytes,
    # so the running-binary digest and self-respawn are unchanged.
    rm -f -- "$bindir/zclassic23"
    ln -s z23 "$bindir/zclassic23" || die "could not link zclassic23 to z23"
    install -m 755 "$stage/zclassic23-package-verify" \
        "$bindir/zclassic23-package-verify"
    # zclassic23-acme is the ONLY binary that can renew a certificate this
    # node obtains (see write_cert_renew_units). Installing it beside the
    # verifier is what closes the "certificate obtained, never renewed" bug.
    install -m 755 "$stage/zclassic23-acme" "$bindir/zclassic23-acme"
    # The agent card is verified payload, so it is installed like payload:
    # an assistant reading it is reading bytes SHA256SUMS covered.
    install -m 644 "$stage/AGENT_CARD.md" "$carddir/AGENT_CARD.md"
}

xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

write_launchd_plist() {
    local prefix="$1" datadir="$2" launchd_dir="$3"
    local plist_tmp bin_xml datadir_xml
    command -v plutil >/dev/null 2>&1 \
        || die "plutil is required for the native macOS service install"
    mkdir -p "$launchd_dir" "$datadir"
    MACOS_PLIST="$launchd_dir/org.z23.zclassic.plist"
    plist_tmp="$(mktemp "$launchd_dir/.org.z23.zclassic.XXXXXX")" \
        || die "could not stage the launchd plist"
    bin_xml="$(xml_escape "$prefix/bin/z23")"
    datadir_xml="$(xml_escape "$datadir")"
    cat >"$plist_tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
         "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>org.z23.zclassic</string>
    <key>ProgramArguments</key>
    <array>
        <string>$bin_xml</string>
        <string>-datadir=$datadir_xml</string>
        <string>-operator-lane=canonical</string>
        <string>-listen</string>
        <string>-tor</string>
        <string>-onion-persist</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ProcessType</key><string>Background</string>
    <key>ThrottleInterval</key><integer>5</integer>
    <key>StandardOutPath</key><string>$datadir_xml/z23.stdout.log</string>
    <key>StandardErrorPath</key><string>$datadir_xml/z23.stderr.log</string>
    <key>WorkingDirectory</key><string>$datadir_xml</string>
    <key>Nice</key><integer>0</integer>
    <key>LowPriorityIO</key><false/>
</dict>
</plist>
EOF
    if ! plutil -lint "$plist_tmp" >/dev/null; then
        rm -f -- "$plist_tmp"
        die "plutil rejected the generated launchd service"
    fi
    mv -f -- "$plist_tmp" "$MACOS_PLIST" \
        || die "could not commit the launchd plist"
}

macos_switch_current() {
    local prefix="$1" target="$2" root="$prefix/lib/z23"
    atomic_relative_link "$target" "$root/current"
}

macos_launchd_start_and_qualify() {
    local prefix="$1" datadir="$2" domain service pid running_path
    local expected_digest running_digest timeout_ms heartbeat_ms
    domain="gui/$(id -u)"
    service="$domain/org.z23.zclassic"
    timeout_ms="${Z23_LAUNCHD_READY_TIMEOUT_MS:-120000}"
    heartbeat_ms="${Z23_LAUNCHD_READY_HEARTBEAT_MS:-250}"
    command -v launchctl >/dev/null 2>&1 || return 1
    command -v lsof >/dev/null 2>&1 || return 1

    if launchctl print "$service" >/dev/null 2>&1; then
        launchctl bootout "$service" >/dev/null || return 1
    fi
    launchctl bootstrap "$domain" "$MACOS_PLIST" >/dev/null || return 1
    launchctl kickstart -k "$service" >/dev/null || return 1
    "$prefix/bin/z23" core node bootwait -datadir="$datadir" \
        --timeout_ms="$timeout_ms" --heartbeat_ms="$heartbeat_ms" \
        >/dev/null || return 1
    pid="$(launchctl print "$service" 2>/dev/null |
        awk '$1 == "pid" && $2 == "=" {print $3; exit}')"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    running_path="$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null |
        sed -n 's/^n//p' | head -1)"
    [ -n "$running_path" ] && [ -f "$running_path" ] || return 1
    expected_digest="$(sha256_file "$MACOS_GENERATION/z23")"
    running_digest="$(sha256_file "$running_path")"
    [ "$running_digest" = "$expected_digest" ] || return 1
}

macos_restore_previous() {
    local prefix="$1" domain service root="$prefix/lib/z23"
    domain="gui/$(id -u)"
    service="$domain/org.z23.zclassic"
    launchctl bootout "$service" >/dev/null 2>&1 || true
    if [ -n "$MACOS_PREVIOUS_TARGET" ]; then
        macos_switch_current "$prefix" "$MACOS_PREVIOUS_TARGET" || return 1
        launchctl bootstrap "$domain" "$MACOS_PLIST" >/dev/null || return 1
        launchctl kickstart -k "$service" >/dev/null || return 1
    else
        rm -f -- "$root/current" "$MACOS_PLIST"
    fi
}

macos_abort_pending_activation() {
    [ "$MACOS_ACTIVATION_PENDING" -eq 1 ] || return 0
    MACOS_ACTIVATION_PENDING=0
    macos_restore_previous "$MACOS_ACTIVE_PREFIX"
}

macos_activation_signal() {
    local status="$1"
    macos_abort_pending_activation || true
    exit "$status"
}

activate_macos_generation() {
    local prefix="$1" datadir="$2" root="$prefix/lib/z23"
    MACOS_PREVIOUS_TARGET=""
    if [ -L "$root/current" ]; then
        MACOS_PREVIOUS_TARGET="$(readlink "$root/current")"
    elif [ -e "$root/current" ]; then
        die "macOS current generation is not a symbolic link"
    fi

    write_launchd_plist "$prefix" "$datadir" \
        "${Z23_LAUNCHD_DIR:-$HOME/Library/LaunchAgents}"
    if [ -n "$MACOS_PREVIOUS_TARGET" ]; then
        atomic_relative_link "$MACOS_PREVIOUS_TARGET" "$root/last-good" \
            || die "could not preserve the last-good macOS generation"
    fi
    macos_switch_current "$prefix" "generations/$MACOS_GENERATION_ID" \
        || die "could not activate the candidate macOS generation"
    MACOS_ACTIVE_PREFIX="$prefix"
    MACOS_ACTIVATION_PENDING=1
    trap 'macos_abort_pending_activation' EXIT
    trap 'macos_activation_signal 129' HUP
    trap 'macos_activation_signal 130' INT
    trap 'macos_activation_signal 143' TERM

    if macos_launchd_start_and_qualify "$prefix" "$datadir"; then
        if [ -z "$MACOS_PREVIOUS_TARGET" ]; then
            atomic_relative_link "generations/$MACOS_GENERATION_ID" \
                "$root/last-good" \
                || die "could not record the first last-good macOS generation"
        fi
        MACOS_ACTIVATION_PENDING=0
        trap - EXIT HUP INT TERM
        return 0
    fi

    say "candidate macOS generation failed launchd readiness or running-image qualification; rolling back"
    MACOS_ACTIVATION_PENDING=0
    macos_restore_previous "$prefix" \
        || die "candidate failed and the previous macOS generation could not be restored"
    trap - EXIT HUP INT TERM
    die "candidate macOS generation was rolled back"
}

activate_macos_generation_without_service() {
    local prefix="$1" root="$prefix/lib/z23" previous=""
    if [ -L "$root/current" ]; then
        previous="$(readlink "$root/current")"
    elif [ -e "$root/current" ]; then
        die "macOS current generation is not a symbolic link"
    fi
    if [ -n "$previous" ]; then
        atomic_relative_link "$previous" "$root/last-good" \
            || die "could not preserve the last-good macOS generation"
    fi
    macos_switch_current "$prefix" "generations/$MACOS_GENERATION_ID" \
        || die "could not select the installed macOS generation"
    if [ -z "$previous" ]; then
        atomic_relative_link "generations/$MACOS_GENERATION_ID" \
            "$root/last-good" \
            || die "could not record the first last-good macOS generation"
    fi
}

write_unit() {
    local prefix="$1" unit_dir="$2"
    local bin="$prefix/bin/zclassic23"
    mkdir -p "$unit_dir"
    # z23.service — never overwrite the production zclassic23.service.
    cat >"$unit_dir/z23.service" <<EOF
[Unit]
Description=Z23 node
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
# First-boot onion: -tor -onion-persist so a stranger is reachable, and
# Type=notify holds activating until READY=1. READY waits for onion
# DESCRIPTOR PUBLICATION (not hostname-only) so cold-boot clients do not
# dial before HSDirs have the descriptor.
ExecStart=$bin -datadir=%h/.zclassic-c23 -listen -tor -onion-persist
# Restart=always (not on-failure): a new node clean-exits once to install the
# checkpoint bundle (install-on-next-boot). on-failure would drop that boot.
Restart=always
RestartSec=5
TimeoutStartSec=14400
NotifyAccess=main

[Install]
WantedBy=default.target
EOF
    if [ "${Z23_SKIP_SYSTEMD:-0}" != "1" ]; then
        systemctl --user daemon-reload 2>/dev/null || true
    fi
}

install_from_source() {
    local src="$1" expected_manifest_sha256="$2"
    [ -n "$src" ] || die "no source: pass --source=<url-or-dir> or set Z23_RELEASE_SOURCE"
    local prefix="${Z23_INSTALL_PREFIX:-$HOME/.local}"
    local unit_dir="${Z23_UNIT_DIR:-$HOME/.config/systemd/user}"
    local install_tmp="${TMPDIR:-/tmp}"
    [ -d "$install_tmp" ] || die "temporary directory does not exist: $install_tmp"
    INSTALL_STAGE_PARENT="$(cd "$install_tmp" && pwd -P)"
    INSTALL_STAGE="$(mktemp -d "$INSTALL_STAGE_PARENT/zcl-install-z23.XXXXXX")" \
        || die "mktemp failed"
    trap 'cleanup_install_stage' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    fetch_into "$src" "$INSTALL_STAGE" "$expected_manifest_sha256"
    verify_strict "$INSTALL_STAGE"
    local install_platform
    install_platform="${Z23_INSTALL_TEST_PLATFORM:-$(uname -s)}"
    if [ "$install_platform" = Darwin ]; then
        install_payload_macos_generation "$INSTALL_STAGE" "$prefix"
    else
        install_payload "$INSTALL_STAGE" "$prefix"
    fi
    cleanup_install_stage
    trap - EXIT HUP INT TERM
    if [ "$install_platform" = Darwin ]; then
        if [ "${Z23_SKIP_SYSTEMD:-0}" != "1" ]; then
            activate_macos_generation "$prefix" \
                "${Z23_DATADIR:-$HOME/.zclassic-c23}"
        else
            activate_macos_generation_without_service "$prefix"
        fi
    elif [ "${Z23_SKIP_SYSTEMD:-0}" != "1" ]; then
            write_unit "$prefix" "$unit_dir"
    fi
    say "installed $prefix/bin/z23"
    printf '%s\n' "$NEXT_COMMAND"
}

run_install() {
    # Drive the shipped entry point in a child so die()/exit is the real path.
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$1" Z23_UNIT_DIR="$2" \
        "$SCRIPT_DIR/install_z23.sh" --source="$3"
}

SELFTEST_TMP=""
SELFTEST_MANIFEST_SHA=""

selftest_prepare() {
    local tmp
    tmp="$(mktemp -d /tmp/zcl-install-z23-selftest.XXXXXX)" || die "mktemp failed"
    SELFTEST_TMP="$tmp"
    trap 'chmod -R u+w "$SELFTEST_TMP" 2>/dev/null || true; rm -rf "$SELFTEST_TMP"' EXIT

    mkdir -p "$tmp/good" "$tmp/bad" "$tmp/prefix" "$tmp/units" \
        "$tmp/stages"
    export TMPDIR="$tmp/stages"
    # The generic installer contract below remains the Linux/systemd shape.
    # A separate lifecycle proof exercises Darwin generations and launchd.
    export Z23_INSTALL_TEST_PLATFORM=Linux

    # A release is five names, and z23/zclassic23 are the same bytes.
    printf 'payload-a\n' >"$tmp/good/z23"
    ln -f -- "$tmp/good/z23" "$tmp/good/zclassic23"
    printf 'confined-verifier\n' >"$tmp/good/zclassic23-package-verify"
    printf 'cert-worker\n' >"$tmp/good/zclassic23-acme"
    printf '# Z23 agent card\n\nRun `z23 status`.\n' >"$tmp/good/AGENT_CARD.md"
    (cd "$tmp/good" && sha256sum $RELEASE_MEMBERS >SHA256SUMS)

    # Shell-only curl fixture: map https://mirror.invalid/<path> into the
    # selftest tree and record every requested object. This proves a bad
    # manifest pin is rejected before any executable payload is downloaded.
    mkdir -p "$tmp/mockbin" "$tmp/http/good" "$tmp/http/replaced" \
        "$tmp/http/oversized" "$tmp/http/oversized-payload" \
        "$tmp/http/duplicate" "$tmp/http/malformed" "$tmp/http/signal" \
        "$tmp/http/split-names" "$tmp/tampered-card"
    cp -f -- "$tmp/good/"* "$tmp/http/good/"
    cp -f -- "$tmp/good/"* "$tmp/http/signal/"

    # A release whose two node names are NOT the same bytes. There is no
    # honest way to pick one, so it is refused before anything is fetched.
    printf 'payload-a\n' >"$tmp/http/split-names/z23"
    printf 'payload-b-different\n' >"$tmp/http/split-names/zclassic23"
    cp -f -- "$tmp/good/zclassic23-package-verify" "$tmp/good/zclassic23-acme" \
        "$tmp/good/AGENT_CARD.md" "$tmp/http/split-names/"
    (cd "$tmp/http/split-names" && sha256sum $RELEASE_MEMBERS >SHA256SUMS)

    # A release whose agent card was edited after the manifest was written.
    # The card tells an assistant what to run, so this must refuse.
    cp -f -- "$tmp/good/"* "$tmp/tampered-card/"
    # Any edit at all is a mismatch; the text is a marker, deliberately not
    # a real fetch-and-run line, so the fixture cannot trip our own
    # supply-chain scanner while proving the card is covered.
    printf '# Z23 agent card\n\nTAMPERED: attacker instructions.\n' \
        >"$tmp/tampered-card/AGENT_CARD.md"

    printf 'replacement-node\n' >"$tmp/http/replaced/z23"
    ln -f -- "$tmp/http/replaced/z23" "$tmp/http/replaced/zclassic23"
    printf 'replacement-verifier\n' \
        >"$tmp/http/replaced/zclassic23-package-verify"
    printf 'replacement-acme\n' >"$tmp/http/replaced/zclassic23-acme"
    printf '# replacement card\n' >"$tmp/http/replaced/AGENT_CARD.md"
    (cd "$tmp/http/replaced" && sha256sum $RELEASE_MEMBERS >SHA256SUMS)
    dd if=/dev/zero bs=1025 count=1 2>/dev/null | tr '\0' x \
        >"$tmp/http/oversized/SHA256SUMS"
    truncate -s $((REMOTE_NODE_MAX_BYTES + 1)) \
        "$tmp/http/oversized-payload/z23"
    ln -f -- "$tmp/http/oversized-payload/z23" \
        "$tmp/http/oversized-payload/zclassic23"
    cp -f -- "$tmp/good/zclassic23-package-verify" "$tmp/good/zclassic23-acme" \
        "$tmp/good/AGENT_CARD.md" "$tmp/http/oversized-payload/"
    (cd "$tmp/http/oversized-payload" && sha256sum $RELEASE_MEMBERS >SHA256SUMS)
    {
        sed -n '1p' "$tmp/good/SHA256SUMS"
        sed -n '1p' "$tmp/good/SHA256SUMS"
        sed -n '2p' "$tmp/good/SHA256SUMS"
        sed -n '3p' "$tmp/good/SHA256SUMS"
    } >"$tmp/http/duplicate/SHA256SUMS"
    sed 's/  / /' "$tmp/good/SHA256SUMS" \
        >"$tmp/http/malformed/SHA256SUMS"
}

selftest_prepare_curl_mock() {
    local tmp="$SELFTEST_TMP"
    cat >"$tmp/mockbin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = --version ]; then
    printf 'curl %s mock\n' "${Z23_INSTALL_TEST_CURL_VERSION:-8.4.0}"
    exit 0
fi
[ "$#" -eq 10 ] || exit 2
[ "$1" = --connect-timeout ] && [ "$2" = 10 ] || exit 2
[ "$3" = --max-time ] || exit 2
[ "$5" = --max-filesize ] || exit 2
[ "$7" = -fsSL ] && [ "$9" = -o ] || exit 2
maximum_seconds="$4"; maximum_bytes="$6"; url="$8"; dest="${10}"
case "$url" in https://mirror.invalid/*) ;; *) exit 3 ;; esac
rel="${url#https://mirror.invalid/}"
case "$rel" in
    */SHA256SUMS)
        [ "$maximum_seconds" = 30 ] && [ "$maximum_bytes" = 1024 ] || exit 4
        ;;
    */z23|*/zclassic23)
        [ "$maximum_seconds" = 300 ] && \
            [ "$maximum_bytes" = 67108864 ] || exit 4
        ;;
    */zclassic23-package-verify)
        [ "$maximum_seconds" = 300 ] && \
            [ "$maximum_bytes" = 134217728 ] || exit 4
        ;;
    */zclassic23-acme)
        [ "$maximum_seconds" = 300 ] && \
            [ "$maximum_bytes" = 33554432 ] || exit 4
        ;;
    */AGENT_CARD.md)
        [ "$maximum_seconds" = 300 ] && [ "$maximum_bytes" = 65536 ] || exit 4
        ;;
    *) exit 4 ;;
esac
printf '%s connect=%s time=%s bytes=%s\n' \
    "$rel" "$2" "$maximum_seconds" "$maximum_bytes" \
    >>"$Z23_INSTALL_TEST_CURL_LOG"
if [ "$rel" = signal/SHA256SUMS ]; then
    : >"$Z23_INSTALL_TEST_SIGNAL_READY"
    while [ ! -e "$Z23_INSTALL_TEST_SIGNAL_RELEASE" ]; do sleep 0.02; done
fi
actual_bytes="$(wc -c <"$Z23_INSTALL_TEST_HTTP_ROOT/$rel" | tr -d ' ')"
[ "$actual_bytes" -le "$maximum_bytes" ] || exit 63
cp -- "$Z23_INSTALL_TEST_HTTP_ROOT/$rel" "$dest"
EOF
    chmod 755 "$tmp/mockbin/curl"
}

selftest_local_refusals() {
    local tmp="$SELFTEST_TMP" rc

    # Missing source refuses.
    rc=0
    run_install "$tmp/prefix" "$tmp/units" "$tmp/no-such" \
        >/dev/null 2>"$tmp/missing.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing source must exit 1"
    grep -q 'not a directory' "$tmp/missing.err" \
        || die "selftest: missing source must name the refusal"

    # Missing SHA256SUMS refuses.
    mkdir -p "$tmp/nosums"
    printf 'x\n' >"$tmp/nosums/z23"
    rc=0
    run_install "$tmp/prefix" "$tmp/units" "$tmp/nosums" \
        >/dev/null 2>"$tmp/nosums.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing SHA256SUMS must exit 1"
    grep -q 'SHA256SUMS missing' "$tmp/nosums.err" \
        || die "selftest: missing SHA256SUMS must be named"

    # Mismatch: dest must stay empty.
    cp -f -- "$tmp/good/"* "$tmp/bad/"
    printf 'TAMPERED\n' >"$tmp/bad/z23"
    rc=0
    run_install "$tmp/empty-dest" "$tmp/units" "$tmp/bad" \
        >/dev/null 2>"$tmp/mismatch.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: checksum mismatch must exit 1"
    grep -qi 'mismatch' "$tmp/mismatch.err" \
        || die "selftest: mismatch must be named"
    if [ -e "$tmp/empty-dest/bin/z23" ]; then
        die "selftest: mismatch installed z23 anyway"
    fi
}

selftest_remote_authority() {
    local tmp="$SELFTEST_TMP" rc curl_version

    # A remote mirror is not the authority for its own checksum manifest.
    # Missing expectation refuses before even fetching SHA256SUMS.
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-missing" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/good \
        >/dev/null 2>"$tmp/remote-missing.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: remote source without manifest digest must exit 1"
    [ ! -s "$tmp/curl.log" ] \
        || die "selftest: missing remote manifest digest still made a request"
    [ ! -e "$tmp/remote-missing/bin/z23" ] \
        || die "selftest: unpinned remote source installed z23"

    # curl 8.4.0 is the first release where --max-filesize also bounds
    # responses without a known Content-Length. Refuse older or unreadable
    # versions before making a transfer request.
    for curl_version in 8.3.0 unreadable; do
        : >"$tmp/curl.log"
        rc=0
        PATH="$tmp/mockbin:$PATH" \
        Z23_INSTALL_TEST_CURL_VERSION="$curl_version" \
        Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
        Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/curl-$curl_version" \
        Z23_UNIT_DIR="$tmp/units" \
            "$SCRIPT_DIR/install_z23.sh" \
            --source=https://mirror.invalid/good \
            --manifest-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
            >/dev/null 2>"$tmp/curl-$curl_version.err" || rc=$?
        [ "$rc" -eq 1 ] || die "selftest: curl $curl_version must refuse"
        [ ! -s "$tmp/curl.log" ] \
            || die "selftest: curl $curl_version refusal made a request"
    done
}

selftest_remote_pins() {
    local tmp="$SELFTEST_TMP" rc

    # A wrong expectation may fetch the manifest to compare it, but must not
    # fetch any payload or install anything.
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-wrong" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/good \
        --manifest-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        >/dev/null 2>"$tmp/remote-wrong.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: wrong remote manifest digest must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        "good/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: wrong manifest digest fetched a payload"
    [ ! -e "$tmp/remote-wrong/bin/z23" ] \
        || die "selftest: wrong manifest digest installed z23"

    # Replacing both payloads and SHA256SUMS does not help a hostile mirror:
    # the independently obtained digest still binds the selected manifest.
    SELFTEST_MANIFEST_SHA="$(sha256sum "$tmp/http/good/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-replaced" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/replaced \
        --manifest-sha256="$SELFTEST_MANIFEST_SHA" \
        >/dev/null 2>"$tmp/remote-replaced.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: replaced remote release must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        "replaced/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: replaced manifest fetched a payload"
    [ ! -e "$tmp/remote-replaced/bin/z23" ] \
        || die "selftest: replaced remote release installed z23"
}

selftest_remote_success() {
    local tmp="$SELFTEST_TMP" out

    # Positive remote path: the selected manifest downloads and installs the
    # same verified files regardless of which mirror served them.
    : >"$tmp/curl.log"
    out="$(PATH="$tmp/mockbin:$PATH" \
        Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
        Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-good" \
        Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/good \
        --manifest-sha256="$SELFTEST_MANIFEST_SHA" 2>"$tmp/remote-good.err")" \
        || die "selftest: correctly pinned remote release failed"
    [ "$out" = "$NEXT_COMMAND" ] \
        || die "selftest: pinned remote install next command drifted"
    cmp -s "$tmp/good/z23" "$tmp/remote-good/bin/z23" \
        || die "selftest: pinned remote z23 bytes differ"
    # zclassic23 carries the SAME digest as z23 in this release, so it is
    # NEVER requested: the third of the download that is a duplicate is not
    # transferred at all. The request log is the proof.
    [ "$(cat "$tmp/curl.log")" = \
        $'good/SHA256SUMS connect=10 time=30 bytes=1024\ngood/AGENT_CARD.md connect=10 time=300 bytes=65536\ngood/z23 connect=10 time=300 bytes=67108864\ngood/zclassic23-package-verify connect=10 time=300 bytes=134217728\ngood/zclassic23-acme connect=10 time=300 bytes=33554432' ] \
        || die "selftest: bounded remote request sequence drifted"
    [ -L "$tmp/remote-good/bin/zclassic23" ] \
        || die "selftest: duplicate remote alias must install as a symlink"
    cmp -s "$tmp/good/zclassic23" "$tmp/remote-good/bin/zclassic23" \
        || die "selftest: remote zclassic23 alias does not read as the release bytes"

    # The other direction of the alias rule: a release whose two node names
    # carry DIFFERENT digests is refused outright, before any payload is
    # requested. There is no honest way to pick one of them.
    local split_sha rc
    split_sha="$(sha256sum "$tmp/http/split-names/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-split" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/split-names \
        --manifest-sha256="$split_sha" \
        >/dev/null 2>"$tmp/remote-split.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: split z23/zclassic23 digests must exit 1"
    grep -q 'different digests' "$tmp/remote-split.err" \
        || die "selftest: split node digests must be named"
    [ "$(cat "$tmp/curl.log")" = \
        "split-names/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: split node digests fetched a payload"
    [ ! -e "$tmp/remote-split/bin/z23" ] \
        || die "selftest: split node digests installed z23"
}

selftest_remote_bounds() {
    local tmp="$SELFTEST_TMP" rc oversized_manifest_sha256
    local oversized_payload_manifest_sha256

    # The transport ceiling is enforced even when a mirror advertises no
    # useful HTTP metadata: the fake curl applies the exact --max-filesize it
    # received and refuses the 1025-byte manifest without copying it.
    oversized_manifest_sha256="$(sha256sum "$tmp/http/oversized/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-oversized" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/oversized \
        --manifest-sha256="$oversized_manifest_sha256" \
        >/dev/null 2>"$tmp/remote-oversized.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: oversized remote manifest must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        "oversized/SHA256SUMS connect=10 time=30 bytes=1024" ] \
        || die "selftest: oversized manifest request was not bounded"
    [ ! -e "$tmp/remote-oversized/bin/z23" ] \
        || die "selftest: oversized remote manifest installed z23"

    oversized_payload_manifest_sha256="$(sha256sum \
        "$tmp/http/oversized-payload/SHA256SUMS" | awk '{print $1}')"
    : >"$tmp/curl.log"
    rc=0
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-oversized-payload" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/oversized-payload \
        --manifest-sha256="$oversized_payload_manifest_sha256" \
        >/dev/null 2>"$tmp/remote-oversized-payload.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: oversized remote payload must exit 1"
    [ "$(cat "$tmp/curl.log")" = \
        $'oversized-payload/SHA256SUMS connect=10 time=30 bytes=1024\noversized-payload/AGENT_CARD.md connect=10 time=300 bytes=65536\noversized-payload/z23 connect=10 time=300 bytes=67108864' ] \
        || die "selftest: oversized payload request was not bounded"
    [ ! -e "$tmp/remote-oversized-payload/bin/z23" ] \
        || die "selftest: oversized remote payload installed z23"
}

selftest_remote_manifest_and_signal() {
    local tmp="$SELFTEST_TMP" rc invalid_kind invalid_sha

    # Grammar and member-set checks happen after the pinned manifest fetch but
    # before the first payload request.
    for invalid_kind in duplicate malformed; do
        invalid_sha="$(sha256sum "$tmp/http/$invalid_kind/SHA256SUMS" | awk '{print $1}')"
        : >"$tmp/curl.log"
        rc=0
        PATH="$tmp/mockbin:$PATH" \
        Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
        Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-$invalid_kind" \
        Z23_UNIT_DIR="$tmp/units" \
            "$SCRIPT_DIR/install_z23.sh" \
            --source="https://mirror.invalid/$invalid_kind" \
            --manifest-sha256="$invalid_sha" \
            >/dev/null 2>"$tmp/remote-$invalid_kind.err" || rc=$?
        [ "$rc" -eq 1 ] \
            || die "selftest: $invalid_kind remote manifest must exit 1"
        [ "$(cat "$tmp/curl.log")" = \
            "$invalid_kind/SHA256SUMS connect=10 time=30 bytes=1024" ] \
            || die "selftest: $invalid_kind manifest fetched a payload"
        [ ! -e "$tmp/remote-$invalid_kind/bin/z23" ] \
            || die "selftest: $invalid_kind remote manifest installed z23"
    done

    # A signal while curl is active preserves the signal exit status and the
    # validated EXIT trap removes the partially populated staging directory.
    rm -f "$tmp/signal.ready" "$tmp/signal.release"
    : >"$tmp/curl.log"
    PATH="$tmp/mockbin:$PATH" \
    Z23_INSTALL_TEST_HTTP_ROOT="$tmp/http" \
    Z23_INSTALL_TEST_CURL_LOG="$tmp/curl.log" \
    Z23_INSTALL_TEST_SIGNAL_READY="$tmp/signal.ready" \
    Z23_INSTALL_TEST_SIGNAL_RELEASE="$tmp/signal.release" \
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/remote-signal" \
    Z23_UNIT_DIR="$tmp/units" \
        "$SCRIPT_DIR/install_z23.sh" \
        --source=https://mirror.invalid/signal \
        --manifest-sha256="$SELFTEST_MANIFEST_SHA" \
        >/dev/null 2>"$tmp/remote-signal.err" &
    local signal_pid=$! signal_wait=0
    while [ ! -e "$tmp/signal.ready" ] && [ "$signal_wait" -lt 100 ]; do
        sleep 0.02
        signal_wait=$((signal_wait + 1))
    done
    [ -e "$tmp/signal.ready" ] || die "selftest: signal fixture did not enter curl"
    kill -TERM "$signal_pid"
    : >"$tmp/signal.release"
    rc=0
    wait "$signal_pid" || rc=$?
    [ "$rc" -eq 143 ] || die "selftest: TERM must exit 143, got $rc"
    [ ! -e "$tmp/remote-signal/bin/z23" ] \
        || die "selftest: signalled install installed z23"
}

selftest_local_success() {
    local tmp="$SELFTEST_TMP" rc out install_card

    # Happy path: dest gets the files; stdout is exactly one next command.
    out="$(run_install "$tmp/prefix" "$tmp/units" "$tmp/good" 2>"$tmp/ok.err")" \
        || die "selftest: good install failed"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: stdout must be exactly '$NEXT_COMMAND', got '$out'"
    cmp -s "$tmp/good/z23" "$tmp/prefix/bin/z23" || die "selftest: installed z23 bytes differ"
    cmp -s "$tmp/good/zclassic23" "$tmp/prefix/bin/zclassic23" \
        || die "selftest: installed zclassic23 bytes differ"
    # The alias must be a RELATIVE symlink to z23 and must still read back as
    # the release bytes (the cmp above follows it). A hard link would keep
    # serving the pre-upgrade program after the next install.
    [ -L "$tmp/prefix/bin/zclassic23" ] \
        || die "selftest: duplicate zclassic23 must install as a symlink"
    [ "$(readlink "$tmp/prefix/bin/zclassic23")" = z23 ] \
        || die "selftest: zclassic23 must link to the relative name z23"
    cmp -s "$tmp/good/zclassic23-package-verify" \
        "$tmp/prefix/bin/zclassic23-package-verify" \
        || die "selftest: installed zclassic23-package-verify bytes differ"
    cmp -s "$tmp/good/zclassic23-acme" "$tmp/prefix/bin/zclassic23-acme" \
        || die "selftest: installed zclassic23-acme bytes differ"

    install_card="$tmp/prefix/share/z23/AGENT_CARD.md"
    cmp -s "$tmp/good/AGENT_CARD.md" "$install_card" \
        || die "selftest: the agent card must install as verified payload"

    # A card edited after the manifest was written is instruction injection
    # into whatever assistant reads it, so it refuses like any other payload.
    rc=0
    run_install "$tmp/card-dest" "$tmp/units" "$tmp/tampered-card" \
        >/dev/null 2>"$tmp/card.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: a tampered agent card must exit 1"
    grep -qi 'mismatch' "$tmp/card.err" \
        || die "selftest: a tampered agent card must name the mismatch"
    [ ! -e "$tmp/card-dest/bin/z23" ] \
        || die "selftest: a tampered agent card installed z23"
    [ ! -e "$tmp/card-dest/share/z23/AGENT_CARD.md" ] \
        || die "selftest: a tampered agent card was installed anyway"

    # A valid checksum manifest that omits the worker is still an incomplete
    # release and must refuse before any payload reaches a fresh destination.
    mkdir -p "$tmp/no-verifier"
    cp -f -- "$tmp/good/z23" "$tmp/no-verifier/z23"
    cp -f -- "$tmp/good/zclassic23" "$tmp/no-verifier/zclassic23"
    (cd "$tmp/no-verifier" && sha256sum z23 zclassic23 >SHA256SUMS)
    rc=0
    run_install "$tmp/no-verifier-dest" "$tmp/units" "$tmp/no-verifier" \
        >/dev/null 2>"$tmp/no-verifier.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing verifier must exit 1"
    grep -Eq 'exactly five|exactly once' "$tmp/no-verifier.err" \
        || die "selftest: missing verifier must name the strict manifest refusal"
    if [ -e "$tmp/no-verifier-dest/bin/z23" ]; then
        die "selftest: incomplete release installed z23 anyway"
    fi

    # The certificate worker is a release member on the same footing as the
    # package verifier: a manifest naming every OTHER member but silently
    # dropping zclassic23-acme is exactly the regression this task exists to
    # close (a node that can get a certificate but never renew it), so it
    # must refuse before any payload reaches a fresh destination too.
    mkdir -p "$tmp/no-acme"
    cp -f -- "$tmp/good/z23" "$tmp/good/zclassic23" \
        "$tmp/good/zclassic23-package-verify" "$tmp/good/AGENT_CARD.md" \
        "$tmp/no-acme/"
    (cd "$tmp/no-acme" && \
        sha256sum z23 zclassic23 zclassic23-package-verify AGENT_CARD.md \
            >SHA256SUMS)
    rc=0
    run_install "$tmp/no-acme-dest" "$tmp/units" "$tmp/no-acme" \
        >/dev/null 2>"$tmp/no-acme.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: missing zclassic23-acme must exit 1"
    grep -Eq 'exactly five|exactly once' "$tmp/no-acme.err" \
        || die "selftest: missing zclassic23-acme must name the strict manifest refusal"
    if [ -e "$tmp/no-acme-dest/bin/z23" ]; then
        die "selftest: a release silently missing zclassic23-acme installed z23 anyway"
    fi

    # Idempotent re-run.
    out="$(run_install "$tmp/prefix" "$tmp/units" "$tmp/good" 2>"$tmp/ok2.err")" \
        || die "selftest: second install failed"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: re-run stdout drifted"

    # The shipped unit must Restart=always so checkpoint install-on-next-boot
    # (a clean exit) is brought back. on-failure would strand a new node.
    grep -qx 'Restart=always' "$0" \
        || die "selftest: z23.service must Restart=always (install-on-next-boot)"

    # Drive the shipped write_unit path (run_install skips it under
    # Z23_SKIP_SYSTEMD=1). First-boot Type=notify READY must wait for onion
    # DESCRIPTOR PUBLICATION: hostname-only readiness lets systemd declare
    # started before HSDir upload, which is why "always connects" fails on
    # cold boots.
    write_unit "$tmp/prefix" "$tmp/units"
    [ -f "$tmp/units/z23.service" ] || die "selftest: write_unit did not emit z23.service"
    grep -q 'DESCRIPTOR PUBLICATION' "$tmp/units/z23.service" \
        || die "selftest: unit must wait for onion DESCRIPTOR PUBLICATION before ready"
    grep -q -- '-listen -tor -onion-persist' "$tmp/units/z23.service" \
        || die "selftest: z23.service must boot with -listen -tor -onion-persist"
}

# Every branch of the three-place agreement, in both directions. A test that
# only ever sees agreement would prove nothing about a refusal.
selftest_release_pin() {
    local tmp="$SELFTEST_TMP" rc out good_sha good_pin wrong_pin bad_installer
    local fake_installer="1111111111111111111111111111111111111111111111111111111111111111"
    good_sha="$(sha256sum "$tmp/good/SHA256SUMS" | awk '{print $1}')"
    good_pin="z23-pin-v1:$good_sha:$fake_installer"
    wrong_pin="z23-pin-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:$fake_installer"
    bad_installer="z23-pin-v1:$good_sha:not-a-digest"

    # PASS: all three sources answered and agreed.
    out="$(Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/pin-three" \
        Z23_UNIT_DIR="$tmp/units" "$SCRIPT_DIR/install_z23.sh" \
        --source="$tmp/good" \
        --attest="baked=$good_pin" --attest="dns=$good_pin" \
        --attest="repo=$good_pin" 2>"$tmp/pin-three.err")" \
        || die "selftest: three agreeing pins must install"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: agreeing pin install drifted"
    [ -x "$tmp/pin-three/bin/z23" ] || die "selftest: agreeing pin did not install z23"

    # REFUSE: three sources agree on a pin that does not describe this
    # release. Agreement is not a substitute for the checksum.
    rc=0
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/pin-wrong" \
        Z23_UNIT_DIR="$tmp/units" "$SCRIPT_DIR/install_z23.sh" \
        --source="$tmp/good" \
        --attest="baked=$wrong_pin" --attest="dns=$wrong_pin" \
        --attest="repo=$wrong_pin" >/dev/null 2>"$tmp/pin-wrong.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: an agreed pin for other bytes must exit 1"
    grep -q 'SHA256SUMS digest mismatch' "$tmp/pin-wrong.err" \
        || die "selftest: agreed-but-wrong pin must name the digest mismatch"
    [ ! -e "$tmp/pin-wrong/bin/z23" ] \
        || die "selftest: agreed-but-wrong pin installed z23"

    # REFUSE: one source disagrees. Never majority-vote, even 2 against 1.
    rc=0
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/pin-split" \
        Z23_UNIT_DIR="$tmp/units" "$SCRIPT_DIR/install_z23.sh" \
        --source="$tmp/good" \
        --attest="baked=$good_pin" --attest="dns=$good_pin" \
        --attest="repo=$wrong_pin" >/dev/null 2>"$tmp/pin-split.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: a disagreeing source must exit 1"
    grep -q 'release pin disagreement between baked and repo' "$tmp/pin-split.err" \
        || die "selftest: disagreement must name both origins"
    [ ! -e "$tmp/pin-split/bin/z23" ] \
        || die "selftest: a disagreeing source installed z23"

    # PASS, loudly: two agreed, one was unreachable. Unreachable is reported
    # as unreachable and never rendered as a disagreement.
    out="$(Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/pin-two" \
        Z23_UNIT_DIR="$tmp/units" "$SCRIPT_DIR/install_z23.sh" \
        --source="$tmp/good" \
        --attest="baked=$good_pin" --attest="repo=$good_pin" \
        --attest-unreachable=dns=no-dns-tool 2>"$tmp/pin-two.err")" \
        || die "selftest: two agreeing sources must install"
    [ "$out" = "$NEXT_COMMAND" ] || die "selftest: two-source install drifted"
    grep -q 'agreed by 2 of 3 sources (unreachable: dns=no-dns-tool)' "$tmp/pin-two.err" \
        || die "selftest: a degraded quorum must say so on stderr"
    if grep -q 'disagreement' "$tmp/pin-two.err"; then
        die "selftest: an unreachable source must not be called a disagreement"
    fi

    # REFUSE: only one source answered. No silent degradation to one.
    rc=0
    Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/pin-one" \
        Z23_UNIT_DIR="$tmp/units" "$SCRIPT_DIR/install_z23.sh" \
        --source="$tmp/good" --attest="baked=$good_pin" \
        --attest-unreachable=dns=no-dns-tool \
        --attest-unreachable=repo=fetch-failed \
        >/dev/null 2>"$tmp/pin-one.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: a single answering source must exit 1"
    grep -q 'release pin quorum: 1 of 3 sources answered' "$tmp/pin-one.err" \
        || die "selftest: quorum refusal must count the sources"
    grep -q 'unreachable: dns=no-dns-tool, repo=fetch-failed' "$tmp/pin-one.err" \
        || die "selftest: quorum refusal must name the unreachable sources"
    [ ! -e "$tmp/pin-one/bin/z23" ] || die "selftest: one source installed z23"

    # REFUSE: malformed pin, unknown origin, repeated origin, and an explicit
    # --manifest-sha256 that contradicts the agreed pin.
    local case_name case_args
    local unset_pin="z23-pin-v1:$ATTEST_PIN_UNSET:$ATTEST_PIN_UNSET"
    for case_name in malformed unset unknown-origin repeated-origin contradicted; do
        case "$case_name" in
            malformed) case_args=(--attest="baked=$bad_installer"
                --attest="dns=$good_pin" --attest="repo=$good_pin") ;;
            unset) case_args=(--attest="baked=$unset_pin"
                --attest="dns=$good_pin" --attest="repo=$good_pin") ;;
            unknown-origin) case_args=(--attest="mirror=$good_pin"
                --attest="dns=$good_pin" --attest="repo=$good_pin") ;;
            repeated-origin) case_args=(--attest="dns=$good_pin"
                --attest="dns=$good_pin" --attest="repo=$good_pin") ;;
            contradicted) case_args=(--attest="baked=$good_pin"
                --attest="dns=$good_pin" --attest="repo=$good_pin"
                --manifest-sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) ;;
        esac
        rc=0
        Z23_SKIP_SYSTEMD=1 Z23_INSTALL_PREFIX="$tmp/pin-$case_name" \
            Z23_UNIT_DIR="$tmp/units" "$SCRIPT_DIR/install_z23.sh" \
            --source="$tmp/good" "${case_args[@]}" \
            >/dev/null 2>"$tmp/pin-$case_name.err" || rc=$?
        [ "$rc" -eq 1 ] || die "selftest: pin case $case_name must exit 1"
        [ ! -e "$tmp/pin-$case_name/bin/z23" ] \
            || die "selftest: pin case $case_name installed z23"
    done
    grep -q 'not a z23-pin-v1' "$tmp/pin-malformed.err" \
        || die "selftest: a malformed pin must name the grammar"
    grep -q 'not a z23-pin-v1' "$tmp/pin-unset.err" \
        || die "selftest: the unset sentinel must never be accepted as a pin"
    grep -q 'unknown attestation origin: mirror' "$tmp/pin-unknown-origin.err" \
        || die "selftest: an unknown origin must be named"
    grep -q 'attestation origin named twice: dns' "$tmp/pin-repeated-origin.err" \
        || die "selftest: a repeated origin must be named"
    grep -q 'disagrees with the pin' "$tmp/pin-contradicted.err" \
        || die "selftest: a contradicted --manifest-sha256 must refuse"
}

# The front door served at the domain is proved by its own harness, which is
# not shipped inside the served script: that script has to stay short enough
# that a careful person reads it before piping it to a shell.
selftest_front_door() {
    local dir="$SCRIPT_DIR/../../packaging/install"
    # This installer also ships alone (the front door downloads just this
    # file), and then there is no repository beside it to test. That is
    # UNOBSERVED, not a pass — but inside the repository, where every gate
    # runs, the directory is present and the harness is mandatory.
    [ -d "$dir" ] || return 0
    [ -f "$dir/install_selftest.sh" ] \
        || die "selftest: packaging/install exists but its front-door harness is missing"
    bash "$dir/install_selftest.sh" \
        || die "selftest: packaging/install front door harness failed"
}

selftest_local_manifest_refusals() {
    local tmp="$SELFTEST_TMP" rc
    # Unexpected SHA256SUMS member refuses before copy.
    mkdir -p "$tmp/extra"
    printf 'x\n' >"$tmp/extra/z23"
    printf 'x\n' >"$tmp/extra/zclassic23"
    printf 'x\n' >"$tmp/extra/zclassic23-package-verify"
    printf 'x\n' >"$tmp/extra/zclassic23-acme"
    printf 'x\n' >"$tmp/extra/evil"
    (cd "$tmp/extra" && \
        sha256sum z23 zclassic23 zclassic23-package-verify zclassic23-acme evil \
            >SHA256SUMS)
    rc=0
    run_install "$tmp/prefix2" "$tmp/units" "$tmp/extra" \
        >/dev/null 2>"$tmp/extra.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: extra SHA256SUMS member must refuse"
    grep -Eq 'exactly five|exactly once' "$tmp/extra.err" \
        || die "selftest: extra member must name the strict manifest refusal"

    [ -z "$(find "$tmp/stages" -mindepth 1 -maxdepth 1 \
        -name 'zcl-install-z23.*' -print -quit)" ] \
        || die "selftest: a negative install path leaked its staging directory"
}

selftest_macos_transaction() {
    local tmp="$SELFTEST_TMP" mac="$SELFTEST_TMP/macos"
    local prefix="$mac/prefix & native" launchd="$mac/LaunchAgents"
    local datadir="$mac/data & chain" mock="$mac/mockbin" rc out
    local v1_id v2_id current_target last_good_target
    mkdir -p "$mac/v1" "$mac/v2" "$mock" "$launchd" "$datadir"

    # This host normally has Homebrew sha256sum, which would otherwise hide
    # the stock-mac path forever. Constrain PATH to shasum + its parser and
    # prove both the one-file digest and manifest checker without GNU tools.
    mkdir -p "$mac/hashbin"

    cat >"$mac/v1/z23" <<'EOF'
#!/usr/bin/env bash
[ "${Z23_INSTALL_TEST_READY_FAIL:-0}" != 1 ]
EOF
    cat >"$mac/v2/z23" <<'EOF'
#!/usr/bin/env bash
# Distinct candidate bytes: readiness stays the same, identity does not.
[ "${Z23_INSTALL_TEST_READY_FAIL:-0}" != 1 ]
EOF
    chmod 755 "$mac/v1/z23" "$mac/v2/z23"
    local version
    for version in v1 v2; do
        ln -f -- "$mac/$version/z23" "$mac/$version/zclassic23"
        printf '%s verifier\n' "$version" >"$mac/$version/zclassic23-package-verify"
        printf '%s acme\n' "$version" >"$mac/$version/zclassic23-acme"
        printf '# %s agent card\n' "$version" >"$mac/$version/AGENT_CARD.md"
        chmod 755 "$mac/$version/zclassic23-package-verify" \
            "$mac/$version/zclassic23-acme"
        (cd "$mac/$version" && sha256sum $RELEASE_MEMBERS >SHA256SUMS)
    done
    v1_id="$(sha256_file "$mac/v1/SHA256SUMS")"
    v2_id="$(sha256_file "$mac/v2/SHA256SUMS")"
    if command -v shasum >/dev/null 2>&1; then
        ln -s "$(command -v shasum)" "$mac/hashbin/shasum"
        ln -s "$(command -v awk)" "$mac/hashbin/awk"
        ln -s "$(command -v dirname)" "$mac/hashbin/dirname"
        ln -s "$(command -v basename)" "$mac/hashbin/basename"
        [ "$(PATH="$mac/hashbin" sha256_file "$mac/v1/SHA256SUMS")" = "$v1_id" ] \
            || die "selftest: stock macOS shasum digest path drifted"
        PATH="$mac/hashbin" sha256_check_manifest "$mac/v1/SHA256SUMS" >/dev/null \
            || die "selftest: stock macOS shasum manifest check failed"
    elif [ "$(uname -s)" = Darwin ]; then
        die "selftest: stock macOS shasum is unavailable"
    else
        say "selftest: shasum fallback UNOBSERVED on this non-Darwin host"
    fi

    cat >"$mock/plutil" <<'EOF'
#!/usr/bin/env bash
[ "$1" = -lint ] && [ -s "$2" ]
EOF
    cat >"$mock/launchctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$Z23_INSTALL_TEST_LAUNCHCTL_LOG"
case "$1" in
    print)
        [ -e "$Z23_INSTALL_TEST_LAUNCHD_STATE" ] || exit 3
        printf '    pid = 4242\n'
        ;;
    bootout) rm -f -- "$Z23_INSTALL_TEST_LAUNCHD_STATE" ;;
    bootstrap) : >"$Z23_INSTALL_TEST_LAUNCHD_STATE" ;;
    kickstart) [ -e "$Z23_INSTALL_TEST_LAUNCHD_STATE" ] ;;
    *) exit 2 ;;
esac
EOF
    cat >"$mock/lsof" <<'EOF'
#!/usr/bin/env bash
root="$Z23_INSTALL_PREFIX/lib/z23"
if [ "${Z23_INSTALL_TEST_WRONG_IMAGE:-0}" = 1 ]; then
    target="$(readlink "$root/last-good")"
else
    target="$(readlink "$root/current")"
fi
printf 'p4242\nn%s/%s/z23\n' "$root" "$target"
EOF
    chmod 755 "$mock/plutil" "$mock/launchctl" "$mock/lsof"
    : >"$mac/launchctl.log"

    out="$(PATH="$mock:$PATH" Z23_INSTALL_TEST_PLATFORM=Darwin \
        Z23_SKIP_SYSTEMD=0 Z23_INSTALL_PREFIX="$prefix" \
        Z23_LAUNCHD_DIR="$launchd" Z23_DATADIR="$datadir" \
        Z23_INSTALL_TEST_LAUNCHCTL_LOG="$mac/launchctl.log" \
        Z23_INSTALL_TEST_LAUNCHD_STATE="$mac/launchd.state" \
        "$SCRIPT_DIR/install_z23.sh" --source="$mac/v1" \
        2>"$mac/v1.err")" || die "selftest: first macOS generation failed"
    [ "$out" = "$NEXT_COMMAND" ] \
        || die "selftest: macOS install did not print one next command"
    current_target="$(readlink "$prefix/lib/z23/current")"
    last_good_target="$(readlink "$prefix/lib/z23/last-good")"
    [ "$current_target" = "generations/$v1_id" ] \
        || die "selftest: first macOS generation is not current"
    [ "$last_good_target" = "$current_target" ] \
        || die "selftest: first macOS generation is not last-good"
    [ -L "$prefix/bin/z23" ] && [ -x "$prefix/bin/z23" ] \
        || die "selftest: stable macOS z23 name does not resolve to its generation"
    [ -f "$launchd/org.z23.zclassic.plist" ] \
        || die "selftest: macOS install did not commit a launchd plist"
    grep -q '&amp; native/bin/z23' "$launchd/org.z23.zclassic.plist" \
        || die "selftest: launchd binary path was not XML escaped"
    grep -q -- '-tor' "$launchd/org.z23.zclassic.plist" \
        || die "selftest: launchd node does not enable embedded Tor"
    if [ "$(uname -s)" = Darwin ]; then
        /usr/bin/plutil -lint "$launchd/org.z23.zclassic.plist" >/dev/null \
            || die "selftest: Apple's plutil rejected the launchd plist"
    fi

    # Readiness can succeed while launchd is still running other bytes. The
    # exact txt-vnode digest must catch that and restore v1 automatically.
    rc=0
    PATH="$mock:$PATH" Z23_INSTALL_TEST_PLATFORM=Darwin \
        Z23_SKIP_SYSTEMD=0 Z23_INSTALL_PREFIX="$prefix" \
        Z23_LAUNCHD_DIR="$launchd" Z23_DATADIR="$datadir" \
        Z23_INSTALL_TEST_WRONG_IMAGE=1 \
        Z23_INSTALL_TEST_LAUNCHCTL_LOG="$mac/launchctl.log" \
        Z23_INSTALL_TEST_LAUNCHD_STATE="$mac/launchd.state" \
        "$SCRIPT_DIR/install_z23.sh" --source="$mac/v2" \
        >/dev/null 2>"$mac/wrong-image.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: wrong running Mac image must refuse"
    grep -q 'was rolled back' "$mac/wrong-image.err" \
        || die "selftest: wrong running Mac image did not name rollback: $(tr '\n' ';' <"$mac/wrong-image.err")"
    [ "$(readlink "$prefix/lib/z23/current")" = "generations/$v1_id" ] \
        || die "selftest: wrong running Mac image did not restore v1"

    # A typed bootwait failure is the other rollback edge.
    rc=0
    PATH="$mock:$PATH" Z23_INSTALL_TEST_PLATFORM=Darwin \
        Z23_SKIP_SYSTEMD=0 Z23_INSTALL_PREFIX="$prefix" \
        Z23_LAUNCHD_DIR="$launchd" Z23_DATADIR="$datadir" \
        Z23_INSTALL_TEST_READY_FAIL=1 \
        Z23_INSTALL_TEST_LAUNCHCTL_LOG="$mac/launchctl.log" \
        Z23_INSTALL_TEST_LAUNCHD_STATE="$mac/launchd.state" \
        "$SCRIPT_DIR/install_z23.sh" --source="$mac/v2" \
        >/dev/null 2>"$mac/not-ready.err" || rc=$?
    [ "$rc" -eq 1 ] || die "selftest: unready Mac generation must refuse"
    [ "$(readlink "$prefix/lib/z23/current")" = "generations/$v1_id" ] \
        || die "selftest: unready Mac generation did not restore v1"

    out="$(PATH="$mock:$PATH" Z23_INSTALL_TEST_PLATFORM=Darwin \
        Z23_SKIP_SYSTEMD=0 Z23_INSTALL_PREFIX="$prefix" \
        Z23_LAUNCHD_DIR="$launchd" Z23_DATADIR="$datadir" \
        Z23_INSTALL_TEST_LAUNCHCTL_LOG="$mac/launchctl.log" \
        Z23_INSTALL_TEST_LAUNCHD_STATE="$mac/launchd.state" \
        "$SCRIPT_DIR/install_z23.sh" --source="$mac/v2" \
        2>"$mac/v2.err")" || die "selftest: ready macOS upgrade failed"
    [ "$out" = "$NEXT_COMMAND" ] \
        || die "selftest: macOS upgrade did not print one next command"
    [ "$(readlink "$prefix/lib/z23/current")" = "generations/$v2_id" ] \
        || die "selftest: ready Mac upgrade did not activate v2"
    [ "$(readlink "$prefix/lib/z23/last-good")" = "generations/$v1_id" ] \
        || die "selftest: ready Mac upgrade did not retain v1 as last-good"
    grep -q '^bootstrap gui/' "$mac/launchctl.log" \
        || die "selftest: macOS lifecycle did not use launchctl bootstrap"
    grep -q '^bootout gui/' "$mac/launchctl.log" \
        || die "selftest: macOS lifecycle did not use launchctl bootout"
    grep -q '^kickstart -k gui/' "$mac/launchctl.log" \
        || die "selftest: macOS lifecycle did not use launchctl kickstart"
}

selftest() {
    selftest_prepare
    selftest_prepare_curl_mock
    selftest_local_refusals
    selftest_remote_authority
    selftest_remote_pins
    selftest_remote_success
    selftest_remote_bounds
    selftest_remote_manifest_and_signal
    selftest_local_success
    selftest_local_manifest_refusals
    selftest_release_pin
    selftest_macos_transaction
    selftest_front_door

    say "selftest PASS"
    trap - EXIT
    chmod -R u+w "$SELFTEST_TMP" 2>/dev/null || true
    rm -rf "$SELFTEST_TMP"
    SELFTEST_TMP=""
}

SOURCE="${Z23_RELEASE_SOURCE:-}"
EXPECTED_MANIFEST_SHA256="${Z23_RELEASE_MANIFEST_SHA256:-}"
ATTEST_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) selftest; exit 0 ;;
        --source=*) SOURCE="${1#--source=}"; shift ;;
        --source)
            [ $# -ge 2 ] || die "--source needs a url or directory"
            SOURCE="$2"
            shift 2
            ;;
        --attest=*)
            ATTEST_ARG="${1#--attest=}"
            case "$ATTEST_ARG" in
                *=*) ;;
                *) die "--attest needs <origin>=<pin>" ;;
            esac
            attest_record "${ATTEST_ARG%%=*}" "${ATTEST_ARG#*=}"
            shift
            ;;
        --attest-unreachable=*)
            ATTEST_ARG="${1#--attest-unreachable=}"
            case "$ATTEST_ARG" in
                *=*) ;;
                *) die "--attest-unreachable needs <origin>=<reason>" ;;
            esac
            attest_record_unreachable "${ATTEST_ARG%%=*}" "${ATTEST_ARG#*=}"
            shift
            ;;
        --manifest-sha256=*) EXPECTED_MANIFEST_SHA256="${1#*=}"; shift ;;
        --manifest-sha256)
            [ $# -ge 2 ] || die "--manifest-sha256 needs a SHA-256 digest"
            EXPECTED_MANIFEST_SHA256="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,22p' "$0"
            exit 0
            ;;
        --*) die "unknown argument: $1" ;;
        *)
            if [ -z "$SOURCE" ]; then
                SOURCE="$1"
                shift
            else
                die "unexpected extra argument: $1"
            fi
            ;;
    esac
done

if [ "$ATTEST_OK_COUNT" -gt 0 ] || [ -n "$ATTEST_DOWN" ]; then
    attest_resolve_manifest
    if [ -n "$EXPECTED_MANIFEST_SHA256" ] \
        && [ "$EXPECTED_MANIFEST_SHA256" != "$ATTESTED_MANIFEST_SHA256" ]; then
        die "--manifest-sha256 disagrees with the pin the attesting sources agreed on"
    fi
    EXPECTED_MANIFEST_SHA256="$ATTESTED_MANIFEST_SHA256"
fi

install_from_source "$SOURCE" "$EXPECTED_MANIFEST_SHA256"
