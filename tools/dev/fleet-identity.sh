#!/usr/bin/env bash
# fleet-identity.sh — publish and check a box's INSTALL IDENTITY.
#
# An install identity is a stable name tag for fleet coordination. It is a
# CONVENIENCE TIER only. Nothing in consensus, custody, datadir handling, or
# deployment may depend on it, and this script gives them no way to.
#
# The claim stays exactly this small:
#   same install — NOT same chip, NOT safe machine.
#
# Everything it reads is world-readable, so no box ever needs elevation to
# publish or check its own identity. That is deliberate: an identity file that
# needs root is one that gets skipped on the host where it mattered.
#
# WHY THE PUBLISHED VALUES ARE SALTED. The natural name for an installation is
# a hash of its SSH host public keys. Published raw, that is a locator: internet
# scan services index host key blobs, so anyone holding scan data could test a
# scanned address against the committed file and place a box. This fleet commits
# onion addresses precisely so committed files never reveal location, and a raw
# hostkey hash would quietly undo that. So every published value is
# sha256(SALT || raw), with the salt in the operator's uncommitted env. The file
# stays a stable pin for whoever holds the salt and is opaque to everyone else.
#
# Consequence worth stating plainly: rotating the salt renames every box. The
# salt is fleet configuration, not a secret whose loss is dangerous — losing it
# costs you the old pins, nothing more.
#
# ID_SCHEME=z23-install-v1 fields, all sha256(SALT || raw):
#   INSTALL_ID   the pin, over this box's SSH host public keys: for each
#                /etc/ssh/ssh_host_*.pub take "<algo> <blob>" (the trailing
#                comment is dropped so a hostname rename does not move the
#                name), sorted. See RECIPE in the file.
#   MACHINE_TAG  over /etc/machine-id. Distinguishes two installations that
#                share a copied host key. systemd calls the raw value
#                confidential; salting is what lets this be published at all.
#   BOOT_TAG     over /proc/sys/kernel/random/boot_id at publication. Changes
#                every reboot by design; it explains heartbeat gaps, and it is
#                NEVER part of the pin.
#
# Committed files carry no address, hostname, username, or local path, per the
# devfleet privacy rule. Where a box answers is reachability, not identity, and
# lives in the uncommitted operator env beside the salt:
#   ZCL_FLEET_ID_SALT=<hex>
#   ZCL_FLEET_NODE<N>_ADDR=<ssh destination>
#
# TRUST ON FIRST USE. The committed .identity file IS the pin. A changed
# INSTALL_ID or MACHINE_TAG is an EVENT that gets flagged; this script never
# silently overwrites a pin. A changed BOOT_TAG is normal and is reported as
# information, not as an event.
#
# OPTIONAL UPGRADE, dormant and owner-gated. Some boxes have an fTPM that could
# back a METAL_TIER field with chip-bound evidence. Enrolling it needs root, so
# only the owner may decide to do it. Agents never request it, nothing waits on
# it, and the absence of METAL_TIER is entirely normal — this tool neither
# creates that field nor complains about its absence.
#
# Usage:
#   tools/dev/fleet-identity.sh init
#   tools/dev/fleet-identity.sh gather --node N [--ssh DEST] [--force]
#   tools/dev/fleet-identity.sh verify --node N [--ssh DEST]
#   tools/dev/fleet-identity.sh show   --node N
#   tools/dev/fleet-identity.sh status
#
# A remote node is reached at its env address; --ssh DEST overrides for a
# one-off. The ssh handshake is what proves the values came from DEST. Raw
# values are salted here, on the operator's box, so remote boxes never need
# the salt at all.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

FLEET_DIR="${ZCL_FLEET_DIR:-$REPO/deploy/devfleet}"
FLEET_ENV="${ZCL_FLEET_ENV:-$HOME/.config/zclassic23-fleetsync/fleet.env}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
SCHEME=z23-install-v1

say() { printf '\033[1mfleet-identity:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mfleet-identity: REFUSE:\033[0m %s\n' "$*" >&2; exit 1; }

NODE=""; SSH_HOST=""; SSH_EXPLICIT=0; FORCE=0
CMD="${1:-}"
[ $# -gt 0 ] && shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --node)   NODE="${2:-}"; shift ;;
        --node=*) NODE="${1#*=}" ;;
        --ssh)    SSH_HOST="${2:-}"; SSH_EXPLICIT=1; shift ;;
        --ssh=*)  SSH_HOST="${1#*=}"; SSH_EXPLICIT=1 ;;
        --force)  FORCE=1 ;;
        -h|--help) sed -n '2,68p' "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

case "$CMD" in
    init|gather|verify|show|status) : ;;
    ""|-h|--help) sed -n '2,68p' "$0"; exit 0 ;;
    *) die "unknown command '$CMD' (init|gather|verify|show|status)" ;;
esac

# Parsed, never sourced: the env is configuration, not code to execute.
env_val() {
    [ -f "$FLEET_ENV" ] || return 1
    awk -F= -v k="$1" '$0 !~ /^[[:space:]]*#/ && $1==k { print $2; exit }' "$FLEET_ENV"
}

if [ "$CMD" = init ]; then
    mkdir -p "$(dirname "$FLEET_ENV")"
    if [ -f "$FLEET_ENV" ] && env_val ZCL_FLEET_ID_SALT | grep -q .; then
        die "$FLEET_ENV already has a salt.
  Rotating it renames every box and invalidates every committed pin. If that
  is really what you want, edit the file by hand."
    fi
    umask 077
    touch "$FLEET_ENV"; chmod 0600 "$FLEET_ENV"
    {
        printf '# Fleet identity + reachability. UNCOMMITTED, operator-local.\n'
        printf '# Salt for tools/dev/fleet-identity.sh. Rotating it renames every box.\n'
        printf 'ZCL_FLEET_ID_SALT=%s\n' "$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        printf '# One ssh destination per node. A node with no entry is this box.\n'
        printf '# ZCL_FLEET_NODE1_ADDR=<ssh destination>\n'
    } >> "$FLEET_ENV"
    say "wrote $FLEET_ENV (mode 0600) — add your ZCL_FLEET_NODE<N>_ADDR lines"
    exit 0
fi

if [ "$CMD" != show ]; then
    SALT="$(env_val ZCL_FLEET_ID_SALT || true)"
    [ -n "$SALT" ] || die "no ZCL_FLEET_ID_SALT in $FLEET_ENV.
  Published values are salted so a committed file cannot be used to locate a
  box by matching internet scan data. Create one:
    tools/dev/fleet-identity.sh init"
fi

if [ "$CMD" != status ]; then
    # The node number is the operator's fleet label. Guessing it from a
    # hostname would publish a box under a name nobody chose, so refuse.
    [ -n "$NODE" ] || NODE="${ZCL_FLEET_NODE:-}"
    [ -n "$NODE" ] || die "--node N is required (this box's fleet label)"
    case "$NODE" in ''|*[!0-9]*) die "--node must be a plain number, got '$NODE'" ;; esac
fi
PIN_FILE="$FLEET_DIR/node${NODE}.identity"

# Resolve where node $1 lives: explicit --ssh wins, then the env, then this box.
resolve_target() {
    [ "$SSH_EXPLICIT" -eq 1 ] && return 0
    SSH_HOST="$(env_val "ZCL_FLEET_NODE$1_ADDR" || true)"
}

salted() { { printf '%s\n' "$SALT"; printf '%s\n' "$1"; } | sha256sum | cut -d' ' -f1; }

# ── observation ─────────────────────────────────────────────────────────────
# One remote round trip, not three. Raw values never leave this function's
# caller unsalted, and never reach a committed file at all.
OBSERVE_SNIPPET='
  cat /etc/ssh/ssh_host_*.pub 2>/dev/null \
    | awk "NF>=2 {print \$1, \$2}" | LC_ALL=C sort | sha256sum | cut -d" " -f1
  cat /etc/machine-id 2>/dev/null || echo -
  cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo -
'
observe() {
    local out
    if [ -n "$SSH_HOST" ]; then
        out="$(ssh "${SSH_OPTS[@]}" "$SSH_HOST" "$OBSERVE_SNIPPET" 2>/dev/null)" \
            || die "cannot observe node over ssh"
    else
        out="$(eval "$OBSERVE_SNIPPET")" || die "cannot observe this box"
    fi
    local hk; hk="$(sed -n 1p <<<"$out")"
    case "$hk" in ''|*[!0-9a-f]*) die "no readable SSH host keys on the target" ;; esac
    O_INSTALL="$(salted "$hk")"
    O_MACHINE="$(salted "$(sed -n 2p <<<"$out")")"
    O_BOOT="$(salted "$(sed -n 3p <<<"$out")")"
}

write_file() {
    local out="$1"
    {
        printf '# node%s install identity — convenience tier, never security-critical.\n' "$NODE"
        printf '\n'
        printf 'BOX=node%s\n' "$NODE"
        printf 'ID_SCHEME=%s\n' "$SCHEME"
        printf 'INSTALL_ID=%s\n' "$O_INSTALL"
        printf 'MACHINE_TAG=%s\n' "$O_MACHINE"
        printf 'BOOT_TAG=%s\n' "$O_BOOT"
        printf 'CLAIM=identifies-this-installation-only-not-hardware\n'
        printf 'OBSERVED=%s\n' "$(date -u +%Y-%m-%d)"
        printf '\n'
        printf '# Every value above is sha256(SALT || raw) with the salt held only in the\n'
        printf '# operator env. Raw host keys and machine-id are never committed: a raw\n'
        printf '# hostkey hash would let anyone with internet scan data match a scanned\n'
        printf '# address to this box, which is exactly what committing onions avoids.\n'
        printf '#\n'
        printf '# RECIPE for INSTALL_ID, for a reader who holds the salt:\n'
        printf '#   { printf "%%s\\\\n" "$ZCL_FLEET_ID_SALT"; \\\n'
        printf '#     cat /etc/ssh/ssh_host_*.pub | awk "NF>=2 {print \\$1, \\$2}" \\\n'
        printf '#       | LC_ALL=C sort | sha256sum | cut -d" " -f1; } | sha256sum\n'
        printf '# The trailing key comment is dropped on purpose: renaming the host must\n'
        printf '# not move the name of the installation.\n'
        printf '#\n'
        printf '# No address appears here, per the devfleet privacy rule. Where the box\n'
        printf '# answers is reachability, not identity, and lives in the operator env.\n'
        printf '#\n'
        printf '# BOOT_TAG changes on every reboot by design. It is recorded to explain\n'
        printf '# heartbeat gaps and is NOT part of the pin.\n'
        printf '#\n'
        printf '# METAL_TIER is an optional owner-gated field that is absent here, which is\n'
        printf '# normal. Nothing reads for it, nothing waits on it.\n'
    } > "$out"
}

pin_field() { awk -F= -v k="$1" '$1==k {print $2; exit}' "$2"; }

# ── commands ────────────────────────────────────────────────────────────────
case "$CMD" in
show)
    [ -f "$PIN_FILE" ] || die "no pin at $PIN_FILE"
    cat "$PIN_FILE"
    ;;

gather)
    mkdir -p "$FLEET_DIR"
    if [ -f "$PIN_FILE" ] && [ "$FORCE" -eq 0 ]; then
        die "$PIN_FILE already exists.
  A committed .identity is a PIN. Overwriting it silently is exactly what the
  trust-on-first-use rule exists to prevent. Run 'verify'; if the identity
  really did change, that is an EVENT to record deliberately, then --force."
    fi
    resolve_target "$NODE"
    observe
    tmp="$(mktemp "$FLEET_DIR/.node${NODE}.identity.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    write_file "$tmp"
    mv "$tmp" "$PIN_FILE"
    trap - EXIT
    chmod 0644 "$PIN_FILE"
    say "wrote $PIN_FILE"
    ;;

verify)
    [ -f "$PIN_FILE" ] || die "no pin at $PIN_FILE — run 'gather' first"
    [ "$(pin_field ID_SCHEME "$PIN_FILE")" = "$SCHEME" ] \
        || die "$PIN_FILE is not $SCHEME"
    want_id="$(pin_field INSTALL_ID "$PIN_FILE")"
    want_mt="$(pin_field MACHINE_TAG "$PIN_FILE")"
    pin_boot="$(pin_field BOOT_TAG "$PIN_FILE")"
    resolve_target "$NODE"
    observe
    rc=0
    if [ "$O_INSTALL" != "$want_id" ]; then
        printf 'IDENTITY_EVENT node=%s reason=install-id-changed pinned=%s observed=%s\n' \
            "$NODE" "$want_id" "$O_INSTALL"
        rc=3
    fi
    if [ "$O_MACHINE" != "$want_mt" ]; then
        printf 'IDENTITY_EVENT node=%s reason=machine-tag-changed pinned=%s observed=%s\n' \
            "$NODE" "$want_mt" "$O_MACHINE"
        rc=3
    fi
    if [ "$rc" -ne 0 ]; then
        printf '  The pin was NOT overwritten. Record the event, then --force if\n'
        printf '  the change was intended. A salt rotation also lands here.\n'
        exit "$rc"
    fi
    if [ "$O_BOOT" != "$pin_boot" ]; then
        printf 'IDENTITY_OK node=%s id=%s (rebooted since pin)\n' "$NODE" "$O_INSTALL"
    else
        printf 'IDENTITY_OK node=%s id=%s\n' "$NODE" "$O_INSTALL"
    fi
    ;;

status)
    rc=0; n_ok=0; n_ev=0; n_un=0
    seen_ids=()
    shopt -s nullglob
    files=("$FLEET_DIR"/node*.identity)
    [ ${#files[@]} -gt 0 ] || die "no identity files in $FLEET_DIR"
    for f in "${files[@]}"; do
        n="$(basename "$f" .identity)"; n="${n#node}"
        want="$(pin_field INSTALL_ID "$f")"
        SSH_EXPLICIT=0; SSH_HOST=""
        resolve_target "$n"
        if ! ( observe ) >/dev/null 2>&1; then
            printf 'IDENTITY_UNREACHABLE node=%-3s\n' "$n"
            n_un=$((n_un+1))
            continue
        fi
        observe
        if [ "$O_INSTALL" = "$want" ]; then
            printf 'IDENTITY_OK          node=%-3s id=%s…\n' "$n" "${want:0:16}"
            n_ok=$((n_ok+1))
        else
            printf 'IDENTITY_EVENT       node=%-3s pinned=%s… observed=%s…\n' \
                "$n" "${want:0:16}" "${O_INSTALL:0:16}"
            n_ev=$((n_ev+1)); rc=3
        fi
        seen_ids+=("$O_INSTALL $n")
    done

    # Two fleet slots resolving to one installation is not a passing fleet: it
    # means a node number points at a box already answering under another
    # number, so anything written "by node A" may be node B.
    if [ ${#seen_ids[@]} -gt 0 ]; then
        dupes="$(printf '%s\n' "${seen_ids[@]}" | LC_ALL=C sort \
                 | awk '{ids[$1]=ids[$1]" "$2; n[$1]++} END{for(i in n) if(n[i]>1) print i, ids[i]}')"
        if [ -n "$dupes" ]; then
            while read -r id nodes; do
                [ -n "$id" ] || continue
                printf 'IDENTITY_EVENT       reason=shared-install id=%s… nodes=%s\n' \
                    "${id:0:16}" "$(printf '%s' "$nodes" | tr -s ' ' ',')"
                n_ev=$((n_ev+1))
            done <<<"$dupes"
            rc=3
        fi
    fi

    # A fleet that was not fully checked must not exit 0. Silence from an
    # unreachable box is absence of evidence, and reporting it as agreement is
    # the failure mode this whole file exists to avoid.
    printf 'IDENTITY_SUMMARY nodes=%s ok=%s events=%s unreachable=%s\n' \
        "${#files[@]}" "$n_ok" "$n_ev" "$n_un"
    [ "$rc" -eq 0 ] && [ "$n_un" -gt 0 ] && rc=4
    exit $rc
    ;;
esac
