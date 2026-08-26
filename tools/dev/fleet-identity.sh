#!/usr/bin/env bash
# fleet-identity.sh — record and check a box's INSTALL IDENTITY.
#
# An install identity is a stable name tag an operator uses to tell their own
# machines apart. It is a CONVENIENCE TIER only. Nothing in consensus,
# custody, datadir handling, or deployment may depend on it, and this script
# gives them no way to.
#
# The claim stays exactly this small:
#   same install — NOT same chip, NOT safe machine.
#
# NOTHING HERE IS EVER COMMITTED. Pins are per-operator state and live under
#   ${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23/fleet/<box>.identity
# outside any checkout. This repository designates no fleet and knows about
# no boxes: which machines you run, and how many, is your business.
#
# Everything it reads is world-readable, so no box ever needs elevation to
# record or check its own identity. That is deliberate: an identity file that
# needs root is one that gets skipped on the host where it mattered.
#
# WHY THE STORED VALUES ARE SALTED. The natural name for an installation is a
# hash of its SSH host public keys. Written down raw, that is a locator:
# internet scan services index host key blobs, so anyone who ever saw the file
# could test a scanned address against it and place a box. So every stored
# value is sha256(SALT || raw), with the salt in the operator's uncommitted
# env. The file stays a stable pin for whoever holds the salt and is opaque to
# everyone else — including anyone who later gets a copy of it.
#
# Consequence worth stating plainly: rotating the salt renames every box. The
# salt is operator configuration, not a secret whose loss is dangerous —
# losing it costs you the old pins, nothing more.
#
# ID_SCHEME=z23-install-v1 fields, all sha256(SALT || raw):
#   INSTALL_ID   the pin, over this box's SSH host public keys: for each
#                /etc/ssh/ssh_host_*.pub take "<algo> <blob>" (the trailing
#                comment is dropped so a hostname rename does not move the
#                name), sorted. See RECIPE in the file.
#   MACHINE_TAG  over /etc/machine-id. Distinguishes two installations that
#                share a copied host key. systemd calls the raw value
#                confidential; salting is what lets it be written at all.
#   BOOT_TAG     over /proc/sys/kernel/random/boot_id when the pin was taken.
#                Changes every reboot by design; it explains a gap in a box's
#                reporting, and it is NEVER part of the pin.
#
# No address, hostname, username, or local path is ever stored in a pin file.
# Where a box answers is reachability, not identity, and lives in the
# uncommitted operator env beside the salt:
#   ZCL_FLEET_ID_SALT=<hex>
#   ZCL_FLEET_<LABEL>_ADDR=<ssh destination>
#
# TRUST ON FIRST USE. The stored .identity file IS the pin. A changed
# INSTALL_ID or MACHINE_TAG is an EVENT that gets flagged; this script never
# silently overwrites a pin. A changed BOOT_TAG is normal and is reported as
# information, not as an event.
#
# OPTIONAL UPGRADE, dormant and owner-gated. Some boxes have an fTPM that
# could back a METAL_TIER field with chip-bound evidence. Enrolling it needs
# root, so only the machine's owner may decide to do it. Nothing here requests
# it, nothing waits on it, and the absence of METAL_TIER is entirely normal:
# this tool neither creates that field nor complains about its absence.
#
# Usage:
#   tools/dev/fleet-identity.sh init
#   tools/dev/fleet-identity.sh gather --box LABEL [--ssh DEST] [--force]
#   tools/dev/fleet-identity.sh verify --box LABEL [--ssh DEST]
#   tools/dev/fleet-identity.sh show   --box LABEL
#   tools/dev/fleet-identity.sh status
#
# A box label is whatever you call that machine. `--node N` is shorthand for
# `--box nodeN`. A remote box is reached at its env address; --ssh DEST
# overrides for a one-off. The ssh handshake is what proves the values came
# from DEST. Raw values are salted here, on the operator's own box, so remote
# boxes never need the salt at all.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

# fleet_state_dir(): the one definition of where local mesh state lives.
# shellcheck source=tools/scripts/fleet_source_status.sh
. "$REPO/tools/scripts/fleet_source_status.sh"

FLEET_DIR="${ZCL_FLEET_DIR:-$(fleet_state_dir)}"
FLEET_ENV="${ZCL_FLEET_ENV:-$HOME/.config/zclassic23-fleetsync/fleet.env}"
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)
SCHEME=z23-install-v1
HELP_LINES='2,73p'

say() { printf '\033[1mfleet-identity:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mfleet-identity: REFUSE:\033[0m %s\n' "$*" >&2; exit 1; }

BOXLABEL=""; SSH_HOST=""; SSH_EXPLICIT=0; FORCE=0
CMD="${1:-}"
[ $# -gt 0 ] && shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --box)    BOXLABEL="${2:-}"; shift ;;
        --box=*)  BOXLABEL="${1#*=}" ;;
        --node)   BOXLABEL="node${2:-}"; shift ;;
        --node=*) BOXLABEL="node${1#*=}" ;;
        --ssh)    SSH_HOST="${2:-}"; SSH_EXPLICIT=1; shift ;;
        --ssh=*)  SSH_HOST="${1#*=}"; SSH_EXPLICIT=1 ;;
        --force)  FORCE=1 ;;
        -h|--help) sed -n "$HELP_LINES" "$0"; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

case "$CMD" in
    init|gather|verify|show|status) : ;;
    ""|-h|--help) sed -n "$HELP_LINES" "$0"; exit 0 ;;
    *) die "unknown command '$CMD' (init|gather|verify|show|status)" ;;
esac

# Parsed, never sourced: the env is configuration, not code to execute.
env_val() {
    [ -f "$FLEET_ENV" ] || return 1
    awk -F= -v k="$1" '$0 !~ /^[[:space:]]*#/ && $1==k { print $2; exit }' "$FLEET_ENV"
}

if [ "$CMD" = init ]; then
    mkdir -p "$(dirname "$FLEET_ENV")"
    if [ -f "$FLEET_ENV" ] && [ -n "$(env_val ZCL_FLEET_ID_SALT || true)" ]; then
        die "$FLEET_ENV already has a salt.
  Rotating it renames every box and invalidates every pin you hold. If that
  is really what you want, edit the file by hand."
    fi
    umask 077
    touch "$FLEET_ENV"; chmod 0600 "$FLEET_ENV"
    {
        printf '# Mesh identity + reachability. UNCOMMITTED, operator-local.\n'
        printf '# Salt for tools/dev/fleet-identity.sh. Rotating it renames every box.\n'
        printf 'ZCL_FLEET_ID_SALT=%s\n' "$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        printf '# One ssh destination per box label, uppercased. A box with no\n'
        printf '# entry is assumed to be this machine.\n'
        printf '# ZCL_FLEET_<LABEL>_ADDR=<ssh destination>\n'
    } >> "$FLEET_ENV"
    say "wrote $FLEET_ENV (mode 0600) — add your ZCL_FLEET_<LABEL>_ADDR lines"
    exit 0
fi

# A clone with no mesh is the NORMAL case, not a failure: most people who run
# this project run one node and never label anything. Answer that before
# demanding a salt, so a stranger's first `status` explains itself instead of
# refusing over configuration they have no reason to have.
if [ "$CMD" = status ]; then
    shopt -s nullglob
    preflight=("$FLEET_DIR"/*.identity)
    if [ ${#preflight[@]} -eq 0 ]; then
        printf 'IDENTITY_SUMMARY no local mesh configured (%s)\n' "$FLEET_DIR"
        exit 0
    fi
fi

if [ "$CMD" != show ]; then
    SALT="$(env_val ZCL_FLEET_ID_SALT || true)"
    [ -n "$SALT" ] || die "no ZCL_FLEET_ID_SALT in $FLEET_ENV.
  Stored values are salted so a pin file cannot be used to locate a box by
  matching internet scan data. Create one:
    tools/dev/fleet-identity.sh init"
fi

if [ "$CMD" != status ]; then
    # The label is the operator's own name for the box. Guessing it from a
    # hostname would file a box under a name nobody chose, so refuse.
    [ -n "$BOXLABEL" ] || BOXLABEL="${ZCL_FLEET_BOX:-}"
    [ -n "$BOXLABEL" ] || die "--box LABEL is required (your own name for this machine)"
    case "$BOXLABEL" in
        *[!A-Za-z0-9_-]*|'') die "--box must be letters, digits, '-' or '_', got '$BOXLABEL'" ;;
    esac
fi
PIN_FILE="$FLEET_DIR/$BOXLABEL.identity"

# Resolve where box $1 lives: explicit --ssh wins, then the env, then this box.
resolve_target() {
    local key
    [ "$SSH_EXPLICIT" -eq 1 ] && return 0
    key="ZCL_FLEET_$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')_ADDR"
    SSH_HOST="$(env_val "$key" || true)"
}

salted() { { printf '%s\n' "$SALT"; printf '%s\n' "$1"; } | sha256sum | cut -d' ' -f1; }

# ── observation ─────────────────────────────────────────────────────────────
# One remote round trip, not three. Raw values never leave this function's
# caller unsalted, and never reach a stored file at all.
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
            || die "cannot observe box over ssh"
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
        printf '# %s install identity — convenience tier, never security-critical.\n' "$BOXLABEL"
        printf '\n'
        printf 'BOX=%s\n' "$BOXLABEL"
        printf 'ID_SCHEME=%s\n' "$SCHEME"
        printf 'INSTALL_ID=%s\n' "$O_INSTALL"
        printf 'MACHINE_TAG=%s\n' "$O_MACHINE"
        printf 'BOOT_TAG=%s\n' "$O_BOOT"
        printf 'CLAIM=identifies-this-installation-only-not-hardware\n'
        printf 'OBSERVED=%s\n' "$(date -u +%Y-%m-%d)"
        printf '\n'
        printf '# Every value above is sha256(SALT || raw) with the salt held only in the\n'
        printf '# operator env. Raw host keys and machine-id are never stored: a raw\n'
        printf '# hostkey hash would let anyone with internet scan data match a scanned\n'
        printf '# address to this box.\n'
        printf '#\n'
        printf '# RECIPE for INSTALL_ID, for a reader who holds the salt:\n'
        printf '#   { printf "%%s\\\\n" "$ZCL_FLEET_ID_SALT"; \\\n'
        printf '#     cat /etc/ssh/ssh_host_*.pub | awk "NF>=2 {print \\$1, \\$2}" \\\n'
        printf '#       | LC_ALL=C sort | sha256sum | cut -d" " -f1; } | sha256sum\n'
        printf '# The trailing key comment is dropped on purpose: renaming the host must\n'
        printf '# not move the name of the installation.\n'
        printf '#\n'
        printf '# No address appears here. Where the box answers is reachability, not\n'
        printf '# identity, and lives in the operator env.\n'
        printf '#\n'
        printf '# BOOT_TAG changes on every reboot by design. It is recorded to explain\n'
        printf '# a gap in this box reporting and is NOT part of the pin.\n'
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
  A stored .identity is a PIN. Overwriting it silently is exactly what the
  trust-on-first-use rule exists to prevent. Run 'verify'; if the identity
  really did change, that is an EVENT to record deliberately, then --force."
    fi
    resolve_target "$BOXLABEL"
    observe
    tmp="$(mktemp "$FLEET_DIR/.$BOXLABEL.identity.XXXXXX")"
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
    resolve_target "$BOXLABEL"
    observe
    rc=0
    if [ "$O_INSTALL" != "$want_id" ]; then
        printf 'IDENTITY_EVENT box=%s reason=install-id-changed pinned=%s observed=%s\n' \
            "$BOXLABEL" "$want_id" "$O_INSTALL"
        rc=3
    fi
    if [ "$O_MACHINE" != "$want_mt" ]; then
        printf 'IDENTITY_EVENT box=%s reason=machine-tag-changed pinned=%s observed=%s\n' \
            "$BOXLABEL" "$want_mt" "$O_MACHINE"
        rc=3
    fi
    if [ "$rc" -ne 0 ]; then
        printf '  The pin was NOT overwritten. Record the event, then --force if\n'
        printf '  the change was intended. A salt rotation also lands here.\n'
        exit "$rc"
    fi
    if [ "$O_BOOT" != "$pin_boot" ]; then
        printf 'IDENTITY_OK box=%s id=%s (rebooted since pin)\n' "$BOXLABEL" "$O_INSTALL"
    else
        printf 'IDENTITY_OK box=%s id=%s\n' "$BOXLABEL" "$O_INSTALL"
    fi
    ;;

status)
    rc=0; n_ok=0; n_ev=0; n_un=0
    seen_ids=()
    shopt -s nullglob
    files=("$FLEET_DIR"/*.identity)
    # A clone with no mesh is the normal case, not a failure: most people who
    # run this project run exactly one node and never label anything.
    if [ ${#files[@]} -eq 0 ]; then
        printf 'IDENTITY_SUMMARY no local mesh configured (%s)\n' "$FLEET_DIR"
        exit 0
    fi
    for f in "${files[@]}"; do
        b="$(basename "$f" .identity)"
        want="$(pin_field INSTALL_ID "$f")"
        SSH_EXPLICIT=0; SSH_HOST=""
        resolve_target "$b"
        if ! ( observe ) >/dev/null 2>&1; then
            printf 'IDENTITY_UNREACHABLE box=%-8s\n' "$b"
            n_un=$((n_un+1))
            continue
        fi
        observe
        if [ "$O_INSTALL" = "$want" ]; then
            printf 'IDENTITY_OK          box=%-8s id=%s…\n' "$b" "${want:0:16}"
            n_ok=$((n_ok+1))
        else
            printf 'IDENTITY_EVENT       box=%-8s pinned=%s… observed=%s…\n' \
                "$b" "${want:0:16}" "${O_INSTALL:0:16}"
            n_ev=$((n_ev+1)); rc=3
        fi
        seen_ids+=("$O_INSTALL $b")
    done

    # Two labels resolving to one installation is not a passing mesh: it means
    # a label points at a box already answering under another label, so
    # anything recorded "by box A" may be box B.
    if [ ${#seen_ids[@]} -gt 0 ]; then
        dupes="$(printf '%s\n' "${seen_ids[@]}" | LC_ALL=C sort \
                 | awk '{ids[$1]=ids[$1]" "$2; n[$1]++} END{for(i in n) if(n[i]>1) print i, ids[i]}')"
        if [ -n "$dupes" ]; then
            while read -r id boxes; do
                [ -n "$id" ] || continue
                printf 'IDENTITY_EVENT       reason=shared-install id=%s… boxes=%s\n' \
                    "${id:0:16}" "$(printf '%s' "$boxes" | tr -s ' ' ',')"
                n_ev=$((n_ev+1))
            done <<<"$dupes"
            rc=3
        fi
    fi

    # A mesh that was not fully checked must not exit 0. Silence from an
    # unreachable box is absence of evidence, and reporting it as agreement is
    # the failure mode this whole file exists to avoid.
    printf 'IDENTITY_SUMMARY boxes=%s ok=%s events=%s unreachable=%s\n' \
        "${#files[@]}" "$n_ok" "$n_ev" "$n_un"
    # Written as an `if`, not an `&&` chain: under `set -e` a chain whose
    # first test is false is a failing command list, and the shell would exit
    # 1 here instead of reaching `exit $rc` with the real verdict.
    if [ "$rc" -eq 0 ] && [ "$n_un" -gt 0 ]; then
        rc=4
    fi
    exit $rc
    ;;
esac
