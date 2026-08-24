#!/usr/bin/env bash
# check_onion_pair_watch.sh — drive the shipped onion_pair_watch.sh and
# assert its source-isolation contract plus pair_probe.jsonl schema.
#
# This is a collector, not a reimplementation of the probe: it runs
# tools/scripts/onion_pair_watch.sh --selftest (which sources
# isolated_node_env.sh and writes one real ledger line through append_probe)
# and then validates every JSONL line with jsonq.
#
# No Python. No mocked probe. A named miss in the live ledger is a valid
# observation; a crash, empty append, prose verdict, or executing the
# isolation helper is not.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
WATCH="$ROOT/tools/scripts/onion_pair_watch.sh"
LOOP="$ROOT/tools/scripts/onion_pair_watch_loop.sh"
HELPER="$ROOT/tools/scripts/isolated_node_env.sh"
LEDGER=${PAIR_PROBE_FILE:-"${XDG_STATE_HOME:-$HOME/.local/state}/zclassic23-referee/pair_probe.jsonl"}
JSONQ=${ZCL_JSONQ:-"$ROOT/build/bin/jsonq"}

die() {
    printf 'check_onion_pair_watch: FAIL: %s\n' "$*" >&2
    exit 1
}

[ -f "$WATCH" ] || die "missing $WATCH"
[ -f "$LOOP" ] || die "missing $LOOP"
[ -f "$HELPER" ] || die "missing $HELPER"
[ -x "$JSONQ" ] || die "jsonq not built at $JSONQ (run make jsonq)"

# Structural: this shipped probe is bash. The repository-wide no-runtime gate
# owns interpreter-path enforcement; duplicating its regex here self-matches.
head -n 1 "$WATCH" | grep -q '^#!/usr/bin/env bash$' \
    || die "onion_pair_watch.sh must start with #!/usr/bin/env bash"

# Structural: sources isolated_node_env.sh; does not execute it.
if ! grep -E '^[[:space:]]*\. .*isolated_node_env\.sh' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh does not source isolated_node_env.sh"
fi
if grep -E '^[[:space:]]*(bash |sh |exec )?("\$[^"]+"|[[:alnum:]_./-]+)*isolated_node_env\.sh([[:space:]]|$)' "$WATCH" \
    | grep -v -E '^[[:space:]]*\.' >/dev/null 2>&1; then
    die "onion_pair_watch.sh executes isolated_node_env.sh instead of sourcing it"
fi
if grep -E '^[[:space:]]*iso_spawn_node( |$)' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must not call iso_spawn_node (that helper is -regtest)"
fi
if ! grep -F 'Dynhost stream: initiated stream' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must observe this fork's Dynhost stream client log"
fi
if ! grep -F 'DESCRIPTOR PUBLICATION observed' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must gate client launch on DESCRIPTOR PUBLICATION observed"
fi
if ! grep -F 'Uploaded hidden service descriptor' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh must observe the HSDir status-200 upload line"
fi
# Launch order: descriptor_publication_observed must appear before STAGE=spawn_b.
desc_line=$(grep -n 'descriptor_publication_observed' "$WATCH" | head -1 | cut -d: -f1)
spawn_b_line=$(grep -n '^STAGE=spawn_b$' "$WATCH" | head -1 | cut -d: -f1)
case $desc_line in ''|*[!0-9]*) die "could not find descriptor_publication_observed" ;; esac
case $spawn_b_line in ''|*[!0-9]*) die "could not find STAGE=spawn_b" ;; esac
if [ "$desc_line" -ge "$spawn_b_line" ]; then
    die "client spawn (STAGE=spawn_b line $spawn_b_line) must follow descriptor_publication_observed (line $desc_line)"
fi
if ! grep -E 'PAIR_WATCH_POLL:-[0-9]+' "$WATCH" >/dev/null 2>&1; then
    die "onion_pair_watch.sh missing PAIR_WATCH_POLL default"
fi
if grep -E 'git (commit|push)|deploy/devfleet/pair_probe\.jsonl' \
    "$WATCH" "$LOOP" >/dev/null 2>&1; then
    die "recurring pair telemetry must not commit, push, or write the tracked tree"
fi
poll_default=$(sed -n 's/^PAIR_POLL=\${PAIR_WATCH_POLL:-\([0-9]*\)}/\1/p' "$WATCH" | head -1)
case $poll_default in
    ''|*[!0-9]*) die "could not parse PAIR_WATCH_POLL default" ;;
esac
if [ "$poll_default" -lt 150 ]; then
    die "PAIR_WATCH_POLL default is ${poll_default}s; paired_at_s~68s needs >=150s"
fi

validate_line() {
    local line=$1 src=$2
    local ts head_sha verdict paired_at dial rend desc
    [ -n "$line" ] || die "$src: empty line"
    ts=$(printf '%s' "$line" | "$JSONQ" get ts 2>/dev/null || true)
    head_sha=$(printf '%s' "$line" | "$JSONQ" get head_sha 2>/dev/null || true)
    verdict=$(printf '%s' "$line" | "$JSONQ" get verdict 2>/dev/null || true)
    paired_at=$(printf '%s' "$line" | "$JSONQ" get paired_at_s 2>/dev/null || true)
    dial=$(printf '%s' "$line" | "$JSONQ" get dial_attempted 2>/dev/null || true)
    rend=$(printf '%s' "$line" | "$JSONQ" get rendezvous_seen 2>/dev/null || true)
    desc=$(printf '%s' "$line" | "$JSONQ" get descriptor_uploaded 2>/dev/null || true)

    [ -n "$ts" ] || die "$src: missing ts"
    case $head_sha in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
        *) die "$src: head_sha is not hex (got '${head_sha:-empty}')" ;;
    esac
    case $verdict in
        [A-Z][A-Z0-9_]*) ;;
        *) die "$src: verdict is not a named token (got '${verdict:-empty}')" ;;
    esac
    case $verdict in
        *' '*) die "$src: verdict contains whitespace: $verdict" ;;
    esac
    case $paired_at in
        null|''|[0-9]|[0-9][0-9]|[0-9][0-9][0-9]|[0-9][0-9][0-9][0-9]) ;;
        *) die "$src: paired_at_s must be numeric or null (got '$paired_at')" ;;
    esac
    if [ "$verdict" = PAIRED ]; then
        case $paired_at in
            ''|null) die "$src: PAIRED line must have numeric paired_at_s" ;;
        esac
    fi
    case $dial in true|false) ;; *) die "$src: dial_attempted must be JSON boolean (got '$dial')" ;; esac
    case $rend in true|false) ;; *) die "$src: rendezvous_seen must be JSON boolean (got '$rend')" ;; esac
    case $desc in true|false) ;; *) die "$src: descriptor_uploaded must be JSON boolean (got '$desc')" ;; esac
}

# Drive the shipped script: --selftest sources the isolation helper and
# writes one ledger line through the same append_probe the live path uses.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl23-pairwatch-check-XXXXXX")
trap 'rm -rf "$tmp"' EXIT
self_ledger="$tmp/pair_probe.jsonl"
if ! PAIR_PROBE_FILE="$self_ledger" "$WATCH" --selftest >"$tmp/selftest.out" 2>"$tmp/selftest.err"; then
    cat "$tmp/selftest.out" >&2 || true
    cat "$tmp/selftest.err" >&2 || true
    die "onion_pair_watch.sh --selftest exited non-zero"
fi
if ! grep -a "sourced isolated_node_env.sh" "$tmp/selftest.out" >/dev/null 2>&1; then
    die "--selftest did not report sourcing isolated_node_env.sh"
fi
[ -s "$self_ledger" ] || die "--selftest did not append a JSONL line"
while IFS= read -r line; do
    [ -z "$line" ] && continue
    validate_line "$line" "$self_ledger"
done <"$self_ledger"

# Live ledger, when present, must tell the truth in the same schema.
if [ -f "$LEDGER" ]; then
    live_n=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        live_n=$((live_n + 1))
        validate_line "$line" "$LEDGER:$live_n"
    done <"$LEDGER"
    echo "check_onion_pair_watch: OK (selftest + $live_n live ledger line(s))"
else
    echo "check_onion_pair_watch: OK (selftest; live ledger not yet present)"
fi
exit 0
