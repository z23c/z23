#!/usr/bin/env bash
# Recover the isolated development lane from a wedged derived-state rebuild.
#
# This is intentionally a different transaction from deploy-dev-lane.sh:
# deployment changes executable generations, while recovery replaces only the
# NONCANONICAL dev datadir.  The old datadir (including any auto-reindex
# marker) is atomically archived and is never deleted.  A fresh datadir is
# populated with a block-index/header bundle plus a UTXO snapshot; the node's
# normal loader must then verify the snapshot body SHA3 and match its anchor to
# the copied validated header-chain location before RPC readiness counts as
# success. This is dev-lane recovery evidence, not state-sovereignty proof.
# Public operation is plan-only during Phase-0 containment. `--apply` always
# refuses; the mutation machinery is reachable only from its inherited-FD,
# fixture-bound hermetic self-test.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

MODE="plan"
RECOVERY_SELFTEST=0
SELFTEST_ROOT=""
SELFTEST_CAP_FD=""
REQUESTED_GENERATION="${ZCL_DEV_RECOVERY_GENERATION:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --plan|--dry-run) MODE="plan" ;;
        --apply) MODE="apply" ;;
        --generation=*) REQUESTED_GENERATION="${1#--generation=}" ;;
        --generation)
            shift
            [ $# -gt 0 ] || {
                echo "usage: $0 [--plan|--apply] [--generation=<id>]" >&2
                exit 2
            }
            REQUESTED_GENERATION="$1"
            ;;
        --self-test)
            exec bash "$REPO/tools/dev/recover-dev-lane-selftest.sh"
            ;;
        --internal-self-test)
            shift
            [ $# -ge 2 ] || {
                echo "recover-dev-lane: invalid internal self-test capability" >&2
                exit 3
            }
            RECOVERY_SELFTEST=1
            SELFTEST_ROOT="$1"
            shift
            SELFTEST_CAP_FD="$1"
            ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "usage: $0 [--plan|--apply|--self-test] [--generation=<id>]" >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$MODE" = "apply" ] && [ "$RECOVERY_SELFTEST" -ne 1 ]; then
    echo "recover-dev-lane: REFUSING — dev recovery apply is contained; planning remains read-only" >&2
    exit 3
fi
if [ "$RECOVERY_SELFTEST" -eq 1 ] && [ "$MODE" != "apply" ]; then
    echo "recover-dev-lane: internal self-test capability is apply-only" >&2
    exit 3
fi

UNIT="${ZCL_DEV_RECOVERY_UNIT:-zcl23-dev.service}"
DEV_DATADIR="${ZCL_DEV_RECOVERY_DATADIR:-$HOME/.zclassic-c23-dev}"
DEV_RPCPORT="${ZCL_DEV_RECOVERY_RPCPORT:-18252}"
GEN_ROOT="${ZCL_DEV_GENERATION_ROOT:-$HOME/.local/lib/zclassic23-dev}"
CURRENT_LINK="$GEN_ROOT/current"
LAST_GOOD_LINK="$GEN_ROOT/last-good"
STAGED_LINK="$GEN_ROOT/staged"
LOCK_PATH="$GEN_ROOT/activation.lock"
REJECTED_DIR="$GEN_ROOT/rejected"
REJECTED_HISTORY_DIR="$GEN_ROOT/rejected-history"
ACCEPTED_DIR="$GEN_ROOT/accepted"
STATE_DIR="${ZCL_DEV_WATCH_STATE_DIR:-$HOME/.local/state/zclassic23-dev}"
LOADER_DROPIN="$HOME/.config/systemd/user/zcl23-dev.service.d/80-snapshot-loader.conf"
BUILD_ID_DROPIN="$HOME/.config/systemd/user/zcl23-dev.service.d/90-build-identity.conf"
CLI="${ZCL_DEV_RECOVERY_CLI:-$REPO/build/bin/zclassic-cli}"
JSONQ="${ZCL_DEV_RECOVERY_JSONQ:-$REPO/build/bin/jsonq}"
# Default to the bundle already present in the dev datadir. It is copied and
# hash-checked before the old datadir is archived, so recovery does not depend
# on or even read the canonical lane. An explicit bundle directory/file pair
# remains available for an independently-proven replacement.
SOURCE_DIR="${ZCL_DEV_RECOVERY_BUNDLE_DIR:-$DEV_DATADIR}"
SOURCE_SNAPSHOT="${ZCL_DEV_RECOVERY_SNAPSHOT:-}"
SOURCE_INDEX="${ZCL_DEV_RECOVERY_BLOCK_INDEX:-}"
VERIFY_TIMEOUT="${ZCL_DEV_RECOVERY_TIMEOUT:-300}"
MIN_PAYLOAD_BYTES="${ZCL_DEV_RECOVERY_MIN_PAYLOAD_BYTES:-10485760}"
TXN_ID="${ZCL_DEV_RECOVERY_TXN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
ARCHIVE="${DEV_DATADIR}.recovery-archive-${TXN_ID}"
STAGE="${DEV_DATADIR}.recovery-stage-${TXN_ID}"
FAILED_FRESH="${DEV_DATADIR}.recovery-failed-${TXN_ID}"
TXN_STATE_DIR="$STATE_DIR/recovery-$TXN_ID"
RECOVERY_RECORD="$STATE_DIR/recovery-latest.json"

LOCK_HELD=0
SWAPPED=0
DROPIN_EXISTED=0
BUILD_ID_DROPIN_EXISTED=0
CURRENT_GENERATION=""
CURRENT_SOURCE_ID=""
TARGET_GENERATION=""
PREVIOUS_CURRENT=""
PREVIOUS_LAST_GOOD=""
GENERATION_LINKS_CHANGED=0
SNAPSHOT_BASENAME=""
SNAPSHOT_HEIGHT=""
SNAPSHOT_VERSION=""
SNAPSHOT_HEADER_HEIGHT=""
SNAPSHOT_RECORD_COUNT="" SNAPSHOT_PAYLOAD_SHA3="" SNAPSHOT_ANCHOR_HASH=""
SNAPSHOT_SHA256=""
INDEX_SHA256=""
INDEX_TIP_HEIGHT=""

json_escape()
{
    printf '%s' "${1:-}" | sed \
        -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
        -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g'
}

die()
{
    printf '[dev-recovery] REFUSE: %s\n' "$*" >&2
    exit 1
}

is_uint()
{
    case "${1:-}" in ""|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

safe_absolute_path()
{
    case "${1:-}" in
        ""|*".."*|*[$'\n\r\t']*) return 1 ;;
        /*) return 0 ;;
        *) return 1 ;;
    esac
}

sha256_file()
{
    sha256sum "$1" | awk '{print $1}'
}

highest_snapshot_in()
{
    local dir="$1" file base stem best_h="" best_path=""
    [ -d "$dir" ] || return 1
    for file in "$dir"/utxo-seed-*.snapshot; do
        [ -f "$file" ] || continue
        base="${file##*/}"
        stem="${base#utxo-seed-}"
        stem="${stem%.snapshot}"
        is_uint "$stem" || continue
        if [ -z "$best_h" ] || [ "$stem" -gt "$best_h" ]; then
            best_h="$stem"
            best_path="$file"
        fi
    done
    [ -n "$best_path" ] || return 1
    printf '%s\n' "$best_path"
}

block_index_tip_height()
{
    local file="$1" lead payload_off count size expected height_off height
    command -v od >/dev/null 2>&1 || return 1
    size="$(stat -c %s "$file")" || return 1
    [ "$size" -ge 180 ] || return 1
    lead="$(od -An -tx1 -N4 "$file" | tr -d ' \n')"
    case "$lead" in
        42494945) payload_off=48 ;; # embedded "BIIE" integrity header
        494c435a) payload_off=0 ;;  # legacy little-endian ZCLI payload
        *) return 1 ;;
    esac
    count="$(od -An -tu4 -j $((payload_off + 4)) -N4 "$file" | tr -d ' ')"
    is_uint "$count" && [ "$count" -gt 0 ] && [ "$count" -le 10000000 ] ||
        return 1
    expected=$((payload_off + 8 + count * 172))
    [ "$size" -eq "$expected" ] || return 1
    height_off=$((payload_off + 8 + (count - 1) * 172 + 64))
    height="$(od -An -td4 -j "$height_off" -N4 "$file" | tr -d ' ')"
    is_uint "$height" || return 1
    printf '%s\n' "$height"
}

snapshot_header_fields()
{
    local file="$1" size magic version height count payload_sha3 anchor_hash
    size="$(stat -c %s "$file")" || return 1
    [ "$size" -ge 24 ] || return 1
    magic="$(od -An -tx1 -N8 "$file" | tr -d ' \n')"
    [ "$magic" = "5a434c5554584f00" ] || return 1 # "ZCLUTXO\0"
    version="$(od -An -tu4 -j 8 -N4 "$file" | tr -d ' ')"
    height="$(od -An -td8 -j 16 -N8 "$file" | tr -d ' ')"
    count="$(od -An -tu8 -j 24 -N8 "$file" | tr -d ' ')"
    anchor_hash="$(od -An -v -tx1 -j 40 -N32 "$file" | tr -d ' \n')"; payload_sha3="$(od -An -v -tx1 -j 72 -N32 "$file" | tr -d ' \n')"
    is_uint "$version" && is_uint "$height" && is_uint "$count" &&
        [[ "$anchor_hash" =~ ^[0-9a-f]{64}$ ]] &&
        [[ "$payload_sha3" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s %s %s %s %s\n' "$version" "$height" "$count" \
        "$payload_sha3" "$anchor_hash"
}

read_generation_link()
{
    local link="$1" target
    [ -L "$link" ] || return 1
    target="$(readlink "$link")" || return 1
    case "$target" in
        gen-[0-9a-f]*|legacy-[0-9a-f]*) ;;
        *) return 1 ;;
    esac
    case "$target" in */*) return 1 ;; esac
    [ -x "$GEN_ROOT/$target/zclassic23-dev" ] || return 1
    printf '%s\n' "$target"
}

generation_source_id()
{
    local manifest="$GEN_ROOT/$1/manifest.json" source_id
    [ -r "$manifest" ] || return 0
    source_id="$(sed -n 's/.*"source_id_sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$manifest" | head -1)"
    [[ "$source_id" =~ ^[0-9a-f]{64}$ ]] || return 0
    printf '%s\n' "$source_id"
}

generation_name_valid()
{
    local generation="$1" suffix
    case "$generation" in
        gen-*) suffix="${generation#gen-}" ;;
        legacy-*) suffix="${generation#legacy-}" ;;
        *) return 1 ;;
    esac
    [ "${#suffix}" -eq 64 ] || return 1
    case "$suffix" in *[!0-9a-f]*) return 1 ;; esac
    [ -x "$GEN_ROOT/$generation/zclassic23-dev" ]
}

resolve_target_generation()
{
    local current
    current="$(read_generation_link "$CURRENT_LINK" || true)"
    [ -n "$current" ] || die "no valid current dev generation"
    TARGET_GENERATION="${REQUESTED_GENERATION:-$current}"
    generation_name_valid "$TARGET_GENERATION" ||
        die "requested generation is absent or invalid: $TARGET_GENERATION"
    CURRENT_GENERATION="$TARGET_GENERATION"
    CURRENT_SOURCE_ID="$(generation_source_id "$CURRENT_GENERATION")"
    [ -n "$CURRENT_SOURCE_ID" ] ||
        die "target generation has no authoritative source_id_sha256: $CURRENT_GENERATION"
}

atomic_generation_link()
{
    local name="$1" generation="$2" link tmp
    link="$GEN_ROOT/$name"
    [ -x "$GEN_ROOT/$generation/zclassic23-dev" ] || return 1
    tmp="$GEN_ROOT/.${name}.recovery.$$"
    rm -f "$tmp"
    ln -s "$generation" "$tmp"
    mv -Tf "$tmp" "$link"
}

service_command()
{
    local injected="$1"; shift
    if [ -n "$injected" ]; then
        /bin/sh -c "$injected"
    else
        timeout "${ZCL_DEV_RECOVERY_SYSTEMCTL_TIMEOUT:-330}" \
            systemctl --user "$@"
    fi
}

service_stop()
{
    service_command "${ZCL_DEV_RECOVERY_STOP_COMMAND:-}" stop "$UNIT"
}

service_start()
{
    service_command "${ZCL_DEV_RECOVERY_START_COMMAND:-}" start "$UNIT"
}

service_daemon_reload()
{
    service_command "${ZCL_DEV_RECOVERY_DAEMON_RELOAD_COMMAND:-}" daemon-reload
}

service_reset_failed()
{
    service_command "${ZCL_DEV_RECOVERY_RESET_FAILED_COMMAND:-}" \
        reset-failed "$UNIT"
}

service_active()
{
    if [ -n "${ZCL_DEV_RECOVERY_ACTIVE_COMMAND:-}" ]; then
        /bin/sh -c "$ZCL_DEV_RECOVERY_ACTIVE_COMMAND"
    else
        systemctl --user is-active --quiet "$UNIT"
    fi
}

service_pid()
{
    if [ -n "${ZCL_DEV_RECOVERY_PID_COMMAND:-}" ]; then
        /bin/sh -c "$ZCL_DEV_RECOVERY_PID_COMMAND"
    else
        systemctl --user show "$UNIT" -p MainPID --value 2>/dev/null
    fi
}

running_executable()
{
    local pid="$1"
    if [ -n "${ZCL_DEV_RECOVERY_RUNNING_EXE_COMMAND:-}" ]; then
        /bin/sh -c "$ZCL_DEV_RECOVERY_RUNNING_EXE_COMMAND"
    else
        is_uint "$pid" && [ "$pid" -gt 0 ] || return 1
        readlink -f "/proc/$pid/exe"
    fi
}

recovery_selftest_refuse()
{
    printf '[dev-recovery] REFUSE: invalid internal self-test capability: %s\n' "$*" >&2
    exit 3
}

require_recovery_selftest_env_exact()
{
    local name="$1" expected="$2"
    [ "${!name-}" = "$expected" ] ||
        recovery_selftest_refuse "$name"
}

validate_internal_recovery_selftest_capability()
{
    local root capability observed fd_observed fd_path owner mode home tail
    local service_log binary found=0 active cli generation
    [[ "$SELFTEST_CAP_FD" =~ ^[3-8]$ ]] ||
        recovery_selftest_refuse "capability fd"
    root="$(readlink -f "$SELFTEST_ROOT" 2>/dev/null || true)"
    [ -n "$root" ] && [ "$root" = "$SELFTEST_ROOT" ] &&
        [ -d "$root" ] && [ ! -L "$root" ] ||
        recovery_selftest_refuse "fixture root"
    case "$root" in /tmp/zcl-dev-recovery-selftest.*) ;;
        *) recovery_selftest_refuse "fixture root locus" ;;
    esac
    owner="$(stat -c '%u' "$root" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$root" 2>/dev/null || true)"
    [ "$owner" = "$(id -u)" ] && [ "$mode" = "700" ] ||
        recovery_selftest_refuse "fixture root ownership/mode"

    capability="$root/.recover-dev-lane-selftest-capability"
    [ -f "$capability" ] && [ ! -L "$capability" ] ||
        recovery_selftest_refuse "sentinel"
    owner="$(stat -c '%u' "$capability" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$capability" 2>/dev/null || true)"
    [ "$owner" = "$(id -u)" ] && [ "$mode" = "600" ] ||
        recovery_selftest_refuse "sentinel ownership/mode"
    fd_path="$(readlink -f "/proc/$$/fd/$SELFTEST_CAP_FD" 2>/dev/null || true)"
    [ "$fd_path" = "$capability" ] ||
        recovery_selftest_refuse "fd is not bound to sentinel"
    IFS= read -r fd_observed <&"$SELFTEST_CAP_FD" || fd_observed=""
    IFS= read -r observed < "$capability" || observed=""
    [[ "$observed" =~ ^[0-9a-f]{64}$ ]] && [ "$fd_observed" = "$observed" ] ||
        recovery_selftest_refuse "sentinel mismatch"

    home="$(readlink -f "$HOME" 2>/dev/null || true)"
    case "$home" in "$root"/*-home) ;;
        *) recovery_selftest_refuse "HOME locus" ;;
    esac
    tail="${home#"$root"/}"
    case "$tail" in */*) recovery_selftest_refuse "HOME depth" ;; esac
    [ -d "$home" ] && [ ! -L "$home" ] ||
        recovery_selftest_refuse "HOME shape"
    [ "$(readlink -m "$DEV_DATADIR")" = "$home/.zclassic-c23-dev" ] &&
        [ "$(readlink -m "$GEN_ROOT")" = "$home/.local/lib/zclassic23-dev" ] &&
        [ "$(readlink -m "$STATE_DIR")" = "$home/.local/state/zclassic23-dev" ] &&
        [ "$(readlink -m "$SOURCE_DIR")" = "$home/.zclassic-c23-dev" ] ||
        recovery_selftest_refuse "fixture paths"
    [ "$MIN_PAYLOAD_BYTES" = "1" ] ||
        recovery_selftest_refuse "payload floor"
    case "$VERIFY_TIMEOUT" in 1|10) ;;
        *) recovery_selftest_refuse "verify timeout" ;;
    esac
    case "$TXN_ID" in success|failure-digest|failure-hstar|signal) ;;
        *) recovery_selftest_refuse "transaction id" ;;
    esac

    service_log="$home/service.log"
    active="$home/service-active"
    generation="${REQUESTED_GENERATION:-}"
    cli="$home/fake-cli"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_STOP_COMMAND \
        "rm -f '$active'; printf 'stop\\n' >> '$service_log'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_START_COMMAND \
        "touch '$active'; printf 'start\\n' >> '$service_log'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_DAEMON_RELOAD_COMMAND \
        "printf 'reload\\n' >> '$service_log'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_RESET_FAILED_COMMAND \
        "printf 'reset\\n' >> '$service_log'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_ACTIVE_COMMAND "test -f '$active'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_PID_COMMAND "printf '4242\\n'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_RUNNING_EXE_COMMAND "printf '%s\\n' '$GEN_ROOT/$generation/zclassic23-dev'"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_CLI "$cli"
    require_recovery_selftest_env_exact ZCL_DEV_RECOVERY_JSONQ "$REPO/build/bin/jsonq"
    [ -z "${ZCL_DEV_RECOVERY_SNAPSHOT:-}" ] &&
        [ -z "${ZCL_DEV_RECOVERY_BLOCK_INDEX:-}" ] ||
        recovery_selftest_refuse "bundle file override"
    [ -f "$cli" ] && [ ! -L "$cli" ] && [ -x "$cli" ] ||
        recovery_selftest_refuse "CLI fixture"
    for binary in "$GEN_ROOT"/gen-*/zclassic23-dev; do
        [ -e "$binary" ] || continue
        found=1
        [ -f "$binary" ] && [ ! -L "$binary" ] &&
            printf '#!/usr/bin/env bash\nexit 0\n' | cmp -s - "$binary" ||
            recovery_selftest_refuse "generation fixture"
    done
    [ "$found" -eq 1 ] || recovery_selftest_refuse "missing generation fixture"
}

validate_confinement()
{
    local canonical soak legacy expected injected
    expected="$(readlink -m "$HOME/.zclassic-c23-dev")"
    [ "$(readlink -m "$DEV_DATADIR")" = "$expected" ] ||
        die "recovery target must be the isolated dev datadir: $expected"
    [ "$UNIT" = "zcl23-dev.service" ] || die "refusing non-dev unit: $UNIT"
    [ "$DEV_RPCPORT" = "18252" ] || die "refusing non-dev RPC port: $DEV_RPCPORT"
    safe_absolute_path "$DEV_DATADIR" || die "unsafe dev datadir path"
    safe_absolute_path "$GEN_ROOT" || die "unsafe generation root"

    canonical="$(readlink -m "$HOME/.zclassic-c23")"
    soak="$(readlink -m "$HOME/.zclassic-c23-soak")"
    legacy="$(readlink -m "$HOME/.zclassic")"
    case "$(readlink -m "$DEV_DATADIR")" in
        "$canonical"|"$soak"|"$legacy")
            die "canonical, soak, and legacy datadirs are structurally unreachable"
            ;;
    esac
    case "$(readlink -m "$GEN_ROOT")/" in
        "$canonical/"*|"$soak/"*|"$legacy/"*)
            die "generation root enters a protected datadir"
            ;;
    esac

    is_uint "$VERIFY_TIMEOUT" && [ "$VERIFY_TIMEOUT" -ge 1 ] ||
        die "invalid recovery timeout: $VERIFY_TIMEOUT"
    is_uint "$MIN_PAYLOAD_BYTES" || die "invalid payload floor"
    case "$TXN_ID" in ""|*[!A-Za-z0-9_.-]*) die "unsafe transaction id" ;; esac

    if [ "$RECOVERY_SELFTEST" -ne 1 ]; then
        for injected in ZCL_DEV_RECOVERY_STOP_COMMAND \
            ZCL_DEV_RECOVERY_START_COMMAND \
            ZCL_DEV_RECOVERY_DAEMON_RELOAD_COMMAND \
            ZCL_DEV_RECOVERY_RESET_FAILED_COMMAND \
            ZCL_DEV_RECOVERY_ACTIVE_COMMAND ZCL_DEV_RECOVERY_PID_COMMAND \
            ZCL_DEV_RECOVERY_RUNNING_EXE_COMMAND; do
            [ -z "${!injected:-}" ] ||
                die "$injected is confined to hermetic recovery tests"
        done
    fi
}

resolve_bundle()
{
    local snapshot_fields
    if [ -z "$SOURCE_SNAPSHOT" ]; then
        SOURCE_SNAPSHOT="$(highest_snapshot_in "$SOURCE_DIR" || true)"
    fi
    [ -n "$SOURCE_SNAPSHOT" ] ||
        die "no utxo-seed-<height>.snapshot found in $SOURCE_DIR"
    [ -z "$SOURCE_INDEX" ] && SOURCE_INDEX="$(dirname "$SOURCE_SNAPSHOT")/block_index.bin"
    safe_absolute_path "$SOURCE_SNAPSHOT" || die "unsafe snapshot source path"
    safe_absolute_path "$SOURCE_INDEX" || die "unsafe block-index source path"
    [ -f "$SOURCE_SNAPSHOT" ] && [ ! -L "$SOURCE_SNAPSHOT" ] ||
        die "snapshot source must be a regular non-symlink file: $SOURCE_SNAPSHOT"
    [ -f "$SOURCE_INDEX" ] && [ ! -L "$SOURCE_INDEX" ] ||
        die "block-index source must be a regular non-symlink file: $SOURCE_INDEX"
    [ "$(stat -c %s "$SOURCE_SNAPSHOT")" -ge "$MIN_PAYLOAD_BYTES" ] ||
        die "snapshot source is below the payload floor"
    [ "$(stat -c %s "$SOURCE_INDEX")" -ge "$MIN_PAYLOAD_BYTES" ] ||
        die "block-index source is below the payload floor"

    SNAPSHOT_BASENAME="${SOURCE_SNAPSHOT##*/}"
    case "$SNAPSHOT_BASENAME" in
        utxo-seed-[0-9]*.snapshot) ;;
        *) die "snapshot must use utxo-seed-<height>.snapshot naming" ;;
    esac
    SNAPSHOT_HEIGHT="${SNAPSHOT_BASENAME#utxo-seed-}"
    SNAPSHOT_HEIGHT="${SNAPSHOT_HEIGHT%.snapshot}"
    is_uint "$SNAPSHOT_HEIGHT" || die "snapshot filename height is invalid"
    snapshot_fields="$(snapshot_header_fields "$SOURCE_SNAPSHOT" || true)"
    [ -n "$snapshot_fields" ] ||
        die "snapshot has an invalid ZCLUTXO header: $SOURCE_SNAPSHOT"
    read -r SNAPSHOT_VERSION SNAPSHOT_HEADER_HEIGHT SNAPSHOT_RECORD_COUNT \
        SNAPSHOT_PAYLOAD_SHA3 SNAPSHOT_ANCHOR_HASH <<< "$snapshot_fields"
    [ "$SNAPSHOT_HEADER_HEIGHT" = "$SNAPSHOT_HEIGHT" ] ||
        die "snapshot filename height $SNAPSHOT_HEIGHT disagrees with header height $SNAPSHOT_HEADER_HEIGHT"
    [ "$SNAPSHOT_VERSION" = "2" ] ||
        die "fast dev recovery requires a v2 snapshot with an embedded Sapling frontier (got v$SNAPSHOT_VERSION); set ZCL_DEV_RECOVERY_BUNDLE_DIR to a verified v2 starter bundle"
    INDEX_TIP_HEIGHT="$(block_index_tip_height "$SOURCE_INDEX" || true)"
    is_uint "$INDEX_TIP_HEIGHT" ||
        die "block-index bundle has an invalid or unsupported flat-file shape"
    [ "$INDEX_TIP_HEIGHT" -ge "$SNAPSHOT_HEIGHT" ] ||
        die "block-index tip $INDEX_TIP_HEIGHT is below snapshot anchor $SNAPSHOT_HEIGHT"
}

write_loader_dropin()
{
    local tmp
    mkdir -p "$(dirname "$LOADER_DROPIN")"
    tmp="${LOADER_DROPIN}.recovery.$$"
    {
        printf '# Managed by tools/dev/recover-dev-lane.sh. Noncanonical dev lane only.\n'
        printf '[Service]\n'
        printf 'Environment="ZCL_LANE_SNAPSHOT_LOADER_FLAG=-nolegacyimport -load-snapshot-at-own-height=%s/%s"\n' \
            "$DEV_DATADIR" "$SNAPSHOT_BASENAME"
    } > "$tmp"
    mv -f "$tmp" "$LOADER_DROPIN"
}

write_recovery_record()
{
    local path="$1" status="$2" detail="$3" tmp
    mkdir -p "$(dirname "$path")"
    tmp="${path}.tmp.$$"
    {
        printf '{"schema":"zcl.dev_recovery.v1",'
        printf '"transaction_id":"%s","status":"%s",' \
            "$(json_escape "$TXN_ID")" "$(json_escape "$status")"
        printf '"detail":"%s","unit":"%s",' \
            "$(json_escape "$detail")" "$UNIT"
        printf '"datadir":"%s","archive":"%s",' \
            "$(json_escape "$DEV_DATADIR")" "$(json_escape "$ARCHIVE")"
        printf '"failed_fresh":"%s","snapshot":"%s",' \
            "$(json_escape "$FAILED_FRESH")" "$(json_escape "$SNAPSHOT_BASENAME")"
        printf '"snapshot_height":%s,"snapshot_version":%s,' \
            "$SNAPSHOT_HEIGHT" "$SNAPSHOT_VERSION"
        printf '"embedded_sapling_frontier_required":true,"snapshot_sha256":"%s",' \
            "$SNAPSHOT_SHA256"
        printf '"block_index_sha256":"%s","generation":"%s",' \
            "$INDEX_SHA256" "$(json_escape "$CURRENT_GENERATION")"
        printf '"source_id_sha256":"%s",' "$CURRENT_SOURCE_ID"
        printf '"block_index_tip_height":%s,' "$INDEX_TIP_HEIGHT"
        printf '"canonical_mutated":false,"soak_mutated":false,'
        printf '"captured_at_utc":"%s"}\n' "$(date -u +%FT%TZ)"
    } > "$tmp"
    mv -f "$tmp" "$path"
}

prepare_fresh_datadir()
{
    local dst_snap="$STAGE/$SNAPSHOT_BASENAME" dst_index="$STAGE/block_index.bin"
    [ ! -e "$STAGE" ] || die "staging path already exists: $STAGE"
    mkdir -m 700 "$STAGE"
    cp --reflink=auto --sparse=always "$SOURCE_SNAPSHOT" "$dst_snap"
    cp --reflink=auto --sparse=always "$SOURCE_INDEX" "$dst_index"
    chmod 0644 "$dst_snap" "$dst_index"

    SNAPSHOT_SHA256="$(sha256_file "$SOURCE_SNAPSHOT")"
    INDEX_SHA256="$(sha256_file "$SOURCE_INDEX")"
    [ "$(sha256_file "$dst_snap")" = "$SNAPSHOT_SHA256" ] ||
        die "snapshot copy hash mismatch"
    [ "$(sha256_file "$dst_index")" = "$INDEX_SHA256" ] ||
        die "block-index copy hash mismatch"
    [ ! -e "$STAGE/auto_reindex_request" ] ||
        die "fresh staging datadir unexpectedly inherited auto-reindex state"
    write_recovery_record "$STAGE/recovery-origin.json" prepared \
        "fresh bundle copied; node SHA3/header binding still required"
}

verify_recovery_default()
{
    local deadline now pid pid_after exe height hstar agent observed_source_id expected_bin
    local proof frontier expected_snapshot
    expected_bin="$GEN_ROOT/$CURRENT_GENERATION/zclassic23-dev"
    expected_snapshot="$DEV_DATADIR/$SNAPSHOT_BASENAME"
    deadline=$(( $(date +%s) + VERIFY_TIMEOUT ))
    while :; do
        pid="$(service_pid 2>/dev/null || true)"
        exe="$(running_executable "$pid" 2>/dev/null || true)"
        proof="$(timeout 10 "$CLI" -datadir="$DEV_DATADIR" \
            -rpcport="$DEV_RPCPORT" dumpstate boot 2>/dev/null || true)"
        if service_active && [ -n "$exe" ] &&
           [ "$(readlink -m "$exe")" = "$(readlink -m "$expected_bin")" ] &&
           [ -x "$CLI" ] && [ -x "$JSONQ" ] &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.complete true &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.seed_height "$SNAPSHOT_HEIGHT" &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.record_count "$SNAPSHOT_RECORD_COUNT" &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.payload_sha3 "$SNAPSHOT_PAYLOAD_SHA3" &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.anchor_block_hash "$SNAPSHOT_ANCHOR_HASH" &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.artifact_sha256 "$SNAPSHOT_SHA256" &&
           printf '%s\n' "$proof" | "$JSONQ" eq state.assisted_snapshot_load.snapshot_path "$expected_snapshot"; then
            height="$(timeout 10 "$CLI" -datadir="$DEV_DATADIR" \
                -rpcport="$DEV_RPCPORT" getblockcount 2>/dev/null || true)"
            agent="$(timeout 10 "$CLI" -datadir="$DEV_DATADIR" \
                -rpcport="$DEV_RPCPORT" agent 2>/dev/null || true)"
            frontier="$(timeout 10 "$CLI" -datadir="$DEV_DATADIR" -rpcport="$DEV_RPCPORT" dumpstate reducer_frontier 2>/dev/null || true)"
            hstar="$(printf '%s\n' "$frontier" | "$JSONQ" get state.hstar 2>/dev/null || true)"
            observed_source_id="$(printf '%s\n' "$agent" |
                "$JSONQ" get source_id_sha256 2>/dev/null || true)"
            pid_after="$(service_pid 2>/dev/null || true)"
            if is_uint "$height" && is_uint "$hstar" &&
               [ "$height" -ge "$hstar" ] && [ "$hstar" -gt "$SNAPSHOT_HEIGHT" ] &&
               { printf '%s\n' "$agent" | "$JSONQ" eq schema zcl.public_status.v2 ||
                 printf '%s\n' "$agent" | "$JSONQ" eq schema zcl.public_status.v3; } &&
               [ "$observed_source_id" = "$CURRENT_SOURCE_ID" ] &&
               [ "$pid_after" = "$pid" ]; then
                return 0
            fi
        fi
        now="$(date +%s)"
        [ "$now" -lt "$deadline" ] || return 1
        sleep 1
    done
}

restore_dropin()
{
    if [ "$DROPIN_EXISTED" -eq 1 ]; then
        cp "$TXN_STATE_DIR/original-loader-dropin.conf" "$LOADER_DROPIN"
    else
        rm -f "$LOADER_DROPIN"
    fi
    if [ "$BUILD_ID_DROPIN_EXISTED" -eq 1 ]; then
        cp "$TXN_STATE_DIR/original-build-identity.conf" "$BUILD_ID_DROPIN"
    else
        rm -f "$BUILD_ID_DROPIN"
    fi
}

restore_generation_links()
{
    [ "$GENERATION_LINKS_CHANGED" -eq 1 ] || return 0
    if [ -n "$PREVIOUS_CURRENT" ]; then
        atomic_generation_link current "$PREVIOUS_CURRENT" || return 1
    else
        rm -f "$CURRENT_LINK"
    fi
    if [ -n "$PREVIOUS_LAST_GOOD" ]; then
        atomic_generation_link last-good "$PREVIOUS_LAST_GOOD" || return 1
    else
        rm -f "$LAST_GOOD_LINK"
    fi
    GENERATION_LINKS_CHANGED=0
}

rollback_datadir_swap()
{
    set +e
    service_stop >/dev/null 2>&1
    if [ -d "$DEV_DATADIR" ]; then
        if [ -e "$FAILED_FRESH" ]; then
            FAILED_FRESH="${FAILED_FRESH}.$$"
        fi
        mv "$DEV_DATADIR" "$FAILED_FRESH"
    fi
    if [ -d "$ARCHIVE" ] && [ ! -e "$DEV_DATADIR" ]; then
        mv "$ARCHIVE" "$DEV_DATADIR"
    fi
    restore_generation_links || true
    restore_dropin
    service_daemon_reload >/dev/null 2>&1
    SWAPPED=0
    write_recovery_record "$RECOVERY_RECORD" rolled_back \
        "fresh lane failed proof; archived datadir restored; service left stopped"
    set -e
}

generation_build_commit()
{
    local manifest="$GEN_ROOT/$1/manifest.json"
    [ -r "$manifest" ] || return 0
    sed -n 's/.*"build_commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$manifest" | head -1
}

write_build_identity_dropin()
{
    local commit tmp
    [ -n "$CURRENT_SOURCE_ID" ] ||
        die "target generation has no source_id_sha256 manifest"
    commit="$(generation_build_commit "$CURRENT_GENERATION")"
    [ -n "$commit" ] || commit="unknown"
    mkdir -p "$(dirname "$BUILD_ID_DROPIN")"
    tmp="${BUILD_ID_DROPIN}.recovery.$$"
    {
        printf '[Service]\n'
        printf 'Environment="ZCL_AGENT_EXPECT_SOURCE_ID=%s"\n' \
            "$CURRENT_SOURCE_ID"
        # Compatibility/display metadata only; freshness is source-ID.
        printf 'Environment="ZCL_AGENT_EXPECT_BUILD_COMMIT=%s"\n' "$commit"
        printf 'Environment="ZCL_AGENT_EXPECT_BUILD_SOURCE=dev-recovery"\n'
    } > "$tmp"
    mv -f "$tmp" "$BUILD_ID_DROPIN"
}

archive_false_rejection()
{
    local marker="$REJECTED_DIR/$CURRENT_GENERATION.json" history accepted tmp
    [ -f "$marker" ] || return 0
    mkdir -p "$REJECTED_HISTORY_DIR" "$ACCEPTED_DIR"
    history="$REJECTED_HISTORY_DIR/${CURRENT_GENERATION}.${TXN_ID}.json"
    mv "$marker" "$history"
    accepted="$ACCEPTED_DIR/$CURRENT_GENERATION.json"
    tmp="${accepted}.tmp.$$"
    printf '{"schema":"zcl.dev_accepted_generation.v1","generation":"%s",' \
        "$CURRENT_GENERATION" > "$tmp"
    printf '"accepted_at_utc":"%s","reason":"fresh dev recovery proved exact executable, snapshot SHA3 and chain-location match, RPC, and agent contract",' \
        "$(date -u +%FT%TZ)" >> "$tmp"
    printf '"superseded_rejection":"%s"}\n' "$(json_escape "$history")" >> "$tmp"
    mv "$tmp" "$accepted"
}

write_coherent_deploy_state()
{
    local commit last_good tmp="$DEV_DATADIR/agent-deploy.json.tmp.$$"
    commit="$(generation_build_commit "$CURRENT_GENERATION")"
    [ -n "$commit" ] || commit="unknown"
    last_good="$(read_generation_link "$LAST_GOOD_LINK" || true)"
    {
        printf '{\n'
        printf '  "schema": "zcl.agent_dev_deploy.v1",\n'
        printf '  "deployed_at_utc": "%s",\n' "$(date -u +%FT%TZ)"
        printf '  "source_id_sha256": "%s",\n' "$CURRENT_SOURCE_ID"
        printf '  "build_commit": "%s",\n' "$(json_escape "$commit")"
        printf '  "build_type": "recovery-proven-existing-generation",\n'
        printf '  "build_artifact": "%s/%s/zclassic23-dev",\n' "$GEN_ROOT" "$CURRENT_GENERATION"
        printf '  "installed_binary": "%s/.local/bin/zclassic23-dev",\n' "$HOME"
        printf '  "generation_root": "%s",\n' "$GEN_ROOT"
        printf '  "candidate_generation": "%s",\n' "$CURRENT_GENERATION"
        printf '  "current_generation": "%s",\n' "$CURRENT_GENERATION"
        printf '  "running_generation": "%s",\n' "$CURRENT_GENERATION"
        printf '  "last_good_generation": "%s",\n' "$last_good"
        printf '  "rollback_available": true,\n'
        printf '  "activation_status": "recovery_ready",\n'
        printf '  "rollback_status": "not_needed",\n'
        printf '  "activation_lock": "%s",\n' "$LOCK_PATH"
        printf '  "activation_lock_held": false,\n'
        printf '  "rejected_generations": [],\n'
        printf '  "service": "%s",\n' "$UNIT"
        printf '  "datadir": "%s",\n' "$DEV_DATADIR"
        printf '  "rpcport": %s,\n' "$DEV_RPCPORT"
        printf '  "verify_status": "ready",\n'
        printf '  "verify_detail": "fresh dev datadir seeded from SHA3/header-bound bundle; exact generation and RPC proved",\n'
        printf '  "failure_capsule": "",\n'
        printf '  "auto_reindex_pending": false,\n'
        printf '  "auto_reindex_anchor": "",\n'
        printf '  "auto_reindex_count": ""\n'
        printf '}\n'
    } > "$tmp"
    mv "$tmp" "$DEV_DATADIR/agent-deploy.json"
}

acquire_lock()
{
    local owner=""
    mkdir -p "$GEN_ROOT"
    exec 9>>"$LOCK_PATH"
    if ! flock -n 9; then
        owner="$(sed -n 's/.*"pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
            "$LOCK_PATH" 2>/dev/null | head -1 || true)"
        die "activation/recovery lock busy owner_pid=${owner:-unknown}"
    fi
    LOCK_HELD=1
    : > "$LOCK_PATH"
    printf '{"schema":"zcl.dev_activation_lock.v1","pid":%s,' "$$" >&9
    printf '"acquired_at_utc":"%s","mode":"recover-fresh-dev"}\n' \
        "$(date -u +%FT%TZ)" >&9
}

emit_plan()
{
    printf '{"schema":"zcl.dev_recovery_plan.v1","mode":"%s",' "$MODE"
    printf '"unit":"%s","datadir":"%s","archive":"%s",' \
        "$UNIT" "$(json_escape "$DEV_DATADIR")" "$(json_escape "$ARCHIVE")"
    printf '"snapshot_source":"%s","block_index_source":"%s",' \
        "$(json_escape "$SOURCE_SNAPSHOT")" "$(json_escape "$SOURCE_INDEX")"
    printf '"snapshot_height":%s,"snapshot_version":%s,' \
        "$SNAPSHOT_HEIGHT" "$SNAPSHOT_VERSION"
    printf '"embedded_sapling_frontier_required":true,"old_datadir_archived":true,'
    printf '"block_index_tip_height":%s,' "$INDEX_TIP_HEIGHT"
    printf '"generation":"%s","generation_switch":%s,' \
        "$(json_escape "$CURRENT_GENERATION")" \
        "$([ -n "$REQUESTED_GENERATION" ] && printf true || printf false)"
    printf '"source_id_sha256":"%s",' "$CURRENT_SOURCE_ID"
    printf '"auto_reindex_inherited":false,"legacy_import":false,"canonical_mutated":false,'
    printf '"soak_mutated":false,"apply":%s}\n' \
        "$([ "$MODE" = apply ] && printf true || printf false)"
}

apply_recovery()
{
    [ -d "$DEV_DATADIR" ] && [ ! -L "$DEV_DATADIR" ] ||
        die "existing dev datadir is missing or not a real directory"
    [ ! -e "$ARCHIVE" ] || die "archive path already exists: $ARCHIVE"
    [ ! -e "$FAILED_FRESH" ] || die "failed-fresh path already exists"
    acquire_lock

    service_stop
    service_active && die "dev service remained active after bounded stop"
    PREVIOUS_CURRENT="$(read_generation_link "$CURRENT_LINK" || true)"
    PREVIOUS_LAST_GOOD="$(read_generation_link "$LAST_GOOD_LINK" || true)"
    [ -n "$PREVIOUS_CURRENT" ] || die "no valid current dev generation"
    TARGET_GENERATION="${REQUESTED_GENERATION:-$PREVIOUS_CURRENT}"
    generation_name_valid "$TARGET_GENERATION" ||
        die "requested generation is absent or invalid: $TARGET_GENERATION"
    CURRENT_GENERATION="$TARGET_GENERATION"
    if [ "$CURRENT_GENERATION" != "$PREVIOUS_CURRENT" ]; then
        atomic_generation_link current "$CURRENT_GENERATION" ||
            die "could not select requested recovery generation"
        GENERATION_LINKS_CHANGED=1
    fi

    mkdir -p "$TXN_STATE_DIR"
    if [ -f "$LOADER_DROPIN" ]; then
        cp "$LOADER_DROPIN" "$TXN_STATE_DIR/original-loader-dropin.conf"
        DROPIN_EXISTED=1
    fi
    if [ -f "$BUILD_ID_DROPIN" ]; then
        cp "$BUILD_ID_DROPIN" "$TXN_STATE_DIR/original-build-identity.conf"
        BUILD_ID_DROPIN_EXISTED=1
    fi
    prepare_fresh_datadir

    mv "$DEV_DATADIR" "$ARCHIVE"
    mv "$STAGE" "$DEV_DATADIR"
    SWAPPED=1
    write_loader_dropin
    write_build_identity_dropin
    service_daemon_reload
    service_reset_failed
    service_start

    if ! verify_recovery_default; then
        rollback_datadir_swap
        die "fresh dev lane did not prove SHA3/header-bound seed plus RPC readiness; old datadir restored and service left stopped"
    fi

    atomic_generation_link last-good "$CURRENT_GENERATION" || {
        rollback_datadir_swap
        die "could not promote proven generation to last-good"
    }
    GENERATION_LINKS_CHANGED=1
    archive_false_rejection
    write_coherent_deploy_state
    write_recovery_record "$DEV_DATADIR/recovery-origin.json" committed \
        "snapshot body SHA3, anchor/header chain-location match, exact executable, RPC, and agent contract proved"
    write_recovery_record "$RECOVERY_RECORD" committed \
        "fresh dev lane ready; old datadir retained at archive path"
    SWAPPED=0
    GENERATION_LINKS_CHANGED=0
    printf '[dev-recovery] READY: fresh dev lane proved at/above seed %s\n' "$SNAPSHOT_HEIGHT"
    printf '[dev-recovery] archived old datadir (including marker): %s\n' "$ARCHIVE"
}

on_exit()
{
    local rc=$?
    if [ "$rc" -ne 0 ] && [ "$SWAPPED" -eq 1 ]; then
        rollback_datadir_swap
    elif [ "$rc" -ne 0 ] && [ "$GENERATION_LINKS_CHANGED" -eq 1 ]; then
        restore_generation_links || true
    fi
    return "$rc"
}
on_signal()
{
    local signal_rc="$1"
    # Convert asynchronous termination into an ordinary nonzero exit so the
    # EXIT trap above always executes the same datadir/drop-in/generation
    # rollback transaction. This also covers interruption through `make`.
    exit "$signal_rc"
}
trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM HUP

[ "$RECOVERY_SELFTEST" -ne 1 ] || validate_internal_recovery_selftest_capability
validate_confinement
resolve_bundle
resolve_target_generation
emit_plan
[ "$MODE" = "apply" ] || exit 0
apply_recovery
