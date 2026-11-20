# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Sourced by zcode_dht_acceptance.sh after its seven real daemons have formed
# an authenticated sparse topology. All dht_* helpers and topology arrays are
# owned by that parent harness. This hook composes the existing source,
# publication, content.v2, swarm and DHT owners; it defines no test transport.

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "sovereign-source-network: FATAL: run make sovereign-source-network-acceptance" >&2
    exit 2
fi

ssn_die() { dht_die "sovereign-source-network: $*"; }
ssn_note() { dht_note "sovereign-source-network: $*"; }

JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"
[ -x "$JSONQ" ] || ssn_die "build/bin/jsonq is missing"

ssn_json() {
    local document="$1" path="$2"
    printf '%s' "$document" | "$JSONQ" get "$path"
}

# Insert a unique C comment after `#include "..."\n\n`. Fail if the include
# line is not unique or is not followed by a blank line.
ssn_insert_after_include_blank() {
    local file="$1" needle="$2" insert="$3"
    [ "$(grep -F -c -- "$needle" "$file")" -eq 1 ] || return 1
    NEEDLE="$needle" INSERT="$insert" awk '
        BEGIN { needle = ENVIRON["NEEDLE"]; insert = ENVIRON["INSERT"] }
        $0 == needle {
            if (seen++)
                exit 1
            print
            if ((getline nxt) <= 0)
                exit 1
            if (nxt != "")
                exit 1
            print nxt
            print insert
            next
        }
        { print }
        END { if (seen != 1) exit 1 }
    ' "$file" > "$file.ssn-edit" || return 1
    mv "$file.ssn-edit" "$file"
}

ssn_native() {
    local role="$1" leaf="$2" input="$3"
    dht_native "${DDS[$role]}" "${RPCS[$role]}" "$leaf" --input="$input"
}

ssn_local() {
    # Native leaves return their structured refusal with a nonzero exit. Keep
    # that exact result available to ssn_require_ok so a failed boundary is
    # named instead of disappearing through the harness's `set -e` policy.
    "$NODE_BIN" "$@" 2>/dev/null | tail -1 || true
}

ssn_require_ok() {
    local label="$1" result="$2"
    [ "$(ssn_json "$result" ok 2>/dev/null || true)" = true ] ||
        ssn_die "$label failed: $result"
}

ssn_restart_role() {
    local role="$1" pos=-1 i
    local connects=()
    for i in 0 1 2 3 4 5 6; do
        [ "${ORDER[$i]}" = "$role" ] && pos="$i"
    done
    [ "$pos" -ge 0 ] || ssn_die "role $role is absent from sparse order"
    dht_kill_group "${PIDS[$role]:-}"
    PIDS[$role]=""
    if [ "$pos" -eq 0 ]; then
        connects=("127.0.0.1:$DEAD_SINK")
    else
        connects=("127.0.0.1:${PORTS[${ORDER[$((pos - 1))]}]}")
        if [ "$pos" -eq 3 ]; then
            connects+=("127.0.0.1:${PORTS[${ORDER[1]}]}")
        fi
    fi
    dht_spawn "PIDS[$role]" "${DDS[$role]}" "${PORTS[$role]}" \
        "${RPCS[$role]}" "${FSPORTS[$role]}" "${HTTPSPORTS[$role]}" \
        "${connects[@]}"
    [ "$role" -eq 0 ] && DHT_PGID_A="${PIDS[$role]}"
    [ "$role" -eq 1 ] && DHT_PGID_B="${PIDS[$role]}"
    DHT_EXTRA_PGIDS=("${PIDS[@]}")
    dht_wait_rpc "${DDS[$role]}" "${RPCS[$role]}" "${PIDS[$role]}" ||
        ssn_die "role $role did not restart"
    dht_wait_auth "${DDS[$role]}" "${RPCS[$role]}" 1 ||
        ssn_die "role $role did not reauthenticate"
}

ssn_wait_complete() {
    local role="$1" root="$2" deadline out bytes last_bytes=-1 stagnant=0
    local resumed
    deadline=$(( $(date +%s) + ${SSN_WAIT:-180} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        # A pin plan performs the package-store completeness/possession
        # preflight without mutating. It is the honest cross-process status
        # surface for a daemon-owned swarm engine.
        out="$(ssn_native "$role" zcode.package.pin \
            "{\"root\":\"$root\",\"mode\":\"plan\"}" || true)"
        [ "$(ssn_json "$out" data.package.complete 2>/dev/null || true)" = true ] &&
            return 0
        bytes="$(ssn_json "$out" data.package.present_bytes 2>/dev/null || echo -1)"
        if [ "$bytes" = "$last_bytes" ] && [ "$bytes" != -1 ]; then
            stagnant=$((stagnant + 1))
        else
            last_bytes="$bytes"
            stagnant=0
        fi
        # A controlled Noise reconnect can retire the session after the first
        # flight of chunks. The store is resumable; when its verified-byte
        # frontier is unchanged for ten polls, rediscover an authenticated
        # provider and idempotently re-arm the same download. A transient
        # discovery miss remains retryable until the outer deadline.
        if [ "$stagnant" -ge 10 ]; then
            resumed="$(ssn_native "$role" zcode.package.fetch \
                "{\"root\":\"$root\",\"namespace\":\"zclassic23.source\",\"maximum_bytes\":268435456}" || true)"
            if [ "$(ssn_json "$resumed" ok 2>/dev/null || true)" = true ] &&
               [ "$(ssn_json "$resumed" data.live 2>/dev/null || true)" = true ]; then
                ssn_note "role $role resumed stalled fetch at $bytes bytes"
            fi
            stagnant=0
        fi
        sleep 1
    done
    return 1
}

ssn_live_fetch() {
    local role="$1" root="$2" fetched
    fetched="$(ssn_native "$role" zcode.package.fetch \
        "{\"root\":\"$root\",\"namespace\":\"zclassic23.source\",\"maximum_bytes\":268435456}")"
    ssn_require_ok "role $role live DHT-routed fetch" "$fetched"
    [ "$(ssn_json "$fetched" data.live 2>/dev/null || true)" = true ] ||
        ssn_die "role $role fetch did not enter the daemon-owned swarm: $fetched"
}

ssn_pin() {
    local role="$1" root="$2" plan token commit
    plan="$(ssn_native "$role" zcode.package.pin \
        "{\"root\":\"$root\",\"mode\":\"plan\"}")"
    ssn_require_ok "role $role pin plan" "$plan"
    token="$(ssn_json "$plan" data.plan_token)"
    commit="$(ssn_native "$role" zcode.package.pin \
        "{\"root\":\"$root\",\"mode\":\"commit\",\"plan_token\":\"$token\"}")"
    ssn_require_ok "role $role pin commit" "$commit"
    [ "$(ssn_json "$commit" data.pinned 2>/dev/null || true)" = true ] ||
        ssn_die "role $role did not report pinned: $commit"
}

ssn_allow_source_policy() {
    local role="$1" common plan token commit
    common='"operation":"add","source":"local","effect":"allow","scope":"service_type","action_mask":63,"value":"zclassic23.source"'
    plan="$(ssn_native "$role" zcode.network.policy.mutate \
        "{\"mode\":\"plan\",$common}")"
    ssn_require_ok "role $role source policy plan" "$plan"
    token="$(ssn_json "$plan" data.plan_token)"
    commit="$(ssn_native "$role" zcode.network.policy.mutate \
        "{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}")"
    ssn_require_ok "role $role source policy commit" "$commit"
}

ssn_publish_record() {
    local role="$1" leaf="$2" kind="$3" root="$4" semantic="$5"
    local now expiry common plan token commit
    now="$(date +%s)"; expiry=$((now + 3600))
    common="\"namespace\":\"zclassic23.source\",\"transport_root\":\"$root\",\"sequence\":1,\"not_before\":$((now - 5)),\"expiry\":$expiry"
    if [ "$kind" = provider ]; then
        common="\"kind\":\"provider\",$common"
    else
        # STORAGE_ACK records require a nonzero owner group and forbid the
        # semantic_root field. Bind the ACK cohort to this signed release.
        common="\"owner_group\":\"$semantic\",$common"
    fi
    plan="$(ssn_native "$role" "$leaf" "{\"mode\":\"plan\",$common}")"
    ssn_require_ok "role $role $leaf plan" "$plan"
    token="$(ssn_json "$plan" data.plan_token)"
    commit="$(ssn_native "$role" "$leaf" \
        "{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}")"
    ssn_require_ok "role $role $leaf commit" "$commit"
    printf '%s' "$commit"
}

# Roles follow actual sparse edges: publisher -> Host A -> Host B, while the
# consumer is the next independent identity. This makes every source byte use
# the real wire and permits Host B to replicate from Host A after A possesses
# the package.
SSN_PUBLISHER="${ORDER[0]}"
SSN_HOST_A="${ORDER[1]}"
SSN_HOST_B="${ORDER[2]}"
SSN_CONSUMER="${ORDER[3]}"

for role in "$SSN_PUBLISHER" "$SSN_HOST_A" "$SSN_HOST_B" "$SSN_CONSUMER"; do
    [ -n "${PIDS[$role]:-}" ] || ssn_die "role $role has no live daemon"
    dht_wait_auth "${DDS[$role]}" "${RPCS[$role]}" 1 ||
        ssn_die "role $role lost DHT authentication"
done
ssn_note "roles live: publisher=$SSN_PUBLISHER host_a=$SSN_HOST_A host_b=$SSN_HOST_B consumer=$SSN_CONSUMER"

# Network sovereignty defaults to discovery-only. These consenting fixtures
# explicitly allow source-package fetch/store/index/serve/forward, then cold
# reload that local policy before any publication claim is made.
for role in "$SSN_PUBLISHER" "$SSN_HOST_A" "$SSN_HOST_B" "$SSN_CONSUMER"; do
    ssn_allow_source_policy "$role"
done
# Host A is the publisher's only intended authenticated inbound edge after a
# forward sparse reload. Reconnect it to the still-live publisher first, then
# reload the publisher; the remaining roles can follow dependency order. This
# also works after the parent acceptance's reverse cold-bootstrap topology.
for role in "$SSN_HOST_A" "$SSN_PUBLISHER" "$SSN_HOST_B" "$SSN_CONSUMER"; do
    ssn_restart_role "$role"
done

# Publisher-only source preparation. Git is allowed here solely to select the
# accepted local commit; no host or consumer below receives a path into this
# tree. The archive already contains regular, canonical AGENTS.md and CLAUDE.md
# files, so their distinct model-neutral contract/adapter bytes are preserved.
SSN_SOURCE="$DHT_WORK/sovereign-source-envelope"
mkdir -p "$SSN_SOURCE/zclassic23" "$SSN_SOURCE/include" \
    "$SSN_SOURCE/src" "$SSN_SOURCE/tests" "$SSN_SOURCE/vendor/.cache" \
    "$SSN_SOURCE/zclassic23/vendor/.cache"
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$SSN_SOURCE/zclassic23"
[ -f "$SSN_SOURCE/zclassic23/AGENTS.md" ] ||
    ssn_die "publisher archive is missing canonical AGENTS.md"
[ -f "$SSN_SOURCE/zclassic23/CLAUDE.md" ] ||
    ssn_die "publisher archive is missing the Claude adapter"
cp "$SSN_SOURCE/zclassic23/LICENSE" "$SSN_SOURCE/LICENSE"
for archive in \
    leveldb-1.23.tar.gz \
    libevent-2.1.12.tar.gz \
    openssl-3.0.16.tar.gz \
    sqlite-amalgamation-3510300.zip \
    zlib-1.3.1.tar.gz; do
    [ -f "$REPO_ROOT/vendor/.cache/$archive" ] ||
        ssn_die "publisher is missing pinned offline input $archive"
    cp "$REPO_ROOT/vendor/.cache/$archive" \
        "$SSN_SOURCE/vendor/.cache/$archive"
    cp "$REPO_ROOT/vendor/.cache/$archive" \
        "$SSN_SOURCE/zclassic23/vendor/.cache/$archive"
done
[ "$(find "$SSN_SOURCE/vendor/.cache" -maxdepth 1 -type f | wc -l)" -eq 5 ] ||
    ssn_die "publisher does not have the five pinned offline inputs"

# Prove the five carried archives can prepare the vendor tree offline before
# asking a human to accept anything. This is preflight evidence, not source:
# generated libraries, amalgamations, headers, and the duplicate nested cache
# must not enter the immutable task that also carries those exact archives.
SSN_NO_GIT_BIN="$DHT_WORK/no-git-bin"
mkdir -p "$SSN_NO_GIT_BIN"
ln -sf /bin/false "$SSN_NO_GIT_BIN/git"
PRE_VENDOR_CAPTURE="$(ssn_local zcode.workspace.source.capture \
    --input="{\"workspace\":\"$SSN_SOURCE/zclassic23\"}")"
ssn_require_ok "publisher pre-vendor source capture" "$PRE_VENDOR_CAPTURE"
PRE_VENDOR_ROOT="$(ssn_json "$PRE_VENDOR_CAPTURE" data.source_root)"
if ! PATH="$SSN_NO_GIT_BIN:$PATH" \
    ZCL_SOVEREIGN_SOURCE_ROOT="$PRE_VENDOR_ROOT" \
    ZCL_SOVEREIGN_VERIFY_BIN="$NODE_BIN" ZCL_VENDOR_OFFLINE=1 \
    make -C "$SSN_SOURCE/zclassic23" -j"$(nproc)" vendor \
    >"$DHT_WORK/publisher-vendor-build.log" 2>&1; then
    ssn_die "publisher could not prepare pinned vendor inputs offline"
fi
# The pre-vendor capture's CAS is bootstrap scratch, not accepted source. Move
# it outside the inspected workspace before `zcode work start`; otherwise its
# ~5,000 immutable objects are mistaken for project files and exhaust the
# ordinary package-inspection file bound. The post-vendor work capture below
# creates the authoritative CAS in its normal external task datadir.
if [ -d "$SSN_SOURCE/zclassic23/.zvcs" ]; then
    mv "$SSN_SOURCE/zclassic23/.zvcs" "$DHT_WORK/pre-vendor-zvcs"
fi
mv "$SSN_SOURCE/zclassic23" "$DHT_WORK/publisher-vendor-preflight"
mkdir -p "$SSN_SOURCE/zclassic23"
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$SSN_SOURCE/zclassic23"
[ -f "$SSN_SOURCE/zclassic23/AGENTS.md" ] ||
    ssn_die "clean publisher archive is missing canonical AGENTS.md"
[ -f "$SSN_SOURCE/zclassic23/CLAUDE.md" ] ||
    ssn_die "clean publisher archive is missing the Claude adapter"

printf '%s\n' '{"schema":1,"name":"zclassic23/sovereign-source-envelope","semver":"0.1.0-dev.1","language":"c23","license":"Apache-2.0","include_dir":"include","source_dir":"src","dependencies":[]}' \
    >"$SSN_SOURCE/zcode-package.json"
printf '%s\n' '#ifndef ZCLASSIC23_SOURCE_ENVELOPE_H' \
    '#define ZCLASSIC23_SOURCE_ENVELOPE_H' \
    'int zclassic23_source_envelope(void);' '#endif' \
    >"$SSN_SOURCE/include/source_envelope.h"
printf '%s\n' '#include "source_envelope.h"' '' \
    'int zclassic23_source_envelope(void) { return 1; }' \
    >"$SSN_SOURCE/src/source_envelope.c"
printf '%s\n' '#include "source_envelope.h"' '' \
    'int main(void) { return zclassic23_source_envelope() == 1 ? 0 : 1; }' \
    >"$SSN_SOURCE/tests/test_source_envelope.c"

START="$(ssn_local zcode.work.start --input="{\"workspace\":\"$SSN_SOURCE\",\"goal\":\"Accept the exact enclosed Zclassic23 source and root license for sovereign P2P publication\",\"profile\":\"quick\",\"details\":true}")"
ssn_require_ok "work start" "$START"
TASK_ROOT="$(ssn_json "$START" data.expert.task_root)"

# Build the publisher reference after immutable task creation but before its
# proof receipts. A whole-program source build can take longer than the quick
# profile's proof-freshness window on a loaded host; doing it first keeps the
# later human acceptance fresh without extending or bypassing that policy. The
# task's captured source predates these build outputs, as did the historical
# post-acceptance ordering. Build in a separate exact archive so no generated
# dependency byte can mutate the planned task workspace. Reuse only the
# locally preflighted vendor tree; the later consumer independently rebuilds
# the same tree from carrier bytes.
PUBLISHER_BUILD_SOURCE="$DHT_WORK/publisher-reference-source"
mkdir -p "$PUBLISHER_BUILD_SOURCE"
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$PUBLISHER_BUILD_SOURCE"
mv "$PUBLISHER_BUILD_SOURCE/vendor" "$DHT_WORK/publisher-clean-vendor"
cp -a "$DHT_WORK/publisher-vendor-preflight/vendor" \
    "$PUBLISHER_BUILD_SOURCE/vendor"
BUILD_CAPTURE="$(ssn_local zcode.workspace.source.capture \
    --input="{\"workspace\":\"$PUBLISHER_BUILD_SOURCE\"}")"
ssn_require_ok "publisher build-source capture" "$BUILD_CAPTURE"
BUILD_SOURCE_ROOT="$(ssn_json "$BUILD_CAPTURE" data.source_root)"
PUBLISHER_REFERENCE="$DHT_WORK/publisher-reference-zclassic23"
if ! PATH="$SSN_NO_GIT_BIN:$PATH" \
    ZCL_SOVEREIGN_SOURCE_ROOT="$BUILD_SOURCE_ROOT" \
    ZCL_SOVEREIGN_VERIFY_BIN="$NODE_BIN" ZCL_VENDOR_OFFLINE=1 \
    make -C "$PUBLISHER_BUILD_SOURCE" -j"$(nproc)" zclassic23 \
    >"$DHT_WORK/publisher-reference-build.log" 2>&1; then
    ssn_die "publisher reference binary did not build from accepted source"
fi
cp "$PUBLISHER_BUILD_SOURCE/build/bin/zclassic23" "$PUBLISHER_REFERENCE"
chmod 0555 "$PUBLISHER_REFERENCE"
PUBLISHER_BINARY_SHA256="$(sha256sum "$PUBLISHER_REFERENCE" | awk '{print $1}')"

EXPORT="$(ssn_local zcode.work.run --input="{\"workspace\":\"$SSN_SOURCE\",\"work\":\"latest\",\"adapter\":\"manual\"}")"
ssn_require_ok "manual candidate export" "$EXPORT"
CANDIDATE_DIR="$(ssn_json "$EXPORT" data.candidate_workspace)"
ssn_insert_after_include_blank \
    "$CANDIDATE_DIR/src/source_envelope.c" \
    '#include "source_envelope.h"' \
    '/* Explicit human acceptance of this inert source envelope. */' ||
    ssn_die "candidate marker edit failed"
RUN="$(ssn_local zcode.work.run --input="{\"workspace\":\"$SSN_SOURCE\",\"work\":\"latest\",\"adapter\":\"manual\"}")"
ssn_require_ok "candidate proof" "$RUN"
[ "$(ssn_json "$RUN" data.state)" = EVIDENCE_READY ] ||
    ssn_die "candidate did not reach EVIDENCE_READY: $RUN"
REVIEW="$(ssn_local zcode.work.review --input="{\"workspace\":\"$SSN_SOURCE\",\"work\":\"latest\",\"adapter\":\"manual\",\"verdict\":\"approve\",\"findings\":\"The exact nested Zclassic23 source and root license are bound; only the inert envelope marker changed.\"}")"
ssn_require_ok "independent review" "$REVIEW"
ACCEPT="$(ssn_local zcode.work.accept --input="{\"workspace\":\"$SSN_SOURCE\",\"work\":\"latest\",\"details\":true}")"
ssn_require_ok "explicit human acceptance" "$ACCEPT"
[ "$(ssn_json "$ACCEPT" data.state)" = PROVEN ] ||
    ssn_die "human acceptance did not produce PROVEN: $ACCEPT"
SOURCE_ROOT="$(ssn_json "$ACCEPT" data.expert.source_root)"
ACCEPTED_WORK_ROOT="$(ssn_json "$ACCEPT" data.expert.lane_receipt_root)"
ssn_insert_after_include_blank \
    "$SSN_SOURCE/src/source_envelope.c" \
    '#include "source_envelope.h"' \
    '/* Explicit human acceptance of this inert source envelope. */' ||
    ssn_die "accepted marker apply failed"

# Offline publisher identity and detached signature. The secret is a 32-byte
# mode-0600 file used only through inherited descriptors; it never reaches a
# command JSON body or daemon datadir.
SIGNER="$REPO_ROOT/build/bin/z23-package-sign"
[ -x "$SIGNER" ] || ssn_die "offline z23-package-sign is not built"
PUBLISH_KEY="$DHT_WORK/source-publisher.key"
PUBLISHER_PUBKEY="$($SIGNER --generate "$PUBLISH_KEY")"
WORK_DATADIR="/tmp/zclassic23-zcode-workspaces/$(id -u)/$TASK_ROOT/zbuild"
PLAN="$(ssn_local zcode.package.dev.publish.plan --input="{\"workspace\":\"$SSN_SOURCE\",\"datadir\":\"${DDS[$SSN_PUBLISHER]}\",\"acceptance_datadir\":\"$WORK_DATADIR\",\"source_root\":\"$SOURCE_ROOT\",\"publisher_pubkey\":\"$PUBLISHER_PUBKEY\",\"name\":\"zclassic23/sovereign-source-envelope\",\"semver\":\"0.1.0-dev.1\",\"license\":\"Apache-2.0\",\"publisher_sequence\":1}")"
ssn_require_ok "source publication plan" "$PLAN"
PACKAGE_ROOT="$(ssn_json "$PLAN" data.package_root)"
DIGEST="$(ssn_json "$PLAN" data.release_signing_digest)"
RELEASE_BODY="$(ssn_json "$PLAN" data.release_body_hex)"
DIGEST_FILE="$DHT_WORK/release.digest"
SIGNATURE_FILE="$DHT_WORK/release.signature"
printf '%s' "$DIGEST" | xxd -r -p >"$DIGEST_FILE"
: >"$SIGNATURE_FILE"; chmod 0600 "$DIGEST_FILE" "$SIGNATURE_FILE"
exec 7<"$PUBLISH_KEY" 8<"$DIGEST_FILE" 9>"$SIGNATURE_FILE"
"$SIGNER" --sign --key-fd 7 --digest-fd 8 --signature-fd 9 ||
    ssn_die "offline release signing failed"
exec 7<&- 8<&- 9>&-
SIGNATURE="$(xxd -p -c 128 "$SIGNATURE_FILE")"
SEAL="$(ssn_local zcode.package.dev.seal --input="{\"release_body_hex\":\"$RELEASE_BODY\",\"signature_hex\":\"$SIGNATURE\"}")"
ssn_require_ok "source release seal" "$SEAL"
RELEASE_HEX="$(ssn_json "$SEAL" data.release_hex)"
RELEASE_ROOT="$(ssn_json "$SEAL" data.release_id)"
COMMIT="$(ssn_native "$SSN_PUBLISHER" zcode.package.dev.publish.commit \
    "{\"workspace\":\"$SSN_SOURCE\",\"datadir\":\"${DDS[$SSN_PUBLISHER]}\",\"acceptance_datadir\":\"$WORK_DATADIR\",\"source_root\":\"$SOURCE_ROOT\",\"release_hex\":\"$RELEASE_HEX\"}")"
ssn_require_ok "content.v2 publication commit" "$COMMIT"
[ "$(ssn_json "$COMMIT" data.package_root)" = "$PACKAGE_ROOT" ] ||
    ssn_die "publication commit changed the package root: $COMMIT"
ssn_note "accepted source published: source=$SOURCE_ROOT package=$PACKAGE_ROOT release=$RELEASE_ROOT"

# Reload the publisher's ordinary store, then announce the signed provider
# record. Host A obtains every byte from the live package swarm.
ssn_restart_role "$SSN_PUBLISHER"
PROVIDER="$(ssn_publish_record "$SSN_PUBLISHER" zcode.network.publish \
    provider "$PACKAGE_ROOT" "$RELEASE_ROOT")"
ssn_live_fetch "$SSN_HOST_A" "$PACKAGE_ROOT"
ssn_wait_complete "$SSN_HOST_A" "$PACKAGE_ROOT" ||
    ssn_die "Host A did not complete the package"
ssn_pin "$SSN_HOST_A" "$PACKAGE_ROOT"
ssn_restart_role "$SSN_HOST_A"
ACK_A="$(ssn_publish_record "$SSN_HOST_A" zcode.network.storage_ack \
    "" "$PACKAGE_ROOT" "$RELEASE_ROOT")"
HOST_A_PROVIDER="$(ssn_publish_record "$SSN_HOST_A" zcode.network.publish \
    provider "$PACKAGE_ROOT" "$RELEASE_ROOT")"

# Host B is downstream of Host A in the authenticated sparse graph. It starts
# only after A is independently complete and pinned, proving real replication
# rather than two readers sharing a publisher-local path.
ssn_live_fetch "$SSN_HOST_B" "$PACKAGE_ROOT"
ssn_wait_complete "$SSN_HOST_B" "$PACKAGE_ROOT" ||
    ssn_die "Host B did not complete the package"
ssn_pin "$SSN_HOST_B" "$PACKAGE_ROOT"
ssn_restart_role "$SSN_HOST_B"
ACK_B="$(ssn_publish_record "$SSN_HOST_B" zcode.network.storage_ack \
    "" "$PACKAGE_ROOT" "$RELEASE_ROOT")"
HOST_B_PROVIDER="$(ssn_publish_record "$SSN_HOST_B" zcode.network.publish \
    provider "$PACKAGE_ROOT" "$RELEASE_ROOT")"

ACK_A_AUTHOR="$(ssn_json "$ACK_A" data.record.provider_node_id)"
ACK_B_AUTHOR="$(ssn_json "$ACK_B" data.record.provider_node_id)"
[ "$ACK_A_AUTHOR" != "$ACK_B_AUTHOR" ] ||
    ssn_die "two storage ACKs came from one node identity"

ssn_note "replication frontier PASS: publisher + two independently pinned hosts + distinct STORAGE_ACKs"

# The publisher now goes offline. The blank consumer has only its bootstrap
# identity/peers plus the immutable package root; Host A and Host B are its
# only byte sources. Fetch, pin, restart, and then close the daemon before
# checkout so reconstruction is a standalone Git-free operation over its own
# persisted package store.
dht_kill_group "${PIDS[$SSN_PUBLISHER]:-}" KILL  # deliberate hard kill: publisher loss
PIDS[$SSN_PUBLISHER]=""
ssn_live_fetch "$SSN_CONSUMER" "$PACKAGE_ROOT"
ssn_wait_complete "$SSN_CONSUMER" "$PACKAGE_ROOT" ||
    ssn_die "consumer did not complete the package from the two source hosts"
ssn_pin "$SSN_CONSUMER" "$PACKAGE_ROOT"
ssn_restart_role "$SSN_CONSUMER"
dht_kill_group "${PIDS[$SSN_CONSUMER]:-}"
PIDS[$SSN_CONSUMER]=""

CONSUMER_ZVCS="$DHT_WORK/consumer-zvcs"
CONSUMER_DEST="$DHT_WORK/consumer-checkout"
mkdir -p "$CONSUMER_ZVCS" "$CONSUMER_DEST"
CHECKOUT="$(env -i PATH=/no-external-tools HOME=/tmp LANG=C \
    "$NODE_BIN" zcode.workspace.source.package.checkout \
    --input="{\"datadir\":\"${DDS[$SSN_CONSUMER]}\",\"package_root\":\"$PACKAGE_ROOT\",\"source_root\":\"$SOURCE_ROOT\",\"accepted_work_root\":\"$ACCEPTED_WORK_ROOT\",\"workspace\":\"$CONSUMER_ZVCS\",\"destination\":\"$CONSUMER_DEST\"}" \
    2>/dev/null | tail -1)"
ssn_require_ok "Git-free accepted source checkout" "$CHECKOUT"
[ "$(ssn_json "$CHECKOUT" data.git_required 2>/dev/null || true)" = false ] ||
    ssn_die "consumer checkout required Git: $CHECKOUT"
[ "$(ssn_json "$CHECKOUT" data.source_executed 2>/dev/null || true)" = false ] ||
    ssn_die "consumer executed source during retrieval: $CHECKOUT"
[ ! -e "$CONSUMER_DEST/.git" ] &&
[ ! -e "$CONSUMER_DEST/zclassic23/.git" ] ||
    ssn_die "consumer checkout materialized forbidden Git metadata"

# The carrier keeps offline inputs beside the accepted envelope; copy only
# those verified package-derived bytes into the nested build tree's expected
# cache path. A fake `git` fails closed on any accidental invocation, while
# ZCL_VENDOR_OFFLINE makes every missing/corrupt archive fail before a network
# downloader can run.
mkdir -p "$CONSUMER_DEST/zclassic23/vendor/.cache"
for archive in \
    leveldb-1.23.tar.gz \
    libevent-2.1.12.tar.gz \
    openssl-3.0.16.tar.gz \
    sqlite-amalgamation-3510300.zip \
    zlib-1.3.1.tar.gz; do
    cp "$CONSUMER_DEST/vendor/.cache/$archive" \
        "$CONSUMER_DEST/zclassic23/vendor/.cache/$archive"
done
CONSUMER_CAPTURE="$(env -i PATH=/no-external-tools HOME=/tmp LANG=C \
    "$NODE_BIN" zcode.workspace.source.capture \
    --input="{\"workspace\":\"$CONSUMER_DEST/zclassic23\"}" \
    2>/dev/null | tail -1)"
ssn_require_ok "consumer build-source capture" "$CONSUMER_CAPTURE"
CONSUMER_BUILD_ROOT="$(ssn_json "$CONSUMER_CAPTURE" data.source_root)"
[ "$CONSUMER_BUILD_ROOT" = "$BUILD_SOURCE_ROOT" ] ||
    ssn_die "consumer nested source root differs from publisher: consumer=$CONSUMER_BUILD_ROOT publisher=$BUILD_SOURCE_ROOT"
if ! PATH="$SSN_NO_GIT_BIN:$PATH" \
    ZCL_SOVEREIGN_SOURCE_ROOT="$CONSUMER_BUILD_ROOT" \
    ZCL_SOVEREIGN_VERIFY_BIN="$NODE_BIN" ZCL_VENDOR_OFFLINE=1 \
    make -C "$CONSUMER_DEST/zclassic23" setup \
    >"$DHT_WORK/consumer-setup.log" 2>&1; then
    ssn_die "consumer Git-free offline setup failed"
fi
if ! PATH="$SSN_NO_GIT_BIN:$PATH" \
    ZCL_SOVEREIGN_SOURCE_ROOT="$CONSUMER_BUILD_ROOT" \
    ZCL_SOVEREIGN_VERIFY_BIN="$NODE_BIN" ZCL_VENDOR_OFFLINE=1 \
    make -C "$CONSUMER_DEST/zclassic23" -j"$(nproc)" zclassic23 \
    >"$DHT_WORK/consumer-build.log" 2>&1; then
    ssn_die "consumer binary did not build from reconstructed source"
fi
CONSUMER_BINARY="$CONSUMER_DEST/zclassic23/build/bin/zclassic23"
cmp -s "$PUBLISHER_REFERENCE" "$CONSUMER_BINARY" ||
    ssn_die "consumer binary differs from the accepted publisher reference"
CONSUMER_BINARY_SHA256="$(sha256sum "$CONSUMER_BINARY" | awk '{print $1}')"
[ "$CONSUMER_BINARY_SHA256" = "$PUBLISHER_BINARY_SHA256" ] ||
    ssn_die "consumer binary digest differs from publisher reference"
ssn_note "consumer frontier PASS: Git-free checkout + offline build + byte-identical binary sha256=$CONSUMER_BINARY_SHA256"

printf '%s\n' "$PLAN" >"$DHT_WORK/source-plan.json"
printf '%s\n' "$COMMIT" >"$DHT_WORK/source-publication.json"
printf '%s\n' "$PROVIDER" >"$DHT_WORK/source-provider.json"
printf '%s\n' "$ACK_A" >"$DHT_WORK/source-host-a-ack.json"
printf '%s\n' "$ACK_B" >"$DHT_WORK/source-host-b-ack.json"
printf '%s\n' "$CHECKOUT" >"$DHT_WORK/source-consumer-checkout.json"
printf '%s\n' \
    "source_root=$SOURCE_ROOT" \
    "accepted_work_root=$ACCEPTED_WORK_ROOT" \
    "package_root=$PACKAGE_ROOT" \
    "release_root=$RELEASE_ROOT" \
    "build_source_root=$BUILD_SOURCE_ROOT" \
    "binary_sha256=$CONSUMER_BINARY_SHA256" \
    "github_contacted=false" \
    "publisher=$SSN_PUBLISHER" \
    "host_a=$SSN_HOST_A" \
    "host_b=$SSN_HOST_B" \
    "consumer=$SSN_CONSUMER" \
    >"$DHT_WORK/sovereign-source-roots.txt"
