# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# purpose: Fly one really-signed ZCLATT attestation from one live daemon to
# another over the real DHT + package swarm, and prove what arrived.
#
# Sourced by zcode_dht_acceptance.sh after its seven real daemons have formed
# an authenticated sparse topology. All dht_* helpers and topology arrays are
# owned by that parent harness. This hook composes the existing publication,
# record, swarm and attestation owners; it defines no test transport and no
# second harness.
#
# THE CLAIM, IN ONE SENTENCE: a signed attestation minted on node P by the
# separate zclassic23-package-verify program reaches node R by itself — no
# operator carries bytes — is independently re-verified there, and lands as
# BYTE-IDENTICAL filed evidence under the SAME attestation-id filename that
# R's own quorum policy then evaluates and honestly declines to count.
#
# Every stage sets AFL_STAGE. A death names the FIRST DEAD STAGE rather than
# printing a generic failure, and no leg may print success it did not observe.

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "attestation-flight: FATAL: run make attestation-flight-acceptance" >&2
    exit 2
fi

AFL_STAGE=hook_entry
afl_die() {
    dht_die "attestation-flight: first dead stage is $AFL_STAGE: $*"
}
afl_note() { dht_note "attestation-flight: $*"; }

JSONQ="${JSONQ:-$REPO_ROOT/build/bin/jsonq}"
[ -x "$JSONQ" ] || afl_die "build/bin/jsonq is missing"
AFL_SIGNER="$REPO_ROOT/build/bin/zclassic23-package-sign"
AFL_VERIFIER="$REPO_ROOT/build/bin/zclassic23-package-verify"
[ -x "$AFL_SIGNER" ] || afl_die "build/bin/zclassic23-package-sign is missing"
[ -x "$AFL_VERIFIER" ] ||
    afl_die "build/bin/zclassic23-package-verify is missing; the attestation \
must be minted by the real verifier, never hand-assembled"

afl_json() {
    local document="$1" path="$2"
    printf '%s' "$document" | "$JSONQ" get "$path"
}

afl_native() {
    local role="$1"; shift
    dht_native "${DDS[$role]}" "${RPCS[$role]}" -regtest "$@"
}

afl_require_ok() {
    local label="$1" document="$2"
    [ "$(afl_json "$document" ok 2>/dev/null || true)" = true ] ||
        afl_die "$label failed: $document"
}

# A refusal is an OUTCOME here, not an accident: assert the exact named error
# code the boundary is supposed to produce, never merely a nonzero exit.
afl_require_error_code() {
    local label="$1" document="$2" want="$3" got
    [ "$(afl_json "$document" ok 2>/dev/null || true)" = false ] ||
        afl_die "$label was ACCEPTED but must be refused: $document"
    got="$(afl_json "$document" error.code 2>/dev/null || true)"
    [ "$got" = "$want" ] ||
        afl_die "$label was refused by the wrong rule: want $want got $got: $document"
}

# Restart one role back into the forward sparse chain. Same shape as the
# sovereign-source hook's: the parent harness leaves a reverse cold-bootstrap
# topology behind, and these roles need the forward edges.
afl_restart_role() {
    local role="$1" pos=-1 i
    local connects=()
    for i in 0 1 2 3 4 5 6; do
        [ "${ORDER[$i]}" = "$role" ] && pos="$i"
    done
    [ "$pos" -ge 0 ] || afl_die "role $role is absent from sparse order"
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
        afl_die "role $role did not restart"
    dht_wait_auth "${DDS[$role]}" "${RPCS[$role]}" 1 ||
        afl_die "role $role did not reauthenticate"
}

# Network sovereignty defaults to discovery-only: a namespace must be locally
# allowed before this node will fetch/store/index/serve/forward under it.
afl_allow_policy() {
    local role="$1" namespace="$2" common plan token commit code message
    common='"operation":"add","source":"local","effect":"allow","scope":"service_type","action_mask":63,"value":"'"$namespace"'"'
    plan="$(afl_native "$role" zcode network policy mutate \
        --input="{\"mode\":\"plan\",$common}" || true)"
    afl_require_ok "role $role policy plan $namespace" "$plan"
    token="$(afl_json "$plan" data.plan_token)"
    commit="$(afl_native "$role" zcode network policy mutate \
        --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}" || true)"
    if [ "$(afl_json "$commit" ok 2>/dev/null || true)" != true ]; then
        code="$(afl_json "$commit" error.code 2>/dev/null || true)"
        message="$(afl_json "$commit" error.message 2>/dev/null || true)"
        [ "$code" = POLICY_REFUSED ] && [ "$message" = duplicate ] ||
            afl_die "role $role policy commit $namespace failed: $commit"
    fi
}

# A PROVIDER record's maximum validity window, from
# VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS in contexts/commons/modules/vcs/include/vcs/zcode_dht_record.h.
# Pinned here because the flight must be able to SAY when a record it was
# handed cannot legally be published, instead of reporting the refusal as a
# mystery.
AFL_PROVIDER_MAX_WINDOW_S=7200

# Publish one of the two ready-to-run records `zcode package attest offer`
# handed back. Every field is asserted before anything is published — kind,
# namespace and the exact roots — so a wrong record can never pass for a
# right one, and the hook never invents a record shape the command already
# specified.
#
# DEFECT SURFACED, NOT PAPERED OVER: offer stamps the same 86400 s window
# (ZAT_PUBLISH_WINDOW_S) into BOTH inputs, but a PROVIDER record's legal
# maximum is 7200 s. The provider input it returns is therefore structurally
# unpublishable, and `zcode network publish` rejects it as DHT_DISABLED /
# "authenticated DHT is disabled" — a message that names neither the window
# nor the record kind. An operator who runs the command's own two inputs
# verbatim ends up with POINTER only, which the command's own header calls a
# silent no-op at pull time. offer documents that the operator may edit
# either number before running it, so this hook clamps an over-long provider
# window to the legal maximum and PRINTS the defect every single run.
afl_publish_offer_record() {
    local role="$1" input_doc="$2" kind="$3" semantic="$4" label="$5"
    local got_kind got_ns got_transport got_semantic nb ex window body
    local plan token commit
    got_kind="$(afl_json "$input_doc" kind 2>/dev/null || true)"
    got_ns="$(afl_json "$input_doc" namespace 2>/dev/null || true)"
    got_transport="$(afl_json "$input_doc" transport_root 2>/dev/null || true)"
    [ "$got_kind" = "$kind" ] ||
        afl_die "$label input is kind=$got_kind, not $kind: $input_doc"
    [ "$got_ns" = zclassic23.attestation ] ||
        afl_die "$label input names namespace $got_ns: $input_doc"
    [ "$got_transport" = "$AFL_TRANSPORT" ] ||
        afl_die "$label input names transport root $got_transport, not the \
offered attestation blob $AFL_TRANSPORT: $input_doc"
    if [ -n "$semantic" ]; then
        got_semantic="$(afl_json "$input_doc" semantic_root 2>/dev/null || true)"
        [ "$got_semantic" = "$semantic" ] ||
            afl_die "$label input binds semantic root $got_semantic, not the \
attested package $semantic: $input_doc"
    fi
    nb="$(afl_num "$input_doc" not_before)"
    ex="$(afl_num "$input_doc" expiry)"
    [ "$nb" -gt 0 ] && [ "$ex" -gt "$nb" ] ||
        afl_die "$label input carries no usable validity window: $input_doc"
    window=$((ex - nb))
    if [ "$kind" = provider ] && [ "$window" -gt "$AFL_PROVIDER_MAX_WINDOW_S" ]; then
        afl_note "DEFECT: zcode package attest offer returned a PROVIDER \
input whose window is ${window}s, over the ${AFL_PROVIDER_MAX_WINDOW_S}s \
legal maximum for a PROVIDER record. Published verbatim it is refused \
DHT_DISABLED (\"authenticated DHT is disabled\"), which names neither the \
window nor the kind, and the publisher is left POINTER-only — the silent \
no-op the command's own header warns about. Clamping to the legal maximum, \
which is the edit the command tells the operator they may make."
        ex=$((nb + AFL_PROVIDER_MAX_WINDOW_S))
    fi
    body="\"kind\":\"$kind\",\"namespace\":\"$got_ns\",\"transport_root\":\"$got_transport\",\"sequence\":$(afl_num "$input_doc" sequence),\"not_before\":$nb,\"expiry\":$ex"
    [ -z "$semantic" ] ||
        body="$body,\"semantic_root\":\"$semantic\""
    plan="$(afl_native "$role" zcode network publish \
        --input="{\"mode\":\"plan\",$body}" || true)"
    afl_require_ok "$label plan" "$plan"
    token="$(afl_json "$plan" data.plan_token)"
    [ "${#token}" -eq 64 ] || afl_die "$label plan returned no plan token: $plan"
    commit="$(afl_native "$role" zcode network publish \
        --input="{\"mode\":\"commit\",$body,\"plan_token\":\"$token\"}" || true)"
    afl_require_ok "$label commit" "$commit"
}

# Announce "ask me for these bytes" on one package carrier. The window is
# well inside the PROVIDER maximum on purpose.
afl_publish_provider() {
    local role="$1" namespace="$2" transport="$3" label="$4"
    local now body plan token commit
    now="$(date +%s)"
    body="\"kind\":\"provider\",\"namespace\":\"$namespace\",\"transport_root\":\"$transport\",\"sequence\":$now,\"not_before\":$((now - 5)),\"expiry\":$((now + 3600))"
    plan="$(afl_native "$role" zcode network publish \
        --input="{\"mode\":\"plan\",$body}" || true)"
    afl_require_ok "$label plan" "$plan"
    token="$(afl_json "$plan" data.plan_token)"
    [ "${#token}" -eq 64 ] || afl_die "$label plan returned no plan token: $plan"
    commit="$(afl_native "$role" zcode network publish \
        --input="{\"mode\":\"commit\",$body,\"plan_token\":\"$token\"}" || true)"
    afl_require_ok "$label commit" "$commit"
}

# Author one minimal, inert C23 package. Small on purpose: the attestation
# below is a REAL confined build+test signed by the real verifier program, so
# the package has to be the smallest honest thing that genuinely compiles and
# genuinely passes its own test.
afl_author_package() {
    local dir="$1" stem="$2" guard="$3" name="$4"
    mkdir -p "$dir/include" "$dir/src" "$dir/tests"
    printf '%s\n' \
        "{\"schema\":1,\"name\":\"$name\",\"semver\":\"0.1.0-dev.1\",\"language\":\"c23\",\"license\":\"Apache-2.0\",\"include_dir\":\"include\",\"source_dir\":\"src\",\"dependencies\":[]}" \
        >"$dir/zcode-package.json"
    printf '%s\n' "#ifndef $guard" "#define $guard" \
        "int $stem(void);" "#endif" >"$dir/include/$stem.h"
    printf '%s\n' "#include \"$stem.h\"" "" \
        "int $stem(void) { return 1; }" >"$dir/src/$stem.c"
    printf '%s\n' "#include \"$stem.h\"" "" \
        "int main(void) { return $stem() == 1 ? 0 : 1; }" \
        >"$dir/tests/test_$stem.c"
    cp "$REPO_ROOT/LICENSE" "$dir/LICENSE"
}

# Derive, offline-sign, seal and publish one package into the publisher's
# store. Reuses the existing dev prepare / dev seal / zcode create owners.
# `day` is the publication calendar day: one publisher key has a per-ISO-week
# tier allowance, so two packages from one identity must sit in two weeks or
# the second is refused PUBLISH_FREQUENCY_LIMIT.
afl_publish_package() {
    local role="$1" dir="$2" sequence="$3" day="$4" label="$5"
    local prep digest signature seal release manifest recipe input plan commit
    prep="$(afl_native "$role" zcode package dev prepare \
        --input="{\"dir\":\"$dir\",\"publisher_pubkey\":\"$AFL_PUBLISHER_PUBKEY\",\"publisher_sequence\":$sequence,\"chain_id\":\"zclassic-regtest\"}" || true)"
    afl_require_ok "$label dev prepare" "$prep"
    digest="$(afl_json "$prep" data.release_signing_digest)"
    exec 7<"$AFL_PUBLISH_KEY"
    signature="$("$AFL_SIGNER" --sign-digest "$digest" --key-fd 7)" ||
        afl_die "$label offline release signing failed"
    exec 7<&-
    [ "${#signature}" -eq 128 ] ||
        afl_die "$label offline signature is not compact: $signature"
    seal="$(afl_native "$role" zcode package dev seal \
        --input="{\"release_body_hex\":\"$(afl_json "$prep" data.release_body_hex)\",\"signature_hex\":\"$signature\"}" || true)"
    afl_require_ok "$label dev seal" "$seal"
    release="$(afl_json "$seal" data.release_hex)"
    manifest="$(afl_json "$prep" data.manifest_hex)"
    recipe="$(afl_json "$prep" data.recipe_hex)"
    input="\"release_hex\":\"$release\",\"manifest_hex\":\"$manifest\",\"recipe_hex\":\"$recipe\",\"dir\":\"$dir\",\"day\":$day"
    plan="$(afl_native "$role" zcode create \
        --input="{\"mode\":\"plan\",$input}" || true)"
    afl_require_ok "$label create plan" "$plan"
    commit="$(afl_native "$role" zcode create \
        --input="{\"mode\":\"commit\",$input}" || true)"
    afl_require_ok "$label create commit" "$commit"
    AFL_PACKAGE_ROOT="$(afl_json "$commit" data.package_root)"
    AFL_PACKAGE_TRANSPORT="$(afl_json "$commit" data.transport_root)"
    [ "${#AFL_PACKAGE_ROOT}" -eq 64 ] && [ "${#AFL_PACKAGE_TRANSPORT}" -eq 64 ] ||
        afl_die "$label publication produced no canonical roots: $commit"
}


# Move one whole package from the publisher to the receiver over the real
# swarm: announce a PROVIDER on its carrier, arm the fetch, wait for the
# store's own completeness verdict, then re-run the fetch so the completed
# carrier is imported under its semantic root.
afl_receiver_acquire() {
    local semantic="$1" transport="$2" label="$3"
    local fetch deadline complete=false plan import
    afl_publish_provider "$AFL_P" zclassic23.package "$transport" \
        "$label PROVIDER"
    fetch="$(afl_native "$AFL_R" zcode package fetch \
        --input="{\"root\":\"$transport\",\"namespace\":\"zclassic23.package\",\"maximum_bytes\":268435456}" || true)"
    afl_require_ok "receiver $label fetch" "$fetch"
    deadline=$(( $(date +%s) + ${AFL_WAIT:-180} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        plan="$(afl_native "$AFL_R" zcode package pin \
            --input="{\"root\":\"$transport\",\"mode\":\"plan\"}" || true)"
        if [ "$(afl_json "$plan" data.package.complete 2>/dev/null || true)" = true ]; then
            complete=true
            break
        fi
        sleep 1
    done
    [ "$complete" = true ] ||
        afl_die "the receiver never completed the $label carrier over the swarm"
    import="$(afl_native "$AFL_R" zcode package fetch \
        --input="{\"root\":\"$transport\",\"namespace\":\"zclassic23.package\",\"maximum_bytes\":268435456}" || true)"
    afl_require_ok "receiver $label import" "$import"
    [ "$(afl_json "$import" data.package_root)" = "$semantic" ] ||
        afl_die "the receiver imported the wrong semantic root for $label: $import"
}
# Count the files a node has filed as attestation evidence. The adversarial
# leg asserts this number does not move. Absent directory is a real answer
# (zero), never a pipeline failure that would die somewhere else.
afl_attestation_count() {
    local role="$1" dir
    # Split from the declaration above on purpose: bash expands every
    # word of one `local` before assigning any of them, so referencing
    # role in the same statement reads it out of the caller's scope.
    dir="${DDS[$role]}/zcode/attestations"
    if [ ! -d "$dir" ]; then
        printf 0
        return 0
    fi
    find "$dir" -maxdepth 1 -type f | wc -l
}

# One integer field from a reply. A missing key is -1 — a value that fails
# every assertion below loudly instead of turning into an empty string that
# would kill the script somewhere the operator cannot read.
afl_num() {
    local document="$1" path="$2" value
    value="$(afl_json "$document" "$path" 2>/dev/null || true)"
    case "$value" in
        ""|*[!0-9]*) printf -- -1 ;;
        *) printf %s "$value" ;;
    esac
}

# ── roles ──────────────────────────────────────────────────────────────
# P publishes and mints; R is the fresh receiver on the far side of a real
# authenticated Noise edge. R is ORDER[1] because the parent harness files
# signed reachability documents at the lookup origin only: adjacency in the
# sparse graph is what makes P's bytes dialable by R at all, exactly as the
# sovereign-source hook's publisher -> Host A leg does.
AFL_STAGE=role_assignment
AFL_P="${ORDER[0]}"
AFL_R="${ORDER[1]}"
AFL_C="${ORDER[2]}"
AFL_D="${ORDER[3]}"
for afl_role in "$AFL_P" "$AFL_R" "$AFL_C" "$AFL_D"; do
    [ -n "${PIDS[$afl_role]:-}" ] || afl_die "role $afl_role has no live daemon"
    dht_wait_auth "${DDS[$afl_role]}" "${RPCS[$afl_role]}" 1 ||
        afl_die "role $afl_role lost DHT authentication"
done
afl_note "roles live: publisher=$AFL_P receiver=$AFL_R (relays $AFL_C $AFL_D)"

AFL_STAGE=namespace_policy
for afl_role in "$AFL_P" "$AFL_R" "$AFL_C" "$AFL_D"; do
    afl_allow_policy "$afl_role" zclassic23.package
    afl_allow_policy "$afl_role" zclassic23.attestation
done
AFL_STAGE=forward_topology
for afl_role in "$AFL_R" "$AFL_P" "$AFL_C" "$AFL_D"; do
    afl_restart_role "$afl_role"
done

# ── leg 1: two real packages exist and are published ───────────────────
AFL_STAGE=leg1_package_publication
AFL_WORK="$DHT_WORK/attestation-flight"
mkdir -p "$AFL_WORK/build"
AFL_PUBLISH_KEY="$AFL_WORK/publisher.key"
AFL_PUBLISHER_PUBKEY="$("$AFL_SIGNER" --generate "$AFL_PUBLISH_KEY")"
[ "$(stat -c %a "$AFL_PUBLISH_KEY")" = 600 ] &&
[ "${#AFL_PUBLISHER_PUBKEY}" -eq 66 ] ||
    afl_die "offline publisher identity is invalid"

afl_author_package "$AFL_WORK/flight" attestation_flight \
    ZCLASSIC23_ATTESTATION_FLIGHT_H zclassic23/attestation-flight
afl_author_package "$AFL_WORK/decoy" attestation_decoy \
    ZCLASSIC23_ATTESTATION_DECOY_H zclassic23/attestation-decoy

afl_publish_package "$AFL_P" "$AFL_WORK/flight" 1 1 "flight package"
AFL_FLIGHT_ROOT="$AFL_PACKAGE_ROOT"
AFL_FLIGHT_TRANSPORT="$AFL_PACKAGE_TRANSPORT"
afl_publish_package "$AFL_P" "$AFL_WORK/decoy" 2 8 "decoy package"
AFL_DECOY_ROOT="$AFL_PACKAGE_ROOT"
AFL_DECOY_TRANSPORT="$AFL_PACKAGE_TRANSPORT"
[ "$AFL_DECOY_ROOT" != "$AFL_FLIGHT_ROOT" ] ||
    afl_die "the two fixture packages collapsed to one root"
afl_note "leg 1 PASS: publisher holds flight=$AFL_FLIGHT_ROOT decoy=$AFL_DECOY_ROOT"

# ── leg 2: mint a REALLY SIGNED attestation on the publisher ───────────
# The node never compiles downloaded code: zclassic23-package-verify is the
# separate program that runs the confined build+test and signs the ZCLATT
# wire. This is a genuine build of a genuine (tiny) package, not a fixture
# blob — the smallest honest package that really compiles and really passes
# its own test, chosen so an acceptance can afford a real confined build.
AFL_STAGE=leg2_mint_attestation
AFL_VERIFIER_RAW="$AFL_WORK/verifier.key"
AFL_VERIFIER_HEX="$AFL_WORK/verifier.hex"
"$AFL_SIGNER" --generate "$AFL_VERIFIER_RAW" >/dev/null ||
    afl_die "verifier identity generation failed"
install -m 600 /dev/null "$AFL_VERIFIER_HEX"
xxd -p -c 32 "$AFL_VERIFIER_RAW" >"$AFL_VERIFIER_HEX"
exec 7<"$AFL_VERIFIER_RAW"
AFL_VERIFIER_PUBKEY="$("$AFL_SIGNER" --public --key-fd 7)" ||
    afl_die "verifier pubkey derivation failed"
exec 7<&-
[ "${#AFL_VERIFIER_PUBKEY}" -eq 66 ] ||
    afl_die "verifier identity is invalid: $AFL_VERIFIER_PUBKEY"
AFL_P_STORE="${DDS[$AFL_P]}/zcode"
AFL_BEFORE_MINT="$(afl_attestation_count "$AFL_P")"
if ! "$AFL_VERIFIER" "$AFL_FLIGHT_ROOT" --store="$AFL_P_STORE" \
    --key="$AFL_VERIFIER_HEX" --work="$AFL_WORK/build" \
    >"$AFL_WORK/mint.txt" 2>"$AFL_WORK/mint.err"; then
    afl_die "the real verifier could not build and sign this package: \
$(tail -3 "$AFL_WORK/mint.err" 2>/dev/null || true)"
fi
AFL_ATTEST_ID="$(sed -n 's/^attestation=\([0-9a-f]\{64\}\).*/\1/p' \
    "$AFL_WORK/mint.txt")"
AFL_MINT_RESULT="$(sed -n 's/.*result=\([a-z-]*\).*/\1/p' "$AFL_WORK/mint.txt")"
[ "${#AFL_ATTEST_ID}" -eq 64 ] ||
    afl_die "the verifier printed no attestation id: $(cat "$AFL_WORK/mint.txt")"
[ "$AFL_MINT_RESULT" = test-pass ] ||
    afl_die "the confined build did not pass its own test: result=$AFL_MINT_RESULT"
AFL_P_ATTESTATION="$AFL_P_STORE/attestations/$AFL_ATTEST_ID"
[ -s "$AFL_P_ATTESTATION" ] ||
    afl_die "the verifier signed nothing into $AFL_P_ATTESTATION"
[ "$(afl_attestation_count "$AFL_P")" -eq $((AFL_BEFORE_MINT + 1)) ] ||
    afl_die "minting did not file exactly one new attestation"
afl_note "leg 2 PASS: real confined build signed attestation $AFL_ATTEST_ID \
result=$AFL_MINT_RESULT signer=$AFL_VERIFIER_PUBKEY \
bytes=$(wc -c <"$AFL_P_ATTESTATION")"

# ── leg 3: offer — the attestation becomes a blob with a transport root ─
AFL_STAGE=leg3_attest_offer
AFL_OFFER="$(afl_native "$AFL_P" zcode package attest offer \
    --input="{\"attestation_id\":\"$AFL_ATTEST_ID\"}" || true)"
afl_require_ok "publisher attest offer" "$AFL_OFFER"
AFL_TRANSPORT="$(afl_json "$AFL_OFFER" data.transport_root)"
[ "${#AFL_TRANSPORT}" -eq 64 ] ||
    afl_die "offer returned no transport root: $AFL_OFFER"
[ "$AFL_TRANSPORT" != "$AFL_ATTEST_ID" ] ||
    afl_die "the transport root must not be the attestation id: $AFL_OFFER"
[ "$(afl_json "$AFL_OFFER" data.package_root)" = "$AFL_FLIGHT_ROOT" ] ||
    afl_die "offer bound the wrong package root: $AFL_OFFER"
[ "$(afl_json "$AFL_OFFER" data.signer_pubkey)" = "$AFL_VERIFIER_PUBKEY" ] ||
    afl_die "offer reports a different signer than the minting verifier: $AFL_OFFER"
[ "$(afl_json "$AFL_OFFER" data.namespace)" = zclassic23.attestation ] ||
    afl_die "offer named the wrong DHT namespace: $AFL_OFFER"
AFL_PROVIDER_INPUT="$(afl_json "$AFL_OFFER" data.provider_publish_input)"
AFL_POINTER_INPUT="$(afl_json "$AFL_OFFER" data.pointer_publish_input)"
afl_note "leg 3 PASS: attestation is a blob at transport root $AFL_TRANSPORT"

# ── leg 4: publish BOTH records, and prove BOTH landed ─────────────────
# Publishing only one is a silent no-op at pull time — pointer-only means the
# puller learns which blob to want and finds nobody serving it; provider-only
# means the bytes are reachable and nobody knows to ask. So both are
# committed, and both are then re-read FROM THE RECEIVER, which is the only
# observation that proves they are on the network rather than in a local reply.
AFL_STAGE=leg4_publish_both_records
# Reload the publisher's ordinary store first. `zcode create` and `zcode
# package attest offer` are native leaves: they run in the CLI process and
# write through their own handle on the datadir's store. The publish GATE and
# the swarm SERVER both live in the daemon, and a daemon that has not reloaded
# refuses its own freshly offered attestation ATTESTATION_NOT_HELD
# (blob=blob-absent) and would serve nobody. This is the same reload the
# sovereign-source hook performs before it announces a provider record.
afl_restart_role "$AFL_P"
afl_publish_offer_record "$AFL_P" "$AFL_PROVIDER_INPUT" provider "" \
    "attestation PROVIDER"
afl_publish_offer_record "$AFL_P" "$AFL_POINTER_INPUT" pointer "$AFL_FLIGHT_ROOT" \
    "attestation POINTER"

# A DHT lookup is a network operation, so both reads are driven to a named
# outcome under a bounded deadline rather than judged on their first reply.
afl_deadline=$(( $(date +%s) + ${AFL_WAIT:-180} ))
AFL_SEEN_PROVIDER=""
while [ "$(date +%s)" -lt "$afl_deadline" ]; do
    AFL_SEEN_PROVIDER="$(afl_native "$AFL_R" zcode network providers \
        --input="{\"namespace\":\"zclassic23.attestation\",\"transport_root\":\"$AFL_TRANSPORT\"}" || true)"
    [ "$(afl_num "$AFL_SEEN_PROVIDER" data.count)" -ge 1 ] && break
    sleep 1
done
[ "$(afl_num "$AFL_SEEN_PROVIDER" data.count)" -ge 1 ] ||
    afl_die "the receiver cannot see any PROVIDER for the attestation blob: $AFL_SEEN_PROVIDER"
AFL_SEEN_POINTER=""
while [ "$(date +%s)" -lt "$afl_deadline" ]; do
    AFL_SEEN_POINTER="$(afl_native "$AFL_R" zcode network records \
        --input="{\"kind\":\"pointer\",\"namespace\":\"zclassic23.attestation\",\"semantic_root\":\"$AFL_FLIGHT_ROOT\"}" || true)"
    [ "$(afl_json "$AFL_SEEN_POINTER" 'data.records[0].transport_root' 2>/dev/null || true)" = "$AFL_TRANSPORT" ] &&
        break
    sleep 1
done
[ "$(afl_json "$AFL_SEEN_POINTER" 'data.records[0].transport_root' 2>/dev/null || true)" = "$AFL_TRANSPORT" ] ||
    afl_die "the receiver cannot see the POINTER binding $AFL_FLIGHT_ROOT to $AFL_TRANSPORT: $AFL_SEEN_POINTER"
afl_note "leg 4 PASS: PROVIDER and POINTER are both visible from the receiver"
# ── the receiver acquires BOTH PACKAGES themselves, so legs 7 and 8 can
#    evaluate ─────────────────────────────────────────────────────────
# The quorum evaluator answers about a package this node has a persisted
# release for; without one the honest answer is UNKNOWN_PACKAGE and legs 7
# and 8 would prove nothing about the evidence that arrived. Every byte here
# comes from the publisher over the same authenticated swarm.
AFL_STAGE=receiver_package_acquisition
afl_receiver_acquire "$AFL_FLIGHT_ROOT" "$AFL_FLIGHT_TRANSPORT" "flight package"
afl_receiver_acquire "$AFL_DECOY_ROOT" "$AFL_DECOY_TRANSPORT" "decoy package"

# The receiver's evidence set for this package must be EMPTY before the pull,
# or nothing below proves the bytes travelled.
AFL_BEFORE_PULL="$(afl_attestation_count "$AFL_R")"
[ ! -e "${DDS[$AFL_R]}/zcode/attestations/$AFL_ATTEST_ID" ] ||
    afl_die "the receiver already held this attestation before the pull"

# ── leg 5: pull on a node that has never seen these bytes ──────────────
# The pull admits immediately after arming the fetch, and the swarm download
# is asynchronous: the honest first answer can be ATTESTATION_BYTES_UNREACHABLE
# or ATTESTATIONS_REFUSED while the one chunk is still in flight. Re-running
# the pull is the operator's own retry and is idempotent, so drive it to a
# named terminal state instead of either sleeping blindly or accepting the
# first reply. A timeout names the last status AND the last admission rule.
AFL_STAGE=leg5_attest_pull
afl_deadline=$(( $(date +%s) + ${AFL_WAIT:-180} ))
AFL_PULL=""
afl_pull_status=never-ran
while [ "$(date +%s)" -lt "$afl_deadline" ]; do
    AFL_PULL="$(afl_native "$AFL_R" zcode package attest pull \
        --input="{\"package_root\":\"$AFL_FLIGHT_ROOT\"}" || true)"
    afl_pull_status="$(afl_json "$AFL_PULL" data.status 2>/dev/null || true)"
    [ "$afl_pull_status" = ATTESTATIONS_ADMITTED ] && break
    sleep 1
done
printf '%s\n' "$AFL_PULL" >"$AFL_WORK/pull.json"
[ "$afl_pull_status" = ATTESTATIONS_ADMITTED ] ||
    afl_die "the receiver never admitted the attestation: status=$afl_pull_status \
fetch=$(afl_json "$AFL_PULL" 'data.rows[0].fetch_outcome' 2>/dev/null || true) \
rule=$(afl_json "$AFL_PULL" 'data.rows[0].admit_rule' 2>/dev/null || true): $AFL_PULL"
afl_require_ok "receiver attest pull" "$AFL_PULL"
[ "$(afl_num "$AFL_PULL" data.pointers_seen)" -ge 1 ] ||
    afl_die "the receiver resolved no attestation pointers: $AFL_PULL"
[ "$(afl_num "$AFL_PULL" data.distinct_transport_roots)" -eq 1 ] ||
    afl_die "the receiver did not resolve exactly one attestation blob: $AFL_PULL"
[ "$(afl_num "$AFL_PULL" data.admitted)" -eq 1 ] ||
    afl_die "the receiver admitted no attestation: $AFL_PULL"
[ "$(afl_num "$AFL_PULL" data.filed)" -eq 1 ] ||
    afl_die "the receiver admitted but did not FILE the attestation: $AFL_PULL"
[ "$(afl_json "$AFL_PULL" 'data.rows[0].transport_root')" = "$AFL_TRANSPORT" ] ||
    afl_die "the receiver filed a different transport root: $AFL_PULL"
[ "$(afl_json "$AFL_PULL" 'data.rows[0].attestation_id')" = "$AFL_ATTEST_ID" ] ||
    afl_die "the receiver filed a different attestation id: $AFL_PULL"
[ "$(afl_json "$AFL_PULL" 'data.rows[0].signer_pubkey')" = "$AFL_VERIFIER_PUBKEY" ] ||
    afl_die "the receiver filed a differently-signed attestation: $AFL_PULL"
afl_note "leg 5 PASS: receiver admitted and filed $AFL_ATTEST_ID \
(admit_result=$(afl_json "$AFL_PULL" 'data.rows[0].admit_result'))"
# ── leg 6: the receipt is BYTE-IDENTICAL under the same filename ───────
AFL_STAGE=leg6_byte_identical_receipt
AFL_R_ATTESTATION="${DDS[$AFL_R]}/zcode/attestations/$AFL_ATTEST_ID"
[ -s "$AFL_R_ATTESTATION" ] ||
    afl_die "the receiver filed nothing at $AFL_R_ATTESTATION"
cmp -s "$AFL_P_ATTESTATION" "$AFL_R_ATTESTATION" ||
    afl_die "the filed attestation is NOT byte-identical to the publisher's"
[ "$(afl_attestation_count "$AFL_R")" -eq $((AFL_BEFORE_PULL + 1)) ] ||
    afl_die "the pull filed something other than exactly one attestation"
afl_note "leg 6 PASS: byte-identical receipt — $(wc -c <"$AFL_R_ATTESTATION") \
bytes, same attestation-id filename $AFL_ATTEST_ID, cmp clean against the \
publisher's file; no operator carried these bytes"

# ── leg 7: the receiver's OWN quorum policy evaluates the evidence ─────
# The point is that the evidence ARRIVED and is EVALUABLE, not that it is
# accepted. This verifier is deliberately NOT on the receiver's approved
# list, so the honest verdict is signer-not-approved and quorum_reached
# false. Asserting a pass here would be asserting a lie: ADMITTING IS NOT
# ACCEPTING.
AFL_STAGE=leg7_receiver_quorum_evaluation
install -m 600 /dev/null "${DDS[$AFL_R]}/zcode/approved_verifiers"
"$AFL_SIGNER" --generate "$AFL_WORK/unrelated.key" \
    >"${DDS[$AFL_R]}/zcode/approved_verifiers" ||
    afl_die "could not write the receiver's approved-verifier allowlist"
AFL_VERDICT="$(afl_native "$AFL_R" zcode package verify \
    --input="{\"root\":\"$AFL_FLIGHT_ROOT\"}" || true)"
afl_require_ok "receiver quorum evaluation" "$AFL_VERDICT"
printf '%s\n' "$AFL_VERDICT" >"$AFL_WORK/receiver-verify.json"
[ "$(afl_num "$AFL_VERDICT" data.attestations_scanned)" -eq 1 ] ||
    afl_die "the receiver's evaluator did not SEE the arrived attestation: $AFL_VERDICT"
[ "$(afl_json "$AFL_VERDICT" 'data.rows[0].verifier')" = "$AFL_VERIFIER_PUBKEY" ] ||
    afl_die "the evaluated row is not the attestation that arrived: $AFL_VERDICT"
[ "$(afl_json "$AFL_VERDICT" 'data.rows[0].result')" = test-pass ] ||
    afl_die "the arrived attestation lost its result class: $AFL_VERDICT"
[ "$(afl_json "$AFL_VERDICT" 'data.rows[0].rule')" = signer-not-approved ] ||
    afl_die "the receiver did not apply its own allowlist by name: $AFL_VERDICT"
[ "$(afl_json "$AFL_VERDICT" 'data.rows[0].counted')" = false ] &&
[ "$(afl_json "$AFL_VERDICT" data.quorum_reached)" = false ] &&
[ "$(afl_json "$AFL_VERDICT" data.verified)" = false ] ||
    afl_die "an unapproved signer was counted toward the quorum: $AFL_VERDICT"
afl_note "leg 7 PASS: the receiver EVALUATES the arrived attestation and \
honestly declines to count it (rule=signer-not-approved, quorum_reached=false) \
— admitting is not accepting"

# ── leg 8: a hostile pointer cannot poison a package's evidence ────────
# The design has two independent defences and this leg reports on both by
# name rather than merging them into one green.
#
# 8a (PROVEN HERE): the publish-side gate. A shipped node REFUSES to publish
# a POINTER in this namespace binding a package root the attestation does not
# attest — ATTESTATION_BINDING_MISMATCH, on plan AND on commit — so a hostile
# pointer never enters the record layer from an honest build, and the
# receiver still sees zero pointers at the decoy root.
#
# 8b (NOT PROVABLE WITH A SHIPPED BINARY, AND SAID SO): the receiver-side
# check, vcs_package_attest_transport_admit(expect_package_root), is what
# actually protects a reader — a hostile node runs its own build and never
# calls the gate. This acceptance CANNOT stage that record, precisely
# because 8a refuses first, so it does not pretend to. That rule is proven
# in-process by tests/harness/src/test_zcode_attest_transport.c and over a real
# two-node swarm by tests/harness/src/test_zcode_swarm_net.c; driving it on a
# live daemon needs a hostile build or a no-DHT admit leaf.
AFL_STAGE=leg8a_hostile_pointer_refused
AFL_HOSTILE="{\"mode\":\"plan\",\"kind\":\"pointer\",\"namespace\":\"zclassic23.attestation\",\"semantic_root\":\"$AFL_DECOY_ROOT\",\"transport_root\":\"$AFL_TRANSPORT\",\"sequence\":$(date +%s),\"not_before\":$(( $(date +%s) - 5 )),\"expiry\":$(( $(date +%s) + 3600 ))}"
AFL_HOSTILE_PLAN="$(afl_native "$AFL_P" zcode network publish \
    --input="$AFL_HOSTILE" || true)"
afl_require_error_code "hostile POINTER plan" "$AFL_HOSTILE_PLAN" \
    ATTESTATION_BINDING_MISMATCH
AFL_HOSTILE_COMMIT="$(afl_native "$AFL_P" zcode network publish \
    --input="${AFL_HOSTILE/\"mode\":\"plan\"/\"mode\":\"commit\"}" || true)"
afl_require_error_code "hostile POINTER commit" "$AFL_HOSTILE_COMMIT" \
    ATTESTATION_BINDING_MISMATCH

AFL_STAGE=leg8a_decoy_evidence_stays_clean
AFL_BEFORE_DECOY="$(afl_attestation_count "$AFL_R")"
AFL_DECOY_PULL="$(afl_native "$AFL_R" zcode package attest pull \
    --input="{\"package_root\":\"$AFL_DECOY_ROOT\"}" || true)"
afl_require_ok "receiver decoy attest pull" "$AFL_DECOY_PULL"
printf '%s\n' "$AFL_DECOY_PULL" >"$AFL_WORK/decoy-pull.json"
[ "$(afl_json "$AFL_DECOY_PULL" data.status 2>/dev/null || true)" = NO_ATTESTATION_POINTERS ] ||
    afl_die "the decoy pull did not report the empty dead end by name: $AFL_DECOY_PULL"
[ "$(afl_num "$AFL_DECOY_PULL" data.pointers_seen)" -eq 0 ] ||
    afl_die "a pointer reached the decoy root despite the refused publish: $AFL_DECOY_PULL"
[ "$(afl_num "$AFL_DECOY_PULL" data.filed)" -eq 0 ] ||
    afl_die "the decoy pull filed evidence: $AFL_DECOY_PULL"
[ "$(afl_attestation_count "$AFL_R")" -eq "$AFL_BEFORE_DECOY" ] ||
    afl_die "the decoy pull changed the receiver's filed evidence set"

# The receiver holds BOTH releases and exactly one attestation. Its evaluator
# therefore SEES that file while answering about the decoy and still refuses
# to let it count — package-root-mismatch. Evidence about one package cannot
# become evidence about another even when the bytes are already local, which
# is the property a hostile pointer would have had to break.
AFL_DECOY_VERDICT="$(afl_native "$AFL_R" zcode package verify \
    --input="{\"root\":\"$AFL_DECOY_ROOT\"}" || true)"
afl_require_ok "receiver decoy quorum evaluation" "$AFL_DECOY_VERDICT"
printf '%s\n' "$AFL_DECOY_VERDICT" >"$AFL_WORK/decoy-verify.json"
[ "$(afl_num "$AFL_DECOY_VERDICT" data.attestations_scanned)" -eq 1 ] ||
    afl_die "the decoy evaluation did not even see the local attestation: $AFL_DECOY_VERDICT"
[ "$(afl_json "$AFL_DECOY_VERDICT" 'data.rows[0].rule')" = package-root-mismatch ] ||
    afl_die "the flight attestation was not refused by the binding rule for the decoy root: $AFL_DECOY_VERDICT"
[ "$(afl_json "$AFL_DECOY_VERDICT" 'data.rows[0].counted')" = false ] &&
[ "$(afl_num "$AFL_DECOY_VERDICT" data.counted)" -eq 0 ] &&
[ "$(afl_json "$AFL_DECOY_VERDICT" data.quorum_reached)" = false ] ||
    afl_die "evidence about the flight package counted toward the decoy: $AFL_DECOY_VERDICT"
afl_note "leg 8a PASS: hostile POINTER refused ATTESTATION_BINDING_MISMATCH on \
plan and commit; the decoy root reports NO_ATTESTATION_POINTERS, files nothing, \
and its evaluation refuses the local attestation package-root-mismatch"
afl_note "leg 8b NOT PROVEN HERE (and not claimed): the receiver-side \
expect_package_root refusal cannot be staged from a shipped binary because 8a \
refuses the record first — see test_zcode_attest_transport.c and \
test_zcode_swarm_net.c"

AFL_STAGE=report
printf '%s\n' \
    "flight_package_root=$AFL_FLIGHT_ROOT" \
    "decoy_package_root=$AFL_DECOY_ROOT" \
    "attestation_id=$AFL_ATTEST_ID" \
    "transport_root=$AFL_TRANSPORT" \
    "verifier_pubkey=$AFL_VERIFIER_PUBKEY" \
    "publisher_role=$AFL_P" \
    "receiver_role=$AFL_R" \
    "byte_identical_receipt=true" \
    "receiver_quorum_reached=false" \
    "receiver_rule=signer-not-approved" \
    "hostile_pointer_rule=ATTESTATION_BINDING_MISMATCH" \
    "offer_provider_window_defect=86400s_returned_vs_7200s_legal" \
    "decoy_evaluation_rule=package-root-mismatch" \
    >"$DHT_WORK/attestation-flight.txt"
afl_note "PASS: legs 1-7 and 8a proven on real daemons over the real network \
stack; leg 8b reported unproven by construction"
