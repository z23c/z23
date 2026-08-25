/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the three `zcode package attest` transport leaves —
 * how a signed ZCLATT attestation MOVES between nodes:
 *
 *   zcode package attest offer  admit one locally-filed attestation into
 *                               this node's package store as an ordinary
 *                               BLOB, and hand back the two ready-to-run
 *                               `zcode network publish` inputs that make
 *                               it discoverable
 *   zcode package attest pull   resolve every published attestation
 *                               POINTER for one package root, fetch each
 *                               distinct attestation blob over the frozen
 *                               swarm codec, and admit what arrives
 *   zcode package attest admit  admit ONE attestation blob this node
 *                               already holds, named by its transport
 *                               root — no DHT involved at all
 *
 * admit exists because the transport must not be coupled to the DHT. A
 * node that fetched the blob (zcode package fetch on the transport root,
 * or the swarm delivering it some other way) had the evidence in its
 * package store and no way in: import wants hex it does not hold, and pull
 * wants an authenticated record layer that needs identity files and a
 * delegation chain verified against real chain history. Where that is not
 * up, a perfectly good fetched attestation was stranded. Its package_root
 * is OPTIONAL where pull's is mandatory, and that asymmetry is argued in
 * full at the handler — it is not a relaxation.
 *
 * NO NEW WIRE MESSAGE EXISTS HERE AND NONE MAY BE ADDED. A canonical
 * attestation is at most VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES (681), far
 * under VCS_BLOB_MAX_BYTES, so it rides the already-frozen 'zpkgswm'
 * ANNOUNCE/WANT/DATA codec as a one-file one-chunk content.v2 package,
 * exactly like any other carrier. Discovery is two ordinary signed DHT
 * records in VCS_PACKAGE_ATTEST_DHT_NAMESPACE, and both are required:
 *
 *   PROVIDER  transport_root = attestation blob root
 *             — "ask me for these bytes". This is the record the fetch
 *               path actually reads: zcl_native_handle_zcode_package_fetch
 *               builds a {kind:"provider", namespace, transport_root}
 *               selector and routes to authenticated peers holding one.
 *   POINTER   semantic_root  = the attested package root
 *             transport_root = attestation blob root
 *             — "that blob attests this package". This is what a puller
 *               looks up when all it knows is a package root.
 *
 * They answer different questions and neither substitutes for the other.
 * Publish only the POINTER and a puller learns which blob to want but
 * finds nobody serving it; publish only the PROVIDER and the bytes are
 * reachable but nobody knows to ask for them. `offer` therefore returns
 * BOTH inputs, provider first.
 *
 * ADMITTING IS NOT ACCEPTING. Both leaves file attestations from signers
 * this node has never approved, with failure result classes, for packages
 * it does not hold. That is deliberate: refusing evidence at intake would
 * let this node's own allowlist decide what it is allowed to SEE, and a
 * quorum you can only observe when you already agree with it proves
 * nothing. The approved-verifier quorum is applied later, by
 * `zcode package verify`.
 *
 * THE ONE SECURITY PROPERTY ON THE PULL PATH is the receiver-side binding
 * check: every admit here passes the caller's package_root as
 * expect_package_root, never NULL. That is what stops a hostile pointer in
 * this namespace from delivering an attestation for a DIFFERENT package.
 * The publish-side gate in config/src/boot_zcode_dht_publish_gate.c is
 * local hygiene and constrains nobody else.
 *
 * A row that fails stays in the report naming its rule. One bad pointer
 * never aborts the pull — the other verifiers' attestations still land.
 *
 * This lives in its own translation unit rather than in
 * native_zcode_command.c so the transport half of the attestation surface
 * has one file. Bound by config/commands/zcode.def. */

#include "base/safe_alloc.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "command/native_command.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/package_attest.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Row cap for a pull report. A package with more independent verifiers
 * than this is a good problem; the reply says so rather than truncating
 * silently, and the operator raises maximum_records. */
#define ZAT_ROWS_DEFAULT 16u
#define ZAT_ROWS_CEILING 64u

/* Validity window stamped into the two ready-to-run publish inputs. One
 * day: long enough that an operator is not republishing hourly, short
 * enough that a withdrawn attestation stops being advertised on its own.
 * The operator may edit either number before running the command. */
#define ZAT_PUBLISH_WINDOW_S 86400u

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zat_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zat_datadir(const struct zcl_command_request *request)
{
    const char *dd = zat_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Resolve <datadir>/zcode. False with the error body already set. */
static bool zat_zcode_dir(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply,
                          const char *command, char out[4400])
{
    const char *datadir = zat_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return false;
    }
    int n = snprintf(out, 4400, "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= 4400) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return false;
    }
    return true;
}

/* One required canonical 64-hex root input. False with the error body set. */
static bool zat_hex32(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *command,
                      const char *key, const char *code, const char *what,
                      uint8_t out[32])
{
    const char *hex = zat_input_str(request->input, key);
    if (!hex || strlen(hex) != 64 || !zcl_hex_decode_lower(hex, out, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "normalize",
                               false, false, what,
                               hex && hex[0] ? hex : command);
        return false;
    }
    return true;
}

/* The store these leaves write through. The node-global handle when a
 * hosting daemon owns this process; otherwise the datadir's own store,
 * exactly as zcode package fetch does for its one-shot path. Both leaves
 * are MUTATE, so opening the store is not a read side-effect. */
static struct vcs_package_store *zat_open_store(
    const struct zcl_command_request *request, bool *own_out)
{
    *own_out = false;
    struct vcs_package_store *store = vcs_package_store_global();
    if (store)
        return store;
    const char *datadir = zat_datadir(request);
    if (!datadir || !datadir[0])
        return NULL;
    store = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (!store) {
        LOG_ERROR("zcode.package.attest", "package store failed to open under %s",
                  datadir);
        return NULL;
    }
    *own_out = true;
    return store;
}

static void zat_close_store(struct vcs_package_store *store, bool own)
{
    if (own && store)
        vcs_package_store_close(store);
}

/* The exact named rule for one transport outcome, flattened into one
 * string an operator can act on: the transport verdict always, plus the
 * underlying blob or attestation rule when that layer is the one that
 * refused. Never "something went wrong". */
static void zat_rule_string(
    const struct vcs_package_attest_transport_outcome *outcome,
    enum vcs_package_attest_transport_result result, char out[192])
{
    (void)snprintf(out, 192, "%s (blob=%s, attestation=%s)",
                   vcs_package_attest_transport_result_string(result),
                   vcs_blob_result_string(outcome->blob_error),
                   vcs_package_attest_error_string(outcome->attest_error));
}

/* Fill one ready-to-run `zcode network publish` input. The window numbers
 * are the caller's; kind decides whether semantic_root is carried. */
static void zat_publish_input(struct json_value *out, const char *kind,
                              const char *semantic_root_hex,
                              const char *transport_root_hex, uint64_t now)
{
    json_set_object(out);
    (void)json_push_kv_str(out, "mode", "plan");
    (void)json_push_kv_str(out, "kind", kind);
    (void)json_push_kv_str(out, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE);
    if (semantic_root_hex)
        (void)json_push_kv_str(out, "semantic_root", semantic_root_hex);
    (void)json_push_kv_str(out, "transport_root", transport_root_hex);
    (void)json_push_kv_int(out, "sequence", (int64_t)now);
    (void)json_push_kv_int(out, "not_before", (int64_t)now);
    (void)json_push_kv_int(out, "expiry",
                           (int64_t)(now + ZAT_PUBLISH_WINDOW_S));
}

/* ── zcode package attest offer ─────────────────────────────────────── */

void zcl_native_handle_zcode_package_attest_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zat_zcode_dir(request, reply, "zcode.package.attest.offer",
                       zcode_dir))
        return;
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    if (!zat_hex32(request, reply, "zcode.package.attest.offer",
                   "attestation_id", "BAD_ATTESTATION_ID",
                   "attestation_id must be 64 lowercase hex chars (the "
                   "attestations/ filename, not the transport root)", id))
        return;

    bool own_store = false;
    struct vcs_package_store *store = zat_open_store(request, &own_store);
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store could not be opened; the "
                               "attestation cannot be made reachable without "
                               "one",
                               zcode_dir);
        return;
    }

    /* Re-reads the filed bytes, re-parses them, re-verifies the embedded
     * signature, re-derives the id, and admits the EXACT bytes as a blob.
     * Idempotent: re-offering identical bytes yields the same root. */
    struct vcs_package_attest_transport_outcome outcome;
    memset(&outcome, 0, sizeof(outcome));
    enum vcs_package_attest_transport_result r =
        vcs_package_attest_transport_offer(store, zcode_dir, id, &outcome);
    zat_close_store(store, own_store);

    char id_hex[65];
    zcl_hex_encode(id, sizeof(id), id_hex);
    if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK) {
        char rule[192];
        zat_rule_string(&outcome, r, rule);
        const char *code = "OFFER_REFUSED";
        const char *why = "the attestation could not be made reachable";
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INVALID;
        if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT) {
            code = "ATTESTATION_ABSENT";
            why = "no attestation is filed under this id; import it first "
                  "with zcode package attest import";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST) {
            code = "ATTESTATION_INVALID";
            why = "the filed bytes are not a canonical ZCLATT wire, or the "
                  "embedded verifier signature does not verify";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ID) {
            code = "ATTESTATION_ID_MISMATCH";
            why = "the recomputed attestation id does not match the filename "
                  "the bytes are stored under";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB ||
                   r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_STORE) {
            code = "STORE_WRITE";
            why = "the package store refused to admit the attestation bytes";
            exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH) {
            code = "DATADIR_TOO_LONG";
            why = "datadir path too long";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC) {
            code = "ALLOC";
            why = "attestation wire buffer";
            exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        }
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code,
                               code, "execute", false, false, why, rule);
        return;
    }

    char transport_hex[65], package_hex[65], release_hex[65], recipe_hex[65];
    char signer_hex[VCS_PACKAGE_ATTEST_PUBKEY_BYTES * 2 + 1];
    zcl_hex_encode(outcome.transport_root, 32, transport_hex);
    zcl_hex_encode(outcome.attestation.package_root, 32, package_hex);
    zcl_hex_encode(outcome.attestation.release_id, 32, release_hex);
    zcl_hex_encode(outcome.attestation.recipe_root, 32, recipe_hex);
    zcl_hex_encode(outcome.attestation.verifier_pubkey,
                   sizeof(outcome.attestation.verifier_pubkey), signer_hex);

    (void)json_push_kv_str(&reply->data, "attestation_id", id_hex);
    (void)json_push_kv_str(&reply->data, "transport_root", transport_hex);
    (void)json_push_kv_str(&reply->data, "package_root", package_hex);
    (void)json_push_kv_str(&reply->data, "release_id", release_hex);
    (void)json_push_kv_str(&reply->data, "recipe_root", recipe_hex);
    (void)json_push_kv_str(&reply->data, "signer_pubkey", signer_hex);
    (void)json_push_kv_str(&reply->data, "result_class",
                           vcs_package_attest_result_string(
                               outcome.attestation.result_class));
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE);

    /* PROVIDER first: it is the record the fetch path actually reads. */
    uint64_t now = (uint64_t)platform_time_wall_unix();
    struct json_value publish;
    json_init(&publish);
    zat_publish_input(&publish, "provider", NULL, transport_hex, now);
    (void)json_push_kv(&reply->data, "provider_publish_input", &publish);
    json_free(&publish);
    json_init(&publish);
    zat_publish_input(&publish, "pointer", package_hex, transport_hex, now);
    (void)json_push_kv(&reply->data, "pointer_publish_input", &publish);
    json_free(&publish);

    (void)json_push_kv_str(
        &reply->data, "note",
        "offering makes the bytes REACHABLE and announces NOTHING: the "
        "attestation is now an ordinary blob this node will serve over the "
        "frozen package swarm codec, but no peer can find it yet. Telling "
        "the network is the separate second act, and it takes BOTH records "
        "in this namespace: run zcode network publish with "
        "provider_publish_input (\"ask me for these bytes\" — the record the "
        "fetch path reads to route a peer here) AND with "
        "pointer_publish_input (\"that blob attests this package root\" — "
        "what a puller looks up when all it knows is the package root). "
        "Either one alone is a silent no-op at pull time: pointer-only "
        "means a puller learns which blob to want and finds nobody serving "
        "it; provider-only means the bytes are reachable and nobody knows "
        "to ask. Both inputs are mode=plan; each returns a plan_token to "
        "commit. Offering is idempotent — the transport root is a pure "
        "function of the exact signed bytes, identical on every node "
        "forever, and is NOT the attestation id");
}

/* ── zcode package attest pull ──────────────────────────────────────── */

/* One resolved pointer's fate, kept flat so a failure never grows a
 * control path that could abort the sweep. */
struct zat_row {
    char transport_root[65];
    char fetch_outcome[96];   /* the fetch path's own named verdict */
    bool fetched;
    char admit_rule[192];     /* the transport layer's NAMED result */
    bool admitted;
    bool filed;
    bool already_present;
    char attestation_id[65];
    char signer_pubkey[VCS_PACKAGE_ATTEST_PUBKEY_BYTES * 2 + 1];
    const char *result_class;
};

/* Drive the EXISTING record-discovery handler rather than reimplementing a
 * DHT query: {kind:"pointer", namespace, semantic_root} is exactly the
 * selector boot_zcode_dht_record_begin parses. Returns false with the
 * error body already set on the caller's reply. */
static bool zat_query_pointers(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply,
                               const char *package_root_hex,
                               struct json_value *records_out)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "kind", "pointer");
    (void)json_push_kv_str(&input, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE);
    (void)json_push_kv_str(&input, "semantic_root", package_root_hex);
    const char *datadir = zat_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&input, "datadir", datadir);
    struct zcl_command_request forwarded = *request;
    forwarded.input = &input;
    struct zcl_command_reply records;
    zcl_command_reply_init(&records, "zcl.zcode_network_records.v1");
    zcl_native_handle_zcode_network_records(&forwarded, &records);
    json_free(&input);
    if (records.exit_code != ZCL_COMMAND_EXIT_OK) {
        zcl_command_reply_fail(
            reply, records.status, records.exit_code,
            records.error.code[0] ? records.error.code
                                  : "POINTER_LOOKUP_FAILED",
            records.error.phase[0] ? records.error.phase : "discover",
            records.error.retryable, false,
            records.error.message[0]
                ? records.error.message
                : "the attestation pointer lookup did not complete",
            records.error.evidence);
        zcl_command_reply_free(&records);
        return false;
    }
    const struct json_value *rows = json_get(&records.data, "records");
    json_init(records_out);
    if (rows && rows->type == JSON_ARR)
        json_copy(records_out, rows);
    else
        json_set_array(records_out);
    zcl_command_reply_free(&records);
    return true;
}

/* Drive the EXISTING fetch handler for one attestation blob root. Never
 * fails the caller: the row records whatever verdict came back. */
static void zat_fetch_one(const struct zcl_command_request *request,
                          const char *transport_root_hex,
                          struct zat_row *row)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "root", transport_root_hex);
    (void)json_push_kv_str(&input, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE);
    const char *datadir = zat_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&input, "datadir", datadir);
    (void)json_push_kv_int(&input, "maximum_bytes",
                           (int64_t)VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES);
    struct zcl_command_request forwarded = *request;
    forwarded.input = &input;
    struct zcl_command_reply fetch;
    zcl_command_reply_init(&fetch, "zcl.zcode_package_fetch.v1");
    zcl_native_handle_zcode_package_fetch(&forwarded, &fetch);
    json_free(&input);
    if (fetch.exit_code != ZCL_COMMAND_EXIT_OK) {
        (void)snprintf(row->fetch_outcome, sizeof(row->fetch_outcome), "%s",
                       fetch.error.code[0] ? fetch.error.code
                                           : "FETCH_FAILED");
        zcl_command_reply_free(&fetch);
        return;
    }
    const char *verdict = json_get_str(json_get(&fetch.data, "fetch_result"));
    if (!verdict)
        verdict = json_get_str(json_get(&fetch.data, "result"));
    row->fetched = json_get_bool_or(&fetch.data, "already_complete", false) ||
        (verdict && strcmp(verdict, "already-complete") == 0);
    (void)snprintf(row->fetch_outcome, sizeof(row->fetch_outcome), "%s",
                   verdict ? verdict : (row->fetched ? "already-complete"
                                                     : "scheduled"));
    zcl_command_reply_free(&fetch);
}

void zcl_native_handle_zcode_package_attest_pull(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zat_zcode_dir(request, reply, "zcode.package.attest.pull",
                       zcode_dir))
        return;
    uint8_t package_root[32];
    if (!zat_hex32(request, reply, "zcode.package.attest.pull",
                   "package_root", "BAD_PACKAGE_ROOT",
                   "package_root must be 64 lowercase hex chars (the "
                   "attested package root)", package_root))
        return;
    char package_hex[65];
    zcl_hex_encode(package_root, 32, package_hex);

    uint32_t cap = ZAT_ROWS_DEFAULT;
    const struct json_value *mv = json_get(request->input, "maximum_records");
    if (mv && mv->type == JSON_INT) {
        int64_t want = json_get_int(mv);
        if (want <= 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID,
                                   "BAD_MAXIMUM_RECORDS", "normalize", false,
                                   false,
                                   "maximum_records must be a positive "
                                   "integer",
                                   "zcode.package.attest.pull");
            return;
        }
        cap = want > (int64_t)ZAT_ROWS_CEILING ? ZAT_ROWS_CEILING
                                               : (uint32_t)want;
    }

    struct json_value pointers;
    if (!zat_query_pointers(request, reply, package_hex, &pointers))
        return;

    /* Distinct transport roots, in discovery order, bounded. N independent
     * verifiers publish N pointers at this one key; duplicates of the same
     * blob (a republished sequence, a second provider) collapse here so a
     * verifier cannot consume the row budget by republishing. */
    size_t seen = json_size(&pointers);
    struct zat_row *rows = zcl_calloc(cap, sizeof(*rows), "zat_pull_rows");
    if (!rows) {
        json_free(&pointers);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "execute",
                               false, false, "pull row table",
                               "zcode.package.attest.pull");
        return;
    }
    uint32_t distinct = 0;
    bool truncated = false;
    for (size_t i = 0; i < seen; i++) {
        const struct json_value *record = json_at(&pointers, i);
        const char *transport =
            record ? json_get_str(json_get(record, "transport_root")) : NULL;
        if (!transport || strlen(transport) != 64)
            continue;
        bool duplicate = false;
        for (uint32_t j = 0; j < distinct; j++)
            if (strcmp(rows[j].transport_root, transport) == 0) {
                duplicate = true;
                break;
            }
        if (duplicate)
            continue;
        if (distinct >= cap) {
            truncated = true;
            break;
        }
        (void)snprintf(rows[distinct].transport_root,
                       sizeof(rows[distinct].transport_root), "%s",
                       transport);
        (void)snprintf(rows[distinct].fetch_outcome,
                       sizeof(rows[distinct].fetch_outcome), "%s",
                       "not-attempted");
        (void)snprintf(rows[distinct].admit_rule,
                       sizeof(rows[distinct].admit_rule), "%s",
                       "not-attempted");
        rows[distinct].result_class = "";
        distinct++;
    }
    json_free(&pointers);

    bool own_store = false;
    struct vcs_package_store *store = NULL;
    if (distinct > 0) {
        store = zat_open_store(request, &own_store);
        if (!store) {
            free(rows);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                                   "execute", false, false,
                                   "the package store could not be opened; "
                                   "attestation bytes cannot be fetched or "
                                   "admitted without one",
                                   zcode_dir);
            return;
        }
    }

    uint32_t fetched = 0, admitted = 0, filed = 0, refused = 0;
    for (uint32_t i = 0; i < distinct; i++) {
        struct zat_row *row = &rows[i];
        zat_fetch_one(request, row->transport_root, row);
        fetched += row->fetched ? 1u : 0u;

        /* Admit unconditionally, even when the fetch only SCHEDULED the
         * download: the blob layer is the authority on whether the bytes
         * are actually here, and its refusal names the rule. A row that
         * fails stays in the report; the sweep continues so one bad or
         * unreachable pointer cannot cost the other verifiers' evidence. */
        uint8_t transport_root[32];
        if (!zcl_hex_decode_lower(row->transport_root, transport_root, 32)) {
            (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                           "pointer-transport-root-not-canonical-hex");
            refused++;
            continue;
        }
        struct vcs_package_attest_transport_outcome outcome;
        memset(&outcome, 0, sizeof(outcome));

        /* expect_package_root is the caller's root and is NEVER NULL. This
         * single argument is the whole reason a hostile pointer in this
         * namespace cannot poison a package's evidence: an attestation
         * whose package_root differs is refused ERR_BINDING and not filed.
         * Do not "simplify" it to NULL. */
        enum vcs_package_attest_transport_result r =
            vcs_package_attest_transport_admit(store, zcode_dir,
                                               transport_root, package_root,
                                               &outcome);
        zat_rule_string(&outcome, r, row->admit_rule);
        if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK) {
            refused++;
            continue;
        }
        row->admitted = true;
        row->filed = outcome.filed;
        row->already_present = outcome.already_present;
        admitted++;
        filed += outcome.filed ? 1u : 0u;
        zcl_hex_encode(outcome.attestation_id, sizeof(outcome.attestation_id),
                       row->attestation_id);
        zcl_hex_encode(outcome.attestation.verifier_pubkey,
                       sizeof(outcome.attestation.verifier_pubkey),
                       row->signer_pubkey);
        row->result_class = vcs_package_attest_result_string(
            outcome.attestation.result_class);
    }
    zat_close_store(store, own_store);

    /* Two very different dead ends, never merged into one "not found":
     * nobody has attested this package yet, versus somebody has and
     * nobody reachable is serving the bytes. The next step differs
     * completely — wait for a verifier, or fix reachability. */
    const char *status = "ATTESTATIONS_ADMITTED";
    const char *blocker = "";
    if (distinct == 0) {
        status = "NO_ATTESTATION_POINTERS";
        blocker = "no_pointer_record_names_an_attestation_for_this_package_"
                  "root";
    } else if (admitted == 0) {
        /* Only once NOTHING landed is it honest to name a dead end, and
         * only then does it matter which one. admitted is tested BEFORE
         * fetched because admission above is deliberately unconditional:
         * a blob this node already holds is admitted and filed even when
         * provider discovery served nothing. Testing fetched first would
         * print "no authenticated provider served the attestation bytes"
         * in a reply that also says filed=1, sending an operator to
         * repair reachability that was never broken. */
        if (fetched == 0) {
            status = "ATTESTATION_BYTES_UNREACHABLE";
            blocker = "pointers_exist_but_no_authenticated_provider_served_"
                      "the_attestation_bytes";
        } else {
            status = "ATTESTATIONS_REFUSED";
            blocker = "every_fetched_attestation_failed_a_named_admission_"
                      "rule";
        }
    }

    (void)json_push_kv_str(&reply->data, "package_root", package_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_PACKAGE_ATTEST_DHT_NAMESPACE);
    (void)json_push_kv_str(&reply->data, "status", status);
    if (blocker[0])
        (void)json_push_kv_str(&reply->data, "blocker", blocker);
    (void)json_push_kv_int(&reply->data, "pointers_seen", (int64_t)seen);
    (void)json_push_kv_int(&reply->data, "distinct_transport_roots",
                           (int64_t)distinct);
    (void)json_push_kv_int(&reply->data, "fetched", (int64_t)fetched);
    (void)json_push_kv_int(&reply->data, "admitted", (int64_t)admitted);
    (void)json_push_kv_int(&reply->data, "filed", (int64_t)filed);
    (void)json_push_kv_int(&reply->data, "refused", (int64_t)refused);
    (void)json_push_kv_int(&reply->data, "maximum_records", (int64_t)cap);
    (void)json_push_kv_bool(&reply->data, "rows_truncated", truncated);

    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (uint32_t i = 0; i < distinct; i++) {
        const struct zat_row *row = &rows[i];
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "transport_root", row->transport_root);
        (void)json_push_kv_str(&entry, "fetch_outcome", row->fetch_outcome);
        (void)json_push_kv_bool(&entry, "fetched", row->fetched);
        (void)json_push_kv_str(&entry, "admit_result", row->admit_rule);
        (void)json_push_kv_bool(&entry, "admitted", row->admitted);
        (void)json_push_kv_str(&entry, "attestation_id",
                               row->attestation_id);
        (void)json_push_kv_str(&entry, "signer_pubkey", row->signer_pubkey);
        (void)json_push_kv_str(&entry, "result_class",
                               row->result_class ? row->result_class : "");
        (void)json_push_kv_bool(&entry, "filed", row->filed);
        (void)json_push_kv_bool(&entry, "already_present",
                                row->already_present);
        (void)json_push_back(&list, &entry);
        json_free(&entry);
    }
    (void)json_push_kv(&reply->data, "rows", &list);
    json_free(&list);
    free(rows);

    (void)json_push_kv_str(
        &reply->data, "note",
        "pulling is NOT accepting. Every admitted wire was checked for "
        "canonical ZCLATT grammar, a verifying embedded verifier "
        "signature, and — the security property on this path — that its "
        "package_root equals the package_root you asked about, so a "
        "hostile pointer in this namespace cannot deliver an attestation "
        "for a different package. Nothing here consults the approved-"
        "verifier allowlist: this command deliberately files attestations "
        "from signers you have never approved and with failure result "
        "classes, because a quorum you can only observe when you already "
        "agree with it proves nothing. The quorum is applied later by "
        "zcode package verify. A row that failed stays in the report "
        "naming its rule and never aborts the sweep — one bad or "
        "unreachable pointer must not cost you the other verifiers' "
        "attestations. Read status: NO_ATTESTATION_POINTERS means nobody "
        "has published an attestation for this package root yet (wait for "
        "a verifier); ATTESTATION_BYTES_UNREACHABLE means pointers exist "
        "but no authenticated provider served the bytes (a reachability "
        "problem, or the publisher never ran the PROVIDER half of zcode "
        "package attest offer). Those are different problems and are "
        "never reported as one");
}

/* ── zcode package attest admit ─────────────────────────────────────── */

/* The third leaf, and the one that decouples the transport from the DHT.
 *
 * offer puts bytes within reach; pull finds them for you. admit is for the
 * node that ALREADY HAS the bytes — `zcode package fetch` was run on the
 * transport root, or the swarm brought the blob in some other way — and
 * therefore has a perfectly good attestation sitting in its package store
 * with no way in. Before this leaf, `import` wanted hex that node does not
 * hold and `pull` wanted a working authenticated DHT, so on any node where
 * the identity files and the delegation chain are not up, fetched evidence
 * was stranded. Nothing about carrying an attestation needs a DHT.
 *
 * THE package_root ASYMMETRY WITH pull IS DELIBERATE AND LOAD-BEARING.
 * On pull, package_root is MANDATORY and is passed as expect_package_root
 * on every admit, because pull resolved the blob FROM a POINTER keyed on
 * that package root: it is answering a question about one specific
 * package, so an unbound admit would let a hostile pointer in this
 * namespace hand back an attestation for a DIFFERENT package and have it
 * read as evidence about yours. Here the operator names a transport root
 * DIRECTLY, so there is no pointer to lie and no package under question
 * unless the caller says there is.
 *
 * Therefore: a caller who is asking "is this attestation evidence about
 * package X?" MUST pass package_root. Omitting it is NOT the safe default
 * and is not a detail — it is the strictly weaker "file these bytes, I am
 * not asking about any one package" case, and the reply says which of the
 * two happened rather than leaving the operator to guess. */

void zcl_native_handle_zcode_package_attest_admit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zat_zcode_dir(request, reply, "zcode.package.attest.admit",
                       zcode_dir))
        return;
    uint8_t transport_root[32];
    if (!zat_hex32(request, reply, "zcode.package.attest.admit",
                   "transport_root", "BAD_TRANSPORT_ROOT",
                   "transport_root must be 64 lowercase hex chars (the "
                   "attestation BLOB root returned by zcode package attest "
                   "offer, not the attestation id)", transport_root))
        return;

    /* OPTIONAL — and the asymmetry above is why. Present means "this
     * attestation must be about THIS package or do not file it"; absent
     * means the caller is filing bytes and asking about no package. A
     * malformed value is never quietly treated as absent: that would turn
     * a typo in the root the caller cares about into an unbound admit. */
    uint8_t package_root[32];
    const uint8_t *expect_package_root = NULL;
    const char *want_hex = zat_input_str(request->input, "package_root");
    if (want_hex && want_hex[0]) {
        if (!zat_hex32(request, reply, "zcode.package.attest.admit",
                       "package_root", "BAD_PACKAGE_ROOT",
                       "package_root is optional, but when given it must be "
                       "64 lowercase hex chars (the package root this "
                       "attestation must be about); it is never silently "
                       "ignored", package_root))
            return;
        expect_package_root = package_root;
    }

    bool own_store = false;
    struct vcs_package_store *store = zat_open_store(request, &own_store);
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store could not be opened; the "
                               "delivered attestation bytes cannot be read "
                               "back without one",
                               zcode_dir);
        return;
    }

    /* The blob layer re-verifies the manifest, the root, and the chunk
     * hash; then the wire is re-parsed, its embedded secp256k1 signature
     * re-verified, and its id re-derived — the bytes are never trusted for
     * having arrived. expect_package_root is the caller's binding or NULL,
     * exactly as decided above; do not "simplify" it to NULL on the path
     * where the caller supplied one. */
    struct vcs_package_attest_transport_outcome outcome;
    memset(&outcome, 0, sizeof(outcome));
    enum vcs_package_attest_transport_result r =
        vcs_package_attest_transport_admit(store, zcode_dir, transport_root,
                                           expect_package_root, &outcome);
    zat_close_store(store, own_store);

    char rule[192];
    zat_rule_string(&outcome, r, rule);
    char transport_hex[65];
    zcl_hex_encode(transport_root, 32, transport_hex);

    if (r != VCS_PACKAGE_ATTEST_TRANSPORT_OK) {
        /* One code per rule, never "something went wrong". */
        const char *code = "ADMIT_REFUSED";
        const char *why = "the delivered bytes were not admitted";
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INVALID;
        if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB &&
            outcome.blob_error == VCS_BLOB_ERR_ABSENT) {
            code = "ATTESTATION_BYTES_ABSENT";
            why = "this node holds no blob at that transport root; fetch the "
                  "bytes first with zcode package fetch on the transport "
                  "root, or use zcode package attest pull to discover and "
                  "fetch them from a package root";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB) {
            code = "BLOB_REFUSED";
            why = "the blob layer refused the delivered bytes: the tracked "
                  "root is not a one-file blob, does not hash back to its "
                  "root, or exceeds the canonical attestation wire bound";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST) {
            code = "ATTESTATION_INVALID";
            why = "the delivered bytes are not a canonical ZCLATT wire, or "
                  "the embedded verifier signature does not verify";
        /* Deliberately no ERR_ID branch: it is structurally unreachable
         * here. ERR_ID comes only from the OFFER path, where the caller
         * names the filename and it can disagree with the id recomputed
         * from the bytes. This leaf calls _admit(), which derives the id
         * from the wire and files at that same derived id, so there is
         * nothing to mismatch. Naming an id check we do not perform would
         * tell a reader this leaf verifies more than it does. */
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING) {
            code = "PACKAGE_ROOT_BINDING";
            why = "the delivered attestation names a different package_root "
                  "than the one you asked about, so nothing was filed: it is "
                  "not evidence about your package";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT) {
            code = "STORE_CONFLICT";
            why = "a different or unreadable object already occupies this "
                  "attestation id — impossible for honest wires, since the "
                  "id is the content hash, so this fails closed";
            exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_STORE) {
            code = "STORE_WRITE";
            why = "the attestation could not be filed under "
                  "<datadir>/zcode/attestations";
            exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH) {
            code = "DATADIR_TOO_LONG";
            why = "datadir path too long";
        } else if (r == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC) {
            code = "ALLOC";
            why = "attestation wire buffer";
            exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        }
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code,
                               code, "execute", false, false, why, rule);
        return;
    }

    char id_hex[65], package_hex[65], release_hex[65], recipe_hex[65];
    char signer_hex[VCS_PACKAGE_ATTEST_PUBKEY_BYTES * 2 + 1];
    zcl_hex_encode(outcome.attestation_id, sizeof(outcome.attestation_id),
                   id_hex);
    zcl_hex_encode(outcome.attestation.package_root, 32, package_hex);
    zcl_hex_encode(outcome.attestation.release_id, 32, release_hex);
    zcl_hex_encode(outcome.attestation.recipe_root, 32, recipe_hex);
    zcl_hex_encode(outcome.attestation.verifier_pubkey,
                   sizeof(outcome.attestation.verifier_pubkey), signer_hex);

    (void)json_push_kv_str(&reply->data, "transport_root", transport_hex);
    (void)json_push_kv_str(&reply->data, "attestation_id", id_hex);
    (void)json_push_kv_str(&reply->data, "package_root", package_hex);
    (void)json_push_kv_str(&reply->data, "release_id", release_hex);
    (void)json_push_kv_str(&reply->data, "recipe_root", recipe_hex);
    (void)json_push_kv_str(&reply->data, "signer_pubkey", signer_hex);
    (void)json_push_kv_str(&reply->data, "result_class",
                           vcs_package_attest_result_string(
                               outcome.attestation.result_class));
    (void)json_push_kv_bool(&reply->data, "filed", outcome.filed);
    (void)json_push_kv_bool(&reply->data, "already_present",
                            outcome.already_present);
    (void)json_push_kv_str(&reply->data, "admit_result", rule);

    (void)json_push_kv_str(
        &reply->data, "note",
        expect_package_root
            ? "admitting is NOT accepting. The bytes were read back out of "
              "the package store (the blob layer re-verified the manifest, "
              "the root, and the chunk hash), re-parsed as a canonical "
              "ZCLATT wire, their embedded verifier signature re-verified, "
              "their id re-derived, and — because you passed package_root — "
              "checked to name exactly that package root before anything was "
              "filed. Nothing here consults the approved-verifier allowlist: "
              "this command deliberately files attestations from signers you "
              "have never approved, with failure result classes, for "
              "packages this node does not hold, because a quorum you can "
              "only observe when you already agree with it proves nothing. "
              "The quorum is applied later by zcode package verify. This "
              "leaf touches no DHT: it admits bytes you already have, so a "
              "node whose authenticated record layer is not up can still "
              "take in evidence it fetched"
            : "admitting is NOT accepting, and this admission was NOT BOUND "
              "TO ANY PACKAGE. The bytes were read back out of the package "
              "store (the blob layer re-verified the manifest, the root, and "
              "the chunk hash), re-parsed as a canonical ZCLATT wire, their "
              "embedded verifier signature re-verified, and their id "
              "re-derived — but you did not pass package_root, so this "
              "command filed whatever package the wire itself names and made "
              "NO claim that it is evidence about any package you care "
              "about. package_root is optional here ONLY because an operator "
              "may be filing bytes they already hold without asking a "
              "question about one package; if you are asking whether this "
              "attestation is evidence about a specific package, RE-RUN WITH "
              "package_root, and the reply's package_root field is what you "
              "would have had to compare by hand. zcode package attest pull "
              "makes that binding mandatory because it resolved the blob "
              "from a POINTER keyed on a package root, where an unbound "
              "admit would let a hostile pointer deliver an attestation for "
              "a DIFFERENT package as if it were evidence about yours. "
              "Nothing here consults the approved-verifier allowlist: "
              "unapproved signers and failure result classes are filed on "
              "purpose, and the quorum is applied later by zcode package "
              "verify");
}
