/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the two `zcode work` transport leaves — how a proven
 * accepted solution to a task MOVES between nodes:
 *
 *   zcode work offer   verify one held source package reconstructs to a
 *                      proven accepted work, derive the task root it
 *                      solves, and hand back the two ready-to-run
 *                      `zcode network publish` inputs that make the
 *                      solution discoverable BY TASK
 *   zcode work pull    given a task root, resolve every published
 *                      work-solution POINTER for it, fetch each distinct
 *                      package over the frozen swarm codec, and
 *                      re-derive each package's own task chain — refusing
 *                      any package that proves a different task
 *
 * A task is content-addressed: task_root. A solution is the source package
 * whose accepted-work chain (task -> candidate -> proof policy -> proof
 * receipts -> PROVEN lane) verifies against exactly that root. Discovery
 * is keyed by the PROBLEM, not by author or package name — a stranger who
 * knows only the task asks zclassic23.work at semantic_root=task_root and
 * learns every carrier claiming to solve it.
 *
 * NO NEW WIRE MESSAGE EXISTS HERE AND NONE MAY BE ADDED. A source package
 * rides the already-frozen 'zpkgswm' ANNOUNCE/WANT/DATA codec exactly like
 * any other carrier, fetched by `zcode package fetch`. Discovery is two
 * ordinary signed DHT records in VCS_ZCODE_WORK_DHT_NAMESPACE, and both
 * are required:
 *
 *   PROVIDER  transport_root = source package root
 *             — "ask me for these bytes". The record the fetch path
 *               actually routes on.
 *   POINTER   semantic_root  = the task root the package proves
 *             transport_root = source package root
 *             — "this package solves this task". What a puller looks up
 *               when all it knows is the task.
 *
 * They answer different questions and neither substitutes for the other,
 * for the same reason as the attestation lane: pointer-only means a puller
 * learns which package to want and finds nobody serving it; provider-only
 * means the bytes are reachable and nobody solving that task knows to ask.
 * `offer` returns BOTH inputs, provider first.
 *
 * THE ONE SECURITY PROPERTY ON THE PULL PATH is the receiver-side binding
 * check: every admit here passes the caller's task_root as
 * expect_task_root, never NULL. vcs_zcode_work_solution_admit reconstructs
 * the package from stored bytes — re-verifying the whole accepted-work
 * chain — and refuses unless the task the package ITSELF proves equals the
 * root the reader asked about. That is what stops a hostile pointer in
 * this namespace from delivering a solution to a different problem. The
 * publish-side gate in config/src/boot_zcode_dht_publish_gate.c is local
 * hygiene and constrains nobody else.
 *
 * PULLING IS NOT ACCEPTING, AND IT IS NOT EXECUTING. A verified row means
 * "this package proves it solves this task, and this node holds the
 * bytes" — nothing more. Reconstruction happens in fresh private scratch
 * that is removed before returning; downloaded source is never executed,
 * installed, or run. Doing anything with the source is the separate,
 * explicit acts the operator already has (checkout, reproduce).
 *
 * A row that fails stays in the report naming its rule. One bad pointer
 * never aborts the pull — the other solvers' packages still land.
 *
 * This lives in its own translation unit rather than in
 * native_zcode_work_command.c so the transport half of the work surface
 * has one file. Bound by config/commands/zcode.def. */

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/package_store.h"
#include "vcs/source_bundle.h"
#include "vcs/source_package_checkout.h"
#include "vcs/zcode_dht_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Row cap for a pull report. A task with more independent solvers than
 * this is a good problem; the reply says so rather than truncating
 * silently, and the operator raises maximum_records. */
#define ZWT_ROWS_DEFAULT 16u
#define ZWT_ROWS_CEILING 64u

/* Validity windows stamped into each ready-to-run publish input. PER KIND
 * and derived from the record layer's own ceilings, because the two kinds
 * do not share one: VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS is 7200 while
 * VCS_ZCODE_DHT_POINTER_MAX_SECONDS is 604800. A provider ad is a claim
 * about reachability right now and is short-lived on purpose; a pointer is
 * a claim about content that stays true. The operator may edit either
 * number before running publish. */
#define ZWT_PROVIDER_WINDOW_S VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS
#define ZWT_POINTER_WINDOW_S UINT64_C(86400)

/* Fail the BUILD, not the operator's publish, if either ceiling moves
 * under us: an unpublishable input handed out as "ready to run" is a
 * defect that only shows up at the far end of a two-command sequence. */
static_assert(ZWT_PROVIDER_WINDOW_S <= VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS,
              "the provider publish input must be publishable as a PROVIDER "
              "record; an over-long window is refused and leaves the "
              "operator pointer-only");
static_assert(ZWT_POINTER_WINDOW_S <= VCS_ZCODE_DHT_POINTER_MAX_SECONDS,
              "the pointer publish input must be publishable as a POINTER "
              "record");

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zwt_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zwt_datadir(const struct zcl_command_request *request)
{
    const char *dd = zwt_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static bool zwt_zcode_dir(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply,
                          const char *command, char out[4400])
{
    const char *datadir = zwt_datadir(request);
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
static bool zwt_hex32(const struct zcl_command_request *request,
                      struct zcl_command_reply *reply, const char *command,
                      const char *key, const char *code, const char *what,
                      uint8_t out[32])
{
    const char *hex = zwt_input_str(request->input, key);
    if (!hex || strlen(hex) != 64 || !zcl_hex_decode_lower(hex, out, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "normalize",
                               false, false, what,
                               hex && hex[0] ? hex : command);
        return false;
    }
    return true;
}

/* The store these leaves verify and fetch through. The node-global handle
 * when a hosting daemon owns this process; otherwise the datadir's own
 * store, exactly as zcode package fetch does for its one-shot path. pull
 * is MUTATE, so opening the store is not a read side-effect. */
static struct vcs_package_store *zwt_open_store(
    const struct zcl_command_request *request, bool *own_out)
{
    *own_out = false;
    struct vcs_package_store *store = vcs_package_store_global();
    if (store)
        return store;
    const char *datadir = zwt_datadir(request);
    if (!datadir || !datadir[0])
        return NULL;
    store = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (!store) {
        LOG_ERROR("zcode.work", "package store failed to open under %s",
                  datadir);
        return NULL;
    }
    *own_out = true;
    return store;
}

static void zwt_close_store(struct vcs_package_store *store, bool own)
{
    if (own && store)
        vcs_package_store_close(store);
}

/* Fill one ready-to-run `zcode network publish` input. kind decides
 * whether semantic_root (the task root) is carried. */
static void zwt_publish_input(struct json_value *out, const char *kind,
                              const char *semantic_root_hex,
                              const char *transport_root_hex, uint64_t now,
                              uint64_t window_s)
{
    json_set_object(out);
    (void)json_push_kv_str(out, "mode", "plan");
    (void)json_push_kv_str(out, "kind", kind);
    (void)json_push_kv_str(out, "namespace", VCS_ZCODE_WORK_DHT_NAMESPACE);
    if (semantic_root_hex)
        (void)json_push_kv_str(out, "semantic_root", semantic_root_hex);
    (void)json_push_kv_str(out, "transport_root", transport_root_hex);
    (void)json_push_kv_int(out, "sequence", (int64_t)now);
    (void)json_push_kv_int(out, "not_before", (int64_t)now);
    (void)json_push_kv_int(out, "expiry", (int64_t)(now + window_s));
}

/* ── zcode work offer ───────────────────────────────────────────────── */

void zcl_native_handle_zcode_work_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zwt_zcode_dir(request, reply, "zcode.work.offer", zcode_dir))
        return;
    uint8_t package_root[32];
    if (!zwt_hex32(request, reply, "zcode.work.offer", "package_root",
                   "BAD_PACKAGE_ROOT",
                   "package_root must be 64 lowercase hex chars (the "
                   "accepted source package root)", package_root))
        return;

    bool own_store = false;
    struct vcs_package_store *store = zwt_open_store(request, &own_store);
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store could not be opened; a "
                               "solution cannot be verified or made "
                               "reachable without one",
                               zcode_dir);
        return;
    }

    /* expect_task_root is NULL here on purpose: offer DERIVES the task
     * root rather than checking one. The package's own accepted-work
     * chain is the only authority on which task it solves — that is the
     * binding every later reader re-derives, so it is the binding this
     * command reports. One call proves the package is held complete and
     * reconstructs to a verified chain (task, candidate, proof policy,
     * every receipt, PROVEN lane) before a single publish input exists,
     * and hands back the derived task root as an output of verification. */
    uint8_t task_root[32], source_root[32], accepted_work_root[32];
    enum vcs_zcode_work_admit_result r = vcs_zcode_work_solution_admit(
        store, package_root, NULL, task_root, source_root,
        accepted_work_root);
    zwt_close_store(store, own_store);

    char package_hex[65];
    zcl_hex_encode(package_root, 32, package_hex);
    if (r != VCS_ZCODE_WORK_ADMIT_OK) {
        const char *code = "WORK_NOT_RECONSTRUCTIBLE";
        const char *why =
            "the package at package_root is not held complete in this "
            "node's store, or does not reconstruct to a verified "
            "accepted-work chain; accept the work first (zcode work "
            "accept) and offer the resulting source package root";
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "execute",
                               false, false, why, package_hex);
        return;
    }

    char task_hex[65], source_hex[65], work_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);
    zcl_hex_encode(source_root, 32, source_hex);
    zcl_hex_encode(accepted_work_root, 32, work_hex);

    (void)json_push_kv_str(&reply->data, "package_root", package_hex);
    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "source_root", source_hex);
    (void)json_push_kv_str(&reply->data, "accepted_work_root", work_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_WORK_DHT_NAMESPACE);

    /* PROVIDER first: it is the record the fetch path actually routes on. */
    uint64_t now = (uint64_t)platform_time_wall_unix();
    struct json_value publish;
    json_init(&publish);
    zwt_publish_input(&publish, "provider", NULL, package_hex, now,
                      ZWT_PROVIDER_WINDOW_S);
    (void)json_push_kv(&reply->data, "provider_publish_input", &publish);
    json_free(&publish);
    json_init(&publish);
    zwt_publish_input(&publish, "pointer", task_hex, package_hex, now,
                      ZWT_POINTER_WINDOW_S);
    (void)json_push_kv(&reply->data, "pointer_publish_input", &publish);
    json_free(&publish);

    (void)json_push_kv_str(
        &reply->data, "note",
        "offering verifies what THIS node holds and announces NOTHING: no "
        "peer can find the solution yet. Telling the network is the "
        "separate second act, and it takes BOTH records in this namespace: "
        "run zcode network publish with provider_publish_input (\"ask me "
        "for these bytes\" — the record the fetch path routes on) AND with "
        "pointer_publish_input (\"this package solves this task\" — what a "
        "puller looks up when all it knows is the task root). Either one "
        "alone is a silent no-op at pull time. Both inputs are mode=plan; "
        "each returns a plan_token to commit. The task root in the pointer "
        "is the one the package's own accepted-work chain proves, derived "
        "here by verification — never typed by the operator");
}

/* ── zcode work pull ────────────────────────────────────────────────── */

/* One resolved pointer's fate, kept flat so a failure never grows a
 * control path that could abort the sweep. */
struct zwt_row {
    char transport_root[65];
    char fetch_outcome[96];   /* the fetch path's own named verdict */
    bool fetched;
    char admit_rule[192];     /* the work layer's NAMED result */
    bool admitted;
    char source_root[65];     /* filled only on a verified row */
    char accepted_work_root[65];
};

/* Drive the EXISTING record-discovery handler rather than reimplementing a
 * DHT query: {kind:"pointer", namespace, semantic_root} is exactly the
 * selector the records handler parses. Returns false with the error body
 * already set on the caller's reply. */
static bool zwt_query_pointers(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply,
                               const char *task_root_hex,
                               struct json_value *records_out)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "kind", "pointer");
    (void)json_push_kv_str(&input, "namespace", VCS_ZCODE_WORK_DHT_NAMESPACE);
    (void)json_push_kv_str(&input, "semantic_root", task_root_hex);
    const char *datadir = zwt_input_str(request->input, "datadir");
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
                : "the work pointer lookup did not complete",
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

/* Drive the EXISTING fetch handler for one source package root. Never
 * fails the caller: the row records whatever verdict came back. */
static void zwt_fetch_one(const struct zcl_command_request *request,
                          const char *transport_root_hex,
                          struct zwt_row *row)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "root", transport_root_hex);
    (void)json_push_kv_str(&input, "namespace", VCS_ZCODE_WORK_DHT_NAMESPACE);
    const char *datadir = zwt_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&input, "datadir", datadir);
    (void)json_push_kv_int(&input, "maximum_bytes",
                           (int64_t)VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES);
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

void zcl_native_handle_zcode_work_pull(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zwt_zcode_dir(request, reply, "zcode.work.pull", zcode_dir))
        return;
    uint8_t task_root[32];
    if (!zwt_hex32(request, reply, "zcode.work.pull", "task_root",
                   "BAD_TASK_ROOT",
                   "task_root must be 64 lowercase hex chars (the task the "
                   "packages must prove they solve)", task_root))
        return;
    char task_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);

    uint32_t cap = ZWT_ROWS_DEFAULT;
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
                                   "zcode.work.pull");
            return;
        }
        cap = want > (int64_t)ZWT_ROWS_CEILING ? ZWT_ROWS_CEILING
                                               : (uint32_t)want;
    }

    struct json_value pointers;
    if (!zwt_query_pointers(request, reply, task_hex, &pointers))
        return;

    /* Distinct transport roots, in discovery order, bounded. Two solvers
     * may publish two packages; a republished sequence of the same package
     * collapses here so a solver cannot consume the row budget by
     * republishing. */
    size_t seen = json_size(&pointers);
    struct zwt_row *rows = zcl_calloc(cap, sizeof(*rows), "zwt_pull_rows");
    if (!rows) {
        json_free(&pointers);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "execute",
                               false, false, "pull row table",
                               "zcode.work.pull");
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
        distinct++;
    }
    json_free(&pointers);

    bool own_store = false;
    struct vcs_package_store *store = NULL;
    if (distinct > 0) {
        store = zwt_open_store(request, &own_store);
        if (!store) {
            free(rows);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                                   "execute", false, false,
                                   "the package store could not be opened; "
                                   "solution packages cannot be fetched or "
                                   "verified without one",
                                   zcode_dir);
            return;
        }
    }

    uint32_t fetched = 0, admitted = 0, refused = 0;
    for (uint32_t i = 0; i < distinct; i++) {
        struct zwt_row *row = &rows[i];
        zwt_fetch_one(request, row->transport_root, row);
        fetched += row->fetched ? 1u : 0u;

        /* expect_task_root is the caller's root and is NEVER NULL. This
         * single argument is the whole reason a hostile pointer in this
         * namespace cannot deliver a solution to a different problem: the
         * package's own accepted-work chain must re-verify AND name this
         * exact task. Do not "simplify" it to NULL. The check runs even
         * when the fetch only SCHEDULED the download — the store is the
         * authority on whether the bytes are here, and its refusal names
         * the rule. A row that fails stays in the report; the sweep
         * continues so one bad or unreachable pointer cannot cost the
         * other solvers' packages. */
        uint8_t transport_root[32];
        if (!zcl_hex_decode_lower(row->transport_root, transport_root, 32)) {
            (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                           "pointer-transport-root-not-canonical-hex");
            refused++;
            continue;
        }
        uint8_t derived_task_root[32], source_root[32],
            accepted_work_root[32];
        enum vcs_zcode_work_admit_result r = vcs_zcode_work_solution_admit(
            store, transport_root, task_root, derived_task_root,
            source_root, accepted_work_root);
        (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                       vcs_zcode_work_admit_result_string(r));
        if (r != VCS_ZCODE_WORK_ADMIT_OK) {
            refused++;
            continue;
        }
        row->admitted = true;
        admitted++;
        zcl_hex_encode(source_root, 32, row->source_root);
        zcl_hex_encode(accepted_work_root, 32, row->accepted_work_root);
    }
    zwt_close_store(store, own_store);

    /* Two very different dead ends, never merged into one "not found":
     * nobody has solved this task yet, versus somebody has and nobody
     * reachable is serving the package. The next step differs
     * completely — wait for a solver, or fix reachability. */
    const char *status = "SOLUTIONS_VERIFIED";
    const char *blocker = "";
    if (distinct == 0) {
        status = "NO_WORK_POINTERS";
        blocker = "no_pointer_record_names_a_solution_for_this_task_root";
    } else if (admitted == 0) {
        /* Only once NOTHING landed is it honest to name a dead end.
         * admitted is tested BEFORE fetched because the admit above is
         * deliberately unconditional: a package this node already holds
         * verifies even when provider discovery served nothing. Testing
         * fetched first would print "no authenticated provider served the
         * solution bytes" in a reply that also says admitted=1. */
        if (fetched == 0) {
            status = "WORK_BYTES_UNREACHABLE";
            blocker = "pointers_exist_but_no_authenticated_provider_served_"
                      "the_solution_bytes";
        } else {
            status = "SOLUTIONS_REFUSED";
            blocker = "every_fetched_package_failed_a_named_admission_rule";
        }
    }

    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_WORK_DHT_NAMESPACE);
    (void)json_push_kv_str(&reply->data, "status", status);
    if (blocker[0])
        (void)json_push_kv_str(&reply->data, "blocker", blocker);
    (void)json_push_kv_int(&reply->data, "pointers_seen", (int64_t)seen);
    (void)json_push_kv_int(&reply->data, "distinct_transport_roots",
                           (int64_t)distinct);
    (void)json_push_kv_int(&reply->data, "fetched", (int64_t)fetched);
    (void)json_push_kv_int(&reply->data, "admitted", (int64_t)admitted);
    (void)json_push_kv_int(&reply->data, "refused", (int64_t)refused);
    (void)json_push_kv_int(&reply->data, "maximum_records", (int64_t)cap);
    (void)json_push_kv_bool(&reply->data, "rows_truncated", truncated);

    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (uint32_t i = 0; i < distinct; i++) {
        const struct zwt_row *row = &rows[i];
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "transport_root", row->transport_root);
        (void)json_push_kv_str(&entry, "fetch_outcome", row->fetch_outcome);
        (void)json_push_kv_bool(&entry, "fetched", row->fetched);
        (void)json_push_kv_str(&entry, "admit_result", row->admit_rule);
        (void)json_push_kv_bool(&entry, "admitted", row->admitted);
        (void)json_push_kv_str(&entry, "source_root", row->source_root);
        (void)json_push_kv_str(&entry, "accepted_work_root",
                               row->accepted_work_root);
        (void)json_push_back(&list, &entry);
        json_free(&entry);
    }
    (void)json_push_kv(&reply->data, "rows", &list);
    json_free(&list);
    free(rows);

    (void)json_push_kv_str(
        &reply->data, "note",
        "pulling is NOT accepting, and it is NOT executing. Every "
        "admitted row was reconstructed from stored bytes — re-verifying "
        "the package's whole accepted-work chain — and refused unless the "
        "task that chain proves equals the task_root you asked about, so "
        "a hostile pointer in this namespace cannot deliver a solution to "
        "a different problem. Reconstruction ran in fresh private scratch "
        "that was removed before returning; nothing was executed, "
        "installed, or run, and nothing here says the solution is GOOD — "
        "only that it is genuinely a solution to this task. Choosing what "
        "to do with the source (checkout, reproduce) is a separate, "
        "explicit act. A row that failed stays in the report naming its "
        "rule and never aborts the sweep. Read status: NO_WORK_POINTERS "
        "means nobody has published a solution for this task yet; "
        "WORK_BYTES_UNREACHABLE means solutions exist but no "
        "authenticated provider served the bytes (a reachability problem, "
        "or the publisher never ran the PROVIDER half of zcode work "
        "offer). Those are different problems and are never reported as "
        "one");
}
