/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `zcode work` transport leaves — how a proven
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
 *   zcode work receipt verify one durable pull receipt by root
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
 * publish-side gate in engine/composition/src/boot_zcode_dht_publish_gate.c is local
 * hygiene and constrains nobody else.
 *
 * PULLING IS NOT ACCEPTING, AND IT IS NOT EXECUTING. A verified row means
 * "this package proves it solves this task, and this node holds the
 * bytes" — nothing more. Reconstruction happens in fresh private scratch
 * that is removed before returning; downloaded source is never executed,
 * installed, or run. Doing anything with the source is the separate,
 * explicit acts the operator already has (checkout, reproduce).
 *
 * A verified row is also recorded, once and durably, as this observer
 * node's signed work receipt in <datadir>/zcode (vcs/zcode_work_pull_receipt.h)
 * — the lifecycle's remote receipt for that pointer — and `zcode work
 * receipt` verifies one by root. A refused row never yields a receipt.
 *
 * A row that fails stays in the report naming its rule. One bad pointer
 * never aborts the pull — the other solvers' packages still land.
 *
 * This lives in its own translation unit rather than in
 * native_zcode_work_command.c so the transport half of the work surface
 * has one file. Bound by engine/composition/commands/zcode.def. */

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "command/native_zcode_transport_leaves.h"

#include "json/json.h"
#include "models/build_fabric.h"
#include "platform/time_compat.h"
#include "services/build_fabric_worker.h"
#include "vcs/package_store.h"
#include "vcs/source_bundle.h"
#include "vcs/source_package_checkout.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/zcode_work_pull_receipt.h"

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

/* ── zcode work offer ───────────────────────────────────────────────── */

void zcl_native_handle_zcode_work_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.work.offer", zcode_dir))
        return;
    uint8_t package_root[32];
    if (!ztl_hex32(request, reply, "zcode.work.offer", "package_root",
                   "BAD_PACKAGE_ROOT",
                   "the accepted source package root", package_root))
        return;

    bool own_store = false;
    struct vcs_package_store *store =
        ztl_open_store(request, &own_store, "zcode.work");
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
    ztl_close_store(store, own_store);

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
    ztl_publish_input(&publish, "provider", VCS_ZCODE_WORK_DHT_NAMESPACE,
                      NULL, package_hex, now, ZWT_PROVIDER_WINDOW_S);
    (void)json_push_kv(&reply->data, "provider_publish_input", &publish);
    json_free(&publish);
    json_init(&publish);
    ztl_publish_input(&publish, "pointer", VCS_ZCODE_WORK_DHT_NAMESPACE,
                      task_hex, package_hex, now, ZWT_POINTER_WINDOW_S);
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

/* A fetch the running node accepted may still be committing its chunks
 * when the fetch reply returns. The pull waits — bounded, once per pull
 * across all rows — for the store to report the package complete, so its
 * verdict reflects the commit it started rather than racing it. */
#define ZWT_SETTLE_MS INT64_C(15000)
#define ZWT_SETTLE_POLL_MS 250

/* One resolved pointer's fate, kept flat so a failure never grows a
 * control path that could abort the sweep. */
struct zwt_row {
    char transport_root[65];
    char pointer_root[65];    /* record_root of the POINTER naming it */
    bool pointer_usable;      /* neither conflicted nor superseded */
    char fetch_outcome[96];   /* the fetch path's own named verdict */
    bool fetched;
    bool pending;             /* accepted, not complete within the wait */
    int64_t settle_ms;
    char admit_rule[192];     /* the work layer's NAMED result */
    bool admitted;
    char source_root[65];     /* filled only on a verified row */
    char accepted_work_root[65];
    char receipt_root[65];    /* filled only when a receipt is held */
    const char *receipt_result;
    bool receipt_attached;
};

/* The sweep's shared state: the store (reopened while settling when this
 * process owns a one-shot handle), the observer identity that signs pull
 * receipts, and the running totals. */
struct zwt_pull {
    const struct zcl_command_request *request;
    uint8_t task_root[32];
    const char *datadir;
    const char *workspace;
    struct vcs_package_store *store;
    bool own_store;
    bool observer;
    uint8_t secret[32];
    uint8_t pubkey[32];
    int64_t started_unix;
    int64_t settle_deadline_ms;
    uint32_t fetched, admitted, refused, pending, receipts;
};

static bool zwt_record_usable(const struct json_value *record)
{
    return !json_get_bool(json_get(record, "conflicted")) &&
        !json_get_bool(json_get(record, "superseded"));
}

static void zwt_row_pointer(struct zwt_row *row, const char *pointer,
                            bool usable)
{
    if (!pointer || strlen(pointer) != 64)
        return;
    if (row->pointer_root[0] && (row->pointer_usable || !usable))
        return;
    (void)snprintf(row->pointer_root, sizeof(row->pointer_root), "%s",
                   pointer);
    row->pointer_usable = usable;
}

static void zwt_row_init(struct zwt_row *row, const char *transport)
{
    (void)snprintf(row->transport_root, sizeof(row->transport_root), "%s",
                   transport);
    (void)snprintf(row->fetch_outcome, sizeof(row->fetch_outcome), "%s",
                   "not-attempted");
    (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                   "not-attempted");
    row->receipt_result = "not-attempted";
}

/* Distinct transport roots, in discovery order, bounded. Two solvers may
 * publish two packages; a republished sequence of the same package
 * collapses here so a solver cannot consume the row budget by
 * republishing. Each row keeps one POINTER record root — a usable one when
 * any exists — as the publication its receipt binds. */
static uint32_t zwt_collect(const struct json_value *pointers,
                            const char *task_hex, struct zwt_row *rows,
                            uint32_t cap, bool *truncated)
{
    uint32_t distinct = 0;
    size_t seen = json_size(pointers);
    for (size_t i = 0; i < seen; i++) {
        const struct json_value *record = json_at(pointers, i);
        const char *transport =
            record ? json_get_str(json_get(record, "transport_root")) : NULL;
        const char *semantic =
            record ? json_get_str(json_get(record, "semantic_root")) : NULL;
        if (!transport || strlen(transport) != 64 ||
            (semantic && strcmp(semantic, task_hex) != 0))
            continue;
        uint32_t at = 0;
        while (at < distinct && strcmp(rows[at].transport_root, transport))
            at++;
        if (at == distinct && distinct >= cap) {
            *truncated = true;
            break;
        }
        if (at == distinct)
            zwt_row_init(&rows[distinct++], transport);
        zwt_row_pointer(&rows[at],
                        json_get_str(json_get(record, "record_root")),
                        zwt_record_usable(record));
    }
    return distinct;
}

static bool zwt_store_complete(struct vcs_package_store *store,
                               const uint8_t root[32])
{
    struct vcs_package_store_status status;
    memset(&status, 0, sizeof(status));
    return store && vcs_package_store_package_status(store, root, &status) &&
        status.tracked && status.complete;
}

/* A one-shot handle indexes the store once at open, so bytes the running
 * node commits afterwards are visible only to a fresh open. */
static bool zwt_settle(struct zwt_pull *p, const uint8_t root[32],
                       int64_t *waited_ms)
{
    int64_t start = platform_time_monotonic_ms();
    if (p->settle_deadline_ms == 0)
        p->settle_deadline_ms = start + ZWT_SETTLE_MS;
    bool complete = zwt_store_complete(p->store, root);
    while (!complete && platform_time_monotonic_ms() < p->settle_deadline_ms) {
        platform_sleep_ms(ZWT_SETTLE_POLL_MS);
        if (p->own_store) {
            ztl_close_store(p->store, true);
            p->store = vcs_package_store_open(
                p->datadir, vcs_package_store_quota_bytes());
        }
        complete = zwt_store_complete(p->store, root);
    }
    *waited_ms = platform_time_monotonic_ms() - start;
    return complete;
}

static void zwt_row_receipt(struct zwt_pull *p, struct zwt_row *row,
                            enum vcs_zcode_work_pull_receipt_result result,
                            const struct vcs_zcode_work_pull_observation *o)
{
    row->receipt_result = vcs_zcode_work_pull_receipt_result_string(result);
    if (result != VCS_ZCODE_WORK_PULL_RECEIPT_OK)
        return;
    zcl_hex_encode(o->receipt_root, 32, row->receipt_root);
    row->receipt_attached = o->attached;
    p->receipts++;
}

static void zwt_pull_row(struct zwt_pull *p, struct zwt_row *row)
{
    bool accepted = false;
    ztl_fetch_one(p->request, VCS_ZCODE_WORK_DHT_NAMESPACE,
                  row->transport_root,
                  (int64_t)VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES, &row->fetched,
                  &accepted, row->fetch_outcome, sizeof(row->fetch_outcome));
    struct vcs_zcode_work_pull_observation o;
    memset(&o, 0, sizeof(o));
    if (!zcl_hex_decode_lower(row->transport_root, o.package_root, 32)) {
        (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                       "pointer-transport-root-not-canonical-hex");
        p->refused++;
        return;
    }
    if (accepted && !row->fetched) {
        row->fetched = zwt_settle(p, o.package_root, &row->settle_ms);
        row->pending = !row->fetched;
    }
    p->fetched += row->fetched ? 1u : 0u;
    p->pending += row->pending ? 1u : 0u;

    /* The observation's task root is the caller's root and is NEVER
     * NULL: vcs_zcode_work_pull_observe admits with it as
     * expect_task_root. This single binding is the whole reason a hostile
     * pointer in this namespace cannot deliver a solution to a different
     * problem: the package's own accepted-work chain must re-verify AND
     * name this exact task. The check runs even when the fetch only
     * scheduled the download — the store is the authority on whether the
     * bytes are here — and only a verified row yields a receipt. A row
     * that fails stays in the report; the sweep continues so one bad or
     * unreachable pointer cannot cost the other solvers' packages. */
    memcpy(o.task_root, p->task_root, 32);
    (void)zcl_hex_decode_lower(row->pointer_root, o.pointer_root, 32);
    o.started_unix = p->started_unix;
    int64_t now = (int64_t)platform_time_wall_unix();
    o.observed_unix = now < p->started_unix ? p->started_unix : now;
    enum vcs_zcode_work_pull_receipt_result result =
        vcs_zcode_work_pull_observe(p->store, p->workspace,
                                    p->observer ? p->secret : NULL,
                                    p->observer ? p->pubkey : NULL, &o);
    (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                   vcs_zcode_work_admit_result_string(o.admit));
    if (o.admit != VCS_ZCODE_WORK_ADMIT_OK) {
        row->receipt_result = "not-verified";
        p->refused++;
        return;
    }
    row->admitted = true;
    p->admitted++;
    zcl_hex_encode(o.source_root, 32, row->source_root);
    zcl_hex_encode(o.accepted_work_root, 32, row->accepted_work_root);
    zwt_row_receipt(p, row, result, &o);
}

/* Four dead ends that must never be merged into one "not found": nobody
 * has solved this task yet; somebody has and nobody reachable served the
 * package; a download was accepted but did not finish inside the bounded
 * wait; or every package that arrived failed a named rule. The next step
 * differs for each. Only once NOTHING landed is it honest to name a dead
 * end, and admitted is tested BEFORE fetched because the admit is
 * deliberately unconditional: a package this node already holds verifies
 * even when provider discovery served nothing. */
static const char *zwt_status(uint32_t distinct, const struct zwt_pull *p,
                              const char **blocker)
{
    *blocker = "";
    if (distinct == 0) {
        *blocker = "no_pointer_record_names_a_solution_for_this_task_root";
        return "NO_WORK_POINTERS";
    }
    if (p->admitted > 0)
        return "SOLUTIONS_VERIFIED";
    if (p->fetched == 0 && p->pending > 0) {
        *blocker = "a_fetch_was_accepted_but_the_package_did_not_complete_"
                   "within_the_bounded_wait";
        return "WORK_BYTES_PENDING";
    }
    if (p->fetched == 0) {
        *blocker = "pointers_exist_but_no_authenticated_provider_served_"
                   "the_solution_bytes";
        return "WORK_BYTES_UNREACHABLE";
    }
    *blocker = "every_fetched_package_failed_a_named_admission_rule";
    return "SOLUTIONS_REFUSED";
}

static void zwt_push_row(struct json_value *list, const struct zwt_row *row)
{
    struct json_value entry;
    json_init(&entry);
    json_set_object(&entry);
    (void)json_push_kv_str(&entry, "transport_root", row->transport_root);
    (void)json_push_kv_str(&entry, "pointer_root", row->pointer_root);
    (void)json_push_kv_str(&entry, "fetch_outcome", row->fetch_outcome);
    (void)json_push_kv_bool(&entry, "fetched", row->fetched);
    (void)json_push_kv_int(&entry, "settle_ms", row->settle_ms);
    (void)json_push_kv_str(&entry, "admit_result", row->admit_rule);
    (void)json_push_kv_bool(&entry, "admitted", row->admitted);
    (void)json_push_kv_str(&entry, "source_root", row->source_root);
    (void)json_push_kv_str(&entry, "accepted_work_root",
                           row->accepted_work_root);
    (void)json_push_kv_str(&entry, "receipt_result", row->receipt_result);
    (void)json_push_kv_str(&entry, "receipt_root", row->receipt_root);
    (void)json_push_kv_bool(&entry, "receipt_attached",
                            row->receipt_attached);
    (void)json_push_back(list, &entry);
    json_free(&entry);
}

static void zwt_push_report(struct zcl_command_reply *reply,
                            const char *task_hex, size_t seen,
                            uint32_t distinct, uint32_t cap, bool truncated,
                            const struct zwt_pull *p,
                            const struct zwt_row *rows)
{
    const char *blocker = "";
    const char *status = zwt_status(distinct, p, &blocker);
    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_WORK_DHT_NAMESPACE);
    (void)json_push_kv_str(&reply->data, "status", status);
    if (blocker[0])
        (void)json_push_kv_str(&reply->data, "blocker", blocker);
    (void)json_push_kv_int(&reply->data, "pointers_seen", (int64_t)seen);
    (void)json_push_kv_int(&reply->data, "distinct_transport_roots",
                           (int64_t)distinct);
    (void)json_push_kv_int(&reply->data, "fetched", (int64_t)p->fetched);
    (void)json_push_kv_int(&reply->data, "admitted", (int64_t)p->admitted);
    (void)json_push_kv_int(&reply->data, "refused", (int64_t)p->refused);
    (void)json_push_kv_int(&reply->data, "receipts", (int64_t)p->receipts);
    char observer_hex[65] = "";
    if (p->observer)
        zcl_hex_encode(p->pubkey, 32, observer_hex);
    (void)json_push_kv_str(&reply->data, "observer_pubkey", observer_hex);
    (void)json_push_kv_int(&reply->data, "maximum_records", (int64_t)cap);
    (void)json_push_kv_bool(&reply->data, "rows_truncated", truncated);
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (uint32_t i = 0; i < distinct; i++)
        zwt_push_row(&list, &rows[i]);
    (void)json_push_kv(&reply->data, "rows", &list);
    json_free(&list);
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
        "only that it is genuinely a solution to this task. Each admitted "
        "row is recorded once as this node's signed work receipt "
        "(receipt_root, in <datadir>/zcode) binding the pointer, package, "
        "task, source, candidate and accepted-work roots; a repeat pull of "
        "the same roots attaches to it (receipt_attached) and a refused row "
        "never produces one. Check one with zcode work receipt. Choosing "
        "what to do with the source (checkout, reproduce) is a separate, "
        "explicit act. A row that failed stays in the report naming its "
        "rule and never aborts the sweep. Read status: NO_WORK_POINTERS "
        "means nobody has published a solution for this task yet; "
        "WORK_BYTES_UNREACHABLE means solutions exist but no "
        "authenticated provider served the bytes (a reachability problem, "
        "or the publisher never ran the PROVIDER half of zcode work "
        "offer); WORK_BYTES_PENDING means a download was accepted but did "
        "not finish within the bounded wait — pull again. Those are "
        "different problems and are never reported as one");
}

static void zwt_load_observer(struct zwt_pull *p)
{
    struct db_build_worker worker;
    p->observer = p->datadir &&
        build_fabric_worker_identity_load(p->datadir, &worker, p->secret,
                                          p->pubkey).ok;
    if (!p->observer) {
        memory_cleanse(p->secret, sizeof(p->secret));
        memset(p->pubkey, 0, sizeof(p->pubkey));
    }
}

static bool zwt_pull_cap(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply, uint32_t *cap)
{
    *cap = ZWT_ROWS_DEFAULT;
    const struct json_value *mv = json_get(request->input, "maximum_records");
    if (!mv || mv->type != JSON_INT)
        return true;
    int64_t want = json_get_int(mv);
    if (want <= 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "BAD_MAXIMUM_RECORDS", "normalize", false,
                               false,
                               "maximum_records must be a positive integer",
                               "zcode.work.pull");
        return false;
    }
    *cap = want > (int64_t)ZWT_ROWS_CEILING ? ZWT_ROWS_CEILING
                                            : (uint32_t)want;
    return true;
}

static void zwt_pull_rows(struct zwt_pull *p, struct zwt_row *rows,
                          uint32_t distinct)
{
    zwt_load_observer(p);
    for (uint32_t i = 0; i < distinct; i++)
        zwt_pull_row(p, &rows[i]);
    memory_cleanse(p->secret, sizeof(p->secret));
}

void zcl_native_handle_zcode_work_pull(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.work.pull", zcode_dir))
        return;
    struct zwt_pull p;
    memset(&p, 0, sizeof(p));
    p.request = request;
    p.datadir = ztl_datadir(request);
    p.workspace = zcode_dir;
    p.started_unix = (int64_t)platform_time_wall_unix();
    if (!ztl_hex32(request, reply, "zcode.work.pull", "task_root",
                   "BAD_TASK_ROOT",
                   "the task the packages must prove they solve",
                   p.task_root))
        return;
    char task_hex[65];
    zcl_hex_encode(p.task_root, 32, task_hex);
    uint32_t cap = ZWT_ROWS_DEFAULT;
    if (!zwt_pull_cap(request, reply, &cap))
        return;

    struct json_value pointers;
    if (!ztl_query_pointers(request, reply, VCS_ZCODE_WORK_DHT_NAMESPACE,
                            task_hex, &pointers))
        return;
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
    bool truncated = false;
    uint32_t distinct = zwt_collect(&pointers, task_hex, rows, cap,
                                    &truncated);
    json_free(&pointers);

    if (distinct > 0) {
        p.store = ztl_open_store(request, &p.own_store, "zcode.work");
        if (!p.store) {
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
        zwt_pull_rows(&p, rows, distinct);
    }
    ztl_close_store(p.store, p.own_store);
    zwt_push_report(reply, task_hex, seen, distinct, cap, truncated, &p,
                    rows);
    free(rows);
}

/* ── zcode work receipt ─────────────────────────────────────────────── */

static void zwt_receipt_fail(struct zcl_command_reply *reply,
                             enum vcs_zcode_work_pull_receipt_result result,
                             const char *root_hex)
{
    char message[192];
    (void)snprintf(message, sizeof(message),
                   "the work pull receipt did not verify: %s",
                   vcs_zcode_work_pull_receipt_result_string(result));
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
        result == VCS_ZCODE_WORK_PULL_RECEIPT_NOT_FOUND
            ? "WORK_RECEIPT_NOT_FOUND"
            : result == VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED
            ? "WORK_RECEIPT_CONTRADICTED" : "WORK_RECEIPT_REFUSED",
        "verify", false, false, message, root_hex);
}

/* A supplied wire is verified exactly as a CAS copy would be, so a party
 * that never held the receipt can check one handed to it. */
static enum vcs_zcode_work_pull_receipt_result zwt_receipt_resolve(
    const struct zcl_command_request *request, const char *zcode_dir,
    const uint8_t root[32], struct vcs_zcode_work_receipt_v1 *receipt)
{
    const char *wire_hex = ztl_input_str(request->input, "receipt_hex");
    if (!wire_hex || !wire_hex[0])
        return vcs_zcode_work_pull_receipt_load(zcode_dir, root, receipt);
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES], checked[32];
    if (!zcl_hex_decode_lower(wire_hex, wire, sizeof(wire)))
        return VCS_ZCODE_WORK_PULL_RECEIPT_CODEC;
    return vcs_zcode_work_pull_receipt_decode(wire, sizeof(wire), root,
                                              receipt, checked);
}

static void zwt_push_hex(struct json_value *data, const char *key,
                         const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(data, key, hex);
}

static void zwt_push_receipt(struct json_value *data,
                             const struct vcs_zcode_work_receipt_v1 *r)
{
    zwt_push_hex(data, "task_root", r->task_root);
    zwt_push_hex(data, "package_root", r->input_root);
    zwt_push_hex(data, "pointer_root", r->lease_id);
    zwt_push_hex(data, "source_root", r->output_root);
    zwt_push_hex(data, "accepted_work_root", r->evidence_root);
    zwt_push_hex(data, "candidate_root", r->candidate_root);
    zwt_push_hex(data, "proof_policy_root", r->proof_policy_root);
    zwt_push_hex(data, "toolchain_capsule_root", r->toolchain_capsule_root);
    zwt_push_hex(data, "action_root", r->action_root);
    zwt_push_hex(data, "observer_pubkey", r->signer_pubkey);
    (void)json_push_kv_int(data, "started_unix", r->started_unix);
    (void)json_push_kv_int(data, "observed_unix", r->finished_unix);
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    char wire_hex[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES * 2u + 1u] = "";
    if (vcs_zcode_work_receipt_serialize(r, wire) == VCS_ZCODE_DEV_OK)
        zcl_hex_encode(wire, sizeof(wire), wire_hex);
    (void)json_push_kv_str(data, "receipt_hex", wire_hex);
}

void zcl_native_handle_zcode_work_receipt(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.work.receipt", zcode_dir))
        return;
    uint8_t root[32];
    if (!ztl_hex32(request, reply, "zcode.work.receipt", "receipt_root",
                   "BAD_RECEIPT_ROOT", "the work pull receipt root", root))
        return;
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    struct vcs_zcode_work_receipt_v1 receipt;
    enum vcs_zcode_work_pull_receipt_result result =
        zwt_receipt_resolve(request, zcode_dir, root, &receipt);
    if (result != VCS_ZCODE_WORK_PULL_RECEIPT_OK) {
        zwt_receipt_fail(reply, result, root_hex);
        return;
    }
    /* Re-derivation from bytes needs a store this read may use as-is: only
     * the resident node's. A one-shot read never opens (and so never
     * recovers or collects) the datadir store. */
    struct vcs_package_store *store = vcs_package_store_global();
    enum vcs_zcode_work_pull_receipt_result reverify =
        store ? vcs_zcode_work_pull_receipt_reverify(store, &receipt)
              : VCS_ZCODE_WORK_PULL_RECEIPT_NOT_HELD;
    if (reverify == VCS_ZCODE_WORK_PULL_RECEIPT_CONTRADICTED) {
        zwt_receipt_fail(reply, reverify, root_hex);
        return;
    }
    (void)json_push_kv_str(&reply->data, "receipt_root", root_hex);
    (void)json_push_kv_bool(&reply->data, "verified", true);
    (void)json_push_kv_str(&reply->data, "work_kind", "reproduce");
    zwt_push_receipt(&reply->data, &receipt);
    (void)json_push_kv_bool(&reply->data, "reverified",
                            reverify == VCS_ZCODE_WORK_PULL_RECEIPT_OK);
    (void)json_push_kv_str(
        &reply->data, "reverify_result",
        store ? vcs_zcode_work_pull_receipt_result_string(reverify)
              : "no-resident-store");
    (void)json_push_kv_str(
        &reply->data, "note",
        "verified means: canonical receipt bytes, their root, the "
        "observer's signature, and the fixed work-pull shape (reproduce, "
        "pass, the action root derived from task and package, the fixed "
        "confinement statement). It proves which observer key vouched for "
        "these roots, not that the key is trusted, and it grants no "
        "acceptance, execution or publication authority. To re-derive the "
        "roots yourself, pull the task_root on your own node");
}
