/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the three `zcode task` transport leaves — how a
 * posted dev task MOVES between nodes so a stranger can pick it up:
 *
 *   zcode task offer   load one task's wires from the workspace CAS
 *                      (task wire, goal preimage, proof policy — each
 *                      re-hashed against its own address), bind them into
 *                      the fixed-layout task-context carrier, admit it to
 *                      the package store, and hand back the two
 *                      ready-to-run `zcode network publish` inputs that
 *                      make the PROBLEM discoverable
 *   zcode task pull    given a task root, resolve every task POINTER for
 *                      it, fetch each distinct context over the frozen
 *                      swarm codec, and re-verify each context against
 *                      exactly that root — returning the goal and proof
 *                      policy a remote agent needs to start work
 *   zcode task board   list what THIS node has seen posted in the task
 *                      namespace (local record-store projection, never a
 *                      peer query), enriching every row whose context is
 *                      already held and verified
 *
 * A task object is unsigned by design: it is a content-addressed
 * constraint set, not an identity claim. Record signatures identify the
 * publishing key; receiver verification binds the task bytes, and local
 * sovereignty policy decides visibility. AGENT_SCOPE remains dormant. The
 * carrier contributes the part a stranger
 * cannot re-derive from the task wire alone — the goal preimage and the
 * proof policy bytes — cross-bound so sha3(goal.bin) equals
 * task.goal_root and the policy wire roots to task.proof_policy_root.
 *
 * NO NEW WIRE MESSAGE EXISTS HERE AND NONE MAY BE ADDED. The context
 * rides the already-frozen 'zpkgswm' codec like any other package,
 * fetched by `zcode package fetch`. Discovery is two ordinary signed
 * records, and both are required (see zcode work offer for why either
 * record alone is a silent no-op at pull time); `offer` returns BOTH
 * inputs, provider first.
 *
 * THE ONE SECURITY PROPERTY ON THE PULL PATH is the receiver-side binding
 * check: every admit here passes the caller's task_root as
 * expect_task_root, never NULL. vcs_zcode_task_context_admit re-derives
 * the context from stored bytes and refuses unless the task the context
 * ITSELF proves equals the root the reader asked about — including a
 * liveness check, so an expired posting drops off every board that
 * re-verifies it. The publish-side gate is local hygiene and constrains
 * nobody else.
 *
 * PULLING IS NOT EXECUTING. A verified row means "this context provably
 * posts this task, this node holds the bytes, and here is the goal" —
 * nothing more. Doing the work is the ordinary local journey (zcode work
 * run against the task's roots); offering its result is zcode work offer.
 *
 * A row that fails stays in the report naming its rule. One bad pointer
 * never aborts the sweep — the other postings still land.
 *
 * This lives in its own translation unit rather than in
 * native_zcode_work_command.c so the posting half of the task surface has
 * one file beside its solution half. Bound by engine/composition/commands/zcode.def.
 */

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "command/native_zcode_transport_leaves.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "vcs/package_store.h"
#include "vcs/source_package_checkout.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dht_record.h"
#include "vcs/zcode_task_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Row cap for a pull report, the work lane's numbers: a namespace with
 * more live postings than this is a good problem; the reply says so
 * rather than truncating silently. */
#define ZTT_ROWS_DEFAULT 16u
#define ZTT_ROWS_CEILING 64u

/* Validity windows stamped into each ready-to-run publish input — same
 * per-kind derivation and reasoning as the work lane (a provider ad is a
 * short-lived claim about reachability right now; a pointer is a claim
 * about content that stays true). */
#define ZTT_PROVIDER_WINDOW_S VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS
#define ZTT_POINTER_WINDOW_S UINT64_C(86400)

/* Fail the BUILD if either ceiling moves under us: an unpublishable input
 * handed out as "ready to run" is a defect that only shows up at the far
 * end of a two-command sequence. */
static_assert(ZTT_PROVIDER_WINDOW_S <= VCS_ZCODE_DHT_PROVIDER_MAX_SECONDS,
              "the provider publish input must be publishable as a PROVIDER "
              "record; an over-long window is refused and leaves the "
              "operator pointer-only");
static_assert(ZTT_POINTER_WINDOW_S <= VCS_ZCODE_DHT_POINTER_MAX_SECONDS,
              "the pointer publish input must be publishable as a POINTER "
              "record");

/* ── workspace CAS loads (address agreement is the caller's job here:
 * vcs_object_load_raw deliberately does not re-hash) ─────────────────── */

static uint8_t *ztt_load_object(const char *zcode_dir, const uint8_t root[32],
                                size_t max, size_t *len_out)
{
    *len_out = 0;
    uint8_t *bytes = NULL;
    size_t len = 0;
    if (vcs_object_load_raw_bounded(zcode_dir, root, max, &bytes, &len) != 0)
        return NULL;
    *len_out = len;
    return bytes;
}

/* The three wires one task needs, every one re-derived against its own
 * CAS address before the carrier will bind them. */
static bool ztt_load_context_wires(const char *zcode_dir,
                                   const uint8_t task_root[32],
                                   uint8_t **task_wire, size_t *task_len,
                                   uint8_t **goal, size_t *goal_len,
                                   uint8_t **policy_wire, size_t *policy_len,
                                   struct vcs_zcode_task_v1 *task_out)
{
    *task_wire = *goal = *policy_wire = NULL;
    *task_len = *goal_len = *policy_len = 0;
    uint8_t *tw = ztt_load_object(zcode_dir, task_root,
                                  VCS_ZCODE_TASK_WIRE_BYTES, task_len);
    struct vcs_zcode_task_v1 task;
    uint8_t derived[32];
    if (!tw ||
        vcs_zcode_task_parse(tw, *task_len, &task) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(&task, derived) != VCS_ZCODE_DEV_OK ||
        memcmp(derived, task_root, 32) != 0) {
        free(tw);
        return false;
    }
    uint8_t *gl = ztt_load_object(zcode_dir, task.goal_root,
                                  VCS_ZCODE_TASK_CONTEXT_GOAL_MAX, goal_len);
    uint8_t check[32];
    if (!gl || *goal_len == 0 || memchr(gl, '\0', *goal_len)) {
        free(tw);
        free(gl);
        return false;
    }
    sha3_256(gl, *goal_len, check);
    if (memcmp(check, task.goal_root, 32) != 0) {
        free(tw);
        free(gl);
        return false;
    }
    uint8_t *pw = ztt_load_object(zcode_dir, task.proof_policy_root,
                                  VCS_ZCODE_PROOF_POLICY_WIRE_BYTES,
                                  policy_len);
    struct vcs_zcode_proof_policy_v1 policy;
    if (!pw ||
        vcs_zcode_proof_policy_parse(pw, *policy_len, &policy) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(&policy, derived) != VCS_ZCODE_DEV_OK ||
        memcmp(derived, task.proof_policy_root, 32) != 0) {
        free(tw);
        free(gl);
        free(pw);
        return false;
    }
    *task_wire = tw;
    *goal = gl;
    *policy_wire = pw;
    if (task_out)
        *task_out = task;
    return true;
}

/* ── zcode task offer ───────────────────────────────────────────────── */

void zcl_native_handle_zcode_task_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.task.offer", zcode_dir))
        return;
    uint8_t task_root[32];
    if (!ztl_hex32(request, reply, "zcode.task.offer", "task_root",
                   "BAD_TASK_ROOT",
                   "the posted task's own root", task_root))
        return;
    char task_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);

    uint8_t *task_wire = NULL, *goal = NULL, *policy_wire = NULL;
    size_t task_len = 0, goal_len = 0, policy_len = 0;
    struct vcs_zcode_task_v1 task;
    if (!ztt_load_context_wires(zcode_dir, task_root, &task_wire, &task_len,
                                &goal, &goal_len, &policy_wire, &policy_len,
                                &task)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "TASK_WIRES_NOT_HELD", "execute", false, false,
                               "the task's three wires are not held "
                               "complete in this workspace's object store "
                               "(task root, goal preimage at task.goal_root, "
                               "proof policy at task.proof_policy_root) or "
                               "do not hash to their own addresses",
                               task_hex);
        return;
    }

    bool own_store = false;
    struct vcs_package_store *store =
        ztl_open_store(request, &own_store, "zcode.task");
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store could not be opened; a "
                               "context cannot be exported or made "
                               "reachable without one",
                               zcode_dir);
        free(task_wire);
        free(goal);
        free(policy_wire);
        return;
    }
    uint8_t context_root[32];
    enum vcs_zcode_task_context_error exported = vcs_zcode_task_context_export(
        task_wire, task_len, goal, goal_len, policy_wire, policy_len, store,
        (int64_t)platform_time_wall_unix(), context_root);
    ztl_close_store(store, own_store);
    free(task_wire);
    free(goal);
    free(policy_wire);

    char context_hex[65];
    zcl_hex_encode(context_root, 32, context_hex);
    if (exported != VCS_ZCODE_TASK_CONTEXT_OK) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "TASK_CONTEXT_REFUSED", "execute", false,
                               false,
                               "the task-context carrier refused these "
                               "bytes; every cross-binding runs at export "
                               "exactly as it will at admit",
                               vcs_zcode_task_context_error_string(exported));
        return;
    }

    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "context_root", context_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    (void)json_push_kv_int(&reply->data, "expires_unix",
                           (int64_t)task.expires_unix);

    /* PROVIDER first: it is the record the fetch path actually routes on. */
    uint64_t now = (uint64_t)platform_time_wall_unix();
    struct json_value publish;
    json_init(&publish);
    ztl_publish_input(&publish, "provider", VCS_ZCODE_TASK_DHT_NAMESPACE,
                      NULL, context_hex, now, ZTT_PROVIDER_WINDOW_S);
    (void)json_push_kv(&reply->data, "provider_publish_input", &publish);
    json_free(&publish);
    json_init(&publish);
    uint64_t pointer_window = (uint64_t)task.expires_unix - now;
    if (pointer_window > ZTT_POINTER_WINDOW_S)
        pointer_window = ZTT_POINTER_WINDOW_S;
    ztl_publish_input(&publish, "pointer", VCS_ZCODE_TASK_DHT_NAMESPACE,
                      task_hex, context_hex, now, pointer_window);
    (void)json_push_kv(&reply->data, "pointer_publish_input", &publish);
    json_free(&publish);

    (void)json_push_kv_str(
        &reply->data, "note",
        "offering exports what THIS node holds and announces NOTHING: no "
        "peer can find the posting yet. Telling the network is the "
        "separate second act, and it takes BOTH records in this namespace: "
        "run zcode network publish with provider_publish_input (\"ask me "
        "for these bytes\" — the record the fetch path routes on) AND with "
        "pointer_publish_input (\"this context posts this task\" — what a "
        "puller looks up when all it knows is the task root). Either one "
        "alone is a silent no-op at pull time. Both inputs are mode=plan; "
        "each returns a plan_token to commit. The context binds the goal "
        "preimage and proof policy bytes to the task's own root — a "
        "stranger re-verifies all of it from fetched bytes alone");
}

/* ── zcode task pull ────────────────────────────────────────────────── */

/* One resolved pointer's fate, kept flat so a failure never grows a
 * control path that could abort the sweep. */
struct ztt_row {
    char transport_root[65];
    char fetch_outcome[96];   /* the fetch path's own named verdict */
    bool fetched;
    char admit_rule[192];     /* the task-context layer's NAMED result */
    bool admitted;
    int64_t expires_unix;     /* filled only on a verified row */
    char goal[VCS_ZCODE_TASK_CONTEXT_GOAL_MAX + 1u];
};

void zcl_native_handle_zcode_task_pull(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!ztl_zcode_dir(request, reply, "zcode.task.pull", zcode_dir))
        return;
    uint8_t task_root[32];
    if (!ztl_hex32(request, reply, "zcode.task.pull", "task_root",
                   "BAD_TASK_ROOT",
                   "the task the contexts must prove they post", task_root))
        return;
    char task_hex[65];
    zcl_hex_encode(task_root, 32, task_hex);

    uint32_t cap = ZTT_ROWS_DEFAULT;
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
                                   "zcode.task.pull");
            return;
        }
        cap = want > (int64_t)ZTT_ROWS_CEILING ? ZTT_ROWS_CEILING
                                               : (uint32_t)want;
    }

    struct json_value pointers;
    if (!ztl_query_pointers(request, reply, VCS_ZCODE_TASK_DHT_NAMESPACE,
                            task_hex, &pointers))
        return;

    /* Distinct transport roots, in discovery order, bounded. A republished
     * sequence of the same context collapses here so one publisher cannot
     * consume the row budget by republishing. */
    size_t seen = json_size(&pointers);
    struct ztt_row *rows = zcl_calloc(cap, sizeof(*rows), "ztt_pull_rows");
    if (!rows) {
        json_free(&pointers);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "execute",
                               false, false, "pull row table",
                               "zcode.task.pull");
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
        store = ztl_open_store(request, &own_store, "zcode.task");
        if (!store) {
            free(rows);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                                   "execute", false, false,
                                   "the package store could not be opened; "
                                   "task contexts cannot be fetched or "
                                   "verified without one",
                                   zcode_dir);
            return;
        }
    }

    uint32_t fetched = 0, admitted = 0, refused = 0;
    int64_t now = (int64_t)platform_time_wall_unix();
    for (uint32_t i = 0; i < distinct; i++) {
        struct ztt_row *row = &rows[i];
        ztl_fetch_one(request, VCS_ZCODE_TASK_DHT_NAMESPACE,
                      row->transport_root,
                      (int64_t)VCS_ZCODE_TASK_CONTEXT_MAX_PACKAGE_BYTES,
                      &row->fetched, row->fetch_outcome,
                      sizeof(row->fetch_outcome));
        fetched += row->fetched ? 1u : 0u;

        /* expect_task_root is the caller's root and is NEVER NULL. This
         * single argument is the whole reason a hostile pointer in this
         * namespace cannot deliver a different task's context: the bytes
         * must re-verify AND prove this exact task, live at this instant
         * (an expired posting drops off here). The check runs even when
         * the fetch only SCHEDULED the download — the store is the
         * authority on whether the bytes are here. A row that fails stays
         * in the report; the sweep continues. */
        uint8_t transport_root[32];
        if (!zcl_hex_decode_lower(row->transport_root, transport_root, 32)) {
            (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                           "pointer-transport-root-not-canonical-hex");
            refused++;
            continue;
        }
        struct vcs_zcode_task_v1 task;
        uint8_t derived_task_root[32];
        size_t goal_len = 0;
        enum vcs_zcode_task_context_error r = vcs_zcode_task_context_admit(
            store, transport_root, task_root, now, &task, NULL,
            (uint8_t *)row->goal, sizeof(row->goal) - 1u, &goal_len,
            derived_task_root);
        (void)snprintf(row->admit_rule, sizeof(row->admit_rule), "%s",
                       vcs_zcode_task_context_error_string(r));
        if (r != VCS_ZCODE_TASK_CONTEXT_OK) {
            refused++;
            continue;
        }
        row->admitted = true;
        row->expires_unix = task.expires_unix;
        row->goal[goal_len] = '\0';
        admitted++;
    }
    ztl_close_store(store, own_store);

    /* Two very different dead ends, never merged into one "not found":
     * nobody has posted this task, versus somebody has and nobody
     * reachable is serving the context. The next step differs
     * completely — wait for a poster, or fix reachability. */
    const char *status = "TASKS_VERIFIED";
    const char *blocker = "";
    if (distinct == 0) {
        status = "NO_TASK_POINTERS";
        blocker = "no_pointer_record_names_a_posting_for_this_task_root";
    } else if (admitted == 0) {
        /* admitted is tested BEFORE fetched, exactly as the work lane: the
         * admit above is deliberately unconditional, so a context this
         * node already holds verifies even when provider discovery served
         * nothing. */
        if (fetched == 0) {
            status = "TASK_BYTES_UNREACHABLE";
            blocker = "pointers_exist_but_no_authenticated_provider_served_"
                      "the_context_bytes";
        } else {
            status = "TASKS_REFUSED";
            blocker = "every_fetched_context_failed_a_named_admission_rule";
        }
    }

    (void)json_push_kv_str(&reply->data, "task_root", task_hex);
    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
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
        const struct ztt_row *row = &rows[i];
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "context_root", row->transport_root);
        (void)json_push_kv_str(&entry, "fetch_outcome", row->fetch_outcome);
        (void)json_push_kv_str(&entry, "admit_rule", row->admit_rule);
        if (row->admitted) {
            (void)json_push_kv_bool(&entry, "verified", true);
            (void)json_push_kv_int(&entry, "expires_unix",
                                   row->expires_unix);
            (void)json_push_kv_str(&entry, "goal", row->goal);
        } else {
            (void)json_push_kv_bool(&entry, "verified", false);
        }
        (void)json_push_back(&list, &entry);
        json_free(&entry);
    }
    (void)json_push_kv(&reply->data, "rows", &list);
    json_free(&list);
    free(rows);

    (void)json_push_kv_str(
        &reply->data, "note",
        "a verified row is a posting, not an assignment and not "
        "execution: the context proves which task it posts, this node "
        "holds the bytes, and the goal text is the problem statement. "
        "Doing the work is the ordinary local journey; offering its "
        "result is zcode work offer under the work namespace");
}

/* ── zcode task board ───────────────────────────────────────────────── */

/* The board is the records lane's namespace-wide local projection (the
 * board input of `zcode network records`), enriched: every row whose
 * context this node already holds is re-verified and carries its goal, so
 * an operator reads problem statements straight off the board. Rows whose
 * bytes are not here yet say so — zcode task pull fetches them. */
void zcl_native_handle_zcode_task_board(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    struct json_value forwarded_input;
    json_init(&forwarded_input);
    json_set_object(&forwarded_input);
    (void)json_push_kv_str(&forwarded_input, "kind", "pointer");
    (void)json_push_kv_str(&forwarded_input, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    const char *datadir = ztl_input_str(request->input, "datadir");
    if (datadir && datadir[0])
        (void)json_push_kv_str(&forwarded_input, "datadir", datadir);
    (void)json_push_kv_bool(&forwarded_input, "board", true);
    struct zcl_command_request forwarded = *request;
    forwarded.input = &forwarded_input;
    struct zcl_command_reply records;
    zcl_command_reply_init(&records, "zcl.zcode_network_records.v1");
    zcl_native_handle_zcode_network_records(&forwarded, &records);
    json_free(&forwarded_input);
    if (records.exit_code != ZCL_COMMAND_EXIT_OK) {
        zcl_command_reply_fail(
            reply, records.status, records.exit_code,
            records.error.code[0] ? records.error.code : "BOARD_FAILED",
            records.error.phase[0] ? records.error.phase : "discover",
            records.error.retryable, false,
            records.error.message[0]
                ? records.error.message
                : "the task board listing did not complete",
            records.error.evidence);
        zcl_command_reply_free(&records);
        return;
    }

    /* READ means no recovery, lock creation, garbage collection, or directory
     * creation in a caller-selected datadir. Enrich only through a store the
     * hosting daemon already owns; otherwise report bytes-not-held. */
    struct vcs_package_store *store = vcs_package_store_global();
    int64_t now = (int64_t)platform_time_wall_unix();
    struct json_value rows;
    const struct json_value *in_rows = json_get(&records.data, "records");
    json_init(&rows);
    json_set_array(&rows);
    size_t count = in_rows && in_rows->type == JSON_ARR
                       ? json_size(in_rows)
                       : 0;
    for (size_t i = 0; i < count; i++) {
        const struct json_value *record = json_at(in_rows, i);
        const char *semantic =
            record ? json_get_str(json_get(record, "semantic_root")) : NULL;
        const char *transport =
            record ? json_get_str(json_get(record, "transport_root")) : NULL;
        if (!semantic || strlen(semantic) != 64 || !transport ||
            strlen(transport) != 64)
            continue;
        struct json_value entry;
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "task_root", semantic);
        (void)json_push_kv_str(&entry, "context_root", transport);
        uint8_t task_root[32], context_root[32];
        if (store && zcl_hex_decode_lower(semantic, task_root, 32) &&
            zcl_hex_decode_lower(transport, context_root, 32)) {
            struct vcs_zcode_task_v1 task;
            char goal[VCS_ZCODE_TASK_CONTEXT_GOAL_MAX + 1u];
            size_t goal_len = 0;
            enum vcs_zcode_task_context_error r =
                vcs_zcode_task_context_admit(
                    store, context_root, task_root, now, &task, NULL,
                    (uint8_t *)goal, sizeof(goal) - 1u, &goal_len, NULL);
            (void)json_push_kv_str(&entry, "admit_rule",
                                   vcs_zcode_task_context_error_string(r));
            if (r == VCS_ZCODE_TASK_CONTEXT_OK) {
                goal[goal_len] = '\0';
                (void)json_push_kv_bool(&entry, "verified", true);
                (void)json_push_kv_int(&entry, "expires_unix",
                                       (int64_t)task.expires_unix);
                (void)json_push_kv_str(&entry, "goal", goal);
            } else {
                (void)json_push_kv_bool(&entry, "verified", false);
            }
        } else {
            (void)json_push_kv_str(&entry, "admit_rule", "bytes-not-held");
            (void)json_push_kv_bool(&entry, "verified", false);
        }
        (void)json_push_back(&rows, &entry);
        json_free(&entry);
    }
    zcl_command_reply_free(&records);

    (void)json_push_kv_str(&reply->data, "namespace",
                           VCS_ZCODE_TASK_DHT_NAMESPACE);
    (void)json_push_kv_bool(&reply->data, "local_projection", true);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)json_size(&rows));
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    (void)json_push_kv_str(
        &reply->data, "note",
        "this board is what THIS node has seen — records arrive only "
        "through the ordinary paths (publish here, exact-root discovery "
        "merges, replication), so an empty board means nothing seen yet, "
        "not nothing anywhere. A verified row carries its goal text; a "
        "row whose bytes are not held yet names its rule — zcode task "
        "pull fetches and re-verifies it against the task root");
}
