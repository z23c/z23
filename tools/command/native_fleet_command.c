/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The three `fleet` leaves: append one row, say what this box holds, and
 * answer what the fleet spent.
 *
 * ALL THREE ANSWER LOCALLY. No peer is contacted, no RPC is made and no
 * node has to be running: the store is files under the datadir, and the
 * chainlog's own exclusive lock is what makes an operator's command and the
 * node's own service safe over one store. That is the whole point of every
 * box holding every box's rows — the question is answered on the machine
 * the person is already on.
 *
 * NOTHING HERE PRINTS A ROW'S CONTENTS ANYWHERE BUT THE ANSWER. Refusals
 * name their reason and nothing else; there is no logging of a value, a
 * note, or a box's identity, because a log is not private and these rows
 * are the owner's own data.
 */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "fleetledger/fleet_ledger.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dht_identity.h"

#include <stdio.h>
#include <string.h>

#define FLEET_USAGE_DAYS_DEFAULT 7u
#define FLEET_BUCKETS_MAX 256u

static void fleet_refuse(struct zcl_command_reply *reply, const char *code,
                         const char *message, const char *evidence,
                         bool mutated)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "ledger", false,
                           mutated, message, evidence);
}

/* `<datadir>/fleet_ledger`, absolute or nothing. A relative datadir has
 * bitten this tree before: a writer and a reader resolve it against
 * different working directories and quietly use two different stores. */
static bool fleet_dir(char *out, size_t cap)
{
    const char *datadir = zcl_native_command_datadir();
    if (!datadir || datadir[0] != '/')
        return false;
    return (size_t)snprintf(out, cap, "%s/fleet_ledger", datadir) < cap;
}

/* This box's own identity, read from the filed delegation and the online
 * key beside it. Both live under the datadir at owner-only permissions, so
 * an operator running this command has exactly the authority the node has,
 * and a box with no delegation cannot write at all. */
static bool fleet_identity(uint8_t box_id[32], uint8_t signer[32],
                           uint8_t seed[32], const char **why)
{
    const char *datadir = zcl_native_command_datadir();
    struct vcs_zcode_dht_delegation delegation;
    char error[160];
    if (!datadir ||
        !vcs_zcode_dht_delegation_load(datadir, &delegation, error,
                                       sizeof error)) {
        *why = "this machine has no filed delegation, so it has no name to "
               "write under";
        return false;
    }
    uint8_t online_pub[32];
    if (!vcs_zcode_dht_online_key_load(datadir, seed, online_pub, error,
                                       sizeof error)) {
        *why = "this machine has no online key, so it has nothing to sign "
               "with";
        return false;
    }
    if (memcmp(online_pub, delegation.online_pubkey, 32) != 0) {
        *why = "the online key on disk is not the one this machine's "
               "delegation delegates";
        return false;
    }
    memcpy(box_id, delegation.doc.master_pubkey, 32);
    memcpy(signer, online_pub, 32);
    return true;
}

static void fleet_push_box(struct json_value *obj, const uint8_t id[32])
{
    char hex[65] = { 0 };
    zcl_hex_encode(id, 32, hex);
    (void)json_push_kv_str(obj, "box", hex);
}

/* ── fleet ledger add ────────────────────────────────────────────────── */

/* Every pair key, read by its own name. A key that is not passed is not a
 * pair: absent and zero are different facts and this is where that starts. */
static size_t fleet_collect_pairs(const struct json_value *input,
                                  struct zcl_fleet_pair *out)
{
    size_t n = 0;
    for (uint8_t key = 1; key <= ZCL_FLEET_PAIR_KEY_MAX; key++) {
        const char *name = zcl_fleet_pair_name(key);
        const struct json_value *v = name ? json_get(input, name) : NULL;
        if (!v || v->type != JSON_INT)
            continue;
        out[n].key = key;
        out[n].value = json_get_int(v);
        n++;
    }
    return n; /* ascending by construction, which is the canonical order */
}

void zcl_native_handle_fleet_ledger_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_ledger_add.v1");
    if (!request || !request->input) {
        fleet_refuse(reply, "MISSING_INPUT",
                     "kind and subject are required", "input", false);
        return;
    }
    const struct json_value *v = json_get(request->input, "kind");
    const char *kind_name = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    uint8_t kind = 0;
    if (!kind_name || !zcl_fleet_kind_from_name(kind_name, &kind)) {
        fleet_refuse(reply, "LEDGER_KIND_UNKNOWN",
                     "kind is one of usage, task or vitals", "input.kind",
                     false);
        return;
    }
    if (!zcl_fleet_kind_writable(kind)) {
        fleet_refuse(reply, "LEDGER_KIND_NOT_WRITABLE",
                     "this kind is reserved and nothing writes it yet",
                     "input.kind", false);
        return;
    }
    v = json_get(request->input, "subject");
    const char *subject_name =
        v && v->type == JSON_STR ? json_get_str(v) : NULL;
    uint16_t subject = 0;
    if (!subject_name ||
        !zcl_fleet_subject_from_name(kind, subject_name, &subject)) {
        /* A vitals subject outside the declared catalog gets the catalog's
         * own refusal token: a number whose id nobody wrote down is not a
         * metric, and storing it would make it look like one. */
        bool vitals = kind == ZCL_FLEET_KIND_VITALS;
        fleet_refuse(reply, vitals ? "VITAL_UNKNOWN" : "LEDGER_SUBJECT_UNKNOWN",
                     vitals ? "subject is a metric id from the declared fleet "
                              "vitals catalog"
                            : "subject is not in this kind's vocabulary",
                     "input.subject", false);
        return;
    }
    const char *note = NULL;
    v = json_get(request->input, "note");
    if (v && v->type == JSON_STR)
        note = json_get_str(v);

    struct zcl_fleet_pair pairs[ZCL_FLEET_PAIRS_MAX];
    size_t pair_count = fleet_collect_pairs(request->input, pairs);

    char dir[512];
    uint8_t box_id[32];
    uint8_t signer[32];
    uint8_t seed[32];
    const char *why = "";
    if (!fleet_dir(dir, sizeof dir)) {
        fleet_refuse(reply, "DATADIR_UNAVAILABLE",
                     "the datadir must be an absolute path", "datadir", false);
        return;
    }
    if (!fleet_identity(box_id, signer, seed, &why)) {
        fleet_refuse(reply, "IDENTITY_UNAVAILABLE", why, "datadir", false);
        return;
    }

    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *ledger =
        zcl_fleet_ledger_open(dir, box_id, signer, &report);
    if (!ledger) {
        memset(seed, 0, sizeof seed);
        fleet_refuse(reply, "LEDGER_UNAVAILABLE",
                     zcl_fleet_status_label(report.status), "fleet_ledger",
                     false);
        return;
    }
    uint64_t seq = 0;
    enum zcl_fleet_status status = zcl_fleet_ledger_append(
        ledger, kind, subject, pairs, pair_count, note, seed, &seq);
    memset(seed, 0, sizeof seed);
    zcl_fleet_ledger_close(ledger);
    if (status != ZCL_FLEET_OK) {
        fleet_refuse(reply, "LEDGER_REFUSED", zcl_fleet_status_label(status),
                     "row", false);
        return;
    }

    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet_ledger_add.v1");
    fleet_push_box(&reply->data, box_id);
    (void)json_push_kv_str(&reply->data, "kind", kind_name);
    (void)json_push_kv_str(&reply->data, "subject", subject_name);
    (void)json_push_kv_int(&reply->data, "seq", (int64_t)seq);
    (void)json_push_kv_int(&reply->data, "pairs", (int64_t)pair_count);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
}

/* ── fleet ledger status ─────────────────────────────────────────────── */

void zcl_native_handle_fleet_ledger_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_ledger_status.v1");
    char dir[512];
    if (!fleet_dir(dir, sizeof dir)) {
        fleet_refuse(reply, "DATADIR_UNAVAILABLE",
                     "the datadir must be an absolute path", "datadir", false);
        return;
    }
    /* No identity is needed to READ, and asking for one would make a box
     * that cannot write also unable to look. */
    uint8_t box_id[32];
    uint8_t signer[32];
    uint8_t seed[32];
    const char *why = "";
    bool have_self = fleet_identity(box_id, signer, seed, &why);
    memset(seed, 0, sizeof seed);

    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *ledger = zcl_fleet_ledger_open(
        dir, have_self ? box_id : NULL, have_self ? signer : NULL, &report);
    if (!ledger) {
        fleet_refuse(reply, "LEDGER_UNAVAILABLE",
                     zcl_fleet_status_label(report.status), "fleet_ledger",
                     false);
        return;
    }
    struct zcl_fleet_box_status boxes[ZCL_FLEET_BOXES_MAX];
    size_t count = zcl_fleet_ledger_boxes(ledger, boxes, ZCL_FLEET_BOXES_MAX);
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint64_t overflow = zcl_fleet_ledger_index_overflow(ledger);

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        fleet_push_box(&row, boxes[i].box_id);
        (void)json_push_kv_bool(&row, "self", boxes[i].is_self);
        (void)json_push_kv_int(&row, "rows", (int64_t)boxes[i].rows);
        (void)json_push_kv_int(&row, "last_seq", (int64_t)boxes[i].last_seq);
        /* A replica answers instantly and that is not the same as answering
         * currently. The age is the difference, and it is always shown. */
        if (boxes[i].last_ts > 0 && now > boxes[i].last_ts)
            (void)json_push_kv_int(&row, "age_s", now - boxes[i].last_ts);
        else if (boxes[i].last_ts > 0)
            (void)json_push_kv_int(&row, "age_s", 0);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    zcl_fleet_ledger_close(ledger);

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.fleet_ledger_status.v1");
    (void)json_push_kv_bool(&reply->data, "writable", have_self);
    if (!have_self)
        (void)json_push_kv_str(&reply->data, "read_only_because", why);
    (void)json_push_kv_int(&reply->data, "boxes", (int64_t)count);
    (void)json_push_kv_int(&reply->data, "rows_loaded", (int64_t)report.rows);
    (void)json_push_kv_int(&reply->data, "load_us", (int64_t)report.load_us);
    /* A per-day answer that is incomplete says so rather than printing a
     * smaller number as if it were the whole one. */
    (void)json_push_kv_int(&reply->data, "index_overflow_rows",
                           (int64_t)overflow);
    (void)json_push_kv(&reply->data, "chains", &rows);
    json_free(&rows);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── fleet usage ─────────────────────────────────────────────────────── */

/* The weekly cap a `task`/`quota` row states for one provider, as a
 * `limit` pair. A cap is a ledger row like any other, so calibration
 * replicates with everything else instead of living in one box's config. */
static bool fleet_quota_for(const struct zcl_fleet_ledger *ledger,
                            uint16_t provider, int64_t now, int64_t *limit_out)
{
    struct zcl_fleet_query q;
    memset(&q, 0, sizeof q);
    q.kind = ZCL_FLEET_KIND_TASK;
    q.have_subject = true;
    q.subject = ZCL_FLEET_TASK_QUOTA;
    q.days = ZCL_FLEET_INDEX_DAYS;
    q.now_unix = now;
    struct zcl_fleet_bucket buckets[ZCL_FLEET_BOXES_MAX];
    size_t count = 0;
    if (zcl_fleet_ledger_query(ledger, &q, buckets, ZCL_FLEET_BOXES_MAX,
                               &count, NULL) != ZCL_FLEET_OK)
        return false;
    /* A quota row names its provider in the `count` pair, because a quota
     * is a statement ABOUT a provider rather than a row FROM one. */
    for (size_t i = 0; i < count; i++) {
        if (buckets[i].state[ZCL_FLEET_PAIR_LIMIT] != ZCL_FLEET_FIELD_PRESENT ||
            buckets[i].state[ZCL_FLEET_PAIR_COUNT] != ZCL_FLEET_FIELD_PRESENT)
            continue;
        if (buckets[i].value[ZCL_FLEET_PAIR_COUNT] != (int64_t)provider)
            continue;
        *limit_out = buckets[i].value[ZCL_FLEET_PAIR_LIMIT];
        return *limit_out > 0;
    }
    return false;
}

void zcl_native_handle_fleet_usage(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_usage.v1");
    struct zcl_fleet_query query;
    memset(&query, 0, sizeof query);
    query.kind = ZCL_FLEET_KIND_USAGE;
    query.days = FLEET_USAGE_DAYS_DEFAULT;

    if (request && request->input) {
        const struct json_value *v = json_get(request->input, "days");
        if (v) {
            long long want = v->type == JSON_INT ? json_get_int(v) : -1;
            if (want < 1 || want > (long long)ZCL_FLEET_INDEX_DAYS) {
                fleet_refuse(reply, "LEDGER_WINDOW_EXCEEDED",
                             "days is between 1 and the index window; a "
                             "longer window is refused rather than answered "
                             "from days the index does not hold",
                             "input.days", false);
                return;
            }
            query.days = (uint32_t)want;
        }
        v = json_get(request->input, "provider");
        if (v && v->type == JSON_STR) {
            if (!zcl_fleet_subject_from_name(ZCL_FLEET_KIND_USAGE,
                                             json_get_str(v),
                                             &query.subject)) {
                fleet_refuse(reply, "LEDGER_SUBJECT_UNKNOWN",
                             "provider is not one this ledger records",
                             "input.provider", false);
                return;
            }
            query.have_subject = true;
        }
        v = json_get(request->input, "box");
        if (v && v->type == JSON_STR) {
            const char *hex = json_get_str(v);
            if (!hex || strlen(hex) != 64 ||
                !zcl_hex_decode_lower(hex, query.box_id, 32)) {
                fleet_refuse(reply, "BOX_INVALID",
                             "box is a 64-character lowercase hex box id",
                             "input.box", false);
                return;
            }
            query.have_box = true;
        }
    }

    char dir[512];
    if (!fleet_dir(dir, sizeof dir)) {
        fleet_refuse(reply, "DATADIR_UNAVAILABLE",
                     "the datadir must be an absolute path", "datadir", false);
        return;
    }
    uint8_t box_id[32];
    uint8_t signer[32];
    uint8_t seed[32];
    const char *why = "";
    bool have_self = fleet_identity(box_id, signer, seed, &why);
    memset(seed, 0, sizeof seed);

    struct zcl_fleet_report report;
    struct zcl_fleet_ledger *ledger = zcl_fleet_ledger_open(
        dir, have_self ? box_id : NULL, have_self ? signer : NULL, &report);
    if (!ledger) {
        fleet_refuse(reply, "LEDGER_UNAVAILABLE",
                     zcl_fleet_status_label(report.status), "fleet_ledger",
                     false);
        return;
    }
    query.now_unix = (int64_t)platform_time_wall_time_t();

    struct zcl_fleet_bucket *buckets =
        zcl_calloc(FLEET_BUCKETS_MAX, sizeof *buckets, "fleet_usage_buckets");
    if (!buckets) {
        zcl_fleet_ledger_close(ledger);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "OUT_OF_MEMORY",
                               "answer", true, false,
                               "the answer table could not be allocated", "");
        return;
    }
    size_t count = 0;
    uint64_t index_us = 0;
    enum zcl_fleet_status status = zcl_fleet_ledger_query(
        ledger, &query, buckets, FLEET_BUCKETS_MAX, &count, &index_us);
    if (status != ZCL_FLEET_OK && status != ZCL_FLEET_FULL) {
        free(buckets);
        zcl_fleet_ledger_close(ledger);
        fleet_refuse(reply, "LEDGER_REFUSED", zcl_fleet_status_label(status),
                     "query", false);
        return;
    }

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < count; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        fleet_push_box(&row, buckets[i].box_id);
        const char *provider =
            zcl_fleet_subject_name(ZCL_FLEET_KIND_USAGE, buckets[i].subject);
        (void)json_push_kv_str(&row, "provider", provider ? provider : "");
        (void)json_push_kv_int(&row, "rows", (int64_t)buckets[i].rows);
        /* Only the keys a row actually carried. An absent measurement is
         * absent from the answer, never reported as zero. */
        for (uint8_t k = 1; k <= ZCL_FLEET_PAIR_KEY_MAX; k++) {
            if (buckets[i].state[k] != ZCL_FLEET_FIELD_PRESENT)
                continue;
            const char *name = zcl_fleet_pair_name(k);
            if (name)
                (void)json_push_kv_int(&row, name, buckets[i].value[k]);
        }
        int64_t limit = 0;
        if (fleet_quota_for(ledger, buckets[i].subject, query.now_unix,
                            &limit) &&
            buckets[i].state[ZCL_FLEET_PAIR_TOKENS_IN] ==
                ZCL_FLEET_FIELD_PRESENT) {
            int64_t spent = buckets[i].value[ZCL_FLEET_PAIR_TOKENS_IN] +
                            (buckets[i].state[ZCL_FLEET_PAIR_TOKENS_OUT] ==
                                     ZCL_FLEET_FIELD_PRESENT
                                 ? buckets[i].value[ZCL_FLEET_PAIR_TOKENS_OUT]
                                 : 0);
            /* Basis points, not a float: this tree keeps no floating point
             * on a path a second machine has to agree with. */
            (void)json_push_kv_int(&row, "week_pct_bp",
                                   (spent * 10000) / limit);
        }
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    free(buckets);
    uint64_t overflow = zcl_fleet_ledger_index_overflow(ledger);
    zcl_fleet_ledger_close(ledger);

    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet_usage.v1");
    (void)json_push_kv_int(&reply->data, "days", (int64_t)query.days);
    (void)json_push_kv_int(&reply->data, "boxes", (int64_t)report.boxes);
    /* The two costs are reported apart, because the claim that this is
     * instant is a claim about the second one. */
    (void)json_push_kv_int(&reply->data, "load_us", (int64_t)report.load_us);
    (void)json_push_kv_int(&reply->data, "index_us", (int64_t)index_us);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            status == ZCL_FLEET_FULL);
    (void)json_push_kv_int(&reply->data, "index_overflow_rows",
                           (int64_t)overflow);
    (void)json_push_kv(&reply->data, "usage", &rows);
    json_free(&rows);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
