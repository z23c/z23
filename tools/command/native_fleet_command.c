/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `fleet` leaves: append one row, say what this box holds, answer
 * what the fleet spent, sample this box's catalog vitals, and record or
 * query a delegation experiment.
 *
 * ALL OF THEM ANSWER LOCALLY. No peer is contacted, no RPC is made and no
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
#include "config/boot_fleet_ledger.h"
#include "fleetledger/fleet_ledger.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/disk_space.h"
#include "platform/logical_cpu.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dht_identity.h"

#include <stdint.h>
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
    /* What the replication lane refused and what it could not keep up with,
     * counted since this process started. A pairing row whose peer identity
     * was revoked on chain is invisible in every other field here. */
    (void)json_push_kv_int(&reply->data, "delegation_refused",
                           (int64_t)boot_fleet_ledger_delegation_refused_count());
    (void)json_push_kv_int(&reply->data, "inbox_full",
                           (int64_t)boot_fleet_ledger_inbox_full_count());
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

/* ── fleet vitals sample ─────────────────────────────────────────────── */

enum { FLEET_HOST_N = 9 };
static const char *const k_host_ids[FLEET_HOST_N] = {
    "box.load1", "box.cores", "box.cores_free_for_qedc", "box.ram_used_mib",
    "box.ram_total_mib", "box.disk_free_gib", "box.disk_free_pct",
    "box.uptime_s", "node.rss_mib"
};

static int fleet_host_index(const char *id)
{
    for (int i = 0; i < FLEET_HOST_N; i++)
        if (strcmp(k_host_ids[i], id) == 0)
            return i;
    return -1;
}

static void fleet_snapshot(const char *datadir, int64_t v[FLEET_HOST_N],
                           bool p[FLEET_HOST_N])
{
    const int64_t mib = 1024 * 1024, gib = mib * 1024;
    int64_t load = os_proc_load1_centi();
    int64_t cores = (int64_t)platform_logical_cpu_count();
    struct os_proc_mem mem = { .rss_bytes = -1, .sys_total_bytes = -1,
                               .sys_avail_bytes = -1 };
    bool mem_ok = os_proc_mem_read(&mem);
    int64_t up = os_proc_uptime_seconds();
    uint64_t d_avail = 0, d_total = 0;
    bool disk = datadir && platform_disk_space(datadir, &d_avail, &d_total);
    int64_t load_ceil = load >= 0 ? (load + 99) / 100 : 0;
    p[0] = load >= 0; v[0] = load;
    p[1] = cores > 0; v[1] = cores;
    p[2] = load >= 0 && cores > 0;
    v[2] = p[2] && cores > load_ceil ? cores - load_ceil : 0;
    p[3] = mem_ok && mem.sys_total_bytes >= 0 && mem.sys_avail_bytes >= 0 &&
           mem.sys_total_bytes >= mem.sys_avail_bytes;
    v[3] = p[3] ? (mem.sys_total_bytes - mem.sys_avail_bytes) / mib : 0;
    p[4] = mem_ok && mem.sys_total_bytes >= 0;
    v[4] = p[4] ? mem.sys_total_bytes / mib : 0;
    p[5] = disk; v[5] = disk ? (int64_t)(d_avail / (uint64_t)gib) : 0;
    p[6] = disk && d_total > 0 && d_avail <= UINT64_MAX / 100ull;
    v[6] = p[6] ? (int64_t)((d_avail * 100ull) / d_total) : 0;
    p[7] = up >= 0; v[7] = up;
    p[8] = mem_ok && mem.rss_bytes >= 0;
    v[8] = p[8] ? mem.rss_bytes / mib : 0;
}

void zcl_native_handle_fleet_vitals_sample(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_vitals_sample.v1");
    const char *want = NULL;
    if (request && request->input) {
        const struct json_value *v = json_get(request->input, "id");
        if (v && v->type == JSON_STR)
            want = json_get_str(v);
    }
    const char *ids[FLEET_HOST_N];
    uint16_t subjects[FLEET_HOST_N];
    size_t nids = FLEET_HOST_N;
    memcpy(ids, k_host_ids, sizeof k_host_ids);
    if (want && want[0]) {
        ids[0] = want;
        nids = 1;
    }
    for (size_t i = 0; i < nids; i++) {
        if (!zcl_fleet_subject_from_name(ZCL_FLEET_KIND_VITALS, ids[i],
                                         &subjects[i])) {
            fleet_refuse(reply, "VITAL_UNKNOWN",
                         "subject is a metric id from the declared fleet "
                         "vitals catalog",
                         ids[i], false);
            return;
        }
    }

    char dir[512];
    uint8_t box_id[32], signer[32], seed[32];
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

    int64_t values[FLEET_HOST_N];
    bool present[FLEET_HOST_N];
    fleet_snapshot(zcl_native_command_datadir(), values, present);
    uint64_t first = 0, last = 0;
    size_t wrote = 0;
    for (size_t i = 0; i < nids; i++) {
        int idx = fleet_host_index(ids[i]);
        bool have = idx >= 0 && present[idx];
        struct zcl_fleet_pair pair = { ZCL_FLEET_PAIR_VALUE,
                                       have ? values[idx] : 0 };
        uint64_t seq = 0;
        enum zcl_fleet_status status = zcl_fleet_ledger_append(
            ledger, ZCL_FLEET_KIND_VITALS, subjects[i],
            have ? &pair : NULL, have ? 1u : 0u, NULL, seed, &seq);
        if (status != ZCL_FLEET_OK) {
            memset(seed, 0, sizeof seed);
            zcl_fleet_ledger_close(ledger);
            fleet_refuse(reply, "LEDGER_REFUSED",
                         zcl_fleet_status_label(status), "row", wrote > 0);
            return;
        }
        if (wrote == 0)
            first = seq;
        last = seq;
        wrote++;
    }
    memset(seed, 0, sizeof seed);
    zcl_fleet_ledger_close(ledger);

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.fleet_vitals_sample.v1");
    fleet_push_box(&reply->data, box_id);
    (void)json_push_kv_int(&reply->data, "rows", (int64_t)wrote);
    (void)json_push_kv_int(&reply->data, "seq_first", (int64_t)first);
    (void)json_push_kv_int(&reply->data, "seq_last", (int64_t)last);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
}

/* ── fleet experiment ────────────────────────────────────────────────── */

#define FLEET_EXPERIMENT_GROUPS_MAX 64u
#define FLEET_EXPERIMENT_TEXT_MAX 8192u

static bool fleet_pair_add(struct zcl_fleet_pair *pairs, size_t *n, uint8_t key,
                           int64_t value)
{
    if (*n >= ZCL_FLEET_PAIRS_MAX)
        return false;
    size_t i = *n;
    while (i > 0 && pairs[i - 1].key > key) {
        pairs[i] = pairs[i - 1];
        i--;
    }
    if (i > 0 && pairs[i - 1].key == key)
        return false;
    pairs[i].key = key;
    pairs[i].value = value;
    (*n)++;
    return true;
}

static const char *fleet_input_str(const struct json_value *v)
{
    if (!v || v->type != JSON_STR)
        return NULL;
    const char *s = json_get_str(v);
    return s && s[0] ? s : NULL;
}

static bool fleet_input_i64(const struct json_value *v, int64_t *out)
{
    if (!v)
        return false;
    if (v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool fleet_enum_stored(const struct json_value *v, const char *field,
                              uint8_t *out)
{
    const char *name = fleet_input_str(v);
    uint8_t value = 0;
    if (!name || !zcl_fleet_experiment_enum_from_name(field, name, &value) ||
        !zcl_fleet_experiment_enum_stored(field, value))
        return false;
    *out = value;
    return true;
}

static void fleet_refuse_enum(struct zcl_command_reply *reply, const char *field,
                              const char *evidence)
{
    char message[160];
    (void)snprintf(message, sizeof message,
                   "%s is not in the closed vocabulary", field);
    fleet_refuse(reply, "EXPERIMENT_ENUM", message, evidence, false);
}

static void fleet_experiment_write(struct zcl_command_reply *reply,
                                   uint16_t subject, const char *subject_name,
                                   const struct zcl_fleet_pair *pairs,
                                   size_t pair_count, const char *note)
{
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
        ledger, ZCL_FLEET_KIND_EXPERIMENT, subject, pairs, pair_count, note,
        seed, &seq);
    memset(seed, 0, sizeof seed);
    zcl_fleet_ledger_close(ledger);
    if (status != ZCL_FLEET_OK) {
        fleet_refuse(reply, "LEDGER_REFUSED", zcl_fleet_status_label(status),
                     "row", false);
        return;
    }

    (void)json_push_kv_str(&reply->data, "schema",
                           subject == ZCL_FLEET_EXPERIMENT_PREDICT
                               ? "zcl.fleet_experiment_predict.v1"
                               : "zcl.fleet_experiment_result.v1");
    fleet_push_box(&reply->data, box_id);
    (void)json_push_kv_str(&reply->data, "kind", "experiment");
    (void)json_push_kv_str(&reply->data, "subject", subject_name);
    (void)json_push_kv_int(&reply->data, "seq", (int64_t)seq);
    (void)json_push_kv_int(&reply->data, "pairs", (int64_t)pair_count);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->error.mutated = true;
}

void zcl_native_handle_fleet_experiment_predict(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_experiment_predict.v1");
    if (!request || !request->input) {
        fleet_refuse(reply, "MISSING_INPUT", "task_id is required", "input",
                     false);
        return;
    }
    const char *task_id = fleet_input_str(json_get(request->input, "task_id"));
    const char *note = fleet_input_str(json_get(request->input, "note"));
    if (!task_id)
        task_id = note;
    if (!task_id) {
        fleet_refuse(reply, "MISSING_INPUT", "task_id is required",
                     "input.task_id", false);
        return;
    }
    (void)json_get(request->input, "story");
    (void)json_get(request->input, "executor");

    uint8_t task_class = 0, harness = 0, model = 0, effort = 0;
    if (!fleet_enum_stored(json_get(request->input, "task_class"), "task_class",
                           &task_class)) {
        fleet_refuse_enum(reply, "task_class", "input.task_class");
        return;
    }
    if (!fleet_enum_stored(json_get(request->input, "harness"), "harness",
                           &harness)) {
        fleet_refuse_enum(reply, "harness", "input.harness");
        return;
    }
    if (!fleet_enum_stored(json_get(request->input, "model"), "model",
                           &model)) {
        fleet_refuse_enum(reply, "model", "input.model");
        return;
    }
    if (!fleet_enum_stored(json_get(request->input, "effort"), "effort",
                           &effort)) {
        fleet_refuse_enum(reply, "effort", "input.effort");
        return;
    }

    struct zcl_fleet_pair pairs[ZCL_FLEET_PAIRS_MAX];
    size_t n = 0;
    if (!fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TASK_CLASS, task_class) ||
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_HARNESS, harness) ||
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_MODEL, model) ||
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_EFFORT, effort)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    int64_t number = 0;
    if (fleet_input_i64(json_get(request->input, "tokens"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TOKENS_IN, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "wall_s"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_WALL_S, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    const struct json_value *outcome_v = json_get(request->input, "outcome");
    if (outcome_v) {
        uint8_t outcome = 0;
        if (!fleet_enum_stored(outcome_v, "outcome", &outcome)) {
            fleet_refuse_enum(reply, "outcome", "input.outcome");
            return;
        }
        if (!fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_OUTCOME, outcome)) {
            fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row",
                         false);
            return;
        }
    }
    fleet_experiment_write(reply, ZCL_FLEET_EXPERIMENT_PREDICT, "predict",
                           pairs, n, task_id);
}

void zcl_native_handle_fleet_experiment_result(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_experiment_result.v1");
    if (!request || !request->input) {
        fleet_refuse(reply, "MISSING_INPUT", "task_id is required", "input",
                     false);
        return;
    }
    const char *task_id = fleet_input_str(json_get(request->input, "task_id"));
    const char *note = fleet_input_str(json_get(request->input, "note"));
    if (!task_id)
        task_id = note;
    if (!task_id) {
        fleet_refuse(reply, "MISSING_INPUT", "task_id is required",
                     "input.task_id", false);
        return;
    }
    (void)json_get(request->input, "story");
    (void)json_get(request->input, "executor");

    uint8_t task_class = 0, model = 0, outcome = 0;
    if (!fleet_enum_stored(json_get(request->input, "task_class"), "task_class",
                           &task_class)) {
        fleet_refuse_enum(reply, "task_class", "input.task_class");
        return;
    }
    if (!fleet_enum_stored(json_get(request->input, "model"), "model",
                           &model)) {
        fleet_refuse_enum(reply, "model", "input.model");
        return;
    }
    if (!fleet_enum_stored(json_get(request->input, "outcome"), "outcome",
                           &outcome)) {
        fleet_refuse_enum(reply, "outcome", "input.outcome");
        return;
    }

    struct zcl_fleet_pair pairs[ZCL_FLEET_PAIRS_MAX];
    size_t n = 0;
    if (!fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TASK_CLASS, task_class) ||
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_MODEL, model) ||
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_OUTCOME, outcome)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }

    const struct json_value *harness_v = json_get(request->input, "harness");
    if (harness_v) {
        uint8_t harness = 0;
        if (!fleet_enum_stored(harness_v, "harness", &harness)) {
            fleet_refuse_enum(reply, "harness", "input.harness");
            return;
        }
        if (!fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_HARNESS, harness)) {
            fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row",
                         false);
            return;
        }
    }
    const struct json_value *effort_v = json_get(request->input, "effort");
    if (effort_v) {
        uint8_t effort = 0;
        if (!fleet_enum_stored(effort_v, "effort", &effort)) {
            fleet_refuse_enum(reply, "effort", "input.effort");
            return;
        }
        if (!fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_EFFORT, effort)) {
            fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row",
                         false);
            return;
        }
    }

    int64_t number = 0;
    if (fleet_input_i64(json_get(request->input, "in"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TOKENS_IN, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "out"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TOKENS_OUT, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "cache"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TOKENS_CACHED, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "reasoning"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TOKENS_REASONING, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "tool_uses"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TOOL_USES, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "turns"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_TURNS, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "wall_s"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_WALL_S, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "added"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_LINES_ADDED, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "removed"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_LINES_REMOVED, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    if (fleet_input_i64(json_get(request->input, "defects"), &number) &&
        !fleet_pair_add(pairs, &n, ZCL_FLEET_PAIR_DEFECTS, number)) {
        fleet_refuse(reply, "LEDGER_REFUSED", "ledger_argument", "row", false);
        return;
    }
    fleet_experiment_write(reply, ZCL_FLEET_EXPERIMENT_RESULT, "result", pairs,
                           n, task_id);
}

static void fleet_exp_absent_or_i64(char *out, size_t cap, uint8_t have,
                                    int64_t value)
{
    if (!have)
        (void)snprintf(out, cap, "-");
    else
        (void)snprintf(out, cap, "%lld", (long long)value);
}

void zcl_native_handle_fleet_experiment_stats(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_experiment_stats.v1");
    bool have_class = false, have_model = false;
    uint8_t want_class = 0, want_model = 0;
    if (request && request->input) {
        const struct json_value *v = json_get(request->input, "task_class");
        if (v) {
            if (!fleet_enum_stored(v, "task_class", &want_class)) {
                fleet_refuse_enum(reply, "task_class", "input.task_class");
                return;
            }
            have_class = true;
        }
        v = json_get(request->input, "model");
        if (v) {
            if (!fleet_enum_stored(v, "model", &want_model)) {
                fleet_refuse_enum(reply, "model", "input.model");
                return;
            }
            have_model = true;
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

    struct zcl_fleet_experiment_group groups[FLEET_EXPERIMENT_GROUPS_MAX];
    size_t count = 0;
    uint64_t unmatched = 0;
    uint64_t index_us = 0;
    enum zcl_fleet_status status = zcl_fleet_ledger_experiment_stats(
        ledger, groups, FLEET_EXPERIMENT_GROUPS_MAX, &count, &unmatched,
        &index_us);
    uint64_t overflow = zcl_fleet_ledger_experiment_overflow(ledger);
    zcl_fleet_ledger_close(ledger);
    if (status != ZCL_FLEET_OK && status != ZCL_FLEET_FULL) {
        fleet_refuse(reply, "LEDGER_REFUSED", zcl_fleet_status_label(status),
                     "query", false);
        return;
    }

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    char text[FLEET_EXPERIMENT_TEXT_MAX];
    size_t tlen = 0;
    text[0] = 0;
    uint64_t t_predicts = 0, t_results = 0, t_lands = 0, t_unpred = 0;
    for (size_t i = 0; i < count; i++) {
        if (have_class && groups[i].task_class != want_class)
            continue;
        if (have_model && groups[i].model != want_model)
            continue;
        const char *class_name =
            zcl_fleet_experiment_enum_name("task_class", groups[i].task_class);
        const char *model_name =
            zcl_fleet_experiment_enum_name("model", groups[i].model);
        int64_t land_bp = 0;
        uint8_t have_land = 0;
        if (groups[i].results > 0) {
            land_bp =
                (int64_t)((groups[i].lands * 10000ull) / groups[i].results);
            have_land = 1;
        }
        char wall[32], toks[32], ratio[32], land[32];
        fleet_exp_absent_or_i64(wall, sizeof wall, groups[i].have_median_wall,
                                groups[i].median_wall_s);
        fleet_exp_absent_or_i64(toks, sizeof toks, groups[i].have_median_tokens,
                                groups[i].median_tokens);
        fleet_exp_absent_or_i64(ratio, sizeof ratio, groups[i].have_pred_actual,
                                groups[i].pred_actual_bp);
        fleet_exp_absent_or_i64(land, sizeof land, have_land, land_bp);

        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "task_class",
                               class_name ? class_name : "");
        (void)json_push_kv_str(&row, "model", model_name ? model_name : "");
        (void)json_push_kv_int(&row, "predicts", (int64_t)groups[i].predicts);
        (void)json_push_kv_int(&row, "results", (int64_t)groups[i].results);
        (void)json_push_kv_int(&row, "lands", (int64_t)groups[i].lands);
        if (have_land)
            (void)json_push_kv_int(&row, "land_bp", land_bp);
        if (groups[i].have_median_wall)
            (void)json_push_kv_int(&row, "median_wall_s",
                                   groups[i].median_wall_s);
        if (groups[i].have_median_tokens)
            (void)json_push_kv_int(&row, "median_tokens",
                                   groups[i].median_tokens);
        if (groups[i].have_pred_actual)
            (void)json_push_kv_int(&row, "pred_actual_bp",
                                   groups[i].pred_actual_bp);
        (void)json_push_kv_int(&row, "unpredicted",
                               (int64_t)groups[i].unpredicted);
        (void)json_push_back(&rows, &row);
        json_free(&row);

        int wrote = snprintf(
            text + tlen, sizeof text - tlen,
            "%s %s predicts=%llu results=%llu lands=%llu land_bp=%s "
            "median_wall_s=%s median_tokens=%s pred_actual_bp=%s "
            "unpredicted=%llu\n",
            class_name ? class_name : "", model_name ? model_name : "",
            (unsigned long long)groups[i].predicts,
            (unsigned long long)groups[i].results,
            (unsigned long long)groups[i].lands, land, wall, toks, ratio,
            (unsigned long long)groups[i].unpredicted);
        if (wrote > 0 && (size_t)wrote < sizeof text - tlen)
            tlen += (size_t)wrote;
        t_predicts += groups[i].predicts;
        t_results += groups[i].results;
        t_lands += groups[i].lands;
        t_unpred += groups[i].unpredicted;
    }
    char land_total[32];
    if (t_results > 0)
        fleet_exp_absent_or_i64(land_total, sizeof land_total, 1,
                                (int64_t)((t_lands * 10000ull) / t_results));
    else
        fleet_exp_absent_or_i64(land_total, sizeof land_total, 0, 0);
    int wrote = snprintf(text + tlen, sizeof text - tlen,
                         "total predicts=%llu results=%llu lands=%llu "
                         "land_bp=%s unpredicted=%llu\n",
                         (unsigned long long)t_predicts,
                         (unsigned long long)t_results,
                         (unsigned long long)t_lands, land_total,
                         (unsigned long long)t_unpred);
    if (wrote > 0 && (size_t)wrote < sizeof text - tlen)
        tlen += (size_t)wrote;
    (void)tlen;
    (void)unmatched;

    (void)json_push_kv_str(&reply->data, "schema",
                           "zcl.fleet_experiment_stats.v1");
    (void)json_push_kv_int(&reply->data, "groups", (int64_t)json_size(&rows));
    (void)json_push_kv_int(&reply->data, "predicts", (int64_t)t_predicts);
    (void)json_push_kv_int(&reply->data, "results", (int64_t)t_results);
    (void)json_push_kv_int(&reply->data, "lands", (int64_t)t_lands);
    (void)json_push_kv_int(&reply->data, "unpredicted", (int64_t)t_unpred);
    (void)json_push_kv_int(&reply->data, "load_us", (int64_t)report.load_us);
    (void)json_push_kv_int(&reply->data, "index_us", (int64_t)index_us);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            status == ZCL_FLEET_FULL);
    (void)json_push_kv_int(&reply->data, "index_overflow_rows",
                           (int64_t)overflow);
    (void)json_push_kv(&reply->data, "stats", &rows);
    (void)json_push_kv_str(&reply->data, "text", text);
    json_free(&rows);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
