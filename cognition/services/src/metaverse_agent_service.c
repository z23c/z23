/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reconcile broker custody bindings with authoritative wallet reads.
 * // supervisor-ok:bounded-custody-readers — at most two one-shot workers,
 * joined by money_query_configured before the service returns.
 *
 * See services/metaverse_agent_service.h. Two readers over a broker directory,
 * plus the one validation both share.
 *
 * The absolute-path requirement is not cosmetic: a relative `dir` would be
 * resolved against whatever working directory the node happens to have, which
 * for a linger service is not the operator's shell. Refusing it makes the
 * subject of the read explicit at the call site.
 */

#include "services/metaverse_agent_service.h"

#include "base/result.h"
#include "base/hex.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "session/agent_broker.h"
#include "util/thread_registry.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define MVS_DIR_MAX 384

/* A custody snapshot can contend with the reducer's authoritative wallet and
 * vault readers while the dev lane is catching up.  Use the RPC client's
 * normal bounded read deadline: a shorter front-door latency budget turned a
 * valid snapshot into the false claim that its endpoint was unreachable. A
 * live dev-lane restart reproduced a correct response just beyond ten seconds
 * while the reducer held the authority lock, so retain a finite 30-second
 * bound. Freshness is still decided from the returned snapshot, never from
 * how quickly it arrived. */
#define MVS_MONEY_RPC_CONNECT_MS 500L
#define MVS_MONEY_RPC_TOTAL_MS 30000L

/* The one validation both readers share. Every refusal names which of the
 * three shape rules the caller broke, because "bad dir" alone does not tell an
 * operator whether to fix the path, the spelling, or the directory. */
static struct zcl_result dir_ok(const char *dir, char *out, size_t out_cap,
                                size_t *out_len)
{
    if (!out || out_cap == 0 || !out_len)
        return ZCL_ERR(MVS_ERR_BAD_ARGS, "out buffer is required");
    *out_len = 0;
    if (!dir || !dir[0])
        return ZCL_ERR(MVS_ERR_BAD_ARGS, "dir is required");
    if (dir[0] != '/')
        return ZCL_ERR(MVS_ERR_BAD_ARGS,
                       "dir must be an absolute path, got '%s'", dir);
    if (strnlen(dir, MVS_DIR_MAX + 1) > MVS_DIR_MAX)
        return ZCL_ERR(MVS_ERR_BAD_ARGS, "dir longer than %d bytes",
                       MVS_DIR_MAX);
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return ZCL_ERR(MVS_ERR_NOT_A_DIR,
                       "'%s' is not an existing directory", dir);
    return ZCL_OK;
}

struct zcl_result metaverse_agent_service_status(const char *dir, char *out,
                                                 size_t out_cap,
                                                 size_t *out_len)
{
    struct zcl_result r = dir_ok(dir, out, out_cap, out_len);
    if (!r.ok)
        return r;

    size_t n = agent_broker_render_status_json(dir, out, out_cap);
    if (n == 0)
        return ZCL_ERR(MVS_ERR_RENDER_FAILED,
                       "status document for '%s' did not fit %zu bytes", dir,
                       out_cap);
    *out_len = n;
    return ZCL_OK;
}

struct zcl_result metaverse_agent_service_audit(const char *dir, size_t limit,
                                                char *out, size_t out_cap,
                                                size_t *out_len)
{
    struct zcl_result r = dir_ok(dir, out, out_cap, out_len);
    if (!r.ok)
        return r;

    size_t n = agent_audit_render_json(dir, limit, out, out_cap);
    if (n == 0)
        return ZCL_ERR(MVS_ERR_RENDER_FAILED,
                       "audit document for '%s' did not fit %zu bytes", dir,
                       out_cap);
    *out_len = n;
    return ZCL_OK;
}

struct money_binding_read {
    struct agent_money_binding binding;
    struct json_value snapshot;
    char observed_wallet_instance_id[33];
    metaverse_agent_rpc_fn rpc;
    bool configured;
    bool current;
};

static bool money_load_bindings(const char *dir,
                                struct money_binding_read rows[2])
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/money-bindings.json", dir);
    FILE *f = fopen(path, "re");
    if (!f)
        return true; /* explicit UNKNOWN rows are produced by the caller */
    char raw[4096];
    size_t n = fread(raw, 1, sizeof(raw) - 1, f);
    bool overflow = !feof(f);
    (void)fclose(f);
    if (overflow || n == 0)
        return false;
    raw[n] = '\0';
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, raw, n)) {
        json_free(&doc);
        return false;
    }
    const struct json_value *wallets = json_get(&doc, "wallets");
    if (!wallets || wallets->type != JSON_ARR || json_size(wallets) > 2) {
        json_free(&doc);
        return false;
    }
    for (size_t i = 0; i < json_size(wallets); i++) {
        const struct json_value *w = json_at(wallets, i);
        const char *scope = w ? json_get_str(json_get(w, "scope")) : NULL;
        int slot = scope && strcmp(scope, "dev") == 0 ? 0
                 : scope && strcmp(scope, "prod") == 0 ? 1 : -1;
        const char *wid = w ? json_get_str(json_get(w, "wallet_instance_id")) : NULL;
        const char *gen = w ? json_get_str(json_get(w, "network_genesis")) : NULL;
        const char *dd = w ? json_get_str(json_get(w, "node_datadir")) : NULL;
        int64_t port = w ? json_get_int(json_get(w, "rpc_port")) : 0;
        if (slot < 0 || rows[slot].configured || !wid || strlen(wid) != 32 ||
            !gen || strlen(gen) != 64 || !dd || dd[0] != '/' ||
            strlen(dd) >= sizeof(rows[slot].binding.node_datadir) ||
            port <= 0 || port > 65535) {
            json_free(&doc);
            return false;
        }
        struct agent_money_binding *b = &rows[slot].binding;
        (void)snprintf(b->wallet_scope, sizeof(b->wallet_scope), "%s", scope);
        (void)snprintf(b->wallet_instance_id, sizeof(b->wallet_instance_id),
                       "%s", wid);
        (void)snprintf(b->network_genesis, sizeof(b->network_genesis), "%s",
                       gen);
        (void)snprintf(b->node_datadir, sizeof(b->node_datadir), "%s", dd);
        b->rpc_port = (int)port;
        rows[slot].configured = true;
    }
    json_free(&doc);
    return true;
}

static void money_unknown(struct json_value *out, const char *scope,
                          const char *status, const char *reason)
{
    json_set_object(out);
    (void)json_push_kv_str(out, "wallet_scope", scope);
    (void)json_push_kv_str(out, "wallet_instance_id", "");
    (void)json_push_kv_str(out, "status", status);
    (void)json_push_kv_bool(out, "complete", false);
    (void)json_push_kv_str(out, "reason", reason);
    (void)json_push_kv_str(out, "confirmed_zcl", "UNKNOWN");
    (void)json_push_kv_str(out, "pending_zcl", "UNKNOWN");
    (void)json_push_kv_str(out, "encumbered_zcl", "UNKNOWN");
    (void)json_push_kv_str(out, "intent_reserved_zcl", "UNKNOWN");
    (void)json_push_kv_str(out, "agent_available_zcl", "UNKNOWN");
    (void)json_push_kv_str(out, "snapshot_root", "");
}

static bool money_query(struct money_binding_read *row)
{
    if (!row->rpc)
        return false; /* raw-return-ok:no transport means explicit UNKNOWN */
    char params[96];
    (void)snprintf(params, sizeof(params),
                   "[\"custody\",{\"wallet_scope\":\"%s\"}]",
                   row->binding.wallet_scope);
    char *raw = row->rpc(row->binding.node_datadir, row->binding.rpc_port,
                         "agentsession", params, MVS_MONEY_RPC_CONNECT_MS,
                         MVS_MONEY_RPC_TOTAL_MS);
    if (!raw)
        return false;
    struct json_value reply;
    json_init(&reply);
    bool parsed = json_read(&reply, raw, strlen(raw));
    free(raw);
    const struct json_value *snapshot = parsed ? json_get(&reply, "snapshot")
                                               : NULL;
    if (!snapshot || snapshot->type != JSON_OBJ) {
        json_free(&reply);
        return false;
    }
    const char *scope = json_get_str(json_get(snapshot, "wallet_scope"));
    const char *wid = json_get_str(json_get(snapshot, "wallet_instance_id"));
    const char *gen = json_get_str(json_get(snapshot, "network_genesis"));
    const char *status = json_get_str(json_get(snapshot, "status"));
    const bool reported_current = status && strcmp(status, "CURRENT") == 0;
    if (wid && strlen(wid) == 32)
        (void)snprintf(row->observed_wallet_instance_id,
                       sizeof(row->observed_wallet_instance_id), "%s", wid);
    int64_t observed = json_get_int(json_get(snapshot, "observed_at"));
    int64_t now = (int64_t)platform_time_wall_time_t();
    bool identity_ok = scope && wid && gen &&
        strcmp(scope, row->binding.wallet_scope) == 0 &&
        strcmp(wid, row->binding.wallet_instance_id) == 0 &&
        strcmp(gen, row->binding.network_genesis) == 0;
    json_copy(&row->snapshot, snapshot);
    json_free(&reply);
    if (!identity_ok) {
        json_free(&row->snapshot);
        json_init(&row->snapshot);
        money_unknown(&row->snapshot, row->binding.wallet_scope,
                      "CONFLICTED", "live wallet identity differs from grant");
        return true;
    }
    if (observed <= 0 || now < observed || now - observed > 30) {
        struct json_value *status_value =
            (struct json_value *)json_get(&row->snapshot, "status");
        struct json_value *complete_value =
            (struct json_value *)json_get(&row->snapshot, "complete");
        struct json_value *reason_value =
            (struct json_value *)json_get(&row->snapshot, "reason");
        if (status_value) json_set_str(status_value, "STALE");
        if (complete_value) json_set_bool(complete_value, false);
        if (reason_value)
            json_set_str(reason_value, "observation is older than 30 seconds");
        return true;
    }
    row->current = reported_current &&
        json_get_bool(json_get(&row->snapshot, "complete"));
    return true;
}

struct money_query_job {
    struct money_binding_read *row;
    bool ok;
};

static void *money_query_thread(void *arg)
{
    struct money_query_job *job = arg;
    job->ok = money_query(job->row);
    return NULL;
}

/* Dev and prod are independent custody authorities. Reading them serially
 * doubled the user-visible deadline (two bounded 30 s RPCs) without adding
 * consistency: the portfolio root already records each observation and is
 * known only when both are CURRENT. Run both bounded reads concurrently, then
 * reconcile them in deterministic dev/prod order. If a worker cannot start,
 * execute that read inline so resource pressure degrades latency, never truth. */
static void money_query_configured(struct money_binding_read rows[2],
                                   bool queried[2])
{
    struct money_query_job jobs[2] = {
        { .row = &rows[0] }, { .row = &rows[1] },
    };
    pthread_t threads[2];
    bool spawned[2] = { false, false };
    for (int i = 0; i < 2; i++) {
        if (!rows[i].configured)
            continue;
        // thread-supervision-ok:bounded two-reader pool joined below
        int rc = thread_registry_spawn("zcl_money_rpc", money_query_thread,
                                       &jobs[i], &threads[i]);
        if (rc == 0)
            spawned[i] = true;
        else
            jobs[i].ok = money_query(jobs[i].row);
    }
    for (int i = 0; i < 2; i++) {
        if (spawned[i])
            (void)pthread_join(threads[i], NULL);
        queried[i] = rows[i].configured && jobs[i].ok;
    }
}

static void money_portfolio_root(const struct money_binding_read rows[2],
                                 char out[65])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)"zcl.agent_money.portfolio.v1", 28);
    for (int i = 0; i < 2; i++) {
        const char *status = json_get_str(json_get(&rows[i].snapshot, "status"));
        const char *root = json_get_str(json_get(&rows[i].snapshot,
                                                 "snapshot_root"));
        sha3_256_write(&c, (const uint8_t *)(status ? status : "UNKNOWN"),
                       strlen(status ? status : "UNKNOWN"));
        uint8_t decoded[32] = { 0 };
        if (root && root[0])
            (void)zcl_hex_decode(root, decoded, 32);
        sha3_256_write(&c, decoded, 32);
    }
    uint8_t root[32];
    sha3_256_finalize(&c, root);
    zcl_hex_encode(root, 32, out);
}

struct zcl_result metaverse_agent_service_money(
    const char *dir, metaverse_agent_rpc_fn rpc,
    char *out, size_t out_cap, size_t *out_len)
{
    struct zcl_result valid = dir_ok(dir, out, out_cap, out_len);
    if (!valid.ok)
        return valid;
    struct money_binding_read rows[2];
    memset(rows, 0, sizeof(rows));
    for (int i = 0; i < 2; i++) {
        rows[i].rpc = rpc;
        json_init(&rows[i].snapshot);
    }
    bool binding_ok = money_load_bindings(dir, rows);
    bool queried[2] = { false, false };
    if (binding_ok)
        money_query_configured(rows, queried);
    for (int i = 0; i < 2; i++) {
        const char *scope = i == 0 ? "dev" : "prod";
        if (!binding_ok)
            money_unknown(&rows[i].snapshot, scope, "CONFLICTED",
                          "private custody binding file is malformed");
        else if (!rows[i].configured)
            money_unknown(&rows[i].snapshot, scope, "UNKNOWN",
                          "owner created no binding for this wallet scope");
        else if (!queried[i])
            money_unknown(&rows[i].snapshot, scope, "UNKNOWN",
                          "bound wallet endpoint is unreachable");
    }
    const bool configured_duplicate = rows[0].configured && rows[1].configured &&
        strcmp(rows[0].binding.wallet_instance_id,
               rows[1].binding.wallet_instance_id) == 0;
    const bool observed_duplicate =
        rows[0].observed_wallet_instance_id[0] &&
        rows[1].observed_wallet_instance_id[0] &&
        strcmp(rows[0].observed_wallet_instance_id,
               rows[1].observed_wallet_instance_id) == 0;
    if (configured_duplicate || observed_duplicate) {
        for (int i = 0; i < 2; i++) {
            json_free(&rows[i].snapshot); json_init(&rows[i].snapshot);
            money_unknown(&rows[i].snapshot, i == 0 ? "dev" : "prod",
                          "CONFLICTED",
                          "duplicate wallet_instance_id on active bindings");
            rows[i].current = false;
        }
    }

    struct json_value doc, wallets;
    json_init(&doc); json_set_object(&doc);
    json_init(&wallets); json_set_array(&wallets);
    (void)json_push_kv_str(&doc, "schema", "zcl.metaverse_agent_money.v1");
    for (int i = 0; i < 2; i++)
        (void)json_push_back(&wallets, &rows[i].snapshot);
    (void)json_push_kv(&doc, "wallets", &wallets);
    json_free(&wallets);
    bool known = rows[0].current && rows[1].current;
    (void)json_push_kv_bool(&doc, "portfolio_total_known", known);
    if (known) {
        int64_t total = json_get_int(json_get(&rows[0].snapshot,
                                              "confirmed_zat")) +
                        json_get_int(json_get(&rows[1].snapshot,
                                              "confirmed_zat"));
        char zcl[32];
        (void)snprintf(zcl, sizeof(zcl), "%lld.%08lld",
                       (long long)(total / 100000000LL),
                       (long long)(total % 100000000LL));
        (void)json_push_kv_str(&doc, "portfolio_confirmed_zcl", zcl);
        (void)json_push_kv_int(&doc, "portfolio_confirmed_zat", total);
    }
    char root[65];
    money_portfolio_root(rows, root);
    (void)json_push_kv_str(&doc, "snapshot_root", root);
    for (int i = 0; i < 2; i++)
        json_free(&rows[i].snapshot);
    size_t n = json_write(&doc, out, out_cap);
    json_free(&doc);
    if (n == 0)
        return ZCL_ERR(MVS_ERR_RENDER_FAILED,
                       "money document did not fit %zu bytes", out_cap);
    *out_len = n;
    return ZCL_OK;
}

static void liquidity_unknown(struct json_value *doc, const char *scope,
                              const char *status, const char *reason)
{
    json_set_object(doc);
    (void)json_push_kv_str(doc, "schema",
                           "zcl.metaverse_agent_liquidity.v1");
    (void)json_push_kv_str(doc, "wallet_scope", scope ? scope : "");
    (void)json_push_kv_str(doc, "status", status);
    (void)json_push_kv_str(doc, "reason", reason);
    (void)json_push_kv_bool(doc, "amounts_known", false);
    (void)json_push_kv_bool(doc, "ready_now", false);
    (void)json_push_kv_bool(doc, "fanout_recommended", false);
    (void)json_push_kv_bool(doc, "automatic_rebalance", false);
}

static void liquidity_copy_scalar(struct json_value *dst,
                                  const struct json_value *src,
                                  const char *key)
{
    const struct json_value *v = json_get(src, key);
    if (!v)
        return;
    if (v->type == JSON_STR)
        (void)json_push_kv_str(dst, key, json_get_str(v));
    else if (v->type == JSON_INT)
        (void)json_push_kv_int(dst, key, json_get_int(v));
    else if (v->type == JSON_BOOL)
        (void)json_push_kv_bool(dst, key, json_get_bool(v));
}

static void liquidity_copy_fanout(struct json_value *dst,
                                  const struct json_value *src)
{
    const struct json_value *from = json_get(src, "fanout");
    if (!from || from->type != JSON_OBJ)
        return;
    static const char *const keys[] = {
        "automatic", "output_count", "output_value_zat",
        "outputs_total_zat", "maximum_fee_zat",
        "maximum_slots_under_policy", "prepare_command", "plan_command",
        "commit_command", "route", "owner_commit_required",
    };
    struct json_value fanout;
    json_init(&fanout);
    json_set_object(&fanout);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        liquidity_copy_scalar(&fanout, from, keys[i]);
    (void)json_push_kv(dst, "fanout", &fanout);
    json_free(&fanout);
}

struct zcl_result metaverse_agent_service_liquidity(
    const char *dir, const char *wallet_scope, int64_t recipient_value_zat,
    int64_t maximum_fee_zat, int requested_concurrency,
    metaverse_agent_rpc_fn rpc, char *out, size_t out_cap, size_t *out_len)
{
    struct zcl_result valid = dir_ok(dir, out, out_cap, out_len);
    if (!valid.ok)
        return valid;
    if (!wallet_scope ||
        (strcmp(wallet_scope, "dev") != 0 &&
         strcmp(wallet_scope, "prod") != 0) ||
        recipient_value_zat <= 0 || maximum_fee_zat < 0 ||
        requested_concurrency < 1 || requested_concurrency > 50)
        return ZCL_ERR(MVS_ERR_BAD_ARGS,
                       "wallet_scope dev|prod, positive recipient value, non-negative fee, and concurrency 1..50 are required");

    struct money_binding_read rows[2];
    memset(rows, 0, sizeof(rows));
    for (int i = 0; i < 2; i++) {
        rows[i].rpc = rpc;
        json_init(&rows[i].snapshot);
    }
    const bool bindings_ok = money_load_bindings(dir, rows);
    const int slot = strcmp(wallet_scope, "dev") == 0 ? 0 : 1;
    const int other_slot = slot == 0 ? 1 : 0;
    struct json_value doc;
    json_init(&doc);
    if (!bindings_ok) {
        liquidity_unknown(&doc, wallet_scope, "CONFLICTED",
                          "private custody binding file is malformed");
    } else if (!rows[slot].configured) {
        liquidity_unknown(&doc, wallet_scope, "UNKNOWN",
                          "owner created no binding for this wallet scope");
    } else if (rows[0].configured && rows[1].configured &&
               strcmp(rows[0].binding.wallet_instance_id,
                      rows[1].binding.wallet_instance_id) == 0) {
        liquidity_unknown(&doc, wallet_scope, "CONFLICTED",
                          "duplicate wallet_instance_id on active bindings");
    } else if (!rpc) {
        liquidity_unknown(&doc, wallet_scope, "UNKNOWN",
                          "bound wallet endpoint is unreachable");
    } else {
        char params[256];
        (void)snprintf(params, sizeof(params),
            "[\"liquidity\",{\"wallet_scope\":\"%s\","
            "\"recipient_value_zat\":%lld,\"maximum_fee_zat\":%lld,"
            "\"concurrency\":%d}]",
            wallet_scope, (long long)recipient_value_zat,
            (long long)maximum_fee_zat, requested_concurrency);
        char *raw = rpc(rows[slot].binding.node_datadir,
                        rows[slot].binding.rpc_port, "agentsession", params,
                        MVS_MONEY_RPC_CONNECT_MS, MVS_MONEY_RPC_TOTAL_MS);
        struct json_value reply;
        json_init(&reply);
        bool parsed = raw && json_read(&reply, raw, strlen(raw));
        free(raw);
        const char *scope = parsed
            ? json_get_str(json_get(&reply, "wallet_scope")) : NULL;
        const char *wid = parsed
            ? json_get_str(json_get(&reply, "wallet_instance_id")) : NULL;
        const char *gen = parsed
            ? json_get_str(json_get(&reply, "network_genesis")) : NULL;
        bool identity_ok = scope && wid && gen &&
            strcmp(scope, rows[slot].binding.wallet_scope) == 0 &&
            strcmp(wid, rows[slot].binding.wallet_instance_id) == 0 &&
            strcmp(gen, rows[slot].binding.network_genesis) == 0;
        bool observed_duplicate = false;
        if (identity_ok && rows[other_slot].configured &&
            money_query(&rows[other_slot]) &&
            rows[other_slot].observed_wallet_instance_id[0]) {
            observed_duplicate = strcmp(
                wid, rows[other_slot].observed_wallet_instance_id) == 0;
        }
        if (!parsed) {
            liquidity_unknown(&doc, wallet_scope, "UNKNOWN",
                              "bound wallet endpoint is unreachable");
        } else if (!identity_ok) {
            liquidity_unknown(&doc, wallet_scope, "CONFLICTED",
                              "live wallet identity differs from binding");
        } else if (observed_duplicate) {
            liquidity_unknown(&doc, wallet_scope, "CONFLICTED",
                              "duplicate wallet_instance_id on active bindings");
        } else {
            json_set_object(&doc);
            (void)json_push_kv_str(&doc, "schema",
                                   "zcl.metaverse_agent_liquidity.v1");
            static const char *const keys[] = {
                "wallet_scope", "wallet_instance_id", "network_genesis",
                "money_status", "money_reason", "money_snapshot_root",
                "observed_at", "status", "reason", "amounts_known",
                "requested_concurrency", "current_independent_slots",
                "current_inputs_used", "recipient_value_zat",
                "maximum_fee_zat", "required_per_slot_zat",
                "future_total_required_zat", "transparent_available_zat",
                "agent_available_zat", "ready_now", "fanout_recommended",
                "fanout_possible", "advisory", "next_command",
            };
            for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
                liquidity_copy_scalar(&doc, &reply, keys[i]);
            liquidity_copy_fanout(&doc, &reply);
            (void)json_push_kv_bool(&doc, "automatic_rebalance", false);
        }
        json_free(&reply);
    }

    size_t n = json_write(&doc, out, out_cap);
    json_free(&doc);
    for (int i = 0; i < 2; i++)
        json_free(&rows[i].snapshot);
    if (n == 0)
        return ZCL_ERR(MVS_ERR_RENDER_FAILED,
                       "liquidity document did not fit %zu bytes", out_cap);
    *out_len = n;
    return ZCL_OK;
}
