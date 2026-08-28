/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "controllers/api_controller.h"
#include "controllers/blockchain_controller.h"
#include "controllers/explorer_internal.h"
#include "controllers/file_controller.h"
#include "controllers/file_market_controller.h"
#include "controllers/game_controller.h"
#include "controllers/health_controller.h"
#include "controllers/messaging_controller.h"
#include "controllers/name_controller.h"
#include "controllers/swap_controller.h"
#include "api_controller_internal.h"
#include "chain/mmb.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "keys/key_io.h"
#include "models/block.h"
#include "models/database.h"
#include "models/file_service.h"
#include "models/hodl_wave.h"
#include "models/onion_announcement.h"
#include "models/peer.h"
#include "models/zslp.h"
#include "json/json.h"
#include "views/explorer_factoids_view.h"
#include "net/download.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/node_health_service.h"
#include "net/snapshot_sync_contract.h"
#include "services/zslp_service.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "views/format_helpers.h"
#include "supervisors/domains.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Lookup queue and parameterized handlers: /api/block/:id, /tx/:txid, /address/:addr. Single-slot work queue, served via background thread. */

#define LOOKUP_HEIGHT_UNAVAILABLE INT64_C(-1)

static int64_t json_i64_or(const struct json_value *obj, const char *key,
                           int64_t fallback)
{
    const struct json_value *v = json_get(obj, key);

    if (!v || json_is_null(v))
        return fallback;
    return json_get_int(v);
}

static double json_real_or(const struct json_value *obj, const char *key,
                           double fallback)
{
    const struct json_value *v = json_get(obj, key);

    if (!v || json_is_null(v))
        return fallback;
    return json_get_real(v);
}

static const char *json_str_or(const struct json_value *obj, const char *key,
                               const char *fallback)
{
    const struct json_value *v = json_get(obj, key);

    if (!v || v->type != JSON_STR)
        return fallback;
    return v->val.s ? v->val.s : fallback;
}

static const struct json_value *rpc_result_json(const char *buf,
                                                struct json_value *root)
{
    const struct json_value *result;
    const struct json_value *error;

    if (!buf || !root || !json_read(root, buf, strlen(buf)))
        return NULL;
    error = json_get(root, "error");
    if (error && !json_is_null(error))
        return NULL;
    result = json_get(root, "result");
    if (!result || json_is_null(result))
        return NULL;
    return result;
}

static int64_t indexed_height_from_confirmations(int64_t height,
                                                 int64_t confirmations)
{
    if (height >= 0 && confirmations > 0)
        return height + confirmations - 1;
    if (height >= 0)
        return height;
    return LOOKUP_HEIGHT_UNAVAILABLE;
}

static size_t push_string_array_limited(struct json_value *out,
                                        const struct json_value *src,
                                        size_t limit)
{
    size_t n;
    size_t pushed = 0;

    json_set_array(out);
    n = json_size(src);
    if (limit > 0 && n > limit)
        n = limit;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *item = json_at(src, i);
        const char *s;
        if (!item || item->type != JSON_STR)
            continue;
        s = item->val.s;
        if (!s)
            continue;
        struct json_value v;
        json_init(&v);
        json_set_str(&v, s);
        json_push_back(out, &v);
        json_free(&v);
        pushed++;
    }
    return pushed;
}

static size_t push_tx_vouts(struct json_value *out,
                            const struct json_value *vout)
{
    size_t pushed = 0;

    json_set_array(out);
    for (size_t i = 0; i < json_size(vout); i++) {
        const struct json_value *entry = json_at(vout, i);
        if (!entry || entry->type != JSON_OBJ)
            continue;

        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_int(&item, "n", json_i64_or(entry, "n", -1));
        json_push_kv_real(&item, "value", json_real_or(entry, "value", 0.0));

        const struct json_value *script = json_get(entry, "scriptPubKey");
        const struct json_value *addresses = json_get(script, "addresses");
        const struct json_value *addr_v = json_at(addresses, 0);
        const char *addr = addr_v && addr_v->type == JSON_STR
            ? addr_v->val.s : NULL;
        if (addr && addr[0])
            json_push_kv_str(&item, "address", addr);

        json_push_back(out, &item);
        json_free(&item);
        pushed++;
    }
    return pushed;
}

static size_t push_tx_vins(struct json_value *out,
                           const struct json_value *vin)
{
    size_t pushed = 0;

    json_set_array(out);
    for (size_t i = 0; i < json_size(vin); i++) {
        const struct json_value *entry = json_at(vin, i);
        if (!entry || entry->type != JSON_OBJ)
            continue;

        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        if (json_get(entry, "coinbase")) {
            json_push_kv_bool(&item, "coinbase", true);
        } else {
            json_push_kv_str(&item, "txid", json_str_or(entry, "txid", ""));
            json_push_kv_int(&item, "vout", json_i64_or(entry, "vout", -1));
        }
        json_push_back(out, &item);
        json_free(&item);
        pushed++;
    }
    return pushed;
}

static size_t push_address_utxos(struct json_value *out,
                                 const struct json_value *utxos)
{
    size_t pushed = 0;

    json_set_array(out);
    for (size_t i = 0; i < json_size(utxos); i++) {
        const struct json_value *entry = json_at(utxos, i);
        if (!entry || entry->type != JSON_OBJ)
            continue;

        int64_t satoshis = json_i64_or(entry, "satoshis", 0);
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "txid", json_str_or(entry, "txid", ""));
        json_push_kv_int(&item, "vout",
                         json_i64_or(entry, "outputIndex", -1));
        json_push_kv_int(&item, "satoshis", satoshis);
        json_push_kv_real(&item, "value",
                          (double)satoshis / (double)ZATOSHI_PER_ZCL);
        json_push_kv_int(&item, "height", json_i64_or(entry, "height", -1));
        json_push_back(out, &item);
        json_free(&item);
        pushed++;
    }
    return pushed;
}

size_t compute_block(const char *param, uint8_t *r, size_t max)
{
    if (!param || !*param)
        return api_json_error(r, max, JSON_404_HEADERS, "Missing block identifier");

    char buf[262144];
    char hash[65] = "";
    struct json_value root;
    const struct json_value *result;

    /* Resolve height to hash if needed */
    if (zcl_is_all_digits(param)) {
        char params[64];
        snprintf(params, sizeof(params), "[%s]", param);
        if (api_rpc_call("getblockhash", params, buf, sizeof(buf)) <= 0)
            return api_json_error(r, max, JSON_500_HEADERS, "RPC unavailable");

        json_init(&root);
        result = rpc_result_json(buf, &root);
        if (result) {
            const char *s = json_get_str(result);
            if (s)
                snprintf(hash, sizeof(hash), "%s", s);
        }
        json_free(&root);
    } else if (zcl_is_hex_string(param, 64)) {
        snprintf(hash, sizeof(hash), "%s", param);
    }

    if (!hash[0])
        return api_json_error(r, max, JSON_404_HEADERS, "Block not found");

    /* Get full block */
    char params2[128];
    snprintf(params2, sizeof(params2), "[\"%s\", true]", hash);
    if (api_rpc_call("getblock", params2, buf, sizeof(buf)) <= 0)
        return api_json_error(r, max, JSON_500_HEADERS, "RPC unavailable");

    json_init(&root);
    result = rpc_result_json(buf, &root);
    if (!result || result->type != JSON_OBJ) {
        json_free(&root);
        return api_json_error(r, max, JSON_404_HEADERS, "Block not found");
    }

    int64_t height = json_i64_or(result, "height", -1);
    int64_t confirmations = json_i64_or(result, "confirmations", -1);
    const struct json_value *tx_src = json_get(result, "tx");

    struct json_value body;
    struct json_value txs;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.blocks.show.v1");
    api_json_add_freshness(&body, "served_height",
                           indexed_height_from_confirmations(height,
                                                             confirmations));
    json_push_kv_str(&body, "hash", json_str_or(result, "hash", hash));
    json_push_kv_int(&body, "height", height);
    json_push_kv_int(&body, "time", json_i64_or(result, "time", -1));
    json_push_kv_int(&body, "size", json_i64_or(result, "size", -1));
    json_push_kv_real(&body, "difficulty",
                      json_real_or(result, "difficulty", 0.0));
    json_push_kv_int(&body, "confirmations", confirmations);
    json_push_kv_int(&body, "num_tx", (int64_t)json_size(tx_src));
    json_push_kv_str(&body, "merkleroot",
                     json_str_or(result, "merkleroot", ""));
    json_push_kv_str(&body, "nonce", json_str_or(result, "nonce", ""));
    const char *prev_hash = json_str_or(result, "previousblockhash", NULL);
    const char *next_hash = json_str_or(result, "nextblockhash", NULL);
    if (prev_hash && prev_hash[0])
        json_push_kv_str(&body, "previousblockhash",
                         prev_hash);
    if (next_hash && next_hash[0])
        json_push_kv_str(&body, "nextblockhash", next_hash);

    json_init(&txs);
    size_t tx_returned = push_string_array_limited(&txs, tx_src, 200);
    json_push_kv(&body, "tx", &txs);
    json_push_kv_int(&body, "tx_returned", (int64_t)tx_returned);
    json_push_kv_bool(&body, "tx_truncated", json_size(tx_src) > tx_returned);
    json_free(&txs);

    size_t n = api_json_ok(r, max, &body);
    json_free(&body);
    json_free(&root);
    return n;
}
size_t compute_tx(const char *param, uint8_t *r, size_t max)
{
    if (!zcl_is_hex_string(param, 64))
        return api_json_error(r, max, JSON_404_HEADERS, "Invalid transaction ID");

    char buf[262144];
    char params[128];
    snprintf(params, sizeof(params), "[\"%s\", 1]", param);
    int n = api_rpc_call("getrawtransaction", params, buf, sizeof(buf));
    if (n <= 0)
        return api_json_error(r, max, JSON_404_HEADERS, "Transaction not found");

    struct json_value root;
    json_init(&root);
    const struct json_value *result = rpc_result_json(buf, &root);
    if (!result || result->type != JSON_OBJ) {
        json_free(&root);
        return api_json_error(r, max, JSON_404_HEADERS,
                              "Transaction not found");
    }

    int64_t confirmations = json_i64_or(result, "confirmations", -1);
    int64_t blk_height = json_i64_or(result, "height", -1);
    const struct json_value *vout_src = json_get(result, "vout");
    const struct json_value *vin_src = json_get(result, "vin");

    struct json_value body;
    struct json_value vout;
    struct json_value vin;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.transactions.show.v1");
    api_json_add_freshness(&body, "served_height",
                           indexed_height_from_confirmations(blk_height,
                                                             confirmations));
    json_push_kv_str(&body, "txid", json_str_or(result, "txid", param));
    json_push_kv_int(&body, "version", json_i64_or(result, "version", -1));
    json_push_kv_int(&body, "size", json_i64_or(result, "size", -1));
    json_push_kv_int(&body, "locktime", json_i64_or(result, "locktime", -1));
    json_push_kv_int(&body, "confirmations", confirmations);
    json_push_kv_str(&body, "blockhash", json_str_or(result, "blockhash", ""));
    json_push_kv_int(&body, "blockheight", blk_height);
    json_push_kv_real(&body, "valuebalance",
                      json_real_or(result, "valuebalance", 0.0));

    json_init(&vout);
    size_t vout_returned = push_tx_vouts(&vout, vout_src);
    json_push_kv(&body, "vout", &vout);
    json_push_kv_int(&body, "vout_returned", (int64_t)vout_returned);
    json_free(&vout);

    json_init(&vin);
    size_t vin_returned = push_tx_vins(&vin, vin_src);
    json_push_kv(&body, "vin", &vin);
    json_push_kv_int(&body, "vin_returned", (int64_t)vin_returned);
    json_free(&vin);

    size_t out_n = api_json_ok(r, max, &body);
    json_free(&body);
    json_free(&root);
    return out_n;
}
size_t compute_address(const char *param, uint8_t *r, size_t max)
{
    if (!param || !*param)
        return api_json_error(r, max, JSON_404_HEADERS, "Missing address");

    size_t alen = strlen(param);
    if (alen < 25 || alen > 95)
        return api_json_error(r, max, JSON_404_HEADERS, "Invalid address");

    /* Ensure address is safe to embed in JSON/RPC params */
    if (!api_is_json_safe_param(param, alen))
        return api_json_error(r, max, JSON_404_HEADERS, "Invalid address characters");

    char buf[262144];
    size_t off = 0;

    /* Try getaddressbalance (addressindex RPC) */
    char params[256];
    snprintf(params, sizeof(params),
        "[{\"addresses\":[\"%s\"]}]", param);
    int n = api_rpc_call("getaddressbalance", params, buf, sizeof(buf));

    int64_t balance_sat = 0;
    bool got_balance = false;

    if (n > 0) {
        struct json_value root;
        json_init(&root);
        const struct json_value *result = rpc_result_json(buf, &root);
        if (result && result->type == JSON_OBJ) {
            balance_sat = json_i64_or(result, "balance", 0);
            got_balance = true;
        }
        json_free(&root);
    }

    /* Try getaddressutxos */
    char ubuf[262144];
    n = api_rpc_call("getaddressutxos", params, ubuf, sizeof(ubuf));

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.addresses.show.v1");
    api_json_add_freshness(&body, "utxo_projection", -1);
    json_push_kv_str(&body, "address", param);

    if (got_balance) {
        json_push_kv_int(&body, "balance_sat", balance_sat);
        json_push_kv_real(&body, "balance",
                          (double)balance_sat / (double)ZATOSHI_PER_ZCL);
    }

    struct json_value utxos;
    json_init(&utxos);
    json_set_array(&utxos);
    size_t utxo_count = 0;
    if (n > 0) {
        struct json_value root;
        json_init(&root);
        const struct json_value *result = rpc_result_json(ubuf, &root);
        if (result)
            utxo_count = push_address_utxos(&utxos, result);
        json_free(&root);
    }
    json_push_kv(&body, "utxos", &utxos);
    json_push_kv_int(&body, "utxo_count", (int64_t)utxo_count);
    json_free(&utxos);

    off = api_json_ok(r, max, &body);
    json_free(&body);
    return off;
}
/* ── Parameterized endpoint request queue ────────────────── */
/* For /api/block/:id, /api/tx/:txid, /api/address/:addr we
 * submit the request to the background thread and serve from
 * a small per-request cache. Uses a simple single-slot queue. */

static pthread_mutex_t g_lookup_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_lookup_request_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  g_lookup_done_cond = PTHREAD_COND_INITIALIZER;

/* enum lookup_type defined in api_controller_internal.h */

static _Atomic enum lookup_type g_lookup_type = LOOKUP_NONE;
static char    g_lookup_param[512];
static uint8_t g_lookup_result[262144];
static size_t  g_lookup_result_len = 0;
static _Atomic int g_lookup_thread_running = 0;
static bool g_lookup_thread_active = false;
static pthread_mutex_t g_lookup_lifecycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_lookup_lifecycle_cond = PTHREAD_COND_INITIALIZER;

/* ── #13: supervision for the detached lookup-worker thread ────────────
 * Previously an unsupervised infinite loop: a DB-lock hang inside
 * compute_block/tx/address freezes /api/block/tx/address lookups forever
 * (do_lookup's 15s client-side wait just returns 503 to each caller, over
 * and over) with no liveness signal anywhere. Self-driven contract (mirrors
 * disk_monitor.c / the api_cache_refresh sibling above): the thread ticks
 * once per idle-wait pass (~1s cadence while there is no request to serve),
 * so a real processing hang — the only time ticks stop — trips the
 * independent supervisor deadline. */
#define API_LOOKUP_SUPERVISOR_DEADLINE_SEC 60
static struct liveness_contract    g_api_lookup_contract;
static _Atomic supervisor_child_id g_api_lookup_sup_id = SUPERVISOR_INVALID_ID;
static _Atomic int64_t             g_api_lookup_loop_ticks = 0;

static void api_lookup_supervisor_heartbeat(void)
{
    supervisor_child_id id = atomic_load(&g_api_lookup_sup_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, atomic_load(&g_api_lookup_loop_ticks));
}

static void api_lookup_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN("api", "[api] lookup-worker thread stall reason=%s "
             "loop_ticks=%lld — /api/block,/tx,/address lookups will 503 "
             "forever", reason, (long long)atomic_load(&g_api_lookup_loop_ticks));
    struct blocker_record rec;
    if (blocker_init(&rec, "api_lookup_stalled", "op.api_lookup",
                     BLOCKER_TRANSIENT,
                     "REST /api lookup worker stopped heartbeating; "
                     "/api/block,/tx,/address requests will 503 forever"))
        (void)blocker_set(&rec);
}

static void api_lookup_register_supervisor(void)
{
    supervisor_child_id existing = atomic_load(&g_api_lookup_sup_id);
    if (existing != SUPERVISOR_INVALID_ID) {
        api_lookup_supervisor_heartbeat();
        supervisor_set_deadline(existing, API_LOOKUP_SUPERVISOR_DEADLINE_SEC);
        return;
    }
    if (!supervisor_start()) {
        LOG_WARN("api", "[api] lookup: supervisor_start failed");
        return;
    }
    liveness_contract_init(&g_api_lookup_contract, "op.api_lookup");
    atomic_store(&g_api_lookup_contract.period_secs, (int64_t)0);
    atomic_store(&g_api_lookup_contract.deadline_secs,
                (int64_t)API_LOOKUP_SUPERVISOR_DEADLINE_SEC);
    g_api_lookup_contract.on_stall = api_lookup_on_stall;
    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_op_sup, &g_api_lookup_contract);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("api", "[api] lookup: supervisor register failed");
        return;
    }
    atomic_store(&g_api_lookup_sup_id, id);
    api_lookup_supervisor_heartbeat();
}

void api_lookup_supervisor_quiesce(void)
{
    supervisor_child_id id = atomic_load(&g_api_lookup_sup_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
}

/* Background thread that processes lookup requests one at a time */
static void *api_lookup_thread(void *arg)
{
    (void)arg;
    printf("API lookup: background thread started\n");
    fflush(stdout);

    while (g_lookup_thread_running) {
        pthread_mutex_lock(&g_lookup_mutex);
        while (g_lookup_type == LOOKUP_NONE && g_lookup_thread_running) {
            struct timespec ts;
            platform_time_realtime_timespec(&ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&g_lookup_request_cond, &g_lookup_mutex, &ts);
            atomic_fetch_add(&g_api_lookup_loop_ticks, 1);
            api_lookup_supervisor_heartbeat();
        }
        if (!g_lookup_thread_running) {
            pthread_mutex_unlock(&g_lookup_mutex);
            break;
        }

        enum lookup_type type = g_lookup_type;
        char param[512];
        snprintf(param, sizeof(param), "%s", g_lookup_param);
        pthread_mutex_unlock(&g_lookup_mutex);

        size_t len = 0;
        switch (type) {
        case LOOKUP_BLOCK:
            len = compute_block(param, g_lookup_result, sizeof(g_lookup_result));
            break;
        case LOOKUP_TX:
            len = compute_tx(param, g_lookup_result, sizeof(g_lookup_result));
            break;
        case LOOKUP_ADDRESS:
            len = compute_address(param, g_lookup_result, sizeof(g_lookup_result));
            break;
        default:
            break;
        }

        pthread_mutex_lock(&g_lookup_mutex);
        g_lookup_result_len = len;
        g_lookup_type = LOOKUP_NONE;
        pthread_cond_broadcast(&g_lookup_done_cond);
        pthread_mutex_unlock(&g_lookup_mutex);
    }

    printf("API lookup: background thread stopped\n");
    fflush(stdout);
    pthread_mutex_lock(&g_lookup_lifecycle_mutex);
    g_lookup_thread_active = false;
    pthread_cond_broadcast(&g_lookup_lifecycle_cond);
    pthread_mutex_unlock(&g_lookup_lifecycle_mutex);
    return NULL;
}

static bool ensure_lookup_thread(void)
{
    pthread_t t;

    pthread_mutex_lock(&g_api_worker_generation_mutex);
    pthread_mutex_lock(&g_lookup_lifecycle_mutex);
    if (g_lookup_thread_active) {
        pthread_mutex_unlock(&g_lookup_lifecycle_mutex);
        pthread_mutex_unlock(&g_api_worker_generation_mutex);
        return true;
    }
    atomic_store(&g_lookup_thread_running, 1);
    g_lookup_thread_active = true;
    api_lookup_register_supervisor();
    if (!api_start_detached_thread(&t, api_lookup_thread, NULL)) {
        atomic_store(&g_lookup_thread_running, 0);
        g_lookup_thread_active = false;
        pthread_mutex_unlock(&g_lookup_lifecycle_mutex);
        pthread_mutex_unlock(&g_api_worker_generation_mutex);
        LOG_FAIL("api", "ensure_lookup_thread: failed to start lookup thread");
    }
    pthread_mutex_unlock(&g_lookup_lifecycle_mutex);
    pthread_mutex_unlock(&g_api_worker_generation_mutex);
    return true;
}

/* Submit a lookup request and wait for result (with timeout) */
size_t do_lookup(enum lookup_type type, const char *param,
                         uint8_t *response, size_t response_max)
{
    if (!ensure_lookup_thread()) {
        return api_json_error(response, response_max, JSON_503_HEADERS,
                          "Lookup worker unavailable");
    }

    pthread_mutex_lock(&g_lookup_mutex);

    /* If another request is pending, return 503 */
    if (g_lookup_type != LOOKUP_NONE) {
        pthread_mutex_unlock(&g_lookup_mutex);
        return api_json_error(response, response_max, JSON_503_HEADERS,
                          "Lookup worker busy");
    }

    snprintf(g_lookup_param, sizeof(g_lookup_param), "%s", param);
    g_lookup_result_len = 0;
    g_lookup_type = type;
    pthread_cond_signal(&g_lookup_request_cond);

    /* Wait up to 15 seconds for result */
    struct timespec ts;
    platform_time_realtime_timespec(&ts);
    ts.tv_sec += 15;

    while (g_lookup_type != LOOKUP_NONE) {
        int rc = pthread_cond_timedwait(&g_lookup_done_cond, &g_lookup_mutex, &ts);
        if (rc != 0) {
            /* Timeout */
            pthread_mutex_unlock(&g_lookup_mutex);
            return api_json_error(response, response_max, JSON_503_HEADERS,
                              "Request timed out");
        }
    }

    size_t len = g_lookup_result_len;
    if (len > 0) {
        size_t copy = len < response_max ? len : response_max;
        memcpy(response, g_lookup_result, copy);
        pthread_mutex_unlock(&g_lookup_mutex);
        return copy;
    }

    pthread_mutex_unlock(&g_lookup_mutex);
    return api_json_error(response, response_max, JSON_500_HEADERS, "RPC unavailable");
}

void api_lookup_stop(void)
{
    api_lookup_supervisor_quiesce();
    pthread_mutex_lock(&g_lookup_lifecycle_mutex);
    atomic_store(&g_lookup_thread_running, 0);
    pthread_mutex_lock(&g_lookup_mutex);
    pthread_cond_broadcast(&g_lookup_request_cond);
    pthread_cond_broadcast(&g_lookup_done_cond);
    pthread_mutex_unlock(&g_lookup_mutex);
    while (g_lookup_thread_active)
        pthread_cond_wait(&g_lookup_lifecycle_cond,
                          &g_lookup_lifecycle_mutex);
    pthread_mutex_unlock(&g_lookup_lifecycle_mutex);
}

#ifdef ZCL_TESTING
bool api_lookup_test_worker_alive(void)
{
    pthread_mutex_lock(&g_lookup_lifecycle_mutex);
    bool alive = g_lookup_thread_active;
    pthread_mutex_unlock(&g_lookup_lifecycle_mutex);
    return alive;
}

/* #13 test seams — see the "supervision for the detached lookup-worker
 * thread" block comment near g_api_lookup_sup_id above. Registers the
 * liveness contract WITHOUT spawning the real detached thread, so the
 * wiring can be exercised hermetically and fast. */
void api_lookup_test_register_supervisor(void)
{
    api_lookup_register_supervisor();
}

supervisor_child_id api_lookup_test_supervisor_id(void)
{
    return atomic_load(&g_api_lookup_sup_id);
}

void api_lookup_test_force_stall(void)
{
    api_lookup_on_stall(&g_api_lookup_contract);
}
#endif
