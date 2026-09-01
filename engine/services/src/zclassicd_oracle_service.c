// one-result-type-ok:json-dump-bool — E2 (one way out): the sole remaining
// Dump-state export: zclassicd_oracle_dump_state_json.
// introspection dumper. The dump convention (CLAUDE.md "Adding state
// introspection") mandates a bool return (false = couldn't populate), not
// struct zcl_result; every other fallible surface in this file already
// returns zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zclassicd Oracle Service. See header for the high-level rationale.
 *
 * Layout:
 *   1. Config + creds (parse zclassic.conf)
 *   2. zclassicd_oracle_probe() — synchronous probe of one height
 *   3. on_tick() — periodic supervisor callback (random-height fan-out)
 *   4. init/start/stop + stats snapshot + dump_state_json
 *
 * Threading: the only background work is the supervisor tick loop. No
 * new pthreads are created here.
 */

#include "services/zclassicd_oracle_service.h"
#include "services/oracle_policy.h"

#include "supervisors/domains.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "core/random.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "event/event.h"
#include "platform/time_compat.h"
#include "rpc/legacy_rpc_client.h"
#include "rpc/zclassicd_port.h"
#include "util/log_macros.h"
#include "util/supervisor.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* ── Constants ─────────────────────────────────────────────────── */

#define ORACLE_DEFAULT_HOST          "127.0.0.1"
#define ORACLE_DEFAULT_CADENCE       60
#define ORACLE_DEFAULT_HEIGHTS_TICK  3
#define ORACLE_TIP_SAFETY_MARGIN     100  /* avoid races at the tip */

/* ── Global state ──────────────────────────────────────────────── */

static struct {
    pthread_mutex_t lock;       /* guards config + stats */
    bool   initialized;
    char   rpc_host[64];
    int    rpc_port;
    char   rpc_user[64];
    char   rpc_password[128];
    int    cadence_secs;
    int    heights_per_tick;
    _Atomic supervisor_child_id supervisor_id;

    /* Stats */
    _Atomic int64_t attempts_total;
    _Atomic int64_t probes_total;
    _Atomic int64_t probes_agree;
    _Atomic int64_t probes_disagree;
    _Atomic int64_t rpc_errors;
    _Atomic int64_t last_probe_unix_us;
    _Atomic int     last_probed_height;
    _Atomic int64_t last_attempt_unix_us;
    _Atomic int     last_attempt_height;
    _Atomic int64_t last_error_unix_us;
    _Atomic int     last_error_height;
    _Atomic int     last_error_code;
    _Atomic int     rpc_transport_reachable;
    _Atomic int     oracle_usable;
    _Atomic int     reachable;
    char            last_error[128];
} g_oracle = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .supervisor_id = SUPERVISOR_INVALID_ID,
};

static struct liveness_contract g_oracle_contract;

static int64_t zclassicd_oracle_progress_marker(void)
{
    return atomic_load(&g_oracle.probes_total);
}

static int64_t zclassicd_oracle_now_us(void)
{
    return platform_time_realtime_us();
}

static int zclassicd_oracle_error_code(const char *err)
{
    if (!err)
        return 0;
    int code = 0;
    if (sscanf(err, "rpc error %d", &code) == 1)
        return code;
    return 0;
}

static void zclassicd_oracle_record_attempt(int height)
{
    int64_t now = zclassicd_oracle_now_us();
    atomic_fetch_add(&g_oracle.attempts_total, 1);
    atomic_store(&g_oracle.last_attempt_height, height);
    atomic_store(&g_oracle.last_attempt_unix_us, now);
    atomic_store(&g_oracle.last_probed_height, height);
    atomic_store(&g_oracle.last_probe_unix_us, now);
}

static void zclassicd_oracle_set_dependency_error(const char *err,
                                                  int height,
                                                  bool transport_reachable)
{
    int64_t now = zclassicd_oracle_now_us();
    atomic_store(&g_oracle.rpc_transport_reachable,
                 transport_reachable ? 1 : 0);
    atomic_store(&g_oracle.oracle_usable, 0);
    atomic_store(&g_oracle.reachable, 0);
    atomic_store(&g_oracle.last_error_height, height);
    atomic_store(&g_oracle.last_error_unix_us, now);
    atomic_store(&g_oracle.last_error_code,
                 zclassicd_oracle_error_code(err));
    pthread_mutex_lock(&g_oracle.lock);
    snprintf(g_oracle.last_error, sizeof(g_oracle.last_error), "%s",
             err && err[0] ? err : "rpc-unreachable");
    pthread_mutex_unlock(&g_oracle.lock);
}

static void zclassicd_oracle_mark_dependency_reachable(void)
{
    atomic_store(&g_oracle.rpc_transport_reachable, 1);
    atomic_store(&g_oracle.oracle_usable, 1);
    atomic_store(&g_oracle.reachable, 1);
    atomic_store(&g_oracle.last_error_height, 0);
    atomic_store(&g_oracle.last_error_unix_us, 0);
    atomic_store(&g_oracle.last_error_code, 0);
    pthread_mutex_lock(&g_oracle.lock);
    g_oracle.last_error[0] = '\0';
    pthread_mutex_unlock(&g_oracle.lock);
}

/* Parse a JSON-RPC `.result` string and require exactly 64 hex chars
 * (a block hash). Thin wrapper over the shared transport parser so the
 * "getblockhash result + 64-hex validation" idiom lives in one place
 * (legacy_chain_oracle.c uses the same shape). out_hex must be >= 65
 * bytes. */
static bool parse_rpc_hex_result(const char *raw, char *out_hex,
                                 char *err, size_t err_sz)
{
    if (!legacy_rpc_parse_result_string(raw, out_hex, 65, err, err_sz))
        return false;  // raw-return-ok:err-out-param-carries-reason-to-caller
    if (strlen(out_hex) != 64) {
        snprintf(err, err_sz, "result not 64 hex chars (got %zu)",
                 strlen(out_hex));
        return false;
    }
    return true;
}

/* ── Our-side block lookup ─────────────────────────────────────── */

static bool our_hash_at_height(int height, char out_hex[65])
{
    struct main_state *ms = wallet_rpc_main_state();
    if (!ms) {
        out_hex[0] = '\0';
        return false;
    }
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi || !bi->phashBlock) {
        out_hex[0] = '\0';
        return false;
    }
    uint256_get_hex(bi->phashBlock, out_hex);
    return true;
}

static int our_tip_height(void)
{
    struct main_state *ms = wallet_rpc_main_state();
    if (!ms) return -1; /* raw-return-ok:sentinel */
    return active_chain_height(&ms->chain_active);
}

/* ── Public probe ──────────────────────────────────────────────── */

struct zcl_result zclassicd_oracle_probe(int height,
                            struct zclassicd_oracle_probe_result *out)
{
    if (!out)
        return ZCL_ERR(-1, "zclassicd_oracle_probe: NULL out");
    memset(out, 0, sizeof(*out));
    out->height = height;

    if (height < 0) {
        out->error = true;
        snprintf(out->error_msg, sizeof(out->error_msg),
                 "negative height %d", height);
        return ZCL_ERR(-2, "zclassicd_oracle_probe: negative height %d", height);
    }
    zclassicd_oracle_record_attempt(height);

    /* Snapshot config */
    char host[64], user[64], pass[128];
    int port;
    pthread_mutex_lock(&g_oracle.lock);
    snprintf(host, sizeof(host), "%s",
             g_oracle.rpc_host[0] ? g_oracle.rpc_host : ORACLE_DEFAULT_HOST);
    port = g_oracle.rpc_port ? g_oracle.rpc_port : ZCLASSICD_RPC_DEFAULT_PORT;
    snprintf(user, sizeof(user), "%s", g_oracle.rpc_user);
    snprintf(pass, sizeof(pass), "%s", g_oracle.rpc_password);
    pthread_mutex_unlock(&g_oracle.lock);

    /* Build JSON-RPC body */
    char body[256];
    snprintf(body, sizeof(body),
        "{\"jsonrpc\":\"1.0\",\"id\":\"zcl-oracle\","
        "\"method\":\"getblockhash\",\"params\":[%d]}", height);

    char *resp = NULL;
    if (!legacy_rpc_call(host, port, user, pass, body, &resp,
                         out->error_msg, sizeof(out->error_msg))) {
        out->error = true;
        atomic_fetch_add(&g_oracle.rpc_errors, 1);
        zclassicd_oracle_set_dependency_error(out->error_msg, height, false);
        return ZCL_OK;
    }

    if (!parse_rpc_hex_result(resp, out->their_hash,
                              out->error_msg, sizeof(out->error_msg))) {
        free(resp);
        out->error = true;
        atomic_fetch_add(&g_oracle.rpc_errors, 1);
        zclassicd_oracle_set_dependency_error(out->error_msg, height, true);
        return ZCL_OK;
    }
    free(resp);
    zclassicd_oracle_mark_dependency_reachable();

    /* Our-side lookup */
    out->our_have_block = our_hash_at_height(height, out->our_hash);
    out->match = out->our_have_block &&
                 strcasecmp(out->our_hash, out->their_hash) == 0;

    /* Stats */
    atomic_fetch_add(&g_oracle.probes_total, 1);
    if (out->our_have_block) {
        if (out->match) {
            atomic_fetch_add(&g_oracle.probes_agree, 1);
            event_emitf(EV_ORACLE_AGREE, 0,
                        "h=%d hash=%s", height, out->their_hash);
        } else {
            atomic_fetch_add(&g_oracle.probes_disagree, 1);
            event_emitf(EV_ORACLE_DISAGREE, 0,
                        "h=%d our=%s their=%s",
                        height, out->our_hash, out->their_hash);
            /* T2.1: feed the policy state machine. It decides whether
             * to halt new block acceptance or panic. */
            oracle_policy_record_disagreement(height,
                                              out->our_hash,
                                              out->their_hash);
        }
    }
    /* If we don't have the block locally, neither agree nor disagree;
     * still counted in probes_total. */
    return ZCL_OK;
}

/* ── Periodic tick (supervisor callback) ───────────────────────── */

static void zclassicd_oracle_on_stall(struct liveness_contract *c)
{
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int64_t probes = atomic_load(&g_oracle.probes_total);
    int64_t errors = atomic_load(&g_oracle.rpc_errors);
    LOG_WARN("oracle",
             "[oracle] zclassicd oracle dependency stall reason=%s probes=%lld rpc_errors=%lld",
             reason, (long long)probes, (long long)errors);
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "source=oracle.zclassicd decision=dependency_stall "
                "reason=%s probes=%lld rpc_errors=%lld",
                reason, (long long)probes, (long long)errors);
}

static void zclassicd_oracle_on_tick(struct liveness_contract *c)
{
    (void)c;
    supervisor_child_id id = atomic_load(&g_oracle.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_tick(id);

    int64_t errors_before = atomic_load(&g_oracle.rpc_errors);
    int tip = our_tip_height();
    int margin = ORACLE_TIP_SAFETY_MARGIN;
    /* Tests can lower the margin so a tiny synthetic chain still
     * exercises the periodic-tick path. Production code never sets
     * this env var. */
    const char *m = getenv("ZCL_ORACLE_TIP_MARGIN");
    if (m && m[0]) {
        int n = atoi(m);
        if (n >= 0) margin = n;
    }
    int max_h = tip - margin;
    if (max_h <= 0) {
        if (id != SUPERVISOR_INVALID_ID)
            supervisor_progress(id, zclassicd_oracle_progress_marker());
        return;  /* not synced yet */
    }

    int n = g_oracle.heights_per_tick > 0
                ? g_oracle.heights_per_tick : ORACLE_DEFAULT_HEIGHTS_TICK;
    for (int i = 0; i < n; i++) {
        int h = GetRandInt(max_h + 1);
        struct zclassicd_oracle_probe_result r;
        (void)zclassicd_oracle_probe(h, &r);  /* periodic; discard result */
    }

    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_progress(id, zclassicd_oracle_progress_marker());
        if (atomic_load(&g_oracle.rpc_errors) > errors_before) {
            /* Auto mode is advisory.  Preserve the typed reachability/error
             * counters but classify an absent external oracle as idle, not a
             * node liveness stall.  A CHILD_REPORTED stall used to trigger a
             * debug-bundle capture every time the rate limiter opened. */
            supervisor_progress_idle(id);
        }
    }
}

/* ── init / start / stop ───────────────────────────────────────── */

struct zcl_result zclassicd_oracle_init(const struct zclassicd_oracle_config *cfg)
{
    pthread_mutex_lock(&g_oracle.lock);

    snprintf(g_oracle.rpc_host, sizeof(g_oracle.rpc_host), "%s",
             (cfg && cfg->rpc_host) ? cfg->rpc_host : ORACLE_DEFAULT_HOST);
    g_oracle.rpc_port = (cfg && cfg->rpc_port > 0)
                            ? cfg->rpc_port : ZCLASSICD_RPC_DEFAULT_PORT;
    g_oracle.cadence_secs = (cfg && cfg->cadence_secs > 0)
                            ? cfg->cadence_secs : ORACLE_DEFAULT_CADENCE;
    g_oracle.heights_per_tick = (cfg && cfg->heights_per_tick > 0)
                            ? cfg->heights_per_tick : ORACLE_DEFAULT_HEIGHTS_TICK;

    /* Credentials: caller-provided beats zclassic.conf. */
    if (cfg && cfg->rpc_user && cfg->rpc_user[0]) {
        snprintf(g_oracle.rpc_user, sizeof(g_oracle.rpc_user),
                 "%s", cfg->rpc_user);
    }
    if (cfg && cfg->rpc_password && cfg->rpc_password[0]) {
        snprintf(g_oracle.rpc_password, sizeof(g_oracle.rpc_password),
                 "%s", cfg->rpc_password);
    }

    /* Fill any missing credential from zclassic.conf; an explicit port
     * (cfg->rpc_port > 0) is never overridden. */
    if (!legacy_rpc_fill_missing_creds(
            g_oracle.rpc_user, sizeof(g_oracle.rpc_user),
            g_oracle.rpc_password, sizeof(g_oracle.rpc_password),
            &g_oracle.rpc_port, cfg && cfg->rpc_port > 0)) {
        pthread_mutex_unlock(&g_oracle.lock);
        return ZCL_ERR(-1,
            "zclassicd_oracle_init: no RPC credentials: pass via config or ~/.zclassic/zclassic.conf");
    }

    g_oracle.initialized = true;
    pthread_mutex_unlock(&g_oracle.lock);

    /* T2.1: ensure the policy module is ready before any disagreement
     * can be recorded. Idempotent — safe even if init runs multiple
     * times. */
    oracle_policy_init(NULL);
    return ZCL_OK;
}

struct zcl_result zclassicd_oracle_start(void)
{
    if (!g_oracle.initialized) {
        struct zcl_result init_r = zclassicd_oracle_init(NULL);
        if (!init_r.ok)
            return ZCL_ERR(-1, "zclassicd_oracle_start: init failed: %s",
                           init_r.message);
    }

    if (!supervisor_start())
        return ZCL_ERR(-2, "zclassicd_oracle_start: supervisor_start failed");

    pthread_mutex_lock(&g_oracle.lock);
    int cad = g_oracle.cadence_secs > 0
        ? g_oracle.cadence_secs : ORACLE_DEFAULT_CADENCE;
    pthread_mutex_unlock(&g_oracle.lock);

    supervisor_child_id id = atomic_load(&g_oracle.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_period(id, cad);
        supervisor_progress(id, zclassicd_oracle_progress_marker());
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_oracle_contract, "oracle.zclassicd");
    atomic_store(&g_oracle_contract.period_secs, cad);
    atomic_store(&g_oracle_contract.deadline_secs, 0);
    atomic_store(&g_oracle_contract.progress_max_quiet_us, 0);
    g_oracle_contract.on_tick = zclassicd_oracle_on_tick;
    g_oracle_contract.on_stall = zclassicd_oracle_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_oracle_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-3, "zclassicd_oracle_start: supervisor_register failed");

    atomic_store(&g_oracle.supervisor_id, id);
    supervisor_progress(id, zclassicd_oracle_progress_marker());
    supervisor_tick(id);
    return ZCL_OK;
}

void zclassicd_oracle_stop(void)
{
    supervisor_child_id id = atomic_load(&g_oracle.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID) return;
    supervisor_set_period(id, 0);
}

/* ── Stats snapshot ────────────────────────────────────────────── */

void zclassicd_oracle_stats_snapshot(struct zclassicd_oracle_stats *out)
{
    if (!out) return;
    out->attempts_total     = atomic_load(&g_oracle.attempts_total);
    out->probes_total       = atomic_load(&g_oracle.probes_total);
    out->probes_agree       = atomic_load(&g_oracle.probes_agree);
    out->probes_disagree    = atomic_load(&g_oracle.probes_disagree);
    out->rpc_errors         = atomic_load(&g_oracle.rpc_errors);
    out->last_probe_unix_us = atomic_load(&g_oracle.last_probe_unix_us);
    out->last_probed_height = atomic_load(&g_oracle.last_probed_height);
    out->last_attempt_unix_us =
        atomic_load(&g_oracle.last_attempt_unix_us);
    out->last_attempt_height =
        atomic_load(&g_oracle.last_attempt_height);
    out->last_error_unix_us = atomic_load(&g_oracle.last_error_unix_us);
    out->last_error_height  = atomic_load(&g_oracle.last_error_height);
    out->last_error_code    = atomic_load(&g_oracle.last_error_code);
    out->rpc_transport_reachable =
        atomic_load(&g_oracle.rpc_transport_reachable) != 0;
    out->oracle_usable      = atomic_load(&g_oracle.oracle_usable) != 0;
    out->reachable          = out->oracle_usable;
    pthread_mutex_lock(&g_oracle.lock);
    snprintf(out->last_error, sizeof(out->last_error), "%s",
             g_oracle.last_error);
    pthread_mutex_unlock(&g_oracle.lock);
}

void zclassicd_oracle_reset_for_test(void)
{
    supervisor_child_id id = atomic_load(&g_oracle.supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_period(id, 0);
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_oracle.supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif

    pthread_mutex_lock(&g_oracle.lock);
    g_oracle.initialized = false;
    g_oracle.rpc_host[0] = '\0';
    g_oracle.rpc_port = 0;
    g_oracle.rpc_user[0] = '\0';
    g_oracle.rpc_password[0] = '\0';
    g_oracle.cadence_secs = 0;
    g_oracle.heights_per_tick = 0;
    atomic_store(&g_oracle.attempts_total, 0);
    atomic_store(&g_oracle.probes_total, 0);
    atomic_store(&g_oracle.probes_agree, 0);
    atomic_store(&g_oracle.probes_disagree, 0);
    atomic_store(&g_oracle.rpc_errors, 0);
    atomic_store(&g_oracle.last_probe_unix_us, 0);
    atomic_store(&g_oracle.last_probed_height, 0);
    atomic_store(&g_oracle.last_attempt_unix_us, 0);
    atomic_store(&g_oracle.last_attempt_height, 0);
    atomic_store(&g_oracle.last_error_unix_us, 0);
    atomic_store(&g_oracle.last_error_height, 0);
    atomic_store(&g_oracle.last_error_code, 0);
    atomic_store(&g_oracle.rpc_transport_reachable, 0);
    atomic_store(&g_oracle.oracle_usable, 0);
    atomic_store(&g_oracle.reachable, 0);
    g_oracle.last_error[0] = '\0';
    pthread_mutex_unlock(&g_oracle.lock);
}

/* ── State dump (see CLAUDE.md "Adding state introspection") ───── */

bool zclassicd_oracle_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    struct zclassicd_oracle_stats s;
    zclassicd_oracle_stats_snapshot(&s);

    pthread_mutex_lock(&g_oracle.lock);
    supervisor_child_id sid = atomic_load(&g_oracle.supervisor_id);
    bool running = sid != SUPERVISOR_INVALID_ID &&
                   atomic_load(&g_oracle_contract.period_secs) > 0;
    int cad        = g_oracle.cadence_secs;
    int hpt        = g_oracle.heights_per_tick;
    int port       = g_oracle.rpc_port;
    char host[64];
    snprintf(host, sizeof(host), "%s", g_oracle.rpc_host);
    bool have_user = g_oracle.rpc_user[0] != '\0';
    bool have_pass = g_oracle.rpc_password[0] != '\0';
    bool initialized = g_oracle.initialized;
    pthread_mutex_unlock(&g_oracle.lock);

    json_push_kv_bool(out, "running",         running);
    json_push_kv_bool(out, "initialized",     initialized);
    json_push_kv_str (out, "rpc_host",        host);
    json_push_kv_int (out, "rpc_port",        port);
    json_push_kv_bool(out, "have_user",       have_user);
    json_push_kv_bool(out, "have_password",   have_pass);
    json_push_kv_int (out, "cadence_secs",    cad);
    json_push_kv_int (out, "heights_per_tick",hpt);
    json_push_kv_int (out, "attempts_total",  s.attempts_total);
    json_push_kv_int (out, "probes_total",    s.probes_total);
    json_push_kv_int (out, "probes_agree",    s.probes_agree);
    json_push_kv_int (out, "probes_disagree", s.probes_disagree);
    json_push_kv_int (out, "rpc_errors",      s.rpc_errors);
    json_push_kv_bool(out, "rpc_transport_reachable",
                      s.rpc_transport_reachable);
    json_push_kv_bool(out, "oracle_usable",   s.oracle_usable);
    json_push_kv_bool(out, "reachable",       s.reachable);
    json_push_kv_str (out, "last_error",      s.last_error);
    json_push_kv_int (out, "last_error_code", s.last_error_code);
    json_push_kv_int (out, "last_error_unix_us", s.last_error_unix_us);
    json_push_kv_int (out, "last_error_height", s.last_error_height);
    json_push_kv_int (out, "last_attempt_unix_us",
                      s.last_attempt_unix_us);
    json_push_kv_int (out, "last_attempt_height", s.last_attempt_height);
    json_push_kv_int (out, "last_probe_unix_us", s.last_probe_unix_us);
    json_push_kv_int (out, "last_probed_height", s.last_probed_height);
    return true;
}
