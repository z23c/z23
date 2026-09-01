/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: Peer
 *
 * validates :ip, presence: true
 * validates :port, not_zero: true
 * validates :attempts, range: [0, 10000]
 *
 * after_save -> emit EV_MODEL_SAVED */

#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "models/peer.h"
#include "models/query_builder.h"
#include "event/event.h"
#include "net/port_policy.h"
#include "storage/peers_projection.h"
#include "util/ar_step_readonly.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* The projection every read in this file uses, in row_to_peer() order. */
static const enum qb_column k_peer_cols[] = {
    QB_C_peers_id,        QB_C_peers_ip,              QB_C_peers_port,
    QB_C_peers_services,  QB_C_peers_last_seen,       QB_C_peers_last_try,
    QB_C_peers_attempts,  QB_C_peers_source,          QB_C_peers_bandwidth_score,
    QB_C_peers_is_zcl23,
};
#define K_PEER_NCOLS (sizeof(k_peer_cols) / sizeof(k_peer_cols[0]))

#define DB_PEER_SAVE_MAX_ATTEMPTS 1200
#define DB_PEER_SAVE_RETRY_MS 25
#define DB_PEER_SAVE_ADVISORY_MAX_ATTEMPTS 4

/* ── Callbacks ─────────────────────────────────────────────────── */

DEFINE_MODEL_CALLBACKS(peer)

static bool peer_before_validate(void *record, void *ctx)
{
    struct db_peer *peer = record;
    static const uint8_t zero_ip[16] = {0};

    (void)ctx;
    if (!peer)
        return false;
    if (peer->last_seen == 0)
        peer->last_seen = (int64_t)platform_time_wall_time_t();
    if (peer->last_try < 0)
        peer->last_try = 0;
    if (peer->attempts < 0)
        peer->attempts = 0;
    if (!peer->has_source)
        memcpy(peer->source, zero_ip, sizeof(peer->source));
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(peer, peer_before_validate)

/* ── Validation ────────────────────────────────────────────────── */

bool db_peer_validate(const struct db_peer *p, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_presence_of(errors, p, ip);
    validates_not_zero(errors, p, port);
    validates_non_negative(errors, p, last_seen);
    validates_non_negative(errors, p, last_try);
    validates_non_negative(errors, p, attempts);
    validates_max(errors, p, attempts, 10000);
    validates_max(errors, p, bandwidth_score, 255);
    if (p->has_source) {
        static const uint8_t z[16] = {0};
        validates_custom(errors,
            memcmp(p->source, z, 16) != 0,
            "source", "can't be blank when has_source");
    }
    return !ar_errors_any(errors);
}

/* ── Row Deserialization ──────────────────────────────────────── */

static void row_to_peer(sqlite3_stmt *s, struct db_peer *out, int off)
{
    out->id = AR_COL_INT(s, off);
    AR_READ_BLOB(s, off + 1, out->ip, 16);
    out->port = (uint16_t)AR_COL_INT(s, off + 2);
    out->services = (uint64_t)AR_COL_INT(s, off + 3);
    out->last_seen = AR_COL_INT(s, off + 4);
    out->last_try = AR_COL_INT(s, off + 5);
    out->attempts = (int)AR_COL_INT(s, off + 6);
    const void *src = sqlite3_column_blob(s, off + 7);
    if (src && sqlite3_column_bytes(s, off + 7) >= 16) {
        memcpy(out->source, src, 16);
        out->has_source = true;
    }
    out->bandwidth_score = (uint32_t)AR_COL_INT(s, off + 8);
    out->is_zcl23 = AR_COL_INT(s, off + 9) != 0;
}

/* ── Save (cached stmt) ──────────────────────────────────────── */

static bool db_peer_save_with_attempts(struct node_db *ndb,
                                       const struct db_peer *p,
                                       int max_attempts,
                                       const char *op_name,
                                       bool health_error)
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = peer_callbacks_ready();
    AR_BEGIN_SAVE(cbs, "peer", p, db_peer_validate);

    sqlite3_stmt *s = ndb->stmt_peer_save;
    bool locked_stmt = false;
    char err_msg[128] = {0};
    if (ndb->state_mutex_init) {
        zcl_mutex_lock(&ndb->state_mutex);
        locked_stmt = true;
    }

    int rc = SQLITE_OK;
    int attempts = 0;
    for (; attempts < max_attempts; attempts++) {
        AR_RESET(s);
        sqlite3_clear_bindings(s);
        AR_BIND_BLOB(s, 1, p->ip, 16);
        AR_BIND_INT(s, 2, p->port);
        AR_BIND_INT(s, 3, (int64_t)p->services);
        AR_BIND_INT(s, 4, p->last_seen);
        AR_BIND_INT(s, 5, p->last_try);
        AR_BIND_INT(s, 6, p->attempts);
        if (p->has_source)
            AR_BIND_BLOB(s, 7, p->source, 16);
        else
            AR_BIND_NULL(s, 7);
        AR_BIND_INT(s, 8, p->bandwidth_score);
        AR_BIND_INT(s, 9, p->is_zcl23 ? 1 : 0);

        rc = AR_STEP_ROW_READONLY(s);
        if (rc == SQLITE_DONE)
            break;
        sqlite3_reset(s);
        if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED)
            break;
        sqlite3_sleep(DB_PEER_SAVE_RETRY_MS);
    }
    if (rc != SQLITE_DONE) {
        const char *msg = sqlite3_errmsg(ndb->db);
        if (!msg || strcmp(msg, "not an error") == 0)
            msg = sqlite3_errstr(rc);
        snprintf(err_msg, sizeof(err_msg), "%s", msg ? msg : "unknown");
    }
    AR_RESET(s);
    ndb->last_sqlite_rc = rc;
    snprintf(ndb->last_op, sizeof(ndb->last_op), "%s", "db_peer_save");
    if (locked_stmt)
        zcl_mutex_unlock(&ndb->state_mutex);

    bool ok = rc == SQLITE_DONE;
    if (!ok) {
        if (health_error) {
            LOG_WARN("net", "peer %s failed: rc=%d msg=%s attempts=%d", op_name, rc, err_msg, attempts);
        } else {
            fprintf(stderr, "peer %s skipped: rc=%d msg=%s attempts=%d\n",
                    op_name, rc, err_msg, attempts);
        }
        if (health_error) {
            event_emitf(EV_DB_ERROR, 0,
                        "model=peer op=%s rc=%d attempts=%d msg=%s",
                        op_name, rc, attempts, err_msg);
        }
    }
    AR_FINISH_SAVE(cbs, p, ok);
}

bool db_peer_save(struct node_db *ndb, const struct db_peer *p)
{
    bool ok = db_peer_save_with_attempts(ndb, p, DB_PEER_SAVE_MAX_ATTEMPTS,
                                         "save", true);
    if (ok && peers_projection_event_log() &&
        !peers_projection_emit_observed(p->ip, p->port, p->services,
                                        p->last_seen, -1)) {
        LOG_WARN("net", "peer projection emit failed for save");
    }
    return ok;
}

bool db_peer_save_advisory(struct node_db *ndb, const struct db_peer *p)
{
    bool ok = db_peer_save_with_attempts(ndb, p,
                                         DB_PEER_SAVE_ADVISORY_MAX_ATTEMPTS,
                                         "save_advisory", false);
    if (ok && peers_projection_event_log() &&
        !peers_projection_emit_observed(p->ip, p->port, p->services,
                                        p->last_seen, -1)) {
        LOG_WARN("net", "peer projection emit failed for advisory save");
    }
    return ok;
}

/* ── Find (cached stmt) ──────────────────────────────────────── */

bool db_peer_find_by_addr(struct node_db *ndb,
                          const uint8_t ip[16], uint16_t port,
                          struct db_peer *out)
{
    if (!ndb->open) return false;

    sqlite3_stmt *s = ndb->stmt_peer_find;
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, ip, 16);
    AR_BIND_INT(s, 2, port);
    AR_FIND_ONE_CACHED(s, out, row_to_peer(s, out, 0));
}

/* ── Delete (cached stmt) ────────────────────────────────────── */

bool db_peer_delete(struct node_db *ndb, const uint8_t ip[16], uint16_t port)
{
    if (!ndb->open) return false;

    struct ar_callbacks *cbs = db_peer_callbacks();
    struct db_peer p;
    memset(&p, 0, sizeof(p));
    memcpy(p.ip, ip, 16);
    p.port = port;
    sqlite3_stmt *s = ndb->stmt_peer_delete;
    if (!ar_run_before_destroy(cbs, &p)) {
        LOG_WARN("net", "peer delete: before_destroy hook rejected port=%u", port);
        return false;
    }
    AR_RESET(s);
    AR_BIND_BLOB(s, 1, ip, 16);
    AR_BIND_INT(s, 2, port);
    bool ok = AR_STEP_DONE(s);
    if (ok)
        ar_run_after_destroy(cbs, &p);
    if (ok && peers_projection_event_log() &&
        !peers_projection_emit_dropped(ip, port, 1)) {
        LOG_WARN("net", "peer projection emit failed for delete");
    }
    return ok;
}

/* ── Count (cached stmt) ─────────────────────────────────────── */

int db_peer_count(struct node_db *ndb)
{
    if (!ndb->open) return 0;
    AR_CACHED_COUNT(ndb->stmt_peer_count);
}

/* ── Recent (ad-hoc query — not on hot path) ─────────────────── */

int db_peer_recent(struct node_db *ndb, struct db_peer *out, size_t max)
{
    if (!ndb->open) return 0;
    struct qb q;
    qb_select(&q, QB_T_peers);
    qb_select_columns(&q, k_peer_cols, K_PEER_NCOLS);
    qb_order_by(&q, QB_C_peers_last_seen, QB_DESC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max, row_to_peer(s, &out[count], 0));
}

/* ── Mark Tried ───────────────────────────────────────────────── */

/* NOTE (found by the query-builder conversion): the literal this replaced
 * read `strftime('%%s','now')`. Nothing printf-formats a model SQL string —
 * it goes straight to sqlite3_prepare_v2 — and in SQLite `%%` is an escaped
 * percent, so that expression evaluated to the TEXT "%s" and every
 * mark_tried since had been storing the two characters `%s` in last_try
 * instead of the epoch. Every other strftime site in app/models uses a
 * single `%s`. qb_set_unix_now() emits the correct form. */
bool db_peer_mark_tried(struct node_db *ndb,
                        const uint8_t ip[16], uint16_t port)
{
    if (!ndb->open) return false;
    struct qb q;
    qb_update(&q, QB_T_peers);
    qb_set_unix_now(&q, QB_C_peers_last_try);
    qb_set_increment(&q, QB_C_peers_attempts, 1);
    qb_where_blob(&q, QB_C_peers_ip, QB_EQ, ip, 16);
    qb_where_int(&q, QB_C_peers_port, QB_EQ, port);
    QB_EXEC_BOOL(ndb, &q, s);
}

/* ── Mark Seen ────────────────────────────────────────────────── */

bool db_peer_mark_seen(struct node_db *ndb,
                       const uint8_t ip[16], uint16_t port,
                       int64_t now)
{
    if (!ndb->open) return false;
    struct qb q;
    qb_update(&q, QB_T_peers);
    qb_set_int(&q, QB_C_peers_last_seen, now);
    qb_set_int(&q, QB_C_peers_attempts, 0);
    qb_where_blob(&q, QB_C_peers_ip, QB_EQ, ip, 16);
    qb_where_int(&q, QB_C_peers_port, QB_EQ, port);
    QB_EXEC_BOOL(ndb, &q, s);
}

/* ── Update Score ─────────────────────────────────────────────── */

bool db_peer_update_score(struct node_db *ndb,
                          const uint8_t ip[16], uint16_t port,
                          uint32_t bandwidth_score, bool is_zcl23)
{
    if (!ndb->open) return false;
    struct qb q;
    qb_update(&q, QB_T_peers);
    qb_set_int(&q, QB_C_peers_bandwidth_score, (int64_t)bandwidth_score);
    qb_set_int(&q, QB_C_peers_is_zcl23, is_zcl23 ? 1 : 0);
    qb_where_blob(&q, QB_C_peers_ip, QB_EQ, ip, 16);
    qb_where_int(&q, QB_C_peers_port, QB_EQ, port);
    QB_EXEC_BOOL(ndb, &q, s);
}

/* ── Fast ZCL23 Peers ─────────────────────────────────────────── */

/* The reachable-port set used to exist twice: as the C switch in
 * core/modules/net/include/net/port_policy.h and, for this one query, as a second
 * hand-maintained comma list in ZCL_NET_REACHABLE_PORTS_SQL. Two copies of
 * a policy that must agree is one copy too many, so this derives the list
 * from the switch — the authority every dialer already consults — and binds
 * each port as a parameter. */
#define PEER_REACHABLE_PORTS_MAX 256

static size_t peer_reachable_ports(int64_t *out, size_t max)
{
    size_t n = 0;
    for (uint32_t p = 1; p <= UINT16_MAX; p++) {
        if (!zcl_net_port_is_reachable_candidate((uint16_t)p))
            continue;
        if (n >= max)
            return 0;   /* policy outgrew the buffer: refuse, never truncate */
        out[n++] = (int64_t)p;
    }
    return n;
}

int db_peer_fast_zcl23(struct node_db *ndb, struct db_peer *out, size_t max)
{
    if (!ndb->open) return 0;

    int64_t ports[PEER_REACHABLE_PORTS_MAX];
    size_t nports = peer_reachable_ports(ports, PEER_REACHABLE_PORTS_MAX);
    if (nports == 0)
        LOG_RETURN(0, "peer", "no reachable candidate ports in port policy");

    struct qb q;
    qb_select(&q, QB_T_peers);
    qb_select_columns(&q, k_peer_cols, K_PEER_NCOLS);
    qb_where_int(&q, QB_C_peers_is_zcl23, QB_EQ, 1);
    qb_where_in_int(&q, QB_C_peers_port, ports, nports);
    qb_order_by(&q, QB_C_peers_bandwidth_score, QB_DESC);
    qb_order_by(&q, QB_C_peers_last_seen, QB_DESC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max, row_to_peer(s, &out[count], 0));
}
