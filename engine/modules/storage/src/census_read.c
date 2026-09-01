/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * census_read — read-only reader over the network census + topology stores.
 * See storage/census_read.h for the contract and the REAL writer schemas this
 * reader is designed to. There are two stores: peers_projection.db (node_census,
 * census_observations — keyed on a 16-byte ip BLOB) and topology.db
 * (topology_edges, topology_sweeps — rendered TEXT ip columns). The reader opens
 * peers_projection.db read-only as the primary connection, registers an
 * `ip_to_str()` SQL function that renders the 16-byte blob to the same dotted /
 * colon TEXT form topology_edges stores, and ATTACHes topology.db read-only so
 * the two stores can be related in one query.
 *
 * Every path is bounded and fails closed / degrades gracefully: a missing
 * primary file or missing node_census table is CENSUS_READ_DB_ABSENT /
 * CENSUS_READ_TABLES_ABSENT; a missing topology.db just zeroes the graph/edge
 * surfaces — never a hard error or a crash. Reads use AR_STEP_ROW_READONLY (the
 * lint-exempt single-shot read step); the module never issues consensus DML.
 */

#include "storage/census_read.h"

#include "net/netaddr.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CENSUS_SUBSYS "census_read"

struct census_reader {
    sqlite3 *db;                /* peers_projection.db (main) + topology.db as `topo` */
    bool node_census_present;
    bool observations_present;
    bool topology_present;
    bool sweeps_present;
};

/* ── ip rendering ────────────────────────────────────────────────────── */

/* Render a 16-byte ip blob exactly as topology_store renders a non-onion
 * net_addr (net_addr_to_string), so census endpoints and topology edges relate
 * byte-for-byte. */
static void render_ip16(const unsigned char ip[16], char *out, size_t cap)
{
    struct net_addr a;
    net_addr_init(&a);
    memcpy(a.ip, ip, 16);
    a.has_torv3 = false;
    net_addr_to_string(&a, out, cap);
}

/* SQL function ip_to_str(blob) -> text. A 16-byte blob renders to the dotted /
 * colon form; anything else yields '' so it can never match a real endpoint. */
static void ip_to_str_udf(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 1 || sqlite3_value_type(argv[0]) != SQLITE_BLOB ||
        sqlite3_value_bytes(argv[0]) != 16) {
        sqlite3_result_text(ctx, "", 0, SQLITE_STATIC);
        return;
    }
    const unsigned char *blob = sqlite3_value_blob(argv[0]);
    char rendered[CENSUS_IP_MAX];
    render_ip16(blob, rendered, sizeof(rendered));
    sqlite3_result_text(ctx, rendered, -1, SQLITE_TRANSIENT);
}

/* ── path resolution ─────────────────────────────────────────────────── */

static void census_datadir(const char *datadir, char *out, size_t cap)
{
    if (datadir && datadir[0]) {
        snprintf(out, cap, "%s", datadir);
        return;
    }
    const char *home = getenv("HOME");
    snprintf(out, cap, "%s/.zclassic-c23", home && home[0] ? home : ".");
}

bool census_read_db_path(const char *datadir, char *out, size_t out_cap)
{
    if (!out || out_cap == 0)
        return false;
    char dir[512];
    census_datadir(datadir, dir, sizeof(dir));
    snprintf(out, out_cap, "%s/%s", dir, CENSUS_PEERS_DB_BASENAME);
    return true;
}

static bool census_topology_path(const char *datadir, char *out, size_t out_cap)
{
    if (!out || out_cap == 0)
        return false;
    char dir[512];
    census_datadir(datadir, dir, sizeof(dir));
    snprintf(out, out_cap, "%s/%s", dir, CENSUS_TOPOLOGY_DB_BASENAME);
    return true;
}

/* ── bounded string copy (pedantic read-surface bound) ───────────────── */

/* Copy a wire-fed text column into a fixed buffer, flagging over-length so a
 * caller never silently trusts a truncated value at full length. */
static void copy_bounded(const unsigned char *src, char *dst, size_t cap,
                         bool *truncated)
{
    if (truncated)
        *truncated = false;
    if (!dst || cap == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen((const char *)src);
    if (n >= cap) {
        n = cap - 1;
        if (truncated)
            *truncated = true;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ── table existence ─────────────────────────────────────────────────── */

/* `schema` is "" for the main DB or "topo" for the attached topology DB. */
static bool table_present(sqlite3 *db, const char *schema, const char *name)
{
    if (!db || !name)
        return false;
    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT 1 FROM %s%ssqlite_master WHERE type='table' AND name=?",
             schema && schema[0] ? schema : "",
             schema && schema[0] ? "." : "");
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, name, -1, SQLITE_TRANSIENT);
    bool present = AR_STEP_ROW_READONLY(s) == SQLITE_ROW;
    sqlite3_finalize(s);
    return present;
}

/* ── open / close ────────────────────────────────────────────────────── */

enum census_read_status census_read_open(const char *datadir,
                                         census_reader **out)
{
    if (out)
        *out = NULL;
    char path[600];
    if (!census_read_db_path(datadir, path, sizeof(path)))
        return CENSUS_READ_DB_ABSENT;

    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX |
                             SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK || !db) {
        /* Absent / unreadable census file — graceful, not an error. */
        if (db)
            sqlite3_close(db);
        return CENSUS_READ_DB_ABSENT;
    }
    sqlite3_busy_timeout(db, 250);

    /* Render helper for the 16-byte ip blobs, and cross-store matching. */
    (void)sqlite3_create_function(db, "ip_to_str", 1,
                                  SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                  ip_to_str_udf, NULL, NULL);

    if (!table_present(db, "", "node_census")) {
        sqlite3_close(db);
        return CENSUS_READ_TABLES_ABSENT;
    }

    census_reader *r = zcl_malloc(sizeof(*r), "census_reader");
    if (!r) {
        sqlite3_close(db);
        return CENSUS_READ_DB_ABSENT;
    }
    memset(r, 0, sizeof(*r));
    r->db = db;
    r->node_census_present = true;
    r->observations_present = table_present(db, "", "census_observations");

    /* ATTACH topology.db read-only (best-effort). A missing/unreadable file
     * just leaves the graph/edge surfaces empty. */
    char topo[600];
    if (census_topology_path(datadir, topo, sizeof(topo))) {
        char attach[900];
        snprintf(attach, sizeof(attach),
                 "ATTACH DATABASE 'file:%s?mode=ro' AS topo", topo);
        if (sqlite3_exec(db, attach, NULL, NULL, NULL) == SQLITE_OK) {
            r->topology_present = table_present(db, "topo", "topology_edges");
            r->sweeps_present = table_present(db, "topo", "topology_sweeps");
        }
    }

    if (out)
        *out = r;
    else
        census_read_close(r);
    return CENSUS_READ_OK;
}

void census_read_close(census_reader *r)
{
    if (!r)
        return;
    if (r->db)
        sqlite3_close(r->db);
    free(r);
}

/* ── counts ──────────────────────────────────────────────────────────── */

/* `table` may be schema-qualified (e.g. "topo.topology_edges"). */
static int64_t count_rows(sqlite3 *db, const char *table)
{
    if (!db || !table)
        return 0;
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK)
        return 0;
    int64_t n = 0;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

int64_t census_read_node_total(census_reader *r)
{
    if (!r || !r->db)
        return 0;
    return count_rows(r->db, "node_census");
}

/* ── list ────────────────────────────────────────────────────────────── */

/* Append the filter WHERE clause (fixed condition order: ua, min_height,
 * seen_within). Bind order in bind_filter() MUST match this order. Columns are
 * the REAL node_census columns. */
static void append_where(const struct census_filter *f, char *buf, size_t cap)
{
    buf[0] = '\0';
    if (!f)
        return;
    size_t off = 0;
    bool first = true;
    #define WCOND(cond, sql) do { \
        if (cond) { \
            int _n = snprintf(buf + off, cap - off, "%s%s", \
                              first ? " WHERE " : " AND ", (sql)); \
            if (_n > 0 && (size_t)_n < cap - off) off += (size_t)_n; \
            first = false; \
        } \
    } while (0)
    WCOND(f->ua_contains && f->ua_contains[0], "user_agent LIKE ?");
    WCOND(f->min_height >= 0, "last_reported_height >= ?");
    WCOND(f->seen_within_secs >= 0, "last_seen >= ?");
    #undef WCOND
}

static void bind_filter(sqlite3_stmt *s, const struct census_filter *f,
                        int *idx)
{
    if (!f)
        return;
    if (f->ua_contains && f->ua_contains[0]) {
        char like[CENSUS_UA_MAX + 4];
        char clipped[CENSUS_UA_MAX];
        snprintf(clipped, sizeof(clipped), "%s", f->ua_contains);
        snprintf(like, sizeof(like), "%%%s%%", clipped);
        sqlite3_bind_text(s, (*idx)++, like, -1, SQLITE_TRANSIENT);
    }
    if (f->min_height >= 0)
        sqlite3_bind_int64(s, (*idx)++, f->min_height);
    if (f->seen_within_secs >= 0) {
        int64_t cutoff = f->now_unix - f->seen_within_secs;
        if (cutoff < 0)
            cutoff = 0;
        sqlite3_bind_int64(s, (*idx)++, cutoff);
    }
}

static int64_t list_matched_total(census_reader *r,
                                  const struct census_filter *f)
{
    char where[256];
    append_where(f, where, sizeof(where));
    char sql[384];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM node_census%s", where);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(r->db, sql, -1, &s, NULL) != SQLITE_OK)
        return 0;
    int idx = 1;
    bind_filter(s, f, &idx);
    int64_t n = 0;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* Column order for a node_census row read (matches CENSUS_NODE_SELECT). */
static void read_node_row(sqlite3_stmt *s, struct census_node *n)
{
    memset(n, 0, sizeof(*n));
    copy_bounded(sqlite3_column_text(s, 0), n->ip, sizeof(n->ip), NULL);
    n->port = sqlite3_column_int(s, 1);
    copy_bounded(sqlite3_column_text(s, 2), n->user_agent,
                 sizeof(n->user_agent), &n->ua_truncated);
    n->ua_overflow = sqlite3_column_int(s, 3) != 0;
    n->protocol_version = sqlite3_column_int64(s, 4);
    n->services = sqlite3_column_int64(s, 5);
    n->reported_height = sqlite3_column_int64(s, 6);
    n->first_seen = sqlite3_column_int64(s, 7);
    n->last_seen = sqlite3_column_int64(s, 8);
    n->last_success = sqlite3_column_int64(s, 9);
    n->dial_success_count = sqlite3_column_int64(s, 10);
    n->dial_fail_count = sqlite3_column_int64(s, 11);
    n->reachable = n->dial_success_count > 0;
}

/* ip_to_str(ip) renders the 16-byte blob to the display TEXT form. */
#define CENSUS_NODE_SELECT \
    "ip_to_str(ip),port,user_agent,ua_overflow,protocol_version,services," \
    "last_reported_height,first_seen,last_seen,last_success," \
    "dial_success_count,dial_fail_count"

int census_read_list(census_reader *r, const struct census_filter *filter,
                     int64_t offset, int limit,
                     struct census_node *rows, int cap, int64_t *matched_total)
{
    if (matched_total)
        *matched_total = 0;
    if (!r || !r->db || !rows || cap <= 0)
        return 0;
    if (offset < 0)
        offset = 0;
    int want = limit;
    if (want <= 0)
        want = CENSUS_LIST_DEFAULT_LIMIT;
    if (want > cap)
        want = cap;
    if (want > CENSUS_LIST_HARD_CAP)
        want = CENSUS_LIST_HARD_CAP;

    if (matched_total)
        *matched_total = list_matched_total(r, filter);

    char where[256];
    append_where(filter, where, sizeof(where));
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT " CENSUS_NODE_SELECT " FROM node_census%s"
             " ORDER BY last_seen DESC, ip ASC, port ASC LIMIT ? OFFSET ?",
             where);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(r->db, sql, -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(CENSUS_SUBSYS, "list prepare failed: %s",
                 sqlite3_errmsg(r->db));
        return 0;
    }
    int idx = 1;
    bind_filter(s, filter, &idx);
    sqlite3_bind_int(s, idx++, want);
    sqlite3_bind_int64(s, idx++, offset);

    int count = 0;
    while (count < want && AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        read_node_row(s, &rows[count++]);
    sqlite3_finalize(s);
    return count;
}

/* ── one node ────────────────────────────────────────────────────────── */

bool census_read_node(census_reader *r, const char *ip, int port,
                      struct census_node *node,
                      struct census_observation *obs, int obs_cap, int *obs_n,
                      struct census_edge *edges, int edge_cap, int *edge_n)
{
    if (obs_n)
        *obs_n = 0;
    if (edge_n)
        *edge_n = 0;
    if (!r || !r->db || !ip || !node)
        return false;

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(r->db,
            "SELECT " CENSUS_NODE_SELECT
            " FROM node_census WHERE ip_to_str(ip)=? AND port=?",
            -1, &s, NULL) != SQLITE_OK)
        LOG_FAIL(CENSUS_SUBSYS, "node prepare failed: %s",
                 sqlite3_errmsg(r->db));
    sqlite3_bind_text(s, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, port);
    bool found = AR_STEP_ROW_READONLY(s) == SQLITE_ROW;
    if (found)
        read_node_row(s, node);
    sqlite3_finalize(s);
    if (!found)
        return false;

    /* Bounded observation history (newest first). Census observations key on
     * the same 16-byte ip blob; match via ip_to_str(). */
    if (obs && obs_cap > 0 && obs_n && r->observations_present) {
        int lim = obs_cap > CENSUS_MAX_OBSERVATIONS ? CENSUS_MAX_OBSERVATIONS
                                                    : obs_cap;
        if (sqlite3_prepare_v2(r->db,
                "SELECT observed_unix,reported_height,protocol_version,services,"
                "user_agent,ua_overflow FROM census_observations"
                " WHERE ip_to_str(ip)=? AND port=?"
                " ORDER BY observed_unix DESC LIMIT ?",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_text(s, 1, node->ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(s, 2, port);
            sqlite3_bind_int(s, 3, lim);
            int k = 0;
            while (k < lim && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                struct census_observation *o = &obs[k];
                memset(o, 0, sizeof(*o));
                o->observed_unix = sqlite3_column_int64(s, 0);
                o->reported_height = sqlite3_column_int64(s, 1);
                o->protocol_version = sqlite3_column_int64(s, 2);
                o->services = sqlite3_column_int64(s, 3);
                copy_bounded(sqlite3_column_text(s, 4), o->user_agent,
                             sizeof(o->user_agent), &o->ua_truncated);
                o->ua_overflow = sqlite3_column_int(s, 5) != 0;
                k++;
            }
            sqlite3_finalize(s);
            *obs_n = k;
        }
    }

    /* Bounded edges referencing this endpoint (as observer or advertised).
     * topology_edges keeps ip and port as separate TEXT/INT columns. */
    if (edges && edge_cap > 0 && edge_n && r->topology_present) {
        int lim = edge_cap > CENSUS_MAX_EDGES ? CENSUS_MAX_EDGES : edge_cap;
        if (sqlite3_prepare_v2(r->db,
                "SELECT observer_ip,observer_port,advertised_ip,advertised_port,"
                "times_seen,last_advertised FROM topo.topology_edges"
                " WHERE (observer_ip=? AND observer_port=?)"
                " OR (advertised_ip=? AND advertised_port=?)"
                " ORDER BY times_seen DESC, last_advertised DESC LIMIT ?",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_text(s, 1, node->ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(s, 2, port);
            sqlite3_bind_text(s, 3, node->ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(s, 4, port);
            sqlite3_bind_int(s, 5, lim);
            int k = 0;
            while (k < lim && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                struct census_edge *e = &edges[k];
                memset(e, 0, sizeof(*e));
                const char *oip = (const char *)sqlite3_column_text(s, 0);
                int oport = sqlite3_column_int(s, 1);
                const char *aip = (const char *)sqlite3_column_text(s, 2);
                int aport = sqlite3_column_int(s, 3);
                snprintf(e->observer, sizeof(e->observer), "%s:%d",
                         oip ? oip : "", oport);
                snprintf(e->advertised, sizeof(e->advertised), "%s:%d",
                         aip ? aip : "", aport);
                e->times_seen = sqlite3_column_int64(s, 4);
                e->last_advertised = sqlite3_column_int64(s, 5);
                k++;
            }
            sqlite3_finalize(s);
            *edge_n = k;
        }
    }
    return true;
}

/* ── versions ────────────────────────────────────────────────────────── */

int census_read_versions(census_reader *r,
                         struct census_version_bucket *buckets, int cap)
{
    if (!r || !r->db || !buckets || cap <= 0)
        return 0;
    if (cap > CENSUS_MAX_VERSION_BUCKETS)
        cap = CENSUS_MAX_VERSION_BUCKETS;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(r->db,
            "SELECT COALESCE(NULLIF(user_agent,''),'(unknown)') AS ua,"
            " COUNT(*) c, MAX(last_reported_height) mh FROM node_census"
            " GROUP BY ua ORDER BY c DESC, ua ASC LIMIT ?",
            -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(CENSUS_SUBSYS, "versions prepare failed: %s",
                 sqlite3_errmsg(r->db));
        return 0;
    }
    sqlite3_bind_int(s, 1, cap);
    int k = 0;
    while (k < cap && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        struct census_version_bucket *b = &buckets[k];
        memset(b, 0, sizeof(*b));
        copy_bounded(sqlite3_column_text(s, 0), b->user_agent,
                     sizeof(b->user_agent), &b->ua_truncated);
        b->count = sqlite3_column_int64(s, 1);
        b->max_reported_height = sqlite3_column_int64(s, 2);
        k++;
    }
    sqlite3_finalize(s);
    return k;
}

/* ── graph ───────────────────────────────────────────────────────────── */

bool census_read_graph(census_reader *r, struct census_graph_stats *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!r || !r->db)
        return false;

    out->node_count = count_rows(r->db, "node_census");
    out->edge_count = r->topology_present
                          ? count_rows(r->db, "topo.topology_edges") : 0;
    out->observation_count =
        r->observations_present ? count_rows(r->db, "census_observations") : 0;

    if (r->sweeps_present) {
        out->sweeps_total = count_rows(r->db, "topo.topology_sweeps");
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(r->db,
                "SELECT COALESCE(MAX(finished_unix),0) FROM topo.topology_sweeps",
                -1, &s, NULL) == SQLITE_OK) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                out->last_sweep_finished_unix = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
        }
    }

    if (r->topology_present) {
        /* DISTINCT advertised endpoints that are themselves in the census.
         * node_census keys on a blob; ip_to_str() bridges to the TEXT form. */
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(r->db,
                "SELECT COUNT(*) FROM (SELECT DISTINCT advertised_ip,"
                "advertised_port FROM topo.topology_edges) t WHERE EXISTS("
                "SELECT 1 FROM node_census n WHERE ip_to_str(n.ip)=t.advertised_ip"
                " AND n.port=t.advertised_port)",
                -1, &s, NULL) == SQLITE_OK) {
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                out->advertised_in_census = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
        }

        if (sqlite3_prepare_v2(r->db,
                "SELECT advertised_ip,advertised_port,SUM(times_seen) ts,"
                " COUNT(*) obs FROM topo.topology_edges"
                " GROUP BY advertised_ip,advertised_port"
                " ORDER BY ts DESC, advertised_ip ASC, advertised_port ASC"
                " LIMIT ?",
                -1, &s, NULL) == SQLITE_OK) {
            sqlite3_bind_int(s, 1, CENSUS_MAX_TOP_ADVERTISED);
            int k = 0;
            while (k < CENSUS_MAX_TOP_ADVERTISED &&
                   AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                struct census_top_advertised *t = &out->top[k];
                memset(t, 0, sizeof(*t));
                const char *aip = (const char *)sqlite3_column_text(s, 0);
                int aport = sqlite3_column_int(s, 1);
                snprintf(t->advertised, sizeof(t->advertised), "%s:%d",
                         aip ? aip : "", aport);
                t->times_seen = sqlite3_column_int64(s, 2);
                t->distinct_observers = sqlite3_column_int64(s, 3);
                k++;
            }
            sqlite3_finalize(s);
            out->top_count = k;
        }
    }
    return true;
}

/* ── test fixture helpers ────────────────────────────────────────────── */

#ifdef ZCL_TESTING
/* Parse a display ip string (dotted IPv4, or the 8-group hex IPv6 form
 * net_addr_to_string emits) into the 16-byte blob node_census/census_observations
 * store. Returns false on a malformed address. */
static bool census_ip_to_blob(const char *ip, unsigned char out[16])
{
    if (!ip || !ip[0])
        return false;
    if (strchr(ip, ':')) {
        /* net_addr_to_string always emits exactly 8 colon-separated hex groups
         * (no "::" compression), so parse that exact form. */
        unsigned int g[8];
        int n = sscanf(ip, "%x:%x:%x:%x:%x:%x:%x:%x",
                       &g[0], &g[1], &g[2], &g[3], &g[4], &g[5], &g[6], &g[7]);
        if (n != 8)
            return false;
        for (int i = 0; i < 8; i++) {
            if (g[i] > 0xffff)
                return false;
            out[i * 2] = (unsigned char)(g[i] >> 8);
            out[i * 2 + 1] = (unsigned char)(g[i] & 0xff);
        }
        return true;
    }
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255)
        return false;
    memcpy(out, pchIPv4Prefix, 12);
    out[12] = (unsigned char)a;
    out[13] = (unsigned char)b;
    out[14] = (unsigned char)c;
    out[15] = (unsigned char)d;
    return true;
}

static sqlite3 *census_open_rw(const char *path)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK || !db) {
        if (db)
            sqlite3_close(db);
        return NULL;
    }
    return db;
}

static sqlite3 *census_open_peers_rw(const char *datadir)
{
    char path[600];
    if (!census_read_db_path(datadir, path, sizeof(path)))
        return NULL;
    return census_open_rw(path);
}

static sqlite3 *census_open_topo_rw(const char *datadir)
{
    char path[600];
    if (!census_topology_path(datadir, path, sizeof(path)))
        return NULL;
    return census_open_rw(path);
}

bool census_read_test_create_schema(const char *datadir)
{
    /* VERBATIM copy of the peers_projection.c ensure_schema() node_census /
     * census_observations CREATE TABLE text (peers_projection.c:192,210). Keep
     * in sync — the reader SELECTs these exact columns and drift fails the
     * schema-parity test in test_net_census.c. */
    static const char *PEERS_DDL =
        "CREATE TABLE IF NOT EXISTS node_census ("
        " ip BLOB NOT NULL,"
        " port INTEGER NOT NULL,"
        " user_agent TEXT,"
        " ua_overflow INTEGER NOT NULL DEFAULT 0,"
        " protocol_version INTEGER NOT NULL DEFAULT 0,"
        " services INTEGER NOT NULL DEFAULT 0,"
        " last_reported_height INTEGER NOT NULL DEFAULT -1,"
        " first_seen INTEGER NOT NULL,"
        " last_seen INTEGER NOT NULL,"
        " last_success INTEGER NOT NULL DEFAULT 0,"
        " dial_success_count INTEGER NOT NULL DEFAULT 0,"
        " dial_fail_count INTEGER NOT NULL DEFAULT 0,"
        " source INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY(ip, port)"
        ") WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS census_observations ("
        " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ip BLOB NOT NULL,"
        " port INTEGER NOT NULL,"
        " observed_unix INTEGER NOT NULL,"
        " user_agent TEXT,"
        " ua_overflow INTEGER NOT NULL DEFAULT 0,"
        " protocol_version INTEGER NOT NULL,"
        " services INTEGER NOT NULL,"
        " reported_height INTEGER NOT NULL,"
        " source INTEGER NOT NULL"
        ");";
    /* VERBATIM copy of the topology_store.c ensure_schema() topology_edges /
     * topology_sweeps CREATE TABLE text (topology_store.c:58,78). */
    static const char *TOPO_DDL =
        "CREATE TABLE IF NOT EXISTS topology_edges ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " observer_ip TEXT NOT NULL,"
        " observer_port INTEGER NOT NULL,"
        " advertised_ip TEXT NOT NULL,"
        " advertised_port INTEGER NOT NULL,"
        " first_advertised INTEGER NOT NULL,"
        " last_advertised INTEGER NOT NULL,"
        " times_seen INTEGER NOT NULL DEFAULT 1,"
        " UNIQUE(observer_ip,observer_port,advertised_ip,advertised_port));"
        "CREATE TABLE IF NOT EXISTS topology_sweeps ("
        " sweep_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " started_unix INTEGER NOT NULL,"
        " finished_unix INTEGER NOT NULL DEFAULT 0,"
        " nodes_contacted INTEGER NOT NULL DEFAULT 0,"
        " nodes_reachable INTEGER NOT NULL DEFAULT 0,"
        " edges_seen INTEGER NOT NULL DEFAULT 0,"
        " new_nodes INTEGER NOT NULL DEFAULT 0);";

    sqlite3 *pdb = census_open_peers_rw(datadir);
    if (!pdb)
        return false;
    int rc = sqlite3_exec(pdb, PEERS_DDL, NULL, NULL, NULL);
    sqlite3_close(pdb);
    if (rc != SQLITE_OK)
        return false;

    sqlite3 *tdb = census_open_topo_rw(datadir);
    if (!tdb)
        return false;
    rc = sqlite3_exec(tdb, TOPO_DDL, NULL, NULL, NULL);
    sqlite3_close(tdb);
    return rc == SQLITE_OK;
}

bool census_read_test_insert_node(const char *datadir,
                                  const struct census_node *n)
{
    if (!n)
        return false;
    unsigned char ip[16];
    if (!census_ip_to_blob(n->ip, ip))
        return false;
    sqlite3 *db = census_open_peers_rw(datadir);
    if (!db)
        return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO node_census(ip,port,user_agent,ua_overflow,"
        "protocol_version,services,last_reported_height,first_seen,last_seen,"
        "last_success,dial_success_count,dial_fail_count,source)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)", -1, &s, NULL);
    bool ok = false;
    if (rc == SQLITE_OK) {
        sqlite3_bind_blob(s, 1, ip, 16, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, n->port);
        sqlite3_bind_text(s, 3, n->user_agent, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 4, n->ua_overflow ? 1 : 0);
        sqlite3_bind_int64(s, 5, n->protocol_version);
        sqlite3_bind_int64(s, 6, n->services);
        sqlite3_bind_int64(s, 7, n->reported_height);
        sqlite3_bind_int64(s, 8, n->first_seen);
        sqlite3_bind_int64(s, 9, n->last_seen);
        sqlite3_bind_int64(s, 10, n->last_success);
        sqlite3_bind_int64(s, 11, n->dial_success_count);
        sqlite3_bind_int64(s, 12, n->dial_fail_count);
        ok = AR_STEP_WRITE(s) == SQLITE_DONE;
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
    return ok;
}

bool census_read_test_insert_edge(const char *datadir,
                                  const char *observer_ip, int observer_port,
                                  const char *advertised_ip, int advertised_port,
                                  int64_t times_seen, int64_t last_advertised)
{
    if (!observer_ip || !advertised_ip)
        return false;
    sqlite3 *db = census_open_topo_rw(datadir);
    if (!db)
        return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO topology_edges"
        "(observer_ip,observer_port,advertised_ip,advertised_port,"
        " first_advertised,last_advertised,times_seen) VALUES(?,?,?,?,?,?,?)",
        -1, &s, NULL);
    bool ok = false;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(s, 1, observer_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, observer_port);
        sqlite3_bind_text(s, 3, advertised_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 4, advertised_port);
        sqlite3_bind_int64(s, 5, last_advertised);
        sqlite3_bind_int64(s, 6, last_advertised);
        sqlite3_bind_int64(s, 7, times_seen);
        ok = AR_STEP_WRITE(s) == SQLITE_DONE;
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
    return ok;
}

bool census_read_test_insert_observation(const char *datadir, const char *ip,
                                         int port, int64_t observed_unix,
                                         int64_t reported_height, const char *ua,
                                         int64_t protocol_version,
                                         int64_t services)
{
    if (!ip)
        return false;
    unsigned char ipb[16];
    if (!census_ip_to_blob(ip, ipb))
        return false;
    sqlite3 *db = census_open_peers_rw(datadir);
    if (!db)
        return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO census_observations"
        "(ip,port,observed_unix,user_agent,ua_overflow,protocol_version,"
        " services,reported_height,source) VALUES(?,?,?,?,0,?,?,?,0)",
        -1, &s, NULL);
    bool ok = false;
    if (rc == SQLITE_OK) {
        sqlite3_bind_blob(s, 1, ipb, 16, SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 2, port);
        sqlite3_bind_int64(s, 3, observed_unix);
        if (ua)
            sqlite3_bind_text(s, 4, ua, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(s, 4);
        sqlite3_bind_int64(s, 5, protocol_version);
        sqlite3_bind_int64(s, 6, services);
        sqlite3_bind_int64(s, 7, reported_height);
        ok = AR_STEP_WRITE(s) == SQLITE_DONE;
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
    return ok;
}

bool census_read_test_insert_sweep(const char *datadir, int64_t started_unix,
                                   int64_t finished_unix, int nodes_contacted,
                                   int nodes_reachable, int edges_seen,
                                   int new_nodes)
{
    sqlite3 *db = census_open_topo_rw(datadir);
    if (!db)
        return false;
    sqlite3_stmt *s = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO topology_sweeps"
        "(started_unix,finished_unix,nodes_contacted,nodes_reachable,"
        " edges_seen,new_nodes) VALUES(?,?,?,?,?,?)", -1, &s, NULL);
    bool ok = false;
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(s, 1, started_unix);
        sqlite3_bind_int64(s, 2, finished_unix);
        sqlite3_bind_int(s, 3, nodes_contacted);
        sqlite3_bind_int(s, 4, nodes_reachable);
        sqlite3_bind_int(s, 5, edges_seen);
        sqlite3_bind_int(s, 6, new_nodes);
        ok = AR_STEP_WRITE(s) == SQLITE_DONE;
        sqlite3_finalize(s);
    }
    sqlite3_close(db);
    return ok;
}
#endif /* ZCL_TESTING */
