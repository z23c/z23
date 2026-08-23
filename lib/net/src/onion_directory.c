/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * onion_directory — the peer directory this node publishes at
 * /directory.json, and the onion graph it learns from other nodes'.
 *
 * Split out of onion_service.c, which owns the onion FRONT DOOR (request
 * routing and page chrome). This file owns the DATA behind two of those
 * routes: the peer_directory table, its freshness rules, the supervised
 * refresh round that keeps it current, and the parser + bounds for the
 * transitive discovery half. The two serve_directory_* renderers stay
 * with the chrome they share; they read the freshness rule from here.
 *
 * It also owns the read-only join onto the ZNAM name projection, so a
 * page can show the on-chain NAME beside every raw .onion. Names are
 * READ here and never written: znam_names has exactly one writer (the
 * on-chain ZNAM fold). A second writable copy of a name inside the
 * directory would be the cloned-ledger bug the architecture forbids.
 *
 * A lib/ module talking raw SQLite rather than the AR_* model macros:
 * those live under app/models and would invert the lib/ -> app/
 * dependency direction check-lib-layering enforces. Same principled
 * exception as lib/net/src/rom_seed_ledger.c and
 * lib/storage/src/peers_projection.c; every step goes through the
 * AR_STEP_* wrappers.
 *
 * The whole contract, including what a directory record IS and is not,
 * is in net/onion_service.h. The one-line version: a record is a hint
 * about where to look, never proof of who is there, so nothing in this
 * file may ever REMOVE a peer from any other source's reach. */

#include "platform/time_compat.h"
#include "net/onion_service.h"
#include "net/onion_peer_merge.h"
#include "net/site_routes.h"
#include "znam/znam.h"
#include "util/log_json.h"
#include "util/log_macros.h"
#include "util/path_check.h"
#include "util/supervisor.h"
#include "util/ar_step_readonly.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define ODIR_LOG "net.onion_directory"

/* ── App advertisements: one id rule, two normalizers ─────────────
 *
 * A directory row may carry the app-catalog ids its host serves on its
 * onion ("apps":["yardsale",...] on /directory.json, a bounded CSV in the
 * peer_directory.apps column). The rule is deliberately local, like the
 * ZNAM render guard above: lib/net ranks below lib/framework
 * (check-lib-module-order), so the catalog's own predicate
 * (zcl_app_definition_id_valid_v1) is unreachable from here — and this
 * rule is kept at or tighter than that one, so it can only ever withhold
 * an id, never invent one. */
bool onion_directory_app_id_valid(const char *app_id)
{
    if (!app_id || !app_id[0]) return false;
    size_t n = strlen(app_id);
    if (n > ONION_DIR_APP_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = app_id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

/* Append `tok` to the CSV in `out` when it is not already a token of it.
 * Returns the new length, or the old one when the token is a duplicate or
 * would exceed out_len / ONION_DIR_APPS_MAX. */
static size_t odir_apps_csv_add(char *out, size_t out_len, size_t cur,
                                const char *tok, size_t tok_len)
{
    char id[ONION_DIR_APP_ID_MAX + 1];
    if (tok_len == 0 || tok_len > ONION_DIR_APP_ID_MAX)
        return cur;
    memcpy(id, tok, tok_len);
    id[tok_len] = '\0';
    if (!onion_directory_app_id_valid(id))
        return cur;

    /* Count + dedupe against what is already kept. */
    size_t kept = 0;
    const char *p = out;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == tok_len && memcmp(p, tok, len) == 0)
            return cur;                 /* duplicate: keep first sighting */
        kept++;
        p += len + (comma ? 1 : 0);
    }
    if (kept >= ONION_DIR_APPS_MAX)
        return cur;                     /* the cap is a hard stop */
    size_t need = cur + (cur ? 1 : 0) + tok_len;
    if (need + 1 > out_len)
        return cur;
    if (cur)
        out[cur++] = ',';
    memcpy(out + cur, tok, tok_len);
    cur += tok_len;
    out[cur] = '\0';
    return cur;
}

size_t onion_directory_apps_normalize(const char *csv,
                                      char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!csv)
        return 0;
    size_t cur = 0;
    const char *p = csv;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        cur = odir_apps_csv_add(out, out_len, cur, p, len);
        p += len + (comma ? 1 : 0);
    }
    return cur;
}

size_t onion_directory_apps_from_json(const char *seg,
                                      char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!seg)
        return 0;

    const char *k = strstr(seg, "\"apps\"");
    if (!k)
        return 0;
    k += sizeof("\"apps\"") - 1;
    while (*k == ' ' || *k == ':')
        k++;
    if (*k != '[')
        return 0;
    k++;

    size_t cur = 0;
    for (;;) {
        while (*k == ' ' || *k == ',')
            k++;
        if (*k == ']')
            break;
        if (*k != '"')
            break;          /* unterminated or non-string: keep what we have */
        k++;
        const char *end = strchr(k, '"');
        if (!end)
            break;
        cur = odir_apps_csv_add(out, out_len, cur, k, (size_t)(end - k));
        k = end + 1;
    }
    return cur;
}

size_t onion_directory_apps_for_onion(const char *body, const char *onion,
                                      char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!body || !onion_hostname_valid(onion))
        return 0;

    /* Find THIS host's object, then bound the segment exactly like the
     * relay-hint walk does, so a later object's apps can never be read as
     * this one's. */
    char needle[96];
    int nn = snprintf(needle, sizeof(needle), "\"onion\":\"%s\"", onion);
    if (nn <= 0 || (size_t)nn >= sizeof(needle))
        return 0;
    const char *hit = strstr(body, needle);
    if (!hit)
        return 0;
    const char *val = hit + nn;
    char seg[512];
    const char *obj_end = strchr(val, '}');
    size_t seglen = obj_end ? (size_t)(obj_end - val) : strlen(val);
    if (seglen >= sizeof(seg))
        seglen = sizeof(seg) - 1;
    memcpy(seg, val, seglen);
    seg[seglen] = '\0';
    return onion_directory_apps_from_json(seg, out, out_len);
}

/* ── Render guard for an on-chain label ───────────────────────
 *
 * A RENDER guard, not a re-implementation of ZNAM validity.
 *
 * Registry validity is znam_validate_name()'s job and has exactly one
 * enforcement point: the on-chain ZNAM fold that writes znam_names.
 * lib/net ranks BELOW lib/znam in the module graph
 * (check-lib-module-order), so calling into it from here would invert
 * the dependency — and re-deciding "is this a legal name" in a second
 * place is how two answers start to drift. What the directory actually
 * needs is narrower and local: is this string safe to put in an HTML
 * page and a JSON document as a label. Kept deliberately at or tighter
 * than the registry rule, so it can only ever withhold a label, never
 * invent one. */
bool onion_directory_label_is_renderable(const char *name)
{
    if (!name || !name[0]) return false;
    size_t n = strlen(name);
    if (n > ZNAM_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

/* Contract in net/onion_discovery.h: skip malformed fields, never abort
 * the scan on one — a hostile peer must not be able to hide the honest
 * records that follow its own by emitting one broken field. */
bool onion_directory_scan_next_onion(const char **cursor,
                                     char *out, size_t out_len)
{
    if (!cursor || !*cursor || !out || out_len == 0)
        return false;
    out[0] = '\0';

    static const char KEY[] = "\"onion\":\"";
    const char *p = *cursor;

    for (;;) {
        const char *hit = strstr(p, KEY);
        if (!hit) {
            *cursor = p + strlen(p);
            return false;
        }
        const char *val = hit + (sizeof(KEY) - 1);
        const char *end = strchr(val, '"');
        if (!end) {
            /* Unterminated: nothing parseable remains. */
            *cursor = val + strlen(val);
            return false;
        }
        size_t len = (size_t)(end - val);
        p = end + 1;
        if (len == 0 || len >= out_len)
            continue;   /* empty or over-long: skip, keep scanning */
        memcpy(out, val, len);
        out[len] = '\0';
        *cursor = p;
        return true;
    }
}

/* ── ZNAM name join (READ-only) ───────────────────────────────
 *
 * The peer_directory has no name column and never will. Discovery READS
 * the on-chain projection instead.
 *
 * `db` is any open handle on node.db. Returns false (out = "") when the
 * projection table does not exist yet — a node that has not folded a
 * ZNAM registration is nameless, not broken. */
bool onion_directory_name_for_db(sqlite3 *db, const char *onion,
                                 char *out, size_t out_len)
{
    if (!db || !out || out_len == 0) return false;
    out[0] = '\0';
    if (!onion_hostname_valid(onion)) return false;

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT name FROM znam_names WHERE target_type=?1 "
        "AND (target_value=?2 OR target_value=?3) "
        "ORDER BY reg_height ASC, name ASC LIMIT 1",
        -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return false;   /* projection absent: nameless, not an error */
    }

    /* Registrations in the wild carry the target with or without the
     * ".onion" suffix; match both rather than silently missing half. */
    char bare[64];
    snprintf(bare, sizeof(bare), "%.56s", onion);

    sqlite3_bind_int(s, 1, ZNAM_TYPE_ONION);
    sqlite3_bind_text(s, 2, onion, -1, SQLITE_STATIC);
    sqlite3_bind_text(s, 3, bare, -1, SQLITE_STATIC);

    bool got = false;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(s, 0);
        if (name && name[0] && onion_directory_label_is_renderable(name)) {
            snprintf(out, out_len, "%s", name);
            got = true;
        }
    }
    sqlite3_finalize(s);
    return got;
}

bool onion_directory_name_for(const char *datadir, const char *onion,
                              char *out, size_t out_len)
{
    if (!out || out_len == 0) return false;
    out[0] = '\0';
    if (!datadir) return false;

    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_busy_timeout(db, 5000);
    bool got = onion_directory_name_for_db(db, onion, out, out_len);
    sqlite3_close(db);
    return got;
}

static void ensure_directory_table(sqlite3 *db)
{
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS peer_directory ("
        "onion_address TEXT PRIMARY KEY,"
        "port INTEGER NOT NULL DEFAULT 8033,"
        "services INTEGER NOT NULL DEFAULT 0,"
        "height INTEGER NOT NULL DEFAULT 0,"
        "last_seen INTEGER NOT NULL,"
        "version TEXT,"
        "self INTEGER NOT NULL DEFAULT 0,"
        "clearnet_ip TEXT DEFAULT '',"
        "clearnet_port INTEGER DEFAULT 0,"
        "apps TEXT NOT NULL DEFAULT ''"
        ")", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "onion_service: failed to create directory table: %s\n",  // obs-ok:pre-existing-diagnostic
                err ? err : "unknown");
        sqlite3_free(err);
    }
    /* Add clearnet columns to existing databases */
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN clearnet_ip TEXT DEFAULT ''",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN clearnet_port INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    /* Freshness columns. first_seen/last_probe/probe_ok/fail_count make a
     * row's history readable; `source` says whether we measured it
     * ourselves or another node told us about it. Adding a column that is
     * already present is an expected no-op here, exactly like the two
     * clearnet ALTERs above. */
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN first_seen INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN last_probe INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN probe_ok INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN fail_count INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN source TEXT DEFAULT ''",
                 NULL, NULL, NULL);
    /* CONTACT, kept distinct from `last_seen`. last_seen moves on hearsay
     * (a peer's directory named this host); last_success only moves when
     * WE completed a fetch against it. The served pages show both, so a
     * reader can tell "someone mentioned it" from "we reached it". */
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN last_success INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN dial_success_count INTEGER DEFAULT 0",
                 NULL, NULL, NULL);
    /* The app-service advertisement (Track 2): which app-catalog Apps the
     * host serves on its onion, as a bounded normalized CSV ("yardsale" —
     * see the helpers at the top of this file). Additive exactly like the
     * ALTERs above: a duplicate-column error on an existing database is an
     * expected no-op, and rows that predate the column read as ''. */
    sqlite3_exec(db, "ALTER TABLE peer_directory ADD COLUMN apps TEXT NOT NULL DEFAULT ''",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_peer_directory_last_seen "
                     "ON peer_directory(last_seen)", NULL, NULL, NULL);
}

/* ── Freshness: one pure rule, no database ─────────────────── */

int64_t onion_directory_age_secs(int64_t last_seen, int64_t now)
{
    int64_t age = now - last_seen;
    return age < 0 ? 0 : age;
}

enum onion_dir_freshness onion_directory_freshness(int64_t last_seen,
                                                   int64_t now, bool self)
{
    /* Our own presence is not hearsay — we are the node. */
    if (self)
        return ONION_DIR_FRESH;
    /* No stamp at all is no provenance at all. */
    if (last_seen <= 0)
        return ONION_DIR_EXPIRED;
    int64_t age = onion_directory_age_secs(last_seen, now);
    if (age < ONION_DIR_STALE_SECS)
        return ONION_DIR_FRESH;
    if (age < ONION_DIR_EXPIRE_SECS)
        return ONION_DIR_STALE;
    return ONION_DIR_EXPIRED;
}

/* Populate directory from the discovery sources (signed descriptors +
 * the on-chain/wallet scrape, merged by onion_peers_collect).
 *
 * This is an UPSERT, not the old INSERT OR IGNORE: a peer the sources
 * still announce is a peer we still have evidence for, so its last_seen
 * moves forward. Without that, every row froze at its first sighting and
 * the whole table aged out or, worse, was served forever as if current.
 * Returns the number of rows inserted or refreshed. */
static int populate_directory_from_chain(sqlite3 *db)
{
    if (!onion_service_datadir()) return 0;

    struct onion_peer peers[256];
    int found = onion_service_discover_peers(peers, 256);

    if (found <= 0) return 0;

    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO peer_directory "
        "(onion_address, height, first_seen, last_seen, version, source) "
        "VALUES (?, ?, ?, ?, 'chain', 'discovery') "
        "ON CONFLICT(onion_address) DO UPDATE SET "
        "  last_seen = excluded.last_seen,"
        "  height = MAX(peer_directory.height, excluded.height),"
        "  fail_count = 0",
        -1, &ins, NULL) != SQLITE_OK || !ins) {
        LOG_WARN(ODIR_LOG, "failed to prepare peer upsert: %s", sqlite3_errmsg(db));
        return 0;
    }

    int64_t now = (int64_t)platform_time_wall_time_t();
    int touched = 0;
    for (int i = 0; i < found; i++) {
        if (!peers[i].hostname[0]) continue;
        sqlite3_reset(ins);
        sqlite3_bind_text(ins, 1, peers[i].hostname, -1, SQLITE_STATIC);
        sqlite3_bind_int(ins, 2, peers[i].height);
        sqlite3_bind_int64(ins, 3, now);
        sqlite3_bind_int64(ins, 4, now);
        if (AR_STEP_WRITE(ins) == SQLITE_DONE)
            touched++;
    }
    sqlite3_finalize(ins);

    log_jsonf(LOG_JSON_INFO, "onion_directory_loaded",
              "\"peers_loaded\":%d,\"rows_touched\":%d", found, touched);
    return touched;
}

/* Drop rows nothing has confirmed for ONION_DIR_EXPIRE_SECS. Our own row
 * is never expired; a row with no stamp at all (last_seen <= 0) is, since
 * it has no provenance to age. Returns the number deleted. */
static int expire_directory_rows(sqlite3 *db, int64_t now)
{
    sqlite3_stmt *del = NULL;
    if (sqlite3_prepare_v2(db,
        "DELETE FROM peer_directory WHERE self = 0 AND "
        "(last_seen <= 0 OR last_seen < ?)",
        -1, &del, NULL) != SQLITE_OK || !del) {
        LOG_WARN(ODIR_LOG, "failed to prepare directory expiry: %s",
                 sqlite3_errmsg(db));
        return 0;
    }
    sqlite3_bind_int64(del, 1, now - ONION_DIR_EXPIRE_SECS);
    int deleted = 0;
    if (AR_STEP_WRITE(del) == SQLITE_DONE)
        deleted = sqlite3_changes(db);
    sqlite3_finalize(del);
    return deleted;
}

static int count_directory_rows(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM peer_directory",
                           -1, &s, NULL) != SQLITE_OK || !s)
        return -1;
    int n = -1;
    if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
        n = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* Open the directory database read-write. NULL when there is no datadir
 * (the onion service was never started) or the file will not open — both
 * of which the callers must treat as "not wired", never as "nothing to
 * do". */
static sqlite3 *directory_open_rw(void)
{
    const char *datadir = onion_service_datadir();
    if (!datadir)
        return NULL;
    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    /* Short, deliberate: the refresh round runs on the shared supervisor
     * tick runner, which must never park behind a long reducer commit. */
    sqlite3_busy_timeout(db, 2000);
    ensure_directory_table(db);
    return db;
}

/* ── Our own clearnet endpoint: cached, never dialled from a tick ──
 *
 * The public-IP probe (peer_strategy_discover_self) does NAT-PMP, then
 * UPnP SSDP + SOAP, then a naked IP discovery. Its own comment in
 * lib/net/src/peer_strategy.c records that it "blocks for tens of
 * seconds on a host whose gateway ignores it" — which is why it is
 * gated out of regtest boot.
 *
 * The refresh round runs on the SHARED supervisor tick runner, whose
 * liveness deadline is 30 s (SUPERVISOR_TICK_RUNNER_DEADLINE_SECS): a
 * blocking probe there freezes every other supervised child and burns
 * half the runner's deadline on a network round-trip. It is the same
 * failure class as the tick-runner hang the systemd watchdog has
 * SIGABRT'd this node for before.
 *
 * So the tick READS a cache and never dials. The cache is published by
 * whoever is allowed to block — today boot_services.c, which already
 * runs the probe once synchronously — through
 * onion_directory_set_self_clearnet(). Until it is published, this
 * node's row simply carries no clearnet endpoint, which is exactly what
 * a probe failure produced anyway. */

static pthread_mutex_t g_self_ep_mutex = PTHREAD_MUTEX_INITIALIZER;
static char     g_self_ip[64] = "";
static uint16_t g_self_ip_port = 0;

void onion_directory_set_self_clearnet(const uint8_t ip[4], uint16_t port)
{
    char buf[64] = "";
    if (ip && port > 0 && (ip[0] || ip[1] || ip[2] || ip[3]))
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 ip[0], ip[1], ip[2], ip[3]);
    pthread_mutex_lock(&g_self_ep_mutex);
    snprintf(g_self_ip, sizeof(g_self_ip), "%s", buf);
    g_self_ip_port = buf[0] ? port : 0;
    pthread_mutex_unlock(&g_self_ep_mutex);
}

/* Copy the cached endpoint out. Returns the port (0 = none known). */
static uint16_t self_clearnet_snapshot(char *out, size_t out_len)
{
    if (!out || out_len == 0) return 0;
    pthread_mutex_lock(&g_self_ep_mutex);
    snprintf(out, out_len, "%s", g_self_ip);
    uint16_t port = g_self_ip_port;
    pthread_mutex_unlock(&g_self_ep_mutex);
    return port;
}

/* Our own app advertisement: the mounted app-catalog Apps, read off the
 * ONE registry of app web mounts (net/site_routes.def — a row carries an
 * app_id only when it mounts that App, and test_site_routes cross-checks
 * the column against apps/<id>/app.def's ZCL_APP_ONION(true) declaration,
 * so this list cannot drift from what the catalog declares onion-enabled).
 * Compile-time static, so no cache and no publisher is needed — unlike the
 * clearnet endpoint above, nothing here can change at runtime. */
static size_t self_apps_csv(char *out, size_t out_len)
{
    if (!out || out_len == 0) return 0;
    out[0] = '\0';
    size_t cur = 0;
    for (size_t i = 0; i < g_zcl_site_routes_count; i++) {
        const char *id = g_zcl_site_routes[i].app_id;
        if (!id)
            continue;
        cur = odir_apps_csv_add(out, out_len, cur, id, strlen(id));
    }

    /* Operator-declared extras (ONION_DIR_EXTRA_APPS_REL — `app shop init`
     * writes "shop" there): re-read every round so initializing a shop
     * lands on the self row without a restart, and deleting the file
     * un-announces. The extra file passed the same normalize rule on the
     * way out of onion_directory_extra_apps_csv, so these tokens are
     * already bounded and valid; odir_apps_csv_add re-checks regardless. */
    char extra[ONION_DIR_APPS_CSV_MAX + 1];
    if (onion_directory_extra_apps_csv(onion_service_datadir(), extra,
                                       sizeof(extra)) > 0) {
        const char *p = extra;
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t tl = comma ? (size_t)(comma - p) : strlen(p);
            cur = odir_apps_csv_add(out, out_len, cur, p, tl);
            p += tl + (comma ? 1 : 0);
        }
    }
    return cur;
}

size_t onion_directory_extra_apps_csv(const char *datadir,
                                      char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    if (!datadir || !datadir[0])
        return 0;
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/%s", datadir,
                     ONION_DIR_EXTRA_APPS_REL);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return 0;
    char buf[ONION_DIR_APPS_CSV_MAX + 1];
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;               /* absent is the common case, not an error */
    size_t len = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[len] = '\0';
    /* A trailing newline or a junk token cannot smuggle anything in:
     * normalize drops whatever fails onion_directory_app_id_valid. */
    return onion_directory_apps_normalize(buf, out, out_len);
}

void onion_directory_reset_self_clearnet(void)
{
    pthread_mutex_lock(&g_self_ep_mutex);
    g_self_ip[0] = '\0';
    g_self_ip_port = 0;
    pthread_mutex_unlock(&g_self_ep_mutex);
}

/* Register our own .onion address with clearnet IP if known. Returns true
 * when a row was written — the refresh round counts that as real work,
 * because it is what keeps THIS node's served row current. */
static bool register_self(sqlite3 *db)
{
    const char *self_addr = onion_service_get_address();
    if (!self_addr || !self_addr[0]) return false;

    /* Cache read only — see the note above. Never a network call here. */
    char ip_str[64] = "";
    uint16_t ip_port = self_clearnet_snapshot(ip_str, sizeof(ip_str));

    /* Our mounted app-catalog Apps, off the site-route registry. Static
     * per build; re-published every round like the rest of the row. */
    char apps[ONION_DIR_APPS_CSV_MAX + 1];
    self_apps_csv(apps, sizeof(apps));

    /* UPSERT rather than INSERT OR REPLACE: replacing the row would reset
     * first_seen, losing how long this node has been announcing itself. */
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO peer_directory "
        "(onion_address, port, services, height, first_seen, last_seen,"
        " last_probe, last_success, probe_ok, dial_success_count,"
        " fail_count, version, self, clearnet_ip, clearnet_port, source,"
        " apps) "
        "VALUES (?, 8033, 1029, 0, ?, ?, ?, ?, 1, 0, 0, '0.1.0', 1, ?, ?,"
        " 'self', ?) "
        "ON CONFLICT(onion_address) DO UPDATE SET "
        "  last_seen = excluded.last_seen,"
        "  last_probe = excluded.last_probe,"
        "  last_success = excluded.last_success,"
        "  probe_ok = 1, fail_count = 0, self = 1, source = 'self',"
        "  clearnet_ip = excluded.clearnet_ip,"
        "  clearnet_port = excluded.clearnet_port,"
        "  apps = excluded.apps",
        -1, &ins, NULL) != SQLITE_OK || !ins) {
        fprintf(stderr, "onion_service: failed to prepare self-register: %s\n",
                sqlite3_errmsg(db));
        return false;
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    sqlite3_bind_text(ins, 1, self_addr, -1, SQLITE_STATIC);
    sqlite3_bind_int64(ins, 2, now);
    sqlite3_bind_int64(ins, 3, now);
    sqlite3_bind_int64(ins, 4, now);
    sqlite3_bind_int64(ins, 5, now);
    sqlite3_bind_text(ins, 6, ip_str[0] ? ip_str : "", -1, SQLITE_STATIC);
    sqlite3_bind_int(ins, 7, ip_str[0] ? (int)ip_port : 0);
    sqlite3_bind_text(ins, 8, apps, -1, SQLITE_STATIC);
    bool ok = (AR_STEP_WRITE(ins) == SQLITE_DONE);
    sqlite3_finalize(ins);
    return ok;
}

/* ── The census bridge ────────────────────────────────────── */

int onion_service_directory_observe(const struct onion_directory_observation *obs,
                                    size_t n,
                                    struct onion_directory_refresh_stats *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (n == 0)
        return 0;                    /* a census with nothing to say is fine */
    if (!obs)
        LOG_ERR(ODIR_LOG, "observe: NULL observations for n=%zu", n);

    sqlite3 *db = directory_open_rw();
    if (!db)
        LOG_ERR(ODIR_LOG, "observe: directory not open (no datadir)");

    /* Reachable: last_seen only ever moves FORWARD (MAX), so a probe with
     * a stale clock cannot age a row backwards. Unreachable: last_seen is
     * deliberately untouched — a failed dial is not evidence of absence,
     * it just stops being evidence of presence, and the row ages out on
     * its own. */
    sqlite3_stmt *up_ok = NULL, *up_fail = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE peer_directory SET last_seen = MAX(last_seen, ?),"
            " last_probe = ?, last_success = MAX(last_success, ?),"
            " probe_ok = 1, fail_count = 0,"
            " dial_success_count = dial_success_count + 1,"
            " height = MAX(height, ?) WHERE onion_address = ?",
            -1, &up_ok, NULL) != SQLITE_OK || !up_ok ||
        sqlite3_prepare_v2(db,
            "UPDATE peer_directory SET last_probe = ?, probe_ok = 0,"
            " fail_count = fail_count + 1 WHERE onion_address = ?",
            -1, &up_fail, NULL) != SQLITE_OK || !up_fail) {
        LOG_WARN(ODIR_LOG, "observe: prepare failed: %s", sqlite3_errmsg(db));
        sqlite3_finalize(up_ok);
        sqlite3_finalize(up_fail);
        sqlite3_close(db);
        return -1;
    }

    struct onion_directory_refresh_stats st = {0};
    int64_t now = (int64_t)platform_time_wall_time_t();
    for (size_t i = 0; i < n; i++) {
        const struct onion_directory_observation *o = &obs[i];
        if (!onion_hostname_valid(o->hostname)) {
            st.unknown++;
            continue;
        }
        int64_t probe = (o->observed_unix > 0 && o->observed_unix <= now)
                            ? o->observed_unix : now;
        if (o->reachable) {
            sqlite3_reset(up_ok);
            sqlite3_bind_int64(up_ok, 1, probe);
            sqlite3_bind_int64(up_ok, 2, probe);
            sqlite3_bind_int64(up_ok, 3, probe);
            sqlite3_bind_int64(up_ok, 4,
                               o->best_height > 0 ? o->best_height : 0);
            sqlite3_bind_text(up_ok, 5, o->hostname, -1, SQLITE_STATIC);
            if (AR_STEP_WRITE(up_ok) == SQLITE_DONE && sqlite3_changes(db) > 0) {
                st.observed++;
                st.refreshed++;
            } else {
                st.unknown++;
            }
        } else {
            sqlite3_reset(up_fail);
            sqlite3_bind_int64(up_fail, 1, probe);
            sqlite3_bind_text(up_fail, 2, o->hostname, -1, SQLITE_STATIC);
            if (AR_STEP_WRITE(up_fail) == SQLITE_DONE && sqlite3_changes(db) > 0) {
                st.observed++;
                st.failed++;
            } else {
                st.unknown++;
            }
        }
    }
    sqlite3_finalize(up_ok);
    sqlite3_finalize(up_fail);
    st.rows_after = count_directory_rows(db);
    sqlite3_close(db);

    if (out)
        *out = st;
    return st.observed;
}

bool onion_service_directory_refresh(struct onion_directory_refresh_stats *out)
{
    struct onion_directory_refresh_stats st = {0};
    if (out)
        *out = st;

    sqlite3 *db = directory_open_rw();
    if (!db)
        LOG_FAIL(ODIR_LOG, "refresh: directory not open (no datadir)");

    int64_t now = (int64_t)platform_time_wall_time_t();
    st.discovered = populate_directory_from_chain(db);
    if (register_self(db))
        st.refreshed++;
    st.expired = expire_directory_rows(db, now);
    st.rows_after = count_directory_rows(db);
    sqlite3_close(db);

    if (out)
        *out = st;
    if (st.discovered || st.expired)
        log_jsonf(LOG_JSON_INFO, "onion_directory_refreshed",
                  "\"discovered\":%d,\"expired\":%d,\"rows\":%d",
                  st.discovered, st.expired, st.rows_after);
    return true;
}

/* ── The onion graph: parse + ADD-only persistence ────────── */

/* Read `key`'s integer value out of a single directory object's text.
 * `seg` is already bounded to one object by the caller. */
static int64_t odir_json_int(const char *seg, const char *key, int64_t dflt)
{
    const char *k = strstr(seg, key);
    if (!k)
        return dflt;
    k += strlen(key);
    while (*k == ' ' || *k == ':')
        k++;
    if (*k != '-' && (*k < '0' || *k > '9'))
        return dflt;
    return (int64_t)strtoll(k, NULL, 10);
}

int onion_directory_parse_relay_hints(const char *body, const char *self_host,
                                      struct onion_relay_hint *out, size_t max)
{
    if (!body || !out || max == 0)
        return 0;

    static const char NEEDLE[] = "\"onion\":\"";
    const size_t NEEDLE_LEN = sizeof(NEEDLE) - 1;

    int kept = 0;
    const char *p = body;
    while ((size_t)kept < max && (p = strstr(p, NEEDLE)) != NULL) {
        p += NEEDLE_LEN;
        const char *end = strchr(p, '"');
        if (!end || end == p) {
            p++;
            continue;
        }
        size_t hlen = (size_t)(end - p);
        char host[64];
        if (hlen >= sizeof(host)) {
            p = end + 1;
            continue;
        }
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        p = end + 1;

        /* Every hostname, from every source, through the one v3 rule. */
        if (!onion_hostname_valid(host))
            continue;
        if (self_host && self_host[0] && strcmp(host, self_host) == 0)
            continue;
        bool dup = false;
        for (int i = 0; i < kept && !dup; i++)
            dup = (strcmp(out[i].hostname, host) == 0);
        if (dup)
            continue;

        /* Only the rest of THIS object, so a later node's port/height can
         * never be read as this one's. */
        char seg[512];
        const char *obj_end = strchr(p, '}');
        size_t seglen = obj_end ? (size_t)(obj_end - p) : strlen(p);
        if (seglen >= sizeof(seg))
            seglen = sizeof(seg) - 1;
        memcpy(seg, p, seglen);
        seg[seglen] = '\0';

        memset(&out[kept], 0, sizeof(out[kept]));
        snprintf(out[kept].hostname, sizeof(out[kept].hostname), "%s", host);
        int64_t port = odir_json_int(seg, "\"port\"", 0);
        out[kept].port = (port > 0 && port <= 65535) ? (int)port : 0;
        int64_t height = odir_json_int(seg, "\"height\"", 0);
        out[kept].height = (height > 0 && height <= 0x7fffffff) ? (int)height : 0;
        int64_t seen = odir_json_int(seg, "\"last_seen\"", 0);
        out[kept].last_seen = seen > 0 ? seen : 0;
        /* The app-service advertisement, same per-object binding: only the
         * rest of THIS object, normalized (junk ids dropped, capped). An
         * old peer simply has no "apps" key and reads as "". */
        (void)onion_directory_apps_from_json(seg, out[kept].apps,
                                             sizeof(out[kept].apps));
        kept++;
    }
    return kept;
}

/* ── Follow budget for the one transitive hop ─────────────── */

static pthread_mutex_t g_relay_mutex = PTHREAD_MUTEX_INITIALIZER;
static char    g_relay_seen[ONION_RELAY_VISIT_CAP][64];
static int     g_relay_seen_n = 0;
static int     g_relay_follows = 0;
static int64_t g_relay_window_start = 0;

bool onion_directory_claim_relay_follow(const char *hostname, int64_t now)
{
    if (!onion_hostname_valid(hostname))
        LOG_FAIL(ODIR_LOG, "claim_relay_follow: hostname fails the v3 rule");

    bool claimed = false;
    pthread_mutex_lock(&g_relay_mutex);
    if (g_relay_window_start == 0 ||
        now - g_relay_window_start >= ONION_RELAY_WINDOW_SECS ||
        now < g_relay_window_start) {
        g_relay_window_start = now;
        g_relay_follows = 0;
        g_relay_seen_n = 0;
    }
    bool seen = false;
    for (int i = 0; i < g_relay_seen_n && !seen; i++)
        seen = (strcmp(g_relay_seen[i], hostname) == 0);
    if (!seen && g_relay_follows < ONION_RELAY_FOLLOW_BUDGET &&
        g_relay_seen_n < ONION_RELAY_VISIT_CAP) {
        snprintf(g_relay_seen[g_relay_seen_n], sizeof(g_relay_seen[0]),
                 "%s", hostname);
        g_relay_seen_n++;
        g_relay_follows++;
        claimed = true;
    }
    pthread_mutex_unlock(&g_relay_mutex);
    return claimed;
}

void onion_directory_reset_relay_follow(void)
{
    pthread_mutex_lock(&g_relay_mutex);
    g_relay_seen_n = 0;
    g_relay_follows = 0;
    g_relay_window_start = 0;
    pthread_mutex_unlock(&g_relay_mutex);
}

/* ── Stale hearsay: counted, reported once per window ──────────
 *
 * A relayed stamp already past ONION_DIR_EXPIRE_SECS is EXPECTED input,
 * not a fault of ours. Any peer still running a binary from before
 * last_seen became a maintained column serves a directory frozen at first
 * sighting (the UPSERT comment above describes exactly that pathology),
 * and it serves the SAME frozen rows on every discovery pass — so the
 * rejection re-fires per record, per seed, forever. At one ERROR line per
 * record that single message took 707 of the node's last 3000 log lines:
 * a quarter of the log restating a condition that never changes, at a
 * level that means "something is broken here".
 *
 * Counted instead, with the same rolling-window shape and the same
 * cadence (ONION_RELAY_WINDOW_SECS) as the follow budget above, and
 * reported as ONE line: how many were ignored, over how long, the oldest
 * age seen and the host it belonged to. That is strictly more useful than
 * the per-record lines were — those never named the host, so no reader
 * could tell WHICH records were stale.
 *
 * The report fires on whichever comes first, the window elapsing or the
 * count reaching ONION_DIR_STALE_REPORT_MAX. The count bound is what
 * keeps a genuine BURST visible: at the observed fleet rate the window is
 * always the trigger, but a peer suddenly relaying thousands of dead rows
 * would otherwise sit unreported for the rest of the window. Either way
 * the log grows by at most one line per REPORT, never per record.
 *
 * INFO, not ERROR: the aggregate reports a remote peer's directory
 * hygiene, and this node's own handling of it is correct and complete.
 *
 * The window is only ever advanced by a new rejection, so a node that
 * stops meeting stale directories goes quiet rather than reporting an
 * empty window forever; the counters are the whole record and no other
 * code reads them. */
#define ONION_DIR_STALE_REPORT_MAX 256

static pthread_mutex_t g_stale_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t  g_stale_window_start = 0;
static uint64_t g_stale_ignored = 0;
static int64_t  g_stale_oldest_age = 0;
static char     g_stale_oldest_host[64];

static void note_stale_hearsay(const char *hostname, int64_t age, int64_t now)
{
    bool rolled = false;
    uint64_t n = 0;
    int64_t oldest = 0, span = 0;
    char host[64] = "";

    pthread_mutex_lock(&g_stale_mutex);
    if (g_stale_window_start == 0) {
        g_stale_window_start = now;
    } else if (now - g_stale_window_start >= ONION_RELAY_WINDOW_SECS ||
               now < g_stale_window_start ||
               g_stale_ignored >= ONION_DIR_STALE_REPORT_MAX) {
        /* Window ran its course, the burst filled the budget, or the wall
         * clock stepped backwards: hand the finished tally to the caller
         * and start a fresh one. */
        n = g_stale_ignored;
        oldest = g_stale_oldest_age;
        span = now - g_stale_window_start;
        if (span < 0) span = 0;
        snprintf(host, sizeof(host), "%s", g_stale_oldest_host);
        rolled = true;
        g_stale_window_start = now;
        g_stale_ignored = 0;
        g_stale_oldest_age = 0;
        g_stale_oldest_host[0] = '\0';
    }
    g_stale_ignored++;
    if (age > g_stale_oldest_age) {
        g_stale_oldest_age = age;
        snprintf(g_stale_oldest_host, sizeof(g_stale_oldest_host), "%s",
                 hostname ? hostname : "");
    }
    pthread_mutex_unlock(&g_stale_mutex);

    /* Emitted outside the lock: the sink is stderr, and no lock in this
     * file is held across I/O. */
    if (rolled && n > 0)
        LOG_INFO(ODIR_LOG,
                 "learn: ignored %llu relayed stamp%s already past expiry in "
                 "the last %llds (oldest %llds, %s) — a peer is relaying a "
                 "directory it never refreshes",
                 (unsigned long long)n, n == 1 ? "" : "s",
                 (long long)span, (long long)oldest,
                 host[0] ? host : "host unrecorded");
}

bool onion_service_directory_learn(const char *hostname, int port, int height,
                                   int64_t peer_last_seen, const char *apps)
{
    if (!onion_hostname_valid(hostname))
        LOG_FAIL(ODIR_LOG, "learn: hostname fails the v3 rule");

    int64_t now = (int64_t)platform_time_wall_time_t();
    /* Hearsay may age a row, never freshen it past our own clock. */
    int64_t stamp = (peer_last_seen > 0 && peer_last_seen < now)
                        ? peer_last_seen : now;
    /* An already-expired stamp is refused, not clamped up to the expiry
     * floor. Clamping would make this row read STALE — served by our own
     * /directory.json — so the next hop would clamp it to the floor again,
     * and a host nobody has reached in weeks would ride the relay graph
     * forever with its apparent age reset at every hop. The refusal is
     * what terminates that chain: hearsay may only ADD a place to look,
     * and a place nobody has confirmed inside the expiry window is not one
     * we can honestly pass on. Counted, never logged per record — see
     * note_stale_hearsay() above. */
    if (now - stamp >= ONION_DIR_EXPIRE_SECS) {
        note_stale_hearsay(hostname, now - stamp, now);
        return false;
    }

    /* Re-normalize whatever the caller handed in: the column only ever
     * holds bounded, validated CSV. */
    char apps_csv[ONION_DIR_APPS_CSV_MAX + 1];
    (void)onion_directory_apps_normalize(apps, apps_csv, sizeof(apps_csv));

    sqlite3 *db = directory_open_rw();
    if (!db)
        LOG_FAIL(ODIR_LOG, "learn: directory not open (no datadir)");

    /* INSERT OR IGNORE, by construction: a hostname another node told us
     * about may only ADD a place to look. It never overwrites a row we
     * measured ourselves and it never deletes anything. */
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO peer_directory "
            "(onion_address, port, services, height, first_seen, last_seen,"
            " last_probe, probe_ok, fail_count, version, self,"
            " clearnet_ip, clearnet_port, source, apps) "
            "VALUES (?, ?, 0, ?, ?, ?, 0, 0, 0, 'relay', 0, '', 0, 'relay', ?)",
            -1, &ins, NULL) != SQLITE_OK || !ins) {
        LOG_WARN(ODIR_LOG, "learn: prepare failed: %s", sqlite3_errmsg(db));
        sqlite3_finalize(ins);
        sqlite3_close(db);
        return false;
    }
    sqlite3_bind_text(ins, 1, hostname, -1, SQLITE_STATIC);
    sqlite3_bind_int(ins, 2, (port > 0 && port <= 65535) ? port : 8033);
    sqlite3_bind_int(ins, 3, height > 0 ? height : 0);
    sqlite3_bind_int64(ins, 4, now);
    sqlite3_bind_int64(ins, 5, stamp);
    sqlite3_bind_text(ins, 6, apps_csv, -1, SQLITE_STATIC);
    bool ok = (AR_STEP_WRITE(ins) == SQLITE_DONE);
    sqlite3_finalize(ins);
    if (!ok) {
        sqlite3_close(db);
        LOG_FAIL(ODIR_LOG, "learn: insert failed for a valid hostname");
    }

    /* The apps list is the ONE field hearsay may refresh on an existing
     * row (a what-they-serve hint, never identity): a fresh non-empty
     * advertisement replaces the stored one; an empty one clears nothing,
     * and no other column is touched. */
    if (apps_csv[0]) {
        sqlite3_stmt *up = NULL;
        if (sqlite3_prepare_v2(db,
                "UPDATE peer_directory SET apps = ? WHERE onion_address = ?",
                -1, &up, NULL) != SQLITE_OK || !up) {
            LOG_WARN(ODIR_LOG, "learn: apps refresh prepare failed: %s",
                     sqlite3_errmsg(db));
        } else {
            sqlite3_bind_text(up, 1, apps_csv, -1, SQLITE_STATIC);
            sqlite3_bind_text(up, 2, hostname, -1, SQLITE_STATIC);
            (void)AR_STEP_WRITE(up);
        }
        sqlite3_finalize(up);
    }
    sqlite3_close(db);
    return true;
}

/* ── Seller/app discovery (read side) ─────────────────────────────── */

/* Does `csv` (already normalized) carry `tok` as a whole token? */
static bool odir_csv_has_token(const char *csv, const char *tok)
{
    size_t want = strlen(tok);
    const char *p = csv;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == want && memcmp(p, tok, len) == 0)
            return true;
        p += len + (comma ? 1 : 0);
    }
    return false;
}

int onion_directory_app_peers_db(sqlite3 *db, const char *app_id,
                                 int64_t now,
                                 struct onion_directory_app_peer *out,
                                 int max)
{
    if (!db || !out || max <= 0 || !onion_directory_app_id_valid(app_id))
        return 0;

    /* FRESH per the one freshness rule (age < ONION_DIR_STALE_SECS ⇔
     * last_seen > now - ONION_DIR_STALE_SECS; a future stamp reads FRESH,
     * same as onion_directory_freshness). Self rows are excluded — our own
     * node is not a discovered seller. A missing peer_directory table is
     * "none discovered", never an error: the prepare simply fails. */
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT onion_address, COALESCE(apps,'') FROM peer_directory "
        "WHERE self = 0 AND last_seen > 0 AND last_seen > ?1 "
        "AND INSTR(',' || COALESCE(apps,'') || ',', ',' || ?2 || ',') > 0 "
        "ORDER BY last_seen DESC LIMIT ?3",
        -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return 0;
    }
    sqlite3_bind_int64(s, 1, now - ONION_DIR_STALE_SECS);
    sqlite3_bind_text(s, 2, app_id, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 3, max);

    int kept = 0;
    while (kept < max && AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
        const char *addr = (const char *)sqlite3_column_text(s, 0);
        const char *apps = (const char *)sqlite3_column_text(s, 1);
        /* Rows stored by pre-validation binaries may be hostile: the
         * hostname goes through the one v3 rule and the apps through the
         * one normalizer, and a row whose sanitized list no longer names
         * the app is dropped. */
        if (!onion_hostname_valid(addr))
            continue;
        char clean[ONION_DIR_APPS_CSV_MAX + 1];
        (void)onion_directory_apps_normalize(apps, clean, sizeof(clean));
        if (!odir_csv_has_token(clean, app_id))
            continue;
        snprintf(out[kept].onion, sizeof(out[kept].onion), "%s", addr);
        snprintf(out[kept].apps, sizeof(out[kept].apps), "%s", clean);
        kept++;
    }
    sqlite3_finalize(s);
    return kept;
}

/* ── Supervised refresh (no dedicated thread) ─────────────── */

/* Four missed rounds. Long enough that a transient busy database or a
 * boot-time race never fires it, short enough that a directory which has
 * genuinely stopped refreshing is named within an hour instead of being
 * served stale for a week. */
#define ONION_DIR_MAX_QUIET_US \
    ((int64_t)ONION_DIR_REFRESH_SECS * 4 * 1000 * 1000)

static struct liveness_contract g_dir_contract;
static _Atomic supervisor_child_id g_dir_child = SUPERVISOR_INVALID_ID;
static _Atomic int64_t  g_dir_marker = 0;   /* cumulative rows written */
static _Atomic uint64_t g_dir_rounds = 0;

static void onion_directory_tick(struct liveness_contract *c)
{
    (void)c;
    supervisor_child_id id = atomic_load(&g_dir_child);
    struct onion_directory_refresh_stats st;
    bool ok = onion_service_directory_refresh(&st);
    atomic_fetch_add(&g_dir_rounds, 1);

    if (!ok) {
        /* Directory unopenable. Report NEITHER progress nor idle: this is
         * precisely the state the no-progress detector exists to surface,
         * and calling it idle would hide it forever. */
        supervisor_tick(id);
        return;
    }

    int touched = st.discovered + st.refreshed + st.expired;
    if (touched > 0) {
        int64_t marker = atomic_fetch_add(&g_dir_marker, touched) + touched;
        supervisor_progress(id, marker);
    } else {
        /* The round completed against a writable directory and there was
         * nothing to write: no source announced a peer, nothing aged out,
         * and Tor has not handed us an address to publish yet. Positively
         * established no-work, not a failure and not a skipped round. */
        supervisor_progress_idle(id);
    }
    supervisor_tick(id);
}

void onion_service_directory_register_refresh(void)
{
    if (atomic_load(&g_dir_child) != SUPERVISOR_INVALID_ID)
        return;
    liveness_contract_init(&g_dir_contract, "net.onion_directory");
    atomic_store(&g_dir_contract.period_secs, (int64_t)ONION_DIR_REFRESH_SECS);
    atomic_store(&g_dir_contract.deadline_secs, (int64_t)0);
    g_dir_contract.on_tick = onion_directory_tick;
    g_dir_contract.on_stall = NULL;
    /* A ROOT child, not supervisor_register_in_domain(net, ...): lib/net
     * cannot include the app-side supervisors/domains.h without a layering
     * violation — same reason the four connman threads are root children. */
    supervisor_child_id id = supervisor_register(&g_dir_contract);  // supervisor-root-ok:lib-net-cannot-include-app-domains
    atomic_store(&g_dir_child, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN(ODIR_LOG, "supervisor register failed (registry full)");
        return;
    }
    /* Count RESULTS, not activity: rounds that write nothing and report
     * nothing idle accumulate into a NO_PROGRESS stall. */
    supervisor_set_progress_max_quiet(id, ONION_DIR_MAX_QUIET_US);
}

void onion_service_directory_unregister_refresh(void)
{
    supervisor_child_id id = atomic_exchange(&g_dir_child, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
}


/* ── Boot and address-change entry points ─────────────────── */

void onion_directory_boot_round(void)
{
    sqlite3 *db = directory_open_rw();
    if (!db) {
        LOG_WARN(ODIR_LOG, "boot round: directory not open (no datadir)");
        return;
    }
    (void)populate_directory_from_chain(db);
    (void)register_self(db);
    /* Expire on the way in as well as on the tick: a node that has been
     * down for a week must not serve its pre-shutdown list as current
     * during the first refresh interval after boot. */
    (void)expire_directory_rows(db, (int64_t)platform_time_wall_time_t());
    sqlite3_close(db);
}

void onion_directory_register_self(void)
{
    sqlite3 *db = directory_open_rw();
    if (!db) {
        LOG_WARN(ODIR_LOG, "self-register: directory not open (no datadir)");
        return;
    }
    bool wrote = register_self(db);
    sqlite3_close(db);
    if (!wrote)
        return;
    const char *addr = onion_service_get_address();
    char addr_safe[96];
    log_json_escape(addr_safe, sizeof(addr_safe), addr ? addr : "");
    log_jsonf(LOG_JSON_INFO, "onion_self_registered",
              "\"address\":\"%s\"", addr_safe);
}
