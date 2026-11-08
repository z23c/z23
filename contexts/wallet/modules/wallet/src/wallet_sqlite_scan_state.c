/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet scan state in node_state.
 *
 * 'wallet_scan_height' is the height through which the wallet has read every
 * block. While a boot catch-up's range is unread it is written as
 * wallet_scanned_through_height(), never as best_block_height, and the
 * 'wallet_scan_incomplete' row records the unread start, the blocker, when it
 * was first seen, and the depth height: the best_block_height every stored
 * confirmation depth is measured from. Both rows are written by the flush in
 * its transaction, so the marker is cleared only together with the tx rows
 * of the rescan that read the range. The row is an additive key: a build
 * that does not know it reads the lower scan height and rescans from there. */

#include "base/serialize_le.h"
#include "models/database.h"
#include "wallet/wallet_sqlite.h"
#include "wallet_sqlite_internal.h"
#include "wallet/wallet.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WSS_MARKER_WRITE_SQL \
    "INSERT OR REPLACE INTO node_state(key,value)" \
    " VALUES('wallet_scan_incomplete',?)"
#define WSS_MARKER_CLEAR_SQL \
    "DELETE FROM node_state WHERE key='wallet_scan_incomplete'"
#define WSS_MARKER_READ_SQL \
    "SELECT value FROM node_state WHERE key='wallet_scan_incomplete'"
#define WSS_MARKER_UNREADABLE "WALLET_SCAN_MARKER_UNREADABLE"

static bool wss_write_marker(struct wallet_sqlite *ws, const struct wallet *w)
{
    char text[160];
    int n = snprintf(text, sizeof(text),
                     "from=%d depth=%d since=%" PRId64 " blocker=%s",
                     w->scan_retry.from, w->best_block_height,
                     w->scan_retry.since,
                     w->scan_retry.blocker[0] ? w->scan_retry.blocker : "-");
    sqlite3_stmt *s = NULL;
    if (n <= 0 || (size_t)n >= sizeof(text) ||
        sqlite3_prepare_v2(ws->db, w->scan_retry.pending
                               ? WSS_MARKER_WRITE_SQL : WSS_MARKER_CLEAR_SQL,
                           -1, &s, NULL) != SQLITE_OK || !s) {
        sqlite3_finalize(s);
        LOG_FAIL("wallet_sqlite", "write_scan_marker: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
    }
    if (w->scan_retry.pending)
        sqlite3_bind_text(s, 1, text, n, SQLITE_TRANSIENT);
    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    if (!ok)
        LOG_FAIL("wallet_sqlite", "write_scan_marker: step failed: %s",
                 sqlite3_errmsg(ws->db));
    return true;
}

bool wallet_sqlite_write_scan_state(struct wallet_sqlite *ws,
                                    const struct wallet *w)
{
    if (!ws || !ws->open || !w)
        LOG_FAIL("wallet_sqlite", "write_scan_state: not open");
    return wallet_sqlite_write_scan_height(
               ws, wallet_scanned_through_height(w)) &&
           wss_write_marker(ws, w);
}

/* A present row that does not parse still means "incomplete": report it
 * from height 0 with no depth height, so the caller rescans rather than
 * trusting a scan height the marker was written to qualify. */
static void wss_parse_marker(const unsigned char *text,
                             struct wallet_scan_marker *out)
{
    int64_t since = 0;
    if (text && sscanf((const char *)text,
                       "from=%d depth=%d since=%" SCNd64 " blocker=%47s",
                       &out->from, &out->depth_height, &since,
                       out->blocker) == 4) {
        out->since = since;
        return;
    }
    out->from = 0;
    out->depth_height = -1;
    out->since = 0;
    snprintf(out->blocker, sizeof(out->blocker), "%s", WSS_MARKER_UNREADABLE);
}

bool wallet_sqlite_read_scan_marker(struct wallet_sqlite *ws,
                                    struct wallet_scan_marker *out)
{
    if (!ws || !ws->open || !ws->db || !out)
        return false;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, WSS_MARKER_READ_SQL, -1, &s, NULL) !=
            SQLITE_OK || !s) {
        LOG_WARN("wallet_sqlite", "read_scan_marker: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
        sqlite3_finalize(s);
        return false;
    }
    bool present = ar_step_checked(s, "wallet scan state: read", NULL) == ZCL_STEP_ROW;
    if (present)
        wss_parse_marker(sqlite3_column_text(s, 0), out);
    sqlite3_finalize(s);
    return present;
}

static enum wallet_scan_state_status wss_checked_height(struct wallet_sqlite *ws, int *height)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key='wallet_scan_height'", -1, &s, NULL) != SQLITE_OK)
        return WALLET_SCAN_STATE_ERROR;
    int rc = AR_STEP_ROW_READONLY(s);
    enum wallet_scan_state_status status = WALLET_SCAN_STATE_ERROR;
    if (rc == SQLITE_DONE) status = WALLET_SCAN_STATE_ABSENT;
    else if (rc == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
             sqlite3_column_bytes(s, 0) == (int)sizeof(int32_t) && sqlite3_column_blob(s, 0)) {
        int32_t h; memcpy(&h, sqlite3_column_blob(s, 0), sizeof(h));
        if (h >= -1) { *height = h; status = WALLET_SCAN_STATE_OK; }
    }
    sqlite3_finalize(s);
    return status;
}

static bool wss_checked_number(const char **cursor, const char *prefix,
                               int64_t minimum, int64_t maximum, int64_t *out)
{
    size_t n = strlen(prefix);
    if (strncmp(*cursor, prefix, n)) return false;
    const char *start = *cursor + n;
    char *end = NULL;
    errno = 0;
    intmax_t value = strtoimax(start, &end, 10);
    if (errno || end == start || value < minimum || value > maximum) return false;
    *cursor = end; *out = (int64_t)value;
    return true;
}

static bool wss_checked_marker_value(sqlite3_stmt *s, struct wallet_scan_marker *m)
{
    if (sqlite3_column_type(s, 0) != SQLITE_TEXT) return false;
    const unsigned char *text = sqlite3_column_text(s, 0);
    int len = sqlite3_column_bytes(s, 0);
    if (!text || len <= 0 || len >= 160 || memchr(text, 0, (size_t)len)) return false;
    const char *p = (const char *)text;
    int64_t from, depth, since;
    if (!wss_checked_number(&p, "from=", 0, INT_MAX, &from) ||
        !wss_checked_number(&p, " depth=", -1, INT_MAX, &depth) ||
        !wss_checked_number(&p, " since=", 0, INT64_MAX, &since) ||
        strncmp(p, " blocker=", 9)) return false;
    p += 9;
    size_t left = (size_t)((const char *)text + len - p);
    if (!left || left >= sizeof(m->blocker) || strpbrk(p, " \t\r\n")) return false;
    m->from = (int)from; m->depth_height = (int)depth; m->since = since;
    memcpy(m->blocker, p, left); m->blocker[left] = 0;
    return true;
}

static enum wallet_scan_state_status wss_checked_marker(struct wallet_sqlite *ws, struct wallet_scan_marker *m)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, WSS_MARKER_READ_SQL, -1, &s, NULL) != SQLITE_OK) return WALLET_SCAN_STATE_ERROR;
    int rc = AR_STEP_ROW_READONLY(s);
    enum wallet_scan_state_status status = rc == SQLITE_DONE ? WALLET_SCAN_STATE_ABSENT : WALLET_SCAN_STATE_ERROR;
    if (rc == SQLITE_ROW && wss_checked_marker_value(s, m)) status = WALLET_SCAN_STATE_OK;
    sqlite3_finalize(s);
    return status;
}

static void wss_apply_checked(struct wallet *w, enum wallet_height_encoding encoding,
                              enum wallet_scan_state_status hs, int height, int reference,
                              enum wallet_scan_state_status ms, const struct wallet_scan_marker *marker)
{
    if (encoding == WALLET_HEIGHT_V2) w->best_block_height = reference;
    else if (hs == WALLET_SCAN_STATE_OK) w->best_block_height = height;
    memset(&w->scan_retry, 0, sizeof(w->scan_retry));
    if (ms != WALLET_SCAN_STATE_OK) return;
    w->scan_retry.pending = true; w->scan_retry.from = marker->from; w->scan_retry.since = marker->since;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s", marker->blocker);
    if (encoding == WALLET_HEIGHT_LEGACY && height < marker->from && marker->depth_height > height)
        w->best_block_height = marker->depth_height;
}

struct wss_checked_state {
    enum wallet_height_encoding encoding;
    enum wallet_scan_state_status height_status, marker_status;
    int reference, height;
    struct wallet_scan_marker marker;
};

static enum wallet_scan_state_status wss_checked_snapshot(struct wallet_sqlite *ws,
                                                           struct wss_checked_state *state)
{
    if (!ws || !ws->open || !ws->db || !state) return WALLET_SCAN_STATE_ERROR;
    memset(state, 0, sizeof(*state));
    state->encoding = wallet_sqlite_height_encoding(ws, &state->reference);
    state->height_status = wss_checked_height(ws, &state->height);
    state->marker_status = wss_checked_marker(ws, &state->marker);
    if (state->encoding == WALLET_HEIGHT_ERROR || state->height_status == WALLET_SCAN_STATE_ERROR ||
        state->marker_status == WALLET_SCAN_STATE_ERROR ||
        (state->encoding == WALLET_HEIGHT_V2 && state->height_status == WALLET_SCAN_STATE_ABSENT))
        return WALLET_SCAN_STATE_ERROR;
    return state->height_status == WALLET_SCAN_STATE_ABSENT && state->marker_status == WALLET_SCAN_STATE_ABSENT ?
        WALLET_SCAN_STATE_ABSENT : WALLET_SCAN_STATE_OK;
}

enum wallet_scan_state_status wallet_sqlite_validate_scan_state(struct wallet_sqlite *ws)
{
    struct wss_checked_state state;
    return wss_checked_snapshot(ws, &state);
}

static bool wss_snapshot_begin(struct wallet_sqlite *ws, sqlite3_mutex **out)
{
    sqlite3_mutex *mutex = sqlite3_db_mutex(ws->db);
    if (!mutex || sqlite3_mutex_try(mutex) != SQLITE_OK) return false;
    if (!sqlite3_get_autocommit(ws->db)) { sqlite3_mutex_leave(mutex); return false; }
    if (sqlite3_exec(ws->db, "SAVEPOINT wallet_scan_snapshot", NULL, NULL, NULL) != SQLITE_OK) {
        if (!sqlite3_get_autocommit(ws->db)) abort();
        sqlite3_mutex_leave(mutex); return false;
    }
    *out = mutex;
    return true;
}

enum wallet_scan_state_status wallet_sqlite_read_scan_state_checked(struct wallet_sqlite *ws, struct wallet *w)
{
    if (!ws || !ws->open || !ws->db || !w) return WALLET_SCAN_STATE_ERROR;
    sqlite3_mutex *mutex = NULL;
    if (!wss_snapshot_begin(ws, &mutex)) return WALLET_SCAN_STATE_ERROR;
    struct wss_checked_state state;
    enum wallet_scan_state_status status = wss_checked_snapshot(ws, &state);
    bool held = status == WALLET_SCAN_STATE_OK && zcl_mutex_trylock(&w->cs);
    if (status == WALLET_SCAN_STATE_OK && !held) status = WALLET_SCAN_STATE_ERROR;
    if (!wsql_snapshot_release(ws->db, WSQL_SNAPSHOT_SCAN)) status = WALLET_SCAN_STATE_ERROR;
    if (status == WALLET_SCAN_STATE_OK)
        wss_apply_checked(w, state.encoding, state.height_status, state.height, state.reference,
                          state.marker_status, &state.marker);
    if (held) zcl_mutex_unlock(&w->cs);
    sqlite3_mutex_leave(mutex);
    return status;
}

bool wallet_sqlite_read_scan_state(struct wallet_sqlite *ws, struct wallet *w)
{
    if (!w)
        return false;
    int reference = 0;
    enum wallet_height_encoding encoding = wallet_sqlite_height_encoding(ws, &reference);
    if (encoding == WALLET_HEIGHT_ERROR) return false;
    if (encoding == WALLET_HEIGHT_V2) w->best_block_height = reference;
    int height = 0;
    bool have_height = wallet_sqlite_read_scan_height(ws, &height);
    if (have_height && encoding == WALLET_HEIGHT_LEGACY)
        w->best_block_height = height;
    memset(&w->scan_retry, 0, sizeof(w->scan_retry));
    struct wallet_scan_marker m;
    if (!wallet_sqlite_read_scan_marker(ws, &m))
        return have_height;
    w->scan_retry.pending = true;
    w->scan_retry.from = m.from > 0 ? m.from : 0;
    w->scan_retry.since = m.since;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "%s",
             m.blocker);
    /* Stored depths are measured from the depth height, which this build
     * writes only while the scan height sits below `from`. A scan height at
     * or past `from` came from a build that does not know the marker, and
     * its depths follow that scan height. */
    if (encoding == WALLET_HEIGHT_LEGACY && height < w->scan_retry.from && m.depth_height > height)
        w->best_block_height = m.depth_height;
    LOG_WARN("wallet", "%s: wallet scanned through %d only since %" PRId64
             "; this boot rescans from %d", w->scan_retry.blocker,
             wallet_scanned_through_height(w), w->scan_retry.since,
             w->scan_retry.from);
    return have_height;
}

/* Version 1 is the original 114-byte binding. Version 2 appends the whole
 * snapshot digest and history-manifest root without changing the prefix. */
#define WSS_BINDING_V1_BYTES 114
#define WSS_BINDING_BYTES 178
static size_t wss_binding_size(const struct wallet_cutover_binding *b)
{ return b->history_identity_present ? WSS_BINDING_BYTES : WSS_BINDING_V1_BYTES; }
static bool wss_encode(const struct wallet_cutover_binding *b, uint8_t *p)
{
    static const uint8_t zero[32];
    if (!b || b->old_height < -1 || b->target_height < 0 ||
        (!b->old_generation_present && b->old_generation != 0) ||
        (!b->history_identity_present && (memcmp(b->snapshot_whole_sha3, zero, 32) ||
                                          memcmp(b->history_manifest_root, zero, 32)))) return false;
    p[0] = b->history_identity_present ? 2 : 1; p[1] = b->old_generation_present ? 1 : 0;
    zcl_write_u64_le(p + 2, b->old_generation);
    zcl_write_u32_le(p + 10, (uint32_t)b->old_height);
    zcl_write_u32_le(p + 14, (uint32_t)b->target_height);
    memcpy(p + 18, b->old_hash, 32); memcpy(p + 50, b->target_hash, 32);
    memcpy(p + 82, b->artifact_digest, 32);
    if (b->history_identity_present) {
        memcpy(p + 114, b->snapshot_whole_sha3, 32);
        memcpy(p + 146, b->history_manifest_root, 32);
    }
    return true;
}
static bool wss_decode(const uint8_t *p, int len, struct wallet_cutover_binding *b)
{
    if (!p || !b || !((len == WSS_BINDING_V1_BYTES && p[0] == 1) ||
                       (len == WSS_BINDING_BYTES && p[0] == 2)) || p[1] > 1 ||
        (zcl_read_u32_le(p + 10) > INT32_MAX && zcl_read_u32_le(p + 10) != UINT32_MAX) || zcl_read_u32_le(p + 14) > INT32_MAX ||
        (!p[1] && zcl_read_u64_le(p + 2) != 0)) return false;
    memset(b, 0, sizeof(*b)); b->old_generation_present = p[1] != 0;
    b->old_generation = zcl_read_u64_le(p + 2);
    b->old_height = zcl_read_u32_le(p + 10) == UINT32_MAX ? -1 : (int32_t)zcl_read_u32_le(p + 10);
    b->target_height = (int32_t)zcl_read_u32_le(p + 14);
    memcpy(b->old_hash, p + 18, 32); memcpy(b->target_hash, p + 50, 32);
    memcpy(b->artifact_digest, p + 82, 32);
    b->history_identity_present = p[0] == 2;
    if (b->history_identity_present) {
        memcpy(b->snapshot_whole_sha3, p + 114, 32);
        memcpy(b->history_manifest_root, p + 146, 32);
    }
    return true;
}
/* DISCOVER version 2 extends its binding and shifts later fields by 64. */
#define WSS_DISCOVER_V1_BYTES 304
#define WSS_DISCOVER_BYTES 368
static bool wss_discover_encode(const struct wallet_discover_checkpoint *c, uint8_t *p, size_t *size)
{
    if (!c || !wss_encode(&c->binding, p + 1) ||
        (!c->generation_present && c->generation != 0) || c->floor < 0 ||
        c->next_height < c->floor || c->endpoint_height < c->next_height ||
        c->endpoint_height < c->binding.target_height) return false;
    size_t d = c->binding.history_identity_present ? 64 : 0;
    *size = WSS_DISCOVER_V1_BYTES + d;
    p[0] = d ? 2 : 1; p[115 + d] = c->generation_present ? 1 : 0;
    zcl_write_u64_le(p + 116 + d, c->generation);
    zcl_write_u32_le(p + 124 + d, (uint32_t)c->floor);
    zcl_write_u32_le(p + 128 + d, (uint32_t)c->next_height);
    zcl_write_u32_le(p + 132 + d, (uint32_t)c->endpoint_height);
    memcpy(p + 136 + d, c->endpoint_hash, 32); memcpy(p + 168 + d, c->endpoint_root, 32);
    memcpy(p + 200 + d, c->scan_identity, 32); memcpy(p + 232 + d, c->key_digest, 32);
    zcl_write_u64_le(p + 264 + d, c->event_end); memcpy(p + 272 + d, c->event_digest, 32);
    return true;
}
static bool wss_discover_header(const uint8_t *p, int size, size_t *delta,
                                struct wallet_cutover_binding *binding)
{
    if (!p || !((size == WSS_DISCOVER_V1_BYTES && p[0] == 1) ||
                (size == WSS_DISCOVER_BYTES && p[0] == 2))) return false;
    *delta = p[0] == 2 ? 64 : 0;
    return wss_decode(p + 1, (int)(WSS_BINDING_V1_BYTES + *delta), binding) &&
           binding->history_identity_present == (*delta != 0);
}
static bool wss_discover_decode(const uint8_t *p, int size, struct wallet_discover_checkpoint *out)
{
    struct wallet_discover_checkpoint c = {0};
    size_t d = 0;
    if (!wss_discover_header(p, size, &d, &c.binding)) return false;
    if (p[115 + d] > 1 ||
        (!p[115 + d] && zcl_read_u64_le(p + 116 + d)) ||
        zcl_read_u32_le(p + 124 + d) > INT32_MAX || zcl_read_u32_le(p + 128 + d) > INT32_MAX ||
        zcl_read_u32_le(p + 132 + d) > INT32_MAX) return false;
    c.generation_present = p[115 + d] != 0; c.generation = zcl_read_u64_le(p + 116 + d);
    c.floor = (int32_t)zcl_read_u32_le(p + 124 + d);
    c.next_height = (int32_t)zcl_read_u32_le(p + 128 + d);
    c.endpoint_height = (int32_t)zcl_read_u32_le(p + 132 + d);
    if (c.next_height < c.floor || c.endpoint_height < c.next_height ||
        c.endpoint_height < c.binding.target_height) return false;
    memcpy(c.endpoint_hash, p + 136 + d, 32); memcpy(c.endpoint_root, p + 168 + d, 32);
    memcpy(c.scan_identity, p + 200 + d, 32); memcpy(c.key_digest, p + 232 + d, 32);
    c.event_end = zcl_read_u64_le(p + 264 + d); memcpy(c.event_digest, p + 272 + d, 32);
    *out = c; return true;
}
bool wallet_sqlite_discover_checkpoint_save(struct wallet_sqlite *ws,
    const struct wallet_discover_checkpoint *checkpoint)
{
    uint8_t bytes[WSS_DISCOVER_BYTES]; size_t encoded = 0; struct wallet_cutover_binding current;
    if (!ws || !ws->open || !ws->db || sqlite3_get_autocommit(ws->db) ||
        !wss_discover_encode(checkpoint, bytes, &encoded) ||
        wallet_sqlite_cutover_read(ws, &current) != WALLET_CUTOVER_PENDING ||
        !wallet_cutover_binding_equal(&current, &checkpoint->binding)) return false;
    sqlite3_stmt *s = NULL;
    const char *sql = "INSERT INTO node_state(key,value) VALUES('wallet_discover_checkpoint',?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value";
    if (sqlite3_prepare_v2(ws->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, bytes, (int)encoded, SQLITE_TRANSIENT) == SQLITE_OK &&
              AR_STEP_WRITE(s) == SQLITE_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}
enum wallet_discover_checkpoint_status wallet_sqlite_discover_checkpoint_read(
    struct wallet_sqlite *ws, struct wallet_discover_checkpoint *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!ws || !ws->open || !ws->db || !out) return WALLET_DISCOVER_IO_ERROR;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key='wallet_discover_checkpoint'",
                           -1, &s, NULL) != SQLITE_OK) return WALLET_DISCOVER_IO_ERROR;
    int rc = AR_STEP_ROW_READONLY(s);
    enum wallet_discover_checkpoint_status status = WALLET_DISCOVER_IO_ERROR;
    if (rc == SQLITE_DONE) status = WALLET_DISCOVER_ABSENT;
    else if (rc == SQLITE_ROW) {
        status = sqlite3_column_type(s, 0) == SQLITE_BLOB &&
            wss_discover_decode(sqlite3_column_blob(s, 0), sqlite3_column_bytes(s, 0), out)
                ? WALLET_DISCOVER_FOUND : WALLET_DISCOVER_MALFORMED;
        if (ar_step_checked(s, "wallet discover checkpoint: read completion", NULL) != ZCL_STEP_DONE)
            status = WALLET_DISCOVER_IO_ERROR;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) status = WALLET_DISCOVER_IO_ERROR;
    if (status != WALLET_DISCOVER_FOUND) memset(out, 0, sizeof(*out));
    return status;
}

static bool wss_decimal(const char *text, int64_t min, int64_t max, int64_t *out)
{
    char *end = NULL;
    errno = 0;
    long long v = strtoll(text, &end, 10);
    if (errno || !end || *end || end == text || v < min || v > max) return false;
    *out = (int64_t)v;
    return true;
}
static bool wss_marker_valid(const unsigned char *p, int bytes)
{
    char from[24], depth[24], since[24], blocker[48], canonical[160];
    int end = 0; int64_t a, b, c;
    if (!p || bytes <= 0 || bytes >= (int)sizeof(canonical) ||
        (int)strlen((const char *)p) != bytes ||
        sscanf((const char *)p, "from=%23s depth=%23s since=%23s blocker=%47s%n",
               from, depth, since, blocker, &end) != 4 || end != bytes ||
        !wss_decimal(from, 0, INT_MAX, &a) ||
        !wss_decimal(depth, -1, INT_MAX, &b) ||
        !wss_decimal(since, 0, INT64_MAX, &c)) return false;
    int n = snprintf(canonical, sizeof(canonical),
                     "from=%" PRId64 " depth=%" PRId64 " since=%" PRId64 " blocker=%s",
                     a, b, c, blocker);
    return n == bytes && memcmp(p, canonical, (size_t)n) == 0;
}

static enum wallet_cutover_floor_status wss_floor_row(sqlite3_stmt *s, int *floor)
{
    bool height_present = sqlite3_column_int(s, 1) != 0;
    bool marker_present = sqlite3_column_int(s, 3) != 0;
    if (!height_present && !marker_present) {
        *floor = 0;
        return WALLET_CUTOVER_FLOOR_ABSENT;
    }
    if (!height_present || sqlite3_column_type(s, 0) != SQLITE_BLOB ||
        sqlite3_column_bytes(s, 0) != 4 || !sqlite3_column_blob(s, 0))
        return WALLET_CUTOVER_FLOOR_MALFORMED;
    int32_t height; memcpy(&height, sqlite3_column_blob(s, 0), sizeof(height));
    int marker_type = sqlite3_column_type(s, 2);
    const unsigned char *marker = marker_type == SQLITE_TEXT ? sqlite3_column_text(s, 2) : NULL;
    if (height < -1 || height >= INT32_MAX ||
        (marker_present && (marker_type != SQLITE_TEXT ||
         !wss_marker_valid(marker, sqlite3_column_bytes(s, 2)))))
        return WALLET_CUTOVER_FLOOR_MALFORMED;
    *floor = height + 1;
    if (marker_present) {
        struct wallet_scan_marker m; wss_parse_marker(marker, &m);
        if (m.from < *floor) *floor = m.from;
    }
    return WALLET_CUTOVER_FLOOR_FOUND;
}

static void wss_set_pending_floor(struct wallet *w, int floor)
{
    if (w->scan_retry.pending && w->scan_retry.from < floor) floor = w->scan_retry.from;
    w->scan_retry.pending = true; w->scan_retry.from = floor;
    if (w->scan_retry.since < 0) w->scan_retry.since = 0;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "WALLET_CUTOVER_PENDING");
}

enum wallet_cutover_floor_status wallet_sqlite_cutover_scan_floor(
    struct wallet_sqlite *ws, int *floor)
{
    if (!ws || !ws->open || !ws->db || !floor) return WALLET_CUTOVER_FLOOR_IO_ERROR;
    const char *sql = "SELECT (SELECT value FROM node_state WHERE key='wallet_scan_height'),"
        "EXISTS(SELECT 1 FROM node_state WHERE key='wallet_scan_height'),"
        "(SELECT value FROM node_state WHERE key='wallet_scan_incomplete'),"
        "EXISTS(SELECT 1 FROM node_state WHERE key='wallet_scan_incomplete')";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, sql, -1, &s, NULL) != SQLITE_OK)
        return WALLET_CUTOVER_FLOOR_IO_ERROR;
    enum wallet_cutover_floor_status status = WALLET_CUTOVER_FLOOR_IO_ERROR;
    if (ar_step_checked(s, "wallet scan state: read", NULL) == ZCL_STEP_ROW) {
        status = wss_floor_row(s, floor);
        if (ar_step_checked(s, "wallet scan state: read completion", NULL) != ZCL_STEP_DONE) status = WALLET_CUTOVER_FLOOR_IO_ERROR;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) return WALLET_CUTOVER_FLOOR_IO_ERROR;
    return status;
}

/* Caller holds w->cs. The outer savepoint makes cursor evidence and both
 * pending rows one transaction; a nested caller still owns durability. */
bool wallet_sqlite_cutover_prepare_preserving_cursor(struct wallet_sqlite *ws,
    struct wallet *w, const struct wallet_cutover_binding *binding)
{
    if (!ws || !ws->open || !ws->db || !w || !binding) return false;
    if (sqlite3_exec(ws->db, "SAVEPOINT wallet_cutover_floor", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_ERROR("wallet_sqlite", "cutover cursor savepoint failed: %s", sqlite3_errmsg(ws->db));
        return false;
    }
    int floor = 0;
    enum wallet_cutover_floor_status s = wallet_sqlite_cutover_scan_floor(ws, &floor);
    bool ok = s == WALLET_CUTOVER_FLOOR_FOUND || s == WALLET_CUTOVER_FLOOR_ABSENT;
    if (ok) {
        wss_set_pending_floor(w, floor);
        ok = wallet_sqlite_cutover_prepare(ws, w, binding);
    }
    if (ok) {
        if (sqlite3_exec(ws->db, "RELEASE wallet_cutover_floor", NULL, NULL, NULL) == SQLITE_OK)
            return true;
        LOG_ERROR("wallet_sqlite", "cutover cursor release failed: %s", sqlite3_errmsg(ws->db));
    }
    if (sqlite3_exec(ws->db, "ROLLBACK TO wallet_cutover_floor", NULL, NULL, NULL) != SQLITE_OK)
        LOG_ERROR("wallet_sqlite", "cutover cursor rollback failed: %s", sqlite3_errmsg(ws->db));
    if (sqlite3_exec(ws->db, "RELEASE wallet_cutover_floor", NULL, NULL, NULL) != SQLITE_OK)
        LOG_ERROR("wallet_sqlite", "cutover cursor release failed: %s", sqlite3_errmsg(ws->db));
    return false;
}
bool wallet_cutover_binding_equal(const struct wallet_cutover_binding *a,
                                   const struct wallet_cutover_binding *b)
{
    return a->old_generation_present == b->old_generation_present &&
        a->old_generation == b->old_generation && a->old_height == b->old_height &&
        a->target_height == b->target_height &&
        memcmp(a->old_hash, b->old_hash, 32) == 0 &&
        memcmp(a->target_hash, b->target_hash, 32) == 0 &&
        memcmp(a->artifact_digest, b->artifact_digest, 32) == 0 &&
        a->history_identity_present == b->history_identity_present &&
        (!a->history_identity_present ||
         (!memcmp(a->snapshot_whole_sha3, b->snapshot_whole_sha3, 32) &&
          !memcmp(a->history_manifest_root, b->history_manifest_root, 32)));
}


enum wallet_cutover_status wallet_sqlite_cutover_read(
    struct wallet_sqlite *ws, struct wallet_cutover_binding *out)
{
    if (!ws || !ws->open || !ws->db || !out) return WALLET_CUTOVER_IO_ERROR;
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT value,(SELECT value FROM node_state WHERE key="
        "'wallet_scan_incomplete') FROM node_state WHERE key='wallet_cutover_binding'";
    if (sqlite3_prepare_v2(ws->db, sql, -1, &s, NULL) != SQLITE_OK)
        return WALLET_CUTOVER_IO_ERROR;
    int rc = AR_STEP_ROW_READONLY(s);
    enum wallet_cutover_status status = WALLET_CUTOVER_IO_ERROR;
    if (rc == SQLITE_DONE) status = WALLET_CUTOVER_ABSENT;
    else if (rc == SQLITE_ROW) {
        status = sqlite3_column_type(s, 0) == SQLITE_BLOB &&
                 sqlite3_column_type(s, 1) == SQLITE_TEXT &&
                 wss_marker_valid(sqlite3_column_text(s, 1), sqlite3_column_bytes(s, 1)) &&
                 wss_decode(sqlite3_column_blob(s, 0), sqlite3_column_bytes(s, 0), out)
                     ? WALLET_CUTOVER_PENDING : WALLET_CUTOVER_MALFORMED;
        if (ar_step_checked(s, "wallet scan state: read completion", NULL) != ZCL_STEP_DONE) status = WALLET_CUTOVER_IO_ERROR;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) return WALLET_CUTOVER_IO_ERROR;
    return status;
}
enum wallet_cutover_status wallet_sqlite_cutover_read_snapshot(sqlite3 *db)
{
    if (!db || !sqlite3_get_autocommit(db) ||
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        return WALLET_CUTOVER_IO_ERROR;
    struct wallet_sqlite ws = {.db = db, .open = true};
    struct wallet_cutover_binding binding;
    enum wallet_cutover_status status = wallet_sqlite_cutover_read(&ws, &binding);
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_WARN("wallet_recovery", "status snapshot rollback failed: %s", sqlite3_errmsg(db));
        return WALLET_CUTOVER_IO_ERROR;
    }
    return status;
}

static bool wss_authority_pending(sqlite3_stmt *s, struct wallet_cutover_binding *value)
{
    return sqlite3_column_type(s, 0) == SQLITE_BLOB && sqlite3_column_type(s, 2) == SQLITE_TEXT &&
        wss_marker_valid(sqlite3_column_text(s, 2), sqlite3_column_bytes(s, 2)) &&
        wss_decode(sqlite3_column_blob(s, 0), sqlite3_column_bytes(s, 0), value);
}
static bool wss_authority_completed(sqlite3_stmt *s, struct wallet_cutover_binding *value)
{
    return sqlite3_column_type(s, 4) == SQLITE_BLOB &&
        wss_decode(sqlite3_column_blob(s, 4), sqlite3_column_bytes(s, 4), value) &&
        value->history_identity_present;
}
static bool wss_authority_mismatch(enum wallet_cutover_authority_status status,
    const struct wallet_cutover_binding *expected, const struct wallet_cutover_binding *value)
{
    if (status != WALLET_CUTOVER_AUTH_PENDING && status != WALLET_CUTOVER_AUTH_COMPLETED) return false;
    if (!expected) return status == WALLET_CUTOVER_AUTH_COMPLETED;
    return !wallet_cutover_binding_equal(expected, value);
}
static bool wss_authority_schema(sqlite3_stmt *s)
{
    int32_t version = 0, floor = 0;
    if (sqlite3_column_type(s, 6) != SQLITE_BLOB || sqlite3_column_bytes(s, 6) != (int)sizeof(version) ||
        sqlite3_column_type(s, 7) != SQLITE_BLOB || sqlite3_column_bytes(s, 7) != (int)sizeof(floor) ||
        !sqlite3_column_blob(s, 6) || !sqlite3_column_blob(s, 7)) return false;
    memcpy(&version, sqlite3_column_blob(s, 6), sizeof(version));
    memcpy(&floor, sqlite3_column_blob(s, 7), sizeof(floor));
    return version == NODE_DB_SCHEMA_LATEST && floor >= WALLET_BOUND_CUTOVER_SCHEMA_VERSION && floor <= version;
}
static enum wallet_cutover_authority_status wss_authority_row(sqlite3_stmt *s,
    const struct wallet_cutover_binding *expected, struct wallet_cutover_binding *value, bool observe)
{
    bool pending = sqlite3_column_int(s, 1) != 0;
    bool marker = sqlite3_column_int(s, 3) != 0;
    bool completed = sqlite3_column_int(s, 5) != 0;
    enum wallet_cutover_authority_status status = WALLET_CUTOVER_AUTH_MALFORMED;
    if (!pending && !completed) return WALLET_CUTOVER_AUTH_ABSENT;
    if (pending && !completed && marker && wss_authority_pending(s, value))
        status = WALLET_CUTOVER_AUTH_PENDING;
    else if (completed && !pending && !marker && wss_authority_completed(s, value))
        status = WALLET_CUTOVER_AUTH_COMPLETED;
    if (value->history_identity_present && !wss_authority_schema(s))
        return WALLET_CUTOVER_AUTH_MALFORMED;
    if (!observe && wss_authority_mismatch(status, expected, value))
        status = WALLET_CUTOVER_AUTH_MISMATCH;
    return status;
}
static enum wallet_cutover_authority_status wss_authority_read(
    struct wallet_sqlite *ws, const struct wallet_cutover_binding *expected,
    struct wallet_cutover_binding *out, bool observe)
{
    struct wallet_cutover_binding wanted;
    if (expected) { wanted = *expected; expected = &wanted; }
    if (out) memset(out, 0, sizeof(*out));
    if (!ws || !ws->open || !ws->db || !out) return WALLET_CUTOVER_AUTH_IO_ERROR;
    static const char sql[] =
        "SELECT (SELECT value FROM node_state WHERE key='wallet_cutover_binding'),"
        "EXISTS(SELECT 1 FROM node_state WHERE key='wallet_cutover_binding'),"
        "(SELECT value FROM node_state WHERE key='wallet_scan_incomplete'),"
        "EXISTS(SELECT 1 FROM node_state WHERE key='wallet_scan_incomplete'),"
        "(SELECT value FROM node_state WHERE key='wallet_cutover_completed'),"
        "EXISTS(SELECT 1 FROM node_state WHERE key='wallet_cutover_completed'),"
        "(SELECT value FROM node_state WHERE key='schema_version'),"
        "(SELECT value FROM node_state WHERE key='schema_compat_floor')";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, sql, -1, &s, NULL) != SQLITE_OK)
        return WALLET_CUTOVER_AUTH_IO_ERROR;
    enum wallet_cutover_authority_status status = WALLET_CUTOVER_AUTH_IO_ERROR;
    struct wallet_cutover_binding value = {0};
    if (ar_step_checked(s, "wallet cutover authority: read", NULL) == ZCL_STEP_ROW) {
        status = wss_authority_row(s, expected, &value, observe);
        if (ar_step_checked(s, "wallet cutover authority: read completion", NULL) != ZCL_STEP_DONE)
            status = WALLET_CUTOVER_AUTH_IO_ERROR;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) status = WALLET_CUTOVER_AUTH_IO_ERROR;
    if (status == WALLET_CUTOVER_AUTH_PENDING || status == WALLET_CUTOVER_AUTH_COMPLETED) *out = value;
    return status;
}

enum wallet_cutover_authority_status wallet_sqlite_cutover_authority_read(
    struct wallet_sqlite *ws, const struct wallet_cutover_binding *expected,
    struct wallet_cutover_binding *out)
{
    return wss_authority_read(ws, expected, out, false);
}

enum wallet_cutover_observation_status wallet_sqlite_cutover_observe_completed(
    struct wallet_sqlite *ws, struct wallet_cutover_binding *out)
{
    struct wallet_cutover_binding value = {0};
    if (out) memset(out, 0, sizeof(*out));
    if (!out) return WALLET_CUTOVER_OBS_IO_ERROR;
    enum wallet_cutover_authority_status status = wss_authority_read(ws, NULL, &value, true);
    if (status == WALLET_CUTOVER_AUTH_COMPLETED) { *out = value; return WALLET_CUTOVER_OBS_FOUND; }
    if (status == WALLET_CUTOVER_AUTH_ABSENT) return WALLET_CUTOVER_OBS_ABSENT;
    if (status == WALLET_CUTOVER_AUTH_PENDING) return WALLET_CUTOVER_OBS_PENDING;
    if (status == WALLET_CUTOVER_AUTH_MALFORMED) return WALLET_CUTOVER_OBS_MALFORMED;
    return WALLET_CUTOVER_OBS_IO_ERROR;
}
static bool wss_delete_completed(struct wallet_sqlite *ws)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "DELETE FROM node_state WHERE key='wallet_cutover_completed'", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

/* The caller owns the cutover savepoint. The compatibility floor must rise in
 * that same transaction before any bound binding becomes visible. */
static bool wss_schema_value(struct wallet_sqlite *ws, const char *key, int32_t *value)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "SELECT value FROM node_state WHERE key=?", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC) == SQLITE_OK &&
        ar_step_checked(s, "wallet cutover schema: read", NULL) == ZCL_STEP_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(s, 0) == (int)sizeof(*value) && sqlite3_column_blob(s, 0);
    if (ok) memcpy(value, sqlite3_column_blob(s, 0), sizeof(*value));
    if (ok) ok = ar_step_checked(s, "wallet cutover schema: read completion", NULL) == ZCL_STEP_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}
static bool wss_bound_floor(struct wallet_sqlite *ws)
{
    int32_t version = 0, floor = 0;
    if (!wss_schema_value(ws, "schema_version", &version) ||
        !wss_schema_value(ws, "schema_compat_floor", &floor) ||
        version != NODE_DB_SCHEMA_LATEST || version < WALLET_BOUND_CUTOVER_SCHEMA_VERSION ||
        floor < 0 || floor > version) return false;
    if (floor >= WALLET_BOUND_CUTOVER_SCHEMA_VERSION) return true;
    int32_t next = WALLET_BOUND_CUTOVER_SCHEMA_VERSION;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db, "UPDATE node_state SET value=? WHERE key='schema_compat_floor'", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, &next, sizeof(next), SQLITE_TRANSIENT) == SQLITE_OK &&
              AR_STEP_WRITE(s) == SQLITE_DONE && sqlite3_changes(ws->db) == 1;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool wss_binding_insert(struct wallet_sqlite *ws, const struct wallet *w,
                               const uint8_t bytes[WSS_BINDING_BYTES], size_t size)
{
    sqlite3_stmt *s = NULL;
    bool ok = (size != WSS_BINDING_BYTES || wss_bound_floor(ws)) &&
        wallet_sqlite_write_scan_state(ws, w) && wss_delete_completed(ws) &&
        sqlite3_prepare_v2(ws->db, "INSERT INTO node_state(key,value) VALUES('wallet_cutover_binding',?)", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(s, 1, bytes, (int)size, SQLITE_TRANSIENT) == SQLITE_OK &&
        AR_STEP_WRITE(s) == SQLITE_DONE;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool wss_binding_matches_scan(struct wallet_sqlite *ws, const struct wallet *w)
{
    struct wallet_cutover_binding binding;
    struct wallet_scan_marker marker;
    int height = 0;
    return wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        wallet_sqlite_read_scan_height(ws, &height) &&
        height == wallet_scanned_through_height(w) &&
        wallet_sqlite_read_scan_marker(ws, &marker) &&
        marker.from == w->scan_retry.from && marker.depth_height == w->best_block_height;
}

static bool wss_binding_compatible(enum wallet_cutover_status status,
    const struct wallet_cutover_binding *old, const struct wallet_cutover_binding *binding)
{
    return status == WALLET_CUTOVER_ABSENT ||
        (status == WALLET_CUTOVER_PENDING && wallet_cutover_binding_equal(old, binding));
}

static bool wss_cutover_prepare(struct wallet_sqlite *ws,
    const struct wallet *w, const struct wallet_cutover_binding *binding)
{
    uint8_t bytes[WSS_BINDING_BYTES];
    struct wallet_cutover_binding old;
    if (!ws || !ws->open || !ws->db || !w || !w->scan_retry.pending ||
        !wss_encode(binding, bytes)) return false;
    if (sqlite3_exec(ws->db, "SAVEPOINT wallet_cutover", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_ERROR("wallet_sqlite", "cutover savepoint failed: %s", sqlite3_errmsg(ws->db));
        return false;
    }
    enum wallet_cutover_status status = wallet_sqlite_cutover_read(ws, &old);
    bool ok = wss_binding_compatible(status, &old, binding);
    if (ok && status == WALLET_CUTOVER_ABSENT)
        ok = wss_binding_insert(ws, w, bytes, wss_binding_size(binding));
    if (ok) ok = wss_binding_matches_scan(ws, w);
    if (ok) {
        if (sqlite3_exec(ws->db, "RELEASE wallet_cutover", NULL, NULL, NULL) == SQLITE_OK)
            return true;
        LOG_ERROR("wallet_sqlite", "cutover savepoint release failed: %s", sqlite3_errmsg(ws->db));
    }
    if (sqlite3_exec(ws->db, "ROLLBACK TO wallet_cutover", NULL, NULL, NULL) != SQLITE_OK)
        LOG_ERROR("wallet_sqlite", "cutover savepoint rollback failed: %s", sqlite3_errmsg(ws->db));
    if (sqlite3_exec(ws->db, "RELEASE wallet_cutover", NULL, NULL, NULL) != SQLITE_OK)
        LOG_ERROR("wallet_sqlite", "cutover savepoint release failed: %s", sqlite3_errmsg(ws->db));
    return false;
}

bool wallet_sqlite_cutover_prepare(struct wallet_sqlite *ws,
    const struct wallet *w, const struct wallet_cutover_binding *binding)
{
    return binding && !binding->history_identity_present && wss_cutover_prepare(ws, w, binding);
}

static bool wss_bound_finish(sqlite3 *db, bool own, bool ok)
{
    if (ok) ok = sqlite3_exec(db, "RELEASE wallet_bound_prepare", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) {
        if (sqlite3_exec(db, "ROLLBACK TO wallet_bound_prepare", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet_sqlite", "bound cutover savepoint rollback failed: %s", sqlite3_errmsg(db));
        if (sqlite3_exec(db, "RELEASE wallet_bound_prepare", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet_sqlite", "bound cutover savepoint release failed: %s", sqlite3_errmsg(db));
    }
    if (own) {
        if (ok) ok = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        if (!ok && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet_sqlite", "bound cutover transaction rollback failed: %s", sqlite3_errmsg(db));
    }
    return ok;
}

static bool wss_bound_input_valid(struct wallet_sqlite *ws, const struct wallet *w,
    const struct wallet_cutover_binding *binding, const uint8_t hash[32],
    wallet_height_resolver resolve, wallet_cutover_endpoint_check current)
{
    return ws && ws->open && ws->db && w && binding && binding->history_identity_present &&
        hash && resolve && current;
}

bool wallet_sqlite_cutover_prepare_bound(struct wallet_sqlite *ws, const struct wallet *w,
    const struct wallet_cutover_binding *binding, int reference, const uint8_t hash[32],
    wallet_height_resolver resolve, wallet_cutover_endpoint_check endpoint_current, void *ctx)
{
    if (!wss_bound_input_valid(ws, w, binding, hash, resolve, endpoint_current) ||
        !endpoint_current(ctx, reference, hash)) return false;
    bool own = sqlite3_get_autocommit(ws->db) != 0;
    if (own && sqlite3_exec(ws->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    if (!own && sqlite3_txn_state(ws->db, "main") != SQLITE_TXN_WRITE) return false;
    if (sqlite3_exec(ws->db, "SAVEPOINT wallet_bound_prepare", NULL, NULL, NULL) != SQLITE_OK) {
        if (own && sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet_sqlite", "bound cutover transaction rollback failed: %s", sqlite3_errmsg(ws->db));
        return false;
    }
    bool ok = wallet_sqlite_cutover_height_prepare_in_open_tx(ws, w, reference, hash, resolve, ctx) &&
        wss_cutover_prepare(ws, w, binding) && endpoint_current(ctx, reference, hash);
    return wss_bound_finish(ws->db, own, ok);
}

bool wallet_sqlite_cutover_prepare_bound_preserving_cursor(struct wallet_sqlite *ws,
    struct wallet *w, const struct wallet_cutover_binding *binding, int reference,
    const uint8_t hash[32], wallet_height_resolver resolve,
    wallet_cutover_endpoint_check endpoint_current, void *ctx)
{
    if (!wss_bound_input_valid(ws, w, binding, hash, resolve, endpoint_current) ||
        !sqlite3_get_autocommit(ws->db) ||
        sqlite3_exec(ws->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    typeof(w->scan_retry) saved = w->scan_retry;
    int floor = 0;
    enum wallet_cutover_floor_status status = wallet_sqlite_cutover_scan_floor(ws, &floor);
    bool ok = status == WALLET_CUTOVER_FLOOR_FOUND || status == WALLET_CUTOVER_FLOOR_ABSENT;
    if (ok) {
        wss_set_pending_floor(w, floor);
        ok = wallet_sqlite_cutover_prepare_bound(ws, w, binding, reference, hash, resolve, endpoint_current, ctx);
    }
    if (ok) ok = sqlite3_exec(ws->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) {
        if (sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet_sqlite", "bound cursor transaction rollback failed: %s", sqlite3_errmsg(ws->db));
        w->scan_retry = saved;
    }
    return ok;
}
