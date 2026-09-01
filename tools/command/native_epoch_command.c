/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the `core epoch` tree — the Bounded Node keystone
 * (docs/spec/sovereign-identity-layer.md). The OP_RETURN catalog projection
 * (engine/models/src/op_return_index.c, folded forward by the backfill
 * service) maintains an incremental digest-chain over EVERY OP_RETURN the
 * chain has ever carried; anchoring that digest in a ZANC anchor commits
 * the entire overlay state (ZNAM/ZSLP/ZANC/ZID) in one ~40-byte tx.
 *
 * v1 discipline: NO background service, NO auto-broadcast. Anchoring
 * spends fees, so it is an operator decision, triggered only by
 * `core epoch anchor`. Label semantics: an epoch anchor is a ZANC anchor
 * labeled "zepoch@<H>" where H is the catalog cursor height the digest
 * was read at; an anchor counts as covering the current epoch E =
 * tip/1000 when its label height H >= E*1000. These semantics match
 * zepoch_status_dump_state_json (dumpstate zepoch) exactly.
 *
 * `core epoch verify --height=H` reports BOTH halves of the question:
 * whether the operators who anchored H agree with each other (distinct
 * digests among the zepoch@<H> anchors — a finding even when this node
 * cannot take a side), and whether this node agrees with them (only when
 * its catalog cursor sits exactly at H, since the digest chain folds
 * forward and is recomputable only at the cursor). A node whose declared
 * base_height is ABOVE H is reported `incomparable`, never `disagree`:
 * base_height/base_digest are folded into every preimage, so digests over
 * different ranges are SUPPOSED to differ.
 *
 * Reads open <datadir>/node.db READONLY (the core.storage.query.offline
 * pattern) so status/verify also answer for a stopped or copied datadir.
 * `core epoch anchor` prefers the LIVE node: it dispatches the wallet
 * compose+broadcast through the anchor_publish RPC (which itself falls
 * back to op_return_hex when no wallet is loaded); with no live node it
 * builds the same OP_RETURN locally and returns op_return_hex with a
 * next-step hint. */

#include "command/native_command.h"

#include "controllers/rpc_client.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "models/op_return_index.h"
#include "models/zanc.h"
#include "zanc/zanc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EP_LOG "core.epoch"

/* ── small helpers ────────────────────────────────────────────────── */

static const char *ep_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

/* Resolve the target datadir: explicit input.datadir wins, else the CLI's
 * --datadir (core.node.bootstatus precedent). NULL when neither is set. */
static const char *ep_datadir(const struct zcl_command_request *request)
{
    const char *dd = ep_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* The read-only open is zcl_native_node_db_require_readonly
 * (command/native_command.h); this only names what these leaves read. */
static bool ep_open_catalog(const char *datadir,
                            struct zcl_command_reply *reply,
                            sqlite3 **db_out, struct node_db *ndb_out)
{
    return zcl_native_node_db_require_readonly(
        datadir, reply, "the OP_RETURN epoch catalog", db_out, ndb_out);
}

/* Current catalog state: declared range (base) + cursor height + digest +
 * row count. Returns false on an unreadable OR refused persisted record. */
static bool ep_read_catalog(struct node_db *ndb, int32_t *cursor_out,
                            uint8_t digest_out[32], int64_t *rows_out,
                            struct op_return_index_cursor *cur_out)
{
    struct op_return_index_cursor cur;
    if (!op_return_index_get_cursor(ndb, &cur))
        return false;
    *cursor_out = cur.height;
    memcpy(digest_out, cur.digest, 32);
    if (cur_out) *cur_out = cur;
    *rows_out = op_return_index_count(ndb);
    return true;
}

/* The catalog digest commits to [base_height, tip_height] — publish the
 * declared range wherever the digest is published, so nobody reads an epoch
 * anchor as a whole-chain commitment. */
static void ep_push_range(struct json_value *obj,
                          const struct op_return_index_cursor *cur)
{
    json_push_kv_int(obj, "base_height", cur->base_height);
    char hex[65];
    HexStr(cur->base_digest, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "base_digest", hex);
    json_push_kv_bool(obj, "partial_coverage", cur->base_height > 0);
}

/* ── epoch-anchor enumeration ──────────────────────────────────────
 *
 * Epoch anchors are ZANC anchors labeled "zepoch@<H>". They are a tiny
 * labeled family inside a table that holds every ZANC anchor the chain
 * ever carried, so they must be enumerated by LABEL, not by reading a
 * fixed window off the front of the global newest-first list.
 *
 * This used to be `db_zanc_list(ndb, rows, 100)` — the newest 100 anchors
 * of ANY label. One hundred unrelated anchors newer than the epoch anchor
 * (routine on a live chain: every ZSLP/ZNAM/zcode anchor counts) hid it
 * completely, and the command answered "anchored: false" for an anchor
 * that is on-chain. A silent wrong answer, and the exact failure mode an
 * anchor exists to rule out. The scan below is filtered in SQL and paged,
 * so no window exists; the only remaining bound is EP_SCAN_MAX, and it is
 * REPORTED (`truncated`) rather than assumed away. */

#define EP_LABEL_PREFIX "zepoch@"
#define EP_LABEL_PREFIX_LEN 7
#define EP_PAGE 128
#define EP_SCAN_MAX 8192

/* Parse the height out of a "zepoch@<H>" label. False on any other shape
 * (including a trailing-garbage or empty height) — never a partial parse. */
static bool ep_label_height(const char *label, int32_t *out)
{
    if (strncmp(label, EP_LABEL_PREFIX, EP_LABEL_PREFIX_LEN) != 0)
        return false;
    const char *hstr = label + EP_LABEL_PREFIX_LEN;
    if (!hstr[0])
        return false;
    char *end = NULL;
    long h = strtol(hstr, &end, 10);
    if (!end || *end != '\0' || h < 0 || h > INT32_MAX)
        return false;
    *out = (int32_t)h;
    return true;
}

typedef void (*ep_visit_fn)(const struct zanc_anchor *a, void *user);

/* Page through EVERY anchor labeled "zepoch@…", newest chain height
 * first, calling `visit` for each. Returns the number scanned and sets
 * *truncated_out when EP_SCAN_MAX stopped the scan early. */
static size_t ep_scan_zepoch(struct node_db *ndb, ep_visit_fn visit,
                             void *user, bool *truncated_out)
{
    struct zanc_anchor page[EP_PAGE];
    size_t scanned = 0;
    bool truncated = false;
    for (size_t offset = 0;; offset += EP_PAGE) {
        if (scanned >= EP_SCAN_MAX) {
            truncated = true;
            break;
        }
        int n = db_zanc_list_by_label_prefix(ndb, EP_LABEL_PREFIX, page,
                                             EP_PAGE, offset);
        if (n <= 0)
            break;
        for (int i = 0; i < n; i++) {
            visit(&page[i], user);
            scanned++;
        }
        if ((size_t)n < EP_PAGE)
            break;
    }
    if (truncated_out)
        *truncated_out = truncated;
    return scanned;
}

struct ep_latest_ctx {
    int32_t min_height;
    bool found;
    int32_t best;
    struct zanc_anchor anchor;
};

static void ep_visit_latest(const struct zanc_anchor *a, void *user)
{
    struct ep_latest_ctx *c = user;
    int32_t h;
    if (!ep_label_height(a->label, &h) || h < c->min_height)
        return;
    if (!c->found || h > c->best) {
        c->best = h;
        c->anchor = *a;
        c->found = true;
    }
}

/* Latest zepoch anchor with label height >= min_height. Returns true and
 * fills *out. Ordering is by LABEL height (the epoch the anchor claims),
 * which is what "covers this epoch" means; chain height only orders the
 * scan. */
static bool ep_find_anchor(struct node_db *ndb, int32_t min_height,
                           struct zanc_anchor *out, size_t *scanned_out,
                           bool *truncated_out)
{
    struct ep_latest_ctx c;
    memset(&c, 0, sizeof(c));
    c.min_height = min_height;
    size_t scanned = ep_scan_zepoch(ndb, ep_visit_latest, &c, truncated_out);
    if (scanned_out)
        *scanned_out = scanned;
    if (c.found)
        *out = c.anchor;
    return c.found;
}

static void ep_anchor_json(const struct zanc_anchor *a, int32_t cursor,
                           struct json_value *obj)
{
    json_set_object(obj);
    json_push_kv_str(obj, "label", a->label);
    char hex[65];
    HexStr(a->txid, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "txid", hex);
    json_push_kv_int(obj, "height", a->height);
    json_push_kv_int(obj, "confirmations",
                     cursor >= a->height ? (int64_t)(cursor - a->height + 1)
                                         : 0);
    HexStr(a->digest, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, "digest", hex);
}

/* A node_rpc_call body that is an error, not a result: the transport's
 * own {"error":{...}} envelope, the extracted JSON-RPC error value
 * ({"code":int,"message":str}), or a bare string (the RPC handler's
 * error message, e.g. anchor_publish's "Missing file or digest").
 * Returns the best human message (into msg, when non-NULL). */
static bool ep_rpc_body_error(const struct json_value *v, char *msg,
                              size_t msg_size)
{
    const char *m = NULL;
    if (v->type == JSON_STR) {
        m = json_get_str(v);
    } else if (v->type == JSON_OBJ) {
        const struct json_value *err = json_get(v, "error");
        if (err && err->type != JSON_NULL) {
            const struct json_value *em =
                err->type == JSON_OBJ ? json_get(err, "message") : NULL;
            m = (em && em->type == JSON_STR) ? json_get_str(em)
                                             : "node RPC error";
        } else {
            const struct json_value *code = json_get(v, "code");
            const struct json_value *msg_v = json_get(v, "message");
            if (code && code->type == JSON_INT && msg_v &&
                msg_v->type == JSON_STR)
                m = json_get_str(msg_v);
        }
    }
    if (m && msg)
        snprintf(msg, msg_size, "%s", m);
    return m != NULL;
}

/* ── core.epoch.status ─────────────────────────────────────────────── */

void zcl_native_handle_core_epoch_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = ep_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.epoch.status");
        return;
    }

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!ep_open_catalog(datadir, reply, &db, &ndb))
        return;

    int32_t cursor = -1;
    uint8_t digest[32] = {0};
    int64_t rows = 0;
    struct op_return_index_cursor opcur;
    memset(&opcur, 0, sizeof(opcur));
    opcur.height = -1;
    bool have = ep_read_catalog(&ndb, &cursor, digest, &rows, &opcur);

    json_push_kv_str(&reply->data, "datadir", datadir);
    if (!have) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "CATALOG_CURSOR_UNREADABLE", "execute", true,
                               false,
                               "catalog cursor unreadable — the op_return "
                               "backfill has not folded anything yet; boot "
                               "the node and let the backfill advance",
                               datadir);
        return;
    }

    json_push_kv_int(&reply->data, "tip_height", cursor);
    char hex[65];
    HexStr(digest, 32, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "catalog_digest", hex);
    json_push_kv_int(&reply->data, "catalog_rows", rows);
    ep_push_range(&reply->data, &opcur);

    int64_t epoch = cursor >= 0 ? cursor / 1000 : -1;
    json_push_kv_int(&reply->data, "epoch", epoch);
    json_push_kv_int(&reply->data, "epoch_start", epoch >= 0 ? epoch * 1000 : -1);
    json_push_kv_int(&reply->data, "blocks_into_epoch",
                     epoch >= 0 ? (int64_t)cursor - epoch * 1000 : -1);

    struct zanc_anchor a;
    size_t scanned = 0;
    bool truncated = false;
    bool anchored = epoch >= 0 &&
                    ep_find_anchor(&ndb, (int32_t)(epoch * 1000), &a,
                                   &scanned, &truncated);
    json_push_kv_int(&reply->data, "anchors_scanned", (int64_t)scanned);
    if (truncated) {
        json_push_kv_bool(&reply->data, "truncated", true);
        json_push_kv_int(&reply->data, "truncated_cap", EP_SCAN_MAX);
    }
    json_push_kv_bool(&reply->data, "anchored", anchored);
    if (anchored) {
        struct json_value aj = {0};
        ep_anchor_json(&a, cursor, &aj);
        json_push_kv(&reply->data, "anchor", &aj);
        json_free(&aj);
        json_push_kv_bool(&reply->data, "digest_match",
                          memcmp(a.digest, digest, 32) == 0);
    } else {
        json_push_kv_str(&reply->data, "next",
                         "no zepoch anchor in the current epoch — run "
                         "`z23 core epoch anchor` to commit the "
                         "catalog digest on-chain (operator decision; "
                         "spends a fee)");
    }
    zcl_native_node_db_close_readonly(&db, &ndb);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.epoch.anchor ─────────────────────────────────────────────── */

void zcl_native_handle_core_epoch_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = ep_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.epoch.anchor");
        return;
    }

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!ep_open_catalog(datadir, reply, &db, &ndb))
        return;

    int32_t cursor = -1;
    uint8_t digest[32] = {0};
    int64_t rows = 0;
    struct op_return_index_cursor opcur;
    memset(&opcur, 0, sizeof(opcur));
    opcur.height = -1;
    bool have = ep_read_catalog(&ndb, &cursor, digest, &rows, &opcur);
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (!have || cursor < 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "CATALOG_EMPTY", "execute", true, false,
                               "the OP_RETURN catalog has no folded digest "
                               "yet — boot the node and let the op_return "
                               "backfill advance, then re-run",
                               datadir);
        return;
    }

    char digest_hex[65];
    HexStr(digest, 32, false, digest_hex, sizeof(digest_hex));
    char label[ZANC_LABEL_MAX + 1];
    snprintf(label, sizeof(label), "zepoch@%d", (int)cursor);
    /* Publish the range the anchored digest actually covers alongside it: on
     * a snapshot-seeded node this anchor commits to [base_height, cursor],
     * NOT to the whole chain. */
    ep_push_range(&reply->data, &opcur);

    /* Live-node path: anchor_publish composes + broadcasts when the node
     * has a wallet loaded, and itself returns op_return_hex when not.
     * params is a JSON-RPC array whose [0] is the --input-style object;
     * only a JSON object result is a success — a string is the RPC's
     * error message, surfaced as node_rpc_error on the offline reply. */
    char params[320];
    snprintf(params, sizeof(params),
             "[{\"digest\":\"%s\",\"hash_type\":\"sha3\",\"label\":\"%s\"}]",
             digest_hex, label);
    char rpc_err[256] = {0};
    zcl_native_bridge_ensure_rpc();
    char *rpc_result = node_rpc_call("anchor_publish", params);
    if (rpc_result) {
        struct json_value body;
        bool parsed = json_read(&body, rpc_result, strlen(rpc_result));
        bool error_body = parsed &&
                          ep_rpc_body_error(&body, rpc_err, sizeof(rpc_err));
        if (parsed && body.type == JSON_OBJ && !error_body) {
            json_push_kv_str(&body, "via", "node_rpc anchor_publish");
            json_push_kv_int(&body, "catalog_height", cursor);
            json_copy(&reply->data, &body);
            json_free(&body);
            free(rpc_result);
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
            return;
        }
        if (!error_body)
            snprintf(rpc_err, sizeof(rpc_err), "%s",
                     parsed ? "node RPC returned an unexpected body"
                            : "node RPC returned an unparseable body");
        json_free(&body);
        free(rpc_result);
    }

    /* Offline / no-live-node path: build the same OP_RETURN locally. */
    uint8_t script[128];
    size_t script_len = zanc_build_anchor(script, sizeof(script),
                                          ZANC_HASH_SHA3_256, digest, label);
    if (script_len == 0) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "OP_RETURN_BUILD_FAILED", "execute", false,
                               false, "zanc_build_anchor rejected the digest/"
                               "label", label);
        return;
    }

    json_push_kv_str(&reply->data, "hash_type", "sha3");
    json_push_kv_str(&reply->data, "digest", digest_hex);
    json_push_kv_str(&reply->data, "label", label);
    json_push_kv_int(&reply->data, "catalog_height", cursor);
    if (rpc_err[0])
        json_push_kv_str(&reply->data, "node_rpc_error", rpc_err);
    char hex[257];
    HexStr(script, script_len, false, hex, sizeof(hex));
    json_push_kv_str(&reply->data, "op_return_hex", hex);
    json_push_kv_int(&reply->data, "op_return_size", (int64_t)script_len);
    json_push_kv_str(&reply->data, "status", "ready");
    json_push_kv_str(&reply->data, "note",
                     "no live node answered — start the node and re-run "
                     "`core epoch anchor` to compose+broadcast with the "
                     "node wallet, or include this OP_RETURN manually as "
                     "vout[0] of any transaction");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── verify --height: checkpoint comparison + cross-operator agreement ──
 *
 * At a given height H the question has two independent halves, and both
 * must be visible:
 *
 *   1. Do the operators agree with EACH OTHER? Every anchor labeled
 *      zepoch@<H> commits 32 bytes. Two anchors carrying different bytes
 *      for the same height is a finding on its own — it needs no local
 *      catalog to adjudicate, and it is reported (and exits non-zero)
 *      whether or not this node can take a side.
 *
 *   2. Does THIS node agree with them? Only when the node holds a local
 *      checkpoint for exactly H. The catalog digest chain folds forward
 *      and is recomputable only at the cursor height, so "the cursor is
 *      at H" is precisely the condition for a genuine comparison. Any
 *      other state is reported with a NAMED reason and is never a
 *      silent match.
 *
 * The incomparable case is the one that must not be collapsed into
 * "disagree": a node whose declared base_height is ABOVE H never folded
 * H at all. Its digest and the anchor's digest are commitments over
 * different ranges (base_height and base_digest are folded into every
 * preimage), so they SHOULD differ. Calling that a disagreement would
 * cry wolf on every bounded node that meets an archival one. */

#define EP_MATCH_MAX 64

struct ep_match_ctx {
    int32_t want;
    struct zanc_anchor rows[EP_MATCH_MAX];
    size_t count;   /* rows written (<= EP_MATCH_MAX) */
    size_t total;   /* true match count, may exceed count */
};

static void ep_visit_match(const struct zanc_anchor *a, void *user)
{
    struct ep_match_ctx *c = user;
    int32_t h;
    if (!ep_label_height(a->label, &h) || h != c->want)
        return;
    c->total++;
    if (c->count < EP_MATCH_MAX)
        c->rows[c->count++] = *a;
}

/* Whether this node holds a digest it can honestly compare at height H. */
enum ep_local_state {
    EP_LOCAL_AVAILABLE,      /* cursor folded exactly H */
    EP_LOCAL_BELOW_BASE,     /* declared base is above H — never folded it */
    EP_LOCAL_NOT_AT_HEIGHT,  /* cursor elsewhere; the chain is forward-only */
    EP_LOCAL_NO_CATALOG,     /* no readable cursor at all */
};

static enum ep_local_state ep_local_at(bool have,
                                       const struct op_return_index_cursor *c,
                                       int32_t h)
{
    if (!have)
        return EP_LOCAL_NO_CATALOG;
    if (c->base_height > h)
        return EP_LOCAL_BELOW_BASE;
    if (c->height != h)
        return EP_LOCAL_NOT_AT_HEIGHT;
    return EP_LOCAL_AVAILABLE;
}

static const char *ep_local_reason(enum ep_local_state s)
{
    switch (s) {
    case EP_LOCAL_AVAILABLE:     return "local_checkpoint_at_height";
    case EP_LOCAL_BELOW_BASE:    return "local_base_above_height";
    case EP_LOCAL_NOT_AT_HEIGHT: return "no_local_checkpoint_at_height";
    default:                     return "no_local_catalog";
    }
}

/* Distinct digests among the collected anchors — the operator-vs-operator
 * half. >1 means two anchors committed different bytes for one height. */
static size_t ep_distinct_roots(const struct ep_match_ctx *m)
{
    size_t distinct = 0;
    for (size_t i = 0; i < m->count; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(m->rows[i].digest, m->rows[j].digest, 32) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen)
            distinct++;
    }
    return distinct;
}

/* Per-anchor verdict against the local checkpoint. */
static const char *ep_verdict(enum ep_local_state s,
                              const struct zanc_anchor *a,
                              const uint8_t local_digest[32])
{
    if (s == EP_LOCAL_BELOW_BASE)
        return "incomparable";
    if (s != EP_LOCAL_AVAILABLE)
        return "unverifiable";
    return memcmp(a->digest, local_digest, 32) == 0 ? "agree" : "disagree";
}

static void ep_verify_at_height(struct node_db *ndb, int32_t want,
                                bool have, int32_t cursor,
                                const uint8_t digest[32],
                                const struct op_return_index_cursor *opcur,
                                struct zcl_command_reply *reply)
{
    struct ep_match_ctx m;
    memset(&m, 0, sizeof(m));
    m.want = want;
    bool truncated = false;
    size_t scanned = ep_scan_zepoch(ndb, ep_visit_match, &m, &truncated);

    enum ep_local_state local = ep_local_at(have, opcur, want);
    const char *reason = ep_local_reason(local);

    json_push_kv_int(&reply->data, "height", want);
    json_push_kv_bool(&reply->data, "anchored", m.total > 0);
    json_push_kv_int(&reply->data, "anchor_count", (int64_t)m.total);
    json_push_kv_int(&reply->data, "anchors_scanned", (int64_t)scanned);
    if (truncated) {
        json_push_kv_bool(&reply->data, "truncated", true);
        json_push_kv_int(&reply->data, "truncated_cap", EP_SCAN_MAX);
    }
    if (m.total > m.count) {
        json_push_kv_bool(&reply->data, "anchors_truncated", true);
        json_push_kv_int(&reply->data, "anchors_reported", (int64_t)m.count);
    }

    json_push_kv_bool(&reply->data, "local_digest_available",
                      local == EP_LOCAL_AVAILABLE);
    json_push_kv_str(&reply->data, "local_digest_reason", reason);
    char hex[65];
    if (local == EP_LOCAL_AVAILABLE) {
        HexStr(digest, 32, false, hex, sizeof(hex));
        json_push_kv_str(&reply->data, "local_digest", hex);
    }
    json_push_kv_int(&reply->data, "catalog_cursor_height", cursor);

    size_t agree = 0, disagree = 0, incomparable = 0, unverifiable = 0;
    struct json_value arr = {0};
    json_set_array(&arr);
    for (size_t i = 0; i < m.count; i++) {
        const char *v = ep_verdict(local, &m.rows[i], digest);
        if (strcmp(v, "agree") == 0) agree++;
        else if (strcmp(v, "disagree") == 0) disagree++;
        else if (strcmp(v, "incomparable") == 0) incomparable++;
        else unverifiable++;
        struct json_value aj = {0};
        ep_anchor_json(&m.rows[i], cursor, &aj);
        json_push_kv_str(&aj, "verdict", v);
        json_push_kv_str(&aj, "verdict_reason", reason);
        json_push_back(&arr, &aj);
        json_free(&aj);
    }
    json_push_kv(&reply->data, "anchors", &arr);
    json_free(&arr);

    /* Back-compat: the single `anchor` object earlier callers read. */
    if (m.count > 0) {
        struct json_value aj = {0};
        ep_anchor_json(&m.rows[0], cursor, &aj);
        json_push_kv(&reply->data, "anchor", &aj);
        json_free(&aj);
    }

    json_push_kv_int(&reply->data, "agree_count", (int64_t)agree);
    json_push_kv_int(&reply->data, "disagree_count", (int64_t)disagree);
    json_push_kv_int(&reply->data, "incomparable_count", (int64_t)incomparable);
    json_push_kv_int(&reply->data, "unverifiable_count", (int64_t)unverifiable);
    size_t distinct = ep_distinct_roots(&m);
    json_push_kv_int(&reply->data, "distinct_roots", (int64_t)distinct);

    const char *comparison;
    if (m.total == 0)
        comparison = "no_anchor";
    else if (local == EP_LOCAL_BELOW_BASE)
        comparison = "incomparable";
    else if (local != EP_LOCAL_AVAILABLE)
        comparison = "no_local_checkpoint";
    else
        comparison = disagree > 0 ? "mismatch" : "match";
    json_push_kv_str(&reply->data, "comparison", comparison);

    bool disagreement = disagree > 0 || distinct > 1;
    json_push_kv_bool(&reply->data, "disagreement", disagreement);
    if (disagreement) {
        /* Full report AND a non-zero exit: zcl_command_reply_fail leaves
         * reply->data intact, so neither a JSON reader nor a shell exit
         * code can miss this. */
        char ev[256];
        snprintf(ev, sizeof(ev),
                 "height=%d anchors=%zu distinct_roots=%zu disagree=%zu",
                 want, m.total, distinct, disagree);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "EPOCH_DIGEST_DISAGREEMENT", "execute", false,
                               false,
                               "anchors for this epoch height commit "
                               "different digests (or disagree with the "
                               "local catalog) — the overlay states being "
                               "committed are not the same state",
                               ev);
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.epoch.verify ─────────────────────────────────────────────── */

void zcl_native_handle_core_epoch_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = ep_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "core.epoch.verify");
        return;
    }

    int64_t want_height = -1;
    const struct json_value *hv = json_get(request->input, "height");
    if (hv && hv->type == JSON_INT)
        want_height = json_get_int(hv);

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!ep_open_catalog(datadir, reply, &db, &ndb))
        return;

    int32_t cursor = -1;
    uint8_t digest[32] = {0};
    int64_t rows = 0;
    struct op_return_index_cursor opcur;
    memset(&opcur, 0, sizeof(opcur));
    opcur.height = -1;
    bool have = ep_read_catalog(&ndb, &cursor, digest, &rows, &opcur);

    json_push_kv_str(&reply->data, "datadir", datadir);
    (void)rows;
    if (have) ep_push_range(&reply->data, &opcur);

    if (want_height >= 0 && want_height <= INT32_MAX) {
        ep_verify_at_height(&ndb, (int32_t)want_height, have, cursor, digest,
                            &opcur, reply);
        zcl_native_node_db_close_readonly(&db, &ndb);
        return;
    }

    if (!have || cursor < 0) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "CATALOG_EMPTY", "execute", true, false,
                               "no folded catalog digest at the tip — boot "
                               "the node and let the backfill advance",
                               datadir);
        return;
    }

    /* Tip path: fresh-read digest, latest zepoch anchor, compare. */
    char hex[65];
    HexStr(digest, 32, false, hex, sizeof(hex));
    json_push_kv_int(&reply->data, "tip_height", cursor);
    json_push_kv_str(&reply->data, "catalog_digest", hex);
    int64_t epoch = cursor / 1000;
    json_push_kv_int(&reply->data, "epoch", epoch);

    struct zanc_anchor a;
    size_t scanned = 0;
    bool truncated = false;
    bool anchored = ep_find_anchor(&ndb, (int32_t)(epoch * 1000), &a,
                                   &scanned, &truncated);
    json_push_kv_int(&reply->data, "anchors_scanned", (int64_t)scanned);
    if (truncated) {
        json_push_kv_bool(&reply->data, "truncated", true);
        json_push_kv_int(&reply->data, "truncated_cap", EP_SCAN_MAX);
    }
    json_push_kv_bool(&reply->data, "anchored", anchored);
    if (anchored) {
        struct json_value aj = {0};
        ep_anchor_json(&a, cursor, &aj);
        json_push_kv(&reply->data, "anchor", &aj);
        json_free(&aj);
        bool match = memcmp(a.digest, digest, 32) == 0;
        json_push_kv_bool(&reply->data, "digest_match", match);
        if (!match)
            json_push_kv_str(&reply->data, "note",
                             "digest mismatch — the catalog has advanced "
                             "past the anchored digest (or the anchor "
                             "committed different bytes); re-anchor with "
                             "`core epoch anchor` if this epoch is not yet "
                             "committed");
    } else {
        json_push_kv_str(&reply->data, "next",
                         "no zepoch anchor in the current epoch — run "
                         "`z23 core epoch anchor` to commit");
    }
    zcl_native_node_db_close_readonly(&db, &ndb);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
