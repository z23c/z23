/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The role/grant store: one signed chainlog per node, folded into an
 * in-memory table of the latest (fingerprint, role) state. See
 * tools/dev/fleet_roles.h for the contract.
 *
 * Every row is self-signed: it names the granting box's own public key and
 * a signature only that key could have produced, so a row cannot be edited
 * on disk without the edit being detected the next time the store opens —
 * with one measured exception. A corrupted row BEFORE the chain's tail is
 * refused (row_decode's signature check fails, the whole open fails with
 * ZCL_ROLE_SIG_INVALID). A corrupted TAIL row is not: the chainlog beneath
 * this store cannot distinguish "the last frame was damaged" from "the
 * process crashed mid-append", so it treats a broken final frame as an
 * ordinary torn write, truncates it away, and logs one WARN — the open
 * succeeds and that one row is simply gone. The practical effect is that
 * the chain's LENGTH is not authenticated: an attacker (or a bad disk) who
 * truncates the file removes the newest grants and revokes with nothing
 * here to detect it, until some later lane anchors the head elsewhere.
 * Only this node's own operator key is ever asked to sign a row — a grant
 * is always this node's own decision about a key, never a statement
 * carried in from a peer.
 */

#include "fleet_roles.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "chainlog/chainlog.h"
#include "crypto/ed25519.h"
#include "platform/private_directory.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZCL_ROLE_ROW_DOMAIN "zcl.fleet_role_row.v1"
#define ZCL_ROLE_CHAINLOG_KIND 0x524f4c45u /* "ROLE" */
#define ZCL_ROLE_ROW_VERSION_BYTE 1u
#define ZCL_ROLE_ROW_BODY_BYTES 76u
#define ZCL_ROLE_ROW_BYTES (ZCL_ROLE_ROW_BODY_BYTES + ZCL_ROLE_SIG_BYTES)
#define ZCL_ROLE_ACTION_GRANT  1u
#define ZCL_ROLE_ACTION_REVOKE 2u
#define ZCL_ROLE_TABLE_MAX 512u

struct role_row {
    uint8_t action;
    uint8_t role;
    uint8_t target_fp[ZCL_ROLE_FP_BYTES];
    uint8_t granted_by[32];
    int64_t ts;
    uint8_t sig[ZCL_ROLE_SIG_BYTES];
};

struct zcl_role_store {
    struct zcl_chainlog *log;
    struct zcl_role_entry table[ZCL_ROLE_TABLE_MAX];
    size_t table_n;
};

const char *zcl_role_status_label(enum zcl_role_status s)
{
    switch (s) {
    case ZCL_ROLE_OK:            return "ok";
    case ZCL_ROLE_ARGUMENT:      return "role_argument";
    case ZCL_ROLE_IO:            return "role_io";
    case ZCL_ROLE_MALFORMED:     return "role_row_malformed";
    case ZCL_ROLE_SIG_INVALID:   return "role_sig_invalid";
    case ZCL_ROLE_UNKNOWN_ROLE:  return "role_unknown";
    case ZCL_ROLE_NOT_GRANTED:   return "role_not_granted";
    case ZCL_ROLE_FULL:          return "role_table_full";
    default:                     return "role_argument";
    }
}

static void row_write_body(const struct role_row *r, uint8_t *out)
{
    out[0] = ZCL_ROLE_ROW_VERSION_BYTE;
    out[1] = r->action;
    out[2] = r->role;
    out[3] = 0;
    memcpy(out + 4, r->target_fp, ZCL_ROLE_FP_BYTES);
    memcpy(out + 4 + ZCL_ROLE_FP_BYTES, r->granted_by, 32);
    zcl_write_u64_be(out + 4 + ZCL_ROLE_FP_BYTES + 32, (uint64_t)r->ts);
}

static size_t sign_message(const struct role_row *r, uint8_t *out)
{
    memcpy(out, ZCL_ROLE_ROW_DOMAIN, sizeof(ZCL_ROLE_ROW_DOMAIN));
    size_t n = sizeof(ZCL_ROLE_ROW_DOMAIN);
    row_write_body(r, out + n);
    return n + ZCL_ROLE_ROW_BODY_BYTES;
}

static bool row_sign(struct role_row *r, const uint8_t seed[32])
{
    uint8_t pk[32], sk[32];
    zcl_ed25519_keypair(pk, sk, seed);
    if (memcmp(pk, r->granted_by, 32) != 0) {
        memset(sk, 0, sizeof sk);
        return false;
    }
    uint8_t msg[sizeof(ZCL_ROLE_ROW_DOMAIN) + ZCL_ROLE_ROW_BODY_BYTES];
    size_t len = sign_message(r, msg);
    zcl_ed25519_sign(r->sig, msg, len, sk, pk);
    memset(sk, 0, sizeof sk);
    return true;
}

static bool row_verify(const struct role_row *r)
{
    uint8_t msg[sizeof(ZCL_ROLE_ROW_DOMAIN) + ZCL_ROLE_ROW_BODY_BYTES];
    size_t len = sign_message(r, msg);
    return ed25519_verify(r->sig, msg, len, r->granted_by);
}

static size_t row_encode(const struct role_row *r, uint8_t *out)
{
    row_write_body(r, out);
    memcpy(out + ZCL_ROLE_ROW_BODY_BYTES, r->sig, ZCL_ROLE_SIG_BYTES);
    return ZCL_ROLE_ROW_BYTES;
}

static enum zcl_role_status row_decode(const uint8_t *in, size_t len,
                                       struct role_row *out)
{
    if (len != ZCL_ROLE_ROW_BYTES)
        return ZCL_ROLE_MALFORMED;
    if (in[0] != ZCL_ROLE_ROW_VERSION_BYTE || in[3] != 0)
        return ZCL_ROLE_MALFORMED;
    out->action = in[1];
    out->role = in[2];
    if (out->action != ZCL_ROLE_ACTION_GRANT &&
        out->action != ZCL_ROLE_ACTION_REVOKE)
        return ZCL_ROLE_MALFORMED;
    if (!zcl_role_name(out->role))
        return ZCL_ROLE_UNKNOWN_ROLE;
    memcpy(out->target_fp, in + 4, ZCL_ROLE_FP_BYTES);
    memcpy(out->granted_by, in + 4 + ZCL_ROLE_FP_BYTES, 32);
    out->ts = (int64_t)zcl_read_u64_be(in + 4 + ZCL_ROLE_FP_BYTES + 32);
    memcpy(out->sig, in + ZCL_ROLE_ROW_BODY_BYTES, ZCL_ROLE_SIG_BYTES);
    if (!row_verify(out))
        return ZCL_ROLE_SIG_INVALID;
    return ZCL_ROLE_OK;
}

/* ── table fold ──────────────────────────────────────────────────────── */

static struct zcl_role_entry *table_find(struct zcl_role_store *s,
                                         const uint8_t fp[ZCL_ROLE_FP_BYTES],
                                         uint8_t role)
{
    for (size_t i = 0; i < s->table_n; i++)
        if (s->table[i].role == role &&
            memcmp(s->table[i].fp, fp, ZCL_ROLE_FP_BYTES) == 0)
            return &s->table[i];
    return NULL;
}

static enum zcl_role_status table_apply(struct zcl_role_store *s,
                                        const struct role_row *r)
{
    struct zcl_role_entry *e = table_find(s, r->target_fp, r->role);
    if (!e) {
        if (s->table_n >= ZCL_ROLE_TABLE_MAX)
            return ZCL_ROLE_FULL;
        e = &s->table[s->table_n++];
        memcpy(e->fp, r->target_fp, ZCL_ROLE_FP_BYTES);
        e->role = r->role;
    }
    e->active = r->action == ZCL_ROLE_ACTION_GRANT;
    e->changed_at = r->ts;
    return ZCL_ROLE_OK;
}

/* ── open/close ──────────────────────────────────────────────────────── */

static void store_stream(uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char tag[] = "zcl.fleet_role_store.v1";
    sha3_256_write(&ctx, (const unsigned char *)tag, sizeof(tag));
    sha3_256_finalize(&ctx, out);
}

struct zcl_role_store *zcl_role_store_open(const char *datadir,
                                           struct zcl_role_report *report)
{
    struct zcl_role_report local;
    if (!report)
        report = &local;
    memset(report, 0, sizeof(*report));
    if (!datadir || datadir[0] != '/') {
        report->status = ZCL_ROLE_ARGUMENT;
        return NULL;
    }
    char path[600];
    if ((size_t)snprintf(path, sizeof path, "%s/fleet_roles", datadir) >=
        sizeof path) {
        report->status = ZCL_ROLE_ARGUMENT;
        return NULL;
    }
    /* Best-effort: the chainlog open below fails loudly if the directory
     * truly cannot be created, so a stray mkdir failure here is not a
     * second refusal path to keep in sync with that one. */
    (void)platform_private_directory_create(path);
    char chain_path[640];
    if ((size_t)snprintf(chain_path, sizeof chain_path, "%s/roles.chain",
                        path) >= sizeof chain_path) {
        report->status = ZCL_ROLE_ARGUMENT;
        return NULL;
    }
    uint8_t stream[32];
    store_stream(stream);
    struct zcl_chainlog_report crep;
    struct zcl_chainlog *log = zcl_chainlog_open(chain_path, stream, &crep);
    if (!log) {
        report->status = ZCL_ROLE_IO;
        return NULL;
    }
    struct zcl_role_store *s =
        zcl_calloc(1, sizeof(*s), "fleet_roles.store");
    if (!s) {
        zcl_chainlog_close(log);
        report->status = ZCL_ROLE_IO;
        return NULL;
    }
    s->log = log;
    uint64_t count = zcl_chainlog_count(log);
    for (uint64_t seq = 1; seq <= count; seq++) {
        uint8_t buf[ZCL_ROLE_ROW_BYTES];
        uint32_t kind = 0;
        size_t len = 0;
        if (zcl_chainlog_read(log, seq, &kind, buf, sizeof buf, &len) !=
                ZCL_CHAINLOG_OK ||
            kind != ZCL_ROLE_CHAINLOG_KIND) {
            zcl_chainlog_close(log);
            free(s);
            report->status = ZCL_ROLE_IO;
            return NULL;
        }
        struct role_row row;
        enum zcl_role_status rs = row_decode(buf, len, &row);
        if (rs != ZCL_ROLE_OK) {
            zcl_chainlog_close(log);
            free(s);
            report->status = rs;
            return NULL;
        }
        rs = table_apply(s, &row);
        if (rs != ZCL_ROLE_OK) {
            zcl_chainlog_close(log);
            free(s);
            report->status = rs;
            return NULL;
        }
    }
    report->status = ZCL_ROLE_OK;
    report->rows = count;
    return s;
}

void zcl_role_store_close(struct zcl_role_store *store)
{
    if (!store)
        return;
    zcl_chainlog_close(store->log);
    free(store);
}

/* ── writes ──────────────────────────────────────────────────────────── */

static enum zcl_role_status store_append(
    struct zcl_role_store *store, uint8_t action,
    const uint8_t target_fp[ZCL_ROLE_FP_BYTES], uint8_t role,
    const uint8_t operator_pub[32], const uint8_t seed[32], int64_t now,
    uint64_t *out_seq)
{
    if (!store || !target_fp || !operator_pub || !seed || now <= 0)
        return ZCL_ROLE_ARGUMENT;
    if (!zcl_role_name(role) || role == ZCL_ROLE_OPERATOR)
        return ZCL_ROLE_UNKNOWN_ROLE;
    struct role_row row = { 0 };
    row.action = action;
    row.role = role;
    memcpy(row.target_fp, target_fp, ZCL_ROLE_FP_BYTES);
    memcpy(row.granted_by, operator_pub, 32);
    row.ts = now;
    if (!row_sign(&row, seed))
        return ZCL_ROLE_SIG_INVALID;
    uint8_t encoded[ZCL_ROLE_ROW_BYTES];
    size_t len = row_encode(&row, encoded);
    uint64_t seq = 0;
    if (zcl_chainlog_append(store->log, ZCL_ROLE_CHAINLOG_KIND, encoded, len,
                            &seq, NULL) != ZCL_CHAINLOG_OK)
        return ZCL_ROLE_IO;
    enum zcl_role_status rs = table_apply(store, &row);
    if (rs != ZCL_ROLE_OK)
        return rs;
    if (out_seq)
        *out_seq = seq;
    return ZCL_ROLE_OK;
}

enum zcl_role_status zcl_role_store_grant(
    struct zcl_role_store *store, const uint8_t target_fp[ZCL_ROLE_FP_BYTES],
    uint8_t role, const uint8_t operator_pub[32], const uint8_t seed[32],
    int64_t now, uint64_t *out_seq)
{
    return store_append(store, ZCL_ROLE_ACTION_GRANT, target_fp, role,
                        operator_pub, seed, now, out_seq);
}

enum zcl_role_status zcl_role_store_revoke(
    struct zcl_role_store *store, const uint8_t target_fp[ZCL_ROLE_FP_BYTES],
    uint8_t role, const uint8_t operator_pub[32], const uint8_t seed[32],
    int64_t now, uint64_t *out_seq)
{
    return store_append(store, ZCL_ROLE_ACTION_REVOKE, target_fp, role,
                        operator_pub, seed, now, out_seq);
}

bool zcl_role_store_has_role(const struct zcl_role_store *store,
                             const uint8_t fp[ZCL_ROLE_FP_BYTES],
                             uint8_t role)
{
    if (!store || !fp)
        return false;
    for (size_t i = 0; i < store->table_n; i++)
        if (store->table[i].role == role &&
            store->table[i].active &&
            memcmp(store->table[i].fp, fp, ZCL_ROLE_FP_BYTES) == 0)
            return true;
    return false;
}

size_t zcl_role_store_list(const struct zcl_role_store *store,
                           struct zcl_role_entry *out, size_t cap)
{
    if (!store || !out)
        return 0;
    size_t n = store->table_n < cap ? store->table_n : cap;
    memcpy(out, store->table, n * sizeof(*out));
    return n;
}

bool zcl_role_check(const struct zcl_role_store *store,
                    const uint8_t fp[ZCL_ROLE_FP_BYTES], bool is_operator,
                    const char *leaf, const char *kind, char *why,
                    size_t why_cap)
{
    if (is_operator)
        return true;
    if (!store || !fp || !leaf) {
        if (why)
            snprintf(why, why_cap, "REFUSED role: no role store to check "
                                   "against");
        return false;
    }
    for (size_t i = 0; i < store->table_n; i++) {
        const struct zcl_role_entry *e = &store->table[i];
        if (!e->active || memcmp(e->fp, fp, ZCL_ROLE_FP_BYTES) != 0)
            continue;
        if (zcl_role_leaf_allowed(e->role, leaf, kind))
            return true;
    }
    if (why) {
        char fp8[9];
        zcl_role_fingerprint_short(fp, fp8);
        if (kind)
            snprintf(why, why_cap,
                     "REFUSED role: key %s has no role granting %s kind=%s",
                     fp8, leaf, kind);
        else
            snprintf(why, why_cap,
                     "REFUSED role: key %s has no role granting %s", fp8,
                     leaf);
    }
    return false;
}
