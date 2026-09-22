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
 * the chain's length is authenticated by policy.head beside this file.
 * Truncating the chain, or changing its bytes, makes the saved chain head
 * disagree with the log, and the store then refuses to open until the
 * operator signs a fresh head.
 * Only this node's own operator key is ever asked to sign a row — a grant
 * is always this node's own decision about a key, never a statement
 * carried in from a peer.
 */

#include "fleet_roles.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "chainlog/chainlog.h"
#include "crypto/ed25519.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZCL_ROLE_ROW_DOMAIN "zcl.fleet_role_row.v1"
#define ZCL_ROLE_HEAD_DOMAIN "zcl.fleet_role_head.v1"
#define ZCL_ROLE_HEAD_VERSION 1u
/* version + sequence + high_water + chain head + predecessor + operator */
#define ZCL_ROLE_HEAD_BODY 113u
#define ZCL_ROLE_HEAD_BYTES (ZCL_ROLE_HEAD_BODY + ZCL_ROLE_SIG_BYTES)
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
    char dir[600];
    bool anchored;
    uint64_t head_seq;
    uint64_t head_high_water;
    uint8_t head_root[32];
};

struct role_head {
    uint64_t sequence;
    uint64_t high_water;
    uint8_t chain[32];
    uint8_t predecessor[32];
    uint8_t operator_pub[32];
    uint8_t sig[ZCL_ROLE_SIG_BYTES];
    uint8_t root[32];
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
    case ZCL_ROLE_HEAD_LOST:     return "role_head_lost";
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

static enum zcl_role_status head_bind(struct zcl_role_store *s);

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
    if ((size_t)snprintf(s->dir, sizeof s->dir, "%s", path) >= sizeof s->dir) {
        zcl_chainlog_close(log);
        free(s);
        report->status = ZCL_ROLE_ARGUMENT;
        return NULL;
    }
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
    {
        enum zcl_role_status hs = head_bind(s);
        if (hs != ZCL_ROLE_OK) {
            zcl_chainlog_close(log);
            free(s);
            report->status = hs;
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

/* ── policy head ─────────────────────────────────────────────────────── */

static void head_body(const struct role_head *h, uint8_t *out)
{
    memset(out, 0, ZCL_ROLE_HEAD_BODY);
    out[0] = ZCL_ROLE_HEAD_VERSION;
    zcl_write_u64_be(out + 1, h->sequence);
    zcl_write_u64_be(out + 9, h->high_water);
    memcpy(out + 17, h->chain, 32);
    memcpy(out + 49, h->predecessor, 32);
    memcpy(out + 81, h->operator_pub, 32);
}

static void head_root(const struct role_head *h, uint8_t out[32])
{
    uint8_t body[ZCL_ROLE_HEAD_BODY];
    struct sha3_256_ctx ctx;
    head_body(h, body);
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)ZCL_ROLE_HEAD_DOMAIN,
                   sizeof(ZCL_ROLE_HEAD_DOMAIN));
    sha3_256_write(&ctx, body, sizeof body);
    sha3_256_finalize(&ctx, out);
}

static bool head_sign(struct role_head *h, const uint8_t seed[32])
{
    uint8_t pk[32], sk[32], msg[sizeof(ZCL_ROLE_HEAD_DOMAIN) + ZCL_ROLE_HEAD_BODY];
    zcl_ed25519_keypair(pk, sk, seed);
    if (memcmp(pk, h->operator_pub, 32) != 0) {
        memset(sk, 0, sizeof sk);
        return false;
    }
    memcpy(msg, ZCL_ROLE_HEAD_DOMAIN, sizeof(ZCL_ROLE_HEAD_DOMAIN));
    head_body(h, msg + sizeof(ZCL_ROLE_HEAD_DOMAIN));
    zcl_ed25519_sign(h->sig, msg, sizeof msg, sk, pk);
    memset(sk, 0, sizeof sk);
    head_root(h, h->root);
    return true;
}

static bool head_verify(const struct role_head *h)
{
    uint8_t msg[sizeof(ZCL_ROLE_HEAD_DOMAIN) + ZCL_ROLE_HEAD_BODY];
    memcpy(msg, ZCL_ROLE_HEAD_DOMAIN, sizeof(ZCL_ROLE_HEAD_DOMAIN));
    head_body(h, msg + sizeof(ZCL_ROLE_HEAD_DOMAIN));
    return ed25519_verify(h->sig, msg, sizeof msg, h->operator_pub);
}

static bool head_path(const char *dir, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/policy.head", dir);
    return n > 0 && (size_t)n < cap;
}

/* 0 absent, 1 ok, -1 unreadable or not this statement. */
static int head_load(const char *dir, struct role_head *out)
{
    char path[640];
    uint8_t buf[ZCL_ROLE_HEAD_BYTES];
    struct platform_positioned_file file;
    uint64_t size = 0;
    if (!head_path(dir, path, sizeof path))
        return -1;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return 0;
    bool ok = platform_positioned_file_size(&file, &size) &&
              size == ZCL_ROLE_HEAD_BYTES &&
              platform_positioned_file_read(&file, buf, sizeof buf, 0) ==
                  (int64_t)sizeof buf;
    platform_positioned_file_close(&file);
    if (!ok || buf[0] != ZCL_ROLE_HEAD_VERSION)
        return -1;
    memset(out, 0, sizeof *out);
    out->sequence = zcl_read_u64_be(buf + 1);
    out->high_water = zcl_read_u64_be(buf + 9);
    memcpy(out->chain, buf + 17, 32);
    memcpy(out->predecessor, buf + 49, 32);
    memcpy(out->operator_pub, buf + 81, 32);
    memcpy(out->sig, buf + ZCL_ROLE_HEAD_BODY, ZCL_ROLE_SIG_BYTES);
    if (!head_verify(out) || out->sequence == 0 ||
        out->high_water < out->sequence)
        return -1;
    head_root(out, out->root);
    return 1;
}

static bool head_save(const char *dir, const struct role_head *h)
{
    char path[640];
    uint8_t buf[ZCL_ROLE_HEAD_BYTES];
    struct platform_private_file file;
    if (!head_path(dir, path, sizeof path))
        return false;
    head_body(h, buf);
    memcpy(buf + ZCL_ROLE_HEAD_BODY, h->sig, ZCL_ROLE_SIG_BYTES);
    platform_private_file_init(&file);
    if (!platform_private_file_open_locked_create(path, &file))
        return false;
    bool ok = platform_private_file_truncate(&file, 0) &&
              platform_private_file_write_at(&file, buf, sizeof buf, 0) &&
              platform_private_file_authority_flush(&file);
    platform_private_file_close(&file);
    return ok;
}

static enum zcl_role_status head_bind(struct zcl_role_store *s)
{
    struct role_head h;
    uint8_t cur[32];
    int loaded = head_load(s->dir, &h);
    if (loaded == 0)
        return ZCL_ROLE_OK;
    if (loaded != 1)
        return ZCL_ROLE_HEAD_LOST;
    if (!zcl_chainlog_head(s->log, cur) || memcmp(cur, h.chain, 32) != 0)
        return ZCL_ROLE_HEAD_LOST;
    s->anchored = true;
    s->head_seq = h.sequence;
    s->head_high_water = h.high_water;
    memcpy(s->head_root, h.root, 32);
    return ZCL_ROLE_OK;
}

static enum zcl_role_status head_advance(struct zcl_role_store *s,
                                         uint64_t chain_seq,
                                         const uint8_t chain[32],
                                         const uint8_t operator_pub[32],
                                         const uint8_t seed[32])
{
    struct role_head h;
    memset(&h, 0, sizeof h);
    memcpy(h.operator_pub, operator_pub, 32);
    memcpy(h.chain, chain, 32);
    if (!s->anchored) {
        h.sequence = chain_seq;
        h.high_water = chain_seq;
    } else {
        h.sequence = s->head_seq + 1u;
        h.high_water = h.sequence;
        memcpy(h.predecessor, s->head_root, 32);
    }
    if (h.sequence == 0 || !head_sign(&h, seed) || !head_save(s->dir, &h))
        return ZCL_ROLE_IO;
    s->anchored = true;
    s->head_seq = h.sequence;
    s->head_high_water = h.high_water;
    memcpy(s->head_root, h.root, 32);
    return ZCL_ROLE_OK;
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
    uint8_t chain[32];
    size_t len = row_encode(&row, encoded);
    uint64_t seq = 0;
    if (zcl_chainlog_append(store->log, ZCL_ROLE_CHAINLOG_KIND, encoded, len,
                            &seq, chain) != ZCL_CHAINLOG_OK)
        return ZCL_ROLE_IO;
    enum zcl_role_status rs = table_apply(store, &row);
    if (rs != ZCL_ROLE_OK)
        return rs;
    rs = head_advance(store, seq, chain, operator_pub, seed);
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

bool zcl_role_store_policy_head(const struct zcl_role_store *store,
                                uint64_t *sequence, uint64_t *high_water)
{
    if (!store || !store->anchored || !sequence || !high_water)
        return false;
    *sequence = store->head_seq;
    *high_water = store->head_high_water;
    return true;
}

static enum zcl_role_status head_plan(int loaded, const struct role_head *old,
                                      const uint8_t cur[32],
                                      const uint8_t operator_pub[32],
                                      uint64_t count, struct role_head *next,
                                      bool *write)
{
    *write = false;
    if (loaded < 0)
        return ZCL_ROLE_HEAD_LOST;
    if (loaded == 1 && memcmp(old->operator_pub, operator_pub, 32) != 0)
        return ZCL_ROLE_SIG_INVALID;
    if (loaded == 1 && memcmp(old->chain, cur, 32) == 0)
        return ZCL_ROLE_OK;
    memset(next, 0, sizeof *next);
    memcpy(next->operator_pub, operator_pub, 32);
    memcpy(next->chain, cur, 32);
    if (loaded == 1) {
        next->sequence = old->sequence + 1u;
        memcpy(next->predecessor, old->root, 32);
    } else {
        next->sequence = count == 0 ? 1u : count;
    }
    next->high_water = next->sequence;
    *write = true;
    return ZCL_ROLE_OK;
}

enum zcl_role_status zcl_role_store_reanchor(const char *datadir,
                                            const uint8_t operator_pub[32],
                                            const uint8_t seed[32],
                                            int64_t now)
{
    char dir[600], chain_path[640];
    uint8_t stream[32], cur[32];
    struct zcl_chainlog_report crep;
    struct zcl_chainlog *log = NULL;
    struct role_head old, next;
    bool write = false;
    enum zcl_role_status st;
    (void)now;
    if (!datadir || datadir[0] != '/' || !operator_pub || !seed)
        return ZCL_ROLE_ARGUMENT;
    if ((size_t)snprintf(dir, sizeof dir, "%s/fleet_roles", datadir) >=
            sizeof dir ||
        (size_t)snprintf(chain_path, sizeof chain_path, "%s/roles.chain",
                         dir) >= sizeof chain_path)
        return ZCL_ROLE_ARGUMENT;
    store_stream(stream);
    log = zcl_chainlog_open(chain_path, stream, &crep);
    if (!log || !zcl_chainlog_head(log, cur)) {
        if (log)
            zcl_chainlog_close(log);
        return ZCL_ROLE_IO;
    }
    st = head_plan(head_load(dir, &old), &old, cur, operator_pub,
                   zcl_chainlog_count(log), &next, &write);
    zcl_chainlog_close(log);
    if (st != ZCL_ROLE_OK || !write)
        return st;
    if (!head_sign(&next, seed) || !head_save(dir, &next))
        return ZCL_ROLE_IO;
    return ZCL_ROLE_OK;
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
