/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seal_kv — implementation. See storage/seal_kv.h.
 *
 * The ring is four progress_meta blobs ("seal_slot_0".."seal_slot_3") plus a
 * head index ("seal_ring_head"). Each blob is a fixed 190-byte canonical
 * little-endian record with a trailing SHA3-256 self-hash so a torn/corrupt
 * slot is detectable and skippable. Writes ride the caller's open
 * progress.kv txn via progress_meta_set_in_tx (the sanctioned kernel hatch —
 * progress.kv sits below the AR layer, same as coins_kv and the trusted-base
 * writer); reads take the recursive progress_store_tx_lock themselves. */

#include "storage/seal_kv.h"
#include "storage/progress_store.h"

#include "crypto/sha3.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <string.h>

/* Offset where self_sha3 begins: 190 - 32. */
#define SEAL_SELF_SHA3_OFFSET (SEAL_RECORD_BYTES - 32)

static void put_u32_le(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

static void put_u64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

static uint32_t get_u32_le(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static uint64_t get_u64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

bool seal_serialize(const struct seal_record *r, uint8_t out[SEAL_RECORD_BYTES])
{
    if (!r || !out) return false;
    uint8_t *p = out;
    *p++ = (uint8_t)SEAL_RECORD_VERSION;       /* [1]   version       @0   */
    put_u32_le(p, (uint32_t)r->height); p += 4; /* [4]   height        @1   */
    memcpy(p, r->block_hash, 32); p += 32;      /* [32]  block_hash    @5   */
    memcpy(p, r->coins_sha3, 32); p += 32;      /* [32]  coins_sha3    @37  */
    memcpy(p, r->nullifier_sha3, 32); p += 32;  /* [32]  nullifier_sha3@69  */
    memcpy(p, r->anchor_window_sha3, 32); p += 32; /*[32] anchor_window@101 */
    put_u64_le(p, (uint64_t)r->utxo_count); p += 8; /*[8] utxo_count   @133 */
    put_u64_le(p, (uint64_t)r->supply); p += 8;  /* [8]  supply        @141 */
    *p++ = r->ratified ? 1u : 0u;                /* [1]  ratified      @149 */
    put_u64_le(p, (uint64_t)r->sealed_at); p += 8; /*[8] sealed_at     @150 */
    /* p is now at SEAL_SELF_SHA3_OFFSET (158). */
    sha3_256(out, SEAL_SELF_SHA3_OFFSET, p);     /* [32] self_sha3     @158 */
    return true;
}

bool seal_deserialize(const uint8_t *in, size_t len, struct seal_record *out,
                      bool *self_ok)
{
    if (self_ok) *self_ok = false;
    if (!in || !out) return false;
    if (len != SEAL_RECORD_BYTES) return false;
    if (in[0] != (uint8_t)SEAL_RECORD_VERSION) return false;

    const uint8_t *p = in + 1;
    memset(out, 0, sizeof(*out));
    out->height = (int32_t)get_u32_le(p); p += 4;
    memcpy(out->block_hash, p, 32); p += 32;
    memcpy(out->coins_sha3, p, 32); p += 32;
    memcpy(out->nullifier_sha3, p, 32); p += 32;
    memcpy(out->anchor_window_sha3, p, 32); p += 32;
    out->utxo_count = (int64_t)get_u64_le(p); p += 8;
    out->supply = (int64_t)get_u64_le(p); p += 8;
    out->ratified = (*p++ != 0) ? 1u : 0u;
    out->sealed_at = (int64_t)get_u64_le(p); p += 8;
    memcpy(out->self_sha3, in + SEAL_SELF_SHA3_OFFSET, 32);

    uint8_t recomputed[32];
    sha3_256(in, SEAL_SELF_SHA3_OFFSET, recomputed);
    if (self_ok) *self_ok = (memcmp(recomputed, out->self_sha3, 32) == 0);
    return true;
}

bool seal_kv_ensure_schema(struct sqlite3 *db)
{
    if (!db) return false;
    return progress_meta_table_ensure(db);
}

static void seal_slot_key(int slot, char out[24])
{
    /* slot is 0..SEAL_RING_SLOTS-1 (single digit). */
    snprintf(out, 24, "%s%d", SEAL_SLOT_KEY_PREFIX, slot);
}

/* Read the head index. Returns -1 (empty ring) when absent or malformed. The
 * caller must hold progress_store_tx_lock (the read helpers wrap this). */
static int seal_read_head(struct sqlite3 *db)
{
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool found = false;
    if (!progress_meta_get(db, SEAL_HEAD_KEY, blob, sizeof(blob), &n, &found))
        return -1;
    if (!found || n != sizeof(blob)) return -1;
    int64_t v = (int64_t)get_u64_le(blob);
    if (v < 0 || v >= SEAL_RING_SLOTS) return -1;
    return (int)v;
}

/* Read slot `slot` into *out, reporting self-validity. *present=false when the
 * slot key is absent. Returns false only on a hard read error. */
static bool seal_read_slot(struct sqlite3 *db, int slot,
                           struct seal_record *out, bool *present,
                           bool *self_ok)
{
    if (present) *present = false;
    if (self_ok) *self_ok = false;
    char key[24];
    seal_slot_key(slot, key);
    uint8_t blob[SEAL_RECORD_BYTES];
    size_t n = 0;
    bool found = false;
    if (!progress_meta_get(db, key, blob, sizeof(blob), &n, &found))
        return false;
    if (!found) return true; /* absent slot is not an error */
    if (n != SEAL_RECORD_BYTES) {
        /* Wrong length — treat as corrupt/absent; the ring steps over it. */
        LOG_WARN("seal", "[seal] slot %d blob len=%zu != %d — skipping",
                 slot, n, SEAL_RECORD_BYTES);
        return true;
    }
    bool ok = false;
    if (!seal_deserialize(blob, n, out, &ok))
        return true; /* bad version — skip, not a hard error */
    if (present) *present = true;
    if (self_ok) *self_ok = ok;
    return true;
}

bool seal_kv_insert_candidate_in_tx(struct sqlite3 *db,
                                    const struct seal_record *r)
{
    if (!db || !r) return false;

    /* RAISE-ONLY: no-op if a newer (or equal) self-valid seal already exists. */
    struct seal_record newest;
    bool found = false;
    if (!seal_kv_newest(db, &newest, &found)) {
        LOG_WARN("seal", "[seal] insert: newest read failed G=%d", r->height);
        return false;
    }
    if (found && r->height <= newest.height) {
        /* Already sealed at/above this grid point — nothing to do. */
        return true;
    }

    int head = seal_read_head(db);
    int slot = (head < 0) ? 0 : (head + 1) % SEAL_RING_SLOTS;

    struct seal_record rec = *r;
    rec.ratified = 0;
    uint8_t blob[SEAL_RECORD_BYTES];
    if (!seal_serialize(&rec, blob)) {
        LOG_WARN("seal", "[seal] insert: serialize failed G=%d", r->height);
        return false;
    }
    char key[24];
    seal_slot_key(slot, key);
    if (!progress_meta_set_in_tx(db, key, blob, sizeof(blob))) {
        LOG_WARN("seal", "[seal] insert: slot %d write failed G=%d",
                 slot, r->height);
        return false;
    }
    uint8_t hb[8];
    put_u64_le(hb, (uint64_t)slot);
    if (!progress_meta_set_in_tx(db, SEAL_HEAD_KEY, hb, sizeof(hb))) {
        LOG_WARN("seal", "[seal] insert: head write failed G=%d", r->height);
        return false;
    }
    return true;
}

/* Scan all self-valid slots for the one with the highest height. ratified_only
 * restricts to ratified slots. *found=false if none match. */
static bool seal_scan_newest(struct sqlite3 *db, bool ratified_only,
                             struct seal_record *out, bool *found)
{
    if (found) *found = false;
    if (!db || !out) return false;

    progress_store_tx_lock();
    bool any = false;
    struct seal_record best;
    memset(&best, 0, sizeof(best));
    for (int s = 0; s < SEAL_RING_SLOTS; s++) {
        struct seal_record rec;
        bool present = false, self_ok = false;
        if (!seal_read_slot(db, s, &rec, &present, &self_ok)) {
            progress_store_tx_unlock();
            return false;
        }
        if (!present || !self_ok) continue;
        if (ratified_only && !rec.ratified) continue;
        if (!any || rec.height > best.height) {
            best = rec;
            any = true;
        }
    }
    progress_store_tx_unlock();
    if (any) {
        *out = best;
        if (found) *found = true;
    }
    return true;
}

bool seal_kv_newest(struct sqlite3 *db, struct seal_record *out, bool *found)
{
    return seal_scan_newest(db, false, out, found);
}

bool seal_kv_newest_ratified(struct sqlite3 *db, struct seal_record *out,
                             bool *found)
{
    return seal_scan_newest(db, true, out, found);
}

bool seal_kv_get_at_height(struct sqlite3 *db, int32_t g,
                           struct seal_record *out, bool *found, int *out_slot)
{
    if (found) *found = false;
    if (out_slot) *out_slot = -1;
    if (!db || !out) return false;

    progress_store_tx_lock();
    for (int s = 0; s < SEAL_RING_SLOTS; s++) {
        struct seal_record rec;
        bool present = false, self_ok = false;
        if (!seal_read_slot(db, s, &rec, &present, &self_ok)) {
            progress_store_tx_unlock();
            return false;
        }
        if (!present || !self_ok) continue;
        if (rec.height == g) {
            *out = rec;
            if (found) *found = true;
            if (out_slot) *out_slot = s;
            break;
        }
    }
    progress_store_tx_unlock();
    return true;
}

bool seal_kv_nearest_rewind_base(struct sqlite3 *db, int32_t H,
                                 struct seal_record *out, bool *found)
{
    if (found) *found = false;
    if (!db || !out) return false;

    progress_store_tx_lock();
    bool any = false;
    struct seal_record best;
    memset(&best, 0, sizeof(best));
    for (int s = 0; s < SEAL_RING_SLOTS; s++) {
        struct seal_record rec;
        bool present = false, self_ok = false;
        if (!seal_read_slot(db, s, &rec, &present, &self_ok)) {
            progress_store_tx_unlock();
            return false;
        }
        if (!present || !self_ok) continue;
        if (rec.height > H) continue;   /* not a base at/below the target */
        if (!any || rec.height > best.height) {
            best = rec;
            any = true;
        }
    }
    progress_store_tx_unlock();
    if (any) {
        *out = best;
        if (found) *found = true;
    }
    return true;
}

bool seal_kv_mark_ratified_in_tx(struct sqlite3 *db, int slot,
                                 struct seal_record *r)
{
    if (!db || !r) return false;
    if (slot < 0 || slot >= SEAL_RING_SLOTS) return false;
    r->ratified = 1;
    uint8_t blob[SEAL_RECORD_BYTES];
    if (!seal_serialize(r, blob)) return false;
    char key[24];
    seal_slot_key(slot, key);
    if (!progress_meta_set_in_tx(db, key, blob, sizeof(blob))) {
        LOG_WARN("seal", "[seal] ratify: slot %d rewrite failed G=%d",
                 slot, r->height);
        return false;
    }
    return true;
}

/* DELETE one table's rows at/below `limit` in the caller's open txn. A missing
 * table is tolerated (a repair path can reach here before a stage's schema is
 * created). Returns false only on a real step error. */
static bool seal_prune_table(sqlite3 *db, const char *table, int32_t limit)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE height <= ?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        /* No such table — tolerated (nothing to prune). */
        return true;
    }
    sqlite3_bind_int(st, 1, limit);
    int rc = sqlite3_step(st);  // raw-sql-ok:kernel-primitive
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        LOG_WARN("seal", "[seal] prune %s <= %d step rc=%d", table, limit, rc);
        return false;
    }
    return true;
}

bool seal_prune_below_in_tx(sqlite3 *db, int32_t G)
{
    if (!db) return false;
    /* utxo_apply_delta below the seal is sealed-domain — drop it. */
    if (!seal_prune_table(db, "utxo_apply_delta", G))
        return false;
    /* Stage *_log tails, kept generous below the seal. NEVER tip_finalize_log
     * (the trusted-base/anchor source) and NEVER nullifiers (permanent). */
    int32_t log_limit = G - SEAL_LOG_RETENTION;
    if (log_limit < 0) return true; /* nothing old enough to prune */
    static const char *const logs[] = {
        "validate_headers_log", "body_persist_log", "script_validate_log",
        "proof_validate_log", "utxo_apply_log",
    };
    for (size_t i = 0; i < sizeof(logs) / sizeof(logs[0]); i++) {
        if (!seal_prune_table(db, logs[i], log_limit))
            return false;
    }
    return true;
}

static void seal_push_hash(struct json_value *obj, const char *key,
                           const uint8_t h[32])
{
    char hex[65];
    HexStr(h, 32, false, hex, sizeof(hex));
    json_push_kv_str(obj, key, hex);
}

bool seal_kv_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);

    struct sqlite3 *db = progress_store_db();
    json_push_kv_bool(out, "open", db != NULL);
    if (!db) {
        json_push_kv_int(out, "head", -1);
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        json_push_kv(out, "slots", &arr);
        json_free(&arr);
        return true;
    }

    progress_store_tx_lock();
    int head = seal_read_head(db);
    json_push_kv_int(out, "head", head);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int s = 0; s < SEAL_RING_SLOTS; s++) {
        struct seal_record rec;
        bool present = false, self_ok = false;
        if (!seal_read_slot(db, s, &rec, &present, &self_ok)) {
            /* hard read error — emit a minimal error marker and stop */
            struct json_value e;
            json_init(&e);
            json_set_object(&e);
            json_push_kv_int(&e, "slot", s);
            json_push_kv_bool(&e, "read_error", true);
            json_push_back(&arr, &e);
            json_free(&e);
            break;
        }
        if (!present) continue;
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        json_push_kv_int(&o, "slot", s);
        json_push_kv_int(&o, "height", rec.height);
        json_push_kv_bool(&o, "self_sha3_valid", self_ok);
        json_push_kv_bool(&o, "ratified", rec.ratified != 0);
        json_push_kv_int(&o, "utxo_count", rec.utxo_count);
        json_push_kv_int(&o, "supply", rec.supply);
        json_push_kv_int(&o, "sealed_at", rec.sealed_at);
        seal_push_hash(&o, "block_hash", rec.block_hash);
        seal_push_hash(&o, "coins_sha3", rec.coins_sha3);
        seal_push_hash(&o, "nullifier_sha3", rec.nullifier_sha3);
        seal_push_hash(&o, "anchor_window_sha3", rec.anchor_window_sha3);
        seal_push_hash(&o, "self_sha3", rec.self_sha3);
        json_push_back(&arr, &o);
        json_free(&o);
    }
    progress_store_tx_unlock();

    json_push_kv(out, "slots", &arr);
    json_free(&arr);
    return true;
}
