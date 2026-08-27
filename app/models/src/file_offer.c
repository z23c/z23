/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model: FileOffer (ZCL Market gossip)
 *
 * Wires callbacks, validation, and SQLite persistence for the `file_offers`
 * table. The P2P gossip/cache logic lives in lib/net/src/file_market.c.
 *
 * The record type is `struct file_offer` from net/file_market.h —
 * deliberately reused (rather than a parallel `struct db_file_offer`)
 * so the gossip layer and persistence layer agree byte-for-byte on
 * the on-the-wire / at-rest representation. */

#include "models/file_offer.h"
#include "platform/time_compat.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(file_offer)

static bool read_file_offer_blob(sqlite3_stmt *s, int col, void *dest,
                                 int expected_len, const char *column)
{
    int got = sqlite3_column_bytes(s, col);
    const void *blob = sqlite3_column_blob(s, col);
    if (!blob || got != expected_len)
        LOG_FAIL("market",
                 "file_offers.%s blob length mismatch: got=%d expected=%d",
                 column, got, expected_len);

    AR_READ_BLOB(s, col, dest, expected_len);
    return true;
}

bool db_file_offer_validate(const struct file_offer *offer,
                            struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!offer) {
        ar_errors_add(errors, "offer", "is NULL");
        return false;
    }

    static const uint8_t zero32[32] = {0};
    uint32_t expected_chunks = 0;

    validates_custom(errors,
        memcmp(offer->root_hash, zero32, 32) != 0,
        "root_hash", "can't be all zero");
    validates_presence_of(errors, offer, filename);
    validates_positive(errors, offer, size_bytes);
    validates_positive(errors, offer, num_chunks);
    validates_non_negative(errors, offer, price_per_mb);
    validates_custom(errors,
        file_market_num_chunks_for_size(offer->size_bytes,
                                        &expected_chunks) &&
        expected_chunks == offer->num_chunks,
        "num_chunks", "must exactly cover size_bytes");
    if (offer->price_per_mb > 0) {
        validates_custom(errors,
            file_offer_auth_validate_at(
                offer, (int64_t)platform_time_wall_time_t()) ==
                FILE_OFFER_AUTH_OK &&
            file_offer_auth_verify_signature(offer) == FILE_OFFER_AUTH_OK,
            "seller_signature", "must verify for the canonical paid offer");
        uint8_t expected_id[32] = {0};
        validates_custom(errors,
            file_offer_auth_offer_id(offer, expected_id) ==
                FILE_OFFER_AUTH_OK &&
            memcmp(expected_id, offer->offer_id, 32) == 0,
            "offer_id", "must commit the complete signed offer wire");
    } else {
        validates_custom(errors, offer->auth_version == 0,
            "auth_version", "free legacy offers must be unsigned");
    }
    validates_non_negative(errors, offer, last_seen);
    validates_range(errors, offer, ttl, 1, FILE_MARKET_MAX_TTL);

    return !ar_errors_any(errors);
}

bool db_file_offer_save(struct node_db *ndb,
                        const struct file_offer *offer)
{
    if (!ndb || !ndb->open) LOG_FAIL("market", "db_file_offer_save: db not open");
    if (!offer) LOG_FAIL("market", "db_file_offer_save: offer is NULL");

    /* file_offers is keyed by content root, so an upsert that ignored the
     * signer would let any peer who holds the same bytes re-key someone
     * else's listing under their own signature, payment address, and
     * metadata. The root belongs to its first accepted listing: only the
     * same seller may rewrite a signed listing, and unsigned legacy rows
     * accept only byte-identical refreshes (last_seen, port, ttl). */
    struct ar_callbacks *cbs = db_file_offer_callbacks();
    sqlite3_stmt *s = NULL;
    AR_BEGIN_SAVE(cbs, "file_offer", offer, db_file_offer_validate);
    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR REPLACE INTO file_offers"
        "(root_hash,filename,size_bytes,num_chunks,price_per_mb,"
        "z_addr,peer_ip,peer_port,last_seen,ttl,auth_version,"
        "network_genesis,seller_pubkey,nonce,issued_unix,expires_unix,"
        "seller_signature,offer_id,endpoint_type,onion_pubkey)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(root_hash) DO UPDATE SET "
        "filename=excluded.filename,size_bytes=excluded.size_bytes,"
        "num_chunks=excluded.num_chunks,price_per_mb=excluded.price_per_mb,"
        "z_addr=excluded.z_addr,peer_ip=excluded.peer_ip,"
        "peer_port=excluded.peer_port,last_seen=excluded.last_seen,"
        "ttl=excluded.ttl,auth_version=excluded.auth_version,"
        "network_genesis=excluded.network_genesis,"
        "seller_pubkey=excluded.seller_pubkey,nonce=excluded.nonce,"
        "issued_unix=excluded.issued_unix,expires_unix=excluded.expires_unix,"
        "seller_signature=excluded.seller_signature,offer_id=excluded.offer_id,"
        "endpoint_type=excluded.endpoint_type,"
        "onion_pubkey=excluded.onion_pubkey "
        "WHERE (file_offers.auth_version>=1 AND excluded.auth_version>=1 "
        "AND file_offers.seller_pubkey=excluded.seller_pubkey "
        "AND (file_offers.offer_id=excluded.offer_id "
        "OR excluded.issued_unix>file_offers.issued_unix "
        "OR (excluded.issued_unix=file_offers.issued_unix "
        "AND excluded.nonce>file_offers.nonce))) OR "
        "(file_offers.auth_version=0 AND excluded.auth_version=0 "
        "AND file_offers.filename=excluded.filename "
        "AND file_offers.size_bytes=excluded.size_bytes "
        "AND file_offers.num_chunks=excluded.num_chunks "
        "AND file_offers.price_per_mb=excluded.price_per_mb "
        "AND file_offers.z_addr=excluded.z_addr "
        "AND file_offers.peer_ip=excluded.peer_ip "
        "AND file_offers.endpoint_type=excluded.endpoint_type "
        "AND file_offers.onion_pubkey=excluded.onion_pubkey "
        "AND file_offers.network_genesis=excluded.network_genesis "
        "AND file_offers.seller_pubkey=excluded.seller_pubkey "
        "AND file_offers.nonce=excluded.nonce "
        "AND file_offers.issued_unix=excluded.issued_unix "
        "AND file_offers.expires_unix=excluded.expires_unix "
        "AND file_offers.seller_signature=excluded.seller_signature "
        "AND file_offers.offer_id=excluded.offer_id) RETURNING 1");
    AR_BIND_BLOB(s, 1, offer->root_hash, 32);
    AR_BIND_TEXT(s, 2, offer->filename);
    AR_BIND_INT(s, 3, (int64_t)offer->size_bytes);
    AR_BIND_INT(s, 4, offer->num_chunks);
    AR_BIND_INT(s, 5, offer->price_per_mb);
    AR_BIND_BLOB(s, 6, offer->z_addr, 43);
    AR_BIND_BLOB(s, 7, offer->peer_ip, 16);
    AR_BIND_INT(s, 8, offer->peer_port);
    AR_BIND_INT(s, 9, offer->last_seen
        ? offer->last_seen : (int64_t)platform_time_wall_time_t());
    AR_BIND_INT(s, 10, offer->ttl);
    AR_BIND_INT(s, 11, offer->auth_version);
    AR_BIND_BLOB(s, 12, offer->network_genesis, 32);
    AR_BIND_BLOB(s, 13, offer->seller_pubkey, 32);
    AR_BIND_INT(s, 14, (int64_t)offer->nonce);
    AR_BIND_INT(s, 15, offer->issued_unix);
    AR_BIND_INT(s, 16, offer->expires_unix);
    AR_BIND_BLOB(s, 17, offer->seller_signature, 64);
    AR_BIND_BLOB(s, 18, offer->offer_id, 32);
    AR_BIND_INT(s, 19, offer->endpoint_type);
    AR_BIND_BLOB(s, 20, offer->onion_pubkey, 32);

    bool saved = AR_STEP_ROW(s) && sqlite3_column_int(s, 0) == 1;
    bool completed = saved ? AR_STEP_DONE(s) :
        sqlite3_errcode(ndb->db) == SQLITE_OK;
    if (!completed) {
        LOG_ERROR("market", "file_offers atomic save failed: error=%s",
                  sqlite3_errmsg(ndb->db));
        saved = false;
    }
    AR_FINALIZE(s);
    if (!saved)
        LOG_WARN("market",
                 "file_offers listing update refused by atomic root policy");
    AR_FINISH_SAVE(cbs, offer, saved);
}

static bool row_to_file_offer(sqlite3_stmt *s, struct file_offer *out)
{
    memset(out, 0, sizeof(*out));
    if (!read_file_offer_blob(s, 0, out->root_hash, 32, "root_hash"))
        LOG_FAIL("market", "file_offers.root_hash rejected");

    const char *name = (const char *)sqlite3_column_text(s, 1);
    if (name) snprintf(out->filename, sizeof(out->filename), "%s", name);

    out->size_bytes = (uint64_t)sqlite3_column_int64(s, 2);
    out->num_chunks = (uint32_t)sqlite3_column_int(s, 3);
    out->price_per_mb = sqlite3_column_int64(s, 4);

    if (!read_file_offer_blob(s, 5, out->z_addr, 43, "z_addr"))
        LOG_FAIL("market", "file_offers.z_addr rejected");

    if (!read_file_offer_blob(s, 6, out->peer_ip, 16, "peer_ip"))
        LOG_FAIL("market", "file_offers.peer_ip rejected");

    out->peer_port = (uint16_t)sqlite3_column_int(s, 7);
    out->last_seen = sqlite3_column_int64(s, 8);
    out->ttl = (uint8_t)sqlite3_column_int(s, 9);
    out->auth_version = (uint16_t)sqlite3_column_int(s, 10);
    if (!read_file_offer_blob(s, 11, out->network_genesis, 32,
                              "network_genesis"))
        LOG_FAIL("market", "file_offers.network_genesis rejected");
    if (!read_file_offer_blob(s, 12, out->seller_pubkey, 32,
                              "seller_pubkey"))
        LOG_FAIL("market", "file_offers.seller_pubkey rejected");
    out->nonce = (uint64_t)sqlite3_column_int64(s, 13);
    out->issued_unix = sqlite3_column_int64(s, 14);
    out->expires_unix = sqlite3_column_int64(s, 15);
    if (!read_file_offer_blob(s, 16, out->seller_signature, 64,
                              "seller_signature"))
        LOG_FAIL("market", "file_offers.seller_signature rejected");
    if (!read_file_offer_blob(s, 17, out->offer_id, 32, "offer_id"))
        LOG_FAIL("market", "file_offers.offer_id rejected");
    out->endpoint_type = (uint8_t)sqlite3_column_int(s, 18);
    if (!read_file_offer_blob(s, 19, out->onion_pubkey, 32, "onion_pubkey"))
        LOG_FAIL("market", "file_offers.onion_pubkey rejected");
    return true;
}

int db_file_offer_list(struct node_db *ndb,
                       struct file_offer *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "market", "db_file_offer_list: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT root_hash,filename,size_bytes,num_chunks,price_per_mb,"
        "z_addr,peer_ip,peer_port,last_seen,ttl,auth_version,"
        "network_genesis,seller_pubkey,nonce,issued_unix,expires_unix,"
        "seller_signature,offer_id,endpoint_type,onion_pubkey"
        " FROM file_offers ORDER BY last_seen DESC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        struct ar_errors errors;
        if (!row_to_file_offer(s, &out[count]) ||
            !db_file_offer_validate(&out[count], &errors)) continue);
}

bool db_file_offer_find(struct node_db *ndb,
                        const uint8_t root_hash[32],
                        struct file_offer *out)
{
    if (!ndb || !ndb->open) LOG_FAIL("market", "db_file_offer_find: db not open");
    if (!root_hash) LOG_FAIL("market", "db_file_offer_find: root_hash is NULL");
    if (!out) LOG_FAIL("market", "db_file_offer_find: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT root_hash,filename,size_bytes,num_chunks,price_per_mb,"
        "z_addr,peer_ip,peer_port,last_seen,ttl,auth_version,"
        "network_genesis,seller_pubkey,nonce,issued_unix,expires_unix,"
        "seller_signature,offer_id,endpoint_type,onion_pubkey"
        " FROM file_offers WHERE root_hash=?",
        AR_BIND_BLOB(s, 1, root_hash, 32),
        struct ar_errors errors;
        if (!row_to_file_offer(s, out) ||
            !db_file_offer_validate(out, &errors)) {
            AR_FINALIZE(s);
            return false;
        });
}

bool db_file_offer_find_by_id(struct node_db *ndb,
                              const uint8_t offer_id[32],
                              struct file_offer *out)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "db_file_offer_find_by_id: db not open");
    if (!offer_id)
        LOG_FAIL("market", "db_file_offer_find_by_id: offer_id is NULL");
    if (!out)
        LOG_FAIL("market", "db_file_offer_find_by_id: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT root_hash,filename,size_bytes,num_chunks,price_per_mb,"
        "z_addr,peer_ip,peer_port,last_seen,ttl,auth_version,"
        "network_genesis,seller_pubkey,nonce,issued_unix,expires_unix,"
        "seller_signature,offer_id,endpoint_type,onion_pubkey"
        " FROM file_offers WHERE offer_id=? AND auth_version IN (1,2)",
        AR_BIND_BLOB(s, 1, offer_id, 32),
        struct ar_errors errors;
        if (!row_to_file_offer(s, out) ||
            !db_file_offer_validate(out, &errors)) {
            AR_FINALIZE(s);
            return false;
        });
}

int db_file_offer_prune(struct node_db *ndb, int64_t max_age)
{
    if (!ndb || !ndb->open) return 0;

    int64_t cutoff = (int64_t)platform_time_wall_time_t() - max_age;
    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s, "DELETE FROM file_offers WHERE last_seen < ?", 0);
    AR_BIND_INT(s, 1, cutoff);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    return ok ? sqlite3_changes(ndb->db) : 0;
}

bool db_file_offer_delete(struct node_db *ndb, const uint8_t root_hash[32])
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "db_file_offer_delete: db not open");
    if (!root_hash)
        LOG_FAIL("market", "db_file_offer_delete: root_hash is NULL");

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s, "DELETE FROM file_offers WHERE root_hash=?", false);
    AR_BIND_BLOB(s, 1, root_hash, 32);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    return ok;
}

/* ── Local-only listing moderation (v65 review_state) ─────────────── */

bool db_file_offer_get_review_state(struct node_db *ndb,
                                    const uint8_t root_hash[32],
                                    char *out, size_t out_len)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "db_file_offer_get_review_state: db not open");
    if (!root_hash)
        LOG_FAIL("market", "db_file_offer_get_review_state: root_hash NULL");
    if (!out || out_len < 16)
        LOG_FAIL("market", "db_file_offer_get_review_state: out too small");

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT review_state FROM file_offers WHERE root_hash=?", false);
    AR_BIND_BLOB(s, 1, root_hash, 32);
    if (!AR_STEP_ROW(s)) {
        AR_FINALIZE(s);
        return false; /* row-ok: absent offer is locally unreviewed */
    }
    const char *text = AR_COL_TEXT(s, 0);
    snprintf(out, out_len, "%s", text ? text : "unreviewed");
    AR_FINALIZE(s);
    return true;
}

bool db_file_offer_set_review_state(struct node_db *ndb,
                                    const uint8_t offer_id[32],
                                    const char *review_state)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "db_file_offer_set_review_state: db not open");
    if (!offer_id)
        LOG_FAIL("market", "db_file_offer_set_review_state: offer_id NULL");
    if (!review_state || !review_state[0])
        LOG_FAIL("market", "db_file_offer_set_review_state: state empty");

    sqlite3_stmt *s = NULL;
    AR_EXEC_CHANGED_BOOL(ndb, s,
        "UPDATE file_offers SET review_state=? "
        "WHERE offer_id=? AND auth_version IN (1,2)",
        AR_BIND_TEXT(s, 1, review_state);
        AR_BIND_BLOB(s, 2, offer_id, 32));
}

enum db_file_offer_review_cas_result
db_file_offer_compare_set_review_state(struct node_db *ndb,
                                       const uint8_t offer_id[32],
                                       const char *expected_review_state,
                                       const char *next_review_state)
{
    if (!ndb || !ndb->open) {
        LOG_ERROR("market", "review CAS: db not open");
        return DB_FILE_OFFER_REVIEW_CAS_ERROR;
    }
    if (!offer_id || !expected_review_state || !expected_review_state[0] ||
        !next_review_state || !next_review_state[0]) {
        LOG_ERROR("market", "review CAS: invalid arguments");
        return DB_FILE_OFFER_REVIEW_CAS_ERROR;
    }

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "UPDATE file_offers SET review_state=? "
        "WHERE offer_id=? AND auth_version IN (1,2) AND review_state=? "
        "RETURNING 1",
        DB_FILE_OFFER_REVIEW_CAS_ERROR);
    AR_BIND_TEXT(s, 1, next_review_state);
    AR_BIND_BLOB(s, 2, offer_id, 32);
    AR_BIND_TEXT(s, 3, expected_review_state);
    int rc = sqlite3_step(s);  // raw-sql-ok:atomic-review-state-cas
    bool changed = rc == SQLITE_ROW && sqlite3_column_int(s, 0) == 1;
    if (changed)
        rc = sqlite3_step(s);  // raw-sql-ok:prove-one-returned-row-and-done
    AR_FINALIZE(s);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("market", "review CAS step failed: rc=%d msg=%s", rc,
                  sqlite3_errmsg(ndb->db));
        return DB_FILE_OFFER_REVIEW_CAS_ERROR;
    }
    if (changed)
        return DB_FILE_OFFER_REVIEW_CAS_UPDATED;
    return DB_FILE_OFFER_REVIEW_CAS_STALE;
}

bool db_file_offer_review_counts(struct node_db *ndb, int64_t counts[3])
{
    if (!ndb || !ndb->open)
        LOG_FAIL("market", "db_file_offer_review_counts: db not open");
    if (!counts)
        LOG_FAIL("market", "db_file_offer_review_counts: counts is NULL");
    counts[0] = counts[1] = counts[2] = 0;

    sqlite3_stmt *s = NULL;
    AR_PREPARE_RET(ndb, s,
        "SELECT review_state,COUNT(*) FROM file_offers "
        "GROUP BY review_state", false);
    bool ok = true;
    while (ok && AR_STEP_ROW(s)) {
        const char *state = AR_COL_TEXT(s, 0);
        int64_t n = AR_COL_INT(s, 1);
        if (state && strcmp(state, "unreviewed") == 0) counts[0] = n;
        else if (state && strcmp(state, "reviewed_ok") == 0) counts[1] = n;
        else if (state && strcmp(state, "sensitive") == 0) counts[2] = n;
    }
    AR_FINALIZE(s);
    return ok;
}
