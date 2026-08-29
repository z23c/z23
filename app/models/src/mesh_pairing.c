/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for local machine pairing authority. */

#include "models/mesh_pairing.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(mesh_pairing)

static bool mesh_pairing_nonzero(const uint8_t value[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= value[i];
    return any != 0;
}

bool mesh_pairing_id_derive(
    const uint8_t network_genesis[32], const uint8_t peer_master_pubkey[32],
    const uint8_t peer_noise_pubkey[32],
    char out[MESH_PAIRING_ID_HEX + 1])
{
    if (!network_genesis || !peer_master_pubkey || !peer_noise_pubkey ||
        !out || !mesh_pairing_nonzero(network_genesis) ||
        !mesh_pairing_nonzero(peer_master_pubkey) ||
        !mesh_pairing_nonzero(peer_noise_pubkey))
        LOG_FAIL("mesh_pairing", "derive: missing or zero identity input");
    static const uint8_t domain[] = "zcl.mesh.pairing.v1";
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, network_genesis, 32);
    sha3_256_write(&hash, peer_master_pubkey, 32);
    sha3_256_write(&hash, peer_noise_pubkey, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return true;
}

static bool mesh_pairing_before_validate(void *record, void *ctx)
{
    struct db_mesh_pairing *row = record;
    (void)ctx;
    if (!row)
        return false;
    return mesh_pairing_id_derive(
        row->network_genesis, row->peer_master_pubkey,
        row->peer_noise_pubkey, row->pairing_id);
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(mesh_pairing,
                                   mesh_pairing_before_validate)

static bool mesh_pairing_hex_id(const char *value)
{
    if (!value || strlen(value) != MESH_PAIRING_ID_HEX)
        return false;
    for (size_t i = 0; i < MESH_PAIRING_ID_HEX; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

bool db_mesh_pairing_validate(const struct db_mesh_pairing *row,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    char derived[MESH_PAIRING_ID_HEX + 1] = {0};
    bool identities = mesh_pairing_nonzero(row->network_genesis) &&
                      mesh_pairing_nonzero(row->peer_master_pubkey) &&
                      mesh_pairing_nonzero(row->peer_noise_pubkey);
    bool id_ok = identities && mesh_pairing_id_derive(
        row->network_genesis, row->peer_master_pubkey,
        row->peer_noise_pubkey, derived);
    validates_custom(errors, mesh_pairing_hex_id(row->pairing_id) && id_ok &&
                     strcmp(row->pairing_id, derived) == 0,
                     "pairing_id", "must match the bound public identities");
    validates_custom(errors, identities, "identities",
                     "must be non-zero public identities");
    validates_custom(errors, row->capability_mask != 0 &&
                     (row->capability_mask & ~MESH_PAIRING_CAP_KNOWN) == 0,
                     "capability_mask", "contains an unavailable capability");
    validates_custom(errors, row->delegation_sequence > 0 &&
                     row->delegation_sequence <= (uint64_t)INT64_MAX,
                     "delegation_sequence", "must be a positive int64");
    validates_custom(errors, row->paired_at > 0, "paired_at",
                     "must be positive");
    validates_custom(errors, row->expires_at > row->paired_at, "expires_at",
                     "must be after pairing");
    validates_custom(errors,
                     (row->revoked_at == 0 &&
                      row->revocation_generation == 0) ||
                     (row->revoked_at >= row->paired_at &&
                      row->revocation_generation > 0),
                     "revocation", "timestamp and generation disagree");
    return !ar_errors_any(errors);
}

bool db_mesh_pairing_insert(struct node_db *ndb,
                            const struct db_mesh_pairing *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("mesh_pairing", "insert: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO mesh_pairings(pairing_id,network_genesis,"
        "peer_master_pubkey,peer_noise_pubkey,capability_mask,"
        "delegation_sequence,paired_at,expires_at,revoked_at,"
        "revocation_generation) VALUES(?,?,?,?,?,?,?,?,?,?)",
        mesh_pairing_callbacks_ready(), "mesh_pairing", row,
        db_mesh_pairing_validate,
        AR_BIND_TEXT(st, 1, row->pairing_id);
        AR_BIND_BLOB(st, 2, row->network_genesis, 32);
        AR_BIND_BLOB(st, 3, row->peer_master_pubkey, 32);
        AR_BIND_BLOB(st, 4, row->peer_noise_pubkey, 32);
        AR_BIND_INT(st, 5, (int64_t)row->capability_mask);
        AR_BIND_INT(st, 6, (int64_t)row->delegation_sequence);
        AR_BIND_INT(st, 7, row->paired_at);
        AR_BIND_INT(st, 8, row->expires_at);
        AR_BIND_INT(st, 9, row->revoked_at);
        AR_BIND_INT(st, 10, (int64_t)row->revocation_generation));
}

static void mesh_pairing_read(struct db_mesh_pairing *out, sqlite3_stmt *st)
{
    memset(out, 0, sizeof(*out));
    AR_READ_STR(st, 0, out->pairing_id, sizeof(out->pairing_id));
    AR_READ_BLOB(st, 1, out->network_genesis, 32);
    AR_READ_BLOB(st, 2, out->peer_master_pubkey, 32);
    AR_READ_BLOB(st, 3, out->peer_noise_pubkey, 32);
    out->capability_mask = (uint64_t)AR_COL_INT(st, 4);
    out->delegation_sequence = (uint64_t)AR_COL_INT(st, 5);
    out->paired_at = AR_COL_INT(st, 6);
    out->expires_at = AR_COL_INT(st, 7);
    out->revoked_at = AR_COL_INT(st, 8);
    out->revocation_generation = (uint64_t)AR_COL_INT(st, 9);
}

#define MESH_PAIRING_COLS \
    "pairing_id,network_genesis,peer_master_pubkey,peer_noise_pubkey," \
    "capability_mask,delegation_sequence,paired_at,expires_at,revoked_at," \
    "revocation_generation"

bool db_mesh_pairing_find(struct node_db *ndb, const char *pairing_id,
                          struct db_mesh_pairing *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !pairing_id || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " MESH_PAIRING_COLS " FROM mesh_pairings WHERE pairing_id=?",
        AR_BIND_TEXT(st, 1, pairing_id), mesh_pairing_read(out, st));
}

int db_mesh_pairing_list(struct node_db *ndb, struct db_mesh_pairing *out,
                         size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " MESH_PAIRING_COLS " FROM mesh_pairings "
        "ORDER BY paired_at,pairing_id LIMIT ?",
        out, max, AR_BIND_INT(st, 1, (int64_t)max),
        mesh_pairing_read(&out[count], st));
}

bool db_mesh_pairing_count_states(struct node_db *ndb, int64_t now,
                                  struct db_mesh_pairing_counts *out)
{
    if (!ndb || !ndb->open || now <= 0 || !out)
        LOG_FAIL("mesh_pairing", "count_states: bad args");
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    AR_PREPARE_RET(ndb, st,
        "SELECT COUNT(*),"
        "COALESCE(SUM(CASE WHEN revoked_at=0 AND expires_at>? "
        "THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN revoked_at=0 AND expires_at<=? "
        "THEN 1 ELSE 0 END),0),"
        "COALESCE(SUM(CASE WHEN revoked_at!=0 THEN 1 ELSE 0 END),0) "
        "FROM mesh_pairings", false);
    AR_BIND_INT(st, 1, now);
    AR_BIND_INT(st, 2, now);
    if (!AR_STEP_ROW(st)) {
        AR_FINALIZE(st);
        LOG_FAIL("mesh_pairing", "count_states: query returned no row");
    }
    out->total = AR_COL_INT(st, 0);
    out->active = AR_COL_INT(st, 1);
    out->expired = AR_COL_INT(st, 2);
    out->revoked = AR_COL_INT(st, 3);
    AR_FINALIZE(st);
    return out->total >= 0 && out->active >= 0 && out->expired >= 0 &&
           out->revoked >= 0 &&
           out->total == out->active + out->expired + out->revoked;
}

bool db_mesh_pairing_revoke(struct node_db *ndb, const char *pairing_id,
                            int64_t revoked_at)
{
    struct db_mesh_pairing row;
    if (!ndb || !ndb->open || !pairing_id || revoked_at <= 0 ||
        !db_mesh_pairing_find(ndb, pairing_id, &row))
        LOG_FAIL("mesh_pairing", "revoke: pairing not found or bad args");
    if (row.revoked_at != 0)
        return true;
    if (revoked_at < row.paired_at ||
        row.revocation_generation == UINT64_MAX)
        LOG_FAIL("mesh_pairing", "revoke: invalid time or generation");
    uint64_t prior_generation = row.revocation_generation;
    row.revoked_at = revoked_at;
    row.revocation_generation++;
    sqlite3_stmt *st = NULL;
    AR_BEGIN_SAVE(mesh_pairing_callbacks_ready(), "mesh_pairing", &row,
                  db_mesh_pairing_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE mesh_pairings SET revoked_at=?,revocation_generation=? "
        "WHERE pairing_id=? AND revoked_at=0 AND revocation_generation=? "
        "RETURNING pairing_id");
    AR_BIND_INT(st, 1, row.revoked_at);
    AR_BIND_INT(st, 2, (int64_t)row.revocation_generation);
    AR_BIND_TEXT(st, 3, row.pairing_id);
    AR_BIND_INT(st, 4, (int64_t)prior_generation);
    bool ok = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    AR_FINISH_SAVE(mesh_pairing_callbacks_ready(), &row, ok);
}

bool mesh_pairing_allows(const struct db_mesh_pairing *row,
                         uint64_t required_capability, int64_t now)
{
    if (!row || required_capability == 0 ||
        (required_capability & ~MESH_PAIRING_CAP_KNOWN) != 0 || now <= 0)
        return false;
    return row->revoked_at == 0 && now < row->expires_at &&
           (row->capability_mask & required_capability) ==
               required_capability;
}
