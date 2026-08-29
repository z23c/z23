/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for latest paired-machine evidence. */

#include "models/mesh_machine_observation.h"

#include "base/hex.h"
#include "util/log_macros.h"

#include <limits.h>
#include <string.h>

DEFINE_MODEL_CALLBACKS(mesh_machine_observation)

static bool mesh_machine_pairing_id_valid(const char *value)
{
    uint8_t decoded[32];
    return value && strlen(value) == MESH_PAIRING_ID_HEX &&
           zcl_hex_decode_lower(value, decoded, sizeof(decoded));
}

static bool mesh_machine_observation_decode(
    const struct db_mesh_machine_observation *row,
    struct mesh_status_receipt_v1 *receipt)
{
    uint8_t root[32];
    if (!row || !receipt ||
        mesh_status_receipt_v1_decode(receipt, row->receipt_wire,
                                      row->receipt_len) !=
            MESH_STATUS_PROTO_OK ||
        mesh_status_receipt_v1_root(receipt, root) != MESH_STATUS_PROTO_OK)
        return false;
    return memcmp(root, row->receipt_root, sizeof(root)) == 0;
}

bool db_mesh_machine_observation_validate(
    const struct db_mesh_machine_observation *row, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, mesh_machine_pairing_id_valid(row->pairing_id),
                     "pairing_id", "must be 64 canonical lowercase hex chars");
    validates_custom(errors,
                     row->receipt_len >= MESH_STATUS_RECEIPT_V1_FIXED_BYTES &&
                         row->receipt_len <=
                             MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES,
                     "receipt_wire", "has an invalid length");
    validates_custom(errors, row->observed_unix > 0, "observed_unix",
                     "must be positive");
    validates_custom(errors, row->expires_unix > row->observed_unix,
                     "expires_unix", "must be after observation");
    validates_custom(errors, row->received_unix > 0, "received_unix",
                     "must be positive");

    struct mesh_status_receipt_v1 receipt;
    bool decoded = mesh_machine_observation_decode(row, &receipt);
    validates_custom(errors, decoded, "receipt_wire",
                     "must be an exact valid signed receipt");
    if (decoded) {
        char pairing_id[MESH_PAIRING_ID_HEX + 1];
        zcl_hex_encode(receipt.pairing_id, 32, pairing_id);
        validates_custom(errors, strcmp(pairing_id, row->pairing_id) == 0,
                         "pairing_id", "differs from the signed receipt");
        validates_custom(errors, receipt.status == row->status, "status",
                         "differs from the signed receipt");
        validates_custom(errors,
                         receipt.observed_unix <= INT64_MAX &&
                             (int64_t)receipt.observed_unix ==
                                 row->observed_unix,
                         "observed_unix", "differs from the signed receipt");
        validates_custom(errors,
                         receipt.expires_unix <= INT64_MAX &&
                             (int64_t)receipt.expires_unix == row->expires_unix,
                         "expires_unix", "differs from the signed receipt");
    }
    return !ar_errors_any(errors);
}

static bool mesh_machine_observation_matches_pairing(
    const struct db_mesh_pairing *pairing,
    const struct mesh_status_receipt_v1 *receipt)
{
    char pairing_id[MESH_PAIRING_ID_HEX + 1];
    zcl_hex_encode(receipt->pairing_id, 32, pairing_id);
    return strcmp(pairing->pairing_id, pairing_id) == 0 &&
           memcmp(pairing->network_genesis, receipt->network_genesis, 32) == 0 &&
           memcmp(pairing->peer_master_pubkey,
                  receipt->responder_master_pubkey, 32) == 0 &&
           memcmp(pairing->peer_noise_pubkey,
                  receipt->responder_noise_static, 32) == 0;
}

bool db_mesh_machine_observation_save(
    struct node_db *ndb, const struct db_mesh_machine_observation *row)
{
    if (!ndb || !ndb->open || !row) {
        LOG_ERROR("mesh_machine_observation", "save: bad arguments");
        return false;
    }
    struct ar_callbacks *callbacks = db_mesh_machine_observation_callbacks();
    AR_BEGIN_SAVE(callbacks, "mesh_machine_observation", row,
                  db_mesh_machine_observation_validate);
    struct db_mesh_pairing pairing;
    struct mesh_status_receipt_v1 receipt;
    if (!db_mesh_pairing_find(ndb, row->pairing_id, &pairing) ||
        !mesh_machine_observation_decode(row, &receipt) ||
        !mesh_machine_observation_matches_pairing(&pairing, &receipt)) {
        LOG_ERROR("mesh_machine_observation",
                  "save: receipt identity does not match pairing %.64s",
                  row->pairing_id);
        AR_FINISH_SAVE(callbacks, row, false);
    }

    sqlite3_stmt *st = NULL;
    AR_PREPARE_BOOL(ndb, st,
        "INSERT INTO mesh_machine_observations("
        "pairing_id,receipt_wire,receipt_root,status,observed_unix,"
        "expires_unix,received_unix) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(pairing_id) DO UPDATE SET "
        "receipt_wire=excluded.receipt_wire,"
        "receipt_root=excluded.receipt_root,status=excluded.status,"
        "observed_unix=excluded.observed_unix,"
        "expires_unix=excluded.expires_unix,"
        "received_unix=excluded.received_unix "
        "WHERE excluded.observed_unix>mesh_machine_observations.observed_unix "
        "OR (excluded.observed_unix=mesh_machine_observations.observed_unix "
        "AND excluded.receipt_root=mesh_machine_observations.receipt_root) "
        "RETURNING pairing_id");
    AR_BIND_TEXT(st, 1, row->pairing_id);
    AR_BIND_BLOB(st, 2, row->receipt_wire, row->receipt_len);
    AR_BIND_BLOB(st, 3, row->receipt_root, 32);
    AR_BIND_INT(st, 4, row->status);
    AR_BIND_INT(st, 5, row->observed_unix);
    AR_BIND_INT(st, 6, row->expires_unix);
    AR_BIND_INT(st, 7, row->received_unix);
    bool saved = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    if (!saved)
        LOG_ERROR("mesh_machine_observation",
                  "save: refused stale or equivocal receipt for pairing %.64s",
                  row->pairing_id);
    AR_FINISH_SAVE(callbacks, row, saved);
}

static void mesh_machine_pairing_read(struct db_mesh_pairing *out,
                                      sqlite3_stmt *st)
{
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

static bool mesh_machine_observation_read(
    struct db_mesh_machine_observation *out, sqlite3_stmt *st, int first)
{
    int wire_len = AR_COL_BYTES(st, first + 1);
    const void *wire = sqlite3_column_blob(st, first + 1);
    if (!wire || wire_len < (int)MESH_STATUS_RECEIPT_V1_FIXED_BYTES ||
        wire_len > (int)MESH_STATUS_RECEIPT_V1_MAX_WIRE_BYTES)
        return false;
    AR_READ_STR(st, first, out->pairing_id, sizeof(out->pairing_id));
    memcpy(out->receipt_wire, wire, (size_t)wire_len);
    out->receipt_len = (size_t)wire_len;
    AR_READ_BLOB(st, first + 2, out->receipt_root, 32);
    out->status = (enum mesh_status_receipt_status)AR_COL_INT(st, first + 3);
    out->observed_unix = AR_COL_INT(st, first + 4);
    out->expires_unix = AR_COL_INT(st, first + 5);
    out->received_unix = AR_COL_INT(st, first + 6);
    return true;
}

int db_mesh_machine_observation_list(
    struct node_db *ndb, struct db_mesh_machine_view *out, size_t max,
    int64_t now)
{
    if (!ndb || !ndb->open || !out || max == 0 || now <= 0) {
        LOG_ERROR("mesh_machine_observation", "list: bad arguments");
        return -1;
    }
    sqlite3_stmt *st = NULL;
    AR_PREPARE_RET(ndb, st,
        "SELECT p.pairing_id,p.network_genesis,p.peer_master_pubkey,"
        "p.peer_noise_pubkey,p.capability_mask,p.delegation_sequence,"
        "p.paired_at,p.expires_at,p.revoked_at,p.revocation_generation,"
        "o.pairing_id,o.receipt_wire,o.receipt_root,o.status,"
        "o.observed_unix,o.expires_unix,o.received_unix "
        "FROM mesh_pairings p LEFT JOIN mesh_machine_observations o "
        "ON o.pairing_id=p.pairing_id "
        "ORDER BY p.paired_at,p.pairing_id LIMIT ?", -1);
    AR_BIND_INT(st, 1, (int64_t)max);
    int count = 0;
    while ((size_t)count < max && AR_STEP_ROW(st)) {
        memset(&out[count], 0, sizeof(out[count]));
        mesh_machine_pairing_read(&out[count].pairing, st);
        if (sqlite3_column_type(st, 10) != SQLITE_NULL) {
            out[count].has_observation = mesh_machine_observation_read(
                &out[count].observation, st, 10);
            if (!out[count].has_observation) {
                LOG_ERROR("mesh_machine_observation",
                          "list: malformed durable row for pairing %.64s",
                          out[count].pairing.pairing_id);
                AR_FINALIZE(st);
                return -1;
            }
        }
        count++;
    }
    AR_FINALIZE(st);
    return count;
}
