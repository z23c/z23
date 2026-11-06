/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_install_assisted_seam.c — the assisted-tier promotion seam.
 *
 * An ASSISTED (above-checkpoint, RELEASE_ASSISTED) install stamps only the
 * operational migration-complete marker and records THIS seam — the bundle
 * height plus the three manifest commitments (utxo_root, anchor_digest,
 * nullifier_digest) the borrowed state was verified against at activate time —
 * inside the same atomic cutover transaction. Background promotion later
 * re-derives from the compiled checkpoint UP TO this height and ratifies the
 * borrowed install to sovereign ONLY on an exact match. The same file keeps
 * the install authority stamp every activate writes in that transaction.
 * Contract: config/consensus_state_snapshot_install.h. */

#include "config/consensus_state_snapshot_install.h"

#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

#define ASSISTED_SEAM_SUBSYS "consensus_bundle_activate"

/* key -> 4-byte LE height || utxo_root[32] || anchor_digest[32] ||
 * nullifier_digest[32] (100 bytes). */
#define ASSISTED_SEAM_META_KEY "consensus_state.assisted_seam"
#define ASSISTED_SEAM_BLOB_LEN (4u + 32u + 32u + 32u)

bool consensus_state_install_record_assisted_seam(
    sqlite3 *progress_db, int32_t height, const uint8_t utxo_root[32],
    const uint8_t anchor_digest[32], const uint8_t nullifier_digest[32])
{
    if (!progress_db || height < 0 || !utxo_root || !anchor_digest ||
        !nullifier_digest) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS, "record_assisted_seam: invalid args");
        return false;
    }
    uint8_t blob[ASSISTED_SEAM_BLOB_LEN];
    uint32_t h = (uint32_t)height;
    for (size_t i = 0; i < 4; i++)
        blob[i] = (uint8_t)(h >> (8u * i));
    memcpy(blob + 4, utxo_root, 32);
    memcpy(blob + 36, anchor_digest, 32);
    memcpy(blob + 68, nullifier_digest, 32);
    /* Must run inside the caller's open activate cutover transaction. */
    if (!progress_meta_set_in_tx(progress_db, ASSISTED_SEAM_META_KEY, blob,
                                 sizeof(blob))) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS,
                 "record_assisted_seam: progress_meta_set_in_tx failed");
        return false;
    }
    return true;
}

bool consensus_state_install_read_assisted_seam(
    sqlite3 *progress_db, int32_t *height, uint8_t utxo_root[32],
    uint8_t anchor_digest[32], uint8_t nullifier_digest[32], bool *found)
{
    if (found)
        *found = false;
    if (!progress_db || !height || !utxo_root || !anchor_digest ||
        !nullifier_digest || !found) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS, "read_assisted_seam: invalid args");
        return false;
    }
    uint8_t blob[ASSISTED_SEAM_BLOB_LEN];
    size_t got = 0;
    bool present = false;
    /* Authority-bearing metadata: exact-BLOB reader (no TEXT/INT coercion). */
    if (!progress_meta_get_blob_exact(progress_db, ASSISTED_SEAM_META_KEY, blob,
                                      sizeof(blob), &got, &present)) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS, "read_assisted_seam: blob read failed");
        return false;
    }
    if (!present)
        return true; /* no assisted seam recorded — a sovereign install */
    if (got != sizeof(blob)) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS,
                 "read_assisted_seam: seam blob length %zu != %u (corrupt)",
                 got, (unsigned)sizeof(blob));
        return false;
    }
    uint32_t h = 0;
    for (size_t i = 0; i < 4; i++)
        h |= (uint32_t)blob[i] << (8u * i);
    *height = (int32_t)h;
    memcpy(utxo_root, blob + 4, 32);
    memcpy(anchor_digest, blob + 36, 32);
    memcpy(nullifier_digest, blob + 68, 32);
    *found = true;
    return true;
}

/* key -> kind[1] || 4-byte LE height || block_hash[32] || utxo_root[32] ||
 * 8-byte LE coins authority generation. */
#define INSTALL_STAMP_META_KEY "consensus_state.install_authority"
#define INSTALL_STAMP_BLOB_LEN (1u + 4u + 32u + 32u + 8u)

static bool install_stamp_kind_known(int kind)
{
    return kind >= CONSENSUS_INSTALL_STAMP_RECEIPT &&
           kind <= CONSENSUS_INSTALL_STAMP_ASSISTED;
}

bool consensus_state_install_record_authority_stamp(
    sqlite3 *progress_db, const struct consensus_state_install_stamp *stamp)
{
    if (!progress_db || !stamp || stamp->height < 0 ||
        !install_stamp_kind_known((int)stamp->kind)) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS, "record_authority_stamp: invalid args");
        return false;
    }
    uint8_t blob[INSTALL_STAMP_BLOB_LEN];
    uint32_t h = (uint32_t)stamp->height;
    blob[0] = (uint8_t)stamp->kind;
    for (size_t i = 0; i < 4; i++)
        blob[1 + i] = (uint8_t)(h >> (8u * i));
    memcpy(blob + 5, stamp->block_hash, 32);
    memcpy(blob + 37, stamp->utxo_root, 32);
    for (size_t i = 0; i < 8; i++)
        blob[69 + i] = (uint8_t)(stamp->coins_generation >> (8u * i));
    /* Must run inside the caller's open activate cutover transaction. */
    if (!progress_meta_set_in_tx(progress_db, INSTALL_STAMP_META_KEY, blob,
                                 sizeof(blob))) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS,
                 "record_authority_stamp: progress_meta_set_in_tx failed");
        return false;
    }
    return true;
}

bool consensus_state_install_read_authority_stamp(
    sqlite3 *progress_db, struct consensus_state_install_stamp *out,
    bool *found)
{
    if (found)
        *found = false;
    if (!progress_db || !out || !found) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS, "read_authority_stamp: invalid args");
        return false;
    }
    uint8_t blob[INSTALL_STAMP_BLOB_LEN];
    size_t got = 0;
    bool present = false;
    if (!progress_meta_get_blob_exact(progress_db, INSTALL_STAMP_META_KEY, blob,
                                      sizeof(blob), &got, &present)) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS, "read_authority_stamp: blob read failed");
        return false;
    }
    if (!present)
        return true; /* no install stamped this store */
    if (got != sizeof(blob) || !install_stamp_kind_known(blob[0])) {
        LOG_WARN(ASSISTED_SEAM_SUBSYS,
                 "read_authority_stamp: record length %zu kind %u (corrupt)",
                 got, (unsigned)blob[0]);
        return false;
    }
    uint32_t h = 0;
    for (size_t i = 0; i < 4; i++)
        h |= (uint32_t)blob[1 + i] << (8u * i);
    out->kind = (enum consensus_state_install_stamp_kind)blob[0];
    out->height = (int32_t)h;
    memcpy(out->block_hash, blob + 5, 32);
    memcpy(out->utxo_root, blob + 37, 32);
    out->coins_generation = 0;
    for (size_t i = 0; i < 8; i++)
        out->coins_generation |= (uint64_t)blob[69 + i] << (8u * i);
    *found = true;
    return true;
}
