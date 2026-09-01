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
 * borrowed install to sovereign ONLY on an exact match. Contract:
 * config/consensus_state_snapshot_install.h. */

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
