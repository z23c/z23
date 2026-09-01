/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * See config/boot_snapshot_install.h. */

#include "config/boot.h"
#include "config/boot_snapshot_install.h"

#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"
#include "event/event.h"
#include "services/chain_restore_boot_snapshot.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <stddef.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SNAPSHOT_INSTALL_MARKER_VERSION 2u
#define SNAPSHOT_INSTALL_PENDING 0u
#define SNAPSHOT_INSTALL_COMPLETE 1u

static void put_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value; out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16); out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32_le(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void put_u64_le(uint8_t *out, uint64_t value)
{
    for (size_t i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (8u * i));
}

static uint64_t get_u64_le(const uint8_t *in)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++) value |= (uint64_t)in[i] << (8u * i);
    return value;
}

static bool marker_shape_valid(
    const uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES], size_t len)
{
    return marker && len == BOOT_SNAPSHOT_INSTALL_MARKER_BYTES &&
           memcmp(marker, "ZCLSIM2", 7) == 0 && marker[7] == 0 &&
           get_u32_le(marker + 8) == SNAPSHOT_INSTALL_MARKER_VERSION &&
           get_u32_le(marker + 12) == BOOT_SNAPSHOT_INSTALL_MARKER_BYTES &&
           marker[48] <= SNAPSHOT_INSTALL_COMPLETE && marker[49] <= 1 &&
           memcmp(marker + 58, (uint8_t[6]){0}, 6) == 0 &&
           (marker[48] == SNAPSHOT_INSTALL_COMPLETE || marker[49] == 0);
}

static bool legacy_marker_matches(
    const uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES], size_t len,
    const struct uss_header *header)
{
    return marker && header && len == BOOT_SNAPSHOT_INSTALL_MARKER_BYTES &&
           memcmp(marker, "ZCLSIM1", 7) == 0 && marker[7] == 0 &&
           get_u32_le(marker + 8) == 1 &&
           get_u32_le(marker + 12) == BOOT_SNAPSHOT_INSTALL_MARKER_BYTES &&
           get_u32_le(marker + 16) == header->height &&
           marker[20] == 0 && marker[21] == 0 && marker[22] == 0 &&
           marker[23] == 0 && get_u64_le(marker + 24) == header->count &&
           memcmp(marker + 32, header->sha3_hash, 32) == 0;
}

static void marker_encode(uint8_t out[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES],
                          const uint8_t artifact_sha256[32], uint8_t state,
                          bool embedded_frontier_verified,
                          uint64_t authority_generation)
{
    memset(out, 0, BOOT_SNAPSHOT_INSTALL_MARKER_BYTES);
    memcpy(out, "ZCLSIM2", 7);
    put_u32_le(out + 8, SNAPSHOT_INSTALL_MARKER_VERSION);
    put_u32_le(out + 12, BOOT_SNAPSHOT_INSTALL_MARKER_BYTES);
    memcpy(out + 16, artifact_sha256, 32);
    out[48] = state;
    out[49] = embedded_frontier_verified ? 1 : 0;
    put_u64_le(out + 50, authority_generation);
}

static bool marker_identity_matches(
    const uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES], size_t len,
    const uint8_t artifact_sha256[32])
{
    return marker_shape_valid(marker, len) && artifact_sha256 &&
           memcmp(marker + 16, artifact_sha256, 32) == 0;
}

bool boot_snapshot_install_marker_begin(
    struct sqlite3 *db, const struct uss_header *header,
    const uint8_t artifact_sha256[32])
{
    if (!db || !header || !artifact_sha256)
        LOG_FAIL("boot", "snapshot install marker: invalid begin arguments");
    bool pending = true, matches = false;
    if (!boot_snapshot_install_marker_pending(db, &pending))
        LOG_FAIL("boot", "snapshot install marker: prior state unreadable");
    if (pending) {
        uint8_t prior[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
        size_t prior_len = 0;
        bool found = false;
        if (progress_meta_get_blob_exact(
                db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY, prior, sizeof(prior),
                &prior_len, &found) && found &&
            legacy_marker_matches(prior, prior_len, header)) {
            marker_encode(prior, artifact_sha256, SNAPSHOT_INSTALL_PENDING,
                          false, 0);
            return progress_meta_set(db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                                     prior, sizeof(prior));
        }
        (void)boot_snapshot_install_marker_blocks_resume(
            db, artifact_sha256, &matches);
        if (!matches)
            LOG_FAIL("boot", "snapshot install marker: pending identity mismatch");
        return true;
    }
    uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES];
    marker_encode(marker, artifact_sha256, SNAPSHOT_INSTALL_PENDING, false, 0);
    if (!progress_meta_set(db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                           marker, sizeof(marker)))
        LOG_FAIL("boot", "snapshot install marker: durable begin failed");
    return true;
}

bool boot_snapshot_install_marker_blocks_resume(
    struct sqlite3 *db, const uint8_t artifact_sha256[32], bool *matches)
{
    if (matches) *matches = false;
    if (!db || !artifact_sha256) return true;
    uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
    size_t len = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                                      marker, sizeof(marker), &len, &found))
        return true;
    if (!found) return false;
    bool identity_matches = marker_identity_matches(
        marker, len, artifact_sha256);
    if (matches) *matches = identity_matches;
    return !identity_matches ||
           marker[48] != SNAPSHOT_INSTALL_COMPLETE;
}

bool boot_snapshot_install_marker_complete(
    struct sqlite3 *db, const uint8_t artifact_sha256[32],
    bool embedded_frontier_verified)
{
    if (!db || !artifact_sha256)
        LOG_FAIL("boot", "snapshot install marker: invalid complete arguments");

    char *err = NULL;
    bool ok = true;
    uint64_t authority_generation = 0;
    uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
    size_t len = 0;
    bool found = false;
    progress_store_tx_lock();
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (ok && (!progress_meta_get_blob_exact(
                   db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY, marker,
                   sizeof(marker), &len, &found) || !found ||
               !marker_identity_matches(marker, len, artifact_sha256) ||
               marker[48] != SNAPSHOT_INSTALL_PENDING))
        ok = false;
    if (ok && !coins_kv_get_authority_generation(
                  db, &authority_generation))
        ok = false;
    if (ok) {
        marker_encode(marker, artifact_sha256, SNAPSHOT_INSTALL_COMPLETE,
                      embedded_frontier_verified, authority_generation);
        if (!progress_meta_set_in_tx(db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                                     marker, sizeof(marker))) ok = false;
    }
    if (ok && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK)
        ok = false;
    if (!ok)
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err)
        sqlite3_free(err);
    progress_store_tx_unlock();
    if (!ok)
        LOG_WARN("boot", "snapshot install marker: durable completion failed");
    return ok;
}

bool boot_snapshot_install_marker_pending(struct sqlite3 *db, bool *pending)
{
    if (pending) *pending = true;
    if (!db || !pending)
        LOG_FAIL("boot", "snapshot install marker: invalid pending arguments");
    uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
    size_t len = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY,
                                      marker, sizeof(marker), &len, &found))
        LOG_FAIL("boot", "snapshot install marker: pending read failed");
    if (!found) {
        *pending = false;
        return true;
    }
    if (!marker_shape_valid(marker, len) &&
        !(len == sizeof(marker) && memcmp(marker, "ZCLSIM1", 7) == 0 &&
          marker[7] == 0 && get_u32_le(marker + 8) == 1 &&
          get_u32_le(marker + 12) == BOOT_SNAPSHOT_INSTALL_MARKER_BYTES))
        LOG_FAIL("boot", "snapshot install marker: malformed durable receipt");
    *pending = !marker_shape_valid(marker, len) ||
               marker[48] == SNAPSHOT_INSTALL_PENDING;
    return true;
}

bool boot_snapshot_install_pending_artifact_matches(
    struct sqlite3 *db, const char *path, bool *pending_out)
{
    if (pending_out)
        *pending_out = true;
    bool pending = true;
    if (!db || !pending_out ||
        !boot_snapshot_install_marker_pending(db, &pending))
        return false;
    *pending_out = pending;
    if (!pending)
        return true;
    if (!path || !path[0])
        return false;

    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *snapshot = uss_open(
        path, /*verify_full_sha3=*/true, /*expected_sha3=*/NULL,
        &hdr, err, sizeof(err));
    if (!snapshot)
        return false;
    uint8_t artifact_sha256[32] = {0};
    bool matches = false;
    bool blocked = false;
    if (hdr.height <= (uint64_t)INT32_MAX &&
        uss_artifact_sha256(snapshot, artifact_sha256)) {
        uint8_t durable[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
        size_t durable_len = 0;
        bool found = false;
        if (progress_meta_get_blob_exact(
                db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY, durable,
                sizeof(durable), &durable_len, &found) && found &&
            legacy_marker_matches(durable, durable_len, &hdr)) {
            matches = true;
            blocked = true;
        } else {
            blocked = boot_snapshot_install_marker_blocks_resume(
                db, artifact_sha256, &matches);
        }
    }
    uss_close(snapshot);
    return blocked && matches;
}

bool boot_snapshot_install_resume_allowed(struct sqlite3 *db,
    const struct uss_header *snapshot, const uint8_t artifact_sha256[32],
    int32_t *applied, bool *install_pending, bool *marker_matches,
    bool *embedded_frontier_verified)
{
    if (applied) *applied = -1;
    if (install_pending) *install_pending = true;
    if (marker_matches) *marker_matches = false;
    if (embedded_frontier_verified) *embedded_frontier_verified = false;
    if (!db || !snapshot || !artifact_sha256 || !applied) return false;
    bool matches = false;
    bool pending = boot_snapshot_install_marker_blocks_resume(
        db, artifact_sha256, &matches);
    if (install_pending) *install_pending = pending;
    if (marker_matches) *marker_matches = matches;
    if (!pending && matches) {
        uint8_t marker[BOOT_SNAPSHOT_INSTALL_MARKER_BYTES] = {0};
        size_t len = 0;
        bool found = false;
        uint64_t authority_generation = 0;
        if (!progress_meta_get_blob_exact(
                db, BOOT_SNAPSHOT_INSTALL_MARKER_KEY, marker,
                sizeof(marker), &len, &found) || !found ||
            !marker_identity_matches(marker, len, artifact_sha256) ||
            marker[48] != SNAPSHOT_INSTALL_COMPLETE ||
            !coins_kv_get_authority_generation(db, &authority_generation) ||
            get_u64_le(marker + 50) != authority_generation)
            matches = false;
        else if (embedded_frontier_verified)
            *embedded_frontier_verified = marker[49] == 1;
    }
    return !pending && matches && coins_kv_is_proven_authority(db, applied) &&
           *applied >= (int32_t)snapshot->height + 1;
}

bool boot_snapshot_anchor_hash_matches(const unsigned char *index_hash,
                                       const unsigned char *snapshot_hash)
{
    return index_hash && snapshot_hash &&
           memcmp(index_hash, snapshot_hash, 32) == 0;
}

bool boot_snapshot_install_headers_equal(const struct uss_header *a,
                                         const struct uss_header *b)
{
    return a && b && a->version == b->version && a->height == b->height &&
           a->count == b->count && a->total_supply == b->total_supply &&
           memcmp(a->anchor_block_hash, b->anchor_block_hash, 32) == 0 &&
           memcmp(a->sha3_hash, b->sha3_hash, 32) == 0;
}

bool boot_legacy_uss_matches_checkpoint(
    struct uss_handle *snapshot, const struct uss_header *header,
    const struct sha3_utxo_checkpoint *checkpoint,
    char *err, size_t err_size)
{
    if (!snapshot || !header || !checkpoint)
        return false;
    struct uss_utxo_component component;
    if (!uss_utxo_component_compute(snapshot, &component, err, err_size))
        return false;
    return header->height == (uint32_t)checkpoint->height &&
           memcmp(header->anchor_block_hash, checkpoint->block_hash, 32) == 0 &&
           component.count == checkpoint->utxo_count &&
           component.total_supply == checkpoint->total_supply &&
           memcmp(component.sha3_hash, checkpoint->sha3_hash, 32) == 0;
}

void boot_snapshot_install_require_chain_context(
    const struct main_state *main_state)
{
#ifdef ZCL_TESTING
    (void)main_state;
#else
    if (main_state) return;
    fprintf(stderr,
            "FATAL: snapshot install requires main_state to bind its anchor "
            "to the validated local header chain; REFUSING unbound state\n");
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "load_snapshot_at_own_height missing_main_state");
    _exit(EXIT_FAILURE);
#endif
}

void boot_snapshot_install_gate_boot(bool progress_open,
                                     const char *loader_path)
{
    if (!progress_open) {
        fprintf(stderr,
                "FATAL: progress_store unavailable; reducer cursors and "
                "snapshot journal cannot be verified; REFUSING to boot\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "progress_store_unavailable");
        _exit(EXIT_FAILURE);
    }
    bool pending = true;
    if (!boot_snapshot_install_marker_pending(progress_store_db(), &pending)) {
        fprintf(stderr,
                "FATAL: snapshot install journal read failed; REFUSING "
                "possibly partial state\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "snapshot_install_journal_read_failed");
        _exit(EXIT_FAILURE);
    }
    if (!pending)
        return;

    bool bound_pending = true;
    if (!boot_snapshot_install_pending_artifact_matches(
            progress_store_db(), loader_path, &bound_pending) ||
        !bound_pending) {
        fprintf(stderr,
                "FATAL: snapshot install incomplete; the exact prior "
                "whole-artifact SHA256 is required and the artifact must "
                "fully verify before recovery can resume\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "snapshot_install_pending_loader_mismatch_or_invalid");
        _exit(EXIT_FAILURE);
    }
}

void boot_snapshot_install_record_proof(
    const char *path, const struct uss_header *header,
    const uint8_t artifact_sha256[32],
    bool embedded_frontier_verified)
{
    if (!header || !artifact_sha256) return;
    chain_restore_record_assisted_snapshot_load(
        true, embedded_frontier_verified, true, header->height, header->count,
        header->sha3_hash, header->anchor_block_hash, artifact_sha256, path);
}

void boot_snapshot_install_require_complete(void)
{
    bool pending = true;
    if (!boot_snapshot_install_marker_pending(progress_store_db(), &pending) ||
        pending) {
        fprintf(stderr,
                "FATAL: snapshot loader returned with an incomplete install "
                "journal; REFUSING normal boot\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "snapshot_install_loader_returned_pending");
        _exit(EXIT_FAILURE);
    }
}
