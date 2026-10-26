/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The CAS frontier-capture seam, split out of
 * consensus_state_publication_cas.c. Captures the node's provable frontier
 * (H*) and H*'s own block hash for the publication decision's staleness
 * binding, reading the open progress-store singleton (never mutating it). */

// one-result-type-ok:cas-frontier-capture-total-predicate — capture is a TOTAL
// bool predicate over the open progress store (captured / genuinely-unknown),
// logging every number on refusal; it owns no fallible service I/O surface.

#include "services/consensus_state_publication_cas.h"

#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAS_SUBSYS "consensus_publication_cas"

/* Null-guard for the capture's inputs: refuse before touching the store. */
static bool frontier_capture_args_present(sqlite3 *db, int32_t *height,
                                          uint8_t hash[32])
{
    return db != NULL && height != NULL && hash != NULL;
}

/* Resolve H*'s own block hash; the lookup is attempted only when
 * compute_hstar succeeded and H* is a non-negative height. */
static bool frontier_capture_hstar_hash_resolves(sqlite3 *db, bool hstar_ok,
                                                 int32_t hstar,
                                                 uint8_t hstar_hash[32])
{
    return hstar_ok && hstar >= 0 &&
           tip_finalize_stage_block_hash_at(db, hstar, hstar_hash);
}

/* Instant-on eligibility probe: the published provable tip sits at height 0. */
static bool frontier_capture_provable_tip_sits_at_genesis(void)
{
    return reducer_frontier_provable_tip_is_published() &&
           reducer_frontier_provable_tip_cached() == 0;
}

/* Accept the warm authority snapshot only when it is the genesis pair. */
static bool frontier_capture_authority_pins_genesis(
    int64_t *authority_h, uint8_t authority_hash[32])
{
    return tip_finalize_stage_authority_snapshot(authority_h,
                                                 authority_hash) &&
           *authority_h == 0;
}

/* Diagnostic divergence predicate: by the finalized-row lattice durable_h is
 * H* or H*+1, so anything else is worth a warning. */
static bool frontier_capture_durable_tip_diverges(bool durable_ok,
                                                  int durable_h,
                                                  int32_t hstar)
{
    return durable_ok && durable_h != hstar && durable_h != hstar + 1;
}

/* Render a 32-byte hash as 64 lowercase hex digits in hh[65]. */
static void frontier_capture_hash_to_hex(const uint8_t hash[32], char hh[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(hh + (size_t)i * 2, 3, "%02x", hash[i]);
}

/* Bind H* with block_hash_at(H*) — the provable, consumer-facing frontier and
 * its OWN hash. The earlier capture demanded resolve_durable_tip()==H*, which
 * the finalized lattice never satisfies in steady state: a `finalized`
 * tip_finalize_log row at height H binds tip H+1, so resolve_durable_tip()
 * legitimately LEADS H* by one (it equals H* only right after a fresh
 * seed-anchor install, where the row at H carries hash(H)). A node that has
 * SERVED and advanced the pipeline therefore always has durable_h == H*+1, so
 * the old equality could only succeed on an un-advanced datadir — the observed
 * -install-consensus-bundle `frontier_unknown` refusal. This binds the same
 * (H*, hash-of-H*) pair the old success path produced, obtained directly, and
 * refuses ONLY on a genuine unknown (compute_hstar fails, H*<0, or H*'s hash is
 * unresolvable). resolve_durable_tip() stays as a logged diagnostic. The
 * captured frontier is consumed only as "a consistent frontier >= bundle
 * height" (cas_run's frontier_height >= manifest.height guard + the staleness
 * match), never as exact tip equality. */
bool consensus_state_publication_cas_capture_frontier_locked(
    sqlite3 *db, int32_t *height, uint8_t hash[32])
{
    if (!frontier_capture_args_present(db, height, hash))
        return false; /* raw-return-ok:null-out-param */
    bool ok = false;
    int32_t hstar = -1;
    int32_t served_floor = -1;
    int durable_h = -1;
    uint8_t durable_hash[32] = {0};
    uint8_t hstar_hash[32] = {0};

    bool hstar_ok = reducer_frontier_compute_hstar(db, &hstar, &served_floor);
    bool hash_ok = frontier_capture_hstar_hash_resolves(db, hstar_ok, hstar,
                                                        hstar_hash);
    /* Diagnostic cross-check only (never a gate): durable_h is expected in
     * {H*, H*+1} by the finalized-row lattice. */
    bool durable_ok =
        tip_finalize_stage_resolve_durable_tip(db, &durable_h, durable_hash);
    if (hstar_ok && hash_ok) {
        *height = hstar;
        memcpy(hash, hstar_hash, 32);
        ok = true;
    } else if (frontier_capture_provable_tip_sits_at_genesis()) {
        /* Fresh instant-on runs before reducer tables have a durable row, but
         * tip_finalize_stage_warm_authority_caches has published the genuine
         * runtime genesis pair. Bind that exact (0, genesis-hash) pair into the
         * CAS record; the opaque chain evidence independently requires stable
         * clean-genesis plus compiled-checkpoint authority before admission. */
        int64_t authority_h = -1;
        uint8_t authority_hash[32] = {0};
        if (frontier_capture_authority_pins_genesis(&authority_h,
                                                    authority_hash)) {
            *height = 0;
            memcpy(hash, authority_hash, 32);
            memcpy(hstar_hash, authority_hash, 32);
            ok = true;
            LOG_INFO(CAS_SUBSYS,
                     "frontier capture used clean-genesis runtime authority "
                     "h=0 (durable reducer rows not initialized yet)");
        }
    }
    if (!ok) {
        /* A blind refusal after a long verify is a diagnosed defect class in
         * this repo — log EVERY number so the refusal is self-explaining. */
        char hh[65] = {0};
        frontier_capture_hash_to_hex(hstar_hash, hh);
        LOG_ERROR(CAS_SUBSYS,
                  "frontier capture failed: compute_hstar=%s hstar=%d "
                  "served_floor=%d hstar_hash_resolved=%s durable_resolve=%s "
                  "durable_h=%d hstar_hash=%s (bind requires compute_hstar ok, "
                  "hstar>=0, and a resolvable hash at hstar)",
                  hstar_ok ? "ok" : "FAIL", hstar, served_floor,
                  hash_ok ? "ok" : "FAIL", durable_ok ? "ok" : "FAIL",
                  durable_h, hh);
    } else if (frontier_capture_durable_tip_diverges(durable_ok, durable_h,
                                                     hstar)) {
        LOG_WARN(CAS_SUBSYS,
                 "frontier captured at hstar=%d but durable tip resolved to "
                 "durable_h=%d (>1 above H* — check finalize lattice)",
                 hstar, durable_h);
    }
    return ok;
}

bool consensus_state_publication_cas_capture_frontier(int32_t *height,
                                                      uint8_t hash[32])
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return false; /* raw-return-ok:no-open-progress-store */
    progress_store_tx_lock();
    bool ok = consensus_state_publication_cas_capture_frontier_locked(
        db, height, hash);
    progress_store_tx_unlock();
    return ok;
}
