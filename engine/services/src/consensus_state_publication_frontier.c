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
    if (!db || !height || !hash)
        return false; /* raw-return-ok:null-out-param */
    bool ok = false;
    int32_t hstar = -1;
    int32_t served_floor = -1;
    int durable_h = -1;
    uint8_t durable_hash[32] = {0};
    uint8_t hstar_hash[32] = {0};

    bool hstar_ok = reducer_frontier_compute_hstar(db, &hstar, &served_floor);
    bool hash_ok = hstar_ok && hstar >= 0 &&
                   tip_finalize_stage_block_hash_at(db, hstar, hstar_hash);
    /* Diagnostic cross-check only (never a gate): durable_h is expected in
     * {H*, H*+1} by the finalized-row lattice. */
    bool durable_ok =
        tip_finalize_stage_resolve_durable_tip(db, &durable_h, durable_hash);
    if (hstar_ok && hash_ok) {
        *height = hstar;
        memcpy(hash, hstar_hash, 32);
        ok = true;
    } else if (reducer_frontier_provable_tip_is_published() &&
               reducer_frontier_provable_tip_cached() == 0) {
        /* Fresh instant-on runs before reducer tables have a durable row, but
         * tip_finalize_stage_warm_authority_caches has published the genuine
         * runtime genesis pair. Bind that exact (0, genesis-hash) pair into the
         * CAS record; the opaque chain evidence independently requires stable
         * clean-genesis plus compiled-checkpoint authority before admission. */
        int64_t authority_h = -1;
        uint8_t authority_hash[32] = {0};
        if (tip_finalize_stage_authority_snapshot(&authority_h,
                                                  authority_hash) &&
            authority_h == 0) {
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
        for (int i = 0; i < 32; i++)
            snprintf(hh + (size_t)i * 2, 3, "%02x", hstar_hash[i]);
        LOG_ERROR(CAS_SUBSYS,
                  "frontier capture failed: compute_hstar=%s hstar=%d "
                  "served_floor=%d hstar_hash_resolved=%s durable_resolve=%s "
                  "durable_h=%d hstar_hash=%s (bind requires compute_hstar ok, "
                  "hstar>=0, and a resolvable hash at hstar)",
                  hstar_ok ? "ok" : "FAIL", hstar, served_floor,
                  hash_ok ? "ok" : "FAIL", durable_ok ? "ok" : "FAIL",
                  durable_h, hh);
    } else if (durable_ok && durable_h != hstar && durable_h != hstar + 1) {
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
