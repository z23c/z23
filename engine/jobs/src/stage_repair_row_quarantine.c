/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_row_quarantine — the RUNTIME poisoned-`blocks`-row cure (Lane
 * B3), sibling of the boot-time blocks-hydrate quarantine
 * (engine/services/src/block_index_blocks_hydrate.c:bhc_quarantine_row).
 *
 * The runtime header-solution repair loop (stale_validate_headers_repair) heals
 * a poisoned header_solution SIDE-TABLE row by re-fetching and overwriting it.
 * But when the DURABLE `blocks`-table row itself carries a poisoned/wrong
 * solution, that loop never purges the row, so the same poison re-hits the
 * frontier forever — the typed blocker re-arms on unbounded cooldown and H*
 * never advances. This helper closes that loop: it purges the poisoned `blocks`
 * row so header sync + body_fetch re-request a CLEAN body.
 *
 * SAFETY (load-bearing): the DELETE fires ONLY on concrete failure evidence —
 * the row's raw stored header is run through the SAME frozen block_row_verify()
 * primitive the persisted-state loaders admit at, and only a failing verdict
 * (hash-bind / high-hash / bad-Equihash) authorizes the purge. A row that
 * verifies OK is REFUSED, never deleted ("row looks odd" is not evidence). It
 * never touches tip_finalize_log and never lowers the served floor — it only
 * deletes ONE poisoned header row and clears its in-memory HAVE_DATA bit.
 *
 * TENACITY I3 (don't grow the repair ladder — fix the writer): the WRITER that
 * would emit a poisoned durable `blocks` row is the persisted-state admission
 * path, and it already REFUSES it at write time — the same block_row_verify()
 * gate quarantines a poisoned row on import (test_importblockindex_roundtrip,
 * scenarios C/D) and on the boot blocks-hydrate load (test_block_index_loader
 * case 16). This runtime rung is the last-mile for a row that became durable
 * BEFORE that gate existed (legacy / borrowed datadir state) and can only
 * DELETE what that same frozen verify independently rejects — it can never
 * fabricate a wrong deletion, so it adds no new trusted state, only removes
 * un-trustable state. // repair-rung-ok:test_importblockindex_roundtrip */

#include "jobs/stage_repair.h"
#include "jobs/block_header_emit.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "core/uint256.h"
#include "models/block.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "services/block_row_verify.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Process-monotonic tally of poisoned `blocks` rows purged at RUNTIME. Surfaced
 * by diag_block_index_dump_state_json (distinct from the boot blocks-hydrate
 * tally so an operator can tell a boot cure from a live one). */
static _Atomic int64_t g_runtime_row_quarantined = 0;

int64_t stage_repair_runtime_row_quarantined(void)
{
    return atomic_load_explicit(&g_runtime_row_quarantined,
                                memory_order_relaxed);
}

/* De-storm the quarantine WARN: keyed on height so a genuinely-different height
 * still emits, a repeat collapses to first-fire + 60 s keepalive. */
static struct log_throttle g_runtime_row_quarantine_log = LOG_THROTTLE_INIT;

/* Fixed typed-blocker id (height+hash+verdict travel in the reason string;
 * fire_count + the counter above carry multiplicity, so a per-height id is
 * deliberately NOT used — it would exhaust the registry on a shredded frontier).
 * TRANSIENT: the purge is recoverable — the height re-fetches and revalidates. */
#define RUNTIME_ROW_QUARANTINE_BLOCKER_ID "block_index.runtime_row_quarantine"

static const char *row_verify_verdict_name(enum block_row_verify_result r)
{
    switch (r) {
        case BLOCK_ROW_VERIFY_OK:                  return "ok";
        case BLOCK_ROW_VERIFY_NO_PARAMS:           return "no-chain-params";
        case BLOCK_ROW_VERIFY_HASH_BIND_MISMATCH:  return "hash-bind-mismatch";
        case BLOCK_ROW_VERIFY_HIGH_HASH:           return "high-hash";
        case BLOCK_ROW_VERIFY_BAD_EQUIHASH:        return "invalid-equihash-solution";
    }
    return "unknown";
}

/* Clear BLOCK_HAVE_DATA on the in-memory canonical block_index entry and re-emit
 * the header event, so the cleared re-fetch state is durable across restarts —
 * the same discipline as body_persist_stage.c:requeue_body_for_refetch and
 * stale_validate_headers_repair.c:cure_request_peer_refetch. Best-effort: no
 * main_state (isolated fixture / pre-context) is not a failure — the durable row
 * is already gone, so the height re-fetches once the map is present. */
static void runtime_row_clear_have_data(struct main_state *ms, int height)
{
    if (!ms)
        return;
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi || !bi->phashBlock)
        return;
    if (block_index_status_load(bi) & BLOCK_HAVE_DATA) {
        block_index_status_clear_bits(bi, BLOCK_HAVE_DATA);
        block_index_emit_header_event(bi, "stage_repair_row_quarantine",
                                      NULL, NULL);
    }
}

bool stage_repair_quarantine_blocks_row(
    struct node_db *ndb, struct main_state *ms, int64_t height,
    const struct uint256 *hash,
    struct stage_repair_row_quarantine_result *out)
{
    struct stage_repair_row_quarantine_result r;
    memset(&r, 0, sizeof(r));
    r.height = (int)height;
    r.verdict = BLOCK_ROW_VERIFY_OK;

    if (!ndb || !hash || height < 0 || height > INT32_MAX) {
        LOG_WARN("stage_repair",
                 "[row_quarantine] invalid args (ndb=%p height=%lld)",
                 (void *)ndb, (long long)height);
        if (out) *out = r;
        return false; // raw-return-ok:invalid-args-logged
    }

    /* ── Evidence: read the RAW stored header (fixed fields + solution) and run
     *    it through the frozen block_row_verify() against the canonical hash.
     *    Primary key is the canonical hash (the poisoned-solution-preserving-
     *    hash case); fall back to the height when no row is stored under that
     *    hash (a wrong-block / reorg-residue row), pairing the DELETE key to
     *    whichever read found the row so we only ever purge the row we verified. */
    struct block_header hdr;
    bool by_hash = db_block_load_raw_header_by_hash(ndb, hash->data, &hdr);
    uint8_t stored_hash[32];
    memcpy(stored_hash, hash->data, 32);
    if (!by_hash) {
        if (!db_block_load_raw_header_by_height(ndb, (int)height, &hdr,
                                                stored_hash)) {
            /* No addressable row at (hash | height): nothing to purge. The
             * repair loop's re-fetch remains the path forward. */
            r.row_absent = true;
            if (out) *out = r;
            return false; // raw-return-ok:no-row-to-quarantine
        }
        r.deleted_by_height = true;
    }
    r.attempted = true;

    const struct chain_params *cp = chain_params_get();
    /* Full Equihash check above the baked ROM checkpoint — the runtime frontier
     * lives in that unverified tail, so a live quarantine always runs the full
     * solution check (matching the loaders' above-checkpoint budget). Below the
     * checkpoint (fixtures / early history) the hash-bind + PoW-target checks
     * still catch a poisoned row without the expensive solution check. */
    const struct rom_state_checkpoint *rom_cp = get_rom_state_checkpoint();
    int64_t rom_h = rom_cp ? (int64_t)rom_cp->height : -1;
    bool full_check = (rom_h >= 0 && height > rom_h);

    enum block_row_verify_result verdict =
        block_row_verify(hash->data, hdr.nBits, &hdr, cp, full_check);
    r.verdict = (int)verdict;

    char hex[65];
    uint256_get_hex(hash, hex);

    if (verdict == BLOCK_ROW_VERIFY_NO_PARAMS) {
        /* Cannot prove evidence without chain params (not expected at runtime).
         * Refuse — never delete on an unverifiable read. */
        r.no_params = true;
        LOG_WARN("stage_repair",
                 "[row_quarantine] h=%lld hash=%s: chain params unavailable — "
                 "refusing to purge (cannot prove poison)",
                 (long long)height, hex);
        if (out) *out = r;
        return false; // raw-return-ok:no-params-refused
    }

    if (verdict == BLOCK_ROW_VERIFY_OK) {
        /* The durable row IS the valid canonical block. The poison is elsewhere
         * (the header_solution side-table); leave the row alone — the existing
         * refetch/overwrite path owns that case. Deleting here would drop a good
         * body. */
        r.refused_clean = true;
        LOG_WARN("stage_repair",
                 "[row_quarantine] h=%lld hash=%s: `blocks` row verifies OK — "
                 "NOT a poisoned row, refusing to purge",
                 (long long)height, hex);
        if (out) *out = r;
        return false; // raw-return-ok:clean-row-refused
    }

    /* ── Concrete failure evidence (hash-bind / high-hash / bad-Equihash): purge
     *    the poisoned row. By hash when the stored hash is usable (the common
     *    case), else by height (a row whose `hash` column could not address it). */
    bool purged = r.deleted_by_height
        ? db_block_delete_by_height(ndb, (int)height)
        : db_block_delete(ndb, hash->data);

    /* Clear the in-memory HAVE_DATA bit + re-emit so the cleared re-fetch state
     * is durable (header sync + body_fetch re-request the height). */
    runtime_row_clear_have_data(ms, (int)height);

    atomic_fetch_add_explicit(&g_runtime_row_quarantined, 1,
                              memory_order_relaxed);

    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "poisoned blocks row height=%lld hash=%.64s verdict=%.40s; "
             "purge%s; header sync and body_fetch will refetch it",
             (long long)height, hex,
             row_verify_verdict_name(verdict),
             purged ? "=ok" : "=failed (repair loop retries)");
    if (blocker_init(&rec, RUNTIME_ROW_QUARANTINE_BLOCKER_ID, "block_index",
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&rec);

    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_runtime_row_quarantine_log,
                                 (uint64_t)(uint32_t)height,
                                 platform_time_wall_unix(), 60, &reps)) {
        if (purged)
            LOG_WARN("stage_repair",
                     "[row_quarantine] quarantined poisoned `blocks` row "
                     "h=%lld hash=%s verdict=%s — purged, re-fetch will replace "
                     "(repeats=%llu)", (long long)height, hex,
                     row_verify_verdict_name(verdict),
                     (unsigned long long)reps);
        else
            LOG_WARN("stage_repair",
                     "[row_quarantine] poisoned `blocks` row h=%lld hash=%s "
                     "verdict=%s — purge FAILED, repair loop retries "
                     "(repeats=%llu)", (long long)height, hex,
                     row_verify_verdict_name(verdict),
                     (unsigned long long)reps);
    }

    r.quarantined = purged;
    if (out) *out = r;
    return purged;
}
