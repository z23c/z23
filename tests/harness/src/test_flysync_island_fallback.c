/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * flysync_island fall-back cases: the detach of a fallen-back island, its
 * crash windows, the rejoin and retire, and the island state read. Part of
 * the flysync_island group; the shared fixture lives in
 * test/test_flysync_island_common.h. */

#include "test/test_core.h"
#include "test/test_flysync_island_common.h"


#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "config/consensus_state_install_runtime.h"
#include "config/flysync_island.h"
#include "config/state_offer_store.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "services/block_index_loader.h"
#include "services/chain_frontier_snapshot_service.h"
#include "services/chain_state_service.h"
#include "services/sync_monitor.h"
#include "config/boot_consensus_bundle_marker.h"
#include "storage/progress_store.h"
#include "services/island_anchor.h"
#include "services/utxo_recovery_service.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/process_block.h"
#include "validation/accept_block_header.h"
#include "net/checkpoint_header_fetch.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netbase.h"
#include "net/protocol.h"
#include "net/rom_seed.h"
#include "net/state_offer.h"
#include "primitives/block.h"
#include "util/util.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static bool fsi_rows_detached(struct fsi_node *n)
{
    struct block_index *genesis = active_chain_tip(&n->ms.chain_active);
    if (!genesis)
        return false;
    for (int i = 0; i < FSI_W; i++)
        if (n->rows[i]->pprev ||
            arith_uint256_is_zero(&n->rows[i]->nChainWork) ||
            arith_uint256_compare(&n->rows[i]->nChainWork,
                                  &genesis->nChainWork) >= 0)
            return false;
    return true;
}

/* A warm boot's loader: rows relinked from their durable records, the root
 * without a parent, work from the forward pass, the most-work header best. */
static void fsi_reload_rows(struct fsi_node *n)
{
    n->rows[0]->pprev = NULL;
    for (int i = 1; i < FSI_W; i++)
        n->rows[i]->pprev = n->rows[i - 1];
    fsi_reload_work(n);
    n->ms.pindex_best_header = fsi_top(n);
}

/* Normal sync reaching the island from below: the root's real parent is
 * admitted, then the window is delivered again through accept_block_header. */
static struct block_index *fsi_redeliver(struct fsi_node *n)
{
    struct uint256 ph = n->is.w[FSI_W - 1].hashPrevBlock;
    struct block_index *p =
        chainstate_insert_block_index((struct chainstate *)&n->ms, &ph);
    if (!p)
        return NULL;
    p->nHeight = FSI_RUNG_H - FSI_W;
    p->nBits = FSI_BITS;
    p->pprev = active_chain_tip(&n->ms.chain_active);
    struct arith_uint256 root_proof = GetBlockProof(n->rows[0]);
    arith_uint256_sub(&p->nChainWork, &n->a.root_work, &root_proof);
    for (int i = FSI_W - 1; i >= 0; i--) {
        struct validation_state st;
        validation_state_init(&st);
        struct block_index *out = NULL;
        if (!accept_block_header(&n->is.w[i], &st, &n->ms, chain_params_get(),
                                 &out) || out != n->rows[FSI_W - 1 - i])
            return NULL;
    }
    return p;
}

/* MUST 1 / A: a fall-back after seeding leaves no orphan chain, in process
 * and after the restart it asks for; the rows rejoin when sync reaches them. */
static int fsi_case_fallback_detach(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *genesis = active_chain_tip(&n->ms.chain_active);
    sqlite3 *db = progress_store_db();
    struct island_anchor back;
    bool found = false;
    FSI_CHECK("fall-back from SEEDED detaches every island row",
              fsi_rows_detached(n));
    FSI_CHECK("fall-back moves the best header off the island",
              genesis && n->ms.pindex_best_header == genesis);
    FSI_CHECK("a fall-back in the running node asks for a restart",
              flysync_island_test_respawns() == 1);
    FSI_CHECK("the fact stays for the boot detach",
              island_anchor_load(db, &back, &found).ok && found);

    flysync_island_test_reset();
    fsi_reload_rows(n);
    FSI_CHECK("restart: the loader would make the island best again",
              n->ms.pindex_best_header == fsi_top(n) &&
              !arith_uint256_is_zero(&fsi_top(n)->nChainWork));
    FSI_CHECK("restart: the FELL_BACK boot detaches the island again",
              flysync_island_boot_after_index(NULL, &n->ms) &&
              fsi_rows_detached(n) && n->ms.pindex_best_header == genesis &&
              flysync_island_phase() == FLYSYNC_OFF &&
              !flysync_island_holds_header_sync());
    return failures;
}

/* A crash in the middle of the detach flush: row 5 stored parentless, rows
 * 6..27 still stored linked to it, so they load with the summed work of their
 * proofs, neither under the root nor parentless. */
static int fsi_case_fallback_midflush(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *genesis = active_chain_tip(&n->ms.chain_active);
    flysync_island_test_reset();
    fsi_reload_rows(n);
    n->rows[5]->pprev = NULL;
    n->rows[5]->pskip = NULL;   /* a loaded parentless row has no skip */
    fsi_reload_work(n);
    n->ms.pindex_best_header = fsi_top(n);
    FSI_CHECK("mid-flush restart: the rows above the break load with work",
              fsi_top(n)->pprev == n->rows[FSI_W - 2] &&
              arith_uint256_compare(&fsi_top(n)->nChainWork,
                                    &n->rows[5]->nChainWork) > 0);
    FSI_CHECK("mid-flush restart: the row list detaches linked and "
              "parentless rows alike",
              flysync_island_boot_after_index(NULL, &n->ms) &&
              fsi_rows_detached(n) && n->ms.pindex_best_header == genesis);
    return failures;
}

/* Headers above the rung, as normal sync admits them once the rows rejoined. */
#define FSI_UP 3
static bool fsi_build_up(struct fsi_node *n, struct block_header *up,
                         struct block_index **ub)
{
    struct uint256 prev = n->is.hash[0];   /* the rung */
    for (int k = 0; k < FSI_UP; k++) {
        block_header_init(&up[k]);
        up[k].nVersion = 4;
        up[k].hashPrevBlock = prev;
        up[k].hashMerkleRoot.data[0] = (uint8_t)(0xa0 + k);
        up[k].nTime = 1760010000u + 150u * (uint32_t)k;
        up[k].nBits = FSI_BITS;
        up[k].nSolutionSize = 32;
        block_header_get_hash(&up[k], &prev);
        ub[k] = chainstate_insert_block_index((struct chainstate *)&n->ms,
                                              &prev);
        if (!ub[k])
            return false;
        ub[k]->nHeight = FSI_RUNG_H + 1 + k;
        ub[k]->nBits = FSI_BITS;
    }
    return true;
}

/* `base` plus the proof of each of v[0..n), in order. */
static struct arith_uint256 fsi_work_over(struct arith_uint256 base,
                                          struct block_index **v, int n)
{
    for (int i = 0; i < n; i++) {
        struct arith_uint256 proof = GetBlockProof(v[i]), sum;
        arith_uint256_add(&sum, &base, &proof);
        base = sum;
    }
    return base;
}

static bool fsi_up_detached(struct block_index **ub)
{
    for (int k = 0; k < FSI_UP; k++)
        if (ub[k]->pprev || !arith_uint256_equal_u64(&ub[k]->nChainWork, 1))
            return false;
    return true;
}

/* MUST 1 (re-review): normal sync rejoined the island in memory and saved
 * headers above the rung linked to it, then the process died before the
 * relinked rows were saved. The rows load parentless, the headers above load
 * linked to the rung with stale work; the boot must detach them too, so the
 * re-delivered headers relink with real work and header sync passes the rung. */
static int fsi_case_fallback_crash_rejoin(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *genesis = active_chain_tip(&n->ms.chain_active);
    struct block_header up[FSI_UP];
    struct block_index *ub[FSI_UP];
    FSI_CHECK("headers above the rung are admitted", fsi_build_up(n, up, ub));
    flysync_island_test_reset();
    struct block_index *all[FSI_W + FSI_UP];
    for (int i = 0; i < FSI_W; i++) {
        n->rows[i]->pprev = NULL;
        n->rows[i]->pskip = NULL;
        all[i] = n->rows[i];
    }
    for (int k = 0; k < FSI_UP; k++) {
        ub[k]->pprev = k ? ub[k - 1] : fsi_top(n);
        all[FSI_W + k] = ub[k];
    }
    for (int i = 0; i < FSI_W + FSI_UP; i++)
        arith_uint256_set_zero(&all[i]->nChainWork);
    block_index_forward_pass(all, FSI_W + FSI_UP);
    n->ms.pindex_best_header = ub[FSI_UP - 1];
    FSI_CHECK("crash after rejoin: the headers above load linked to the rung",
              ub[0]->pprev == fsi_top(n) && fsi_top(n)->pprev == NULL);
    FSI_CHECK("crash after rejoin: the boot detaches the headers above too",
              flysync_island_boot_after_index(NULL, &n->ms) &&
              fsi_rows_detached(n) && fsi_up_detached(ub) &&
              n->ms.pindex_best_header == genesis);
    struct block_index *p = fsi_redeliver(n);
    bool relinked = p != NULL;
    for (int k = 0; relinked && k < FSI_UP; k++) {
        struct validation_state st;
        validation_state_init(&st);
        struct block_index *out = NULL;
        relinked = accept_block_header(&up[k], &st, &n->ms, chain_params_get(),
                                       &out) && out == ub[k];
    }
    struct arith_uint256 want = fsi_work_over(n->is.rung_work, ub, FSI_UP);
    FSI_CHECK("re-delivered: the headers above carry real work past the rung",
              relinked && fsi_top_work_is_rung(n) &&
              arith_uint256_compare(&ub[FSI_UP - 1]->nChainWork, &want) == 0);
    return failures;
}

/* A flushed detach persists each row's parent as zero (the record takes
 * hashPrev from pprev): the loader brings every row back as a parentless root
 * carrying its own proof, outside the root's ancestry. Then normal sync
 * reaches the island and the fact retires. */
static int fsi_case_fallback_rejoin(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *genesis = active_chain_tip(&n->ms.chain_active);
    sqlite3 *db = progress_store_db();
    struct island_anchor back;
    bool found = false;
    flysync_island_test_reset();
    for (int i = 0; i < FSI_W; i++)
        n->rows[i]->pprev = NULL;
    fsi_reload_work(n);
    n->ms.pindex_best_header = fsi_top(n);
    FSI_CHECK("flushed restart: every row loads as a root with its own work",
              !arith_uint256_is_zero(&n->rows[5]->nChainWork) &&
              !arith_uint256_is_zero(&fsi_top(n)->nChainWork));
    /* The crash case before this one admitted the root's real parent: it is
     * the most-work entry left once the island is detached. */
    struct block_index *real = block_map_find(
        &n->ms.map_block_index, &n->is.w[FSI_W - 1].hashPrevBlock);
    FSI_CHECK("flushed restart: the row list detaches all 28 by height and "
              "hash",
              flysync_island_boot_after_index(NULL, &n->ms) &&
              fsi_rows_detached(n) &&
              n->ms.pindex_best_header == (real ? real : genesis));

    struct block_index *p = fsi_redeliver(n);
    FSI_CHECK("normal sync re-delivers the window from its real parent", p);
    FSI_CHECK("the rows rejoin as ordinary headers with their real work",
              p && block_index_get_ancestor(fsi_top(n), FSI_RUNG_H - FSI_W) ==
                       p && fsi_top_work_is_rung(n));
    /* The retire runs the canonical forward pass, which derives every row's
     * work from its real parent (the fixture's parent work is synthetic, so
     * compare against that derivation, not the compiled rung figure). */
    bool booted = flysync_island_boot_after_index(NULL, &n->ms);
    struct arith_uint256 want = p ? fsi_work_over(p->nChainWork, n->rows, FSI_W)
                                  : n->is.rung_work;
    FSI_CHECK("rejoined: the next boot retires the fact, detaches nothing",
              booted && island_anchor_load(db, &back, &found).ok && !found &&
              n->rows[0]->pprev == p &&
              arith_uint256_compare(&fsi_top(n)->nChainWork, &want) == 0);
    struct island_anchor_rows list;
    FSI_CHECK("retired: the row list goes with the fact",
              island_anchor_rows_load(db, &list, &found).ok && !found);
    return failures;
}

/* A fallen-back datadir whose root row never reached the index: rows 1..27
 * load linked to each other, row 1 parentless, with real work. */
static bool fsi_listonly_load(struct fsi_node *n)
{
    n->rows[0] = NULL;
    for (int i = 1; i < FSI_W; i++) {
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)&n->ms, &n->is.hash[FSI_W - 1 - i]);
        if (!bi)
            return false;
        bi->nHeight = n->a.root_height + i;
        bi->nBits = FSI_BITS;
        bi->pprev = i > 1 ? n->rows[i - 1] : NULL;
        bi->pskip = NULL;
        arith_uint256_set_zero(&bi->nChainWork);
        n->rows[i] = bi;
    }
    block_index_forward_pass(&n->rows[1], FSI_W - 1);
    n->ms.pindex_best_header = fsi_top(n);
    return !arith_uint256_is_zero(&fsi_top(n)->nChainWork);
}

static bool fsi_listonly_detached(struct fsi_node *n)
{
    struct block_index *genesis = active_chain_tip(&n->ms.chain_active);
    for (int i = 1; i < FSI_W; i++)
        if (n->rows[i]->pprev ||
            !arith_uint256_equal_u64(&n->rows[i]->nChainWork, 1))
            return false;
    return n->ms.pindex_best_header == genesis;
}

static bool fsi_listonly_open(struct fsi_node *n)
{
    if (!fsi_node_open(n, "flysync_listonly"))
        return false;
    fsi_build_island(&n->is);
    flysync_island_test_set_rung(&n->is.rung);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    char why[160];
    struct island_anchor_rows list;
    for (int i = 0; i < FSI_W; i++)
        list.hash[i] = n->is.hash[FSI_W - 1 - i];
    sqlite3 *db = progress_store_db();
    return flysync_island_verify_window(n->is.w, FSI_W, FSI_RUNG_H, &n->a, why,
                                        sizeof(why)) &&
           island_anchor_save(db, &n->a, &list).ok &&
           island_anchor_note_fallback(db, "test").ok;
}

/* SHOULD 3 and 5 (re-review): the detach works from the row list without the
 * root, and from the fact's height range when the list is unreadable. */
static int fsi_case_listonly(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("list-only fixture opens", fsi_listonly_open(&n));
    FSI_CHECK("root missing: rows 1..27 load with work", fsi_listonly_load(&n));
    FSI_CHECK("root missing: the row list alone detaches rows 1..27",
              flysync_island_boot_after_index(NULL, &n.ms) &&
              fsi_listonly_detached(&n));
    uint8_t junk[5] = {1, 2, 3, 4, 5};
    FSI_CHECK("row list unreadable: rows 1..27 load with work again",
              progress_meta_set(progress_store_db(), "flysync.island_rows.v1",
                                junk, sizeof(junk)) &&
              (flysync_island_test_reset(), fsi_listonly_load(&n)));
    FSI_CHECK("row list unreadable: the fact's height range detaches the "
              "off-chain rows",
              flysync_island_boot_after_index(NULL, &n.ms) &&
              fsi_listonly_detached(&n));
    fsi_release_globals();
    fsi_node_close(&n);
    return failures;
}

/* A datadir that never ran FlySync: the state reads NONE, and a start without
 * the flag passes the gate with FlySync off. */
static int fsi_case_state_fresh(void)
{
    int failures = 0;
    struct fsi_node n;
    char why[320];
    why[0] = '\0';
    FSI_CHECK("fresh fixture opens", fsi_node_open(&n, "flysync_fresh"));
    FSI_CHECK("a fresh progress store reads NONE, not UNREADABLE",
              island_anchor_state_load(progress_store_db()) ==
                  ISLAND_ANCHOR_STATE_NONE);
    FSI_CHECK("no flag, no island keys: the gate passes, FlySync stays off",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_OFF);
    fsi_node_close(&n);
    return failures;
}

/* SHOULD 4 (re-review): an unreadable island state never reads as fresh. */
static int fsi_case_state_unreadable(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("unreadable fixture opens", fsi_listonly_open(&n));
    sqlite3 *db = progress_store_db();
    uint8_t junk[2] = {9, 9};
    FSI_CHECK("a malformed state reads as UNREADABLE, not NONE",
              progress_meta_set(db, "flysync.island_state", junk,
                                sizeof(junk)) &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_UNREADABLE);
    flysync_island_set_requested(true);
    char why[320];
    why[0] = '\0';
    FSI_CHECK("unreadable state: -flysync refuses to decide this start",
              !flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              strstr(why, "unreadable") != NULL);
    FSI_CHECK("unreadable state: the durable fall-back is refused",
              !island_anchor_note_fallback(db, "test").ok &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_UNREADABLE);
    flysync_island_test_reset();
    FSI_CHECK("unreadable state with a fact: refused without the flag too",
              !flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)));
    FSI_CHECK("no fact and no flag: the node starts as it does today",
              progress_meta_delete(db, "flysync.island_anchor.v1") &&
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)));
    fsi_release_globals();
    fsi_node_close(&n);
    return failures;
}

int fsi_fallback_cases(struct fsi_node *n)
{
    int failures = 0;
    failures += fsi_case_fallback_detach(n);
    failures += fsi_case_fallback_midflush(n);
    failures += fsi_case_fallback_crash_rejoin(n);
    failures += fsi_case_fallback_rejoin(n);
    return failures;
}

int fsi_state_cases(void)
{
    int failures = 0;
    failures += fsi_case_listonly();
    failures += fsi_case_state_fresh();
    failures += fsi_case_state_unreadable();
    return failures;
}
