/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_flysync_island — FlySync island start.
 *
 * Window walk (core/modules/net/src/checkpoint_header_fetch.c): a backward,
 * hash-pinned capture of a header window from an armed top hash. A forged or
 * out-of-order header is never captured; the window completes only along the
 * hashPrevBlock links; single-mode capture is untouched while no window is
 * armed and reports nothing while one is. */

#include "test/test_core.h"

#include "../../../engine/services/src/chain_evidence_reconstruct.h"
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
#include "services/island_anchor.h"
#include "services/utxo_recovery_service.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/check_block.h"
#include "validation/process_block.h"
#include "net/checkpoint_header_fetch.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netbase.h"
#include "net/protocol.h"
#include "primitives/block.h"
#include "util/util.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define FSI_CHECK(desc, cond)                                                \
    do {                                                                     \
        printf("flysync_island: %s... ", (desc));                            \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                               \
    } while (0)

/* A deterministic header with a non-empty solution; hash returned. */
static void fsi_build_header(struct block_header *h, int salt,
                             const struct uint256 *prev, struct uint256 *hash)
{
    block_header_init(h);
    if (prev)
        h->hashPrevBlock = *prev;
    h->hashMerkleRoot.data[0] = (uint8_t)salt;
    h->hashMerkleRoot.data[1] = 0x6d;
    h->nTime = 1760000000u + (uint32_t)salt;
    h->nBits = 0x1f07ffff;
    h->nNonce.data[0] = (uint8_t)salt;
    h->nNonce.data[2] = 0x33;
    h->nSolutionSize = 32;
    for (size_t i = 0; i < h->nSolutionSize; i++)
        h->nSolution[i] = (uint8_t)(salt * 7 + (int)i);
    block_header_get_hash(h, hash);
}

#define FSI_DEPTH 4

/* chain[0] is the top; chain[i].hashPrevBlock == hash(chain[i+1]). */
static void fsi_build_chain(struct block_header *chain, struct uint256 *hashes,
                            int n)
{
    struct uint256 below;
    memset(&below, 0x11, sizeof(below));
    for (int i = n - 1; i >= 0; i--) {
        fsi_build_header(&chain[i], 40 + i, &below, &hashes[i]);
        below = hashes[i];
    }
}

static int fsi_case_window_walk(void)
{
    int failures = 0;
    struct block_header chain[FSI_DEPTH];
    struct uint256 hashes[FSI_DEPTH];
    fsi_build_chain(chain, hashes, FSI_DEPTH);
    const int32_t top_h = 3200000;

    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_arm_window(top_h, &hashes[0], FSI_DEPTH);
    FSI_CHECK("window arms", checkpoint_header_fetch_is_armed());

    struct block_header forged;
    struct uint256 forged_hash;
    fsi_build_header(&forged, 99, &hashes[1], &forged_hash);
    checkpoint_header_fetch_offer(&forged, &forged_hash);
    FSI_CHECK("forged header (not the pinned hash) is not captured",
              checkpoint_header_fetch_window_progress() == 0);

    checkpoint_header_fetch_offer(&chain[0], &hashes[0]);
    FSI_CHECK("top header captured",
              checkpoint_header_fetch_window_progress() == 1);
    checkpoint_header_fetch_offer(&chain[2], &hashes[2]);
    FSI_CHECK("out-of-order header is not captured",
              checkpoint_header_fetch_window_progress() == 1);
    checkpoint_header_fetch_offer(&chain[0], &hashes[0]);
    FSI_CHECK("re-delivered top is not captured twice",
              checkpoint_header_fetch_window_progress() == 1);
    checkpoint_header_fetch_offer(&chain[1], &hashes[1]);
    checkpoint_header_fetch_offer(&chain[2], &hashes[2]);
    FSI_CHECK("single-mode take sees nothing while a window walks",
              !checkpoint_header_fetch_has_capture());
    checkpoint_header_fetch_offer(&chain[3], &hashes[3]);
    FSI_CHECK("window complete after the linked walk",
              checkpoint_header_fetch_window_progress() == FSI_DEPTH);
    FSI_CHECK("single-mode has_capture stays false for a window",
              !checkpoint_header_fetch_has_capture());

    struct block_header got[CHECKPOINT_HEADER_FETCH_WINDOW_MAX];
    int32_t got_top = -1;
    FSI_CHECK("take refuses a too-small buffer",
              checkpoint_header_fetch_take_window(got, FSI_DEPTH - 1,
                                                  &got_top) == 0);
    int n = checkpoint_header_fetch_take_window(
        got, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &got_top);
    FSI_CHECK("take returns the whole window", n == FSI_DEPTH);
    FSI_CHECK("take reports the top height", got_top == top_h);
    bool order = n == FSI_DEPTH;
    for (int i = 0; order && i < FSI_DEPTH; i++) {
        struct uint256 h;
        block_header_get_hash(&got[i], &h);
        order = uint256_eq(&h, &hashes[i]);
    }
    FSI_CHECK("window is top-first and hash-linked", order);
    FSI_CHECK("take consumes once",
              checkpoint_header_fetch_take_window(
                  got, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &got_top) == 0);
    FSI_CHECK("take disarms the walk", !checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_test_reset();
    return failures;
}

static int fsi_case_window_args_and_single_mode(void)
{
    int failures = 0;
    struct uint256 hash;
    struct block_header h;
    fsi_build_header(&h, 7, NULL, &hash);

    checkpoint_header_fetch_test_reset();
    checkpoint_header_fetch_arm_window(100, &hash, 0);
    FSI_CHECK("depth 0 does not arm", !checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_arm_window(100, &hash,
                                       CHECKPOINT_HEADER_FETCH_WINDOW_MAX + 1);
    FSI_CHECK("depth above the max does not arm",
              !checkpoint_header_fetch_is_armed());
    checkpoint_header_fetch_arm_window(2, &hash, 4);
    FSI_CHECK("a window below genesis does not arm",
              !checkpoint_header_fetch_is_armed());

    /* Single mode is exactly as before, and re-arming single cancels a window. */
    checkpoint_header_fetch_arm_window(100, &hash, 3);
    checkpoint_header_fetch_arm(100, &hash);
    checkpoint_header_fetch_offer(&h, &hash);
    FSI_CHECK("single-mode capture after a window is replaced",
              checkpoint_header_fetch_has_capture());
    FSI_CHECK("window progress reads 0 in single mode",
              checkpoint_header_fetch_window_progress() == 0);
    struct block_header taken;
    int32_t th = -1;
    FSI_CHECK("single-mode take works",
              checkpoint_header_fetch_take(&taken, &th) && th == 100);

    checkpoint_header_fetch_arm_window(100, &hash, 3);
    checkpoint_header_fetch_disarm();
    FSI_CHECK("disarm clears a window walk",
              !checkpoint_header_fetch_is_armed() &&
              checkpoint_header_fetch_window_progress() == 0);
    checkpoint_header_fetch_test_reset();
    return failures;
}

/* ── Header-sync hold and service bits ───────────────────────────────────── */

static bool fsi_hold_on(void) { return true; }

static void fsi_setup_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.7:8033");
    node->id = 7;
    node->services = NODE_ZCL23;
    node->socket = ZCL_INVALID_SOCKET;
}

/* Count queued messages named `cmd`, then drop the queue. */
static int fsi_drain_count(struct p2p_node *node, const char *cmd)
{
    int n = 0;
    struct send_segment *seg = node->send_head;
    while (seg) {
        struct send_segment *next = seg->next;
        if (seg->size >= MSG_HEADER_SIZE &&
            strncmp((const char *)seg->data + MESSAGE_START_SIZE, cmd,
                    strlen(cmd)) == 0)
            n++;
        send_segment_free(seg);
        seg = next;
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->send_size = 0;
    node->send_offset = 0;
    return n;
}

static struct net_manager g_fsi_nm;

static int fsi_case_hold_and_services(void)
{
    int failures = 0;
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "flysync_hold", "ok");
    SetDataDir(dir);
    struct main_state ms;
    main_state_init(&ms);
    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_fsi_nm, NULL);
    struct p2p_node node;
    fsi_setup_node(&node);
    struct uint256 a, b;
    memset(a.data, 0x21, 32);
    memset(b.data, 0x22, 32);

    msg_processor_set_header_sync_hold(NULL);
    push_getheaders_span(&mp, &node, &a, &b);
    FSI_CHECK("no hold: a span request goes out",
              fsi_drain_count(&node, "getheaders") == 1);
    msg_processor_set_header_sync_hold(fsi_hold_on);
    push_getheaders_span(&mp, &node, &a, &b);
    push_getheaders(&mp, &node);
    FSI_CHECK("hold: span and plain getheaders are held",
              fsi_drain_count(&node, "getheaders") == 0);
    push_getheaders_by_hash(&mp, &node, &a);
    FSI_CHECK("hold: the window walk request still goes out",
              fsi_drain_count(&node, "getheaders") == 1);
    msg_processor_set_header_sync_hold(NULL);

    struct version_message ver;
    msg_version_build(&ver, &mp, &node, 0);
    FSI_CHECK("default node advertises NODE_NETWORK",
              (ver.services & NODE_NETWORK) != 0 &&
              (ver.services & NODE_ZCL23) != 0);
    net_set_advertise_full_history(false);
    msg_version_build(&ver, &mp, &node, 0);
    FSI_CHECK("island node does not advertise NODE_NETWORK",
              (ver.services & NODE_NETWORK) == 0 &&
              (ver.services & NODE_ZCL23) != 0);
    net_set_advertise_full_history(true);

    main_state_free(&ms);
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* ── Island window: verify, seed, exemptions ─────────────────────────────── */

#define FSI_RUNG_H 3200000
#define FSI_W ISLAND_ANCHOR_WINDOW
#define FSI_BITS 0x1f07ffffu

struct fsi_island {
    struct block_header w[FSI_W];   /* w[0] is the rung, w[FSI_W-1] the root */
    struct uint256 hash[FSI_W];
    struct rom_state_rung rung;
    struct arith_uint256 rung_work;
};

/* A 28-header window at FSI_RUNG_H, times rising with height, and a rung whose
 * compiled hash is w[0]'s and whose chainwork is 2^88. */
static void fsi_build_island(struct fsi_island *is)
{
    memset(is, 0, sizeof(*is));
    struct uint256 below;
    memset(&below, 0x5a, sizeof(below));
    for (int i = FSI_W - 1; i >= 0; i--) {
        struct block_header *h = &is->w[i];
        block_header_init(h);
        h->nVersion = 4;
        h->hashPrevBlock = below;
        h->hashMerkleRoot.data[0] = (uint8_t)i;
        h->hashMerkleRoot.data[1] = 0xf5;
        h->nTime = 1760000000u + 150u * (uint32_t)(FSI_W - i);
        h->nBits = FSI_BITS;
        h->nNonce.data[0] = (uint8_t)i;
        h->nSolutionSize = 32;
        for (size_t k = 0; k < h->nSolutionSize; k++)
            h->nSolution[k] = (uint8_t)(i + (int)k);
        block_header_get_hash(h, &is->hash[i]);
        below = is->hash[i];
    }
    is->rung.cp.height = FSI_RUNG_H;
    memcpy(is->rung.cp.block_hash, is->hash[0].data, 32);
    is->rung.chainwork[20] = 0x01;                      /* 2^88, big-endian */
    island_anchor_work_from_be(&is->rung_work, is->rung.chainwork);
}

static bool fsi_accept_all(const struct uint256 *hash,
                           const struct block_header *hdr)
{
    (void)hash;
    (void)hdr;
    return true;
}

static struct uint256 g_fsi_bad_hash;
static bool fsi_reject_one(const struct uint256 *hash,
                           const struct block_header *hdr)
{
    (void)hdr;
    return !uint256_eq(hash, &g_fsi_bad_hash);
}

static int fsi_case_verify_window(void)
{
    int failures = 0;
    struct fsi_island is;
    fsi_build_island(&is);
    flysync_island_test_reset();
    flysync_island_test_set_rung(&is.rung);
    struct island_anchor a;
    char why[160];

    FSI_CHECK("the real frozen verifier refuses headers without valid "
              "PoW/Equihash",
              !flysync_island_verify_window(is.w, FSI_W, FSI_RUNG_H, &a, why,
                                            sizeof(why)) &&
              strstr(why, "PoW") != NULL);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    bool ok = flysync_island_verify_window(is.w, FSI_W, FSI_RUNG_H, &a, why,
                                           sizeof(why));
    FSI_CHECK("a hash-linked window at the rung verifies", ok);
    FSI_CHECK("the fact names the root and the rung",
              ok && a.root_height == FSI_RUNG_H - (FSI_W - 1) &&
              a.rung_height == FSI_RUNG_H &&
              uint256_eq(&a.root_hash, &is.hash[FSI_W - 1]) &&
              uint256_eq(&a.rung_hash, &is.hash[0]));
    struct block_index probe;
    memset(&probe, 0, sizeof(probe));
    probe.nBits = FSI_BITS;
    struct arith_uint256 proof = GetBlockProof(&probe), sum = a.root_work;
    for (int i = 0; i < FSI_W - 1; i++) {
        struct arith_uint256 t;
        arith_uint256_add(&t, &sum, &proof);
        sum = t;
    }
    FSI_CHECK("root work plus the 27 proofs above it is the compiled chainwork",
              ok && arith_uint256_compare(&sum, &is.rung_work) == 0);

    FSI_CHECK("a window of 27 is refused",
              !flysync_island_verify_window(is.w, FSI_W - 1, FSI_RUNG_H, &a,
                                            why, sizeof(why)));
    FSI_CHECK("a window at a height that is no rung is refused",
              !flysync_island_verify_window(is.w, FSI_W, FSI_RUNG_H + 1, &a,
                                            why, sizeof(why)));
    struct fsi_island forged = is;
    forged.w[5].nNonce.data[3] ^= 0x40;
    FSI_CHECK("a forged header inside the window is refused (hash link)",
              !flysync_island_verify_window(forged.w, FSI_W, FSI_RUNG_H, &a,
                                            why, sizeof(why)) &&
              strstr(why, "link") != NULL);
    g_fsi_bad_hash = is.hash[3];
    flysync_island_test_set_frozen_verifier(fsi_reject_one);
    FSI_CHECK("one header failing PoW/Equihash refuses the window",
              !flysync_island_verify_window(is.w, FSI_W, FSI_RUNG_H, &a, why,
                                            sizeof(why)) &&
              strstr(why, "PoW") != NULL);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    struct fsi_island light = is;
    memset(light.rung.chainwork, 0, 32);
    light.rung.chainwork[31] = 0x10;
    flysync_island_test_set_rung(&light.rung);
    FSI_CHECK("a window heavier than the compiled rung chainwork is refused",
              !flysync_island_verify_window(is.w, FSI_W, FSI_RUNG_H, &a, why,
                                            sizeof(why)));
    flysync_island_test_reset();
    return failures;
}

struct fsi_node {
    char dir[256];
    struct main_state ms;
    struct fsi_island is;
    struct island_anchor a;
    struct block_index *rows[FSI_W];   /* ascending: rows[0] is the root */
};

static bool fsi_node_open(struct fsi_node *n, const char *tag)
{
    chain_params_select(CHAIN_MAIN);
    test_make_tmpdir(n->dir, sizeof(n->dir), tag, "ok");
    SetDataDir(n->dir);
    main_state_init(&n->ms);
    flysync_island_test_reset();
    return progress_store_open(n->dir);
}

static void fsi_node_close(struct fsi_node *n)
{
    flysync_island_test_reset();
    progress_store_close();
    main_state_free(&n->ms);
    ClearDataDirCache();
    test_rm_rf(n->dir);
}

static bool fsi_node_seed(struct fsi_node *n)
{
    fsi_build_island(&n->is);
    flysync_island_test_set_rung(&n->is.rung);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    char why[160];
    if (!flysync_island_verify_window(n->is.w, FSI_W, FSI_RUNG_H, &n->a, why,
                                      sizeof(why)) ||
        !flysync_island_seed(&n->ms, n->is.w, FSI_W, &n->a))
        return false;
    for (int i = 0; i < FSI_W; i++)
        n->rows[FSI_W - 1 - i] =
            block_map_find(&n->ms.map_block_index, &n->is.hash[i]);
    for (int i = 0; i < FSI_W; i++)
        if (!n->rows[i])
            return false;
    if (!n->ms.pindex_best_header)
        n->ms.pindex_best_header = n->rows[FSI_W - 1];
    return true;
}

static struct block_index *fsi_top(struct fsi_node *n)
{
    return n->rows[FSI_W - 1];
}

static bool fsi_top_work_is_rung(struct fsi_node *n)
{
    return arith_uint256_compare(&fsi_top(n)->nChainWork,
                                 &n->is.rung_work) == 0;
}

/* The loader's forward pass over the island, as a warm boot runs it. */
static void fsi_reload_work(struct fsi_node *n)
{
    for (int i = 0; i < FSI_W; i++)
        arith_uint256_set_zero(&n->rows[i]->nChainWork);
    block_index_forward_pass(n->rows, FSI_W);
}

static int fsi_case_seed_rows(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *top = fsi_top(n), *root = n->rows[0];
    FSI_CHECK("seeded rung row sits at the rung height",
              top->nHeight == FSI_RUNG_H && root->nHeight == FSI_RUNG_H - 27);
    FSI_CHECK("seeded rung row carries the compiled chainwork",
              fsi_top_work_is_rung(n));
    FSI_CHECK("the root has no parent and is the registered root",
              root->pprev == NULL && island_anchor_is_root(root));
    FSI_CHECK("no other row is taken for the root",
              !island_anchor_is_root(n->rows[1]) && !island_anchor_is_root(top));
    sqlite3 *db = progress_store_db();
    FSI_CHECK("the fact is durable with state SEEDED",
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_SEEDED);
    island_anchor_unregister();
    struct island_anchor back;
    FSI_CHECK("a restart registers the durable fact again",
              island_anchor_boot_register(db) && island_anchor_get(&back) &&
              back.root_height == n->a.root_height &&
              uint256_eq(&back.root_hash, &n->a.root_hash) &&
              arith_uint256_compare(&back.root_work, &n->a.root_work) == 0);
    return failures;
}

static int fsi_case_exemptions(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *top = fsi_top(n), *root = n->rows[0];
    fsi_reload_work(n);
    FSI_CHECK("island: the loader keeps the root work (rung chainwork after "
              "restart)", fsi_top_work_is_rung(n));
    FSI_CHECK("island: no ancestry break (no band backfill below the rung)",
              utxo_recovery_block_ancestry_break(top) == NULL);
    FSI_CHECK("island: the evidence ancestry walk ends at the root",
              cec_test_tip_ancestry_linked(NULL, top));
    FSI_CHECK("island: a fork below the rung is refused, at the rung is not",
              island_anchor_refuses_fork_at(FSI_RUNG_H - 1) &&
              !island_anchor_refuses_fork_at(FSI_RUNG_H));
    FSI_CHECK("island: the install header gate accepts exactly this rung",
              consensus_state_install_header_ready_for(&n->ms, FSI_RUNG_H,
                                                       n->is.hash[0].data) &&
              !consensus_state_install_header_ready_for(&n->ms, FSI_RUNG_H,
                                                        n->is.hash[1].data));

    island_anchor_unregister();
    fsi_reload_work(n);
    FSI_CHECK("no fact: the loader resets the root work as before",
              !fsi_top_work_is_rung(n) &&
              arith_uint256_compare(&root->nChainWork,
                                    &(struct arith_uint256){0}) != 0);
    FSI_CHECK("no fact: the island is an ancestry break (band backfill)",
              utxo_recovery_block_ancestry_break(top) == root);
    FSI_CHECK("no fact: the evidence ancestry walk refuses the island",
              !cec_test_tip_ancestry_linked(NULL, top));
    FSI_CHECK("no fact: no fork is refused by the island floor",
              !island_anchor_refuses_fork_at(FSI_RUNG_H - 1) &&
              !island_anchor_refuses_fork_at(0));
    FSI_CHECK("no fact: the install header gate still wants the keystone",
              !consensus_state_install_header_ready_for(&n->ms, FSI_RUNG_H,
                                                        n->is.hash[0].data));
    (void)island_anchor_boot_register(progress_store_db());
    return failures;
}

/* The first header above the rung gets the full contextual check. */
static int fsi_case_contextual(struct fsi_node *n)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    struct block_index *top = fsi_top(n);
    FSI_CHECK("the header above the rung is not skipped (window complete)",
              !process_block_should_skip_contextual_header(&n->ms, top,
                                                           &cp->consensus));
    struct block_header next;
    block_header_init(&next);
    next.nVersion = 4;
    next.hashPrevBlock = n->is.hash[0];
    next.nTime = n->is.w[0].nTime + 150;
    next.nBits = FSI_BITS;
    struct validation_state st;
    validation_state_init(&st);
    bool good = contextual_check_block_header(&next, &st, cp, top, false);
    FSI_CHECK("the right difficulty passes the contextual check", good);
    if (!good)
        printf("flysync_island: reject=%s\n", st.reject_reason);
    next.nBits = 0x1e07ffffu;
    validation_state_init(&st);
    FSI_CHECK("a wrong difficulty is rejected bad-diffbits",
              !contextual_check_block_header(&next, &st, cp, top, false) &&
              strcmp(st.reject_reason, "bad-diffbits") == 0);
    struct block_index *cut = n->rows[FSI_W - 10];
    struct block_index *saved = cut->pprev;
    cut->pprev = NULL;
    FSI_CHECK("a shorter window would skip it (why 28 rows are fetched)",
              process_block_should_skip_contextual_header(&n->ms, top,
                                                          &cp->consensus));
    cut->pprev = saved;
    return failures;
}

static int fsi_case_island(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("island fixture opens", fsi_node_open(&n, "flysync_island"));
    bool seeded = fsi_node_seed(&n);
    FSI_CHECK("a verified window seeds the island", seeded);
    if (seeded) {
        failures += fsi_case_seed_rows(&n);
        failures += fsi_case_exemptions(&n);
        failures += fsi_case_contextual(&n);
        char why[320];
        flysync_island_test_set_rung(NULL);
        FSI_CHECK("a seeded island continues without the flag",
                  flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
                  flysync_island_phase() == FLYSYNC_SEEDED &&
                  flysync_island_holds_header_sync());
    }
    fsi_node_close(&n);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* ── Boot gate and fall-back ─────────────────────────────────────────────── */

static int fsi_case_boot_gate(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("gate fixture opens", fsi_node_open(&n, "flysync_gate"));
    char why[320];
    why[0] = '\0';
    FSI_CHECK("default off: the gate passes and nothing starts",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_OFF &&
              !flysync_island_holds_header_sync());
    flysync_island_set_requested(true);
    FSI_CHECK("-flysync on an empty datadir starts the wait",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_WAIT &&
              flysync_island_holds_header_sync());

    state_offer_store_reset();
    state_offer_store_note_first_peer(1000);
    flysync_island_test_set_clock_ms(1000 + STATE_OFFER_WAIT_MS);
    flysync_island_tick();
    FSI_CHECK("inside the offer wait the node keeps waiting",
              flysync_island_phase() == FLYSYNC_WAIT);
    flysync_island_test_set_clock_ms(1000 + STATE_OFFER_WAIT_MS + 30001);
    flysync_island_tick();
    FSI_CHECK("no rung offer inside the wait: fall back, hold lifts",
              flysync_island_phase() == FLYSYNC_FELL_BACK &&
              !flysync_island_holds_header_sync());
    FSI_CHECK("the fall-back is durable",
              island_anchor_state_load(progress_store_db()) ==
              ISLAND_ANCHOR_STATE_FELL_BACK);
    flysync_island_test_reset();
    flysync_island_set_requested(true);
    struct uint256 h1, h2;
    memset(h1.data, 0x31, 32);
    memset(h2.data, 0x32, 32);
    (void)chainstate_insert_block_index((struct chainstate *)&n.ms, &h1);
    (void)chainstate_insert_block_index((struct chainstate *)&n.ms, &h2);
    FSI_CHECK("a fallen-back datadir continues with normal sync",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_FELL_BACK);
    state_offer_store_reset();
    fsi_node_close(&n);

    FSI_CHECK("refusal fixture opens", fsi_node_open(&n, "flysync_refuse"));
    flysync_island_set_requested(true);
    (void)chainstate_insert_block_index((struct chainstate *)&n.ms, &h1);
    (void)chainstate_insert_block_index((struct chainstate *)&n.ms, &h2);
    why[0] = '\0';
    FSI_CHECK("-flysync refuses a datadir that holds chain state",
              !flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              strstr(why, "no chain state") != NULL &&
              flysync_island_phase() == FLYSYNC_OFF);
    fsi_node_close(&n);
    return failures;
}

int test_flysync_island(void)
{
    int failures = 0;
    failures += fsi_case_window_walk();
    failures += fsi_case_window_args_and_single_mode();
    failures += fsi_case_hold_and_services();
    failures += fsi_case_verify_window();
    failures += fsi_case_island();
    failures += fsi_case_boot_gate();
    printf("flysync_island: %d failures\n", failures);
    return failures;
}
