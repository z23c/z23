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
#include "test/test_flysync_island_common.h"

#include "../../../engine/services/src/chain_evidence_reconstruct.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "config/consensus_state_install_runtime.h"
#include "config/flysync_island.h"
#include "config/boot.h"
#include "config/args.h"
#include "config/boot_blkidx_ladder.h"
#include "models/database.h"
#include "jobs/block_header_emit.h"
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
#include "storage/event_log_singleton.h"
#include "storage/event_log_payloads.h"
#include "storage/block_index_projection.h"
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
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

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


/* A 28-header window at FSI_RUNG_H, times rising with height, and a rung whose
 * compiled hash is w[0]'s and whose chainwork is 2^88. */
void fsi_build_island(struct fsi_island *is)
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

bool fsi_accept_all(const struct uint256 *hash,
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

/* Genesis as the active tip, the chain a fallen-back node syncs from. */
static struct block_index *fsi_add_genesis(struct main_state *ms)
{
    struct uint256 g = chain_params_get()->consensus.hashGenesisBlock;
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &g);
    if (!bi)
        return NULL;
    bi->nHeight = 0;
    bi->nBits = FSI_BITS;
    bi->nChainWork = GetBlockProof(bi);
    bi->nStatus = (bi->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TREE;
    active_chain_move_window_tip(&ms->chain_active, bi);
    ms->pindex_best_header = bi;
    return bi;
}

static event_log_t *g_fsi_log;
static block_index_projection_t *g_fsi_projection;

bool fsi_node_open(struct fsi_node *n, const char *tag)
{
    chain_params_select(CHAIN_MAIN);
    test_make_tmpdir(n->dir, sizeof(n->dir), tag, "ok");
    SetDataDir(n->dir);
    main_state_init(&n->ms);
    flysync_island_test_reset();
    csr_test_reset_singleton();
    csr_init(csr_instance(), &n->ms.map_block_index, &n->ms.chain_active,
             &n->ms.pindex_best_header, NULL, NULL, NULL);
    sync_monitor_set_context(NULL, NULL, &n->ms);
    char log_path[320], db_path[320];
    snprintf(log_path, sizeof(log_path), "%s/events.log", n->dir);
    snprintf(db_path, sizeof(db_path), "%s/block_index_projection.db", n->dir);
    g_fsi_log = event_log_open(log_path);
    g_fsi_projection = g_fsi_log ? block_index_projection_open(db_path, g_fsi_log) : NULL;
    event_log_set_singleton(g_fsi_log);
    block_index_projection_set_singleton(g_fsi_projection);
    return g_fsi_projection && fsi_add_genesis(&n->ms) && progress_store_open(n->dir);
}

void fsi_node_close(struct fsi_node *n)
{
    sync_monitor_set_context(NULL, NULL, NULL);
    csr_test_reset_singleton();
    flysync_island_test_reset();
    progress_store_close();
    block_index_projection_set_singleton(NULL);
    event_log_set_singleton(NULL);
    if (g_fsi_projection) block_index_projection_close(g_fsi_projection);
    if (g_fsi_log) event_log_close(g_fsi_log);
    g_fsi_projection = NULL; g_fsi_log = NULL;
    main_state_free(&n->ms);
    ClearDataDirCache();
    test_rm_rf(n->dir);
}

bool fsi_node_seed(struct fsi_node *n)
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
    return true;
}

struct block_index *fsi_top(struct fsi_node *n)
{
    return n->rows[FSI_W - 1];
}

bool fsi_top_work_is_rung(struct fsi_node *n)
{
    return arith_uint256_compare(&fsi_top(n)->nChainWork,
                                 &n->is.rung_work) == 0;
}

static bool fsi_boot_reg(sqlite3 *db)
{
    bool reg = false;
    return island_anchor_boot_register(db, &reg).ok && reg;
}

static bool fsi_held(sqlite3 *db)
{
    bool held = false;
    return island_anchor_hold_recorded(db, &held).ok && held;
}

/* The loader's forward pass over the island, as a warm boot runs it. */
void fsi_reload_work(struct fsi_node *n)
{
    for (int i = 0; i < FSI_W; i++)
        arith_uint256_set_zero(&n->rows[i]->nChainWork);
    block_index_forward_pass(n->rows, FSI_W);
}

static bool fsi_richer_status(const struct fsi_node *n)
{
    struct ev_block_status status = { .nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA,
        .nFile = 7, .nDataPos = 123, .nUndoPos = 45, .nTx = 9 };
    memcpy(status.hash, n->is.hash[9].data, 32);
    uint8_t wire[EV_BLOCK_STATUS_WIRE_LEN];
    return ev_block_status_serialize(&status, wire) &&
        event_log_append(g_fsi_log, EV_BLOCK_STATUS, wire, sizeof(wire)) != UINT64_MAX &&
        event_log_flush(g_fsi_log) && block_index_projection_catch_up(g_fsi_projection) != UINT64_MAX;
}

static bool fsi_remove_projection_row(const struct fsi_node *n, int i)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/block_index_projection.db", n->dir);
    sqlite3 *db = NULL;
    sqlite3_stmt *s = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db, "DELETE FROM block_index WHERE hash=?", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(s, 1, n->is.hash[i].data, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_DONE && sqlite3_changes(db) == 1;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static int fsi_case_missing_projection_row(struct fsi_node *n)
{
    int failures = 0;
    island_anchor_unregister();
    FSI_CHECK("durable window verifies before registration", flysync_island_boot_register(n->dir));
    FSI_CHECK("island recovery refuses early projection tip publication",
              !flysync_island_boot_loader_allowed(true) && flysync_island_boot_loader_allowed(false));
    FSI_CHECK("richer projection status is recorded", fsi_richer_status(n));
    size_t before = n->ms.map_block_index.size;
    struct disk_block_index row;
    FSI_CHECK("missing derived row is rebuilt without publishing map entries",
              fsi_remove_projection_row(n, 7) &&
              block_index_projection_lookup_strict(g_fsi_projection, n->is.hash[7].data, &row) == BIP_LOOKUP_ABSENT &&
              flysync_island_boot_rehydrate(&n->ms) &&
              n->ms.map_block_index.size == before &&
              block_index_projection_get_strict(g_fsi_projection, n->is.hash[7].data, &row) &&
              row.nHeight == FSI_RUNG_H - 7);
    FSI_CHECK("reconstruction preserves existing body metadata",
              block_index_projection_get_strict(g_fsi_projection, n->is.hash[9].data, &row) &&
              (row.nStatus & BLOCK_HAVE_DATA) && row.nFile == 7 &&
              row.nDataPos == 123 && row.nUndoPos == 45 && row.nTx == 9);
    return failures;
}

static bool fsi_append_post_rung(struct fsi_node *n, struct uint256 *hash)
{
    struct block_header header;
    fsi_build_header(&header, 123, &n->is.hash[0], hash);
    struct block_index row;
    block_index_init(&row);
    row.phashBlock = hash;
    row.pprev = fsi_top(n);
    row.nHeight = FSI_RUNG_H + 1;
    row.nVersion = header.nVersion;
    row.hashFinalSaplingRoot = header.hashFinalSaplingRoot;
    row.nTime = header.nTime;
    row.nBits = header.nBits;
    row.nStatus = BLOCK_VALID_TREE;
    bool ok = block_index_set_hdrext(&row, &header.hashMerkleRoot, &header.nNonce,
                                     header.nSolution, header.nSolutionSize) &&
        block_index_emit_header_event(&row, "flysync-test", NULL, NULL) &&
        event_log_flush(g_fsi_log) &&
        block_index_projection_catch_up(g_fsi_projection) != UINT64_MAX;
    block_index_hdrext_free(&row);
    return ok;
}

static int fsi_case_ladder_restart(struct fsi_node *n)
{
    int failures = 0;
    struct uint256 post_hash;
    FSI_CHECK("post-rung header is durable", fsi_append_post_rung(n, &post_hash));
    struct main_state restarted;
    main_state_init(&restarted);
    FSI_CHECK("restart begins with genesis only", fsi_add_genesis(&restarted));
    size_t before = restarted.map_block_index.size;
    FSI_CHECK("derived recovery leaves loader map unchanged",
              flysync_island_boot_rehydrate(&restarted) && restarted.map_block_index.size == before);
    struct app_context ctx = {0};
    ctx.datadir = n->dir;
    ctx.no_legacy_auto_import = true;
    ctx.no_legacy_utxo_import = true;
    struct node_db db = {0};
    struct boot_blkidx_load_ctx load = {
        .ctx = &ctx, .st = &restarted, .ndb = &db, .params = chain_params_get()
    };
    boot_blkidx_run_ladder(&load);
    FSI_CHECK("own recovery ladder retains post-rung header with legacy imports disabled",
              block_map_find(&restarted.map_block_index, &post_hash) != NULL);
    FSI_CHECK("verified window materializes after ladder", flysync_island_boot_materialize(&restarted));
    struct block_index *post = block_map_find(&restarted.map_block_index, &post_hash);
    struct block_index *rung = block_map_find(&restarted.map_block_index, &n->is.hash[0]);
    struct arith_uint256 expected;
    if (post && rung) {
        struct arith_uint256 proof = GetBlockProof(post);
        arith_uint256_add(&expected, &rung->nChainWork, &proof);
    }
    FSI_CHECK("post-rung height, parent and cumulative work survive recovery",
              post && rung && post->nHeight == FSI_RUNG_H + 1 && post->pprev == rung &&
              arith_uint256_compare(&post->nChainWork, &expected) == 0);
    main_state_free(&restarted);
    return failures;
}

static int fsi_case_seed_rows(struct fsi_node *n)
{
    int failures = 0;
    struct block_index *top = fsi_top(n), *root = n->rows[0];
    FSI_CHECK("seeded rung row sits at the rung height",
              top->nHeight == FSI_RUNG_H && root->nHeight == FSI_RUNG_H - 27);
    FSI_CHECK("seeded rung row carries the compiled chainwork",
              fsi_top_work_is_rung(n));
    FSI_CHECK("seeding promotes the rung row to best header through the csr",
              n->ms.pindex_best_header == top);
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
              fsi_boot_reg(db) && island_anchor_get(&back) &&
              back.root_height == n->a.root_height &&
              uint256_eq(&back.root_hash, &n->a.root_hash) &&
              arith_uint256_compare(&back.root_work, &n->a.root_work) == 0);
    failures += fsi_case_missing_projection_row(n);
    failures += fsi_case_ladder_restart(n);
    return failures;
}

/* The chain-binding frontier: is genesis an ancestor of the island's rung? */
static int fsi_case_frontier_ancestry(struct fsi_node *n, const char *who,
                                      bool island)
{
    int failures = 0;
    const struct chain_params *cp = chain_params_get();
    struct uint256 genesis_hash = cp->consensus.hashGenesisBlock, other;
    memset(other.data, 0x47, 32);
    struct block_index genesis, stranger;
    memset(&genesis, 0, sizeof(genesis));
    genesis.phashBlock = &genesis_hash;
    stranger = genesis;
    stranger.phashBlock = &other;
    bool known = false;
    bool rel = chain_frontier_test_ancestor_relation(&genesis, fsi_top(n),
                                                     &known);
    char d[128];
    snprintf(d, sizeof(d), "%s: frontier ancestry genesis -> rung is %s", who,
             island ? "known and true" : "unknown (refused as before)");
    FSI_CHECK(d, island ? (known && rel) : (!known && !rel));
    known = false;
    rel = chain_frontier_test_ancestor_relation(&stranger, fsi_top(n), &known);
    snprintf(d, sizeof(d), "%s: a height-0 entry that is not genesis is "
             "never the rung's ancestor", who);
    FSI_CHECK(d, !rel);
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
    failures += fsi_case_frontier_ancestry(n, "island", true);

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
    failures += fsi_case_frontier_ancestry(n, "no fact", false);
    (void)fsi_boot_reg(progress_store_db());
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

/* A seeded island whose rung bundle install budget is spent falls back; while
 * the budget lasts and the bundle is staged it keeps waiting. */
static int fsi_case_install_budget(struct fsi_node *n)
{
    int failures = 0;
    char bdir[512], bpath[600];
    snprintf(bdir, sizeof(bdir), "%s/bundles", n->dir);
    snprintf(bpath, sizeof(bpath), "%s/consensus-state-bundle-%d.sqlite", bdir,
             FSI_RUNG_H);
    FILE *fp = (mkdir(bdir, 0700) == 0) ? fopen(bpath, "w") : NULL;
    FSI_CHECK("a rung bundle is staged", fp != NULL);
    if (fp)
        fclose(fp);
    FSI_CHECK("install requested", boot_install_bundle_request(n->dir, bpath) == 1);
    flysync_island_tick();
    FSI_CHECK("seeded, bundle staged, budget left: still waiting",
              flysync_island_phase() == FLYSYNC_SEEDED &&
              flysync_island_owns_state_source());
    char out[600];
    for (int i = 0; i <= BOOT_INSTALL_BUNDLE_MAX; i++)
        (void)boot_install_bundle_consume(n->dir, out, sizeof(out));
    FSI_CHECK("the install budget is spent",
              boot_install_bundle_terminal(n->dir, NULL));
    flysync_island_tick();
    FSI_CHECK("budget spent: FlySync falls back, hold lifts",
              flysync_island_phase() == FLYSYNC_FELL_BACK &&
              !flysync_island_holds_header_sync() &&
              !flysync_island_owns_state_source() &&
              !island_anchor_registered());
    FSI_CHECK("the budget fall-back is durable",
              island_anchor_state_load(progress_store_db()) ==
              ISLAND_ANCHOR_STATE_FELL_BACK);
    return failures;
}

/* Detached: no parent, and work that is not zero (the boot block-index scan
 * ranks a zero-work entry by height, so the rung row would win) yet below
 * genesis's, so every work comparison passes over the row. */
/* C: the fact, its row list and its state are one record. */
static int fsi_case_fact_record(struct fsi_node *nn)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    FSI_CHECK("a fact without its state reads as no island",
              progress_meta_delete(db, "flysync.island_state") &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_NONE);
    struct island_anchor_rows list, back;
    for (int i = 0; i < FSI_W; i++)
        list.hash[i] = nn->is.hash[FSI_W - 1 - i];
    struct island_anchor_rows wrong = list;
    wrong.hash[FSI_W - 1] = list.hash[FSI_W - 2];
    FSI_CHECK("save refuses a row list that does not end at the rung",
              !island_anchor_save(db, &nn->a, &wrong).ok &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_NONE);
    struct zcl_result saved = island_anchor_save(db, &nn->a, &list);
    bool rows_found = false;
    FSI_CHECK("save writes the fact, its rows and SEEDED together",
              saved.ok && island_anchor_state_load(db) ==
                              ISLAND_ANCHOR_STATE_SEEDED &&
              island_anchor_rows_load(db, &back, &rows_found).ok &&
              rows_found &&
              memcmp(back.hash, list.hash, sizeof(list.hash)) == 0);
    return failures;
}

/* SHOULD 3: an installed island never falls back, and INSTALLED keys on the
 * exact rung. */
static int fsi_case_installed(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("installed fixture opens", fsi_node_open(&n, "flysync_installed"));
    if (!fsi_node_seed(&n)) {
        FSI_CHECK("installed fixture seeds", false);
        fsi_node_close(&n);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    failures += fsi_case_fact_record(&n);
    uint8_t digest[32] = {0};
    char why[320];
    FSI_CHECK("a bundle marker at another height leaves the island SEEDED",
              boot_consensus_bundle_marker_write(n.dir, FSI_RUNG_H - 100000,
                                                 digest) &&
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_SEEDED &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_SEEDED);
    flysync_island_set_auto(true);
    FSI_CHECK("-flysync-auto preserves a seeded island",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_SEEDED);
    FSI_CHECK("the rung bundle marker makes the island INSTALLED, durably",
              boot_consensus_bundle_marker_write(n.dir, FSI_RUNG_H, digest) &&
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_DONE &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_INSTALLED);
    struct block_index *saved_prev = n.rows[5]->pprev;
    n.rows[5]->pprev = NULL;
    FSI_CHECK("a damaged installed island refuses restart without falling back",
              !flysync_island_boot_reconcile(&n.ms) &&
              island_anchor_registered() &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_INSTALLED &&
              flysync_island_phase() == FLYSYNC_DONE);
    struct zcl_result fb = island_anchor_note_fallback(db, "test");
    FSI_CHECK("the durable fall-back is refused once installed",
              !fb.ok && island_anchor_registered() &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_INSTALLED);
    n.rows[5]->pprev = saved_prev;
    FSI_CHECK("an installed island registers at every boot",
              (island_anchor_unregister(), fsi_boot_reg(db)));
    fsi_node_close(&n);
    return failures;
}

void fsi_release_globals(void)
{
    msg_processor_set_header_sync_hold(NULL);
    state_offer_store_set_height_filter(NULL);
    net_set_advertise_full_history(true);
    state_offer_store_reset();
}

/* SHOULD 4, 5 and E: one tick at a time, a hold bound that survives restarts,
 * a stalled chosen offer, and no permanent refusal of a datadir FlySync held. */
static int fsi_case_hold_bound(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("hold fixture opens", fsi_node_open(&n, "flysync_hold"));
    sqlite3 *db = progress_store_db();
    const int64_t t0 = INT64_C(5000000000);
    const int64_t day_ms = INT64_C(86400000);
    flysync_island_set_requested(true);
    flysync_island_test_set_clock_ms(t0);
    FSI_CHECK("a held boot is counted durably",
              flysync_island_boot_after_index(NULL, &n.ms) &&
              flysync_island_phase() == FLYSYNC_WAIT &&
              fsi_held(db));

    /* Boots 2..N, each 30 days after the last: downtime never counts. */
    bool waiting = true;
    for (int b = 2; b <= FLYSYNC_HOLD_BOOTS; b++) {
        flysync_island_test_reset();
        fsi_release_globals();
        flysync_island_set_requested(true);
        int64_t tb = t0 + (int64_t)b * 30 * day_ms;
        flysync_island_test_set_clock_ms(tb);
        state_offer_store_note_first_peer(tb);
        (void)flysync_island_boot_after_index(NULL, &n.ms);
        flysync_island_tick();
        waiting = waiting && flysync_island_phase() == FLYSYNC_WAIT;
    }
    FSI_CHECK("boots up to the bound keep waiting, however long apart",
              waiting);
    int64_t tl = t0 + (int64_t)FLYSYNC_HOLD_BOOTS * 30 * day_ms +
                 STATE_OFFER_WAIT_MS * 4;
    flysync_island_test_set_clock_ms(tl);
    flysync_island_test_hold_tick(true);
    flysync_island_tick();
    FSI_CHECK("the tick is single-entry: a second caller does nothing",
              flysync_island_phase() == FLYSYNC_WAIT);
    flysync_island_test_hold_tick(false);
    flysync_island_tick();
    FSI_CHECK("released, the same tick closes the offer wait",
              flysync_island_phase() == FLYSYNC_FELL_BACK);

    flysync_island_test_reset();
    fsi_release_globals();
    FSI_CHECK("hold count kept for the over-bound boot",
              progress_meta_delete(db, "flysync.island_state"));
    flysync_island_set_requested(true);
    flysync_island_test_set_clock_ms(tl + day_ms);
    FSI_CHECK("the boot past the bound falls back before choosing a source, "
              "with no restart",
              flysync_island_boot_after_index(NULL, &n.ms) &&
              flysync_island_phase() == FLYSYNC_FELL_BACK &&
              flysync_island_test_respawns() == 0 &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_FELL_BACK &&
              !flysync_island_holds_header_sync());

    flysync_island_test_reset();
    flysync_island_set_requested(true);
    struct uint256 h1;
    memset(h1.data, 0x31, 32);
    (void)chainstate_insert_block_index((struct chainstate *)&n.ms, &h1);
    char why[320];
    why[0] = '\0';
    FSI_CHECK("chain state admitted while FlySync waited: fall back, no "
              "refusal",
              progress_meta_delete(db, "flysync.island_state") &&
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_FELL_BACK);
    fsi_release_globals();
    fsi_node_close(&n);
    return failures;
}

/* SHOULD 5: a chosen rung offer that never arrives ends the wait. */
static int fsi_case_fetch_stall(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("stall fixture opens", fsi_node_open(&n, "flysync_stall"));
    fsi_build_island(&n.is);
    flysync_island_test_set_rung(&n.is.rung);
    flysync_island_set_requested(true);
    const int64_t t0 = INT64_C(7000000000);
    flysync_island_test_set_clock_ms(t0);
    (void)flysync_island_boot_after_index(NULL, &n.ms);
    struct state_offer_v1 o;
    fsi_make_offer(&o, FSI_RUNG_H, 0x50);
    uint8_t ip[16] = {0};
    ip[10] = 0xff; ip[11] = 0xff; ip[12] = 10; ip[15] = 34;
    struct state_offer_record rec;
    state_offer_store_note_first_peer(t0);
    (void)state_offer_store_record(&o, ip, 18034, 3, t0);
    FSI_CHECK("the rung offer is chosen",
              state_offer_store_decide(t0 + 1000, &rec) ==
              STATE_OFFER_DECIDE_FETCH);
    /* A slow link that keeps moving: one verified chunk every 9 minutes for
     * an hour, past any total-time rule shorter than the cap. */
    const int64_t step = FLYSYNC_FETCH_STALL_MS - 60000;
    bool waiting = true;
    int64_t t = t0;
    for (uint32_t c = 1; c <= 7; c++) {
        t += step;
        state_offer_store_note_fetch_progress(c, 1000, (uint64_t)c << 20,
                                              (uint64_t)1000 << 20);
        flysync_island_test_set_clock_ms(t);
        flysync_island_tick();
        waiting = waiting && flysync_island_phase() == FLYSYNC_WAIT;
    }
    FSI_CHECK("a slow download that keeps landing chunks keeps waiting",
              waiting && t - t0 > INT64_C(1800000)); /* old 30 min rule */
    flysync_island_test_set_clock_ms(t + FLYSYNC_FETCH_STALL_MS - 1);
    flysync_island_tick();
    FSI_CHECK("inside the stall bound the node keeps waiting",
              flysync_island_phase() == FLYSYNC_WAIT);
    flysync_island_test_set_clock_ms(t + FLYSYNC_FETCH_STALL_MS);
    flysync_island_tick();
    FSI_CHECK("no new chunk for the stall bound: fall back",
              flysync_island_phase() == FLYSYNC_FELL_BACK);
    fsi_release_globals();
    fsi_node_close(&n);
    return failures;
}

/* The cap: a download that keeps moving still ends after FLYSYNC_FETCH_CAP_MS
 * of this process's time. */
static int fsi_case_fetch_cap(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("cap fixture opens", fsi_node_open(&n, "flysync_cap"));
    fsi_build_island(&n.is);
    flysync_island_test_set_rung(&n.is.rung);
    flysync_island_set_requested(true);
    const int64_t t0 = INT64_C(9000000000);
    flysync_island_test_set_clock_ms(t0);
    (void)flysync_island_boot_after_index(NULL, &n.ms);
    struct state_offer_v1 o;
    fsi_make_offer(&o, FSI_RUNG_H, 0x51);
    uint8_t ip[16] = {0};
    ip[10] = 0xff; ip[11] = 0xff; ip[12] = 10; ip[15] = 35;
    struct state_offer_record rec;
    state_offer_store_note_first_peer(t0);
    (void)state_offer_store_record(&o, ip, 18035, 3, t0);
    (void)state_offer_store_decide(t0 + 1000, &rec);
    /* The fetch starts 100 s into the offer wait; the cap counts from there,
     * not from entering WAIT. */
    const int64_t f0 = t0 + 100000;
    flysync_island_test_set_clock_ms(f0);
    flysync_island_tick();
    const int64_t step = FLYSYNC_FETCH_STALL_MS / 2;
    bool waiting = flysync_island_phase() == FLYSYNC_WAIT;
    uint32_t c = 0;
    int64_t t = f0;
    while (t + step < t0 + FLYSYNC_FETCH_CAP_MS) {
        t += step;
        c++;
        state_offer_store_note_fetch_progress(c, 100000, c, 100000);
        flysync_island_test_set_clock_ms(t);
        flysync_island_tick();
        waiting = waiting && flysync_island_phase() == FLYSYNC_WAIT;
    }
    FSI_CHECK("a moving download waits up to the cap", waiting);
    c++;
    state_offer_store_note_fetch_progress(c, 100000, c, 100000);
    flysync_island_test_set_clock_ms(t0 + FLYSYNC_FETCH_CAP_MS);
    flysync_island_tick();
    FSI_CHECK("at WAIT entry + cap the download still waits: the cap counts "
              "from the fetch start",
              flysync_island_phase() == FLYSYNC_WAIT);
    c++;
    state_offer_store_note_fetch_progress(c, 100000, c, 100000);
    flysync_island_test_set_clock_ms(f0 + FLYSYNC_FETCH_CAP_MS);
    flysync_island_tick();
    FSI_CHECK("at the cap a still-moving download falls back",
              flysync_island_phase() == FLYSYNC_FELL_BACK);
    fsi_release_globals();
    fsi_node_close(&n);
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
        FSI_CHECK("seeded, not yet installed: only a rung offer is taken",
                  flysync_island_wants_offer_height(FSI_RUNG_H) &&
                  !flysync_island_wants_offer_height(FSI_RUNG_H - 1));
        failures += fsi_case_install_budget(&n);
        failures += fsi_fallback_cases(&n);
    }
    fsi_node_close(&n);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

/* ── State-offer height filter ───────────────────────────────────────────── */

/* A signed offer at `height`, built as test_stale_offers_only builds one. */
void fsi_make_offer(struct state_offer_v1 *o, int32_t height, uint8_t tag)
{
    memset(o, 0, sizeof(*o));
    o->version = STATE_OFFER_VERSION;
    o->flags = STATE_OFFER_FLAGS_NONE;
    o->bundle_height = height;
    o->offerer_tip_height = 3309702;
    o->chunk_size = STATE_OFFER_CHUNK_SIZE_BYTES;
    o->content_bytes = (uint64_t)STATE_OFFER_CHUNK_SIZE_BYTES * 8u;
    o->num_chunks = 8u;
    o->kind = (uint16_t)ROM_ARTIFACT_CONSENSUS_BUNDLE;
    for (size_t i = 0; i < 32; i++) {
        o->header_hash[i] = (uint8_t)(0x11u + tag + i);
        o->content_digest[i] = (uint8_t)(tag + i);
        o->chunk_tree_root[i] = (uint8_t)(0x51u + tag + i);
        o->mmb_peaks_digest[i] = (uint8_t)(0x71u + i);
        o->producer_receipt_id[i] = (uint8_t)(0x91u + i);
    }
    o->issued_unix = UINT64_C(1800000000);
    memcpy(o->filename, "consensus-state-bundle-1.sqlite", 31);
    o->filename_len = 31;
    uint8_t seed[32];
    for (size_t i = 0; i < 32; i++)
        seed[i] = (uint8_t)(0x0du ^ (uint8_t)(i * 7u + 3u));
    (void)state_offer_v1_sign(o, seed);
}

/* Only a keystone offer on the table: chosen without the filter, never while
 * a FlySync node waits for its rung. */
static int fsi_case_offer_filter(void)
{
    int failures = 0;
    const struct rom_state_checkpoint *ks = get_rom_state_checkpoint();
    struct state_offer_v1 o;
    fsi_make_offer(&o, ks ? ks->height : 3056758, 0x40);
    uint8_t ip[16] = {0};
    ip[10] = 0xff; ip[11] = 0xff; ip[12] = 10; ip[15] = 33;
    struct state_offer_record rec;

    state_offer_store_reset();
    state_offer_store_set_height_filter(NULL);
    bool kept = state_offer_store_record(&o, ip, 18034, 3, 1000) ==
                STATE_OFFER_STORE_KEPT;
    FSI_CHECK("no filter: the keystone offer is kept and chosen",
              kept && state_offer_store_decide(2000, &rec) ==
                          STATE_OFFER_DECIDE_FETCH);

    state_offer_store_reset();
    flysync_island_test_reset();
    flysync_island_set_requested(true);
    struct fsi_node n;
    if (!fsi_node_open(&n, "flysync_offer_filter")) {
        FSI_CHECK("offer filter fixture opens", false);
        fsi_node_close(&n);
        state_offer_store_reset();
        return failures;
    }
    flysync_island_set_requested(true);
    char why[160];
    FSI_CHECK("offer filter fixture starts FlySync",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)));
    state_offer_store_set_height_filter(flysync_island_wants_offer_height);
    (void)state_offer_store_record(&o, ip, 18034, 3, 1000);
    FSI_CHECK("FlySync waiting: the keystone offer is not chosen",
              flysync_island_phase() == FLYSYNC_WAIT &&
              state_offer_store_decide(2000, &rec) != STATE_OFFER_DECIDE_FETCH);
    FSI_CHECK("FlySync waiting: a baked rung height is wanted",
              flysync_island_wants_offer_height(FSI_RUNG_H) &&
              !flysync_island_wants_offer_height(FSI_RUNG_H + 1));
    flysync_island_test_reset();
    FSI_CHECK("FlySync off: every height is wanted",
              flysync_island_wants_offer_height(ks ? ks->height : 1));
    state_offer_store_set_height_filter(NULL);
    state_offer_store_reset();
    fsi_node_close(&n);
    return failures;
}

/* ── Boot gate and fall-back ─────────────────────────────────────────────── */

static int fsi_case_auto_fresh(struct fsi_node *n)
{
    int failures = 0;
    char why[320] = {0};
    struct app_context parsed = {0};
    bool metrics = false;
    char *auto_argv[] = { (char *)"z23", (char *)"-flysync-auto",
        (char *)"-nolegacyimport", (char *)"-nolegacyutxoimport", NULL };
    FSI_CHECK("Android auto arguments parse with imports disabled",
              args_parse_node_options(4, auto_argv, &parsed, &metrics) == -1 &&
              parsed.no_legacy_auto_import && parsed.no_legacy_utxo_import);
    FSI_CHECK("-flysync-auto on an empty datadir starts the wait",
              flysync_island_boot_gate(n->dir, &n->ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_WAIT &&
              flysync_island_holds_header_sync());
    flysync_island_test_reset();
    return failures;
}

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
    failures += fsi_case_auto_fresh(&n);
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
              flysync_island_phase() == FLYSYNC_FELL_BACK &&
              !flysync_island_owns_state_source());
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
    flysync_island_test_reset();
    flysync_island_set_auto(true);
    FSI_CHECK("-flysync-auto preserves an existing non-island chain",
              flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              flysync_island_phase() == FLYSYNC_OFF &&
              !flysync_island_holds_header_sync());
    flysync_island_set_requested(true);
    FSI_CHECK("explicit -flysync overrides auto on an existing chain",
              !flysync_island_boot_gate(n.dir, &n.ms, why, sizeof(why)) &&
              strstr(why, "no chain state") != NULL);
    fsi_node_close(&n);
    return failures;
}

#if !defined(_WIN32) && defined(ZCL_TESTING)
static bool fsi_crash_after_commit;
static void fsi_crash_hook(bool committed)
{
    if (committed == fsi_crash_after_commit)
        _exit(73);
}

static bool fsi_crash_transaction(struct fsi_node *n, bool after)
{
    struct island_anchor_rows rows;
    for (int i = 0; i < FSI_W; ++i)
        rows.hash[i] = n->is.hash[FSI_W - 1 - i];
    progress_store_close();
    pid_t child = fork();
    if (child == 0) {
        if (!progress_store_open(n->dir)) _exit(74);
        fsi_crash_after_commit = after;
        island_anchor_test_commit_hook(fsi_crash_hook);
        (void)island_anchor_save_window(progress_store_db(), &n->a, &rows, n->is.w);
        _exit(75);
    }
    int status = 0;
    bool killed = child > 0 && waitpid(child, &status, 0) == child &&
                  WIFEXITED(status) && WEXITSTATUS(status) == 73;
    return killed && progress_store_open(n->dir);
}

static int fsi_case_window_commit_crash(void)
{
    int failures = 0;
    struct fsi_node n;
    FSI_CHECK("window crash fixture opens", fsi_node_open(&n, "flysync_window_crash"));
    fsi_build_island(&n.is);
    flysync_island_test_set_rung(&n.is.rung);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    char why[160];
    bool valid = flysync_island_verify_window(n.is.w, FSI_W, FSI_RUNG_H,
                                              &n.a, why, sizeof(why));
    FSI_CHECK("window verifies before crash", valid);
    FSI_CHECK("crash before commit preserves absent state",
              valid && fsi_crash_transaction(&n, false) &&
              island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_NONE);
    FSI_CHECK("crash after commit preserves seeded state",
              valid && fsi_crash_transaction(&n, true) &&
              island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_SEEDED);
    struct block_header window[FSI_W];
    bool found = false;
    FSI_CHECK("committed window survives reopen and verifies",
              island_anchor_window_load(progress_store_db(), window, &found).ok && found &&
              flysync_island_verify_window(window, FSI_W, FSI_RUNG_H, &n.a, why, sizeof(why)));
    FSI_CHECK("orphaned committed window without state is refused",
              progress_meta_delete(progress_store_db(), "flysync.island_state") &&
              !flysync_island_boot_register(n.dir));
    fsi_node_close(&n);
    return failures;
}
#endif

/* The caller keeps ownership of transaction and progress-store lock. */
static int fsi_intx_refusal_cases(struct fsi_node *n, const struct island_anchor_rows *rows)
{
    int failures = 0;
    sqlite3 *db = progress_store_db(), *other = NULL;
    FSI_CHECK("in-tx refuses autocommit", !island_anchor_install_window_in_tx(db, &n->a, rows, n->is.w).ok);
    bool opened = sqlite3_open(":memory:", &other) == SQLITE_OK;
    FSI_CHECK("in-tx refuses another connection", opened && sqlite3_exec(other, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
              !island_anchor_install_window_in_tx(other, &n->a, rows, n->is.w).ok);
    if (other) { (void)sqlite3_exec(other, "ROLLBACK", NULL, NULL, NULL); sqlite3_close(other); }
    static const char *const orphans[] = {"flysync.island_anchor.v1", "flysync.island_rows.v1", "flysync.island_window.v1", "flysync.island_state"};
    for (size_t i = 0; i < sizeof(orphans) / sizeof(orphans[0]); i++) {
        uint8_t junk = 0;
        progress_store_tx_lock();
        bool begun = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
        bool refused = begun && progress_meta_set_in_tx(db, orphans[i], &junk, 1) &&
            !island_anchor_install_window_in_tx(db, &n->a, rows, n->is.w).ok && !sqlite3_get_autocommit(db);
        bool rolled = begun && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
        progress_store_tx_unlock();
        FSI_CHECK("in-tx refuses orphan or malformed state", refused && rolled);
    }
    return failures;
}

static int fsi_intx_rollback_case(struct fsi_node *n, const struct island_anchor_rows *rows)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    progress_store_tx_lock();
    bool begun = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    bool wrote = begun && island_anchor_install_window_in_tx(db, &n->a, rows, n->is.w).ok;
    bool retained = wrote && !sqlite3_get_autocommit(db) && !island_anchor_registered();
    bool rolled = begun && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    progress_store_tx_unlock();
    FSI_CHECK("in-tx write retains transaction without RAM registration", retained);
    struct island_anchor fact; struct island_anchor_rows reread; struct block_header window[FSI_W];
    bool have_fact = false, have_rows = false, have_window = false;
    FSI_CHECK("in-tx rollback removes all proof records", wrote && rolled &&
              island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_NONE &&
              island_anchor_load(db, &fact, &have_fact).ok && !have_fact &&
              island_anchor_rows_load(db, &reread, &have_rows).ok && !have_rows &&
              island_anchor_window_load(db, window, &have_window).ok && !have_window);
    return failures;
}

static bool fsi_intx_fact_matches(const struct island_anchor *a, const struct island_anchor *b)
{
    return a->root_height == b->root_height && a->rung_height == b->rung_height &&
        uint256_eq(&a->root_hash, &b->root_hash) && uint256_eq(&a->rung_hash, &b->rung_hash) &&
        arith_uint256_compare(&a->root_work, &b->root_work) == 0;
}

static bool fsi_intx_headers_match(const struct block_header *window, const struct island_anchor_rows *rows)
{
    for (int i = 0; i < FSI_W; i++) {
        struct uint256 hash;
        block_header_get_hash(&window[i], &hash);
        if (!uint256_eq(&hash, &rows->hash[FSI_W - 1 - i])) return false;
    }
    return true;
}

static bool fsi_intx_reload_proof(sqlite3 *db, struct fsi_node *n,
                                  const struct island_anchor_rows *rows)
{
    struct island_anchor fact; struct island_anchor_rows reread; struct block_header window[FSI_W];
    bool have_fact = false, have_rows = false, have_window = false;
    bool exact = island_anchor_load(db, &fact, &have_fact).ok && have_fact &&
        island_anchor_rows_load(db, &reread, &have_rows).ok && have_rows &&
        island_anchor_window_load(db, window, &have_window).ok && have_window &&
        island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_INSTALLED &&
        !memcmp(&reread, rows, sizeof(*rows)) &&
        fsi_intx_fact_matches(&fact, &n->a) && fsi_intx_headers_match(window, rows);
    char why[160];
    return exact && flysync_island_verify_window(window, FSI_W, FSI_RUNG_H, &fact, why, sizeof(why));
}

static int fsi_intx_commit_case(struct fsi_node *n, const struct island_anchor_rows *rows)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    progress_store_tx_lock();
    bool begun = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    bool wrote = begun && island_anchor_install_window_in_tx(db, &n->a, rows, n->is.w).ok;
    bool committed = wrote && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (begun && !committed) (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    FSI_CHECK("in-tx commit reloads the full proof", committed && fsi_intx_reload_proof(db, n, rows));
    progress_store_tx_lock();
    begun = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    bool existing = begun && !island_anchor_install_window_in_tx(db, &n->a, rows, n->is.w).ok;
    bool rolled = begun && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    progress_store_tx_unlock();
    FSI_CHECK("in-tx refuses existing proof", existing && rolled);
    return failures;
}

/* An activation-owned transaction either retains the whole proof or none. */
static int fsi_case_window_in_tx(void)
{
    int failures = 0;
    struct fsi_node n;
    if (!fsi_node_open(&n, "flysync_window_in_tx")) {
        FSI_CHECK("in-tx fixture opens", false);
        fsi_node_close(&n);
        return failures;
    }
    fsi_build_island(&n.is);
    flysync_island_test_set_rung(&n.is.rung);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    char why[160];
    bool verified = flysync_island_verify_window(n.is.w, FSI_W, FSI_RUNG_H, &n.a, why, sizeof(why));
    struct island_anchor_rows rows;
    for (int i = 0; i < FSI_W; i++) block_header_get_hash(&n.is.w[FSI_W - 1 - i], &rows.hash[i]);
    FSI_CHECK("in-tx fixture window verifies", verified);
    if (verified) {
        failures += fsi_intx_refusal_cases(&n, &rows);
        failures += fsi_intx_rollback_case(&n, &rows);
        failures += fsi_intx_commit_case(&n, &rows);
    }
    fsi_node_close(&n);
    return failures;
}

static int fsi_case_terminal_prepare(void)
{
    int failures = 0;
    struct fsi_node n;
    if (!fsi_node_open(&n, "terminal_prepare")) return 1;
    fsi_build_island(&n.is);
    flysync_island_test_set_rung(&n.is.rung);
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    struct block_index *old = n.ms.pindex_best_header;
    struct fsi_island bad = n.is;
    bad.w[5].nNonce.data[3] ^= 0x40;
    size_t count = n.ms.map_block_index.size;
    FSI_CHECK("terminal preparation refuses invalid proof without insertion",
              !flysync_island_prepare_terminal_window(&n.ms, bad.w, FSI_W, FSI_RUNG_H) &&
              n.ms.map_block_index.size == count);
    struct block_index *top = flysync_island_prepare_terminal_window(&n.ms, n.is.w, FSI_W, FSI_RUNG_H);
    FSI_CHECK("terminal preparation inserts verified rows without selecting or registering",
              top && n.ms.pindex_best_header == old && active_chain_tip(&n.ms.chain_active) == old &&
              !island_anchor_registered());
    struct block_index *saved_parent = top ? top->pprev : NULL;
    count = n.ms.map_block_index.size;
    FSI_CHECK("terminal preparation refuses existing rows without changing parent",
              top && !flysync_island_prepare_terminal_window(&n.ms, n.is.w, FSI_W, FSI_RUNG_H) &&
              top->pprev == saved_parent && n.ms.map_block_index.size == count);
    struct block_header window[FSI_W]; bool found = false;
    FSI_CHECK("terminal preparation does not persist a window",
              island_anchor_window_load(progress_store_db(), window, &found).ok && !found);
    fsi_node_close(&n);
    return failures;
}

int test_flysync_island(void)
{
    int failures = 0;
    failures += fsi_case_window_in_tx();
#if !defined(_WIN32) && defined(ZCL_TESTING)
    failures += fsi_case_window_commit_crash();
#endif
    failures += fsi_case_window_walk();
    failures += fsi_case_window_args_and_single_mode();
    failures += fsi_case_hold_and_services();
    failures += fsi_case_verify_window();
    failures += fsi_case_terminal_prepare();
    failures += fsi_case_island();
    failures += fsi_case_boot_gate();
    failures += fsi_case_offer_filter();
    failures += fsi_case_installed();
    failures += fsi_case_hold_bound();
    failures += fsi_case_fetch_stall();
    failures += fsi_case_fetch_cap();
    failures += fsi_state_cases();
    printf("flysync_island: %d failures\n", failures);
    return failures;
}
