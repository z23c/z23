/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A snapshot offer from a mirror, end to end between two fixtures.
 *
 * Node A has a real node.db whose mirror cursor sits behind its chain tip, a
 * leaf store on disk and boundary roots in its progress store. Its offer comes
 * from boot_snapshot_offer_build_from_mirror, the function the offer worker
 * calls. Node B holds A's headers and nothing else. Between them run the real
 * message handlers over framed bytes: offer, challenge, proofs, request, data,
 * end, with no FlyClient bypass.
 *
 * The one thing production does not do yet is load the serialized file into a
 * RAM buffer, so the test does that step from the file the builder wrote, and
 * opens the serving gates with their test overrides. Both are named in
 * boot_snapshot_offer.c as what keeps a real node from offering.
 *
 * The end state of an honest transfer is containment: B staged bytes that hash
 * to the offer, installed nothing, and holds nothing against A. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/mmb.h"
#include "chain/mmr.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "config/boot_flyclient.h"
#include "config/boot_internal.h"
#include "config/boot_snapshot_offer.h"
#include "config/runtime.h"
#include "core/arith_uint256.h"
#include "models/database.h"
#include "models/mmb_leaf_store.h"
#include "net/fast_sync.h"
#include "net/flyclient.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/protocol.h"
#include "net/snapshot_sync_contract.h"
#include "services/snapshot_offer_anchor.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/utxo_mirror_schema.h"
#include "sync/sync_state.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool mp_snapshot_send_tick_serve(struct msg_processor *mp,
                                 struct p2p_node *node);

/* The tip is past the anchor: an offer built from tip-wide state would prove
 * over the wrong number of leaves. The anchor clears the 5000-block lead a
 * receiver with no chain requires. */
#define E2E_BLOCKS 5210
#define E2E_ANCHOR 5200
#define E2E_NBITS 0x1f07ffffu
#define E2E_WORK_ABOVE_FLOOR 0x100u
#define E2E_LONG_SCRIPT 600
#define E2E_ROWS 3

static struct {
    char dir[128];
    char db_path[256];
    struct block_index idx[E2E_BLOCKS];
    struct node_db ndb_a, ndb_b;
    struct main_state ms_a, ms_b;
    struct tx_mempool mempool_a, mempool_b;
    struct coins_view null_view_a, null_view_b;
    struct coins_view_cache coins_a, coins_b;
    struct net_manager nm_a, nm_b;
    struct msg_processor mp_a, mp_b;
    struct snapshot_sync_service svc_b;
    struct app_runtime_context runtime_b;
    struct p2p_node *a_side, *b_side;
    struct send_segment *sentinel_a, *sentinel_b;
    struct snapshot_offer offer;
    bool claim_long_chain;
    bool mirror_moved;
} g;

/* ── A's chain, rows and leaves ───────────────────────────────────────── */

static void e2e_fill_chain(void)
{
    for (uint32_t i = 0; i < E2E_BLOCKS; i++) {
        struct block_index *bi = &g.idx[i];

        memset(bi, 0, sizeof(*bi));
        memcpy(bi->hashBlock.data, &i, sizeof(i));
        bi->hashBlock.data[4] = 0xA5;
        bi->phashBlock = &bi->hashBlock;
        bi->nHeight = (int)i;
        bi->nTime = 1600000000u + i * 150u;
        bi->nBits = E2E_NBITS;
        memset(bi->hashFinalSaplingRoot.data, (int)(i + 1), 32);
        bi->nChainWork.pn[0] = i + 1;
        bi->nChainWork.pn[6] = E2E_WORK_ABOVE_FLOOR;
        bi->pprev = i > 0 ? &g.idx[i - 1] : NULL;
        block_index_build_skip(bi);
    }
}

static bool e2e_insert_block_rows(struct node_db *ndb, int through_height)
{
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(ndb->db,
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status) VALUES(?,?,zeroblob(32),4,"
        "zeroblob(32),1,1,zeroblob(32),zeroblob(1),?,3)",
        -1, &st, NULL) == SQLITE_OK;

    ok = ok && node_db_exec(ndb, "BEGIN");
    for (int h = 0; ok && h <= through_height; h++) {
        sqlite3_bind_blob(st, 1, g.idx[h].hashBlock.data, 32, SQLITE_STATIC);
        sqlite3_bind_int(st, 2, h);
        sqlite3_bind_blob(st, 3, g.idx[h].nChainWork.pn, 32, SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-setup
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    return ok && node_db_exec(ndb, "COMMIT");
}

static bool e2e_insert_utxo(struct node_db *ndb, uint8_t txid_byte, int height,
                            size_t script_len)
{
    uint8_t txid[32];
    uint8_t script[E2E_LONG_SCRIPT];
    sqlite3_stmt *st = NULL;
    bool ok;

    memset(txid, txid_byte, sizeof(txid));
    memset(script, 0x6a, sizeof(script));
    ok = sqlite3_prepare_v2(ndb->db,
        "INSERT INTO utxos(txid,vout,value,script,script_type,height,"
        "is_coinbase) VALUES(?,0,5000,?,0,?,0)",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, script, (int)script_len, SQLITE_STATIC);
        sqlite3_bind_int(st, 3, height);
        ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-fixture-setup
    }
    sqlite3_finalize(st);
    return ok;
}

static bool e2e_seed_mirror(void)
{
    /* The long script is one a chunk entry could not hold. */
    return e2e_insert_block_rows(&g.ndb_a, E2E_ANCHOR) &&
           node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                 E2E_ANCHOR + 1) &&
           e2e_insert_utxo(&g.ndb_a, 0x11, 10, 25) &&
           e2e_insert_utxo(&g.ndb_a, 0x22, E2E_ANCHOR, E2E_LONG_SCRIPT) &&
           e2e_insert_utxo(&g.ndb_a, 0x33, 5000, 1);
}

static bool e2e_seed_leaves(void)
{
    char path[300];
    sqlite3 *pdb;
    uint8_t root[32];

    if (!progress_store_open(g.dir))
        return false;
    pdb = progress_store_db();
    if (!pdb || !coins_kv_ensure_schema(pdb))
        return false;
    for (int h = MMR_COMMITMENT_INTERVAL; h < E2E_BLOCKS;
         h += MMR_COMMITMENT_INTERVAL) {
        memset(root, 0x80 | (h / MMR_COMMITMENT_INTERVAL), sizeof(root));
        if (!coins_kv_boundary_root_set(pdb, h, root))
            return false;
    }
    snprintf(path, sizeof(path), "%s/mmb_leaves.bin", g.dir);
    if (!mmb_leaf_store_open(&g_mmb_leaf_store, path))
        return false;
    bool seeded = mmb_leaf_store_rebuild(&g_mmb_leaf_store, &g.ms_a.chain_active) == E2E_BLOCKS;
    mmb_leaf_store_close(&g_mmb_leaf_store);
    struct boot_svc_ctx svc = {.state = &g.ms_a};
    return seeded && boot_prepare_mmb_leaf_store(&svc, g.dir, NULL) &&
           boot_mmb_leaf_store_available(&g.ms_a.chain_active);
}

/* ── The peer: A answers with what the leaf store proves ──────────────── */

static bool e2e_answer_challenge(struct fc_response *resp,
                                 const struct fc_challenge *challenge,
                                 const struct active_chain *chain, void *ctx)
{
    (void)ctx;
    if (!snapsync_build_fc_response(resp, challenge, chain,
                                    &g_mmb_leaf_store).ok)
        return false;
    if (g.claim_long_chain)
        resp->samples[0].proof.mmb_size += 1;
    return true;
}

static struct send_segment *e2e_sentinel(struct p2p_node *node)
{
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "test_offer_e2e_sentinel");

    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    return sentinel;
}

static bool e2e_pump(struct p2p_node *from, struct send_segment *sentinel,
                     struct msg_processor *to_mp, struct p2p_node *to)
{
    bool any = false;

    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        bool taken;

        sentinel->next = seg->next;
        if (from->send_tail == seg)
            from->send_tail = sentinel;
        from->send_size = from->send_size >= seg->size
                              ? from->send_size - seg->size : 0;
        taken = p2p_node_receive_bytes(to, (const char *)seg->data,
                                       (unsigned int)seg->size,
                                       to_mp->params->pchMessageStart);
        send_segment_free(seg);
        if (!taken)
            return false;
        any = true;
    }
    from->send_head = sentinel;
    from->send_offset = 0;
    return !any || msg_process_messages(to_mp, to);
}

static bool e2e_a_to_b(void)
{
    return e2e_pump(g.a_side, g.sentinel_a, &g.mp_b, g.b_side);
}

static bool e2e_b_to_a(void)
{
    return e2e_pump(g.b_side, g.sentinel_b, &g.mp_a, g.a_side);
}

static void e2e_init_side(struct main_state *ms, struct tx_mempool *mempool,
                          struct coins_view *view, struct coins_view_cache *tip,
                          struct net_manager *nm, struct msg_processor *mp)
{
    main_state_init(ms);
    tx_mempool_init(mempool, 0);
    coins_view_cache_init(tip, view);
    net_manager_init(nm);
    mp->main_state = ms;
    mp->mempool = mempool;
    mp->coins_tip = tip;
    mp->params = chain_params_get();
    mp->datadir = g.dir;
    mp->net_mgr = nm;
}

static struct p2p_node *e2e_peer(struct net_manager *nm, uint8_t last_octet,
                                 const char *name)
{
    struct net_address addr;
    struct p2p_node *node;

    memset(&addr, 0, sizeof(addr));
    memcpy(addr.svc.addr.ip, pchIPv4Prefix, 12);
    addr.svc.addr.ip[12] = 5;
    addr.svc.addr.ip[15] = last_octet;
    addr.svc.port = 18033;
    node = p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr, name, false);
    if (node) {
        node->version = 1;
        node->services = NODE_ZCL23;
        node->state = PEER_HANDSHAKE_COMPLETE;
    }
    return node;
}

/* Both nodes with their fixtures. Stops short of building an offer. */
static bool e2e_setup(void)
{
    char b_path[300];

    memset(&g, 0, sizeof(g));
    snprintf(g.dir, sizeof(g.dir), "./test-tmp/offer_e2e_%d_XXXXXX",
             (int)getpid());
    (void)mkdir("./test-tmp", 0755);
    if (!mkdtemp(g.dir))
        return false;
    snprintf(g.db_path, sizeof(g.db_path), "%s/node.db", g.dir);
    snprintf(b_path, sizeof(b_path), "%s/node_b.db", g.dir);
    if (!node_db_open(&g.ndb_a, g.db_path) || !node_db_open(&g.ndb_b, b_path))
        return false;

    e2e_fill_chain();
    e2e_init_side(&g.ms_a, &g.mempool_a, &g.null_view_a, &g.coins_a, &g.nm_a,
                  &g.mp_a);
    e2e_init_side(&g.ms_b, &g.mempool_b, &g.null_view_b, &g.coins_b, &g.nm_b,
                  &g.mp_b);
    active_chain_move_window_tip(&g.ms_a.chain_active, &g.idx[E2E_BLOCKS - 1]);
    g.ms_a.pindex_best_header = &g.idx[E2E_BLOCKS - 1];
    /* B has every header and no block. */
    g.ms_b.pindex_best_header = &g.idx[E2E_BLOCKS - 1];

    g.mp_a.flyclient_proof = e2e_answer_challenge;
    snapsync_init(&g.svc_b, &g.ndb_b);
    g.runtime_b.snapshot_sync = &g.svc_b;
    g.mp_b.runtime = &g.runtime_b;

    g.a_side = e2e_peer(&g.nm_a, 2, "peer-b");
    g.b_side = e2e_peer(&g.nm_b, 1, "peer-a");
    if (!g.a_side || !g.b_side)
        return false;
    g.sentinel_a = e2e_sentinel(g.a_side);
    g.sentinel_b = e2e_sentinel(g.b_side);


    boot_snapshot_offer_test_set_trust_override(1);
    boot_snapshot_offer_test_set_publication_override(1);
    fast_sync_reset_snapshot_cache();
    blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
    return e2e_seed_mirror() && e2e_seed_leaves();
}

static void e2e_free_queue(struct send_segment *sentinel)
{
    while (sentinel && sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        send_segment_free(seg);
    }
    send_segment_free(sentinel);
}

static void e2e_free_side(struct p2p_node *node, struct send_segment *sentinel,
                          struct main_state *ms, struct tx_mempool *mempool,
                          struct coins_view_cache *tip, struct net_manager *nm)
{
    e2e_free_queue(sentinel);
    if (node) {
        node->send_head = NULL;
        node->send_tail = NULL;
        p2p_node_free(node);
    }
    net_manager_free(nm);
    coins_view_cache_free(tip);
    tx_mempool_free(mempool);
    main_state_free(ms);
}

static void e2e_remove_datadir(void)
{
    static const char *const names[] = {
        "node.db", "node.db-wal", "node.db-shm", "node_b.db", "node_b.db-wal",
        "node_b.db-shm", "mmb_leaves.bin", "short_leaves.bin", "snapshot.bin",
    };
    char path[400];

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", g.dir, names[i]);
        (void)unlink(path);
    }
}

static void e2e_teardown(void)
{
    snapshot_offer_anchor_test_set_mid_read_hook(NULL, NULL);
    boot_snapshot_offer_test_set_publication_override(-1);
    boot_snapshot_offer_test_set_trust_override(-1);
    fast_sync_reset_snapshot_cache();
    blocker_clear(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID);
    mmb_leaf_store_close(&g_mmb_leaf_store);
    progress_store_close();
    snapsync_reset(&g.svc_b);
    e2e_free_side(g.a_side, g.sentinel_a, &g.ms_a, &g.mempool_a, &g.coins_a,
                  &g.nm_a);
    e2e_free_side(g.b_side, g.sentinel_b, &g.ms_b, &g.mempool_b, &g.coins_b,
                  &g.nm_b);
    node_db_close(&g.ndb_a);
    node_db_close(&g.ndb_b);
    /* The progress store's files are its own; a test directory is left only
     * when they outlive this list, under the ignored test-tmp. */
    e2e_remove_datadir();
}

/* ── Building and serving ─────────────────────────────────────────────── */

/* The one step production lacks: the file the builder wrote, held in RAM. */
static bool e2e_load_served_bytes(const struct snapshot_offer *offer)
{
    char path[300];
    FILE *fp;
    long size;
    uint8_t *buf;

    snprintf(path, sizeof(path), "%s/snapshot.bin", g.dir);
    fp = fopen(path, "rb");
    if (!fp)
        return false;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = size > 0 ? zcl_malloc((size_t)size, "test_offer_e2e_served") : NULL;
    if (!buf || fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        fclose(fp);
        free(buf);
        return false;
    }
    fclose(fp);
    return fast_sync_publish_snapshot_cache(buf, size, offer->utxo_root,
                                            offer->num_utxos);
}

static bool e2e_build_offer(void)
{
    bool serving_ready = false;

    return boot_snapshot_offer_build_from_mirror(&g.ndb_a, &g.ms_a, g.dir, &g.offer,
                                                 &serving_ready) &&
           e2e_load_served_bytes(&g.offer);
}

/* Offer, challenge, proofs: to the point B has asked for the snapshot. */
static bool e2e_offer_through_proof(void)
{
    msg_processor_update_offer(&g.offer);
    send_snapshot_offer_msg(g.a_side, &g.offer,
                            g.mp_a.params->pchMessageStart);
    return e2e_a_to_b() && g.svc_b.state == SNAPSYNC_NEGOTIATING &&
           e2e_b_to_a() && e2e_a_to_b();
}

/* Request, data, end. */
static bool e2e_request_through_end(void)
{
    if (!e2e_b_to_a() || g.a_side->state != PEER_SNAPSHOT_SERVING)
        return false;
    for (int tick = 0; tick < 16 && g.a_side->state == PEER_SNAPSHOT_SERVING;
         tick++) {
        (void)mp_snapshot_send_tick_serve(&g.mp_a, g.a_side);
    }
    return g.a_side->state != PEER_SNAPSHOT_SERVING && e2e_a_to_b();
}

static int64_t e2e_count(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t n = -1;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:read-only-introspection
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* What an install would have changed on B, as one comparable record. */
struct e2e_b_state {
    int64_t utxos;
    int64_t coins;
    int64_t evidence;
    int tip;
};

static void e2e_read_b_state(struct e2e_b_state *s)
{
    s->utxos = e2e_count(g.ndb_b.db, "SELECT COUNT(*) FROM utxos");
    s->coins = e2e_count(progress_store_db(), "SELECT COUNT(*) FROM coins");
    s->evidence = e2e_count(g.ndb_b.db, "SELECT COUNT(*) FROM node_state "
                                        "WHERE key LIKE 'cec.%'");
    s->tip = active_chain_height(&g.ms_b.chain_active);
}

/* ── Cases ────────────────────────────────────────────────────────────── */

static int e2e_case_honest_offer_is_staged_and_contained(void)
{
    int failures = 0;

    TEST("offer e2e: a mirror's offer passes the proof, is staged whole, and "
         "installs nothing") {
        struct e2e_b_state before, after;
        uint8_t staged_root[32];
        uint64_t staged_count = 0;
        struct snapshot_offer_anchor anchor;
        struct snapshot_offer tip_height_offer;

        ASSERT(e2e_setup());
        /* The sealed builder reads a node_state key no production code writes,
         * which is why the worker builds from the mirror instead. */
        ASSERT(!fast_sync_build_offer(g.dir, &tip_height_offer));
        ASSERT_RESULT_OK(snapshot_offer_anchor_read(g.db_path, &anchor));
        ASSERT(anchor.height == E2E_ANCHOR);
        ASSERT(e2e_build_offer());
        ASSERT(g.offer.height == E2E_ANCHOR);
        ASSERT(g.offer.peer_tip_height == E2E_ANCHOR);
        ASSERT(g.offer.num_utxos == E2E_ROWS);
        ASSERT(memcmp(g.offer.block_hash, g.idx[E2E_ANCHOR].hashBlock.data,
                      32) == 0);
        ASSERT(memcmp(g.offer.chain_work, g.idx[E2E_ANCHOR].nChainWork.pn,
                      32) == 0);
        ASSERT(memcmp(g.offer.utxo_root, anchor.utxo_root, 32) == 0);

        e2e_read_b_state(&before);
        ASSERT(e2e_offer_through_proof());
        ASSERT(g.svc_b.fc_verified);
        ASSERT(g.svc_b.state == SNAPSYNC_RECEIVING);
        ASSERT(e2e_request_through_end());

        utxo_commitment_sha3_compute_table(g.ndb_b.db, "snapshot_staging_utxos",
                                           staged_root, &staged_count);
        ASSERT(staged_count == E2E_ROWS);
        ASSERT(memcmp(staged_root, g.offer.utxo_root, 32) == 0);

        ASSERT(g.svc_b.state == SNAPSYNC_FAILED);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(g.b_side->misbehavior == 0);
        ASSERT(!g.b_side->disconnect);
        e2e_read_b_state(&after);
        ASSERT(after.utxos == before.utxos);
        ASSERT(after.coins == before.coins);
        ASSERT(after.evidence == before.evidence);
        ASSERT(after.tip == before.tip);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

/* A set that fills its last chunk exactly has nothing after it to serve. */
static int e2e_case_exact_chunk_multiple_reaches_the_end(void)
{
    int failures = 0;

    TEST("offer e2e: a set that exactly fills its chunks is served to the end") {
        ASSERT(e2e_setup());
        for (int i = E2E_ROWS; i < SYNC_CHUNK_SIZE; i++) {
            uint8_t txid[32] = {0x55, (uint8_t)i, (uint8_t)(i >> 8)};
            sqlite3_stmt *st = NULL;
            ASSERT(sqlite3_prepare_v2(g.ndb_a.db,
                "INSERT INTO utxos(txid,vout,value,script,script_type,height,"
                "is_coinbase) VALUES(?,0,5000,X'51',0,7,0)",
                -1, &st, NULL) == SQLITE_OK);
            sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
            ASSERT(sqlite3_step(st) == SQLITE_DONE);  // raw-sql-ok:test-fixture-setup
            sqlite3_finalize(st);
        }
        ASSERT(e2e_build_offer());
        ASSERT(g.offer.num_utxos == SYNC_CHUNK_SIZE);
        ASSERT(e2e_offer_through_proof());
        ASSERT(e2e_request_through_end());
        ASSERT(g.svc_b.state == SNAPSYNC_FAILED);
        ASSERT(blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(g.b_side->misbehavior == 0);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

static int e2e_case_wrong_root_is_an_offence(void)
{
    int failures = 0;

    TEST("offer e2e: bytes that do not hash to the offered root are staged out "
         "and scored") {
        struct e2e_b_state before, after;

        ASSERT(e2e_setup());
        ASSERT(e2e_build_offer());
        g.offer.utxo_root[0] ^= 0xFF;
        e2e_read_b_state(&before);
        ASSERT(e2e_offer_through_proof());
        ASSERT(g.svc_b.state == SNAPSYNC_RECEIVING);
        ASSERT(e2e_request_through_end());
        ASSERT(g.svc_b.state == SNAPSYNC_FAILED);
        ASSERT(!blocker_exists(SNAPSYNC_ACTIVATION_CONTAINED_BLOCKER_ID));
        ASSERT(g.b_side->misbehavior ==
               peer_offence_weight(PEER_OFFENCE_INVALID_PROOF));
        e2e_read_b_state(&after);
        ASSERT(after.utxos == before.utxos);
        ASSERT(after.tip == before.tip);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

static int e2e_case_no_block_row_refuses(void)
{
    int failures = 0;

    TEST("offer e2e: a mirror height with no validated block row offers "
         "nothing") {
        struct snapshot_offer_anchor anchor;
        bool serving_ready = true;

        ASSERT(e2e_setup());
        ASSERT(node_db_exec(&g.ndb_a, "UPDATE blocks SET status=1 WHERE "
                                      "height=5200"));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &anchor).ok);
        ASSERT(!boot_snapshot_offer_build_from_mirror(&g.ndb_a, &g.ms_a, g.dir, &g.offer,
                                                      &serving_ready));
        ASSERT(!serving_ready);
        ASSERT(node_db_exec(&g.ndb_a, "DELETE FROM blocks WHERE height=5200"));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &anchor).ok);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

/* The mirror applies a block while the anchor is being read. */
static void e2e_move_mirror(void *ctx)
{
    (void)ctx;
    g.mirror_moved =
        e2e_insert_utxo(&g.ndb_a, 0x44, E2E_ANCHOR + 1, 1) &&
        node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                              E2E_ANCHOR + 2);
    snapshot_offer_anchor_test_set_mid_read_hook(NULL, NULL);
}

static int e2e_case_mirror_moves_during_read(void)
{
    int failures = 0;

    TEST("offer e2e: a mirror that moves during the read cannot mix two "
         "heights") {
        struct snapshot_offer_anchor before, during, after;
        bool serving_ready = true;

        ASSERT(e2e_setup());
        ASSERT_RESULT_OK(snapshot_offer_anchor_read(g.db_path, &before));

        /* The read holds its moment: old height, old root, old count. */
        snapshot_offer_anchor_test_set_mid_read_hook(e2e_move_mirror, NULL);
        ASSERT_RESULT_OK(snapshot_offer_anchor_read(g.db_path, &during));
        ASSERT(g.mirror_moved);
        ASSERT(during.height == before.height);
        ASSERT(during.num_utxos == before.num_utxos);
        ASSERT(memcmp(during.utxo_root, before.utxo_root, 32) == 0);

        /* Now the next read names no validated block, and says so. */
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &after).ok);

        /* The served file is written after the anchor: moved rows differ from
         * the anchor's root, so the offer is withheld. */
        ASSERT(node_db_exec(&g.ndb_a, "DELETE FROM utxos WHERE height=5201"));
        ASSERT(node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                     E2E_ANCHOR + 1));
        snapshot_offer_anchor_test_set_mid_read_hook(e2e_move_mirror, NULL);
        g.mirror_moved = false;
        ASSERT(!boot_snapshot_offer_build_from_mirror(&g.ndb_a, &g.ms_a, g.dir, &g.offer,
                                                      &serving_ready));
        ASSERT(g.mirror_moved);
        ASSERT(!serving_ready);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

static bool e2e_shorten_leaf_store(void)
{
    char path[300];
    uint8_t leaf[32] = {1};

    mmb_leaf_store_close(&g_mmb_leaf_store);
    snprintf(path, sizeof(path), "%s/short_leaves.bin", g.dir);
    if (!mmb_leaf_store_open(&g_mmb_leaf_store, path))
        return false;
    for (int i = 0; i < 10; i++)
        if (!mmb_leaf_store_append(&g_mmb_leaf_store, leaf))
            return false;
    return mmb_leaf_store_remap(&g_mmb_leaf_store);
}

static int e2e_case_too_long_chain_claim(void)
{
    int failures = 0;

    TEST("offer e2e: a chain claim longer than the proof is refused on both "
         "sides") {
        struct snapshot_offer unused;
        bool serving_ready = false;
        struct e2e_b_state before, after;

        ASSERT(e2e_setup());
        ASSERT(e2e_build_offer());

        /* The receiver: a proof sized past the challenge is an offence, and no
         * request follows. */
        g.claim_long_chain = true;
        e2e_read_b_state(&before);
        ASSERT(e2e_offer_through_proof());
        ASSERT(g.svc_b.state == SNAPSYNC_NEGOTIATING);
        ASSERT(!g.svc_b.fc_verified);
        ASSERT(g.sentinel_b->next == NULL);
        ASSERT(g.b_side->misbehavior ==
               peer_offence_weight(PEER_OFFENCE_INVALID_PROOF));
        e2e_read_b_state(&after);
        ASSERT(after.utxos == before.utxos);
        ASSERT(after.tip == before.tip);

        /* The sender: leaves short of the anchor leave no root to offer. */
        g.claim_long_chain = false;
        ASSERT(e2e_shorten_leaf_store());
        memset(&unused, 0, sizeof(unused));
        ASSERT(boot_snapshot_offer_build_from_mirror(&g.ndb_a, &g.ms_a, g.dir, &unused,
                                                     &serving_ready));
        {
            static const uint8_t zero[32];
            ASSERT(memcmp(unused.mmb_root, zero, 32) == 0);
        }
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

/* The prover's own check, over leaves that carry a boundary root. */
static int e2e_case_proof_over_nonzero_root(void)
{
    int failures = 0;

    TEST("offer e2e: the prover answers for a boundary leaf with a non-zero "
         "root, and refuses when that root no longer matches its store") {
        struct fc_challenge challenge;
        static struct fc_response resp;
        static const uint8_t zero[32];
        uint8_t changed[32];
        uint64_t boundary = 0;
        bool found = false;
        struct mmb replay;

        ASSERT(e2e_setup());
        mmb_init(&replay);
        for (uint64_t i = 0; i < E2E_ANCHOR + 1u; i++)
            mmb_append_hash(&replay, mmb_leaf_store_get(&g_mmb_leaf_store, i));
        memset(&challenge, 0, sizeof(challenge));
        mmb_root(&replay, challenge.mmb_root);
        challenge.chain_length = E2E_ANCHOR + 1u;
        for (int seed = 1; seed < 256 && !found; seed++) {
            memset(challenge.seed, seed, sizeof(challenge.seed));
            ASSERT_RESULT_OK(snapsync_build_fc_response(
                &resp, &challenge, &g.ms_a.chain_active, &g_mmb_leaf_store));
            for (uint32_t i = 0; i < resp.num_samples && !found; i++) {
                const struct fc_sample *s = &resp.samples[i];
                if (s->leaf.height > 0 &&
                    s->leaf.height % MMR_COMMITMENT_INTERVAL == 0 &&
                    memcmp(s->leaf.utxo_root, zero, 32) != 0) {
                    boundary = s->leaf.height;
                    found = true;
                }
            }
        }
        ASSERT(found);

        memset(changed, 0x7E, sizeof(changed));
        ASSERT(coins_kv_boundary_root_set(progress_store_db(),
                                          (int32_t)boundary, changed));
        ASSERT(!snapsync_build_fc_response(&resp, &challenge,
                                           &g.ms_a.chain_active,
                                           &g_mmb_leaf_store).ok);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

static int e2e_case_cursor_shapes_refuse(void)
{
    int failures = 0;

    TEST("offer e2e: only a well-formed cursor with rows under it names an "
         "anchor") {
        struct snapshot_offer_anchor a;
        const int64_t bad_values[] = { -1, 0, (int64_t)INT32_MAX + 2 };
        uint8_t short_blob = 2;

        ASSERT(e2e_setup());
        for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
            ASSERT(node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                         bad_values[i]));
            ASSERT(!snapshot_offer_anchor_read(g.db_path, &a).ok);
        }
        ASSERT(node_db_state_set(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                 &short_blob, sizeof(short_blob)));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &a).ok);
        ASSERT(node_db_exec(&g.ndb_a, "DELETE FROM node_state WHERE key="
                                      "'" UTXO_MIRROR_SYNC_CURSOR_KEY "'"));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &a).ok);

        /* A row at the cursor is a block the cursor does not cover. */
        ASSERT(node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                     E2E_ANCHOR));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &a).ok);

        /* No rows at all is no snapshot. */
        ASSERT(node_db_exec(&g.ndb_a, "DELETE FROM utxos"));
        ASSERT(node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                     E2E_ANCHOR + 1));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &a).ok);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

/* Everything else about this mirror would serve: one height up it reads, so at
 * cursor 1 the only thing left to refuse is the cursor naming genesis. */
static int e2e_case_genesis_cursor_refuses(void)
{
    int failures = 0;

    TEST("offer e2e: a cursor that names genesis names no anchor") {
        struct snapshot_offer_anchor a;

        ASSERT(e2e_setup());
        ASSERT(node_db_exec(&g.ndb_a, "UPDATE utxos SET height=0"));
        ASSERT(node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY, 2));
        ASSERT_RESULT_OK(snapshot_offer_anchor_read(g.db_path, &a));
        ASSERT(a.height == 1);

        ASSERT(node_db_state_set_int(&g.ndb_a, UTXO_MIRROR_SYNC_CURSOR_KEY, 1));
        ASSERT(!snapshot_offer_anchor_read(g.db_path, &a).ok);
        PASS();
    } _test_next:;
    e2e_teardown();
    return failures;
}

int test_snapshot_offer_e2e(void)
{
    int failures = 0;

    failures += e2e_case_genesis_cursor_refuses();

    failures += e2e_case_honest_offer_is_staged_and_contained();
    failures += e2e_case_exact_chunk_multiple_reaches_the_end();
    failures += e2e_case_wrong_root_is_an_offence();
    failures += e2e_case_no_block_row_refuses();
    failures += e2e_case_mirror_moves_during_read();
    failures += e2e_case_too_long_chain_claim();
    failures += e2e_case_proof_over_nonzero_root();
    failures += e2e_case_cursor_shapes_refuse();
    return failures;
}
