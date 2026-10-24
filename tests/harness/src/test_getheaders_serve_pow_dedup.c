/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_getheaders_serve_pow_dedup: the getheaders SERVE path spends at most one
 * full Equihash verification per header, and a stranger cannot make it spend more.
 *
 * `getheaders` needs only a completed handshake, and a full
 * check_equihash_solution costs 383-390 us of a core at 200,9. The fix resolves
 * which bytes are authoritative with the cheap hash bind (nSolution is part of
 * the serialized header, so bound bytes are unique and a PoW verdict over them
 * is final), verifies once, and the successor walk hands the proved header back.
 *
 * The test counts verifications (getheaders_serve_pow_checks(), incremented at
 * the check_equihash_solution call site) using real regtest Equihash (48,5)
 * headers mined via mine_block_pow:
 *
 *   A. one lookup: an entry reachable from all three stores (index, flat block
 *      file, node.db row) with a forged solution costs <= 1 verification and is
 *      still refused (the security floor; see test_getheaders_serve_fallback case 7).
 *   B. one request: a served `getheaders` costs exactly one verification per header.
 *   C. headers_served_total and getheaders_served_requests both move on a served
 *      request and are neither always-zero nor always-equal (a 0-header reply
 *      advances requests only).
 *   D. the per-peer serve window bounds how often one peer may ask: an honest
 *      burst is fully served, a flood gets exactly the allowance and the rest
 *      is deferred (no reply, no disconnect, no offence), the window is
 *      per-peer, and expiry restores service. Time is injected through the
 *      window field itself.
 *
 * A watches the refusal path (a re-verify after a failed check takes A to 2), B
 * the success path (a re-verify of an accepted header takes B to 6 for 3
 * headers); each mutation is invisible to the other case.
 */

#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"

#include "chain/chainparams.h"
#include "chain/equihash.h"
#include "chain/pow.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "mining/miner.h"
#include "models/block.h"
#include "models/database.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/netbase.h"
#include "net/protocol.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "storage/node_db_runtime.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define PD_CHECK(name, expr) do { \
    printf("getheaders_serve_pow_dedup: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Mine a consensus-valid regtest header at `height` on `prev`. */
static bool pd_mine_header(struct block_header *out, int height,
                           const struct uint256 *prev,
                           const struct chain_params *cp, uint8_t salt)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.hashPrevBlock = *prev;
    uint256_set_null(&blk.header.hashMerkleRoot);
    blk.header.hashMerkleRoot.data[0] = (uint8_t)height;
    blk.header.hashMerkleRoot.data[1] = salt;
    uint256_set_null(&blk.header.hashFinalSaplingRoot);
    blk.header.nTime = 1600000000u + (uint32_t)height;
    struct arith_uint256 pow_limit;
    uint256_to_arith(&pow_limit, &cp->consensus.powLimit);
    blk.header.nBits = arith_uint256_get_compact(&pow_limit, false);
    bool ok = mine_block_pow(&blk, height, cp, 0);
    if (ok)
        *out = blk.header;
    block_free(&blk);
    return ok;
}

/* Store the full hash-bound header as a connected node.db `blocks` row, as a
 * snapshot-seeded node has below its body floor. */
static bool pd_db_put_header(struct node_db *ndb, int height,
                             const struct block_header *h,
                             const struct uint256 *hash)
{
    if (!ndb || !h || !hash)
        return false;
    struct db_block blk;
    memset(&blk, 0, sizeof(blk));
    memcpy(blk.hash, hash->data, 32);
    blk.height = height;
    memcpy(blk.prev_hash, h->hashPrevBlock.data, 32);
    blk.version = h->nVersion;
    memcpy(blk.merkle_root, h->hashMerkleRoot.data, 32);
    blk.time = h->nTime;
    blk.bits = h->nBits;
    memcpy(blk.nonce, h->nNonce.data, 32);
    blk.solution = (uint8_t *)h->nSolution;
    blk.solution_len = h->nSolutionSize;
    memset(blk.chain_work, 0x44, 32);
    blk.status = 3;
    blk.num_tx = 1;
    memcpy(blk.sapling_root, h->hashFinalSaplingRoot.data, 32);
    return db_block_save(ndb, &blk);
}

/* Append a one-transaction block carrying exactly `h` to a flat blk*.dat, giving
 * the flat-file fallback a hash-binding source. Returns the disk position via `pos`. */
static bool pd_write_flat_block(const char *datadir,
                                const struct block_header *h,
                                const struct chain_params *cp,
                                struct disk_block_pos *pos)
{
    struct block b;
    block_init(&b);
    b.header = *h;
    b.num_vtx = 1;
    b.vtx = zcl_calloc(1, sizeof(struct transaction), "pd_flat_vtx");
    if (!b.vtx) {
        block_free(&b);
        return false;
    }
    transaction_init(&b.vtx[0]);
    if (!transaction_alloc(&b.vtx[0], 1, 1)) {
        block_free(&b);
        return false;
    }
    b.vtx[0].vin[0].sequence = 0xffffffff;
    b.vtx[0].vout[0].value = 10 * COIN;

    disk_block_pos_init(pos);
    pos->nFile = -1;   /* append: writer allocates the position */
    bool ok = write_block_to_disk(&b, pos, datadir,
                                 cp->pchMessageStart);
    block_free(&b);
    return ok;
}

/* Hydrated-style index entry: header fields present, NO nSolution, and
 * header-only validity. */
static struct block_index *pd_seed_index(struct main_state *ms,
                                         const struct block_header *h,
                                         const struct uint256 *hash,
                                         int height,
                                         struct block_index *prev)
{
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nVersion = h->nVersion;
    tbi_ext(bi)->hashMerkleRoot = h->hashMerkleRoot;
    bi->hashFinalSaplingRoot = h->hashFinalSaplingRoot;
    bi->nTime = h->nTime;
    bi->nBits = h->nBits;
    tbi_ext(bi)->nNonce = h->nNonce;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->pprev = prev;
    return bi;
}

/* Pin `h`'s solution onto `bi` so the in-memory candidate hash-binds
 * without touching any store. */
static bool pd_pin_solution(struct block_index *bi,
                            const struct block_header *h,
                            const char *label)
{
    uint8_t *sol = zcl_malloc(h->nSolutionSize, label);
    if (!sol)
        return false;
    memcpy(sol, h->nSolution, h->nSolutionSize);
    tbi_ext(bi)->nSolution = sol;
    tbi_ext(bi)->nSolutionSize = h->nSolutionSize;
    return true;
}

/* Non-localhost peer with an INVALID socket: process_getheaders queues its reply
 * on node->send_head and socket_send_data(-1) fails EBADF without closing
 * anything, so the framed bytes stay inspectable. */
static void pd_setup_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.7:8033");
    node->id = 7;
    node->socket = ZCL_INVALID_SOCKET;
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 1;
    node->addr.svc.addr.ip[13] = 2;
    node->addr.svc.addr.ip[14] = 3;
    node->addr.svc.addr.ip[15] = 4;
}

/* Drop whatever process_getheaders queued, after reading it. */
static void pd_drain_send_queue(struct p2p_node *node)
{
    struct send_segment *seg = node->send_head;
    while (seg) {
        struct send_segment *next = seg->next;
        send_segment_free(seg);
        seg = next;
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->send_size = 0;
    node->send_offset = 0;
}

/* Every SERVED reply runs socket_send_data(), whose EBADF latches
 * p2p_node_close_socket's LOCAL_SHUTDOWN on the node. That is fake-socket
 * noise; clear it so defer checks observe only real punishment. */
static void pd_clear_fixture_disconnect(struct p2p_node *node)
{
    node->disconnect = false;
    node->disconnect_reason = P2P_DISCONNECT_NONE;
}

/* Header count of the framed `headers` reply in the send queue (skip the 24-byte
 * message header, read the leading compact_size); -1 if none or not `headers`. */
static int64_t pd_queued_headers_count(struct p2p_node *node)
{
    struct send_segment *seg = node->send_head;
    if (!seg || seg->size < MSG_HEADER_SIZE + 1)
        return -1;
    if (memcmp(seg->data + MESSAGE_START_SIZE, "headers", 7) != 0)
        return -1;

    struct byte_stream s;
    stream_init_from_data(&s, seg->data + MSG_HEADER_SIZE,
                          seg->size - MSG_HEADER_SIZE);
    uint64_t n = 0;
    bool ok = stream_read_compact_size(&s, &n);
    stream_free(&s);
    return ok ? (int64_t)n : -1;
}

/* Serialize a getheaders payload into the caller-owned writable stream `buf`:
 * locator (version + hashes) then hash_stop. The caller wraps buf->data in a
 * read view for process_getheaders and stream_free()s `buf`. */
/* D2c helper: drives a fresh ZCL23 peer through allowance+5 identical requests
 * in one window and reports whether its window closed at its own allowance
 * (GETHEADERS_SERVE_MAX_REQUESTS_PER_WINDOW) while the legacy flooder's window
 * still holds the legacy allowance. A gate reading allowance(0) for everyone
 * would pass D0-D3 but hand every ZCL23 peer 375 pages. Kept out of the test
 * body so the pinned test function does not grow. */
static bool pd_zcl23_window_closes_at_own_allowance(
    struct msg_processor *mp, struct byte_stream *req, node_id_t fast_id,
    const struct p2p_node *flooder, int legacy_allowance)
{
    struct p2p_node fast;
    pd_setup_node(&fast);
    fast.id = fast_id;
    fast.services = NODE_ZCL23;
    const int fast_allowance =
        (int)getheaders_serve_request_allowance(fast.services);
    const int extra = 5;
    int served = 0;
    int deferred = 0;
    for (int i = 0; i < fast_allowance + extra; i++) {
        req->read_pos = 0;   /* re-send the identical request */
        bool answered = process_getheaders(mp, &fast, req);
        bool queued = pd_queued_headers_count(&fast) >= 0;
        pd_drain_send_queue(&fast);
        pd_clear_fixture_disconnect(&fast);
        if (answered && queued)
            served++;
        else
            deferred++;
    }
    return fast_allowance == (int)GETHEADERS_SERVE_MAX_REQUESTS_PER_WINDOW &&
           fast_allowance < legacy_allowance && served == fast_allowance &&
           deferred == extra &&
           fast.getheaders_rate_window_count == (uint32_t)fast_allowance &&
           flooder->getheaders_rate_window_count ==
               (uint32_t)legacy_allowance;
}

/* D4 helpers: a deferred request is parked and answered once, from this node's
 * side, when the peer's serve window rolls (the stock legacy client has no
 * headers-sync timeout and chains its next getheaders only off a full reply).
 * Pinned: the defer parks the request; replay stays quiet while the window is
 * open; after the roll it is served exactly once, counted as a replay not a
 * defer; a second tick does nothing; the snapshot-serving defer never arms the
 * slot; a request served after the roll supersedes the parked one; and an
 * unparkable (empty) or malformed ask leaves the owed park in place. Time is
 * injected through the window fields as in D3. Split across seven helpers to
 * stay under the complexity cap. */

/* Fill this peer's window, then ask once more so the last request is deferred;
 * report whether that defer parked it. */
static bool pd_park_deferred_request(struct msg_processor *mp,
                                     struct byte_stream *req,
                                     struct p2p_node *node)
{
    const int allowance =
        (int)getheaders_serve_request_allowance(node->services);
    for (int i = 0; i < allowance + 1; i++) {
        /* Hold the window open by injection (as D3 rolls it). */
        node->getheaders_rate_window_start = platform_time_wall_time_t();
        req->read_pos = 0;   /* re-send the identical request */
        (void)process_getheaders(mp, node, req);
        pd_drain_send_queue(node);
        pd_clear_fixture_disconnect(node);
    }
    return node->getheaders_deferred_len > 0 &&
           node->getheaders_rate_window_count == (uint32_t)allowance;
}

/* While the window is open the send tick does nothing: no reply, no replay
 * count, and the request stays parked. */
static bool pd_replay_quiet_before_roll(struct msg_processor *mp,
                                        struct p2p_node *node)
{
    uint64_t replays_before = getheaders_replayed_deferred();
    bool early = getheaders_replay_deferred(mp, node);
    bool quiet = !early && pd_queued_headers_count(node) < 0 &&
                 getheaders_replayed_deferred() == replays_before &&
                 node->getheaders_deferred_len > 0;
    pd_drain_send_queue(node);
    pd_clear_fixture_disconnect(node);
    return quiet;
}

/* Roll the window through the fields, then tick with no new request: exactly
 * one reply goes out, counted as a replay not a second defer, the slot
 * disarms, and a further tick is inert. */
static bool pd_replay_once_after_roll(struct msg_processor *mp,
                                      struct p2p_node *node)
{
    uint64_t replays_before = getheaders_replayed_deferred();
    uint64_t defers_before = getheaders_deferred_rate_window();
    node->getheaders_rate_window_start =
        platform_time_wall_time_t() - GETHEADERS_SERVE_WINDOW_SECS - 1;
    node->getheaders_deferred_replay_after = platform_time_wall_time_t() - 1;

    bool replayed = getheaders_replay_deferred(mp, node);
    int64_t wire = pd_queued_headers_count(node);
    pd_drain_send_queue(node);
    pd_clear_fixture_disconnect(node);
    bool served_once = replayed && wire == 1 &&
                       getheaders_replayed_deferred() == replays_before + 1 &&
                       getheaders_deferred_rate_window() == defers_before &&
                       node->getheaders_deferred_len == 0;

    bool again = getheaders_replay_deferred(mp, node);
    bool once_only = !again && pd_queued_headers_count(node) < 0 &&
                     getheaders_replayed_deferred() == replays_before + 1;
    pd_drain_send_queue(node);
    pd_clear_fixture_disconnect(node);
    return served_once && once_only;
}

/* D4b: the peer-snapshot-serving defer must not arm the slot. */
static bool pd_snapshot_defer_parks_nothing(struct msg_processor *mp,
                                            struct byte_stream *req,
                                            node_id_t node_id)
{
    struct p2p_node snap;
    pd_setup_node(&snap);
    snap.id = node_id;
    snap.swarm_manifest_sent = true;
    req->read_pos = 0;
    bool handled = process_getheaders(mp, &snap, req);
    bool unarmed = handled && snap.getheaders_deferred_len == 0 &&
                   pd_queued_headers_count(&snap) < 0 &&
                   !getheaders_replay_deferred(mp, &snap);
    pd_drain_send_queue(&snap);
    return unarmed;
}

/* D4c: a request served after the window rolls supersedes the parked one, so
 * the older locator does not replay behind it. */
static bool pd_served_ask_supersedes_parked(struct msg_processor *mp,
                                            struct byte_stream *req,
                                            node_id_t node_id)
{
    struct p2p_node node;
    pd_setup_node(&node);
    node.id = node_id;
    node.services = 0;
    if (!pd_park_deferred_request(mp, req, &node))
        return false;
    uint64_t replays_before = getheaders_replayed_deferred();
    node.getheaders_rate_window_start =
        platform_time_wall_time_t() - GETHEADERS_SERVE_WINDOW_SECS - 1;
    node.getheaders_deferred_replay_after = platform_time_wall_time_t() - 1;
    req->read_pos = 0;
    (void)process_getheaders(mp, &node, req);
    bool served = pd_queued_headers_count(&node) == 1 &&
                  node.getheaders_rate_window_count == 1 &&
                  node.getheaders_deferred_len == 0;
    pd_drain_send_queue(&node);
    pd_clear_fixture_disconnect(&node);
    bool inert = !getheaders_replay_deferred(mp, &node) &&
                 pd_queued_headers_count(&node) < 0 &&
                 getheaders_replayed_deferred() == replays_before;
    pd_drain_send_queue(&node);
    return served && inert;
}

/* D4d: an empty ask inside the closed window is deferred but cannot be parked;
 * it leaves the existing park alone and counts as a defer, not an evict. */
static bool pd_unparkable_ask_keeps_park(struct msg_processor *mp,
                                         struct byte_stream *req,
                                         node_id_t node_id)
{
    struct p2p_node node;
    pd_setup_node(&node);
    node.id = node_id;
    node.services = 0;
    if (!pd_park_deferred_request(mp, req, &node))
        return false;
    uint16_t parked_len = node.getheaders_deferred_len;
    uint64_t defers_before = getheaders_deferred_rate_window();
    struct byte_stream empty;
    stream_init(&empty, 8);
    empty.read_pos = 0;
    bool handled = process_getheaders(mp, &node, &empty);
    stream_free(&empty);
    bool kept = handled && node.getheaders_deferred_len == parked_len &&
                getheaders_deferred_rate_window() == defers_before + 1 &&
                pd_queued_headers_count(&node) < 0;
    pd_drain_send_queue(&node);
    return kept;
}

/* D4e: a malformed ask after the roll is admitted but never answered; the park
 * must survive it (disarm on serve, not on admission) and the next tick replays once. */
static bool pd_malformed_ask_after_roll_keeps_park(struct msg_processor *mp,
                                                   struct byte_stream *req,
                                                   node_id_t node_id)
{
    struct p2p_node node;
    pd_setup_node(&node);
    node.id = node_id;
    node.services = 0;
    if (!pd_park_deferred_request(mp, req, &node))
        return false;
    uint64_t replays_before = getheaders_replayed_deferred();
    node.getheaders_rate_window_start =
        platform_time_wall_time_t() - GETHEADERS_SERVE_WINDOW_SECS - 1;
    node.getheaders_deferred_replay_after = platform_time_wall_time_t() - 1;
    static const uint8_t version_only[4] = {1, 0, 0, 0};
    struct byte_stream bad;   /* nVersion only: no locator, no hash_stop */
    stream_init(&bad, 8);
    (void)stream_write_bytes(&bad, version_only, sizeof version_only);
    bad.read_pos = 0;
    bool handled = process_getheaders(mp, &node, &bad);
    stream_free(&bad);
    bool kept = !handled && node.getheaders_deferred_len > 0 &&
                pd_queued_headers_count(&node) < 0;
    pd_drain_send_queue(&node);
    pd_clear_fixture_disconnect(&node);
    bool replayed = getheaders_replay_deferred(mp, &node) &&
                    pd_queued_headers_count(&node) == 1 &&
                    getheaders_replayed_deferred() == replays_before + 1 &&
                    node.getheaders_deferred_len == 0;
    pd_drain_send_queue(&node);
    return kept && replayed;
}

/* The one pin the test body carries: the stages above in order on a fresh
 * legacy peer (services=0), then the snapshot defer, the served-ask
 * supersession, and the two unanswerable asks on their own fresh peers. */
static bool pd_deferred_request_replays_once(struct msg_processor *mp,
                                             struct byte_stream *req,
                                             node_id_t node_id)
{
    struct p2p_node node;
    pd_setup_node(&node);
    node.id = node_id;
    node.services = 0;
    bool parked = pd_park_deferred_request(mp, req, &node);
    bool quiet = pd_replay_quiet_before_roll(mp, &node);
    bool once = pd_replay_once_after_roll(mp, &node);
    return parked && quiet && once &&
           pd_snapshot_defer_parks_nothing(mp, req, node_id + 1) &&
           pd_served_ask_supersedes_parked(mp, req, node_id + 2) &&
           pd_unparkable_ask_keeps_park(mp, req, node_id + 3) &&
           pd_malformed_ask_after_roll_keeps_park(mp, req, node_id + 4);
}

static bool pd_build_getheaders(struct byte_stream *buf,
                                const struct uint256 *locator_hashes,
                                size_t num_hashes,
                                const struct uint256 *hash_stop)
{
    struct block_locator loc;
    block_locator_init(&loc);
    loc.num_hashes = num_hashes;
    loc.vhave = (struct uint256 *)locator_hashes;   /* borrowed, not freed */
    stream_init(buf, 256);
    return block_locator_serialize(&loc, buf) &&
           stream_write_bytes(buf, hash_stop->data, 32);
}

static struct net_manager g_pd_nm;

int test_getheaders_serve_pow_dedup(void);
int test_getheaders_serve_pow_dedup(void)
{
    int failures = 0;
    printf("\n=== getheaders serve-path Equihash dedup tests ===\n");

    /* Regtest: small Equihash (48,5) mines in milliseconds. Restore CHAIN_MAIN on exit. */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "gh_pow_dedup", "ok");

    /* Pin the datadir and write the flat-file fixture where the serve path
     * opens it: msg_processor_init ignores its `datadir` argument and uses the
     * net-specific GetDataDir(true) (see msgprocessor.c), so without SetDataDir
     * the fallback reads the host's default datadir. Assert the resolved path
     * is inside the tmpdir. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    PD_CHECK("fixture datadir resolves inside the test tmpdir",
             netdir[0] && strncmp(netdir, dir, strlen(dir)) == 0);
    {
        char blocks[576];
        snprintf(blocks, sizeof(blocks), "%s/blocks", netdir);
        mkdir(blocks, 0755);
    }

    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    memset(&ndb, 0, sizeof(ndb));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));
    PD_CHECK("node.db fixture opens", node_db_open(&ndb, ":memory:"));
    db_service_init(&dbsvc);
    PD_CHECK("db_service attaches", db_service_attach(&dbsvc, &ndb));
    PD_CHECK("db_service starts", db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);

    /* ── A. one lookup, three stores, one verification ────────────────
     * Entry Y hash-binds, is BLOCK_VALID_TREE and passes CheckProofOfWork, but
     * its Equihash solution is garbage (the shape a hostile block_index.bin /
     * node.db bundle can carry), and it is reachable from the index, a flat
     * block file and a node.db row. */
    {
        struct main_state ms;
        main_state_init(&ms);

        struct block_header hg, ha, hb;
        struct uint256 hash_g, hash_a, hash_b, null_hash;
        uint256_set_null(&null_hash);
        PD_CHECK("A: mine g", pd_mine_header(&hg, 0, &null_hash, cp, 0xA0));
        block_header_get_hash(&hg, &hash_g);
        PD_CHECK("A: mine A", pd_mine_header(&ha, 1, &hash_g, cp, 0xA1));
        block_header_get_hash(&ha, &hash_a);
        PD_CHECK("A: mine B", pd_mine_header(&hb, 2, &hash_a, cp, 0xA2));
        block_header_get_hash(&hb, &hash_b);

        struct block_index *bi_g = pd_seed_index(&ms, &hg, &hash_g, 0, NULL);
        struct block_index *bi_a = pd_seed_index(&ms, &ha, &hash_a, 1, bi_g);
        PD_CHECK("A: index chain seeded", bi_g && bi_a);

        /* Forge B: same solution size, grind until CheckProofOfWork passes
         * (regtest powLimit is 0x0f0f..., a few tries). */
        struct block_header hy = hb;
        struct uint256 hash_y;
        bool y_ready = false;
        for (int attempt = 0; attempt < 4096 && !y_ready; attempt++) {
            for (size_t i = 0; i < hy.nSolutionSize; i++)
                hy.nSolution[i] = (uint8_t)(hb.nSolution[i] ^ 0xa5 ^
                                            (uint8_t)attempt);
            block_header_get_hash(&hy, &hash_y);
            if (!CheckProofOfWork(hash_y, hy.nBits, &cp->consensus))
                continue;
            if (check_equihash_solution(&hy, cp))
                continue;      /* astronomically unlikely; skip it */
            y_ready = true;
        }
        PD_CHECK("A: forged header found (PoW passes, Equihash does not)",
                 y_ready);
        PD_CHECK("A: forged solution really fails Equihash",
                 y_ready && !check_equihash_solution(&hy, cp));

        struct block_index *bi_y = NULL;
        if (y_ready && bi_a) {
            bi_y = pd_seed_index(&ms, &hy, &hash_y, 2, bi_a);
            PD_CHECK("A: forged entry inserted", bi_y != NULL);
        }

        struct msg_processor mp;
        msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_pd_nm, NULL);

        if (bi_y) {
            ms.pindex_best_header = bi_y;

            /* Store 1 — in-memory index. */
            PD_CHECK("A: store 1/3 in-memory solution pinned",
                     pd_pin_solution(bi_y, &hy, "pd_forged_sol"));

            /* Store 2 — flat block file. */
            struct disk_block_pos pos;
            bool wrote = pd_write_flat_block(netdir, &hy, cp, &pos);
            PD_CHECK("A: store 2/3 flat block file written", wrote);
            if (wrote) {
                bi_y->nStatus |= BLOCK_HAVE_DATA;
                block_index_disk_pos_store(bi_y, pos.nFile, pos.nPos);
                struct block probe;
                block_init(&probe);
                bool readable = read_block_from_disk_index(&probe, bi_y, netdir);
                struct uint256 probe_hash;
                uint256_set_null(&probe_hash);
                if (readable)
                    block_header_get_hash(&probe.header, &probe_hash);
                PD_CHECK("A: store 2/3 really hash-binds (fallback would "
                         "fire)",
                         readable && uint256_eq(&probe_hash, &hash_y));
                block_free(&probe);
            }

            /* Store 3 — node.db `blocks` row. */
            bool row = pd_db_put_header(&ndb, 2, &hy, &hash_y);
            PD_CHECK("A: store 3/3 node.db row stored", row);
            if (row) {
                struct block_header probe;
                block_header_init(&probe);
                bool loaded = node_db_runtime_load_header_by_hash_height(
                    2, hash_y.data, &probe);
                struct uint256 probe_hash;
                uint256_set_null(&probe_hash);
                if (loaded)
                    block_header_get_hash(&probe, &probe_hash);
                PD_CHECK("A: store 3/3 really hash-binds (fallback would "
                         "fire)",
                         loaded && uint256_eq(&probe_hash, &hash_y));
            }

            unsigned int status_before = bi_y->nStatus;
            uint64_t pow_before = getheaders_serve_pow_checks();
            struct block_header out;
            block_header_init(&out);
            bool ok = getheaders_index_header_servable(&mp, bi_y, &out);
            uint64_t spent = getheaders_serve_pow_checks() - pow_before;

            printf("getheaders_serve_pow_dedup: A: three-store lookup spent "
                   "%llu Equihash verification(s) (pre-fix: 3)\n",
                   (unsigned long long)spent);
            PD_CHECK("A: a three-store lookup spends at most ONE Equihash "
                     "verification", spent <= 1);
            PD_CHECK("A: it spends at least one — verifying once must not "
                     "become verifying zero", spent >= 1);

            /* The security floor: still refused, not a validity verdict. */
            PD_CHECK("A: the forged header is still REFUSED", !ok);
            PD_CHECK("A: the refusal is still not a validity verdict",
                     bi_y->nStatus == status_before);
        }

        main_state_free(&ms);
    }

    /* ── B/C. one request, one verification per header served ─────────
     * A clean 3-header chain above an active tip, every header mined and pinned
     * in the index, so each entry is servable in-memory at one verification. */
    {
        struct main_state ms;
        main_state_init(&ms);

        struct block_header h[4];
        struct uint256 hash[4], null_hash;
        uint256_set_null(&null_hash);
        bool mined = true;
        for (int i = 0; i < 4; i++) {
            mined = mined && pd_mine_header(&h[i], i,
                                            i == 0 ? &null_hash : &hash[i - 1],
                                            cp, 0xB0);
            if (!mined)
                break;
            block_header_get_hash(&h[i], &hash[i]);
        }
        PD_CHECK("B: mined a 4-header chain", mined);

        struct block_index *bi[4] = {0};
        bool seeded = mined;
        for (int i = 0; i < 4 && seeded; i++) {
            bi[i] = pd_seed_index(&ms, &h[i], &hash[i], i,
                                  i == 0 ? NULL : bi[i - 1]);
            seeded = bi[i] && pd_pin_solution(bi[i], &h[i], "pd_chain_sol");
        }
        PD_CHECK("B: index chain seeded with real solutions", seeded);

        struct msg_processor mp;
        msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_pd_nm, NULL);

        if (seeded) {
            /* A same-hash twin of entry 0 is the validated active tip while the
             * block map retains bi[0] (the restart shape where locator lookup and
             * chain[] own different block_index objects). Entries 1..3 are the
             * header-only zone the serve path must walk. */
            bi[0]->nStatus |= BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
            bi[0]->nTx = 1;
            bi[0]->nChainTx = 1;
            struct block_index active_twin;
            block_index_init(&active_twin);
            active_twin.phashBlock = bi[0]->phashBlock;
            active_twin.nHeight = bi[0]->nHeight;
            active_twin.nStatus = bi[0]->nStatus;
            active_twin.nTx = bi[0]->nTx;
            active_twin.nChainTx = bi[0]->nChainTx;
            active_twin.nChainWork = bi[0]->nChainWork;
            PD_CHECK("B: active tip parked at same-hash entry-0 twin",
                     active_chain_move_window_tip(&ms.chain_active,
                                                  &active_twin));
            ms.pindex_best_header = bi[3];

            struct p2p_node node;
            pd_setup_node(&node);

            /* B1 — locator anchored at the active tip: serve 1, 2, 3. */
            struct byte_stream buf, req;
            bool built = pd_build_getheaders(&buf, &hash[0], 1, &null_hash);
            PD_CHECK("B1: getheaders payload built", built);
            stream_init_from_data(&req, buf.data, buf.size);

            struct msg_headers_stats st_before, st_after;
            msg_headers_get_stats(&st_before);
            uint64_t pow_before = getheaders_serve_pow_checks();
            bool served = built && process_getheaders(&mp, &node, &req);
            uint64_t pow_spent = getheaders_serve_pow_checks() - pow_before;
            msg_headers_get_stats(&st_after);
            int64_t wire_count = pd_queued_headers_count(&node);
            uint64_t served_delta =
                st_after.headers_served_total - st_before.headers_served_total;
            uint64_t req_delta = st_after.getheaders_served_requests -
                st_before.getheaders_served_requests;

            printf("getheaders_serve_pow_dedup: B1: served %lld header(s) on "
                   "the wire for %llu Equihash verification(s) (pre-fix: 5 "
                   "for 3)\n", (long long)wire_count,
                   (unsigned long long)pow_spent);

            PD_CHECK("B1: the request was answered", served);
            PD_CHECK("B1: the reply carried the 3 header-only entries",
                     wire_count == 3);
            PD_CHECK("B1: exactly one Equihash verification per header "
                     "SERVED", wire_count > 0 &&
                     pow_spent == (uint64_t)wire_count);
            PD_CHECK("B1: headers_served_total counted the served headers",
                     served_delta == (uint64_t)wire_count);
            PD_CHECK("B1: getheaders_served_requests counted the request",
                     req_delta == 1);
            PD_CHECK("C: the two counters are not the same number "
                     "(3 headers, 1 request)", served_delta != req_delta);
            stream_free(&req);
            stream_free(&buf);
            pd_drain_send_queue(&node);

            /* B2/C: hash_stop-only form anchored at the best header (successor NULL)
             * serves nothing: requests move, headers do not, proving neither
             * counter copies the other or sticks at zero. */
            msg_headers_get_stats(&st_before);
            pow_before = getheaders_serve_pow_checks();
            struct byte_stream buf2, req2;
            bool built2 = pd_build_getheaders(&buf2, NULL, 0, &hash[3]);
            PD_CHECK("B2: empty-locator getheaders payload built", built2);
            stream_init_from_data(&req2, buf2.data, buf2.size);
            bool served2 = built2 && process_getheaders(&mp, &node, &req2);
            pow_spent = getheaders_serve_pow_checks() - pow_before;
            msg_headers_get_stats(&st_after);
            int64_t wire2 = pd_queued_headers_count(&node);

            PD_CHECK("B2: the request was answered", served2);
            PD_CHECK("B2: with a 0-header reply", wire2 == 0);
            PD_CHECK("B2: and cost no Equihash work at all", pow_spent == 0);
            PD_CHECK("C: a 0-header reply still counts as a request",
                     st_after.getheaders_served_requests -
                     st_before.getheaders_served_requests == 1);
            PD_CHECK("C: and adds nothing to headers_served_total",
                     st_after.headers_served_total ==
                     st_before.headers_served_total);
            PD_CHECK("C: both counters are non-zero overall — not stubs",
                     st_after.headers_served_total > 0 &&
                     st_after.getheaders_served_requests > 0);
            stream_free(&req2);
            stream_free(&buf2);
            pd_drain_send_queue(&node);

        /* ── D. the per-peer serve window ─────────────────────────────
         * Each reply costs real Equihash work, so the serve path bounds how
         * often one peer may ask (GETHEADERS_SERVE_* in net/msg_internal.h): a
         * fixed header budget per window (GETHEADERS_SERVE_HEADERS_PER_WINDOW)
         * translated into a request allowance by the peer's reply page size
         * (getheaders_serve_request_allowance() / getheaders_serve_page()).
         *
         *   D0 allowance helpers: legacy (services=0) gets 375, a ZCL23 peer
         *      30; allowance * page size is invariant across the two;
         *   D1 an honest burst is fully served;
         *   D2 the flood: served stops at the allowance, every excess request
         *      is deferred silently (true return, zero wire bytes, no
         *      disconnect, its own counter), and the window is per-peer;
         *   D3 expiry restores service.
         *
         * Time is injected through the window field (as in
         * test_net_handshake_adversarial.c): D3 backdates
         * node.getheaders_rate_window_start past the window. No sleeps. */
            PD_CHECK("D0: legacy services get a 375-request allowance",
                     getheaders_serve_request_allowance(0) == 375u);
            PD_CHECK("D0: a ZCL23 peer gets a 30-request allowance",
                     getheaders_serve_request_allowance(NODE_ZCL23) == 30u);
            PD_CHECK("D0: both allowances draw down the same header budget",
                     getheaders_serve_request_allowance(0) *
                             (uint32_t)getheaders_serve_page(0) ==
                     getheaders_serve_request_allowance(NODE_ZCL23) *
                             (uint32_t)getheaders_serve_page(NODE_ZCL23));
            struct p2p_node flooder;
            pd_setup_node(&flooder);
            node_id_t flood_id = flooder.id;
            /* pd_setup_node() memsets the fixture, so flooder.services is 0: a legacy
             * peer taking 160-header pages, allowance 375 vs 30 for ZCL23; see
             * getheaders_serve_request_allowance() in net/msg_internal.h. */
            const int allowance =
                (int)getheaders_serve_request_allowance(flooder.services);

            /* hash_stop-only form anchored at h[2]: each admitted request serves
             * exactly one header (h[3]), so the window is measured against the real
             * per-request cost. */
            struct byte_stream buf_d, req_d;
            bool built_d = pd_build_getheaders(&buf_d, NULL, 0, &hash[2]);
            PD_CHECK("D: getheaders payload built", built_d);
            stream_init_from_data(&req_d, buf_d.data, buf_d.size);

            uint64_t defer_before = getheaders_deferred_rate_window();
            msg_headers_get_stats(&st_before);
            /* Window baseline: everything served from here is admitted against one allowance. */
            uint64_t served_at_window_start =
                st_before.getheaders_served_requests;
            const int burst = 5;
            bool burst_served = true;
            int64_t burst_wire = 1;
            for (int i = 0; i < burst && burst_served; i++) {
                req_d.read_pos = 0;   /* re-send the identical request */
                burst_served = process_getheaders(&mp, &flooder, &req_d);
                burst_wire = pd_queued_headers_count(&flooder);
                pd_drain_send_queue(&flooder);
            }
            msg_headers_get_stats(&st_after);
            PD_CHECK("D1: an honest burst is answered every time",
                     burst_served);
            PD_CHECK("D1: every burst reply carried its header",
                     burst_wire == 1);
            PD_CHECK("D1: the burst moved only the served counters",
                     st_after.getheaders_served_requests -
                         st_before.getheaders_served_requests == burst &&
                     st_after.headers_served_total -
                         st_before.headers_served_total == burst);
            PD_CHECK("D1: the burst deferred nothing",
                     getheaders_deferred_rate_window() == defer_before);

            /* D2, the flood: another burst+10 requests in the same window get the
             * allowance; the rest are deferred. */
            msg_headers_get_stats(&st_before);
            uint64_t pow_before_d = getheaders_serve_pow_checks();
            /* Every admitted request is witnessed once: the receipt layer skips a
             * proof it already paid (a hit) or the serve pays one fresh pow check, so
             * the pow counter alone does not count admitted serves. A witness count
             * below the admitted count (a serve that skipped verification) or more
             * than one fresh proof (a receipt miss re-proving per request) is a failure. */
            struct getheaders_receipt_stats rs_before;
            getheaders_verify_receipt_stats(&rs_before);
            const int flood_extra = 10;
            const int flood_total = allowance - burst + flood_extra;
            int deferred_seen = 0;
            int served_seen = 0;
            bool defer_clean = true;
            for (int i = 0; i < flood_total; i++) {
                req_d.read_pos = 0;   /* re-send the identical request */
                bool answered = process_getheaders(&mp, &flooder, &req_d);
                bool queued = pd_queued_headers_count(&flooder) >= 0;
                pd_drain_send_queue(&flooder);
                bool punished = flooder.disconnect;
                pd_clear_fixture_disconnect(&flooder);
                if (answered && queued) {
                    served_seen++;
                } else {
                    /* DEFER shape: handled, nothing on the wire, no new disconnect. */
                    deferred_seen++;
                    defer_clean = defer_clean && answered && !queued &&
                                  !punished;
                }
            }
            msg_headers_get_stats(&st_after);
            PD_CHECK("D2: served stops EXACTLY at the window allowance",
                     st_after.getheaders_served_requests -
                         st_before.getheaders_served_requests ==
                     (uint64_t)(allowance - burst));
            PD_CHECK("D2: the window admitted the allowance and no more",
                     st_after.getheaders_served_requests -
                         served_at_window_start == (uint64_t)allowance);
            PD_CHECK("D2: every request past the allowance is deferred",
                     deferred_seen == flood_extra &&
                     served_seen == allowance - burst);
            PD_CHECK("D2: a deferred request is silent, handled, and "
                     "unpunished", defer_clean);
            PD_CHECK("D2: deferrals are counted as deferrals, not serves",
                     getheaders_deferred_rate_window() - defer_before ==
                     flood_extra);
            PD_CHECK("D2: the stats object surfaces the same defer count",
                     st_after.getheaders_deferred_rate_window -
                         st_before.getheaders_deferred_rate_window ==
                     (uint64_t)flood_extra);
            {
                struct getheaders_receipt_stats rs_after;
                getheaders_verify_receipt_stats(&rs_after);
                uint64_t fresh = getheaders_serve_pow_checks() - pow_before_d;
                PD_CHECK("D2: every admitted request was witnessed once — "
                         "a receipt hit or a fresh proof, never neither, "
                         "never both",
                         rs_after.hits - rs_before.hits + fresh ==
                         (uint64_t)(allowance - burst));
                PD_CHECK("D2: the flood's fresh-proof bill is at most ONE — "
                         "the receipt covers every repeat of a served "
                         "header",
                         fresh <= 1u);
            }

            /* D2b: the window is per-peer; a fresh peer is served while the flooder is exhausted. */
            {
                struct p2p_node other;
                pd_setup_node(&other);
                other.id = flood_id + 1;
                req_d.read_pos = 0;
                bool other_served = process_getheaders(&mp, &other, &req_d);
                bool other_queued = pd_queued_headers_count(&other) >= 0;
                pd_drain_send_queue(&other);
                pd_clear_fixture_disconnect(&other);
                /* The fresh peer's own window opened and drew one admission. */
                PD_CHECK("D2: the window is per-peer, not global",
                         other_served && other_queued &&
                         other.getheaders_rate_window_count == 1 &&
                         flooder.getheaders_rate_window_count ==
                             (uint32_t)allowance);
            }

            /* D2c: the allowance follows the requesting peer's services: a ZCL23
             * peer closes at 30 while the legacy flooder holds 375. */
            PD_CHECK("D2c: a ZCL23 peer's window closes at ITS allowance "
                     "(30 pages), the legacy flooder's at 375",
                     pd_zcl23_window_closes_at_own_allowance(
                         &mp, &req_d, flood_id + 2, &flooder, allowance));

            /* D3: backdate the window start to the boundary with the count
             * exhausted; the next request rolls the window, resets the count, and
             * is served. */
            msg_headers_get_stats(&st_before);
            uint64_t defer_stable = getheaders_deferred_rate_window();
            flooder.getheaders_rate_window_start =
                platform_time_wall_time_t() -
                GETHEADERS_SERVE_WINDOW_SECS - 1;
            flooder.getheaders_rate_window_count = (uint32_t)allowance;
            req_d.read_pos = 0;
            bool resumed = process_getheaders(&mp, &flooder, &req_d);
            int64_t resumed_wire = pd_queued_headers_count(&flooder);
            pd_drain_send_queue(&flooder);
            msg_headers_get_stats(&st_after);
            PD_CHECK("D3: an expired window serves the same peer again",
                     resumed && resumed_wire == 1);
            PD_CHECK("D3: the roll reset the exhausted window",
                     flooder.getheaders_rate_window_count == 1);
            PD_CHECK("D3: resumed service counts as a serve, not a defer",
                     st_after.getheaders_served_requests -
                         st_before.getheaders_served_requests == 1 &&
                     getheaders_deferred_rate_window() == defer_stable);

            /* D4: a deferred request is parked and answered once the window rolls,
             * since a legacy client has no retry timer. Contract in the helpers above. */
            PD_CHECK("D4: a deferred getheaders is replayed exactly once "
                     "when the window rolls, unasked, without spending a "
                     "second defer — the snapshot defer parks nothing, a "
                     "served ask supersedes the park, and unanswerable "
                     "asks leave it in place",
                     pd_deferred_request_replays_once(&mp, &req_d,
                                                      flood_id + 3));

            stream_free(&req_d);
            stream_free(&buf_d);
            pd_drain_send_queue(&flooder);
        }

        main_state_free(&ms);
    }

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    /* Unpin the datadir rather than pinning the host default: SetDataDir()
     * mkdir()s its argument. Clearing the cache restores resolve-on-next-use. */
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("getheaders serve-path Equihash dedup tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
