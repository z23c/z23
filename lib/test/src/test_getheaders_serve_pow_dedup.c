/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_getheaders_serve_pow_dedup — the getheaders SERVE path must spend at
 * most ONE full Equihash verification per header, and a stranger must not be
 * able to make it spend more.
 *
 * `getheaders` needs nothing but a completed handshake, and answering it is
 * the one thing an unauthenticated peer can make this node do real CPU work
 * for: one full check_equihash_solution costs 383-390 us of a core at 200,9.
 * Pre-fix a peer got a multiplier on that for free, from two independent
 * places:
 *
 *   a) getheaders_index_header_servable() ran the FULL PoW screen once per
 *      candidate SOURCE — in-memory index, then flat block file, then the
 *      node.db `blocks` row — before anything had established which bytes
 *      were even the right bytes. Three sources, three Equihash
 *      verifications, one served header. Driving the fallback path cost the
 *      peer nothing.
 *
 *   b) the serve loop then proved every entry twice: the successor walk
 *      verified a candidate and threw the header away, and the loop head
 *      verified the same entry again before appending it.
 *
 * The fix resolves WHICH bytes are authoritative using only the cheap hash
 * bind, then verifies once; and the walk hands the proved header back. The
 * bind is what licenses that: nSolution is part of the serialized header,
 * so bound bytes are unique, so a PoW verdict over bound bytes is final and
 * re-running it against another store cannot change it.
 *
 * This test COUNTS verifications (getheaders_serve_pow_checks(), a real
 * counter incremented at the check_equihash_solution call site) rather than
 * asserting the code still works. It fails on the parent commit with 3 and 5
 * where it now demands 1 and 3.
 *
 * Pins, all with REAL regtest Equihash (48,5) headers mined via
 * mine_block_pow:
 *
 *   A. worst case, one lookup: an entry reachable from ALL THREE stores
 *      whose solution is FORGED costs <= 1 Equihash verification (was 3) —
 *      and is still REFUSED. Verifying once must not become verifying zero:
 *      the refusal is the security floor
 *      (test_getheaders_serve_fallback case 7 on a one-store fixture).
 *   B. worst case, one request: a served `getheaders` costs exactly one
 *      verification per header on the wire (was 5 for 3 headers).
 *   C. the two serve-side counters are non-vacuous: headers_served_total and
 *      getheaders_served_requests both move on a real served request, and
 *      they are neither always-zero nor always-equal (a 0-header reply
 *      advances requests only).
 *   D. the per-peer serve window bounds how OFTEN one peer may ask: an
 *      honest burst is fully served, a flood gets exactly the allowance
 *      worth of replies and the rest DEFERRED (no reply, no disconnect, no
 *      offence), the window is per-peer, and expiry restores service.
 *      Time is injected through the window field itself (see the D note).
 *
 * A and B cover complementary halves, so keep both: A watches the REFUSAL
 * path (a re-verify added after a failed check — literally the old
 * retry-against-the-next-store shape — takes A to 2), B watches the SUCCESS
 * path (a re-verify of an accepted header takes B to 6 for 3 headers). Each
 * mutation is invisible to the other case.
 */

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

/* Store the full hash-bound header as a connected node.db `blocks` row —
 * the row a snapshot-seeded node has below its body floor. */
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

/* Append a one-transaction block carrying exactly `h` to a flat blk*.dat,
 * so the serve path's flat-file fallback has a real, hash-binding source.
 * Returns the disk position through `pos`. */
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
    bi->hashMerkleRoot = h->hashMerkleRoot;
    bi->hashFinalSaplingRoot = h->hashFinalSaplingRoot;
    bi->nTime = h->nTime;
    bi->nBits = h->nBits;
    bi->nNonce = h->nNonce;
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
    bi->nSolution = sol;
    bi->nSolutionSize = h->nSolutionSize;
    return true;
}

/* Non-localhost peer with an INVALID socket: process_getheaders queues its
 * reply on node->send_head and socket_send_data(-1) fails EBADF without
 * closing anything (p2p_node_close_socket guards on ZCL_INVALID_SOCKET), so
 * the framed bytes stay inspectable. */
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

/* The fixture's peers own ZCL_INVALID_SOCKET, so every SERVED reply runs
 * socket_send_data(), whose send() fails EBADF and latches
 * p2p_node_close_socket's LOCAL_SHUTDOWN disconnect on the node. That latch
 * is fake-socket noise, not the serve path's verdict — neither the serve nor
 * the defer path punishes. Clear it so the defer checks observe only
 * punishment the code under test actually performed. */
static void pd_clear_fixture_disconnect(struct p2p_node *node)
{
    node->disconnect = false;
    node->disconnect_reason = P2P_DISCONNECT_NONE;
}

/* Header count of the framed `headers` reply sitting in the send queue:
 * skip the 24-byte message header, read the leading compact_size. Returns
 * -1 when there is no reply or it is not a `headers` message. */
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

/* Serialize a getheaders payload into the caller-owned writable stream
 * `buf`: locator (version + hashes) then hash_stop. The caller wraps
 * buf->data in a read view for process_getheaders and stream_free()s `buf`
 * afterwards. */
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

    /* Regtest: small Equihash (48,5) mines in milliseconds. Restore
     * CHAIN_MAIN on the way out (sequential runner shares the process). */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "gh_pow_dedup", "ok");

    /* PIN the datadir, and write the flat-file fixture into the directory
     * the serve path will actually open.
     *
     * msg_processor_init IGNORES its `datadir` argument: it sets
     * mp->datadir = GetDataDir(true), the NET-SPECIFIC directory (see the
     * note in msgprocessor.c). Without SetDataDir the serve path's flat-file
     * fallback therefore reads the host's DEFAULT datadir — the live node's —
     * instead of this fixture, which both silently weakens the test and
     * reaches outside it. Assert the resolved path really is inside the
     * tmpdir so that can never regress unnoticed. */
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
     *
     * Entry Y hash-binds, is marked BLOCK_VALID_TREE, passes
     * CheckProofOfWork — and its Equihash solution is garbage. That is the
     * shape a hostile block_index.bin / node.db bundle can carry (one
     * PoW-passing grind, not a mine), and it is reachable from all three
     * stores: pinned in the index, written to a flat block file, and stored
     * as a node.db row. Pre-fix that cost three full Equihash
     * verifications, each reaching the identical verdict over byte-identical
     * bytes. */
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

        /* Forge B: same solution size (so the size check still passes),
         * grind until the serialized bytes still satisfy CheckProofOfWork.
         * Regtest powLimit is 0x0f0f..., so this lands in a few tries. */
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

            /* THE measurement. Pre-fix: 3. */
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

            /* The security floor: still refused, still not a validity
             * verdict. If the dedup ever made a forged solution servable,
             * that is a broken fix, not a passing test. */
            PD_CHECK("A: the forged header is still REFUSED", !ok);
            PD_CHECK("A: the refusal is still not a validity verdict",
                     bi_y->nStatus == status_before);
        }

        main_state_free(&ms);
    }

    /* ── B/C. one request, one verification per header served ─────────
     *
     * A clean 3-header chain above an active tip, every header genuinely
     * mined and pinned in the index, so every entry is servable off the
     * in-memory path at one verification each. Pre-fix the serve loop spent
     * 5 for 3 headers: the successor walk proved each entry and discarded
     * the header, then the loop head proved it again. */
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
            /* A same-hash twin of genesis-equivalent entry 0 is the validated
             * active tip, while the block map retains bi[0].  This is the
             * restart shape where locator lookup and chain[] own different
             * block_index objects for the same block.  Entries 1..3 are the
             * header-only zone the serve path must still walk. */
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

            /* B2/C — a request that legitimately serves nothing:
             * hash_stop-only form anchored at the best header, whose
             * successor is NULL. requests must still move; headers must
             * not. That asymmetry is the amplification signal (a peer
             * grinding empty replies), and it also proves neither counter
             * is a copy of the other or stuck at zero. */
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
         *
         * Each reply costs real Equihash work, so the serve path bounds how
         * OFTEN one peer may ask (GETHEADERS_SERVE_* in net/msg_internal.h).
         * An honest IBD peer re-asks at its scheduler-driven pace, orders of
         * magnitude under the allowance; a flood must get exactly the
         * allowance worth of replies and DEFER the rest — no reply, no
         * disconnect, no offence. Pins:
         *
         *   D1 an honest burst is fully served;
         *   D2 the flood: served stops exactly at the allowance, every
         *      excess request is deferred silently (true return, zero wire
         *      bytes, no disconnect, its own counter — not the served one),
         *      and the window is PER-PEER (a fresh peer is served while the
         *      flooder is deferred);
         *   D3 expiry restores service: the window rolls and the same peer
         *      is served again.
         *
         * Time is injected through the window field itself — the same seam
         * test_net_handshake_adversarial.c reads on the addr window: D3
         * backdates node.getheaders_rate_window_start past the window and
         * lets the roll condition do the rest. No sleeps: the production
         * read is now >= window_start + WINDOW_SECS, so a start far enough
         * in the past is deterministic no matter how slowly this runs. */
            struct p2p_node flooder;
            pd_setup_node(&flooder);
            node_id_t flood_id = flooder.id;
            const int allowance =
                (int)GETHEADERS_SERVE_MAX_REQUESTS_PER_WINDOW;

            /* hash_stop-only form anchored at h[2]: every admitted request
             * serves exactly ONE header (h[3], B2's shape with a successor),
             * so the window is measured against the real per-request cost,
             * and a mutation that served without gating (or gated without
             * serving) moves a checked number. */
            struct byte_stream buf_d, req_d;
            bool built_d = pd_build_getheaders(&buf_d, NULL, 0, &hash[2]);
            PD_CHECK("D: getheaders payload built", built_d);
            stream_init_from_data(&req_d, buf_d.data, buf_d.size);

            uint64_t defer_before = getheaders_deferred_rate_window();
            msg_headers_get_stats(&st_before);
            /* The window's own baseline: everything this peer is served from
             * here on is admitted against ONE allowance. */
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

            /* D2 — the flood. Another burst+10 requests arrive in the SAME
             * window; the allowance is what the peer gets, the rest are
             * deferred. */
            msg_headers_get_stats(&st_before);
            uint64_t pow_before_d = getheaders_serve_pow_checks();
            /* Every ADMITTED request is witnessed exactly once: either the
             * receipt layer skips a proof it already paid (a hit) or the
             * serve pays a fresh one (one pow check). The receipt layer on
             * main means a repeat of the same anchor normally hits — so the
             * pow counter alone no longer counts admitted serves (it would
             * read 0 here, since B1 already proved the header D serves).
             * What must NEVER happen: a witness count below the admitted
             * count (a serve that skipped verification) or a fresh-proof
             * bill above one (a receipt miss that re-proves per request). */
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
                    /* DEFER shape: handled, nothing on the wire, and no NEW
                     * disconnect — a defer queues nothing, so nothing but
                     * the defer path itself could latch it here. */
                    deferred_seen++;
                    defer_clean = defer_clean && answered && !queued &&
                                  !punished;
                }
            }
            msg_headers_get_stats(&st_after);
            PD_CHECK("D2: served stops EXACTLY at the window allowance",
                     st_after.getheaders_served_requests -
                         st_before.getheaders_served_requests ==
                     allowance - burst);
            PD_CHECK("D2: the window admitted the allowance and no more",
                     st_after.getheaders_served_requests -
                         served_at_window_start == allowance);
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

            /* D2b — the window is PER-PEER: a fresh peer is served while
             * the flooder sits exhausted. */
            {
                struct p2p_node other;
                pd_setup_node(&other);
                other.id = flood_id + 1;
                req_d.read_pos = 0;
                bool other_served = process_getheaders(&mp, &other, &req_d);
                bool other_queued = pd_queued_headers_count(&other) >= 0;
                pd_drain_send_queue(&other);
                pd_clear_fixture_disconnect(&other);
                /* The strong per-peer pin: the fresh peer's OWN window
                 * opened and drew one admission while the flooder's window
                 * sits exhausted at exactly the allowance. */
                PD_CHECK("D2: the window is per-peer, not global",
                         other_served && other_queued &&
                         other.getheaders_rate_window_count == 1 &&
                         flooder.getheaders_rate_window_count == allowance);
            }

            /* D3 — expiry restores service. Backdate the window start to the
             * exact window boundary and leave the count exhausted (time
             * injection through the window field itself, no sleeps); the
             * next request rolls the window and is served, and the roll
             * resets the count, so the same peer can draw another full
             * allowance. */
            msg_headers_get_stats(&st_before);
            uint64_t defer_stable = getheaders_deferred_rate_window();
            flooder.getheaders_rate_window_start =
                platform_time_wall_time_t() -
                GETHEADERS_SERVE_WINDOW_SECS - 1;
            flooder.getheaders_rate_window_count =
                GETHEADERS_SERVE_MAX_REQUESTS_PER_WINDOW;
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

            stream_free(&req_d);
            stream_free(&buf_d);
            pd_drain_send_queue(&flooder);
        }

        main_state_free(&ms);
    }

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    /* Unpin the datadir rather than pinning it back to the host default:
     * SetDataDir() mkdir()s what it is given, and the default is a real
     * node's directory. Clearing the cache restores "resolve on next use". */
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("getheaders serve-path Equihash dedup tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
