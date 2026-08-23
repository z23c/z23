/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_getheaders_serve_fallback — offline regression test for the
 * getheaders SERVE path on snapshot-seeded nodes (Wedge B).
 *
 * A snapshot-seeded node holds full headers in the node.db `blocks` table
 * (1344-byte Equihash nSolution included) but its hydrated in-memory block
 * index carries NO nSolution, and the flat block files below the body
 * floor are absent. Pre-fix, getheaders_index_header_servable built a
 * header with nSolutionSize=0 from such an entry, failed Equihash with
 * "invalid-solution", refused to serve, AND marked the entry
 * BLOCK_FAILED_VALID (an availability failure is not a validity verdict);
 * the successor walk then re-queried the same parent instead of advancing,
 * so the peer got a 0-header reply.
 *
 * Pins, with REAL regtest Equihash (48,5) headers mined via mine_block_pow
 * and a REAL node.db fixture behind the production node_db_runtime port
 * (db_service + app_runtime_set_current — the exact seam the live serve
 * path reads):
 *
 *   1. an index entry with no in-memory solution IS served when the
 *      node.db `blocks` row carries the full hash-bound header (fallback
 *      fires, served header hash-binds, and the index entry is healed so
 *      later serves take the in-memory hot path);
 *   2. an entry with no reachable store is refused WITHOUT gaining
 *      BLOCK_FAILED_VALID and WITHOUT a fabricated solution;
 *   3. the successor walk ADVANCES past an unservable entry and returns
 *      the next servable one instead of re-querying the same parent;
 *   4. a healed entry serves again off the in-memory hot path and still
 *      produces exactly the accepted header;
 *   5. the pinned-solution cache is accounted (it is budget-capped so an
 *      unauthenticated peer's header walk cannot grow it without bound);
 *   6. a header that solves Equihash but is filed under the WRONG hash is
 *      REFUSED — a served header must hash-bind to the entry it is served
 *      under, which "the solution is valid" alone never proves;
 *   7. a header that hash-binds AND is marked BLOCK_VALID_TREE but whose
 *      Equihash solution is FORGED is REFUSED — the status bit is not a
 *      witness that Equihash ever ran (four persisted-index loaders set
 *      it at sampled or zero PoW strength), so the serve path re-verifies
 *      unconditionally;
 *   8. the serve-path solution cache stays inside its declared budget.
 *
 * Cost of (7), MEASURED on this host (32-core x86-64-v3, three runs,
 * single-threaded, spread under 1.8%): check_equihash_solution() costs
 * 383-390 us per header on the 200,9 span and 36.7-36.9 us on the 192,7
 * span — 192,7 is ~10x CHEAPER, not dearer (128 indices vs 512, 24-byte
 * rows vs 30). Serving one peer the whole 3.19M-header chain therefore
 * costs ~320 s of one thread. That is real, and it is also exactly what
 * main has always paid: an unconditional re-verify here is the status
 * quo, and skipping it is what would be the change. If that cost is to
 * be recovered it must be gated on something that actually witnesses an
 * Equihash check (the validate_headers stage cursor), never on nStatus.
 */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "chain/equihash.h"
#include "chain/pow.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "jobs/stage_repair.h"
#include "mining/miner.h"
#include "models/block.h"
#include "models/database.h"
#include "net/header_serve_repair.h"
#include "net/net.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "primitives/block.h"
#include "storage/progress_store.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define GSF_CHECK(name, expr) do { \
    printf("getheaders_serve_fallback: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Mine a consensus-valid regtest header at `height` on `prev` (mirrors
 * ph_mine_header in test_process_headers_adversarial.c). */
static bool gsf_mine_header(struct block_header *out, int height,
                            const struct uint256 *prev,
                            const struct chain_params *cp)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.hashPrevBlock = *prev;
    uint256_set_null(&blk.header.hashMerkleRoot);
    blk.header.hashMerkleRoot.data[0] = (uint8_t)height;
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

/* Store the full hash-bound header (Equihash solution included) as a
 * connected node.db `blocks` row — the row a snapshot seed has. */
static bool gsf_db_put_header(struct node_db *ndb, int height,
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
    blk.solution = (uint8_t *)h->nSolution;   /* save copies; cast matches
                                               * vh_db_put_header */
    blk.solution_len = h->nSolutionSize;
    memset(blk.chain_work, 0x44, 32);
    blk.status = 3;                            /* connected floor */
    blk.num_tx = 1;
    memcpy(blk.sapling_root, h->hashFinalSaplingRoot.data, 32);
    return db_block_save(ndb, &blk);
}

/* Insert a hydrated-style index entry: every fixed header field populated
 * from the stored header, but NO nSolution (the snapshot-seed hydration
 * gap) and header-only validity (no HAVE_DATA, no FAILED bits). */
static struct block_index *gsf_seed_index(struct main_state *ms,
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

static struct net_manager g_gsf_nm;

static void gsf_setup_outbound_peer(struct p2p_node *node, int32_t height)
{
    memset(node, 0, sizeof(*node));
    node->socket = ZCL_INVALID_SOCKET;
    node->starting_height = height;
    snprintf(node->addr_name, sizeof(node->addr_name),
             "203.0.113.23:8033");
    atomic_store(&node->state, PEER_HANDSHAKE_COMPLETE);
    zcl_mutex_init(&node->cs_send);
}

static void gsf_drain_send_queue(struct p2p_node *node)
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

static void gsf_free_outbound_peer(struct p2p_node *node)
{
    gsf_drain_send_queue(node);
    zcl_mutex_destroy(&node->cs_send);
}

int test_getheaders_serve_fallback(void);
int test_getheaders_serve_fallback(void)
{
    int failures = 0;
    printf("\n=== getheaders serve-path fallback tests ===\n");

    /* Regtest: small Equihash (48,5) mines in milliseconds. Restore
     * CHAIN_MAIN on the way out (sequential runner shares the process). */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "gsf", "ok");

    GSF_CHECK("repair store opens", progress_store_open(dir));
    sqlite3 *progress_db = progress_store_db();
    GSF_CHECK("repair store handle published", progress_db != NULL);

    /* node.db fixture behind the production port seam. */
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    memset(&ndb, 0, sizeof(ndb));
    memset(&dbsvc, 0, sizeof(dbsvc));
    memset(&runtime, 0, sizeof(runtime));
    GSF_CHECK("node.db fixture opens", node_db_open(&ndb, ":memory:"));
    db_service_init(&dbsvc);
    GSF_CHECK("db_service attaches", db_service_attach(&dbsvc, &ndb));
    GSF_CHECK("db_service starts", db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);

    /* Mine a 4-header chain g(0) -> A(1) -> B(2) -> D(3). */
    struct block_header hg, ha, hb, hd;
    struct uint256 hash_g, hash_a, hash_b, hash_d;
    struct uint256 null_hash;
    uint256_set_null(&null_hash);
    GSF_CHECK("mine g", gsf_mine_header(&hg, 0, &null_hash, cp));
    block_header_get_hash(&hg, &hash_g);
    GSF_CHECK("mine A", gsf_mine_header(&ha, 1, &hash_g, cp));
    block_header_get_hash(&ha, &hash_a);
    GSF_CHECK("mine B", gsf_mine_header(&hb, 2, &hash_a, cp));
    block_header_get_hash(&hb, &hash_b);
    GSF_CHECK("mine D", gsf_mine_header(&hd, 3, &hash_b, cp));
    block_header_get_hash(&hd, &hash_d);

    struct main_state ms;
    main_state_init(&ms);
    struct block_index *bi_g = gsf_seed_index(&ms, &hg, &hash_g, 0, NULL);
    struct block_index *bi_a = gsf_seed_index(&ms, &ha, &hash_a, 1, bi_g);
    struct block_index *bi_b = gsf_seed_index(&ms, &hb, &hash_b, 2, bi_a);
    struct block_index *bi_d = gsf_seed_index(&ms, &hd, &hash_d, 3, bi_b);
    GSF_CHECK("index chain seeded", bi_g && bi_a && bi_b && bi_d);
    ms.pindex_best_header = bi_d;

    /* Only B gets a node.db row: A models the entry whose store is gone. */
    GSF_CHECK("node.db row for B stored",
              gsf_db_put_header(&ndb, 2, &hb, &hash_b));

    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_gsf_nm, NULL);

    /* 1. Fallback serve: no in-memory solution, node.db has the full
     *    hash-bound header -> servable, real solution, hash-bind, heal. */
    {
        struct block_header out;
        block_header_init(&out);
        bool ok = getheaders_index_header_servable(&mp, bi_b, &out);
        GSF_CHECK("fallback serves header from node.db row", ok);
        struct uint256 served_hash;
        block_header_get_hash(&out, &served_hash);
        GSF_CHECK("served header hash-binds to the index entry",
                  ok && uint256_eq(&served_hash, &hash_b));
        GSF_CHECK("served header carries the real Equihash solution",
                  ok && out.nSolutionSize == hb.nSolutionSize &&
                  out.nSolutionSize > 0 &&
                  memcmp(out.nSolution, hb.nSolution,
                         hb.nSolutionSize) == 0);
        GSF_CHECK("index entry healed with the stored solution",
                  ok && bi_b->nSolutionSize == hb.nSolutionSize);
        GSF_CHECK("served entry keeps its validity bits",
                  ok && bi_b->nStatus == BLOCK_VALID_TREE);
    }

    /* 2. Availability is not a validity verdict: A has no in-memory
     *    solution, no flat file, and no node.db row -> refuse, but do NOT
     *    mark BLOCK_FAILED_VALID and do NOT fabricate a solution. */
    {
        struct block_header out;
        block_header_init(&out);
        uint64_t nb_before = getheaders_serve_refusals_no_header_bytes();
        bool ok = getheaders_index_header_servable(&mp, bi_a, &out);
        GSF_CHECK("entry with no reachable store is refused", !ok);
        GSF_CHECK("refusal does NOT mark BLOCK_FAILED_VALID",
                  !ok && bi_a->nStatus == BLOCK_VALID_TREE);
        GSF_CHECK("refusal fabricates no in-memory solution",
                  !ok && bi_a->nSolutionSize == 0);
        /* 2b. ATTRIBUTION. This refusal is DATA AVAILABILITY — no store on
         *     this node holds the bytes — and it must be named and counted as
         *     that. Pre-fix headers_fill_header_from_index returned "filled"
         *     with an empty nSolution, so the bind screen relabelled it
         *     "header-hash-mismatch": a hash-comparison verdict over a header
         *     the node had never actually assembled. On a bundle/snapshot
         *     -seeded datadir that is the state of EVERY height below the seed
         *     floor, and the mislabel read as index corruption to two
         *     independent investigations of the live fleet. */
        GSF_CHECK("refusal is attributed to no-header-bytes, not a hash "
                  "mismatch",
                  !ok && getheaders_serve_refusals_no_header_bytes() ==
                             nb_before + 1);
        GSF_CHECK("missing local solution arms bounded header-only repair",
                  !ok && header_serve_repair_test_armed() &&
                  header_serve_repair_wants(bi_a));

        struct p2p_node peer;
        gsf_setup_outbound_peer(&peer, bi_d->nHeight);
        header_serve_repair_maybe_send(&mp, &peer, 1);
        GSF_CHECK("first peer publishes one exact bounded repair span",
                  peer.send_size > 0 &&
                  header_serve_repair_test_expected_count() == 3);
        GSF_CHECK("verified span member records partial progress",
                  getheaders_cache_repair_candidate(&mp, bi_b, &hb) &&
                  header_serve_repair_test_cached_count() == 1 &&
                  header_serve_repair_test_armed());
        struct p2p_node retry_peer;
        gsf_setup_outbound_peer(&retry_peer, bi_d->nHeight);
        header_serve_repair_maybe_send(&mp, &retry_peer, 7);
        GSF_CHECK("retry preserves the immutable span and partial progress",
                  retry_peer.send_size > 0 &&
                  header_serve_repair_test_expected_count() == 3 &&
                  header_serve_repair_test_cached_count() == 1);
        gsf_free_outbound_peer(&peer);
        gsf_free_outbound_peer(&retry_peer);
    }

    /* 3. The successor walk ADVANCES: from g, past unservable A, to
     *    servable B. Pre-fix the walk re-queried successor(g) — the same
     *    unservable A — until the guard gave up and returned NULL (a
     *    0-header reply to the peer). */
    {
        struct block_index *next =
            getheaders_next_servable_successor(&mp, bi_g, NULL);
        GSF_CHECK("walk advances past the unservable entry",
                  next == bi_b);
        GSF_CHECK("walk skipped entry is still not FAILED-marked",
                  next == bi_b && bi_a->nStatus == BLOCK_VALID_TREE);
    }
    header_serve_repair_test_reset();

    /* 4. Snapshot reducers already retain many complete, hash-bound headers
     *    in header_solution_repair even when both the old body and node.db
     *    row are absent. The runtime port must reuse that existing authority,
     *    and the serve path must still run its independent full-PoW gate. */
    GSF_CHECK("repair row for A stored",
              progress_db && stage_repair_header_solution_save(
                  progress_db, 1, &hash_a, &ha));
    {
        struct block_header out;
        block_header_init(&out);
        bool ok = getheaders_index_header_servable(&mp, bi_a, &out);
        struct uint256 served_hash;
        block_header_get_hash(&out, &served_hash);
        GSF_CHECK("fallback serves header from reducer repair row", ok);
        GSF_CHECK("repair-row header hash-binds to the index entry",
                  ok && uint256_eq(&served_hash, &hash_a));
        GSF_CHECK("repair-row header carries the real Equihash solution",
                  ok && out.nSolutionSize == ha.nSolutionSize &&
                  memcmp(out.nSolution, ha.nSolution,
                         ha.nSolutionSize) == 0);
        GSF_CHECK("repair-row fallback heals the in-memory entry",
                  ok && bi_a->nSolutionSize == ha.nSolutionSize);
    }

    /* 5. No local store retains D. A refusal arms one header-only peer fetch;
     *    its response remains inert until the serve path independently
     *    hash-binds and full-PoW verifies it. Successful verification heals D
     *    and completes the bounded flight without downloading a block body. */
    {
        struct block_header out;
        block_header_init(&out);
        bool missed = !getheaders_index_header_servable(&mp, bi_d, &out);
        GSF_CHECK("storeless D arms header-only peer repair",
                  missed && header_serve_repair_test_armed() &&
                  header_serve_repair_wants(bi_d));
        struct block_header forged_d = hd;
        forged_d.nSolution[0] ^= 0x01;
        bool forged_cached =
            getheaders_cache_repair_candidate(&mp, bi_d, &forged_d);
        GSF_CHECK("wrong-hash peer repair candidate remains inert",
                  !forged_cached && header_serve_repair_test_armed() &&
                  bi_d->nSolutionSize == 0);
        bool cached = getheaders_cache_repair_candidate(&mp, bi_d, &hd);
        GSF_CHECK("peer repair candidate passes independent full verification",
                  cached);
        GSF_CHECK("verified peer repair completes its bounded flight",
                  cached && !header_serve_repair_test_armed());
        block_header_init(&out);
        GSF_CHECK("verified peer repair heals subsequent serving",
                  cached && getheaders_index_header_servable(&mp, bi_d, &out));
    }

    /* 6. The healed entry serves again off the in-memory hot path, still
     *    hash-bound and still carrying the real solution — no re-read of
     *    the store needed, and the same accepted header comes back. */
    {
        struct block_header out;
        block_header_init(&out);
        bool ok = getheaders_index_header_servable(&mp, bi_b, &out);
        struct uint256 served_hash;
        block_header_get_hash(&out, &served_hash);
        GSF_CHECK("healed entry serves again from the in-memory path", ok);
        GSF_CHECK("second serve still hash-binds",
                  ok && uint256_eq(&served_hash, &hash_b));
        GSF_CHECK("second serve still carries the real solution",
                  ok && out.nSolutionSize == hb.nSolutionSize &&
                  memcmp(out.nSolution, hb.nSolution,
                         hb.nSolutionSize) == 0);
    }

    /* 7. Serve-path solution cache accounting is wired: healing A, B, and D pins
     *    their solutions, and it is bounded (never unbounded growth
     *    driven by an unauthenticated peer's header walk). */
    GSF_CHECK("healed solution is counted against the serve cache budget",
              getheaders_solution_cache_bytes() >=
              ha.nSolutionSize + hb.nSolutionSize + hd.nSolutionSize);

    /* 8. A header that is internally VALID but is filed under the WRONG
     *    hash must never be served. Entry X is keyed by a hash that is not
     *    B's, yet reassembles byte-for-byte into B's header — same prev
     *    (pprev = A), same fields, same real Equihash solution. So every
     *    self-contained check passes: solution size is right, Equihash
     *    verifies, PoW verifies, the timestamp is sane. The one thing
     *    wrong is that these bytes are not the block X claims to be.
     *
     *    A serve path that only asks "does this solve Equihash?" hands the
     *    peer B's header under X's announced hash, and the peer wires it
     *    into its chain under the wrong identity. Requiring the serialized
     *    header to hash to the entry's own phashBlock is what closes that,
     *    and it is the STRICTLY stronger check: "these bytes are the block
     *    we accepted" implies the solution is valid, never the reverse.
     *    X has no flat file and no node.db row, so no retry can rescue it
     *    — refusal is the only correct answer. */
    {
        struct uint256 hash_x = hash_b;
        hash_x.data[0] ^= 0x5a;   /* not B, not A, not g */

        struct block_index *bi_x =
            chainstate_insert_block_index((struct chainstate *)&ms, &hash_x);
        GSF_CHECK("wrong-hash fixture entry inserted", bi_x != NULL);
        if (bi_x) {
            bi_x->nHeight = 2;
            bi_x->nVersion = hb.nVersion;
            bi_x->hashMerkleRoot = hb.hashMerkleRoot;
            bi_x->hashFinalSaplingRoot = hb.hashFinalSaplingRoot;
            bi_x->nTime = hb.nTime;
            bi_x->nBits = hb.nBits;
            bi_x->nNonce = hb.nNonce;
            bi_x->nStatus = BLOCK_VALID_TREE;
            bi_x->pprev = bi_a;   /* reassembles to exactly hb */

            uint8_t *sol = zcl_malloc(hb.nSolutionSize, "gsf_wrong_hash_sol");
            GSF_CHECK("wrong-hash fixture solution allocated", sol != NULL);
            if (sol) {
                memcpy(sol, hb.nSolution, hb.nSolutionSize);
                bi_x->nSolution = sol;
                bi_x->nSolutionSize = hb.nSolutionSize;

                /* Sanity: the assembled header really is valid on its own
                 * terms, so a pass below cannot come from the fixture
                 * being accidentally malformed. */
                struct block_header rebuilt = hb;
                struct uint256 rebuilt_hash;
                block_header_get_hash(&rebuilt, &rebuilt_hash);
                GSF_CHECK("wrong-hash fixture rebuilds a genuinely valid "
                          "header", uint256_eq(&rebuilt_hash, &hash_b) &&
                          !uint256_eq(&hash_x, &hash_b));

                struct block_header out;
                block_header_init(&out);
                bool ok = getheaders_index_header_servable(&mp, bi_x, &out);
                GSF_CHECK("a valid header filed under the wrong hash is "
                          "refused", !ok);
                GSF_CHECK("that refusal is still not a validity verdict",
                          !ok && bi_x->nStatus == BLOCK_VALID_TREE);
                GSF_CHECK("off-authority refusal cannot pin peer repair",
                          !header_serve_repair_test_armed());
            }
        }
    }

    /* 9. F1 REGRESSION — a hash-bound header marked BLOCK_VALID_TREE whose
     *    Equihash solution is GARBAGE must still be refused.
     *
     *    This is the whole reason the serve path re-verifies Equihash
     *    unconditionally. BLOCK_VALID_TREE does not witness an Equihash
     *    check in this codebase: block_index_blocks_hydrate.c full-checks
     *    one row in 10,000 below the ROM checkpoint, block_index_loader.c
     *    calls block_row_verify with a NULL header (which skips both the
     *    hash bind and Equihash), boot_block_file_scan.c assigns the bit
     *    unconditionally, and boot_header_seed_import.c clamps a
     *    PEER-SUPPLIED artifact down to it. So a hostile bundle can carry
     *    rows that hash-bind, carry the bit, pass CheckProofOfWork on the
     *    claimed hash — and have never had Equihash run over them. Fixture
     *    Y is exactly such a row.
     *
     *    Entry Y has no flat file and no node.db row, so no store retry
     *    can rescue it: refusal is the only correct answer. A serve path
     *    that trusts the status bit serves Y and re-broadcasts unmined
     *    headers to the network. */
    {
        struct block_header hy = hb;
        struct uint256 hash_y;
        bool y_ready = false;
        /* Corrupt the solution (same size, so the size check still
         * passes), then search for a variant whose serialized bytes still
         * satisfy CheckProofOfWork — that is the cheap grind a hostile
         * bundle-builder does instead of mining. Regtest powLimit is
         * 0x0f0f..., so this lands within a handful of tries. */
        for (int attempt = 0; attempt < 4096 && !y_ready; attempt++) {
            for (size_t i = 0; i < hy.nSolutionSize; i++)
                hy.nSolution[i] = (uint8_t)(hb.nSolution[i] ^ 0xa5 ^
                                            (uint8_t)attempt);
            block_header_get_hash(&hy, &hash_y);
            if (!CheckProofOfWork(hash_y, hy.nBits, &cp->consensus))
                continue;
            if (check_equihash_solution(&hy, cp))
                continue;          /* astronomically unlikely; skip it */
            y_ready = true;
        }
        GSF_CHECK("F1 fixture: forged header found (PoW passes, Equihash "
                  "does not)", y_ready);

        if (y_ready) {
            GSF_CHECK("F1 fixture: forged solution really fails Equihash",
                      !check_equihash_solution(&hy, cp));
            GSF_CHECK("F1 fixture: forged header really passes "
                      "CheckProofOfWork",
                      CheckProofOfWork(hash_y, hy.nBits, &cp->consensus));
            GSF_CHECK("F1 fixture: forged header is not one we mined",
                      !uint256_eq(&hash_y, &hash_b));

            struct block_index *bi_y =
                chainstate_insert_block_index((struct chainstate *)&ms,
                                              &hash_y);
            GSF_CHECK("F1 fixture entry inserted", bi_y != NULL);
            if (bi_y) {
                bi_y->nHeight = 2;
                bi_y->nVersion = hy.nVersion;
                bi_y->hashMerkleRoot = hy.hashMerkleRoot;
                bi_y->hashFinalSaplingRoot = hy.hashFinalSaplingRoot;
                bi_y->nTime = hy.nTime;
                bi_y->nBits = hy.nBits;
                bi_y->nNonce = hy.nNonce;
                bi_y->nStatus = BLOCK_VALID_TREE;   /* the hydrate/loader
                                                     * strength, no more */
                bi_y->pprev = bi_a;

                uint8_t *ysol = zcl_malloc(hy.nSolutionSize,
                                           "gsf_forged_sol");
                GSF_CHECK("F1 fixture solution allocated", ysol != NULL);
                if (ysol) {
                    memcpy(ysol, hy.nSolution, hy.nSolutionSize);
                    bi_y->nSolution = ysol;
                    bi_y->nSolutionSize = hy.nSolutionSize;

                    /* Sanity: this entry DOES hash-bind, so the refusal
                     * below can only come from the Equihash check. */
                    struct block_header rebuilt;
                    block_header_init(&rebuilt);
                    rebuilt.nVersion = bi_y->nVersion;
                    rebuilt.hashPrevBlock = hash_a;
                    rebuilt.hashMerkleRoot = bi_y->hashMerkleRoot;
                    rebuilt.hashFinalSaplingRoot = bi_y->hashFinalSaplingRoot;
                    rebuilt.nTime = bi_y->nTime;
                    rebuilt.nBits = bi_y->nBits;
                    rebuilt.nNonce = bi_y->nNonce;
                    memcpy(rebuilt.nSolution, hy.nSolution, hy.nSolutionSize);
                    rebuilt.nSolutionSize = hy.nSolutionSize;
                    struct uint256 rebuilt_hash;
                    block_header_get_hash(&rebuilt, &rebuilt_hash);
                    GSF_CHECK("F1 fixture hash-binds to its index entry",
                              uint256_eq(&rebuilt_hash, &hash_y));

                    struct block_header out;
                    block_header_init(&out);
                    uint64_t nb_before =
                        getheaders_serve_refusals_no_header_bytes();
                    bool ok = getheaders_index_header_servable(&mp, bi_y,
                                                               &out);
                    GSF_CHECK("a BLOCK_VALID_TREE entry whose Equihash "
                              "solution is forged is REFUSED", !ok);
                    GSF_CHECK("that refusal is still not a validity verdict",
                              !ok && bi_y->nStatus == BLOCK_VALID_TREE);
                    /* The no-header-bytes counter ATTRIBUTES; it does not
                     * just tally refusals. This entry's bytes were right
                     * here in the index — it failed on PoW, not on
                     * availability — so it must NOT move that counter. */
                    GSF_CHECK("a PoW refusal is NOT counted as missing "
                              "header bytes",
                              !ok &&
                              getheaders_serve_refusals_no_header_bytes() ==
                                  nb_before);
                }
            }
        }
    }

    /* 10. F3 — the serve-path solution cache is BOUNDED, not merely
     *    counted. 64 MiB mirrors HEADERS_SOLUTION_CACHE_MAX_BYTES in
     *    lib/net/src/msg_headers.c; that constant is the whole worst case
     *    an unauthenticated post-handshake peer can drive this cache to,
     *    because every byte it accounts is reserved BEFORE the allocation
     *    and rolled back on refusal, and the count is never decremented
     *    (a freed-and-replaced buffer stays counted, which biases the
     *    number high — the safe direction for a ceiling). */
    GSF_CHECK("serve cache stays inside its 64 MiB budget",
              getheaders_solution_cache_bytes() <=
              (size_t)64 * 1024 * 1024);

    /* 11. A peer can be node2's source for the current block, so ordinary
     *     anti-echo relay intentionally sends it no header. Its first BIP 130
     *     sendheaders negotiation must therefore publish one independently
     *     verified current-tip header. Duplicates are inert: the proof is
     *     bounded to once per connection. */
    {
        struct p2p_node peer;
        gsf_setup_outbound_peer(&peer, bi_d->nHeight);
        GSF_CHECK("active tip fixture installed",
                  active_chain_move_window_tip(&ms.chain_active, bi_d));
        bool first = process_sendheaders(&mp, &peer);
        struct send_segment *seg = peer.send_head;
        bool framed = first && peer.prefer_headers && seg &&
                      seg->size > (size_t)MSG_HEADER_SIZE &&
                      memcmp(seg->data + MESSAGE_START_SIZE, "headers", 7) == 0;
        GSF_CHECK("first sendheaders publishes one current-tip header",
                  framed && seg->data[MSG_HEADER_SIZE] == 1);
        if (framed) {
            struct byte_stream wire;
            stream_init_from_data(&wire, seg->data + MSG_HEADER_SIZE,
                                  seg->size - MSG_HEADER_SIZE);
            uint64_t count = 0;
            uint64_t tx_count = 1;
            struct block_header announced;
            block_header_init(&announced);
            bool decoded = stream_read_compact_size(&wire, &count) &&
                           block_header_deserialize(&announced, &wire) &&
                           stream_read_compact_size(&wire, &tx_count);
            struct uint256 announced_hash;
            block_header_get_hash(&announced, &announced_hash);
            GSF_CHECK("negotiation header is exact verified tip",
                      decoded && count == 1 && tx_count == 0 &&
                      uint256_eq(&announced_hash, &hash_d));
        }
        gsf_drain_send_queue(&peer);
        GSF_CHECK("duplicate sendheaders emits no second tip proof",
                  process_sendheaders(&mp, &peer) && peer.send_head == NULL &&
                  peer.send_size == 0);
        gsf_free_outbound_peer(&peer);
    }

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    progress_store_close();
    header_serve_repair_test_reset();
    main_state_free(&ms);
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("getheaders serve-path fallback tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
