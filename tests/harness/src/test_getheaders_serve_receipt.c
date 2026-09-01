/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_getheaders_serve_receipt — a peer must not be able to make this node
 * REDO an Equihash verification it has already done, and the proof standard
 * must not drop one bit to achieve that.
 *
 * `getheaders` needs nothing but a completed handshake, and answering one is
 * the only thing an unauthenticated peer can make this node spend real CPU
 * on: a full check_equihash_solution costs 383-390 us of a core at 200,9.
 * test_getheaders_serve_pow_dedup pinned the WITHIN-a-lookup half of that
 * bill — resolve which bytes are authoritative, then verify those bytes once.
 * It says nothing about repetition. Pre-fix, re-sending the identical
 * `getheaders` locator re-proved the identical page from scratch every single
 * time: a 61-byte request buying 2000 x 385 us = 0.78 s of a core, repeatable
 * forever, from a peer that has proved nothing about itself.
 *
 * The fix is a verification receipt: hash-bound (keyed on the header's own
 * hash, re-derived from the verified bytes inside the verifier rather than
 * taken from its caller) and generation-bound (carrying a tag over the build
 * source id, the genesis hash and powLimit, so a verdict minted under a
 * different build or different consensus parameters is a MISS). Minted at
 * exactly one place — the success tail of headers_verify_bound_header — so a
 * receipt can only ever mean "this process ran the full check and it passed".
 *
 * This test COUNTS verifications (getheaders_serve_pow_checks(), incremented
 * at the check_equihash_solution call site) and receipt activity
 * (getheaders_verify_receipt_stats()). It never infers from timing.
 *
 * Cases, all on REAL regtest Equihash (48,5) headers mined via mine_block_pow:
 *
 *   A. THE HEADLINE, both directions. The same `getheaders` served twice
 *      costs N verifications, not 2N. Direction 1 (the saving): the second
 *      request costs exactly 0 while still putting the same N headers on the
 *      wire. Direction 2 (the floor): the FIRST request costs exactly N — a
 *      cold table must not hit, so "verified once" can never have become
 *      "verified never". Pre-fix: N and N.
 *   B. A MISS PAYS IN FULL. With the table warm, a header it has never seen
 *      costs a full verification. Proof already done is skipped; proof never
 *      done is never skipped.
 *   C. GENERATION BINDING. The same header, byte-identical and equally
 *      verifiable, presented under a different generation tag is NOT
 *      honoured — it is re-verified. Built by handing the serve path a
 *      shallow params copy whose hashGenesisBlock differs and whose powLimit
 *      is untouched, so verifiability is provably unchanged and the ONLY
 *      variable is the generation. Restoring the real params then costs a
 *      verification too — the alt-generation mint displaced the original in
 *      its slot — which pins the fail-safe direction: a generation excursion
 *      can only ever cost extra proof, never grant an unearned pass.
 *   D. FAILURES ARE NOT CACHED, AND REFUSAL IS STILL REFUSAL. A forged
 *      header (Equihash garbage, but the serialized bytes still pass
 *      CheckProofOfWork — one grind, not a mine) is refused, and offering it
 *      twice costs TWO verifications, not one. This is the deliberate
 *      asymmetry: a PASS is monotone and safe to keep, a FAIL is not
 *      (time-too-new un-fails as the clock advances), so caching a refusal
 *      could poison the serve path against a valid chain for the process
 *      lifetime. It also pins the security floor — the receipt must never
 *      make a forged solution servable.
 *   E. THE CAP HOLDS UNDER A FLOOD. Many distinct real headers, each served
 *      once, must leave the table at a fixed size: occupied never exceeds
 *      slots and the byte footprint never moves. An attacker feeding
 *      unlimited distinct headers churns slots, never grows them.
 *
 * A/B/C/D/E cover distinct mutations. Deleting the receipt lookup breaks A;
 * making the lookup ignore the hash breaks B; dropping the generation from
 * the key breaks C; caching failures breaks D; making the table grow breaks
 * E. Keep all five.
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
#include "primitives/block.h"
#include "storage/disk_block_io.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define RC_CHECK(name, expr) do { \
    printf("getheaders_serve_receipt: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Mine a consensus-valid regtest header at `height` on `prev`. */
static bool rc_mine_header(struct block_header *out, int height,
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
    blk.header.hashMerkleRoot.data[2] = (uint8_t)(height >> 8);
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

/* Hydrated-style index entry: header fields present, header-only validity. */
static struct block_index *rc_seed_index(struct main_state *ms,
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

/* Pin `h`'s solution onto `bi` so the candidate hash-binds off the in-memory
 * path without consulting any store. */
static bool rc_pin_solution(struct block_index *bi,
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
 * closing anything, so the framed bytes stay inspectable. */
static void rc_setup_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.9:8033");
    node->id = 9;
    node->socket = ZCL_INVALID_SOCKET;
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 5;
    node->addr.svc.addr.ip[13] = 6;
    node->addr.svc.addr.ip[14] = 7;
    node->addr.svc.addr.ip[15] = 8;
}

static void rc_drain_send_queue(struct p2p_node *node)
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

/* Header count of the framed `headers` reply in the send queue. -1 when there
 * is no reply or it is not a `headers` message. */
static int64_t rc_queued_headers_count(struct p2p_node *node)
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

/* Serialize a getheaders payload (locator then hash_stop) into `buf`. */
static bool rc_build_getheaders(struct byte_stream *buf,
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

/* Serve one getheaders request built from `locator`, reporting the Equihash
 * verifications it cost and the header count it put on the wire. */
static bool rc_serve_once(struct msg_processor *mp, struct p2p_node *node,
                          const struct uint256 *locator,
                          const struct uint256 *hash_stop,
                          uint64_t *pow_spent, int64_t *wire_count)
{
    struct byte_stream buf, req;
    if (!rc_build_getheaders(&buf, locator, 1, hash_stop))
        return false;
    stream_init_from_data(&req, buf.data, buf.size);

    uint64_t before = getheaders_serve_pow_checks();
    bool served = process_getheaders(mp, node, &req);
    *pow_spent = getheaders_serve_pow_checks() - before;
    *wire_count = rc_queued_headers_count(node);

    stream_free(&req);
    stream_free(&buf);
    rc_drain_send_queue(node);
    return served;
}

static struct net_manager g_rc_nm;

int test_getheaders_serve_receipt(void);
int test_getheaders_serve_receipt(void)
{
    int failures = 0;
    printf("\n=== getheaders serve-path verification receipt tests ===\n");

    /* Regtest: small Equihash (48,5) mines in milliseconds. Restore
     * CHAIN_MAIN on the way out (the sequential runner shares the process). */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "gh_receipt", "ok");

    /* PIN the datadir. msg_processor_init IGNORES its `datadir` argument and
     * uses GetDataDir(true), so without SetDataDir the serve path's flat-file
     * fallback reads the HOST's default datadir — a live node's — which both
     * reaches outside the fixture and silently weakens it. Assert the
     * resolved path is really inside the tmpdir so that cannot regress. */
    SetDataDir(dir);
    char netdir[512];
    GetDataDir(true, netdir, sizeof(netdir));
    RC_CHECK("fixture datadir resolves inside the test tmpdir",
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
    RC_CHECK("node.db fixture opens", node_db_open(&ndb, ":memory:"));
    db_service_init(&dbsvc);
    RC_CHECK("db_service attaches", db_service_attach(&dbsvc, &ndb));
    RC_CHECK("db_service starts", db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);

    /* The table is process-global and other groups in this binary serve
     * headers too, so measure DELTAS throughout and never absolute totals. */
    struct getheaders_receipt_stats rs0;
    memset(&rs0, 0, sizeof(rs0));
    getheaders_verify_receipt_stats(&rs0);
    RC_CHECK("receipt table reports a non-zero structural cap",
             rs0.slots > 0 && rs0.bytes > 0);
    RC_CHECK("occupied never exceeds the cap", rs0.occupied <= rs0.slots);

    /* ── A. the same request served twice ─────────────────────────────
     *
     * A clean 3-header chain above an active tip, every header genuinely
     * mined and pinned. Serve the identical locator twice. */
    {
        struct main_state ms;
        main_state_init(&ms);

        struct block_header h[4];
        struct uint256 hash[4], null_hash;
        uint256_set_null(&null_hash);
        bool mined = true;
        for (int i = 0; i < 4; i++) {
            mined = mined && rc_mine_header(&h[i], i,
                                            i == 0 ? &null_hash : &hash[i - 1],
                                            cp, 0xC0);
            if (!mined)
                break;
            block_header_get_hash(&h[i], &hash[i]);
        }
        RC_CHECK("A: mined a 4-header chain", mined);

        struct block_index *bi[4] = {0};
        bool seeded = mined;
        for (int i = 0; i < 4 && seeded; i++) {
            bi[i] = rc_seed_index(&ms, &h[i], &hash[i], i,
                                  i == 0 ? NULL : bi[i - 1]);
            seeded = bi[i] && rc_pin_solution(bi[i], &h[i], "rc_chain_sol");
        }
        RC_CHECK("A: index chain seeded with real solutions", seeded);

        struct msg_processor mp;
        msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_rc_nm, NULL);

        if (seeded) {
            bi[0]->nStatus |= BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
            bi[0]->nTx = 1;
            bi[0]->nChainTx = 1;
            RC_CHECK("A: active tip parked at entry 0",
                     active_chain_move_window_tip(&ms.chain_active, bi[0]));
            ms.pindex_best_header = bi[3];

            struct p2p_node node;
            rc_setup_node(&node);

            /* Request 1 — cold table. */
            uint64_t pow1 = 0;
            int64_t wire1 = -1;
            bool served1 = rc_serve_once(&mp, &node, &hash[0], &null_hash,
                                         &pow1, &wire1);

            /* Request 2 — byte-identical request, warm table. */
            uint64_t pow2 = 0;
            int64_t wire2 = -1;
            bool served2 = rc_serve_once(&mp, &node, &hash[0], &null_hash,
                                         &pow2, &wire2);

            printf("getheaders_serve_receipt: A: request 1 = %lld header(s) "
                   "for %llu verification(s); request 2 (identical) = %lld "
                   "header(s) for %llu verification(s) "
                   "(pre-fix: 3 then 3)\n",
                   (long long)wire1, (unsigned long long)pow1,
                   (long long)wire2, (unsigned long long)pow2);

            RC_CHECK("A: both requests were answered", served1 && served2);
            RC_CHECK("A: request 1 carried the 3 header-only entries",
                     wire1 == 3);
            RC_CHECK("A: request 2 carried the SAME 3 headers — the saving "
                     "is not a shorter reply", wire2 == wire1);

            /* Direction 2, the floor: a cold table must NOT hit. If the
             * receipt ever became a status bit that skipped work never done,
             * this drops below 3. */
            RC_CHECK("A: request 1 paid one verification per header served "
                     "(a cold table must not hit)",
                     wire1 > 0 && pow1 == (uint64_t)wire1);

            /* Direction 1, the saving: THE headline. Fails on the parent
             * commit with 3. */
            RC_CHECK("A: request 2 repeated NO Equihash work at all",
                     pow2 == 0);
            RC_CHECK("A: so N identical headers served twice cost N "
                     "verifications, not 2N",
                     pow1 + pow2 == (uint64_t)wire1);

            struct getheaders_receipt_stats rsa;
            memset(&rsa, 0, sizeof(rsa));
            getheaders_verify_receipt_stats(&rsa);
            RC_CHECK("A: the skipped verifications are counted as receipt "
                     "hits", rsa.hits - rs0.hits >= (uint64_t)wire1);
            RC_CHECK("A: receipts were minted only for verifications that "
                     "succeeded", rsa.mints - rs0.mints == (uint64_t)wire1);

            /* ── B. a miss pays in full ───────────────────────────────
             *
             * Extend the chain with a header the table has never seen. The
             * table is warm; this header is not in it; it must cost a full
             * verification. */
            struct block_header hnew;
            struct uint256 hash_new;
            bool mined_new = rc_mine_header(&hnew, 4, &hash[3], cp, 0xC4);
            RC_CHECK("B: mined a header the table has never seen", mined_new);
            if (mined_new) {
                block_header_get_hash(&hnew, &hash_new);
                struct block_index *bi_new =
                    rc_seed_index(&ms, &hnew, &hash_new, 4, bi[3]);
                bool ready = bi_new &&
                    rc_pin_solution(bi_new, &hnew, "rc_new_sol");
                RC_CHECK("B: new entry seeded", ready);
                if (ready) {
                    ms.pindex_best_header = bi_new;
                    uint64_t before = getheaders_serve_pow_checks();
                    struct block_header out;
                    block_header_init(&out);
                    bool ok = getheaders_index_header_servable(&mp, bi_new,
                                                               &out);
                    uint64_t spent = getheaders_serve_pow_checks() - before;
                    printf("getheaders_serve_receipt: B: an unseen header "
                           "cost %llu verification(s) with the table warm\n",
                           (unsigned long long)spent);
                    RC_CHECK("B: it is servable", ok);
                    RC_CHECK("B: a MISS still pays a full verification",
                             spent == 1);

                    /* And immediately after, it is a hit — so B measured a
                     * genuine miss, not a broken table. */
                    before = getheaders_serve_pow_checks();
                    ok = getheaders_index_header_servable(&mp, bi_new, &out);
                    spent = getheaders_serve_pow_checks() - before;
                    RC_CHECK("B: the same header is then free", ok &&
                             spent == 0);
                }
            }

            /* ── C. generation binding ────────────────────────────────
             *
             * Same entry, byte-identical header, still hash-binding, still
             * genuinely mined — presented under a DIFFERENT generation. The
             * params copy differs only in hashGenesisBlock; powLimit is
             * untouched, and check_equihash_solution ignores its params
             * argument entirely, so verifiability is provably identical and
             * the generation tag is the only variable. */
            {
                struct chain_params alt = *cp;   /* POD; shallow copy is whole */
                alt.consensus.hashGenesisBlock.data[0] ^= 0x5a;
                RC_CHECK("C: the alternate generation keeps powLimit "
                         "byte-identical",
                         memcmp(alt.consensus.powLimit.data,
                                cp->consensus.powLimit.data, 32) == 0);
                RC_CHECK("C: and differs only in the genesis hash",
                         !uint256_eq(&alt.consensus.hashGenesisBlock,
                                     &cp->consensus.hashGenesisBlock));

                /* bi[1] carries a live receipt from request 1/2 above. */
                uint64_t before = getheaders_serve_pow_checks();
                struct block_header out;
                block_header_init(&out);
                bool warm_ok = getheaders_index_header_servable(&mp, bi[1],
                                                                &out);
                uint64_t warm = getheaders_serve_pow_checks() - before;
                RC_CHECK("C: under the real params the header is free "
                         "(a receipt exists)", warm_ok && warm == 0);

                const struct chain_params *saved = mp.params;
                mp.params = &alt;
                before = getheaders_serve_pow_checks();
                bool alt_ok = getheaders_index_header_servable(&mp, bi[1],
                                                               &out);
                uint64_t alt_spent = getheaders_serve_pow_checks() - before;
                printf("getheaders_serve_receipt: C: the same header under a "
                       "different source generation cost %llu "
                       "verification(s)\n", (unsigned long long)alt_spent);
                RC_CHECK("C: a receipt from another generation is NOT "
                         "honoured — the header is re-verified",
                         alt_spent == 1);
                RC_CHECK("C: and it still verifies, so the miss was the tag "
                         "and not a broken header", alt_ok);

                /* The alt-generation miss re-verified and then minted, into
                 * the same slot (same hash, direct-mapped), displacing the
                 * original receipt. So restoring the real params MISSES and
                 * verifies again — the fail-safe direction, and the one that
                 * matters: a generation excursion can only ever cost extra
                 * verification, never grant an unearned pass. Two generations
                 * alternating on one header thrash the slot, which is correct
                 * and free of consequence in production, where the tag moves
                 * only on a build change or a network switch. */
                mp.params = saved;
                before = getheaders_serve_pow_checks();
                bool back_ok = getheaders_index_header_servable(&mp, bi[1],
                                                               &out);
                uint64_t back = getheaders_serve_pow_checks() - before;
                printf("getheaders_serve_receipt: C: back under the real "
                       "generation cost %llu verification(s)\n",
                       (unsigned long long)back);
                RC_CHECK("C: the displaced receipt degrades to VERIFY AGAIN, "
                         "never to assume-pass", back_ok && back == 1);

                before = getheaders_serve_pow_checks();
                back_ok = getheaders_index_header_servable(&mp, bi[1], &out);
                back = getheaders_serve_pow_checks() - before;
                RC_CHECK("C: and the re-minted receipt is honoured again, so "
                         "the table still works after the excursion",
                         back_ok && back == 0);
            }
        }

        main_state_free(&ms);
    }

    /* ── D. failures are never cached ─────────────────────────────────
     *
     * A forged header: same solution size, Equihash garbage, but the
     * serialized bytes still satisfy CheckProofOfWork — one grind, not a
     * mine, which is what a hostile block_index.bin / node.db bundle can
     * carry. It must be REFUSED, and refusing it twice must cost two
     * verifications: a cached refusal would be the dangerous direction, and
     * time-too-new proves refusals are not even monotone. */
    {
        struct main_state ms;
        main_state_init(&ms);

        struct block_header hg, ha, hb;
        struct uint256 hash_g, hash_a, hash_b, null_hash;
        uint256_set_null(&null_hash);
        RC_CHECK("D: mine g", rc_mine_header(&hg, 0, &null_hash, cp, 0xD0));
        block_header_get_hash(&hg, &hash_g);
        RC_CHECK("D: mine A", rc_mine_header(&ha, 1, &hash_g, cp, 0xD1));
        block_header_get_hash(&ha, &hash_a);
        RC_CHECK("D: mine B", rc_mine_header(&hb, 2, &hash_a, cp, 0xD2));
        block_header_get_hash(&hb, &hash_b);

        struct block_index *bi_g = rc_seed_index(&ms, &hg, &hash_g, 0, NULL);
        struct block_index *bi_a = rc_seed_index(&ms, &ha, &hash_a, 1, bi_g);
        RC_CHECK("D: index chain seeded", bi_g && bi_a);

        struct block_header hy = hb;
        struct uint256 hash_y;
        bool y_ready = false;
        for (int attempt = 0; attempt < 4096 && !y_ready; attempt++) {
            for (size_t i = 0; i < hy.nSolutionSize; i++)
                hy.nSolution[i] = (uint8_t)(hb.nSolution[i] ^ 0x5c ^
                                            (uint8_t)attempt);
            block_header_get_hash(&hy, &hash_y);
            if (!CheckProofOfWork(hash_y, hy.nBits, &cp->consensus))
                continue;
            if (check_equihash_solution(&hy, cp))
                continue;      /* astronomically unlikely; skip it */
            y_ready = true;
        }
        RC_CHECK("D: forged header found (PoW passes, Equihash does not)",
                 y_ready);
        RC_CHECK("D: forged solution really fails Equihash",
                 y_ready && !check_equihash_solution(&hy, cp));

        struct msg_processor mp;
        msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_rc_nm, NULL);

        if (y_ready && bi_a) {
            struct block_index *bi_y =
                rc_seed_index(&ms, &hy, &hash_y, 2, bi_a);
            bool ready = bi_y && rc_pin_solution(bi_y, &hy, "rc_forged_sol");
            RC_CHECK("D: forged entry seeded", ready);
            if (ready) {
                ms.pindex_best_header = bi_y;
                unsigned int status_before = bi_y->nStatus;

                struct block_header out;
                block_header_init(&out);
                uint64_t before = getheaders_serve_pow_checks();
                bool ok1 = getheaders_index_header_servable(&mp, bi_y, &out);
                uint64_t spent1 = getheaders_serve_pow_checks() - before;

                before = getheaders_serve_pow_checks();
                bool ok2 = getheaders_index_header_servable(&mp, bi_y, &out);
                uint64_t spent2 = getheaders_serve_pow_checks() - before;

                printf("getheaders_serve_receipt: D: the forged header cost "
                       "%llu then %llu verification(s) and was refused "
                       "both times\n", (unsigned long long)spent1,
                       (unsigned long long)spent2);

                RC_CHECK("D: the forged header is REFUSED", !ok1);
                RC_CHECK("D: and refused again on the second offer", !ok2);
                RC_CHECK("D: the first refusal cost a full verification",
                         spent1 == 1);
                RC_CHECK("D: the second ALSO cost a full verification — "
                         "refusals are never cached", spent2 == 1);
                RC_CHECK("D: no receipt can exist for a header that failed",
                         spent1 + spent2 == 2);
                RC_CHECK("D: the refusal is still not a validity verdict",
                         bi_y->nStatus == status_before);
            }
        }

        main_state_free(&ms);
    }

    /* ── E. the cap holds under a flood ───────────────────────────────
     *
     * Serve many DISTINCT real headers once each. The table must not grow:
     * occupied stays within the cap and the byte footprint never moves. A
     * peer offering unlimited distinct headers churns slots at a constant
     * cost, which is the whole point of a fixed static table. */
    {
        struct main_state ms;
        main_state_init(&ms);

        struct msg_processor mp;
        msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_rc_nm, NULL);

        struct getheaders_receipt_stats before_flood;
        memset(&before_flood, 0, sizeof(before_flood));
        getheaders_verify_receipt_stats(&before_flood);

        /* 48,5 regtest headers mine in milliseconds, but a flood still has
         * to stay inside a unit test's budget. 96 distinct headers is enough
         * to churn slots and prove the invariant; the cap is structural, so
         * it does not need saturation to be established. */
        const int flood = 96;
        struct uint256 prev;
        uint256_set_null(&prev);
        struct block_index *chain_prev = NULL;
        int served = 0;
        bool cap_held = true;
        size_t bytes_seen = before_flood.bytes;

        for (int i = 0; i < flood; i++) {
            struct block_header fh;
            if (!rc_mine_header(&fh, i, &prev, cp, 0xE0))
                break;
            struct uint256 fhash;
            block_header_get_hash(&fh, &fhash);
            struct block_index *bi =
                rc_seed_index(&ms, &fh, &fhash, i, chain_prev);
            if (!bi || !rc_pin_solution(bi, &fh, "rc_flood_sol"))
                break;

            struct block_header out;
            block_header_init(&out);
            if (getheaders_index_header_servable(&mp, bi, &out))
                served++;

            struct getheaders_receipt_stats now;
            memset(&now, 0, sizeof(now));
            getheaders_verify_receipt_stats(&now);
            if (now.occupied > now.slots || now.slots != before_flood.slots ||
                now.bytes != bytes_seen)
                cap_held = false;

            prev = fhash;
            chain_prev = bi;
        }

        struct getheaders_receipt_stats after_flood;
        memset(&after_flood, 0, sizeof(after_flood));
        getheaders_verify_receipt_stats(&after_flood);

        printf("getheaders_serve_receipt: E: %d distinct headers served; "
               "table %zu/%zu slots occupied, %zu bytes, %llu eviction(s)\n",
               served, after_flood.occupied, after_flood.slots,
               after_flood.bytes,
               (unsigned long long)(after_flood.evictions -
                                    before_flood.evictions));

        RC_CHECK("E: the flood really served distinct headers",
                 served == flood);
        RC_CHECK("E: occupied never exceeded the cap at any point during "
                 "the flood", cap_held);
        RC_CHECK("E: occupied is still within the cap afterwards",
                 after_flood.occupied <= after_flood.slots);
        RC_CHECK("E: the byte footprint did not move — the table cannot "
                 "grow", after_flood.bytes == before_flood.bytes);
        RC_CHECK("E: the slot count is a constant",
                 after_flood.slots == before_flood.slots);
        RC_CHECK("E: every served header was verified exactly once — a "
                 "flood of distinct headers gets no discount",
                 after_flood.mints - before_flood.mints == (uint64_t)served);

        main_state_free(&ms);
    }

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    /* Unpin rather than pinning back to the host default: SetDataDir()
     * mkdir()s what it is given, and the default is a real node's directory.
     * Clearing the cache restores "resolve on next use". */
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("getheaders serve-path verification receipt tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
