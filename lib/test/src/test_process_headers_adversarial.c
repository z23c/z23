/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial tests for the inbound `headers` P2P handler
 * (lib/net/src/msg_headers.c::process_headers). A hostile peer fully
 * controls the payload bytes; these cases pin the handler's defensive
 * contract with a stub msg_processor + stack p2p_node + raw byte_stream
 * payloads (no sockets — all hooks left NULL are no-ops by design):
 *
 *   1. oversize count (> 2000)  -> rejected, peer penalized + disconnected
 *   2. truncated mid-header     -> clean failure, NO partial accept,
 *                                  no block-tree mutation, peer penalized
 *   3. valid 2-header batch with trailing garbage -> both accepted, the
 *      per-header tx-count compact-size is consumed correctly (stream
 *      stops exactly at the garbage; the garbage is never parsed)
 *   4. non-connecting batch (unknown prev) -> rejected with DoS 0:
 *      no block-tree mutation, no peer penalty (orphans are normal)
 *
 * Headers for case 3/4 are REAL regtest Equihash (48,5) blocks mined via
 * mine_block_pow, so accept_block_header's PoW gate runs for real. */

#include "test/test_core.h"
#include "util/util.h"
#include "platform/time_compat.h"

#include "mining/miner.h"
#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/peer_scoring.h"
#include "validation/chainstate.h"
#include "validation/process_block.h"  /* accept_block_header */

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define PH_CHECK(name, expr) do { \
    printf("process_headers_adversarial: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Snapshot-active stub for the push_getheaders_from suppression cases. */
static bool ph_snapshot_active_true(void *ctx) { (void)ctx; return true; }

/* Non-localhost peer (is_trusted_peer matches the IPv4-mapped 127/8
 * prefix at ip[10..12]; use 1.2.3.4) so peer_misbehaving scores it. */
static void ph_setup_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "203.0.113.9:8033");
    node->id = 9;
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 1;
    node->addr.svc.addr.ip[13] = 2;
    node->addr.svc.addr.ip[14] = 3;
    node->addr.svc.addr.ip[15] = 4;
}

/* Mine a consensus-valid regtest header at `height` on `prev`: PoW-true
 * Equihash witness + hash <= powLimit target. Merkle root is arbitrary —
 * header acceptance never inspects it. */
static bool ph_mine_header(struct block_header *out, int height,
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

/* Serialize one wire `headers` element: header bytes + tx-count 0. */
static bool ph_write_header(struct byte_stream *s,
                            const struct block_header *hdr)
{
    return block_header_serialize(hdr, s) &&
           stream_write_compact_size(s, 0);
}

static struct net_manager g_ph_nm;

static int g_ph_header_votes;
static uint32_t g_ph_header_vote_peer;
static int g_ph_header_vote_height;
static char g_ph_header_vote_hash[65];

static void ph_record_header_vote(uint32_t peer_id, int height,
                                  const char hash_hex[65], void *ctx)
{
    (void)ctx;
    g_ph_header_votes++;
    g_ph_header_vote_peer = peer_id;
    g_ph_header_vote_height = height;
    snprintf(g_ph_header_vote_hash, sizeof(g_ph_header_vote_hash), "%s",
             hash_hex ? hash_hex : "");
}

/* Case 5 authority shims: replay the EXACT inconsistent authority pair
 * found at the finalize frontier — height = tip-1 while
 * the hash resolves to the tip block itself. */
static int64_t g_ph_auth_height = -1;
static uint8_t g_ph_auth_hash[32];
static bool ph_auth_is_authoritative(void) { return true; }
static int64_t ph_auth_get_height(void) { return g_ph_auth_height; }
static bool ph_auth_get_hash(uint8_t out[32])
{
    memcpy(out, g_ph_auth_hash, 32);
    return true;
}

int test_process_headers_adversarial(void);
int test_process_headers_adversarial(void)
{
    int failures = 0;
    printf("\n=== process_headers adversarial tests ===\n");

    /* Regtest: small Equihash (48,5) mines in milliseconds. Restore
     * CHAIN_MAIN on the way out (sequential runner shares the process). */
    chain_params_select(CHAIN_REGTEST);
    const struct chain_params *cp = chain_params_get();
    peer_scoring_init();
    enum sync_state sync0 = sync_get_state();

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "ph_adversarial", "main");
    SetDataDir(dir); /* hermetic datadir for mp->datadir resolution */

    struct main_state ms;
    main_state_init(&ms);
    struct uint256 gh = cp->consensus.hashGenesisBlock;
    struct block_index *gen =
        chainstate_insert_block_index((struct chainstate *)&ms, &gh);
    PH_CHECK("genesis block_index inserted", gen != NULL);
    if (gen) {
        gen->nHeight = 0;
        gen->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        gen->nTx = 1;
        gen->nChainTx = 1;
        active_chain_move_window_tip(&ms.chain_active, gen);
        ms.pindex_best_header = gen;
    }

    memset(&g_ph_nm, 0, sizeof(g_ph_nm));
    struct msg_processor mp;
    msg_processor_init(&mp, &ms, NULL, NULL, cp, dir, &g_ph_nm, NULL);
    msg_processor_set_peer_header_vote(&mp, ph_record_header_vote, NULL);

    struct p2p_node node;
    ph_setup_node(&node);

    /* ── 1. oversize count (> 2000): reject + penalize + disconnect ── */
    if (gen) {
        size_t map0 = ms.map_block_index.size;
        struct msg_headers_stats st0, st1;
        msg_headers_get_stats(&st0);
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 2001);
        bool ret = process_headers(&mp, &node, &s);
        msg_headers_get_stats(&st1);
        PH_CHECK("oversize: handler returns false", ret == false);
        PH_CHECK("oversize: peer flagged for disconnect",
                 node.disconnect == true);
        PH_CHECK("oversize: peer penalized",
                 atomic_load(&node.misbehavior) > 0);
        PH_CHECK("oversize: no block-tree mutation",
                 ms.map_block_index.size == map0);
        PH_CHECK("oversize: no batch counted",
                 st1.batches_received == st0.batches_received);
        stream_free(&s);
    }

    /* ── 2. truncated mid-header: clean failure, no partial accept ── */
    if (gen) {
        node.disconnect = false;
        atomic_store(&node.misbehavior, 0);
        size_t map0 = ms.map_block_index.size;
        struct msg_headers_stats st0, st1;
        msg_headers_get_stats(&st0);
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 2); /* promises 2 headers... */
        unsigned char garbage[20];
        memset(garbage, 0xab, sizeof(garbage));
        stream_write_bytes(&s, garbage, sizeof(garbage)); /* ...delivers 20B */
        bool ret = process_headers(&mp, &node, &s);
        msg_headers_get_stats(&st1);
        PH_CHECK("truncated: handler returns false", ret == false);
        PH_CHECK("truncated: peer penalized",
                 atomic_load(&node.misbehavior) > 0);
        PH_CHECK("truncated: no block-tree mutation",
                 ms.map_block_index.size == map0);
        PH_CHECK("truncated: nothing accepted",
                 st1.total_accepted == st0.total_accepted &&
                 st1.batches_received == st0.batches_received);
        stream_free(&s);
    }

    /* ── 3. valid 2-header batch + trailing garbage ── */
    struct block_header h1, h2;
    struct uint256 h1_hash;
    bool mined = gen &&
                 ph_mine_header(&h1, 1, &gh, cp);
    if (mined) {
        block_header_get_hash(&h1, &h1_hash);
        mined = ph_mine_header(&h2, 2, &h1_hash, cp);
    }
    PH_CHECK("two connecting regtest headers mined", mined);
    if (mined) {
        g_ph_header_votes = 0;
        g_ph_header_vote_peer = 0;
        g_ph_header_vote_height = -1;
        g_ph_header_vote_hash[0] = '\0';
        node.disconnect = false;
        atomic_store(&node.misbehavior, 0);
        struct msg_headers_stats st0, st1;
        msg_headers_get_stats(&st0);
        struct byte_stream s;
        stream_init(&s, 1024);
        stream_write_compact_size(&s, 2);
        bool wrote = ph_write_header(&s, &h1) && ph_write_header(&s, &h2);
        unsigned char garbage[16];
        memset(garbage, 0xcd, sizeof(garbage));
        wrote = wrote && stream_write_bytes(&s, garbage, sizeof(garbage));
        PH_CHECK("batch payload built", wrote);
        size_t payload_end = s.size - sizeof(garbage);
        bool ret = process_headers(&mp, &node, &s);
        msg_headers_get_stats(&st1);
        PH_CHECK("valid batch: handler returns true", ret == true);
        PH_CHECK("valid batch: both headers accepted",
                 st1.total_accepted == st0.total_accepted + 2 &&
                 st1.newly_added == st0.newly_added + 2);
        struct uint256 h2_hash;
        block_header_get_hash(&h2, &h2_hash);
        struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1_hash);
        struct block_index *bi2 = block_map_find(&ms.map_block_index, &h2_hash);
        PH_CHECK("valid batch: both in block tree at h=1,2",
                 bi1 && bi1->nHeight == 1 && bi2 && bi2->nHeight == 2);
        PH_CHECK("valid batch: compact-size consumed exactly "
                 "(garbage never parsed)",
                 s.read_pos == payload_end);
        PH_CHECK("valid batch: best header promoted to h=2",
                 ms.pindex_best_header == bi2);
        char h2_hex[65];
        uint256_get_hex(&h2_hash, h2_hex);
        PH_CHECK("valid batch: standard peer contributes header vote",
                 node.services == 0 && g_ph_header_votes == 1 &&
                 g_ph_header_vote_peer == (uint32_t)node.id &&
                 g_ph_header_vote_height == 2 &&
                 strcmp(g_ph_header_vote_hash, h2_hex) == 0);
        PH_CHECK("valid batch: honest peer not penalized",
                 atomic_load(&node.misbehavior) == 0 && !node.disconnect);
        stream_free(&s);
    }

    /* ── 4. non-connecting batch: reject, DoS 0, no tree mutation ── */
    if (gen) {
        struct uint256 unknown_prev;
        memset(unknown_prev.data, 0xee, 32);
        struct block_header orphan;
        bool orphan_mined = ph_mine_header(&orphan, 1, &unknown_prev, cp);
        PH_CHECK("orphan header mined", orphan_mined);
        if (orphan_mined) {
            node.disconnect = false;
            atomic_store(&node.misbehavior, 0);
            /* The all-rejected recovery probe (bad-prevblk → getheaders from
             * our best header) would legitimately fire here; arm its per-peer
             * rate limit so the send path stays untouched (no-socket test
             * design — a failed send would close the stub node and mask the
             * penalty assertions below). The probe decision itself is pinned
             * in test_sync_service. */
            int64_t probe_armed = (int64_t)platform_time_wall_time_t();
            atomic_store(&node.last_reject_probe_time, probe_armed);
            size_t map0 = ms.map_block_index.size;
            struct msg_headers_stats st0, st1;
            msg_headers_get_stats(&st0);
            struct byte_stream s;
            stream_init(&s, 1024);
            stream_write_compact_size(&s, 1);
            PH_CHECK("orphan payload built", ph_write_header(&s, &orphan));
            bool ret = process_headers(&mp, &node, &s);
            msg_headers_get_stats(&st1);
            PH_CHECK("non-connecting: handler completes", ret == true);
            struct uint256 ohash;
            block_header_get_hash(&orphan, &ohash);
            PH_CHECK("non-connecting: header NOT added to block tree",
                     block_map_find(&ms.map_block_index, &ohash) == NULL &&
                     ms.map_block_index.size == map0);
            PH_CHECK("non-connecting: counted as rejected",
                     st1.total_rejected == st0.total_rejected + 1);
            PH_CHECK("non-connecting: DoS 0 — orphan peer NOT penalized",
                     atomic_load(&node.misbehavior) == 0 && !node.disconnect);
            PH_CHECK("non-connecting: recovery probe rate-limited, not fired",
                     atomic_load(&node.last_reject_probe_time) == probe_armed);
            PH_CHECK("non-connecting: recovery probe pending armed",
                     atomic_load(&node.reject_probe_pending));
            atomic_store(&node.reject_probe_pending, false);
            stream_free(&s);
        }
    }

    /* ── 5. tip-header re-delivery must NOT relabel heights (the
     *       height-splice regression class). Re-use h1/h2 from case 3 (accepted at
     *       h=1,2). Serve h2 as the window tip and register an authority
     *       publishing the INCONSISTENT pair captured at the
     *       finalize frontier (height = tip-1, hash = tip). The deleted
     *       label-trust install in accept_block_header would re-height the
     *       tip 2->1 and rewrite its parent 1->0, cascading a -1 splice over
     *       every header above; the derive-from-parent rule must leave the
     *       graph untouched and a successor must still land at parent+1. */
    if (mined) {
        struct uint256 h2_hash;
        block_header_get_hash(&h2, &h2_hash);
        struct block_index *bi1 = block_map_find(&ms.map_block_index, &h1_hash);
        struct block_index *bi2 = block_map_find(&ms.map_block_index, &h2_hash);
        PH_CHECK("relabel: accepted tip + parent present", bi1 && bi2);
        if (bi1 && bi2) {
            PH_CHECK("relabel: window tip installed at h=2",
                     active_chain_move_window_tip(&ms.chain_active, bi2));
            g_ph_auth_height = bi2->nHeight - 1;       /* the poisoned label */
            memcpy(g_ph_auth_hash, h2_hash.data, 32);  /* ...of the tip hash */
            struct active_chain_authority poisoned = {
                .get_height = ph_auth_get_height,
                .get_hash = ph_auth_get_hash,
                .is_authoritative = ph_auth_is_authoritative,
            };
            active_chain_register_authority(&poisoned);
            active_chain_register_block_map(&ms.map_block_index);
            PH_CHECK("relabel: simulated pair is the inconsistent one",
                     active_chain_height(&ms.chain_active) == 1 &&
                     active_chain_tip(&ms.chain_active) == bi2);

            struct validation_state state;
            validation_state_init(&state);
            struct block_index *re = NULL;
            bool ok = accept_block_header(&h2, &state, &ms, cp, &re);
            PH_CHECK("relabel: re-delivered tip header accepted",
                     ok && re == bi2);
            PH_CHECK("relabel: tip nHeight NOT mutated", bi2->nHeight == 2);
            PH_CHECK("relabel: parent nHeight NOT mutated", bi1->nHeight == 1);
            PH_CHECK("relabel: links intact",
                     bi2->pprev == bi1 && bi1->pprev == gen &&
                     gen->nHeight == 0);

            /* Overlapping successor batch: a child above the re-delivered
             * tip still derives parent+1, never authority-label+1. */
            struct block_header h3;
            bool m3 = ph_mine_header(&h3, 3, &h2_hash, cp);
            PH_CHECK("relabel: successor mined", m3);
            if (m3) {
                struct validation_state st3;
                validation_state_init(&st3);
                struct block_index *bi3 = NULL;
                bool ok3 = accept_block_header(&h3, &st3, &ms, cp, &bi3);
                PH_CHECK("relabel: successor derives parent+1",
                         ok3 && bi3 && bi3->nHeight == 3 &&
                         bi3->pprev == bi2);
                PH_CHECK("relabel: graph heights unchanged after batch",
                         bi1->nHeight == 1 && bi2->nHeight == 2);
            }

            /* Restore globals for the sequential in-process runner. */
            struct active_chain_authority none = {0};
            active_chain_register_authority(&none);
            active_chain_register_block_map(NULL);
        }
    }

    /* ── 6. push_getheaders_from continuation-suppression must be LOUD +
     *       COUNTED, never a silent header-sync stop (the header-continuation
     *       wedge class). Uses a fresh EMPTY main_state so the null-hash
     *       re-anchor finds no hashed frontier and returns after counting,
     *       and the snapshot guard returns before touching the send path —
     *       both stay off the node send mutex. */
    {
        struct main_state ms2;
        main_state_init(&ms2);
        struct msg_processor mp2;
        msg_processor_init(&mp2, &ms2, NULL, NULL, cp, dir, &g_ph_nm, NULL);

        /* (a) null-hash anchor: counted no-hash suppression (pre-fix this
         *     was a silent `return;` that killed the continuation). */
        {
            struct block_index ghost;
            memset(&ghost, 0, sizeof(ghost));
            ghost.nHeight = 5;
            ghost.phashBlock = NULL;   /* stable hash slot never populated */
            struct msg_headers_stats a, b;
            msg_headers_get_stats(&a);
            push_getheaders_from(&mp2, &node, &ghost);
            msg_headers_get_stats(&b);
            PH_CHECK("null-hash anchor: counted (no silent continuation drop)",
                     b.getheaders_suppressed_no_hash ==
                         a.getheaders_suppressed_no_hash + 1);
        }

        /* (b) active snapshot exchange: counted snapshot suppression (pre-fix
         *     this was the silent latch that wedged header sync after one
         *     in-flight batch). */
        {
            struct msg_headers_stats a, b;
            msg_headers_get_stats(&a);
            msg_processor_set_snapshot_active(&mp2, ph_snapshot_active_true,
                                              NULL);
            push_getheaders_from(&mp2, &node, NULL);
            msg_processor_set_snapshot_active(&mp2, NULL, NULL);
            msg_headers_get_stats(&b);
            PH_CHECK("snapshot active: counted getheaders suppression",
                     b.getheaders_suppressed_snapshot ==
                         a.getheaders_suppressed_snapshot + 1);
        }

        main_state_free(&ms2);
    }

    /* ── 7. sibling silent-drop sites in the same file, same defect class:
     *       inbound `headers` dropped receive-side, push_getheaders() and
     *       push_getheaders_span() dropped send-side while a snapshot
     *       exchange owns the wire, and the getheaders-serving defer while
     *       a peer snapshot transfer is in progress — all must count and
     *       (rising-edge) log instead of silently returning. */
    {
        struct main_state ms3;
        main_state_init(&ms3);
        struct msg_processor mp3;
        msg_processor_init(&mp3, &ms3, NULL, NULL, cp, dir, &g_ph_nm, NULL);

        /* (a) process_headers: inbound headers dropped while a snapshot
         *     exchange is active — counted, never a silent stop. */
        {
            struct msg_headers_stats a, b;
            msg_headers_get_stats(&a);
            msg_processor_set_snapshot_active(&mp3, ph_snapshot_active_true,
                                              NULL);
            struct byte_stream s;
            stream_init(&s, 8);
            bool ret = process_headers(&mp3, &node, &s);
            msg_processor_set_snapshot_active(&mp3, NULL, NULL);
            stream_free(&s);
            msg_headers_get_stats(&b);
            PH_CHECK("process_headers: snapshot-active drop counted",
                     ret == true &&
                     b.headers_recv_suppressed_snapshot ==
                         a.headers_recv_suppressed_snapshot + 1);
        }

        /* (b) push_getheaders: send-side request suppressed while a
         *     snapshot exchange is active — counted. */
        {
            struct msg_headers_stats a, b;
            msg_headers_get_stats(&a);
            msg_processor_set_snapshot_active(&mp3, ph_snapshot_active_true,
                                              NULL);
            push_getheaders(&mp3, &node);
            msg_processor_set_snapshot_active(&mp3, NULL, NULL);
            msg_headers_get_stats(&b);
            PH_CHECK("push_getheaders: snapshot-active drop counted",
                     b.push_getheaders_suppressed_snapshot ==
                         a.push_getheaders_suppressed_snapshot + 1);
        }

        /* (c) push_getheaders_span: span request suppressed while a
         *     snapshot exchange is active — counted. */
        {
            struct msg_headers_stats a, b;
            msg_headers_get_stats(&a);
            msg_processor_set_snapshot_active(&mp3, ph_snapshot_active_true,
                                              NULL);
            push_getheaders_span(&mp3, &node, &gh, NULL);
            msg_processor_set_snapshot_active(&mp3, NULL, NULL);
            msg_headers_get_stats(&b);
            PH_CHECK("push_getheaders_span: snapshot-active drop counted",
                     b.push_getheaders_span_suppressed_snapshot ==
                         a.push_getheaders_span_suppressed_snapshot + 1);
        }

        /* (d) process_getheaders: request deferred while we are serving a
         *     snapshot to this peer — counted (was a bare printf). */
        {
            struct msg_headers_stats a, b;
            msg_headers_get_stats(&a);
            bool saved = node.swarm_manifest_sent;
            node.swarm_manifest_sent = true;
            struct byte_stream s;
            stream_init(&s, 8);
            bool ret = process_getheaders(&mp3, &node, &s);
            stream_free(&s);
            node.swarm_manifest_sent = saved;
            msg_headers_get_stats(&b);
            PH_CHECK("process_getheaders: snapshot-serving defer counted",
                     ret == true &&
                     b.getheaders_deferred_snapshot_serving ==
                         a.getheaders_deferred_snapshot_serving + 1);
        }

        main_state_free(&ms3);
    }

    /* ── 8. getheaders SERVE side: the reply must stay under the 2 MiB wire
     *       cap. ~2000 Equihash headers (1344-byte solution ≈ 1.5 KB each)
     *       serialize to ~2.9 MB > MAX_PROTOCOL_MESSAGE_LENGTH, and the peer
     *       drops the whole oversized reply. getheaders_try_append_header()
     *       bounds the batch by bytes so the framed reply always fits. */
    {
        struct block_header big;
        block_header_init(&big);
        big.nBits = 0x1f07ffff;
        big.nSolutionSize = MAX_SOLUTION_SIZE;   /* pre-Bubbles 200,9 size */
        memset(big.nSolution, 0xab, MAX_SOLUTION_SIZE);

        struct byte_stream body;
        stream_init(&body, 1u << 20);
        int served = 0;
        bool stopped_by_cap = false;
        for (int i = 0; i < 2000; i++) {
            if (!getheaders_try_append_header(&body, &big)) {
                stopped_by_cap = true;
                break;
            }
            served++;
        }
        size_t framed = compact_size_sizeof((uint64_t)served) + body.size;
        PH_CHECK("getheaders serve: byte cap stops the batch before count 2000",
                 stopped_by_cap && served > 0 && served < 2000);
        PH_CHECK("getheaders serve: framed reply within wire cap",
                 framed <= (size_t)MAX_PROTOCOL_MESSAGE_LENGTH);
        PH_CHECK("getheaders serve: one more header would overflow (tight)",
                 body.size + 1488u + 16u > (size_t)MAX_PROTOCOL_MESSAGE_LENGTH);
        stream_free(&body);
    }

    /* ── 9. batch-order relink heal refuses a STALE ANCHOR (the
     *       refuse-don't-mutate contract). The heal may only rewrite an
     *       entry's parent/height/skip/chain-work when the claimed prev
     *       resolves IN THE MAP to exactly the batch's previous anchor;
     *       accept_block_header has already repaired each entry against
     *       the map, so any residual disagreement means the anchor went
     *       stale (orphaned twin, concurrent re-key, freed slot) and the
     *       rewrite would split the ladder onto an out-of-map twin.
     *
     *       Hermetic staging: admit A normally, then install a hand-built
     *       TWIN of A (same hash bytes, outside the map) as the active-
     *       chain window tip, so the next batch's sequence anchor is not
     *       what the map resolves. Pre-fix behavior: B(prev=A) mutates
     *       onto the twin — ancestry pointing OUTSIDE the map, invisible
     *       to every map walker. Post-fix: refused without mutation, the
     *       cursor keeps the last map-agreed anchor, and the next header
     *       in the same batch still admits cleanly. */
    {
        struct main_state ms4;
        main_state_init(&ms4);
        struct msg_processor mp4;
        msg_processor_init(&mp4, &ms4, NULL, NULL, cp, dir, &g_ph_nm, NULL);

        struct uint256 gh4 = cp->consensus.hashGenesisBlock;
        struct block_index *gen4 =
            chainstate_insert_block_index((struct chainstate *)&ms4, &gh4);
        PH_CHECK("stale-anchor: genesis inserted", gen4 != NULL);
        if (gen4) {
            gen4->nHeight = 0;
            gen4->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
            gen4->nTx = 1;
            gen4->nChainTx = 1;
            active_chain_move_window_tip(&ms4.chain_active, gen4);
            ms4.pindex_best_header = gen4;

            struct block_header ha, hb, hc;
            bool ok9 = ph_mine_header(&ha, 1, &gh4, cp);
            if (ok9) {
                struct uint256 ha_hash;
                block_header_get_hash(&ha, &ha_hash);
                ok9 = ph_mine_header(&hb, 2, &ha_hash, cp);
                if (ok9) {
                    struct uint256 hb_hash;
                    block_header_get_hash(&hb, &hb_hash);
                    ok9 = ph_mine_header(&hc, 3, &hb_hash, cp);
                }
            }
            PH_CHECK("stale-anchor: three chained regtest headers mined", ok9);

            /* Batch 1 [A]: admitted through the heal path with an honest
             * anchor (genesis resolves in the map) — the healthy flow
             * this slice must preserve. */
            size_t map0 = ms4.map_block_index.size;
            struct byte_stream s1;
            stream_init(&s1, 512);
            stream_write_compact_size(&s1, 1);
            PH_CHECK("stale-anchor: batch1 payload built",
                     ph_write_header(&s1, &ha));
            PH_CHECK("stale-anchor: honest batch1 accepted",
                     process_headers(&mp4, &node, &s1));
            PH_CHECK("stale-anchor: batch1 grew the map by one",
                     ms4.map_block_index.size == map0 + 1);
            stream_free(&s1);

            struct uint256 ha_hash;
            block_header_get_hash(&ha, &ha_hash);
            struct block_index *map_a =
                block_map_find(&ms4.map_block_index, &ha_hash);
            PH_CHECK("stale-anchor: A resolved in the map", map_a != NULL);

            /* Stage the out-of-map twin as the sequence anchor. */
            struct uint256 twin_hash;
            struct block_index twin;
            memset(&twin, 0, sizeof(twin));
            twin.nHeight = 1;
            twin.phashBlock = &twin_hash;
            memcpy(twin_hash.data, ha_hash.data, 32);
            PH_CHECK("stale-anchor: twin installed as window tip",
                     active_chain_move_window_tip(&ms4.chain_active, &twin));

            node.disconnect = false;
            atomic_store(&node.misbehavior, 0);

            /* Batch 2 [B(prev=A), C(prev=B)] with the anchor stale. */
            struct byte_stream s2;
            stream_init(&s2, 1024);
            stream_write_compact_size(&s2, 2);
            PH_CHECK("stale-anchor: batch2 payload built",
                     ph_write_header(&s2, &hb) && ph_write_header(&s2, &hc));
            bool ret9 = process_headers(&mp4, &node, &s2);
            stream_free(&s2);
            PH_CHECK("stale-anchor: batch2 completes", ret9 == true);
            PH_CHECK("stale-anchor: batch2 grew the map by two",
                     ms4.map_block_index.size == map0 + 3);

            struct uint256 hb_hash, hc_hash;
            block_header_get_hash(&hb, &hb_hash);
            block_header_get_hash(&hc, &hc_hash);
            struct block_index *bi_b =
                block_map_find(&ms4.map_block_index, &hb_hash);
            struct block_index *bi_c =
                block_map_find(&ms4.map_block_index, &hc_hash);
            PH_CHECK("stale-anchor: B kept its MAP-resolved parent "
                     "(not mutated onto the twin)",
                     bi_b && bi_b->nHeight == 2 &&
                     map_a && bi_b->pprev == map_a);
            PH_CHECK("stale-anchor: cursor survived the refusal — "
                     "next header admits at parent+1",
                     bi_c && bi_c->nHeight == 3 &&
                     bi_c->pprev == bi_b);
            PH_CHECK("stale-anchor: refusal scores no penalty",
                     atomic_load(&node.misbehavior) == 0 && !node.disconnect);
            PH_CHECK("stale-anchor: ladder unchanged elsewhere",
                     map_a->nHeight == 1 &&
                     (gen4 ? gen4->nHeight == 0 : true));
        }
        main_state_free(&ms4);
    }

    sync_set_state(sync0, "process_headers_adversarial restore");
    main_state_free(&ms);
    SetDataDir("");
    ClearDataDirCache();
    test_rm_rf(dir);
    chain_params_select(CHAIN_MAIN);

    printf("process_headers adversarial tests: %s\n",
           failures ? "FAILED" : "PASSED");
    return failures;
}
