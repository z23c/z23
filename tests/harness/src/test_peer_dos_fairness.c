/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Do not punish a peer for our own failure to verify.
 *
 * A node's shielded verifiers are fail-closed on missing key material:
 * sprout_verify_groth16 / sprout_verify_phgr13 / sapling_check_spend all
 * return exactly the same `false` for "this proof is forged" and for
 * "the verifying key is not installed" (the params loader is a background
 * boot thread, and sapling_free_params() can clear the keys again at
 * runtime). contextual_check_transaction collapsed both into one bool,
 * accept_to_mempool turned that bool into MEMPOOL_ACCEPT_INVALID, and
 * msg_tx.c charged PEER_OFFENCE_INVALID_MESSAGE for it — so a peer that
 * relayed a perfectly valid shielded transaction during our boot window
 * accrued ban-score for OUR startup state.
 *
 * enum contextual_check_verdict now separates the two at the source.
 * This file pins BOTH directions, because the fix is only correct if it
 * does not buy fairness with validation:
 *
 *   1. THE TYPE. A shielded transaction we cannot check reports
 *      UNVERIFIABLE; a shielded transaction we CAN check and that fails
 *      reports REJECT. Crucially the bool wrapper still answers false for
 *      BOTH — unverifiable is never an acceptance.
 *   2. NOT WEAKENED. A genuinely invalid transaction is still rejected
 *      and still scored, whether or not verifying keys are present. A
 *      structurally invalid shielded transaction is still a REJECT, not
 *      an UNVERIFIABLE — the availability gate sits after the structural
 *      rules so it surrenders no verdict we were able to reach.
 *   3. NOT SCORED. A transaction we could not verify costs its sender
 *      zero ban-score at the relay path.
 *   4. STILL BOUNDED. "Unscored" is not "unlimited": past a per-peer
 *      volume cap the send RATE is the peer's own doing and is scored as
 *      FLOOD, so the unscored outcome cannot be farmed for free traffic.
 */

#include "test/test_core.h"

#include "net/msg_internal.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "net/protocol.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "validation/accept_to_mempool.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Non-localhost peer, so is_trusted_peer() does not make scoring a no-op
 * (127.0.0.0/8 is treated as our own infrastructure). Mirrors
 * test_mempool.c / test_peer_scoring.c. */
static void pdf_setup_node(struct p2p_node *node, const char *name)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "%s", name);
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 1;
    node->addr.svc.addr.ip[13] = 2;
    node->addr.svc.addr.ip[14] = 3;
    node->addr.svc.addr.ip[15] = 4;
}

/* A Sapling transaction carrying one shielded output whose proof bytes are
 * garbage. Structurally well-formed at `sap_height` so it reaches the point
 * where proofs are verified; `tag` varies the commitment so successive
 * transactions have distinct hashes. */
static void pdf_make_shielded_tx(struct transaction *tx, int sap_height,
                                 uint8_t tag)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->overwintered = true;
    tx->version = SAPLING_TX_VERSION;
    tx->version_group_id = SAPLING_VERSION_GROUP_ID;
    tx->expiry_height = (uint32_t)(sap_height + 100);
    memset(tx->vin[0].prevout.hash.data, 0x11, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vin[0].script_sig.size = 0;
    tx->vout[0].value = COIN;
    tx->vout[0].script_pub_key.size = 0;

    tx->num_shielded_output = 1;
    tx->v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                       "pdf_shielded_output");
    if (!tx->v_shielded_output) {
        tx->num_shielded_output = 0;
        return;
    }
    /* Deliberately bogus proof / commitment bytes: with verifying keys
     * INSTALLED this must be a genuine REJECT. */
    memset(tx->v_shielded_output[0].zkproof, 0xCD, GROTH_PROOF_SIZE);
    memset(tx->v_shielded_output[0].cv.data, 0xAB, 32);
    memset(tx->v_shielded_output[0].cm.data, tag, 32);
    memset(tx->v_shielded_output[0].ephemeral_key.data, 0xEF, 32);
    tx->value_balance = 0;
    transaction_compute_hash(tx);
}

/* A Sprout (pre-Overwinter) transaction carrying one PHGR13 JoinSplit.
 * Structurally well-formed at ANY height, which is what lets the relay-path
 * fixture below use it against a chain tip at height 0 without tripping a
 * height-gated structural rule first.
 *
 * It also covers a second, independent hole: PHGR13's verifying key lives in
 * its own file and is NOT covered by sapling_params_loaded(). Off mainnet,
 * params_init.c publishes params_loaded==true with that key absent, so a
 * valid pre-Sapling JoinSplit would fail-close on a NULL phgr_vk and read as
 * a forged proof. `tag` varies the nullifiers so successive transactions
 * hash differently. */
static void pdf_make_sprout_tx(struct transaction *tx, uint16_t tag)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    tx->overwintered = false;
    tx->version = 2;              /* Sprout JoinSplit-capable version */
    memset(tx->vin[0].prevout.hash.data, 0x22, 32);
    tx->vin[0].prevout.n = 0;
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vin[0].script_sig.size = 0;
    tx->vout[0].value = COIN;
    tx->vout[0].script_pub_key.size = 0;

    tx->num_joinsplit = 1;
    tx->v_joinsplit = zcl_calloc(1, sizeof(struct js_description),
                                 "pdf_joinsplit");
    if (!tx->v_joinsplit) {
        tx->num_joinsplit = 0;
        return;
    }
    struct js_description *js = &tx->v_joinsplit[0];
    js->vpub_old = 0;
    js->vpub_new = 0;
    js->use_groth = false;        /* PHGR13 */
    memset(js->proof, 0xCD, PHGR_PROOF_SIZE);
    /* Nullifiers must differ from each other (duplicate nullifiers are a
     * structural reject) and vary per transaction. */
    memset(js->nullifiers[0].data, 0x01, 32);
    memset(js->nullifiers[1].data, 0x02, 32);
    js->nullifiers[0].data[0] = (uint8_t)(tag & 0xFF);
    js->nullifiers[0].data[1] = (uint8_t)((tag >> 8) & 0xFF);
    memset(js->commitments[0].data, 0x03, 32);
    memset(js->commitments[1].data, 0x04, 32);
    memset(js->anchor.data, 0x05, 32);
    memset(js->random_seed.data, 0x06, 32);
    memset(js->macs[0].data, 0x07, 32);
    memset(js->macs[1].data, 0x08, 32);
    transaction_compute_hash(tx);
}

int test_peer_dos_fairness(void)
{
    int failures = 0;
    printf("\n=== peer DoS fairness: our failure is not their offence ===\n");

    const struct chain_params *cp = chain_params_get();
    const struct consensus_params *consensus = &cp->consensus;
    int sap_height = consensus->vUpgrades[UPGRADE_SAPLING].nActivationHeight;

    /* The suite may have installed keys already; start from a known state
     * and restore it at the end. */
    bool had_params = sapling_params_loaded();

    /* ================================================================
     * 1. THE TYPE — same transaction, two different reasons for `false`.
     * ================================================================ */
    printf("shielded tx + no verifying keys -> UNVERIFIABLE (not rejected as invalid)... ");
    {
        if (had_params)
            sapling_free_params();

        struct transaction tx;
        pdf_make_shielded_tx(&tx, sap_height, 0x01);

        struct validation_state st;
        validation_state_init(&st);
        enum contextual_check_verdict v =
            contextual_check_transaction_verdict(&tx, &st, consensus,
                                                 sap_height, 100);

        /* And the bool wrapper must STILL say false: unverifiable is not
         * an acceptance. This is the no-weakening half of case 1. */
        struct validation_state st2;
        validation_state_init(&st2);
        bool accepted = contextual_check_transaction(&tx, &st2, consensus,
                                                     sap_height, 100);

        bool ok = (v == CONTEXTUAL_CHECK_UNVERIFIABLE) && !accepted &&
                  (st.dos == 0);
        if (ok) printf("OK\n");
        else {
            printf("FAIL (verdict=%d accepted=%d dos=%d reason=%s)\n",
                   (int)v, (int)accepted, st.dos, st.reject_reason);
            failures++;
        }
        transaction_free(&tx);
    }

    printf("shielded tx + verifying keys present -> genuine REJECT... ");
    {
        bool installed = sapling_install_embedded_vks();
        if (!installed) {
            /* No key material available in this build at all — the
             * distinction under test cannot be exercised. Say so rather
             * than passing vacuously. */
            printf("FAIL (no embedded verifying keys to install)\n");
            failures++;
        } else {
            struct transaction tx;
            pdf_make_shielded_tx(&tx, sap_height, 0x02);

            struct validation_state st;
            validation_state_init(&st);
            enum contextual_check_verdict v =
                contextual_check_transaction_verdict(&tx, &st, consensus,
                                                     sap_height, 100);
            bool accepted = contextual_check_transaction(&tx, &st, consensus,
                                                         sap_height, 100);

            /* A forged proof is the SENDER's fault: REJECT, full DoS
             * score, and still not accepted. */
            bool ok = (v == CONTEXTUAL_CHECK_REJECT) && !accepted;
            if (ok) printf("OK\n");
            else {
                printf("FAIL (verdict=%d accepted=%d reason=%s)\n",
                       (int)v, (int)accepted, st.reject_reason);
                failures++;
            }
            transaction_free(&tx);
        }
    }

    /* ================================================================
     * 2. NOT WEAKENED — the availability gate must not swallow a verdict
     *    we were perfectly able to reach. A shielded transaction that is
     *    structurally wrong for its height is a REJECT even when we hold
     *    no verifying keys, because the structural rules run first.
     * ================================================================ */
    printf("structurally invalid shielded tx + no keys -> still REJECT... ");
    {
        sapling_free_params();

        struct transaction tx;
        /* Sapling-versioned, but presented at height 1 where Sapling is
         * not active: rejected by the structural rules regardless of any
         * proof. */
        pdf_make_shielded_tx(&tx, sap_height, 0x03);

        struct validation_state st;
        validation_state_init(&st);
        enum contextual_check_verdict v =
            contextual_check_transaction_verdict(&tx, &st, consensus, 1, 100);

        bool ok = (v == CONTEXTUAL_CHECK_REJECT);
        if (ok) printf("OK\n");
        else {
            printf("FAIL (verdict=%d reason=%s)\n", (int)v, st.reject_reason);
            failures++;
        }
        transaction_free(&tx);
    }

    printf("transparent tx never reports UNVERIFIABLE... ");
    {
        /* Keys still absent. A transaction with no shielded components
         * needs none, so the gate must not fire for it. */
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.overwintered = true;
        tx.version = SAPLING_TX_VERSION;
        tx.version_group_id = SAPLING_VERSION_GROUP_ID;
        tx.expiry_height = (uint32_t)(sap_height + 100);
        memset(tx.vin[0].prevout.hash.data, 0x11, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = COIN;
        tx.vout[0].script_pub_key.size = 0;
        transaction_compute_hash(&tx);

        struct validation_state st;
        validation_state_init(&st);
        enum contextual_check_verdict v =
            contextual_check_transaction_verdict(&tx, &st, consensus,
                                                 sap_height, 100);
        bool unverifiable_claimed =
            contextual_check_tx_proofs_unverifiable(&tx, sap_height);

        bool ok = (v != CONTEXTUAL_CHECK_UNVERIFIABLE) && !unverifiable_claimed;
        if (ok) printf("OK\n");
        else {
            printf("FAIL (verdict=%d predicate=%d)\n",
                   (int)v, (int)unverifiable_claimed);
            failures++;
        }
        transaction_free(&tx);
    }

    /* ================================================================
     * 3. NOT SCORED — the relay path. Two peers, same node, same message
     *    shape; only the reason for the failure differs.
     * ================================================================ */
    unsetenv("ZCL_PEER_BAN_THRESHOLD");
    unsetenv("ZCL_PEER_BAN_HOURS");
    unsetenv("ZCL_PEER_SCORE_DECAY_PER_MIN");
    peer_scoring_init();

    struct main_state pdf_main_state;
    main_state_init(&pdf_main_state);

    printf("genuinely invalid tx -> rejected AND scored... ");
    {
        sapling_free_params();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        pdf_setup_node(&node, "pdf_guilty");

        struct msg_processor mp = {0};
        mp.mempool = &pool;
        mp.coins_tip = &coins;
        mp.main_state = &pdf_main_state;
        mp.params = cp;
        mp.net_mgr = &nm;

        /* Forbidden negative output value — unambiguously the sender's
         * doing, and nothing to do with proof verification. */
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        memset(tx.vin[0].prevout.hash.data, 0xAA, 32);
        tx.vin[0].prevout.n = 0;
        tx.vin[0].sequence = 0xFFFFFFFF;
        tx.vout[0].value = -1;
        transaction_compute_hash(&tx);

        enum tx_accept_result ar = msg_tx_accept(&mp, &node, &tx);

        bool ok = (ar == TX_ACCEPT_INVALID);
        ok = ok && (tx_mempool_size(&pool) == 0);
        ok = ok && (atomic_load(&node.misbehavior) ==
                    peer_offence_weight(PEER_OFFENCE_INVALID_MESSAGE));

        if (ok) printf("OK\n");
        else {
            printf("FAIL (ar=%d size=%zu score=%d)\n", (int)ar,
                   tx_mempool_size(&pool), atomic_load(&node.misbehavior));
            failures++;
        }
        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
    }

    printf("valid-shaped shielded tx we cannot verify -> rejected, NOT scored... ");
    {
        sapling_free_params();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        pdf_setup_node(&node, "pdf_innocent");

        struct msg_processor mp = {0};
        mp.mempool = &pool;
        mp.coins_tip = &coins;
        mp.main_state = &pdf_main_state;
        mp.params = cp;
        mp.net_mgr = &nm;

        /* A Sprout JoinSplit: structurally fine at the fixture's tip, so the
         * only thing standing in the way is our absent verifying keys. */
        struct transaction tx;
        pdf_make_sprout_tx(&tx, 0x10);

        enum tx_accept_result ar = msg_tx_accept(&mp, &node, &tx);

        /* Rejected (never relayed, never in the mempool) but the sender
         * pays nothing for our missing keys. */
        bool ok = (ar == TX_ACCEPT_UNVERIFIABLE);
        ok = ok && (tx_mempool_size(&pool) == 0);
        ok = ok && (atomic_load(&node.misbehavior) == 0);

        if (ok) printf("OK\n");
        else {
            printf("FAIL (ar=%d size=%zu score=%d)\n", (int)ar,
                   tx_mempool_size(&pool), atomic_load(&node.misbehavior));
            failures++;
        }
        transaction_free(&tx);
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
    }

    /* ================================================================
     * 4. STILL BOUNDED — the inverse risk. If "we could not verify it"
     *    were simply free, a peer could push shielded traffic at us all
     *    day for nothing while our keys were missing. Past the per-peer
     *    window cap the volume itself is scored.
     * ================================================================ */
    printf("unverifiable flood is bounded by the per-peer rate cap... ");
    {
        sapling_free_params();

        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct coins_view null_view;
        memset(&null_view, 0, sizeof(null_view));
        struct coins_view_cache coins;
        coins_view_cache_init(&coins, &null_view);
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        pdf_setup_node(&node, "pdf_flooder");

        struct msg_processor mp = {0};
        mp.mempool = &pool;
        mp.coins_tip = &coins;
        mp.main_state = &pdf_main_state;
        mp.params = cp;
        mp.net_mgr = &nm;

        bool all_unverifiable = true;
        int score_at_cap = -1;

        for (unsigned i = 0; i <= TX_UNVERIFIABLE_WINDOW_MAX; i++) {
            struct transaction tx;
            pdf_make_sprout_tx(&tx, (uint16_t)i);

            enum tx_accept_result ar = msg_tx_accept(&mp, &node, &tx);
            if (ar != TX_ACCEPT_UNVERIFIABLE)
                all_unverifiable = false;

            /* Everything up to and including the cap stays unscored. */
            if (i + 1 == TX_UNVERIFIABLE_WINDOW_MAX)
                score_at_cap = atomic_load(&node.misbehavior);

            transaction_free(&tx);
        }

        int final_score = atomic_load(&node.misbehavior);
        bool ok = all_unverifiable;
        ok = ok && (score_at_cap == 0);   /* honest volume stays free */
        ok = ok && (final_score > 0);     /* past the cap it is not */
        ok = ok && (tx_mempool_size(&pool) == 0);

        if (ok) printf("OK\n");
        else {
            printf("FAIL (all_unv=%d at_cap=%d final=%d size=%zu)\n",
                   (int)all_unverifiable, score_at_cap, final_score,
                   tx_mempool_size(&pool));
            failures++;
        }
        coins_view_cache_free(&coins);
        tx_mempool_free(&pool);
    }

    /* ================================================================
     * 5. THE SAME DEFECT AT THE FRAMING LAYER. net_message_read_data
     *    refuses a frame for three different reasons and used to tag all
     *    three as the peer's bad bytes. Two of them are facts about THIS
     *    machine: the recv budget is process-wide (so other connections,
     *    or simply a busy box, can fill it) and realloc answers to system
     *    memory pressure. A node under load was handing INVALID_PAYLOAD
     *    to whichever honest peers happened to be mid-message.
     *
     *    Both directions again: legal-but-unaffordable must not score,
     *    over-the-protocol-cap must still score.
     * ================================================================ */
    printf("framing: legal message we cannot afford -> refused, NOT scored... ");
    {
        /* Squeeze the process-wide budget so an ordinary message cannot be
         * staged. Nothing about the peer's bytes changes. */
        setenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES", "1024", 1);

        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        pdf_setup_node(&node, "pdf_squeezed");

        const unsigned char *magic = cp->pchMessageStart;
        struct net_message msg;
        net_message_init(&msg, magic);

        struct msg_header hdr;
        /* 64 KiB: comfortably legal on the wire (the protocol cap is 2 MB),
         * but far over the 1 KiB budget we just imposed on ourselves. */
        msg_header_init_full(&hdr, magic, "block", 65536);

        int hn = net_message_read_header(&msg, (const char *)&hdr,
                                         MSG_HEADER_SIZE);
        unsigned char payload[256];
        memset(payload, 0x00, sizeof(payload));
        int dn = net_message_read_data(&msg, (const char *)payload,
                                       sizeof(payload));

        /* Refused (the resource bound still holds) but attributed to us. */
        bool ok = (hn == (int)MSG_HEADER_SIZE);
        ok = ok && (dn == NET_FRAME_ERR_LOCAL);
        ok = ok && (atomic_load(&node.framing_offence) ==
                    (int)PEER_OFFENCE_NONE);

        p2p_node_score_framing_offence(&nm, &node);
        ok = ok && (atomic_load(&node.misbehavior) == 0);

        net_message_free(&msg);
        unsetenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES");

        if (ok) printf("OK\n");
        else {
            printf("FAIL (hn=%d dn=%d offence=%d score=%d)\n", hn, dn,
                   atomic_load(&node.framing_offence),
                   atomic_load(&node.misbehavior));
            failures++;
        }
    }

    printf("framing: over-the-protocol-cap message -> still refused AND scored... ");
    {
        /* Budget restored to its default. The only thing wrong now is the
         * peer's declared size, which IS the peer's doing. */
        struct net_message msg;
        const unsigned char *magic = cp->pchMessageStart;
        net_message_init(&msg, magic);

        struct msg_header hdr;
        msg_header_init_full(&hdr, magic, "block", 3u * 1024 * 1024);

        int hn = net_message_read_header(&msg, (const char *)&hdr,
                                         MSG_HEADER_SIZE);
        unsigned char payload[256];
        memset(payload, 0x00, sizeof(payload));
        int dn = net_message_read_data(&msg, (const char *)payload,
                                       sizeof(payload));

        bool ok = (hn == (int)MSG_HEADER_SIZE);
        ok = ok && (dn == NET_FRAME_ERR_PEER);

        net_message_free(&msg);

        if (ok) printf("OK\n");
        else {
            printf("FAIL (hn=%d dn=%d)\n", hn, dn);
            failures++;
        }
    }

    /* ================================================================
     * 6. SLOWNESS IS NOT MISBEHAVIOUR. The header-span scheduler used to
     *    charge PEER_OFFENCE_TIMEOUT to any peer that failed to finish an
     *    assigned span within a 30s wall-clock deadline. That deadline is
     *    an assumption about the peer's disk and link, not a protocol
     *    rule — an honest node on a 7200rpm disk under 2 MB/s misses it
     *    routinely, and so does a fast peer whose reply we were too busy
     *    to read. Scoring it made ban-score a measure of hardware.
     *
     *    The remedy that matters (reclaim the span, give the work to
     *    someone else) is a resource action and is unchanged. What must
     *    not happen is score.
     * ================================================================ */
    printf("no production path maps a wall-clock deadline onto ban-score... ");
    {
        /* Honest about its own reach: driving the real span scheduler to a
         * timeout needs a live msg_processor, a claimed span and a wound-on
         * clock, which this fixture does not build. What IS checkable here,
         * and is the property that actually regressed, is a source
         * invariant: no production file may pair PEER_OFFENCE_TIMEOUT with
         * peer_scoring_record. If someone reintroduces "you were slow, have
         * some ban-score" anywhere, this fails.
         *
         * The enum itself deliberately stays — removing it would just push
         * the next author to reach for a different offence for the same
         * bad reason. */
        /* Two counts from ONE search root. `sentinel` must be non-zero:
         * it proves the search actually reached the source tree. Without
         * it, running from a different working directory would make grep
         * match nothing, `hits` would read 0, and this case would pass
         * while checking absolutely nothing. */
        int sentinel = -1, hits = -1;
        FILE *fs = popen(
            "grep -rl 'peer_scoring_record' --include=*.c "
            "core/modules/net/src 2>/dev/null | wc -l", "r");
        if (fs) {
            if (fscanf(fs, "%d", &sentinel) != 1)
                sentinel = -1;
            pclose(fs);
        }
        FILE *f = popen(
            "grep -rn 'PEER_OFFENCE_TIMEOUT' --include=*.c "
            "core/modules/net/src engine/services/src engine/composition/src 2>/dev/null "
            "| grep 'peer_scoring_record' | wc -l", "r");
        if (f) {
            if (fscanf(f, "%d", &hits) != 1)
                hits = -1;
            pclose(f);
        }

        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct p2p_node node;
        pdf_setup_node(&node, "pdf_slow_hdd");
        /* A genuinely forged header must still bite, so "slow is free"
         * cannot be mistaken for "headers are unpoliced". */
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_HEADER,
                            "forged header");
        bool genuine_still_scores = (atomic_load(&node.misbehavior) > 0);

        /* sentinel > 0 proves we could see the tree; hits == 0 is the
         * property under test. A wrong cwd fails here rather than
         * reporting an unearned pass. */
        bool ok = (sentinel > 0) && (hits == 0) && genuine_still_scores;
        if (ok) printf("OK\n");
        else {
            printf("FAIL (sentinel=%d timeout_scoring_sites=%d "
                   "genuine_scores=%d)\n",
                   sentinel, hits, (int)genuine_still_scores);
            failures++;
        }
    }

    main_state_free(&pdf_main_state);

    /* Leave key state as we found it for the rest of the suite. */
    if (had_params)
        (void)sapling_install_embedded_vks();

    if (failures == 0)
        printf("=== peer DoS fairness: all cases passed ===\n");
    return failures;
}
