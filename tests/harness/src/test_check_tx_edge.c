/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * test_check_tx_edge.c — NET-NEW consensus edge cases for the
 * structural transaction checks behind check_transaction() /
 * domain_consensus_check_transaction_structural().
 *
 * These complement (do NOT duplicate) test_domain_consensus_tx_structural.c,
 * which already covers the representative happy/sad shapes (empty vin,
 * empty vout, negative vout, vout > MAX_MONEY, vout-total overflow,
 * duplicate inputs, coinbase scriptSig 5/1/101, null prevout, version
 * floor, version-group-id, expiry threshold, valueBalance nonzero).
 *
 * The gaps pinned here are the BOUNDARY and CLASSIFICATION cases that a
 * single off-by-one or a comparison-operator regression would slip past
 * the existing tests:
 *
 *   1. vout == MAX_MONEY (exactly at the cap) is ACCEPTED   [> vs >=]
 *   2. coinbase scriptSig == 2 and == 100 (the inclusive bounds) ACCEPTED
 *   3. vout total == MAX_MONEY (sum exactly at the cap) ACCEPTED
 *      and vout total == MAX_MONEY+1 (one zatoshi over) REJECTED
 *   4. inputs that differ ONLY in prevout.n are NOT duplicates (accepted)
 *      — a hash-only dedup would false-reject this (a fork-causing bug)
 *   5. duplicate inputs at NON-adjacent positions (vin[0] vs vin[2])
 *      are caught — pins the all-pairs nested scan, not just neighbors
 *   6. a 1-vin tx with a NULL prevout is CLASSIFIED as coinbase: an
 *      out-of-range scriptSig yields "bad-cb-length", NOT
 *      "bad-txns-prevout-null" — pins the coinbase branch selection
 *   7. value_balance < -MAX_MONEY (with shielded io present, so the
 *      nonzero-without-shielded rule is bypassed) is REJECTED as
 *      "bad-txns-valuebalance-toolarge" — the lower range bound, which
 *      no existing test reaches.
 *
 * Every case invokes the REAL consensus function via BOTH the domain
 * entry point and the legacy check_transaction() wrapper and asserts
 * they agree byte-for-byte (ok bit + reject_reason + DoS score), so a
 * one-sided "improvement" still shouts. Pure: no UTXO, no clock, no RNG,
 * no network, no node process.
 */

#include "test/test_core.h"

#include "domain/consensus/tx_structural.h"
#include "validation/check_transaction.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "core/amount.h"
#include "core/uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTE_CHECK(name, expr) do { \
    printf("check_tx_edge: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a minimal non-coinbase tx: n_in inputs (each a distinct, non-null
 * prevout so dedup passes by default) and n_out outputs of `each_value`. */
static void cte_build_tx(struct transaction *tx, size_t n_in, size_t n_out,
                         int64_t each_value)
{
    transaction_init(tx);
    transaction_alloc(tx, n_in, n_out);
    for (size_t i = 0; i < n_in; i++) {
        uint256_set_null(&tx->vin[i].prevout.hash);
        tx->vin[i].prevout.hash.data[0] = (unsigned char)(i + 1);
        tx->vin[i].prevout.n = (uint32_t)i;
        tx->vin[i].sequence = 0xFFFFFFFEu;
        tx->vin[i].script_sig.size = 0;
    }
    for (size_t i = 0; i < n_out; i++) {
        tx->vout[i].value = each_value;
        tx->vout[i].script_pub_key.size = 0;
    }
    tx->lock_time = 0;
}

/* Build a minimal coinbase tx: 1 vin (null prevout), scriptSig of the
 * given size, 1 vout. */
static void cte_build_coinbase(struct transaction *tx, size_t scriptsig_size)
{
    transaction_init(tx);
    transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vin[0].script_sig.size = scriptsig_size;
    for (size_t i = 0; i < scriptsig_size &&
                       i < sizeof(tx->vin[0].script_sig.data); i++)
        tx->vin[0].script_sig.data[i] = 0;
    tx->vin[0].sequence = 0xFFFFFFFFu;
    tx->vout[0].value = 12 * COIN;
    tx->vout[0].script_pub_key.size = 0;
}

struct cte_legacy {
    bool ok;
    char reason[MAX_REJECT_REASON];
    int dos;
};

static struct cte_legacy cte_run_legacy(const struct transaction *tx)
{
    struct validation_state st;
    validation_state_init(&st);
    bool ok = check_transaction(tx, &st);
    struct cte_legacy v;
    v.ok = ok;
    v.dos = st.dos;
    strncpy(v.reason, st.reject_reason, sizeof(v.reason) - 1);
    v.reason[sizeof(v.reason) - 1] = '\0';
    return v;
}

struct cte_domain {
    bool ok;
    const char *reason; /* NULL on ok */
    int dos;
};

static struct cte_domain cte_run_domain(const struct transaction *tx)
{
    struct domain_consensus_tx_structural_failure f = {0};
    struct zcl_result r =
        domain_consensus_check_transaction_structural(
                tx, DOMAIN_TX_CTX_STANDALONE, &f);
    struct cte_domain v;
    v.ok = r.ok;
    v.reason = f.reject_reason;
    v.dos = f.dos;
    return v;
}

/* Domain and legacy must agree on ok + reason + dos. */
static bool cte_agree(const struct cte_domain *d, const struct cte_legacy *l)
{
    if (d->ok != l->ok) return false;
    if (d->ok) return true;
    const char *dr = d->reason ? d->reason : "";
    if (strcmp(dr, l->reason) != 0) return false;
    if (d->dos != l->dos) return false;
    return true;
}

int test_check_tx_edge(void)
{
    int failures = 0;

    /* === 1. vout == MAX_MONEY exactly: ACCEPTED (the cap is inclusive). === */
    {
        struct transaction tx;
        cte_build_tx(&tx, 1, 1, MAX_MONEY); /* single output AT the cap */
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("vout == MAX_MONEY: accepted (boundary inclusive)",
                  d.ok && l.ok);
        CTE_CHECK("vout == MAX_MONEY: verdicts agree", cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 2a. coinbase scriptSig == 2 (low inclusive bound): ACCEPTED. === */
    {
        struct transaction tx;
        cte_build_coinbase(&tx, 2);
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("coinbase scriptSig == 2: accepted (low bound inclusive)",
                  d.ok && l.ok);
        CTE_CHECK("coinbase scriptSig == 2: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 2b. coinbase scriptSig == 100 (high inclusive bound): ACCEPTED. === */
    {
        struct transaction tx;
        cte_build_coinbase(&tx, 100);
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("coinbase scriptSig == 100: accepted (high bound inclusive)",
                  d.ok && l.ok);
        CTE_CHECK("coinbase scriptSig == 100: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 3a. vout running total == MAX_MONEY exactly: ACCEPTED. ===
     * Two outputs summing to exactly MAX_MONEY (each <= MAX_MONEY).  */
    {
        struct transaction tx;
        cte_build_tx(&tx, 1, 2, 0);
        tx.vout[0].value = MAX_MONEY - 1;
        tx.vout[1].value = 1; /* sum == MAX_MONEY */
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("vout total == MAX_MONEY: accepted (sum boundary inclusive)",
                  d.ok && l.ok);
        CTE_CHECK("vout total == MAX_MONEY: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 3b. vout running total == MAX_MONEY + 1: REJECTED. ===
     * One zatoshi over the cap — neither single output exceeds MAX_MONEY,
     * so only the running-total guard can catch this.                 */
    {
        struct transaction tx;
        cte_build_tx(&tx, 1, 2, 0);
        tx.vout[0].value = MAX_MONEY;
        tx.vout[1].value = 1; /* sum == MAX_MONEY + 1 */
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("vout total == MAX_MONEY+1: rejected txouttotal-toolarge",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-txns-txouttotal-toolarge") == 0);
        CTE_CHECK("vout total == MAX_MONEY+1: dos=100", d.dos == 100);
        CTE_CHECK("vout total == MAX_MONEY+1: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 4. inputs differing ONLY in prevout.n are NOT duplicates. ===
     * Same prevout hash, distinct index n. A hash-only dedup would
     * false-reject these legitimate inputs and could fork the chain.  */
    {
        struct transaction tx;
        cte_build_tx(&tx, 2, 1, 1 * COIN);
        /* Force both inputs onto the same (non-null) prevout hash but
         * keep distinct output indices. */
        uint256_set_null(&tx.vin[0].prevout.hash);
        tx.vin[0].prevout.hash.data[0] = 0x42;
        tx.vin[1].prevout.hash = tx.vin[0].prevout.hash;
        tx.vin[0].prevout.n = 0;
        tx.vin[1].prevout.n = 1; /* differs only in n */
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("same prevout hash, differing n: accepted (not a dup)",
                  d.ok && l.ok);
        CTE_CHECK("same prevout hash, differing n: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 5. duplicate inputs at NON-adjacent positions (vin[0] vs vin[2]). ===
     * The dup scan must compare all pairs, not just neighbors.        */
    {
        struct transaction tx;
        cte_build_tx(&tx, 3, 1, 1 * COIN);
        /* vin[1] stays distinct; vin[2] duplicates vin[0]. */
        tx.vin[2].prevout = tx.vin[0].prevout;
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("non-adjacent dup inputs: rejected inputs-duplicate",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-txns-inputs-duplicate") == 0);
        CTE_CHECK("non-adjacent dup inputs: dos=100", d.dos == 100);
        CTE_CHECK("non-adjacent dup inputs: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 6. 1-vin tx with a NULL prevout is CLASSIFIED as coinbase. ===
     * transaction_is_coinbase() == (num_vin==1 && null prevout). A
     * single-input null-prevout tx with an out-of-range scriptSig must
     * therefore fail with "bad-cb-length" (coinbase branch) and NOT
     * "bad-txns-prevout-null" (non-coinbase branch). This pins the
     * branch selection that decides which whole rule-set applies.     */
    {
        struct transaction tx;
        cte_build_tx(&tx, 1, 1, 1 * COIN);
        outpoint_set_null(&tx.vin[0].prevout); /* now looks like coinbase */
        tx.vin[0].script_sig.size = 0;         /* < 2 -> bad-cb-length */
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("1-vin null prevout: classified coinbase -> bad-cb-length",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-cb-length") == 0);
        CTE_CHECK("1-vin null prevout: NOT bad-txns-prevout-null",
                  !(d.reason && strcmp(d.reason, "bad-txns-prevout-null") == 0));
        CTE_CHECK("1-vin null prevout: verdicts agree", cte_agree(&d, &l));
        transaction_free(&tx);
    }

    /* === 7. value_balance < -MAX_MONEY (with shielded io present). ===
     * The nonzero-without-shielded rule (covered elsewhere) only fires
     * when there is NO shielded io. By attaching one shielded spend we
     * bypass it and reach the unconditional range guard, pinning the
     * lower bound value_balance < -MAX_MONEY -> bad-txns-valuebalance-
     * toolarge, which no existing test exercises.                     */
    {
        struct transaction tx;
        cte_build_tx(&tx, 1, 1, 1 * COIN);
        tx.v_shielded_spend =
            calloc(1, sizeof(*tx.v_shielded_spend)); /* freed by transaction_free */
        tx.num_shielded_spend = tx.v_shielded_spend ? 1 : 0;
        tx.value_balance = -MAX_MONEY - 1; /* one below the lower bound */
        struct cte_domain d = cte_run_domain(&tx);
        struct cte_legacy l = cte_run_legacy(&tx);
        CTE_CHECK("value_balance < -MAX_MONEY: rejected valuebalance-toolarge",
                  !d.ok && d.reason &&
                  strcmp(d.reason, "bad-txns-valuebalance-toolarge") == 0);
        CTE_CHECK("value_balance < -MAX_MONEY: dos=100", d.dos == 100);
        CTE_CHECK("value_balance < -MAX_MONEY: verdicts agree",
                  cte_agree(&d, &l));
        transaction_free(&tx);
    }

    return failures;
}
