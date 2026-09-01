/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Adversarial coverage of the deterministic simnet RAM mempool
 * (engine/modules/sim/src/simnet_mempool.c) — the P2P attack surface between wire
 * ingress and block inclusion. simnet_mempool_add() is the sim's
 * admission predicate: it structurally screens a transaction against the
 * live in-RAM coins view before the tx is eligible to be minted into the
 * next block by simnet_mempool_mint().
 *
 * This group hammers that admission layer with the hostile inputs a real
 * relay peer can send, and asserts each one is handled with the exact
 * typed reject reason the code actually returns. It is DISTINCT from:
 *   - test_simnet_doublespend / _chained_tx / _duplicate_input /
 *     _value_inflation / _empty_vin_vout / _input_value_range, which drive
 *     the BLOCK-level connect_block() path (simnet_mint_txs), not the
 *     mempool_add() boundary; and
 *   - test_simnet_txkit, which touches a few mempool reasons through the
 *     wallet helper but does not adversarially cover in-mempool conflict,
 *     no-RBF parity, immature-coinbase-at-admission, duplicate-input, the
 *     coinbase/empty-vin structural screens, orphan handling, or
 *     deterministic batch admission + conservation.
 *
 * ── Which REAL predicates the sim mempool ENFORCES at accept time ──────
 * simnet_mempool_add() mirrors these production AcceptToMemoryPool /
 * connect_block predicates:
 *   - coinbase-into-mempool rejection           (transaction_is_coinbase)
 *   - empty-vin structural rejection            (num_vin == 0)
 *   - transaction finality / nLockTime          (domain_consensus_tx_is_final,
 *                                                the SAME pure predicate
 *                                                contextual_check_tx uses)
 *   - output value range                        (value_out < 0 || !MoneyRange)
 *   - duplicate input within one tx             (outpoint_seen_in_tx)
 *   - in-mempool conflict / no-RBF              (outpoint_seen_in_mempool)
 *   - input coin present & unspent              (coins_is_available)
 *   - coinbase maturity                         (COINBASE_MATURITY, against
 *                                                next block height)
 *   - input value range + fee range + no value
 *     inflation (value_in >= value_out)         (MoneyRange / sum checks)
 *
 * ── Which real predicates the sim mempool SKIPS (documented, NOT bugs) ──
 * The sim mempool is a structural admission layer, not full relay policy.
 * It deliberately does NOT run: scriptSig / signature verification, sigops
 * limits, tx size / standardness, dust thresholds, a MINIMUM RELAY FEE
 * floor (there is no fee floor — any non-negative fee, including zero, is
 * admitted), nExpiryHeight expiry, or an ORPHAN POOL. A missing-parent tx
 * is rejected immediately as MISSING_INPUT rather than being held for a
 * later parent (see the orphan case below). These are simulator-scope
 * simplifications, not consensus divergences: every predicate the sim DOES
 * enforce matches production; the skipped ones are relay policy that lives
 * above consensus. This is asserted, not silently assumed.
 *
 * Determinism: the whole suite runs for a base seed and one derived alt
 * seed (env ZCL_SIMNET_MEMPOOL_SEED pins the base for replay). The seed
 * only varies tx content (scriptSig markers, fees) via a pure splitmix64 —
 * no wall clock, no entropy. The sim's own virtual block clock
 * (next_block_time, deterministic from simnet_init) supplies block nTime;
 * like test_simnet_doublespend / _chained_tx this group installs NO
 * seed_tape (a tape pinned to a past wall time would freeze
 * GetAdjustedTime while the block clock advances, tripping the
 * time-too-new header check once ~100 maturity blocks are minted). On ANY
 * failure the repro seed is printed.
 *
 * Per the harness contract (simnet.h): if a mint or an admission is
 * rejected unexpectedly, the fix is in THIS file's tx construction, never
 * in simnet_mempool.c or a consensus predicate.
 */

#include "test/test_core.h"
#include "validation/main_constants.h"

#include "sim/simnet.h"
#include "sim/simnet_mempool.h"
/* COINBASE_MATURITY, MAX_MONEY, MoneyRange come in transitively through the
 * simnet headers above (validation/main_constants.h, core/amount.h). */

#include <stdio.h>
#include <string.h>

#define MP_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Pure, seed-driven variation source: splitmix64. No globals, no clock. */
static uint64_t mp_mix(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* Build a transparent single-in / single-out spend of `in_txid`:`in_n`
 * paying `out_value` to a placeholder P2PKH-shaped script. `marker` varies
 * the scriptSig so distinct logical spends get distinct txids (identical
 * to ds_make_spend in test_simnet_doublespend.c). simnet admits at heights
 * covered by a synthetic checkpoint, so scriptSig content is never
 * verified — only outpoint linkage, coin availability, and value matter.
 * lock_time 0 + final sequence, so finality always passes here. */
static bool mp_make_spend(struct transaction *tx, const struct uint256 *in_txid,
                          uint32_t in_n, int64_t out_value, uint8_t marker)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *in_txid;
    tx->vin[0].prevout.n = in_n;
    uint8_t sig[] = { 0x00, marker };
    script_set(&tx->vin[0].script_sig, sig, sizeof(sig));
    tx->vin[0].sequence = 0xFFFFFFFF;
    tx->vout[0].value = out_value;
    uint8_t pk[] = { 0x76, 0xa9, 0x14 };
    script_set(&tx->vout[0].script_pub_key, pk, sizeof(pk));
    tx->lock_time = 0;
    transaction_compute_hash(tx);
    return true;
}

/* Mint a coinbase and mature it so its output is spendable through the
 * mempool's maturity predicate (next_height - coin.height >=
 * COINBASE_MATURITY). Returns the coinbase txid and its output value.
 * Mirrors the maturity setup in test_simnet_doublespend.c. */
static bool mp_matured_coinbase(struct simnet *s, struct uint256 *out_cb,
                                int64_t *out_value)
{
    if (!simnet_mint_coinbase(s, out_cb))
        return false;
    int cb_height = simnet_tip_height(s);
    /* tip = cb_height + MATURITY - 1  ->  next mint height satisfies
     * (next_height - cb_height) == COINBASE_MATURITY exactly. */
    if (!simnet_mint_to_height(s, cb_height + COINBASE_MATURITY - 1))
        return false;
    return simnet_coin_value(s, out_cb, 0, out_value);
}

/* ── Case: coinbase / empty-vin structural screens ────────────────────── */
static void mp_case_structural(struct simnet *s, int *failures_io)
{
    int failures = *failures_io;

    /* A coinbase-shaped tx (single null-prevout input) must never enter
     * the mempool — REJECT_COINBASE, checked before anything else. */
    struct transaction cb;
    transaction_init(&cb);
    MP_CHECK("structural: alloc coinbase-shaped tx",
             transaction_alloc(&cb, 1, 1));
    outpoint_set_null(&cb.vin[0].prevout);   /* -> transaction_is_coinbase */
    cb.vin[0].sequence = 0xFFFFFFFF;
    cb.vout[0].value = 1000;
    uint8_t pk[] = { 0x76, 0xa9, 0x14 };
    script_set(&cb.vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(&cb);

    struct simnet_mempool_result r;
    bool ok = simnet_mempool_add(s, &cb, &r);
    MP_CHECK("structural: coinbase tx is rejected",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_COINBASE);
    MP_CHECK("structural: coinbase rejection leaves mempool empty",
             simnet_mempool_size(s) == 0);
    transaction_free(&cb);

    /* A tx with zero inputs is structurally invalid — REJECT_MISSING_INPUT
     * (the num_vin==0 screen, distinct from an absent coin). */
    struct transaction empty;
    transaction_init(&empty);
    MP_CHECK("structural: alloc zero-input tx",
             transaction_alloc(&empty, 0, 1));
    empty.vout[0].value = 1000;
    script_set(&empty.vout[0].script_pub_key, pk, sizeof(pk));
    transaction_compute_hash(&empty);

    ok = simnet_mempool_add(s, &empty, &r);
    MP_CHECK("structural: zero-input tx is rejected as missing input",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_MISSING_INPUT);
    transaction_free(&empty);

    *failures_io = failures;
}

/* ── Case: in-mempool double spend + no-RBF parity ────────────────────── */
static void mp_case_conflict_norbf(struct simnet *s, uint64_t *rng,
                                   int *failures_io)
{
    int failures = *failures_io;

    struct uint256 cb;
    int64_t cbval = 0;
    MP_CHECK("conflict: fund matured coinbase",
             mp_matured_coinbase(s, &cb, &cbval) && cbval > 100000);
    int pre_height = simnet_tip_height(s);

    uint8_t m1 = (uint8_t)(mp_mix(rng) | 1);
    int64_t low_fee_out = cbval - 1000;      /* fee = 1000 */

    struct transaction first;
    MP_CHECK("conflict: build first spend of the coinbase outpoint",
             mp_make_spend(&first, &cb, 0, low_fee_out, m1));
    struct simnet_mempool_result r1;
    bool ok1 = simnet_mempool_add(s, &first, &r1);
    MP_CHECK("conflict: first spend is admitted",
             ok1 && r1.reason == SIMNET_MEMPOOL_OK &&
             simnet_mempool_size(s) == 1);
    struct uint256 first_txid = r1.txid;
    transaction_free(&first);

    /* Second tx spends the SAME outpoint. In ZCL/Zcash there is NO RBF:
     * a conflicting replacement is rejected regardless of the fee it
     * offers. Build it to pay a STRICTLY HIGHER fee (smaller output) to
     * prove the rejection is a no-RBF policy, not an accident of fee
     * ordering. Expected: REJECT_CONFLICT, mempool unchanged. */
    uint8_t m2 = (uint8_t)(mp_mix(rng) | 2);
    int64_t high_fee_out = cbval - 50000;    /* fee = 50000 > 1000 */
    struct transaction replacement;
    MP_CHECK("conflict: build higher-fee replacement of the same input",
             mp_make_spend(&replacement, &cb, 0, high_fee_out, m2) &&
             high_fee_out > 0);
    struct simnet_mempool_result r2;
    bool ok2 = simnet_mempool_add(s, &replacement, &r2);
    MP_CHECK("no-RBF: higher-fee replacement of an in-mempool input is REJECTED",
             !ok2 && r2.reason == SIMNET_MEMPOOL_REJECT_CONFLICT);
    MP_CHECK("no-RBF: rejected replacement does not grow or reorder the mempool",
             simnet_mempool_size(s) == 1);
    transaction_free(&replacement);

    /* Minting confirms the ORIGINAL (lower-fee) tx survived, not the
     * replacement — the no-RBF guarantee end-to-end. */
    MP_CHECK("no-RBF: mint the surviving mempool", simnet_mempool_mint(s));
    MP_CHECK("no-RBF: original tx's output is in the live UTXO view",
             simnet_coin_exists(s, &first_txid));
    MP_CHECK("no-RBF: coinbase outpoint is consumed exactly once",
             !simnet_coin_exists(s, &cb));
    MP_CHECK("no-RBF: tip advanced by exactly one block",
             simnet_tip_height(s) == pre_height + 1);

    *failures_io = failures;
}

/* ── Case: non-final nLockTime rejected via the finality predicate ────── */
static void mp_case_nonfinal(struct simnet *s, uint64_t *rng,
                             int *failures_io)
{
    int failures = *failures_io;

    struct uint256 cb;
    int64_t cbval = 0;
    MP_CHECK("nonfinal: fund matured coinbase",
             mp_matured_coinbase(s, &cb, &cbval) && cbval > 10000);

    uint8_t marker = (uint8_t)(mp_mix(rng) | 4);
    int64_t out_value = cbval - 2000;

    /* Height-based lock_time in the FUTURE (below LOCKTIME_THRESHOLD, so
     * interpreted as a block height) + a non-final input sequence. The
     * mempool checks finality at the NEXT block height (tip+1); the tx is
     * locked past it, so domain_consensus_tx_is_final() is false. */
    struct transaction locked;
    MP_CHECK("nonfinal: build otherwise-valid spend",
             mp_make_spend(&locked, &cb, 0, out_value, marker));
    locked.lock_time = (uint32_t)(simnet_tip_height(s) + 6);
    locked.vin[0].sequence = 0xFFFFFFFE;     /* not final -> locktime active */
    transaction_compute_hash(&locked);

    struct simnet_mempool_result r;
    bool ok = simnet_mempool_add(s, &locked, &r);
    MP_CHECK("nonfinal: future-locktime tx is rejected as nonfinal",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_NONFINAL);
    MP_CHECK("nonfinal: rejection leaves mempool empty",
             simnet_mempool_size(s) == 0);
    transaction_free(&locked);

    /* Attributable to finality ALONE: the same coin spent by a final
     * (lock_time 0) tx is admitted. Same input, same value. */
    struct transaction final_tx;
    MP_CHECK("nonfinal: build a final spend of the same coin",
             mp_make_spend(&final_tx, &cb, 0, out_value, marker));
    ok = simnet_mempool_add(s, &final_tx, &r);
    MP_CHECK("nonfinal: the final version of the same spend IS admitted",
             ok && r.reason == SIMNET_MEMPOOL_OK &&
             simnet_mempool_size(s) == 1);
    transaction_free(&final_tx);

    *failures_io = failures;
}

/* ── Case: absent / already-spent / immature-coinbase inputs ──────────── */
static void mp_case_bad_inputs(struct simnet *s, uint64_t *rng,
                               int *failures_io)
{
    int failures = *failures_io;

    /* (a) Non-existent outpoint: a spend of a coin that was never created
     * is rejected as MISSING_INPUT (this is ALSO the sim's orphan
     * behavior — no orphan pool; a missing parent is not held). */
    struct uint256 bogus;
    memset(bogus.data, 0xAB, sizeof(bogus.data));
    struct transaction absent;
    MP_CHECK("bad-inputs: build spend of a non-existent outpoint",
             mp_make_spend(&absent, &bogus, 0, 1000,
                           (uint8_t)(mp_mix(rng) | 8)));
    struct simnet_mempool_result r;
    bool ok = simnet_mempool_add(s, &absent, &r);
    MP_CHECK("bad-inputs: non-existent outpoint rejected as missing input",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_MISSING_INPUT);
    MP_CHECK("orphan: missing-parent tx is NOT held (no orphan pool)",
             simnet_mempool_size(s) == 0);
    transaction_free(&absent);

    /* (b) Already-spent outpoint: spend a matured coinbase (commits to a
     * block), then try to spend the SAME outpoint again — the coin is no
     * longer available in the view, so MISSING_INPUT. */
    struct uint256 cb;
    int64_t cbval = 0;
    MP_CHECK("bad-inputs: fund matured coinbase for already-spent case",
             mp_matured_coinbase(s, &cb, &cbval) && cbval > 10000);
    struct uint256 spent_txid;
    MP_CHECK("bad-inputs: first spend commits to a block",
             simnet_spend(s, &cb, 0, cbval - 3000, &spent_txid) &&
             !simnet_coin_exists(s, &cb));

    struct transaction respend;
    MP_CHECK("bad-inputs: build a second spend of the now-spent outpoint",
             mp_make_spend(&respend, &cb, 0, cbval - 4000,
                           (uint8_t)(mp_mix(rng) | 16)));
    ok = simnet_mempool_add(s, &respend, &r);
    MP_CHECK("bad-inputs: already-spent outpoint rejected as missing input",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_MISSING_INPUT);
    transaction_free(&respend);

    /* (c) Immature coinbase: mint a coinbase and try to spend it in the
     * VERY NEXT block, before COINBASE_MATURITY blocks have passed. The
     * mempool's own maturity screen fires: COINBASE_IMMATURE. */
    struct uint256 young_cb;
    MP_CHECK("bad-inputs: mint a fresh (immature) coinbase",
             simnet_mint_coinbase(s, &young_cb));
    int64_t young_val = 0;
    MP_CHECK("bad-inputs: read immature coinbase value",
             simnet_coin_value(s, &young_cb, 0, &young_val) &&
             young_val > 1000);
    struct transaction premature;
    MP_CHECK("bad-inputs: build spend of the immature coinbase",
             mp_make_spend(&premature, &young_cb, 0, young_val - 1000,
                           (uint8_t)(mp_mix(rng) | 32)));
    ok = simnet_mempool_add(s, &premature, &r);
    MP_CHECK("bad-inputs: immature-coinbase spend rejected as immature",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_COINBASE_IMMATURE);
    transaction_free(&premature);

    *failures_io = failures;
}

/* ── Case: value rules at the admission boundary ──────────────────────── */
static void mp_case_value_rules(struct simnet *s, uint64_t *rng,
                                int *failures_io)
{
    int failures = *failures_io;

    struct uint256 cb;
    int64_t cbval = 0;
    MP_CHECK("value: fund matured coinbase",
             mp_matured_coinbase(s, &cb, &cbval) && cbval > 100000);

    struct simnet_mempool_result r;

    /* (a) Negative output value -> VALUE_OVERFLOW (value_out < 0). */
    struct transaction neg;
    MP_CHECK("value: build negative-output tx",
             mp_make_spend(&neg, &cb, 0, -1, (uint8_t)(mp_mix(rng) | 3)));
    bool ok = simnet_mempool_add(s, &neg, &r);
    MP_CHECK("value: negative output value rejected as value_overflow",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW);
    transaction_free(&neg);

    /* (b) Above-MAX_MONEY output -> VALUE_OVERFLOW (!MoneyRange). */
    struct transaction huge;
    MP_CHECK("value: build over-MAX_MONEY-output tx",
             mp_make_spend(&huge, &cb, 0, MAX_MONEY + 1,
                           (uint8_t)(mp_mix(rng) | 5)));
    ok = simnet_mempool_add(s, &huge, &r);
    MP_CHECK("value: over-MAX_MONEY output rejected as value_overflow",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW);
    transaction_free(&huge);

    /* (c) Value inflation: output exceeds the input value -> VALUE_OVERFLOW
     * with the "input value is below output value" detail (no coin
     * creation from the mempool). */
    struct transaction inflate;
    MP_CHECK("value: build value-inflating tx (out > in)",
             mp_make_spend(&inflate, &cb, 0, cbval + 1,
                           (uint8_t)(mp_mix(rng) | 6)) && cbval + 1 <= MAX_MONEY);
    ok = simnet_mempool_add(s, &inflate, &r);
    MP_CHECK("value: value inflation rejected as value_overflow",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_VALUE_OVERFLOW);
    MP_CHECK("value: inflation detail names input-below-output",
             strstr(r.detail, "input value is below output value") != NULL);
    transaction_free(&inflate);

    /* (d) Duplicate input within one tx: two vin both spend the coinbase
     * outpoint -> DUPLICATE_INPUT (checked before the coin lookup for the
     * second input). */
    struct transaction dup;
    transaction_init(&dup);
    MP_CHECK("value: alloc two-input tx", transaction_alloc(&dup, 2, 1));
    dup.version = 1;
    for (int i = 0; i < 2; i++) {
        dup.vin[i].prevout.hash = cb;
        dup.vin[i].prevout.n = 0;
        uint8_t sig[] = { 0x00, (uint8_t)(0x40 + i) };
        script_set(&dup.vin[i].script_sig, sig, sizeof(sig));
        dup.vin[i].sequence = 0xFFFFFFFF;
    }
    dup.vout[0].value = cbval - 1000;
    uint8_t pk[] = { 0x76, 0xa9, 0x14 };
    script_set(&dup.vout[0].script_pub_key, pk, sizeof(pk));
    dup.lock_time = 0;
    transaction_compute_hash(&dup);
    ok = simnet_mempool_add(s, &dup, &r);
    MP_CHECK("value: duplicate input within one tx rejected as duplicate_input",
             !ok && r.reason == SIMNET_MEMPOOL_REJECT_DUPLICATE_INPUT);
    transaction_free(&dup);

    /* (e) NO FEE FLOOR: a valid spend paying ZERO fee (output == input)
     * is ADMITTED. Documents that the sim mempool enforces no minimum
     * relay fee — a skipped relay-policy predicate. */
    struct transaction zerofee;
    MP_CHECK("value: build zero-fee spend (out == in)",
             mp_make_spend(&zerofee, &cb, 0, cbval,
                           (uint8_t)(mp_mix(rng) | 7)));
    ok = simnet_mempool_add(s, &zerofee, &r);
    MP_CHECK("value: zero-fee spend is admitted (no minimum-fee floor)",
             ok && r.reason == SIMNET_MEMPOOL_OK && r.fee == 0 &&
             simnet_mempool_size(s) == 1);
    transaction_free(&zerofee);

    *failures_io = failures;
}

/* Build a deterministic batch of N independent spends from N matured
 * coinbases, admitting each. Fills `txids`/`values` with the admitted
 * txid and output value in FIFO order. Returns the number admitted (== N
 * on success). Shared by the batch case and its determinism replay. */
static size_t mp_admit_batch(struct simnet *s, uint64_t seed, size_t n,
                             struct uint256 *cbs, int64_t *cbvals,
                             struct uint256 *txids, int64_t *out_values,
                             int *failures_io)
{
    int failures = *failures_io;
    uint64_t rng = seed ^ 0xBA7C4;

    /* Mint n coinbases, then a single mint_to_height matures ALL of them. */
    int last_cb_height = 0;
    for (size_t i = 0; i < n; i++) {
        if (!simnet_mint_coinbase(s, &cbs[i])) {
            *failures_io = failures + 1;
            return i;
        }
        last_cb_height = simnet_tip_height(s);
    }
    if (!simnet_mint_to_height(s, last_cb_height + COINBASE_MATURITY - 1)) {
        *failures_io = failures + 1;
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (!simnet_coin_value(s, &cbs[i], 0, &cbvals[i])) {
            *failures_io = failures + 1;
            return i;
        }
    }

    size_t admitted = 0;
    for (size_t i = 0; i < n; i++) {
        int64_t fee = 1000 + (int64_t)(mp_mix(&rng) % 4000);
        int64_t out_value = cbvals[i] - fee;
        struct transaction tx;
        if (!mp_make_spend(&tx, &cbs[i], 0, out_value,
                           (uint8_t)(0x80 | (i & 0x3F)))) {
            *failures_io = failures + 1;
            return admitted;
        }
        struct simnet_mempool_result r;
        bool ok = simnet_mempool_add(s, &tx, &r);
        if (ok && r.reason == SIMNET_MEMPOOL_OK &&
            simnet_mempool_size(s) == i + 1) {
            txids[admitted] = r.txid;
            out_values[admitted] = out_value;
            admitted++;
        } else {
            failures++;
        }
        transaction_free(&tx);
    }
    *failures_io = failures;
    return admitted;
}

/* ── Case: large valid batch admits, mints, and conserves value ───────── */
static void mp_case_batch(uint64_t seed, int *failures_io)
{
    int failures = *failures_io;
    const size_t N = 12;

    struct uint256 cbs[12], txids[12], txids_replay[12];
    int64_t cbvals[12], out_values[12], out_values_replay[12];

    struct simnet sim;
    MP_CHECK("batch: simnet init", simnet_init(&sim));
    size_t admitted = mp_admit_batch(&sim, seed, N, cbs, cbvals,
                                     txids, out_values, &failures);
    MP_CHECK("batch: all valid txs admitted in FIFO order", admitted == N);
    MP_CHECK("batch: mempool holds the whole batch",
             simnet_mempool_size(&sim) == N);

    int pre_height = simnet_tip_height(&sim);
    MP_CHECK("batch: the whole held set mints in one block",
             simnet_mempool_mint(&sim));
    MP_CHECK("batch: tip advances by exactly one block",
             simnet_tip_height(&sim) == pre_height + 1);
    MP_CHECK("batch: mempool is drained after mint",
             simnet_mempool_size(&sim) == 0);

    bool all_present = true, inputs_consumed = true, conserved = true;
    for (size_t i = 0; i < N; i++) {
        int64_t v = 0;
        if (!simnet_coin_value(&sim, &txids[i], 0, &v) ||
            v != out_values[i])
            all_present = false, conserved = false;
        if (simnet_coin_exists(&sim, &cbs[i]))
            inputs_consumed = false;
    }
    MP_CHECK("batch: every admitted tx's output appears in the next block",
             all_present);
    MP_CHECK("batch: every spent coinbase input is consumed", inputs_consumed);
    MP_CHECK("batch: per-coin value conserved (output == input - fee)",
             conserved);
    simnet_free(&sim);

    /* Determinism: a fresh sim with the SAME seed admits an IDENTICAL
     * batch (same txids, same order) — the FIFO admission is a pure
     * function of the seed. */
    struct simnet sim2;
    MP_CHECK("batch-determinism: second simnet init", simnet_init(&sim2));
    size_t admitted2 = mp_admit_batch(&sim2, seed, N, cbs, cbvals,
                                      txids_replay, out_values_replay,
                                      &failures);
    bool same = (admitted2 == admitted);
    for (size_t i = 0; i < N && same; i++)
        if (!uint256_eq(&txids[i], &txids_replay[i]) ||
            out_values[i] != out_values_replay[i])
            same = false;
    MP_CHECK("batch-determinism: identical seed -> identical admitted batch",
             same);
    simnet_free(&sim2);

    *failures_io = failures;
}

/* Run the full adversarial suite for one seed. Each per-simnet case that
 * does not need a clean chain of its own shares a single sim; cases that
 * commit blocks (conflict/bad-inputs) run on their own sim to keep the
 * pre/post height assertions exact. */
static int mp_run_suite(uint64_t seed)
{
    int failures = 0;
    uint64_t rng = seed;

    printf("-- simnet_mempool_adv seed=0x%016llx --\n",
           (unsigned long long)seed);

    /* Structural screens: no committed blocks, share one sim. */
    {
        struct simnet sim;
        MP_CHECK("structural: simnet init", simnet_init(&sim));
        mp_case_structural(&sim, &failures);
        simnet_free(&sim);
    }
    /* In-mempool conflict + no-RBF (commits a block). */
    {
        struct simnet sim;
        MP_CHECK("conflict: simnet init", simnet_init(&sim));
        mp_case_conflict_norbf(&sim, &rng, &failures);
        simnet_free(&sim);
    }
    /* Non-final locktime. */
    {
        struct simnet sim;
        MP_CHECK("nonfinal: simnet init", simnet_init(&sim));
        mp_case_nonfinal(&sim, &rng, &failures);
        simnet_free(&sim);
    }
    /* Absent / already-spent / immature inputs (commits blocks). */
    {
        struct simnet sim;
        MP_CHECK("bad-inputs: simnet init", simnet_init(&sim));
        mp_case_bad_inputs(&sim, &rng, &failures);
        simnet_free(&sim);
    }
    /* Value rules at the boundary. */
    {
        struct simnet sim;
        MP_CHECK("value: simnet init", simnet_init(&sim));
        mp_case_value_rules(&sim, &rng, &failures);
        simnet_free(&sim);
    }
    /* Large valid batch + determinism replay. */
    mp_case_batch(seed, &failures);

    return failures;
}

int test_simnet_mempool_adv(void)
{
    printf("\n=== simnet mempool adversarial admission ===\n");
    int failures = 0;

    /* Base seed: env override for replay, else a fixed default. */
    uint64_t base_seed = 0x5EEDBEEFCAFE0001ULL;
    const char *env = getenv("ZCL_SIMNET_MEMPOOL_SEED");
    if (env && *env)
        base_seed = strtoull(env, NULL, 0);

    /* One alt seed derived deterministically from the base. */
    uint64_t alt = base_seed;
    (void)mp_mix(&alt);
    uint64_t seeds[2] = { base_seed, alt };

    for (int i = 0; i < 2; i++) {
        int f = mp_run_suite(seeds[i]);
        if (f != 0)
            printf("  !! %d failure(s) at seed 0x%016llx — "
                   "replay: ZCL_SIMNET_MEMPOOL_SEED=0x%016llx\n",
                   f, (unsigned long long)seeds[i],
                   (unsigned long long)base_seed);
        failures += f;
    }

    printf("=== simnet_mempool_adv: %d failures "
           "(base seed 0x%016llx) ===\n",
           failures, (unsigned long long)base_seed);
    return failures;
}
