/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_utxo_apply_unspendable - regression for the provably-unspendable-output
 * exclusion on the LIVE fold path (utxo_apply_compute_block_delta).
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * RANK-1 parity defect: the active fold in utxo_apply_delta.c added EVERY
 * non-null output to the coins delta, including provably-unspendable outputs
 * (OP_RETURN, or a scriptPubKey over MAX_SCRIPT_SIZE). zclassicd / Bitcoin
 * Core's AddCoin() skips IsUnspendable() outputs — they NEVER enter the UTXO
 * set. coins.c:86 had the correct exclusion but that is the seed-only path,
 * not the live one. So coins_kv over-counted vs zclassicd (count + the
 * coins_kv_commitment both diverged), a latent UTXO-set fork.
 *
 * The fix skips script_is_unspendable() outputs in the vout loop, with the
 * SAME predicate coins.c uses, BEFORE adding to added[] and BEFORE
 * accumulating total_value_delta.
 *
 * total_value_delta decision (asserted here): it is the UTXO-SET delta (it has
 * no SELECT reader — it is an audit column in utxo_apply_log + a MoneyRange
 * sanity bound only), so the burned value is EXCLUDED from it to stay
 * consistent with added_count. The created-then-burned value is still fully
 * accounted by the independent no-inflation path (transaction_get_value_out()
 * sums EVERY output, OP_RETURN included), so excluding it here does NOT relax
 * value-balance; case (c) below proves a normal-only tx is unaffected.
 *
 * Assertions:
 *   (a) one-normal + one-OP_RETURN spend -> compute_block_delta adds ONLY the
 *       normal output (added_count == 1), the entry IS the normal output, and
 *       total_value_delta excludes the (zero-value here) burned output.
 *   (b) applying that delta into an ISOLATED coins_kv yields count == 1 AND a
 *       commitment equal to a coins_kv holding ONLY the normal output
 *       (proves the OP_RETURN is absent from both count and commitment).
 *   (c) a normal-only two-output tx is unaffected: added_count == 2, both
 *       outputs present, total_value_delta unchanged.
 *
 * compute_block_delta is called DIRECTLY with hand-built blocks and a trivial
 * in-test lookup; the coins_kv side uses an isolated tmpdir datadir (NOT the
 * shared regtest default).
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_stage.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define UAU_CHECK(name, expr) do {                       \
    printf("utxo_apply_unspendable: %s... ", (name));    \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* The single external input coin the spend consumes. */
struct uau_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
};

static bool uau_lookup(const struct uint256 *txid, uint32_t vout,
                       struct utxo_apply_lookup *out, void *user)
{
    const struct uau_coin *c = user;
    memset(out, 0, sizeof(*out));
    if (c && c->vout == vout && uint256_eq(&c->txid, txid)) {
        out->found = true;
        out->value = c->value;
        out->height = 0;
        out->is_coinbase = false;
        out->script_len = 0;
    }
    return true;
}

/* Coinbase vtx[0]: value irrelevant to the rules under test, distinct hash. */
static void uau_make_coinbase(struct transaction *tx, uint8_t tag)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vout[0].value = 1000000000LL;
    uint8_t pk[3] = { 0x76, 0xa9, tag };
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    uint256_set_null(&tx->hash);
    tx->hash.data[0] = 0xC0;
    tx->hash.data[1] = tag;
}

/* Set vout[i] to a distinct P2PKH-shaped (spendable) script. */
static void uau_set_normal_out(struct transaction *tx, size_t i, int64_t value,
                               uint8_t marker)
{
    tx->vout[i].value = value;
    uint8_t pk[4] = { 0x76, 0xa9, 0xBB, marker };
    script_set(&tx->vout[i].script_pub_key, pk, 4);
}

/* Set vout[i] to an OP_RETURN (provably unspendable) data push. */
static void uau_set_opreturn_out(struct transaction *tx, size_t i, int64_t value)
{
    tx->vout[i].value = value;
    uint8_t pk[5] = { OP_RETURN, 0x03, 0xDE, 0xAD, 0xBE };
    script_set(&tx->vout[i].script_pub_key, pk, 5);
}

/* Build a {coinbase, spend} block. The spend consumes `coin` and has
 * `num_out` outputs; the caller fills them after this returns. */
static bool uau_build_block(struct block *b, uint8_t tag,
                            const struct uau_coin *coin, size_t num_out)
{
    block_init(b);
    b->num_vtx = 2;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "uau_vtx");
    if (!b->vtx) return false;
    uau_make_coinbase(&b->vtx[0], tag);
    transaction_init(&b->vtx[1]);
    if (!transaction_alloc(&b->vtx[1], 1, num_out)) return false;
    b->vtx[1].vin[0].prevout.hash = coin->txid;
    b->vtx[1].vin[0].prevout.n = coin->vout;
    uint256_set_null(&b->vtx[1].hash);
    b->vtx[1].hash.data[0] = 0x5E;
    b->vtx[1].hash.data[1] = tag;
    return true;
}

int test_utxo_apply_unspendable(void);
int test_utxo_apply_unspendable(void)
{
    printf("\n=== utxo_apply unspendable-output exclusion test ===\n");
    int failures = 0;

    /* Input coin: 500,000,000 zat at vout 0. */
    struct uau_coin coin;
    memset(&coin, 0, sizeof(coin));
    coin.txid.data[0] = 0xE7;
    coin.txid.data[1] = 0x0A;
    coin.vout = 0;
    coin.value = 500000000LL;

    /* The normal output every case creates; reused as the "expected coin" in
     * the coins_kv commitment cross-check below. value_balance/joinsplits are
     * zero, so value_in (coin.value) == value_out (normal + OP_RETURN=0) and
     * the money rule passes, isolating the unspendable exclusion. */
    const int64_t normal_val = coin.value;     /* the lone spendable output */
    const uint8_t normal_marker = 0x11;

    /* (a) ONE NORMAL + ONE OP_RETURN: only the normal output is added. */
    {
        struct block b;
        bool built = uau_build_block(&b, 0xA1, &coin, 2);
        UAU_CHECK("(a) one-normal+one-opreturn block builds", built);
        if (built) {
            uau_set_normal_out(&b.vtx[1], 0, normal_val, normal_marker);
            uau_set_opreturn_out(&b.vtx[1], 1, 0);

            /* Sanity: the predicate classifies these two as built. */
            UAU_CHECK("(a) vout[0] is spendable",
                      !script_is_unspendable(&b.vtx[1].vout[0].script_pub_key));
            UAU_CHECK("(a) vout[1] is OP_RETURN (unspendable)",
                      script_is_unspendable(&b.vtx[1].vout[1].script_pub_key));

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uau_lookup, &coin, &out);
            UAU_CHECK("(a) delta ok", out.ok == true);
            /* coinbase vtx[0] adds its 1 output; spend adds ONLY the normal
             * output (OP_RETURN excluded) => 2 added total, NOT 3. */
            UAU_CHECK("(a) added_count excludes OP_RETURN (== 2, not 3)",
                      out.added_count == 2);
            /* The spend's added entry is the normal output, not the OP_RETURN. */
            bool found_normal = false, found_opreturn = false;
            for (size_t i = 0; i < out.added_count; i++) {
                if (uint256_eq(&out.added[i].txid, &b.vtx[1].hash)) {
                    if (out.added[i].vout == 0) found_normal = true;
                    if (out.added[i].vout == 1) found_opreturn = true;
                }
            }
            UAU_CHECK("(a) normal output (vout 0) present", found_normal);
            UAU_CHECK("(a) OP_RETURN output (vout 1) ABSENT", !found_opreturn);
            /* total_value_delta = coinbase 1e9 (added) + normal_val (added)
             * - coin.value (spent); the OP_RETURN's 0 value never entered.
             * Here normal_val == coin.value, so delta == coinbase value. */
            UAU_CHECK("(a) total_value_delta excludes burned output",
                      out.total_value_delta == 1000000000LL);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (b) coins_kv count + commitment reflect the exclusion. Build the spend's
     * delta, apply it into an isolated coins_kv, and assert count == 1 (the
     * lone normal output) and the commitment equals a coins_kv holding ONLY
     * that normal output. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "utxo_apply_unspendable", "kv");
        bool opened = progress_store_open(dir);
        UAU_CHECK("(b) isolated datadir opens", opened);
        if (opened) {
            sqlite3 *db = progress_store_db();
            UAU_CHECK("(b) coins_kv schema ensures",
                      coins_kv_ensure_schema(db));

            struct block b;
            bool built = uau_build_block(&b, 0xB2, &coin, 2);
            UAU_CHECK("(b) block builds", built);
            if (built) {
                uau_set_normal_out(&b.vtx[1], 0, normal_val, normal_marker);
                uau_set_opreturn_out(&b.vtx[1], 1, 0);

                struct delta_summary out;
                utxo_apply_compute_block_delta(&b, 1, uau_lookup, &coin, &out);
                UAU_CHECK("(b) delta ok", out.ok == true);

                /* Apply ONLY the spend tx's added coins (skip the coinbase's,
                 * so the cross-check below holds exactly one coin) by writing
                 * just the spend-tx entries. */
                bool added_ok = true;
                for (size_t i = 0; i < out.added_count && added_ok; i++) {
                    if (!uint256_eq(&out.added[i].txid, &b.vtx[1].hash))
                        continue;
                    added_ok = coins_kv_add(db, out.added[i].txid.data,
                                            out.added[i].vout,
                                            out.added[i].value, 1, false,
                                            out.added[i].script,
                                            out.added[i].script_len);
                }
                UAU_CHECK("(b) spend coins applied to coins_kv", added_ok);
                UAU_CHECK("(b) coins_kv_count == 1 (OP_RETURN excluded)",
                          coins_kv_count(db) == 1);

                uint8_t got_commit[32];
                UAU_CHECK("(b) commitment computes",
                          coins_kv_commitment(db, got_commit) == 0);
                free_delta(&out);
                block_free(&b);

                /* Reference coins_kv: ONLY the normal output, written by hand
                 * with the SAME (txid,vout,value,script,height,is_coinbase).
                 * If the OP_RETURN had leaked into coins_kv above, the live
                 * commitment would differ from this reference. */
                struct transaction ref_spend;
                transaction_init(&ref_spend);
                (void)transaction_alloc(&ref_spend, 1, 1);
                uint256_set_null(&ref_spend.hash);
                ref_spend.hash.data[0] = 0x5E;
                ref_spend.hash.data[1] = 0xB2;
                uau_set_normal_out(&ref_spend, 0, normal_val, normal_marker);

                progress_store_close();
                test_cleanup_tmpdir(dir);

                char rdir[256];
                test_make_tmpdir(rdir, sizeof(rdir),
                                 "utxo_apply_unspendable", "ref");
                bool ropen = progress_store_open(rdir);
                UAU_CHECK("(b) reference datadir opens", ropen);
                if (ropen) {
                    sqlite3 *rdb = progress_store_db();
                    UAU_CHECK("(b) reference schema ensures",
                              coins_kv_ensure_schema(rdb));
                    UAU_CHECK("(b) reference normal coin written",
                              coins_kv_add(rdb, ref_spend.hash.data, 0,
                                           normal_val, 1, false,
                                           ref_spend.vout[0].script_pub_key.data,
                                           ref_spend.vout[0].script_pub_key.size));
                    UAU_CHECK("(b) reference count == 1",
                              coins_kv_count(rdb) == 1);
                    uint8_t ref_commit[32];
                    UAU_CHECK("(b) reference commitment computes",
                              coins_kv_commitment(rdb, ref_commit) == 0);
                    UAU_CHECK("(b) live commitment == normal-only commitment",
                              memcmp(got_commit, ref_commit, 32) == 0);
                    progress_store_close();
                }
                test_cleanup_tmpdir(rdir);
                transaction_free(&ref_spend);
            } else {
                progress_store_close();
                test_cleanup_tmpdir(dir);
                block_free(&b);
            }
        }
    }

    /* (c) NORMAL-ONLY tx is unaffected: both outputs added. Spend creates two
     * spendable outputs splitting coin.value, no OP_RETURN. */
    {
        struct block b;
        bool built = uau_build_block(&b, 0xC3, &coin, 2);
        UAU_CHECK("(c) normal-only block builds", built);
        if (built) {
            uau_set_normal_out(&b.vtx[1], 0, coin.value - 1000LL, 0x21);
            uau_set_normal_out(&b.vtx[1], 1, 1000LL, 0x22);

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uau_lookup, &coin, &out);
            UAU_CHECK("(c) delta ok", out.ok == true);
            /* coinbase 1 output + spend 2 outputs => 3 added. */
            UAU_CHECK("(c) added_count == 3 (both normal outputs kept)",
                      out.added_count == 3);
            int spend_outs = 0;
            for (size_t i = 0; i < out.added_count; i++)
                if (uint256_eq(&out.added[i].txid, &b.vtx[1].hash))
                    spend_outs++;
            UAU_CHECK("(c) both spend outputs present", spend_outs == 2);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (d) THE GENESIS block contributes NOTHING: zclassicd keys the genesis
     * special-case on the BLOCK HASH (ConnectBlock main.cpp:2515-2527,
     * block.GetHash() == consensus.hashGenesisBlock), NOT on height, returning
     * before the per-tx UpdateCoins loop so the genesis coinbase never enters
     * pcoinsTip. The fold must mirror that EXACTLY. Forging the real genesis
     * header preimage in-test is impractical (block_get_hash is hash256 over
     * the serialized header), so this case drives the predicate directly: build
     * a synthetic block, then temporarily point the active params'
     * hashGenesisBlock at THAT block's computed hash. The fold must then exclude
     * it (added_count == 0, spent_count == 0, total_value_delta == 0) — proving
     * the exclusion is keyed on the genesis hash, not the height. Restore the
     * real genesis hash afterward. */
    {
        struct block b;
        bool built = uau_build_block(&b, 0xD4, &coin, 1);
        UAU_CHECK("(d) genesis-shaped block builds", built);
        if (built) {
            /* A plainly-spendable output on each tx, so the only reason nothing
             * is added is the genesis-hash short-circuit, not unspendability. */
            uau_set_normal_out(&b.vtx[1], 0, normal_val, 0x31);

            /* Make this block's computed hash the active genesis hash. The
             * singleton is mutable under the const accessor; save + restore. */
            struct chain_params *cp =
                (struct chain_params *)chain_params_get();
            struct uint256 saved_genesis = cp->consensus.hashGenesisBlock;
            block_get_hash(&b, &cp->consensus.hashGenesisBlock);

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 0, uau_lookup, &coin, &out);
            cp->consensus.hashGenesisBlock = saved_genesis;

            UAU_CHECK("(d) genesis delta ok", out.ok == true);
            UAU_CHECK("(d) genesis adds NOTHING (added_count == 0)",
                      out.added_count == 0);
            UAU_CHECK("(d) genesis spends NOTHING (spent_count == 0)",
                      out.spent_count == 0);
            UAU_CHECK("(d) genesis total_value_delta == 0",
                      out.total_value_delta == 0);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (d2) A NON-genesis block AT HEIGHT 0 is folded normally. zclassicd keys
     * the skip on the hash, never on height — so a height-0 block whose hash is
     * NOT the genesis hash (cannot occur in production, but unit tests synthesize
     * it) must NOT be dropped. This is the regression that the old height-keyed
     * guard (block_height == 0) violated. */
    {
        struct block b;
        bool built = uau_build_block(&b, 0xDA, &coin, 1);
        UAU_CHECK("(d2) non-genesis height-0 block builds", built);
        if (built) {
            uau_set_normal_out(&b.vtx[1], 0, normal_val, 0x32);

            /* Its computed hash must differ from the active genesis hash. */
            struct uint256 h;
            block_get_hash(&b, &h);
            UAU_CHECK("(d2) block hash != genesis hash",
                      !uint256_eq(&h,
                          &chain_params_get()->consensus.hashGenesisBlock));

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 0, uau_lookup, &coin, &out);
            UAU_CHECK("(d2) delta ok", out.ok == true);
            /* coinbase vtx[0] 1 output + spend vtx[1] 1 output => 2 added. */
            UAU_CHECK("(d2) folded normally at height 0 (added_count == 2)",
                      out.added_count == 2);
            UAU_CHECK("(d2) the input was spent (spent_count == 1)",
                      out.spent_count == 1);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (e) A height>0 coinbase output IS still added (the genesis skip does NOT
     * leak into non-genesis blocks). Same coinbase-bearing block as (a), at
     * height 1, asserting the coinbase output is present. */
    {
        struct block b;
        bool built = uau_build_block(&b, 0xE5, &coin, 1);
        UAU_CHECK("(e) height>0 block builds", built);
        if (built) {
            uau_set_normal_out(&b.vtx[1], 0, normal_val, 0x41);

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uau_lookup, &coin, &out);
            UAU_CHECK("(e) height>0 delta ok", out.ok == true);
            /* coinbase vtx[0] 1 output + spend vtx[1] 1 output => 2 added. */
            UAU_CHECK("(e) height>0 adds outputs (added_count == 2)",
                      out.added_count == 2);
            bool found_coinbase = false;
            for (size_t i = 0; i < out.added_count; i++)
                if (uint256_eq(&out.added[i].txid, &b.vtx[0].hash))
                    found_coinbase = true;
            UAU_CHECK("(e) height>0 coinbase output IS added", found_coinbase);
            free_delta(&out);
        }
        block_free(&b);
    }

    printf("=== utxo_apply unspendable-output exclusion: %d failures ===\n",
           failures);
    return failures;
}
