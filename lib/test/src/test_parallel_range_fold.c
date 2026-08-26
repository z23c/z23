/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_parallel_range_fold — the differential oracle for the Parallel State
 * Compiler P0 core (app/jobs/src/psc_*.c).
 *
 * WHAT IT PROVES
 *   (1) EQUIVALENCE: fold a synthetic ~N-block chain (coinbases + cross-block
 *       spends + intra-block create-then-spend chains) two ways —
 *         serial  = utxo_apply_compute_block_delta (the PRODUCTION delta
 *                   builder) applied per height into a running coin map with the
 *                   documented adds-before-spends order (= what coins_kv holds);
 *         parallel= psc_compile_range (K extraction workers + S-shard join) —
 *       and assert the terminal transparent set is BIT-IDENTICAL: same SHA3 over
 *       the canonical (txid,vout) records (the exact encoder coins_kv_commitment
 *       uses), same coin count, same supply. Asserted INVARIANT under (K,S) for
 *       (1,2),(4,8),(8,16),(16,32). The serial oracle is INDEPENDENT of PSC's
 *       extraction, so any block-local predicate drift in PSC fails here.
 *   (2) NEGATIVES: the sharded join REFUSES each consensus-ordering violation
 *       with the right typed error — spend-before-create → spend_unknown_utxo,
 *       duplicate-outpoint / BIP30 → utxo_collision, spend-of-spent →
 *       spend_unknown_utxo — while accepting a legitimate create-spend-recreate.
 *   (3) MEASUREMENT: serial vs parallel us/block at K=4,8,16 over the fixture.
 *       NOTE: the fixture is in-RAM (no disk read, no per-coin durable write),
 *       so this measures the EXTRACTION+JOIN compute parallelism only; the
 *       production structural win (write-volume O(chain-churn)→O(terminal-set))
 *       is not exercised by an in-memory fixture and is asserted structurally in
 *       the design, not measured here.
 *
 * make t ONLY=parallel_range_fold
 */
#include "test/test_core.h"

#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/subsidy.h"
#include "coins/utxo_commitment.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "jobs/psc_range_fold.h"
#include "jobs/psc_internal.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_stage.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRF_CHECK(name, expr) do {                             \
    printf("  parallel_range_fold: %s... ", (name));           \
    if ((expr)) printf("OK\n");                                \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

/* ══════════════════════════════════════════════════════════════════════
 * Serial-oracle coin map (open-addressing, LIVE coins only). Backs the
 * utxo_apply_compute_block_delta lookup and holds the terminal serial set.
 * ══════════════════════════════════════════════════════════════════════ */

#define OM_CAP (1u << 20)   /* 1,048,576 slots; fixture live set << 0.5*cap */

struct om_slot {
    uint8_t  used;
    uint8_t  txid[32];
    uint32_t vout;
    int64_t  value;
    int32_t  height;
    uint8_t  is_coinbase;
    uint32_t script_len;
    uint8_t  script[64];
};

struct oracle_map {
    struct om_slot *s;
    size_t          live;
};

static uint64_t om_hash(const uint8_t txid[32], uint32_t vout)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < 32; i++) { h ^= txid[i]; h *= 1099511628211ULL; }
    for (int i = 0; i < 4; i++) { h ^= (uint8_t)(vout >> (8*i)); h *= 1099511628211ULL; }
    return h;
}

static bool om_init(struct oracle_map *m)
{
    m->s = zcl_calloc(OM_CAP, sizeof(*m->s), "oracle_map");
    m->live = 0;
    return m->s != NULL;
}
static void om_free(struct oracle_map *m) { free(m->s); m->s = NULL; }

static struct om_slot *om_probe(struct oracle_map *m, const uint8_t txid[32],
                                uint32_t vout, bool *found)
{
    size_t i = (size_t)(om_hash(txid, vout) & (OM_CAP - 1));
    for (size_t p = 0; p < OM_CAP; p++) {
        struct om_slot *s = &m->s[i];
        if (!s->used) { *found = false; return s; }
        if (s->vout == vout && memcmp(s->txid, txid, 32) == 0) {
            *found = true; return s;
        }
        i = (i + 1) & (OM_CAP - 1);
    }
    *found = false;
    return NULL;   /* table full — sized so this cannot happen for the fixture */
}

static void om_put(struct oracle_map *m, const uint8_t txid[32], uint32_t vout,
                   int64_t value, int32_t height, bool is_coinbase,
                   const uint8_t *script, uint32_t script_len)
{
    bool found = false;
    struct om_slot *s = om_probe(m, txid, vout, &found);
    if (!s) return;
    if (!found) { s->used = 1; memcpy(s->txid, txid, 32); s->vout = vout; m->live++; }
    s->value = value;
    s->height = height;
    s->is_coinbase = is_coinbase ? 1 : 0;
    uint32_t cp = script_len > sizeof(s->script) ? (uint32_t)sizeof(s->script)
                                                 : script_len;
    s->script_len = cp;
    if (cp) memcpy(s->script, script, cp);
}

/* Tombstone-free delete for open addressing: remove then re-insert the probe
 * run after the hole (Knuth 6.4 alg R). The fixture's load factor is tiny so
 * the run walks a handful of slots. */
static void om_del(struct oracle_map *m, const uint8_t txid[32], uint32_t vout)
{
    bool found = false;
    struct om_slot *s = om_probe(m, txid, vout, &found);
    if (!s || !found) return;   /* spend of absent coin is a no-op (matches coins_kv) */
    size_t i = (size_t)(s - m->s);
    m->s[i].used = 0;
    m->live--;
    size_t j = (i + 1) & (OM_CAP - 1);
    while (m->s[j].used) {
        struct om_slot moved = m->s[j];
        m->s[j].used = 0;
        m->live--;
        om_put(m, moved.txid, moved.vout, moved.value, moved.height,
               moved.is_coinbase, moved.script, moved.script_len);
        j = (j + 1) & (OM_CAP - 1);
    }
}

/* utxo_apply_lookup_fn over the oracle map (resolves cross-block prevouts). */
static bool oracle_lookup(const struct uint256 *txid, uint32_t vout,
                          struct utxo_apply_lookup *out, void *user)
{
    struct oracle_map *m = user;
    bool found = false;
    struct om_slot *s = om_probe(m, txid->data, vout, &found);
    memset(out, 0, sizeof(*out));
    if (!s || !found) { out->found = false; return true; }
    out->found = true;
    out->value = s->value;
    out->height = (uint32_t)s->height;
    out->is_coinbase = s->is_coinbase != 0;
    out->script_len = s->script_len;
    if (s->script_len) memcpy(out->script, s->script, s->script_len);
    return true;
}

/* Terminal digest of the serial map — the SAME canonical (txid,vout) SHA3
 * encoder psc_range_fold + coins_kv_commitment use. */
struct om_rec { uint8_t txid[32]; uint32_t vout; struct om_slot *s; };
static int om_rec_cmp(const void *a, const void *b)
{
    const struct om_rec *x = a, *y = b;
    int c = memcmp(x->txid, y->txid, 32);
    if (c) return c;
    return x->vout < y->vout ? -1 : x->vout > y->vout ? 1 : 0;
}
static bool oracle_digest(struct oracle_map *m, uint8_t sha3[32],
                          uint64_t *count, int64_t *supply)
{
    struct om_rec *recs = m->live ? zcl_malloc(m->live * sizeof(*recs),
                                               "oracle_recs") : NULL;
    if (m->live && !recs) return false;
    size_t n = 0;
    for (size_t i = 0; i < OM_CAP; i++) {
        if (!m->s[i].used) continue;
        memcpy(recs[n].txid, m->s[i].txid, 32);
        recs[n].vout = m->s[i].vout;
        recs[n].s = &m->s[i];
        n++;
    }
    qsort(recs, n, sizeof(*recs), om_rec_cmp);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    int64_t sup = 0;
    for (size_t i = 0; i < n; i++) {
        struct om_slot *s = recs[i].s;
        utxo_commitment_sha3_write_record(&ctx, s->txid, s->vout, s->value,
                                          s->script_len ? s->script : NULL,
                                          s->script_len, (uint32_t)s->height,
                                          s->is_coinbase);
        sup += s->value;
    }
    sha3_256_finalize(&ctx, sha3);
    free(recs);
    *count = n;
    *supply = sup;
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * Synthetic fixture chain
 * ══════════════════════════════════════════════════════════════════════ */

/* Generator-side unspent-pool entry. */
struct pool_coin { struct uint256 txid; uint32_t vout; int64_t value; };

struct fixture {
    struct block *blocks;   /* [0..n_blocks-1] correspond to heights 1..n_blocks */
    int           n_blocks;
};

/* A varied-but-deterministic 25-byte P2PKH-shaped scriptPubKey. */
static void prf_script(struct script *s, uint32_t salt)
{
    s->data[0] = 0x76; s->data[1] = 0xa9; s->data[2] = 0x14;
    for (int i = 0; i < 20; i++)
        s->data[3 + i] = (unsigned char)((salt >> (i % 24)) + i * 7 + 0x11);
    s->data[23] = 0x88; s->data[24] = 0xac;
    s->size = 25;
}

/* Build one transaction with the given inputs (prevouts) and outputs, computing
 * its content hash. is_coinbase => exactly one NULL-prevout input. */
static bool prf_build_tx(struct transaction *tx,
                         const struct outpoint *ins, size_t n_in,
                         const int64_t *out_vals, const uint32_t *out_salts,
                         size_t n_out)
{
    transaction_init(tx);
    tx->version = 1;
    if (!transaction_alloc(tx, n_in ? n_in : 1, n_out)) return false;
    if (n_in == 0) {
        /* coinbase: single null-prevout input (transaction_alloc set it null) */
        tx->vin[0].script_sig.data[0] = 0x51; /* OP_1, arbitrary */
        tx->vin[0].script_sig.size = 1;
    } else {
        for (size_t i = 0; i < n_in; i++) {
            tx->vin[i].prevout = ins[i];
            tx->vin[i].script_sig.size = 0;
        }
    }
    for (size_t i = 0; i < n_out; i++) {
        tx->vout[i].value = out_vals[i];
        prf_script(&tx->vout[i].script_pub_key, out_salts[i]);
    }
    transaction_compute_hash(tx);
    return true;
}

/* Push a fresh unspent coin into the generator pool. */
static bool pool_push(struct pool_coin **pool, size_t *n, size_t *cap,
                      const struct uint256 *txid, uint32_t vout, int64_t value)
{
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 256;
        struct pool_coin *np = zcl_realloc(*pool, nc * sizeof(**pool), "prf_pool");
        if (!np) return false;
        *pool = np; *cap = nc;
    }
    (*pool)[*n].txid = *txid;
    (*pool)[*n].vout = vout;
    (*pool)[*n].value = value;
    (*n)++;
    return true;
}

/* Build the fixture: heights 1..n_blocks. Each block has a coinbase; even
 * blocks spend an old pooled coin (cross-block); every third block adds an
 * intra-block create-then-spend chain (tx A creates O, tx B spends O). */
static bool build_fixture(struct fixture *fx, int n_blocks,
                          const struct chain_params *cp)
{
    memset(fx, 0, sizeof(*fx));
    fx->blocks = zcl_calloc((size_t)n_blocks, sizeof(struct block), "prf_blocks");
    if (!fx->blocks) return false;
    fx->n_blocks = n_blocks;

    struct pool_coin *pool = NULL; size_t np = 0, cap = 0;
    uint32_t salt = 1;
    bool ok = true;

    for (int h = 1; h <= n_blocks && ok; h++) {
        struct block *blk = &fx->blocks[h - 1];
        block_init(blk);
        blk->header.nTime = 1700000000u + (uint32_t)h;

        /* Collect this block's txs in a temp vector, then attach. */
        struct transaction txs[8];
        size_t ntx = 0;

        /* (0) coinbase */
        int64_t subsidy = get_block_subsidy(h, &cp->consensus);
        uint32_t cb_salt = salt++;
        if (!prf_build_tx(&txs[ntx], NULL, 0, &subsidy, &cb_salt, 1)) { ok = false; break; }
        struct uint256 cb_hash = txs[ntx].hash;
        ntx++;

        /* (1) cross-block spend on even heights. Guard on value >= 2 so the
         * fee-1 output stays positive (regtest subsidy halves every 150 blocks,
         * so high-height coins are small — a value-0 coin is left unspent, which
         * both folds treat identically). */
        if ((h % 2) == 0 && np > 0 && pool[np - 1].value >= 2) {
            struct pool_coin pc = pool[np - 1]; np--;   /* spend newest-ish */
            struct outpoint in = { .hash = pc.txid, .n = pc.vout };
            int64_t ov = pc.value - 1;                  /* fee 1 */
            uint32_t os = salt++;
            if (!prf_build_tx(&txs[ntx], &in, 1, &ov, &os, 1)) { ok = false; break; }
            ntx++;
        }

        /* (2) intra-block create-then-spend chain on every third height:
         * tx A spends a pooled coin and creates output O; tx B (later in THIS
         * block) spends O and creates the surviving leaf. O is created and
         * spent within the block → net absent, exercising the intra-block
         * create-then-spend path in both the serial builder and the join. */
        if ((h % 3) == 0 && np > 0 && pool[np - 1].value >= 3) {
            struct pool_coin pc = pool[np - 1]; np--;
            struct outpoint inA = { .hash = pc.txid, .n = pc.vout };
            int64_t oA = pc.value - 1; uint32_t sA = salt++;
            if (!prf_build_tx(&txs[ntx], &inA, 1, &oA, &sA, 1)) { ok = false; break; }
            struct uint256 aHash = txs[ntx].hash; ntx++;
            struct outpoint inB = { .hash = aHash, .n = 0 };
            int64_t oB = oA - 1; uint32_t sB = salt++;
            if (!prf_build_tx(&txs[ntx], &inB, 1, &oB, &sB, 1)) { ok = false; break; }
            ntx++;
        }

        /* Attach txs to the block (move — the block owns them now). */
        blk->vtx = zcl_calloc(ntx, sizeof(struct transaction), "prf_vtx");
        if (!blk->vtx) { for (size_t i = 0; i < ntx; i++) transaction_free(&txs[i]);
                         ok = false; break; }
        for (size_t i = 0; i < ntx; i++) blk->vtx[i] = txs[i];
        blk->num_vtx = ntx;

        /* Pool bookkeeping: the coinbase output is always live; every other
         * output is live UNLESS a LATER tx in this same block spends it. */
        if (!pool_push(&pool, &np, &cap, &cb_hash, 0, subsidy)) { ok = false; break; }
        for (size_t ti = 1; ti < ntx && ok; ti++) {
            struct transaction *t = &blk->vtx[ti];
            for (size_t vo = 0; vo < t->num_vout; vo++) {
                bool spent_here = false;
                for (size_t tj = ti + 1; tj < ntx && !spent_here; tj++) {
                    struct transaction *u = &blk->vtx[tj];
                    for (size_t vi = 0; vi < u->num_vin; vi++)
                        if (uint256_eq(&u->vin[vi].prevout.hash, &t->hash) &&
                            u->vin[vi].prevout.n == (uint32_t)vo) {
                            spent_here = true; break;
                        }
                }
                if (!spent_here &&
                    !pool_push(&pool, &np, &cap, &t->hash, (uint32_t)vo,
                               t->vout[vo].value)) { ok = false; break; }
            }
        }
    }

    free(pool);
    return ok;
}

static void free_fixture(struct fixture *fx)
{
    if (!fx->blocks) return;
    for (int i = 0; i < fx->n_blocks; i++) block_free(&fx->blocks[i]);
    free(fx->blocks);
    memset(fx, 0, sizeof(*fx));
}

/* PSC block provider: clone the fixture block for height (1-indexed). */
static bool fixture_provider(uint32_t height, struct block *blk, void *user)
{
    struct fixture *fx = user;
    if (height < 1 || (int)height > fx->n_blocks) return false;
    return block_clone(blk, &fx->blocks[height - 1]);
}

/* Serial fold: compute_block_delta per height into the oracle map, applying
 * adds-before-spends. Returns false if any block rejects (a fixture bug). */
static bool serial_fold(struct fixture *fx, struct oracle_map *m,
                        double *out_us)
{
    int64_t t0 = platform_time_monotonic_us();
    for (int h = 1; h <= fx->n_blocks; h++) {
        struct delta_summary sum;
        utxo_apply_compute_block_delta(&fx->blocks[h - 1], (uint32_t)h,
                                       oracle_lookup, m, &sum);
        if (!sum.ok) {
            printf("  [serial_fold] block %d rejected: status=%s kind=%s\n",
                   h, sum.status ? sum.status : "?",
                   sum.failure_kind ? sum.failure_kind : "?");
            free_delta(&sum);
            return false;
        }
        for (size_t i = 0; i < sum.added_count; i++)
            om_put(m, sum.added[i].txid.data, sum.added[i].vout,
                   sum.added[i].value, h, sum.added[i].is_coinbase,
                   sum.added[i].script, sum.added[i].script_len);
        for (size_t i = 0; i < sum.spent_count; i++)
            om_del(m, sum.spent[i].txid.data, sum.spent[i].vout);
        free_delta(&sum);
    }
    *out_us = (double)(platform_time_monotonic_us() - t0);
    return true;
}

/* ══════════════════════════════════════════════════════════════════════
 * (1) + (3) EQUIVALENCE and MEASUREMENT
 * ══════════════════════════════════════════════════════════════════════ */

static void hexstr(const uint8_t d[32], char out[65])
{
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2*i] = hx[d[i] >> 4]; out[2*i+1] = hx[d[i] & 15]; }
    out[64] = '\0';
}

static int prf_equivalence_and_measure(void)
{
    int failures = 0;
    const int N = 4000;
    printf("\n=== parallel_range_fold: (1) serial-vs-parallel equivalence + "
           "(3) measurement over a %d-block fixture ===\n", N);

    const struct chain_params *cp = chain_params_get();
    struct fixture fx;
    PRF_CHECK("fixture built", build_fixture(&fx, N, cp));
    if (!fx.blocks) return failures;

    struct oracle_map m;
    if (!om_init(&m)) { free_fixture(&fx); return ++failures; }

    double serial_us = 0;
    bool sok = serial_fold(&fx, &m, &serial_us);
    PRF_CHECK("serial fold accepted every block", sok);

    uint8_t ssha[32]; uint64_t scount = 0; int64_t ssup = 0;
    bool sdok = sok && oracle_digest(&m, ssha, &scount, &ssup);
    PRF_CHECK("serial terminal digest computed", sdok);
    char shex[65]; if (sdok) hexstr(ssha, shex);

    /* Parallel at several (K,S) — invariance + equality to serial. */
    static const int Ks[] = { 1, 4, 8, 16 };
    static const int Ss[] = { 2, 8, 16, 32 };
    struct psc_range_result first = {0};
    bool have_first = false;

    printf("\n  %-6s %-6s %-14s %-12s %-12s %-10s\n",
           "K", "S", "events", "extract_us", "join_us", "us/blk");
    for (size_t i = 0; i < sizeof(Ks)/sizeof(Ks[0]); i++) {
        struct psc_range_result r = {0};
        bool ran = psc_compile_range(1, (uint32_t)N, Ks[i], Ss[i],
                                     fixture_provider, &fx, &r);
        char name[96];
        snprintf(name, sizeof(name), "PSC compiled cleanly (K=%d,S=%d)",
                 Ks[i], Ss[i]);
        PRF_CHECK(name, ran && r.ok);
        if (!ran || !r.ok) continue;

        printf("  %-6d %-6d %-14llu %-12.0f %-12.0f %-10.3f\n",
               Ks[i], Ss[i], (unsigned long long)r.events_total,
               r.extract_us, r.join_us, r.total_us / (double)N);

        if (sdok) {
            char phex[65]; hexstr(r.terminal_sha3, phex);
            snprintf(name, sizeof(name), "terminal SHA3 == serial (K=%d,S=%d)",
                     Ks[i], Ss[i]);
            PRF_CHECK(name, strcmp(phex, shex) == 0);
            if (strcmp(phex, shex) != 0)
                printf("    >> serial=%s parallel=%s\n", shex, phex);
            snprintf(name, sizeof(name), "coin count == serial (K=%d,S=%d)",
                     Ks[i], Ss[i]);
            PRF_CHECK(name, r.terminal_count == scount);
            snprintf(name, sizeof(name), "supply == serial (K=%d,S=%d)",
                     Ks[i], Ss[i]);
            PRF_CHECK(name, r.terminal_supply == ssup);
        }
        if (!have_first) { first = r; have_first = true; }
        else {
            char name2[64];
            snprintf(name2, sizeof(name2),
                     "(K=%d,S=%d) invariant vs first (K,S)", Ks[i], Ss[i]);
            PRF_CHECK(name2,
                      memcmp(first.terminal_sha3, r.terminal_sha3, 32) == 0 &&
                      first.terminal_count == r.terminal_count &&
                      first.terminal_supply == r.terminal_supply);
        }
    }

    printf("\n  MEASUREMENT (in-RAM fixture; measures extraction+join compute "
           "parallelism, NOT production write-volume):\n");
    printf("    serial fold      : %.3f us/blk (%.1f blk/s), %llu terminal coins\n",
           serial_us / (double)N,
           serial_us > 0 ? (double)N * 1e6 / serial_us : 0.0,
           (unsigned long long)scount);

    /* FOLD-RATE REGRESSION FLOOR — "sync stays FAST" enshrined.
     * The tail fold is O(1) work per block (constant-cost delta apply, no
     * pprev-walk / no H* recompute). If a regression reintroduces an
     * O(chain)/O(chain^2) per-block term (see
     * docs/work/refold-fold-rate-bottlenecks.md), us/blk explodes and this
     * trips. The floor is set GENEROUSLY (5000 us/blk => >200 blk/s on this
     * in-RAM fixture, orders of magnitude above the observed ~sub-us/blk and
     * well clear of machine load jitter) so it fires ONLY on an algorithmic
     * regression, never on a loaded box. */
    {
        double us_per_blk = serial_us / (double)N;
        const double FLOOR_US_PER_BLK = 5000.0;
        char rname[128];
        snprintf(rname, sizeof(rname),
                 "serial fold rate under floor (%.3f < %.0f us/blk)",
                 us_per_blk, FLOOR_US_PER_BLK);
        PRF_CHECK(rname, us_per_blk < FLOOR_US_PER_BLK);
    }

    free_fixture(&fx);
    om_free(&m);
    return failures;
}

/* ══════════════════════════════════════════════════════════════════════
 * (2) NEGATIVES — join refuses each ordering violation with a typed error
 * ══════════════════════════════════════════════════════════════════════ */

/* Serial parallel-for so the negatives drive psc_join directly without the
 * production worker pool (the join logic is what is under test). */
static void serial_pf(int n_items, int n_workers,
                      void (*fn)(int item, void *ctx), void *ctx)
{
    (void)n_workers;
    for (int i = 0; i < n_items; i++) fn(i, ctx);
}

static struct uint256 mk_txid(uint8_t tag)
{
    struct uint256 t; memset(&t, 0, sizeof(t)); t.data[0] = tag; t.data[31] = 0xAB;
    return t;
}

/* Run psc_join over `e`, returning ok + reject + terminal count. */
static bool run_join(struct psc_events *e, char reject[48], int32_t *rh,
                     size_t *count)
{
    struct psc_coin *coins = NULL; size_t n = 0;
    bool ok = psc_join(e->ev, e->n, e->scripts, /*S*/4, /*K*/2, serial_pf,
                       &coins, &n, reject, rh);
    if (count) *count = n;
    free(coins);
    return ok;
}

static int prf_negatives(void)
{
    int failures = 0;
    printf("\n=== parallel_range_fold: (2) join refuses consensus-ordering "
           "violations with typed errors ===\n");
    uint8_t script[25]; memset(script, 0x51, sizeof(script));
    struct uint256 X = mk_txid(0x01);

    /* (a) spend-before-create → spend_unknown_utxo */
    {
        struct psc_events e; psc_events_init(&e);
        psc_events_add_spend(&e, X.data, 0, 5, psc_seq_make(5, 1, 0));
        char rej[48] = {0}; int32_t rh = -1; size_t cnt = 0;
        bool ok = run_join(&e, rej, &rh, &cnt);
        PRF_CHECK("spend-before-create refused",
                  !ok && strcmp(rej, "spend_unknown_utxo") == 0);
        psc_events_free(&e);
    }

    /* (b) duplicate outpoint / BIP30 → utxo_collision */
    {
        struct psc_events e; psc_events_init(&e);
        psc_events_add_create(&e, X.data, 0, 100, 3, false, script,
                              sizeof(script), psc_seq_make(3, 0, 0));
        psc_events_add_create(&e, X.data, 0, 100, 7, false, script,
                              sizeof(script), psc_seq_make(7, 0, 0));
        char rej[48] = {0}; int32_t rh = -1; size_t cnt = 0;
        bool ok = run_join(&e, rej, &rh, &cnt);
        PRF_CHECK("duplicate-outpoint (BIP30) refused",
                  !ok && strcmp(rej, "utxo_collision") == 0);
        psc_events_free(&e);
    }

    /* (c) spend-of-spent (double spend) → spend_unknown_utxo */
    {
        struct psc_events e; psc_events_init(&e);
        psc_events_add_create(&e, X.data, 0, 100, 2, false, script,
                              sizeof(script), psc_seq_make(2, 0, 0));
        psc_events_add_spend(&e, X.data, 0, 4, psc_seq_make(4, 1, 0));
        psc_events_add_spend(&e, X.data, 0, 6, psc_seq_make(6, 1, 0));
        char rej[48] = {0}; int32_t rh = -1; size_t cnt = 0;
        bool ok = run_join(&e, rej, &rh, &cnt);
        PRF_CHECK("spend-of-spent (double spend) refused",
                  !ok && strcmp(rej, "spend_unknown_utxo") == 0);
        psc_events_free(&e);
    }

    /* (d) legitimate create-spend-recreate → accepted, terminal live (1 coin) */
    {
        struct psc_events e; psc_events_init(&e);
        psc_events_add_create(&e, X.data, 0, 100, 2, false, script,
                              sizeof(script), psc_seq_make(2, 0, 0));
        psc_events_add_spend(&e, X.data, 0, 4, psc_seq_make(4, 1, 0));
        psc_events_add_create(&e, X.data, 0, 100, 8, false, script,
                              sizeof(script), psc_seq_make(8, 0, 0));
        char rej[48] = {0}; int32_t rh = -1; size_t cnt = 0;
        bool ok = run_join(&e, rej, &rh, &cnt);
        PRF_CHECK("create-spend-recreate accepted (terminal live)",
                  ok && cnt == 1);
        psc_events_free(&e);
    }

    return failures;
}

int test_parallel_range_fold(void);
int test_parallel_range_fold(void)
{
    int failures = 0;
    printf("\n=== test_parallel_range_fold: Parallel State Compiler P0 core "
           "(order-independent range fold) ===\n");

    /* The fixture is regtest (fCoinbaseMustBeProtected=false, so coinbase
     * outputs spend to transparent; deterministic subsidy). The parallel
     * harness sets CHAIN_MAIN before each group — override here. */
    chain_params_select(CHAIN_REGTEST);

    failures += prf_equivalence_and_measure();
    failures += prf_negatives();

    chain_params_select(CHAIN_MAIN);
    printf("=== test_parallel_range_fold complete: %d failure(s) ===\n",
           failures);
    return failures;
}
