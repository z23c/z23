/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for engine/services/mempool_limits.
 *
 * Every case builds a fresh `struct tx_mempool`, populates it
 * with hand-crafted fake transactions (size and fee controlled
 * per-test), and drives the service synchronously. The only
 * lifecycle test starts and immediately stops the expire thread
 * to prove start()/stop() don't leak or hang — it doesn't wait
 * for a real tick.
 *
 * Double-spend note: `tx_mempool_add_unchecked` rejects adds
 * whose inputs are already present in the pool, so every test
 * tx gets a unique prevout derived from its index.
 */

#include "test/test_core.h"
#include "services/mempool_limits.h"
#include "validation/txmempool.h"
#include "event/event.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Fake clock ─────────────────────────────────────────────── */

static _Atomic int64_t g_fake_now;

static int64_t mlt_fake_clock(void)
{
    return atomic_load(&g_fake_now);
}

/* ── Event observer ─────────────────────────────────────────── */

static _Atomic int g_ev_evict;
static _Atomic int g_ev_expire;

static void mlt_ev_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_MEMPOOL_EVICT)  atomic_fetch_add(&g_ev_evict,  1);
    if (type == EV_MEMPOOL_EXPIRE) atomic_fetch_add(&g_ev_expire, 1);
}

static void mlt_install_observer(void)
{
    event_clear_observers(EV_MEMPOOL_EVICT);
    event_clear_observers(EV_MEMPOOL_EXPIRE);
    atomic_store(&g_ev_evict,  0);
    atomic_store(&g_ev_expire, 0);
    event_observe(EV_MEMPOOL_EVICT,  mlt_ev_observer, NULL);
    event_observe(EV_MEMPOOL_EXPIRE, mlt_ev_observer, NULL);
}

/* ── Test tx builder ────────────────────────────────────────── */

/* Fill a transaction with `num_vin`/`num_vout` synthetic inputs
 * whose prevouts are unique by byte-prefix (taken from `seed`).
 * The fee+time are attached at the entry level. */
static void mlt_build_tx(struct transaction *tx, unsigned seed,
                         int num_vin, int num_vout, int64_t amount)
{
    transaction_init(tx);
    transaction_alloc(tx, num_vin, num_vout);
    for (int i = 0; i < num_vin; i++) {
        memset(tx->vin[i].prevout.hash.data, 0, 32);
        /* Encode seed + i into first 4 bytes so each prevout is unique. */
        tx->vin[i].prevout.hash.data[0] = (unsigned char)(seed & 0xFF);
        tx->vin[i].prevout.hash.data[1] = (unsigned char)((seed >> 8) & 0xFF);
        tx->vin[i].prevout.hash.data[2] = (unsigned char)((seed >> 16) & 0xFF);
        tx->vin[i].prevout.hash.data[3] = (unsigned char)(i & 0xFF);
        tx->vin[i].prevout.n = (uint32_t)i;
        tx->vin[i].sequence = 0xFFFFFFFF;
    }
    for (int i = 0; i < num_vout; i++) {
        tx->vout[i].value = amount;
    }
    tx->lock_time = 0;
    transaction_compute_hash(tx);
}

/* Add a tx with the given fee + timestamp. Returns tx_size on
 * success, 0 on failure. Frees the entry but leaves `tx`
 * ownership to the caller (it may need the hash for assertions). */
static size_t mlt_add(struct tx_mempool *pool, struct transaction *tx,
                      int64_t fee, int64_t time_unix)
{
    struct mempool_entry entry;
    mempool_entry_init(&entry, tx, fee, time_unix, 1e6, 100,
                       true, false, 0);
    bool ok = tx_mempool_add_unchecked(pool, &tx->hash, &entry);
    size_t sz = entry.tx_size;
    mempool_entry_free(&entry);
    return ok ? sz : 0;
}

/* ── Tests ──────────────────────────────────────────────────── */

int test_mempool_limits(void);

int test_mempool_limits(void)
{
    int failures = 0;
    mlt_install_observer();

    /* ── 1. defaults populate from env-aware config ────────── */
    printf("mempool_limits: config defaults... ");
    {
        struct mempool_limits_config cfg;
        mempool_limits_config_defaults(&cfg);
        bool ok = cfg.max_bytes      == MEMPOOL_LIMITS_DEFAULT_MAX_BYTES;
        ok = ok && cfg.max_tx_count  == MEMPOOL_LIMITS_DEFAULT_MAX_TX_COUNT;
        ok = ok && cfg.expiry_seconds == MEMPOOL_LIMITS_DEFAULT_EXPIRY_SEC;
        ok = ok && cfg.min_relay_fee_zat == MEMPOOL_LIMITS_DEFAULT_MIN_RELAY;
        ok = ok && cfg.tick_seconds  == MEMPOOL_LIMITS_DEFAULT_TICK_SEC;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. env overrides ─────────────────────────────────── */
    printf("mempool_limits: env override... ");
    {
        setenv("ZCL_MEMPOOL_MAX_BYTES",   "1048576",  1);
        setenv("ZCL_MEMPOOL_MAX_TXS",     "42",       1);
        setenv("ZCL_MEMPOOL_EXPIRY_SECONDS", "3600",  1);
        setenv("ZCL_MIN_RELAY_FEE_ZAT",   "500",      1);
        setenv("ZCL_MEMPOOL_LIMITS_TICK_SEC", "5",    1);
        struct mempool_limits_config cfg;
        mempool_limits_config_defaults(&cfg);
        bool ok = cfg.max_bytes        == 1048576;
        ok = ok && cfg.max_tx_count    == 42;
        ok = ok && cfg.expiry_seconds  == 3600;
        ok = ok && cfg.min_relay_fee_zat == 500;
        ok = ok && cfg.tick_seconds    == 5;
        unsetenv("ZCL_MEMPOOL_MAX_BYTES");
        unsetenv("ZCL_MEMPOOL_MAX_TXS");
        unsetenv("ZCL_MEMPOOL_EXPIRY_SECONDS");
        unsetenv("ZCL_MIN_RELAY_FEE_ZAT");
        unsetenv("ZCL_MEMPOOL_LIMITS_TICK_SEC");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 3. enforce: no-op when under caps ─────────────────── */
    printf("mempool_limits: enforce no-op when under caps... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct transaction tx[3];
        for (int i = 0; i < 3; i++) {
            mlt_build_tx(&tx[i], 0x100 + i, 1, 1, (int64_t)(i + 1) * COIN_VALUE);
            mlt_add(&pool, &tx[i], 1000, 1700000000);
        }
        mempool_limits_reset_stats();
        atomic_store(&g_ev_evict, 0);
        struct mempool_limits_config cfg = {0};
        cfg.max_bytes = 1000000;
        cfg.max_tx_count = 100;
        int evicted = mempool_limits_enforce(&pool, &cfg);
        bool ok = evicted == 0 && tx_mempool_size(&pool) == 3;
        ok = ok && atomic_load(&g_ev_evict) == 0;
        struct mempool_limits_stats st;
        mempool_limits_stats_snapshot(&st);
        ok = ok && st.enforce_calls == 1 && st.evicted_total == 0;

        for (int i = 0; i < 3; i++) transaction_free(&tx[i]);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 4. enforce: evicts lowest fee-per-byte first (count cap) ── */
    printf("mempool_limits: evict lowest fee/byte first... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        /* Three txs, all ~same size, clearly ranked by fee:
         *   idx 0 fee=100   (worst)
         *   idx 1 fee=5000  (middle)
         *   idx 2 fee=10000 (best)
         * Cap = 2 → idx 0 must be evicted. */
        struct transaction tx[3];
        int64_t fees[3] = {100, 5000, 10000};
        for (int i = 0; i < 3; i++) {
            mlt_build_tx(&tx[i], 0x200 + i, 1, 1, COIN_VALUE);
            mlt_add(&pool, &tx[i], fees[i], 1700000000);
        }
        mempool_limits_reset_stats();
        atomic_store(&g_ev_evict, 0);

        struct mempool_limits_config cfg = {0};
        cfg.max_tx_count = 2;
        int evicted = mempool_limits_enforce(&pool, &cfg);

        bool ok = evicted == 1;
        ok = ok && tx_mempool_size(&pool) == 2;
        ok = ok && !tx_mempool_exists(&pool, &tx[0].hash);
        ok = ok && tx_mempool_exists(&pool, &tx[1].hash);
        ok = ok && tx_mempool_exists(&pool, &tx[2].hash);
        ok = ok && atomic_load(&g_ev_evict) == 1;

        for (int i = 0; i < 3; i++) transaction_free(&tx[i]);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 5. enforce: evicts by byte cap (count under limit) ─── */
    printf("mempool_limits: evict by byte cap... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct transaction tx[4];
        size_t sizes[4] = {0};
        for (int i = 0; i < 4; i++) {
            mlt_build_tx(&tx[i], 0x300 + i, 1, 1, COIN_VALUE);
            sizes[i] = mlt_add(&pool, &tx[i], 1000, 1700000000);
        }
        /* Set byte cap below 4× but above 1×. Let one add get in
         * free, force enforce to drop ~half. All have the same fee
         * so the tie-breaker (earlier time) kicks in — but all
         * have the same time too, so order is implementation-defined
         * within the tie group. We only require: under-cap after,
         * at least one eviction. */
        uint64_t total = tx_mempool_total_size(&pool);
        struct mempool_limits_config cfg = {0};
        cfg.max_bytes = (int64_t)(total / 2);
        cfg.max_tx_count = 100;
        atomic_store(&g_ev_evict, 0);
        int evicted = mempool_limits_enforce(&pool, &cfg);

        bool ok = evicted > 0;
        ok = ok && (int64_t)tx_mempool_total_size(&pool) <= cfg.max_bytes;
        ok = ok && atomic_load(&g_ev_evict) == 1;
        (void)sizes; /* sizes unused in assertions — kept for debug */

        for (int i = 0; i < 4; i++) transaction_free(&tx[i]);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 6. enforce: fee/byte not fee alone ────────────────── */
    printf("mempool_limits: fee-per-byte beats raw fee... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        /* A huge tx (3 vin, 3 vout) with high absolute fee but
         * low fee-per-byte, vs a tiny tx (1 vin, 1 vout) with
         * lower absolute fee but higher fee-per-byte. With
         * count-cap = 1, the huge tx should be evicted. */
        struct transaction tx_huge, tx_tiny;
        mlt_build_tx(&tx_huge, 0x400, 3, 3, COIN_VALUE);
        mlt_build_tx(&tx_tiny, 0x401, 1, 1, COIN_VALUE);

        size_t size_huge = mlt_add(&pool, &tx_huge, 1500, 1700000000);
        size_t size_tiny = mlt_add(&pool, &tx_tiny,  800, 1700000000);

        /* Verify our assumption: size_huge > size_tiny, and
         * 1500/size_huge < 800/size_tiny so huge really is the
         * lower fee-per-byte one. */
        bool assumption = (size_huge > size_tiny) &&
            (1500LL * (int64_t)size_tiny < 800LL * (int64_t)size_huge);

        struct mempool_limits_config cfg = {0};
        cfg.max_tx_count = 1;
        int evicted = mempool_limits_enforce(&pool, &cfg);

        bool ok = assumption && evicted == 1;
        ok = ok && tx_mempool_size(&pool) == 1;
        ok = ok && !tx_mempool_exists(&pool, &tx_huge.hash);
        ok = ok && tx_mempool_exists(&pool, &tx_tiny.hash);

        transaction_free(&tx_huge);
        transaction_free(&tx_tiny);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 7. expire: sweeps old entries (injected clock) ────── */
    printf("mempool_limits: expiry sweep... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        atomic_store(&g_fake_now, 2000000000);
        mempool_limits_set_clock_fn(mlt_fake_clock);

        struct transaction old_tx, new_tx;
        mlt_build_tx(&old_tx, 0x500, 1, 1, COIN_VALUE);
        mlt_build_tx(&new_tx, 0x501, 1, 1, COIN_VALUE);
        /* old added at t-5000, new added at t-10 */
        mlt_add(&pool, &old_tx, 1000, 2000000000 - 5000);
        mlt_add(&pool, &new_tx, 1000, 2000000000 - 10);
        mempool_limits_reset_stats();
        atomic_store(&g_ev_expire, 0);

        struct mempool_limits_config cfg = {0};
        cfg.expiry_seconds = 1000;
        int expired = mempool_limits_expire(&pool, &cfg);

        bool ok = expired == 1;
        ok = ok && !tx_mempool_exists(&pool, &old_tx.hash);
        ok = ok && tx_mempool_exists(&pool, &new_tx.hash);
        ok = ok && atomic_load(&g_ev_expire) == 1;
        struct mempool_limits_stats st;
        mempool_limits_stats_snapshot(&st);
        ok = ok && st.expire_calls == 1 && st.expired_total == 1;

        mempool_limits_set_clock_fn(NULL);
        transaction_free(&old_tx);
        transaction_free(&new_tx);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 8. expire: no-op when empty ───────────────────────── */
    printf("mempool_limits: expire empty pool... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        struct mempool_limits_config cfg = {0};
        cfg.expiry_seconds = 60;
        int expired = mempool_limits_expire(&pool, &cfg);
        bool ok = expired == 0;
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 9. min relay fee gate ─────────────────────────────── */
    printf("mempool_limits: min relay fee gate... ");
    {
        struct mempool_limits_config cfg = {0};
        cfg.min_relay_fee_zat = 1000;
        bool ok = true;
        ok = ok &&  mempool_limits_passes_min_relay(&cfg, 1000, 200).ok;
        ok = ok &&  mempool_limits_passes_min_relay(&cfg, 5000, 200).ok;
        ok = ok && !mempool_limits_passes_min_relay(&cfg,  999, 200).ok;
        ok = ok && !mempool_limits_passes_min_relay(&cfg, 1000,   0).ok;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 10. post-add hook auto-enforces ───────────────────── */
    printf("mempool_limits: post-add hook enforces automatically... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct mempool_limits_config cfg = {0};
        cfg.max_tx_count = 2;
        cfg.tick_seconds = 3600; /* never tick during test */
        bool started = mempool_limits_start(&pool, &cfg).ok;
        atomic_store(&g_ev_evict, 0);

        /* Add 5 txs with strictly ascending fees — every add past
         * the second will fire the hook, which should evict until
         * the pool fits. End state: the 2 best-fee txs survive. */
        struct transaction tx[5];
        for (int i = 0; i < 5; i++) {
            mlt_build_tx(&tx[i], 0x600 + i, 1, 1, COIN_VALUE);
            mlt_add(&pool, &tx[i], 1000 * (int64_t)(i + 1), 1700000000);
        }
        bool ok = started;
        ok = ok && tx_mempool_size(&pool) == 2;
        /* The two best-fee survivors are idx 3 and idx 4. */
        ok = ok && tx_mempool_exists(&pool, &tx[3].hash);
        ok = ok && tx_mempool_exists(&pool, &tx[4].hash);
        ok = ok && atomic_load(&g_ev_evict) >= 1;

        mempool_limits_stop();
        for (int i = 0; i < 5; i++) transaction_free(&tx[i]);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 11. start/stop idempotent ─────────────────────────── */
    printf("mempool_limits: start/stop lifecycle... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        struct mempool_limits_config cfg = {0};
        cfg.tick_seconds = 3600;

        bool r1 = mempool_limits_start(&pool, &cfg).ok;
        bool r2 = mempool_limits_start(&pool, &cfg).ok; /* already running */
        struct mempool_limits_stats st;
        mempool_limits_stats_snapshot(&st);
        bool running = st.running;
        mempool_limits_stop();
        mempool_limits_stop(); /* idempotent */
        mempool_limits_stats_snapshot(&st);
        bool stopped = !st.running;

        bool ok = r1 && !r2 && running && stopped;
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 12. stats counters reflect calls ──────────────────── */
    printf("mempool_limits: stats counters... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);
        mempool_limits_reset_stats();

        struct transaction tx[3];
        for (int i = 0; i < 3; i++) {
            mlt_build_tx(&tx[i], 0x700 + i, 1, 1, COIN_VALUE);
            mlt_add(&pool, &tx[i], 1000, 1700000000);
        }
        struct mempool_limits_config cfg = {0};
        cfg.max_tx_count = 1;
        (void)mempool_limits_enforce(&pool, &cfg);
        (void)mempool_limits_expire(&pool, &cfg);

        struct mempool_limits_stats st;
        mempool_limits_stats_snapshot(&st);
        bool ok = st.enforce_calls == 1;
        ok = ok && st.expire_calls  == 1;
        ok = ok && st.evicted_total == 2;
        ok = ok && st.last_enforce_evicted == 2;

        for (int i = 0; i < 3; i++) transaction_free(&tx[i]);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 13. fee/byte sort does NOT overflow at MoneyRange fees ──
     *
     * Regression for the integer-overflow eviction-ordering bug:
     * the comparator cross-multiplies fee*size. With both txs the
     * same (large) size, A's fee/byte > B's fee/byte iff A.fee >
     * B.fee — so under count-cap=1 the lower-fee B must be evicted.
     *
     * We pick fees from the *measured* size so the OLD int64 product
     * fee*size wraps past INT64_MAX: feeA*size just exceeds
     * INT64_MAX (wraps negative) while feeB*size stays positive.
     * Under the buggy code the sort inverts (A's negative product
     * sorts as "worst") and A — the genuinely higher-fee tx — gets
     * evicted instead of B. Both fees stay within MoneyRange
     * (<= MAX_MONEY) so this is a reachable on-chain scenario. */
    printf("mempool_limits: fee/byte no int64 overflow at MoneyRange... ");
    {
        struct tx_mempool pool;
        tx_mempool_init(&pool, 0);

        /* ~600 empty vouts → serialized size well above the ~4400
         * bytes needed for the overflow window to exist. */
        struct transaction tx_a, tx_b;
        mlt_build_tx(&tx_a, 0x800, 1, 600, COIN_VALUE);
        mlt_build_tx(&tx_b, 0x801, 1, 600, COIN_VALUE);

        /* Add cheaply first to measure the real serialized size,
         * then re-derive fees from it. Sizes are equal (identical
         * vin/vout shape), so measure once via a throwaway add. */
        size_t size_a = mlt_add(&pool, &tx_a, 1, 1700000000);
        bool sized = size_a >= 4400;
        /* Remove the throwaway so we can re-add with the real fee. */
        tx_mempool_remove(&pool, &tx_a.hash);

        int64_t feeA = (INT64_MAX / (int64_t)size_a) + 1; /* feeA*size overflows */
        int64_t feeB = (INT64_MAX / (int64_t)size_a) / 2; /* feeB*size positive */
        bool inrange = MoneyRange(feeA) && MoneyRange(feeB) && feeA > feeB;

        size_t ra = mlt_add(&pool, &tx_a, feeA, 1700000000);
        size_t rb = mlt_add(&pool, &tx_b, feeB, 1700000000);
        bool added = ra > 0 && rb > 0;

        mempool_limits_reset_stats();
        atomic_store(&g_ev_evict, 0);

        struct mempool_limits_config cfg = {0};
        cfg.max_tx_count = 1;
        int evicted = mempool_limits_enforce(&pool, &cfg);

        /* Correct: B (lower fee, equal size) is evicted; A survives.
         * Buggy int64 code evicts A and keeps B. */
        bool ok = sized && inrange && added && evicted == 1;
        ok = ok && tx_mempool_size(&pool) == 1;
        ok = ok &&  tx_mempool_exists(&pool, &tx_a.hash);
        ok = ok && !tx_mempool_exists(&pool, &tx_b.hash);
        ok = ok && atomic_load(&g_ev_evict) == 1;

        transaction_free(&tx_a);
        transaction_free(&tx_b);
        tx_mempool_free(&pool);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    event_clear_observers(EV_MEMPOOL_EVICT);
    event_clear_observers(EV_MEMPOOL_EXPIRE);
    return failures;
}
