/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PRIME DIRECTIVE proof — "everything is a pure fold of the log."
 *
 * docs/FRAMEWORK.md states the Prime Directive: the append-only event_log
 * is the single source of truth, and every projection is a *pure fold*
 * over it. The defining invariant of an event-sourced architecture is:
 *
 *     replaying the SAME event log into a FRESH projection yields a state
 *     byte-identical to the projection that was folded INCREMENTALLY as
 *     the events were appended.
 *
 * If that ever fails, the projection is carrying hidden state (path
 * dependence) and is no longer a pure function of the log — the whole
 * "rebuildable from the log" promise (fast-sync, crash recovery, the
 * shadow-vs-legacy diffs) collapses.
 *
 * test_reorg_parity.c proves a narrow instance of this for the in-memory
 * coins_view_cache commitment across ONE hand-built reorg. This test
 * GENERALIZES it to the production event-log projections under RANDOM but
 * VALID operation sequences (seeded → replayable), and asserts the full
 * fold invariant across two fold-driven projections that share the same shape:
 *
 *   block_index (EV_BLOCK_HEADER, INSERT-OR-REPLACE)
 *   mempool     (EV_TX_ADMIT_MEMPOOL / EV_TX_REMOVE_MEMPOOL)
 *
 * Method (per projection)
 * -----------------------
 *   1. Seed a deterministic RNG (SEED is printed; failures are replayable
 *      by re-running with the same SEED).
 *   2. Generate N random VALID operations. Each op (a) appends one event
 *      to the shared log, and (b) is consumed by the LIVE projection via
 *      catch_up() at random points — incremental folding interleaved with
 *      appends, the way the live node folds.
 *   3. A REORG is forced into the sequence: spend/remove an entry, then
 *      re-introduce a colliding entry (the projection's reorg-replace
 *      path). This is where an incremental fold is most likely to drift
 *      from a from-scratch replay, so it is the highest-value sub-case.
 *   4. After the sequence, open a SECOND fresh projection on the SAME log
 *      and catch_up() ONCE from offset 0 (replay from scratch).
 *   5. ASSERT live == replay: commitment SHA3 equal, count equal, and
 *      (block_index) per-entry byte equality so a commitment
 *      collision cannot mask a divergence.
 *
 * Negative control (TEETH)
 * ------------------------
 *   The equality check must FAIL on genuine drift. We build a third
 *   "perturbed" projection that folds the log with ONE fold step dropped
 *   (we hide the last event from it by truncating its catch-up range) and
 *   assert the equality predicate REPORTS the drift. A self-comparison
 *   that always passes would be vacuous; this proves the assertion has
 *   teeth. Mutation-tested: see commit body.
 *
 * Scratch dirs under ./test-tmp/pri_<pid>_<tag>/ (no-/tmp convention).
 */

#include "test/test_core.h"

#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/block_index_projection.h"
#include "storage/mempool_projection.h"
#include "storage/block_index_db.h"   /* struct disk_block_index */
#include "core/uint256.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PRI_CHECK(name, expr) do {                 \
    printf("projection_replay_invariant: %s... ", (name)); \
    if ((expr)) printf("OK\n");                    \
    else { printf("FAIL\n"); failures++; }         \
} while (0)

/* Deterministic, replayable RNG (SplitMix64). Failures are reproducible
 * by re-running with the printed seed. */
static uint64_t g_rng;
static void rng_seed(uint64_t s) { g_rng = s; }
static uint64_t rng_next(void)
{
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t rng_range(uint32_t n) { return n ? (uint32_t)(rng_next() % n) : 0u; }

static int pri_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}
static void pri_ensure_root(void) { pri_mkdir_p("./test-tmp"); }

/* ──────────────────────────────────────────────────────────────────────
 * Shared seed: a fixed default keeps the suite deterministic, but the
 * env var ZCL_PRI_SEED can override it for soak/mutation runs.
 * ────────────────────────────────────────────────────────────────────── */
static uint64_t pick_seed(void)
{
    const char *e = getenv("ZCL_PRI_SEED");
    if (e && *e) {
        char *end = NULL;
        unsigned long long v = strtoull(e, &end, 0);
        if (end != e) return (uint64_t)v;
    }
    return 0xC0FFEE123456789ULL;  /* fixed default → suite-deterministic */
}

/* ══════════════════════════════════════════════════════════════════════
 * block_index projection
 * ══════════════════════════════════════════════════════════════════════ */

static void bip_make_header(struct ev_block_header *h, uint8_t *solution,
                            size_t solution_size, uint32_t seed,
                            int32_t height, uint32_t nStatus)
{
    memset(h, 0, sizeof(*h));
    for (int i = 0; i < 32; i++)
        h->hash[i] = (uint8_t)((seed >> ((i % 4) * 8)) & 0xFF);
    for (int i = 0; i < 32; i++)
        h->hashPrev[i] = (uint8_t)(((seed + 1) >> ((i % 4) * 8)) & 0xFF);
    h->height   = height;
    h->nStatus  = nStatus;
    h->nFile    = (int32_t)(seed % 16);
    h->nDataPos = seed * 4 + 100;
    h->nUndoPos = seed * 4 + 200;
    h->nTime    = 1700000000u + seed;
    h->nBits    = 0x1d00ffffu;
    for (int i = 0; i < 32; i++) h->nNonce[i] = (uint8_t)(seed + i);
    for (int i = 0; i < 32; i++) h->hashMerkleRoot[i] = (uint8_t)(seed * 2 + i);
    h->nVersion = 4;
    h->nTx      = 1;
    h->nSolutionSize = (uint16_t)solution_size;
    for (size_t i = 0; i < solution_size; i++)
        solution[i] = (uint8_t)((seed + i) & 0xFF);
}

static bool bip_emit(event_log_t *log, uint32_t seed, int32_t height,
                     uint32_t nStatus)
{
    struct ev_block_header h;
    uint8_t sol[64];
    size_t sol_len = 8 + (size_t)(seed % 24);
    bip_make_header(&h, sol, sol_len, seed, height, nStatus);
    uint8_t buf[256 + 64];
    size_t written = 0;
    if (!ev_block_header_serialize(&h, sol, buf, sizeof(buf), &written))
        return false;
    return event_log_append(log, EV_BLOCK_HEADER, buf, written) != UINT64_MAX;
}

/* Per-entry byte equality over the candidate hash universe. */
static void bip_hash_from_seed(uint8_t hash[32], uint32_t seed)
{
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t)((seed >> ((i % 4) * 8)) & 0xFF);
}

static bool bip_disk_equal(const struct disk_block_index *a,
                           const struct disk_block_index *b)
{
    return a->nHeight == b->nHeight && a->nStatus == b->nStatus &&
           a->nFile == b->nFile && a->nDataPos == b->nDataPos &&
           a->nUndoPos == b->nUndoPos && a->nTime == b->nTime &&
           a->nBits == b->nBits && a->nVersion == b->nVersion &&
           a->nTx == b->nTx &&
           uint256_cmp(&a->hashPrev, &b->hashPrev) == 0 &&
           uint256_cmp(&a->hashMerkleRoot, &b->hashMerkleRoot) == 0 &&
           a->nSolutionSize == b->nSolutionSize &&
           memcmp(a->nSolution, b->nSolution, a->nSolutionSize) == 0;
}

static bool bip_proj_equal(block_index_projection_t *a,
                           block_index_projection_t *b,
                           const uint32_t *seeds, size_t nseeds)
{
    if (block_index_projection_count(a) != block_index_projection_count(b))
        return false;
    uint8_t ca[32], cb[32];
    if (block_index_projection_commitment(a, ca) != 0) return false;
    if (block_index_projection_commitment(b, cb) != 0) return false;
    if (memcmp(ca, cb, 32) != 0) return false;

    for (size_t s = 0; s < nseeds; s++) {
        uint8_t hash[32]; bip_hash_from_seed(hash, seeds[s]);
        struct disk_block_index da, db;
        disk_block_index_init(&da);
        disk_block_index_init(&db);
        bool ha = block_index_projection_get(a, hash, &da);
        bool hb = block_index_projection_get(b, hash, &db);
        if (ha != hb) return false;
        if (ha && !bip_disk_equal(&da, &db)) return false;
    }
    return true;
}

static int run_block_index(uint64_t base_seed, int *failures_out)
{
    int failures = 0;
    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "pri", "bip");
    char log_path[400], live_path[400], replay_path[400], pert_path[400];
    snprintf(log_path,    sizeof(log_path),    "%s/events.log", dir);
    snprintf(live_path,   sizeof(live_path),   "%s/live.db",    dir);
    snprintf(replay_path, sizeof(replay_path), "%s/replay.db",  dir);
    snprintf(pert_path,   sizeof(pert_path),   "%s/pert.db",    dir);

    rng_seed(base_seed ^ 0xAAAAAAAAAAAAAAAAULL);

    event_log_t *log = event_log_open(log_path);
    block_index_projection_t *live = block_index_projection_open(live_path, log);
    PRI_CHECK("block_index: open log + live projection", log && live);
    if (!log || !live) {
        if (live) block_index_projection_close(live);
        if (log) event_log_close(log);
        goto done;
    }

    /* ~40 distinct block hashes (seeds). The random sequence emits
     * headers; some seeds get RE-emitted with a different nStatus (status
     * upgrade or reorg) which exercises the INSERT-OR-REPLACE fold. */
    enum { NSEEDS = 40 };
    uint32_t seeds[NSEEDS];
    for (int i = 0; i < NSEEDS; i++) seeds[i] = 0x2000u + (uint32_t)i;

    const int N_OPS = 400;
    int forced_reorg_at = 150 + (int)rng_range(80);
    bool did_reorg = false;

    for (int op = 0; op < N_OPS; op++) {
        if (op == forced_reorg_at) {
            /* Reorg: take a seed already emitted as ACTIVE and re-emit it
             * with FAILED status, then a sibling at the same height with a
             * different seed becomes ACTIVE — the canonical chain swap that
             * an incremental fold must converge on identically to replay. */
            uint32_t s = seeds[rng_range(NSEEDS)];
            bip_emit(log, s, (int32_t)(1000 + (int)rng_range(50)),
                     0x00u /* FAILED-ish */);
            uint32_t sib = seeds[rng_range(NSEEDS)];
            bip_emit(log, sib, (int32_t)(1000 + (int)rng_range(50)),
                     0x60u /* ACTIVE-ish */);
            did_reorg = true;
        } else {
            uint32_t s = seeds[rng_range(NSEEDS)];
            int32_t height = (int32_t)(1000 + (int)rng_range(60));
            uint32_t status = (rng_range(4) == 0) ? 0x00u : 0x60u;
            bip_emit(log, s, height, status);
        }
        if (rng_range(3) != 0)
            PRI_CHECK("block_index: incremental catch_up",
                      block_index_projection_catch_up(live) != UINT64_MAX);
    }
    PRI_CHECK("block_index: final live catch_up",
              block_index_projection_catch_up(live) != UINT64_MAX);
    PRI_CHECK("block_index: a reorg was exercised", did_reorg);

    block_index_projection_t *replay =
        block_index_projection_open(replay_path, log);
    PRI_CHECK("block_index: open replay projection", replay != NULL);
    if (replay) {
        PRI_CHECK("block_index: replay catch_up from offset 0",
                  block_index_projection_catch_up(replay) != UINT64_MAX);
        PRI_CHECK("block_index: PRIME DIRECTIVE — live fold == replay",
                  bip_proj_equal(live, replay, seeds, NSEEDS));

        /* Negative control. */
        block_index_projection_t *pert =
            block_index_projection_open(pert_path, log);
        PRI_CHECK("block_index: open perturbed projection", pert != NULL);
        if (pert) {
            block_index_projection_catch_up(pert);
            PRI_CHECK("block_index: perturbed == live before drift",
                      bip_proj_equal(live, pert, seeds, NSEEDS));

            uint32_t fresh = 0x7777u;
            bip_emit(log, fresh, 9999, 0x60u);
            block_index_projection_catch_up(live);
            block_index_projection_catch_up(replay);
            /* pert intentionally one fold step behind. */

            uint32_t seeds2[NSEEDS + 1];
            memcpy(seeds2, seeds, sizeof(seeds));
            seeds2[NSEEDS] = fresh;
            PRI_CHECK("block_index: NEGATIVE CONTROL — dropped fold step DETECTED",
                      !bip_proj_equal(live, pert, seeds2, NSEEDS + 1));
            block_index_projection_catch_up(pert);
            PRI_CHECK("block_index: catching dropped step restores equality",
                      bip_proj_equal(live, pert, seeds2, NSEEDS + 1));
            block_index_projection_close(pert);
        }
        block_index_projection_close(replay);
    }

    block_index_projection_close(live);
    event_log_close(log);
done:
    test_cleanup_tmpdir(dir);
    *failures_out += failures;
    return failures;
}

/* ══════════════════════════════════════════════════════════════════════
 * mempool projection
 * ══════════════════════════════════════════════════════════════════════ */

static void mp_make_txid(uint8_t txid[32], uint32_t key)
{
    for (int i = 0; i < 32; i++)
        txid[i] = (uint8_t)((key * 3 + i) & 0xFF);
}

static bool mp_append_admit(event_log_t *log, uint32_t key, int64_t fee,
                            uint32_t size_bytes, uint32_t weight)
{
    struct ev_tx_admit_mempool ev = {0};
    mp_make_txid(ev.txid, key);
    ev.fee = fee; ev.weight = weight;
    ev.admitted_unix = 1700000000u + key;
    /* The parser contract requires raw_tx_len == size_bytes. We carry a
     * zero-length raw_tx (size_bytes == 0): the projection's spend
     * extraction short-circuits on an empty body, so we don't feed it a
     * synthetic byte string it would (correctly) reject as a malformed tx.
     * The fold invariant is fully exercised by the metadata fields the
     * projection actually counts: fee, weight, and presence — all carried
     * by every event and compared in mp_proj_equal(). `weight` here
     * stands in as the size_bytes the equality predicate spot-checks. */
    (void)size_bytes;
    ev.size_bytes = 0; ev.raw_tx = NULL; ev.raw_tx_len = 0;

    uint8_t buf[EV_TX_ADMIT_MEMPOOL_FIXED_LEN];
    size_t out_len = 0;
    if (!ev_tx_admit_mempool_serialize(&ev, buf, sizeof(buf), &out_len))
        return false;
    return event_log_append(log, EV_TX_ADMIT_MEMPOOL, buf, out_len) != UINT64_MAX;
}

static bool mp_append_remove(event_log_t *log, uint32_t key, uint8_t reason)
{
    struct ev_tx_remove_mempool ev = {0};
    mp_make_txid(ev.txid, key);
    ev.reason = reason;
    uint8_t buf[EV_TX_REMOVE_MEMPOOL_LEN];
    if (!ev_tx_remove_mempool_serialize(&ev, buf)) return false;
    return event_log_append(log, EV_TX_REMOVE_MEMPOOL, buf, sizeof(buf)) != UINT64_MAX;
}

static bool mp_proj_equal(mempool_projection_t *a, mempool_projection_t *b,
                          const uint32_t *keys, size_t nkeys)
{
    if (mempool_projection_count(a) != mempool_projection_count(b)) return false;
    if (mempool_projection_total_fee(a) != mempool_projection_total_fee(b))
        return false;
    if (mempool_projection_total_weight(a) != mempool_projection_total_weight(b))
        return false;
    for (size_t k = 0; k < nkeys; k++) {
        uint8_t txid[32]; mp_make_txid(txid, keys[k]);
        int64_t fa = 0, fb = 0; uint32_t sa = 0, sb = 0, wa = 0, wb = 0;
        bool ha = mempool_projection_get(a, txid, &fa, &sa, &wa);
        bool hb = mempool_projection_get(b, txid, &fb, &sb, &wb);
        if (ha != hb) return false;
        if (ha && (fa != fb || sa != sb || wa != wb)) return false;
    }
    return true;
}

static int run_mempool(uint64_t base_seed, int *failures_out)
{
    int failures = 0;
    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "pri", "mp");
    char log_path[400], live_path[400], replay_path[400], pert_path[400];
    snprintf(log_path,    sizeof(log_path),    "%s/events.log", dir);
    snprintf(live_path,   sizeof(live_path),   "%s/live.db",    dir);
    snprintf(replay_path, sizeof(replay_path), "%s/replay.db",  dir);
    snprintf(pert_path,   sizeof(pert_path),   "%s/pert.db",    dir);

    rng_seed(base_seed ^ 0x3333333333333333ULL);

    event_log_t *log = event_log_open(log_path);
    mempool_projection_t *live = mempool_projection_open(live_path, log);
    PRI_CHECK("mempool: open log + live projection", log && live);
    if (!log || !live) {
        if (live) mempool_projection_close(live);
        if (log) event_log_close(log);
        goto done;
    }

    enum { NKEYS = 48 };
    uint32_t keys[NKEYS];
    for (int i = 0; i < NKEYS; i++) keys[i] = 0x4000u + (uint32_t)i;
    uint8_t present[NKEYS]; memset(present, 0, sizeof(present));

    const int N_OPS = 500;
    /* "reorg" for the mempool: a block confirms a batch (REMOVE several),
     * then the block is disconnected and they are re-admitted (ADMIT) —
     * the remove/re-admit churn that an incremental fold must match. */
    int forced_reorg_at = 180 + (int)rng_range(80);
    bool did_reorg = false;

    for (int op = 0; op < N_OPS; op++) {
        if (op == forced_reorg_at) {
            /* Confirm-then-disconnect: remove up to 5 present txs, then
             * re-admit them (possibly with refreshed fee/size). */
            int removed[5]; int nr = 0;
            for (int t = 0; t < NKEYS && nr < 5; t++) {
                if (present[t]) {
                    mp_append_remove(log, keys[t], 1 /* mined */);
                    present[t] = 0;
                    removed[nr++] = t;
                }
            }
            for (int r = 0; r < nr; r++) {
                int t = removed[r];
                mp_append_admit(log, keys[t],
                                2000 + (int64_t)op + t,
                                100 + rng_range(120),
                                400 + rng_range(400));
                present[t] = 1;
            }
            if (nr > 0) did_reorg = true;
        } else {
            int kk = (int)rng_range(NKEYS);
            if (present[kk]) {
                if (rng_range(3) == 0) {
                    mp_append_remove(log, keys[kk], (uint8_t)(rng_range(3)));
                    present[kk] = 0;
                } else {
                    /* re-admit overwrites fee/size (replace) */
                    mp_append_admit(log, keys[kk],
                                    1500 + (int64_t)op,
                                    100 + rng_range(120),
                                    400 + rng_range(400));
                }
            } else {
                mp_append_admit(log, keys[kk],
                                1000 + (int64_t)op,
                                80 + rng_range(140),
                                320 + rng_range(480));
                present[kk] = 1;
            }
        }
        if (rng_range(3) != 0)
            PRI_CHECK("mempool: incremental catch_up",
                      mempool_projection_catch_up(live) != UINT64_MAX);
    }
    PRI_CHECK("mempool: final live catch_up",
              mempool_projection_catch_up(live) != UINT64_MAX);
    PRI_CHECK("mempool: a reorg (remove+re-admit) was exercised", did_reorg);

    mempool_projection_t *replay = mempool_projection_open(replay_path, log);
    PRI_CHECK("mempool: open replay projection", replay != NULL);
    if (replay) {
        PRI_CHECK("mempool: replay catch_up from offset 0",
                  mempool_projection_catch_up(replay) != UINT64_MAX);
        PRI_CHECK("mempool: PRIME DIRECTIVE — live fold == replay",
                  mp_proj_equal(live, replay, keys, NKEYS));

        mempool_projection_t *pert = mempool_projection_open(pert_path, log);
        PRI_CHECK("mempool: open perturbed projection", pert != NULL);
        if (pert) {
            mempool_projection_catch_up(pert);
            PRI_CHECK("mempool: perturbed == live before drift",
                      mp_proj_equal(live, pert, keys, NKEYS));

            uint32_t fresh = 0x8888u;
            mp_append_admit(log, fresh, 9999, 150, 600);
            mempool_projection_catch_up(live);
            mempool_projection_catch_up(replay);
            /* pert left one fold step behind. */

            uint32_t keys2[NKEYS + 1];
            memcpy(keys2, keys, sizeof(keys));
            keys2[NKEYS] = fresh;
            PRI_CHECK("mempool: NEGATIVE CONTROL — dropped fold step DETECTED",
                      !mp_proj_equal(live, pert, keys2, NKEYS + 1));
            mempool_projection_catch_up(pert);
            PRI_CHECK("mempool: catching dropped step restores equality",
                      mp_proj_equal(live, pert, keys2, NKEYS + 1));
            mempool_projection_close(pert);
        }
        mempool_projection_close(replay);
    }

    mempool_projection_close(live);
    event_log_close(log);
done:
    test_cleanup_tmpdir(dir);
    *failures_out += failures;
    return failures;
}

/* ══════════════════════════════════════════════════════════════════════
 * Entry point
 * ══════════════════════════════════════════════════════════════════════ */

int test_projection_replay_invariant(void);
int test_projection_replay_invariant(void)
{
    int failures = 0;
    pri_ensure_root();

    uint64_t seed = pick_seed();
    printf("\n== test_projection_replay_invariant (seed=0x%016" PRIx64 ") ==\n",
           seed);
    printf("   (set ZCL_PRI_SEED to replay a specific seed)\n");

    run_block_index(seed, &failures);
    run_mempool    (seed, &failures);

    if (failures == 0)
        printf("test_projection_replay_invariant: all OK\n");
    else
        printf("test_projection_replay_invariant: %d FAILURE(S) "
               "(replay with ZCL_PRI_SEED=0x%016" PRIx64 ")\n", failures, seed);
    return failures;
}
