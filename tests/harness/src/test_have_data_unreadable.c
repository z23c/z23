/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the have_data_unreadable Condition — the continuous self-healer
 * for the "torn HAVE_DATA block wedges the tip" class observed live:
 *
 *   find_most_work_chain: STUCK at tip h=N (best_header h=N+k, gap=k)
 *   read_block_pread_fail: h=N+1 file=-1 pos=0   (repeating)
 *
 * MECHANISM (confirmed in source):
 *   - A block above the tip carries BLOCK_HAVE_DATA in nStatus but its
 *     on-disk location is torn: nFile == -1 / nDataPos == 0 (a stale flag
 *     left by a quarantined synthetic tip; no actual body on disk).
 *   - gap_fill_service.c:168 skips any block with BLOCK_HAVE_DATA set, so the
 *     torn block is NEVER re-requested → the body never re-downloads.
 *   - connect_tip cannot read the body (read_block_from_disk_index_pread
 *     fails because nFile < 0), so the tip cannot advance → wedge.
 *
 * THE HEAL (engine/conditions/src/have_data_unreadable.c):
 *   detect : tip stalled >=60s AND tip+1 is marked HAVE_DATA but
 *            block_index_have_data_readable() == false (file=-1 → read fails).
 *   remedy : CLEAR the provably-bogus HAVE_DATA flag (+ nFile=-1, nDataPos=0)
 *            so gap_fill re-requests the body. Never drops real data — the
 *            read genuinely failed AND file is already -1.
 *   witness: the tip advanced past the target (re-fetch + connect succeeded),
 *            or the block became readable.
 * Anti-thrash: the Condition engine bounds this at max_attempts=3 with a
 *   backoff_secs=30 window; after exhaustion it re-arms on a 600s cooldown
 *   (unbounded re-arms) instead of latching permanently — this is an
 *   external-resource-dependent remedy (the sibling body_fetch_missing_
 *   have_data Condition drives the actual re-fetch).
 *
 * Also covers the GENERALIZED detect target (2026-07): the LOWEST read-failed
 * height across the reducer stages, not just tip+1 — utxo_apply's own
 * select-idle record of an ARBITRARY mid-chain height it is stuck re-reading
 * (e.g. a stale-script/coin-backfill replay that rewinds its cursor), read via
 * the test-only stub seam (have_data_unreadable_test_set_select_idle_stubs).
 *
 * Fixture pattern mirrors test_orphan_utxo_above_tip.c: a minimal in-RAM
 * main_state chain, the engine driven via condition_engine_tick(), tip
 * staleness injected via sync_monitor_test_set_tip_advance_ts(). The
 * torn-block readability gate needs NO disk file: a block with nFile=-1
 * makes block_index_have_data_readable() return false immediately.
 */

#include "test/test_core.h"

#include "conditions/have_data_unreadable.h"
#include "core/arith_uint256.h"
#include "core/serialize.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "platform/clock.h"
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "services/sync_monitor.h"
#include "storage/disk_block_io.h"
#include "util/blocker.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define HDU_CHECK(name, expr) do {                   \
    printf("have_data_unreadable: %s... ", (name));  \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

/* Build a minimal linked chain in main_state with tip at height n-1. */
static struct block_index *hdu_build_chain(struct main_state *ms, int n,
                                           struct uint256 *hashes)
{
    struct block_index *tip = NULL;
    for (int h = 0; h < n; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[3] = 0xCD; /* distinct salt from other tests */

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        pi->nFile = 0;       /* on-disk (notional) */
        pi->nDataPos = 8;
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
        if (h > 0)
            pi->pprev = block_map_find(&ms->map_block_index, &hashes[h - 1]);
        tip = pi;
    }
    if (tip)
        active_chain_move_window_tip(&ms->chain_active, tip);
    return tip;
}

/* Insert a torn next-block at height `h`: header-valid, HAVE_DATA flagged,
 * but its on-disk location is missing (nFile=-1). It is NOT linked into the
 * active chain (the tip is at h-1) — this is the would-be next tip. */
static struct block_index *hdu_insert_torn(struct main_state *ms, int h,
                                           struct uint256 *hash,
                                           struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[3] = 0xCD;

    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!pi)
        return NULL;
    pi->nHeight = h;
    pi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA; /* flag set... */
    pi->nFile = -1;                                   /* ...but torn */
    pi->nDataPos = 0;
    pi->nChainTx = 0;
    pi->pprev = prev;
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    return pi;
}

/* Same as hdu_insert_torn but distinguished from siblings AT THE SAME HEIGHT
 * by `salt` — target_index() matches by height alone, so several distinct
 * (distinct-hash) torn entries can coexist at one height, each requiring its
 * own remedy call to clear. Models several stale/retried candidate bodies
 * left behind at one height. */
static struct block_index *hdu_insert_torn_variant(struct main_state *ms,
                                                    int h, uint8_t salt,
                                                    struct uint256 *hash,
                                                    struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(h & 0xFF);
    hash->data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash->data[3] = 0xCD;
    hash->data[4] = salt;

    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!pi)
        return NULL;
    pi->nHeight = h;
    pi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    pi->nFile = -1;
    pi->nDataPos = 0;
    pi->nChainTx = 0;
    pi->pprev = prev;
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    return pi;
}

/* Test seams for the mid-chain (utxo_apply select-idle) candidate — see
 * have_data_unreadable_test_set_select_idle_stubs(). */
static int64_t g_hdu_stub_height = -1;
static int64_t hdu_stub_select_idle_height(void) { return g_hdu_stub_height; }
static bool hdu_stub_select_idle_is_read_failure(void) { return true; }

/* Insert a block_index entry at an EXPLICIT (already-computed, real) hash —
 * the "witness clears on readability" test needs a genuine on-disk block a
 * real pread can hash-verify, unlike hdu_insert_torn's fabricated hash. */
static struct block_index *hdu_insert_torn_at_hash(struct main_state *ms,
                                                    int h,
                                                    const struct uint256 *hash,
                                                    struct block_index *prev)
{
    struct block_index *pi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!pi)
        return NULL;
    pi->nHeight = h;
    pi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
    pi->nFile = -1;
    pi->nDataPos = 0;
    pi->nChainTx = 0;
    pi->pprev = prev;
    arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));
    return pi;
}

/* Write a minimal real block to `netdir` and return its on-disk position +
 * true hash — mirrors test_disk_block_io.c's write_test_block. `pos->nFile`
 * must be -1 on entry (append mode); write_block_to_disk fills in the real
 * (nFile,nPos) it chose. */
static bool hdu_write_real_block(const char *netdir, uint32_t ntime,
                                 struct disk_block_pos *pos,
                                 struct uint256 *hash_out)
{
    struct block b;
    block_init(&b);
    b.header.nVersion = 4;
    b.header.nTime = ntime;
    b.header.nBits = 0x2000ffff;
    b.num_vtx = 1;
    b.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (!b.vtx) {
        block_free(&b);
        return false;
    }
    transaction_init(&b.vtx[0]);
    transaction_alloc(&b.vtx[0], 1, 1);
    b.vtx[0].vin[0].sequence = 0xffffffff;
    b.vtx[0].vout[0].value = 10 * COIN;

    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    bool ok = write_block_to_disk(&b, pos, netdir, msg_start);
    if (ok)
        block_get_hash(&b, hash_out);
    block_free(&b);
    return ok;
}

struct fake_clock {
    _Atomic int64_t wall_ms;
};

static int64_t hdu_fake_now_mono(void *self) { (void)self; return 1; }
static int64_t hdu_fake_now_wall(void *self)
{
    struct fake_clock *c = (struct fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

static void hdu_fake_clock_install(struct fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    static clock_iface_t iface;
    iface.now_monotonic_ns = hdu_fake_now_mono;
    iface.now_wall_ms = hdu_fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void hdu_fake_clock_set(struct fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
}

int test_have_data_unreadable(void)
{
    printf("\n=== have_data_unreadable condition tests ===\n");
    int failures = 0;
    struct uint256 hashes[64];
    struct uint256 torn_hash;

    /* ── 1. Readable tip+1, fresh tip: detect false, no remedy. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9, all blocks readable */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        /* Tip just advanced (age ~0 < 60) — even a torn block must not fire. */
        sync_monitor_test_set_tip_advance_ts(platform_time_wall_unix());

        struct block_index *tip = block_map_find(&ms.map_block_index,
                                                 &hashes[9]);
        hdu_insert_torn(&ms, 10, &torn_hash, tip);

        condition_engine_tick();

        bool ok = condition_engine_get_active_count() == 0;
        ok = ok && have_data_unreadable_test_remedy_calls() == 0;
        HDU_CHECK("fresh tip (age<60) -> detect false, no remedy", ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        main_state_free(&ms);
    }

    /* ── 1b. Unknown tip age is not fresh. A restored/snapshot boot may not
     *      have observed a block-connected callback yet; if tip+1 is
     *      provably unreadable, clear the bogus HAVE_DATA flag anyway. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9 */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        struct block_index *tip = block_map_find(&ms.map_block_index,
                                                 &hashes[9]);
        struct block_index *torn = hdu_insert_torn(&ms, 10, &torn_hash, tip);

        sync_monitor_test_set_tip_advance_ts(0); /* sentinel: age unknown */
        condition_engine_tick();

        bool ok = have_data_unreadable_test_remedy_calls() == 1;
        ok = ok && (torn->nStatus & BLOCK_HAVE_DATA) == 0;
        HDU_CHECK("unknown tip age + torn block -> remedy clears HAVE_DATA",
                  ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        main_state_free(&ms);
    }

    /* ── 2. Stalled tip + torn HAVE_DATA next block: detect fires, remedy
     *      CLEARS the provably-bogus flag, and the engine witnesses the heal
     *      (the bogus flag is gone → the block is eligible for re-download).
     *
     *      TEETH: the remedy MUST clear BLOCK_HAVE_DATA. gap_fill_service.c
     *      skips any block with BLOCK_HAVE_DATA set, so leaving the flag set
     *      (disabling the remedy) means the torn block is never re-requested
     *      AND target_index() still finds it → the witness reports the
     *      symptom persists → the condition is NOT cleared and the assertions
     *      below fail. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9 */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        struct block_index *tip = block_map_find(&ms.map_block_index,
                                                 &hashes[9]);
        struct block_index *torn = hdu_insert_torn(&ms, 10, &torn_hash, tip);

        /* Tip has been stuck for 120s (> 60s gate). tip_advance_age uses the
         * wall clock (now - last); set last to 120s ago. */
        int64_t now = platform_time_wall_unix();
        sync_monitor_test_set_tip_advance_ts(now - 120);

        /* Pre-state: torn block is flagged HAVE_DATA with file=-1. */
        bool pre_flagged = (torn->nStatus & BLOCK_HAVE_DATA) != 0 &&
                           torn->nFile == -1;

        struct condition_runtime_snapshot pre;
        int cleared_before = 0;
        if (condition_engine_get_registered_snapshot("have_data_unreadable",
                                                     &pre))
            cleared_before = pre.cleared_count;

        /* One tick: detect true → active; remedy clears the bogus flag; the
         * post-remedy witness sees the flag is gone → condition cleared. */
        condition_engine_tick();

        bool ok = pre_flagged;
        ok = ok && have_data_unreadable_test_remedy_calls() == 1;
        /* TEETH: the provably-bogus HAVE_DATA flag is cleared so the
         * downloader (gap_fill skips HAVE_DATA blocks) will re-request it. */
        ok = ok && (torn->nStatus & BLOCK_HAVE_DATA) == 0;
        ok = ok && torn->nFile == -1 && torn->nDataPos == 0;
        HDU_CHECK("stalled tip + torn block -> remedy clears HAVE_DATA", ok);

        struct condition_runtime_snapshot post;
        bool gotpost = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &post);
        bool ok2 = gotpost;
        ok2 = ok2 && condition_engine_get_active_count() == 0;
        ok2 = ok2 && post.cleared_count == cleared_before + 1;
        HDU_CHECK("bogus flag cleared -> condition witnessed/cleared", ok2);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        main_state_free(&ms);
    }

    /* ── 3. Anti-thrash: the remedy is self-limiting. Once the bogus flag is
     *      cleared, the condition resolves; further ticks (with the tip still
     *      stalled, but the block no longer falsely marked HAVE_DATA) do NOT
     *      re-fire the remedy. The remedy only ever acts on a block that is
     *      STILL falsely flagged — it cannot repeatedly hammer an already
     *      healed block. Combined with the engine's bounded backoff/
     *      max_attempts (asserted via the snapshot), this is the no-thrash
     *      guarantee. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9 */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        struct block_index *tip = block_map_find(&ms.map_block_index,
                                                 &hashes[9]);
        hdu_insert_torn(&ms, 10, &torn_hash, tip);

        int64_t now = platform_time_wall_unix();
        sync_monitor_test_set_tip_advance_ts(now - 120); /* tip stalled */

        /* First tick heals the bogus flag (one remedy). */
        condition_engine_tick();
        int calls_after_heal = have_data_unreadable_test_remedy_calls();

        /* Drive more ticks WITHOUT re-arming the flag: the tip is still
         * stalled, but the block is no longer falsely HAVE_DATA, so detect is
         * false and the remedy must NOT fire again — no thrash. */
        for (int i = 0; i < 6; i++)
            condition_engine_tick();
        int calls_total = have_data_unreadable_test_remedy_calls();

        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &snap);
        bool ok = got;
        ok = ok && calls_after_heal == 1;          /* healed in one remedy */
        ok = ok && calls_total == 1;               /* never re-fired: no thrash */
        ok = ok && snap.backoff_secs > 0;          /* backoff configured */
        ok = ok && snap.max_attempts > 0;          /* attempt cap configured */
        ok = ok && snap.attempts <= snap.max_attempts;
        HDU_CHECK("self-limiting -> remedy does not re-fire on healed block",
                  ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        sync_monitor_test_set_tip_advance_ts(0);
        main_state_free(&ms);
    }

    /* ── 4. GENERALIZED target: a read-fail at an ARBITRARY mid-chain height
     *      (not tip+1) is detected and targeted. tip+1 does not even exist
     *      (so the legacy candidate cannot fire); the ONLY signal is
     *      utxo_apply's select-idle record (the test stub) naming h=5 — well
     *      below the tip — with a read-failure reason. This is the live
     *      class the generalization heals: a stale-script/coin-backfill
     *      replay rewinds utxo_apply's cursor to re-derive an OLDER height
     *      whose local body has since bit-rotted. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9, all blocks readable */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        /* Corrupt an ALREADY-APPLIED mid-chain block's on-disk location —
         * simulates bit rot discovered long after the block was folded, not
         * a torn just-fetched tip+1 candidate. */
        struct block_index *mid = block_map_find(&ms.map_block_index,
                                                  &hashes[5]);
        mid->nFile = -1;
        mid->nDataPos = 0;

        int64_t now = platform_time_wall_unix();
        sync_monitor_test_set_tip_advance_ts(now - 120); /* tip stalled */
        g_hdu_stub_height = 5;
        have_data_unreadable_test_set_select_idle_stubs(
            hdu_stub_select_idle_height, hdu_stub_select_idle_is_read_failure);

        struct condition_runtime_snapshot pre;
        int cleared_before = 0;
        if (condition_engine_get_registered_snapshot("have_data_unreadable",
                                                      &pre))
            cleared_before = pre.cleared_count;

        condition_engine_tick();

        bool ok = have_data_unreadable_test_remedy_calls() == 1;
        /* TEETH: the mid-chain height (h=5), NOT some phantom tip+1 (h=10,
         * which does not exist in this 10-block chain), was targeted. */
        ok = ok && (mid->nStatus & BLOCK_HAVE_DATA) == 0;
        ok = ok && mid->nFile == -1 && mid->nDataPos == 0;
        /* Every OTHER block stays untouched — only the named height heals. */
        for (int h = 0; h < 10 && ok; h++) {
            if (h == 5) continue;
            struct block_index *bi =
                block_map_find(&ms.map_block_index, &hashes[h]);
            ok = ok && bi && (bi->nStatus & BLOCK_HAVE_DATA) != 0;
        }
        HDU_CHECK("mid-chain read-fail height (not tip+1) is detected and "
                  "targeted", ok);

        struct condition_runtime_snapshot snap;
        bool ok2 = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &snap);
        ok2 = ok2 && condition_engine_get_active_count() == 0;
        ok2 = ok2 && snap.cleared_count == cleared_before + 1;
        HDU_CHECK("mid-chain heal witnessed/cleared", ok2);

        g_hdu_stub_height = -1;
        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        sync_monitor_test_set_tip_advance_ts(0);
        main_state_free(&ms);
    }

    /* ── 5. Witness clears on readability (not just "flag gone"): TWO
     *      candidates at the same height, each backed by a REAL on-disk
     *      block (so block_index_have_data_readable() does a genuine
     *      pread + hash-verify, not just an nFile>=0 check). Both start
     *      torn (nFile=-1); the first remedy clears whichever one
     *      target_index scans first, leaving the episode active. The
     *      SURVIVING one is then pointed at its real on-disk position (as
     *      if a P2P re-fetch landed a good copy under a flag this
     *      Condition never touched) — the top-of-tick witness check must
     *      clear the episode via the readability branch, WITHOUT another
     *      remedy call. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "have_data_unreadable", "readable");
        SetDataDir(dir);
        char netdir[512];
        GetDataDir(true, netdir, sizeof(netdir));
        char blocksdir[560];
        snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", netdir);
        mkdir(blocksdir, 0755);

        struct disk_block_pos pos_a, pos_b;
        struct uint256 hash_a, hash_b;
        disk_block_pos_init(&pos_a);
        disk_block_pos_init(&pos_b);
        bool wrote = hdu_write_real_block(netdir, 91001, &pos_a, &hash_a) &&
                     hdu_write_real_block(netdir, 91002, &pos_b, &hash_b);

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9 */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        struct block_index *tip = block_map_find(&ms.map_block_index,
                                                 &hashes[9]);
        struct block_index *a =
            hdu_insert_torn_at_hash(&ms, 10, &hash_a, tip);
        struct block_index *b =
            hdu_insert_torn_at_hash(&ms, 10, &hash_b, tip);

        int64_t now = platform_time_wall_unix();
        sync_monitor_test_set_tip_advance_ts(now - 120);

        struct condition_runtime_snapshot pre;
        int cleared_before = 0;
        if (condition_engine_get_registered_snapshot("have_data_unreadable",
                                                      &pre))
            cleared_before = pre.cleared_count;

        condition_engine_tick(); /* clears whichever of A/B target_index scans
                                   * first; the other remains -> still active
                                   * (block_map iteration order is not this
                                   * test's concern, only that exactly one
                                   * clears). */

        bool a_have = (a->nStatus & BLOCK_HAVE_DATA) != 0;
        bool b_have = (b->nStatus & BLOCK_HAVE_DATA) != 0;
        bool ok = wrote;
        ok = ok && have_data_unreadable_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && (a_have != b_have); /* exactly one cleared, one remains */
        HDU_CHECK("first remedy clears one candidate, second keeps episode "
                  "active", ok);

        /* The still-flagged one is independently repaired (NOT by this
         * Condition) — a real re-fetch landed a valid copy under the flag,
         * at ITS OWN real on-disk position. */
        struct block_index *remaining = a_have ? a : b;
        struct disk_block_pos *remaining_pos = a_have ? &pos_a : &pos_b;
        remaining->nFile = remaining_pos->nFile;
        remaining->nDataPos = remaining_pos->nPos;

        condition_engine_tick();
        bool ok2 = have_data_unreadable_test_remedy_calls() == 1; /* no 2nd
                                                                    * remedy */
        struct condition_runtime_snapshot snap;
        ok2 = ok2 && condition_engine_get_registered_snapshot(
            "have_data_unreadable", &snap);
        ok2 = ok2 && condition_engine_get_active_count() == 0;
        ok2 = ok2 && snap.cleared_count == cleared_before + 1;
        HDU_CHECK("witness clears on readability, without a remedy call", ok2);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        sync_monitor_test_set_tip_advance_ts(0);
        main_state_free(&ms);
        SetDataDir(""); ClearDataDirCache();
        test_rm_rf(dir);
    }

    /* ── 6. Exhaustion re-arms after cooldown (never latches permanently):
     *      four independently-torn candidates at the same height each need
     *      their own remedy call. The first three exhaust max_attempts=3 and
     *      page the operator; the engine's continue-with-cooldown tier
     *      (cooldown_secs=600, cooldown_max_rearms=0) re-arms the attempt
     *      budget on the very next eligible tick (the first re-arm in an
     *      episode is free — see condition.c's condition_cooldown_rearm) so a
     *      4th remedy call runs and finally clears the last candidate. ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9 */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        struct condition_runtime_snapshot cfg;
        bool ok = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &cfg);
        ok = ok && cfg.max_attempts == 3;
        ok = ok && cfg.cooldown_secs == 600;
        ok = ok && cfg.cooldown_max_rearms == 0;
        HDU_CHECK("cooldown tier configured (never latches at max_attempts)",
                  ok);

        struct block_index *tip = block_map_find(&ms.map_block_index,
                                                 &hashes[9]);
        struct uint256 h1, h2, h3, h4;
        hdu_insert_torn_variant(&ms, 10, 0x11, &h1, tip);
        hdu_insert_torn_variant(&ms, 10, 0x22, &h2, tip);
        hdu_insert_torn_variant(&ms, 10, 0x33, &h3, tip);
        hdu_insert_torn_variant(&ms, 10, 0x44, &h4, tip);

        int cleared_before = cfg.cleared_count;

        struct fake_clock clock;
        hdu_fake_clock_install(&clock, 1000);
        sync_monitor_test_set_tip_advance_ts(1000 - 120);

        hdu_fake_clock_set(&clock, 1000); condition_engine_tick(); /* clears
                                                                     * #1 */
        hdu_fake_clock_set(&clock, 1031); condition_engine_tick(); /* #2 */
        hdu_fake_clock_set(&clock, 1062); condition_engine_tick(); /* #3 */

        struct condition_runtime_snapshot mid;
        bool okm = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &mid);
        okm = okm && have_data_unreadable_test_remedy_calls() == 3;
        okm = okm && mid.attempts == 3;
        okm = okm && mid.currently_active;
        okm = okm && mid.operator_needed_emitted;
        okm = okm && mid.cleared_count == cleared_before; /* not cleared yet */
        HDU_CHECK("three attempts exhaust the budget and page the operator",
                  okm);

        /* The 4th tick: cooldown re-arms the budget (free first re-arm) so
         * the remedy runs again — never a permanent latch — and clears the
         * last torn candidate. */
        hdu_fake_clock_set(&clock, 1093);
        condition_engine_tick();

        struct condition_runtime_snapshot post;
        bool okp = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &post);
        okp = okp && have_data_unreadable_test_remedy_calls() == 4;
        okp = okp && !post.currently_active;
        okp = okp && post.cleared_count == cleared_before + 1;
        HDU_CHECK("cooldown re-arm fires a 4th remedy that finally clears",
                  okp);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        sync_monitor_test_set_tip_advance_ts(0);
        clock_reset_default();
        main_state_free(&ms);
    }

    /* ── 7. Body torn-read repair note (lane E3): a torn/failed canonical body
     *      read recorded by stage_repair_read_active_block_checked raises a
     *      typed blocker (quarantine) and is healed OFF-LOCK by this Condition
     *      — the exact "read_active_block_checked: disk read failed h=3143721
     *      ... repair defers" live wedge. Proves the chain: torn read => typed
     *      blocker emitted => HAVE_DATA dropped so body_fetch refetches => on
     *      heal the note + blocker clear (revalidation flow). This is
     *      candidate 3, fed by the REAL reducer_frontier note channel — NOT a
     *      stub — so it fires even when utxo_apply never reached the height
     *      (the replay defers first). ── */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        blocker_module_init();
        blocker_reset_for_testing();
        reducer_frontier_body_read_note_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes); /* tip h=9 */
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        /* A mid-chain block (h=5) whose on-disk body has torn (nFile=-1 → an
         * unreadable HAVE_DATA flag), exactly as read_active_block_checked
         * discovers it during a replay. */
        struct block_index *mid = block_map_find(&ms.map_block_index,
                                                  &hashes[5]);
        mid->nFile = -1;
        mid->nDataPos = 0;

        /* stage_repair records the torn read; the quarantine bound raises the
         * NAMED typed blocker BEFORE any condition tick. */
        for (int i = 0; i < REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX; i++)
            reducer_frontier_body_read_note_record(
                5, 49, 129998574, REDUCER_FRONTIER_BODY_READ_DISK,
                &hashes[5]);

        bool pre = blocker_exists("reducer_frontier.body_read_torn") &&
                   reducer_frontier_body_read_note_active() &&
                   reducer_frontier_body_read_note_height() == 5 &&
                   (mid->nStatus & BLOCK_HAVE_DATA) != 0;
        HDU_CHECK("body_read_torn: quarantine emits typed blocker, HAVE_DATA "
                  "still set pre-heal", pre);

        int64_t now = platform_time_wall_unix();
        sync_monitor_test_set_tip_advance_ts(now); /* live tip still advancing */

        struct condition_runtime_snapshot presnap;
        int cleared_before = 0;
        if (condition_engine_get_registered_snapshot("have_data_unreadable",
                                                      &presnap))
            cleared_before = presnap.cleared_count;

        /* Explicit disk-failure evidence bypasses the speculative 60-second
         * tip-stall guard. The note must survive HAVE_DATA clearing so the
         * sibling condition can queue the exact peer refetch. */
        condition_engine_tick();

        bool ok = have_data_unreadable_test_remedy_calls() == 1;
        ok = ok && (mid->nStatus & BLOCK_HAVE_DATA) == 0; /* refetch armed */
        ok = ok && mid->nFile == -1 && mid->nDataPos == 0;
        HDU_CHECK("body_read_torn: candidate 3 drops HAVE_DATA for refetch",
                  ok);

        struct condition_runtime_snapshot post;
        bool ok2 = condition_engine_get_registered_snapshot(
            "have_data_unreadable", &post);
        ok2 = ok2 && condition_engine_get_active_count() == 1;
        ok2 = ok2 && post.cleared_count == cleared_before;
        ok2 = ok2 && blocker_exists("reducer_frontier.body_read_torn");
        ok2 = ok2 && reducer_frontier_body_read_note_active();
        HDU_CHECK("body_read_torn: clear retains refetch handoff note", ok2);

        /* The exact body reader clears the note only after a hash-verified
         * replacement is readable. Drive that authoritative completion
         * signal, then prove the condition and typed blocker retire. */
        struct reducer_frontier_body_read_note completed_note;
        bool ok3 = reducer_frontier_body_read_note_snapshot(&completed_note) &&
                   reducer_frontier_body_read_note_clear_if(&completed_note);
        condition_engine_tick();
        ok3 = ok3 && condition_engine_get_registered_snapshot(
            "have_data_unreadable", &post);
        ok3 = ok3 && condition_engine_get_active_count() == 0;
        ok3 = ok3 && post.cleared_count == cleared_before + 1;
        ok3 = ok3 && !blocker_exists("reducer_frontier.body_read_torn");
        HDU_CHECK("body_read_torn: verified reader completion clears episode",
                  ok3);

        /* Only the torn height healed — every other block stays HAVE_DATA. */
        bool others = true;
        for (int h = 0; h < 10; h++) {
            if (h == 5) continue;
            struct block_index *bi =
                block_map_find(&ms.map_block_index, &hashes[h]);
            others = others && bi && (bi->nStatus & BLOCK_HAVE_DATA) != 0;
        }
        HDU_CHECK("body_read_torn: only the torn height healed", others);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        reducer_frontier_body_read_note_reset_for_testing();
        blocker_reset_for_testing();
        sync_monitor_test_set_tip_advance_ts(0);
        main_state_free(&ms);
    }

    /* A same-height orphan note cannot authorize mutation of the active
     * block. The generation/hash binding leaves the stale note intact for
     * its writer to replace or retire after observing the reorg. */
    {
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        reducer_frontier_body_read_note_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        hdu_build_chain(&ms, 10, hashes);
        condition_engine_set_main_state(&ms);
        register_have_data_unreadable();

        struct uint256 orphan_hash;
        struct block_index *prev =
            block_map_find(&ms.map_block_index, &hashes[4]);
        struct block_index *orphan = hdu_insert_torn_variant(
            &ms, 5, 0x7e, &orphan_hash, prev);
        reducer_frontier_body_read_note_record(
            5, -1, 0, REDUCER_FRONTIER_BODY_READ_DISK, &orphan_hash);
        sync_monitor_test_set_tip_advance_ts(platform_time_wall_unix());

        condition_engine_tick();

        struct block_index *active = active_chain_at(&ms.chain_active, 5);
        bool ok = orphan && active && active != orphan;
        ok = ok && have_data_unreadable_test_remedy_calls() == 0;
        ok = ok && (block_index_status_load(active) & BLOCK_HAVE_DATA) != 0;
        ok = ok && reducer_frontier_body_read_note_active();
        HDU_CHECK("same-height orphan note cannot clear active block", ok);

        condition_engine_set_main_state(NULL);
        condition_engine_reset_for_testing();
        have_data_unreadable_test_reset();
        reducer_frontier_body_read_note_reset_for_testing();
        sync_monitor_test_set_tip_advance_ts(0);
        main_state_free(&ms);
    }

    return failures;
}
