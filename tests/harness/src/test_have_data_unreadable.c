/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the have_data_unreadable Condition, the self-healer for the "torn
 * HAVE_DATA block wedges the tip" class:
 *
 *   find_most_work_chain: STUCK at tip h=N (best_header h=N+k, gap=k)
 *   read_block_pread_fail: h=N+1 file=-1 pos=0   (repeating)
 *
 * Mechanism:
 *   - A block above the tip carries BLOCK_HAVE_DATA but its on-disk location
 *     is torn (nFile == -1 / nDataPos == 0).
 *   - gap_fill_service.c skips blocks with BLOCK_HAVE_DATA, so the body is
 *     never re-requested.
 *   - connect_tip cannot read the body, so the tip cannot advance.
 *
 * The heal (engine/conditions/src/have_data_unreadable.c):
 *   detect : tip stalled >=60s AND tip+1 is marked HAVE_DATA but
 *            block_index_have_data_readable() == false.
 *   remedy : clear the bogus HAVE_DATA flag (+ nFile=-1, nDataPos=0) so
 *            gap_fill re-requests the body. Never drops real data.
 *   witness: the tip advanced past the target, or the block became readable.
 * Anti-thrash: the engine bounds this at max_attempts=3, backoff_secs=30;
 *   after exhaustion it re-arms on a 600s cooldown (unbounded re-arms). The
 *   sibling body_fetch_missing_have_data Condition drives the re-fetch.
 *
 * Also covers the generalized detect target: the lowest read-failed height
 * across the reducer stages, not just tip+1 (utxo_apply's select-idle record,
 * via have_data_unreadable_test_set_select_idle_stubs).
 *
 * Fixture mirrors test_orphan_utxo_above_tip.c: a minimal in-RAM main_state
 * chain, the engine driven via condition_engine_tick(), tip staleness injected
 * via sync_monitor_test_set_tip_advance_ts(). A block with nFile=-1 makes
 * block_index_have_data_readable() return false with no disk file.
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
 * on-disk location missing (nFile=-1), not linked into the active chain. */
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

/* Like hdu_insert_torn but distinguished from same-height siblings by `salt`:
 * target_index() matches by height alone, so several distinct-hash torn
 * entries can coexist at one height, each needing its own remedy call. */
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

/* Test seams for the mid-chain (utxo_apply select-idle) candidate; see
 * have_data_unreadable_test_set_select_idle_stubs(). */
static int64_t g_hdu_stub_height = -1;
static int64_t hdu_stub_select_idle_height(void) { return g_hdu_stub_height; }
static bool hdu_stub_select_idle_is_read_failure(void) { return true; }

/* Insert a block_index entry at an explicit real hash; the "witness clears on
 * readability" test needs a block a real pread can hash-verify. */
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

/* Write a minimal real block to `netdir` and return its on-disk position and
 * true hash (as test_disk_block_io.c's write_test_block). `pos->nFile` must be
 * -1 on entry (append mode). */
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

/* Heights other than 5 keep BLOCK_HAVE_DATA. stop_when_false is the
 * mid-chain scan, which does not visit further heights once acc is false;
 * the body-torn scan passes false and visits every height. */
static bool hdu_other_heights_keep_have_data(const struct main_state *ms,
                                             const struct uint256 *hashes,
                                             bool acc, bool stop_when_false)
{
    for (int h = 0; h < 10 && (!stop_when_false || acc); h++) {
        if (h == 5)
            continue;
        struct block_index *bi =
            block_map_find(&ms->map_block_index, &hashes[h]);
        acc = acc && bi && (bi->nStatus & BLOCK_HAVE_DATA) != 0;
    }
    return acc;
}

/* The still-flagged one is repaired independently: a re-fetch landed
 * a valid copy at its own real on-disk position. */
static void hdu_repair_remaining_candidate(struct block_index *a,
                                           struct block_index *b,
                                           bool a_have,
                                           struct disk_block_pos *pos_a,
                                           struct disk_block_pos *pos_b)
{
    struct block_index *remaining = a_have ? a : b;
    struct disk_block_pos *remaining_pos = a_have ? pos_a : pos_b;
    remaining->nFile = remaining_pos->nFile;
    remaining->nDataPos = remaining_pos->nPos;
}

static bool hdu_attempts_exhausted_and_paged(
    const struct condition_runtime_snapshot *mid, int cleared_before)
{
    return have_data_unreadable_test_remedy_calls() == 3
        && mid->attempts == 3
        && mid->currently_active
        && mid->operator_needed_emitted
        && mid->cleared_count == cleared_before; /* not cleared yet */
}

/* stage_repair records the torn read; the quarantine bound raises the
 * named typed blocker before any condition tick. */
static bool hdu_arm_body_torn_quarantine(const struct uint256 *hash,
                                         const struct block_index *mid)
{
    for (int i = 0; i < REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX; i++)
        reducer_frontier_body_read_note_record(
            5, 49, 129998574, REDUCER_FRONTIER_BODY_READ_DISK,
            hash);

    return blocker_exists("reducer_frontier.body_read_torn") &&
           reducer_frontier_body_read_note_active() &&
           reducer_frontier_body_read_note_height() == 5 &&
           (mid->nStatus & BLOCK_HAVE_DATA) != 0;
}

static bool hdu_body_torn_refetch_armed(const struct block_index *mid)
{
    bool ok = have_data_unreadable_test_remedy_calls() == 1;
    ok = ok && (mid->nStatus & BLOCK_HAVE_DATA) == 0; /* refetch armed */
    ok = ok && mid->nFile == -1 && mid->nDataPos == 0;
    return ok;
}

static bool hdu_body_torn_handoff_retained(
    int cleared_before, struct condition_runtime_snapshot *post)
{
    bool ok2 = condition_engine_get_registered_snapshot(
        "have_data_unreadable", post);
    ok2 = ok2 && condition_engine_get_active_count() == 1;
    ok2 = ok2 && post->cleared_count == cleared_before;
    ok2 = ok2 && blocker_exists("reducer_frontier.body_read_torn");
    ok2 = ok2 && reducer_frontier_body_read_note_active();
    return ok2;
}

/* The exact body reader clears the note only after a hash-verified
 * replacement is readable; drive that signal, then prove the condition
 * and blocker retire. */
static bool hdu_body_torn_reader_completion_clears(
    int cleared_before, struct condition_runtime_snapshot *post)
{
    struct reducer_frontier_body_read_note completed_note;
    bool ok3 = reducer_frontier_body_read_note_snapshot(&completed_note) &&
               reducer_frontier_body_read_note_clear_if(&completed_note);
    condition_engine_tick();
    ok3 = ok3 && condition_engine_get_registered_snapshot(
        "have_data_unreadable", post);
    ok3 = ok3 && condition_engine_get_active_count() == 0;
    ok3 = ok3 && post->cleared_count == cleared_before + 1;
    ok3 = ok3 && !blocker_exists("reducer_frontier.body_read_torn");
    return ok3;
}

/* ── 1. Readable tip+1, fresh tip: detect false, no remedy. ── */
static int hdu_case_fresh_tip_no_remedy(void)
{
    int failures = 0;
    struct uint256 hashes[64];
    struct uint256 torn_hash;

    condition_engine_reset_for_testing();
    have_data_unreadable_test_reset();

    struct main_state ms;
    main_state_init(&ms);
    hdu_build_chain(&ms, 10, hashes); /* tip h=9, all blocks readable */
    condition_engine_set_main_state(&ms);
    register_have_data_unreadable();

    /* Tip just advanced (age ~0 < 60): even a torn block must not fire. */
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
    return failures;
}

/* ── 1b. Unknown tip age is not fresh: a snapshot boot may not have seen a
 *      block-connected callback, so an unreadable tip+1 still gets its
 *      bogus flag cleared. ── */
static int hdu_case_unknown_age_clears_have_data(void)
{
    int failures = 0;
    struct uint256 hashes[64];
    struct uint256 torn_hash;

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
    return failures;
}

/* ── 2. Stalled tip + torn HAVE_DATA next block: detect fires, the remedy
 *      clears the bogus flag, and the engine witnesses the heal.
 *
 *      TEETH: the remedy must clear BLOCK_HAVE_DATA; otherwise gap_fill
 *      never re-requests the block, target_index() still finds it, and the
 *      witness reports the symptom persists. ── */
static int hdu_case_stalled_tip_clears_have_data(void)
{
    int failures = 0;
    struct uint256 hashes[64];
    struct uint256 torn_hash;

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

    /* Tip stuck for 120s (> 60s gate); tip_advance_age uses the wall
     * clock. */
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

    /* One tick: detect fires, remedy clears the flag, the witness sees it
     * gone and clears the condition. */
    condition_engine_tick();

    bool ok = pre_flagged;
    ok = ok && have_data_unreadable_test_remedy_calls() == 1;
    /* TEETH: the bogus HAVE_DATA flag is cleared so gap_fill re-requests
     * the body. */
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
    return failures;
}

/* ── 3. Anti-thrash: once the bogus flag is cleared the condition
 *      resolves; further ticks do not re-fire the remedy, which acts only
 *      on a still-falsely-flagged block. With the engine's bounded
 *      backoff/max_attempts this is the no-thrash guarantee. ── */
static int hdu_case_healed_block_does_not_refire(void)
{
    int failures = 0;
    struct uint256 hashes[64];
    struct uint256 torn_hash;

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

    /* More ticks without re-arming the flag: detect is false and the
     * remedy must not fire again. */
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
    return failures;
}

/* ── 4. Generalized target: a read-fail at an arbitrary mid-chain height
 *      is detected. tip+1 does not exist, so the only signal is
 *      utxo_apply's select-idle record (test stub) naming h=5 with a
 *      read-failure reason (e.g. a replay rewinding the cursor onto a
 *      bit-rotted body). ── */
static int hdu_case_midchain_read_fail_targeted(void)
{
    int failures = 0;
    struct uint256 hashes[64];

    condition_engine_reset_for_testing();
    have_data_unreadable_test_reset();

    struct main_state ms;
    main_state_init(&ms);
    hdu_build_chain(&ms, 10, hashes); /* tip h=9, all blocks readable */
    condition_engine_set_main_state(&ms);
    register_have_data_unreadable();

    /* Corrupt an already-applied mid-chain block's on-disk location
     * (bit rot found after the block was folded). */
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
    /* TEETH: the mid-chain height (h=5), not a phantom tip+1 (h=10), was
     * targeted. */
    ok = ok && (mid->nStatus & BLOCK_HAVE_DATA) == 0;
    ok = ok && mid->nFile == -1 && mid->nDataPos == 0;
    /* Every other block stays untouched. */
    ok = hdu_other_heights_keep_have_data(&ms, hashes, ok, true);
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
    return failures;
}

/* ── 5. Witness clears on readability: two candidates at one height, each
 *      backed by a real on-disk block (a genuine pread + hash-verify). Both
 *      start torn; the first remedy clears one, leaving the episode active.
 *      The survivor is then pointed at its real position (a re-fetch
 *      landed a good copy); the top-of-tick witness must clear the episode
 *      via the readability branch without another remedy call. ── */
static int hdu_case_witness_clears_when_readable(void)
{
    int failures = 0;
    struct uint256 hashes[64];

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

    hdu_repair_remaining_candidate(a, b, a_have, &pos_a, &pos_b);

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
    return failures;
}

/* ── 6. Exhaustion re-arms after cooldown (never latches): four torn
 *      candidates at one height need four remedy calls. The first three
 *      exhaust max_attempts=3 and page the operator; the cooldown tier
 *      (cooldown_secs=600, cooldown_max_rearms=0) re-arms the budget on the
 *      next eligible tick (first re-arm is free, condition_cooldown_rearm)
 *      so the 4th call clears the last candidate. ── */
static int hdu_case_cooldown_rearm_fourth_remedy(void)
{
    int failures = 0;
    struct uint256 hashes[64];

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
    okm = okm && hdu_attempts_exhausted_and_paged(&mid, cleared_before);
    HDU_CHECK("three attempts exhaust the budget and page the operator",
              okm);

    /* The 4th tick: cooldown re-arms the budget (free first re-arm), the
     * remedy runs and clears the last torn candidate. */
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
    return failures;
}

/* ── 7. Body torn-read repair note: a torn canonical body read recorded by
 *      stage_repair_read_active_block_checked raises a typed blocker
 *      (quarantine) and is healed off-lock by this Condition. Chain: torn
 *      read => typed blocker => HAVE_DATA dropped so body_fetch refetches
 *      => on heal the note and blocker clear. Fed by the real
 *      reducer_frontier note channel (candidate 3), not a stub. ── */
static int hdu_case_body_torn_read_repair(void)
{
    int failures = 0;
    struct uint256 hashes[64];

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

    /* A mid-chain block (h=5) whose on-disk body is torn (nFile=-1), as
     * read_active_block_checked discovers it during a replay. */
    struct block_index *mid = block_map_find(&ms.map_block_index,
                                              &hashes[5]);
    mid->nFile = -1;
    mid->nDataPos = 0;

    bool pre = hdu_arm_body_torn_quarantine(&hashes[5], mid);
    HDU_CHECK("body_read_torn: quarantine emits typed blocker, HAVE_DATA "
              "still set pre-heal", pre);

    int64_t now = platform_time_wall_unix();
    sync_monitor_test_set_tip_advance_ts(now); /* live tip still advancing */

    struct condition_runtime_snapshot presnap;
    int cleared_before = 0;
    if (condition_engine_get_registered_snapshot("have_data_unreadable",
                                                 &presnap))
        cleared_before = presnap.cleared_count;

    /* Explicit disk-failure evidence bypasses the 60-second tip-stall
     * guard; the note survives HAVE_DATA clearing so the sibling condition
     * can queue the peer refetch. */
    condition_engine_tick();

    bool ok = hdu_body_torn_refetch_armed(mid);
    HDU_CHECK("body_read_torn: candidate 3 drops HAVE_DATA for refetch",
              ok);

    struct condition_runtime_snapshot post;
    bool ok2 = hdu_body_torn_handoff_retained(cleared_before, &post);
    HDU_CHECK("body_read_torn: clear retains refetch handoff note", ok2);

    bool ok3 = hdu_body_torn_reader_completion_clears(cleared_before, &post);
    HDU_CHECK("body_read_torn: verified reader completion clears episode",
              ok3);

    /* Only the torn height healed — every other block stays HAVE_DATA. */
    bool others = hdu_other_heights_keep_have_data(&ms, hashes, true, false);
    HDU_CHECK("body_read_torn: only the torn height healed", others);

    condition_engine_set_main_state(NULL);
    condition_engine_reset_for_testing();
    have_data_unreadable_test_reset();
    reducer_frontier_body_read_note_reset_for_testing();
    blocker_reset_for_testing();
    sync_monitor_test_set_tip_advance_ts(0);
    main_state_free(&ms);
    return failures;
}

/* A same-height orphan note cannot authorize mutation of the active
 * block; the stale note stays for its writer to replace or retire. */
static int hdu_case_orphan_note_spares_active(void)
{
    int failures = 0;
    struct uint256 hashes[64];

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
    return failures;
}

int test_have_data_unreadable(void)
{
    printf("\n=== have_data_unreadable condition tests ===\n");
    int failures = 0;

    failures += hdu_case_fresh_tip_no_remedy();
    failures += hdu_case_unknown_age_clears_have_data();
    failures += hdu_case_stalled_tip_clears_have_data();
    failures += hdu_case_healed_block_does_not_refire();
    failures += hdu_case_midchain_read_fail_targeted();
    failures += hdu_case_witness_clears_when_readable();
    failures += hdu_case_cooldown_rearm_fourth_remedy();
    failures += hdu_case_body_torn_read_repair();
    failures += hdu_case_orphan_note_spares_active();

    return failures;
}
