/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the block pruning service.
 *
 * Strategy: build a fake active_chain with block_index entries that
 * have BLOCK_HAVE_DATA pointing at numbered files. Create actual
 * blk*.dat / rev*.dat files on disk. Run block_pruning_run_once()
 * and verify: correct files deleted, flags cleared, stats updated.
 */

#include "test/test_core.h"
#include "storage/disk_block_io.h"
#include "services/block_pruning_service.h"
#include "chain/chain.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PRUNE_SCRATCH "./test-tmp/prune_test"

#define PRUNE_CHECK(name, expr) do { \
    printf("%s... ", (name));        \
    if ((expr)) printf("OK\n");      \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Event counter ─────────────────────────────────────────── */

static _Atomic int g_prune_events;

static void prune_ev_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_BLOCK_PRUNING_DONE)
        atomic_fetch_add(&g_prune_events, 1);
}

static void install_prune_observer(void)
{
    event_clear_observers(EV_BLOCK_PRUNING_DONE);
    atomic_store(&g_prune_events, 0);
    event_observe(EV_BLOCK_PRUNING_DONE, prune_ev_observer, NULL);
}

/* ── Test fixture ──────────────────────────────────────────── */

/* We need a main_state with a usable active_chain. We'll build a
 * minimal chain of block_index entries and place them in the chain. */

struct prune_fixture {
    struct main_state ms;
    struct block_pruning_service svc;
    struct block_index *blocks;   /* heap array */
    struct uint256 *hashes;       /* heap array of fake hashes */
    int num_blocks;
    char datadir[256];
};

static void make_blocks_dir(const char *datadir)
{
    char path[512];
    mkdir("./test-tmp", 0755);
    snprintf(path, sizeof(path), "%s", datadir);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/blocks", datadir);
    mkdir(path, 0755);
}

/* Create a fake blk/rev file with some content. */
static bool create_fake_block_file(const char *datadir, int file_num,
                                   const char *prefix, size_t size)
{
    char path[512];
    struct disk_block_pos pos = { .nFile = file_num, .nPos = 0 };
    get_block_pos_filename(path, sizeof(path), datadir, &pos, prefix);

    FILE *f = fopen(path, "wb");
    if (!f) return false;
    /* Write `size` bytes of filler */
    for (size_t i = 0; i < size; i++)
        fputc((int)(i & 0xFF), f);
    fclose(f);
    return true;
}

static bool fake_file_exists(const char *datadir, int file_num,
                             const char *prefix)
{
    char path[512];
    struct disk_block_pos pos = { .nFile = file_num, .nPos = 0 };
    get_block_pos_filename(path, sizeof(path), datadir, &pos, prefix);
    return access(path, F_OK) == 0;
}

static bool fixture_init(struct prune_fixture *f, int num_blocks,
                         const char *tag)
{
    memset(f, 0, sizeof(*f));
    f->num_blocks = num_blocks;
    snprintf(f->datadir, sizeof(f->datadir),
             PRUNE_SCRATCH "_%d_%s", (int)getpid(), tag);
    make_blocks_dir(f->datadir);

    /* Allocate block index entries */
    f->blocks = zcl_malloc((size_t)num_blocks * sizeof(struct block_index),
                           "prune_test_blocks");
    if (!f->blocks) return false;

    f->hashes = zcl_malloc((size_t)num_blocks * sizeof(struct uint256),
                           "prune_test_hashes");
    if (!f->hashes) { free(f->blocks); return false; }

    /* Initialize block indices */
    for (int i = 0; i < num_blocks; i++) {
        block_index_init(&f->blocks[i]);
        memset(&f->hashes[i], 0, sizeof(struct uint256));
        f->hashes[i].data[0] = (unsigned char)(i & 0xFF);
        f->hashes[i].data[1] = (unsigned char)((i >> 8) & 0xFF);
        f->blocks[i].phashBlock = &f->hashes[i];
        f->blocks[i].nHeight = i;
        if (i > 0) f->blocks[i].pprev = &f->blocks[i - 1];
    }

    /* Set up active chain */
    active_chain_init(&f->ms.chain_active);
    active_chain_move_window_tip(&f->ms.chain_active, &f->blocks[num_blocks - 1]);

    /* Init pruning service */
    block_pruning_init(&f->svc, &f->ms, f->datadir);
    return true;
}

static void fixture_destroy(struct prune_fixture *f)
{
    active_chain_free(&f->ms.chain_active);
    free(f->blocks);
    free(f->hashes);

    /* Clean up files */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", f->datadir);
    int ret = system(cmd);
    (void)ret;
}

/* ── Stub for sync_get_state (tests don't link the full sync module) ── */

/* The real sync_get_state is defined elsewhere; tests provide a weak
 * symbol so the pruning service can call it without linking the full
 * sync module. For run_once() calls in tests, the sync state doesn't
 * matter (it's only checked in the background thread loop). */

/* ── Tests ─────────────────────────────────────────────────── */

int test_block_pruning(void)
{
    printf("\n=== block_pruning tests ===\n");
    int failures = 0;

    /* ── 1. Chain too short — nothing pruned ──────────── */
    {
        struct prune_fixture f;
        bool ok = fixture_init(&f, 500, "short");
        PRUNE_CHECK("prune: fixture init (short chain)", ok);

        /* All blocks have data in file 1 */
        for (int i = 0; i < 500; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 1;
        }
        f.svc.keep_blocks = 1000;

        int pruned = block_pruning_run_once(&f.svc);
        PRUNE_CHECK("prune: short chain prunes nothing", pruned == 0);

        fixture_destroy(&f);
    }

    /* ── 2. Basic pruning — old file deleted ──────────── */
    {
        install_prune_observer();
        struct prune_fixture f;
        bool ok = fixture_init(&f, 3001, "basic");
        PRUNE_CHECK("prune: fixture init (basic)", ok);

        /* 3001 blocks (0..3000). chain_height = 3000.
         * keep_blocks = 1000 → prune_below = 3000 - 1000 = 2000.
         * Blocks 0-999 in file 1, 1000-1999 in file 2, 2000-3000 in file 3. */
        for (int i = 0; i < 3001; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
            if (i < 1000)       f.blocks[i].nFile = 1;
            else if (i < 2000)  f.blocks[i].nFile = 2;
            else                f.blocks[i].nFile = 3;
        }

        /* Create fake block files */
        create_fake_block_file(f.datadir, 1, "blk", 4096);
        create_fake_block_file(f.datadir, 1, "rev", 2048);
        create_fake_block_file(f.datadir, 2, "blk", 4096);
        create_fake_block_file(f.datadir, 2, "rev", 2048);
        create_fake_block_file(f.datadir, 3, "blk", 4096);
        create_fake_block_file(f.datadir, 3, "rev", 2048);

        f.svc.keep_blocks = 1000;  /* prune_below = 3000 - 1000 = 2000 */

        int pruned = block_pruning_run_once(&f.svc);
        /* File 1 (max_h=999 < 2000) and file 2 (max_h=1999 < 2000) pruned.
         * File 3 (max_h=3000 >= 2000) kept. */
        PRUNE_CHECK("prune: two files pruned", pruned == 2);

        /* Verify files deleted */
        PRUNE_CHECK("prune: blk00001.dat deleted",
                    !fake_file_exists(f.datadir, 1, "blk"));
        PRUNE_CHECK("prune: rev00001.dat deleted",
                    !fake_file_exists(f.datadir, 1, "rev"));
        PRUNE_CHECK("prune: blk00002.dat deleted",
                    !fake_file_exists(f.datadir, 2, "blk"));
        PRUNE_CHECK("prune: blk00003.dat NOT deleted",
                    fake_file_exists(f.datadir, 3, "blk"));

        /* Verify flags cleared on pruned blocks */
        bool flags_ok = true;
        for (int i = 0; i < 2000; i++) {
            if (f.blocks[i].nStatus & BLOCK_HAVE_DATA) { flags_ok = false; break; }
            if (f.blocks[i].nStatus & BLOCK_HAVE_UNDO) { flags_ok = false; break; }
        }
        PRUNE_CHECK("prune: BLOCK_HAVE_DATA cleared on pruned blocks", flags_ok);

        /* Verify flags preserved on kept blocks */
        bool kept_ok = true;
        for (int i = 2000; i < 3001; i++) {
            if (!(f.blocks[i].nStatus & BLOCK_HAVE_DATA)) { kept_ok = false; break; }
        }
        PRUNE_CHECK("prune: BLOCK_HAVE_DATA preserved on kept blocks", kept_ok);

        /* Verify events emitted */
        PRUNE_CHECK("prune: two EV_BLOCK_PRUNING_DONE events",
                    atomic_load(&g_prune_events) == 2);

        /* Verify stats */
        struct block_pruning_status st;
        block_pruning_get_status(&f.svc, &st);
        PRUNE_CHECK("prune: bytes_reclaimed > 0", st.bytes_reclaimed > 0);
        PRUNE_CHECK("prune: blocks_pruned == 2000", st.blocks_pruned == 2000);
        PRUNE_CHECK("prune: lowest_have_data == 2000",
                    st.lowest_have_data == 2000);

        fixture_destroy(&f);
    }

    /* ── 3. File 0 never pruned ───────────────────────── */
    {
        struct prune_fixture f;
        fixture_init(&f, 2000, "file0");

        /* All blocks in file 0 */
        for (int i = 0; i < 2000; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 0;
        }
        create_fake_block_file(f.datadir, 0, "blk", 1024);
        f.svc.keep_blocks = 500;

        int pruned = block_pruning_run_once(&f.svc);
        PRUNE_CHECK("prune: file 0 is never pruned", pruned == 0);
        PRUNE_CHECK("prune: blk00000.dat still exists",
                    fake_file_exists(f.datadir, 0, "blk"));

        fixture_destroy(&f);
    }

    /* ── 4. File with mixed heights — not pruned until max is old enough ── */
    {
        struct prune_fixture f;
        fixture_init(&f, 3000, "mixed");

        /* File 1: blocks 0-499 AND block 1800 (mixed) */
        for (int i = 0; i < 500; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 1;
        }
        f.blocks[1800].nStatus = BLOCK_HAVE_DATA;
        f.blocks[1800].nFile = 1;

        /* File 2: blocks 500-999 */
        for (int i = 500; i < 1000; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 2;
        }

        /* Rest in file 3 */
        for (int i = 1000; i < 3000; i++) {
            if (i == 1800) continue;
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 3;
        }

        create_fake_block_file(f.datadir, 1, "blk", 2048);
        create_fake_block_file(f.datadir, 2, "blk", 2048);

        f.svc.keep_blocks = 1000;  /* prune_below = 2000 */

        int pruned = block_pruning_run_once(&f.svc);
        /* File 1: max_h=1800 < 2000 → pruned
         * File 2: max_h=999 < 2000 → pruned */
        PRUNE_CHECK("prune: mixed file pruned when max_height old enough",
                    pruned == 2);

        fixture_destroy(&f);
    }

    /* ── 5. Second pass is idempotent ─────────────────── */
    {
        struct prune_fixture f;
        fixture_init(&f, 2000, "idempotent");

        for (int i = 0; i < 500; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 1;
        }
        for (int i = 500; i < 2000; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 2;
        }
        create_fake_block_file(f.datadir, 1, "blk", 1024);
        f.svc.keep_blocks = 1000;

        int p1 = block_pruning_run_once(&f.svc);
        PRUNE_CHECK("prune: first pass prunes 1 file", p1 == 1);

        int p2 = block_pruning_run_once(&f.svc);
        PRUNE_CHECK("prune: second pass prunes nothing (idempotent)", p2 == 0);

        fixture_destroy(&f);
    }

    /* ── 6. Blocks without BLOCK_HAVE_DATA are ignored ── */
    {
        struct prune_fixture f;
        fixture_init(&f, 2000, "nodata");

        /* Blocks 0-999 have no data flag (already pruned or header-only) */
        for (int i = 0; i < 1000; i++) {
            f.blocks[i].nStatus = BLOCK_VALID_SCRIPTS;
            f.blocks[i].nFile = 1;
        }
        for (int i = 1000; i < 2000; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            f.blocks[i].nFile = 2;
        }

        f.svc.keep_blocks = 500;

        int pruned = block_pruning_run_once(&f.svc);
        PRUNE_CHECK("prune: blocks without BLOCK_HAVE_DATA ignored", pruned == 0);

        fixture_destroy(&f);
    }

    /* ── 6b. prune_sealed_range: never prunes beyond the caller's proven
     * sealed+verified boundary, even when keep_blocks alone would allow it —
     * the two floors intersect (min), so a shallow seal frontier can never
     * be outrun. ── */
    {
        struct prune_fixture f;
        fixture_init(&f, 3001, "sealed_gate");

        /* Same layout as test 2: file 1 = [0,999], file 2 = [1000,1999],
         * file 3 = [2000,3000]. keep_blocks=1000 alone would allow pruning
         * up to height 2000 (files 1 and 2). */
        for (int i = 0; i < 3001; i++) {
            f.blocks[i].nStatus = BLOCK_HAVE_DATA;
            if (i < 1000)       f.blocks[i].nFile = 1;
            else if (i < 2000)  f.blocks[i].nFile = 2;
            else                f.blocks[i].nFile = 3;
        }
        create_fake_block_file(f.datadir, 1, "blk", 4096);
        create_fake_block_file(f.datadir, 2, "blk", 4096);
        create_fake_block_file(f.datadir, 3, "blk", 4096);
        f.svc.keep_blocks = 1000;

        /* Caller has only sealed+verified [0,1000) — file 2 (max_h=1999) is
         * NOT yet covered by any proven sealed range, even though it is
         * "old enough" by keep_blocks. It must survive. */
        int p1 = block_pruning_prune_sealed_range(&f.svc, 1000);
        PRUNE_CHECK("prune_sealed_range: prunes only the sealed+verified file",
                    p1 == 1);
        PRUNE_CHECK("prune_sealed_range: blk00001.dat deleted (sealed)",
                    !fake_file_exists(f.datadir, 1, "blk"));
        PRUNE_CHECK("prune_sealed_range: blk00002.dat SURVIVES (unsealed, "
                    "despite keep_blocks allowing it)",
                    fake_file_exists(f.datadir, 2, "blk"));
        PRUNE_CHECK("prune_sealed_range: blk00003.dat SURVIVES (unsealed)",
                    fake_file_exists(f.datadir, 3, "blk"));

        /* Now the caller has sealed+verified all the way to height 3000 —
         * but keep_blocks still floors at chain_height(3000)-1000=2000, so
         * file 3 (max_h=3000 >= 2000) must still survive: the retention
         * floor and the seal-proof floor both apply (intersection, not
         * whichever is looser). */
        int p2 = block_pruning_prune_sealed_range(&f.svc, 3001);
        PRUNE_CHECK("prune_sealed_range: keep_blocks floor still applies "
                    "even when the seal boundary is deep", p2 == 1);
        PRUNE_CHECK("prune_sealed_range: blk00002.dat now deleted",
                    !fake_file_exists(f.datadir, 2, "blk"));
        PRUNE_CHECK("prune_sealed_range: blk00003.dat still survives "
                    "(keep_blocks floor, max_h=3000 >= 2000)",
                    fake_file_exists(f.datadir, 3, "blk"));

        /* NULL svc / zero-range are safe no-ops. */
        PRUNE_CHECK("prune_sealed_range: NULL svc returns 0",
                    block_pruning_prune_sealed_range(NULL, 5000) == 0);

        fixture_destroy(&f);
    }

    /* ── 7. Status snapshot works ─────────────────────── */
    {
        struct block_pruning_service svc;
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);

        block_pruning_init(&svc, &ms, "/tmp/fake");

        struct block_pruning_status st;
        block_pruning_get_status(&svc, &st);
        PRUNE_CHECK("prune: initial state is IDLE",
                    st.state == BLOCK_PRUNING_IDLE);
        PRUNE_CHECK("prune: initial files_pruned is 0",
                    st.files_pruned == 0);
        PRUNE_CHECK("prune: default keep_blocks is 1000",
                    st.keep_blocks == BLOCK_PRUNING_DEFAULT_KEEP_BLOCKS);

        active_chain_free(&ms.chain_active);
    }

    /* ── 8. NULL svc doesn't crash ────────────────────── */
    {
        int p = block_pruning_run_once(NULL);
        PRUNE_CHECK("prune: run_once(NULL) returns 0", p == 0);

        struct block_pruning_status st;
        block_pruning_get_status(NULL, &st);
        PRUNE_CHECK("prune: get_status(NULL) returns zeroed status",
                    st.state == 0 && st.files_pruned == 0);
    }

    /* ── 9. Minimum keep_blocks enforced ──────────────── */
    {
        struct block_pruning_service svc;
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);

        /* Temporarily set env to something too low */
        setenv("ZCL_PRUNE_KEEP_BLOCKS", "10", 1);
        block_pruning_init(&svc, &ms, "/tmp/fake");
        PRUNE_CHECK("prune: keep_blocks clamped to default when env too low",
                    svc.keep_blocks == BLOCK_PRUNING_DEFAULT_KEEP_BLOCKS);

        /* Valid env */
        setenv("ZCL_PRUNE_KEEP_BLOCKS", "500", 1);
        block_pruning_init(&svc, &ms, "/tmp/fake");
        PRUNE_CHECK("prune: keep_blocks reads valid env",
                    svc.keep_blocks == 500);

        /* Clean up env */
        unsetenv("ZCL_PRUNE_KEEP_BLOCKS");
        active_chain_free(&ms.chain_active);
    }

    /* ── 10. Start/stop lifecycle ─────────────────────── */
    {
        supervisor_reset_for_testing();
        struct prune_fixture f;
        fixture_init(&f, 100, "lifecycle");
        f.svc.tick_seconds = 3600;  /* long tick so thread doesn't run_once */

        bool start_ok = block_pruning_start(&f.svc).ok;
        PRUNE_CHECK("prune: start() succeeds", start_ok);

        bool start2 = block_pruning_start(&f.svc).ok;
        PRUNE_CHECK("prune: second start() rejected", !start2);

        /* start() blocks until the thread is live — no sleep needed. */
        struct block_pruning_status st;
        block_pruning_get_status(&f.svc, &st);
        PRUNE_CHECK("prune: state is RUNNING after start",
                    st.state == BLOCK_PRUNING_RUNNING);

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int snap_n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        bool saw_contract = false;
        bool period_ok = false;
        bool deadline_ok = false;
        bool progress_ok = false;
        for (int i = 0; i < snap_n; i++) {
            if (strcmp(snaps[i].name, "chain.block_pruning") == 0) {
                saw_contract = true;
                period_ok = snaps[i].period_secs == 0;
                deadline_ok =
                    snaps[i].deadline_secs == (int64_t)f.svc.tick_seconds * 3 + 30;
                progress_ok = snaps[i].progress_marker == 0;
                break;
            }
        }
        PRUNE_CHECK("prune: supervisor contract registered", saw_contract);
        PRUNE_CHECK("prune: supervisor observes worker thread", period_ok);
        PRUNE_CHECK("prune: supervisor deadline tracks tick", deadline_ok);
        PRUNE_CHECK("prune: supervisor progress starts at zero", progress_ok);

        block_pruning_stop(&f.svc);
        block_pruning_get_status(&f.svc, &st);
        PRUNE_CHECK("prune: state is STOPPED after stop",
                    st.state == BLOCK_PRUNING_STOPPED);
        PRUNE_CHECK("prune: supervisor child removed after test stop",
                    supervisor_child_count_total() == 0);

        block_pruning_stop(&f.svc);  /* safe no-op */
        PRUNE_CHECK("prune: double stop is safe no-op", true);

        fixture_destroy(&f);
        supervisor_reset_for_testing();
    }

    event_clear_observers(EV_BLOCK_PRUNING_DONE);
    return failures;
}
