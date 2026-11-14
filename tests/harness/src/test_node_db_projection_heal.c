/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* node.db projection heal: a reorg that replaces an indexed block, a boot
 * cursor that must not claim rows node.db lost, and a lean replay that must
 * not erase imported roots. Every fixture is a private temporary datadir. */

#include "test/test_core.h"
#include "config/boot_projection_hole_scan.h"
#include "config/boot_background_workers.h"
#include "config/boot_internal.h"
#include "config/db_service.h"
#include "jobs/node_pace.h"
#include "services/node_db_catchup_owed.h"
#include "platform/time_compat.h"
#include "util/util.h"
#ifndef _WIN32
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#endif
#include "controllers/sync_controller.h"
#include "models/block.h"
#include "models/database.h"
#include "services/node_db_catchup_service.h"
#include "chain/chain.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "validation/chainstate.h"
#include <sqlite3.h>

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PH_CHECK(name, expr) do { \
    printf("node_db_projection_heal: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* NOT NULL solution column: any non-empty blob satisfies it. */
static uint8_t g_ph_solution[1] = {0x01};

/* One-coinbase block on disk; nonce picks a distinct hash. */
static bool ph_write_block(const char *dir, uint32_t nonce,
                           struct disk_block_pos *pos, struct uint256 *hash)
{
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    struct block b;
    block_init(&b);
    b.header.nVersion = 4;
    b.header.nTime = 1700000123u + nonce;
    b.header.nBits = 0x2000ffffu;
    b.header.hashPrevBlock.data[0] = 0x01;
    b.header.hashMerkleRoot.data[0] = (uint8_t)(0x60 + nonce);
    b.num_vtx = 1;
    b.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    bool ok = false;
    if (b.vtx) {
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].sequence = 0xffffffffu;
        b.vtx[0].vout[0].value = 5000000000LL + nonce;
        disk_block_pos_init(pos);
        ok = write_block_to_disk(&b, pos, dir, msg_start);
        block_get_hash(&b, hash);
    }
    block_free(&b);
    return ok;
}

static int ph_connected_rows(struct node_db *ndb, int height,
                             const uint8_t hash[32])
{
    sqlite3_stmt *stmt = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT count(*) FROM blocks WHERE height=? AND status>=3 "
            "AND hash=?", -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(stmt, 1, height);
    sqlite3_bind_blob(stmt, 2, hash, 32, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

/* Two competing bodies at height 1 (A then B) and an active chain holding
 * either, under a fresh datadir with node.db. */
struct ph_fork_fx {
    char dir[256];
    struct uint256 hashA, hashB;
    struct block_index slotA, slotB;
    struct active_chain ac;
    struct node_db ndb;
    bool opened;
};

static void ph_slot(struct block_index *s, const struct disk_block_pos *pos,
                    struct uint256 *hash, unsigned status)
{
    memset(s, 0, sizeof(*s));
    s->nHeight = 1;
    s->nStatus = status;
    s->nFile = pos->nFile;
    s->nDataPos = pos->nPos;
    s->phashBlock = hash;
}

static void ph_fork_open(struct ph_fork_fx *x, const char *tag,
                         unsigned b_status)
{
    char blocks[512], path[512];
    test_make_tmpdir(x->dir, sizeof(x->dir), "node_db_projection_heal", tag);
    snprintf(blocks, sizeof(blocks), "%s/blocks", x->dir);
    mkdir(blocks, 0755);
    struct disk_block_pos posA, posB;
    bool wrote = ph_write_block(x->dir, 1, &posA, &x->hashA) &&
                 ph_write_block(x->dir, 2, &posB, &x->hashB);
    ph_slot(&x->slotA, &posA, &x->hashA, BLOCK_HAVE_DATA);
    ph_slot(&x->slotB, &posB, &x->hashB, b_status);
    active_chain_init(&x->ac);
    snprintf(path, sizeof(path), "%s/node.db", x->dir);
    x->opened = wrote && active_chain_install_tip_slot(&x->ac, &x->slotA) &&
                node_db_open(&x->ndb, path);
}

static void ph_fork_close(struct ph_fork_fx *x)
{
    if (x->opened)
        node_db_close(&x->ndb);
    active_chain_free(&x->ac);
    test_cleanup_tmpdir(x->dir);
}

/* A is indexed at height 1; the active chain then switches to B at the same
 * height (tip height unchanged). The projection must end with B as the single
 * connected row and A demoted. */
static int ph_check_reorg_replaces_projected_tip(void)
{
    int failures = 0;
    struct ph_fork_fx x;
    memset(&x, 0, sizeof(x));
    ph_fork_open(&x, "reorg", BLOCK_HAVE_DATA);
    int r1 = x.opened
        ? node_db_catchup_service_run(&x.ndb, &x.ac, NULL, x.dir) : -1;
    PH_CHECK("reorg fixture: A projected at height 1",
             r1 == 1 && ph_connected_rows(&x.ndb, 1, x.hashA.data) == 1 &&
             node_db_sync_get_tip_height(&x.ndb) == 1);

    active_chain_init(&x.ac);
    bool swapped = x.opened && active_chain_install_tip_slot(&x.ac, &x.slotB);
    int r2 = swapped
        ? node_db_catchup_service_run(&x.ndb, &x.ac, NULL, x.dir) : -1;
    PH_CHECK("reorg: winner B is the single connected row at its height",
             swapped && r2 >= 0 &&
             ph_connected_rows(&x.ndb, 1, x.hashB.data) == 1);
    PH_CHECK("reorg: loser A is demoted below connected",
             x.opened && ph_connected_rows(&x.ndb, 1, x.hashA.data) == 0);
    ph_fork_close(&x);
    return failures;
}

/* The heal fires only for a real loser: a missing active slot and a winner
 * without body data leave the cursor alone (else the backfill loop livelocks);
 * a body-bearing winner heals once and is then quiet. */
static int ph_noop_checks(struct ph_fork_fx *x)
{
    int failures = 0;
    struct node_db *ndb = &x->ndb;
    struct active_chain none;
    active_chain_init(&none);
    PH_CHECK("missing active slot does not rewind",
             !node_db_catchup_service_rewind_stale_fork(ndb, &none) &&
             node_db_sync_get_tip_height(ndb) == 1);
    active_chain_free(&none);

    active_chain_init(&x->ac);
    bool swapped = active_chain_install_tip_slot(&x->ac, &x->slotB);
    bool first = swapped &&
        !node_db_catchup_service_rewind_stale_fork(ndb, &x->ac);
    bool second = swapped &&
        !node_db_catchup_service_rewind_stale_fork(ndb, &x->ac);
    PH_CHECK("winner without body data does not rewind (twice)",
             first && second && node_db_sync_get_tip_height(ndb) == 1 &&
             ph_connected_rows(ndb, 1, x->hashA.data) == 1);

    x->slotB.nStatus = BLOCK_HAVE_DATA;
    bool healed = swapped &&
        node_db_catchup_service_rewind_stale_fork(ndb, &x->ac);
    int rc = healed ? node_db_catchup_service_run(ndb, &x->ac, NULL, x->dir)
                    : -1;
    int cursor = node_db_sync_get_tip_height(ndb);
    PH_CHECK("body-bearing winner heals once",
             healed && rc >= 0 &&
             ph_connected_rows(ndb, 1, x->hashB.data) == 1);
    PH_CHECK("repeat call after healing returns false, cursor unchanged",
             !node_db_catchup_service_rewind_stale_fork(ndb, &x->ac) &&
             node_db_sync_get_tip_height(ndb) == cursor);
    return failures;
}

static int ph_check_reorg_no_spurious_rewind(void)
{
    int failures = 0;
    struct ph_fork_fx x;
    memset(&x, 0, sizeof(x));
    ph_fork_open(&x, "noop", 0);
    int r1 = x.opened
        ? node_db_catchup_service_run(&x.ndb, &x.ac, NULL, x.dir) : -1;
    PH_CHECK("no-op fixture: A projected",
             r1 == 1 && node_db_sync_get_tip_height(&x.ndb) == 1);
    if (x.opened)
        failures += ph_noop_checks(&x);
    ph_fork_close(&x);
    return failures;
}

/* ── boot cursor ─────────────────────────────────────────────── */

#define PH_CHAIN_N 5

struct ph_chain_fx {
    char dir[256];
    struct uint256 hash[PH_CHAIN_N];
    struct block_index slot[PH_CHAIN_N];
    struct active_chain ac;
    struct node_db ndb;
    bool opened;
    bool db_up;
};

/* Slots 1..PH_CHAIN_N-1 on the active chain; heights >= first_bodiless carry
 * no body data. Connected node.db rows only at heights 1..rows. */
static void ph_chain_open(struct ph_chain_fx *x, int rows, int first_bodiless)
{
    char path[512];
    test_make_tmpdir(x->dir, sizeof(x->dir), "node_db_projection_heal",
                     "cursor");
    snprintf(path, sizeof(path), "%s/node.db", x->dir);
    active_chain_init(&x->ac);
    x->db_up = node_db_open(&x->ndb, path);
    x->opened = x->db_up;
    for (int h = 1; h < PH_CHAIN_N && x->opened; h++) {
        memset(&x->hash[h], 0, sizeof(x->hash[h]));
        x->hash[h].data[0] = (uint8_t)(0x40 + h);
        memset(&x->slot[h], 0, sizeof(x->slot[h]));
        x->slot[h].nHeight = h;
        x->slot[h].nStatus = h >= first_bodiless ? 0 : BLOCK_HAVE_DATA;
        x->slot[h].phashBlock = &x->hash[h];
        x->opened = active_chain_install_tip_slot(&x->ac, &x->slot[h]);
        if (h > rows)
            continue;
        struct db_block row;
        memset(&row, 0, sizeof(row));
        memcpy(row.hash, x->hash[h].data, 32);
        row.height = h;
        row.solution = g_ph_solution;
        row.solution_len = sizeof(g_ph_solution);
        row.prev_hash[0] = 0x01;
        row.merkle_root[0] = 0x02;
        row.time = 1700000000u + (uint32_t)h;
        row.bits = 0x2000ffffu;
        row.status = 3;
        x->opened = db_block_save(&x->ndb, &row);
    }
    if (x->opened)
        node_db_sync_set_tip(&x->ndb, x->hash[PH_CHAIN_N - 1].data,
                             PH_CHAIN_N - 1);
}

static void ph_chain_close(struct ph_chain_fx *x)
{
    if (x->db_up)
        node_db_close(&x->ndb);
    active_chain_free(&x->ac);
    test_cleanup_tmpdir(x->dir);
}

static int ph_check_finalize_cursor(void)
{
    int failures = 0;
    struct ph_chain_fx x;
    memset(&x, 0, sizeof(x));

    /* Rows end at 2, tip is 4, bodies exist: the cursor drops to the top row
     * so catchup refills 3..4 instead of resuming above the lost range. */
    ph_chain_open(&x, 2, PH_CHAIN_N);
    int got = -1;
    bool ok = x.opened &&
        boot_projection_finalize_cursor(&x.ndb, &x.ac, &got);
    PH_CHECK("rows end below tip: cursor clamps to the top row",
             ok && got == 2 && node_db_sync_get_tip_height(&x.ndb) == 2);
    ph_chain_close(&x);

    /* Fully projected: stays at the tip. */
    ph_chain_open(&x, 4, PH_CHAIN_N);
    ok = x.opened && boot_projection_finalize_cursor(&x.ndb, &x.ac, &got);
    PH_CHECK("fully projected: cursor stays at the tip",
             ok && got == 4 && node_db_sync_get_tip_height(&x.ndb) == 4);
    ph_chain_close(&x);

    /* The next height has no body: catchup could only record a lean hole, so
     * rewinding would replay to the tip on every boot. */
    ph_chain_open(&x, 2, 3);
    ok = x.opened && boot_projection_finalize_cursor(&x.ndb, &x.ac, &got);
    PH_CHECK("bodiless next height: cursor stays at the tip",
             ok && got == 4 && node_db_sync_get_tip_height(&x.ndb) == 4);
    ph_chain_close(&x);

    /* No connected rows (sparse / imported history): explicit tip jump. */
    ph_chain_open(&x, 0, PH_CHAIN_N);
    ok = x.opened && boot_projection_finalize_cursor(&x.ndb, &x.ac, &got);
    PH_CHECK("no connected rows: cursor jumps to the tip",
             ok && got == 4 && node_db_sync_get_tip_height(&x.ndb) == 4);
    ph_chain_close(&x);
    return failures;
}

/* ── lean replay keeps populated roots ───────────────────────── */

static void ph_fill_row(struct db_block *row, uint8_t fill_root, int undo)
{
    memset(row, 0, sizeof(*row));
    row->hash[0] = 0x77;
    row->height = 3;
    row->solution = g_ph_solution;
    row->solution_len = sizeof(g_ph_solution);
    row->prev_hash[0] = 0x01;
    row->merkle_root[0] = 0x02;
    row->time = 1700000003u;
    row->bits = 0x2000ffffu;
    row->status = 3;
    row->undo_pos = undo;
    memset(row->sapling_root, fill_root, 32);
    memset(row->sprout_root, fill_root, 32);
}

static bool ph_roots_are(struct node_db *ndb, uint8_t want, int want_undo)
{
    struct db_block got;
    uint8_t expect[32];
    memset(expect, want, sizeof(expect));
    uint8_t hash[32] = {0x77};
    return db_block_find_by_hash(ndb, hash, &got) &&
           memcmp(got.sapling_root, expect, 32) == 0 &&
           memcmp(got.sprout_root, expect, 32) == 0 &&
           got.undo_pos == want_undo;
}

static int ph_check_lean_replay_keeps_roots(void)
{
    int failures = 0;
    char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "node_db_projection_heal", "roots");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    bool up = node_db_open(&ndb, path);
    struct db_block imported, lean, body;
    ph_fill_row(&imported, 0xab, 9);
    ph_fill_row(&lean, 0x00, 0);
    ph_fill_row(&body, 0xcd, 0);
    PH_CHECK("imported row saved", up && db_block_save(&ndb, &imported) &&
             ph_roots_are(&ndb, 0xab, 9));
    PH_CHECK("lean replay keeps imported roots and undo position",
             up && db_block_save_canonical(&ndb, &lean) &&
             ph_roots_are(&ndb, 0xab, 9));
    PH_CHECK("body-derived roots still overwrite",
             up && db_block_save_canonical(&ndb, &body) &&
             ph_roots_are(&ndb, 0xcd, 9));
    PH_CHECK("plain db_block_save keeps full-replace semantics",
             up && db_block_save(&ndb, &lean) && ph_roots_are(&ndb, 0x00, 0));
    if (up)
        node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}

#ifndef _WIN32
struct ph_writer_barrier { _Atomic bool entered; _Atomic bool release; };
struct ph_writer_job { struct ph_writer_barrier *barrier; };

static bool ph_block_writer(struct node_db *ndb, void *ctx)
{
    (void)ndb;
    struct ph_writer_job *job = ctx;
    struct ph_writer_barrier *b = job->barrier;
    atomic_store(&b->entered, true);
    while (!atomic_load(&b->release)) platform_sleep_ms(5);
    return true;
}

static bool ph_index_present(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;
    bool present = sqlite3_prepare_v2(ndb->db, "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_utxo_address'", -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW;
    sqlite3_finalize(s);
    return present;
}

static int ph_synchronous(struct node_db *ndb)
{
    sqlite3_stmt *s = NULL;
    int mode = -1;
    if (sqlite3_prepare_v2(ndb->db, "PRAGMA synchronous", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW) mode = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return mode;
}

struct ph_thermal {
    struct ph_chain_fx x;
    struct db_service ds;
    struct main_state *ms;
    struct boot_svc_ctx *svc;
    _Atomic bool running;
    enum node_pace saved;
    char saved_datadir[4096], blocks[512];
    bool up, ms_initialized, db_started, owed, index_before, index_dropped;
    int normal_sync;
    struct ph_writer_barrier barrier;
    bool queued;
    unsigned v0, s0, j0, v, s, j;
    int64_t first_marker;
};

static bool ph_thermal_bodies(struct ph_thermal *t)
{
    ph_chain_open(&t->x, 0, PH_CHAIN_N);
    snprintf(t->blocks, sizeof(t->blocks), "%s/blocks", t->x.dir);
    bool ok = mkdir(t->blocks, 0755) == 0;
    for (int h = 1; h < PH_CHAIN_N && ok; h++) {
        struct disk_block_pos pos = {0};
        ok = ph_write_block(t->x.dir, (uint32_t)h, &pos, &t->x.hash[h]);
        t->x.slot[h].nFile = pos.nFile;
        t->x.slot[h].nDataPos = pos.nPos;
    }
    return ok && node_db_sync_set_tip(&t->x.ndb, t->x.hash[1].data, 1);
}

static void ph_thermal_setup(struct ph_thermal *t)
{
    t->ms = calloc(1, sizeof(*t->ms)); // raw-alloc-ok:test-fixture
    t->svc = calloc(1, sizeof(*t->svc)); // raw-alloc-ok:test-fixture
    atomic_store(&t->running, true);
    t->saved = node_pace_get();
    GetDataDir(false, t->saved_datadir, sizeof(t->saved_datadir));
    bool bodies = ph_thermal_bodies(t);
    db_service_init(&t->ds);
    t->up = t->ms && t->svc && t->x.opened && bodies && SetDataDir(t->x.dir);
    if (!t->up) return;
    main_state_init(t->ms);
    t->ms_initialized = true;
    for (int h = 1; h < PH_CHAIN_N && t->up; h++)
        t->up = active_chain_install_tip_slot(&t->ms->chain_active, &t->x.slot[h]);
    t->up = t->up && db_service_attach(&t->ds, &t->x.ndb) &&
            db_service_start_test_worker(&t->ds);
    t->db_started = t->up;
}

static void ph_thermal_queue(struct ph_thermal *t)
{
    t->normal_sync = t->up ? ph_synchronous(&t->x.ndb) : -1;
    t->index_before = t->up && ph_index_present(&t->x.ndb);
    struct sync_db_turbo_scope scope = {0};
    t->owed = t->up && sync_db_turbo_scope_begin(&scope, &t->x.ndb, true);
    t->index_dropped = t->owed && !ph_index_present(&t->x.ndb);
    if (t->owed) node_db_catchup_owed_defer(&scope);
    struct ph_writer_job *writer = t->owed ? malloc(sizeof(*writer)) : NULL; // raw-alloc-ok:test-fixture
    if (writer) writer->barrier = &t->barrier;
    t->queued = writer && db_service_enqueue_write(&t->ds, ph_block_writer, writer, free);
    for (int i = 0; t->queued && i < 100 && !atomic_load(&t->barrier.entered); i++)
        platform_sleep_ms(10); /* real-clock: wait for the actual database worker thread */
}

static int ph_thermal_start(struct ph_thermal *t)
{
    int failures = 0;
    boot_projection_test_counts(&t->v0, &t->s0, &t->j0);
    node_pace_set(NODE_PACE_GENTLE);
    if (t->up) {
        t->svc->state = t->ms; t->svc->running = &t->running;
        t->svc->datadir = t->x.dir; t->svc->runtime.db_service = &t->ds;
        t->up = boot_start_projection_backfill_service(t->svc);
    }
    struct db_service_status status = {0};
    for (int i = 0; t->up && i < 100; i++) {
        db_service_get_status(&t->ds, &status);
        if (status.queue_depth > 0) break;
        platform_sleep_ms(10); /* real-clock: projection worker queues restore behind held database writer */
    }
    PH_CHECK("gentle queues owed restore behind writer",
             t->queued && atomic_load(&t->barrier.entered) && status.queue_depth > 0);
    atomic_store(&t->barrier.release, true);
    return failures;
}

static int ph_thermal_check_gentle(struct ph_thermal *t)
{
    int failures = 0;
    for (int i = 0; t->up && i < 100; i++) {
        boot_projection_test_counts(&t->v, &t->s, &t->j);
        if (t->v > t->v0 && t->first_marker == 0)
            t->first_marker = boot_projection_test_marker();
        if (t->v >= t->v0 + 2) break;
        platform_sleep_ms(100); /* real-clock: wait for the actual projection worker thread */
    }
    PH_CHECK("gentle worker preserves cursor and skips history",
             t->up && t->v >= t->v0 + 2 && t->s == t->s0 && t->j == t->j0 &&
             node_db_sync_get_tip_height(&t->x.ndb) == 1);
    PH_CHECK("gentle quiescent progress advances",
             t->first_marker != 0 && boot_projection_test_marker() > t->first_marker);
    PH_CHECK("gentle restores database synchronization",
             t->normal_sync >= 0 && ph_synchronous(&t->x.ndb) == t->normal_sync);
    PH_CHECK("gentle restores dropped index",
             t->index_before && t->index_dropped && ph_index_present(&t->x.ndb));
    return failures;
}

static int ph_thermal_check_normal(struct ph_thermal *t)
{
    int failures = 0;
    node_pace_set(NODE_PACE_NORMAL);
    for (int i = 0; t->up && i < 100; i++) {
        boot_projection_test_counts(&t->v, &t->s, &t->j);
        if (t->j > t->j0 && node_db_sync_get_tip_height(&t->x.ndb) >= 2) break;
        platform_sleep_ms(100); /* real-clock: wait for the actual projection worker thread */
    }
    PH_CHECK("normal worker advances durable cursor",
             t->up && t->s > t->s0 && t->j > t->j0 &&
             node_db_sync_get_tip_height(&t->x.ndb) >= 2);
    return failures;
}

static void ph_thermal_cleanup(struct ph_thermal *t)
{
    if (t->svc && t->svc->projection_backfill_thread_started)
        boot_join_projection_backfill_service(t->svc);
    if (t->svc) boot_join_catchup_service(t->svc);
    if (t->db_started) db_service_stop(&t->ds);
    if (t->owed) (void)node_db_catchup_service_restore_owed(&t->x.ndb);
    if (t->ms_initialized) main_state_free(t->ms);
    free(t->ms); free(t->svc);
    (void)SetDataDir(t->saved_datadir);
    char blk[512];
    snprintf(blk, sizeof(blk), "%s/blk00000.dat", t->blocks);
    (void)unlink(blk); (void)rmdir(t->blocks);
    ph_chain_close(&t->x); node_pace_set(t->saved);
}

static int ph_check_thermal_worker_inner(void)
{
    struct ph_thermal t = {0};
    ph_thermal_setup(&t);
    ph_thermal_queue(&t);
    int failures = ph_thermal_start(&t);
    failures += ph_thermal_check_gentle(&t);
    failures += ph_thermal_check_normal(&t);
    ph_thermal_cleanup(&t);
    return failures;
}

static int ph_check_thermal_worker(void)
{
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        int failures = ph_check_thermal_worker_inner();
        fflush(NULL);
        _exit(failures ? 1 : 0);
    }
    if (child < 0) return 1;
    int status = 0;
    int64_t deadline = platform_time_monotonic_ms() + 30000;
    while (platform_time_monotonic_ms() < deadline) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (r < 0 && errno != EINTR) break;
        platform_sleep_ms(100);
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return 1;
}
#endif

int test_node_db_projection_heal(void)
{
    int failures = 0;
#ifndef _WIN32
    failures += ph_check_thermal_worker();
#endif
    failures += ph_check_reorg_replaces_projected_tip();
    failures += ph_check_reorg_no_spurious_rewind();
    failures += ph_check_finalize_cursor();
    failures += ph_check_lean_replay_keeps_roots();
    printf("node_db_projection_heal: %d failures\n", failures);
    return failures;
}
