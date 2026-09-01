/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the Wave S S-2 header_admit stage
 * (engine/jobs/src/header_admit_stage.c).
 *
 * Coverage:
 *   - init / shutdown round-trip; idempotent re-init
 *   - drain a 5-block synthetic chain → cursor = 5, log has 5 rows
 *   - extra drain after no-more-blocks → IDLE, cursor unchanged
 *   - missing-pprev → JOB_BLOCKED with PERMANENT typed blocker
 *   - replay across progress_store close/reopen: cursor + log persist */

#include "test/test_core.h"
#include "json/json.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "jobs/header_admit_stage.h"
#include "jobs/reducer_frontier.h"
#include "services/header_admit_inbox.h"
#include "jobs/validate_headers_stage.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/chainstate.h"
#include "validation/main_logic.h"
#include "validation/main_state.h"

#include "../../../engine/jobs/src/header_admit_forward_rewind.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HA_CHECK(name, expr) do { \
    printf("header_admit: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static int mkdir_p_ha(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* Build a chain of `n` synthetic block_index entries linked via pprev,
 * with deterministic hashes derived from height. Caller owns the
 * blocks + hashes arrays. */
struct synth_chain {
    struct block_index *blocks;
    struct uint256     *hashes;
    int                 n;
};

static bool synth_chain_build(struct synth_chain *sc, int n)
{
    memset(sc, 0, sizeof(*sc));
    sc->blocks = zcl_malloc(
        (size_t)n * sizeof(struct block_index), "synth_blocks");
    if (!sc->blocks) return false;
    sc->hashes = zcl_malloc(
        (size_t)n * sizeof(struct uint256), "synth_hashes");
    if (!sc->hashes) { free(sc->blocks); return false; }
    for (int i = 0; i < n; i++) {
        block_index_init(&sc->blocks[i]);
        memset(&sc->hashes[i], 0, sizeof(struct uint256));
        sc->hashes[i].data[0] = (uint8_t)(i & 0xFF);
        sc->hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
        sc->hashes[i].data[2] = 0xAB;  /* distinguish from null */
        sc->blocks[i].phashBlock = &sc->hashes[i];
        sc->blocks[i].nHeight = i;
        if (i > 0) sc->blocks[i].pprev = &sc->blocks[i - 1];
    }
    sc->n = n;
    return true;
}

static void synth_chain_free(struct synth_chain *sc)
{
    free(sc->blocks);
    free(sc->hashes);
    memset(sc, 0, sizeof(*sc));
}

/* SELECT COUNT(*) FROM header_admit_log. */
static int log_row_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM header_admit_log",
        -1, &st, NULL) != SQLITE_OK) return -1;
    int n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* SELECT hash FROM header_admit_log WHERE height=?. Copies up to 32
 * bytes into `out` and sets `*found`. */
static bool log_hash_at(sqlite3 *db, int height,
                        uint8_t out[32], bool *found)
{
    *found = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT hash FROM header_admit_log WHERE height=?",
        -1, &st, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(st, 1, height);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int nb = sqlite3_column_bytes(st, 0);
        if (blob && nb == 32) {
            memcpy(out, blob, 32);
            *found = true;
        }
    }
    sqlite3_finalize(st);
    return true;
}

static bool force_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO stage_cursor(name, cursor, updated_at) "
            "VALUES(?,?,0) "
            "ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor, "
            "updated_at=excluded.updated_at",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static int cursor_at(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int out = -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return out;
}

static bool put_header_row(sqlite3 *db, int height,
                           const struct uint256 *hash,
                           const struct uint256 *parent)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) "
            "VALUES(?,?,?,0)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    if (parent) {
        sqlite3_bind_blob(st, 3, parent->data, 32, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(st, 3);
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

struct auth_hook_state {
    int calls;
    int height;
};

static bool auth_observer(struct main_state *ms,
                          struct block_index *bi,
                          void *user)
{
    struct auth_hook_state *st = user;
    if (!st || !ms || !bi)
        return false;
    st->calls++;
    st->height = bi->nHeight;
    return true;
}

int test_header_admit_stage(void)
{
    printf("\n=== header_admit_stage tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── happy path: drain a 5-block synthetic chain ───────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","happy");
        mkdir_p_ha(dir);

        HA_CHECK("progress_store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);

        struct synth_chain sc;
        HA_CHECK("synth chain builds", synth_chain_build(&sc, 5));
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[4]);

        HA_CHECK("stage init", header_admit_stage_init(&ms));
        HA_CHECK("init is idempotent (same ms)",
                 header_admit_stage_init(&ms));

        uint64_t audits_before = header_admit_stage_reorg_audit_total();
        int advanced = header_admit_stage_drain(100);
        HA_CHECK("drain advances 5 times", advanced == 5);
        HA_CHECK("one bounded reorg audit per drain batch",
                 header_admit_stage_reorg_audit_total() == audits_before + 1);
        HA_CHECK("cursor reaches 5",
                 header_admit_stage_cursor() == 5);
        HA_CHECK("admitted_total == 5",
                 header_admit_stage_admitted_total() == 5);

        sqlite3 *db = progress_store_db();
        HA_CHECK("log has 5 rows", log_row_count(db) == 5);

        /* Spot-check hashes round-trip. */
        for (int h = 0; h < 5; h++) {
            uint8_t got[32];
            bool found = false;
            log_hash_at(db, h, got, &found);
            if (!found) { failures++; printf("FAIL log_hash_at(%d) missing\n", h); continue; }
            HA_CHECK("logged hash matches synth hash",
                     memcmp(got, sc.hashes[h].data, 32) == 0);
        }

        /* Extra drain → IDLE, no change. */
        job_result_t r = header_admit_stage_step_once();
        HA_CHECK("next step is IDLE", r == JOB_IDLE);
        HA_CHECK("cursor unchanged after IDLE",
                 header_admit_stage_cursor() == 5);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── replay across reopen: cursor + log persist ────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","replay");
        mkdir_p_ha(dir);

        HA_CHECK("replay: store opens", progress_store_open(dir));
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 3);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[2]);

        HA_CHECK("replay: init", header_admit_stage_init(&ms));
        HA_CHECK("replay: drain 3",
                 header_admit_stage_drain(100) == 3);

        /* Tear down: shutdown stage, close store. */
        header_admit_stage_shutdown();
        progress_store_close();

        /* Reopen. Cursor must be remembered. */
        HA_CHECK("replay: reopen store", progress_store_open(dir));
        HA_CHECK("replay: re-init stage",
                 header_admit_stage_init(&ms));
        /* Stage cursor reflects persisted state on first step. */
        job_result_t r = header_admit_stage_step_once();
        HA_CHECK("replay: first step after reopen is IDLE (cursor=3)",
                 r == JOB_IDLE);
        HA_CHECK("replay: cursor restored to 3",
                 header_admit_stage_cursor() == 3);

        sqlite3 *db = progress_store_db();
        HA_CHECK("replay: log still has 3 rows",
                 log_row_count(db) == 3);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── missing-pprev → JOB_BLOCKED ─────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","blocked");
        mkdir_p_ha(dir);
        HA_CHECK("blocked: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 3);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[2]);
        /* Sabotage AFTER set_tip: a NULL pprev set first would make the
         * chain-walker stop at the broken link and leave chain[0] NULL,
         * which would short-circuit genesis admission to IDLE before
         * step 1 ever runs. Setting it after set_tip preserves the
         * chain array but still leaves bi->pprev NULL when step 1
         * inspects it. */
        sc.blocks[1].pprev = NULL;

        HA_CHECK("blocked: init", header_admit_stage_init(&ms));
        /* Step 0 (genesis) succeeds; step 1 hits missing pprev. */
        HA_CHECK("blocked: genesis admits OK",
                 header_admit_stage_step_once() == JOB_ADVANCED);
        job_result_t r = header_admit_stage_step_once();
        HA_CHECK("blocked: step 1 returns BLOCKED", r == JOB_BLOCKED);
        HA_CHECK("blocked: cursor stuck at 1",
                 header_admit_stage_cursor() == 1);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── authoritative path calls the reducer hook ─────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","authoritative");
        mkdir_p_ha(dir);
        HA_CHECK("auth: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 2);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[1]);

        struct auth_hook_state st = {0, -1};
        header_admit_stage_set_authoritative_hook(auth_observer, &st);

        HA_CHECK("auth: init", header_admit_stage_init(&ms));
        HA_CHECK("auth: step calls authoritative hook",
                 header_admit_stage_step_once() == JOB_ADVANCED);
        HA_CHECK("auth: hook saw height 0",
                 st.calls == 1 && st.height == 0);
        HA_CHECK("auth: log still records row",
                 log_row_count(progress_store_db()) == 1);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── producer path: a staged raw header CREATES a block_index ──────
     * Reducer step 2. When the active chain has no block at the needed
     * height, a raw header pushed through the inbox lets the stage build the
     * block_index via add_to_block_index. The reducer extends the chain
     * without legacy accept_block_header. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","producer");
        mkdir_p_ha(dir);
        HA_CHECK("producer: store opens", progress_store_open(dir));

        struct main_state ms;
        main_state_init(&ms);

        /* Parent at height 0, in the map AND the active chain. */
        struct uint256 parent_hash;
        memset(&parent_hash, 0, sizeof(parent_hash));
        parent_hash.data[0] = 0x77;
        struct block_index *parent = chainstate_insert_block_index(
            (struct chainstate *)&ms, &parent_hash);
        HA_CHECK("producer: parent inserted", parent != NULL);
        if (parent) {
            parent->nHeight = 0;
            parent->nStatus = BLOCK_VALID_TREE;
            active_chain_move_window_tip(&ms.chain_active, parent);
            ms.pindex_best_header = parent;
        }

        HA_CHECK("producer: stage init", header_admit_stage_init(&ms));
        HA_CHECK("producer: produced_total starts at 0",
                 header_admit_stage_produced_total() == 0);

        /* A child header for height 1, carried as raw bytes in the inbox. */
        struct block_header child;
        block_header_init(&child);
        child.hashPrevBlock = parent_hash;
        child.nTime = 1;
        child.nBits = 1;
        child.nSolutionSize = 0;
        struct uint256 child_hash;
        block_header_get_hash(&child, &child_hash);

        struct header_admit_msg msg;
        memset(&msg, 0, sizeof(msg));
        msg.height = 1;
        msg.hash = child_hash;
        msg.has_header = true;
        msg.header = child;
        HA_CHECK("producer: push raw header to inbox",
                 mailbox_header_admit_push(&msg));

        /* Before production, the child is not in the block_index. */
        HA_CHECK("producer: child absent from map pre-step",
                 block_map_find(&ms.map_block_index, &child_hash) == NULL);

        /* Step 1 drains the inbox (staging the header) and admits the
         * height-0 parent (already in the active chain). Step 2 hits the
         * absent height 1 → producer path CREATES the entry. */
        HA_CHECK("producer: step 0 admits parent (ADVANCED)",
                 header_admit_stage_step_once() == JOB_ADVANCED);
        HA_CHECK("producer: step 1 produces+admits child (ADVANCED)",
                 header_admit_stage_step_once() == JOB_ADVANCED);

        HA_CHECK("producer: produced_total == 1",
                 header_admit_stage_produced_total() == 1);
        struct block_index *created =
            block_map_find(&ms.map_block_index, &child_hash);
        HA_CHECK("producer: child now in block_index", created != NULL);
        HA_CHECK("producer: created entry at height 1, VALID_TREE",
                 created != NULL && created->nHeight == 1 &&
                 (created->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE);
        HA_CHECK("producer: created links to parent",
                 created != NULL && created->pprev == parent);
        HA_CHECK("producer: cursor advanced to 2",
                 header_admit_stage_cursor() == 2);

        /* A second fresh raw header is staged and produced the same way. */
        struct block_header child2;
        block_header_init(&child2);
        child2.hashPrevBlock = child_hash;
        child2.nTime = 2;
        child2.nBits = 1;
        struct uint256 child2_hash;
        block_header_get_hash(&child2, &child2_hash);
        struct header_admit_msg msg2;
        memset(&msg2, 0, sizeof(msg2));
        msg2.height = 2;
        msg2.hash = child2_hash;
        msg2.has_header = true;
        msg2.header = child2;
        HA_CHECK("producer: push second raw header",
                 mailbox_header_admit_push(&msg2));
        HA_CHECK("producer: step 2 produces+admits child2 (ADVANCED)",
                 header_admit_stage_step_once() == JOB_ADVANCED);
        HA_CHECK("producer: produced_total == 2",
                 header_admit_stage_produced_total() == 2);
        HA_CHECK("producer: child2 now in block_index",
                 block_map_find(&ms.map_block_index, &child2_hash) != NULL);

        header_admit_stage_shutdown();
        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── dump_state_json shape ─────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","dump");
        mkdir_p_ha(dir);
        progress_store_open(dir);

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 2);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[1]);

        header_admit_stage_init(&ms);
        header_admit_stage_drain(100);

        struct json_value v;
        json_init(&v);
        HA_CHECK("dump returns true",
                 header_admit_stage_dump_state_json(&v, NULL));
        char buf[1024];
        size_t n = json_write(&v, buf, sizeof(buf));
        HA_CHECK("dump serializes", n > 0 && n < sizeof(buf));
        HA_CHECK("dump reports initialised=true",
                 strstr(buf, "\"initialised\":true") != NULL);
        HA_CHECK("dump reports cursor",
                 strstr(buf, "\"cursor\":2") != NULL);
        HA_CHECK("dump reports admitted_total",
                 strstr(buf, "\"admitted_total\":2") != NULL);
        json_free(&v);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── pre-init guard ────────────────────────────────────────────── */
    {
        HA_CHECK("step_once with no init returns IDLE",
                 header_admit_stage_step_once() == JOB_IDLE);
        HA_CHECK("init(NULL) rejected",
                 !header_admit_stage_init(NULL));
    }

    /* ── Reorg self-heal: stale row below a matching tip is rewritten ──
     * Mirrors the live first_divergent_height=3129671 case at small
     * scale: the stale log row sits BELOW the (still-matching) tip. The
     * forward-only stage would never revisit it; the reorg-rewind must
     * detect it, rewind the cursor to the fork point, and re-admit
     * (INSERT OR REPLACE) so the canonical hash overwrites the stale one. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","reorg_heal");
        mkdir_p_ha(dir);
        HA_CHECK("reorg_heal: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 5);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[4]);

        HA_CHECK("reorg_heal: init", header_admit_stage_init(&ms));
        HA_CHECK("reorg_heal: drain 5 → cursor=5",
                 header_admit_stage_drain(100) == 5 &&
                 header_admit_stage_cursor() == 5);
        HA_CHECK("reorg_heal: rewind counter starts at 0",
                 header_admit_stage_reorg_rewind_total() == 0);

        /* Reorg height 2 ONLY (cursor-3). The tip rows (3,4) still match
         * the active chain, so a tip-only check would miss this — the
         * divergence is strictly below the matching tip. */
        sc.hashes[2].data[31] ^= 0xFF;

        HA_CHECK("reorg_heal: pre log has stale height 2",
                 !header_admit_stage_has_record(2, &sc.hashes[2]));

        /* Drive steps: the first step's reorg-rewind rewinds the cursor
         * to 2; subsequent steps re-admit 2,3,4 → cursor back to 5. */
        for (int i = 0; i < 8; i++)
            (void)header_admit_stage_step_once();

        HA_CHECK("reorg_heal: rewind fired (counter incremented)",
                 header_admit_stage_reorg_rewind_total() >= 1);
        HA_CHECK("reorg_heal: cursor restored to 5",
                 header_admit_stage_cursor() == 5);
        HA_CHECK("reorg_heal: post log has canonical height 2",
                 header_admit_stage_has_record(2, &sc.hashes[2]));

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Forward-fork self-heal: stale row at active_tip+1 ────────────
     * Live regression: active tip H was correct, but header_admit_log already
     * held rows for H+1.. on a different parent. The below-tip reorg scan could
     * not see the stale row because active_chain_at(H+1) is intentionally NULL.
     * The pre-step repair must clamp downstream cursors and rewind header_admit
     * to H+1. Since header admission is header-only, replay must then source
     * the canonical child from best-header ancestry instead of idling on the
     * body-window accessor. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","forward_fork");
        mkdir_p_ha(dir);
        HA_CHECK("forward_fork: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 5);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[2]);

        HA_CHECK("forward_fork: init", header_admit_stage_init(&ms));
        HA_CHECK("forward_fork: admit active prefix",
                 header_admit_stage_drain(100) == 3 &&
                 header_admit_stage_cursor() == 3);
        ms.pindex_best_header = &sc.blocks[4];
        HA_CHECK("forward_fork: h3 is above active window",
                 active_chain_at(&ms.chain_active, 3) == NULL &&
                 block_index_get_ancestor(ms.pindex_best_header, 3) ==
                     &sc.blocks[3]);

        sqlite3 *db = progress_store_db();
        struct uint256 stale_parent = sc.hashes[2];
        struct uint256 stale_h3 = sc.hashes[3];
        struct uint256 stale_h4 = sc.hashes[4];
        stale_parent.data[7] ^= 0x55;
        stale_h3.data[9] ^= 0x66;
        stale_h4.data[11] ^= 0x77;

        HA_CHECK("forward_fork: seed stale forward rows",
                 put_header_row(db, 3, &stale_h3, &stale_parent) &&
                 put_header_row(db, 4, &stale_h4, &stale_h3));
        HA_CHECK("forward_fork: force cursors ahead",
                 force_cursor(db, "header_admit", 5) &&
                 force_cursor(db, "validate_headers", 5) &&
                 force_cursor(db, "body_fetch", 5) &&
                 force_cursor(db, "body_persist", 5) &&
                 force_cursor(db, "script_validate", 5) &&
                 force_cursor(db, "proof_validate", 5) &&
                 force_cursor(db, "utxo_apply", 5));
        HA_CHECK("forward_fork: stale h3 is not canonical",
                 !header_admit_stage_has_record(3, &sc.hashes[3]));

        job_result_t r = header_admit_stage_step_once();
        HA_CHECK("forward_fork: repair step rewinds and admits h3",
                 r == JOB_ADVANCED);
        HA_CHECK("forward_fork: header cursor advanced past h3",
                 header_admit_stage_cursor() == 4 &&
                 cursor_at(db, "header_admit") == 4);
        HA_CHECK("forward_fork: downstream cursors clamped",
                 cursor_at(db, "validate_headers") == 3 &&
                 cursor_at(db, "body_fetch") == 3 &&
                 cursor_at(db, "body_persist") == 3 &&
                 cursor_at(db, "script_validate") == 3 &&
                 cursor_at(db, "proof_validate") == 3 &&
                 cursor_at(db, "utxo_apply") == 3);
        HA_CHECK("forward_fork: rewind counter incremented",
                 header_admit_stage_reorg_rewind_total() >= 1);
        HA_CHECK("forward_fork: h3 overwritten with canonical hash",
                 header_admit_stage_has_record(3, &sc.hashes[3]));

        HA_CHECK("forward_fork: second step admits h4",
                 header_admit_stage_step_once() == JOB_ADVANCED);
        HA_CHECK("forward_fork: h4 overwritten with canonical hash",
                 header_admit_stage_has_record(4, &sc.hashes[4]) &&
                 header_admit_stage_cursor() == 5);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Forward-fork guard: best-header child must link to active tip ──
     * Live follow-up: after the rewind above, blindly sourcing H+1 from
     * pindex_best_header can re-admit the SAME fork child whose parent does
     * not match the active tip, so the next tick rewinds again forever. A
     * best-header fallback is useful only when it extends the already-visible
     * active parent. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","fork_parent_guard");
        mkdir_p_ha(dir);
        HA_CHECK("fork_guard: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 5);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[2]);

        HA_CHECK("fork_guard: init", header_admit_stage_init(&ms));
        HA_CHECK("fork_guard: admit active prefix",
                 header_admit_stage_drain(100) == 3 &&
                 header_admit_stage_cursor() == 3);

        struct block_index fork_blocks[3];
        struct uint256 fork_hashes[3];
        for (int i = 0; i < 3; i++) {
            block_index_init(&fork_blocks[i]);
            memset(&fork_hashes[i], 0, sizeof(fork_hashes[i]));
            fork_hashes[i].data[0] = (uint8_t)(0xE0 + i);
            fork_hashes[i].data[1] = 0xFA;
            fork_blocks[i].phashBlock = &fork_hashes[i];
            fork_blocks[i].nHeight = 2 + i;
            if (i > 0)
                fork_blocks[i].pprev = &fork_blocks[i - 1];
        }
        ms.pindex_best_header = &fork_blocks[2];

        sqlite3 *db = progress_store_db();
        HA_CHECK("fork_guard: seed fork forward rows",
                 put_header_row(db, 3, &fork_hashes[1], &fork_hashes[0]) &&
                 put_header_row(db, 4, &fork_hashes[2], &fork_hashes[1]));
        HA_CHECK("fork_guard: force header cursor ahead",
                 force_cursor(db, "header_admit", 5));
        HA_CHECK("fork_guard: fork h3 parent mismatches active h2",
                 !uint256_eq(fork_blocks[1].pprev->phashBlock,
                             sc.blocks[2].phashBlock));

        job_result_t r = header_admit_stage_step_once();
        HA_CHECK("fork_guard: rewind fires but step holds",
                 r == JOB_IDLE);
        HA_CHECK("fork_guard: cursor held at replay point",
                 header_admit_stage_cursor() == 3 &&
                 cursor_at(db, "header_admit") == 3);
        HA_CHECK("fork_guard: stale h3 not overwritten as canonical",
                 !header_admit_stage_has_record(3, &sc.hashes[3]));

        HA_CHECK("fork_guard: second step still holds, no hot loop advance",
                 header_admit_stage_step_once() == JOB_IDLE &&
                 header_admit_stage_cursor() == 3);

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Forward-fork guard: h+2 fallback must link through the prior
     *      admitted header row, not through a stale row with the right
     *      parent. This is the live hot-loop shape after a fork rewind:
     *      parent-only checks let h+2 re-advance the cursor even though h+1
     *      still names the wrong header. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit","prior_hash_guard");
        mkdir_p_ha(dir);
        HA_CHECK("prior_hash_guard: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        struct synth_chain sc;
        synth_chain_build(&sc, 5);
        active_chain_move_window_tip(&ms.chain_active, &sc.blocks[2]);

        HA_CHECK("prior_hash_guard: init", header_admit_stage_init(&ms));
        HA_CHECK("prior_hash_guard: admit active prefix",
                 header_admit_stage_drain(100) == 3 &&
                 header_admit_stage_cursor() == 3);
        ms.pindex_best_header = &sc.blocks[4];

        sqlite3 *db = progress_store_db();
        struct uint256 stale_h3 = sc.hashes[3];
        stale_h3.data[5] ^= 0x44;
        HA_CHECK("prior_hash_guard: seed stale h3 with matching parent",
                 put_header_row(db, 3, &stale_h3, &sc.hashes[2]));
        HA_CHECK("prior_hash_guard: force cursor to h4",
                 force_cursor(db, "header_admit", 4));

        job_result_t r = header_admit_stage_step_once();
        HA_CHECK("prior_hash_guard: h4 holds on stale h3 hash",
                 r == JOB_IDLE);
        HA_CHECK("prior_hash_guard: cursor stays at h4",
                 header_admit_stage_cursor() == 4 &&
                 cursor_at(db, "header_admit") == 4);
        HA_CHECK("prior_hash_guard: stale h3 not treated as canonical",
                 !header_admit_stage_has_record(3, &sc.hashes[3]));
        HA_CHECK("prior_hash_guard: h4 not admitted through stale h3",
                 !header_admit_stage_has_record(4, &sc.hashes[4]));

        header_admit_stage_shutdown();
        active_chain_free(&ms.chain_active);
        synth_chain_free(&sc);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Checkpoint-window hole: after the first header-only finalize, the
     *      active height can name the trusted base while chain[height] is
     *      still absent. The exact durable trusted-base pair is sufficient to
     *      admit its canonical child; any hash mismatch remains fail-closed. */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "header_admit", "trusted_base_parent");
        mkdir_p_ha(dir);
        HA_CHECK("trusted_base_parent: store opens", progress_store_open(dir));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        atomic_store(&ms.chain_active.height, 10);

        struct uint256 parent_hash = {0};
        struct uint256 child_hash = {0};
        parent_hash.data[0] = 0xA1;
        child_hash.data[0] = 0xB2;
        struct block_index parent;
        struct block_index child;
        block_index_init(&parent);
        block_index_init(&child);
        parent.nHeight = 10;
        parent.phashBlock = &parent_hash;
        child.nHeight = 11;
        child.phashBlock = &child_hash;
        child.pprev = &parent;

        uint8_t height_blob[8] = {10, 0, 0, 0, 0, 0, 0, 0};
        sqlite3 *db = progress_store_db();
        HA_CHECK("trusted_base_parent: exact authority pair stored",
                 progress_meta_set(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                   height_blob, sizeof(height_blob)) &&
                 progress_meta_set(db, REDUCER_TRUSTED_BASE_HASH_KEY,
                                   parent_hash.data, sizeof(parent_hash.data)));
        HA_CHECK("trusted_base_parent: absent window parent is hash-bound",
                 header_admit_forward_replay_parent_ok(db, &ms, &child, 11));

        parent_hash.data[0] ^= 0x01;
        HA_CHECK("trusted_base_parent: mismatched parent is refused",
                 !header_admit_forward_replay_parent_ok(db, &ms, &child, 11));

        active_chain_free(&ms.chain_active);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }
    printf("header_admit_stage: %d failures\n", failures);
    return failures;
}
