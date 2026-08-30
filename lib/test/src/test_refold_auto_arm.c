/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_auto_arm — the missing detect->arm->reset->heal proof for the
 * boot torn-import AUTO-ARM (config/src/boot_refold_staged.c:
 * boot_refold_from_anchor_arm_if_torn) PLUS the no-snapshot honest-halt safety
 * guard.
 *
 * THE GAP THIS CLOSES
 * -------------------
 * Before this test the only attempted proof of the from-anchor auto-arm was a
 * ~12 GB live-fixture copy-prove — fragile, slow, and the frozen wedge fixture
 * is a DIFFERENT corruption class so it never exercised this code path. There
 * was NO deterministic, CI-able test that:
 *   (T1) the PURE detect predicate block_index_loader_torn_import_detect fires
 *        on the minimal torn signature (durable prevout_unresolved hole above
 *        the checkpoint, inside the forward-apply ceiling, with coin_backfill's
 *        durable refusal marker) and NO-fires on each negative control;
 *   (T2) boot_refold_from_anchor_arm_if_torn, given a MATCHING SHA3-verified
 *        anchor snapshot, RE-SEEDS coins_kv from that snapshot, HARD-ASSERTs it
 *        against the compiled checkpoint, arms the from-anchor cursors, and
 *        survives (no FATAL) — coins_kv becomes the proven authority at
 *        applied == checkpoint+1, refold_from_anchor_active() == true;
 *   (T3 — THE SAFETY REGRESSION) the SAME torn signature but NO reachable
 *        verified snapshot makes the auto-arm DECLINE: it returns false WITHOUT
 *        resetting, the child SURVIVES (it does NOT fall into the contaminated
 *        node.db reseed + the hard-assert _exit(EXIT_FAILURE)), coins_kv is NOT
 *        reset, and refold_from_anchor_active() stays false. If the decline
 *        guard is removed, this child FATALs with EXIT_FAILURE — the negative
 *        control that pins the guard.
 *
 * Determinism: T2/T3 run in a forked child so a (regression) FATAL is observed
 * as a child exit code, never killing the suite. The fixture snapshot is built
 * with coins_kv_snapshot_write over a tiny synthetic coins_kv set, whose body
 * SHA3 EQUALS coins_kv_commitment by construction (same per-record encoder) —
 * so the reset's recompute matches the installed checkpoint EXACTLY, no 12 GB
 * datadir required.
 *
 * Scratch files live under ./test-tmp/ per the project's no-/tmp convention.
 */

#include "test/test_core.h"

#include "config/boot.h"
#include "services/block_index_loader.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "storage/coins_kv.h"
#include "models/database.h"
#include "chain/checkpoints.h"
#include "core/uint256.h"
#include "jobs/refold_progress.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if !defined(_WIN32)

#define RAA_CHECK(name, expr) do {                       \
    printf("  refold_auto_arm: %s... ", (name));          \
    if (expr) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

/* A scaled-down checkpoint height (far below the production 3,056,758 anchor).
 * The detect window is (checkpoint, ceiling]; the seeded hole sits ABOVE this. */
#define RAA_CP_HEIGHT   1000
#define RAA_HOLE_H      1016   /* hole above the checkpoint */
#define RAA_FRONTIER    1017   /* coins_applied_height (next-height cursor) */

/* ── progress.kv torn-signature seeding (mirrors test_seed_torn_import_gate). ─ */

static void raa_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[2] = (uint8_t)((h >> 16) & 0xFF);
    out->data[31] = 0x5e;
}

/* Production-shape script_validate_log (+ tip_finalize_log so the reset's
 * cursor force / the post-detect reads find the tables). */
static bool raa_create_logs(sqlite3 *db)
{
    if (sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS script_validate_log ("
        " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        " ok INTEGER NOT NULL, tx_count INTEGER NOT NULL,"
        " input_count INTEGER NOT NULL, first_failure_txid BLOB,"
        " first_failure_vin INTEGER, first_failure_serror INTEGER,"
        " validated_at INTEGER NOT NULL, block_hash BLOB)",
        NULL, NULL, NULL) != SQLITE_OK)
        return false;
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        " height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        " tip_hash BLOB)",
        NULL, NULL, NULL) == SQLITE_OK;
}

/* One ok=0 row at `height` with `hash` and explicit `status`. */
static bool raa_insert_hole_status(sqlite3 *db, int height,
                                   const struct uint256 *hash,
                                   const char *status)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log("
            " height, status, ok, tx_count, input_count, validated_at,"
            " block_hash) VALUES(?, ?, 0, 1, 1, 0, ?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* coin_backfill's durable refusal marker (repair_marker kind
 * coin_backfill.refused keyed (height, hash)) — byte-identical to the producer.
 * The detect predicate's (3) condition requires this. */
static bool raa_seed_backfill_refused(sqlite3 *db, int height,
                                      const struct uint256 *hash)
{
    if (!repair_marker_table_ensure(db))
        return false;
    return repair_marker_note(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                              height, hash->data, "spent:v2", 8);
}

/* Stamp coins_applied_height = frontier (the forward-apply ceiling). */
static bool raa_set_applied(sqlite3 *db, int32_t next_cursor)
{
    if (!progress_meta_table_ensure(db))
        return false;
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    bool ok = coins_kv_set_applied_height_in_tx(db, next_cursor);
    const char *finish = ok ? "COMMIT" : "ROLLBACK";
    if (sqlite3_exec(db, finish, NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    return ok;
}

/* Seed `n` synthetic live outputs into coins_kv. Deterministic, so the
 * resulting commitment + snapshot are reproducible across the fork. */
static bool raa_seed_coins(sqlite3 *db, int n)
{
    if (!coins_kv_ensure_schema(db))
        return false;
    for (int i = 0; i < n; i++) {
        uint8_t txid[32];
        memset(txid, 0, 32);
        txid[0] = (uint8_t)(i & 0xFF);
        txid[1] = (uint8_t)((i >> 8) & 0xFF);
        uint8_t script[1] = {0x51};  /* OP_TRUE */
        if (!coins_kv_add(db, txid, 0, (int64_t)(i + 1) * 1000,
                          RAA_CP_HEIGHT, false, script, sizeof(script)))
            return false;
    }
    return true;
}

/* Build the full torn progress.kv signature (hole row + refused marker +
 * applied frontier) on the open progress store `pk`. */
static bool raa_seed_torn_progress(sqlite3 *pk, const char *status_token,
                                   bool seed_marker)
{
    if (!raa_create_logs(pk))
        return false;
    if (!raa_set_applied(pk, RAA_FRONTIER))
        return false;
    struct uint256 hole_hash;
    raa_hash_for(RAA_HOLE_H, &hole_hash);
    if (!raa_insert_hole_status(pk, RAA_HOLE_H, &hole_hash, status_token))
        return false;
    if (seed_marker && !raa_seed_backfill_refused(pk, RAA_HOLE_H, &hole_hash))
        return false;
    return true;
}

/* A main_state whose active chain sits at the frontier (so detect's ceiling
 * raise covers the hole). Installs a body-PRESENT (BLOCK_HAVE_DATA) slot at
 * EVERY height in [RAA_CP_HEIGHT .. height] (ascending installs accumulate the
 * lower slots), so the from-anchor body-span gate
 * (boot_refold_body_span_contiguous, checked in arm_if_torn before the reset)
 * sees a contiguous fold span (checkpoint, frontier] and does not decline the
 * arm. Without the full span only the tip slot existed and the gate would
 * correctly refuse on the first missing body at checkpoint+1. */
static void raa_install_tip(struct main_state *ms, int height)
{
    for (int h = RAA_CP_HEIGHT; h <= height; h++) {
        struct uint256 bh;
        raa_hash_for(h, &bh);
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)ms, &bh);
        if (!bi)
            return;
        bi->nHeight = h;
        bi->nBits = 0x2000ffffu;
        bi->nTime = 1700000000u + (uint32_t)h;
        bi->nVersion = 4;
        /* BLOCK_HAVE_DATA: the body is on disk for the span gate. */
        bi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        bi->nTx = 0;
        bi->nFile = 0;
        bi->nDataPos = 0;
        (void)active_chain_install_tip_slot(&ms->chain_active, bi);
    }
}

/* Build a MATCHING anchor snapshot at `snap_path` from a fresh coins_kv set in
 * its OWN throwaway progress store, and return the resulting checkpoint
 * (sha3_hash == body SHA3 == the commitment of that set, count, height). The
 * caller installs this as the checkpoint override. Returns true on success. */
static bool raa_build_matching_snapshot(const char *snap_path,
                                        struct sha3_utxo_checkpoint *cp_out)
{
    char bdir[256];
    snprintf(bdir, sizeof(bdir), "./test-tmp/raa_build_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(bdir, 0755);

    progress_store_close();
    if (!progress_store_open(bdir))
        return false;
    sqlite3 *bpk = progress_store_db();
    bool ok = bpk && raa_seed_coins(bpk, 6);
    uint8_t root[32] = {0};
    int64_t count = ok ? coins_kv_count(bpk) : -1;
    if (ok && coins_kv_commitment(bpk, root) != 0)
        ok = false;

    uint8_t anchor_block_hash[32] = {0};
    anchor_block_hash[0] = 0xAB;
    uint8_t wr_sha3[32] = {0};
    uint64_t wr_count = 0;
    int64_t wr_total = 0;
    if (ok)
        ok = coins_kv_snapshot_write(bpk, snap_path, RAA_CP_HEIGHT,
                                     anchor_block_hash, /*shielded=*/NULL,
                                     wr_sha3, &wr_count, &wr_total);
    /* The writer's body SHA3 MUST equal the commitment (same encoder). */
    if (ok && memcmp(wr_sha3, root, 32) != 0)
        ok = false;

    if (ok) {
        memset(cp_out, 0, sizeof(*cp_out));
        cp_out->height = RAA_CP_HEIGHT;
        memcpy(cp_out->sha3_hash, root, 32);
        cp_out->utxo_count = (uint64_t)count;
        cp_out->total_supply = wr_total;
        memcpy(cp_out->block_hash, anchor_block_hash, 32);
    }

    progress_store_close();
    test_cleanup_tmpdir(bdir);
    return ok;
}

/* ── T2 / T3 forked-child bodies. Return the child exit code via _exit. ─────
 *
 * Exit-code protocol (so the parent can distinguish a clean PASS from a
 * regression FATAL):
 *   77 = the child's own assertions PASSED (the expected outcome)
 *   1  = a child assertion FAILED, OR a reset FATAL (_exit(EXIT_FAILURE)=1)
 *        reached the process — the regression signature for T3
 *   other = unexpected. */
#define RAA_CHILD_PASS 77

/* Child precondition shared by T2 and T3: open progress.kv at `dir`, seed the
 * torn signature, build the main_state with the tip at the frontier, install
 * the checkpoint override, open node.db. The checkpoint override is passed in
 * (built in the parent so its sha3_hash matches the on-disk snapshot when one
 * exists). */
static void raa_child_common_setup(const char *dir,
                                   const struct sha3_utxo_checkpoint *cp,
                                   struct node_db *ndb_out,
                                   struct main_state *ms_out)
{
    if (!progress_store_open(dir))
        _exit(1);
    sqlite3 *pk = progress_store_db();
    if (!pk || !raa_seed_coins(pk, 4))   /* a non-empty (contaminated) live set */
        _exit(1);
    if (!raa_seed_torn_progress(pk, "prevout_unresolved", /*seed_marker=*/true))
        _exit(1);
    /* Reset the from-anchor cache to the conservative false default for a
     * fresh-boot precondition (the auto-arm requires it false at entry). */
    (void)refold_progress_refresh(pk);

    char dbpath[400];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    if (!node_db_open(ndb_out, dbpath))
        _exit(1);

    checkpoints_set_sha3_override_for_test(cp);

    main_state_init(ms_out);
    raa_install_tip(ms_out, RAA_FRONTIER);
}

/* T2 child: a MATCHING snapshot at ZCL_MINT_ANCHOR_OUT is present (set by the
 * parent before fork). The auto-arm must reset+heal and survive. */
static void raa_t2_child(const char *dir, const struct sha3_utxo_checkpoint *cp)
{
    struct node_db ndb;
    struct main_state ms;
    raa_child_common_setup(dir, cp, &ndb, &ms);

    int fails = 0;

    /* (a) the pure detect fires on this signature. */
    int32_t hole_h = -1, ceiling = -1;
    bool detected = block_index_loader_torn_import_detect(
        &ms, progress_store_db(), cp->height, &hole_h, &ceiling);
    if (!(detected && hole_h == RAA_HOLE_H && ceiling >= RAA_HOLE_H))
        fails++;

    /* (b) arm_if_torn: detect -> arm -> reset (reseed from the verified
     * snapshot) -> hard-assert. Returns true; the child must NOT FATAL. */
    bool armed = boot_refold_from_anchor_arm_if_torn(
        &ms, &ndb, progress_store_db());
    if (!armed)
        fails++;

    /* (c) the heal landed: coins_kv is the proven authority at applied ==
     * checkpoint+1, and the from-anchor signal is live. */
    int32_t applied = -1;
    bool proven = coins_kv_is_proven_authority(progress_store_db(), &applied);
    if (!(proven && applied == cp->height + 1))
        fails++;
    if (!coins_kv_contains_refold_marker(progress_store_db()))
        fails++;
    {
        char reason[96] = {0};
        if (!coins_kv_tip_is_self_derived(progress_store_db(), cp->height,
                                          reason, sizeof(reason)))
            fails++;
    }
    if (!refold_from_anchor_active())
        fails++;
    /* coins_kv now holds EXACTLY the snapshot's anchor set (count + root). */
    uint8_t root[32] = {0};
    if (coins_kv_commitment(progress_store_db(), root) != 0 ||
        memcmp(root, cp->sha3_hash, 32) != 0 ||
        coins_kv_count(progress_store_db()) != (int64_t)cp->utxo_count)
        fails++;

    main_state_free(&ms);
    node_db_close(&ndb);
    progress_store_close();
    checkpoints_set_sha3_override_for_test(NULL);
    _exit(fails == 0 ? RAA_CHILD_PASS : 1);
}

/* T3 child: NO snapshot at the mint path. The auto-arm must DECLINE (return
 * false) WITHOUT resetting, and the child must SURVIVE. If the decline guard is
 * removed, the reset falls into the node.db `utxos` reseed (the contaminated /
 * empty mirror) and the hard-assert _exit(EXIT_FAILURE)s — the parent observes
 * exit 1 and T3 goes RED. */
static void raa_t3_child(const char *dir, const struct sha3_utxo_checkpoint *cp)
{
    struct node_db ndb;
    struct main_state ms;
    raa_child_common_setup(dir, cp, &ndb, &ms);

    int fails = 0;

    /* Detect still fires (the tear is real) — only the snapshot is missing. */
    int32_t hole_h = -1, ceiling = -1;
    bool detected = block_index_loader_torn_import_detect(
        &ms, progress_store_db(), cp->height, &hole_h, &ceiling);
    if (!detected)
        fails++;

    int64_t count_before = coins_kv_count(progress_store_db());

    /* The decisive call: with NO reachable verified snapshot, this must return
     * false WITHOUT resetting (and WITHOUT the node.db-fallback FATAL). */
    bool armed = boot_refold_from_anchor_arm_if_torn(
        &ms, &ndb, progress_store_db());
    if (armed)
        fails++;                                  /* must DECLINE */
    if (refold_from_anchor_active())
        fails++;                                  /* must NOT arm */
    if (coins_kv_count(progress_store_db()) != count_before)
        fails++;                                  /* coins_kv NOT reset */

    main_state_free(&ms);
    node_db_close(&ndb);
    progress_store_close();
    checkpoints_set_sha3_override_for_test(NULL);
    _exit(fails == 0 ? RAA_CHILD_PASS : 1);
}

/* Fork + run a child body; return its exit code (-1 on fork/wait error). */
static int raa_run_child(void (*body)(const char *, const struct sha3_utxo_checkpoint *),
                         const char *dir, const struct sha3_utxo_checkpoint *cp)
{
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        body(dir, cp);
        _exit(2);  /* body must _exit; reaching here is unexpected */
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;  /* killed by a signal — treated as failure */
}

int test_refold_auto_arm(void);
int test_refold_auto_arm(void)
{
    test_reset_shared_globals();
    printf("\n=== refold_auto_arm tests ===\n");
    int failures = 0;

    /* ── T1: the PURE detect predicate (in-process; no FATAL path). ──────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "refold_auto_arm_detect", "main");

        progress_store_close();
        RAA_CHECK("T1: progress store opens", progress_store_open(dir));
        sqlite3 *pk = progress_store_db();

        /* A non-empty live coins_kv (the count token the import recorded). */
        RAA_CHECK("T1: coins_kv seeded", pk && raa_seed_coins(pk, 4));
        RAA_CHECK("T1: torn signature seeded (hole + marker + frontier)",
                  pk && raa_seed_torn_progress(pk, "prevout_unresolved", true));

        struct main_state ms;
        main_state_init(&ms);
        raa_install_tip(&ms, RAA_FRONTIER);
        RAA_CHECK("T1: active tip at the frontier",
                  active_chain_height(&ms.chain_active) == RAA_FRONTIER);

        /* POSITIVE: detect fires, names the hole, ceiling covers it. */
        int32_t hole_h = -1, ceiling = -1;
        bool fired = block_index_loader_torn_import_detect(
            &ms, pk, RAA_CP_HEIGHT, &hole_h, &ceiling);
        RAA_CHECK("T1: detect FIRES on the minimal torn signature", fired);
        RAA_CHECK("T1: out_hole_h == the seeded hole", hole_h == RAA_HOLE_H);
        RAA_CHECK("T1: out_ceiling >= the hole", ceiling >= RAA_HOLE_H);

        /* NEGATIVE 1: checkpoint == hole_h → window is exclusive-low → no fire. */
        hole_h = -1; ceiling = -1;
        bool n1 = block_index_loader_torn_import_detect(
            &ms, pk, RAA_HOLE_H, &hole_h, &ceiling);
        RAA_CHECK("T1-neg: checkpoint == hole_h → NO fire (exclusive low)", !n1);

        /* NEGATIVE 2: remove the refusal marker → refusal-latency → no fire. */
        {
            struct uint256 hh;
            raa_hash_for(RAA_HOLE_H, &hh);
            (void)repair_marker_forget(pk,
                REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED, RAA_HOLE_H, hh.data);
        }
        hole_h = -1; ceiling = -1;
        bool n2 = block_index_loader_torn_import_detect(
            &ms, pk, RAA_CP_HEIGHT, &hole_h, &ceiling);
        RAA_CHECK("T1-neg: no refusal marker → NO fire (refusal latency)", !n2);

        /* Restore the marker, then flip the status to internal_error (transient)
         * → status filter excludes it → no fire. */
        {
            struct uint256 hh;
            raa_hash_for(RAA_HOLE_H, &hh);
            (void)raa_seed_backfill_refused(pk, RAA_HOLE_H, &hh);
            (void)raa_insert_hole_status(pk, RAA_HOLE_H, &hh, "internal_error");
        }
        hole_h = -1; ceiling = -1;
        bool n3 = block_index_loader_torn_import_detect(
            &ms, pk, RAA_CP_HEIGHT, &hole_h, &ceiling);
        RAA_CHECK("T1-neg: internal_error status → NO fire (transient excluded)",
                  !n3);

        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── Build the MATCHING snapshot + its checkpoint ONCE for T2. ───────── */
    char snap_path[400];
    snprintf(snap_path, sizeof(snap_path),
             "./test-tmp/raa_anchor_%d.snapshot", (int)getpid());
    struct sha3_utxo_checkpoint cp_match;
    bool snap_ok = raa_build_matching_snapshot(snap_path, &cp_match);
    RAA_CHECK("snapshot fixture built (body SHA3 == commitment)", snap_ok);

    /* ── T2: end-to-end detect -> arm -> reset (snapshot reseed) -> heal. ── */
    if (snap_ok) {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "refold_auto_arm_heal", "main");
        setenv("ZCL_MINT_ANCHOR_OUT", snap_path, 1);   /* snapshot IS present */

        int code = raa_run_child(raa_t2_child, dir, &cp_match);
        RAA_CHECK("T2: arm->reset->heal child PASSES (no FATAL, proven authority)",
                  code == RAA_CHILD_PASS);

        unsetenv("ZCL_MINT_ANCHOR_OUT");
        test_cleanup_tmpdir(dir);
    }

    /* ── T3: the SAFETY regression — torn but NO reachable snapshot. ─────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "refold_auto_arm_decline", "main");
        /* Point the mint path at a NON-EXISTENT file (no snapshot reachable). */
        char nope[400];
        snprintf(nope, sizeof(nope),
                 "./test-tmp/raa_absent_%d.snapshot", (int)getpid());
        unlink(nope);
        setenv("ZCL_MINT_ANCHOR_OUT", nope, 1);

        int code = raa_run_child(raa_t3_child, dir, &cp_match);
        RAA_CHECK("T3: no-snapshot auto-arm DECLINES + child SURVIVES "
                  "(no FATAL)", code == RAA_CHILD_PASS);
        /* The negative-control note: if the decline guard is removed, the reset
         * falls to the node.db reseed + hard-assert _exit(EXIT_FAILURE) → the
         * child exits 1 and this check goes RED. */

        unsetenv("ZCL_MINT_ANCHOR_OUT");
        test_cleanup_tmpdir(dir);
    }

    unlink(snap_path);
    checkpoints_set_sha3_override_for_test(NULL);
    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's fork crash-window refold lane
 * cannot run here. Skipped loudly rather than faked. */
int test_refold_auto_arm(void)
{
    printf("refold_auto_arm: SKIP (Windows): fork crash-window refold lane\n");
    return 0;
}
#endif
