/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling note-commitment-tree flat-file checkpoint persistence (P1-7).
 *
 * Proves the fail-closed, verify-then-trust cache that lets a clean restart
 * resume the Sapling replay from a persisted frontier instead of re-folding
 * the whole history:
 *   (a) v2 save/load round-trip restores an identical frontier + root + the
 *       {height, block_hash} key.
 *   (b) a corrupted / root-mismatched cache is rejected on load (fail-closed).
 *   (c) a stale cache above the current tip is discarded, not partially used.
 *   (d) a reorg (block hash at H changed) is discarded.
 *   (e) an absent cache behaves like the current full-replay path.
 *
 * All hermetic: tree ops are Pedersen hashing over synthetic commitments —
 * no ~/.zcash-params and no live chain are needed. The header-chain binding
 * is exercised through the pure sapling_ckpt_verify_binding() decision. */

#include "test/test_core.h"

#include "jobs/reducer_frontier.h"
#include "services/sapling_checkpoint_hook.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/process_block.h"

static void ckpt_fill_hash(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx + i));
}

static void ckpt_build_tree(size_t n, struct incremental_merkle_tree *t_out)
{
    sapling_tree_init(t_out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        ckpt_fill_hash(&cm, 0x3C, i);
        incremental_tree_append(t_out, &cm);
    }
}

/* reducer_frontier_derive_coins_best_now (used internally by
 * sapling_tree_flat_checkpoint_note's reducer-cursor bound) also reads
 * validate_headers_log as a hash witness; a genuinely-missing table is
 * treated as a hard read error (not a benign "no witness"), so a hermetic
 * progress_store fixture needs the table present (even empty) for the
 * derivation to succeed. Mirrors test_coins_best_derivation.c's
 * cbd_build_progress_schema subset. */
static bool ckpt_ensure_log_schema(sqlite3 *db)
{
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "  height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "  fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "  height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "  tip_hash BLOB);";
    char *err = NULL;
    if (sqlite3_exec(db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "[sapling_ckpt_persist] log schema: %s\n",
                err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

int test_sapling_ckpt_persist(void)
{
    int failures = 0;
    char path[128];

    /* (a) round-trip: save then load restores frontier + root + block hash. */
    printf("sapling_ckpt_persist round-trip (frontier + block-hash key) ... ");
    {
        strcpy(path, "/tmp/zcl_sapling_ckpt_rt_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) { printf("FAIL (mkstemp)\n"); failures++; goto done_rt; }
        close(fd);
        unlink(path);

        struct incremental_merkle_tree src;
        ckpt_build_tree(300, &src);

        uint8_t bhash[32];
        for (int i = 0; i < 32; i++) bhash[i] = (uint8_t)(0x11 + i);

        if (!sapling_tree_flush_checkpoint(&src, 700000, bhash, path)) {
            printf("FAIL (flush)\n"); failures++; unlink(path); goto done_rt;
        }

        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        uint8_t got_hash[32] = {0};
        if (!sapling_tree_load_checkpoint(&dst, &got_h, got_hash, path)) {
            printf("FAIL (load)\n"); failures++; unlink(path); goto done_rt;
        }
        struct uint256 rs, rd;
        incremental_tree_root(&src, &rs);
        incremental_tree_root(&dst, &rd);
        if (got_h != 700000) {
            printf("FAIL (height %lld)\n", (long long)got_h); failures++;
        } else if (memcmp(got_hash, bhash, 32) != 0) {
            printf("FAIL (block hash not restored)\n"); failures++;
        } else if (memcmp(rs.data, rd.data, 32) != 0) {
            printf("FAIL (root mismatch)\n"); failures++;
        } else if (incremental_tree_size(&dst) != incremental_tree_size(&src)) {
            printf("FAIL (size mismatch)\n"); failures++;
        } else {
            printf("OK\n");
        }
        unlink(path);
done_rt:;
    }

    /* (b) corrupted cache is rejected on load (SHA3 tamper detection). */
    printf("sapling_ckpt_persist corrupted cache rejected ... ");
    {
        strcpy(path, "/tmp/zcl_sapling_ckpt_corrupt_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) { printf("FAIL (mkstemp)\n"); failures++; goto done_corrupt; }
        close(fd);
        unlink(path);

        struct incremental_merkle_tree src;
        ckpt_build_tree(90, &src);
        uint8_t bhash[32];
        for (int i = 0; i < 32; i++) bhash[i] = (uint8_t)(0x55 ^ i);
        if (!sapling_tree_flush_checkpoint(&src, 600000, bhash, path)) {
            printf("FAIL (flush)\n"); failures++; unlink(path); goto done_corrupt;
        }

        /* Flip a byte in the serialized tree blob region (past the header). */
        FILE *f = fopen(path, "r+b");
        if (!f) { printf("FAIL (reopen)\n"); failures++; unlink(path); goto done_corrupt; }
        fseek(f, 90, SEEK_SET);
        uint8_t b;
        if (fread(&b, 1, 1, f) != 1) {
            printf("FAIL (fread)\n"); failures++; fclose(f); unlink(path); goto done_corrupt;
        }
        b ^= 0x40;
        fseek(f, 90, SEEK_SET);
        fwrite(&b, 1, 1, f);
        fclose(f);

        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        uint8_t got_hash[32] = {0};
        bool ok = sapling_tree_load_checkpoint(&dst, &got_h, got_hash, path);
        if (ok) { printf("FAIL (tampered file accepted)\n"); failures++; }
        else    { printf("OK\n"); }
        unlink(path);
done_corrupt:;
    }

    /* (c)+(d)+(e) fail-closed binding decision (pure, no chain needed). */
    printf("sapling_ckpt_persist verify_binding fail-closed verdicts ... ");
    {
        struct uint256 root, other, bhash_u, exp_hash_u;
        ckpt_fill_hash(&root, 0xAA, 1);
        ckpt_fill_hash(&other, 0xBB, 2);
        ckpt_fill_hash(&bhash_u, 0xC1, 3);
        exp_hash_u = bhash_u; /* same block at H by default */

        int local = 0;

        /* OK: height <= tip, block hash matches, root matches. */
        if (sapling_ckpt_verify_binding(1000, &root, bhash_u.data,
                2000, exp_hash_u.data, true, &root, true) != SAPLING_CKPT_OK)
            local++;

        /* (c) stale above tip: H=3000 > tip=2000. */
        if (sapling_ckpt_verify_binding(3000, &root, bhash_u.data,
                2000, exp_hash_u.data, true, &root, true)
            != SAPLING_CKPT_STALE_ABOVE_TIP)
            local++;

        /* (d) reorg: block hash at H differs from expected. */
        if (sapling_ckpt_verify_binding(1000, &root, bhash_u.data,
                2000, other.data, true, &root, true) != SAPLING_CKPT_REORG)
            local++;

        /* reorg: expected hash unknown (absent body) but ckpt carries one. */
        if (sapling_ckpt_verify_binding(1000, &root, bhash_u.data,
                2000, NULL, false, &root, true) != SAPLING_CKPT_REORG)
            local++;

        /* root mismatch: header binding present but differs. */
        if (sapling_ckpt_verify_binding(1000, &root, bhash_u.data,
                2000, exp_hash_u.data, true, &other, true)
            != SAPLING_CKPT_ROOT_MISMATCH)
            local++;

        /* root unknown: header hashFinalSaplingRoot absent -> cannot verify. */
        if (sapling_ckpt_verify_binding(1000, &root, bhash_u.data,
                2000, exp_hash_u.data, true, NULL, false)
            != SAPLING_CKPT_ROOT_UNKNOWN)
            local++;

        /* zero block hash in ckpt skips the reorg gate, relies on root. */
        uint8_t zeros[32] = {0};
        if (sapling_ckpt_verify_binding(1000, &root, zeros,
                2000, other.data, true, &root, true) != SAPLING_CKPT_OK)
            local++;

        if (local) { printf("FAIL (%d verdicts wrong)\n", local); failures += local; }
        else       { printf("OK\n"); }
    }

    /* (e) absent cache: load of a missing file returns false (full replay). */
    printf("sapling_ckpt_persist absent cache = full-replay path ... ");
    {
        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        uint8_t got_hash[32] = {0};
        bool ok = sapling_tree_load_checkpoint(&dst, &got_h, got_hash,
            "/tmp/zcl_sapling_ckpt_absent_does_not_exist_998877");
        if (ok) { printf("FAIL (loaded from missing file)\n"); failures++; }
        else    { printf("OK\n"); }
    }

    /* delta-replay equivalence: a resumed frontier + forward replay yields the
     * same root as a full replay (the fast-resume correctness guarantee). */
    printf("sapling_ckpt_persist delta-replay == full-replay root ... ");
    {
        strcpy(path, "/tmp/zcl_sapling_ckpt_delta_XXXXXX");
        int fd = mkstemp(path);
        if (fd < 0) { printf("FAIL (mkstemp)\n"); failures++; goto done_delta; }
        close(fd);
        unlink(path);

        struct incremental_merkle_tree at150;
        sapling_tree_init(&at150);
        for (size_t i = 0; i < 150; i++) {
            struct uint256 cm; ckpt_fill_hash(&cm, 0x7E, i);
            incremental_tree_append(&at150, &cm);
        }
        uint8_t bhash[32]; for (int i = 0; i < 32; i++) bhash[i] = (uint8_t)i;
        if (!sapling_tree_flush_checkpoint(&at150, 150, bhash, path)) {
            printf("FAIL (flush)\n"); failures++; unlink(path); goto done_delta;
        }

        struct incremental_merkle_tree full;
        sapling_tree_init(&full);
        for (size_t i = 0; i < 400; i++) {
            struct uint256 cm; ckpt_fill_hash(&cm, 0x7E, i);
            incremental_tree_append(&full, &cm);
        }

        struct incremental_merkle_tree delta;
        sapling_tree_init(&delta);
        int64_t ch = 0;
        uint8_t chash[32] = {0};
        if (!sapling_tree_load_checkpoint(&delta, &ch, chash, path)) {
            printf("FAIL (load)\n"); failures++; unlink(path); goto done_delta;
        }
        for (size_t i = 150; i < 400; i++) {
            struct uint256 cm; ckpt_fill_hash(&cm, 0x7E, i);
            incremental_tree_append(&delta, &cm);
        }
        struct uint256 rf, rd;
        incremental_tree_root(&full, &rf);
        incremental_tree_root(&delta, &rd);
        if (memcmp(rf.data, rd.data, 32) != 0) {
            printf("FAIL (delta root diverges)\n"); failures++;
        } else if (incremental_tree_size(&delta) != 400) {
            printf("FAIL (delta size)\n"); failures++;
        } else {
            printf("OK\n");
        }
        unlink(path);
done_delta:;
    }

    /* Make coins_kv the PROVEN authority on `db` (the other two rungs of
     * coins_kv_is_proven_authority, beside coins_applied_height itself):
     * one live coin row + the migration stamp. Mirrors
     * test_coins_best_derivation.c's cbd_mark_canonical. Needed so
     * reducer_frontier_derive_coins_best_now() (which
     * sapling_tree_flat_checkpoint_note calls internally) reports
     * found=true instead of failing open. */
    #define CKPT_BOUND_H ((int32_t)900000)

    /* (f) BOUND: sapling_tree_flat_checkpoint_note refuses a height ahead
     * of the reducer's own applied frontier — even under force=true — and
     * leaves any prior checkpoint file untouched. This is THE fix under
     * test: the flat-file checkpoint writer is bound to the reducer fold
     * cursor (coins_applied_height), never the caller's own pace. */
    printf("sapling_ckpt_persist flat_checkpoint_note refuses height ahead "
           "of reducer applied frontier ... ");
    {
        char dir[256], dir_rel[256];
        test_make_tmpdir(dir_rel, sizeof(dir_rel), "sapling_ckpt_bound",
                         "refuse");
        /* flush_checkpoint resolves its output through the absolute-only
         * platform_private seam — hand it an absolute datadir. */
        test_abs_path(dir_rel, dir, sizeof(dir));
        progress_store_close();
        bool ok = progress_store_open(dir);
        sqlite3 *pdb = ok ? progress_store_db() : NULL;
        ok = ok && pdb != NULL && ckpt_ensure_log_schema(pdb);

        uint8_t txid[32];
        memset(txid, 0x33, sizeof(txid));
        ok = ok && coins_kv_ensure_schema(pdb) &&
             coins_kv_add(pdb, txid, 0, 1000LL, 1, false, NULL, 0);
        uint8_t one = 1;
        ok = ok && progress_meta_set(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                     &one, 1);
        /* Reducer applied through CKPT_BOUND_H: coins_applied_height ==
         * CKPT_BOUND_H + 1, so the derived applied frontier == CKPT_BOUND_H. */
        ok = ok && coins_kv_set_applied_height_in_tx(pdb,
                                                     CKPT_BOUND_H + 1);

        set_sapling_checkpoint_datadir(dir);
        char ckpt_path[512];
        snprintf(ckpt_path, sizeof(ckpt_path), "%s/sapling_tree_ckpt.dat",
                 dir);

        struct incremental_merkle_tree src;
        ckpt_build_tree(20, &src);
        uint8_t bhash[32];
        for (int i = 0; i < 32; i++) bhash[i] = (uint8_t)(0x90 + i);

        /* Ahead of the reducer's applied frontier: refused, even forced,
         * even though nothing has been written to this path yet. */
        bool wrote_ahead = ok && sapling_tree_flat_checkpoint_note(
            &src, (int64_t)CKPT_BOUND_H + 1000, bhash, /*force=*/true);
        struct stat st_after_refuse;
        bool file_absent_after_refuse =
            stat(ckpt_path, &st_after_refuse) != 0;

        /* At/below the frontier: allowed, and round-trips. */
        bool wrote_ok = ok && sapling_tree_flat_checkpoint_note(
            &src, (int64_t)CKPT_BOUND_H, bhash, /*force=*/true);
        struct incremental_merkle_tree dst;
        sapling_tree_init(&dst);
        int64_t got_h = -1;
        uint8_t got_hash[32] = {0};
        bool loaded = wrote_ok && sapling_tree_load_checkpoint(
            &dst, &got_h, got_hash, ckpt_path);

        /* A later attempt beyond the (still CKPT_BOUND_H) frontier must NOT
         * clobber the good in-window checkpoint just written. */
        struct incremental_merkle_tree clobber;
        ckpt_build_tree(21, &clobber);
        bool wrote_clobber = ok && sapling_tree_flat_checkpoint_note(
            &clobber, (int64_t)CKPT_BOUND_H + 5000, bhash, /*force=*/true);
        int64_t got_h2 = -1;
        uint8_t got_hash2[32] = {0};
        struct incremental_merkle_tree dst2;
        sapling_tree_init(&dst2);
        bool still_loads = sapling_tree_load_checkpoint(
            &dst2, &got_h2, got_hash2, ckpt_path);

        set_sapling_checkpoint_datadir(NULL);
        unlink(ckpt_path);
        progress_store_close();

        if (!ok) {
            printf("FAIL (fixture setup)\n"); failures++;
        } else if (wrote_ahead) {
            printf("FAIL (write ahead of frontier was NOT refused)\n");
            failures++;
        } else if (!file_absent_after_refuse) {
            printf("FAIL (refused write still created a file)\n");
            failures++;
        } else if (!wrote_ok || !loaded || got_h != CKPT_BOUND_H) {
            printf("FAIL (in-window write did not round-trip, got_h=%lld)\n",
                   (long long)got_h);
            failures++;
        } else if (wrote_clobber) {
            printf("FAIL (out-of-window write clobbered the good checkpoint)\n");
            failures++;
        } else if (!still_loads || got_h2 != CKPT_BOUND_H) {
            printf("FAIL (good checkpoint was NOT preserved, got_h2=%lld)\n",
                   (long long)got_h2);
            failures++;
        } else {
            printf("OK\n");
        }
    }

    /* (g) sapling_checkpoint_hook_in_tx end-to-end: the reducer-cursor hook
     * checkpoints the anchor_kv frontier at the height the reducer just
     * applied, and that checkpoint satisfies the empty-frontier healer's
     * tier1 window precondition (activation <= ckpt_h < stall_height,
     * where stall_height = H*+1 — the exact inequality
     * tier1_seed_verified_frontier uses in
     * conditions/sapling_anchor_frontier_unavailable.c) even after the
     * reducer advances further past the height the checkpoint was taken
     * at. */
    printf("sapling_ckpt_persist sapling_checkpoint_hook_in_tx lands a "
           "checkpoint that satisfies the healer's tier1 window ... ");
    {
        char dir[256], dir_rel[256];
        test_make_tmpdir(dir_rel, sizeof(dir_rel), "sapling_ckpt_hook",
                         "e2e");
        /* Absolute-only private seam, as above. */
        test_abs_path(dir_rel, dir, sizeof(dir));
        progress_store_close();
        bool ok = progress_store_open(dir);
        sqlite3 *pdb = ok ? progress_store_db() : NULL;
        ok = ok && pdb != NULL && ckpt_ensure_log_schema(pdb);

        uint8_t txid[32];
        memset(txid, 0x44, sizeof(txid));
        ok = ok && coins_kv_ensure_schema(pdb) &&
             coins_kv_add(pdb, txid, 0, 1000LL, 1, false, NULL, 0);
        uint8_t one = 1;
        ok = ok && progress_meta_set(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                     &one, 1);

        const int64_t activation = 100;
        const int64_t H = 500000;   /* height the hook fires at */
        ok = ok && anchor_kv_initialize_history(pdb, activation);
        struct incremental_merkle_tree frontier;
        ckpt_build_tree(11, &frontier);
        ok = ok && anchor_kv_add_tree(pdb, ANCHOR_POOL_SAPLING, &frontier, H);
        /* Reducer applied exactly through H at the moment the hook fires
         * (mirrors utxo_apply_stage.c: coins_applied_height == next_h + 1
         * inside the same transaction as the hook call). */
        ok = ok && coins_kv_set_applied_height_in_tx(pdb, (int32_t)H + 1);

        set_sapling_checkpoint_datadir(dir);
        char ckpt_path[512];
        snprintf(ckpt_path, sizeof(ckpt_path), "%s/sapling_tree_ckpt.dat",
                 dir);

        uint8_t bhash[32];
        for (int i = 0; i < 32; i++) bhash[i] = (uint8_t)(0xB0 + i);
#ifdef ZCL_TESTING
        sapling_checkpoint_hook_test_force_next();
#endif
        if (ok)
            sapling_checkpoint_hook_in_tx(pdb, H, bhash);

        int64_t got_h = -1;
        uint8_t got_hash[32] = {0};
        struct incremental_merkle_tree got;
        sapling_tree_init(&got);
        bool loaded = sapling_tree_load_checkpoint(&got, &got_h, got_hash,
                                                    ckpt_path);
        struct uint256 got_root, want_root;
        incremental_tree_root(&got, &got_root);
        incremental_tree_root(&frontier, &want_root);

        /* The reducer advances further (H*=H+50) before the healer ever
         * looks — the checkpoint taken at H must STILL satisfy the tier1
         * window against the NEW, higher H*. */
        int32_t hstar_now = -1;
        bool have_hstar = ok && coins_kv_set_applied_height_in_tx(
            pdb, (int32_t)H + 51) &&
            reducer_frontier_derive_coins_best_now(&hstar_now, NULL, NULL);
        int64_t stall_height = (int64_t)hstar_now + 1;

        set_sapling_checkpoint_datadir(NULL);
        unlink(ckpt_path);
        progress_store_close();

        if (!ok) {
            printf("FAIL (fixture setup)\n"); failures++;
        } else if (!loaded || got_h != H) {
            printf("FAIL (hook did not land a checkpoint at h=%lld, got=%lld)\n",
                   (long long)H, (long long)got_h);
            failures++;
        } else if (memcmp(got_root.data, want_root.data, 32) != 0) {
            printf("FAIL (checkpointed root != the anchor_kv frontier root)\n");
            failures++;
        } else if (!have_hstar || hstar_now != (int32_t)H + 50) {
            printf("FAIL (reducer frontier re-derivation, hstar=%d)\n",
                   hstar_now);
            failures++;
        } else if (!(got_h >= activation && got_h < stall_height)) {
            printf("FAIL (tier1 window precondition NOT satisfied: "
                   "activation=%lld ckpt_h=%lld stall_height=%lld)\n",
                   (long long)activation, (long long)got_h,
                   (long long)stall_height);
            failures++;
        } else {
            printf("OK\n");
        }
    }

    /* (h) sapling_checkpoint_hook_in_tx names a typed blocker (Wave N
     * hardening, FORWARD_PLAN.md item 7) when anchor_kv_latest_tree hits a
     * genuine store-read error on sapling_anchors (a corrupt tree blob),
     * distinct from the benign "no frontier yet" case (h)'s sibling (g)
     * covers, and self-clears on the next clean read. */
    printf("sapling_ckpt_persist sapling_checkpoint_hook_in_tx names a typed "
           "blocker on an anchor read error, self-clears on repair ... ");
    {
        char dir[256], dir_rel[256];
        test_make_tmpdir(dir_rel, sizeof(dir_rel), "sapling_ckpt_hook",
                         "anchor_err");
        /* Absolute-only private seam, as above. */
        test_abs_path(dir_rel, dir, sizeof(dir));
        progress_store_close();
        bool ok = progress_store_open(dir);
        sqlite3 *pdb = ok ? progress_store_db() : NULL;
        ok = ok && pdb != NULL && ckpt_ensure_log_schema(pdb);

        uint8_t txid[32];
        memset(txid, 0x55, sizeof(txid));
        ok = ok && coins_kv_ensure_schema(pdb) &&
             coins_kv_add(pdb, txid, 0, 1000LL, 1, false, NULL, 0);
        uint8_t one = 1;
        ok = ok && progress_meta_set(pdb, COINS_KV_MIGRATION_COMPLETE_KEY,
                                     &one, 1);

        const int64_t activation = 100;
        const int64_t H = 500000;
        ok = ok && anchor_kv_initialize_history(pdb, activation);
        struct incremental_merkle_tree frontier;
        ckpt_build_tree(11, &frontier);
        ok = ok && anchor_kv_add_tree(pdb, ANCHOR_POOL_SAPLING, &frontier, H);
        ok = ok && coins_kv_set_applied_height_in_tx(pdb, (int32_t)H + 1);

        /* Corrupt the just-written frontier row's tree blob so
         * anchor_kv_latest_tree's decode/root check fails -> ANCHOR_KV_ERROR
         * (a genuine store-read error), not ANCHOR_KV_MISSING/
         * HISTORY_INCOMPLETE. */
        if (ok) {
            sqlite3_stmt *upd = NULL;
            static const uint8_t garbage[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0};
            ok = sqlite3_prepare_v2(pdb,
                    "UPDATE sapling_anchors SET tree=? WHERE height=?",
                    -1, &upd, NULL) == SQLITE_OK;
            if (ok) {
                sqlite3_bind_blob(upd, 1, garbage, sizeof(garbage), SQLITE_STATIC);
                sqlite3_bind_int64(upd, 2, H);
                ok = sqlite3_step(upd) == SQLITE_DONE;
                sqlite3_finalize(upd);
            }
        }

        set_sapling_checkpoint_datadir(dir);
        char ckpt_path[512];
        snprintf(ckpt_path, sizeof(ckpt_path), "%s/sapling_tree_ckpt.dat",
                 dir);

        uint8_t bhash[32];
        for (int i = 0; i < 32; i++) bhash[i] = (uint8_t)(0xC0 + i);
#ifdef ZCL_TESTING
        sapling_checkpoint_hook_test_force_next();
#endif
        if (ok)
            sapling_checkpoint_hook_in_tx(pdb, H, bhash);

        bool blocker_raised_on_error = ok &&
            blocker_exists("sapling_checkpoint_hook.anchor_read_error");

        /* Repair via a fresh, VALID higher-height frontier row (the anchor
         * the reducer would normally append) — the hook reads MAX(height),
         * so this becomes the new latest and the corrupt row is bypassed
         * without needing to hand-repair it. anchor_kv_add_tree keys on the
         * tree's OWN root (anchor_kv.c: INSERT OR IGNORE on the `anchor`
         * primary key), so re-adding the byte-identical `frontier` would
         * silently no-op against the still-corrupted row's PK — append one
         * more commitment so the repair root genuinely differs. */
        struct incremental_merkle_tree frontier2 = frontier;
        struct uint256 extra_cm;
        ckpt_fill_hash(&extra_cm, 0x5A, 99);
        incremental_tree_append(&frontier2, &extra_cm);
        ok = ok && anchor_kv_add_tree(pdb, ANCHOR_POOL_SAPLING, &frontier2, H + 1);
#ifdef ZCL_TESTING
        sapling_checkpoint_hook_test_force_next();
#endif
        if (ok)
            sapling_checkpoint_hook_in_tx(pdb, H + 1, bhash);
        bool blocker_cleared_after_repair = ok &&
            !blocker_exists("sapling_checkpoint_hook.anchor_read_error");

        set_sapling_checkpoint_datadir(NULL);
        unlink(ckpt_path);
        progress_store_close();

        if (!ok) {
            printf("FAIL (fixture setup)\n"); failures++;
        } else if (!blocker_raised_on_error) {
            printf("FAIL (typed blocker NOT raised on anchor read error)\n");
            failures++;
        } else if (!blocker_cleared_after_repair) {
            printf("FAIL (typed blocker did NOT self-clear after repair)\n");
            failures++;
        } else {
            printf("OK\n");
        }
    }

    #undef CKPT_BOUND_H

    return failures;
}
