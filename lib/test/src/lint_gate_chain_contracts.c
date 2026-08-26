/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates and contracts that keep the chain's derived state single-writer and
 * self-derived: no new repair-ladder rung, no new borrowed-seed caller, no new
 * coin-backfill caller, no writer below the sealed frontier, and the
 * operator-needed sink stays wired.
 *
 * Alongside them the chain-index and reducer contracts that assert on source
 * TEXT: repaired-index persistence, chain-evidence reconstruction retries,
 * the explicit-span refold gate, the SHA3 window tool check, the block-index
 * flat atomic save, reducer-language naming in the process_block split,
 * projection deferral not being reported as a block rejection, the
 * trusted-peer stall guard, gap-fill waking the connman dispatch, and message
 * processing yielding to the send phase. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#ifdef ZCL_TESTING

#include "lint_gate_selftests.h"

#define RRUNG_SCRIPT_REL  "tools/scripts/check_no_new_repair_rung.sh"
/* A new repair-rung-named file (basename contains "reconcile") planted under
 * app/services/src so the gate's `find app -name '*.c'` scan sees it. */
#define RRUNG_FIXTURE_DST "app/services/src/_repair_rung_fixture_tmp_reconcile.c"
#define BORROWED_SEED_SCRIPT_REL "tools/lint/check_no_new_borrowed_seed.sh"
/* A production-scope caller planted under app/services/src so the borrowed-seed
 * ratchet's app/config/lib/tools scan sees it. */
#define BORROWED_SEED_FIXTURE_DST \
    "app/services/src/_borrowed_seed_fixture_tmp.c"
#define COIN_BACKFILL_CALLER_SCRIPT_REL \
    "tools/lint/check_no_new_coin_backfill_caller.sh"
/* Production-scope callers planted under app/services/src and domain/ so the
 * coin-backfill entry-point ratchet proves both app-layer and non-app compiled
 * production roots are scanned. */
#define COIN_BACKFILL_CALLER_FIXTURE_DST \
    "app/services/src/_coin_backfill_caller_fixture_tmp.c"
#define COIN_BACKFILL_CALLER_DOMAIN_FIXTURE_DST \
    "domain/wallet/src/_coin_backfill_caller_fixture_tmp.c"
#define COIN_BACKFILL_ROOT_REL \
    "test-tmp/_coin_backfill_caller_root_tmp"

#define WRITER_FRONTIER_SCRIPT_REL \
    "tools/lint/check_no_writer_below_sealed_frontier.sh"
/* A non-designated production caller of the sealed-segment WRITE API
 * (chain_segment_seal_range), planted under app/services/src so the gate's
 * app/lib/config scan sees it. app/services/src IS the designated sealer's
 * own directory, so the fixture basename must not collide with the real
 * segment_sealer_service.c — it doesn't (different file, same dir is fine;
 * the gate allowlists by exact path, not by directory). */
#define WRITER_FRONTIER_FIXTURE_DST \
    "app/services/src/_writer_below_sealed_frontier_fixture_tmp.c"

/* TENACITY I3 ratchet — a NEW repair/reconcile/backfill rung in app/ with no
 * baseline entry and no `// repair-rung-ok:` marker trips the gate; adding the
 * marker (citing a write-time-invariant test) exempts it; removing the file
 * restores green. */
int t_no_new_repair_rung(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(RRUNG_FIXTURE_DST);
    int baseline_rc = run_gate_script(RRUNG_SCRIPT_REL, NULL);
    /* Unjustified new rung — must trip. */
    int planted_bad = (repo_path(path, sizeof(path), RRUNG_FIXTURE_DST) == 0 &&
                       write_file(path, "void rung(void){}\n") == 0) ? 0 : -1;
    int trip_rc = planted_bad == 0 ? run_gate_script(RRUNG_SCRIPT_REL, NULL) : -1;
    /* Same file WITH a write-time-invariant-test marker — must pass. */
    int planted_ok = (repo_path(path, sizeof(path), RRUNG_FIXTURE_DST) == 0 &&
                      write_file(path,
                          "// repair-rung-ok:test_fixture_write_time_invariant\n"
                          "void rung(void){}\n") == 0) ? 0 : -1;
    int marker_rc = planted_ok == 0 ? run_gate_script(RRUNG_SCRIPT_REL, NULL) : -1;
    unlink_rel(RRUNG_FIXTURE_DST);
    int recover_rc = run_gate_script(RRUNG_SCRIPT_REL, NULL);
    TEST("[lint-gate] TENACITY-I3 no-new-repair-rung: clean, trips, marker exempts, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted_bad == 0);
        ASSERT(trip_rc != 0);
        ASSERT(planted_ok == 0);
        ASSERT(marker_rc == 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Sovereign-cure ratchet — coins_kv_seed_from_node_db is the borrowed UTXO
 * seed path. New production callers must fail the gate, and removing the caller
 * must restore green so the baseline remains shrink-only. */
int t_no_new_borrowed_seed_caller(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(BORROWED_SEED_FIXTURE_DST);
    int baseline_rc = run_gate_script(BORROWED_SEED_SCRIPT_REL, NULL);
    int planted = (repo_path(path, sizeof(path),
                             BORROWED_SEED_FIXTURE_DST) == 0 &&
                   write_file(path,
                              "void borrowed_seed_fixture(void) {\n"
                              "    coins_kv_seed_from_node_db(0, 0);\n"
                              "}\n") == 0) ? 0 : -1;
    int trip_rc =
        planted == 0 ? run_gate_script(BORROWED_SEED_SCRIPT_REL, NULL) : -1;
    unlink_rel(BORROWED_SEED_FIXTURE_DST);
    int recover_rc = run_gate_script(BORROWED_SEED_SCRIPT_REL, NULL);
    TEST("[lint-gate] sovereign-cure no-new-borrowed-seed: clean, trips on new caller, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Sovereign-cure ratchet — stage_repair_coin_backfill_try is the public
 * borrowed-seed-era coin-backfill repair entry. New production callers widen
 * the repair fabric; the only allowed caller is the reducer-frontier dispatcher,
 * and it must remain a single call site. */
int t_no_new_coin_backfill_caller(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(COIN_BACKFILL_CALLER_FIXTURE_DST);
    unlink_rel(COIN_BACKFILL_CALLER_DOMAIN_FIXTURE_DST);
    int baseline_rc = run_gate_script(COIN_BACKFILL_CALLER_SCRIPT_REL, NULL);
    int planted = (repo_path(path, sizeof(path),
                             COIN_BACKFILL_CALLER_FIXTURE_DST) == 0 &&
                   write_file(path,
                              "void coin_backfill_caller_fixture(void) {\n"
                              "    stage_repair_coin_backfill_try(0, 0, 0, 0, 0);\n"
                              "}\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0
                      ? run_gate_script(COIN_BACKFILL_CALLER_SCRIPT_REL, NULL)
                      : -1;
    unlink_rel(COIN_BACKFILL_CALLER_FIXTURE_DST);
    int recover_after_new_rc =
        run_gate_script(COIN_BACKFILL_CALLER_SCRIPT_REL, NULL);
    int planted_domain =
        (repo_path(path, sizeof(path),
                   COIN_BACKFILL_CALLER_DOMAIN_FIXTURE_DST) == 0 &&
         write_file(path,
                    "void coin_backfill_domain_fixture(void) {\n"
                    "    stage_repair_coin_backfill_try(0, 0, 0, 0, 0);\n"
                    "}\n") == 0) ? 0 : -1;
    int trip_domain_rc =
        planted_domain == 0
            ? run_gate_script(COIN_BACKFILL_CALLER_SCRIPT_REL, NULL)
            : -1;
    unlink_rel(COIN_BACKFILL_CALLER_DOMAIN_FIXTURE_DST);
    int recover_after_domain_rc =
        run_gate_script(COIN_BACKFILL_CALLER_SCRIPT_REL, NULL);

    char root[PATH_MAX], app_dir[PATH_MAX], jobs_dir[PATH_MAX];
    char src_dir[PATH_MAX], def_path[PATH_MAX], allowed_path[PATH_MAX];
    int root_resolved = repo_path(root, sizeof(root), COIN_BACKFILL_ROOT_REL);
    int app_n = root_resolved == 0
        ? snprintf(app_dir, sizeof(app_dir), "%s/app", root) : -1;
    int jobs_n = app_n > 0 && app_n < (int)sizeof(app_dir)
        ? snprintf(jobs_dir, sizeof(jobs_dir), "%s/app/jobs", root) : -1;
    int src_n = jobs_n > 0 && jobs_n < (int)sizeof(jobs_dir)
        ? snprintf(src_dir, sizeof(src_dir), "%s/app/jobs/src", root) : -1;
    int def_n = src_n > 0 && src_n < (int)sizeof(src_dir)
        ? snprintf(def_path, sizeof(def_path),
                   "%s/stage_repair_coin_backfill.c", src_dir) : -1;
    int allowed_n = def_n > 0 && def_n < (int)sizeof(def_path)
        ? snprintf(allowed_path, sizeof(allowed_path),
                   "%s/stage_repair_reducer_frontier_coin.c", src_dir) : -1;
    int paths_ok = allowed_n > 0 && allowed_n < (int)sizeof(allowed_path);
    int dirs_ok = paths_ok &&
        (mkdir(root, 0700) == 0 || errno == EEXIST) &&
        (mkdir(app_dir, 0700) == 0 || errno == EEXIST) &&
        (mkdir(jobs_dir, 0700) == 0 || errno == EEXIST) &&
        (mkdir(src_dir, 0700) == 0 || errno == EEXIST);
    const char *def_body =
        "void stage_repair_coin_backfill_try(void) {}\n";
    const char *allowed_body =
        "void allowed_coin_backfill(void) {\n"
        "    stage_repair_coin_backfill_try();\n"
        "}\n";
    int isolated_written = dirs_ok &&
        write_file(def_path, def_body) == 0 &&
        write_file(allowed_path, allowed_body) == 0;
    int isolated_green_rc = isolated_written
        ? run_gate_script_with_env(COIN_BACKFILL_CALLER_SCRIPT_REL,
                                   "ZCL_COIN_BACKFILL_ROOT_FOR_TEST", root)
        : -1;
    int append_dup = isolated_written
        ? write_file(allowed_path,
                     "void allowed_coin_backfill(void) {\n"
                     "    stage_repair_coin_backfill_try();\n"
                     "    stage_repair_coin_backfill_try();\n"
                     "}\n")
        : -1;
    int trip_dup_rc = append_dup == 0
        ? run_gate_script_with_env(COIN_BACKFILL_CALLER_SCRIPT_REL,
                                   "ZCL_COIN_BACKFILL_ROOT_FOR_TEST", root)
        : -1;
    int restore_allowed = append_dup == 0
        ? write_file(allowed_path, allowed_body) : -1;
    int recover_after_dup_rc = restore_allowed == 0
        ? run_gate_script_with_env(COIN_BACKFILL_CALLER_SCRIPT_REL,
                                   "ZCL_COIN_BACKFILL_ROOT_FOR_TEST", root)
        : -1;
    if (paths_ok) {
        (void)unlink(def_path);
        (void)unlink(allowed_path);
        (void)rmdir(src_dir);
        (void)rmdir(jobs_dir);
        (void)rmdir(app_dir);
        (void)rmdir(root);
    }

    TEST("[lint-gate] sovereign-cure no-new-coin-backfill-caller: clean, trips on new callers and duplicate dispatcher call, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_after_new_rc == 0);
        ASSERT(planted_domain == 0);
        ASSERT(trip_domain_rc != 0);
        ASSERT(recover_after_domain_rc == 0);
        ASSERT(isolated_written);
        ASSERT(isolated_green_rc == 0);
        ASSERT(append_dup == 0);
        ASSERT(trip_dup_rc != 0);
        ASSERT(restore_allowed == 0);
        ASSERT(recover_after_dup_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Sealed-segment substrate hardening — only the designated sealer/RPC/healer
 * surface may call the ROM write API (chain_segment_seal_range /
 * chain_segment_manifest_rebuild); a planted call from any other production
 * file must trip the gate, the documented `// writer-below-frontier-ok`
 * marker must exempt it, and removing it must recover the gate clean. */
int t_no_writer_below_sealed_frontier(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(WRITER_FRONTIER_FIXTURE_DST);
    int baseline_rc = run_gate_script(WRITER_FRONTIER_SCRIPT_REL, NULL);
    int planted = (repo_path(path, sizeof(path),
                             WRITER_FRONTIER_FIXTURE_DST) == 0 &&
                   write_file(path,
                              "void writer_below_sealed_frontier_fixture("
                              "const char *dir) {\n"
                              "    chain_segment_seal_range(dir, 0, 0, 0, 0, "
                              "0, 0);\n"
                              "}\n") == 0) ? 0 : -1;
    int trip_rc =
        planted == 0 ? run_gate_script(WRITER_FRONTIER_SCRIPT_REL, NULL) : -1;
    /* The documented escape hatch must actually exempt the same call. */
    int planted_marked = planted == 0 &&
                   write_file(path,
                              "void writer_below_sealed_frontier_fixture("
                              "const char *dir) {\n"
                              "    chain_segment_seal_range(dir, 0, 0, 0, 0, "
                              "0, 0); // writer-below-frontier-ok\n"
                              "}\n") == 0 ? 0 : -1;
    int marked_rc = planted_marked == 0
        ? run_gate_script(WRITER_FRONTIER_SCRIPT_REL, NULL) : -1;
    unlink_rel(WRITER_FRONTIER_FIXTURE_DST);
    int recover_rc = run_gate_script(WRITER_FRONTIER_SCRIPT_REL, NULL);
    TEST("[lint-gate] no-writer-below-sealed-frontier: clean, trips on non-designated caller, marker exempts, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(planted_marked == 0);
        ASSERT(marked_rc == 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E9 — operator-needed sink: the live tree satisfies the pairing
 * (emit + alerts.c subscriber), so the gate passes. (HARD gate; the
 * negative control is covered by the sandbox check in the standalone
 * script and would require mutating lib/util/src/alerts.c, which we do
 * not do in-tree.) */
int t_e9_operator_needed_sink(void)
{
    int failures = 0;
    TEST("[lint-gate] E9 operator-needed sink pairing present in tree") {
        ASSERT(run_gate_script(E9_SCRIPT_REL, NULL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_boot_repaired_index_persistence_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("boot persists repaired canonical block index") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *height_repair = strstr(buf, "block_index_repair_heights(&g_state)");
        char *pprev_repair = strstr(buf, "block_index_repair_pprev(&g_state");
        char *repaired_save = strstr(buf, "Block index repaired: saving canonical flat file");
        char *integrity = strstr(buf, "bii_verify(ctx->datadir");
        ASSERT(height_repair != NULL);
        ASSERT(pprev_repair != NULL);
        ASSERT(repaired_save != NULL);
        ASSERT(integrity != NULL);
        ASSERT(height_repair < repaired_save);
        ASSERT(pprev_repair < repaired_save);
        ASSERT(repaired_save < integrity);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_chain_evidence_reconstruct_uses_retry_persistence(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("chain evidence reconstruct uses retry persistence") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "app/services/src/chain_evidence_reconstruct.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "chain_evidence_state_set_retry") != NULL);
        ASSERT(strstr(buf, "chain_evidence_state_set_int_retry") != NULL);
        ASSERT(strstr(buf, "node_db_state_set(") == NULL);
        ASSERT(strstr(buf, "node_db_state_set_int(") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_boot_genesis_init_preserves_restored_authority_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("boot genesis init preserves restored non-genesis authority tip") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *restore = strstr(buf, "utxo_recovery_restore_chain_tip");
        char *guard = strstr(buf, "boot_restored_authority_tip = true");
        char *skip = strstr(buf, "skipped genesis_init");
        char *genesis = strstr(buf, "\"genesis_init\"");
        char *skip_activate = strstr(buf, "skip_initial_activate");
        ASSERT(restore != NULL);
        ASSERT(guard != NULL);
        ASSERT(skip != NULL);
        ASSERT(genesis != NULL);
        ASSERT(skip_activate != NULL);
        ASSERT(restore < guard);
        ASSERT(guard < genesis);
        ASSERT(skip < genesis);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path),
                         "app/services/src/utxo_recovery_restore.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "coins_best_block is genesis but UTXOs reach")
               != NULL);
        ASSERT(strstr(buf, "utxo_recovery_find_disk_backed_utxo_tip")
               != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_refold_from_anchor_explicit_span_gate_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("explicit refold-from-anchor gates body span before reset") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *do_from_anchor = strstr(buf, "if (do_from_anchor)");
        ASSERT(do_from_anchor != NULL);
        char *resume =
            strstr(do_from_anchor, "active_chain_height(&g_state.chain_active)");
        char *span = strstr(do_from_anchor, "boot_refold_body_span_contiguous");
        char *reset =
            strstr(do_from_anchor, "boot_refold_from_anchor_reset(&g_node_db)");
        char *mark =
            strstr(do_from_anchor, "refold_progress_mark_started_from_anchor");
        ASSERT(resume != NULL);
        ASSERT(span != NULL);
        ASSERT(reset != NULL);
        ASSERT(mark != NULL);
        ASSERT(do_from_anchor < resume);
        ASSERT(resume < span);
        ASSERT(span < reset);
        ASSERT(reset < mark);
        ASSERT(strstr(buf, "refold_from_anchor body_gap") != NULL);
        ASSERT(strstr(buf, "first_missing") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_sha3_window_tool_check_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("gen_sha3_windows supports single-window source proof checks") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "tools/gen_sha3_windows.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *flag = strstr(buf, "--check-window=");
        char *no_write = strstr(buf, "without writing output files");
        char *compare = strstr(buf, "expected=%s actual=%s");
        char *return_mismatch = strstr(buf, "return ok ? 0 : 1");
        ASSERT(flag != NULL);
        ASSERT(no_write != NULL);
        ASSERT(compare != NULL);
        ASSERT(return_mismatch != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "Makefile") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "lib/chain/src/sha3_windows.c") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_block_index_flat_atomic_save_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    /* Task #32 strengthened the contract: the block index now persists
     * as a SINGLE file with the 48-byte integrity header embedded inside
     * block_index.bin, published with ONE atomic rename. The old pin
     * encoded the TWO-file shape (body rename, then a separate
     * bii_write_sidecar_raw sidecar rename) — that shape is a bug
     * class: a crash between the two renames strands a fresh body under a
     * stale sidecar. The pin below enforces that:
     *   - the writer streams a SHA3 over the payload in emit_payload,
     *   - it publishes via bii_write_embedded (the shared
     *     placeholder-header → payload → back-patch → one-rename helper),
     *   - it does NOT fall back to the legacy two-file sidecar writer
     *     (bii_write_sidecar_raw is absent from the writer path).
     * The single-rename + fsync + tmp-unlink atomicity itself lives in
     * ssio_write_embedded, asserted separately below. */
    TEST("block index flat save is a single atomic embedded-header file") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "app/services/src/block_index_flat_save.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        /* Payload is streamed through SHA3 as it is written. */
        char *stream_hash = strstr(buf, "sha3_256_init(&sha3)");
        char *stream_fin  = strstr(buf, "sha3_256_finalize(&sha3, sha3_out)");
        /* Publish via the embedded single-file helper. */
        char *embedded = strstr(buf, "bii_write_embedded(datadir, emit_payload");
        /* The legacy two-file sidecar writer must NOT be on the save path. */
        char *legacy_sidecar = strstr(buf, "bii_write_sidecar_raw(datadir");
        ASSERT(stream_hash != NULL);
        ASSERT(stream_fin != NULL);
        ASSERT(embedded != NULL);
        ASSERT(legacy_sidecar == NULL);
        ASSERT(stream_hash < embedded);
        free(buf);
        buf = NULL;

        /* The atomic publish (tmp, fsync, single rename) lives in the
         * shared embedded writer. */
        ASSERT(repo_path(path, sizeof(path),
                         "lib/storage/src/sha3_sidecar_io.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *fn        = strstr(buf, "ssio_write_embedded(");
        ASSERT(fn != NULL);
        char *open_tmp  = strstr(fn, "fopen(tmp_path, \"wb\")");
        char *fsync_fd  = strstr(fn, "(void)fsync(fd)");
        char *rename_tmp = strstr(fn, "rename(tmp_path, body_path)");
        char *unlink_err = strstr(fn, "unlink(tmp_path)");
        ASSERT(open_tmp != NULL);
        ASSERT(fsync_fd != NULL);
        ASSERT(rename_tmp != NULL);
        ASSERT(unlink_err != NULL);
        ASSERT(open_tmp < fsync_fd);
        ASSERT(fsync_fd < rename_tmp);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_process_block_split_uses_reducer_language(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("process-block split comments name reducer, not deleted engines") {
        const char *files[] = {
            "lib/validation/include/validation/process_block.h",
            "lib/validation/include/validation/process_block_internals.h",
            "lib/validation/include/validation/process_block_invalidate.h",
            "lib/validation/src/process_block.c",
            "lib/validation/src/process_block_core.c",
            "lib/validation/src/process_block_crash_hooks.c",
            "lib/validation/src/process_block_failed_child.c",
            "lib/validation/src/process_block_internal.h",
            "lib/validation/src/process_block_revalidate.c",
            "lib/validation/src/process_block_tip_child.c",
            "lib/validation/src/process_block_tip_publish.c",
        };
        const char *stale[] = {
            "connect_tip",
            "disconnect_tip",
            "activate_best_chain",
            "process_new_block",
            "accept_block()",
        };

        for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
            char path[PATH_MAX];
            ASSERT(repo_path(path, sizeof(path), files[i]) == 0);
            ASSERT(read_entire_file(path, &buf) == 0);
            for (size_t j = 0; j < sizeof(stale) / sizeof(stale[0]); j++)
                ASSERT(strstr(buf, stale[j]) == NULL);
            free(buf);
            buf = NULL;
        }
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_projection_deferral_is_not_block_rejected_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("projection deferral is chain advance diagnostic, not block reject") {
        /* The one-engine deletion removed legacy connect_tip(); the reducer
         * consensus path (tip_finalize_post_step.c) is now the sole producer
         * of the projection-deferred DIAGNOSTIC. The contract anchor follows
         * the live consensus path: a deferred projection write is a
         * diagnostic counter on the new path, never a block reject. */
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "app/jobs/src/tip_finalize_post_step.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "block_source_policy_note_projection_deferred") != NULL);
        ASSERT(strstr(buf, "\"consensus_path\"") != NULL);
        ASSERT(strstr(buf, "projection-deferred-consensus-path") == NULL);
        ASSERT(strstr(buf, "EV_CHAIN_ADVANCE_DECISION") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path),
                         "app/controllers/src/sync_controller_blocks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "block_source_policy_note_projection_deferred") != NULL);
        ASSERT(strstr(buf, "\"no_db_service\"") != NULL);
        ASSERT(strstr(buf, "projection-deferred-no-db-service") == NULL);
        ASSERT(strstr(buf, "EV_CHAIN_ADVANCE_DECISION") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path),
                         "app/services/src/block_source_policy_runtime.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "op=projection_deferred reason=%s") != NULL);
        ASSERT(strstr(buf, "projection_deferred_total") != NULL);
        ASSERT(strstr(buf, "EV_CHAIN_ADVANCE_DECISION") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_trusted_peer_stall_guard_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("trusted-peer stall guards stay wired on msgprocessor rules A+B") {
        /* The trusted-peer stall exemption and the P2 frontier-parity
         * term exist only as condition terms on stall rules A and B —
         * deleting either guard is invisible to every unit test (the
         * rules still fire, just for the wrong peers). Pin the exact
         * source text so removal breaks this gate and forces a
         * conscious update here. Brittle by design. */
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msgprocessor.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        /* Trusted-peer predicate: loopback/whitelist exemption (P3). */
        ASSERT(strstr(buf, "stall_peer_trusted = net_addr_is_local") != NULL);
        /* Both consumers: rule A (stale-header disconnect) and rule B
         * (worst-outbound eviction) must each carry the exemption. */
        ASSERT(count_occurrences(buf, "!stall_peer_trusted &&") >= 2);
        /* Rule B's P2 frontier-parity term: no eviction when our header
         * frontier already reached the peer's claimed tip. */
        ASSERT(strstr(buf, "!header_frontier_at_peer_tip &&") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_gap_fill_wakes_connman_dispatch_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("gap-fill requeue wakes connman dispatch") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "app/services/src/gap_fill_service.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "gap_fill_wake_dispatcher(\"timeout_sweep\")")
               != NULL);
        ASSERT(strstr(buf, "gap_fill_wake_dispatcher(\"queued_blocks\")")
               != NULL);
        ASSERT(strstr(buf, "gap_fill_wake_dispatch_if_idle(dm, \"queued_idle\")")
               != NULL);
        ASSERT(strstr(buf, "dispatch_wakes") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_runtime_sync_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "gap_fill_set_dispatch_wake(") != NULL);
        ASSERT(strstr(buf, "connman_wake_message_handler") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/net/src/connman.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "connman_wake_message_handler") != NULL);
        ASSERT(strstr(buf, "pthread_cond_timedwait") != NULL);
        ASSERT(strstr(buf, "message_wakes") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_msg_process_yields_to_send_phase_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("msg_process yields to send phase under recv backlog") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msgprocessor.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "processed < ZCL_MSG_PROCESS_MAX_PER_CYCLE")
               != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "lib/net/src/connman.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "Phase 2: send first") != NULL);
        ASSERT(strstr(buf, "message_send_calls") != NULL);
        ASSERT(strstr(buf, "message_process_calls") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/net/include/net/msgprocessor.h") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "#define ZCL_MSG_PROCESS_MAX_PER_CYCLE 128")
               != NULL);
        ASSERT(strstr(buf, "send phase regularly") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "lib/net/src/connman.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "connman_recv_cap_for_queue") != NULL);
        ASSERT(strstr(buf, "CONNMAN_RECV_LOW_WATER_SLOTS") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_chain_unit;

#endif /* ZCL_TESTING */
