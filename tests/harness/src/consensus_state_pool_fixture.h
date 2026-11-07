/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef CONSENSUS_STATE_POOL_FIXTURE_H
#define CONSENSUS_STATE_POOL_FIXTURE_H

/* A direct database observation for the activation commit/rollback fixtures. */
static bool csi_pool_row_is(sqlite3 *db, int64_t height, bool expected_found,
                            int64_t sprout, int64_t sapling)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT sprout,sapling FROM shielded_pool_totals WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_bind_int64(st, 1, height) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR; // raw-sql-ok:test-fixture
    if (expected_found) {
        ok = rc == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
             sqlite3_column_type(st, 1) == SQLITE_INTEGER &&
             sqlite3_column_int64(st, 0) == sprout &&
             sqlite3_column_int64(st, 1) == sapling;
        if (ok) ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-fixture
    } else {
        ok = rc == SQLITE_DONE;
    }
    int final_rc = sqlite3_finalize(st);
    return ok && final_rc == SQLITE_OK;
}

#include "storage/checkpoint_rung.h"
#include "base/serialize_le.h"
#include "storage/shielded_pool_kv.h"

static int csi_v2_candidate_pool_cases(struct csi_activate_scene *s,
                                       const struct consensus_state_bundle_manifest *m,
                                       const uint8_t receipt[32])
{
    int failures = 0;
    struct consensus_state_candidate_result result;
    sqlite3 *candidate = NULL;
    char path[512];
    snprintf(path, sizeof(path), "%s/v2-candidate.db", s->dir);
    bool built = candidate_build(s->ev, s->active_dir_fd, "v2-candidate.db",
                                 CONSENSUS_CANDIDATE_FAIL_NONE, &result);
    snprintf(path, sizeof(path), "%s/v2-candidate.db", s->active_dir);
    bool opened = built && chmod(path, 0600) == 0 &&
                  sqlite3_open(path, &candidate) == SQLITE_OK;
    CSI_CHECK("v2 candidate: builds and opens", opened);
    if (!opened) goto done;
    CSI_CHECK("v2 candidate: authentic metadata validates",
              consensus_state_candidate_validate_reopened(candidate, m, receipt, &result));
    CSI_CHECK("v2 candidate: changed sprout rejects",
              exec_ok(candidate, "UPDATE consensus_state_candidate_meta SET sprout_pool_total=8") &&
              !consensus_state_candidate_validate_reopened(candidate, m, receipt, &result));
    CSI_CHECK("v2 candidate: changed sapling rejects",
              exec_ok(candidate, "UPDATE consensus_state_candidate_meta SET sprout_pool_total=7,sapling_pool_total=10") &&
              !consensus_state_candidate_validate_reopened(candidate, m, receipt, &result));
    CSI_CHECK("v2 candidate: wrong version rejects",
              exec_ok(candidate, "UPDATE consensus_state_candidate_meta SET sapling_pool_total=9,bundle_format_version=1") &&
              !consensus_state_candidate_validate_reopened(candidate, m, receipt, &result));
done:
    if (candidate) sqlite3_close(candidate);
    (void)unlink(path);
    return failures;
}

static bool csi_v2_make_decision(struct csi_activate_scene *s)
{
    memset(&s->cin, 0, sizeof(s->cin));
    s->ev = NULL;
    s->evr = consensus_state_artifact_evidence_open(s->b->path, -1, &s->ev);
    bool ok = s->evr.ok && s->ev &&
        consensus_state_artifact_evidence_manifest_copy(s->ev, &s->cin.manifest) &&
        consensus_state_artifact_evidence_digest(s->ev, s->cin.artifact_logical_digest) &&
        consensus_state_artifact_evidence_receipt_digest(s->ev, s->cin.artifact_receipt_digest);
    s->cin.chain_evidence_present = true;
    s->cin.chain_bound_to_artifact = true;
    memset(s->cin.chain_evidence_digest, 0xa5, 32);
    s->cin.source_receipt_present = true;
    s->cin.source_receipt = s->b->receipt;
    s->cin.target_lane = CONSENSUS_STATE_TARGET_LANE_COPY_PROOF;
    s->cin.frontier_known = true;
    s->cin.frontier_height = s->b->height;
    memcpy(s->cin.frontier_hash, s->b->block_hash, 32);
    consensus_state_publication_cas_decide(&s->cin, &s->dec);
    if (!ok || s->dec.decision != CONSENSUS_PUBLICATION_ADMIT)
        return false;
    s->active_decision = s->dec;
    s->areq.publication_decision = &s->active_decision;
    memcpy(s->areq.expected_artifact_receipt_digest, s->dec.artifact_receipt_digest, 32);
    return true;
}

static int csi_v2_pool_cutover_cases(struct csi_activate_scene *s)
{
    int failures = 0;
    int32_t old_height = s->b->height - 1;
    CSI_CHECK("v2 activation: distinct old totals seed",
              shielded_pool_kv_ensure_schema(s->pdb) &&
              shielded_pool_kv_put(s->pdb, old_height, 101, 202));
    consensus_state_snapshot_install_activate_test_fail_after_seed_once();
    bool failed = !consensus_state_snapshot_install_activate(s->pdb, &s->areq, &s->ares);
    CSI_CHECK("v2 activation: post-seed failure restores old totals",
              failed && s->ares.status == CONSENSUS_INSTALL_INJECTED_FAILURE &&
              csi_pool_row_is(s->pdb, old_height, true, 101, 202) &&
              csi_pool_row_is(s->pdb, s->b->height, false, 0, 0));
    if (s->ares.prior_generation_path[0]) (void)unlink(s->ares.prior_generation_path);
    bool activated = consensus_state_snapshot_install_activate(s->pdb, &s->areq, &s->ares);
    CSI_CHECK("v2 activation: success replaces old with exact admitted totals",
              activated && s->ares.activated &&
              csi_pool_row_is(s->pdb, old_height, false, 0, 0) &&
              csi_pool_row_is(s->pdb, s->b->height, true, 7, 9));
    if (s->ares.prior_generation_path[0]) (void)unlink(s->ares.prior_generation_path);
    return failures;
}

static int csi_v2_pool_cases(void)
{
    int failures = 0;
    char root[300];
    test_make_tmpdir(root, sizeof(root), "consensus_bundle_v2", "pool_cutover");
    struct csi_fixture f = {0};
    struct csi_activate_scene scene = {0};
    struct csi_activate_scene *s = &scene;
    s->active_dir_fd = -1;
    s->b = &f;
    s->dir = root;
    bool ready = fixture_init(&f, root, "pool", 0x80, 60, true) && rr_test_make_v2(&f);
    CSI_CHECK("v2 activation: fixture bundle", ready);
    if (!ready) goto done;
    struct rom_state_checkpoint rom;
    rom_keystone_from_fixture(&f, &rom);
    rom.format_version = ROM_STATE_CHECKPOINT_V2;
    rom.sprout_pool_total = 7;
    rom.sapling_pool_total = 9;
    struct checkpoint_rung rung;
    ready = checkpoint_rung_from_rom_checkpoint(&rom, NULL, &rung);
    CSI_CHECK("v2 activation: trusted checkpoint root folds", ready);
    if (!ready) goto done;
    memcpy(rom.rom_state_root, rung.rom_state_root, 32);
    checkpoints_set_rom_state_override_for_test(&rom);
    failures += csi_activate_open_store(s);
    failures += csi_activate_seed_wedged_store(s);
    failures += csi_activate_seed_stale_metadata(s);
    failures += csi_activate_init_request(s);
    consensus_state_snapshot_install_activate_test_set_independent_authority(false);
    bool admitted = csi_v2_make_decision(s);
    CSI_CHECK("v2 activation: exact admitted bundle", admitted);
    if (admitted) {
        failures += csi_v2_candidate_pool_cases(s, &s->cin.manifest, s->cin.artifact_receipt_digest);
        failures += csi_v2_pool_cutover_cases(s);
    }
done:
    if (s->ev) consensus_state_artifact_evidence_free(s->ev);
    consensus_state_snapshot_install_activate_test_set_independent_authority(false);
    checkpoints_reset_rom_state_override_for_test();
    reducer_frontier_test_set_compiled_anchor(-1);
    if (s->active_dir_fd >= 0) close(s->active_dir_fd);
    if (s->pdb) progress_store_close();
    fixture_free(&f);
    test_rm_rf_recursive(root);
    return failures;
}
#if !defined(_WIN32)
struct csi_pool_crash_witness {
    int64_t count;
    bool applied_present;
    int32_t applied_height;
    int32_t target;
    bool generation_present;
    uint64_t generation;
    uint8_t root[32];
};

struct csi_pool_crash_hook {
    sqlite3 *db;
    int fd;
    struct csi_pool_crash_witness old;
};

static bool csi_pool_crash_capture(sqlite3 *db, int32_t target,
                                   struct csi_pool_crash_witness *w)
{
    memset(w, 0, sizeof(*w));
    w->target = target;
    w->count = coins_kv_count(db);
    uint8_t raw[8] = {0}; size_t len = 0;
    if (!progress_meta_get_blob_exact(db, COINS_KV_AUTHORITY_GENERATION_KEY,
            raw, sizeof(raw), &len, &w->generation_present) ||
        (w->generation_present && len != sizeof(raw))) return false;
    if (w->generation_present) w->generation = zcl_read_u64_le(raw);
    return w->count >= 0 &&
        coins_kv_get_applied_height(db, &w->applied_height, &w->applied_present) &&
        coins_kv_commitment(db, w->root) == 0;
}

static void csi_pool_crash_signal(int fd, const struct csi_pool_crash_witness *w)
{
    if (write(fd, w, sizeof(*w)) != (ssize_t)sizeof(*w)) _exit(31);
    for (;;) pause();
}

static void csi_pool_crash_before_commit(void *opaque)
{
    struct csi_pool_crash_hook *h = opaque;
    if (!csi_pool_row_is(h->db, h->old.target - 1, false, 0, 0) ||
        !csi_pool_row_is(h->db, h->old.target, true, 7, 9)) _exit(32);
    csi_pool_crash_signal(h->fd, &h->old);
}

static void csi_pool_crash_writer(const char *root, int fd, bool before_commit)
{
    alarm(90);
    struct csi_fixture f = {0};
    struct csi_activate_scene scene = {0};
    struct csi_activate_scene *s = &scene;
    s->active_dir_fd = -1;
    s->b = &f;
    s->dir = root;
    if (!fixture_init(&f, root, "pool-crash", 0x80, 60, true) || !rr_test_make_v2(&f)) _exit(20);
    struct rom_state_checkpoint rom;
    rom_keystone_from_fixture(&f, &rom);
    rom.format_version = ROM_STATE_CHECKPOINT_V2;
    rom.sprout_pool_total = 7;
    rom.sapling_pool_total = 9;
    struct checkpoint_rung rung;
    if (!checkpoint_rung_from_rom_checkpoint(&rom, NULL, &rung)) _exit(21);
    memcpy(rom.rom_state_root, rung.rom_state_root, 32);
    checkpoints_set_rom_state_override_for_test(&rom);
    if (csi_activate_open_store(s) || csi_activate_seed_wedged_store(s) ||
        csi_activate_seed_stale_metadata(s) || csi_activate_init_request(s) ||
        !csi_v2_make_decision(s) || !shielded_pool_kv_ensure_schema(s->pdb) ||
        !shielded_pool_kv_put(s->pdb, f.height - 1, 101, 202)) _exit(22);
    struct csi_pool_crash_hook hook = {.db = s->pdb, .fd = fd};
    if (!csi_pool_crash_capture(s->pdb, f.height, &hook.old)) _exit(23);
    consensus_state_snapshot_install_activate_test_set_independent_authority(false);
    if (before_commit)
        consensus_state_snapshot_install_activate_test_set_after_stream_hook(
            csi_pool_crash_before_commit, &hook);
    if (!consensus_state_snapshot_install_activate(s->pdb, &s->areq, &s->ares) ||
        !s->ares.activated || !csi_pool_row_is(s->pdb, f.height - 1, false, 0, 0) ||
        !csi_pool_row_is(s->pdb, f.height, true, 7, 9)) _exit(24);
    struct csi_pool_crash_witness committed;
    if (!csi_pool_crash_capture(s->pdb, f.height, &committed)) _exit(25);
    csi_pool_crash_signal(fd, &committed);
}

static bool csi_pool_crash_reopen(const char *root, bool before_commit,
                                  const struct csi_pool_crash_witness *expected)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/activate", root);
    if (!progress_store_open(dir)) return false;
    sqlite3 *db = progress_store_db();
    struct csi_pool_crash_witness got;
    bool ok = csi_pool_crash_capture(db, expected->target, &got) &&
        got.count == expected->count && got.applied_present == expected->applied_present &&
        (!got.applied_present || got.applied_height == expected->applied_height) &&
        got.generation_present == expected->generation_present &&
        (!got.generation_present || got.generation == expected->generation) &&
        memcmp(got.root, expected->root, 32) == 0 &&
        csi_pool_row_is(db, expected->target - 1, before_commit, 101, 202) &&
        csi_pool_row_is(db, expected->target, !before_commit, 7, 9);
    progress_store_close();
    return ok;
}

static int csi_pool_crash_case(bool before_commit)
{
    int failures = 0, fd[2];
    char root[256];
    test_make_tmpdir(root, sizeof(root), "v2_pool_crash", before_commit ? "before" : "after");
    if (pipe(fd) != 0) return 1;
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) { close(fd[0]); csi_pool_crash_writer(root, fd[1], before_commit); }
    close(fd[1]);
    struct csi_pool_crash_witness w = {0};
    struct pollfd p = {.fd = fd[0], .events = POLLIN};
    int polled;
    if (child > 0) {
        do { polled = poll(&p, 1, 60000); } while (polled < 0 && errno == EINTR);
    } else polled = -1;
    ssize_t n = -1;
    if (polled == 1 && (p.revents & POLLIN)) {
        do { n = read(fd[0], &w, sizeof(w)); } while (n < 0 && errno == EINTR);
    }
    close(fd[0]);
    int status = 0;
    pid_t reaped = -1;
    if (child > 0) {
        (void)kill(child, SIGKILL);
        do { reaped = waitpid(child, &status, 0); } while (reaped < 0 && errno == EINTR);
    }
    bool killed = n == (ssize_t)sizeof(w) && reaped == child &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    CSI_CHECK("v2 pool crash: synchronized writer killed", killed);
    pid_t reader = killed ? fork() : -1;
    if (reader == 0) { alarm(90); _exit(csi_pool_crash_reopen(root, before_commit, &w) ? 0 : 1); }
    int reader_status = 0;
    pid_t observed = -1;
    if (reader > 0) {
        do { observed = waitpid(reader, &reader_status, 0); } while (observed < 0 && errno == EINTR);
    }
    CSI_CHECK("v2 pool crash: fresh process observes atomic tuple", reader > 0 &&
        observed == reader && WIFEXITED(reader_status) && WEXITSTATUS(reader_status) == 0);
    if (!failures) test_rm_rf_recursive(root);
    else printf("v2 pool crash: retained fixture=%s\n", root);
    return failures;
}

struct csi_pool_guarded_witness {
    struct csi_cutover_witness cutover;
    uint8_t root[32];
    uint8_t artifact[32];
    int64_t count;
    int32_t height;
};

struct csi_pool_guarded_hook {
    struct rung_act_ctx *scene;
    struct node_db *node;
    struct wallet_sqlite *wallet;
    int fd;
};

static void csi_pool_guarded_after_commit(void *opaque)
{
    struct csi_pool_guarded_hook *h = opaque;
    struct rung_act_ctx *c = h->scene;
    struct csi_pool_guarded_witness w = {0};
    int dirfd = open(c->rdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int32_t applied = -1;
    bool found = false;
    w.height = c->kb.height;
    w.count = coins_kv_count(c->pdb);
    memcpy(w.artifact, c->kb.artifact, 32);
    bool ok = dirfd >= 0 && !boot_consensus_bundle_marker_exists(c->rdir) &&
        wallet_sqlite_cutover_read(h->wallet, &w.cutover.binding) == WALLET_CUTOVER_PENDING &&
        consensus_state_wallet_install_classify(h->wallet, h->node, dirfd,
            &w.cutover.generation_present, &w.cutover.generation) == WALLET_INSTALL_COMMITTED &&
        w.cutover.generation_present && active_is(c->pdb, &c->kb) && w.count >= 0 &&
        coins_kv_commitment(c->pdb, w.root) == 0 &&
        coins_kv_get_applied_height(c->pdb, &applied, &found) && found && applied == c->kb.height + 1 &&
        csi_pool_row_is(c->pdb, c->kb.height - 1, false, 0, 0) &&
        csi_pool_row_is(c->pdb, c->kb.height, true, 7, 9);
    if (dirfd >= 0) close(dirfd);
    if (!ok || write(h->fd, &w, sizeof(w)) != (ssize_t)sizeof(w)) _exit(40);
    for (;;) pause();
}

static bool csi_pool_guarded_convert(struct rung_act_ctx *c)
{
    if (!rr_test_make_v2(&c->kb)) return false;
    rom_keystone_from_fixture(&c->kb, &c->rung.cp);
    c->rung.cp.format_version = ROM_STATE_CHECKPOINT_V2;
    c->rung.cp.sprout_pool_total = 7;
    c->rung.cp.sapling_pool_total = 9;
    struct checkpoint_rung rung;
    if (!checkpoint_rung_from_rom_checkpoint(&c->rung.cp, NULL, &rung)) return false;
    memcpy(c->rung.cp.rom_state_root, rung.rom_state_root, 32);
    checkpoints_set_rom_state_rungs_override_for_test(&c->rung, 1);
    struct consensus_state_artifact_evidence *ev = NULL;
    struct consensus_state_bundle_manifest m;
    struct zcl_result result = consensus_state_artifact_evidence_open(c->kb.path, -1, &ev);
    bool ok = result.ok && ev && consensus_state_artifact_evidence_manifest_copy(ev, &m);
    if (ev) consensus_state_artifact_evidence_free(ev);
    if (!ok || m.format_version != CONSENSUS_STATE_BUNDLE_V2) return false;
    memcpy(c->kb.artifact, m.artifact_digest, 32);
    return true;
}

static void csi_pool_guarded_writer(const char *root, int fd)
{
    alarm(90);
    struct rung_act_ctx c;
    struct node_db *node = NULL;
    struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL;
    struct main_state *main = NULL;
    struct coins_view_cache cache;
    if (!csi_guarded_child_setup(&c, root, &node, &ws, &wallet, &main, &cache) ||
        !csi_pool_guarded_convert(&c) || !shielded_pool_kv_ensure_schema(c.pdb) ||
        !shielded_pool_kv_put(c.pdb, c.kb.height - 1, 101, 202)) _exit(41);
    wallet->best_block_height = 10;
    zcl_mutex_lock(&wallet->cs);
    bool saved = wallet_sqlite_write_scan_state(ws, wallet);
    zcl_mutex_unlock(&wallet->cs);
    bool sentinel = sqlite3_exec(node->db,
        "INSERT INTO wallet_watch_only(address_hash,address,created_at) VALUES(zeroblob(20),'fixture',1)",
        NULL, NULL, NULL) == SQLITE_OK;
    if (!saved || !sentinel) _exit(42);
    struct csi_pool_guarded_hook hook = { &c, node, ws, fd };
    consensus_state_install_test_after_commit(csi_pool_guarded_after_commit, &hook);
    struct consensus_state_install_runtime_result out = {0};
    (void)boot_install_startup_bundle(node, main, c.kb.path, c.rdir, &out);
    _exit(43);
}

static bool csi_pool_guarded_reopen(const char *root, const struct csi_pool_guarded_witness *w)
{
    if (!csi_guarded_reopen_check(root, &w->cutover)) return false;
    char dir[320];
    snprintf(dir, sizeof(dir), "%s/ckpt-rung-act", root);
    if (!progress_store_open(dir)) return false;
    sqlite3 *db = progress_store_db();
    uint64_t generation = 0;
    uint8_t digest[32], hash[32];
    int height = -1;
    int32_t applied = -1;
    bool found = false;
    bool ok = boot_consensus_bundle_marker_matches(dir, w->height, w->artifact) &&
        coins_kv_get_authority_generation(db, &generation) && generation == w->cutover.generation &&
        coins_kv_count(db) == w->count && coins_kv_commitment(db, digest) == 0 &&
        memcmp(digest, w->root, 32) == 0 &&
        tip_finalize_stage_resolve_durable_tip(db, &height, hash) && height == w->height &&
        memcmp(hash, w->cutover.binding.target_hash, 32) == 0 &&
        coins_kv_get_applied_height(db, &applied, &found) && found && applied == w->height + 1 &&
        csi_pool_row_is(db, w->height - 1, false, 0, 0) &&
        csi_pool_row_is(db, w->height, true, 7, 9);
    progress_store_close();
    return ok;
}

static int csi_pool_guarded_crash_case(void)
{
    int failures = 0, fd[2];
    char root[256];
    test_make_tmpdir(root, sizeof(root), "v2_pool_crash", "committed");
    if (pipe(fd) != 0) return 1;
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) { close(fd[0]); csi_pool_guarded_writer(root, fd[1]); }
    close(fd[1]);
    struct csi_pool_guarded_witness w = {0};
    ssize_t n = -1;
    if (child > 0) {
        struct pollfd p = {.fd = fd[0], .events = POLLIN};
        int polled;
        do { polled = poll(&p, 1, 60000); } while (polled < 0 && errno == EINTR);
        if (polled == 1 && (p.revents & POLLIN))
            do { n = read(fd[0], &w, sizeof(w)); } while (n < 0 && errno == EINTR);
    }
    close(fd[0]);
    int status = 0;
    pid_t reaped = -1;
    if (child > 0) {
        (void)kill(child, SIGKILL);
        do { reaped = waitpid(child, &status, 0); } while (reaped < 0 && errno == EINTR);
    }
    bool killed = n == (ssize_t)sizeof(w) && reaped == child &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    CSI_CHECK("v2 pool guarded crash: committed before marker", killed);
    pid_t reader = killed ? fork() : -1;
    if (reader == 0) { alarm(90); _exit(csi_pool_guarded_reopen(root, &w) ? 0 : 1); }
    int rs = 0;
    pid_t observed = -1;
    if (reader > 0)
        do { observed = waitpid(reader, &rs, 0); } while (observed < 0 && errno == EINTR);
    CSI_CHECK("v2 pool guarded crash: recovery preserves wallet and state",
        reader > 0 && observed == reader && WIFEXITED(rs) && WEXITSTATUS(rs) == 0);
    if (!failures) test_rm_rf_recursive(root);
    else printf("v2 pool guarded crash: retained fixture=%s\n", root);
    return failures;
}
static int csi_v2_pool_crash_tests(void)
{
    return csi_pool_crash_case(true) + csi_pool_guarded_crash_case();
}
#endif
#endif
