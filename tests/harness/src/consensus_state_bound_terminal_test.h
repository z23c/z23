/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#if defined(__linux__)
#include "../../../engine/composition/src/consensus_state_install_terminal_internal.h"
#include "services/wallet_history_capability.h"
#include "services/wallet_history_manifest.h"
#include "base/hex.h"
static bool csi_bound_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t n = strlen(text);
    bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && chmod(path, 0600) == 0 && ok;
}
static bool csi_bound_prepare_history(const char *base, char parent[512],
                                      char path[512], uint8_t root_hash[32], bool *built)
{
    char blocks[512], file[512];
    if (snprintf(parent, 512, "%s/cap-parent", base) >= 512 ||
        snprintf(path, 512, "%s/history", parent) >= 512 ||
        snprintf(blocks, sizeof(blocks), "%s/blocks", path) >= (int)sizeof(blocks) ||
        mkdir(parent, 0700) || mkdir(path, 0700) || mkdir(blocks, 0700)) return false;
    if (snprintf(file, sizeof(file), "%s/block_index.bin", path) >= (int)sizeof(file) ||
        !csi_bound_write(file, "index") ||
        snprintf(file, sizeof(file), "%s/blk00000.dat", blocks) >= (int)sizeof(file) ||
        !csi_bound_write(file, "block") ||
        snprintf(file, sizeof(file), "%s/lease", parent) >= (int)sizeof(file) ||
        !csi_bound_write(file, "lease")) return false;
    struct file_manifest *manifest = calloc(1, sizeof(*manifest));
    if (!manifest) return false;
    *built = wallet_history_manifest_build(manifest, path, 1).ok;
    if (*built) memcpy(root_hash, manifest->root_hash, 32);
    free(manifest);
    return true;
}
static bool csi_bound_capability(const char *base, struct wallet_history_capability *cap,
                                 char path[512], uint8_t root_hash[32])
{
    char parent[512];
    bool ok;
    if (!csi_bound_prepare_history(base, parent, path, root_hash, &ok)) return false;
    struct platform_directory_transaction p, tree;
    struct platform_directory_lock lease;
    platform_directory_transaction_init(&p); platform_directory_transaction_init(&tree);
    platform_directory_lock_init(&lease); wallet_history_capability_init(cap);
    ok = ok && platform_directory_transaction_open(&p, parent) &&
        platform_directory_lock_acquire(&p, "lease", false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(&p, "history", false, &tree) == PLATFORM_DIRECTORY_OK &&
        wallet_history_capability_acquire(cap, &p, &tree, &lease, "history", "lease", 1, root_hash).ok;
    platform_directory_transaction_close(&tree); platform_directory_lock_release(&lease);
    platform_directory_transaction_close(&p);
    return ok;
}
static void csi_bound_observed_hook(void *opaque) { *(bool *)opaque = true; }
static bool csi_bound_refused(struct node_db *node, struct main_state *main,
    const char *dir, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *cap, const char *reason)
{
    struct consensus_state_install_runtime_result out = {0};
    bool called = false;
    consensus_state_install_test_after_stage(csi_bound_observed_hook, &called);
    struct zcl_result r = consensus_state_install_from_bound_bundle_terminal_guarded(
        node, main, dir, ws, wallet, observation, cap, &out);
    consensus_state_install_test_after_stage(NULL, NULL);
    struct wallet_cutover_binding binding;
    return !r.ok && strstr(r.message, reason) && !called && !out.state_installed &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_ABSENT &&
        !boot_consensus_bundle_marker_exists(dir);
}
static bool csi_bound_other_tree(const char *base, char path[512])
{
    char blocks[512], file[512];
    if (snprintf(path, 512, "%s/other-history", base) >= 512 ||
        snprintf(blocks, sizeof(blocks), "%s/blocks", path) >= (int)sizeof(blocks) ||
        mkdir(path, 0700) || mkdir(blocks, 0700)) return false;
    return snprintf(file, sizeof(file), "%s/block_index.bin", path) < (int)sizeof(file) &&
        csi_bound_write(file, "index") &&
        snprintf(file, sizeof(file), "%s/blk00000.dat", blocks) < (int)sizeof(file) &&
        csi_bound_write(file, "block");
}
static bool csi_bound_retry_mismatch(void)
{
    struct boot_bound_bundle_observation obs = {0};
    struct wallet_cutover_binding expected = {.history_identity_present = true};
    struct consensus_state_install_runtime_result out;
    for (unsigned i = 0; i < 4; ++i) {
        struct boot_bound_bundle_observation bad = obs;
        if (i == 0) bad.endpoint_height++;
        if (i == 1) bad.endpoint_hash[0]++;
        if (i == 2) bad.snapshot_sha3[0]++;
        if (i == 3) bad.history_manifest_root[0]++;
        memset(&out, 0xff, sizeof(out));
        struct zcl_result r = consensus_state_install_from_bound_bundle_terminal_old_retry(
            NULL, NULL, NULL, NULL, NULL, &bad, NULL, &expected, &out);
        if (r.ok || !strstr(r.message, "does not match pending binding") ||
            out.state_installed || !strstr(out.reason, "does not match pending binding")) return false;
    }
    return true;
}
static bool csi_bound_mismatch_cases(struct node_db *node, struct main_state *main,
    const char *dir, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *obs, const struct wallet_history_capability *cap,
    const char *root, bool ok)
{
    struct boot_bound_bundle_observation bad = *obs; bad.history_manifest_root[0] ^= 1;
    ok = ok && csi_bound_refused(node, main, dir, ws, wallet, &bad, cap, "wallet history root does not match request");
    bad = *obs; bad.snapshot_sha3[0] ^= 1;
    ok = ok && csi_bound_refused(node, main, dir, ws, wallet, &bad, cap, "bundle digest does not match request");
    bad = *obs; bad.endpoint_hash[0] ^= 1;
    ok = ok && csi_bound_refused(node, main, dir, ws, wallet, &bad, cap, "bundle endpoint does not match request");
    bad = *obs; bad.endpoint_height++;
    ok = ok && csi_bound_refused(node, main, dir, ws, wallet, &bad, cap, "bundle endpoint does not match request");
    char other[512] = {0};
    ok = ok && csi_bound_other_tree(root, other);
    bad = *obs; snprintf(bad.private_history_path, sizeof(bad.private_history_path), "%s", other);
    return ok && csi_bound_refused(node, main, dir, ws, wallet, &bad, cap, "wallet history path does not match request");
}
static bool csi_bound_swap_refusal(const struct zcl_result *r, const struct csi_stage_swap *swap,
    const struct consensus_state_install_runtime_result *out, struct wallet_sqlite *ws, const char *dir)
{
    struct wallet_cutover_binding binding;
    return !r->ok && strstr(r->message, "retained bundle differs from the admitted source") &&
        swap->swapped && !out->state_installed &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_ABSENT &&
        !boot_consensus_bundle_marker_exists(dir);
}
static bool csi_bound_swap_child(const char *root)
{
    struct rung_act_ctx c; struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL; struct coins_view_cache cache;
    if (!csi_bound_retry_mismatch() ||
        !csi_guarded_child_setup(&c, root, &node, &ws, &wallet, &main, &cache)) return false;
    struct wallet_history_capability cap;
    struct boot_bound_bundle_observation obs = {0};
    if (!csi_bound_capability(root, &cap, obs.private_history_path, obs.history_manifest_root)) return false;
    if (snprintf(obs.bundle_path, sizeof(obs.bundle_path), "%s", c.kb.path) >= (int)sizeof(obs.bundle_path)) return false;
    struct consensus_state_artifact_evidence *e = NULL;
    struct consensus_state_bundle_manifest manifest = {0};
    bool ok = consensus_state_artifact_evidence_open(c.kb.path, -1, &e).ok &&
        consensus_state_artifact_evidence_file_digest(e, obs.snapshot_sha3) &&
        consensus_state_artifact_evidence_manifest_copy(e, &manifest);
    if (!consensus_state_artifact_evidence_close(&e)) ok = false;
    obs.endpoint_height = manifest.height; memcpy(obs.endpoint_hash, manifest.block_hash, 32);
    ok = csi_bound_mismatch_cases(node, main, c.rdir, ws, wallet, &obs, &cap, root, ok);
    char replacement[512];
    int n = snprintf(replacement, sizeof(replacement), "%s/bound-other.sqlite", root);
    ok = ok && n >= 0 && (size_t)n < sizeof(replacement) && csi_stage_swap_replacement(c.kb.path, replacement);
    struct csi_stage_swap swap = {.dir = c.rdir, .replacement = replacement};
    consensus_state_install_test_after_stage(csi_stage_swap_hook, &swap);
    struct consensus_state_install_runtime_result out = {0};
    struct zcl_result r = consensus_state_install_from_bound_bundle_terminal_guarded(
        node, main, c.rdir, ws, wallet, &obs, &cap, &out);
    ok = ok && csi_bound_swap_refusal(&r, &swap, &out, ws, c.rdir);
    consensus_state_install_test_after_stage(NULL, NULL);
    wallet_history_capability_release(&cap);
    return ok && csi_bound_refused(node, main, c.rdir, ws, wallet, &obs, &cap,
                                   "wallet history root does not match request");
}
static bool csi_bound_preflight_unchanged(struct rung_act_ctx *c, struct node_db *node,
    struct main_state *main, struct block_index *tip, sqlite3_int64 progress_before,
    sqlite3_int64 node_before, size_t map_before)
{
    return sqlite3_total_changes64(c->pdb) == progress_before &&
        sqlite3_total_changes64(node->db) == node_before &&
        main->map_block_index.size == map_before && active_chain_tip(&main->chain_active) == tip;
}
static bool csi_bound_preflight_authority(struct block_index *tip, const uint8_t logical[32],
    const struct consensus_state_bundle_manifest *manifest, struct wallet_history_capability *cap,
    const struct boot_bound_bundle_observation *obs)
{
    return tip && tip->phashBlock && !memcmp(logical, manifest->artifact_digest, 32) &&
        wallet_history_capability_matches(cap, obs->history_manifest_root).ok &&
        wallet_history_capability_matches_path(cap, obs->private_history_path).ok &&
        consensus_state_rom_checkpoint_content_matches(manifest);
}
static bool csi_bound_preflight_refusal(struct zcl_result refused,
    const struct bound_history_preflight *p, struct rung_act_ctx *c, struct node_db *node,
    struct main_state *main, struct block_index *tip, sqlite3_int64 progress_before,
    sqlite3_int64 node_before, size_t map_before, struct wallet_sqlite *ws)
{
    struct wallet_cutover_binding binding;
    return !refused.ok && strstr(refused.message, "bound preflight input or authority unavailable") && !p &&
        csi_bound_preflight_unchanged(c, node, main, tip, progress_before, node_before, map_before) &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_ABSENT &&
        !boot_consensus_bundle_marker_exists(c->rdir);
}
static bool csi_bound_preflight_control(bool restored, struct zcl_result result,
    const struct bound_history_preflight *p, struct rung_act_ctx *c, struct node_db *node,
    struct main_state *main, struct block_index *tip, sqlite3_int64 progress_before,
    sqlite3_int64 node_before, size_t map_before)
{
    return restored && !result.ok && !p && strstr(result.message, "block_index_flat: file too small") &&
        csi_bound_preflight_unchanged(c, node, main, tip, progress_before, node_before, map_before);
}
static bool csi_bound_preflight_wrong_commitment(const char *root)
{
    struct rung_act_ctx c; struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL; struct coins_view_cache cache;
    if (!csi_guarded_child_setup(&c, root, &node, &ws, &wallet, &main, &cache)) return false;
    struct wallet_history_capability cap;
    struct boot_bound_bundle_observation obs = {0};
    if (!csi_bound_capability(root, &cap, obs.private_history_path, obs.history_manifest_root)) return false;
    if (snprintf(obs.bundle_path, sizeof(obs.bundle_path), "%s", c.kb.path) >= (int)sizeof(obs.bundle_path)) return false;
    struct consensus_state_artifact_evidence *e = NULL;
    struct consensus_state_bundle_manifest manifest = {0};
    uint8_t logical[32];
    bool ok = consensus_state_artifact_evidence_open(c.kb.path, -1, &e).ok &&
        consensus_state_artifact_evidence_file_digest(e, obs.snapshot_sha3) &&
        consensus_state_artifact_evidence_digest(e, logical) &&
        consensus_state_artifact_evidence_manifest_copy(e, &manifest);
    obs.endpoint_height = manifest.height; memcpy(obs.endpoint_hash, manifest.block_hash, 32);
    struct block_index *tip = active_chain_tip(&main->chain_active);
    int32_t old_height = tip ? tip->nHeight : -1;
    const uint8_t *old_hash = tip && tip->phashBlock ? tip->phashBlock->data : NULL;
    ok = ok && csi_bound_preflight_authority(tip, logical, &manifest, &cap, &obs);
    sqlite3_int64 progress_before = sqlite3_total_changes64(c.pdb);
    sqlite3_int64 node_before = sqlite3_total_changes64(node->db);
    size_t map_before = main->map_block_index.size;
    struct bound_history_preflight *p = NULL;
    c.rung.cp.utxo_root[0] ^= 1;
    bool wrong = ok && !consensus_state_rom_checkpoint_content_matches(&manifest);
    struct zcl_result refused = bound_history_preflight_open(&p, &obs, e, &cap, old_height, old_hash);
    wrong = wrong && csi_bound_preflight_refusal(refused, p, &c, node, main, tip,
                                                  progress_before, node_before, map_before, ws);
    c.rung.cp.utxo_root[0] ^= 1;
    bool restored = consensus_state_rom_checkpoint_content_matches(&manifest);
    struct zcl_result reaches_archive = bound_history_preflight_open(&p, &obs, e, &cap, old_height, old_hash);
    bool control = csi_bound_preflight_control(restored, reaches_archive, p, &c, node, main, tip,
                                                progress_before, node_before, map_before);
    bound_history_preflight_close(&p);
    wallet_history_capability_release(&cap);
    bool closed = consensus_state_artifact_evidence_close(&e);
    return wrong && control && closed;
}
static bool csi_bound_preflight_case(const char *root)
{
    pid_t child = fork();
    if (!child) { alarm(90); _exit(csi_bound_preflight_wrong_commitment(root) ? 0 : 1); }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int csi_bound_swap_case(void)
{
    int failures = 0; char root[256];
    test_make_tmpdir(root, sizeof(root), "bound_stage_swap", "private");
    pid_t child = fork();
    if (!child) { alarm(90); _exit(csi_bound_swap_child(root) ? 0 : 1); }
    int status = 0;
    bool ok = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    CSI_CHECK("bound terminal: mismatches and staged swap preserve wallet fence", ok);
    test_rm_rf_recursive(root);
    test_make_tmpdir(root, sizeof(root), "bound_preflight", "authority");
    CSI_CHECK("bound preflight rejects wrong compiled commitment before archive open", csi_bound_preflight_case(root));
    test_rm_rf_recursive(root); return failures;
}
struct csi_bound_lock { zcl_mutex_t *mutex; int ready, release; bool handshake; };
static void *csi_bound_hold_lock(void *opaque)
{
    struct csi_bound_lock *lock = opaque; char byte = 1;
    zcl_mutex_lock(lock->mutex);
    ssize_t sent = write(lock->ready, &byte, 1);
    ssize_t received = sent == 1 ? read(lock->release, &byte, 1) : -1;
    lock->handshake = sent == 1 && received == 1;
    zcl_mutex_unlock(lock->mutex); return NULL;
}
static bool csi_bound_close_pipes(int ready[2], int release[2])
{
    bool closed = close(ready[0]) == 0;
    closed = close(ready[1]) == 0 && closed;
    closed = close(release[0]) == 0 && closed;
    closed = close(release[1]) == 0 && closed;
    return closed;
}
static bool csi_bound_contention(struct node_db *node, struct main_state *main,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct consensus_state_publication_decision_record *decision,
    const struct consensus_state_bundle_manifest *manifest)
{
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    if (pipe(ready)) return false;
    if (pipe(release)) { close(ready[0]); close(ready[1]); return false; }
    struct csi_bound_lock held = {.mutex = &main->cs_main, .ready = ready[1], .release = release[0]};
    pthread_t thread;
    if (pthread_create(&thread, NULL, csi_bound_hold_lock, &held)) {
        close(ready[0]); close(ready[1]); close(release[0]); close(release[1]); return false;
    }
    char byte = 0; struct pollfd event = {.fd = ready[0], .events = POLLIN};
    bool started = poll(&event, 1, 5000) == 1 && read(ready[0], &byte, 1) == 1;
    unsigned char before[sizeof(wallet->scan_retry)]; memcpy(before, &wallet->scan_retry, sizeof(before));
    struct wallet_cutover_binding binding = {0}; const unsigned char hash[32] = {1};
    bool refused = started && !boot_bound_wallet_fence(node, main, ws, wallet, decision,
                                                        manifest, hash, hash, &binding);
    struct wallet_cutover_binding readback;
    bool clean = wallet_sqlite_cutover_read(ws, &readback) == WALLET_CUTOVER_ABSENT &&
        !memcmp(before, &wallet->scan_retry, sizeof(before));
    bool sent = write(release[1], &byte, 1) == 1;
    bool joined = pthread_join(thread, NULL) == 0;
    bool closed = csi_bound_close_pipes(ready, release);
    return started && refused && clean && sent && joined && held.handshake && closed;
}
static bool csi_bound_height_refusals(struct boot_old_height_map *map,
    struct main_state *main, struct wallet *wallet, struct wallet_cutover_binding *binding,
    struct block_index *frontier, struct block_index *five, bool ok)
{
    int unused = -1; const unsigned char zero[32] = {0};
    ok = ok && !boot_old_height_resolve(map, zero, &unused);
    wallet->map_wallet[0].hash_block.data[0] ^= 0x80;
    if (!boot_old_height_allocate(map)) ok = false;
    else if (boot_old_height_prepare_locked(map, main, wallet, binding)) ok = false;
    boot_old_height_free(map);
    wallet->map_wallet[0].hash_block = *five->phashBlock;
    unsigned saved = frontier->nStatus; frontier->nStatus |= BLOCK_FAILED_VALID;
    if (!boot_old_height_allocate(map)) ok = false;
    else if (boot_old_height_prepare_locked(map, main, wallet, binding)) ok = false;
    boot_old_height_free(map); frontier->nStatus = saved;
    struct block_index *prev = frontier->pprev; frontier->pprev = NULL;
    if (!boot_old_height_allocate(map)) ok = false;
    else if (boot_old_height_prepare_locked(map, main, wallet, binding)) ok = false;
    boot_old_height_free(map); frontier->pprev = prev;
    return ok;
}
static bool csi_bound_tree_height(struct main_state *main, struct wallet *wallet,
    struct boot_old_height_map *map, struct block_index *five,
    int durable_height, const uint8_t durable_hash[32])
{
    struct block_index *durable = active_chain_at(&main->chain_active, durable_height);
    if (!durable || !durable->phashBlock || memcmp(durable->phashBlock->data, durable_hash, 32)) return false;
    unsigned status = five->nStatus;
    five->nStatus = (status & ~(unsigned)BLOCK_VALID_MASK) | BLOCK_VALID_TREE;
    struct wallet_cutover_binding tree_binding = {.old_height = durable_height};
    memcpy(tree_binding.old_hash, durable_hash, 32);
    bool tree_ok = boot_old_height_allocate(map) &&
        boot_old_height_prepare_locked(map, main, wallet, &tree_binding);
    boot_old_height_free(map);
    five->nStatus = status;
    return tree_ok;
}
static bool csi_bound_height_cases(struct main_state *main, struct wallet *wallet, int durable_height, const uint8_t durable_hash[32])
{
    struct block_index *frontier = active_chain_at(&main->chain_active, 120);
    struct block_index *five = active_chain_at(&main->chain_active, 5);
    if (!frontier || !frontier->phashBlock || !five || !five->phashBlock) return false;
    struct wallet_cutover_binding binding = {.old_height = 120};
    memcpy(binding.old_hash, frontier->phashBlock->data, 32);
    wallet->best_block_height = 10;
    wallet->map_wallet[0].used = true; wallet->map_wallet[0].hash_block = *five->phashBlock;
    wallet->map_wallet[1].used = true; wallet->map_wallet[1].hash_block = *five->phashBlock;
    struct boot_old_height_map map = {0};
    bool allocated = boot_old_height_allocate(&map), ok = false;
    zcl_mutex_lock(&main->cs_main);
    if (!progress_store_tx_trylock()) { zcl_mutex_unlock(&main->cs_main); boot_old_height_free(&map); return false; }
    zcl_mutex_lock(&wallet->cs);
    if (allocated && boot_old_height_prepare_locked(&map, main, wallet, &binding)) {
        int height = -1;
        ok = map.tip && map.tip->nHeight > binding.old_height && map.reference_height == 10 &&
            boot_old_height_resolve(&map, five->phashBlock->data, &height) && height == 5 &&
            boot_old_height_reference(&map, 10, map.reference_hash);
    }
    boot_old_height_free(&map);
    bool tree_ok = csi_bound_tree_height(main, wallet, &map, five, durable_height, durable_hash);
    ok = ok && tree_ok;
    ok = csi_bound_height_refusals(&map, main, wallet, &binding, frontier, five, ok);
    memset(&wallet->map_wallet[0], 0, sizeof(wallet->map_wallet[0]));
    memset(&wallet->map_wallet[1], 0, sizeof(wallet->map_wallet[1]));
    zcl_mutex_unlock(&wallet->cs); progress_store_tx_unlock(); zcl_mutex_unlock(&main->cs_main);
    return ok;
}
static bool csi_bound_wallet_identity(sqlite3 *db, unsigned char out[32])
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT txid,raw_tx,block_hash,time_received,from_me,fee FROM wallet_transactions ORDER BY txid";
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) return false;
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    int rc, rows = 0; bool ok = true;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        ++rows;
        for (int i = 0; i < 6; ++i) {
            int type = sqlite3_column_type(s, i), len = sqlite3_column_bytes(s, i);
            const void *value = sqlite3_column_blob(s, i);
            if (len && !value) { ok = false; break; }
            sha3_256_write(&hash, (const uint8_t *)&type, sizeof(type));
            sha3_256_write(&hash, (const uint8_t *)&len, sizeof(len));
            if (len) sha3_256_write(&hash, value, (size_t)len);
        }
        if (!ok) break;
    }
    ok = ok && rc == SQLITE_DONE && rows == 2;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (ok) sha3_256_finalize(&hash, out);
    return ok;
}
static bool csi_bound_wallet_heights(sqlite3 *db, int height, int expected)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM wallet_transactions WHERE block_height=?", -1, &s, NULL) != SQLITE_OK || !s) return false;
    bool ok = sqlite3_bind_int(s, 1, height) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW &&
        sqlite3_column_int(s, 0) == expected && sqlite3_step(s) == SQLITE_DONE;
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}
static bool csi_bound_wallet_reload(struct wallet_sqlite *ws, const struct wallet *original)
{
    struct wallet *copy = calloc(1, sizeof(*copy));
    if (!copy) return false;
    wallet_init(copy);
    bool ok = wallet_sqlite_read_txs(ws, copy) && copy->num_wallet_tx == 2;
    for (size_t i = 0; ok && i < 2; ++i) {
        bool found = false;
        for (size_t j = 0; j < MAX_WALLET_TX; ++j) {
            if (copy->map_wallet[j].used && uint256_eq(&copy->map_wallet[j].tx.hash, &original->map_wallet[i].tx.hash) &&
                uint256_eq(&copy->map_wallet[j].hash_block, &original->map_wallet[i].hash_block) &&
                copy->map_wallet[j].confirms == 6) { found = true; break; }
        }
        ok = found;
    }
    wallet_free(copy); free(copy); return ok;
}
static bool csi_completed_absent_refusal(struct node_db *node, struct wallet_sqlite *ws,
    struct wallet *wallet, struct main_state *main, const char *dir)
{
    struct boot_cutover_env env = {.node = node, .wallet_db = ws, .wallet = wallet, .state = main};
    struct app_context ctx = {.datadir = dir}; struct wallet_cutover_binding binding;
    return wallet_sqlite_cutover_observe_completed(ws, &binding) == WALLET_CUTOVER_OBS_ABSENT &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_UNKNOWN &&
        !boot_cutover_publish_completed(&env, &ctx, true) &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_UNKNOWN &&
        boot_cutover_publish_completed(&env, &ctx, false) &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_UNKNOWN;
}
static bool csi_completed_pending_refusal(struct node_db *node, struct wallet_sqlite *ws,
    struct wallet *wallet, struct main_state *main, const char *dir)
{
    struct boot_cutover_env env = {.node = node, .wallet_db = ws, .wallet = wallet, .state = main};
    struct app_context ctx = {.datadir = dir}; struct wallet_cutover_binding binding;
    bool ok = wallet_sqlite_cutover_observe_completed(ws, &binding) == WALLET_CUTOVER_OBS_PENDING &&
        !boot_cutover_publish_completed(&env, &ctx, true) &&
        !boot_cutover_publish_completed(&env, &ctx, false) &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_UNKNOWN;
    if (!ok || sqlite3_exec(node->db, "UPDATE node_state SET value='invalid' WHERE key='wallet_scan_incomplete'",
                             NULL, NULL, NULL) != SQLITE_OK || sqlite3_changes(node->db) != 1) return false;
    return wallet_sqlite_cutover_observe_completed(ws, &binding) == WALLET_CUTOVER_OBS_MALFORMED &&
        !boot_cutover_publish_completed(&env, &ctx, true) &&
        !boot_cutover_publish_completed(&env, &ctx, false) &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_UNKNOWN;
}
static bool csi_bound_convert_wallet(struct rung_act_ctx *c, struct node_db *node,
    struct wallet_sqlite *ws, struct wallet *wallet, struct main_state *main, bool ok)
{
    struct block_index *tip = active_chain_at(&main->chain_active, c->kb.height);
    struct wallet_cutover_binding old = {.old_height = c->kb.height};
    if (!tip || !tip->phashBlock) return false;
    memcpy(old.old_hash, tip->phashBlock->data, 32);
    struct boot_old_height_map map = {0}; ok = ok && boot_old_height_allocate(&map);
    zcl_mutex_lock(&main->cs_main);
    if (!progress_store_tx_trylock()) { zcl_mutex_unlock(&main->cs_main); boot_old_height_free(&map); return false; }
    sqlite3_mutex *connection = sqlite3_db_mutex(node->db);
    if (!connection || sqlite3_mutex_try(connection) != SQLITE_OK) {
        progress_store_tx_unlock(); zcl_mutex_unlock(&main->cs_main); boot_old_height_free(&map); return false;
    }
    zcl_mutex_lock(&wallet->cs);
    ok = ok && boot_old_height_prepare_locked(&map, main, wallet, &old) &&
        sqlite3_exec(node->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_activate_height_v2_in_open_tx(ws, map.reference_height, boot_old_height_resolve, &map) &&
        sqlite3_exec(node->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (!sqlite3_get_autocommit(node->db)) (void)sqlite3_exec(node->db, "ROLLBACK", NULL, NULL, NULL);
    boot_old_height_free(&map); zcl_mutex_unlock(&wallet->cs); sqlite3_mutex_leave(connection);
    progress_store_tx_unlock(); zcl_mutex_unlock(&main->cs_main);
    return ok;
}
static bool csi_bound_fence_binding(struct wallet_sqlite *ws,
    struct wallet_cutover_binding *binding, const struct consensus_state_bundle_manifest *manifest,
    const uint8_t whole[32], const uint8_t history[32])
{
    return wallet_sqlite_cutover_read(ws, binding) == WALLET_CUTOVER_PENDING && binding->history_identity_present &&
        binding->target_height == manifest->height && !memcmp(binding->target_hash, manifest->block_hash, 32) &&
        !memcmp(binding->snapshot_whole_sha3, whole, 32) && !memcmp(binding->history_manifest_root, history, 32);
}
static bool csi_bound_fence_wallet(struct node_db *node, struct wallet_sqlite *ws,
    struct wallet *wallet, const unsigned char before[32], unsigned char after[32])
{
    int reference = -1, floor = -1;
    return wallet_sqlite_height_encoding(ws, &reference) == WALLET_HEIGHT_V2 && reference == 10 &&
        wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == 11 &&
        wallet->scan_retry.pending && wallet->scan_retry.from == 11 &&
        csi_bound_wallet_identity(node->db, after) && !memcmp(before, after, 32) &&
        csi_bound_wallet_heights(node->db, 5, 2) && csi_bound_wallet_reload(ws, wallet);
}
static bool csi_bound_real_manifest(const char *path, uint8_t whole[32],
                                     struct consensus_state_bundle_manifest *manifest)
{
    struct consensus_state_artifact_evidence *e = NULL;
    bool ok = consensus_state_artifact_evidence_open(path, -1, &e).ok &&
        consensus_state_artifact_evidence_file_digest(e, whole) &&
        consensus_state_artifact_evidence_manifest_copy(e, manifest);
    if (!consensus_state_artifact_evidence_close(&e)) ok = false;
    return ok;
}
static bool csi_bound_seed_wallet(struct wallet *wallet, struct wallet_sqlite *ws,
                                   const struct block_index *five)
{
    for (unsigned i = 0; i < 2; ++i) {
        struct wallet_tx *tx = &wallet->map_wallet[i];
        memset(tx, 0, sizeof(*tx)); transaction_init(&tx->tx);
        tx->tx.lock_time = i + 1; transaction_compute_hash(&tx->tx);
        tx->used = true; tx->hash_block = *five->phashBlock; tx->confirms = 6;
        tx->time_received = 1713000000 + i;
        if (!wallet_sqlite_write_tx(ws, tx)) return false;
    }
    wallet->num_wallet_tx = 2;
    return true;
}
static bool csi_bound_real_child(const char *root, bool convert_first)
{
    struct rung_act_ctx c; struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL; struct coins_view_cache cache;
    if (!csi_guarded_child_setup(&c, root, &node, &ws, &wallet, &main, &cache) ||
        !csi_completed_absent_refusal(node, ws, wallet, main, c.rdir) ||
        !csi_bound_height_cases(main, wallet, c.kb.height, c.kb.block_hash)) return false;
    struct block_index *five = active_chain_at(&main->chain_active, 5);
    if (!five || !five->phashBlock) return false;
    if (!csi_bound_seed_wallet(wallet, ws, five)) return false;
    zcl_mutex_lock(&wallet->cs);
    bool ok = wallet_sqlite_write_scan_state(ws, wallet);
    zcl_mutex_unlock(&wallet->cs);
    if (convert_first) ok = csi_bound_convert_wallet(&c, node, ws, wallet, main, ok);
    unsigned char before[32], after[32], whole[32], history[32] = {3};
    if (!ok || !csi_bound_wallet_identity(node->db, before)) return false;
    struct consensus_state_bundle_manifest manifest = {0};
    ok = csi_bound_real_manifest(c.kb.path, whole, &manifest);
    if (!ok || !csi_bound_contention(node, main, ws, wallet, &c.rdec, &manifest)) return false;
    struct wallet_cutover_binding binding;
    ok = boot_bound_wallet_fence(node, main, ws, wallet, &c.rdec, &manifest, whole, history, &binding) &&
        csi_bound_fence_binding(ws, &binding, &manifest, whole, history) &&
        csi_bound_fence_wallet(node, ws, wallet, before, after);
    return ok && csi_completed_pending_refusal(node, ws, wallet, main, c.rdir);
}
static int csi_bound_real_case(bool convert_first)
{
    int failures = 0; char root[256];
    test_make_tmpdir(root, sizeof(root), "bound_real", convert_first ? "wht2" : "legacy");
    pid_t child = fork();
    if (!child) { alarm(90); _exit(csi_bound_real_child(root, convert_first) ? 0 : 1); }
    int status = 0;
    bool ok = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    CSI_CHECK(convert_first ? "bound fence preserves WHT2 wallet" : "bound fence converts legacy wallet", ok);
    test_rm_rf_recursive(root); return failures;
}
static bool csi_bound_observation(const struct rung_act_ctx *c,
    struct boot_bound_bundle_observation *observation)
{
    snprintf(observation->bundle_path, sizeof(observation->bundle_path), "%s", c->kb.path);
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct consensus_state_bundle_manifest manifest = {0};
    bool ok = consensus_state_artifact_evidence_open(c->kb.path, -1, &evidence).ok &&
        consensus_state_artifact_evidence_file_digest(evidence, observation->snapshot_sha3) &&
        consensus_state_artifact_evidence_manifest_copy(evidence, &manifest);
    if (!consensus_state_artifact_evidence_close(&evidence)) ok = false;
    observation->endpoint_height = manifest.height;
    memcpy(observation->endpoint_hash, manifest.block_hash, 32);
    return ok;
}
static bool csi_bound_received_capability(const char *base, const uint8_t snapshot[32],
    struct wallet_history_capability *cap, char path[512], uint8_t root_hash[32])
{
    char parent[512];
    bool ok;
    if (!csi_bound_prepare_history(base, parent, path, root_hash, &ok)) return false;
    char identity[130], leaf[160], lock[160], named[512], source[512];
    zcl_hex_encode(snapshot, 32, identity);
    identity[64] = '-';
    zcl_hex_encode(root_hash, 32, identity + 65);
    int length = snprintf(leaf, sizeof(leaf), "history-%s", identity);
    ok = ok && length > 0 && (size_t)length < sizeof(leaf) &&
        snprintf(named, sizeof(named), "%s/%s", parent, leaf) < (int)sizeof(named) &&
        rename(path, named) == 0;
    if (!ok) return false;
    memcpy(path, named, strlen(named) + 1);
    length = snprintf(lock, sizeof(lock), ".history-%s-lock", identity);
    ok = length > 0 && (size_t)length < sizeof(lock) &&
        snprintf(source, sizeof(source), "%s/lease", parent) < (int)sizeof(source) &&
        snprintf(named, sizeof(named), "%s/%s", parent, lock) < (int)sizeof(named) &&
        rename(source, named) == 0;
    if (!ok) return false;
    struct platform_directory_transaction p, tree;
    struct platform_directory_lock lease;
    platform_directory_transaction_init(&p); platform_directory_transaction_init(&tree);
    platform_directory_lock_init(&lease); wallet_history_capability_init(cap);
    ok = platform_directory_transaction_open(&p, parent) &&
        platform_directory_lock_acquire(&p, lock, false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(&p, leaf, false, &tree) == PLATFORM_DIRECTORY_OK &&
        wallet_history_capability_acquire(cap, &p, &tree, &lease, leaf, lock, 1, root_hash).ok;
    platform_directory_transaction_close(&tree); platform_directory_lock_release(&lease);
    platform_directory_transaction_close(&p);
    return ok;
}
static bool csi_bound_prebinding_loader(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params, struct block_index **tip)
{
    if (!env || !ctx || !params || !tip) return false;
    *tip = active_chain_tip(&env->state->chain_active);
    return *tip != NULL;
}
static bool csi_bound_success_child(const char *root)
{
    struct rung_act_ctx c; struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL; struct coins_view_cache cache;
    if (!csi_guarded_child_setup(&c, root, &node, &ws, &wallet, &main, &cache)) return false;
    struct wallet_history_capability cap;
    wallet_history_capability_init(&cap);
    struct boot_bound_bundle_observation obs = {0};
    bool ok = csi_bound_observation(&c, &obs) &&
        csi_bound_received_capability(root, obs.snapshot_sha3, &cap,
                                      obs.private_history_path, obs.history_manifest_root);
    wallet_history_capability_release(&cap);
    struct boot_bound_bundle_request request = {
        .bundle_path = obs.bundle_path, .private_history_path = obs.private_history_path,
        .endpoint_height = obs.endpoint_height,
    };
    memcpy(request.snapshot_sha3, obs.snapshot_sha3, 32);
    memcpy(request.endpoint_hash, obs.endpoint_hash, 32);
    memcpy(request.history_manifest_root, obs.history_manifest_root, 32);
    ok = ok && boot_install_bound_bundle_request(c.rdir, &request, NULL) == BOOT_BUNDLE_ARM_CREATED;
    struct boot_cutover_env env = {
        .state = main, .node = node, .wallet = wallet, .wallet_db = ws,
        .sapling_load_ok = true,
    };
    struct app_context ctx = {.datadir = c.rdir};
    boot_cutover_test_set_prebinding_loader(csi_bound_prebinding_loader);
    bool returned = boot_cutover_install_bound(&env, &ctx, chain_params_get(), &obs);
    boot_cutover_test_set_prebinding_loader(NULL);
    struct wallet_cutover_binding binding;
    struct boot_bound_bundle_observation after;
    ok = ok && !returned && boot_old_cutover_restart_pending() &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        binding.target_height == obs.endpoint_height &&
        !memcmp(binding.target_hash, obs.endpoint_hash, 32) &&
        boot_install_bound_bundle_read(c.rdir, &after) == BOOT_BOUND_READ_ABSENT &&
        boot_consensus_bundle_marker_exists(c.rdir);
    if (!ok) fprintf(stderr, "bound success fixture refused: pending=%d marker=%d\n",
        (int)wallet_sqlite_cutover_read(ws, &binding),
        (int)boot_consensus_bundle_marker_exists(c.rdir));
    return ok;
}
static int csi_bound_success_case(void)
{
    int failures = 0; char root[256];
    test_make_tmpdir(root, sizeof(root), "bound_success", "private");
    pid_t child = fork();
    if (!child) { alarm(90); _exit(csi_bound_success_child(root) ? 0 : 1); }
    int status = 0;
    bool ok = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    CSI_CHECK("bound terminal: successful install clears request and arms restart", ok);
    test_rm_rf_recursive(root); return failures;
}
static int csi_bound_attempt_case(void)
{
    int failures = 0; char root[256];
    test_make_tmpdir(root, sizeof(root), "bound_attempt", "private");
    struct boot_bound_bundle_observation observation = {0};
    snprintf(observation.bundle_path, sizeof(observation.bundle_path), "/private/snapshot");
    snprintf(observation.private_history_path, sizeof(observation.private_history_path), "/nonexistent/history");
    struct boot_bound_bundle_request request = {0};
    request.bundle_path = observation.bundle_path;
    request.private_history_path = observation.private_history_path;
    CSI_CHECK("bound attempt fixture", boot_install_bound_bundle_request(root, &request, NULL) == BOOT_BUNDLE_ARM_CREATED);
    chain_params_select(CHAIN_MAIN);
    struct app_context ctx = {.datadir = root};
    struct boot_cutover_env env = {0};
    bool refused = !boot_cutover_install_bound(&env, &ctx, chain_params_get(), &observation);
    struct boot_bound_bundle_observation after;
    CSI_CHECK("bound acquisition failure consumes attempt", refused &&
        boot_install_bound_bundle_read(root, &after) == BOOT_BOUND_READ_READY && after.attempts == 1);
    boot_install_bundle_clear(root);
    test_rm_rf_recursive(root);
    return failures;
}
#endif
