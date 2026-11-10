/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#if defined(__linux__)
#include "wallet/wallet_keystore.h"
#include "conditions/peer_floor_violated.h"
#include <sys/file.h>

static bool csi_test_connect_only(const struct app_context *ctx)
{
    extern bool g_connect_only;
    if (!ctx || !ctx->connect_only) return false;
    g_connect_only = true;
    peer_floor_violated_set_connect_only(true);
    return true;
}
static bool csi_populated_mode(void)
{
    const char *value = getenv("ZCL_TEST_REAL_POPULATED_RETIRE");
    const char *retained = getenv("ZCL_TEST_REAL_POPULATED_RETAINED");
    return (value && !strcmp(value, "1")) || (retained && retained[0]);
}

static bool csi_populated_identity_row(sqlite3 *db, const char *query, int columns,
                                       struct sha3_256_ctx *hash)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &s, NULL) != SQLITE_OK || !s) return false;
    bool ok = sqlite3_step(s) == SQLITE_ROW;
    for (int i = 0; ok && i < columns; ++i) {
        int type = sqlite3_column_type(s, i), len = sqlite3_column_bytes(s, i);
        const void *value = sqlite3_column_blob(s, i);
        if (len && !value) { ok = false; break; }
        sha3_256_write(hash, (const uint8_t *)&type, sizeof(type));
        sha3_256_write(hash, (const uint8_t *)&len, sizeof(len));
        if (len) sha3_256_write(hash, value, (size_t)len);
    }
    if (ok) ok = sqlite3_step(s) == SQLITE_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool csi_populated_unseeded_empty(sqlite3 *db)
{
    static const char query[] = "SELECT EXISTS(SELECT 1 FROM wallet_keys),"
        "EXISTS(SELECT 1 FROM wallet_keypool), EXISTS(SELECT 1 FROM wallet_key_encryption),"
        "EXISTS(SELECT 1 FROM wallet_scripts)";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &s, NULL) != SQLITE_OK || !s) return false;
    bool ok = sqlite3_step(s) == SQLITE_ROW;
    for (int i = 0; ok && i < 4; ++i)
        ok = sqlite3_column_type(s, i) == SQLITE_INTEGER && sqlite3_column_int(s, i) == 0;
    if (ok) ok = sqlite3_step(s) == SQLITE_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool csi_populated_original_row(sqlite3_stmt *s, struct sha3_256_ctx *hash)
{
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB || sqlite3_column_bytes(s, 0) != 32 ||
        sqlite3_column_type(s, 1) != SQLITE_BLOB || sqlite3_column_type(s, 2) != SQLITE_BLOB ||
        sqlite3_column_bytes(s, 2) != 32 || sqlite3_column_type(s, 3) != SQLITE_INTEGER ||
        sqlite3_column_type(s, 4) != SQLITE_INTEGER) return false;
    for (int i = 0; i < 6; ++i) {
        int type = sqlite3_column_type(s, i), len = sqlite3_column_bytes(s, i);
        const void *value = sqlite3_column_blob(s, i);
        if (len && !value) return false;
        sha3_256_write(hash, (const uint8_t *)&type, sizeof(type));
        sha3_256_write(hash, (const uint8_t *)&len, sizeof(len));
        if (len) sha3_256_write(hash, value, (size_t)len);
    }
    return true;
}
static bool csi_populated_original_transactions(sqlite3 *db, uint8_t out[32])
{
    struct transaction tx[2];
    for (unsigned i = 0; i < 2; ++i) {
        transaction_init(&tx[i]);
        tx[i].lock_time = i + 1;
        transaction_compute_hash(&tx[i]);
    }
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT txid,raw_tx,block_hash,time_received,from_me,fee FROM wallet_transactions "
        "WHERE txid=?1 OR txid=?2 ORDER BY txid";
    bool ok = sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s &&
        sqlite3_bind_blob(s, 1, tx[0].hash.data, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(s, 2, tx[1].hash.data, 32, SQLITE_TRANSIENT) == SQLITE_OK;
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    int rc = SQLITE_ERROR, rows = 0;
    while (ok && (rc = sqlite3_step(s)) == SQLITE_ROW) {
        ++rows;
        ok = csi_populated_original_row(s, &hash);
    }
    ok = ok && rc == SQLITE_DONE && rows == 2;
    if (s && sqlite3_finalize(s) != SQLITE_OK) ok = false;
    for (unsigned i = 0; i < 2; ++i) transaction_free(&tx[i]);
    if (ok) sha3_256_finalize(&hash, out);
    return ok;
}

static bool csi_populated_wallet_identity(sqlite3 *db, uint8_t out[32])
{
    uint8_t tx[32]; struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    bool ok = csi_populated_unseeded_empty(db) && csi_populated_original_transactions(db, tx) &&
        csi_populated_identity_row(db, "SELECT seed FROM wallet_seed", 1, &hash) &&
        csi_populated_identity_row(db, "SELECT ivk,xsk,xfvk,diversifier,pk_d,child_index,address "
            "FROM wallet_sapling_keys", 7, &hash) &&
        csi_populated_identity_row(db, "SELECT address_hash,address,created_at FROM wallet_watch_only", 3, &hash);
    if (ok) { sha3_256_write(&hash, tx, sizeof(tx)); sha3_256_finalize(&hash, out); }
    return ok;
}


static bool csi_empty_wallet_identity(sqlite3 *db, uint8_t out[32])
{
    if (csi_populated_mode()) return csi_populated_wallet_identity(db, out);
    static const char query[] = "SELECT EXISTS(SELECT 1 FROM wallet_keys),"
        "EXISTS(SELECT 1 FROM wallet_keypool), EXISTS(SELECT 1 FROM wallet_key_encryption),"
        "EXISTS(SELECT 1 FROM wallet_scripts), EXISTS(SELECT 1 FROM wallet_watch_only),"
        "EXISTS(SELECT 1 FROM wallet_transactions), EXISTS(SELECT 1 FROM wallet_utxos),"
        "EXISTS(SELECT 1 FROM wallet_sapling_diversifier), EXISTS(SELECT 1 FROM wallet_sapling_keys),"
        "EXISTS(SELECT 1 FROM wallet_sapling_notes), EXISTS(SELECT 1 FROM wallet_seed)";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &s, NULL) != SQLITE_OK || !s) return false;
    bool ok = sqlite3_step(s) == SQLITE_ROW;
    for (int i = 0; ok && i < 11; ++i)
        ok = sqlite3_column_type(s, i) == SQLITE_INTEGER && sqlite3_column_int(s, i) == 0;
    if (ok) ok = sqlite3_step(s) == SQLITE_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    if (ok) { struct sha3_256_ctx hash; sha3_256_init(&hash); sha3_256_finalize(&hash, out); }
    return ok;
}

static void csi_empty_retire_fence(void *opaque)
{
    struct wallet_sqlite *ws = opaque;
    csi_real_bound_witness.fence =
        wallet_sqlite_cutover_read(ws, &csi_real_bound_witness.binding) == WALLET_CUTOVER_PENDING &&
        csi_real_bound_witness.binding.history_identity_present &&
        csi_empty_wallet_identity(ws->db, csi_real_bound_witness.wallet);
}

struct csi_empty_fence_crash { struct wallet_sqlite *ws; int fd; };
static void csi_empty_fence_then_crash(void *opaque)
{
    struct csi_empty_fence_crash *ctx = opaque;
    csi_empty_retire_fence(ctx->ws);
    if (!csi_real_bound_witness.fence ||
        write(ctx->fd, &csi_real_bound_witness, sizeof(csi_real_bound_witness)) !=
            (ssize_t)sizeof(csi_real_bound_witness)) _exit(82);
    for (;;) pause();
}
static void csi_empty_retry_existing_fence(void *opaque)
{
    struct wallet_sqlite *ws = opaque; struct wallet_cutover_binding binding;
    uint8_t wallet[32];
    if (wallet_sqlite_cutover_read(ws, &binding) != WALLET_CUTOVER_PENDING ||
        !wallet_cutover_binding_equal(&binding, &csi_real_bound_witness.binding) ||
        !csi_empty_wallet_identity(ws->db, wallet) || memcmp(wallet, csi_real_bound_witness.wallet, 32)) _exit(83);
}
static bool csi_empty_observation_equal(const struct boot_bound_bundle_observation *a,
                                        const struct boot_bound_bundle_observation *b)
{
    return a->attempts == b->attempts && a->endpoint_height == b->endpoint_height &&
        !strcmp(a->bundle_path, b->bundle_path) && !strcmp(a->private_history_path, b->private_history_path) &&
        !memcmp(a->snapshot_sha3, b->snapshot_sha3, 32) && !memcmp(a->endpoint_hash, b->endpoint_hash, 32) &&
        !memcmp(a->history_manifest_root, b->history_manifest_root, 32);
}
static bool csi_empty_refused_lane(const struct app_context *ctx)
{
    return ctx->operator_lane == ZCL_OPERATOR_LANE_UNKNOWN &&
        wallet_at_rest_boot_decision(wallet_at_rest_creation_policy(), ctx->mint_anchor, ctx->operator_lane) ==
            WALLET_BOOT_REFUSE;
}
static bool csi_empty_boot_args_ok(int a, size_t acap, int b, size_t bcap)
{
    return a >= 0 && b >= 0 && (size_t)a < acap && (size_t)b < bcap;
}
static bool csi_empty_boot_options(int argc, char **argv, struct app_context *ctx, bool *metrics)
{
    return args_parse_node_options(argc, argv, ctx, metrics) == -1 &&
        !unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL") && csi_test_connect_only(ctx) &&
        csi_empty_refused_lane(ctx);
}
static bool csi_empty_install_pending(const struct csi_real_paths *p,
    struct wallet_sqlite *ws, bool started, const struct boot_bound_bundle_observation *expected_request)
{
    struct wallet_cutover_binding current = {0}; struct boot_bound_bundle_observation observation = {0};
    return !started && boot_old_cutover_restart_pending() && csi_real_bound_witness.fence && csi_real_bound_witness.committed &&
        wallet_sqlite_cutover_read(ws, &current) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(&current, &csi_real_bound_witness.binding) &&
        boot_install_bound_bundle_read(p->data, &observation) == BOOT_BOUND_READ_READY &&
        (!expected_request || csi_empty_observation_equal(&observation, expected_request));
}
static void csi_empty_retire_install_boot(const struct csi_real_paths *p, int fd,
    bool crash_at_fence, const struct csi_real_bound_witness *previous,
    const struct boot_bound_bundle_observation *expected_request)
{
    char datadir[PATH_MAX + 32], params[PATH_MAX + 32];
    int a = snprintf(datadir, sizeof(datadir), "-datadir=%s", p->data);
    int b = snprintf(params, sizeof(params), "-paramsdir=%s", p->params);
    if (!csi_empty_boot_args_ok(a, sizeof(datadir), b, sizeof(params))) _exit(75);
    char *argv[] = {"z23", datadir, params, "-operator-lane=unknown", "-nolegacyimport",
        "-nolegacyutxoimport", "-no-tor", "-private-listeners", "-observation=0",
        "-connect=127.0.0.1:1", "-port=28033", "-rpcport=28232", "-httpsport=28443", "-fsport=28034"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0])); struct app_context ctx;
    app_context_defaults(&ctx); ctx.datadir = p->data; ctx.params_dir = p->params;
    ParseParameters(argc, (const char *const *)argv); bool metrics = false;
    if (!csi_empty_boot_options(argc, argv, &ctx, &metrics)) _exit(76);
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    struct csi_commit_hook_context hook = {p->data, node, ws, fd};
    struct csi_empty_fence_crash crash = {.ws = ws, .fd = fd};
    if (previous) csi_real_bound_witness = *previous;
    consensus_state_install_test_after_wallet_fence(previous ? csi_empty_retry_existing_fence :
        crash_at_fence ? csi_empty_fence_then_crash : csi_empty_retire_fence,
        crash_at_fence ? (void *)&crash : ws);
    consensus_state_install_test_after_commit(csi_real_bound_commit, &hook);
    boot_stage_reset_for_testing(); ecc_verify_destroy(); ecc_stop();
    bool started = app_init(&ctx);
    bool pending = csi_empty_install_pending(p, ws, started, expected_request);
    if (!pending || !boot_old_cutover_restart_cleanup() || write(fd, &csi_real_bound_witness, sizeof(csi_real_bound_witness)) !=
        (ssize_t)sizeof(csi_real_bound_witness)) _exit(77);
    _exit(0);
}

static bool csi_empty_retire_install(const struct csi_real_paths *p, struct csi_real_bound_witness *w)
{
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(78);
        close(fds[0]); csi_empty_retire_install_boot(p, fds[1], false, NULL, NULL);
    }
    close(fds[1]); int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(fds[0], w, sizeof(*w)); close(fds[0]);
    return waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof(*w);
}

static bool csi_empty_old_fence_wait(pid_t child, int fd, struct csi_real_bound_witness *w)
{
    bool got = false;
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    for (int i = 0; child > 0 && i < 30; ++i) {
        int ready = poll(&pfd, 1, 60000);
        if (ready > 0) { got = read(fd, w, sizeof(*w)) == (ssize_t)sizeof(*w); break; }
        if (ready < 0 && errno != EINTR) break;
        fprintf(stderr, "real OLD retry: awaiting durable fence\n");
    }
    return got;
}
static bool csi_empty_old_fence_kill(const struct csi_real_paths *p, struct csi_real_bound_witness *w)
{
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(84);
        close(fds[0]); csi_empty_retire_install_boot(p, fds[1], true, NULL, NULL);
    }
    close(fds[1]); bool got = csi_empty_old_fence_wait(child, fds[0], w);
    close(fds[0]);
    bool killed = child > 0 && kill(child, SIGKILL) == 0;
    int status = 0;
    pid_t reaped = -1;
    if (child > 0) {
        do { reaped = waitpid(child, &status, 0); } while (reaped < 0 && errno == EINTR);
    }
    return killed && reaped == child && WIFSIGNALED(status) &&
        WTERMSIG(status) == SIGKILL && got && w->fence && !w->committed;
}
static bool csi_empty_old_retry_request(const struct csi_real_paths *p,
    struct csi_real_bound_witness *w, struct boot_bound_bundle_observation *request)
{
    if (boot_install_bound_bundle_read(p->data, request) != BOOT_BOUND_READ_READY ||
        !csi_empty_old_fence_kill(p, w)) return false;
    struct boot_bound_bundle_observation after = {0};
    if (boot_install_bound_bundle_read(p->data, &after) != BOOT_BOUND_READ_READY ||
        request->attempts != 0 || after.attempts != 1) return false;
    request->attempts = after.attempts;
    return csi_empty_observation_equal(request, &after);
}
static bool csi_empty_old_retry(const struct csi_real_paths *p, struct csi_real_bound_witness *w)
{
    struct boot_bound_bundle_observation request = {0};
    if (!csi_empty_old_retry_request(p, w, &request)) return false;
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(85);
        close(fds[0]); csi_empty_retire_install_boot(p, fds[1], false, w, &request);
    }
    close(fds[1]); int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    struct csi_real_bound_witness committed = {0};
    ssize_t n = read(fds[0], &committed, sizeof(committed)); close(fds[0]);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof(committed) &&
        committed.fence && committed.committed && wallet_cutover_binding_equal(&w->binding, &committed.binding) &&
        !memcmp(w->wallet, committed.wallet, 32);
    if (ok) *w = committed;
    return ok;
}

static bool csi_empty_private_dir(const char *source)
{
    struct stat st;
    return source && !lstat(source, &st) && S_ISDIR(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 077);
}
/* Input is a quiescent, private public-chain snapshot with empty WAL files. */
static bool csi_empty_retire_copy_chain(const char *source, const char *destination)
{
    struct stat st;
    if (!csi_empty_private_dir(source)) return false;
    const char *files[] = {"consensus.db"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        char from[PATH_MAX], to[PATH_MAX], wal[PATH_MAX];
        if (!csi_real_path(from, sizeof(from), source, files[i]) ||
            !csi_real_path(to, sizeof(to), destination, files[i])) return false;
        int n = snprintf(wal, sizeof(wal), "%s-wal", from);
        if (n < 0 || (size_t)n >= sizeof(wal)) return false;
        if (lstat(wal, &st) == 0) {
            if (!S_ISREG(st.st_mode) || st.st_size != 0) return false;
        } else if (errno != ENOENT) return false;
        if (!csi_real_copy(from, to)) return false;
    }
    return true;
}

static bool csi_empty_retire_seed(const struct csi_real_paths *p, uint8_t identity[32])
{
    if (csi_populated_mode()) {
        uint8_t tx[32];
        if (!csi_real_seed_wallet(p) || !csi_real_bound_seed(p, tx)) return false;
        struct node_db populated = {0};
        if (!node_db_open(&populated, p->node)) return false;
        bool ok = csi_populated_wallet_identity(populated.db, identity);
        node_db_close(&populated);
        return ok;
    }
    struct node_db db = {0}; struct wallet_sqlite ws = {0};
    if (!node_db_open(&db, p->node)) return false;
    bool opened = wallet_sqlite_open_r(&ws, db.db).ok;
    struct wallet *wallet = calloc(1, sizeof(*wallet));
    bool ok = opened && wallet;
    if (ok) {
        wallet_init(wallet); wallet->best_block_height = 0;
        zcl_mutex_lock(&wallet->cs);
        ok = wallet_sqlite_write_scan_state(&ws, wallet);
        zcl_mutex_unlock(&wallet->cs);
        ok = ok && csi_empty_wallet_identity(db.db, identity);
        wallet_free(wallet);
    }
    free(wallet);
    if (opened) wallet_sqlite_close(&ws);
    node_db_close(&db);
    return ok;
}

static bool csi_empty_retire_seed_child(const struct csi_real_paths *p, uint8_t identity[32])
{
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(79);
        close(fds[0]); uint8_t value[32];
        bool ok = csi_empty_retire_seed(p, value) && write(fds[1], value, sizeof(value)) == (ssize_t)sizeof(value);
        _exit(ok ? 0 : 1);
    }
    close(fds[1]); int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(fds[0], identity, 32); close(fds[0]);
    return waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == 32;
}

static char csi_empty_replacement_path[PATH_MAX];
static bool csi_empty_replaced;
static void csi_empty_replace_at_retire(const char *path)
{
    csi_empty_replaced = rename(csi_empty_replacement_path, path) == 0;
}
static bool csi_empty_replacement_matches(const struct boot_bound_bundle_observation *a,
                                           const struct boot_bound_bundle_observation *b)
{
    return a->attempts == b->attempts + 1 && a->endpoint_height == b->endpoint_height &&
        !strcmp(a->bundle_path, b->bundle_path) && !strcmp(a->private_history_path, b->private_history_path) &&
        !memcmp(a->snapshot_sha3, b->snapshot_sha3, 32) && !memcmp(a->endpoint_hash, b->endpoint_hash, 32) &&
        !memcmp(a->history_manifest_root, b->history_manifest_root, 32);
}
static bool csi_empty_after_matches(const struct boot_bound_bundle_observation *a,
                                    const struct boot_bound_bundle_observation *b)
{
    return a->attempts == b->attempts && !strcmp(a->bundle_path, b->bundle_path) &&
        !strcmp(a->private_history_path, b->private_history_path) &&
        !memcmp(a->snapshot_sha3, b->snapshot_sha3, 32) && !memcmp(a->endpoint_hash, b->endpoint_hash, 32) &&
        !memcmp(a->history_manifest_root, b->history_manifest_root, 32) && a->endpoint_height == b->endpoint_height;
}
static void csi_empty_replacement_check(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *expected, const struct boot_bound_bundle_observation *original,
    bool started, struct node_db *node, struct wallet_sqlite *ws, struct wallet *wallet, struct main_state *main)
{
    struct wallet_cutover_binding done = {0}; struct boot_bound_bundle_observation replacement = {0}, after = {0};
    int fd = open(p->data, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool ok = !started && csi_empty_replaced && fd >= 0 &&
        wallet_sqlite_cutover_observe_completed(ws, &done) == WALLET_CUTOVER_OBS_FOUND &&
        wallet_cutover_binding_equal(expected, &done) &&
        boot_install_bound_bundle_read(p->data, &replacement) == BOOT_BOUND_READ_READY &&
        csi_empty_replacement_matches(&replacement, original) &&
        boot_bound_completed_retire(ws, node, wallet, main, p->data, fd, expected, original) ==
            BOOT_BOUND_COMPLETION_ERROR &&
        boot_install_bound_bundle_read(p->data, &after) == BOOT_BOUND_READ_READY &&
        csi_empty_after_matches(&after, &replacement);
    if (fd >= 0 && close(fd)) ok = false;
    if (!ok) fprintf(stderr, "fixture diagnostic: replacement child started=%d hook=%d fd=%d\n",
                     started, csi_empty_replaced, fd);
    _exit(ok ? 0 : 80);
}

static bool csi_empty_scan_equal(bool scan_read, enum wallet_height_encoding encoding,
    int scan, int reference, enum wallet_cutover_observation_status observed,
    const struct wallet_cutover_binding *completed)
{
    return scan_read && encoding == WALLET_HEIGHT_V2 && scan == reference &&
        observed == WALLET_CUTOVER_OBS_FOUND && scan >= completed->target_height;
}
static bool csi_empty_completion_ok(enum wallet_readiness_state readiness, bool binding_equal,
    enum boot_bound_read_result request, enum wallet_scan_state_status scan_status,
    bool scan_equal, bool identity_equal)
{
    return readiness == WALLET_READINESS_READY && binding_equal && request == BOOT_BOUND_READ_ABSENT &&
        scan_status == WALLET_SCAN_STATE_OK && scan_equal && identity_equal;
}
static void csi_empty_retire_boot(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *expected, const uint8_t before[32],
    const struct boot_bound_bundle_observation *original)
{
    char datadir[PATH_MAX + 32], params[PATH_MAX + 32];
    int a = snprintf(datadir, sizeof(datadir), "-datadir=%s", p->data);
    int b = snprintf(params, sizeof(params), "-paramsdir=%s", p->params);
    if (!csi_empty_boot_args_ok(a, sizeof(datadir), b, sizeof(params))) _exit(70);
    char *argv[] = {"z23", datadir, params, "-operator-lane=unknown", "-nolegacyimport",
        "-nolegacyutxoimport", "-no-tor", "-private-listeners", "-observation=0",
        "-connect=127.0.0.1:1", "-port=28033", "-rpcport=28232", "-httpsport=28443", "-fsport=28034"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0])); struct app_context ctx;
    app_context_defaults(&ctx); ctx.datadir = p->data; ctx.params_dir = p->params;
    ParseParameters(argc, (const char *const *)argv); bool metrics = false;
    if (!csi_empty_boot_options(argc, argv, &ctx, &metrics)) _exit(71);
    boot_stage_reset_for_testing(); ecc_verify_destroy(); ecc_stop();
    if (original) {
        csi_empty_replaced = false;
        boot_install_bound_retire_test_hook(csi_empty_replace_at_retire, false);
    }
    bool started = app_init(&ctx);
    boot_install_bound_retire_test_hook(NULL, false);
    if (!started && !original) _exit(72);
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    if (original) csi_empty_replacement_check(p, expected, original, started, node, ws, wallet, main);
    struct wallet_cutover_binding completed = {0}; struct boot_bound_bundle_observation obs = {0};
    uint8_t after[32]; int scan = -1, reference = -1;
    enum wallet_readiness_state readiness = wallet_readiness_get(wallet).state;
    enum wallet_cutover_observation_status observed = wallet_sqlite_cutover_observe_completed(ws, &completed);
    bool binding_equal = observed == WALLET_CUTOVER_OBS_FOUND && wallet_cutover_binding_equal(expected, &completed);
    enum boot_bound_read_result request = boot_install_bound_bundle_read(p->data, &obs);
    enum wallet_scan_state_status scan_status = wallet_sqlite_validate_scan_state(ws);
    bool scan_read = wallet_sqlite_read_scan_height(ws, &scan);
    enum wallet_height_encoding encoding = wallet_sqlite_height_encoding(ws, &reference);
    bool scan_equal = csi_empty_scan_equal(scan_read, encoding, scan, reference, observed, &completed);
    bool identity_read = csi_empty_wallet_identity(node->db, after);
    bool identity_equal = identity_read && !memcmp(before, after, 32);
    bool ok = csi_empty_completion_ok(readiness, binding_equal, request, scan_status, scan_equal, identity_equal);
    if (!ok) fprintf(stderr, "empty completion: readiness=%d completed=%d binding_equal=%d request=%d "
        "scan_status=%d scan_read=%d encoding=%d scan=%d reference=%d scan_equal=%d identity_read=%d identity_equal=%d\n",
        (int)readiness, (int)observed, binding_equal, (int)request, (int)scan_status, scan_read,
        (int)encoding, scan, reference, scan_equal, identity_read, identity_equal);
    _exit(ok ? 0 : 73);

}

#include "consensus_state_populated_history_test.h"

static bool csi_empty_retire_restart(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *binding, const uint8_t before[32])
{
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(74);
        csi_empty_retire_boot(p, binding, before, NULL);
    }
    int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!ok || getenv("ZCL_TEST_REAL_POPULATED_RETAINED")) fprintf(stderr, "fixture diagnostic: restart waited=%d status=%d exit=%d signal=%d\n",
        waited, status, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
        WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return ok;
}

static bool csi_empty_replacement_prepare(const struct csi_real_paths *p,
                                          struct boot_bound_bundle_observation *original)
{
    char request_path[PATH_MAX];
    return csi_real_path(request_path, sizeof(request_path), p->data, "install_bundle_request") &&
        csi_real_path(csi_empty_replacement_path, sizeof(csi_empty_replacement_path), p->root, "replacement-request") &&
        boot_install_bound_bundle_read(p->data, original) == BOOT_BOUND_READ_READY &&
        boot_install_bound_bundle_test_rewrite(p->data, original->attempts + 1) &&
        csi_real_copy(request_path, csi_empty_replacement_path) &&
        boot_install_bound_bundle_test_rewrite(p->data, original->attempts);
}
static bool csi_empty_retire_replaced(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *binding, const uint8_t before[32])
{
    struct boot_bound_bundle_observation original = {0};
    if (!csi_empty_replacement_prepare(p, &original)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(81);
        csi_empty_retire_boot(p, binding, before, &original);
    }
    int status = 0;
    bool ok = child > 0 && csi_real_wait_child(child, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!ok) fprintf(stderr, "fixture diagnostic: replacement child status=%d exit=%d signal=%d\n",
                     status, WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                     WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return ok && boot_install_bound_bundle_test_rewrite(p->data, original.attempts);
}

/* Copies only quiescent mutable state and retained bundle, never the history archive. */
static bool csi_retained_copy_file(const char *src, const char *dst, const char *name, bool required)
{
    char from[PATH_MAX], to[PATH_MAX]; struct stat before, after;
    if (!csi_real_path(from, sizeof(from), src, name) || !csi_real_path(to, sizeof(to), dst, name)) return false;
    if (lstat(from, &before)) return !required && errno == ENOENT;
    if (!S_ISREG(before.st_mode) || before.st_uid != geteuid() || !csi_real_copy(from, to) ||
        lstat(from, &after)) return false;
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
        before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
}
static bool csi_retained_bundle_source(const char *src, const char *dst, const char *name,
                                       const char *from, mode_t *mode)
{
    struct stat original, after;
    if (lstat(from, &original) || !S_ISREG(original.st_mode) || original.st_uid != geteuid()) return false;
    *mode = original.st_mode & 07777;
    return (*mode == 0400 || *mode == 0600) && csi_retained_copy_file(src, dst, name, true) &&
        !lstat(from, &after) && S_ISREG(after.st_mode) && original.st_dev == after.st_dev &&
        original.st_ino == after.st_ino && (after.st_mode & 07777) == *mode;
}
static bool csi_retained_bundle_target(int fd, const char *to, mode_t mode)
{
    struct stat opened, named;
    return fchmod(fd, mode) == 0 && fsync(fd) == 0 && fstat(fd, &opened) == 0 &&
        S_ISREG(opened.st_mode) && opened.st_uid == geteuid() && opened.st_nlink == 1 &&
        (opened.st_mode & 07777) == mode && lstat(to, &named) == 0 && S_ISREG(named.st_mode) &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}
static bool csi_retained_bundle_copy(const char *src, const char *dst, const char *name)
{
    char from[PATH_MAX], to[PATH_MAX]; mode_t mode;
    if (!csi_real_path(from, sizeof(from), src, name) || !csi_real_path(to, sizeof(to), dst, name) ||
        !csi_retained_bundle_source(src, dst, name, from, &mode)) return false;
    int fd = open(to, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = csi_retained_bundle_target(fd, to, mode);
    if (close(fd)) ok = false;
    int dir = open(dst, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return false;
    if (fsync(dir)) ok = false;
    if (close(dir)) ok = false;
    return ok;
}
static bool csi_retained_copy_bundle(const char *src, const char *dst)
{
    char from[PATH_MAX], to[PATH_MAX];
    if (!csi_real_path(from, sizeof(from), src, "bundles") ||
        !csi_real_path(to, sizeof(to), dst, "bundles") || mkdir(to, 0700)) return false;
    DIR *dir = opendir(from); if (!dir) return false;
    bool ok = true; unsigned count = 0; struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++count != 1 || !csi_retained_bundle_copy(from, to, entry->d_name)) { ok = false; break; }
    }
    return closedir(dir) == 0 && ok && count == 1;
}
static bool csi_retained_sidecars_valid(bool has_wal, const struct stat *w,
                                         bool has_shm, const struct stat *s)
{
    return !(has_wal && (!S_ISREG(w->st_mode) || w->st_uid != geteuid())) &&
        !(has_shm && (!S_ISREG(s->st_mode) || s->st_uid != geteuid())) &&
        !(has_shm && !has_wal) && !(has_wal && w->st_size > 0 && !has_shm);
}
static bool csi_retained_copy_sidecars(const char *src, const char *dst, const char *name)
{
    char wal[128], shm[128], walpath[PATH_MAX], shmpath[PATH_MAX]; struct stat w, s;
    int a = snprintf(wal, sizeof(wal), "%s-wal", name), b = snprintf(shm, sizeof(shm), "%s-shm", name);
    if (a < 0 || (size_t)a >= sizeof(wal) || b < 0 || (size_t)b >= sizeof(shm) ||
        !csi_real_path(walpath, sizeof(walpath), src, wal) ||
        !csi_real_path(shmpath, sizeof(shmpath), src, shm)) return false;
    bool has_wal = lstat(walpath, &w) == 0;
    if (!has_wal && errno != ENOENT) return false;
    bool has_shm = lstat(shmpath, &s) == 0;
    if (!has_shm && errno != ENOENT) return false;
    if (!csi_retained_sidecars_valid(has_wal, &w, has_shm, &s)) {
        fprintf(stderr, "retained probe: inconsistent WAL sidecars for %s\n", name);
        return false;
    }
    return (!has_wal || csi_retained_copy_file(src, dst, wal, true)) &&
        (!has_shm || csi_retained_copy_file(src, dst, shm, true));
}
#include "consensus_state_derived_projection_test.h"
/* The completed source has a real saved flat, including its retained anchor. */
static bool csi_retained_completed_flat(const char *src, const char *dst)
{
    static const uint8_t expected[32] = {
        0xb2,0x00,0xc8,0x06,0xa1,0x5e,0xe4,0x89,0xad,0xf2,0xd8,0x43,0xa5,0x74,0xc5,0xaf,
        0xb1,0x72,0x29,0x65,0xb3,0xfe,0x70,0x78,0x67,0x9e,0x76,0xfe,0x0b,0xbf,0xe8,0x6e};
    char from[PATH_MAX], to[PATH_MAX];
    return csi_real_path(from, sizeof(from), src, "block_index.bin") &&
        csi_real_path(to, sizeof(to), dst, "block_index.bin") &&
        csi_derived_hash(from, expected) && csi_retained_copy_file(src, dst, "block_index.bin", true) &&
        csi_derived_hash(to, expected) && csi_derived_hash(from, expected);
}
static bool csi_completed_index_paths(const char *src, const char *dst,
    char source_index[PATH_MAX], char target_index[PATH_MAX])
{
    char source_blocks[PATH_MAX], target_blocks[PATH_MAX]; struct stat st;
    return csi_real_path(source_blocks, sizeof(source_blocks), src, "blocks") &&
        !lstat(source_blocks, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        csi_real_path(source_index, PATH_MAX, source_blocks, "index") &&
        !lstat(source_index, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        csi_real_path(target_blocks, sizeof(target_blocks), dst, "blocks") && !mkdir(target_blocks, 0700) &&
        csi_real_path(target_index, PATH_MAX, target_blocks, "index") && !mkdir(target_index, 0700);
}
static bool csi_completed_index_unchanged(DIR *dir, const char *source, const struct stat *before)
{
    struct stat after, named;
    return !fstat(dirfd(dir), &after) && !lstat(source, &named) && S_ISDIR(named.st_mode) &&
        before->st_dev == after.st_dev && before->st_ino == after.st_ino &&
        before->st_dev == named.st_dev && before->st_ino == named.st_ino &&
        before->st_mtim.tv_sec == after.st_mtim.tv_sec && before->st_mtim.tv_nsec == after.st_mtim.tv_nsec;
}
static bool csi_completed_index_entries(DIR *dir, const char *source, const char *target,
                                         bool *current, bool *manifest)
{
    bool ok = true; struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) ok = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!strcmp(entry->d_name, "CURRENT")) *current = true;
        if (!strncmp(entry->d_name, "MANIFEST-", 9)) *manifest = true;
        if (!csi_retained_copy_file(source, target, entry->d_name, true)) { ok = false; break; }
    }
    return ok;
}
/* Copy the retained public LevelDB index only while the source datadir lock is held. */
static bool csi_completed_copy_index(const char *src, const char *dst)
{
    char source_index[PATH_MAX], target_index[PATH_MAX];
    if (!csi_completed_index_paths(src, dst, source_index, target_index)) return false;
    int index_fd = open(source_index, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat before;
    if (index_fd < 0) return false;
    if (fstat(index_fd, &before) || !S_ISDIR(before.st_mode) || before.st_uid != geteuid()) { close(index_fd); return false; }
    DIR *dir = fdopendir(index_fd);
    if (!dir) { close(index_fd); return false; }
    bool current = false, manifest = false;
    bool ok = csi_completed_index_entries(dir, source_index, target_index, &current, &manifest);
    if (!csi_completed_index_unchanged(dir, source_index, &before)) ok = false;
    if (closedir(dir)) ok = false;
    return ok && current && manifest;
}
static bool csi_completed_copy_inputs(const char *src, const char *dst)
{
    return csi_retained_completed_flat(src, dst) &&
        csi_retained_copy_file(src, dst, "anchors.dat", true) &&
        csi_retained_copy_file(src, dst, "anchors.dat.sha3", true) &&
        csi_retained_copy_file(src, dst, "progress.kv", true) &&
        csi_retained_copy_sidecars(src, dst, "progress.kv") &&
        csi_completed_copy_index(src, dst);
}
static bool csi_pending_input_presence(const char *src, const char *const files[4], bool present[4])
{
    struct stat st; char path[PATH_MAX];
    for (size_t i = 0; i < 4; ++i) {
        if (!csi_real_path(path, sizeof(path), src, files[i])) return false;
        present[i] = lstat(path, &st) == 0;
        if (!present[i] && errno != ENOENT) return false;
        if (present[i] && (!S_ISREG(st.st_mode) || st.st_uid != geteuid())) return false;
    }
    return present[1] == present[2];
}
static bool csi_pending_absent(const char *src, const char *name)
{
    struct stat st; char path[PATH_MAX];
    return csi_real_path(path, sizeof(path), src, name) && lstat(path, &st) != 0 && errno == ENOENT;
}
static bool csi_pending_copy_inputs(const char *src, const char *dst)
{
    const char *files[] = {"block_index.bin", "anchors.dat", "anchors.dat.sha3", "progress.kv"};
    bool present[4] = {0};
    if (!csi_pending_input_presence(src, files, present)) return false;
    for (size_t i = 0; i < 4; ++i)
        if (present[i] && !csi_retained_copy_file(src, dst, files[i], true)) return false;
    if (!present[3]) {
        const char *sidecars[] = {"progress.kv-wal", "progress.kv-shm"};
        for (size_t i = 0; i < 2; ++i)
            if (!csi_pending_absent(src, sidecars[i]))
                return false;
    }
    if (!csi_retained_copy_sidecars(src, dst, "progress.kv") || !csi_completed_copy_index(src, dst)) return false;
    for (size_t i = 0; i < 4; ++i) {
        if (present[i]) continue;
        if (!csi_pending_absent(src, files[i]))
            return false;
    }
    return true;
}

static bool csi_retained_absent_path(const char *src, const char *name, char path[PATH_MAX])
{
    struct stat st;
    return csi_real_path(path, PATH_MAX, src, name) && lstat(path, &st) != 0 && errno == ENOENT;
}
static bool csi_retained_copy_markers(const char *src, const char *dst, bool request_required,
    bool marker_required, bool copy_inputs, char request_path[PATH_MAX], char marker_path[PATH_MAX])
{
    bool ok = true;
    if (marker_required) ok = csi_retained_copy_file(src, dst, "consensus-bundle-installed.marker", true);
    if (ok && !marker_required) ok = csi_retained_absent_path(src, "consensus-bundle-installed.marker", marker_path);
    if (ok && !request_required) ok = csi_retained_absent_path(src, "install_bundle_request", request_path);
    if (ok && request_required) ok = csi_retained_copy_file(src, dst, "install_bundle_request", true);
    if (ok && !request_required) ok = csi_completed_copy_inputs(src, dst);
    if (ok && request_required && copy_inputs) ok = csi_pending_copy_inputs(src, dst);
    return ok;
}
static bool csi_retained_copy_projection(const char *src, const char *dst, bool derived)
{
    const char *projection[] = {"block_index_projection.db", "event_log.dat"};
    const char *optional[] = {"install-verify-receipt.v1", "shutdown-receipt.v1"};
    const char *families[] = {"node.db", "consensus.db"};
    bool ok = true;
    for (size_t i = 0; ok && !derived && i < sizeof(projection)/sizeof(projection[0]); ++i)
        ok = csi_retained_copy_file(src, dst, projection[i], true);
    for (size_t i = 0; ok && !derived && i < sizeof(optional)/sizeof(optional[0]); ++i)
        ok = csi_retained_copy_file(src, dst, optional[i], false);
    for (size_t i = 0; ok && i < sizeof(families)/sizeof(families[0]); ++i)
        ok = csi_retained_copy_sidecars(src, dst, families[i]);
    if (ok && !derived) ok = csi_retained_copy_sidecars(src, dst, "block_index_projection.db");
    if (ok) ok = csi_retained_copy_bundle(src, dst);
    return ok;
}
static int csi_retained_lock(const char *src)
{
    char pidpath[PATH_MAX]; struct stat st;
    if (!csi_real_path(pidpath, sizeof(pidpath), src, "zclassic23.pid")) return -1;
    int lock = open(pidpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (lock < 0 || fstat(lock, &st) || !S_ISREG(st.st_mode) || flock(lock, LOCK_EX | LOCK_NB)) {
        if (lock >= 0) close(lock);
        return -1;
    }
    return lock;
}
static bool csi_retained_copy_state(const char *src, const char *dst,
                                    bool request_required, bool marker_required, bool copy_inputs)
{
    const char *required[] = {"node.db", "consensus.db",
        "consensus_state_publication_decision.v1"};
    bool derived = getenv("ZCL_TEST_DERIVE_PUBLIC_PROJECTION") != NULL;
    struct stat st;
    int lock = csi_retained_lock(src);
    if (lock < 0) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(required)/sizeof(required[0]); ++i)
        ok = csi_retained_copy_file(src, dst, required[i], true);
    char request_path[PATH_MAX];
    char marker_path[PATH_MAX];
    if (ok) ok = csi_retained_copy_markers(src, dst, request_required, marker_required,
                                            copy_inputs, request_path, marker_path);
    if (ok) ok = csi_retained_copy_projection(src, dst, derived);
    if (ok && !request_required) ok = lstat(request_path, &st) != 0 && errno == ENOENT;
    if (ok && !marker_required) ok = lstat(marker_path, &st) != 0 && errno == ENOENT;
    if (flock(lock, LOCK_UN)) ok = false;
    if (close(lock)) ok = false;
    return ok;
}
static bool csi_retained_pending_read(const struct csi_real_paths *p,
    struct wallet_cutover_binding *binding, uint8_t identity[32], bool require_pending)
{
    struct node_db node = {0}; struct wallet_sqlite ws = {0};
    if (!node_db_open(&node, p->node)) {
        fprintf(stderr, "retained probe: node database open refused\n");
        return false;
    }
    struct zcl_result opened = wallet_sqlite_open_r(&ws, node.db);
    enum wallet_cutover_observation_status observed = WALLET_CUTOVER_OBS_IO_ERROR;
    enum wallet_cutover_status pending = WALLET_CUTOVER_IO_ERROR;
    struct wallet_cutover_binding candidate = {0};
    if (opened.ok) {
        observed = wallet_sqlite_cutover_observe_completed(&ws, &candidate);
        if (observed == WALLET_CUTOVER_OBS_PENDING)
            pending = wallet_sqlite_cutover_read(&ws, &candidate);
    }
    bool present = (observed == WALLET_CUTOVER_OBS_PENDING && pending == WALLET_CUTOVER_PENDING) ||
        (!require_pending && observed == WALLET_CUTOVER_OBS_FOUND);
    bool identity_ok = opened.ok && csi_empty_wallet_identity(node.db, identity);
    bool ok = present && candidate.history_identity_present && identity_ok;
    fprintf(stderr, "retained probe: wallet_open=%d observation=%d pending_read=%d bound=%d identity=%d\n",
        opened.ok, (int)observed, (int)pending, present && candidate.history_identity_present, identity_ok);
    if (ok) *binding = candidate;
    if (opened.ok) wallet_sqlite_close(&ws);
    node_db_close(&node);
    return ok;
}
static bool csi_retained_resolved_roots(const char *source, const char *scratch, char scratch_real[PATH_MAX])
{
    char resolved[PATH_MAX]; struct stat st;
    return source && source[0] == '/' && scratch && scratch[0] == '/' &&
        realpath(source, resolved) && !strcmp(source, resolved) &&
        realpath(scratch, scratch_real) && !strcmp(scratch, scratch_real) &&
        !lstat(source, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077);
}
static bool csi_retained_suffix_valid(const char *suffix)
{
    if (strlen(suffix) != 6) return false;
    for (const char *c = suffix; *c; ++c)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
              (*c >= '0' && *c <= '9'))) return false;
    return true;
}
static bool csi_retained_source_valid(const char *source, const char *scratch)
{
    static const char prefix[] = "real-empty-retire-";
    char parent[PATH_MAX], scratch_real[PATH_MAX], data[PATH_MAX];
    struct stat st;
    if (!csi_retained_resolved_roots(source, scratch, scratch_real)) return false;
    int n = snprintf(parent, sizeof(parent), "%s", source);
    if (n < 0 || (size_t)n >= sizeof(parent)) return false;
    char *leaf = strrchr(parent, '/');
    if (!leaf || leaf == parent || strncmp(leaf + 1, prefix, sizeof(prefix) - 1)) return false;
    const char *suffix = leaf + sizeof(prefix);
    if (!csi_retained_suffix_valid(suffix)) return false;
    *leaf = '\0';
    if (strcmp(parent, scratch_real) || !csi_real_path(data, sizeof(data), source, "data") ||
        lstat(data, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)) return false;
    return true;
}
static bool csi_populated_retained_request(const char *src,
    const struct boot_bound_bundle_observation *request, const struct wallet_cutover_binding *binding)
{
    struct wallet_history_names names; char history[PATH_MAX];
    return binding->history_identity_present &&
        request->endpoint_height == binding->target_height &&
        !memcmp(request->endpoint_hash, binding->target_hash, 32) &&
        !memcmp(request->snapshot_sha3, binding->snapshot_whole_sha3, 32) &&
        !memcmp(request->history_manifest_root, binding->history_manifest_root, 32) &&
        wallet_history_capability_names(request->snapshot_sha3, request->history_manifest_root, &names).ok &&
        csi_real_path(history, sizeof(history), src, names.root) &&
        !strcmp(history, request->private_history_path);
}

static bool csi_retained_prepare_copy(const char *source, const char *scratch,
    struct csi_real_paths *p, char src[PATH_MAX], const char *pattern,
    bool request_required, bool marker_required, bool copy_inputs)
{
    return csi_real_path(src, PATH_MAX, source, "data") &&
        csi_real_path(p->root, sizeof(p->root), scratch, pattern) && mkdtemp(p->root) &&
        csi_real_path(p->data, sizeof(p->data), p->root, "data") && !mkdir(p->data, 0700) &&
        csi_real_path(p->node, sizeof(p->node), p->data, "node.db") &&
        csi_retained_copy_state(src, p->data, request_required, marker_required, copy_inputs);
}
static bool csi_retained_probe_source(const char *source, const char *scratch,
                                       const char *params, const char *expected_leaf)
{
    const char *leaf = source ? strrchr(source, '/') : NULL;
    return params && !getenv("ZCL_TEST_DERIVE_PUBLIC_PROJECTION") && leaf &&
        !strcmp(leaf + 1, expected_leaf) && csi_retained_source_valid(source, scratch) &&
        csi_empty_private_dir(scratch);
}
static int csi_populated_retained_probe(const char *source)
{
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH");
    const char *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    struct csi_real_paths p = {.params = params}; char src[PATH_MAX];
    if (!csi_retained_probe_source(source, scratch, params, "real-empty-retire-AZZyzI") ||
        !csi_retained_prepare_copy(source, scratch, &p, src, "retained-populated-probe-XXXXXX", true, true, true)) {
        fprintf(stderr, "retained populated probe: copy refused\n"); return 1;
    }
    struct boot_bound_bundle_observation request = {0}, after = {0};
    struct wallet_cutover_binding binding = {0}; uint8_t identity[32];
    bool ok = boot_install_bound_bundle_read(p.data, &request) == BOOT_BOUND_READ_READY &&
        csi_retained_pending_read(&p, &binding, identity, true) &&
        csi_populated_retained_request(src, &request, &binding) &&
        boot_install_bound_bundle_read(p.data, &after) == BOOT_BOUND_READ_READY &&
        csi_empty_observation_equal(&request, &after);
    fprintf(stderr, "retained populated probe: pending=%d copy=%s\n", ok, p.root);
    if (ok) {
        int n = snprintf(p.history, sizeof(p.history), "%s", request.private_history_path);
        ok = n >= 0 && (size_t)n < sizeof(p.history) &&
            csi_empty_retire_restart(&p, &binding, identity) && csi_populated_history_check(&p, &binding);
    }
    fprintf(stderr, "retained populated probe: restart=%s copy=%s\n", ok ? "PASS" : "FAIL", p.root);
    return ok ? 0 : 1;
}

static bool csi_retained_inputs_present(const char *source, const char *scratch, const char *params)
{
    return source && scratch && params;
}
static int csi_empty_retained_probe(const char *source)
{
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH");
    const char *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    struct csi_real_paths p = {.params = params}; char src[PATH_MAX];
    if (!csi_retained_inputs_present(source, scratch, params) || !csi_empty_private_dir(scratch) ||
        !csi_retained_source_valid(source, scratch) ||
        !csi_retained_prepare_copy(source, scratch, &p, src, "retained-probe-XXXXXX", true, true, false)) {
        fprintf(stderr, "retained probe: copy refused\n"); return 1;
    }
    struct wallet_cutover_binding binding; uint8_t identity[32];
    bool derived = getenv("ZCL_TEST_DERIVE_PUBLIC_PROJECTION") != NULL;
    bool ok = (!derived || csi_derived_projection(p.root, p.data)) &&
        csi_retained_pending_read(&p, &binding, identity, false);
    fprintf(stderr, "retained probe: binding_valid=%d copy=%s\n", ok, p.root);
    if (ok) ok = csi_empty_retire_replaced(&p, &binding, identity);
    fprintf(stderr, "retained probe: replacement startup=%s copy=%s\n", ok ? "PASS" : "FAIL", p.root);
    if (ok) ok = csi_empty_retire_restart(&p, &binding, identity);
    fprintf(stderr, "retained probe: completion startup=%s copy=%s\n", ok ? "PASS" : "FAIL", p.root);
    if (ok) ok = csi_empty_retire_restart(&p, &binding, identity);
    fprintf(stderr, "retained probe: request-absent startup=%s copy=%s\n", ok ? "PASS" : "FAIL", p.root);
    return ok ? 0 : 1;
}

struct csi_completed_mutation {
    const struct wallet_cutover_binding *expected;
    int mode;
    bool reached, positive, changed;
};
static void csi_completed_mutation_hook(struct boot_cutover_env *env, struct app_context *ctx, void *opaque)
{
    struct csi_completed_mutation *m = opaque; m->reached = true;
    int fd = open(ctx->datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool present = false; uint64_t generation = 0;
    m->positive = fd >= 0 && boot_bound_completed_prove(env->wallet_db, env->node, env->wallet,
        env->state, ctx->datadir, fd, &present, &generation) == BOOT_BOUND_COMPLETION_PROVEN;
    if (fd >= 0 && close(fd)) m->positive = false;
    if (!m->positive || wallet_readiness_get(env->wallet).state != WALLET_READINESS_UNKNOWN) return;
    if (m->mode == 1) {
        sqlite3 *db = progress_store_db();
        progress_store_tx_lock();
        bool began = db && sqlite3_get_autocommit(db) && sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
        m->changed = began && coins_kv_bump_authority_generation_in_tx(db) &&
            sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        if (began && !sqlite3_get_autocommit(db)) (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
    } else {
        m->changed = wallet_sqlite_write_scan_height(env->wallet_db, 0);
    }
}
static bool csi_completed_mutation_result(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *expected, const struct csi_completed_mutation *mutation,
    bool started, int fd, enum boot_bound_completion_result proof, bool present,
    uint64_t generation, struct wallet *wallet, struct wallet_sqlite *ws)
{
    struct wallet_cutover_binding after = {0}; struct boot_bound_bundle_observation request = {0};
    return !started && mutation->reached && mutation->positive && mutation->changed && fd >= 0 &&
        boot_stage_is(BOOT_STAGE_CHAIN_TIP_RESOLVED) && proof == BOOT_BOUND_COMPLETION_ERROR &&
        !present && generation == 0 && wallet_readiness_get(wallet).state == WALLET_READINESS_UNKNOWN &&
        wallet_sqlite_cutover_observe_completed(ws, &after) == WALLET_CUTOVER_OBS_FOUND &&
        wallet_cutover_binding_equal(expected, &after) &&
        boot_install_bound_bundle_read(p->data, &request) == BOOT_BOUND_READ_ABSENT;
}
static void csi_completed_mutation_boot(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *expected, int mode)
{
    char datadir[PATH_MAX + 32], params[PATH_MAX + 32];
    int a = snprintf(datadir, sizeof(datadir), "-datadir=%s", p->data);
    int b = snprintf(params, sizeof(params), "-paramsdir=%s", p->params);
    if (!csi_empty_boot_args_ok(a, sizeof(datadir), b, sizeof(params))) _exit(101);
    char *argv[] = {"z23", datadir, params, "-operator-lane=unknown", "-nolegacyimport", "-nolegacyutxoimport",
        "-no-tor", "-private-listeners", "-observation=0", "-connect=127.0.0.1:1",
        "-port=28033", "-rpcport=28232", "-httpsport=28443", "-fsport=28034"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0])); struct app_context ctx;
    app_context_defaults(&ctx); ctx.datadir = p->data; ctx.params_dir = p->params;
    ParseParameters(argc, (const char *const *)argv); bool metrics = false;
    if (!csi_empty_boot_options(argc, argv, &ctx, &metrics)) _exit(102);
    struct csi_completed_mutation mutation = {.expected = expected, .mode = mode};
    boot_test_completed_before_proof(csi_completed_mutation_hook, &mutation);
    boot_stage_reset_for_testing(); ecc_verify_destroy(); ecc_stop();
    bool started = app_init(&ctx);
    boot_test_completed_before_proof(NULL, NULL);
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    int fd = open(p->data, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool present = true; uint64_t generation = UINT64_MAX;
    enum boot_bound_completion_result proof = fd < 0 ? BOOT_BOUND_COMPLETION_ERROR :
        boot_bound_completed_prove(ws, node, wallet, main, p->data, fd, &present, &generation);
    bool ok = csi_completed_mutation_result(p, expected, &mutation, started, fd, proof,
                                             present, generation, wallet, ws);
    if (fd >= 0 && close(fd)) ok = false;
    fprintf(stderr, "completed mutation mode=%d reached=%d positive=%d changed=%d proof=%d ready=%d\n",
        mode, mutation.reached, mutation.positive, mutation.changed, (int)proof,
        (int)wallet_readiness_get(wallet).state);
    _exit(ok ? 0 : 103);
}
static bool csi_completed_source_valid(const char *source, const char *scratch)
{
    char parent[PATH_MAX], scratch_real[PATH_MAX], data[PATH_MAX]; struct stat st;
    if (!csi_retained_resolved_roots(source, scratch, scratch_real)) return false;
    int n = snprintf(parent, sizeof(parent), "%s", source);
    if (n < 0 || (size_t)n >= sizeof(parent)) return false;
    char *leaf = strrchr(parent, '/');
    if (!leaf || leaf == parent || strcmp(leaf + 1, "retained-probe-fQ3Q9s")) return false;
    *leaf = '\0';
    return !strcmp(parent, scratch_real) && csi_real_path(data, sizeof(data), source, "data") &&
        !lstat(data, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077);
}
static bool csi_completed_read_witness(const struct csi_real_paths *p, struct csi_real_bound_witness *value)
{
    struct node_db node = {0}; struct wallet_sqlite ws = {0};
    bool node_open = node_db_open(&node, p->node);
    bool wallet_open = node_open && wallet_sqlite_open_r(&ws, node.db).ok;
    bool ok = wallet_open && wallet_sqlite_cutover_observe_completed(&ws, &value->binding) == WALLET_CUTOVER_OBS_FOUND &&
        value->binding.history_identity_present && csi_empty_wallet_identity(node.db, value->wallet);
    if (wallet_open) wallet_sqlite_close(&ws);
    if (node_open) node_db_close(&node);
    return ok;
}
static bool csi_completed_copy_observe(const struct csi_real_paths *p, struct csi_real_bound_witness *witness)
{
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(105);
        close(fds[0]); alarm(90);
        struct csi_real_bound_witness value = {0};
        bool ok = csi_completed_read_witness(p, &value);
        ok = ok && write(fds[1], &value, sizeof(value)) == (ssize_t)sizeof(value);
        _exit(ok ? 0 : 106);
    }
    close(fds[1]); int status = 0; bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(fds[0], witness, sizeof(*witness)); close(fds[0]);
    return waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof(*witness);
}

static int csi_completed_mutation_run(struct csi_real_paths *p,
    const struct csi_real_bound_witness *before, int mode)
{
    pid_t parent = getpid(), child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, (uint64_t)parent)) _exit(104);
        csi_completed_mutation_boot(p, &before->binding, mode);
    }
    int status = 0; bool waited = child > 0 && csi_real_wait_child(child, &status);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    fprintf(stderr, "completed mutation mode=%d result=%s exit=%d copy=%s\n", mode, ok ? "PASS" : "FAIL",
        WIFEXITED(status) ? WEXITSTATUS(status) : -1, p->root);
    if (ok) (void)test_rm_rf_recursive(p->root);
    return ok ? 0 : 1;
}
static int csi_completed_mutation_case(const char *source, int mode)
{
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH"), *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    struct csi_real_paths p = {.params = params}; char src[PATH_MAX];
    if (!params || getenv("ZCL_TEST_DERIVE_PUBLIC_PROJECTION") || !csi_completed_source_valid(source, scratch) ||
        !csi_empty_private_dir(scratch) ||
        !csi_retained_prepare_copy(source, scratch, &p, src, "completed-negative-XXXXXX", false, true, false)) {
        fprintf(stderr, "completed mutation mode=%d copy refused\n", mode); return 1;
    }
    struct csi_real_bound_witness before = {0};
    if (!csi_completed_copy_observe(&p, &before)) return 1;
    if (mode == 0) {
        bool baseline = csi_empty_retire_restart(&p, &before.binding, before.wallet);
        fprintf(stderr, "completed mutation baseline=%s copy=%s\n", baseline ? "PASS" : "FAIL", p.root);
        if (baseline) (void)test_rm_rf_recursive(p.root);
        return baseline ? 0 : 1;
    }
    return csi_completed_mutation_run(&p, &before, mode);
}
static int csi_completed_mutation_test(const char *source)
{
    int failures = csi_completed_mutation_case(source, 0);
    if (failures) return failures;
    failures += csi_completed_mutation_case(source, 1);
    failures += csi_completed_mutation_case(source, 2);
    return failures;
}

static bool csi_old_request_binding(const struct boot_bound_bundle_observation *request,
                                    const struct wallet_cutover_binding *binding)
{
    return binding->history_identity_present && request->attempts == 1 &&
        request->endpoint_height == binding->target_height &&
        !memcmp(request->endpoint_hash, binding->target_hash, 32) &&
        !memcmp(request->snapshot_sha3, binding->snapshot_whole_sha3, 32) &&
        !memcmp(request->history_manifest_root, binding->history_manifest_root, 32);
}
static void csi_retained_old_observe_child(const struct csi_real_paths *p, int fd)
{
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    if (!boot_datadir_lock_acquire(p->data) || !node_db_open(node, p->node) ||
        !wallet_sqlite_open_r(ws, node->db).ok) _exit(110);
    wallet_init(wallet); boot_stage_reset_for_testing();
    for (int stage = BOOT_STAGE_DATADIR_LOCKED; stage <= BOOT_STAGE_WALLET_LOADED; ++stage)
        boot_stage_advance_to((enum boot_stage)stage);
    struct boot_cutover_env env = {.node = node, .wallet_db = ws, .wallet = wallet, .state = main};
    struct wallet_cutover_binding binding = {0}; enum boot_cutover_preflight_kind kind = BOOT_CUTOVER_NONE;
    struct boot_bound_bundle_observation request = {0};
    struct csi_real_bound_witness witness = {0};
    bool ok = boot_install_bound_bundle_read(p->data, &request) == BOOT_BOUND_READ_READY &&
        !boot_consensus_bundle_marker_exists(p->data) &&
        boot_cutover_preflight_classify(&env, p->data, &kind, &binding) && kind == BOOT_CUTOVER_OLD_RETRY &&
        csi_old_request_binding(&request, &binding) && csi_empty_wallet_identity(node->db, witness.wallet);
    witness.binding = binding; witness.fence = ok;
    if (ok) ok = write(fd, &witness, sizeof(witness)) == (ssize_t)sizeof(witness);
    _exit(ok ? 0 : 111);
}
static bool csi_retained_old_observe(const struct csi_real_paths *p, struct csi_real_bound_witness *witness)
{
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(112);
        close(fds[0]); alarm(90); csi_retained_old_observe_child(p, fds[1]);
    }
    close(fds[1]); int status = 0; bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(fds[0], witness, sizeof(*witness)); close(fds[0]);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof(*witness);
    fprintf(stderr, "retained OLD preflight=%s exit=%d\n", ok ? "PASS" : "FAIL",
        WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return ok;
}
static bool csi_retained_old_restart(const struct csi_real_paths *p, struct csi_real_bound_witness *witness,
    const struct boot_bound_bundle_observation *request)
{
    int fds[2]; if (pipe(fds)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(113);
        close(fds[0]); csi_empty_retire_install_boot(p, fds[1], false, witness, request);
    }
    close(fds[1]); int status = 0; bool waited = child > 0 && csi_real_wait_child(child, &status);
    struct csi_real_bound_witness committed = {0};
    ssize_t n = read(fds[0], &committed, sizeof(committed)); close(fds[0]);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 && n == (ssize_t)sizeof(committed) &&
        committed.fence && committed.committed &&
        wallet_cutover_binding_equal(&witness->binding, &committed.binding) &&
        !memcmp(witness->wallet, committed.wallet, 32);
    fprintf(stderr, "retained OLD retry=%s exit=%d signal=%d\n", ok ? "PASS" : "FAIL",
        WIFEXITED(status) ? WEXITSTATUS(status) : -1, WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return ok;
}
static int csi_retained_old_probe(const char *source)
{
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH"), *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    struct csi_real_paths p = {.params = params}; char src[PATH_MAX];
    if (!csi_retained_probe_source(source, scratch, params, "real-empty-retire-erQrJ9") ||
        !csi_retained_prepare_copy(source, scratch, &p, src, "retained-old-probe-XXXXXX", true, false, false)) {
        fprintf(stderr, "retained OLD probe: copy refused\n"); return 1;
    }
    struct boot_bound_bundle_observation request = {0}, after = {0};
    struct csi_real_bound_witness witness = {0};
    bool ok = boot_install_bound_bundle_read(p.data, &request) == BOOT_BOUND_READ_READY &&
        csi_retained_old_observe(&p, &witness) && csi_old_request_binding(&request, &witness.binding) &&
        boot_install_bound_bundle_read(p.data, &after) == BOOT_BOUND_READ_READY &&
        csi_empty_observation_equal(&request, &after) && csi_retained_old_restart(&p, &witness, &request);
    fprintf(stderr, "retained OLD probe=%s copy=%s\n", ok ? "PASS" : "FAIL", p.root);
    return ok ? 0 : 1;
}

static bool csi_empty_retire_prepare(struct csi_real_paths *p, const char *scratch)
{
    return p->bundle && p->source && scratch && p->params && csi_empty_private_dir(scratch) &&
        csi_real_path(p->root, sizeof(p->root), scratch, "real-empty-retire-XXXXXX") && mkdtemp(p->root);
}
static bool csi_empty_retire_exercise(struct csi_real_paths *p, uint8_t before[32],
    struct boot_bound_bundle_request *request, struct csi_real_bound_witness *witness, bool old_retry)
{
    return mkdir(p->data, 0700) == 0 &&
        csi_empty_retire_copy_chain(getenv("ZCL_TEST_COLD_PUBLIC_DIR"), p->data) &&
        csi_derived_projection(p->root, p->data) &&
        csi_empty_retire_seed_child(p, before) && csi_real_history(p) && csi_real_bound_history(p, request) &&
        boot_install_bound_bundle_request(p->data, request, NULL) == BOOT_BUNDLE_ARM_CREATED &&
        (old_retry ? csi_empty_old_retry(p, witness) : csi_empty_retire_install(p, witness));
}
static bool csi_empty_retire_finish(struct csi_real_paths *p, const uint8_t before[32],
                                     const struct csi_real_bound_witness *witness)
{
    return witness->fence && witness->committed &&
        !memcmp(before, witness->wallet, 32) && csi_empty_retire_replaced(p, &witness->binding, before) &&
        csi_empty_retire_restart(p, &witness->binding, before) &&
        csi_empty_retire_restart(p, &witness->binding, before) &&
        (!csi_populated_mode() || csi_populated_history_check(p, &witness->binding));
}
static bool csi_empty_projection_ready(void)
{
    const char *derive = getenv("ZCL_TEST_DERIVE_PUBLIC_PROJECTION");
    return derive && !strcmp(derive, "1") && getenv("ZCL_TEST_PUBLIC_PROJECTION") &&
        getenv("ZCL_TEST_PUBLIC_FLAT");
}
static int csi_real_empty_retire_test(void)
{
    const char *old_mode = getenv("ZCL_TEST_REAL_OLD_RETRY");
    bool old_retry = old_mode && !strcmp(old_mode, "1");
    if (!old_retry && !getenv("ZCL_TEST_REAL_EMPTY_RETIRE") && !csi_populated_mode()) return 0;
    if (!csi_empty_projection_ready()) {
        fprintf(stderr, "real empty retirement: derived public projection inputs required\n");
        return 1;
    }
    const char *bundle = getenv("ZCL_TEST_REAL_INSTALL_BUNDLE"), *history = getenv("ZCL_TEST_REAL_INSTALL_HISTORY");
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH"), *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    int failures = 0; struct csi_real_paths p = {.bundle = bundle, .source = history, .params = params};
    bool made = csi_empty_retire_prepare(&p, scratch);
    bool ok = made && csi_real_bound_paths(&p);
    p.bundle = p.artifact;
    uint8_t before[32]; struct boot_bound_bundle_request request = {0}; struct csi_real_bound_witness witness = {0};
    ok = ok && csi_empty_retire_exercise(&p, before, &request, &witness, old_retry) &&
        csi_empty_retire_finish(&p, before, &witness);
    CSI_CHECK(old_retry ? "real OLD fence crash retries and completes" :
        csi_populated_mode() ? "real populated bound wallet completes and retires request" :
        "real empty bound wallet completes and retires request", ok);
    if (made && ok) (void)test_rm_rf_recursive(p.root);
    else if (made) fprintf(stderr, "real empty retirement: fixture retained at %s\n", p.root);
    return failures;
}
#endif
