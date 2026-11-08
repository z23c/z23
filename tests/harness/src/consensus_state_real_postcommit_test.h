/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Opt-in real checkpoint installation interruption and recovery fixture. */
#ifndef ZCL_CONSENSUS_STATE_REAL_POSTCOMMIT_TEST_H
#define ZCL_CONSENSUS_STATE_REAL_POSTCOMMIT_TEST_H
#include "config/args.h"
#include "config/boot_error.h"
#include "config/boot_wallet_cutover_replay.h"
#include "crypto/sha256.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/file_clone.h"
#include "util/util.h"
#include "util/safe_alloc.h"
#include "support/cleanse.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include <time.h>

struct csi_real_paths {
    char root[PATH_MAX], data[PATH_MAX], history[PATH_MAX], node[PATH_MAX], artifact[PATH_MAX];
    const char *bundle, *source, *params;
};

struct csi_real_probe {
    uint8_t wallet[32];
    enum wallet_discover_checkpoint_status checkpoint_status;
    struct wallet_discover_checkpoint checkpoint;
};
void boot_test_pending_detail_hook(void (*hook)(enum boot_cutover_replay_phase, enum boot_cutover_replay_status));

static bool csi_real_sapling_seed(struct wallet_sqlite *ws)
{
    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet), "real stop synthetic wallet");
    if (!wallet) return false;
    wallet_init(wallet);
    uint8_t seed[32] = {1}, diversifier[ZC_DIVERSIFIER_SIZE], pk_d[32];
    bool ok = sapling_keystore_set_seed(&wallet->sapling_keys, seed) &&
        sapling_keystore_new_address(&wallet->sapling_keys, diversifier, pk_d) &&
        wallet_sqlite_write_sapling_seed(ws, seed) &&
        wallet_sqlite_write_sapling_key(ws, 0, &wallet->sapling_keys.keys[0]);
    memory_cleanse(seed, sizeof(seed));
    wallet_free(wallet);
    free(wallet);
    return ok;
}

static bool csi_real_path(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool csi_real_copy_stream(int in, int out)
{
    char bytes[65536];
    for (;;) {
        ssize_t n = read(in, bytes, sizeof(bytes));
        if (n == 0) return true;
        if (n < 0) { if (errno == EINTR) continue; return false; }
        for (ssize_t off = 0; off < n;) {
            ssize_t wrote = write(out, bytes + off, (size_t)(n - off));
            if (wrote < 0 && errno == EINTR) continue;
            if (wrote <= 0) return false;
            off += wrote;
        }
    }
}

static bool csi_real_copy(const char *source, const char *destination)
{
    int in = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) return false;
    int out = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0) { close(in); return false; }
    enum platform_file_clone_result clone = platform_file_clone_fd(in, out);
    bool ok = clone == PLATFORM_FILE_CLONE_CLONED ||
        (clone == PLATFORM_FILE_CLONE_UNAVAILABLE && csi_real_copy_stream(in, out));
    if (close(out) != 0) ok = false;
    if (close(in) != 0) ok = false;
    return ok;
}

static bool csi_real_history(struct csi_real_paths *p)
{
    char src[PATH_MAX], dst[PATH_MAX], src_blocks[PATH_MAX], dst_blocks[PATH_MAX];
    if (mkdir(p->history, 0700) ||
        !csi_real_path(src, sizeof(src), p->source, "block_index.bin") ||
        !csi_real_path(dst, sizeof(dst), p->history, "block_index.bin") ||
        !csi_real_copy(src, dst) ||
        !csi_real_path(src_blocks, sizeof(src_blocks), p->source, "blocks") ||
        !csi_real_path(dst_blocks, sizeof(dst_blocks), p->history, "blocks") ||
        mkdir(dst_blocks, 0700)) return false;
    for (unsigned i = 0; i < 52; ++i) {
        char name[32];
        int n = snprintf(name, sizeof(name), "blk%05u.dat", i);
        if (n < 0 || (size_t)n >= sizeof(name) ||
            !csi_real_path(src, sizeof(src), src_blocks, name) ||
            !csi_real_path(dst, sizeof(dst), dst_blocks, name) ||
            !csi_real_copy(src, dst)) return false;
        if ((i + 1) % 8 == 0) fprintf(stderr, "real install: copied %u history files\n", i + 1);
    }
    return true;
}

static bool csi_real_seed_wallet(const struct csi_real_paths *p)
{
    wallet_lock_reset_for_test();
    struct node_db db = {0};
    struct wallet_sqlite ws = {0};
    if (!node_db_open(&db, p->node)) return false;
    bool opened = wallet_sqlite_open_r(&ws, db.db).ok;
    bool ok = opened && wallet_sqlite_write_scan_height(&ws, -1) && csi_real_sapling_seed(&ws) &&
        sqlite3_exec(db.db, "INSERT INTO wallet_watch_only(address_hash,address,created_at) "
                     "VALUES(zeroblob(20),'fixture',1)", NULL, NULL, NULL) == SQLITE_OK;
    if (opened) wallet_sqlite_close(&ws);
    node_db_close(&db);
    return ok;
}

static void csi_real_boot(const struct csi_real_paths *p, bool install, int signal_fd)
{
    char datadir[PATH_MAX + 32], params[PATH_MAX + 32], verb[PATH_MAX + 64];
    char missing[PATH_MAX];
    if (!csi_real_path(missing, sizeof(missing), p->root, "absent-bundle")) _exit(30);
    int a = snprintf(datadir, sizeof(datadir), "-datadir=%s", p->data);
    int b = snprintf(params, sizeof(params), "-paramsdir=%s", p->params);
    int c = snprintf(verb, sizeof(verb), install ? "-install-consensus-bundle=%s" :
                     "-verify-consensus-bundle=%s", install ? p->bundle : missing);
    if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof(datadir) ||
        (size_t)b >= sizeof(params) || (size_t)c >= sizeof(verb)) _exit(30);
    char *argv[] = {"z23", datadir, params, verb, "-operator-lane=dev",
        "-nolegacyimport", "-nolegacyutxoimport", "-no-tor", "-private-listeners",
        "-observation=0", "-connect=127.0.0.1:1", "-port=28033",
        "-rpcport=28232", "-httpsport=28443", "-fsport=28034"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));
    struct app_context ctx;
    app_context_defaults(&ctx);
    ctx.datadir = p->data;
    ctx.params_dir = p->params;
    ParseParameters(argc, (const char *const *)argv);
    bool metrics = false;
    if (args_parse_node_options(argc, argv, &ctx, &metrics) != -1) _exit(31);
    if (install) {
        struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
        struct wallet *wallet = NULL; struct main_state *main = NULL;
        boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
        static struct csi_commit_hook_context hook;
        hook = (struct csi_commit_hook_context){p->data, node, ws, signal_fd};
        consensus_state_install_test_after_commit(csi_guarded_commit_hook, &hook);
    }
    if (unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL")) _exit(32);
    boot_stage_reset_for_testing();
    /* The forked test runner already owns these process-local contexts. */
    ecc_verify_destroy();
    ecc_stop();
    (void)app_init(&ctx);
    _exit(33);
}

static bool csi_real_wait_child(pid_t child, int *status)
{
    for (int i = 0; i < 600; ++i) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return true;
        if (result < 0 && errno != EINTR) return false;
        if (i > 0 && i % 60 == 0) fprintf(stderr, "real install: awaiting bounded child\n");
        struct timespec delay = {.tv_sec = 1};
        (void)nanosleep(&delay, NULL);
    }
    (void)kill(child, SIGKILL);
    (void)waitpid(child, status, 0);
    return false;
}

static bool csi_real_seed_child(const struct csi_real_paths *p)
{
    uint64_t parent = (uint64_t)getpid();
    pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(39);
        alarm(90);
        _exit(csi_real_seed_wallet(p) ? 0 : 1);
    }
    int status = 0;
    return child > 0 && csi_real_wait_child(child, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool csi_real_bundle_identity(const char *path)
{
    static const uint8_t expected[32] = {
        0x2c, 0xb5, 0xe6, 0x94, 0xd0, 0xc9, 0xb3, 0x36,
        0x93, 0x5f, 0x64, 0x11, 0xaa, 0x0b, 0x0d, 0xae,
        0x08, 0x2b, 0x3e, 0x08, 0xa1, 0xdc, 0x1d, 0x21,
        0x4a, 0x46, 0x4f, 0xd4, 0x3e, 0x52, 0x8a, 0x00
    };
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 519831552;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buffer[65536], digest[32];
    while (ok) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
        sha256_write(&ctx, buffer, (size_t)n);
    }
    if (close(fd) != 0) ok = false;
    sha256_finalize(&ctx, digest);
    return ok && memcmp(digest, expected, sizeof(expected)) == 0;
}

static bool csi_real_bootstrap(const struct csi_real_paths *p)
{
    char log[PATH_MAX];
    if (!csi_real_path(log, sizeof(log), p->root, "bootstrap.log")) return false;
    pid_t child = fork();
    if (child == 0) {
        int fd = open(log, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || dup2(fd, STDERR_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(34);
        close(fd);
        csi_real_boot(p, false, -1);
    }
    int status = 0;
    if (child <= 0 || !csi_real_wait_child(child, &status) ||
        !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_FAILURE) return false;
    FILE *file = fopen(log, "r");
    if (!file) return false;
    char line[512]; bool reached = false;
    while (fgets(line, sizeof(line), file))
        if (strstr(line, "REFUSED: -verify-consensus-bundle:")) reached = true;
    if (fclose(file) != 0) return false;
    return reached;
}

static bool csi_real_kill(const struct csi_real_paths *p, struct csi_cutover_witness *w)
{
    int fd[2];
    if (pipe(fd)) return false;
    pid_t child = fork();
    if (child == 0) { close(fd[0]); csi_real_boot(p, true, fd[1]); }
    close(fd[1]);
    struct pollfd pollfd = {.fd = fd[0], .events = POLLIN};
    bool got = false;
    for (int i = 0; child > 0 && i < 30; ++i) {
        int ready = poll(&pollfd, 1, 60000);
        if (ready > 0) {
            got = read(fd[0], w, sizeof(*w)) == (ssize_t)sizeof(*w);
            break;
        }
        if (ready < 0 && errno != EINTR) break;
        fprintf(stderr, "real install: awaiting durable activation\n");
    }
    close(fd[0]);
    if (child > 0) (void)kill(child, SIGKILL);
    int status = 0;
    bool killed = child > 0 && waitpid(child, &status, 0) == child &&
        WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    return got && killed && w->generation_present && w->binding.target_height == 3309900;
}

static bool csi_real_watch_unchanged(sqlite3 *db)
{
    static const uint8_t zero[20] = {0};
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT address_hash,address,created_at FROM wallet_watch_only", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    bool ok = sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_bytes(stmt, 0) == 20 &&
        sqlite3_column_blob(stmt, 0) && !memcmp(sqlite3_column_blob(stmt, 0), zero, sizeof(zero)) &&
        sqlite3_column_text(stmt, 1) && !strcmp((const char *)sqlite3_column_text(stmt, 1), "fixture") &&
        sqlite3_column_int64(stmt, 2) == 1 && sqlite3_step(stmt) == SQLITE_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && ok;
}

static bool csi_real_recover(const struct csi_real_paths *p, const struct csi_cutover_witness *w,
                             struct csi_real_probe *probe)
{
    chain_params_select(CHAIN_MAIN);
    if (!boot_datadir_lock_acquire(p->data)) return false;
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    if (!node_db_open(node, p->node) || !wallet_sqlite_open_r(ws, node->db).ok) return false;
    wallet_init(wallet);
    boot_stage_reset_for_testing();
    for (int stage = BOOT_STAGE_DATADIR_LOCKED; stage <= BOOT_STAGE_WALLET_LOADED; ++stage)
        boot_stage_advance_to((enum boot_stage)stage);
    bool pending = false;
    bool ok = boot_wallet_cutover_preflight_test(p->data, &pending) && pending &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_PENDING;
    int fd = open(p->data, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool present = false; uint64_t generation = 0; int floor = -1;
    struct wallet_cutover_binding binding;
    if (ok) ok = fd >= 0 && consensus_state_wallet_install_classify(ws, node, fd, &present, &generation) == WALLET_INSTALL_COMMITTED &&
        present == w->generation_present && generation == w->generation &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING &&
        csi_guarded_binding_matches(&binding, &w->binding) && csi_real_watch_unchanged(node->db) &&
        boot_consensus_bundle_marker_exists(p->data) &&
        wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == 0;
    if (ok) {
        probe->checkpoint_status = wallet_sqlite_discover_checkpoint_read(ws, &probe->checkpoint);
        ok = (probe->checkpoint_status == WALLET_DISCOVER_ABSENT ||
              probe->checkpoint_status == WALLET_DISCOVER_FOUND) &&
            csi_old_wallet_fingerprint(node->db, probe->wallet);
    }
    if (fd >= 0) close(fd);
    progress_store_close(); wallet_sqlite_close(ws); node_db_close(node);
    boot_datadir_lock_release();
    return ok;
}

static bool csi_real_probe_child(const struct csi_real_paths *p, const struct csi_cutover_witness *w,
                                 struct csi_real_probe *probe)
{
    int pipefd[2];
    if (pipe(pipefd)) return false;
    uint64_t parent = (uint64_t)getpid();
    pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(44);
        alarm(90);
        close(pipefd[0]);
        struct csi_real_probe local = {0};
        bool ok = csi_real_recover(p, w, &local) &&
            write(pipefd[1], &local, sizeof(local)) == (ssize_t)sizeof(local);
        close(pipefd[1]);
        _exit(ok ? 0 : 1);
    }
    close(pipefd[1]);
    int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(pipefd[0], probe, sizeof(*probe));
    close(pipefd[0]);
    return waited && n == (ssize_t)sizeof(*probe) &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static unsigned csi_real_discover_steps;
static bool csi_real_stop_seen;
static struct wallet_discover_checkpoint csi_real_saved_checkpoint;
static void csi_real_stop_hook(enum boot_cutover_replay_phase phase, enum boot_cutover_replay_status status)
{
    if (phase == BOOT_CUTOVER_DISCOVER && status == BOOT_CUTOVER_PROGRESS &&
        ++csi_real_discover_steps == 2) {
        struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
        struct wallet *wallet = NULL; struct main_state *main = NULL;
        boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
        csi_real_stop_seen = wallet_sqlite_discover_checkpoint_read(ws, &csi_real_saved_checkpoint) == WALLET_DISCOVER_FOUND;
        thread_registry_request_shutdown();
    }
}

/* Runs real startup and cleanup; the hook requests shutdown, not an OS signal. */
static void csi_real_stop_boot(const struct csi_real_paths *p, int signal_fd)
{
    char datadir[PATH_MAX + 32], params[PATH_MAX + 32];
    int a = snprintf(datadir, sizeof(datadir), "-datadir=%s", p->data);
    int b = snprintf(params, sizeof(params), "-paramsdir=%s", p->params);
    if (a < 0 || b < 0 || (size_t)a >= sizeof(datadir) || (size_t)b >= sizeof(params)) _exit(40);
    char *argv[] = {"z23", datadir, params, "-operator-lane=dev", "-nolegacyimport",
        "-nolegacyutxoimport", "-no-tor", "-private-listeners", "-observation=0",
        "-connect=127.0.0.1:1", "-port=28033", "-rpcport=28232", "-httpsport=28443", "-fsport=28034"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));
    struct app_context ctx;
    app_context_defaults(&ctx);
    ctx.datadir = p->data;
    ctx.params_dir = p->params;
    ParseParameters(argc, (const char *const *)argv);
    bool metrics = false;
    if (args_parse_node_options(argc, argv, &ctx, &metrics) != -1 || unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL")) _exit(41);
    boot_stage_reset_for_testing();
    ecc_verify_destroy();
    ecc_stop();
    boot_test_pending_detail_hook(csi_real_stop_hook);
    bool started = app_init(&ctx);
    boot_test_pending_detail_hook(NULL);
    if (started || !csi_real_stop_seen || boot_error_reported() || !boot_pending_stop_cleanup()) _exit(42);
    if (write(signal_fd, &csi_real_saved_checkpoint, sizeof(csi_real_saved_checkpoint)) !=
        (ssize_t)sizeof(csi_real_saved_checkpoint)) _exit(45);
    _exit(0);
}

static bool csi_real_stop_child(const struct csi_real_paths *p, struct wallet_discover_checkpoint *checkpoint)
{
    int pipefd[2];
    if (pipe(pipefd)) return false;
    uint64_t parent = (uint64_t)getpid();
    pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(43);
        close(pipefd[0]);
        csi_real_stop_boot(p, pipefd[1]);
    }
    close(pipefd[1]);
    int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(pipefd[0], checkpoint, sizeof(*checkpoint));
    close(pipefd[0]);
    return waited && n == (ssize_t)sizeof(*checkpoint) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool csi_real_checkpoint_same(const struct wallet_discover_checkpoint *a,
                                     const struct wallet_discover_checkpoint *b)
{
    return wallet_cutover_binding_equal(&a->binding, &b->binding) &&
        a->generation_present == b->generation_present && a->generation == b->generation &&
        a->floor == b->floor && a->next_height == b->next_height && a->endpoint_height == b->endpoint_height &&
        !memcmp(a->endpoint_hash, b->endpoint_hash, 32) && !memcmp(a->endpoint_root, b->endpoint_root, 32) &&
        !memcmp(a->scan_identity, b->scan_identity, 32) && !memcmp(a->key_digest, b->key_digest, 32) &&
        a->event_end == b->event_end && !memcmp(a->event_digest, b->event_digest, 32);
}

static bool csi_real_run(struct csi_real_paths *p)
{
    if (!csi_real_copy(p->bundle, p->artifact) || chmod(p->artifact, 0400) ||
        !csi_real_bundle_identity(p->artifact)) {
        fprintf(stderr, "real install: bundle identity refused\n");
        return false;
    }
    p->bundle = p->artifact;
    if (mkdir(p->data, 0700)) { fprintf(stderr, "real install: datadir creation failed\n"); return false; }
    if (!csi_real_seed_child(p)) { fprintf(stderr, "real install: wallet setup failed\n"); return false; }
    if (!csi_real_bootstrap(p)) { fprintf(stderr, "real install: genesis setup failed\n"); return false; }
    if (!csi_real_history(p)) { fprintf(stderr, "real install: history copy failed\n"); return false; }
    struct csi_cutover_witness witness = {0};
    if (!csi_real_kill(p, &witness)) { fprintf(stderr, "real install: commit witness missing\n"); return false; }
    struct csi_real_probe before = {0}, after = {0};
    struct wallet_discover_checkpoint checkpoint = {0};
    return csi_real_probe_child(p, &witness, &before) && before.checkpoint_status == WALLET_DISCOVER_ABSENT &&
        csi_real_stop_child(p, &checkpoint) && csi_real_probe_child(p, &witness, &after) &&
        after.checkpoint_status == WALLET_DISCOVER_FOUND && csi_real_checkpoint_same(&checkpoint, &after.checkpoint) &&
        !memcmp(before.wallet, after.wallet, sizeof(before.wallet));
}

#if defined(__linux__)
#include "services/wallet_history_capability.h"
#include "../../../engine/composition/src/consensus_state_install_terminal_internal.h"
#include "services/wallet_history_manifest.h"
static bool csi_bound_wallet_identity(sqlite3 *, unsigned char out[32]);
void boot_test_set_terminal_hook(struct zcl_result (*hook)(struct node_db *, struct main_state *,
    const char *, const char *, struct wallet_sqlite *, struct wallet *,
    struct consensus_state_install_runtime_result *));
struct csi_real_bound_witness {
    struct wallet_cutover_binding binding;
    uint8_t wallet[32];
    bool fence, committed;
};
static struct csi_real_bound_witness csi_real_bound_witness;
static int csi_real_bound_pipe = -1;
static struct wallet_history_capability csi_real_bound_cap;
static struct boot_bound_bundle_observation csi_real_bound_observation;

static void csi_real_bound_fence(void *opaque)
{
    struct wallet_sqlite *ws = opaque;
    csi_real_bound_witness.fence = wallet_sqlite_cutover_read(ws, &csi_real_bound_witness.binding) == WALLET_CUTOVER_PENDING &&
        csi_real_bound_witness.binding.history_identity_present &&
        csi_bound_wallet_identity(ws->db, csi_real_bound_witness.wallet);
}
static void csi_real_bound_commit(void *opaque)
{
    struct csi_commit_hook_context *c = opaque;
    int fd = open(c->datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool present = false; uint64_t generation = 0;
    csi_real_bound_witness.committed = fd >= 0 && csi_real_bound_witness.fence &&
        consensus_state_wallet_install_classify(c->ws, c->node, fd, &present, &generation) == WALLET_INSTALL_COMMITTED;
    if (fd >= 0) close(fd);
}
static bool csi_real_bound_header_cancel(struct bound_history_preflight *preflight,
                                        int height, const uint8_t hash[32])
{
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(70);
        alarm(30); thread_registry_request_shutdown();
        struct block_header out, before; memset(&out, 0xa5, sizeof(out)); memset(&before, 0xa5, sizeof(before));
        struct zcl_result r = bound_history_preflight_read_header(preflight, height, hash, &out);
        _exit(!r.ok && r.code == BOUND_HISTORY_HEADER_CANCELLED &&
              !memcmp(&out, &before, sizeof(out)) ? 0 : 1);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool csi_real_bound_headers(struct bound_history_preflight *preflight, const struct block_index *old_tip)
{
    struct block_header out, before;
    uint8_t wrong[32]; memcpy(wrong, csi_real_bound_observation.endpoint_hash, sizeof(wrong)); wrong[0] ^= 1;
    memset(&out, 0xa5, sizeof(out)); memset(&before, 0xa5, sizeof(before));
    struct zcl_result invalid = bound_history_preflight_read_header(preflight, -1, wrong, &out);
    if (invalid.ok || invalid.code != BOUND_HISTORY_HEADER_INVALID || memcmp(&out, &before, sizeof(out))) return false;
    invalid = bound_history_preflight_read_header(preflight, old_tip->nHeight, NULL, &out);
    if (invalid.ok || invalid.code != BOUND_HISTORY_HEADER_INVALID || memcmp(&out, &before, sizeof(out))) return false;
    struct zcl_result unavailable = bound_history_preflight_read_header(preflight,
        csi_real_bound_observation.endpoint_height, wrong, &out);
    if (unavailable.ok || unavailable.code != BOUND_HISTORY_HEADER_UNAVAILABLE ||
        memcmp(&out, &before, sizeof(out))) return false;
    struct zcl_result wrong_height = bound_history_preflight_read_header(preflight,
        old_tip->nHeight + 1, old_tip->phashBlock->data, &out);
    if (wrong_height.ok || wrong_height.code != BOUND_HISTORY_HEADER_UNAVAILABLE ||
        memcmp(&out, &before, sizeof(out))) return false;
    if (!csi_real_bound_header_cancel(preflight, old_tip->nHeight, old_tip->phashBlock->data)) return false;
    struct uint256 hash;
    if (!bound_history_preflight_read_header(preflight, csi_real_bound_observation.endpoint_height,
            csi_real_bound_observation.endpoint_hash, &out).ok) return false;
    block_header_get_hash(&out, &hash);
    if (memcmp(hash.data, csi_real_bound_observation.endpoint_hash, 32)) return false;
    if (!bound_history_preflight_read_header(preflight, old_tip->nHeight, old_tip->phashBlock->data, &out).ok) return false;
    block_header_get_hash(&out, &hash);
    return uint256_eq(&hash, old_tip->phashBlock);
}
static void csi_real_bound_stage_seen(void *opaque) { *(bool *)opaque = true; }
static struct zcl_result csi_real_bound_terminal(struct node_db *node, struct main_state *main,
    const char *bundle, const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    struct consensus_state_install_runtime_result *out)
{
    struct block_index *tip = active_chain_tip(&main->chain_active);
    const struct chain_params *params = chain_params_get();
    if (!tip || !tip->phashBlock || tip->nHeight != 0 || !params ||
        !uint256_eq(tip->phashBlock, &params->consensus.hashGenesisBlock) || wallet->num_wallet_tx != 2)
        return ZCL_ERR(-1, "real bound fixture old frontier unavailable");
    struct consensus_state_artifact_evidence *artifact = NULL;
    struct bound_history_preflight *preflight = NULL;
    bound_history_preflight_test_reset_archive_opens();
    struct zcl_result opened = consensus_state_artifact_evidence_open(bundle, -1, &artifact);
    if (opened.ok) opened = bound_history_preflight_open(&preflight, &csi_real_bound_observation,
        artifact, &csi_real_bound_cap, tip->nHeight, tip->phashBlock->data);
    if (!opened.ok || !preflight || bound_history_preflight_test_archive_opens() != 1) {
        bound_history_preflight_close(&preflight);
        (void)consensus_state_artifact_evidence_close(&artifact);
        return ZCL_ERR(-1, "real bound fixture preflight unavailable");
    }
    if (!csi_real_bound_headers(preflight, tip)) {
        bound_history_preflight_close(&preflight);
        (void)consensus_state_artifact_evidence_close(&artifact);
        return ZCL_ERR(-1, "real bound fixture retained header checks failed");
    }
    struct block_index stale_tip = *tip; stale_tip.nHeight++;
    if (bound_history_preflight_recheck(preflight, &csi_real_bound_observation,
            artifact, &csi_real_bound_cap, &stale_tip).ok) {
        bound_history_preflight_close(&preflight);
        (void)consensus_state_artifact_evidence_close(&artifact);
        return ZCL_ERR(-1, "real bound fixture accepted stale frontier");
    }
    struct icb_terminal_context *terminal = bound_history_preflight_terminal(preflight);
    struct main_state *archive = terminal ? terminal->archive : NULL;
    sqlite3_int64 node_before = sqlite3_total_changes64(node->db);
    sqlite3_int64 progress_before = sqlite3_total_changes64(progress_store_db());
    struct boot_bound_bundle_observation stale = csi_real_bound_observation; stale.attempts++;
    bool staged = false;
    consensus_state_install_test_after_stage(csi_real_bound_stage_seen, &staged);
    struct zcl_result refused = bound_history_preflight_install(preflight, &stale, &csi_real_bound_cap,
        node, main, datadir, ws, wallet, out);
    consensus_state_install_test_after_stage(NULL, NULL);
    struct wallet_cutover_binding binding;
    bool guarded = !refused.ok && !staged && archive && terminal->archive == archive &&
        bound_history_preflight_test_archive_opens() == 1 &&
        sqlite3_total_changes64(node->db) == node_before &&
        sqlite3_total_changes64(progress_store_db()) == progress_before &&
        wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_ABSENT &&
        !boot_consensus_bundle_marker_exists(datadir);
    struct zcl_result result = guarded ? bound_history_preflight_install(preflight,
        &csi_real_bound_observation, &csi_real_bound_cap, node, main, datadir, ws, wallet, out) :
        ZCL_ERR(-1, "real bound fixture stale handoff changed state");
    bool same = terminal && terminal->archive == archive && bound_history_preflight_test_archive_opens() == 1;
    bound_history_preflight_close(&preflight);
    bool closed = consensus_state_artifact_evidence_close(&artifact);
    if (result.ok && (!same || !closed || !csi_real_bound_witness.fence || !csi_real_bound_witness.committed ||
        write(csi_real_bound_pipe, &csi_real_bound_witness, sizeof(csi_real_bound_witness)) !=
            (ssize_t)sizeof(csi_real_bound_witness)))
        return ZCL_ERR(-1, "real bound fixture witness missing");
    return result;
}
static bool csi_real_bound_seed(const struct csi_real_paths *p, uint8_t fingerprint[32])
{
    struct node_db db = {0}; struct wallet_sqlite ws = {0};
    struct wallet *wallet = calloc(1, sizeof(*wallet));
    if (!wallet || !node_db_open(&db, p->node) || !wallet_sqlite_open_r(&ws, db.db).ok) return false;
    chain_params_select(CHAIN_MAIN); const struct chain_params *params = chain_params_get();
    wallet_init(wallet); bool ok = params != NULL;
    for (unsigned i = 0; ok && i < 2; ++i) {
        struct wallet_tx *tx = &wallet->map_wallet[i];
        transaction_init(&tx->tx); tx->tx.lock_time = i + 1; transaction_compute_hash(&tx->tx);
        tx->used = true; tx->hash_block = params->consensus.hashGenesisBlock;
        tx->confirms = 1; tx->time_received = 1713000000 + i;
        ok = wallet_sqlite_write_tx(&ws, tx);
    }
    wallet->num_wallet_tx = 2; wallet->best_block_height = 0;
    ok = ok && wallet_sqlite_write_scan_state(&ws, wallet) && csi_bound_wallet_identity(db.db, fingerprint);
    wallet_free(wallet); free(wallet); wallet_sqlite_close(&ws); node_db_close(&db); return ok;
}
static bool csi_real_bound_history(struct csi_real_paths *p, struct boot_bound_bundle_request *request)
{
    struct consensus_state_artifact_evidence *e = NULL;
    struct consensus_state_bundle_manifest manifest = {0};
    struct file_manifest *history = calloc(1, sizeof(*history));
    bool ok = history && wallet_history_manifest_build(history, p->history, 52).ok &&
        consensus_state_artifact_evidence_open(p->bundle, -1, &e).ok &&
        consensus_state_artifact_evidence_file_digest(e, request->snapshot_sha3) &&
        consensus_state_artifact_evidence_manifest_copy(e, &manifest);
    if (!consensus_state_artifact_evidence_close(&e)) ok = false;
    if (!ok) { free(history); return false; }
    request->endpoint_height = manifest.height; memcpy(request->endpoint_hash, manifest.block_hash, 32);
    memcpy(request->history_manifest_root, history->root_hash, 32); free(history);
    struct wallet_history_names names;
    char path[PATH_MAX], lock[PATH_MAX];
    ok = wallet_history_capability_names(request->snapshot_sha3, request->history_manifest_root, &names).ok &&
        csi_real_path(path, sizeof(path), p->data, names.root) &&
        csi_real_path(lock, sizeof(lock), p->data, names.lock) && rename(p->history, path) == 0;
    int fd = ok ? open(lock, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600) : -1;
    if (fd < 0 || close(fd)) return false;
    if (snprintf(p->history, sizeof(p->history), "%s", path) >= (int)sizeof(p->history)) return false;
    request->bundle_path = p->bundle; request->private_history_path = p->history;
    if (snprintf(csi_real_bound_observation.bundle_path, sizeof(csi_real_bound_observation.bundle_path), "%s", p->bundle) >=
            (int)sizeof(csi_real_bound_observation.bundle_path) ||
        snprintf(csi_real_bound_observation.private_history_path, sizeof(csi_real_bound_observation.private_history_path), "%s", p->history) >=
            (int)sizeof(csi_real_bound_observation.private_history_path)) return false;
    csi_real_bound_observation.endpoint_height = request->endpoint_height;
    memcpy(csi_real_bound_observation.endpoint_hash, request->endpoint_hash, 32);
    memcpy(csi_real_bound_observation.snapshot_sha3, request->snapshot_sha3, 32);
    memcpy(csi_real_bound_observation.history_manifest_root, request->history_manifest_root, 32);
    return true;
}
static void csi_real_bound_boot(const struct csi_real_paths *p, int signal_fd)
{
    csi_real_bound_pipe = signal_fd;
    struct wallet_history_names names;
    struct platform_directory_transaction parent, root; struct platform_directory_lock lease;
    platform_directory_transaction_init(&parent); platform_directory_transaction_init(&root);
    platform_directory_lock_init(&lease); wallet_history_capability_init(&csi_real_bound_cap);
    if (!wallet_history_capability_names(csi_real_bound_observation.snapshot_sha3,
                                         csi_real_bound_observation.history_manifest_root, &names).ok ||
        !platform_directory_transaction_open(&parent, p->data) ||
        platform_directory_lock_acquire(&parent, names.lock, false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) != PLATFORM_DIRECTORY_OK ||
        platform_directory_transaction_open_child(&parent, names.root, false, &root) != PLATFORM_DIRECTORY_OK ||
        !wallet_history_capability_acquire(&csi_real_bound_cap, &parent, &root, &lease, names.root, names.lock, 52,
                                           csi_real_bound_observation.history_manifest_root).ok) _exit(60);
    char datadir[PATH_MAX + 32], params[PATH_MAX + 32], verb[PATH_MAX + 64];
    int a = snprintf(datadir, sizeof(datadir), "-datadir=%s", p->data);
    int b = snprintf(params, sizeof(params), "-paramsdir=%s", p->params);
    int c = snprintf(verb, sizeof(verb), "-install-consensus-bundle=%s", p->bundle);
    if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof(datadir) || (size_t)b >= sizeof(params) || (size_t)c >= sizeof(verb)) _exit(61);
    char *argv[] = {"z23", datadir, params, verb, "-operator-lane=dev", "-nolegacyimport",
        "-nolegacyutxoimport", "-no-tor", "-private-listeners", "-observation=0", "-connect=127.0.0.1:1",
        "-port=28033", "-rpcport=28232", "-httpsport=28443", "-fsport=28034"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0])); struct app_context ctx;
    app_context_defaults(&ctx); ctx.datadir = p->data; ctx.params_dir = p->params;
    ParseParameters(argc, (const char *const *)argv); bool metrics = false;
    if (args_parse_node_options(argc, argv, &ctx, &metrics) != -1 || unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL")) _exit(62);
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    struct csi_commit_hook_context hook = {p->data, node, ws, signal_fd};
    consensus_state_install_test_after_wallet_fence(csi_real_bound_fence, ws);
    consensus_state_install_test_after_commit(csi_real_bound_commit, &hook);
    boot_test_set_terminal_hook(csi_real_bound_terminal);
    boot_stage_reset_for_testing(); ecc_verify_destroy(); ecc_stop();
    (void)app_init(&ctx); _exit(63);
}
#endif

#if defined(__linux__)
static bool csi_real_bound_seed_child(const struct csi_real_paths *p, uint8_t fingerprint[32])
{
    int pipefd[2]; if (pipe(pipefd)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(64);
        close(pipefd[0]); uint8_t hash[32];
        bool ok = csi_real_bound_seed(p, hash) && write(pipefd[1], hash, sizeof(hash)) == (ssize_t)sizeof(hash);
        close(pipefd[1]); _exit(ok ? 0 : 1);
    }
    close(pipefd[1]); int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(pipefd[0], fingerprint, 32); close(pipefd[0]);
    return waited && n == 32 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool csi_real_bound_install_child(const struct csi_real_paths *p, struct csi_real_bound_witness *w)
{
    int pipefd[2]; if (pipe(pipefd)) return false;
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(65);
        close(pipefd[0]); csi_real_bound_boot(p, pipefd[1]);
    }
    close(pipefd[1]); int status = 0;
    bool waited = child > 0 && csi_real_wait_child(child, &status);
    ssize_t n = read(pipefd[0], w, sizeof(*w)); close(pipefd[0]);
    return waited && n == (ssize_t)sizeof(*w) && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
}
static bool csi_real_bound_rows(struct wallet_sqlite *ws)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(ws->db,
        "SELECT COUNT(*), SUM(CASE WHEN block_height=0 THEN 1 ELSE 0 END) FROM wallet_transactions",
        -1, &stmt, NULL) == SQLITE_OK && stmt && sqlite3_step(stmt) == SQLITE_ROW &&
        sqlite3_column_int(stmt, 0) == 2 && sqlite3_column_int(stmt, 1) == 2 &&
        sqlite3_step(stmt) == SQLITE_DONE;
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    struct wallet *wallet = calloc(1, sizeof(*wallet));
    if (!wallet) return false;
    wallet_init(wallet);
    const struct chain_params *params = chain_params_get();
    ok = ok && params && wallet_sqlite_read_txs(ws, wallet) && wallet->num_wallet_tx == 2;
    unsigned found = 0;
    for (size_t i = 0; ok && i < MAX_WALLET_TX; ++i) {
        const struct wallet_tx *tx = &wallet->map_wallet[i];
        if (!tx->used) continue;
        ++found;
        ok = tx->confirms == 1 && uint256_eq(&tx->hash_block, &params->consensus.hashGenesisBlock);
    }
    wallet_free(wallet); free(wallet);
    return ok && found == 2;
}
static bool csi_real_bound_check(bool condition, const char *stage)
{
    if (!condition) fprintf(stderr, "real bound verify: %s failed\n", stage);
    return condition;
}
static bool csi_real_bound_verify(const struct csi_real_paths *p, const struct boot_bound_bundle_request *request,
                                  const struct csi_real_bound_witness *w, const uint8_t before[32])
{
    chain_params_select(CHAIN_MAIN);
    if (!csi_real_bound_check(boot_datadir_lock_acquire(p->data), "datadir lock")) return false;
    struct node_db *node = NULL; struct wallet_sqlite *ws = NULL;
    struct wallet *wallet = NULL; struct main_state *main = NULL;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    if (!csi_real_bound_check(node_db_open(node, p->node) && wallet_sqlite_open_r(ws, node->db).ok,
                              "startup wallet open")) return false;
    wallet_init(wallet);
    boot_stage_reset_for_testing();
    for (int stage = BOOT_STAGE_DATADIR_LOCKED; stage <= BOOT_STAGE_WALLET_LOADED; ++stage)
        boot_stage_advance_to((enum boot_stage)stage);
    bool pending = false;
    bool preflight = boot_wallet_cutover_preflight_test(p->data, &pending) && pending &&
        wallet_readiness_get(wallet).state == WALLET_READINESS_PENDING;
    bool ok = csi_real_bound_check(preflight, "pending preflight");
    int fd = open(p->data, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct wallet_cutover_binding binding = {0}; bool present = false; uint64_t generation = 0;
    uint8_t after[32] = {0}; int floor = -1, reference = -1;
    bool classified = preflight && fd >= 0 && consensus_state_wallet_install_classify(
        ws, node, fd, &present, &generation) == WALLET_INSTALL_COMMITTED;
    ok = csi_real_bound_check(w->fence && w->committed, "install witness") && ok;
    ok = csi_real_bound_check(classified, "canonical classifier") && ok;
    bool binding_read = wallet_sqlite_cutover_read(ws, &binding) == WALLET_CUTOVER_PENDING;
    ok = csi_real_bound_check(binding_read && wallet_cutover_binding_equal(&binding, &w->binding) &&
        binding.old_height == 0 && binding.target_height == request->endpoint_height &&
        !memcmp(binding.target_hash, request->endpoint_hash, 32) &&
        !memcmp(binding.snapshot_whole_sha3, request->snapshot_sha3, 32) &&
        !memcmp(binding.history_manifest_root, request->history_manifest_root, 32), "bound identity") && ok;
    ok = csi_real_bound_check(wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND &&
        floor == 1, "scan floor") && ok;
    ok = csi_real_bound_check(wallet_sqlite_height_encoding(ws, &reference) == WALLET_HEIGHT_V2 &&
        reference == 0 && csi_real_bound_rows(ws), "persisted transaction heights") && ok;
    ok = csi_real_bound_check(csi_bound_wallet_identity(node->db, after) &&
        !memcmp(before, w->wallet, 32) && !memcmp(before, after, 32), "transaction identity") && ok;
    ok = csi_real_bound_check(csi_real_watch_unchanged(node->db), "watch-only identity") && ok;
    ok = csi_real_bound_check(boot_consensus_bundle_marker_exists(p->data), "install marker") && ok;
    if (fd >= 0) close(fd);
    progress_store_close(); wallet_sqlite_close(ws); node_db_close(node);
    boot_datadir_lock_release(); return ok;
}
static bool csi_real_bound_verify_child(const struct csi_real_paths *p, const struct boot_bound_bundle_request *request,
                                        const struct csi_real_bound_witness *w, const uint8_t before[32])
{
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(66);
        alarm(90); _exit(csi_real_bound_verify(p, request, w, before) ? 0 : 1);
    }
    int status = 0;
    return child > 0 && csi_real_wait_child(child, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
/* Private, local test receipt; tied to this build ABI and never a signed attestation. */
struct csi_real_bound_receipt {
    uint8_t magic[8]; uint32_t version, size;
    char bundle[PATH_MAX], history[PATH_MAX];
    int32_t endpoint_height;
    uint8_t endpoint_hash[32], snapshot_sha3[32], history_root[32], before[32];
    uint8_t fence, committed, old_generation_present, history_identity_present;
    uint64_t old_generation;
    int32_t old_height, target_height;
    uint8_t old_hash[32], target_hash[32], artifact_digest[32];
    uint8_t binding_snapshot[32], binding_history[32], witness_wallet[32];
};
static bool csi_real_bound_receipt_write_all(int fd, const void *data, size_t size)
{
    const uint8_t *bytes = data;
    while (size) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += (size_t)n; size -= (size_t)n;
    }
    return true;
}
static bool csi_real_bound_receipt_fill(struct csi_real_bound_receipt *r,
    const struct boot_bound_bundle_request *request, const struct csi_real_bound_witness *w, const uint8_t before[32])
{
    if (!r || !request || !request->bundle_path || !request->private_history_path || !w || !before ||
        !w->fence || !w->committed || strlen(request->bundle_path) >= sizeof(r->bundle) ||
        strlen(request->private_history_path) >= sizeof(r->history)) return false;
    memset(r, 0, sizeof(*r)); memcpy(r->magic, "Z23BND1", 8); r->version = 1; r->size = sizeof(*r);
    memcpy(r->bundle, request->bundle_path, strlen(request->bundle_path) + 1);
    memcpy(r->history, request->private_history_path, strlen(request->private_history_path) + 1);
    r->endpoint_height = request->endpoint_height;
    memcpy(r->endpoint_hash, request->endpoint_hash, 32); memcpy(r->snapshot_sha3, request->snapshot_sha3, 32);
    memcpy(r->history_root, request->history_manifest_root, 32); memcpy(r->before, before, 32);
    r->fence = w->fence; r->committed = w->committed;
    r->old_generation_present = w->binding.old_generation_present;
    r->history_identity_present = w->binding.history_identity_present;
    r->old_generation = w->binding.old_generation; r->old_height = w->binding.old_height;
    r->target_height = w->binding.target_height;
    memcpy(r->old_hash, w->binding.old_hash, 32); memcpy(r->target_hash, w->binding.target_hash, 32);
    memcpy(r->artifact_digest, w->binding.artifact_digest, 32);
    memcpy(r->binding_snapshot, w->binding.snapshot_whole_sha3, 32);
    memcpy(r->binding_history, w->binding.history_manifest_root, 32); memcpy(r->witness_wallet, w->wallet, 32);
    return true;
}
static bool csi_real_bound_receipt_write(const struct csi_real_paths *p,
    const struct boot_bound_bundle_request *request, const struct csi_real_bound_witness *w, const uint8_t before[32])
{
    struct csi_real_bound_receipt record;
    if (!p || !csi_real_bound_receipt_fill(&record, request, w, before)) return false;
    int dir = open(p->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return false;
    int fd = openat(dir, "bound-install.receipt", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool ok = fd >= 0 && csi_real_bound_receipt_write_all(fd, &record, sizeof(record)) && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (ok && fsync(dir) != 0) ok = false;
    if (close(dir) != 0) ok = false;
    return ok;
}
static bool csi_real_bound_receipt_read_all(int fd, void *data, size_t size)
{
    uint8_t *bytes = data;
    while (size) {
        ssize_t n = read(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += (size_t)n; size -= (size_t)n;
    }
    return true;
}
static bool csi_real_bound_receipt_read(const char *root, struct csi_real_paths *p,
    struct csi_real_bound_receipt *record)
{
    const char *leaf = root ? strrchr(root, '/') : NULL;
    size_t root_len = root ? strlen(root) : 0;
    if (!root || root[0] != '/' || !leaf || strncmp(leaf + 1, "real-bound-", 11) || !p || !record ||
        root_len >= sizeof(p->root) || !csi_real_path(p->data, sizeof(p->data), root, "data") ||
        !csi_real_path(p->node, sizeof(p->node), p->data, "node.db") ||
        !csi_real_path(p->artifact, sizeof(p->artifact), root, "bundle.sqlite")) return false;
    memcpy(p->root, root, root_len + 1);
    int dir = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st; bool valid = dir >= 0 && fstat(dir, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 077);
    int fd = valid ? openat(dir, "bound-install.receipt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    valid = valid && fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        st.st_nlink == 1 && !(st.st_mode & 077) && st.st_size == (off_t)sizeof(*record) &&
        csi_real_bound_receipt_read_all(fd, record, sizeof(*record));
    if (fd >= 0 && close(fd) != 0) valid = false;
    if (dir >= 0 && close(dir) != 0) valid = false;
    if (!valid || memcmp(record->magic, "Z23BND1", 8) || record->version != 1 || record->size != sizeof(*record) ||
        !memchr(record->bundle, 0, sizeof(record->bundle)) || !memchr(record->history, 0, sizeof(record->history)) ||
        record->fence != 1 || record->committed != 1 || record->old_generation_present > 1 ||
        record->history_identity_present != 1 || strcmp(record->bundle, p->artifact)) return false;
    struct wallet_history_names names;
    return wallet_history_capability_names(record->snapshot_sha3, record->history_root, &names).ok &&
        csi_real_path(p->history, sizeof(p->history), p->data, names.root) && !strcmp(record->history, p->history);
}
static int csi_real_bound_receipt_probe(const char *root)
{
    int failures = 0;
    struct csi_real_paths p = {0}; struct csi_real_bound_receipt r;
    if (!csi_real_bound_receipt_read(root, &p, &r)) {
        fprintf(stderr, "real bound receipt: private local record unavailable or invalid\n"); return 1;
    }
    struct boot_bound_bundle_request request = {.bundle_path = r.bundle, .private_history_path = r.history,
        .endpoint_height = r.endpoint_height};
    memcpy(request.endpoint_hash, r.endpoint_hash, 32); memcpy(request.snapshot_sha3, r.snapshot_sha3, 32);
    memcpy(request.history_manifest_root, r.history_root, 32);
    struct csi_real_bound_witness witness = {.fence = true, .committed = true};
    witness.binding.old_generation_present = r.old_generation_present != 0;
    witness.binding.history_identity_present = r.history_identity_present != 0;
    witness.binding.old_generation = r.old_generation; witness.binding.old_height = r.old_height;
    witness.binding.target_height = r.target_height;
    memcpy(witness.binding.old_hash, r.old_hash, 32); memcpy(witness.binding.target_hash, r.target_hash, 32);
    memcpy(witness.binding.artifact_digest, r.artifact_digest, 32);
    memcpy(witness.binding.snapshot_whole_sha3, r.binding_snapshot, 32);
    memcpy(witness.binding.history_manifest_root, r.binding_history, 32); memcpy(witness.wallet, r.witness_wallet, 32);
    bool ok = csi_real_bound_verify_child(&p, &request, &witness, r.before);
    CSI_CHECK("retained private receipt matches fresh-process wallet and install", ok);
    return failures;
}
#include "consensus_state_cold_adoption_test.h"
static int csi_cold_retained_test(const char *root)
{
    struct csi_real_paths p = {0}; struct csi_real_bound_receipt receipt;
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH"); struct stat st;
    if (!csi_real_bound_receipt_read(root, &p, &receipt) || !scratch ||
        lstat(scratch, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)) {
        fprintf(stderr, "cold retained: private receipt or scratch unavailable\n"); return 1;
    }
    p.bundle = p.artifact;
    if (!csi_real_path(p.root, sizeof(p.root), scratch, "cold-retained-XXXXXX") || !mkdtemp(p.root)) {
        fprintf(stderr, "cold retained: scratch creation failed\n"); return 1;
    }
    memset(&csi_real_bound_observation, 0, sizeof(csi_real_bound_observation));
    memcpy(csi_real_bound_observation.bundle_path, receipt.bundle, strlen(receipt.bundle) + 1);
    memcpy(csi_real_bound_observation.private_history_path, receipt.history, strlen(receipt.history) + 1);
    csi_real_bound_observation.endpoint_height = receipt.endpoint_height;
    memcpy(csi_real_bound_observation.endpoint_hash, receipt.endpoint_hash, 32);
    memcpy(csi_real_bound_observation.snapshot_sha3, receipt.snapshot_sha3, 32);
    memcpy(csi_real_bound_observation.history_manifest_root, receipt.history_root, 32);
    bool ok = csi_cold_linked_child(&p);
    fprintf(stderr, "COLD_RETAINED result=%s\n", ok ? "PASS" : "FAIL");
    if (ok) (void)test_rm_rf_recursive(p.root);
    else fprintf(stderr, "cold retained: scratch preserved at %s\n", p.root);
    return ok ? 0 : 1;
}

static int csi_real_bound_postcommit_test(void)
{
    if (!getenv("ZCL_TEST_REAL_BOUND_INSTALL")) return 0;
    const char *bundle = getenv("ZCL_TEST_REAL_INSTALL_BUNDLE"), *history = getenv("ZCL_TEST_REAL_INSTALL_HISTORY");
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH"), *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    int failures = 0; struct csi_real_paths p = {.bundle = bundle, .source = history, .params = params};
    struct stat st;
    bool made = bundle && history && scratch && params && lstat(scratch, &st) == 0 &&
        S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077) &&
        csi_real_path(p.root, sizeof(p.root), scratch, "real-bound-XXXXXX") && mkdtemp(p.root);
    bool ok = made && csi_real_path(p.data, sizeof(p.data), p.root, "data") &&
        csi_real_path(p.history, sizeof(p.history), p.data, "wallet-history") &&
        csi_real_path(p.node, sizeof(p.node), p.data, "node.db") &&
        csi_real_path(p.artifact, sizeof(p.artifact), p.root, "bundle.sqlite") &&
        csi_real_copy(p.bundle, p.artifact) && chmod(p.artifact, 0400) == 0 && csi_real_bundle_identity(p.artifact);
    p.bundle = p.artifact;
    uint8_t before[32]; struct boot_bound_bundle_request request = {0}; struct csi_real_bound_witness witness = {0};
    ok = ok && mkdir(p.data, 0700) == 0 && csi_real_seed_child(&p) && csi_real_bootstrap(&p) &&
        csi_real_bound_seed_child(&p, before) && csi_real_history(&p) && csi_real_bound_history(&p, &request) &&
        csi_cold_linked_child(&p) &&
        csi_real_bound_install_child(&p, &witness) && csi_real_bound_receipt_write(&p, &request, &witness, before) &&
        csi_real_bound_verify_child(&p, &request, &witness, before);
    CSI_CHECK("real bound terminal preserves populated genesis wallet and commits install", ok);
    const char *keep = getenv("ZCL_TEST_REAL_BOUND_KEEP");
    if (made && ok && !(keep && !strcmp(keep, "1"))) (void)test_rm_rf_recursive(p.root);
    else if (made) fprintf(stderr, "real bound install: fixture retained at %s\n", p.root);
    return failures;
}
#endif

#if defined(__linux__)
#include "consensus_state_empty_retire_test.h"
#endif

static int csi_real_postcommit_test(void)
{
#if defined(__linux__)
    const char *populated_retained = getenv("ZCL_TEST_REAL_POPULATED_RETAINED");
    if (populated_retained && populated_retained[0]) return csi_populated_retained_probe(populated_retained);
    const char *completed_negative = getenv("ZCL_TEST_REAL_COMPLETED_NEGATIVE");
    if (completed_negative && completed_negative[0]) return csi_completed_mutation_test(completed_negative);
    const char *retained_old = getenv("ZCL_TEST_REAL_OLD_RETAINED");
    if (retained_old && retained_old[0]) return csi_retained_old_probe(retained_old);
    const char *retained_empty = getenv("ZCL_TEST_REAL_EMPTY_RETAINED");
    if (retained_empty && retained_empty[0]) return csi_empty_retained_probe(retained_empty);
    const char *empty_only = getenv("ZCL_TEST_REAL_EMPTY_RETIRE");
    const char *old_only = getenv("ZCL_TEST_REAL_OLD_RETRY");
    if (csi_populated_mode()) return csi_real_empty_retire_test();
    if ((old_only && !strcmp(old_only, "1")) || (empty_only && !strcmp(empty_only, "1"))) return csi_real_empty_retire_test();
    const char *cold_retained = getenv("ZCL_TEST_COLD_RETAINED");
    if (cold_retained && cold_retained[0]) return csi_cold_retained_test(cold_retained);
    const char *receipt_root = getenv("ZCL_TEST_REAL_BOUND_RECEIPT");
    if (receipt_root && receipt_root[0]) return csi_real_bound_receipt_probe(receipt_root);
    const char *bound_only = getenv("ZCL_TEST_REAL_BOUND_ONLY");
    if (bound_only && !strcmp(bound_only, "1")) {
        if (!getenv("ZCL_TEST_REAL_BOUND_INSTALL")) {
            fprintf(stderr, "real bound install: bound-only selector requires opt-in\n");
            return 1;
        }
        return csi_real_bound_postcommit_test();
    }
#endif
    const char *bundle = getenv("ZCL_TEST_REAL_INSTALL_BUNDLE");
    const char *history = getenv("ZCL_TEST_REAL_INSTALL_HISTORY");
    const char *scratch = getenv("ZCL_TEST_REAL_INSTALL_SCRATCH");
    const char *params = getenv("ZCL_TEST_REAL_INSTALL_PARAMS");
    if (!bundle && !history && !scratch && !params) return 0;
    int failures = 0;
    struct csi_real_paths p = {.bundle = bundle, .source = history, .params = params};
    struct stat st;
    bool made = bundle && history && scratch && params && lstat(scratch, &st) == 0 &&
        S_ISDIR(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077) &&
        csi_real_path(p.root, sizeof(p.root), scratch, "real-install-XXXXXX") && mkdtemp(p.root);
    bool ok = made &&
        csi_real_path(p.data, sizeof(p.data), p.root, "data") &&
        csi_real_path(p.history, sizeof(p.history), p.data, "wallet-history") &&
        csi_real_path(p.node, sizeof(p.node), p.data, "node.db") &&
        csi_real_path(p.artifact, sizeof(p.artifact), p.root, "bundle.sqlite");
    if (ok) ok = csi_real_run(&p);
    CSI_CHECK("real artifact post-commit SIGKILL restores pending wallet fence", ok);
    if (made && ok) (void)test_rm_rf_recursive(p.root);
    else if (made) fprintf(stderr, "real install: fixture retained at %s\n", p.root);
#if defined(__linux__)
    failures += csi_real_bound_postcommit_test();
#endif
    return failures;
}
#endif
