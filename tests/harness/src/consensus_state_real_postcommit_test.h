/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Opt-in real checkpoint installation interruption and recovery fixture. */
#ifndef ZCL_CONSENSUS_STATE_REAL_POSTCOMMIT_TEST_H
#define ZCL_CONSENSUS_STATE_REAL_POSTCOMMIT_TEST_H
#include "config/args.h"
#include "crypto/sha256.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "platform/file_clone.h"
#include "util/util.h"
#include <time.h>

struct csi_real_paths {
    char root[PATH_MAX], data[PATH_MAX], history[PATH_MAX], node[PATH_MAX], artifact[PATH_MAX];
    const char *bundle, *source, *params;
};

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
    struct node_db db = {0};
    struct wallet_sqlite ws = {0};
    if (!node_db_open(&db, p->node)) return false;
    bool opened = wallet_sqlite_open_r(&ws, db.db).ok;
    bool ok = opened && wallet_sqlite_write_scan_height(&ws, -1) &&
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

static bool csi_real_recover(const struct csi_real_paths *p, const struct csi_cutover_witness *w)
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
        csi_guarded_binding_matches(&binding, &w->binding) && csi_guarded_sentinel_exists(node->db) &&
        boot_consensus_bundle_marker_exists(p->data) &&
        wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == 0;
    if (fd >= 0) close(fd);
    progress_store_close(); wallet_sqlite_close(ws); node_db_close(node);
    boot_datadir_lock_release();
    return ok;
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
    if (!csi_real_seed_wallet(p)) { fprintf(stderr, "real install: wallet setup failed\n"); return false; }
    if (!csi_real_bootstrap(p)) { fprintf(stderr, "real install: genesis setup failed\n"); return false; }
    if (!csi_real_history(p)) { fprintf(stderr, "real install: history copy failed\n"); return false; }
    struct csi_cutover_witness witness = {0};
    if (!csi_real_kill(p, &witness)) { fprintf(stderr, "real install: commit witness missing\n"); return false; }
    pid_t child = fork();
    if (child == 0) _exit(csi_real_recover(p, &witness) ? 0 : 1);
    int status = 0;
    return child > 0 && csi_real_wait_child(child, &status) &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int csi_real_postcommit_test(void)
{
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
    return failures;
}
#endif
