/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the boot-stage state machine (platform/modules/util/src/boot_phase.c).
 *
 * boot_stage_advance_to() aborts on backward or out-of-range moves, so those
 * are tested only in fork-isolated children; the rest covers legal
 * transitions, idempotent re-advance, name lookup and the predicates.
 * boot_stage_reset_for_testing() (-DZCL_TESTING) restores the global stage. */

#include "test/test_core.h"
#include "wallet/wallet_lock.h"
#include "platform/time_compat.h"
#include "util/ar_step_readonly.h"
#include "crypto/sha3.h"
#if defined(__linux__)
#include <sys/time.h>
#endif
#include "../../../engine/composition/src/boot_wallet_cutover_checkpoint_internal.h"
#include "config/boot_datadir_lock.h"
#include "controllers/wallet_helpers.h"
#include "validation/main_state.h"
#include "platform/os_proc.h"
#include "models/ar_after_commit.h"
#include "base/serialize_le.h"
#include "platform/socket_compat.h"
#include "platform/wallet_startup_auth.h"
#include "platform/wallet_startup_auth_protocol.h"
#include "config/boot.h"
#include "config/db_service.h"
#include "wallet/wallet_keystore.h"
#include "config/boot_wallet_cutover_replay.h"
#include "config/boot_error.h"
#include "config/boot_internal.h"
#include "config/consensus_state_snapshot_install.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/boot_status.h"
#include "util/thread_registry.h"
#include "storage/event_log_singleton.h"
#include "storage/wallet_projection.h"
#include "storage/coins_kv.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"
#include "controllers/wallet_rescan_controller.h"
#include "models/database.h"
#include "storage/progress_store.h"
#include "storage/txdb.h"
#include <sqlite3.h>
#include "util/sd_notify.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#if !defined(_WIN32)
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#endif

#if !defined(_WIN32)
void boot_test_params_boundary(struct boot_svc_ctx *svc, const struct app_context *ctx,
                               bool verifier_ready, bool phgr_ready);

struct bp_params_barrier {
    int ready[2], release[2], returned[2];
    struct boot_svc_ctx svc;
    struct app_context ctx;
    _Atomic bool loaded;
    bool verifier_ready, phgr_ready, worker_ok;
};

static void *bp_params_worker(void *arg)
{
    struct bp_params_barrier *b = arg;
    char byte = 'r';
    if (write(b->ready[1], &byte, 1) != 1) return NULL;
    if (read(b->release[0], &byte, 1) != 1) return NULL;
    atomic_store(&b->loaded, b->worker_ok);
    return NULL;
}

static void *bp_params_caller(void *arg)
{
    struct bp_params_barrier *b = arg;
    boot_test_params_boundary(&b->svc, &b->ctx, b->verifier_ready, b->phgr_ready);
    char byte = 'd';
    if (write(b->returned[1], &byte, 1) != 1) return NULL;
    return NULL;
}

static void *bp_params_shutdown_caller(void *arg)
{
    struct bp_params_barrier *b = arg;
    char byte = boot_params_join_owned(&b->svc) ? 'j' : 'e';
    if (write(b->returned[1], &byte, 1) != 1) return NULL;
    return NULL;
}

static void bp_close_pair(int pair[2])
{
    if (pair[0] >= 0) close(pair[0]);
    if (pair[1] >= 0) close(pair[1]);
}

static int bp_params_finish(struct bp_params_barrier *b, pthread_t caller,
                            bool should_return_early, int before_release,
                            bool worker_ok)
{
    int failures = 0;
    char byte;
    bool caller_joined = false, shutdown_started = false;
    pthread_t shutdown_thread;
    if (should_return_early && before_release == 1) {
        if (read(b->returned[0], &byte, 1) != 1) failures++;
        pthread_join(caller, NULL);
        caller_joined = true;
        if (pthread_create(&shutdown_thread, NULL, bp_params_shutdown_caller, b) == 0) {
            shutdown_started = true;
            struct pollfd pfd = { .fd = b->returned[0], .events = POLLIN };
            if (poll(&pfd, 1, 2000) != 0) failures++; /* real-clock: shutdown must wait for the held real worker */
        } else failures++;
    }
    if (write(b->release[1], "x", 1) != 1) failures++;
    close(b->release[1]); b->release[1] = -1;
    if (!caller_joined) pthread_join(caller, NULL);
    if (shutdown_started) {
        pthread_join(shutdown_thread, NULL);
        if (read(b->returned[0], &byte, 1) != 1 || byte != 'j') failures++;
    }
    if (!boot_params_join_owned(&b->svc) || !boot_params_join_owned(&b->svc) ||
        b->svc.params_thread_started || atomic_load(&b->loaded) != worker_ok)
        failures++;
    return failures;
}

static int bp_params_barrier_case(bool verifier, bool phgr, bool steady,
                                  bool confine, bool should_return_early,
                                  bool worker_ok)
{
    int failures = 0;
    struct bp_params_barrier b = {
        .ready = {-1, -1}, .release = {-1, -1}, .returned = {-1, -1},
        .verifier_ready = verifier, .phgr_ready = phgr, .worker_ok = worker_ok,
    };
    b.ctx.params_dir = "fixture";
    b.ctx.sandbox_steady = steady;
    b.ctx.confine = confine;
    atomic_init(&b.loaded, false);
    b.svc.params_loaded = &b.loaded;
    if (pipe(b.ready) || pipe(b.release) || pipe(b.returned)) {
        failures++;
        goto close_pipes;
    }
    pthread_t worker, caller;
    if (pthread_create(&worker, NULL, bp_params_worker, &b) != 0) {
        failures++;
        goto close_pipes;
    }
    b.svc.params_thread = worker;
    b.svc.params_thread_started = true;
    char byte;
    if (read(b.ready[0], &byte, 1) != 1 ||
        pthread_create(&caller, NULL, bp_params_caller, &b) != 0) {
        if (write(b.release[1], "x", 1) != 1) failures++;
        close(b.release[1]); b.release[1] = -1;
        pthread_join(worker, NULL);
        failures++;
        goto close_pipes;
    }
    struct pollfd pfd = { .fd = b.returned[0], .events = POLLIN };
    int before_release = poll(&pfd, 1, 2000); /* real-clock: bounded wait for an actual blocked pthread; no fake scheduler seam */
    if (before_release != (should_return_early ? 1 : 0) || atomic_load(&b.loaded))
        failures++;
    failures += bp_params_finish(&b, caller, should_return_early,
                                 before_release, worker_ok);
close_pipes:
    bp_close_pair(b.ready); bp_close_pair(b.release); bp_close_pair(b.returned);
    return failures;
}

static int bp_test_params_ready_boundary(void)
{
    return bp_params_barrier_case(true, true, false, false, true, true);
}

/* glibc and macOS refuse pthread_join on the calling thread with EDEADLK, so
 * a self-join is a real, defined join failure without a seam. The loader must
 * stay owned: started remains true and the join reports false. The handle is
 * never joined, so ownership is dropped by hand afterwards. */
#if defined(__SANITIZE_THREAD__) || defined(__SANITIZE_ADDRESS__)
#define BP_SANITIZED_BUILD 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer) || __has_feature(address_sanitizer)
#define BP_SANITIZED_BUILD 1
#endif
#endif
#ifndef BP_SANITIZED_BUILD
#define BP_SANITIZED_BUILD 0
#endif

[[maybe_unused]] static int bp_test_params_join_failure_retains_ownership(void)
{
    struct boot_svc_ctx svc = {0};
    svc.params_thread = pthread_self();
    svc.params_thread_started = true;
    int failures = 0;
    if (boot_params_join_owned(&svc)) failures++;
    if (!svc.params_thread_started) failures++;
    svc.params_thread_started = false;
    return failures;
}
#endif
#if defined(__linux__)
#include <sys/vfs.h>
#include <linux/magic.h>
#endif

bool boot_wallet_rebuild_probe(sqlite3 *db, bool *has_utxos,
                               bool *has_keys);

static int test_wallet_rebuild_probe(void)
{
    sqlite3 *db = NULL;
    bool has_utxos = false;
    bool has_keys = false;
    int failed = 0;

    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return 1;
    failed |= sqlite3_exec(db,
        "CREATE TABLE wallet_utxos (spent_txid BLOB);"
        "CREATE TABLE wallet_keys (pubkey_hash BLOB);",
        NULL, NULL, NULL) != SQLITE_OK;
    failed |= !boot_wallet_rebuild_probe(db, &has_utxos, &has_keys);
    failed |= has_utxos || has_keys;

    failed |= sqlite3_exec(db,
        "INSERT INTO wallet_keys VALUES (X'01')", NULL, NULL, NULL) !=
        SQLITE_OK;
    failed |= !boot_wallet_rebuild_probe(db, &has_utxos, &has_keys);
    failed |= has_utxos || !has_keys;

    failed |= sqlite3_exec(db,
        "DELETE FROM wallet_keys; INSERT INTO wallet_utxos VALUES (NULL);",
        NULL, NULL, NULL) != SQLITE_OK;
    failed |= !boot_wallet_rebuild_probe(db, &has_utxos, &has_keys);
    failed |= !has_utxos || has_keys;

    failed |= sqlite3_exec(db,
        "DELETE FROM wallet_utxos; DROP TABLE wallet_keys",
        NULL, NULL, NULL) != SQLITE_OK;
    failed |= boot_wallet_rebuild_probe(db, &has_utxos, &has_keys);
    failed |= sqlite3_close(db) != SQLITE_OK;
    return failed;
}

/* ── fixture for the out-of-band evidence probe ───────────────────
 *
 * An abstract-namespace socket (leading NUL) needs no filesystem path, so it
 * never writes into a datadir. Windows has no abstract AF_UNIX namespace, so
 * the fixture and its cases are POSIX-only (Windows prints a SKIP). */
#if !defined(_WIN32)
static int bp_bind_notify_socket(char *name_out, size_t name_cap,
                                 char *dir_out, size_t dir_cap)
{
    static unsigned counter;
    int fd = platform_socket_open(AF_UNIX, SOCK_DGRAM, 0, true, true);
    if (fd < 0)
        return -1;

#if defined(__linux__)
    int n = snprintf(name_out, name_cap, "@zcl-bootphase-%d-%u",
                     (int)getpid(), counter++);
    if (n <= 0 || (size_t)n >= name_cap) {
        close(fd);
        return -1;
    }
    if (dir_cap > 0)
        dir_out[0] = '\0';
    size_t name_len = strlen(name_out) - 1;   /* bytes after the '@' */

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    sa.sun_path[0] = '\0';
    memcpy(sa.sun_path + 1, name_out + 1, name_len);
    socklen_t sa_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path)
                                    + 1 + name_len);
#else
    /* Non-Linux POSIX targets use a pathname socket in the suite's private
     * fixture directory, handed to the production sd_notify path. */
    test_make_tmpdir(dir_out, dir_cap, "bootphase", "notify");
    int n = snprintf(name_out, name_cap, "%s/socket-%u", dir_out, counter++);
    if (n <= 0 || (size_t)n >= name_cap ||
        (size_t)n >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        close(fd);
        test_rm_rf(dir_out);
        dir_out[0] = '\0';
        return -1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, name_out, (size_t)n + 1u);
    socklen_t sa_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                    (size_t)n + 1u);
#endif
    if (bind(fd, (struct sockaddr *)&sa, sa_len) != 0) {
        close(fd);
#if !defined(__linux__)
        test_rm_rf(dir_out);
        dir_out[0] = '\0';
#endif
        return -1;
    }
    return fd;
}

/* Discard everything queued. The sends are synchronous local IPC, so the
 * datagrams are already queued on return. */
static void bp_drain(int fd)
{
    char buf[256];
    while (recv(fd, buf, sizeof(buf), 0) >= 0)
        ;
}

/* True iff an EXTEND_TIMEOUT_USEC datagram is among what is queued. Drains
 * the WHOLE queue; a STATUS= line must not mask the absence of an extension. */
static bool bp_saw_extend(int fd)
{
    char buf[256];
    bool seen = false;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n < 0)
            break;
        buf[n] = '\0';
        if (strncmp(buf, "EXTEND_TIMEOUT_USEC=", 20) == 0)
            seen = true;
    }
    return seen;
}
#endif /* !_WIN32 */

/* Injectable evidence source: makes the moved / not-moved distinction exact. */
static uint64_t g_bp_fake_evidence;
static uint64_t bp_fake_evidence_probe(void *ctx)
{
    (void)ctx;
    return g_bp_fake_evidence;
}

#if defined(__linux__)
/* True iff `path` sits on Linux tmpfs, where fsync() is a no-op that never
 * advances ru_oublock. A failing statfs() is treated as not-tmpfs. */
static bool bp_is_tmpfs(const char *path)
{
    struct statfs sfs;
    if (statfs(path, &sfs) != 0)
        return false;
    return (unsigned long)sfs.f_type == (unsigned long)TMPFS_MAGIC;
}

/* mkdir -p, including the leaf, at 0700. Tolerates existing segments. */
static bool bp_mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf))
        return false;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

/* Fallback for bp_burn_block_io() when the suite tmpdir is tmpfs: a
 * disk-backed private dir under $ZCL_TEST_DISK_SCRATCH_ROOT (set by the
 * harness from the real cache dir), else $XDG_CACHE_HOME or $HOME/.cache, verified
 * not to be tmpfs. Returns false (dir unset) when no such root exists. */
static bool bp_disk_scratch_dir(char *dir, size_t dir_cap)
{
    /* The harness names the real disk-backed root before it moves HOME;
     * only without it fall back to the (possibly private) cache dirs. */
    const char *root = getenv("ZCL_TEST_DISK_SCRATCH_ROOT");
    const char *xdg = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    int n = -1;
    if (root && root[0])
        n = snprintf(dir, dir_cap, "%s/bootphase-%d", root, (int)getpid());
    else if (xdg && xdg[0])
        n = snprintf(dir, dir_cap, "%s/zclassic23/test-scratch/bootphase-%d",
                     xdg, (int)getpid());
    else if (home && home[0])
        n = snprintf(dir, dir_cap,
                     "%s/.cache/zclassic23/test-scratch/bootphase-%d", home,
                     (int)getpid());
    if (n <= 0 || (size_t)n >= dir_cap)
        return false;
    if (!bp_mkdir_p(dir))
        return false;
    if (bp_is_tmpfs(dir)) {
        (void)rmdir(dir);
        return false;
    }
    return true;
}
#endif /* __linux__ */

/* Force `bytes` of real device-visible write I/O for the getrusage probe.
 * Redirects to a disk-backed cache dir when the scratch helper returns tmpfs
 * (see bp_is_tmpfs()). Returns false if the fixture itself cannot be built. */
static bool bp_burn_block_io(size_t bytes)
{
    char dir[PATH_MAX];
    test_make_tmpdir(dir, sizeof(dir), "bootphase", "io");

#if defined(__linux__)
    if (bp_is_tmpfs(dir)) {
        test_rm_rf(dir);
        if (!bp_disk_scratch_dir(dir, sizeof(dir))) {
            printf("\nboot_phase: evidence fixture: bootphase/io tmpdir is "
                   "tmpfs (fsync there never advances ru_oublock) and no "
                   "disk-backed fallback was found — set XDG_CACHE_HOME or "
                   "HOME to a non-tmpfs path\n");
            return false;
        }
    }
#endif

    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/burn", dir);
    bool ok = false;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) {
        static char chunk[64 * 1024];
        size_t written = 0;
        ok = true;
        while (written < bytes) {
            size_t want = bytes - written;
            if (want > sizeof(chunk))
                want = sizeof(chunk);
            /* Vary the bytes so no filesystem collapses this to a hole. */
            chunk[0] = (char)(written >> 16);
            chunk[1] = (char)(written >> 8);
            ssize_t w = write(fd, chunk, want);
            if (w <= 0) { ok = false; break; }
            written += (size_t)w;
        }
        if (ok && fsync(fd) != 0)
            ok = false;
        close(fd);
    }
    test_rm_rf(dir);
    return ok;
}

#define BP_CHECK(name, expr) do { \
    printf("boot_phase: %s... ", (name)); \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void boot_test_bind_app_context(const struct app_context *ctx);

/* Capture stdout+stderr around a gate call. The export wrapper greps the
 * combined stream for REFUSED/EXPORTED; PARKED is on stderr. */
static bool bp_capture_gate(const char *datadir, char *out, size_t cap,
                            bool *fn_rc)
{
    FILE *capture = tmpfile();
    if (!capture)
        return false;
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0) {
        if (saved_out >= 0) close(saved_out);
        if (saved_err >= 0) close(saved_err);
        fclose(capture);
        return false;
    }
    fflush(stdout);
    fflush(stderr);
    if (dup2(fileno(capture), STDOUT_FILENO) < 0 ||
        dup2(fileno(capture), STDERR_FILENO) < 0) {
        dup2(saved_out, STDOUT_FILENO);
        dup2(saved_err, STDERR_FILENO);
        close(saved_out);
        close(saved_err);
        fclose(capture);
        return false;
    }
    *fn_rc = boot_node_db_open_failed_gate(datadir);
    fflush(stdout);
    fflush(stderr);
    (void)dup2(saved_out, STDOUT_FILENO);
    (void)dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    rewind(capture);
    size_t n = fread(out, 1, cap - 1, capture);
    out[n] = '\0';
    bool ok = !ferror(capture);
    if (fclose(capture) != 0)
        ok = false;
    return ok;
}

static struct app_context g_bp_park_ctx;

static void bp_park_fixture_begin(char *dir, size_t dir_cap, bool export_mode)
{
    test_make_tmpdir(dir, dir_cap, "bootphase",
                     export_mode ? "export_park" : "serve_park");
    boot_status_init(dir);
    boot_error_reset_for_testing();
    blocker_reset_for_testing();
    thread_registry_reset_for_test();
    thread_registry_request_shutdown();
    memset(&g_bp_park_ctx, 0, sizeof(g_bp_park_ctx));
    g_bp_park_ctx.datadir = dir;
    g_bp_park_ctx.export_consensus_bundle = export_mode;
    boot_test_bind_app_context(&g_bp_park_ctx);
}

static void bp_park_fixture_end(const char *dir)
{
    boot_test_bind_app_context(NULL);
    boot_status_init(NULL);
    boot_error_reset_for_testing();
    blocker_reset_for_testing();
    thread_registry_reset_for_test();
    test_rm_rf(dir);
}

/* ── node.db unopenable REFUSES; it must never park ───────────────
 *
 * Parking sends no READY= under Type=notify and the step stays open, so the
 * gate closes the step as failed (the only producer of verdict=failure),
 * refuses, and lets the unit exit. Its own function to stay under the
 * complexity cap; returns its own failure count. */
static int bp_node_db_gate_refuses(void)
{
    int failures = 0;
    char dir[PATH_MAX];
    char captured[4096];
    bool gate_rc = true;
    struct boot_status_snapshot snap;
    char why[128];

    bp_park_fixture_begin(dir, sizeof(dir), false);
    boot_step_enter("db.open_migrate");
    bool captured_ok = bp_capture_gate(dir, captured, sizeof(captured),
                                       &gate_rc);
    bool status_ok = boot_status_read(dir, &snap, why, sizeof(why));
    BP_CHECK("serving+node_db_unopened: gate returns (does not park)",
             captured_ok && !gate_rc);
    BP_CHECK("serving+node_db_unopened: does not emit PARKED",
             captured_ok && strstr(captured, "PARKED") == NULL);
    BP_CHECK("serving+node_db_unopened: REFUSED line names the gate",
             captured_ok &&
             strstr(captured, "REFUSED: boot gate 'node_db_unopened'") != NULL);
    BP_CHECK("serving+node_db_unopened: closes the step as failed",
             captured_ok &&
             strstr(captured,
                    "step=db.open_migrate state=failed verdict=failure")
                 != NULL);
    BP_CHECK("serving+node_db_unopened: names one operator command",
             captured_ok && strstr(captured, "systemctl --user restart")
                 != NULL);
    BP_CHECK("serving+node_db_unopened: latches FATAL (exit 1 path)",
             boot_error_reported());
    BP_CHECK("serving+node_db_unopened: boot_status names the blocker",
             status_ok && strcmp(snap.blocker, "node_db_unopened") == 0);
    bp_park_fixture_end(dir);
    return failures;
}

/* A legacy index whose snapshot cannot be built (here: no CURRENT) must be
 * left exactly as it was. The step used to unlink zclassicd's LOCK on any
 * snapshot failure and open the directory itself, which lets a second
 * process write a live zclassicd's index. Returns its own failure count. */
static int bp_legacy_snapshot_keeps_source_lock(void)
{
    int failures = 0;
    char dir[PATH_MAX], src[PATH_MAX + 16], lock[PATH_MAX + 32];
    char snap[PATH_MAX + 16];
    test_make_tmpdir(dir, sizeof(dir), "bootphase", "ldblock");
    snprintf(src, sizeof(src), "%s/index", dir);
    snprintf(lock, sizeof(lock), "%s/LOCK", src);
    snprintf(snap, sizeof(snap), "%s/snap", dir);
    FILE *f = mkdir(src, 0700) == 0 ? fopen(lock, "w") : NULL;
    bool fixture_ok = f != NULL;
    if (f)
        fclose(f);
    BP_CHECK("legacy snapshot fixture: index dir with only a LOCK",
             fixture_ok);
    BP_CHECK("legacy snapshot without CURRENT fails",
             fixture_ok && !boot_legacy_index_snapshot(src, snap));
    struct stat st;
    BP_CHECK("failed legacy snapshot keeps zclassicd's LOCK",
             fixture_ok && stat(lock, &st) == 0);
    test_rm_rf(dir);
    return failures;
}
static int bp_test_thread_io_evidence(void);  /* end of file */
static bool bp_event_log_binding_cycle(event_log_t *first)
{
    bool bound = boot_bind_wallet_replay_event_log() && wallet_projection_event_log() == first;
    event_log_set_singleton(NULL);
    bool cleared = !boot_bind_wallet_replay_event_log() && !wallet_projection_event_log();
    event_log_set_singleton(first);
    return bound && cleared && boot_bind_wallet_replay_event_log();
}

static int test_boot_event_log_lifecycle(void)
{
    if (progress_store_db() || event_log_singleton())
        return 1;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_phase", "event-log");
    bool absent = !boot_bind_wallet_replay_event_log() && !wallet_projection_event_log();
    bool rejects_missing = !boot_ensure_event_log(NULL) && !boot_ensure_event_log("");
    bool opened = boot_ensure_event_log(dir);
    event_log_t *first = event_log_singleton();
    bool reused = opened && first && boot_ensure_event_log(dir) && event_log_singleton() == first;
    bool bound = bp_event_log_binding_cycle(first);
    boot_stop_projection_storage();
    bool retired = event_log_singleton() == NULL && progress_store_db() == NULL;
    test_rm_rf(dir);
    return !(absent && rejects_missing && reused && bound && retired && !wallet_projection_event_log());
}

static bool bp_provenance_markers(sqlite3 *db, bool expected)
{
    uint8_t value;
    size_t len;
    bool migration = false, folded = false;
    return progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY, &value, 1, &len, &migration) &&
        progress_meta_get(db, COINS_KV_SELF_FOLDED_KEY, &value, 1, &len, &folded) &&
        migration == expected && folded == expected;
}

static bool bp_provenance_setup(struct wallet_sqlite *ws, struct wallet *w,
    struct node_db *local_db, const char *dir)
{
    w->scan_retry.pending = true;
    w->scan_retry.from = 5; w->scan_retry.since = 123; w->best_block_height = 10;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "CUTOVER");
    struct wallet_cutover_binding b = {.old_generation_present = true,
        .old_generation = 1, .old_height = 10, .target_height = 20};
    b.old_hash[0] = 1; b.target_hash[0] = 2; b.artifact_digest[0] = 3;
    char path[320];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    if (!node_db_open(local_db, path)) { fprintf(stderr, "fixture: node open failed\n"); return false; }
    if (!wallet_sqlite_open_r(ws, local_db->db).ok) { fprintf(stderr, "fixture: wallet open failed\n"); return false; }
    if (!wallet_sqlite_cutover_prepare(ws, w, &b)) { fprintf(stderr, "fixture: prepare failed\n"); return false; }
    if (wallet_sqlite_cutover_read(ws, &b) != WALLET_CUTOVER_PENDING) { fprintf(stderr, "fixture: pending read failed\n"); return false; }
    return boot_ensure_event_log(dir) && boot_bind_wallet_replay_event_log() && progress_store_open(dir);
}

static bool bp_provenance_transition(struct wallet_sqlite *ws, sqlite3 *wallet_db, const char *dir)
{
    sqlite3 *db = progress_store_db();
    uint8_t txid[32] = {1}, script[] = {0x51};
    struct wallet_cutover_binding b;
    return db && coins_kv_ensure_schema(db) &&
        coins_kv_add(db, txid, 0, 1, 1, false, script, sizeof(script)) &&
        bp_provenance_markers(db, false) &&
        sqlite3_exec(wallet_db, "DELETE FROM node_state", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_read(ws, &b) == WALLET_CUTOVER_ABSENT &&
        boot_ensure_event_log(dir) && bp_provenance_markers(db, false);
}

static bool bp_provenance_reopen(const char *dir)
{
    event_log_t *log = event_log_singleton();
    event_log_set_singleton(NULL);
    bool refused = !boot_bind_wallet_replay_event_log();
    event_log_set_singleton(log);
    bool preserved = boot_ensure_event_log(dir) &&
        bp_provenance_markers(progress_store_db(), false);
    boot_stop_projection_storage();
    bool reopened = boot_ensure_event_log(dir) && progress_store_open(dir) &&
        boot_ensure_event_log(dir) && bp_provenance_markers(progress_store_db(), true);
    return refused && preserved && reopened;
}

static int test_boot_replay_provenance(void)
{
    struct node_db *ndb; struct wallet_sqlite *ws; struct wallet *wallet; struct main_state *main;
    boot_wallet_cutover_test_slots(&ndb, &ws, &wallet, &main);
    (void)ndb; (void)wallet; (void)main;
    if (ws->open || ws->db || progress_store_db() || event_log_singleton()) return 1;
    struct wallet *fixture = calloc(1, sizeof(*fixture));
    if (!fixture) return 1;
    wallet_init(fixture);
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_phase", "replay-provenance");
    struct node_db local_db = {0};
    bool ok = bp_provenance_setup(ws, fixture, &local_db, dir) &&
        bp_provenance_transition(ws, local_db.db, dir) && bp_provenance_reopen(dir);
    boot_stop_projection_storage();
    progress_store_close();
    if (ws->open) wallet_sqlite_close(ws);
    if (local_db.db) node_db_close(&local_db);
    wallet_free(fixture);
    free(fixture);
    test_rm_rf(dir);
    return !ok;
}

#if defined(ZCL_TESTING) && !defined(_WIN32)
/* A few bounded, nonblocking fixture events survive a killed child so the
 * existing timeout line can identify the last completed authentication step. */
struct bp_stage_event { int64_t when_us; char stage; };
static int bp_stage_fd = -1;

static void bp_stage_emit(char stage)
{
#if defined(__linux__)
    if (bp_stage_fd < 0) return;
    struct bp_stage_event event = { .when_us = platform_time_monotonic_us(), .stage = stage };
    (void)send(bp_stage_fd, &event, sizeof(event), MSG_DONTWAIT | MSG_NOSIGNAL);
#else
    (void)stage;
#endif
}

static bool bp_stage_report(int fd, const char *label, bool failed)
{
    struct bp_stage_event event, first = {0};
    char text[512]; size_t used = 0; unsigned seen = 0;
    if (fd < 0) return true;
    while (read(fd, &event, sizeof(event)) == (ssize_t)sizeof(event)) {
        if (event.stage == 'P') seen |= 1u;
        if (event.stage == 'R') seen |= 2u;
        if (event.stage == 'U') seen |= 4u;
        if (event.stage == 'T') seen |= 8u;
        if (event.stage == 'V') seen |= 16u;
        if (!first.when_us) first = event;
        int n = snprintf(text + used, sizeof(text) - used, "%s%c:%lld",
            used ? "," : "", event.stage,
            (long long)((event.when_us - first.when_us) / 1000));
        if (n < 0 || (size_t)n >= sizeof(text) - used) break;
        used += (size_t)n;
    }
    if (used) fprintf(stderr, "%scheckpoint %s stage_ms=%s "
        "(c=child-entry,s=seed-start,r=reload-done,a=auth-start,A=auth-return,"
        "p=peer-start,P=peer-ok,F=peer-failed,R/x=receive-ok/fail,"
        "U/u=unlock-ok/fail,T/t=arm-ok/fail,V/v=verify-ok/fail,j=join-start,J=join-return)\n",
        failed ? "FAIL " : "", label, text);
    return seen == 31u;
}

bool boot_test_pending_checkpoint_due(int64_t last, int64_t now);
static bool bp_checkpoint_save(struct boot_cutover_replay *r)
{
    struct wallet_discover_checkpoint c;
    return boot_wallet_discover_checkpoint_prepare(r, &c) &&
        boot_wallet_discover_checkpoint_save(r, &c) == BOOT_DISCOVER_SAVED;
}
#if defined(ZCL_TESTING) && defined(__linux__)
bool boot_test_pending_authenticate(struct wallet *, struct wallet_sqlite *, int, bool *, int64_t *);
void boot_test_auth_observer(void (*observer)(char));
static const char bp_checkpoint_pass[] = "synthetic-checkpoint-credential";
struct bp_auth_peer { int fd; bool ok; };
static bool bp_auth_io(int fd, void *buf, size_t len, bool send_data)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send_data ? send(fd, (const char *)buf + off, len - off, MSG_NOSIGNAL) :
                                read(fd, (char *)buf + off, len - off);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}
static void *bp_auth_peer_main(void *opaque)
{
    struct bp_auth_peer *p = opaque; unsigned char request[8];
    size_t len = strlen(bp_checkpoint_pass);
    unsigned char header[8] = {'Z','W','A','1', Z23_WALLET_AUTH_SECRET, 0,
                               (unsigned char)len, (unsigned char)(len >> 8)};
    struct timeval timeout = {.tv_sec = 5};
    bp_stage_emit('p'); /* peer starts */
    p->ok = setsockopt(p->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        bp_auth_io(p->fd, request, sizeof(request), false) &&
        !memcmp(request, "ZWA1", 4) && request[4] == Z23_WALLET_AUTH_REQUEST &&
        bp_auth_io(p->fd, header, sizeof(header), true) &&
        bp_auth_io(p->fd, (void *)bp_checkpoint_pass, len, true);
    bp_stage_emit(p->ok ? 'P' : 'F'); /* peer finished with result */
    close(p->fd); return NULL;
}
static bool bp_checkpoint_auth(struct wallet *w, struct wallet_sqlite *ws, int64_t *deadline)
{
    int fd[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) return false;
    struct bp_auth_peer peer = {.fd = fd[1]}; pthread_t thread;
    if (pthread_create(&thread, NULL, bp_auth_peer_main, &peer) != 0) {
        close(fd[0]); close(fd[1]); return false;
    }
    bool unlocked = false;
    bp_stage_emit('a'); /* authentication starts */
    bool ok = boot_test_pending_authenticate(w, ws, fd[0], &unlocked, deadline);
    bp_stage_emit('A'); /* authentication returned */
    bp_stage_emit('j'); /* join starts */
    bool joined = pthread_join(thread, NULL) == 0;
    bp_stage_emit('J'); /* join returned */
    return joined && peer.ok && ok && unlocked && *deadline > 0 && !wallet_lock_is_locked();
}
static bool bp_checkpoint_sealed(struct wallet_sqlite *ws)
{
    sqlite3_stmt *stmt = NULL;
    bool sealed = sqlite3_prepare_v2(ws->db, "SELECT seed,(SELECT xsk FROM wallet_sapling_keys LIMIT 1) FROM wallet_seed", -1, &stmt, NULL) == SQLITE_OK &&
        AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW && sqlite3_column_bytes(stmt, 0) > 4 &&
        sqlite3_column_blob(stmt, 0) && !memcmp(sqlite3_column_blob(stmt, 0), "WKS1", 4) &&
        sqlite3_column_bytes(stmt, 1) > 4 && sqlite3_column_blob(stmt, 1) &&
        !memcmp(sqlite3_column_blob(stmt, 1), "WKS1", 4);
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) sealed = false;
    return sealed;
}
static bool bp_checkpoint_seed(struct wallet_sqlite *ws, struct wallet *w, int64_t *deadline)
{
    uint8_t seed[32]; memset(seed, 0x51, sizeof(seed)); wallet_lock_reset_for_test();
    uint8_t div[ZC_DIVERSIFIER_SIZE], pk_d[32];
    if (!wallet_lock_unlock(NULL, NULL, bp_checkpoint_pass).ok ||
        !sapling_keystore_set_seed(&w->sapling_keys, seed) ||
        !sapling_keystore_new_address(&w->sapling_keys, div, pk_d) ||
        !wallet_init_hd(w, seed, sizeof(seed)) ||
        !wallet_sqlite_write_sapling_seed(ws, seed) ||
        !wallet_sqlite_write_sapling_key(ws, 0, &w->sapling_keys.keys[0])) return false;
    bool sealed = bp_checkpoint_sealed(ws);
    wallet_lock_note_encrypted_at_rest(); wallet_lock_lock(w);
    return sealed && wallet_lock_is_locked() && bp_checkpoint_auth(w, ws, deadline);
}
static bool bp_transparent_all_keys_sealed(struct wallet_sqlite *ws)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT count(*),sum(CASE WHEN substr(xsk,1,4)=x'574b5331' THEN 1 ELSE 0 END) FROM wallet_sapling_keys";
    bool ok = sqlite3_prepare_v2(ws->db, sql, -1, &stmt, NULL) == SQLITE_OK && stmt &&
        AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 20 &&
        sqlite3_column_int(stmt, 1) == 20 && AR_STEP_ROW_READONLY(stmt) == SQLITE_DONE;
    if (stmt && sqlite3_finalize(stmt) != SQLITE_OK) ok = false;
    return ok;
}
static bool bp_transparent_seed_rows(struct wallet_sqlite *ws, struct wallet *w)
{
    uint8_t seed[32]; memset(seed, 0x51, sizeof(seed));
    uint8_t div[ZC_DIVERSIFIER_SIZE], pk[32];
    wallet_lock_reset_for_test();
    if (!wallet_lock_unlock(NULL, NULL, bp_checkpoint_pass).ok ||
        !sapling_keystore_set_seed(&w->sapling_keys, seed) ||
        !wallet_sqlite_write_sapling_seed(ws, seed)) return false;
    for (size_t i = 0; i < 20; ++i)
        if (!sapling_keystore_new_address(&w->sapling_keys, div, pk) ||
            !wallet_sqlite_write_sapling_key(ws, i, &w->sapling_keys.keys[i])) return false;
    return bp_checkpoint_sealed(ws) && bp_transparent_all_keys_sealed(ws);
}
static bool bp_transparent_seed_reload(struct wallet_sqlite *ws, struct wallet *w,
                                       int64_t *deadline)
{
    bp_stage_emit('s'); /* seed setup starts */
    if (!bp_transparent_seed_rows(ws, w)) {
        fprintf(stderr, "seeded-skip fixture: sealed row setup failed\n");
        return false;
    }
    fprintf(stderr, "seeded-skip fixture: sealed seed and 20 sealed keys verified\n");
    wallet_lock_note_encrypted_at_rest();
    wallet_lock_lock(w);
    wallet_free(w);
    wallet_init(w);
    bool readiness = wallet_readiness_initialize(w, WALLET_READINESS_PENDING, true, 1);
    bool loaded = wallet_sqlite_read_sapling_keys(ws, w);
    bool locked = wallet_lock_is_locked();
    fprintf(stderr, "seeded-skip fixture: locked reload readiness=%d loaded=%d master=%d locked=%d keys=%zu\n",
            readiness, loaded, w->has_master_key, locked, w->sapling_keys.num_keys);
    bp_stage_emit('r'); /* locked reload finished */
    if (!readiness || !loaded || w->has_master_key || !locked) return false;
    boot_test_auth_observer(bp_stage_emit);
    bool authenticated = bp_checkpoint_auth(w, ws, deadline);
    boot_test_auth_observer(NULL);
    fprintf(stderr, "seeded-skip fixture: authenticated=%d master=%d seed=%d sapling=%zu transparent=%zu watch=%zu scripts=%zu\n",
            authenticated, w->has_master_key, w->sapling_keys.has_seed, w->sapling_keys.num_keys,
            w->keystore.num_keys, w->keystore.num_watching, w->keystore.num_scripts);
    return authenticated && w->has_master_key && w->sapling_keys.has_seed &&
        w->sapling_keys.num_keys == 20 && w->keystore.num_keys == 0 &&
        w->keystore.num_watching == 0 && w->keystore.num_scripts == 0;
}

static bool bp_checkpoint_key_digest(struct wallet *w, uint8_t out[32])
{
    struct sha3_256_ctx hash; static const uint8_t domain[] = "z23-sapling-replay-keys-v1";
    if (!zcl_mutex_trylock(&w->sapling_keys.cs)) return false;
    if (w->sapling_keys.num_keys != 1 || !w->sapling_keys.keys[0].used) {
        zcl_mutex_unlock(&w->sapling_keys.cs); return false;
    }
    const struct sapling_key_entry *key = &w->sapling_keys.keys[0];
    sha3_256_init(&hash); sha3_256_write(&hash, domain, sizeof(domain) - 1);
    sha3_256_write(&hash, key->ivk, 32); sha3_256_write(&hash, key->xfvk.fvk.ak, 32);
    sha3_256_write(&hash, key->xfvk.fvk.nk, 32); sha3_256_finalize(&hash, out);
    zcl_mutex_unlock(&w->sapling_keys.cs); return true;
}
static bool bp_checkpoint_expire(struct boot_cutover_replay *r)
{
    struct wallet *w = r->ctx->wallet;
    if (!bp_checkpoint_save(r) || !wallet_lock_arm_timeout(w, 1).ok) return false;
    for (int i = 0; i < 160 && !wallet_lock_is_locked(); ++i) (void)poll(NULL, 0, 25);
    return wallet_lock_is_locked() && !bp_checkpoint_save(r) &&
        boot_wallet_discover_checkpoint_resume(r) == BOOT_DISCOVER_RETRY &&
        wallet_readiness_get(w).state == WALLET_READINESS_PENDING;
}
static bool bp_checkpoint_reauth(struct boot_cutover_replay *r)
{
    struct wallet *w = r->ctx->wallet; struct wallet_sqlite *ws = r->ctx->wallet_db;
    uint8_t expected[32], after[32];
    if (!bp_checkpoint_key_digest(w, expected)) return false;
    memcpy(r->key_digest, expected, 32);
    if (!bp_checkpoint_expire(r)) return false;
    int64_t deadline = 0; uint8_t identity[32];
    if (!bp_checkpoint_auth(w, ws, &deadline) ||
        !wallet_scan_identity(w, identity) || memcmp(identity, r->identity, 32) ||
        !bp_checkpoint_key_digest(w, after) || memcmp(after, expected, 32)) return false;
    r->auth_deadline_ms = deadline; r->next = 0; memset(r->key_digest, 0, 32);
    if (boot_wallet_discover_checkpoint_resume(r) != BOOT_DISCOVER_RESUMED ||
        r->next != 10 || memcmp(r->key_digest, expected, 32)) return false;
    thread_registry_request_shutdown(); r->next = 11;
    bool stopped = !bp_checkpoint_save(r) && wallet_readiness_get(w).state == WALLET_READINESS_PENDING;
    wallet_lock_lock(w); return stopped && wallet_lock_is_locked();
}
#endif
static bool bp_checkpoint_bench(struct boot_cutover_replay *r, event_log_t *log)
{
    unsigned char payload[4096]; memset(payload, 0x5a, sizeof(payload));
    for (int size = 0; size < 2; ++size) {
        int blocks = size == 0 ? 4 : 2048;
        for (int i = 0; i < blocks; ++i)
            if (event_log_append(log, EV_BLOCK_BODY, payload, sizeof(payload)) == UINT64_MAX) return false;
        for (int sample = 0; sample < 3; ++sample) {
            struct wallet_discover_checkpoint cp;
            int64_t start = platform_time_monotonic_us();
            bool prepared = boot_wallet_discover_checkpoint_prepare(r, &cp);
            int64_t middle = platform_time_monotonic_us();
            bool saved = prepared && boot_wallet_discover_checkpoint_save(r, &cp) == BOOT_DISCOVER_SAVED;
            int64_t end = platform_time_monotonic_us();
            if (!saved || start <= 0 || middle < start || end < middle) return false;
            printf("checkpoint-overhead bytes=%llu sample=%d prepare_us=%lld save_us=%lld\n",
                (unsigned long long)cp.event_end, sample, (long long)(middle - start), (long long)(end - middle));
            fflush(stdout);
        }
    }
    return true;
}

static void bp_checkpoint_die(void *unused) { (void)unused; _exit(77); }
static void bp_checkpoint_die_committed(void *unused) { (void)unused; _exit(78); }
static void bp_checkpoint_request_stop(void *unused) { (void)unused; thread_registry_request_shutdown(); }

static bool bp_checkpoint_stop_save(struct boot_cutover_replay *r, int mode)
{
    if (!bp_checkpoint_save(r)) return false;
    r->next = 11;
    struct wallet_discover_checkpoint candidate;
    if (boot_wallet_discover_checkpoint_prepare_result(r, &candidate) != BOOT_DISCOVER_PREPARED)
        return false;
    if (mode == 9)
        boot_wallet_discover_checkpoint_test_after_commit(bp_checkpoint_request_stop, NULL);
    else
        boot_wallet_discover_checkpoint_test_before_cancel(bp_checkpoint_request_stop, NULL);
    if (mode == 8) boot_wallet_discover_checkpoint_test_fail_rollback(true);
    enum boot_discover_save result = boot_wallet_discover_checkpoint_save(r, &candidate);
    enum boot_discover_save expected = mode == 9 ? BOOT_DISCOVER_SAVED :
        mode == 8 ? BOOT_DISCOVER_SAVE_RETRY : BOOT_DISCOVER_SAVE_STOPPED;
    return result == expected && wallet_readiness_get(r->ctx->wallet).state == WALLET_READINESS_PENDING;
}

static bool bp_checkpoint_stop_digest(struct boot_cutover_replay *r, event_log_t *log, int mode)
{
    if (mode == 10) {
        r->auth_deadline_ms = 1;
        thread_registry_request_shutdown();
        struct wallet_discover_checkpoint c;
        return boot_wallet_discover_checkpoint_prepare_result(r, &c) == BOOT_DISCOVER_PREPARE_FAILED;
    }
    if (mode == 11) {
        boot_wallet_discover_checkpoint_test_after_digest(bp_checkpoint_request_stop, NULL);
        uint64_t end = event_log_size(log);
        int fd = event_log_test_fd(log);
        return fd >= 0 && close(fd) == 0 &&
            boot_wallet_discover_checkpoint_test_digest_failed(r, end);
    }
    if (mode == 13) {
        boot_wallet_discover_checkpoint_test_after_digest(bp_checkpoint_request_stop, NULL);
        return boot_wallet_discover_checkpoint_test_digest_failed(r, event_log_size(log) + 1);
    }
    boot_wallet_discover_checkpoint_test_digest_poll(bp_checkpoint_request_stop, NULL);
    struct wallet_discover_checkpoint c;
    return boot_wallet_discover_checkpoint_prepare_result(r, &c) == BOOT_DISCOVER_PREPARE_STOPPED;
}
static void bp_checkpoint_noop(void *record, void *ctx) { (void)record; (void)ctx; }
struct bp_checkpoint_busy { sqlite3 *db; int calls, rc; };
static int bp_checkpoint_busy_handler(void *context, int attempts)
{ (void)attempts; ((struct bp_checkpoint_busy *)context)->calls++; return 0; }
static void bp_checkpoint_check_handler(void *context)
{ struct bp_checkpoint_busy *b = context; b->rc = sqlite3_exec(b->db, "BEGIN IMMEDIATE", NULL, NULL, NULL); }
static bool bp_checkpoint_generation(uint64_t generation)
{
    uint8_t bytes[8]; zcl_write_u64_le(bytes, generation);
    return progress_meta_set(progress_store_db(), COINS_KV_AUTHORITY_GENERATION_KEY, bytes, sizeof(bytes));
}
static void bp_checkpoint_chain(struct main_state *ms, struct block_index blocks[21])
{
    for (int i = 0; i <= 20; ++i) {
        struct block_index *p = &blocks[i]; block_index_init(p);
        p->nHeight = i; p->hashBlock.data[0] = (uint8_t)(i + 1);
        p->phashBlock = &p->hashBlock; if (i) p->pprev = &blocks[i - 1];
        if (!block_map_insert(&ms->map_block_index, p->phashBlock, p) ||
            !active_chain_install_tip_slot(&ms->chain_active, p)) _exit(12);
    }
}
static event_log_t *bp_checkpoint_setup(const char *dir, const char *path,
    struct node_db *db, struct wallet_sqlite *ws, struct wallet *w, struct main_state *ms,
    struct block_index blocks[21], struct wallet_cutover_binding *binding)
{
    if (!boot_datadir_lock_acquire(dir) || !progress_store_open(dir) ||
        !node_db_open(db, path) || !wallet_sqlite_open_r(ws, db->db).ok) _exit(11);
    wallet_init(w); main_state_init(ms);
    bp_checkpoint_chain(ms, blocks);
    *binding = (struct wallet_cutover_binding){.old_generation_present = true,
        .old_generation = 0, .old_height = 0, .target_height = 20};
    binding->old_hash[0] = 1; binding->target_hash[0] = 21; binding->artifact_digest[0] = 3;
    w->scan_retry.pending = true; w->scan_retry.from = 0;
    snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "CUTOVER");
    if (!wallet_readiness_initialize(w, WALLET_READINESS_PENDING, true, 1) ||
        !wallet_sqlite_cutover_prepare(ws, w, binding) || !bp_checkpoint_generation(1) ||
        !boot_ensure_event_log(dir) || !boot_bind_wallet_replay_event_log()) _exit(13);
    event_log_t *log = event_log_singleton();
    if (!log || event_log_append(log, EV_BLOCK_HEADER, "x", 1) == UINT64_MAX) _exit(14);
    boot_stage_reset_for_testing();
    for (int stage = BOOT_STAGE_DATADIR_LOCKED; stage <= BOOT_STAGE_BLOCK_INDEX_LOADED; ++stage)
        boot_stage_advance_to((enum boot_stage)stage);
    return log;
}
#if defined(__linux__)
unsigned node_db_transparent_test_reads(void);
static bool bp_transparent_replay_init(struct boot_cutover_replay *r,
    struct wallet_rpc_context *ctx, struct db_service *svc,
    const struct wallet_cutover_binding *binding, const struct wallet_witness_endpoint *endpoint)
{
    uint8_t identity[32];
    return wallet_scan_identity(ctx->wallet, identity) &&
        boot_cutover_replay_init(r, ctx, svc, binding, 0, endpoint, identity);
}
static bool bp_transparent_seeded_skip(struct wallet_rpc_context *ctx,
    const struct wallet_cutover_binding *binding, struct block_index blocks[21])
{
    struct db_service svc; db_service_init(&svc);
    struct wallet_witness_endpoint endpoint = {.height = 20,
        .hash = blocks[20].hashBlock, .root = blocks[20].hashFinalSaplingRoot};
    struct boot_cutover_replay replay = {0};
    if (!bp_transparent_replay_init(&replay, ctx, &svc, binding, &endpoint)) return false;
    unsigned before = node_db_transparent_test_reads();
    enum boot_cutover_replay_status skip_status = boot_cutover_replay_step(&replay);
    fprintf(stderr, "seeded-skip fixture: skip status=%d phase=%d empty=%d reads=%u\n",
            (int)skip_status, (int)replay.phase, replay.transparent_empty,
            node_db_transparent_test_reads() - before);
    bool skipped = skip_status == BOOT_CUTOVER_PROGRESS &&
        replay.transparent_empty && replay.phase == BOOT_CUTOVER_DISCOVER &&
        replay.next == replay.floor && node_db_transparent_test_reads() == before &&
        wallet_readiness_get(ctx->wallet).state == WALLET_READINESS_PENDING;
    boot_cutover_replay_clear(&replay);
    if (!skipped) return false;
    struct key_id watch = {0}; watch.id.data[0] = 1;
    if (!keystore_add_watch_only_id(&ctx->wallet->keystore, &watch)) return false;
    blocks[0].nFile = 0;
    if (!bp_transparent_replay_init(&replay, ctx, &svc, binding, &endpoint)) return false;
    before = node_db_transparent_test_reads();
    bool scanned = boot_cutover_replay_step(&replay) == BOOT_CUTOVER_RETRY &&
        !replay.transparent_empty && replay.phase == BOOT_CUTOVER_TRANSPARENT &&
        node_db_transparent_test_reads() > before &&
        wallet_readiness_get(ctx->wallet).state == WALLET_READINESS_PENDING;
    boot_cutover_replay_clear(&replay);
    return scanned;
}

#endif

static void bp_checkpoint_contend(struct boot_cutover_replay *r, const char *path,
                                  struct wallet_discover_checkpoint *pending)
{
    sqlite3 *contender = NULL;
    if (sqlite3_open_v2(path, &contender, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK ||
        sqlite3_exec(contender, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK ||
        boot_wallet_discover_checkpoint_save(r, pending) != BOOT_DISCOVER_SAVE_BUSY ||
        sqlite3_exec(contender, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_close(contender) != SQLITE_OK) _exit(26);
}
static void bp_checkpoint_handler(struct boot_cutover_replay *r, struct node_db *db,
                                  struct wallet_discover_checkpoint *pending)
{
    struct bp_checkpoint_busy busy = {.db = db->db};
    if (sqlite3_busy_handler(db->db, bp_checkpoint_busy_handler, &busy) != SQLITE_OK) _exit(27);
    boot_wallet_discover_checkpoint_test_before_commit(bp_checkpoint_check_handler, &busy);
    if (boot_wallet_discover_checkpoint_save(r, pending) != BOOT_DISCOVER_SAVED ||
        busy.calls == 0 || (busy.rc & 0xff) != SQLITE_BUSY) _exit(28);
    boot_wallet_discover_checkpoint_test_before_commit(NULL, NULL);
    if (sqlite3_busy_timeout(db->db, 10000) != SQLITE_OK) _exit(29);
}
static void bp_checkpoint_open_faults(struct boot_cutover_replay *r,
                                      struct node_db *db, const char *path)
{
    struct wallet_discover_checkpoint pending;
    if (!boot_wallet_discover_checkpoint_prepare(r, &pending)) _exit(17);
    boot_wallet_discover_checkpoint_test_fail_open(true);
    if (boot_wallet_discover_checkpoint_save(r, &pending) != BOOT_DISCOVER_SAVE_RETRY) _exit(24);
    boot_wallet_discover_checkpoint_test_fail_open(false);
    int record = 1; ar_after_commit_note_begin();
    if (!ar_after_commit_enqueue(bp_checkpoint_noop, NULL, &record, sizeof(record)) ||
        boot_wallet_discover_checkpoint_save(r, &pending) != BOOT_DISCOVER_SAVE_RETRY) _exit(25);
    ar_after_commit_note_rollback();
    bp_checkpoint_contend(r, path, &pending);
    bp_checkpoint_handler(r, db, &pending);
}
static void bp_checkpoint_corruption(struct boot_cutover_replay *r, const char *dir)
{
    char events[512]; snprintf(events, sizeof(events), "%s/event_log.dat", dir);
    int fd = open(events, O_RDWR | O_CLOEXEC);
    if (fd < 0 || pwrite(fd, "y", 1, 16) != 1 ||
        boot_wallet_discover_checkpoint_resume(r) != BOOT_DISCOVER_RETRY ||
        pwrite(fd, "x", 1, 16) != 1 || close(fd) != 0) _exit(21);
}
static void bp_checkpoint_resume_faults(struct boot_cutover_replay *r, const char *dir, int mode)
{
    r->next = 0; memset(r->key_digest, 0, 32);
    if (boot_wallet_discover_checkpoint_resume(r) != BOOT_DISCOVER_RESUMED ||
        r->next != 10 || r->key_digest[0] != 0x42) _exit(18);
    if (!bp_checkpoint_generation(2) ||
        boot_wallet_discover_checkpoint_resume(r) != BOOT_DISCOVER_FLOOR ||
        !bp_checkpoint_generation(1)) _exit(19);
    r->auth_deadline_ms = 1;
    if (bp_checkpoint_save(r) ||
        boot_wallet_discover_checkpoint_resume(r) != BOOT_DISCOVER_RETRY) _exit(20);
    r->auth_deadline_ms = 0;
    bp_checkpoint_corruption(r, dir);
    r->next = 11;
    if (mode == 2) boot_wallet_discover_checkpoint_test_after_commit(bp_checkpoint_die_committed, NULL);
    else boot_wallet_discover_checkpoint_test_before_commit(bp_checkpoint_die, NULL);
    (void)bp_checkpoint_save(r);
    _exit(22);
}
static bool bp_checkpoint_stage_before(struct boot_cutover_replay *r,
                                       struct wallet_discover_checkpoint *candidate)
{
    struct wallet_rpc_context *ctx = r->ctx;
    struct wallet_discover_checkpoint stored;
    return boot_wallet_cutover_startup_context_matches(ctx->node_db, ctx->wallet_db, ctx->wallet, ctx->main_state) &&
        !boot_wallet_cutover_replay_context_matches(ctx->node_db, ctx->wallet_db, ctx->wallet, ctx->main_state) &&
        boot_wallet_discover_checkpoint_prepare(r, candidate) &&
        boot_wallet_discover_checkpoint_save(r, candidate) == BOOT_DISCOVER_SAVE_RETRY &&
        wallet_sqlite_discover_checkpoint_read(ctx->wallet_db, &stored) == WALLET_DISCOVER_ABSENT;
}
static bool bp_checkpoint_stage_ready(struct boot_cutover_replay *r,
                                      struct wallet_discover_checkpoint *candidate)
{
    struct wallet_rpc_context *ctx = r->ctx;
    return !boot_wallet_cutover_startup_context_matches(ctx->node_db, ctx->wallet_db, ctx->wallet, ctx->main_state) &&
        boot_wallet_cutover_replay_context_matches(ctx->node_db, ctx->wallet_db, ctx->wallet, ctx->main_state) &&
        !boot_wallet_cutover_replay_context_matches(NULL, ctx->wallet_db, ctx->wallet, ctx->main_state) &&
        boot_wallet_discover_checkpoint_save(r, candidate) == BOOT_DISCOVER_SAVED;
}
static bool bp_checkpoint_stage_late(struct boot_cutover_replay *r,
                                     struct wallet_discover_checkpoint *candidate)
{
    struct wallet_rpc_context *ctx = r->ctx;
    struct wallet_discover_checkpoint stored;
    struct wallet_cutover_binding binding;
    r->next = 11;
    return !boot_wallet_cutover_replay_context_matches(ctx->node_db, ctx->wallet_db, ctx->wallet, ctx->main_state) &&
        boot_wallet_discover_checkpoint_prepare(r, candidate) &&
        boot_wallet_discover_checkpoint_save(r, candidate) == BOOT_DISCOVER_SAVE_RETRY &&
        wallet_sqlite_discover_checkpoint_read(ctx->wallet_db, &stored) == WALLET_DISCOVER_FOUND &&
        stored.next_height == 10 && wallet_readiness_get(ctx->wallet).state == WALLET_READINESS_PENDING &&
        wallet_sqlite_cutover_read(ctx->wallet_db, &binding) == WALLET_CUTOVER_PENDING;
}
static bool bp_checkpoint_stage_cases(struct boot_cutover_replay *r)
{
    struct wallet_discover_checkpoint candidate;
    if (!bp_checkpoint_stage_before(r, &candidate)) return false;
    boot_stage_advance_to(BOOT_STAGE_CHAIN_TIP_RESOLVED);
    if (!bp_checkpoint_stage_ready(r, &candidate)) return false;
    boot_stage_advance_to(BOOT_STAGE_NETWORK_READY);
    return bp_checkpoint_stage_late(r, &candidate);
}

static void bp_checkpoint_stop_special(int mode, struct boot_cutover_replay *r, event_log_t *log)
{
    if (mode >= 7 && mode <= 9) _exit(bp_checkpoint_stop_save(r, mode) ? 0 : 35);
    if (mode >= 10 && mode <= 13) _exit(bp_checkpoint_stop_digest(r, log, mode) ? 0 : 36);
#if defined(__linux__)
    if (mode == 14) _exit(bp_checkpoint_stop_save(r, mode) ? 0 : 37);
#endif
}

static void bp_checkpoint_special(int mode, struct boot_cutover_replay *r,
                                  struct wallet_rpc_context *ctx,
                                  const struct wallet_cutover_binding *binding,
                                  struct block_index blocks[21], event_log_t *log)
{
    bp_checkpoint_stop_special(mode, r, log);
#if defined(__linux__)
    if (mode == 3) _exit(bp_checkpoint_reauth(r) ? 0 : 31);
    if (mode == 6) _exit(bp_transparent_seeded_skip(ctx, binding, blocks) ? 0 : 34);
#else
    (void)ctx; (void)binding; (void)blocks;
#endif
    if (mode == 4) _exit(bp_checkpoint_bench(r, log) ? 0 : 32);
    if (mode == 1) {
        thread_registry_request_shutdown();
        _exit(bp_checkpoint_save(r) ? 16 : 0);
    }
}

static void bp_checkpoint_child(const char *dir, int mode)
{
    struct node_db *db; struct wallet_sqlite *ws; struct wallet *w; struct main_state *ms;
    boot_wallet_cutover_test_slots(&db, &ws, &w, &ms);
    char path[512]; snprintf(path, sizeof(path), "%s/node.db", dir);
    struct block_index blocks[21] = {0}; struct wallet_cutover_binding binding;
    event_log_t *log = bp_checkpoint_setup(dir, path, db, ws, w, ms, blocks, &binding);
    if (mode != 5) boot_stage_advance_to(BOOT_STAGE_CHAIN_TIP_RESOLVED);
    int64_t auth_deadline = 0;
#if defined(__linux__)
    if (mode == 3 && !bp_checkpoint_seed(ws, w, &auth_deadline)) _exit(30);
    if (mode == 14 && !bp_checkpoint_seed(ws, w, &auth_deadline)) _exit(30);
    if (mode == 6 && !bp_transparent_seed_reload(ws, w, &auth_deadline)) _exit(33);
#endif
    struct wallet_rpc_context ctx = {.wallet = w, .wallet_db = ws, .node_db = db,
                                      .main_state = ms, .datadir = dir};
    struct boot_cutover_replay r = {.ctx = &ctx, .binding = binding,
        .readiness = wallet_readiness_get(w), .floor = 0, .next = 10,
        .phase = BOOT_CUTOVER_DISCOVER};
    r.endpoint.height = 20; r.endpoint.hash = blocks[20].hashBlock;
    r.endpoint.root = blocks[20].hashFinalSaplingRoot;
    r.key_digest[0] = 0x42; r.auth_deadline_ms = auth_deadline;
#if defined(__linux__)
    if (mode == 14 && !bp_checkpoint_key_digest(w, r.key_digest)) _exit(38);
#endif
    if (!wallet_scan_identity(w, r.identity)) _exit(15);
    if (mode == 5) _exit(bp_checkpoint_stage_cases(&r) ? 0 : 33);
    bp_checkpoint_special(mode, &r, &ctx, &binding, blocks, log);
    bp_checkpoint_open_faults(&r, db, path);
    bp_checkpoint_resume_faults(&r, dir, mode);
}
static bool bp_checkpoint_wait(pid_t child, int expected, const char *label, int trace_fd)
{
    int status = 0;
    for (int i = 0; i < 400; ++i) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            bool ok = WIFEXITED(status) && WEXITSTATUS(status) == expected;
            bool observed = bp_stage_report(trace_fd, label, !ok);
            if (ok && !observed) {
                fprintf(stderr, "\nFAIL checkpoint %s: authentication phase observation incomplete\n", label);
                ok = false;
            }
            if (!ok) fprintf(stderr, "\nFAIL checkpoint %s: expected=%d exited=%d code=%d signaled=%d signal=%d\n",
                label, expected, WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            return ok;
        }
        if (result < 0) {
            fprintf(stderr, "\nFAIL checkpoint %s: waitpid errno=%d\n", label, errno);
            return false;
        }
        (void)poll(NULL, 0, 50);
    }
    fprintf(stderr, "\nFAIL checkpoint %s: child timeout after 400 polls of 50 ms\n", label);
    (void)kill(child, SIGKILL); (void)waitpid(child, &status, 0);
    (void)bp_stage_report(trace_fd, label, true); return false;
}
static bool bp_checkpoint_reopen(const char *dir, int expected, bool fixed_digest)
{
    char path[512]; snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db db = {0}; struct wallet_sqlite ws = {0}; struct wallet_discover_checkpoint c;
    bool ok = node_db_open(&db, path) && wallet_sqlite_open_r(&ws, db.db).ok &&
        wallet_sqlite_discover_checkpoint_read(&ws, &c) == WALLET_DISCOVER_FOUND &&
        c.next_height == expected && (!fixed_digest || c.key_digest[0] == 0x42);
    if (ws.open) wallet_sqlite_close(&ws);
    if (db.open) node_db_close(&db);
    return ok;
}
static bool bp_checkpoint_extra(int mode, const char *label)
{
    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "boot_phase", label);
    int trace[2] = {-1, -1};
    if (mode == 6 && socketpair(AF_UNIX, SOCK_DGRAM, 0, trace) == 0) {
        if (fcntl(trace[0], F_SETFL, O_NONBLOCK) != 0 ||
            fcntl(trace[1], F_SETFL, O_NONBLOCK) != 0) {
            close(trace[0]); close(trace[1]); trace[0] = trace[1] = -1;
        }
    }
    pid_t parent = getpid(); pid_t child = fork();
    if (!child) {
        if (trace[0] >= 0) close(trace[0]);
        bp_stage_fd = trace[1];
        bp_stage_emit('c'); /* child entry, before fixture setup */
        if (!os_proc_bind_parent_death(SIGKILL, (uint64_t)parent)) _exit(23);
        bp_checkpoint_child(dir, mode);
    }
    if (trace[1] >= 0) close(trace[1]);
    if (child < 0) fprintf(stderr, "\nFAIL checkpoint %s: fork errno=%d\n", label, errno);
    bool ok = child > 0 && bp_checkpoint_wait(child, 0, label, trace[0]);
    if (trace[0] >= 0) close(trace[0]);
    if (ok && mode == 3) {
        ok = bp_checkpoint_reopen(dir, 10, false);
        if (!ok) fprintf(stderr, "\nFAIL checkpoint %s: reopen expected=10 fixed_digest=0\n", label);
    }
    test_rm_rf(dir); return ok;
}
static bool bp_checkpoint_crash_case(int mode, const char *label, int exit_code, int expected)
{
    char dir[256]; test_make_tmpdir(dir, sizeof(dir), "boot_phase", label);
    pid_t parent = getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, (uint64_t)parent)) _exit(23);
        bp_checkpoint_child(dir, mode);
    }
    if (child < 0) fprintf(stderr, "\nFAIL checkpoint %s: fork errno=%d\n", label, errno);
    bool ok = child > 0 && bp_checkpoint_wait(child, exit_code, label, -1);
    if (ok) {
        ok = bp_checkpoint_reopen(dir, expected, true);
        if (!ok) fprintf(stderr, "\nFAIL checkpoint %s: reopen expected=%d fixed_digest=1\n", label, expected);
    }
    test_rm_rf(dir); return ok;
}
static bool bp_checkpoint_cadence(void)
{
    return boot_test_pending_checkpoint_due(0, 1) &&
        !boot_test_pending_checkpoint_due(100, 30099) &&
        boot_test_pending_checkpoint_due(100, 30100) &&
        !boot_test_pending_checkpoint_due(100, 99) &&
        !boot_test_pending_checkpoint_due(0, 0);
}
static bool bp_checkpoint_stop_cases(void)
{
    bool stop_save = bp_checkpoint_crash_case(7, "checkpoint-stop-save", 0, 10);
    bool stop_rollback = bp_checkpoint_crash_case(8, "checkpoint-stop-rollback", 0, 10);
    bool stop_committed = bp_checkpoint_crash_case(9, "checkpoint-stop-committed", 0, 11);
    bool stop_expired = bp_checkpoint_extra(10, "checkpoint-stop-expired");
    bool stop_io = bp_checkpoint_extra(11, "checkpoint-stop-io");
    bool stop_digest = bp_checkpoint_extra(12, "checkpoint-stop-digest");
    bool stop_bad_end = bp_checkpoint_extra(13, "checkpoint-stop-bad-end");
    return stop_save && stop_rollback && stop_committed && stop_expired && stop_io &&
        stop_digest && stop_bad_end;
}

static int test_boot_discover_checkpoint(void)
{
    if (!bp_checkpoint_cadence()) {
        fprintf(stderr, "\nFAIL checkpoint cadence\n");
        return 1;
    }
    bool ok = bp_checkpoint_crash_case(0, "checkpoint", 77, 10);
    bool committed = bp_checkpoint_crash_case(2, "checkpoint-committed", 78, 11);
    bool stopped = bp_checkpoint_extra(1, "checkpoint-stop");
    ok = ok && committed && stopped;
#if defined(__linux__)
    bool authenticated = bp_checkpoint_extra(3, "checkpoint-reauth");
    bool seeded_skip = bp_checkpoint_extra(6, "seeded-transparent-skip");
    bool encrypted_stop = bp_checkpoint_extra(14, "checkpoint-encrypted-stop");
    ok = ok && authenticated && seeded_skip && encrypted_stop;
#endif
    bool measured = bp_checkpoint_extra(4, "checkpoint-bench");
    bool stages = bp_checkpoint_extra(5, "checkpoint-stage");
    bool stop_cases = bp_checkpoint_stop_cases();
    ok = ok && measured && stages && stop_cases;
    return !ok;
}
#endif

static bool bp_stamp_kind(sqlite3 *db, int kind)
{
    struct consensus_state_install_stamp stamp = {
        .kind = (enum consensus_state_install_stamp_kind)kind, .height = 10,
        .coins_generation = 1,
    };
    return sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK &&
        consensus_state_install_record_authority_stamp(db, &stamp) &&
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK &&
        !boot_legacy_commitment_bootstrap_allowed();
}

static int test_boot_commitment_origin(void)
{
    if (progress_store_db()) return 1;
    bool ok = !boot_legacy_commitment_bootstrap_allowed();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_phase", "commitment-origin");
    ok = ok && progress_store_open(dir) && boot_legacy_commitment_bootstrap_allowed();
    sqlite3 *db = progress_store_db();
    for (int kind = CONSENSUS_INSTALL_STAMP_RECEIPT;
         ok && kind <= CONSENSUS_INSTALL_STAMP_ASSISTED; ++kind)
        ok = bp_stamp_kind(db, kind);
    progress_store_close();
    ok = ok && progress_store_open(dir) && !boot_legacy_commitment_bootstrap_allowed();
    db = progress_store_db();
    const uint8_t malformed = 0;
    ok = ok && progress_meta_set(db, "consensus_state.install_authority", &malformed, 1) &&
        !boot_legacy_commitment_bootstrap_allowed() &&
        sqlite3_exec(db, "DROP TABLE progress_meta", NULL, NULL, NULL) == SQLITE_OK &&
        !boot_legacy_commitment_bootstrap_allowed();
    progress_store_close();
    test_rm_rf(dir);
    return !ok;
}

/* The boot_stage_name() table: pinned names, the (invalid) out-of-range
 * fallbacks, and no gaps across the legal range. */
static int bp_test_boot_stage_names(void)
{
    int failures = 0;

    /* ── name lookup ────────────────────────────────────────────── */
    BP_CHECK("name(INIT) is \"init\"",
        strcmp(boot_stage_name(BOOT_STAGE_INIT), "init") == 0);
    BP_CHECK("name(DB_OPEN) is \"db_open\"",
        strcmp(boot_stage_name(BOOT_STAGE_DB_OPEN), "db_open") == 0);
    BP_CHECK("name(READY) is \"ready\"",
        strcmp(boot_stage_name(BOOT_STAGE_READY), "ready") == 0);
    BP_CHECK("name(SHUTDOWN_COMPLETE) is \"shutdown_complete\"",
        strcmp(boot_stage_name(BOOT_STAGE_SHUTDOWN_COMPLETE),
               "shutdown_complete") == 0);

    /* Negative and >= MAX targets return "(invalid)". */
    BP_CHECK("name(-1) is \"(invalid)\"",
        strcmp(boot_stage_name((enum boot_stage)-1), "(invalid)") == 0);
    BP_CHECK("name(__MAX) is \"(invalid)\"",
        strcmp(boot_stage_name(BOOT_STAGE__MAX), "(invalid)") == 0);

    /* Every legal enum has a non-empty name (no gaps in the table). */
    {
        bool all_named = true;
        for (int s = 0; s < (int)BOOT_STAGE__MAX; s++) {
            const char *n = boot_stage_name((enum boot_stage)s);
            if (!n || !*n || strcmp(n, "(invalid)") == 0) {
                all_named = false;
                break;
            }
        }
        BP_CHECK("every legal stage has a non-empty name", all_named);
    }
    return failures;
}

/* Stage predicates and the legal INIT -> DB_OPEN walk; the caller has
 * already reset the stage to INIT. */
static int bp_test_stage_predicates_and_steps(void)
{
    int failures = 0;

    /* ── current + predicate at INIT ────────────────────────────── */
    BP_CHECK("current() is INIT after reset",
        boot_stage_current() == BOOT_STAGE_INIT);
    BP_CHECK("is(INIT) true at INIT",
        boot_stage_is(BOOT_STAGE_INIT));
    BP_CHECK("is(DB_OPEN) false at INIT",
        !boot_stage_is(BOOT_STAGE_DB_OPEN));

    /* ── idempotent re-advance ──────────────────────────────────── */
    boot_stage_advance_to(BOOT_STAGE_INIT);  /* same stage — no-op */
    BP_CHECK("idempotent re-advance keeps stage at INIT",
        boot_stage_current() == BOOT_STAGE_INIT);

    /* ── forward step ───────────────────────────────────────────── */
    boot_stage_advance_to(BOOT_STAGE_DATADIR_LOCKED);
    BP_CHECK("advance to DATADIR_LOCKED",
        boot_stage_current() == BOOT_STAGE_DATADIR_LOCKED);
    BP_CHECK("is(DATADIR_LOCKED) true after advance",
        boot_stage_is(BOOT_STAGE_DATADIR_LOCKED));
    BP_CHECK("is(INIT) false after advance",
        !boot_stage_is(BOOT_STAGE_INIT));

    boot_stage_advance_to(BOOT_STAGE_CRYPTO_READY);
    boot_stage_advance_to(BOOT_STAGE_DB_OPEN);
    BP_CHECK("step through CRYPTO_READY -> DB_OPEN",
        boot_stage_current() == BOOT_STAGE_DB_OPEN);
    return failures;
}

/* Which mainnet / params-dir / mint-anchor combinations make a ZK params
 * loader-thread failure fatal. */
static int bp_test_params_thread_failure_gating(void)
{
    int failures = 0;

    /* ZK params are consensus-critical on mainnet. If the background loader
     * thread cannot even start, boot must name params_missing and park before
     * CRYPTO_READY rather than silently continuing. */
    BP_CHECK("mainnet params thread failure is fatal",
        boot_test_params_thread_failure_is_fatal(true, true, false));
    BP_CHECK("missing params dir has no thread failure",
        !boot_test_params_thread_failure_is_fatal(false, true, false));
    BP_CHECK("mint-anchor-fast keeps params thread failure nonfatal",
        !boot_test_params_thread_failure_is_fatal(true, true, true));
    BP_CHECK("non-mainnet params thread failure stays warning-only",
        !boot_test_params_thread_failure_is_fatal(true, false, false));
    return failures;
}

/* boot_need_legacy_header_pull(): the empty-datadir trigger and the 90pct
 * ratio trigger. */
static int bp_test_legacy_header_pull_predicates(void)
{
    int failures = 0;

    /* ── boot_need_legacy_header_pull (fresh-datadir need_zcd) ──
     * On an empty datadir the ratio test `local < chain_h*9/10` is `0 < 0`
     * and never fires; an explicit local_index_size == 0 trigger, gated on a
     * legacy source being present, covers it. */
    BP_CHECK("empty datadir + legacy present fires the pull (the fix)",
        boot_need_legacy_header_pull(0, 0, true));
    BP_CHECK("empty datadir + no legacy source does NOT fire",
        !boot_need_legacy_header_pull(0, 0, false));
    BP_CHECK("empty datadir + no legacy source, nonzero chain_h estimate",
        !boot_need_legacy_header_pull(0, 3000000, false));
    BP_CHECK("local at 90pct of chain height does not fire (at threshold)",
        !boot_need_legacy_header_pull(2700000, 3000000, true));
    BP_CHECK("local just below 90pct of chain height fires (ratio trigger)",
        boot_need_legacy_header_pull(2699999, 3000000, true));
    BP_CHECK("local far below chain height fires even with tiny local>0",
        boot_need_legacy_header_pull(3, 3000000, true));
    BP_CHECK("local at chain height does not fire",
        !boot_need_legacy_header_pull(3000000, 3000000, true));
    BP_CHECK("ratio trigger requires legacy source present",
        !boot_need_legacy_header_pull(3, 3000000, false));
    return failures;
}

/* boot_need_blocks_table_hydrate(): the bulk rung, the ratio rung and the
 * stale-small-map case. */
static int bp_test_blocks_table_hydrate_predicates(void)
{
    int failures = 0;

    /* ── boot_need_blocks_table_hydrate (importblockindex determinism) ──
     * The bulk-hydrate rung keys on the blocks-table row count vs the
     * CURRENTLY loaded map size, not the `loaded` flag, so a stale small
     * map never blocks it. */
    BP_CHECK("empty map + blocks table populated fires (fresh datadir "
             "chooses bulk)",
        boot_need_blocks_table_hydrate(0, 3100000));
    BP_CHECK("genesis-only map + blocks table populated fires",
        boot_need_blocks_table_hydrate(1, 3100000));
    BP_CHECK("stale small map (200) far below blocks table fires — the "
             "exact `loaded=true` stale-map defect this closes",
        boot_need_blocks_table_hydrate(200, 3100000));
    BP_CHECK("blocks table empty never fires (nothing to hydrate)",
        !boot_need_blocks_table_hydrate(0, 0));
    BP_CHECK("map at 90pct of blocks table rows does not fire (at threshold)",
        !boot_need_blocks_table_hydrate(2790000, 3100000));
    BP_CHECK("map just below 90pct of blocks table rows fires (ratio "
             "trigger)",
        boot_need_blocks_table_hydrate(2789999, 3100000));
    BP_CHECK("fully-loaded map (warm restart) does not re-fire — preserves "
             "existing warm-datadir behavior",
        !boot_need_blocks_table_hydrate(3100000, 3100000));
    return failures;
}

/* Legal forward jumps: INIT -> READY skipping stages, and shutdown entry
 * from mid-boot through SHUTDOWN_COMPLETE. */
static int bp_test_legal_forward_jumps(void)
{
    int failures = 0;

    /* ── forward-jump (legal, emits WARN) ──────────────────────── */
    boot_stage_reset_for_testing();
    boot_stage_advance_to(BOOT_STAGE_READY);
    BP_CHECK("forward-jump from INIT to READY (skipped intermediate)",
        boot_stage_current() == BOOT_STAGE_READY);

    /* ── shutdown entry from mid-boot ──────────────────────────── */
    boot_stage_reset_for_testing();
    boot_stage_advance_to(BOOT_STAGE_DB_OPEN);
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_REQUESTED);
    BP_CHECK("shutdown can be entered from mid-boot (DB_OPEN)",
        boot_stage_current() == BOOT_STAGE_SHUTDOWN_REQUESTED);

    /* Within the shutdown range, advance to SHUTDOWN_COMPLETE is a normal
     * forward step. */
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_COMPLETE);
    BP_CHECK("advance SHUTDOWN_REQUESTED -> SHUTDOWN_COMPLETE",
        boot_stage_current() == BOOT_STAGE_SHUTDOWN_COMPLETE);
    return failures;
}

#if !defined(_WIN32)
/* Wait for one fork-isolated child and grade its death: it must be SIGABRT.
 * Returns this check's failure count. */
static int bp_check_child_sigabrt(pid_t pid, const char *wait_msg,
                                  const char *abort_msg)
{
    int failures = 0;

    if (pid > 0) {
        int status = 0;
        pid_t got = waitpid(pid, &status, 0);
        BP_CHECK(wait_msg, got == pid);
        BP_CHECK(abort_msg, got == pid && WIFSIGNALED(status) &&
                 WTERMSIG(status) == SIGABRT);
    }
    return failures;
}
#endif

/* Illegal stage moves — a BACKWARD move and an OUT-OF-RANGE target — must
 * abort() in fork-isolated children. */
static int bp_test_illegal_transition_aborts(void)
{
    int failures = 0;

    /* ── illegal transitions abort() (fork-isolated) ─────────────────
     * boot_stage_advance_to() aborts on a BACKWARD move and on an
     * OUT-OF-RANGE target. A forked child (stderr to /dev/null) performs the
     * advance and must die by SIGABRT; a distinct _exit() code means abort()
     * did not fire. */

    /* (a) BACKWARD move: DB_OPEN -> INIT must abort. */
    fflush(stdout);
    fflush(stderr);
    {
#if defined(_WIN32)
        void *hp = test_spawn_self_with_role("test_boot_phase", "bp_backward",
                                             "test-tmp/bp_backward_child.log");
        int wcode = hp ? test_self_child_wait(hp) : -1;
        BP_CHECK("backward move (DB_OPEN -> INIT) aborts via SIGABRT",
                 wcode == 3);
#else
        pid_t pid = fork();
        if (pid == 0) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
            boot_stage_reset_for_testing();           /* -> INIT */
            boot_stage_advance_to(BOOT_STAGE_DB_OPEN); /* legal forward jump */
            boot_stage_advance_to(BOOT_STAGE_INIT);    /* illegal: backward */
            _exit(99); /* reached only if the abort() did NOT fire */
        }
        BP_CHECK("fork backward-move child", pid > 0);
        failures += bp_check_child_sigabrt(pid, "wait backward-move child",
            "backward move (DB_OPEN -> INIT) aborts via SIGABRT");
#endif
    }

    /* (b) OUT-OF-RANGE target: BOOT_STAGE__MAX must abort. */
    fflush(stdout);
    fflush(stderr);
    {
#if defined(_WIN32)
        void *hp = test_spawn_self_with_role("test_boot_phase", "bp_range",
                                             "test-tmp/bp_range_child.log");
        int wcode = hp ? test_self_child_wait(hp) : -1;
        BP_CHECK("out-of-range target (__MAX) aborts via SIGABRT",
                 wcode == 3);
#else
        pid_t pid = fork();
        if (pid == 0) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
            boot_stage_reset_for_testing();              /* -> INIT */
            boot_stage_advance_to(BOOT_STAGE__MAX);       /* illegal: >= MAX */
            _exit(99); /* reached only if the abort() did NOT fire */
        }
        BP_CHECK("fork out-of-range child", pid > 0);
        failures += bp_check_child_sigabrt(pid, "wait out-of-range child",
            "out-of-range target (__MAX) aborts via SIGABRT");
#endif
    }
    return failures;
}

/* boot_step_classify(): the running/slow/stuck boundaries, the verdict
 * strings, and that the clock alone cannot manufacture a failure. */
static int bp_test_step_classification(void)
{
    int failures = 0;

    /* ── boot step reporter: slow, stuck, and failed are three states ──
     *
     * Anti-centralization property: no elapsed time, however large, may
     * produce a failure verdict (slow HDD nodes must not be graded off the
     * network). Failure is reported by the step, never inferred from the
     * clock. */
    {
        const int64_t B = BOOT_STEP_BUDGET_MS;

        /* Under budget: nothing is wrong. */
        BP_CHECK("step: inside budget is running",
            boot_step_classify(B - 1, B, 0) == BOOT_STEP_RUNNING);
        BP_CHECK("step: inside budget with progress is still running",
            boot_step_classify(0, B, 9) == BOOT_STEP_RUNNING);

        /* Over budget WITH progress: slow. The HDD case. */
        enum boot_step_state slow = boot_step_classify(B * 20, B, 7);
        BP_CHECK("step: 20x over budget but progressing is slow",
            slow == BOOT_STEP_SLOW);
        BP_CHECK("step: slow is NOT a failure",
            !boot_step_state_is_failure(slow));
        BP_CHECK("step: slow carries verdict=telemetry",
            strcmp(boot_step_state_verdict(slow), "telemetry") == 0);
        BP_CHECK("step: slow is not spelled the same as failed",
            strcmp(boot_step_state_name(slow),
                   boot_step_state_name(BOOT_STEP_FAILED)) != 0);

        /* Over budget WITHOUT progress: stuck, still only an observation. */
        enum boot_step_state stuck = boot_step_classify(B * 20, B, 0);
        BP_CHECK("step: over budget with no progress is stuck",
            stuck == BOOT_STEP_STUCK);
        BP_CHECK("step: stuck is distinguishable from slow", stuck != slow);
        BP_CHECK("step: stuck is NOT a failure either",
            !boot_step_state_is_failure(stuck));
        BP_CHECK("step: stuck carries verdict=telemetry",
            strcmp(boot_step_state_verdict(stuck), "telemetry") == 0);

        /* The clock can never manufacture a failure. */
        {
            bool clock_can_fail = false;
            const int64_t elapsed[] = {
                0, B, B + 1, 3600LL * 1000, 86400LL * 1000, INT64_MAX / 2,
            };
            for (size_t i = 0; i < sizeof(elapsed) / sizeof(elapsed[0]); i++)
                for (uint64_t d = 0; d < 3; d++)
                    if (boot_step_state_is_failure(
                            boot_step_classify(elapsed[i], B, d)))
                        clock_can_fail = true;
            BP_CHECK("step: no elapsed time can produce a failure verdict",
                !clock_can_fail);
        }

        /* Failure is its own state, reported explicitly. */
        BP_CHECK("step: failed is the only failure state",
            boot_step_state_is_failure(BOOT_STEP_FAILED) &&
            !boot_step_state_is_failure(BOOT_STEP_DONE) &&
            !boot_step_state_is_failure(BOOT_STEP_RUNNING));
        BP_CHECK("step: failed carries verdict=failure",
            strcmp(boot_step_state_verdict(BOOT_STEP_FAILED),
                   "failure") == 0);
        BP_CHECK("step: done carries verdict=ok",
            strcmp(boot_step_state_verdict(BOOT_STEP_DONE), "ok") == 0);

        /* A budget of zero must not divide by, or fall back into, chaos. */
        BP_CHECK("step: zero budget falls back to the default budget",
            boot_step_classify(BOOT_STEP_BUDGET_MS + 1, 0, 1) ==
                BOOT_STEP_SLOW);
    }
    return failures;
}

/* The boot_step_state_name() table: every state distinct and non-empty,
 * out-of-range named "(invalid)". */
static int bp_test_step_state_names(void)
{
    int failures = 0;

    /* Every state has a distinct, non-empty name; out-of-range is named. */
    {
        bool all_named = true;
        for (int s = 0; s < (int)BOOT_STEP_STATE__MAX; s++) {
            const char *n = boot_step_state_name((enum boot_step_state)s);
            if (!n || !*n || strcmp(n, "(invalid)") == 0)
                all_named = false;
            for (int t = s + 1; t < (int)BOOT_STEP_STATE__MAX; t++)
                if (strcmp(n, boot_step_state_name(
                               (enum boot_step_state)t)) == 0)
                    all_named = false;
        }
        BP_CHECK("step: every state has a distinct non-empty name",
            all_named);
        BP_CHECK("step: out-of-range state names as (invalid)",
            strcmp(boot_step_state_name(BOOT_STEP_STATE__MAX),
                   "(invalid)") == 0);
    }
    return failures;
}

/* The tracked-step API must be safe when no step is open. */
static int bp_test_step_api_with_no_step_open(void)
{
    int failures = 0;

    /* The tracked-step API is safe with no step open; boot_step_fail
     * always returns false. */
    boot_step_done();                 /* nothing open — no-op */
    boot_step_note();
    BP_CHECK("step: fail() returns false even with no step open",
        !boot_step_fail("nothing open"));
    return failures;
}

/* Which step states earn more systemd start budget: only moving ones. */
static int bp_test_step_budget_earning(void)
{
    int failures = 0;

    /* ── An extension must be EARNED ──────────────────────────────
     * The reporter re-arms every budget window, so a state that extends the
     * systemd start deadline extends it forever; only a moving step may earn
     * it, or Restart=always never gets its turn. These pin the rule at the
     * seam boot_step_emit() consults. */
    {
        BP_CHECK("budget: SLOW earns more start budget (moving, just slow)",
            boot_step_state_earns_budget(BOOT_STEP_SLOW));
        BP_CHECK("budget: RUNNING earns more start budget",
            boot_step_state_earns_budget(BOOT_STEP_RUNNING));
        BP_CHECK("budget: STUCK earns NOTHING — zero progress must not "
                 "push the deadline out",
            !boot_step_state_earns_budget(BOOT_STEP_STUCK));
        BP_CHECK("budget: FAILED earns nothing",
            !boot_step_state_earns_budget(BOOT_STEP_FAILED));
        BP_CHECK("budget: DONE earns nothing",
            !boot_step_state_earns_budget(BOOT_STEP_DONE));

        /* The only way to reach non-earning STUCK is genuine zero progress. */
        BP_CHECK("budget: over budget WITH progress stays earning",
            boot_step_state_earns_budget(
                boot_step_classify(3600000, BOOT_STEP_BUDGET_MS, 1)));
        BP_CHECK("budget: over budget with ZERO progress stops earning",
            !boot_step_state_earns_budget(
                boot_step_classify(3600000, BOOT_STEP_BUDGET_MS, 0)));
        BP_CHECK("budget: under budget always earning",
            boot_step_state_earns_budget(
                boot_step_classify(1, BOOT_STEP_BUDGET_MS, 0)));
        /* A non-earning state is still REPORTED; only the budget is
         * conditional. */
        BP_CHECK("budget: STUCK still reports as telemetry, not failure",
            strcmp(boot_step_state_verdict(BOOT_STEP_STUCK),
                   "telemetry") == 0 &&
            !boot_step_state_is_failure(BOOT_STEP_STUCK));
    }
    return failures;
}

/* The out-of-band evidence probe: EXTEND_TIMEOUT_USEC is sent only when the
 * probe's value moved during the window. */
static int bp_test_step_evidence_probe(void)
{
    int failures = 0;

    /* ── out-of-band evidence probe for an OPAQUE step ─────────────
     *
     * node.db's open ceremony (WAL recovery, quick_check) is blocking calls
     * that cannot call boot_step_note(). The step is reported over the real
     * NOTIFY_SOCKET path and the EXTEND_TIMEOUT_USEC datagram appears ONLY
     * when the probe's value changed during the window. Negative controls:
     * (1) no probe -> STUCK, no datagram; (2) probe installed but not
     * moving -> still STUCK. */
    {
        boot_stage_reset_for_testing();

#if !defined(_WIN32)
        char sock_name[256];
        char sock_dir[256];
        int fd = bp_bind_notify_socket(sock_name, sizeof(sock_name),
                                       sock_dir, sizeof(sock_dir));
        BP_CHECK("evidence: notify socket bound", fd >= 0);

        if (fd >= 0) {
            setenv("NOTIFY_SOCKET", sock_name, 1);
            sd_notify_reset_for_testing();
            BP_CHECK("evidence: sd_notify active for this fixture",
                sd_notify_init() && sd_notify_is_active());

            /* ── NEGATIVE CONTROL 1: opaque step, no probe ───────── */
            boot_step_enter("test.opaque_no_probe");
            bp_drain(fd);   /* discard the BEGIN record's own traffic */
            enum boot_step_state st =
                boot_step_stall_report_for_testing(BOOT_STEP_BUDGET_MS * 2);
            BP_CHECK("evidence[-]: opaque step with no probe grades STUCK",
                st == BOOT_STEP_STUCK);
            BP_CHECK("evidence[-]: STUCK sends NO EXTEND_TIMEOUT_USEC",
                !bp_saw_extend(fd));
            boot_step_done();

            /* ── NEGATIVE CONTROL 2: probe installed, not moving ──── */
            g_bp_fake_evidence = 7;
            boot_step_enter("test.opaque_probe_frozen");
            boot_step_set_evidence_probe(bp_fake_evidence_probe, NULL);
            bp_drain(fd);
            st = boot_step_stall_report_for_testing(BOOT_STEP_BUDGET_MS * 2);
            BP_CHECK("evidence[-]: a probe that does NOT move still "
                     "grades STUCK (presence is not evidence)",
                st == BOOT_STEP_STUCK);
            BP_CHECK("evidence[-]: frozen probe sends NO "
                     "EXTEND_TIMEOUT_USEC",
                !bp_saw_extend(fd));
            boot_step_done();

            /* ── POSITIVE: the same step, probe moving ───────────── */
            boot_step_enter("test.opaque_probe_moving");
            boot_step_set_evidence_probe(bp_fake_evidence_probe, NULL);
            bp_drain(fd);
            g_bp_fake_evidence++;   /* the disk did a unit of work */
            st = boot_step_stall_report_for_testing(BOOT_STEP_BUDGET_MS * 2);
            BP_CHECK("evidence[+]: a probe that MOVED grades SLOW, "
                     "not STUCK",
                st == BOOT_STEP_SLOW);
            BP_CHECK("evidence[+]: SLOW sends EXTEND_TIMEOUT_USEC — the "
                     "slow box keeps its start budget",
                bp_saw_extend(fd));
            boot_step_done();

            /* ── the probe is scoped to the step ─────────────────── */
            g_bp_fake_evidence = 0;
            boot_step_enter("test.after_close");
            bp_drain(fd);
            g_bp_fake_evidence += 1000;  /* would be evidence if still armed */
            st = boot_step_stall_report_for_testing(BOOT_STEP_BUDGET_MS * 2);
            BP_CHECK("evidence: closing a step disarms its probe — it "
                     "cannot leak into the next step",
                st == BOOT_STEP_STUCK);
            boot_step_done();

            /* ── installing a probe is not itself progress ────────── */
            g_bp_fake_evidence = 1000000;   /* large absolute history */
            boot_step_enter("test.install_is_not_progress");
            boot_step_set_evidence_probe(bp_fake_evidence_probe, NULL);
            bp_drain(fd);
            st = boot_step_stall_report_for_testing(BOOT_STEP_BUDGET_MS * 2);
            BP_CHECK("evidence: installing a probe re-seeds the baseline "
                     "— pre-step I/O is not this step's progress",
                st == BOOT_STEP_STUCK);
            boot_step_done();

            close(fd);
            unsetenv("NOTIFY_SOCKET");
            sd_notify_reset_for_testing();
            if (sock_dir[0])
                test_rm_rf(sock_dir);
        }
#else
        printf("boot_phase: SKIP (Windows): sd_notify EXTEND_TIMEOUT_USEC "
               "evidence probe — no abstract AF_UNIX namespace and no "
               "systemd notify socket on this lane\n");
#endif

        /* The stock probe is real, non-blocking, and observes this
         * process's own block I/O: fsync makes ru_oublock move. */
        {
            uint64_t before = boot_evidence_probe_process_io(NULL);
            BP_CHECK("evidence: stock process-io probe wrote real I/O",
                bp_burn_block_io(4 * BOOT_EVIDENCE_IO_QUANTUM_BYTES));
            uint64_t after = boot_evidence_probe_process_io(NULL);
            BP_CHECK("evidence: stock process-io probe advances after "
                     "≥1 MiB of fsynced block I/O",
                after > before);
        }

        /* No step must be left open for the tests that run after this. */
        boot_step_done();
    }
    return failures;
}

#if !defined(_WIN32)
static bool bp_pending_fence(struct node_db *ndb, bool write)
{
    struct wallet_sqlite ws = {0};
    if (!wallet_sqlite_open_r(&ws, ndb->db).ok) return false;
    struct wallet_cutover_binding binding = {
        .old_generation_present = true, .old_generation = 1,
        .old_height = 10, .target_height = 20,
    };
    binding.old_hash[0] = 1; binding.target_hash[0] = 2; binding.artifact_digest[0] = 3;
    bool ok;
    if (write) {
        struct wallet *w = calloc(1, sizeof(*w));
        if (w) {
            wallet_init(w);
            w->scan_retry.pending = true; w->scan_retry.from = 5;
            w->scan_retry.since = 123; w->best_block_height = 10;
            snprintf(w->scan_retry.blocker, sizeof(w->scan_retry.blocker), "CUTOVER");
            ok = wallet_sqlite_cutover_prepare(&ws, w, &binding);
            wallet_free(w); free(w);
        } else ok = false;
    } else {
        struct wallet_cutover_binding got;
        ok = wallet_sqlite_cutover_read(&ws, &got) == WALLET_CUTOVER_PENDING &&
            got.old_generation_present && got.old_generation == 1 &&
            got.old_height == 10 && got.target_height == 20 &&
            got.old_hash[0] == 1 && got.target_hash[0] == 2 && got.artifact_digest[0] == 3;
    }
    wallet_sqlite_close(&ws);
    return ok;
}

static bool bp_pending_stores_persist(const char *dir, struct node_db *ndb,
    struct coins_view_sqlite *coins, struct block_tree_db *tree, bool opened)
{
    bool value = false;
    bool ok = opened && coins->db && tree->db.db &&
        !boot_test_pending_runtime_stores_open(dir, ndb, coins, tree) &&
        block_tree_db_write_flag(tree, "pending-runtime-fixture", true);
    if (opened) {
        block_tree_db_close(tree);
        coins_view_sqlite_close(coins);
    }
    memset(tree, 0, sizeof(*tree));
    memset(coins, 0, sizeof(*coins));
    bool reopened = ok && boot_test_pending_runtime_stores_open(dir, ndb, coins, tree);
    ok = reopened && block_tree_db_read_flag(tree, "pending-runtime-fixture", &value) && value;
    if (reopened) {
        block_tree_db_close(tree);
        coins_view_sqlite_close(coins);
    }
    return ok;
}

static bool bp_pending_block_second(const char *blocks, struct node_db *ndb,
                                    struct coins_view_sqlite *coins)
{
    bool ok = coins_view_sqlite_open(coins, ndb->db);
    if (ok) coins_view_sqlite_close(coins);
    memset(coins, 0, sizeof(*coins));
    int fd = open(blocks, O_CREAT | O_WRONLY | O_EXCL, 0600);
    ok = ok && fd >= 0;
    if (fd >= 0) close(fd);
    return ok;
}

static bool bp_pending_open_failed(bool setup, bool opened, struct node_db *ndb,
    struct coins_view_sqlite *coins, struct block_tree_db *tree)
{
    bool ok = setup && !opened && !coins->db && !tree->db.db && ndb->open;
    if (opened) {
        block_tree_db_close(tree);
        coins_view_sqlite_close(coins);
    }
    return ok;
}

static bool bp_pending_stores_case(bool block_second_open)
{
    char dir[256], dbpath[320], blocks[320];
    test_make_tmpdir(dir, sizeof(dir), "boot_phase", block_second_open ? "stores-fail" : "stores-ok");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    struct node_db ndb = {0};
    struct coins_view_sqlite coins = {0};
    struct block_tree_db tree = {0};
    bool db_open = node_db_open(&ndb, dbpath);
    bool setup = db_open && bp_pending_fence(&ndb, true);
    if (setup && block_second_open)
        setup = bp_pending_block_second(blocks, &ndb, &coins);
    bool opened = setup && boot_test_pending_runtime_stores_open(dir, &ndb, &coins, &tree);
    bool ok;
    if (block_second_open) {
        ok = bp_pending_open_failed(setup, opened, &ndb, &coins, &tree);
    } else {
        ok = bp_pending_stores_persist(dir, &ndb, &coins, &tree, opened);
    }
    ok = ok && bp_pending_fence(&ndb, false);
    if (ndb.open) node_db_close(&ndb);
    test_rm_rf(dir);
    return ok;
}
#endif

#if !defined(_WIN32)
bool boot_test_pending_history_open(const struct app_context *,
    const struct wallet_witness_endpoint *);

static bool bp_pending_history_refusals(void)
{
    char dir[256], archive[320];
    test_make_tmpdir(dir, sizeof(dir), "boot_phase", "pending-history");
    snprintf(archive, sizeof(archive), "%s/wallet-history", dir);
    struct app_context ctx = {.datadir = dir};
    struct wallet_witness_endpoint endpoint = {.height = 28};
    endpoint.hash.data[0] = 1;
    bool ok = !boot_test_pending_history_open(&ctx, &endpoint) &&
        mkdir(archive, 0700) == 0 && !boot_test_pending_history_open(&ctx, &endpoint);
    return test_rm_rf_recursive(dir) == 0 && ok;
}

static bool bp_pending_modes(void)
{
    struct app_context ctx = {0};
    if (!boot_pending_mode_supported_test(&ctx)) return false;
    ctx.no_services = true;
    if (!boot_pending_mode_supported_test(&ctx)) return false;
    bool *modes[] = {&ctx.mint_anchor, &ctx.full_fold, &ctx.reindex_chainstate,
        &ctx.ratify_mint_anchor, &ctx.reindex_explorer, &ctx.backfill_zslp,
        &ctx.backfill_nullifiers, &ctx.refold_staged, &ctx.refold_from_anchor,
        &ctx.verify_rom, &ctx.export_consensus_bundle, &ctx.reimport_utxos};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        *modes[i] = true;
        bool refused = !boot_pending_mode_supported_test(&ctx);
        *modes[i] = false;
        if (!refused) return false;
    }
    const char **paths[] = {&ctx.snapshot_dir, &ctx.verify_consensus_bundle,
                           &ctx.promote_shielded_history};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        *paths[i] = "fixture";
        bool refused = !boot_pending_mode_supported_test(&ctx);
        *paths[i] = NULL;
        if (!refused) return false;
    }
    return boot_pending_mode_supported_test(&ctx);
}

#endif
#if defined(__linux__)
static bool bp_auth_read_request(int fd)
{
    unsigned char req[8]; size_t off = 0;
    while (off < sizeof(req)) {
        ssize_t n = read(fd, req + off, sizeof(req) - off);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    const unsigned char want[8] = {0x5a,0x57,0x41,0x31, Z23_WALLET_AUTH_REQUEST, 0, 0, 0};
    return memcmp(req, want, sizeof(req)) == 0;
}
static void bp_auth_peer(int fd, int mode)
{
    alarm(5);
    if (!bp_auth_read_request(fd)) _exit(2);
    unsigned char frame[11] = {0x5a,0x57,0x41,0x31, Z23_WALLET_AUTH_SECRET, 0, 3, 0, 0x61,0x62,0x63};
    if (mode == 1) { frame[4] = Z23_WALLET_AUTH_CANCEL; frame[6] = 0; }
    if (mode == 2) frame[0] = 0x58;
    if (mode == 3) frame[9] = 0;
    if (mode == 4) frame[6] = 5;
    if (mode == 5) { sleep(1); _exit(0); }
    if (mode == 6) { frame[6] = 1; frame[7] = 2; }
    size_t count = mode == 1 || mode == 6 ? 8 : sizeof(frame);
    _exit(write(fd, frame, count) == (ssize_t)count ? 0 : 3);
}
static bool bp_auth_case(int mode)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return false;
    pid_t pid = fork();
    if (pid == 0) { close(pair[0]); bp_auth_peer(pair[1], mode); }
    close(pair[1]);
    if (pid < 0) { close(pair[0]); return false; }
    char secret[Z23_WALLET_AUTH_SECRET_MAX + 1]; memset(secret, 0x5a, sizeof(secret));
    bool received = platform_wallet_startup_auth_receive(pair[0], mode == 5 ? 50 : 3000,
                                                          secret, sizeof(secret));
    int status = 0;
    bool child = waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    bool cleared = true;
    for (size_t i = 0; i < sizeof(secret); i++) if (secret[i]) cleared = false;
    return child && (mode == 0 ? received && !strcmp(secret, "abc") : !received && cleared);
}
static int bp_auth_transport_checks(void)
{
    int failures = 0;
    BP_CHECK("startup auth receives a framed secret", bp_auth_case(0));
    BP_CHECK("startup auth cancellation refuses and wipes", bp_auth_case(1));
    BP_CHECK("startup auth malformed frame refuses and wipes", bp_auth_case(2));
    BP_CHECK("startup auth embedded NUL refuses and wipes", bp_auth_case(3));
    BP_CHECK("startup auth truncated frame refuses and wipes", bp_auth_case(4));
    BP_CHECK("startup auth timeout refuses and wipes", bp_auth_case(5));
    BP_CHECK("startup auth oversized frame refuses and wipes", bp_auth_case(6));
    int pipefd[2]; char secret[16]; memset(secret, 0x5a, sizeof(secret));
    bool opened = pipe(pipefd) == 0;
    bool denied = opened && !platform_wallet_startup_auth_receive(pipefd[0], 50, secret, sizeof(secret));
    if (opened) close(pipefd[1]);
    BP_CHECK("startup auth rejects non-socket descriptor", denied && secret[0] == 0);
    return failures;
}
#endif


#if !defined(__linux__) && !defined(_WIN32)
static int bp_auth_unsupported_close_checks(void)
{
    int failures = 0, pair[2]; char out[4] = {1};
    bool opened = pipe(pair) == 0;
    bool refused = opened && !platform_wallet_startup_auth_receive(pair[0], 50, out, sizeof(out));
    bool closed = opened && fcntl(pair[0], F_GETFD) == -1 && errno == EBADF;
    if (opened) close(pair[1]);
    BP_CHECK("unsupported startup auth closes descriptor and wipes", refused && closed && out[0] == 0);
    return failures;
}
#endif

#ifdef ZCL_TESTING
bool boot_test_replay_progress_format(const struct boot_cutover_replay *, char *, size_t);
static int bp_replay_progress_checks(void)
{
    int failures = 0;
    char line[160];
    struct boot_cutover_replay replay = {.phase = BOOT_CUTOVER_DISCOVER, .floor = 5, .next = 9};
    replay.endpoint.height = 20;
    BP_CHECK("replay progress reports first incomplete height",
        boot_test_replay_progress_format(&replay, line, sizeof(line)) &&
        strcmp(line, "[wallet-replay] phase=discover floor=5 next=9 reference=20") == 0);
    replay.phase = BOOT_CUTOVER_WITNESS;
    BP_CHECK("replay witness uses its phase label", boot_test_replay_progress_format(&replay, line, sizeof(line)) &&
        strstr(line, "phase=witness") != NULL);
    replay.next = 22;
    BP_CHECK("replay progress rejects beyond endpoint", !boot_test_replay_progress_format(&replay, line, sizeof(line)));
    replay.next = 5; replay.phase = BOOT_CUTOVER_DONE;
    BP_CHECK("replay progress never reports done as ready", !boot_test_replay_progress_format(&replay, line, sizeof(line)));
    return failures;
}
#endif

int test_boot_phase(void)
{
#if defined(_WIN32)
    /* Re-exec'd child lanes for the illegal-transition abort cases (Windows
     * has no fork()). UCRT abort() exits with code 3, the analogue of
     * WTERMSIG==SIGABRT. */
    const char *fork_role = getenv("ZCL_TEST_FORK_ROLE");
    if (fork_role && fork_role[0]) {
        zcl_win_suppress_abort_dialog();
        if (strcmp(fork_role, "bp_backward") == 0) {
            boot_stage_reset_for_testing();            /* -> INIT */
            boot_stage_advance_to(BOOT_STAGE_DB_OPEN); /* legal forward jump */
            boot_stage_advance_to(BOOT_STAGE_INIT);    /* illegal: backward */
            return 99; /* reached only if the abort() did NOT fire */
        }
        if (strcmp(fork_role, "bp_range") == 0) {
            boot_stage_reset_for_testing();            /* -> INIT */
            boot_stage_advance_to(BOOT_STAGE__MAX);    /* illegal: >= MAX */
            return 99; /* reached only if the abort() did NOT fire */
        }
        return 97;
    }
#endif
    printf("\n=== boot_phase tests ===\n");
    int failures = 0;
#ifdef ZCL_TESTING
    failures += bp_replay_progress_checks();
#endif
#if !defined(_WIN32)
    BP_CHECK("pending startup refuses maintenance modes", bp_pending_modes());
    BP_CHECK("pending history rejects missing or invalid archive", bp_pending_history_refusals());
    BP_CHECK("pending runtime stores persist and reopen", bp_pending_stores_case(false));
    BP_CHECK("pending block-tree failure closes coins view", bp_pending_stores_case(true));
#endif
    BP_CHECK("event log publishes once, reuses its handle and retires cleanly",
        test_boot_event_log_lifecycle() == 0);
    BP_CHECK("replay preserves coins provenance through log lifetime",
        test_boot_replay_provenance() == 0);
#if defined(ZCL_TESTING) && !defined(_WIN32)
    BP_CHECK("DISCOVER checkpoint crash, expiry, prefix and stop", test_boot_discover_checkpoint() == 0);
#endif
    BP_CHECK("installed provenance refuses legacy commitment bootstrap",
        test_boot_commitment_origin() == 0);

    boot_stage_reset_for_testing();

    BP_CHECK("wallet rebuild skips no-key wallets, preserves keyed wallets, "
             "and fails closed",
        test_wallet_rebuild_probe() == 0);

#if defined(__linux__)
    failures += bp_auth_transport_checks();
#elif !defined(_WIN32)
    failures += bp_auth_unsupported_close_checks();
#endif
    failures += bp_test_boot_stage_names();
    failures += bp_test_stage_predicates_and_steps();
    failures += bp_test_params_thread_failure_gating();
#if !defined(_WIN32)
    BP_CHECK("published verifier does not wait for blocked prover worker",
             bp_test_params_ready_boundary() == 0);
    BP_CHECK("unpublished verifier retains worker join",
             bp_params_barrier_case(false, true, false, false, false, true) == 0);
    BP_CHECK("missing PHGR key retains worker join",
             bp_params_barrier_case(true, false, false, false, false, true) == 0);
    BP_CHECK("failed worker retains join and false completion",
             bp_params_barrier_case(false, false, false, false, false, false) == 0);
    BP_CHECK("steady sandbox retains worker join",
             bp_params_barrier_case(true, true, true, false, false, true) == 0);
    BP_CHECK("strict confinement retains worker join",
             bp_params_barrier_case(true, true, false, true, false, true) == 0);
#if BP_SANITIZED_BUILD
    /* A self-join is not representable under ASan or TSan: their pthread_join
     * interceptors look the target up in a thread registry and abort on an
     * internal CHECK (null thread) before the real EDEADLK is returned, for
     * the initial thread and for a pthread_create thread alike. The plain
     * build still runs and asserts the case. */
    printf("boot_phase: failed params join retains loader ownership and reports false... SKIP (sanitizer pthread_join interceptor aborts on self-join)\n");
#else
    BP_CHECK("failed params join retains loader ownership and reports false",
             bp_test_params_join_failure_retains_ownership() == 0);
#endif
#endif

    /* ── export mode must not park on a permanent blocker ─────────
     * Shutdown is already requested so a missing export-mode branch cannot
     * sleep; the assertions distinguish REFUSED from PARKED. */
    {
        char dir[PATH_MAX];
        char captured[4096];
        bool gate_rc = true;
        struct boot_status_snapshot snap;
        char why[128];

        bp_park_fixture_begin(dir, sizeof(dir), true);
        bool captured_ok = bp_capture_gate(dir, captured, sizeof(captured),
                                           &gate_rc);
        bool status_ok = boot_status_read(dir, &snap, why, sizeof(why));
        BP_CHECK("export+node_db_unopened: gate returns (does not park)",
                 captured_ok && !gate_rc);
        BP_CHECK("export+node_db_unopened: REFUSED line names the blocker",
                 captured_ok &&
                 strstr(captured,
                        "REFUSED: -export-consensus-bundle: reason=node_db_unopened")
                     != NULL);
        BP_CHECK("export+node_db_unopened: does not emit PARKED",
                 captured_ok && strstr(captured, "PARKED") == NULL);
        BP_CHECK("export+node_db_unopened: latches FATAL (exit 1 path)",
                 boot_error_reported());
        BP_CHECK("export+node_db_unopened: boot_status names the blocker",
                 status_ok && strcmp(snap.blocker, "node_db_unopened") == 0);
        bp_park_fixture_end(dir);
    }

    failures += bp_node_db_gate_refuses();
    failures += bp_legacy_snapshot_keeps_source_lock();
    failures += bp_test_legacy_header_pull_predicates();
    failures += bp_test_blocks_table_hydrate_predicates();
    failures += bp_test_legal_forward_jumps();
    failures += bp_test_illegal_transition_aborts();
    failures += bp_test_step_classification();
    failures += bp_test_step_state_names();
    failures += bp_test_step_api_with_no_step_open();
    failures += bp_test_step_budget_earning();
    failures += bp_test_step_evidence_probe();

    /* Evidence scoped to one thread — its own function, so this one stays
     * inside the complexity cap. */
    failures += bp_test_thread_io_evidence();

    /* Restore for any subsequent tests in this process. */
    boot_stage_reset_for_testing();
    return failures;
}

/* ── evidence scoped to ONE thread ───────────────────────────────────
 *
 * The process-wide probe is honest only when the step is the process's only
 * I/O source; svc.init_wallet runs beside other threads, so it needs the
 * thread-scoped probe. These fixtures pin the difference on the SAME I/O. */
#if defined(__linux__)
struct bp_io_burner {
    size_t bytes;
    bool   ok;
};

static void *bp_io_burner_entry(void *arg)
{
    struct bp_io_burner *b = (struct bp_io_burner *)arg;
    b->ok = bp_burn_block_io(b->bytes);
    return NULL;
}
#endif

static int bp_test_thread_io_evidence(void)
{
    int failures = 0;
#if defined(__linux__)
    boot_step_enter("test.thread_io");
    boot_step_set_thread_io_evidence_probe();

    /* (1) The probe is live and observes THIS thread (must work on Linux). */
    uint64_t self_before = boot_evidence_probe_thread_io(NULL);
    BP_CHECK("thread-io: this thread's own fsynced I/O IS evidence",
        bp_burn_block_io(4 * BOOT_EVIDENCE_IO_QUANTUM_BYTES) &&
        boot_evidence_probe_thread_io(NULL) > self_before);

    /* (2) Another thread's I/O is NOT this step's evidence, while the
     * process-wide probe counts it. */
    uint64_t t0 = boot_evidence_probe_thread_io(NULL);
    uint64_t p0 = boot_evidence_probe_process_io(NULL);
    struct bp_io_burner burner = {
        .bytes = 8 * BOOT_EVIDENCE_IO_QUANTUM_BYTES, .ok = false };
    pthread_t th;
    int rc = pthread_create(&th, NULL, bp_io_burner_entry, &burner);
    BP_CHECK("thread-io: burner thread spawned", rc == 0);
    if (rc == 0)
        pthread_join(th, NULL);
    BP_CHECK("thread-io: the burner thread really wrote to a disk",
        burner.ok);
    uint64_t t1 = boot_evidence_probe_thread_io(NULL);
    uint64_t p1 = boot_evidence_probe_process_io(NULL);
    BP_CHECK("thread-io: 8 MiB written by ANOTHER thread is not this "
             "step's progress",
        t1 - t0 < 4);
    BP_CHECK("thread-io: the process-wide probe DOES count it — why a "
             "multi-threaded step must not use that probe",
        p1 - p0 >= 4);

    /* (3) The grade that follows: a step over budget whose own thread is
     * working is SLOW (keeps its start budget), never STUCK. */
    BP_CHECK("thread-io: own-thread work grades SLOW, not STUCK",
        boot_step_classify(BOOT_STEP_BUDGET_MS * 2, BOOT_STEP_BUDGET_MS, 1)
            == BOOT_STEP_SLOW &&
        boot_step_classify(BOOT_STEP_BUDGET_MS * 2, BOOT_STEP_BUDGET_MS, 0)
            == BOOT_STEP_STUCK);
    boot_step_done();
#else
    printf("boot_phase: SKIP (no per-thread kernel counters on this "
           "platform): thread-scoped I/O evidence probe is inert by "
           "design\n");
#endif
    return failures;
}
