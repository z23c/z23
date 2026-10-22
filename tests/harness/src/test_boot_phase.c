/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the boot-stage state machine (platform/modules/util/src/boot_phase.c).
 *
 * boot_stage_advance_to() aborts on backward or out-of-range moves, so those
 * are tested only in fork-isolated children; the rest covers legal
 * transitions, idempotent re-advance, name lookup and the predicates.
 * boot_stage_reset_for_testing() (-DZCL_TESTING) restores the global stage. */

#include "test/test_core.h"
#include "platform/socket_compat.h"
#include "config/boot.h"
#include "config/boot_error.h"
#include "config/boot_internal.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/boot_status.h"
#include "util/thread_registry.h"
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include <sqlite3.h>
#include "util/sd_notify.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#endif
#if defined(__linux__)
#include <sys/vfs.h>
#include <linux/magic.h>
#endif
#include <unistd.h>
#include <fcntl.h>

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
static int bp_test_thread_io_evidence(void);  /* end of file */
static int test_boot_event_log_lifecycle(void)
{
    if (progress_store_db() || event_log_singleton())
        return 1;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_phase", "event-log");
    bool rejects_missing = !boot_ensure_event_log(NULL) && !boot_ensure_event_log("");
    bool opened = boot_ensure_event_log(dir);
    event_log_t *first = event_log_singleton();
    bool reused = opened && first && boot_ensure_event_log(dir) && event_log_singleton() == first;
    boot_stop_projection_storage();
    bool retired = event_log_singleton() == NULL && progress_store_db() == NULL;
    test_rm_rf(dir);
    return !(rejects_missing && reused && retired);
}

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
    BP_CHECK("event log publishes once, reuses its handle and retires cleanly",
        test_boot_event_log_lifecycle() == 0);

    boot_stage_reset_for_testing();

    BP_CHECK("wallet rebuild skips no-key wallets, preserves keyed wallets, "
             "and fails closed",
        test_wallet_rebuild_probe() == 0);

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
        if (pid > 0) {
            int status = 0;
            pid_t got = waitpid(pid, &status, 0);
            BP_CHECK("wait backward-move child", got == pid);
            BP_CHECK("backward move (DB_OPEN -> INIT) aborts via SIGABRT",
                     got == pid && WIFSIGNALED(status) &&
                     WTERMSIG(status) == SIGABRT);
        }
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
        if (pid > 0) {
            int status = 0;
            pid_t got = waitpid(pid, &status, 0);
            BP_CHECK("wait out-of-range child", got == pid);
            BP_CHECK("out-of-range target (__MAX) aborts via SIGABRT",
                     got == pid && WIFSIGNALED(status) &&
                     WTERMSIG(status) == SIGABRT);
        }
#endif
    }

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

        /* The tracked-step API is safe with no step open; boot_step_fail
         * always returns false. */
        boot_step_done();                 /* nothing open — no-op */
        boot_step_note();
        BP_CHECK("step: fail() returns false even with no step open",
            !boot_step_fail("nothing open"));
    }

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
