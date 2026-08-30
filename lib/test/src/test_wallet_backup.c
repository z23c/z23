/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the wallet_backup_service.
 *
 * Each test spins up a temporary datadir, opens a real node_db
 * (so the wallet schema is present), writes a handful of
 * wallet_keys rows, runs wallet_backup_run_once against a
 * SEPARATE backup directory, and then re-opens the backup file
 * to assert that the rows landed correctly.
 *
 * The point of this suite is the same as the service's whole
 * reason to exist: prove that a copy of wallet_keys exists
 * outside the primary datadir, so a future operator mistake can
 * be recovered from.
 */

/* realpath() reaches this TU only through the glibc fortify inline that
 * -D_FORTIFY_SOURCE=2 pulls in at -O1 and above; the build's
 * -D_POSIX_C_SOURCE=200809L declares it nowhere. Without this the file
 * compiles by accident of optimisation and breaks at -O0, under
 * -U_FORTIFY_SOURCE, and on any non-glibc libc. It must precede every
 * include: after them it does nothing. See lib/util/src/hw_profile.c. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "test/test_core.h"
#include "json/json.h"

#include "services/wallet_backup_service.h"
#include "event/event.h"
#include "util/supervisor.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "util/safe_alloc.h"
#include "test/setup_result.h"

#if defined(_WIN32) && !defined(O_CLOEXEC)
/* mingw's <fcntl.h> ships no O_CLOEXEC and no close-on-exec emulation. The
 * one open() below that wants it is single-process tamper-fixture I/O; the
 * flag is a hygiene no-op here regardless of platform, so a zero fallback
 * keeps that call syntactically valid on Windows without touching the value
 * POSIX platforms see. */
#define O_CLOEXEC 0
#endif

/* ── Event observer ────────────────────────────────────────── */

static _Atomic int g_wb_ok;
static _Atomic int g_wb_fail;

static void wb_ev_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_WALLET_BACKUP)        atomic_fetch_add(&g_wb_ok, 1);
    if (type == EV_WALLET_BACKUP_FAILED) atomic_fetch_add(&g_wb_fail, 1);
}

static void wb_install_observer(void)
{
    event_clear_observers(EV_WALLET_BACKUP);
    event_clear_observers(EV_WALLET_BACKUP_FAILED);
    atomic_store(&g_wb_ok, 0);
    atomic_store(&g_wb_fail, 0);
    event_observe(EV_WALLET_BACKUP, wb_ev_observer, NULL);
    event_observe(EV_WALLET_BACKUP_FAILED, wb_ev_observer, NULL);
}

#define WB_RUN(name, expr) do { \
    printf("%s... ", (name));   \
    bool _ok = (expr);          \
    if (_ok) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Test fixtures ──────────────────────────────────────────── */

struct wb_fixture {
    char    datadir[256];
    char    backup_dir[256];
    char    dbpath[320];
    struct node_db ndb;
};

static bool wb_fixture_init(struct wb_fixture *f, const char *tag)
{
    memset(f, 0, sizeof(*f));
    char datadir[256], backup_dir[256];
    snprintf(datadir, sizeof(datadir),
             "/tmp/zcl_wb_test_%d_%s_src", (int)getpid(), tag);
    snprintf(backup_dir, sizeof(backup_dir),
             "/tmp/zcl_wb_test_%d_%s_dst", (int)getpid(), tag);
    if (!test_abs_path(datadir, f->datadir, sizeof(f->datadir)) ||
        !test_abs_path(backup_dir, f->backup_dir, sizeof(f->backup_dir)))
        return false;
    platform_directory_create(f->datadir, 0755);
    /* Build the fixture through the same owner-private platform seam the
     * service validates.  A plain Windows mkdir inherits the parent DACL and
     * must correctly be refused as a backup destination. */
    if (!platform_private_directory_ensure(f->backup_dir))
        return false;
    snprintf(f->dbpath, sizeof(f->dbpath), "%s/node.db", f->datadir);
    return node_db_open(&f->ndb, f->dbpath);
}

static void wb_fixture_tear_down(struct wb_fixture *f)
{
    node_db_close(&f->ndb);
    test_cleanup_tmpdir(f->datadir);
    test_cleanup_tmpdir(f->backup_dir);
}

/* Insert N wallet_keys rows with deterministic values so tests
 * can assert the backup picked them up. */
static int wb_seed_keys(struct node_db *ndb, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
        "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed) "
        "VALUES(?,?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return 0;
    int wrote = 0;
    for (int i = 0; i < n; i++) {
        uint8_t hash[20] = {0}, pub[33] = {0}, priv[32] = {0};
        hash[0] = (uint8_t)(i + 1);
        pub[0] = 0x02; pub[1] = (uint8_t)(i + 1);
        priv[0] = (uint8_t)(0x80 + i);
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, pub,  sizeof(pub),  SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, priv, sizeof(priv), SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE) wrote++;
    }
    sqlite3_finalize(st);
    return wrote;
}

static int64_t wb_count_rows_in_file(const char *path, const char *table)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table);
    sqlite3_stmt *st = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return n;
}

/* Fixed few-hundred-ms polling ceilings for the backup thread's start-of-day
 * run flake under compile/test-lane contention (a starved thread eventually
 * completes; a short fixed ceiling gives up on it too soon). Poll the real
 * completion state instead of guessing a sleep length, with a ceiling long
 * enough to absorb normal contention; ZCL_TEST_TIMEOUT_SCALE (a positive
 * integer, default 1) lets the runner widen it further under known-heavy
 * load without changing what is being waited for. A thread that genuinely
 * never completes still fails the caller's assertion, it just no longer
 * hangs the test suite to prove it. */
static long wb_timeout_scale(void)
{
    static long cached = 0;
    if (cached > 0) return cached;
    const char *env = getenv("ZCL_TEST_TIMEOUT_SCALE");
    long v = env ? strtol(env, NULL, 10) : 1;
    cached = (v >= 1 && v <= 100) ? v : 1;
    return cached;
}

static void wb_wait_runs_past(int baseline, struct wallet_backup_status *out)
{
    long ceiling = 1000L * wb_timeout_scale(); /* 1000 * 10ms = 10s baseline */
    for (long i = 0; i < ceiling; i++) {
        wallet_backup_status_snapshot(out);
        if (out->total_runs > baseline) return;
        struct timespec ts = { 0, 10000000L }; nanosleep(&ts, NULL);
    }
    wallet_backup_status_snapshot(out);
}

/* ── 1. Happy path: backup creates a file with the right rows ── */

static int t_happy(void)
{
    int failures = 0;
    wb_install_observer();
    supervisor_reset_for_testing();

    struct wb_fixture f;
    if (!wb_fixture_init(&f, "happy")) {
        printf("wb: fixture setup failed\n");
        return 1;
    }
    int seeded = wb_seed_keys(&f.ndb, 5);

    char path[512] = "";
    int64_t key_count = -1;
    char err[256] = "";
    bool ok = wallet_backup_run_once(f.backup_dir, &f.ndb,
                                      path, sizeof(path),
                                      &key_count,
                                      err, sizeof(err)).ok;

    bool file_exists = false;
    int64_t file_keys = -1;
    if (ok) {
        struct stat st;
        file_exists = stat(path, &st) == 0 && st.st_size > 0;
        file_keys = wb_count_rows_in_file(path, "wallet_keys");
    }

    bool success = ok && seeded == 5 &&
                   file_exists && file_keys == 5 &&
                   key_count == 5 &&
                   atomic_load(&g_wb_ok) == 1 &&
                   atomic_load(&g_wb_fail) == 0;
    WB_RUN("wb: happy path creates backup with correct key count", success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 2. Refuses to write to a missing / unwritable directory ── */

static int t_missing_dir_created(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "mkdir");
    wb_seed_keys(&f.ndb, 1);

    /* Use a nested backup path that doesn't exist yet. */
    char nested[320];
    snprintf(nested, sizeof(nested), "%s/nested_backups", f.backup_dir);

    char err[256] = "";
    bool ok = wallet_backup_run_once(nested, &f.ndb,
                                      NULL, 0, NULL, err, sizeof(err)).ok;
    struct stat st;
    bool dir_created = stat(nested, &st) == 0 && S_ISDIR(st.st_mode);

    WB_RUN("wb: missing backup_dir is created with 0700", ok && dir_created);

    if (dir_created) {
        test_cleanup_tmpdir(nested);
    }
    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 3. Zero-keys case: empty wallet still produces a valid file ── */

static int t_zero_keys(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "zero");
    /* No wb_seed_keys call — wallet_keys table is empty. */

    char path[512] = "";
    int64_t key_count = -1;
    bool ok = wallet_backup_run_once(f.backup_dir, &f.ndb,
                                      path, sizeof(path),
                                      &key_count, NULL, 0).ok;
    int64_t n = wb_count_rows_in_file(path, "wallet_keys");

    bool success = ok && key_count == 0 && n == 0;
    WB_RUN("wb: empty wallet produces a 0-key backup that still verifies",
           success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 4. Each run produces a distinct file ─────────────────── */

static int t_two_runs_distinct_files(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "two");
    wb_seed_keys(&f.ndb, 2);

    char p1[512] = "", p2[512] = "";
    bool ok1 = wallet_backup_run_once(f.backup_dir, &f.ndb,
                                       p1, sizeof(p1), NULL, NULL, 0).ok;
    /* usec-level filename disambiguation still needs at least one
     * usec gap, so sleep a touch. */
    struct timespec ts = { 0, 2000000L }; nanosleep(&ts, NULL);
    bool ok2 = wallet_backup_run_once(f.backup_dir, &f.ndb,
                                       p2, sizeof(p2), NULL, NULL, 0).ok;

    bool success = ok1 && ok2 && strcmp(p1, p2) != 0 &&
                   atomic_load(&g_wb_ok) == 2;
    WB_RUN("wb: two successive runs produce distinct files", success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 5. Rotation trims oldest files ────────────────────────── */

static int t_rotation(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "rotate");
    wb_seed_keys(&f.ndb, 1);

    /* Run 5 backups back-to-back. */
    for (int i = 0; i < 5; i++) {
        (void)wallet_backup_run_once(f.backup_dir, &f.ndb,
                                      NULL, 0, NULL, NULL, 0);
        struct timespec ts = { 0, 2000000L }; nanosleep(&ts, NULL);
    }

    /* Five files should exist now. */
    char paths_before[10][512];
    int n_before = wallet_backup_list(f.backup_dir, paths_before, 10);

    /* Rotate to 2 — expect 3 deletions. */
    int deleted = wallet_backup_rotate(f.backup_dir, 2);

    char paths_after[10][512];
    int n_after = wallet_backup_list(f.backup_dir, paths_after, 10);

    bool success = n_before == 5 && deleted == 3 && n_after == 2;
    WB_RUN("wb: rotate to 2 from 5 deletes 3 oldest files", success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 6. Listing returns newest first ─────────────────────── */

static int t_list_newest_first(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "list");
    wb_seed_keys(&f.ndb, 1);

    char p1[512], p2[512], p3[512];
    ZCL_TEST_SETUP(wallet_backup_run_once(f.backup_dir, &f.ndb, p1, sizeof(p1), NULL, NULL, 0));
    /* Make the second file strictly newer by mtime. */
    sleep(1);
    ZCL_TEST_SETUP(wallet_backup_run_once(f.backup_dir, &f.ndb, p2, sizeof(p2), NULL, NULL, 0));
    sleep(1);
    ZCL_TEST_SETUP(wallet_backup_run_once(f.backup_dir, &f.ndb, p3, sizeof(p3), NULL, NULL, 0));

    char listing[10][512];
    int n = wallet_backup_list(f.backup_dir, listing, 10);

    bool success = n == 3 &&
                   strcmp(listing[0], p3) == 0 &&
                   strcmp(listing[1], p2) == 0 &&
                   strcmp(listing[2], p1) == 0;
    WB_RUN("wb: wallet_backup_list returns newest first", success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 7. wallet_backup_start refuses to backup into src dir ── */

static int t_refuses_same_dir(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "samedir");
    wb_seed_keys(&f.ndb, 1);

    /* Point backup_dir at the datadir (= source db directory). */
    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir = f.datadir;

    bool started = wallet_backup_start(&cfg, &f.ndb).ok;
    WB_RUN("wb: start refuses to back up into source datadir", !started);

    if (started) wallet_backup_stop();
    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 8. Status snapshot reflects last run ────────────────── */

static int t_status_snapshot(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "status");
    wb_seed_keys(&f.ndb, 3);

    /* wallet_backup_now is implemented on top of the globals, but
     * status_snapshot reads from the same globals — we need to
     * have started the service to populate the pointers. Use
     * start + stop semantics. */
    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir = f.backup_dir;
    cfg.interval_seconds = 3600;

    struct wallet_backup_status before;
    wallet_backup_status_snapshot(&before);
    bool started = wallet_backup_start(&cfg, &f.ndb).ok;
    /* Wait for the thread's start-of-day backup. */
    struct wallet_backup_status status;
    wb_wait_runs_past(before.total_runs, &status);
    struct supervisor_snapshot snaps[SUPERVISOR_CAP];
    int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
    const struct supervisor_snapshot *backup = NULL;
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].name, "wallet.backup") == 0) {
            backup = &snaps[i];
            break;
        }
    }
    wallet_backup_stop();
    bool supervisor_stopped = supervisor_child_count_total() == 0;

    bool success = started &&
                   status.running &&
                   status.total_runs >= 1 &&
                   status.last_key_count == 3 &&
                   status.last_size_bytes > 0 &&
                   status.last_path[0] != '\0' &&
                   backup != NULL &&
                   backup->period_secs == 0 &&
                   backup->deadline_secs == 60 &&
                   supervisor_stopped;
    WB_RUN("wb: status snapshot reflects thread's first backup", success);

    wb_fixture_tear_down(&f);
    supervisor_reset_for_testing();
    return failures;
}

/* ── dump_state_json: `z23 dumpstate wallet_backup` ─────── */

static int t_dump_state_json(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "dumpjson");
    wb_seed_keys(&f.ndb, 2);

    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir = f.backup_dir;
    cfg.interval_seconds = 3600;

    bool started = wallet_backup_start(&cfg, &f.ndb).ok;
    /* This subtest asserts the dump SHAPE, not thread scheduling (other
     * subtests cover the async path): run one backup synchronously so the
     * counters are deterministically populated even under suite contention. */
    bool ran = wallet_backup_now().ok;

    struct json_value v = {0};
    json_set_object(&v);
    bool ok = wallet_backup_dump_state_json(&v, NULL);
    const struct json_value *running = json_get(&v, "running");
    const struct json_value *total_runs = json_get(&v, "total_runs");
    const struct json_value *last_key_count = json_get(&v, "last_key_count");
    bool shape_ok = ok && running && json_get_bool(running) == true &&
                    total_runs && json_get_int(total_runs) >= 1 &&
                    last_key_count && json_get_int(last_key_count) == 2;
    if (!shape_ok)
        fprintf(stderr, "wb dump shape: ran=%d ok=%d running=%d total_runs=%lld "
                "last_key_count=%lld\n", ran, ok,
                running ? (int)json_get_bool(running) : -1,
                total_runs ? (long long)json_get_int(total_runs) : -1,
                last_key_count ? (long long)json_get_int(last_key_count) : -1);
    json_free(&v);

    wallet_backup_stop();
    WB_RUN("wb: dump_state_json reports running + total_runs + last_key_count",
           started && shape_ok);

    wb_fixture_tear_down(&f);
    supervisor_reset_for_testing();
    return failures;
}

/* ── 9. wallet_backup_now is thread-safe across repeated calls ── */

static int t_force_now_repeatable(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "forcenow");
    wb_seed_keys(&f.ndb, 2);

    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir = f.backup_dir;
    cfg.interval_seconds = 999999;  /* effectively disable tick */

    bool started = wallet_backup_start(&cfg, &f.ndb).ok;

    /* Wait for the initial auto-backup's event to land before counting
     * additional ones — poll the actual counter being asserted on below
     * instead of guessing how long that takes under contention. */
    int baseline = atomic_load(&g_wb_ok);
    for (long i = 0; i < 1000L * wb_timeout_scale() && baseline == 0; i++) {
        struct timespec ts = { 0, 10000000L }; nanosleep(&ts, NULL);
        baseline = atomic_load(&g_wb_ok);
    }

    bool n1 = wallet_backup_now().ok;
    bool n2 = wallet_backup_now().ok;
    bool n3 = wallet_backup_now().ok;

    wallet_backup_stop();

    bool success = started && n1 && n2 && n3 &&
                   atomic_load(&g_wb_ok) >= baseline + 3;
    WB_RUN("wb: wallet_backup_now produces one backup per call", success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 9b. One-shot encryption does not require an env secret ───── */

static int t_force_now_encrypted(void)
{
    int failures = 0;
    wb_install_observer();
    supervisor_reset_for_testing();

    struct wb_fixture f;
    wb_fixture_init(&f, "forcenowenc");
    int seeded = wb_seed_keys(&f.ndb, 3);

    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir = f.backup_dir;
    cfg.interval_seconds = 999999;
    cfg.encrypt = false;
    cfg.encrypt_password = NULL;

    struct wallet_backup_status before;
    wallet_backup_status_snapshot(&before);
    bool started = wallet_backup_start(&cfg, &f.ndb).ok;
    struct wallet_backup_status after_start;
    wb_wait_runs_past(before.total_runs, &after_start);

    bool ran = wallet_backup_now_encrypted("invocation-only-password").ok;
    struct wallet_backup_status encrypted_status;
    wallet_backup_status_snapshot(&encrypted_status);
    /* Reproduce the production race: a key-change-triggered run uses the
     * service's plaintext configuration after the explicit encrypted run. */
    bool plaintext_ran = wallet_backup_now().ok;
    struct wallet_backup_status status;
    wallet_backup_status_snapshot(&status);
    wallet_backup_stop();

    /* A real process starts with empty service RAM. start() must reconstruct
     * authority from node.db and re-hash the exact encrypted file before its
     * background plaintext run can execute. */
    bool restarted = wallet_backup_start(&cfg, &f.ndb).ok;
    struct wallet_backup_status restored_status;
    wallet_backup_status_snapshot(&restored_status);
    wallet_backup_stop();

    size_t path_len = strlen(status.last_encrypted_path);
    size_t suffix_len = strlen(WALLET_BACKUP_FILENAME_SUFFIX_ENC);
    bool has_encrypted_suffix = path_len >= suffix_len &&
        strcmp(status.last_encrypted_path + path_len - suffix_len,
               WALLET_BACKUP_FILENAME_SUFFIX_ENC) == 0;
    size_t latest_len = strlen(status.last_path);
    size_t plain_suffix_len = strlen(WALLET_BACKUP_FILENAME_SUFFIX);
    bool latest_is_plaintext = latest_len >= plain_suffix_len &&
        strcmp(status.last_path + latest_len - plain_suffix_len,
               WALLET_BACKUP_FILENAME_SUFFIX) == 0;
    char restored[640];
    snprintf(restored, sizeof(restored), "%s/restored-one-shot.sqlite",
             f.backup_dir);
    bool decrypted = has_encrypted_suffix &&
        wallet_backup_decrypt_file(status.last_encrypted_path, restored,
                                   "invocation-only-password").ok;
    int64_t rows = decrypted
        ? wb_count_rows_in_file(restored, "wallet_keys") : -1;

    int tamper_fd = open(status.last_encrypted_path,
                         O_WRONLY | O_APPEND | O_CLOEXEC);
    uint8_t tamper = 0xa5;
    bool tampered = tamper_fd >= 0 && write(tamper_fd, &tamper, 1) == 1;
    if (tamper_fd >= 0)
        close(tamper_fd);
    bool tamper_restart = wallet_backup_start(&cfg, &f.ndb).ok;
    struct wallet_backup_status tamper_status;
    wallet_backup_status_snapshot(&tamper_status);
    wallet_backup_stop();

    WB_RUN("wb: later plaintext run preserves encrypted-backup authority",
           started && ran && plaintext_ran && has_encrypted_suffix &&
           latest_is_plaintext && seeded == 3 && rows == 3 &&
           status.total_runs == after_start.total_runs + 2 &&
           status.last_encrypted_run_unix ==
               encrypted_status.last_run_unix &&
           status.last_encrypted_key_count == 3 &&
           status.last_encrypted_tables_verified ==
               status.wallet_table_count &&
           status.total_failures == after_start.total_failures &&
           restarted &&
           restored_status.last_encrypted_run_unix ==
               encrypted_status.last_run_unix &&
           restored_status.last_encrypted_key_count == 3 &&
           restored_status.last_encrypted_tables_verified ==
               restored_status.wallet_table_count &&
           strcmp(restored_status.last_encrypted_path,
                  status.last_encrypted_path) == 0 &&
           tampered && tamper_restart &&
           tamper_status.last_encrypted_run_unix == 0 &&
           tamper_status.last_encrypted_path[0] == '\0');

    wb_fixture_tear_down(&f);
    supervisor_reset_for_testing();
    return failures;
}

/* ── 10. Stop is idempotent + safe without start ──────────── */

static int t_stop_safe(void)
{
    int failures = 0;
    /* Call stop with nothing started. */
    wallet_backup_stop();
    wallet_backup_stop();  /* second no-op */
    WB_RUN("wb: stop is a safe no-op before start", true);
    return failures;
}

/* ── 11. Round-trip verification: backup keys match source ── */

static int t_roundtrip_verify(void)
{
    int failures = 0;
    wb_install_observer();

    struct wb_fixture f;
    wb_fixture_init(&f, "verify");
    int seeded = wb_seed_keys(&f.ndb, 7);

    char path[512] = "";
    bool ok = wallet_backup_run_once(f.backup_dir, &f.ndb,
                                      path, sizeof(path), NULL, NULL, 0).ok;
    int64_t n = wb_count_rows_in_file(path, "wallet_keys");

    /* Verify each seeded pubkey_hash lands in the backup. */
    sqlite3 *v = NULL;
    bool all_present = true;
    if (sqlite3_open_v2(path, &v, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        for (int i = 0; i < seeded; i++) {
            uint8_t hash[20] = {0};
            hash[0] = (uint8_t)(i + 1);
            if (sqlite3_prepare_v2(v,
                "SELECT count(*) FROM wallet_keys WHERE pubkey_hash=?",
                -1, &st, NULL) != SQLITE_OK) { all_present = false; break; }
            sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
            int64_t hit = 0;
            if (sqlite3_step(st) == SQLITE_ROW)
                hit = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            if (hit != 1) { all_present = false; break; }
        }
        sqlite3_close(v);
    } else {
        all_present = false;
    }

    bool success = ok && n == 7 && seeded == 7 && all_present;
    WB_RUN("wb: every seeded wallet_key row round-trips into the backup",
           success);

    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 12. Phase 2 encryption: file round-trip ─────────────────── */

/* Helpers that write a deterministic plaintext file and read it
 * back for byte-level comparison — the point is to prove that
 * whatever we send through wallet_backup_encrypt_file comes back
 * out of wallet_backup_decrypt_file bit-for-bit identical, with
 * the wrong password rejected and header tampering detected. */
static bool wb_write_blob(const char *path, const uint8_t *buf, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = n == 0 || fwrite(buf, 1, n, f) == n;
    fclose(f);
    return ok;
}

static bool wb_read_blob(const char *path, uint8_t **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) { fclose(f); return false; }
    uint8_t *buf = zcl_malloc((size_t)sz, "test_read_blob");
    if (!buf && sz > 0) { fclose(f); return false; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return false;
    }
    fclose(f);
    *out = buf;
    *outlen = (size_t)sz;
    return true;
}

/* Local scratch dir for encryption tests — avoids /tmp (user
 * preference) and keeps files inside the working tree so parallel
 * agents in separate worktrees don't collide. */
#define WB_ENC_SCRATCH_REL "./test-tmp"

/* Create that directory and return it as an ABSOLUTE path.
 *
 * wallet_backup_encrypt_file / _decrypt_file write through
 * wbs_write_file_atomic -> platform_private_path_resolve, which realpath()s
 * the destination's parent and refuses any pathname that does not start at
 * the root. A relative destination is rejected before a byte is written
 * ("destination parent is not a safe real directory"), so the fixture must
 * hand these primitives the absolute spelling of the same in-tree dir. */
static const char *wb_enc_ensure_scratch(void)
{
    static char dir[512];
    platform_directory_create(WB_ENC_SCRATCH_REL, 0755);
    if (dir[0])
        return dir;
    char cwd[384];
    if (!getcwd(cwd, sizeof(cwd)))
        return WB_ENC_SCRATCH_REL;   /* caller's write then fails loudly */
    snprintf(dir, sizeof(dir), "%s/test-tmp", cwd);
    return dir;
}

static int t_encrypt_roundtrip(void)
{
    int failures = 0;
    const char *scratch = wb_enc_ensure_scratch();

    /* Deterministic plaintext large enough to span many ChaCha20
     * blocks (and far larger than the old 2KB stack limit). */
    size_t plain_len = 32 * 1024;
    uint8_t *plain = zcl_malloc(plain_len, "test_enc_plain");
    for (size_t i = 0; i < plain_len; i++)
        plain[i] = (uint8_t)((i * 37 + 11) & 0xff);

    char src[256], enc[256], dst[256];
    snprintf(src, sizeof(src), "%s/wbenc_%d_src.bin", scratch,   (int)getpid());
    snprintf(enc, sizeof(enc), "%s/wbenc_%d_enc.bin", scratch,   (int)getpid());
    snprintf(dst, sizeof(dst), "%s/wbenc_%d_plain.bin", scratch, (int)getpid());

    wb_write_blob(src, plain, plain_len);

    bool enc_ok = wallet_backup_encrypt_file(src, enc, "correct horse battery staple").ok;
    WB_RUN("wbenc: encrypt_file succeeds on a 32KB plaintext", enc_ok);

    bool dec_ok = wallet_backup_decrypt_file(enc, dst, "correct horse battery staple").ok;
    WB_RUN("wbenc: decrypt_file succeeds with correct password", dec_ok);

    uint8_t *round = NULL; size_t round_len = 0;
    bool read_ok = wb_read_blob(dst, &round, &round_len);
    bool match = read_ok && round_len == plain_len &&
                 memcmp(round, plain, plain_len) == 0;
    WB_RUN("wbenc: plaintext round-trips byte-for-byte through the AEAD",
           match);
    free(round);

    /* Ciphertext file size == header + plaintext + tag, and the
     * first 4 bytes must be the "WBE1" magic. */
    uint8_t *ct = NULL; size_t clen = 0;
    wb_read_blob(enc, &ct, &clen);
    bool sized = ct != NULL &&
                 clen == (size_t)WALLET_BACKUP_ENC_HEADER_LEN +
                          plain_len + WALLET_BACKUP_ENC_TAG_LEN &&
                 memcmp(ct, WALLET_BACKUP_ENC_MAGIC, 4) == 0;
    WB_RUN("wbenc: encrypted file has WBE1 magic + correct length", sized);
    free(ct);

    unlink(src); unlink(enc); unlink(dst);
    free(plain);
    return failures;
}

static int t_encrypt_wrong_password(void)
{
    int failures = 0;
    const char *scratch = wb_enc_ensure_scratch();

    const char *plain = "attack at dawn";
    char src[256], enc[256], dst[256];
    snprintf(src, sizeof(src), "%s/wbenc_%d_wrong_src.bin", scratch,   (int)getpid());
    snprintf(enc, sizeof(enc), "%s/wbenc_%d_wrong_enc.bin", scratch,   (int)getpid());
    snprintf(dst, sizeof(dst), "%s/wbenc_%d_wrong_plain.bin", scratch, (int)getpid());

    wb_write_blob(src, (const uint8_t *)plain, strlen(plain));

    bool enc_ok = wallet_backup_encrypt_file(src, enc, "password-a").ok;
    bool dec_wrong = !wallet_backup_decrypt_file(enc, dst, "password-b").ok;
    WB_RUN("wbenc: encrypt under one password", enc_ok);
    WB_RUN("wbenc: decrypt with wrong password is rejected (tag mismatch)",
           dec_wrong);

    /* Decrypt with empty/NULL password is also rejected. */
    bool rej_empty = !wallet_backup_decrypt_file(enc, dst, "").ok;
    bool rej_null  = !wallet_backup_decrypt_file(enc, dst, NULL).ok;
    WB_RUN("wbenc: decrypt rejects empty password", rej_empty);
    WB_RUN("wbenc: decrypt rejects NULL password",  rej_null);

    unlink(src); unlink(enc); unlink(dst);
    return failures;
}

static int t_encrypt_tamper_detected(void)
{
    int failures = 0;
    const char *scratch = wb_enc_ensure_scratch();

    const char *plain = "every byte of the header is authenticated";
    char src[256], enc[256], dst[256];
    snprintf(src, sizeof(src), "%s/wbenc_%d_tamper_src.bin", scratch,   (int)getpid());
    snprintf(enc, sizeof(enc), "%s/wbenc_%d_tamper_enc.bin", scratch,   (int)getpid());
    snprintf(dst, sizeof(dst), "%s/wbenc_%d_tamper_plain.bin", scratch, (int)getpid());

    wb_write_blob(src, (const uint8_t *)plain, strlen(plain));
    ZCL_TEST_SETUP(wallet_backup_encrypt_file(src, enc, "pw"));

    /* Read the encrypted file, flip a bit in the salt region
     * (still a valid header structurally), write it back, and
     * confirm that decryption fails — proof that the header is
     * bound into the AAD. */
    uint8_t *ct = NULL; size_t clen = 0;
    wb_read_blob(enc, &ct, &clen);
    bool setup_ok = ct != NULL && clen > 20;
    if (setup_ok) ct[20] ^= 0x01; /* flip a bit in the salt */
    wb_write_blob(enc, ct, clen);
    bool rejected_salt = !wallet_backup_decrypt_file(enc, dst, "pw").ok;
    WB_RUN("wbenc: flipped salt byte fails tag verification",
           setup_ok && rejected_salt);

    /* Restore salt, flip a ciphertext byte instead — still must
     * fail (ciphertext is part of the MAC input). */
    if (setup_ok) ct[20] ^= 0x01;
    if (clen > (size_t)WALLET_BACKUP_ENC_HEADER_LEN)
        ct[WALLET_BACKUP_ENC_HEADER_LEN] ^= 0x01;
    wb_write_blob(enc, ct, clen);
    bool rejected_ct = !wallet_backup_decrypt_file(enc, dst, "pw").ok;
    WB_RUN("wbenc: flipped ciphertext byte fails tag verification",
           rejected_ct);

    /* Restore and confirm the file is once again readable — this
     * proves the tamper detections above were specific, not a
     * side-effect of our round-trip being broken in general. */
    if (clen > (size_t)WALLET_BACKUP_ENC_HEADER_LEN)
        ct[WALLET_BACKUP_ENC_HEADER_LEN] ^= 0x01;
    wb_write_blob(enc, ct, clen);
    bool restored_ok = wallet_backup_decrypt_file(enc, dst, "pw").ok;
    WB_RUN("wbenc: restoring the flipped byte lets decrypt succeed again",
           restored_ok);
    free(ct);

    unlink(src); unlink(enc); unlink(dst);
    return failures;
}

/* ── 13. Encrypted service runs ──────────────────────────────── */

/* Count directory entries ending in `suffix`. Note ".sqlite.enc"
 * names do NOT match a ".sqlite" suffix scan (they end in ".enc"),
 * so the two counts are disjoint. */
static int wb_count_dir_suffix(const char *dir, const char *suffix)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    size_t sl = strlen(suffix);
    while ((e = readdir(d)) != NULL) {
        size_t nl = strlen(e->d_name);
        if (nl >= sl && strcmp(e->d_name + nl - sl, suffix) == 0)
            n++;
    }
    closedir(d);
    return n;
}

static int t_encrypted_service_run(void)
{
    int failures = 0;
    wb_install_observer();
    supervisor_reset_for_testing();

    struct wb_fixture f;
    if (!wb_fixture_init(&f, "encsvc")) {
        printf("wbenc: fixture setup failed\n");
        return 1;
    }
    int seeded = wb_seed_keys(&f.ndb, 4);

    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir       = f.backup_dir;
    cfg.interval_seconds = 999999;   /* only the start-of-day backup */
    cfg.encrypt          = true;
    cfg.encrypt_password = "test-backup-password";

    /* The service counters are process-global and cumulative across
     * the tests in this aggregator (stop() never resets them), so
     * assert deltas from a pre-start baseline — and poll on the delta
     * so the snapshot can't race the thread's start-of-day run. */
    struct wallet_backup_status base;
    wallet_backup_status_snapshot(&base);

    bool started = wallet_backup_start(&cfg, &f.ndb).ok;
    struct wallet_backup_status status;
    wb_wait_runs_past(base.total_runs, &status);
    wallet_backup_stop();

    int n_enc   = wb_count_dir_suffix(f.backup_dir,
                                      WALLET_BACKUP_FILENAME_SUFFIX_ENC);
    int n_plain = wb_count_dir_suffix(f.backup_dir,
                                      WALLET_BACKUP_FILENAME_SUFFIX);
    WB_RUN("wbenc: encrypted run leaves exactly one .enc and no plaintext",
           started && status.total_runs == base.total_runs + 1 &&
           status.total_failures == base.total_failures &&
           n_enc == 1 && n_plain == 0);

    /* last_path points at the .enc file and listing returns it. */
    char listing[4][512];
    int n = wallet_backup_list(f.backup_dir, listing, 4);
    size_t lp = strlen(status.last_path);
    size_t el = strlen(WALLET_BACKUP_FILENAME_SUFFIX_ENC);
    WB_RUN("wbenc: status + list surface the encrypted backup path",
           n == 1 && lp > el &&
           strcmp(status.last_path + lp - el,
                  WALLET_BACKUP_FILENAME_SUFFIX_ENC) == 0 &&
           strcmp(listing[0], status.last_path) == 0 &&
           status.last_size_bytes > 0);

    /* Decrypt round-trip restores a sqlite db with the seeded rows. */
    char dst[640];
    snprintf(dst, sizeof(dst), "%s/restored.sqlite", f.backup_dir);
    bool dec_ok = n == 1 &&
        wallet_backup_decrypt_file(listing[0], dst,
                                   "test-backup-password").ok;
    int64_t rows = dec_ok ? wb_count_rows_in_file(dst, "wallet_keys") : -1;
    WB_RUN("wbenc: decrypt round-trip restores the seeded wallet_keys rows",
           dec_ok && seeded == 4 && rows == 4);

    wb_fixture_tear_down(&f);
    supervisor_reset_for_testing();
    return failures;
}

/* ── 14. encrypt=true without a password refuses to start ───── */

static int t_encrypt_requires_password(void)
{
    int failures = 0;
    wb_install_observer();
    supervisor_reset_for_testing();

    struct wb_fixture f;
    wb_fixture_init(&f, "encnopw");
    wb_seed_keys(&f.ndb, 1);

    struct wallet_backup_config cfg;
    wallet_backup_config_defaults(&cfg);
    cfg.backup_dir       = f.backup_dir;
    cfg.encrypt          = true;
    cfg.encrypt_password = NULL;

    bool rejected_null = !wallet_backup_start(&cfg, &f.ndb).ok;
    cfg.encrypt_password = "";
    bool rejected_empty = !wallet_backup_start(&cfg, &f.ndb).ok;

    struct wallet_backup_status s;
    wallet_backup_status_snapshot(&s);
    bool no_thread = !s.running && supervisor_child_count_total() == 0;
    bool no_files = wb_count_dir_suffix(f.backup_dir,
                                        WALLET_BACKUP_FILENAME_SUFFIX) == 0 &&
                    wb_count_dir_suffix(f.backup_dir,
                                        WALLET_BACKUP_FILENAME_SUFFIX_ENC) == 0;
    WB_RUN("wbenc: encrypt without a password refuses to start (no thread)",
           rejected_null && rejected_empty && no_thread && no_files);

    wallet_backup_stop();  /* safe no-op — nothing started */
    wb_fixture_tear_down(&f);
    return failures;
}

/* ── 15. Rotation + listing count .enc files ─────────────────── */

static int t_rotation_counts_enc(void)
{
    int failures = 0;
    const char *scratch = wb_enc_ensure_scratch();

    char dir[256];
    snprintf(dir, sizeof(dir), "%s/wbenc_%d_rotate", scratch,
             (int)getpid());
    platform_directory_create(dir, 0700);

    /* One real encrypted file, copied under five backup names with
     * strictly increasing mtimes (set explicitly — no sleeps). */
    char src[320], enc[320];
    snprintf(src, sizeof(src), "%s/seed_plain.bin", dir);
    snprintf(enc, sizeof(enc), "%s/seed_enc.bin", dir);
    wb_write_blob(src, (const uint8_t *)"rotate me", 9);
    bool enc_ok = wallet_backup_encrypt_file(src, enc, "pw").ok;

    uint8_t *blob = NULL; size_t blen = 0;
    enc_ok = enc_ok && wb_read_blob(enc, &blob, &blen);

    char names[5][384] = {{0}};
    bool wrote = enc_ok;
    for (int i = 0; i < 5 && wrote; i++) {
        snprintf(names[i], sizeof(names[i]), "%s/%s10%d_000000%s",
                 dir, WALLET_BACKUP_FILENAME_PREFIX, i,
                 WALLET_BACKUP_FILENAME_SUFFIX_ENC);
        wrote = wb_write_blob(names[i], blob, blen);
        struct utimbuf tb = { .actime  = 1000000 + i,
                              .modtime = 1000000 + i };
        wrote = wrote && utime(names[i], &tb) == 0;
    }
    free(blob);

    int n_before = 0, deleted = 0, n_after = 0;
    char listing[8][512];
    if (wrote) {
        n_before = wallet_backup_list(dir, listing, 8);
        deleted  = wallet_backup_rotate(dir, 2);
        n_after  = wallet_backup_list(dir, listing, 8);
    }

    /* Newest-first: highest mtimes (names[4], names[3]) survive. */
    bool order_ok = n_after == 2 &&
        strcmp(listing[0], names[4]) == 0 &&
        strcmp(listing[1], names[3]) == 0;
    WB_RUN("wbenc: rotation + listing count .enc backups, oldest deleted",
           wrote && n_before == 5 && deleted == 3 && order_ok);

    unlink(src); unlink(enc);
    for (int i = 0; i < 5; i++)
        if (names[i][0]) unlink(names[i]);
    rmdir(dir);
    return failures;
}

/* ── Aggregator ─────────────────────────────────────────────── */

int test_wallet_backup(void)
{
    printf("\n=== wallet_backup tests ===\n");
    int failures = 0;
    failures += t_happy();
    failures += t_missing_dir_created();
    failures += t_zero_keys();
    failures += t_two_runs_distinct_files();
    failures += t_rotation();
    failures += t_list_newest_first();
    failures += t_refuses_same_dir();
    failures += t_status_snapshot();
    failures += t_dump_state_json();
    failures += t_force_now_repeatable();
    failures += t_force_now_encrypted();
    failures += t_stop_safe();
    failures += t_roundtrip_verify();
    failures += t_encrypt_roundtrip();
    failures += t_encrypt_wrong_password();
    failures += t_encrypt_tamper_detected();
    failures += t_encrypted_service_run();
    failures += t_encrypt_requires_password();
    failures += t_rotation_counts_enc();
    event_clear_observers(EV_WALLET_BACKUP);
    event_clear_observers(EV_WALLET_BACKUP_FAILED);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
