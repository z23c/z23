/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * File controller tests — manifest coverage and cache invalidation. */

#include "crypto/sha3.h"
#include "base/serialize_le.h"
#include "platform/time_compat.h"
#include "platform/file_sync.h"
#include "test/test_core.h"
#include "config/boot_snapshot_offer.h"
#include "controllers/file_controller.h"
#include "net/file_service.h"
#include "../../net/src/file_service_worker_internal.h"
#include "../../../core/modules/net/src/file_service_priv.h"
#include "services/consensus_snapshot_export_service.h"
#include <errno.h>
#include <stdatomic.h>
#include <sqlite3.h>
#if !defined(_WIN32)
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#endif
#include <stdlib.h>
#include <utime.h>
#include <unistd.h>

static void test_file_write_bytes(const char *path, size_t size, uint8_t seed)
{
    FILE *f = fopen(path, "wb");
    if (!f) return;

    uint8_t buf[4096];
    memset(buf, seed, sizeof(buf));
    while (size > 0) {
        size_t n = size > sizeof(buf) ? sizeof(buf) : size;
        fwrite(buf, 1, n, f);
        size -= n;
    }
    fclose(f);
}

static void test_file_touch_age(const char *path, int seconds_ago)
{
    struct utimbuf tb;
    time_t now = platform_time_wall_time_t();
    tb.actime = now - seconds_ago;
    tb.modtime = now - seconds_ago;
    utime(path, &tb);
}

static bool manifest_has_file_index(const struct file_manifest *fm,
                                    uint8_t file_index)
{
    for (uint32_t i = 0; i < fm->num_chunks; i++) {
        if (fm->chunks[i].file_index == file_index)
            return true;
    }
    return false;
}

static void setup_manifest_test_dir(char *dir, size_t dir_sz)
{
    test_make_tmpdir(dir, dir_sz, "file_controller", "manifest");

    char blocks[320];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    mkdir(blocks, 0755);
}

static void cleanup_manifest_test_dir(const char *dir)
{
    TEST_DISCARD(test_rm_rf_recursive(dir)); /* No shell: the path is absolute and may contain spaces. */
}

static void cleanup_file_controller_test_dir(const char *dir)
{
    cleanup_manifest_test_dir(dir);
}

static bool build_snapshot_source_db(const char *db_path, bool include_all_tables)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *utxo_insert = NULL;
    int rc = sqlite3_open_v2(db_path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                             NULL);
    if (rc != SQLITE_OK || !db)
        return false;

    sqlite3_exec(db, "PRAGMA journal_mode=OFF", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS blocks("
                     "height INTEGER PRIMARY KEY, hash BLOB, status INTEGER)",
                 NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS addresses(address_hash BLOB, tx_count INTEGER)", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS chain_stats(height INTEGER)", NULL, NULL, NULL);

    if (include_all_tables) {
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS transactions(txid BLOB, block_height INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS utxos(txid BLOB, vout INTEGER)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS zslp_tokens(ticker TEXT)",
            NULL, NULL, NULL);
        sqlite3_exec(db,
            "CREATE TABLE IF NOT EXISTS zslp_balances(token_id BLOB)",
            NULL, NULL, NULL);
    }

    sqlite3_exec(db, "INSERT INTO blocks(height,hash,status) "
                     "VALUES(0,zeroblob(32),3)",
                 NULL, NULL, NULL);
    if (include_all_tables) {
        sqlite3_exec(db,
            "INSERT INTO transactions VALUES(x'11',0)",
            NULL, NULL, NULL);
        sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
        rc = sqlite3_prepare_v2(db,
                                "INSERT INTO utxos VALUES(zeroblob(32),?)",
                                -1, &utxo_insert, NULL);
        if (rc != SQLITE_OK || !utxo_insert) {
            sqlite3_close(db);
            return false;
        }
        /* Keep the locally exported artifact above the production 1 MB
         * serving floor so manifest tests exercise the real path. */
        for (int i = 0; i < 40000; i++) {
            sqlite3_bind_int(utxo_insert, 1, i);
            rc = sqlite3_step(utxo_insert);
            sqlite3_reset(utxo_insert);
            sqlite3_clear_bindings(utxo_insert);
            if (rc != SQLITE_DONE) {
                sqlite3_finalize(utxo_insert);
                sqlite3_close(db);
                return false;
            }
        }
        sqlite3_finalize(utxo_insert);
        utxo_insert = NULL;
        sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO addresses VALUES(x'22',1)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO chain_stats VALUES(0)", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO zslp_tokens VALUES('TKN')", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO zslp_balances VALUES(x'33')", NULL, NULL, NULL);
    }

    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    sqlite3_close(db);

    return true;
}

static bool build_and_export_local_snapshot(const char *dir)
{
    char db_path[320];
    char snap_path[320];
    struct stat st;
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    snprintf(snap_path, sizeof(snap_path), "%s/consensus_snapshot.db", dir);
    const uint8_t block_hash[32] = {0};
    return build_snapshot_source_db(db_path, true) &&
           consensus_snapshot_export_service_run_bound(
               dir, 0, block_hash).ok &&
           stat(snap_path, &st) == 0 && st.st_size > 1000000;
}

static bool sqlite_has_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    fclose(f);
    return true;
}

#define fm (*manifest)
static bool file_controller_check_tampered_snapshot_manifest(
    bool ok, const char *snap, const char *dir,
    struct file_manifest *manifest)
{
        /* Global sovereignty cannot bless changed/downloaded bytes.  The
         * exact locally exported digest is required at serving time. */
        boot_snapshot_offer_test_set_trust_override(1);
        FILE *tamper = fopen(snap, "r+b");
        ok = ok && tamper != NULL;
        if (tamper) {
            ok = ok && fseek(tamper, 4096, SEEK_SET) == 0;
            ok = ok && fputc(0xA5, tamper) != EOF;
            ok = ok && fflush(tamper) == 0;
            ok = ok && platform_data_sync(fileno(tamper)) == 0;
            fclose(tamper);
        }
        memset(&fm, 0, sizeof(fm));
        ok = ok && file_manifest_build(&fm, dir);
        ok = ok && !manifest_has_file_index(&fm, 254);
    return ok;
}
#undef fm

static int test_manifest_build_includes_snapshot(void)
{
    int failures = 0;

    printf("file_controller: manifest includes consensus snapshot when present... ");
    {
        char dir[256];
        char blk[320];
        char snap[320];
        struct file_manifest fm;

        setup_manifest_test_dir(dir, sizeof(dir));
        snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", dir);
        snprintf(snap, sizeof(snap), "%s/consensus_snapshot.db", dir);

        test_file_write_bytes(blk, 4096, 0x11);
        test_file_touch_age(blk, 7200);
        bool ok = build_and_export_local_snapshot(dir);

        boot_snapshot_offer_test_set_trust_override(1);
        memset(&fm, 0, sizeof(fm));
        ok = ok && file_manifest_build(&fm, dir);
        ok = ok && manifest_has_file_index(&fm, 254);

        struct file_chunk snapshot_chunk = {0};
        bool snapshot_found = false;
        for (uint32_t i = 0; i < fm.num_chunks; i++) {
            if (fm.chunks[i].file_index == 254) {
                snapshot_chunk = fm.chunks[i];
                snapshot_found = true;
                break;
            }
        }
        boot_snapshot_offer_test_set_trust_override(0);
        uint8_t *bytes = (uint8_t *)(uintptr_t)1;
        uint32_t bytes_len = 1;
        ok = ok && snapshot_found;
        ok = ok && file_manifest_find(&fm, snapshot_chunk.sha3) == NULL;
        ok = ok && !file_chunk_read(&snapshot_chunk, dir, &bytes, &bytes_len);
        ok = ok && bytes == NULL && bytes_len == 0;

        /* A persisted sovereign cache must be rejected/rebuilt after a trust
         * downgrade, so later REST/RPC manifest copies cannot advertise it. */
        memset(&fm, 0, sizeof(fm));
        ok = ok && file_manifest_build(&fm, dir);
        ok = ok && !manifest_has_file_index(&fm, 254);

        ok = file_controller_check_tampered_snapshot_manifest(ok, snap, dir, &fm);

        boot_snapshot_offer_test_set_trust_override(-1);
        cleanup_manifest_test_dir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_manifest_cache_rebuilds_when_snapshot_appears(void)
{
    int failures = 0;

    printf("file_controller: cached manifest rebuilds when snapshot appears... ");
    {
        char dir[256];
        char blk[320];
        char snap[320];
        struct file_manifest fm;

        setup_manifest_test_dir(dir, sizeof(dir));
        snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", dir);
        snprintf(snap, sizeof(snap), "%s/consensus_snapshot.db", dir);

        test_file_write_bytes(blk, 4096, 0x33);
        test_file_touch_age(blk, 7200);

        boot_snapshot_offer_test_set_trust_override(1);
        memset(&fm, 0, sizeof(fm));
        bool ok = file_manifest_build(&fm, dir);
        ok = ok && !manifest_has_file_index(&fm, 254);

        test_file_write_bytes(snap, 1100000, 0x44);
        memset(&fm, 0, sizeof(fm));
        ok = ok && file_manifest_build(&fm, dir);
        ok = ok && !manifest_has_file_index(&fm, 254);

        ok = ok && build_and_export_local_snapshot(dir);
        memset(&fm, 0, sizeof(fm));
        ok = ok && file_manifest_build(&fm, dir);
        ok = ok && manifest_has_file_index(&fm, 254);

        boot_snapshot_offer_test_set_trust_override(-1);
        cleanup_manifest_test_dir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_manifest_skips_hot_block_index(void)
{
    int failures = 0;

    printf("file_controller: manifest skips recently modified block_index.bin... ");
    {
        char dir[256];
        char blk[320];
        char flat[320];
        struct file_manifest fm;

        setup_manifest_test_dir(dir, sizeof(dir));
        snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", dir);
        snprintf(flat, sizeof(flat), "%s/block_index.bin", dir);

        test_file_write_bytes(blk, 4096, 0x55);
        test_file_touch_age(blk, 7200);
        test_file_write_bytes(flat, 1100000, 0x66);

        memset(&fm, 0, sizeof(fm));
        bool ok = file_manifest_build(&fm, dir);
        ok = ok && !manifest_has_file_index(&fm, 253);

        cleanup_manifest_test_dir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static int test_controller_refresh_manifest_api(void)
{
    int failures = 0;

    printf("file_controller: explicit refresh builds cached manifest... ");
    {
        char dir[256];
        char blk[320];
        char snap[320];
        struct file_manifest fm;

        setup_manifest_test_dir(dir, sizeof(dir));
        snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", dir);
        snprintf(snap, sizeof(snap), "%s/consensus_snapshot.db", dir);

        test_file_write_bytes(blk, 4096, 0x77);
        test_file_touch_age(blk, 7200);
        bool ok = build_and_export_local_snapshot(dir);

        boot_snapshot_offer_test_set_trust_override(1);
        file_controller_init(dir);
        ok = ok && file_controller_refresh_manifest();
        ok = ok && file_controller_get_manifest_copy(&fm);
        ok = ok && manifest_has_file_index(&fm, 254);

        boot_snapshot_offer_test_set_trust_override(-1);
        cleanup_manifest_test_dir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

#define status (*manifest_status)
static bool file_controller_check_refreshed_manifest_status(
    bool ok, struct file_manifest_status *manifest_status)
{
        ok = ok && file_controller_refresh_manifest();
        memset(&status, 0, sizeof(status));
        file_controller_get_manifest_status(&status);
        ok = ok && status.manifest_valid;
        ok = ok && status.snapshot_present;
        ok = ok && status.snapshot_served;
        ok = ok && status.block_index_present;
        ok = ok && !status.block_index_served;
        ok = ok && status.num_chunks > 0;
        ok = ok && status.total_bytes > 0;
    return ok;
}
#undef status

static int test_manifest_status_reports_export_readiness(void)
{
    int failures = 0;

    printf("file_controller: manifest status reports export readiness... ");
    {
        char dir[256];
        char blk[320];
        char snap[320];
        char flat[320];
        struct file_manifest_status status;

        setup_manifest_test_dir(dir, sizeof(dir));
        snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", dir);
        snprintf(snap, sizeof(snap), "%s/consensus_snapshot.db", dir);
        snprintf(flat, sizeof(flat), "%s/block_index.bin", dir);

        test_file_write_bytes(blk, 4096, 0x99);
        test_file_touch_age(blk, 7200);
        bool ok = build_and_export_local_snapshot(dir);
        test_file_write_bytes(flat, 1100000, 0xBB);

        boot_snapshot_offer_test_set_trust_override(1);
        file_controller_init(dir);
        memset(&status, 0, sizeof(status));
        file_controller_get_manifest_status(&status);
        ok = ok && status.datadir_configured;
        ok = ok && !status.manifest_valid;
        ok = ok && status.snapshot_present;
        ok = ok && !status.snapshot_served;
        ok = ok && status.block_index_present;
        ok = ok && !status.block_index_served;

        ok = file_controller_check_refreshed_manifest_status(ok, &status);

        /* The cached manifest is not authority: a live trust downgrade hides
         * the snapshot immediately while preserving honest disk presence. */
        boot_snapshot_offer_test_set_trust_override(0);
        memset(&status, 0, sizeof(status));
        file_controller_get_manifest_status(&status);
        ok = ok && status.manifest_valid;
        ok = ok && status.snapshot_present;
        ok = ok && !status.snapshot_served;

        boot_snapshot_offer_test_set_trust_override(-1);
        cleanup_manifest_test_dir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

struct file_service_lifetime_clock {
    int64_t monotonic_us;
    int64_t wall_unix;
};

static int64_t file_service_lifetime_monotonic_us(void *opaque)
{
    const struct file_service_lifetime_clock *clock = opaque;
    return clock->monotonic_us;
}

static int64_t file_service_lifetime_wall_unix(void *opaque)
{
    const struct file_service_lifetime_clock *clock = opaque;
    return clock->wall_unix;
}

#if !defined(_WIN32)
/* Wait for the worker's EOF, bounded by a hang guard. The fake platform
 * monotonic source expiring the connection cannot advance, so this wait
 * uses the host clock. */
static bool file_service_wait_for_eof(int fd, int timeout_ms)
{
    const int64_t deadline_us = clock_now_monotonic_raw_us() +
        (int64_t)timeout_ms * 1000;

    for (;;) {
        int64_t remaining_us = deadline_us - clock_now_monotonic_raw_us();
        if (remaining_us <= 0)
            return false;
        int remaining_ms = (int)((remaining_us + 999) / 1000);
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int ready = poll(&pfd, 1, remaining_ms);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            return false;

        uint8_t closed_probe;
        ssize_t n = recv(fd, &closed_probe, 1, MSG_DONTWAIT);
        if (n == 0)
            return true;
        if (n > 0)
            continue;
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        /* Closing with an unread padding frame may surface as a reset rather
         * than an orderly EOF; both mean the expired peer cannot use the
         * connection. */
        if (errno == ECONNRESET || errno == ECONNABORTED || errno == ENOTCONN)
            return true;
        return false;
    }
}
#endif

static int test_file_service_start_stop_and_lifetime(void)
{
    int failures = 0;

    printf("file_controller: file service start/stop and connection lifetime... ");
#if defined(_WIN32)
    /* Frame/chunk transport and handshake are native on Windows, but the
     * inbound server refuses until its manifest/snapshot filesystem
     * transaction is qualified, so no accepted connection exists here. */
    printf("SKIP (Windows): inbound file-service server is unavailable on "
           "this lane\n");
    return failures;
#else
    {
        char dir[256];
        int fd = -1;
        struct fs_session client;
        bool session_initialized = false;
        bool clock_installed = false;
        bool ok = true;

        setup_manifest_test_dir(dir, sizeof(dir));
        char blk[320];
        snprintf(blk, sizeof(blk), "%s/blocks/blk00000.dat", dir);
        test_file_write_bytes(blk, 4096, 0xCC);
        test_file_touch_age(blk, 7200);
        fs_server_start(dir, 0, NULL);
        fs_server_start(dir, 0, NULL);
        for (unsigned i = 0; i < 200 && fs_server_get_port() == 0; i++)
            platform_sleep_ms(5);
        ok = ok && fs_server_is_running();

        fd = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 address = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(fs_server_get_port()),
            .sin6_addr = IN6ADDR_LOOPBACK_INIT,
        };
        ok = ok && fd >= 0 && address.sin6_port != 0 &&
            connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0;
        if (ok) {
            uint8_t transport_root[32] = {0};
            fs_session_init(&client, fd);
            session_initialized = true;
            ok = fs_handshake(&client, transport_root, true);
        }

        int64_t expired_ms = platform_time_monotonic_ms() +
            ((int64_t)FS_CONN_MAX_SECONDS + 1) * 1000;
        struct file_service_lifetime_clock lifetime = {
            .monotonic_us = expired_ms * 1000,
            .wall_unix = (int64_t)platform_time_wall_time_t(),
        };
        struct platform_clock_source source = {
            .monotonic_us = file_service_lifetime_monotonic_us,
            .wall_unix = file_service_lifetime_wall_unix,
            .user = &lifetime,
        };
        if (ok) {
            platform_clock_set_source(&source);
            clock_installed = true;
            /* The frame only wakes a worker blocked in recv; the worker may
             * instead close the expired connection first. Both schedules are
             * valid; the contract is the bounded EOF. */
            (void)fs_send_frame(&client, FS_PADDING, NULL, 0);
        }

        /* Bound the peer's EOF observation with the 30 s hostile-peer hang
         * guard (as file-service frame I/O does), not a scheduler latency. */
        bool peer_closed = file_service_wait_for_eof(fd, 30000);
        ok = ok && peer_closed;

        if (clock_installed)
            platform_clock_clear_source();
        if (session_initialized)
            fs_session_cleanup(&client);
        if (fd >= 0)
            close(fd);
        fs_server_stop();
        fs_server_stop();
        ok = ok && !fs_server_is_running();
        cleanup_manifest_test_dir(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
#endif

    return failures;
}

static int test_file_service_range_worker_socket_lifecycle(void)
{
    int failures = 0;

    printf("file_controller: range worker cancellation owns its socket... ");
#if defined(_WIN32)
    printf("SKIP (Windows): inbound file-service range workers are "
           "unavailable on this lane\n");
    return failures;
#else
    if (fs_test_range_worker_socket_lifecycle())
        printf("OK\n");
    else {
        printf("FAIL\n");
        failures++;
    }
    return failures;
#endif
}

static int test_file_service_resolved_connect_lifecycle(void)
{
    int failures = 0;

    printf("file_controller: resolved connects are bounded and blocking on return... ");
#if defined(_WIN32)
    printf("SKIP (Windows): legacy file-service client sync is unavailable "
           "on this lane\n");
    return failures;
#else
    if (fs_test_resolved_connect_lifecycle())
        printf("OK\n");
    else {
        printf("FAIL\n");
        failures++;
    }
    return failures;
#endif
}

#define stmt (*statement)
#define tables_count (*table_count)
static bool file_controller_check_exported_snapshot_tables(
    bool ok, sqlite3 *snap_db, sqlite3_stmt **statement,
    int *table_count)
{
        if (snap_db) {
            sqlite3_prepare_v2(snap_db,
                               "SELECT value FROM _snapshot_meta WHERE key='tables'",
                               -1, &stmt, NULL);
            if (stmt && sqlite3_step(stmt) == SQLITE_ROW) {
                tables_count = sqlite3_column_int(stmt, 0);
            }
            if (stmt) sqlite3_finalize(stmt);
            sqlite3_prepare_v2(snap_db,
                               "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='wallet_utxos'",
                               -1, &stmt, NULL);
            int secret_tables = 0;
            if (stmt && sqlite3_step(stmt) == SQLITE_ROW)
                secret_tables = sqlite3_column_int(stmt, 0);
            if (stmt) sqlite3_finalize(stmt);
            ok = ok && tables_count == 7;
            ok = ok && secret_tables == 0;
            sqlite3_close(snap_db);
        }
    return ok;
}
#undef tables_count
#undef stmt

static int test_file_export_snapshot_success(void)
{
    int failures = 0;

    printf("file_controller: consensus snapshot export succeeds and is queryable... ");
    {
        char dir[320];
        char db_path[320];
        char snap_path[320];
        sqlite3 *snap_db = NULL;
        sqlite3_stmt *stmt = NULL;
        int tables_count = 0;
        bool ok = true;

        ok = ok && test_mkdtemp(dir, sizeof(dir), "zcl_file_export_success")
                       != NULL;
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
        snprintf(snap_path, sizeof(snap_path), "%s/consensus_snapshot.db", dir);
        ok = ok && build_snapshot_source_db(db_path, true);

        if (ok) {
            const uint8_t block_hash[32] = {0};
            ok = consensus_snapshot_export_service_run_bound(
                dir, 0, block_hash).ok;
            ok = ok && sqlite_has_file(snap_path);
            ok = ok && consensus_snapshot_export_artifact_check(
                dir, INT32_MAX).ok;
            ok = ok && sqlite3_open_v2(snap_path, &snap_db,
                                       SQLITE_OPEN_READONLY, NULL) == SQLITE_OK;
        }
        ok = file_controller_check_exported_snapshot_tables(
            ok, snap_db, &stmt, &tables_count);

        /* The digest cache is not enough: a same-height local chain change
         * must invalidate the stamped state binding immediately. */
        sqlite3 *source_db = NULL;
        if (ok && sqlite3_open_v2(db_path, &source_db,
                SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK && source_db) {
            ok = sqlite3_exec(source_db,
                "UPDATE blocks SET hash=x'01010101010101010101010101010101"
                "01010101010101010101010101010101' WHERE height=0",
                NULL, NULL, NULL) == SQLITE_OK;
            sqlite3_close(source_db);
            source_db = NULL;
            ok = ok && !consensus_snapshot_export_artifact_check(
                dir, INT32_MAX).ok;
        } else {
            ok = false;
            if (source_db)
                sqlite3_close(source_db);
        }

        cleanup_file_controller_test_dir(dir);
        if (ok) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static int test_file_export_snapshot_fail_closes_partial(void)
{
    int failures = 0;

    printf("file_controller: consensus snapshot export removes partial file on failure... ");
    {
        char dir[320];
        char db_path[320];
        char snap_path[320];
        bool ok = true;

        ok = ok && test_mkdtemp(dir, sizeof(dir), "zcl_file_export_fail")
                       != NULL;
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
        snprintf(snap_path, sizeof(snap_path), "%s/consensus_snapshot.db", dir);
        ok = ok && build_snapshot_source_db(db_path, false);
        ok = ok && truncate(db_path, 1100000) == 0;
        const uint8_t block_hash[32] = {0};
        ok = ok && !consensus_snapshot_export_service_run_bound(
            dir, 0, block_hash).ok;
        ok = ok && !sqlite_has_file(snap_path);

        cleanup_file_controller_test_dir(dir);
        if (ok) printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static int test_file_export_snapshot_rejects_overlong_datadir(void)
{
    int failures = 0;

    printf("file_controller: consensus snapshot export rejects truncated paths... ");
    {
        /* Long enough to overflow the 576-byte source/destination buffers,
         * while still fitting the separate 640-byte proof-path buffer. */
        char datadir[581];
        const uint8_t block_hash[32] = {0};
        memset(datadir, 'a', sizeof(datadir) - 1);
        datadir[0] = '/';
        datadir[sizeof(datadir) - 1] = '\0';

        struct zcl_result result = consensus_snapshot_export_service_run_bound(
            datadir, 0, block_hash);
        bool ok = !result.ok && strstr(result.message, "path too long") != NULL;
        if (ok) printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

static int test_file_export_snapshot_rejects_empty_datadir(void)
{
    int failures = 0;

    printf("file_controller: consensus snapshot export rejects empty datadir... ");
    {
        const uint8_t block_hash[32] = {0};
        struct zcl_result result = consensus_snapshot_export_service_run_bound(
            "", 0, block_hash);
        bool ok = !result.ok && strstr(result.message, "invalid datadir") != NULL;
        if (ok) printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

#if !defined(_WIN32)
static bool immutable_fixture_initial(const char *dir, struct file_manifest *out)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", dir);
    test_file_write_bytes(path, 17, 7);
    if (file_controller_build_immutable_manifest(out, dir, 1)) return false;
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    test_file_write_bytes(path, 19, 9);
    if (!file_controller_build_immutable_manifest(out, dir, 1)) return false;
    uint8_t bytes[19], block_hash[32], index_hash[32];
    memset(bytes, 7, 17); sha3_256(bytes, 17, block_hash);
    memset(bytes, 9, 19); sha3_256(bytes, 19, index_hash);
    return out->num_chunks == 2 && out->total_bytes == 36 &&
        out->chunks[0].file_index == 0 && out->chunks[1].file_index == 253 &&
        memcmp(out->chunks[0].sha3, block_hash, 32) == 0 &&
        memcmp(out->chunks[1].sha3, index_hash, 32) == 0;
}

static bool immutable_fixture_rejections(const char *dir, struct file_manifest *out)
{
    char path[320];
    memset(out, 0xa5, sizeof(*out));
    struct file_manifest sentinel = *out;
    snprintf(path, sizeof(path), "%s/blocks/blk00002.dat", dir);
    test_file_write_bytes(path, 1, 1);
    bool gap = !file_controller_build_immutable_manifest(out, dir, 3) &&
        memcmp(out, &sentinel, sizeof(*out)) == 0;
    unlink(path);
    snprintf(path, sizeof(path), "%s/blocks/blk000003.dat", dir);
    test_file_write_bytes(path, 1, 1);
    bool malformed = !file_controller_build_immutable_manifest(out, dir, 1);
    unlink(path);
    snprintf(path, sizeof(path), "%s/blocks/blk00253.dat", dir);
    test_file_write_bytes(path, 1, 1);
    bool reserved = !file_controller_build_immutable_manifest(out, dir, 1);
    unlink(path);
    return gap && malformed && reserved;
}

static bool immutable_fixture_symlink(const char *path, const char *dir, struct file_manifest *out)
{
    unlink(path);
    return symlink("/dev/null", path) == 0 &&
        !file_controller_build_immutable_manifest(out, dir, 1);
}

static bool immutable_fixture_limits(const char *dir, struct file_manifest *out)
{
    char path[320];
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    FILE *f = fopen(path, "wb");
    bool oversized = f && ftruncate(fileno(f), (off_t)FILE_CHUNK_SIZE * FILE_MAX_CHUNKS + 1) == 0;
    if (f) fclose(f);
    if (!oversized || file_controller_build_immutable_manifest(out, dir, 1)) return false;
    f = fopen(path, "wb");
    bool boundary = f && ftruncate(fileno(f), (off_t)FILE_CHUNK_SIZE + 1) == 0;
    if (f) fclose(f);
    if (!boundary || !file_controller_build_immutable_manifest(out, dir, 1)) return false;
    uint8_t roots[96], expected[32];
    for (unsigned i = 0; i < 3; i++) memcpy(roots + i * 32, out->chunks[i].sha3, 32);
    sha3_256(roots, sizeof(roots), expected);
    boundary = out->num_chunks == 3 && out->chunks[1].size == FILE_CHUNK_SIZE &&
        out->chunks[2].offset == FILE_CHUNK_SIZE && out->chunks[2].size == 1 &&
        memcmp(expected, out->root_hash, 32) == 0;
    return boundary && immutable_fixture_symlink(path, dir, out);
}

static int test_immutable_manifest(void)
{
    char dir[256];
    setup_manifest_test_dir(dir, sizeof(dir));
    struct file_manifest manifest = {0};
    bool initial = immutable_fixture_initial(dir, &manifest);
    bool refused = immutable_fixture_rejections(dir, &manifest);
    bool limits = immutable_fixture_limits(dir, &manifest);
    cleanup_manifest_test_dir(dir);
    if (initial && refused && limits) return 0;
    printf("immutable manifest: initial=%d refused=%d limits=%d\n", initial, refused, limits);
    return 1;
}
#endif

#if !defined(_WIN32) && defined(ZCL_TESTING)
bool fs_test_manifest_extents(const struct file_chunk *chunks, uint32_t count);
bool fs_test_chunk_open(const char *dir, uint8_t index);
bool fs_test_output_size(const char *dir, uint8_t index, uint64_t size, bool final);
uint32_t fs_test_resume(const char *, const struct file_chunk *, uint32_t);
bool fs_test_manifest_sequence(uint32_t entries, bool done);
bool fs_test_manifest_frame_compat(void);
bool fs_test_expected_manifest(const struct file_chunk *, uint32_t, uint64_t, const struct file_manifest *);
bool fs_test_receive_cancel_fd(void);
static bool fs_test_cancel_before_adoption(void);
bool fs_test_boundary_aggregation(void);
bool fs_test_receive_challenge_difficulty(int bits);
bool fs_test_inventory_complete(const char *, const uint64_t [255]);
bool fs_output_durable(const char *, const uint64_t [255]);
void fs_test_set_fail_fsync(bool);
static int test_fs_history_inventory(void)
{
    char dir[256], blocks[512], index[512], block[512], extra[512];
    test_make_tmpdir(dir, sizeof(dir), "file_controller", "history-inventory");
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    snprintf(index, sizeof(index), "%s/block_index.bin", dir);
    snprintf(block, sizeof(block), "%s/blocks/blk00000.dat", dir);
    snprintf(extra, sizeof(extra), "%s/blocks/extra", dir);
    uint64_t lengths[255] = {0}; lengths[0] = lengths[253] = 4;
    bool ok = mkdir(blocks, 0700) == 0;
    test_file_write_bytes(index, 4, 1);
    ok = ok && !fs_test_inventory_complete(dir, lengths);
    test_file_write_bytes(block, 4, 1);
    ok = ok && fs_test_inventory_complete(dir, lengths);
    test_file_write_bytes(extra, 1, 1);
    ok = ok && !fs_test_inventory_complete(dir, lengths) && unlink(extra) == 0;
    ok = ok && unlink(block) == 0 && symlink("../block_index.bin", block) == 0 &&
        !fs_test_inventory_complete(dir, lengths) && unlink(block) == 0;
    test_file_write_bytes(block, 4, 1);
    ok = ok && fs_test_inventory_complete(dir, lengths);
    fs_test_set_fail_fsync(true);
    ok = ok && !fs_output_durable(dir, lengths);
    fs_test_set_fail_fsync(false);
    ok = ok && fs_output_durable(dir, lengths);
    cleanup_file_controller_test_dir(dir);
    printf("file_controller: history inventory and fsync refusal... %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
struct fs_blocked_manifest_fixture {
    int listener, notice;
    struct fs_receive_op *op;
    const char *dir;
    uint16_t port;
    bool request_seen, probe, saw_eof;
    int behavior;
    struct file_manifest received;
    enum fs_receive_result result;
};

static int fs_test_accept_timed(int listener, int timeout_ms)
{
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    return poll(&ready, 1, timeout_ms) == 1 ? accept(listener, NULL, NULL) : -1;
}

static void *fs_retry_server(void *arg)
{
    struct fs_blocked_manifest_fixture *f = arg;
    int fd = fs_test_accept_timed(f->listener, 5000);
    if (fd < 0) return NULL;
    struct timeval timeout = {.tv_sec = 5};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct fs_session session; fs_session_init(&session, fd);
    const uint8_t root[32] = {0}; uint8_t type; const uint8_t *payload; uint32_t size;
    uint8_t entry[45] = {0}; entry[32] = 1;
    bool ok = fs_handshake(&session, root, false) &&
        fs_recv_frame(&session, &type, &payload, &size) && type == FS_MANIFEST && size == 0 &&
        fs_send_frame(&session, FS_MANIFEST, entry, sizeof(entry));
    entry[36] = 253;
    ok = ok && fs_send_frame(&session, FS_MANIFEST, entry, sizeof(entry)) &&
        fs_send_frame(&session, FS_DONE, NULL, 0);
    fs_session_cleanup(&session); close(fd);
    for (int i = 0; ok && i < 2; ++i) {
        fd = fs_test_accept_timed(f->listener, 5000);
        if (fd < 0) ok = false; else close(fd);
    }
    fd = ok ? fs_test_accept_timed(f->listener, 12000) : -1;
    if (fd < 0) return NULL;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    f->request_seen = true;
    char marker = 'M';
    if (write(f->notice, &marker, 1) != 1) { close(fd); return NULL; }
    char buffer[256]; ssize_t n;
    do { n = recv(fd, buffer, sizeof(buffer), 0); } while (n > 0);
    f->saw_eof = n == 0;
    close(fd);
    return NULL;
}

static void fs_manifest_invalid_response(struct fs_blocked_manifest_fixture *f, struct fs_session *session)
{
    if (f->request_seen && f->behavior >= 6 && f->behavior <= 8) {
        uint8_t entry[46] = {0}; entry[32] = 1;
        uint8_t frame = f->behavior == 8 ? FS_REQUEST : FS_MANIFEST;
        uint32_t size = f->behavior == 6 ? 44 : f->behavior == 7 ? 46 : 45;
        (void)fs_send_frame(session, frame, entry, size);
        if (f->behavior == 7) {
            entry[36] = 253;
            (void)fs_send_frame(session, FS_MANIFEST, entry, 45);
            (void)fs_send_frame(session, FS_DONE, NULL, 0);
        }
    }
}

static void fs_manifest_server_response(struct fs_blocked_manifest_fixture *f, struct fs_session *session, int fd)
{
    if (f->request_seen && (f->behavior == 0 || f->behavior == 4 || f->behavior == 5 || f->behavior == 9)) {
        char buffer[256]; ssize_t n;
        do { n = recv(fd, buffer, sizeof(buffer), 0); } while (n > 0);
        f->saw_eof = n == 0;
    }
    if (f->request_seen && f->behavior == 1) (void)fs_send_frame(session, FS_DONE, NULL, 0);
    if (f->request_seen && f->behavior == 3) {
        uint8_t entry[45] = {0}; entry[32] = 1;
        bool sent = fs_send_frame(session, FS_MANIFEST, entry, sizeof(entry));
        entry[36] = 253;
        sent = sent && fs_send_frame(session, FS_MANIFEST, entry, sizeof(entry));
        sent = sent && fs_send_frame(session, FS_DONE, NULL, 0);
        if (!sent) f->request_seen = false;
    }
    fs_manifest_invalid_response(f, session);
}

static void *fs_blocked_manifest_server(void *arg)
{
    struct fs_blocked_manifest_fixture *f = arg;
    struct pollfd ready = {.fd = f->listener, .events = POLLIN};
    if (poll(&ready, 1, 5000) != 1) return NULL;
    int fd = accept(f->listener, NULL, NULL);
    if (fd < 0) return NULL;
    struct timeval timeout = {.tv_sec = 5};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct fs_session session;
    fs_session_init(&session, fd);
    const uint8_t root[32] = {0};
    uint8_t type; const uint8_t *payload; uint32_t size;
    f->request_seen = (f->behavior == 5 || f->behavior == 9) || (fs_handshake(&session, root, false) &&
        fs_recv_frame(&session, &type, &payload, &size) && type == FS_MANIFEST && size == 0);
    char marker = f->request_seen ? 'M' : 'E';
    if (write(f->notice, &marker, 1) != 1) { fs_session_cleanup(&session); close(fd); return NULL; }
    fs_manifest_server_response(f, &session, fd);
    fs_session_cleanup(&session);
    close(fd);
    return NULL;
}

static void *fs_blocked_manifest_client(void *arg)
{
    struct fs_blocked_manifest_fixture *f = arg;
    const uint8_t root[32] = {0};
    f->result = f->probe ? fs_receive_probe(f->op, "127.0.0.1", f->port, root, &f->received) :
        fs_receive_run(f->op, "127.0.0.1", f->port, f->dir, root);
    return NULL;
}

static bool fs_manifest_notice(int fd, bool ok)
{
    if (ok) {
        struct pollfd p = {.fd = fd, .events = POLLIN}; char marker = 0;
        ok = poll(&p, 1, 15000) == 1 && read(fd, &marker, 1) == 1 && marker == 'M';
    }
    return ok;
}

static bool fs_manifest_verify_payload(const struct fs_blocked_manifest_fixture *f, int behavior, bool ok)
{
    if (behavior == 3) ok = ok && f->result == FS_RECEIVE_COMPLETE &&
        f->received.num_chunks == 2 && f->received.total_bytes == 2 && f->received.chain_height == -1;
    else {
        ok = ok && f->result != FS_RECEIVE_COMPLETE;
        if (f->probe) { const uint8_t *p = (const uint8_t *)&f->received;
            for (size_t i = 0; i < sizeof(f->received); ++i) ok = ok && p[i] == 0; }
    }
    return ok;
}

static bool fs_manifest_verify(const struct fs_blocked_manifest_fixture *f, int behavior, bool ok)
{
    ok = ok && f->request_seen;
    if (behavior == 0 || behavior == 4 || behavior == 5 || behavior == 9) ok = ok && f->saw_eof;
    if (behavior == 9) ok = ok && f->result == FS_RECEIVE_ERROR;
    ok = fs_manifest_verify_payload(f, behavior, ok);
    return ok;
}

static void fs_manifest_retry_input(struct file_manifest *manifest, int behavior)
{
    if (behavior == 9) {
        manifest->num_chunks = 2; manifest->total_bytes = 2;
        manifest->chunks[1].size = 1; manifest->chunks[1].file_index = 253;
        struct sha3_256_ctx hash; sha3_256_init(&hash);
        sha3_256_write(&hash, manifest->chunks[0].sha3, 32);
        sha3_256_write(&hash, manifest->chunks[1].sha3, 32);
        sha3_256_finalize(&hash, manifest->root_hash);
    }
}

static bool fs_manifest_listen(struct fs_blocked_manifest_fixture *f, int notice[2], pthread_t *server, bool *server_started)
{
    bool ok = f->op && pipe(notice) == 0;
    if (ok) f->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    ok = ok && f->listener >= 0 && bind(f->listener, (struct sockaddr *)&address, length) == 0 &&
        getsockname(f->listener, (struct sockaddr *)&address, &length) == 0 && listen(f->listener, 1) == 0;
    if (ok) { f->port = ntohs(address.sin_port); f->notice = notice[1];
        *server_started = pthread_create(server, NULL, f->behavior == 9 ? fs_retry_server :
                                        fs_blocked_manifest_server, f) == 0;
        ok = *server_started; }
    return ok;
}

static void fs_manifest_cancel(struct fs_blocked_manifest_fixture *f, int behavior, bool ok)
{
    if (f->op && (behavior == 0 || behavior == 4 || behavior == 5 || behavior == 9 || !ok)) fs_receive_cancel(f->op);
}

static int test_fs_manifest_case(int behavior)
{
    char dir[256]; int notice[2] = {-1, -1}; pthread_t server, client;
    test_make_tmpdir(dir, sizeof(dir), "file_controller", "history-cancel");
    struct file_manifest manifest = {.num_chunks = 1}; manifest.chunks[0].size = 1;
    fs_manifest_retry_input(&manifest, behavior);
    struct fs_blocked_manifest_fixture f = {.listener = -1, .notice = -1, .dir = dir,
        .probe = behavior != 0 && behavior != 9, .behavior = behavior, .result = FS_RECEIVE_COMPLETE,
        .op = fs_receive_create(behavior == 0 || behavior == 9 ? &manifest : NULL)};
    bool server_started = false, client_started = false;
    bool ok = fs_manifest_listen(&f, notice, &server, &server_started);
    if (f.probe) memset(&f.received, 0xa5, sizeof(f.received));
    if (ok) { client_started = pthread_create(&client, NULL, fs_blocked_manifest_client, &f) == 0;
        ok = client_started; }
    ok = fs_manifest_notice(notice[0], ok);
    fs_manifest_cancel(&f, behavior, ok);
    if (client_started) pthread_join(client, NULL);
    if (server_started) pthread_join(server, NULL);
    ok = fs_manifest_verify(&f, behavior, ok);
    if (f.listener >= 0) close(f.listener);
    if (notice[0] >= 0) close(notice[0]);
    if (notice[1] >= 0) close(notice[1]);
    fs_receive_destroy(f.op);
    cleanup_file_controller_test_dir(dir);
    printf("file_controller: manifest case %d... %s\n", behavior, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int test_fs_manifest_case_isolated(int behavior)
{
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        signal(SIGALRM, SIG_DFL);
        alarm(30);
        _exit(test_fs_manifest_case(behavior) == 0 ? 0 : 1);
    }
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

struct fs_test_adoption {
    struct fs_receive_op *op;
    int fd, ready, release;
    bool adopted;
};

static void *fs_test_adoption_worker(void *arg)
{
    struct fs_test_adoption *test = arg;
    char byte = 'R';
    if (write(test->ready, &byte, 1) == 1 && read(test->release, &byte, 1) == 1)
        test->adopted = fs_receive_adopt(test->op, 1, test->fd);
    return NULL;
}

static bool fs_test_cancel_before_adoption(void)
{
    int pair[2] = {-1, -1}, ready[2] = {-1, -1}, release[2] = {-1, -1};
    struct file_manifest expected = {.num_chunks = 1}; expected.chunks[0].size = 1;
    struct fs_receive_op *op = fs_receive_create(&expected);
    bool ok = op && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 &&
        pipe(ready) == 0 && pipe(release) == 0;
    struct fs_test_adoption test = {.op = op, .fd = pair[0],
        .ready = ready[1], .release = release[0]};
    pthread_t thread; bool started = false; char byte;
    if (ok) { started = pthread_create(&thread, NULL, fs_test_adoption_worker, &test) == 0; ok = started; }
    if (started) {
        struct pollfd pfd = {.fd = ready[0], .events = POLLIN};
        bool signaled = poll(&pfd, 1, 5000) == 1 && read(ready[0], &byte, 1) == 1;
        fs_receive_cancel(op);
        if (signaled) { byte = 'G'; ok = write(release[1], &byte, 1) == 1 && ok; }
        else { close(release[1]); release[1] = -1; ok = false; }
        pthread_join(thread, NULL);
        ok = ok && !test.adopted;
    }
    for (int i = 0; i < 2; ++i) {
        if (pair[i] >= 0) close(pair[i]);
        if (ready[i] >= 0) close(ready[i]);
        if (release[i] >= 0) close(release[i]);
    }
    fs_receive_destroy(op);
    return ok;
}
static bool test_fs_adoption_isolated(void)
{
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        signal(SIGALRM, SIG_DFL);
        alarm(10);
        _exit(fs_test_cancel_before_adoption() ? 0 : 1);
    }
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int fs_test_prefix_scan_decision(const char *, const struct file_chunk *, uint32_t,
                                 struct fs_receive_op *, bool);

enum { TEST_PREFIX_READY, TEST_PREFIX_ERROR, TEST_PREFIX_STOPPED };
struct fs_prefix_fixture {
    int listener;
    uint16_t port;
    bool retry, manifest_seen, range_seen, retry_seen, server_ok, unexpected;
    _Atomic bool client_done;
    struct file_manifest manifest;
};

static void fs_prefix_manifest_init(struct file_manifest *manifest)
{
    memset(manifest, 0, sizeof(*manifest));
    manifest->num_chunks = 2; manifest->total_bytes = 2;
    manifest->chunks[0].size = 1;
    manifest->chunks[1].size = 1; manifest->chunks[1].file_index = 253;
    sha3_256((const uint8_t *)"A", 1, manifest->chunks[0].sha3);
    sha3_256((const uint8_t *)"B", 1, manifest->chunks[1].sha3);
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, manifest->chunks[0].sha3, 32);
    sha3_256_write(&hash, manifest->chunks[1].sha3, 32);
    sha3_256_finalize(&hash, manifest->root_hash);
}

static int fs_prefix_accept(struct fs_prefix_fixture *f, struct fs_session *session)
{
    int fd = fs_test_accept_timed(f->listener, 10000);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 5};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    fs_session_init(session, fd);
    const uint8_t salt[32] = {0};
    if (fs_handshake(session, salt, false)) return fd;
    fs_session_cleanup(session); close(fd);
    return -1;
}

static void fs_prefix_close(struct fs_session *session, int fd)
{
    fs_session_cleanup(session);
    close(fd);
}

static bool fs_prefix_send_manifest(struct fs_prefix_fixture *f)
{
    struct fs_session session;
    int fd = fs_prefix_accept(f, &session);
    if (fd < 0) return false;
    uint8_t type; const uint8_t *body; uint32_t length;
    bool ok = fs_recv_frame(&session, &type, &body, &length) && type == FS_MANIFEST && length == 0;
    for (uint32_t i = 0; ok && i < f->manifest.num_chunks; i++) {
        const struct file_chunk *chunk = &f->manifest.chunks[i];
        uint8_t entry[45];
        memcpy(entry, chunk->sha3, 32); zcl_write_u32_le(entry + 32, chunk->size);
        entry[36] = chunk->file_index; zcl_write_u64_le(entry + 37, chunk->offset);
        ok = fs_send_frame(&session, FS_MANIFEST, entry, sizeof(entry));
    }
    ok = ok && fs_send_frame(&session, FS_DONE, NULL, 0);
    f->manifest_seen = ok;
    fs_prefix_close(&session, fd);
    return ok;
}

static bool fs_prefix_range_request(struct fs_prefix_fixture *f)
{
    struct fs_session session;
    int fd = fs_prefix_accept(f, &session);
    if (fd < 0) return false;
    uint8_t type; const uint8_t *body; uint32_t length;
    uint8_t challenge[FS_CHALLENGE_PAYLOAD_SIZE] = {0};
    challenge[32] = PUZZLE_MIN_BITS;
    bool ok = fs_recv_frame(&session, &type, &body, &length) && type == FS_CHALLENGE && length == 0 &&
        fs_send_frame(&session, FS_CHALLENGE, challenge, sizeof(challenge)) &&
        fs_recv_frame(&session, &type, &body, &length) && type == FS_REQUEST &&
        length == FS_POW_SOLUTION_SIZE + 8 && !memcmp(body + FS_POW_SOLUTION_SIZE, "RNG", 3) &&
        zcl_read_u16_le(body + FS_POW_SOLUTION_SIZE + 3) == 1 &&
        zcl_read_u16_le(body + FS_POW_SOLUTION_SIZE + 5) == 2;
    f->range_seen = ok;
    fs_prefix_close(&session, fd);
    return ok;
}

static bool fs_prefix_retry_request(struct fs_prefix_fixture *f)
{
    struct fs_session session;
    int fd = fs_prefix_accept(f, &session);
    if (fd < 0) return false;
    uint8_t type; const uint8_t *body; uint32_t length;
    bool ok = fs_recv_frame(&session, &type, &body, &length) && type == FS_REQUEST && length == 32 &&
        memcmp(body, f->manifest.chunks[1].sha3, 32) == 0;
    f->retry_seen = ok;
    if (ok) ok = fs_send_chunk_fast(&session, (const uint8_t *)"B", 1, f->manifest.chunks[1].sha3);
    fs_prefix_close(&session, fd);
    return ok;
}

static bool fs_prefix_no_worker(struct fs_prefix_fixture *f)
{
    for (int i = 0; i < 100 && !atomic_load(&f->client_done); i++) {
        int fd = fs_test_accept_timed(f->listener, 100);
        if (fd >= 0) { close(fd); f->unexpected = true; return false; }
    }
    if (!atomic_load(&f->client_done)) return false;
    int fd = fs_test_accept_timed(f->listener, 100);
    if (fd >= 0) { close(fd); f->unexpected = true; return false; }
    return true;
}

static void *fs_prefix_server(void *context)
{
    struct fs_prefix_fixture *f = context;
    bool ok = fs_prefix_send_manifest(f);
    if (ok) ok = f->retry ? fs_prefix_range_request(f) && fs_prefix_retry_request(f) :
                            fs_prefix_no_worker(f);
    f->server_ok = ok;
    return NULL;
}

static bool fs_prefix_listen(struct fs_prefix_fixture *f)
{
    f->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(addr);
    bool ok = f->listener >= 0 && bind(f->listener, (struct sockaddr *)&addr, length) == 0 &&
        listen(f->listener, 4) == 0 && getsockname(f->listener, (struct sockaddr *)&addr, &length) == 0;
    if (ok) f->port = ntohs(addr.sin_port);
    return ok;
}

static bool fs_prefix_make_stage(const char *dir, char block[512], char index[512])
{
    char blocks[512];
    if (snprintf(blocks, sizeof(blocks), "%s/blocks", dir) >= (int)sizeof(blocks) ||
        snprintf(block, 512, "%s/blk00000.dat", blocks) >= 512 ||
        snprintf(index, 512, "%s/block_index.bin", dir) >= 512 || mkdir(blocks, 0700) != 0) return false;
    test_file_write_bytes(block, 1, 'A');
    FILE *f = fopen(block, "rb");
    if (!f) return false;
    bool ok = fgetc(f) == 'A';
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool fs_prefix_decisions(const char *dir, const char *block, const struct file_manifest *manifest)
{
    struct fs_receive_op *op = fs_receive_create_with_prefix(manifest, 1);
    if (!op) return false;
    fs_receive_cancel(op);
    bool ok = fs_test_prefix_scan_decision(dir, manifest->chunks, 2, op, false) == TEST_PREFIX_STOPPED;
    fs_receive_destroy(op);
    test_file_write_bytes(block, 1, 'X');
    op = fs_receive_create(manifest);
    if (!op) return false;
    ok = ok && fs_test_prefix_scan_decision(dir, manifest->chunks, 2, op, false) == TEST_PREFIX_READY;
    fs_receive_destroy(op);
    op = fs_receive_create_with_prefix(manifest, 1);
    if (!op) return false;
    ok = ok && fs_test_prefix_scan_decision(dir, manifest->chunks, 2, op, true) == TEST_PREFIX_ERROR;
    fs_receive_destroy(op);
    test_file_write_bytes(block, 1, 'A');
    return ok;
}

static bool fs_prefix_constructors(const struct file_manifest *manifest)
{
    if (fs_receive_create_with_prefix(NULL, 0) || fs_receive_create_with_prefix(manifest, 3)) return false;
    struct fs_receive_op *zero = fs_receive_create_with_prefix(manifest, 0);
    struct fs_receive_op *full = fs_receive_create_with_prefix(manifest, 2);
    bool ok = zero && full;
    fs_receive_destroy(zero); fs_receive_destroy(full);
    return ok;
}

static bool fs_prefix_file_equals(const char *path, int expected)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fgetc(f) == expected && fgetc(f) == EOF;
    if (fclose(f) != 0) ok = false;
    return ok;
}

struct fs_prefix_case_state {
    char dir[256], block[512], index[512];
    struct fs_prefix_fixture server;
    struct fs_receive_op *op;
    enum fs_receive_result result;
};

static bool fs_prefix_case_prepare(struct fs_prefix_case_state *s, bool retry)
{
    test_make_tmpdir(s->dir, sizeof(s->dir), "file_controller", "history-prefix");
    s->server.listener = -1; s->server.retry = retry;
    fs_prefix_manifest_init(&s->server.manifest);
    if (!fs_prefix_constructors(&s->server.manifest) || !fs_prefix_make_stage(s->dir, s->block, s->index) ||
        !fs_prefix_decisions(s->dir, s->block, &s->server.manifest) ||
        fs_test_resume(s->dir, s->server.manifest.chunks, 1) != 1) return false;
    s->op = fs_receive_create_with_prefix(&s->server.manifest, 1);
    if (!retry) test_file_write_bytes(s->block, 1, 'X');
    return s->op && fs_prefix_listen(&s->server);
}

static bool fs_prefix_case_run(struct fs_prefix_case_state *s)
{
    pthread_t server;
    if (pthread_create(&server, NULL, fs_prefix_server, &s->server) != 0) return false;
    const uint8_t salt[32] = {0};
    s->result = fs_receive_run(s->op, "127.0.0.1", s->server.port, s->dir, salt);
    atomic_store(&s->server.client_done, true);
    pthread_join(server, NULL);
    return s->server.server_ok && s->server.manifest_seen && !s->server.unexpected;
}

static bool fs_prefix_case_verify(const struct fs_prefix_case_state *s, bool retry)
{
    if (retry) return s->result == FS_RECEIVE_COMPLETE && s->server.range_seen && s->server.retry_seen &&
        fs_prefix_file_equals(s->block, 'A') && fs_prefix_file_equals(s->index, 'B');
    return s->result == FS_RECEIVE_ERROR && !s->server.range_seen && !s->server.retry_seen &&
        fs_prefix_file_equals(s->block, 'X') && access(s->index, F_OK) != 0;
}

static int fs_prefix_case(bool retry)
{
    struct fs_prefix_case_state s = {0};
    bool ok = fs_prefix_case_prepare(&s, retry) && fs_prefix_case_run(&s) && fs_prefix_case_verify(&s, retry);
    if (s.server.listener >= 0) close(s.server.listener);
    fs_receive_destroy(s.op);
    cleanup_file_controller_test_dir(s.dir);
    printf("file_controller: verified prefix %s... %s\n", retry ? "retry" : "shortfall", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int fs_prefix_case_isolated(bool retry)
{
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) { signal(SIGALRM, SIG_DFL); alarm(45); _exit(fs_prefix_case(retry)); }
    int status; pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

static bool fs_history_invalid(struct file_chunk chunks[3], struct file_manifest *expected, bool ok)
{
    expected->root_hash[0] ^= 1;
    ok = ok && !fs_test_expected_manifest(chunks, 3, 12, expected);
    expected->root_hash[0] ^= 1;
    chunks[0].sha3[0] ^= 1;
    ok = ok && !fs_test_expected_manifest(chunks, 3, 12, expected);
    chunks[0].sha3[0] ^= 1;
    ok = ok && !fs_test_expected_manifest(chunks, 3, 11, expected);
    chunks[1].offset = 3; ok = ok && !fs_test_manifest_extents(chunks, 3) &&
        !fs_test_expected_manifest(chunks, 3, 12, expected);
    chunks[1].offset = 5; ok = ok && !fs_test_manifest_extents(chunks, 3);
    chunks[1].offset = UINT64_MAX; ok = ok && !fs_test_manifest_extents(chunks, 3);
    chunks[1].offset = 4; chunks[2].file_index = 255;
    ok = ok && !fs_test_manifest_extents(chunks, 3);
    return ok;
}

static bool fs_history_resume_cases(const char *dir, const char *link, bool ok)
{
    struct file_chunk resumed[2] = {0};
    resumed[0].file_index = resumed[1].file_index = 253;
    resumed[0].size = resumed[1].size = 4; resumed[1].offset = 4;
    uint8_t four[4] = {1,1,1,1};
    sha3_256(four, sizeof(four), resumed[0].sha3);
    memcpy(resumed[1].sha3, resumed[0].sha3, 32);
    ok = ok && fs_test_resume(dir, resumed, 2) == 2;
    FILE *mutate = fopen(link, "r+b");
    if (!mutate) ok = false;
    else { bool wrote = fseek(mutate, 4, SEEK_SET) == 0 && fputc(2, mutate) != EOF;
        if (fclose(mutate) != 0 || !wrote) ok = false; }
    ok = ok && fs_test_resume(dir, resumed, 2) == 1;
    return ok;
}

static bool fs_history_file_cases(bool ok)
{
    char dir[256], target[512], link[512];
    test_make_tmpdir(dir, sizeof(dir), "file_controller", "history-symlink");
    snprintf(target, sizeof(target), "%s/target", dir);
    snprintf(link, sizeof(link), "%s/block_index.bin", dir);
    test_file_write_bytes(target, 4, 1);
    ok = ok && symlink("target", link) == 0 && !fs_test_chunk_open(dir, 253);
    ok = ok && unlink(link) == 0;
    ok = ok && mkfifo(link, 0600) == 0 && !fs_test_chunk_open(dir, 253);
    ok = ok && unlink(link) == 0;
    test_file_write_bytes(link, 8, 1);
    ok = ok && !fs_test_output_size(dir, 253, 4, false) &&
         !fs_test_output_size(dir, 253, 4, true) &&
         fs_test_output_size(dir, 253, 8, true);
    ok = fs_history_resume_cases(dir, link, ok);
    cleanup_file_controller_test_dir(dir);
    return ok;
}

static bool fs_history_basic(struct file_chunk chunks[3], struct file_manifest *expected)
{
    bool ok = fs_test_receive_challenge_difficulty(PUZZLE_MIN_BITS) &&
        fs_test_receive_challenge_difficulty(PUZZLE_MAX_BITS) &&
        !fs_test_receive_challenge_difficulty(PUZZLE_MIN_BITS - 1) &&
        !fs_test_receive_challenge_difficulty(PUZZLE_MAX_BITS + 1) &&
        fs_test_receive_cancel_fd() && test_fs_adoption_isolated() && fs_test_boundary_aggregation() && fs_test_expected_manifest(chunks, 3, 12, expected) &&
        fs_test_manifest_extents(chunks, 3) &&
        fs_test_manifest_frame_compat() && fs_test_manifest_sequence(FILE_MAX_CHUNKS, true) &&
        !fs_test_manifest_sequence(FILE_MAX_CHUNKS + 1, true) &&
        !fs_test_manifest_sequence(FILE_MAX_CHUNKS, false);
    return ok;
}

static int test_fs_history_inputs(void)
{
    struct file_chunk chunks[3] = {0};
    chunks[0].size = 4; chunks[1].size = 4; chunks[1].offset = 4;
    chunks[2].file_index = 253; chunks[2].size = 4;
    struct file_manifest expected = {.num_chunks = 3, .total_bytes = 12};
    memcpy(expected.chunks, chunks, sizeof(chunks));
    struct sha3_256_ctx digest;
    sha3_256_init(&digest);
    for (unsigned i = 0; i < 3; ++i) sha3_256_write(&digest, chunks[i].sha3, 32);
    sha3_256_finalize(&digest, expected.root_hash);
    bool ok = fs_history_basic(chunks, &expected);
    ok = fs_history_invalid(chunks, &expected, ok);
    ok = fs_history_file_cases(ok);
    printf("file_controller: history extents and symlink refusal... %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
#endif

int test_file_controller(void)
{
    int failures = 0;
#if !defined(_WIN32) && defined(ZCL_TESTING)
    failures += test_fs_history_inputs();
    failures += fs_prefix_case_isolated(false);
    failures += fs_prefix_case_isolated(true);
    failures += test_fs_history_inventory();
    for (int behavior = 0; behavior < 10; ++behavior) failures += test_fs_manifest_case_isolated(behavior);
#endif
#if !defined(_WIN32)
    failures += test_immutable_manifest();
#endif

    failures += test_manifest_build_includes_snapshot();
    failures += test_manifest_cache_rebuilds_when_snapshot_appears();
    failures += test_manifest_skips_hot_block_index();
    failures += test_controller_refresh_manifest_api();
    failures += test_manifest_status_reports_export_readiness();
    failures += test_file_service_start_stop_and_lifetime();
    failures += test_file_service_range_worker_socket_lifecycle();
    failures += test_file_service_resolved_connect_lifecycle();
    failures += test_file_export_snapshot_success();
    failures += test_file_export_snapshot_fail_closes_partial();
    failures += test_file_export_snapshot_rejects_overlong_datadir();
    failures += test_file_export_snapshot_rejects_empty_datadir();

    return failures;
}
