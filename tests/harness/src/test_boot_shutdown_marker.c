/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_shutdown_marker.h"
#include "config/boot_fast_restart.h"
#include "event/event.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BSM_CHECK(name, expr) do {                                      \
    printf("boot_shutdown_marker: %s... ", (name));                   \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static _Atomic int g_bsm_crash_events;

static void bsm_crash_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t len, void *ctx)
{
    (void)peer_id;
    (void)payload;
    (void)len;
    (void)ctx;
    if (type == EV_CRASH_RECOVERY_START)
        atomic_fetch_add(&g_bsm_crash_events, 1);
}

static bool bsm_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    if (text && fputs(text, f) < 0) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static bool bsm_read_file(const char *path, char *out, size_t out_cap)
{
    if (!path || !out || out_cap == 0)
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, out_cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

int test_boot_shutdown_marker(void)
{
    int failures = 0;

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "unclean");
        char marker[512];
        char wal[512];
        snprintf(marker, sizeof(marker), "%s/.shutdown_clean", dir);
        snprintf(wal, sizeof(wal), "%s/node.db-wal", dir);
        bool ok = bsm_write_file(wal, "wal data");

        atomic_store(&g_bsm_crash_events, 0);
        event_clear_observers(EV_CRASH_RECOVERY_START);
        ok = ok && event_observe(EV_CRASH_RECOVERY_START,
                                 bsm_crash_observer, NULL);
        ok = ok && boot_shutdown_marker_detect_unclean(dir);
        BSM_CHECK("wal without marker emits crash recovery",
                  ok && atomic_load(&g_bsm_crash_events) == 1 &&
                  access(marker, F_OK) != 0 &&
                  access(wal, F_OK) == 0);
        event_clear_observers(EV_CRASH_RECOVERY_START);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "clean");
        char marker[512];
        char wal[512];
        snprintf(marker, sizeof(marker), "%s/.shutdown_clean", dir);
        snprintf(wal, sizeof(wal), "%s/node.db-wal", dir);
        bool ok = bsm_write_file(marker, "1713100000\n");
        ok = ok && bsm_write_file(wal, "wal data");

        atomic_store(&g_bsm_crash_events, 0);
        event_clear_observers(EV_CRASH_RECOVERY_START);
        ok = ok && event_observe(EV_CRASH_RECOVERY_START,
                                 bsm_crash_observer, NULL);
        bool unclean = boot_shutdown_marker_detect_unclean(dir);
        BSM_CHECK("clean marker suppresses event and is consumed",
                  ok && !unclean &&
                  atomic_load(&g_bsm_crash_events) == 0 &&
                  access(marker, F_OK) != 0 &&
                  access(wal, F_OK) == 0);
        event_clear_observers(EV_CRASH_RECOVERY_START);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "first");

        atomic_store(&g_bsm_crash_events, 0);
        event_clear_observers(EV_CRASH_RECOVERY_START);
        bool ok = event_observe(EV_CRASH_RECOVERY_START,
                                bsm_crash_observer, NULL);
        bool unclean = boot_shutdown_marker_detect_unclean(dir);
        BSM_CHECK("first boot without wal stays quiet",
                  ok && !unclean &&
                  atomic_load(&g_bsm_crash_events) == 0);
        event_clear_observers(EV_CRASH_RECOVERY_START);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "write");
        char marker[512];
        char buf[64];
        /* test_fmt_tmpdir() (test/test_core.h) already spells the fixture
         * absolutely, which is exactly what platform_private_path_resolve()
         * demands of a parent — so do NOT prepend getcwd() again here.
         * platform_private_directory_ensure() additionally requires the
         * datadir's mode to be exactly 0700, so pin it and verify the pin
         * landed: a fixture that cannot say it failed to set itself up turns
         * a setup bug into a phantom writer defect. */
        struct stat dir_st;
        bool dir_absolute = dir[0] == '/';
        errno = 0;
        bool dir_chmod = chmod(dir, 0700) == 0;
        bool dir_stat = stat(dir, &dir_st) == 0;
        int setup_errno = errno;
        unsigned dir_mode = dir_stat ? (unsigned)(dir_st.st_mode & 07777) : 0u;
        bool dir_private = dir_chmod && dir_stat && dir_mode == 0700;
        int marker_n = snprintf(marker, sizeof(marker), "%s/.shutdown_clean",
                                dir);
        bool marker_fits = marker_n > 0 && (size_t)marker_n < sizeof(marker);

        errno = 0;
        bool wrote = dir_absolute && dir_private && marker_fits &&
                     boot_shutdown_marker_write_clean(dir);
        int write_errno = errno;
        bool read_back = wrote && bsm_read_file(marker, buf, sizeof(buf));
        char *end = NULL;
        long stamp = read_back ? strtol(buf, &end, 10) : 0;
        bool timestamped = read_back && stamp > 0 && end && *end == '\n';

        BSM_CHECK("write clean marker with timestamp", timestamped);
        if (!timestamped)
            printf("  datadir=%s\n"
                   "  absolute=%d private=%d "
                   "(chmod=%d stat=%d mode=%04o errno=%s) marker_fits=%d\n"
                   "  write_clean=%d (errno=%s) read_back=%d "
                   "stamp=%ld trailing=%d\n"
                   "  marker=%s\n"
                   "  content=[%s]\n",
                   dir, (int)dir_absolute, (int)dir_private, (int)dir_chmod,
                   (int)dir_stat, dir_mode, strerror(setup_errno),
                   (int)marker_fits, (int)wrote,
                   strerror(write_errno), (int)read_back, stamp,
                   read_back && end ? (int)*end : -1, marker,
                   read_back ? buf : "");
        test_rm_rf_recursive(dir);
    }

    BSM_CHECK("invalid datadir fails closed",
              !boot_shutdown_marker_detect_unclean(NULL) &&
              !boot_shutdown_marker_write_clean(""));

    /* A deferred multi-minute quick_check is registry-owned. Shutdown must
     * interrupt its SQLite VM so worker-drain can reach persistence without
     * weakening the process watchdog or treating cancellation as corruption. */
    thread_registry_reset_for_test();
    thread_registry_request_shutdown();
    BSM_CHECK("background quick_check cooperatively interrupts on shutdown",
              boot_fast_restart_bg_quick_check_cancel_for_test());
    thread_registry_reset_for_test();

    /* ── Tier-2 P2 fast-restart binding: format/parse round-trip ───────── */
    {
        struct shutdown_clean_binding b;
        memset(&b, 0, sizeof(b));
        b.valid = true;
        b.node_db_size = 123456789;
        b.change_counter = 42;
        b.version_valid_for = 7;
        b.schema_version = 3;
        b.fr_valid = true;
        b.fr_tip_height = 3176325;
        for (int i = 0; i < 32; i++) b.fr_tip_hash[i] = (uint8_t)(i + 1);
        b.fr_coins_best_height = 3176324;
        for (int i = 0; i < 32; i++) b.fr_coins_best_hash[i] = (uint8_t)(200 - i);
        b.fr_block_index_count = 3176500;
        b.fr_mmb_leaves = 3176326;
        b.fr_sapling_ckpt_height = 3170000;

        char buf[1024];
        int n = boot_shutdown_marker_format(buf, sizeof(buf), 1713100000LL, &b);
        struct shutdown_clean_binding got;
        bool parsed = (n > 0 && (size_t)n < sizeof(buf)) &&
                      boot_shutdown_marker_parse(buf, (size_t)n, &got);
        BSM_CHECK("v3 fast-restart binding round-trips through format/parse",
                  parsed && got.valid && got.fr_valid &&
                  got.fr_tip_height == b.fr_tip_height &&
                  memcmp(got.fr_tip_hash, b.fr_tip_hash, 32) == 0 &&
                  got.fr_coins_best_height == b.fr_coins_best_height &&
                  memcmp(got.fr_coins_best_hash, b.fr_coins_best_hash, 32) == 0 &&
                  got.fr_block_index_count == b.fr_block_index_count &&
                  got.fr_mmb_leaves == b.fr_mmb_leaves &&
                  got.fr_sapling_ckpt_height == b.fr_sapling_ckpt_height &&
                  /* v2 quick_check identity still parses */
                  got.node_db_size == b.node_db_size &&
                  got.change_counter == b.change_counter);
    }

    /* A v2-only marker (fr_valid=false) parses with no fast-restart binding. */
    {
        struct shutdown_clean_binding b;
        memset(&b, 0, sizeof(b));
        b.valid = true;
        b.node_db_size = 555;
        b.change_counter = 9;
        b.version_valid_for = 1;
        b.schema_version = 2;
        char buf[1024];
        int n = boot_shutdown_marker_format(buf, sizeof(buf), 1713100000LL, &b);
        struct shutdown_clean_binding got;
        bool parsed = (n > 0) &&
                      boot_shutdown_marker_parse(buf, (size_t)n, &got);
        BSM_CHECK("v2-only marker parses with fr_valid=false",
                  parsed && got.valid && !got.fr_valid);
    }

    /* detect_unclean caches the fast-restart binding; peek returns it. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "frpeek");
        char marker[512];
        snprintf(marker, sizeof(marker), "%s/.shutdown_clean", dir);

        struct shutdown_clean_binding b;
        memset(&b, 0, sizeof(b));
        b.valid = true;
        b.node_db_size = 100; b.change_counter = 3; b.version_valid_for = 3;
        b.schema_version = 3; b.fr_valid = true;
        b.fr_tip_height = 987654;
        for (int i = 0; i < 32; i++) b.fr_tip_hash[i] = (uint8_t)i;
        b.fr_coins_best_height = 987653;
        for (int i = 0; i < 32; i++) b.fr_coins_best_hash[i] = (uint8_t)(i * 3);
        b.fr_block_index_count = 987700;
        char buf[1024];
        int n = boot_shutdown_marker_format(buf, sizeof(buf), 1713100000LL, &b);
        bool ok = (n > 0);
        FILE *mf = fopen(marker, "wb");
        ok = ok && mf && fwrite(buf, 1, (size_t)n, mf) == (size_t)n;
        if (mf) fclose(mf);

        boot_shutdown_marker_reset_for_test();
        /* No node.db-wal in dir ⇒ clean path ⇒ parse + cache the fr binding. */
        bool unclean = boot_shutdown_marker_detect_unclean(dir);
        struct shutdown_clean_binding peeked;
        bool have = boot_shutdown_marker_peek_fast_restart_binding(&peeked);
        BSM_CHECK("detect_unclean caches fr binding, peek returns it",
                  ok && !unclean && have && peeked.fr_valid &&
                  peeked.fr_tip_height == b.fr_tip_height &&
                  memcmp(peeked.fr_tip_hash, b.fr_tip_hash, 32) == 0 &&
                  peeked.fr_block_index_count == b.fr_block_index_count &&
                  access(marker, F_OK) != 0 /* consumed (unlinked) */);
        boot_shutdown_marker_reset_for_test();
        test_rm_rf_recursive(dir);
    }

    /* ── boot_fast_restart_evaluate: the verify-then-trust decision ─────── */
    {
        struct shutdown_clean_binding b;
        memset(&b, 0, sizeof(b));
        b.fr_valid = true;
        b.fr_tip_height = 3000000;
        for (int i = 0; i < 32; i++) b.fr_tip_hash[i] = (uint8_t)(i + 5);
        b.fr_coins_best_height = 2999999;
        for (int i = 0; i < 32; i++) b.fr_coins_best_hash[i] = (uint8_t)(i + 9);
        b.fr_block_index_count = 3000100;

        struct boot_fast_restart_facts f;
        memset(&f, 0, sizeof(f));
        f.node_db_clean = true;
        f.block_index_count = 3000100;
        f.tip_hash_found = true;
        f.tip_height = 3000000;
        f.coins_best_found = true;
        f.coins_best_height = 2999999;
        for (int i = 0; i < 32; i++) f.coins_best_hash[i] = (uint8_t)(i + 9);

        struct boot_fast_restart_verdict v;

        boot_fast_restart_evaluate(&b, &f, &v);
        BSM_CHECK("evaluate: all bindings verified ⇒ fast_restart",
                  v.fast_restart &&
                  strcmp(v.reason, "all-bindings-verified") == 0);

        /* node.db not clean ⇒ refuse. */
        struct boot_fast_restart_facts f2 = f;
        f2.node_db_clean = false;
        boot_fast_restart_evaluate(&b, &f2, &v);
        BSM_CHECK("evaluate: node.db not clean ⇒ refuse",
                  !v.fast_restart &&
                  strcmp(v.reason, "node_db_not_clean") == 0);

        /* block_index_count mismatch ⇒ refuse. */
        f2 = f; f2.block_index_count = 3000099;
        boot_fast_restart_evaluate(&b, &f2, &v);
        BSM_CHECK("evaluate: block_index_count mismatch ⇒ refuse",
                  !v.fast_restart &&
                  strncmp(v.reason, "block_index_count", 17) == 0);

        /* tip hash absent ⇒ refuse. */
        f2 = f; f2.tip_hash_found = false;
        boot_fast_restart_evaluate(&b, &f2, &v);
        BSM_CHECK("evaluate: tip hash absent ⇒ refuse",
                  !v.fast_restart &&
                  strcmp(v.reason, "tip_hash_absent") == 0);

        /* tip height mismatch ⇒ refuse. */
        f2 = f; f2.tip_height = 2999998;
        boot_fast_restart_evaluate(&b, &f2, &v);
        BSM_CHECK("evaluate: tip height mismatch ⇒ refuse",
                  !v.fast_restart &&
                  strncmp(v.reason, "tip_height", 10) == 0);

        /* coins best height mismatch ⇒ refuse. */
        f2 = f; f2.coins_best_height = 2999998;
        boot_fast_restart_evaluate(&b, &f2, &v);
        BSM_CHECK("evaluate: coins_best height mismatch ⇒ refuse",
                  !v.fast_restart &&
                  strncmp(v.reason, "coins_best_height", 17) == 0);

        /* coins best hash mismatch ⇒ refuse. */
        f2 = f; f2.coins_best_hash[0] ^= 0xFF;
        boot_fast_restart_evaluate(&b, &f2, &v);
        BSM_CHECK("evaluate: coins_best hash mismatch ⇒ refuse",
                  !v.fast_restart &&
                  strcmp(v.reason, "coins_best_hash_mismatch") == 0);

        /* No fast-restart binding ⇒ refuse with the named reason. */
        struct shutdown_clean_binding nob;
        memset(&nob, 0, sizeof(nob));
        boot_fast_restart_evaluate(&nob, &f, &v);
        BSM_CHECK("evaluate: no fr binding ⇒ refuse",
                  !v.fast_restart &&
                  strcmp(v.reason, "no_fast_restart_binding") == 0);
    }

    return failures;
}
