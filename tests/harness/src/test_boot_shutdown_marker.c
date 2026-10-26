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

static int bsm_check_wal_without_marker(void)
{
    int failures = 0;
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
    return failures;
}

static int bsm_check_clean_marker_consumed(void)
{
    int failures = 0;
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
    return failures;
}

static int bsm_check_first_boot_quiet(void)
{
    int failures = 0;
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
    return failures;
}

struct bsm_marker_write {
    char dir[256];
    char marker[512];
    char buf[64];
    bool dir_absolute;
    bool dir_chmod;
    bool dir_stat;
    int setup_errno;
    unsigned dir_mode;
    bool dir_private;
    bool marker_fits;
    bool wrote;
    int write_errno;
    bool read_back;
    long stamp;
    char *end;
    bool timestamped;
};

static void bsm_prepare_marker_datadir(struct bsm_marker_write *w)
{
    test_make_tmpdir(w->dir, sizeof(w->dir), "boot_shutdown_marker", "write");
    /* test_fmt_tmpdir() already spells the fixture absolutely, as
     * platform_private_path_resolve() demands of a parent, so do NOT
     * prepend getcwd(). platform_private_directory_ensure() requires the
     * datadir mode to be exactly 0700, so pin and verify it. */
    struct stat dir_st;
    w->dir_absolute = w->dir[0] == '/';
    errno = 0;
    w->dir_chmod = chmod(w->dir, 0700) == 0;
    w->dir_stat = stat(w->dir, &dir_st) == 0;
    w->setup_errno = errno;
    w->dir_mode = w->dir_stat ? (unsigned)(dir_st.st_mode & 07777) : 0u;
    w->dir_private = w->dir_chmod && w->dir_stat && w->dir_mode == 0700;
    int marker_n = snprintf(w->marker, sizeof(w->marker), "%s/.shutdown_clean",
                            w->dir);
    w->marker_fits = marker_n > 0 && (size_t)marker_n < sizeof(w->marker);
}

static void bsm_record_clean_marker_timestamp(struct bsm_marker_write *w)
{
    errno = 0;
    w->wrote = w->dir_absolute && w->dir_private && w->marker_fits &&
               boot_shutdown_marker_write_clean(w->dir);
    w->write_errno = errno;
    w->read_back = w->wrote && bsm_read_file(w->marker, w->buf, sizeof(w->buf));
    w->end = NULL;
    w->stamp = w->read_back ? strtol(w->buf, &w->end, 10) : 0;
    w->timestamped = w->read_back && w->stamp > 0 && w->end && *w->end == '\n';
}

static int bsm_check_write_clean_timestamp(void)
{
    int failures = 0;
    struct bsm_marker_write w = {0};
    bsm_prepare_marker_datadir(&w);
    bsm_record_clean_marker_timestamp(&w);
    BSM_CHECK("write clean marker with timestamp", w.timestamped);
    if (!w.timestamped)
        printf("  datadir=%s\n"
               "  absolute=%d private=%d "
               "(chmod=%d stat=%d mode=%04o errno=%s) marker_fits=%d\n"
               "  write_clean=%d (errno=%s) read_back=%d "
               "stamp=%ld trailing=%d\n"
               "  marker=%s\n"
               "  content=[%s]\n",
               w.dir, (int)w.dir_absolute, (int)w.dir_private, (int)w.dir_chmod,
               (int)w.dir_stat, w.dir_mode, strerror(w.setup_errno),
               (int)w.marker_fits, (int)w.wrote,
               strerror(w.write_errno), (int)w.read_back, w.stamp,
               w.read_back && w.end ? (int)*w.end : -1, w.marker,
               w.read_back ? w.buf : "");
    test_rm_rf_recursive(w.dir);
    return failures;
}

static bool bsm_v3_binding_fields_match(const struct shutdown_clean_binding *got,
                                        const struct shutdown_clean_binding *b)
{
    return got->valid && got->fr_valid &&
           got->fr_tip_height == b->fr_tip_height &&
           memcmp(got->fr_tip_hash, b->fr_tip_hash, 32) == 0 &&
           got->fr_coins_best_height == b->fr_coins_best_height &&
           memcmp(got->fr_coins_best_hash, b->fr_coins_best_hash, 32) == 0 &&
           got->fr_block_index_count == b->fr_block_index_count &&
           got->fr_mmb_leaves == b->fr_mmb_leaves &&
           got->fr_sapling_ckpt_height == b->fr_sapling_ckpt_height &&
           /* v2 quick_check identity still parses */
           got->node_db_size == b->node_db_size &&
           got->change_counter == b->change_counter;
}

static int bsm_check_v3_binding_roundtrip(void)
{
    /* ── Tier-2 P2 fast-restart binding: format/parse round-trip ───────── */
    int failures = 0;
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
              parsed && bsm_v3_binding_fields_match(&got, &b));
    return failures;
}

static int bsm_check_v2_only_marker(void)
{
    /* A v2-only marker (fr_valid=false) parses with no fast-restart binding. */
    int failures = 0;
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
    return failures;
}

static bool bsm_store_marker_text(const char *marker, const char *buf, int n)
{
    bool ok = (n > 0);
    FILE *mf = fopen(marker, "wb");
    ok = ok && mf && fwrite(buf, 1, (size_t)n, mf) == (size_t)n;
    if (mf) fclose(mf);
    return ok;
}

static int bsm_check_detect_caches_fr_binding(void)
{
    /* detect_unclean caches the fast-restart binding; peek returns it. */
    int failures = 0;
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
    bool ok = bsm_store_marker_text(marker, buf, n);

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
    return failures;
}

static void bsm_prime_all_bindings_verified(struct shutdown_clean_binding *b,
                                            struct boot_fast_restart_facts *f)
{
    memset(b, 0, sizeof(*b));
    b->fr_valid = true;
    b->fr_tip_height = 3000000;
    for (int i = 0; i < 32; i++) b->fr_tip_hash[i] = (uint8_t)(i + 5);
    b->fr_coins_best_height = 2999999;
    for (int i = 0; i < 32; i++) b->fr_coins_best_hash[i] = (uint8_t)(i + 9);
    b->fr_block_index_count = 3000100;

    memset(f, 0, sizeof(*f));
    f->node_db_clean = true;
    f->block_index_count = 3000100;
    f->tip_hash_found = true;
    f->tip_height = 3000000;
    f->coins_best_found = true;
    f->coins_best_height = 2999999;
    for (int i = 0; i < 32; i++) f->coins_best_hash[i] = (uint8_t)(i + 9);
}

static int bsm_check_evaluate_verdicts(void)
{
    /* ── boot_fast_restart_evaluate: the verify-then-trust decision ─────── */
    int failures = 0;
    struct shutdown_clean_binding b;
    struct boot_fast_restart_facts f;
    bsm_prime_all_bindings_verified(&b, &f);

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
    return failures;
}

int test_boot_shutdown_marker(void)
{
    int failures = 0;

    failures += bsm_check_wal_without_marker();
    failures += bsm_check_clean_marker_consumed();
    failures += bsm_check_first_boot_quiet();
    failures += bsm_check_write_clean_timestamp();

    BSM_CHECK("invalid datadir fails closed",
              !boot_shutdown_marker_detect_unclean(NULL) &&
              !boot_shutdown_marker_write_clean(""));

    /* A deferred multi-minute quick_check is registry-owned. Shutdown must
     * interrupt its SQLite VM so worker-drain can reach persistence, without
     * weakening the process watchdog or treating cancellation as corruption. */
    thread_registry_reset_for_test();
    thread_registry_request_shutdown();
    BSM_CHECK("background quick_check cooperatively interrupts on shutdown",
              boot_fast_restart_bg_quick_check_cancel_for_test());
    thread_registry_reset_for_test();

    failures += bsm_check_v3_binding_roundtrip();
    failures += bsm_check_v2_only_marker();
    failures += bsm_check_detect_caches_fr_binding();
    failures += bsm_check_evaluate_verdicts();

    return failures;
}
