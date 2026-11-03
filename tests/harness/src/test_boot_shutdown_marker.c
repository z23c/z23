/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_block_files_fingerprint.h"
#include "config/boot_shutdown_marker.h"
#include "config/boot_fast_restart.h"
#include "chain/chain.h"
#include "event/event.h"
#include "platform/private_file.h"
#include "util/thread_registry.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
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

/* A one-page file carrying node.db's header identity fields. */
static bool bsm_write_db_header(const char *path, uint32_t counter)
{
    unsigned char page[4096];
    memset(page, 0, sizeof(page));
    memcpy(page, "SQLite format 3", 16);
    for (int i = 0; i < 4; i++) {
        page[24 + i] = (unsigned char)(counter >> (24 - 8 * i));
        page[92 + i] = page[24 + i];
    }
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(page, 1, sizeof(page), f) == sizeof(page);
    if (f && fclose(f) != 0)
        ok = false;
    return ok;
}

/* The offline writer's peek: verified-clean only for the bound identity,
 * readable while a booting node holds the marker locked, and the marker is
 * still the boot's to consume afterwards. */
static int bsm_check_peek_verified_clean(void)
{
    int failures = 0;
    char dir[256], marker[512], db[512], buf[1024];
    test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "peek");
    snprintf(marker, sizeof(marker), "%s/.shutdown_clean", dir);
    snprintf(db, sizeof(db), "%s/node.db", dir);
    struct shutdown_clean_binding b = {
        .valid = true, .node_db_size = 4096, .change_counter = 7,
        .version_valid_for = 7, .schema_version = 3,
    };
    int n = boot_shutdown_marker_format(buf, sizeof(buf), 1713100000LL, &b);
    bool ok = bsm_write_db_header(db, 7) &&
              !boot_shutdown_marker_peek_verified_clean(dir, db) &&
              bsm_store_marker_text(marker, buf, n);
    BSM_CHECK("peek: no marker is not verified-clean, a bound one is",
              ok && boot_shutdown_marker_peek_verified_clean(dir, db));
#if !defined(_WIN32)
    /* A peek that locked the marker would make a booting node that tried
     * at the same moment treat it as absent. */
    struct platform_private_file held;
    platform_private_file_init(&held);
    bool locked = platform_private_file_open_locked(marker, &held);
    BSM_CHECK("peek: reads the marker while another holder locks it",
              locked && boot_shutdown_marker_peek_verified_clean(dir, db));
    platform_private_file_close(&held);
#endif
    boot_shutdown_marker_reset_for_test();
    bool unclean = boot_shutdown_marker_detect_unclean(dir);
    bool skipped = boot_shutdown_marker_quick_check_probe(db) &&
                   boot_shutdown_marker_quick_check_was_skipped();
    BSM_CHECK("peek: the boot still consumes the marker and skips",
              ok && !unclean && skipped && access(marker, F_OK) != 0);
    boot_shutdown_marker_reset_for_test();
    ok = bsm_store_marker_text(marker, buf, n) && bsm_write_db_header(db, 8);
    BSM_CHECK("peek: a binding for another identity is not verified-clean",
              ok && !boot_shutdown_marker_peek_verified_clean(dir, db));
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

/* ── Block-file fingerprint: recorded at shutdown, gates the boot scan ── */

static bool bsm_bf_make_file(const char *dir, const char *name,
                             const char *text)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return bsm_write_file(path, text);
}

static bool bsm_bf_append(const char *dir, const char *name)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "ab");
    bool ok = f && fwrite("x", 1, 1, f) == 1;
    if (f) fclose(f);
    return ok;
}

static bool bsm_bf_set_mtime(const char *dir, const char *name, long sec)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    struct timespec ts[2] = {{.tv_sec = sec}, {.tv_sec = sec}};
    return utimensat(AT_FDCWD, path, ts, 0) == 0;
}

static int bsm_check_block_file_fingerprint(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "bfp");
    char blocks[300];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    bool setup = mkdir(blocks, 0700) == 0 &&
                 bsm_bf_make_file(blocks, "blk00000.dat", "aaaa") &&
                 bsm_bf_make_file(blocks, "blk00001.dat", "bbbbbb");

    struct boot_block_files_fingerprint at_shutdown, now;
    BSM_CHECK("fingerprint: reads two block files",
              setup && boot_block_files_fingerprint_read(dir, &at_shutdown) &&
              at_shutdown.count == 2);

    struct shutdown_clean_binding rec;
    memset(&rec, 0, sizeof(rec));
    rec.fr_valid = true;
    rec.bf_valid = true;
    rec.bf_count = at_shutdown.count;
    memcpy(rec.bf_sha3, at_shutdown.sha3, 32);

    BSM_CHECK("scan skip: unchanged files after a taken fast restart",
              boot_block_files_fingerprint_read(dir, &now) &&
              boot_block_files_scan_may_skip(true, &rec, &now));
    BSM_CHECK("scan skip: refused when fast restart was not taken",
              !boot_block_files_scan_may_skip(false, &rec, &now));

    struct shutdown_clean_binding old_marker = rec;
    old_marker.bf_valid = false;
    BSM_CHECK("scan skip: refused for a marker without a fingerprint",
              !boot_block_files_scan_may_skip(true, &old_marker, &now));
    BSM_CHECK("scan skip: refused without a recorded binding or fingerprint",
              !boot_block_files_scan_may_skip(true, NULL, &now) &&
              !boot_block_files_scan_may_skip(true, &rec, NULL));

    BSM_CHECK("scan skip: one file grown means scan",
              bsm_bf_append(blocks, "blk00001.dat") &&
              boot_block_files_fingerprint_read(dir, &now) &&
              !boot_block_files_scan_may_skip(true, &rec, &now));

    (void)bsm_bf_make_file(blocks, "blk00001.dat", "bbbbbb");
    BSM_CHECK("scan skip: same size, different mtime means scan",
              bsm_bf_set_mtime(blocks, "blk00001.dat", 1000000000L) &&
              boot_block_files_fingerprint_read(dir, &now) &&
              !boot_block_files_scan_may_skip(true, &rec, &now));

    BSM_CHECK("scan skip: an extra block file means scan",
              bsm_bf_make_file(blocks, "blk00002.dat", "c") &&
              boot_block_files_fingerprint_read(dir, &now) &&
              now.count == 3 &&
              !boot_block_files_scan_may_skip(true, &rec, &now));

    test_rm_rf_recursive(dir);
    return failures;
}

/* The digest is fixed by the little-endian encoding of slot, size, mtime
 * seconds and nanoseconds per file; changing it invalidates every recorded
 * marker. */
static int bsm_check_block_file_fingerprint_encoding(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker", "bfe");
    char blocks[300];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    bool setup = mkdir(blocks, 0700) == 0 &&
                 bsm_bf_make_file(blocks, "blk00000.dat", "aaaa") &&
                 bsm_bf_set_mtime(blocks, "blk00000.dat", 0x0102030405L);
    /* slot 0, size 4, seconds 0x0102030405, nanoseconds 0. */
    static const unsigned char expect_in[32] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        4, 0, 0, 0, 0, 0, 0, 0,
        0x05, 0x04, 0x03, 0x02, 0x01, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0};
    struct sha3_256_ctx h;
    uint8_t expect[32];
    sha3_256_init(&h);
    sha3_256_write(&h, expect_in, sizeof(expect_in));
    sha3_256_finalize(&h, expect);
    struct boot_block_files_fingerprint fp;
    BSM_CHECK("fingerprint: digest is the little-endian slot, size and mtime",
              setup && boot_block_files_fingerprint_read(dir, &fp) &&
              fp.count == 1 && memcmp(fp.sha3, expect, 32) == 0);
    test_rm_rf_recursive(dir);
    return failures;
}

static int bsm_check_block_file_marker_roundtrip(void)
{
    int failures = 0;
    struct shutdown_clean_binding b;
    memset(&b, 0, sizeof(b));
    b.valid = true;
    b.node_db_size = 10;
    b.fr_valid = true;
    b.fr_tip_height = 5;
    b.bf_valid = true;
    b.bf_count = 35;
    for (int i = 0; i < 32; i++) b.bf_sha3[i] = (uint8_t)(i * 7 + 1);
    char buf[2048];
    int n = boot_shutdown_marker_format(buf, sizeof(buf), 1713100000LL, &b);
    struct shutdown_clean_binding got;
    BSM_CHECK("marker: block-file fingerprint round-trips",
              n > 0 && boot_shutdown_marker_parse(buf, (size_t)n, &got) &&
              got.bf_valid && got.bf_count == 35 &&
              memcmp(got.bf_sha3, b.bf_sha3, 32) == 0 && got.fr_valid);

    b.bf_valid = false;
    n = boot_shutdown_marker_format(buf, sizeof(buf), 1713100000LL, &b);
    BSM_CHECK("marker: old marker without the keys parses with no fingerprint",
              n > 0 && boot_shutdown_marker_parse(buf, (size_t)n, &got) &&
              got.valid && got.fr_valid && !got.bf_valid &&
              !boot_block_files_scan_may_skip(true, &got, &(struct boot_block_files_fingerprint){.count = 35}));
    return failures;
}

/* The shutdown writer records the fingerprint and the next boot reads it. */
static int bsm_check_block_file_shutdown_wiring(void)
{
    int failures = 0;
    struct bsm_marker_write w;
    bsm_prepare_marker_datadir(&w);
    char blocks[600], node_db[600];
    snprintf(blocks, sizeof(blocks), "%s/blocks", w.dir);
    snprintf(node_db, sizeof(node_db), "%s/node.db", w.dir);
    uint8_t header[4096] = "SQLite format 3";
    FILE *f = fopen(node_db, "wb");
    bool setup = f && fwrite(header, 1, sizeof(header), f) == sizeof(header);
    if (f) fclose(f);
    setup = setup && mkdir(blocks, 0700) == 0 &&
            bsm_bf_make_file(blocks, "blk00000.dat", "data");

    boot_shutdown_marker_reset_for_test();
    struct fast_restart_shutdown_facts facts;
    memset(&facts, 0, sizeof(facts));
    facts.valid = true;
    facts.tip_height = 9;
    facts.coins_best_height = 9;
    boot_shutdown_marker_set_fast_restart_facts(&facts);
    bool wrote = setup && boot_shutdown_marker_write_clean(w.dir);
    boot_shutdown_marker_reset_for_test();
    bool unclean = boot_shutdown_marker_detect_unclean(w.dir);
    struct shutdown_clean_binding peeked;
    bool have = boot_shutdown_marker_peek_fast_restart_binding(&peeked);
    struct boot_block_files_fingerprint now;
    BSM_CHECK("shutdown marker records the block-file fingerprint",
              wrote && !unclean && have && peeked.bf_valid &&
              boot_block_files_fingerprint_read(w.dir, &now) &&
              boot_block_files_scan_may_skip(true, &peeked, &now));
    boot_shutdown_marker_reset_for_test();
    test_rm_rf_recursive(w.dir);
    return failures;
}

/* ── Shutdown binding: container tip versus durable tip ── */

static int bsm_check_container_tip_relation(void)
{
    int failures = 0;
    enum { N = 300 };
    static struct block_index chain[N];
    static struct block_index fork[N];
    memset(chain, 0, sizeof(chain));
    memset(fork, 0, sizeof(fork));
    for (int i = 0; i < N; i++) {
        chain[i].nHeight = i;
        chain[i].pprev = i ? &chain[i - 1] : NULL;
        fork[i].nHeight = i;
        fork[i].pprev = i > 150 ? &fork[i - 1] : (i ? &chain[i - 1] : NULL);
    }
    const struct block_index *d = &chain[200];

    BSM_CHECK("tip relation: identical tips match",
              boot_fast_restart_tip_matches_container(d, d));
    BSM_CHECK("tip relation: container one block behind durable matches",
              boot_fast_restart_tip_matches_container(&chain[199], d));
    BSM_CHECK("tip relation: container one block ahead of durable matches",
              boot_fast_restart_tip_matches_container(&chain[201], d));
    BSM_CHECK("tip relation: container at the gap bound matches",
              boot_fast_restart_tip_matches_container(
                  &chain[200 - BOOT_FR_CONTAINER_GAP_MAX], d));
    BSM_CHECK("tip relation: container past the gap bound is refused",
              !boot_fast_restart_tip_matches_container(
                  &chain[200 - BOOT_FR_CONTAINER_GAP_MAX - 1], d) &&
              !boot_fast_restart_tip_matches_container(
                  &chain[200 + BOOT_FR_CONTAINER_GAP_MAX + 1], d));
    BSM_CHECK("tip relation: container on another branch is refused",
              !boot_fast_restart_tip_matches_container(&fork[199], d) &&
              !boot_fast_restart_tip_matches_container(&fork[201], d));
    BSM_CHECK("tip relation: a tip near genesis is refused",
              !boot_fast_restart_tip_matches_container(&chain[10], &chain[12]));
    BSM_CHECK("tip relation: missing tips are refused",
              !boot_fast_restart_tip_matches_container(NULL, d) &&
              !boot_fast_restart_tip_matches_container(d, NULL));
    struct block_index broken = chain[199];
    broken.pprev = NULL;
    BSM_CHECK("tip relation: a broken pprev chain is refused",
              !boot_fast_restart_tip_matches_container(&broken, d) &&
              !boot_fast_restart_tip_matches_container(
                  &chain[201], &broken));
    return failures;
}

/* ── Shutdown binding decision (container tip, durable tip, coins-best) ── */

enum { BSM_DEC_N = 300 };
static struct block_index g_dec_chain[BSM_DEC_N];
static struct uint256 g_dec_hash[BSM_DEC_N];

/* Inputs with the durable tip at `d`; `coins` NULL means the derive found no
 * frontier. */
static struct boot_fr_capture_inputs bsm_dec_inputs(
    int container, int d, const struct block_index *coins,
    const uint8_t *coins_hash)
{
    struct boot_fr_capture_inputs in;
    memset(&in, 0, sizeof(in));
    in.container_tip = &g_dec_chain[container];
    in.durable_found = true;
    in.durable_height = d;
    memcpy(in.durable_hash, g_dec_hash[d].data, 32);
    in.durable_block = &g_dec_chain[d];
    in.block_index_count = 1234;
    if (coins) {
        in.coins_derived = true;
        in.coins_found = true;
        in.coins_height = coins->nHeight;
        memcpy(in.coins_hash, coins_hash, 32);
    }
    return in;
}

static const char *bsm_dec(const struct boot_fr_capture_inputs *in,
                           struct fast_restart_shutdown_facts *fr)
{
    memset(fr, 0, sizeof(*fr));
    return boot_fast_restart_decide_facts(in, fr);
}

/* strcmp against the refusal reason; a recorded binding compares as
 * "recorded" so a wrong verdict fails the check instead of crashing it. */
static int bsm_cmp(const struct boot_fr_capture_inputs *in,
                   struct fast_restart_shutdown_facts *fr, const char *want)
{
    const char *why = bsm_dec(in, fr);
    return strcmp(why ? why : "recorded", want);
}

static int bsm_check_capture_decision(void)
{
    int failures = 0;
    memset(g_dec_chain, 0, sizeof(g_dec_chain));
    memset(g_dec_hash, 0, sizeof(g_dec_hash));
    for (int i = 0; i < BSM_DEC_N; i++) {
        g_dec_hash[i].data[0] = (uint8_t)(i & 0xff);
        g_dec_hash[i].data[1] = (uint8_t)(i >> 8);
        g_dec_hash[i].data[2] = 0x5a;
        g_dec_chain[i].nHeight = i;
        g_dec_chain[i].phashBlock = &g_dec_hash[i];
        g_dec_chain[i].pprev = i ? &g_dec_chain[i - 1] : NULL;
    }
    struct fast_restart_shutdown_facts fr;
    const uint8_t *dh = g_dec_hash[200].data;
    struct boot_fr_capture_inputs in;

    in = bsm_dec_inputs(200, 200, NULL, NULL);
    BSM_CHECK("capture: exact tips record even without a coins frontier",
              bsm_dec(&in, &fr) == NULL && fr.valid &&
              fr.tip_height == 200 && fr.coins_best_height == 200 &&
              memcmp(fr.tip_hash, dh, 32) == 0 &&
              fr.block_index_count == 1234);

    in = bsm_dec_inputs(203, 200, &g_dec_chain[203], g_dec_hash[203].data);
    BSM_CHECK("capture: container ahead, coins-best above durable refuses",
              bsm_cmp(&in, &fr, "coins_best_not_durable_tip") == 0 &&
              !fr.valid);
    in = bsm_dec_inputs(203, 200, NULL, NULL);
    BSM_CHECK("capture: container ahead, no coins frontier refuses",
              bsm_cmp(&in, &fr, "coins_best_not_durable_tip") == 0);
    in = bsm_dec_inputs(203, 200, &g_dec_chain[199], g_dec_hash[199].data);
    BSM_CHECK("capture: container ahead, coins-best below durable refuses",
              bsm_cmp(&in, &fr, "coins_best_not_durable_tip") == 0);
    in = bsm_dec_inputs(203, 200, &g_dec_chain[200], g_dec_hash[201].data);
    BSM_CHECK("capture: coins-best at the durable height with another hash "
              "refuses",
              bsm_cmp(&in, &fr, "coins_best_not_durable_tip") == 0);
    in = bsm_dec_inputs(203, 200, &g_dec_chain[201], g_dec_hash[200].data);
    BSM_CHECK("capture: coins-best with the durable hash at another height "
              "refuses",
              bsm_cmp(&in, &fr, "coins_best_not_durable_tip") == 0);

    in = bsm_dec_inputs(203, 200, &g_dec_chain[200], dh);
    BSM_CHECK("capture: container ahead, coins-best at durable binds the "
              "durable tip",
              bsm_dec(&in, &fr) == NULL && fr.valid && fr.tip_height == 200 &&
              fr.coins_best_height == 200 &&
              memcmp(fr.tip_hash, dh, 32) == 0);
    in = bsm_dec_inputs(198, 200, &g_dec_chain[200], dh);
    BSM_CHECK("capture: container behind, coins-best at durable binds the "
              "durable tip",
              bsm_dec(&in, &fr) == NULL && fr.tip_height == 200);

    in = bsm_dec_inputs(200 - BOOT_FR_CONTAINER_GAP_MAX, 200,
                        &g_dec_chain[200], dh);
    BSM_CHECK("capture: a gap of 64 records",
              bsm_dec(&in, &fr) == NULL);
    in = bsm_dec_inputs(200 - BOOT_FR_CONTAINER_GAP_MAX - 1, 200,
                        &g_dec_chain[200], dh);
    BSM_CHECK("capture: a gap of 65 refuses",
              bsm_cmp(&in, &fr, "container_tip_lags_durable_tip") ==
              0);

    in = bsm_dec_inputs(63, 64, &g_dec_chain[64], g_dec_hash[64].data);
    BSM_CHECK("capture: lower tip at height 63 refuses",
              bsm_cmp(&in, &fr, "container_tip_lags_durable_tip") ==
              0);
    in = bsm_dec_inputs(64, 65, &g_dec_chain[65], g_dec_hash[65].data);
    BSM_CHECK("capture: lower tip at height 64 records",
              bsm_dec(&in, &fr) == NULL);

    in = bsm_dec_inputs(200, 200, NULL, NULL);
    in.durable_block = NULL;
    BSM_CHECK("capture: durable block absent from the index refuses",
              bsm_cmp(&in, &fr, "container_tip_lags_durable_tip") ==
              0);
    in = bsm_dec_inputs(200, 200, NULL, NULL);
    in.durable_found = false;
    BSM_CHECK("capture: no durable tip refuses",
              bsm_cmp(&in, &fr, "no_durable_tip") == 0);
    in = bsm_dec_inputs(200, 200, NULL, NULL);
    in.container_tip = NULL;
    BSM_CHECK("capture: no container tip refuses",
              bsm_cmp(&in, &fr, "no_container_tip") == 0);
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
    failures += bsm_check_peek_verified_clean();
    failures += bsm_check_evaluate_verdicts();
    failures += bsm_check_block_file_marker_roundtrip();
    failures += bsm_check_block_file_fingerprint();
    failures += bsm_check_block_file_fingerprint_encoding();
    failures += bsm_check_block_file_shutdown_wiring();
    failures += bsm_check_container_tip_relation();
    failures += bsm_check_capture_decision();

    return failures;
}
