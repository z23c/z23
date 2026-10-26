/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-2 fast restart — verified-clean quick_check skip marker.
 *
 * Proves the content-binding that lets a warm boot skip the blocking PRAGMA
 * quick_check when the previous shutdown left node.db provably clean, and the
 * unclean/unverified deferral that still skips the blocking check without
 * claiming node_db_clean:
 *   (a) format→parse round-trips a v2 binding exactly.
 *   (b) a corrupt / wrong-magic / wrong-version / not-checkpointed marker does
 *       NOT parse (never trusted).
 *   (c) the pure can_skip() decision: exact match → skip; size / change-counter
 *       / version-valid-for mismatch → run; WAL present → run; file absent → run.
 *   (d) node_db_file_identity_read parses a SQLite header off disk and rejects a
 *       non-SQLite file.
 *   (e) end-to-end: write_clean binds the on-disk node.db, detect_unclean caches
 *       + deletes the marker (single-use), the probe verified-clean-skips on a
 *       byte-identical file, is consumed after one call; a mutated header or
 *       WAL defers (blocking skip, was_skipped=false, was_deferred=true);
 *       missing node.db does not skip.
 *
 * All hermetic: temp files only, no sqlite, no live chain. */

#include "test/test_core.h"
#include "config/boot_shutdown_marker.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Write a minimal but structurally-valid SQLite-format-3 file of `size` bytes
 * whose header carries `change_counter` (offset 24) and `vvf` (offset 92). */
static bool write_fake_node_db(const char *path, int64_t size,
                               uint32_t change_counter, uint32_t vvf)
{
    if (size < 100)
        size = 100;
    uint8_t *buf = calloc(1, (size_t)size);
    if (!buf)
        return false;
    memcpy(buf, "SQLite format 3\0", 16);
    buf[24] = (uint8_t)(change_counter >> 24);
    buf[25] = (uint8_t)(change_counter >> 16);
    buf[26] = (uint8_t)(change_counter >> 8);
    buf[27] = (uint8_t)(change_counter);
    buf[92] = (uint8_t)(vvf >> 24);
    buf[93] = (uint8_t)(vvf >> 16);
    buf[94] = (uint8_t)(vvf >> 8);
    buf[95] = (uint8_t)(vvf);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { free(buf); return false; }
    ssize_t w = write(fd, buf, (size_t)size);
    close(fd);
    free(buf);
    return w == (ssize_t)size;
}

/* Boot once from a marker written with the given consensus.db on disk state
 * `mutate` (0 = untouched, 1 = size grown, 2 = header counter changed,
 * 3 = consensus.db absent at write time so the marker has no binding). Returns
 * what the consensus probe says on the first call; *second gets the 2nd call. */
static bool cdb_boot(const char *dir, int mutate, bool *second)
{
    char ndb[512], cdb[512];
    snprintf(ndb, sizeof(ndb), "%s/node.db", dir);
    snprintf(cdb, sizeof(cdb), "%s/consensus.db", dir);
    boot_shutdown_marker_reset_for_test();
    boot_shutdown_marker_set_schema_version(25);
    (void)write_fake_node_db(ndb, 40960, 0x01020304u, 0x01020304u);
    if (mutate == 3)
        unlink(cdb);
    else
        (void)write_fake_node_db(cdb, 81920, 0x11223344u, 0x11223344u);
    if (!boot_shutdown_marker_write_clean(dir))
        return true; /* forces the caller's expectation to fail loudly */
    (void)boot_shutdown_marker_detect_unclean(dir);
    if (mutate == 1)
        (void)write_fake_node_db(cdb, 90112, 0x11223344u, 0x11223344u);
    else if (mutate == 2)
        (void)write_fake_node_db(cdb, 81920, 0x11223345u, 0x11223345u);
    bool first = boot_shutdown_marker_consensus_quick_check_probe(cdb);
    *second = boot_shutdown_marker_consensus_quick_check_probe(cdb);
    return first;
}

static struct shutdown_clean_binding binding_fixture(bool with_cdb)
{
    struct shutdown_clean_binding b = {
        .valid = true, .node_db_size = 100, .change_counter = 7,
        .version_valid_for = 7, .schema_version = 25,
        .cdb_valid = true, .cdb_size = 1717986918400LL,
        .cdb_change_counter = 0xCAFEF00Du,
        .cdb_version_valid_for = 0xCAFEF00Du,
    };
    b.cdb_valid = with_cdb;
    return b;
}

static bool binding_roundtrip_ok(void)
{
    struct shutdown_clean_binding b = binding_fixture(true);
    char buf[1024];
    struct shutdown_clean_binding got;
    int n = boot_shutdown_marker_format(buf, sizeof(buf), 1700000000LL, &b);
    return n > 0 && boot_shutdown_marker_parse(buf, (size_t)n, &got) &&
           got.valid && got.cdb_valid &&
           got.cdb_size == b.cdb_size &&
           got.cdb_change_counter == b.cdb_change_counter &&
           got.cdb_version_valid_for == b.cdb_version_valid_for;
}

/* Marker from a binary that predates the keys: node.db binding still
 * parses, consensus.db has NO binding. */
static bool binding_old_marker_ok(void)
{
    struct shutdown_clean_binding b = binding_fixture(false);
    char buf[1024];
    struct shutdown_clean_binding got;
    int n = boot_shutdown_marker_format(buf, sizeof(buf), 1700000000LL, &b);
    return n > 0 && boot_shutdown_marker_parse(buf, (size_t)n, &got) &&
           got.valid && !got.cdb_valid &&
           strstr(buf, "consensus_db") == NULL;
}

/* Partial keys are not a binding. */
static bool binding_partial_ok(void)
{
    const char *partial =
        "1\nmagic=ZCLSHUT\nversion=2\nnode_db_size=1\n"
        "node_db_change_counter=1\nnode_db_version_valid_for=1\n"
        "schema_version=1\nwal_checkpointed=1\nconsensus_db_size=5\n";
    struct shutdown_clean_binding got;
    return boot_shutdown_marker_parse(partial, strlen(partial), &got) &&
           got.valid && !got.cdb_valid;
}

static int shutdown_marker_binding_format_case(void)
{
    printf("shutdown_marker consensus.db binding format/parse + old marker ... ");
    bool rt = binding_roundtrip_ok();
    bool old = binding_old_marker_ok();
    bool part = binding_partial_ok();
    if (rt && old && part) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (rt=%d old=%d partial=%d)\n", rt, old, part);
    return 1;
}

/* Results of the four matching/mismatching boots, each with the 2nd call. */
struct cdb_probe_run {
    bool match, s_match, size, s_size, hdr, s_hdr, none, s_none;
};

static void cdb_probe_run_bindings(const char *dir, struct cdb_probe_run *r)
{
    r->match = cdb_boot(dir, 0, &r->s_match);   /* matching -> skip once */
    r->size = cdb_boot(dir, 1, &r->s_size);     /* size changed -> check */
    r->hdr = cdb_boot(dir, 2, &r->s_hdr);       /* header changed -> check */
    r->none = cdb_boot(dir, 3, &r->s_none);     /* no binding -> check */
}

static bool cdb_probe_run_bindings_ok(const struct cdb_probe_run *r)
{
    return r->match && !r->s_match && !r->size && !r->hdr && !r->none &&
           !r->s_size && !r->s_hdr && !r->s_none;
}

static void cdb_probe_write_wal(const char *wal)
{
    int wf = open(wal, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wf >= 0) {
        (void)!write(wf, "w", 1);
        close(wf);
    }
}

/* A -wal beside an otherwise matching file -> check; crash (no marker at
 * all) -> check. */
static void cdb_probe_wal_and_crash(const char *dir, const char *cdb,
                                    bool *walp, bool *crash)
{
    char wal[512];
    snprintf(wal, sizeof(wal), "%s/consensus.db-wal", dir);
    bool wal_s = false;
    (void)cdb_boot(dir, 0, &wal_s); /* consumes; redo with WAL below */
    boot_shutdown_marker_reset_for_test();
    boot_shutdown_marker_set_schema_version(25);
    (void)write_fake_node_db(cdb, 81920, 0x11223344u, 0x11223344u);
    (void)boot_shutdown_marker_write_clean(dir);
    (void)boot_shutdown_marker_detect_unclean(dir);
    cdb_probe_write_wal(wal);
    *walp = boot_shutdown_marker_consensus_quick_check_probe(cdb);
    boot_shutdown_marker_reset_for_test();
    unlink(wal);
    *crash = boot_shutdown_marker_consensus_quick_check_probe(cdb);
}

static void cdb_probe_cleanup(const char *dir)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/consensus.db", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/consensus.db-wal", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/.shutdown_clean", dir);
    unlink(p);
    snprintf(p, sizeof(p), "%s/node.db", dir);
    unlink(p);
    test_cleanup_tmpdir(dir);
    boot_shutdown_marker_reset_for_test();
}

static int shutdown_marker_cdb_probe_case(void)
{
    printf("shutdown_marker consensus.db probe skip/mismatch/single-use ... ");
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "shutdown_marker", "cdb_probe");
    char cdb[512];
    snprintf(cdb, sizeof(cdb), "%s/consensus.db", dir);

    struct cdb_probe_run r = {0};
    cdb_probe_run_bindings(dir, &r);
    bool walp = false, crash = false;
    cdb_probe_wal_and_crash(dir, cdb, &walp, &crash);

    int failures = 0;
    if (cdb_probe_run_bindings_ok(&r) && !walp && !crash) {
        printf("OK\n");
    } else {
        printf("FAIL (match=%d/%d size=%d hdr=%d none=%d wal=%d crash=%d)\n",
               r.match, r.s_match, r.size, r.hdr, r.none, walp, crash);
        failures++;
    }
    cdb_probe_cleanup(dir);
    return failures;
}

static int shutdown_marker_consensus_cases(void)
{
    int failures = shutdown_marker_binding_format_case();
    return failures + shutdown_marker_cdb_probe_case();
}

/* ── progress_store_open consults the skip probe ───────────────────────── */
static int  g_skip_calls;
static bool g_skip_answer;
static bool skip_probe_stub(const char *path)
{
    (void)path;
    g_skip_calls++;
    return g_skip_answer;
}

static int count_quarantined(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strncmp(e->d_name, "consensus.db", 12) == 0 &&
            strstr(e->d_name, ".corrupt.") != NULL)
            n++;
    closedir(d);
    return n;
}

/* Seed consensus.db, garble an interior page, reopen with the probe answering
 * `answer`. Returns quarantine sidecars after the reopen, -1 on setup error.
 * *fresh_calls / *exist_calls = probe consultations on the first (file absent)
 * and second (file present) open. */
static int skip_probe_reopen(const char *dir, bool answer,
                             int *fresh_calls, int *exist_calls)
{
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/consensus.db", dir);
    g_skip_calls = 0;
    g_skip_answer = answer;
    progress_store_set_quick_check_skip_probe(skip_probe_stub);
    if (progress_store_open(dir))
        progress_store_close();
    *fresh_calls = g_skip_calls;
    g_skip_calls = 0;
    FILE *f = fopen(fpath, "r+b");
    if (!f)
        return -1;
    uint8_t garbage[4096];
    memset(garbage, 0xEE, sizeof(garbage));
    bool ok = fseek(f, 4096, SEEK_SET) == 0 &&
              fwrite(garbage, 1, sizeof(garbage), f) == sizeof(garbage);
    fclose(f);
    if (!ok)
        return -1;
    if (progress_store_open(dir))
        progress_store_close();
    progress_store_set_quick_check_skip_probe(NULL);
    *exist_calls = g_skip_calls;
    return count_quarantined(dir);
}

static int shutdown_marker_progress_store_cases(void)
{
    int failures = 0;
    printf("shutdown_marker progress_store_open skip probe wiring ... ");
    blocker_module_init();
    char dir[256];
    int fresh = -1, exist = -1;
    test_make_tmpdir(dir, sizeof(dir), "shutdown_marker", "cdb_skip_yes");
    int q_yes = skip_probe_reopen(dir, true, &fresh, &exist);
    bool yes_ok = q_yes == 0 && fresh == 0 && exist == 1;
    test_cleanup_tmpdir(dir);

    test_make_tmpdir(dir, sizeof(dir), "shutdown_marker", "cdb_skip_no");
    int q_no = skip_probe_reopen(dir, false, &fresh, &exist);
    bool no_ok = q_no >= 1 && fresh == 0 && exist == 1;
    test_cleanup_tmpdir(dir);

    /* No probe installed: the garbled page must be quarantined. */
    progress_store_set_quick_check_skip_probe(NULL);
    test_make_tmpdir(dir, sizeof(dir), "shutdown_marker", "cdb_skip_none");
    char fpath[512];
    snprintf(fpath, sizeof(fpath), "%s/consensus.db", dir);
    if (progress_store_open(dir))
        progress_store_close();
    FILE *f = fopen(fpath, "r+b");
    bool garbled = false;
    if (f) {
        uint8_t garbage[4096];
        memset(garbage, 0xEE, sizeof(garbage));
        garbled = fseek(f, 4096, SEEK_SET) == 0 &&
                  fwrite(garbage, 1, sizeof(garbage), f) == sizeof(garbage);
        fclose(f);
    }
    if (progress_store_open(dir))
        progress_store_close();
    bool none_ok = garbled && count_quarantined(dir) >= 1;
    test_cleanup_tmpdir(dir);

    if (yes_ok && no_ok && none_ok) {
        printf("OK\n");
    } else {
        printf("FAIL (yes q=%d fresh=%d exist=%d; no q=%d; none=%d)\n",
               q_yes, fresh, exist, q_no, none_ok);
        failures++;
    }
    return failures;
}

static int shutdown_marker_format_parse_case(void)
{
    printf("shutdown_marker format/parse round-trip ... ");
    int failures = 0;
    struct shutdown_clean_binding b = {
        .valid = true, .node_db_size = 123456789LL,
        .change_counter = 0xDEADBEEFu, .version_valid_for = 0xDEADBEEFu,
        .schema_version = 25,
    };
    char buf[512];
    int n = boot_shutdown_marker_format(buf, sizeof(buf), 1700000000LL, &b);
    struct shutdown_clean_binding got;
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        printf("FAIL (format n=%d)\n", n); failures++;
    } else if (!boot_shutdown_marker_parse(buf, (size_t)n, &got)) {
        printf("FAIL (parse)\n"); failures++;
    } else if (!got.valid ||
               got.node_db_size != b.node_db_size ||
               got.change_counter != b.change_counter ||
               got.version_valid_for != b.version_valid_for ||
               got.schema_version != b.schema_version) {
        printf("FAIL (field mismatch)\n"); failures++;
    } else {
        printf("OK\n");
    }
    return failures;
}

static int shutdown_marker_untrusted_case(void)
{
    printf("shutdown_marker corrupt marker not trusted ... ");
    struct shutdown_clean_binding got;
    const char *legacy = "1700000000\n";  /* legacy timestamp-only */
    const char *badmagic =
        "1\nmagic=NOPE\nversion=2\nnode_db_size=1\n"
        "node_db_change_counter=1\nnode_db_version_valid_for=1\n"
        "schema_version=1\nwal_checkpointed=1\n";
    const char *v1 =
        "1\nmagic=ZCLSHUT\nversion=1\nnode_db_size=1\n"
        "node_db_change_counter=1\nnode_db_version_valid_for=1\n"
        "wal_checkpointed=1\n";
    const char *no_ckpt =
        "1\nmagic=ZCLSHUT\nversion=2\nnode_db_size=1\n"
        "node_db_change_counter=1\nnode_db_version_valid_for=1\n"
        "schema_version=1\n";  /* wal_checkpointed missing */
    const char *garbage = "\x00\x01\x02 not a marker at all";
    bool any_trusted =
        boot_shutdown_marker_parse(legacy, strlen(legacy), &got) ||
        boot_shutdown_marker_parse(badmagic, strlen(badmagic), &got) ||
        boot_shutdown_marker_parse(v1, strlen(v1), &got) ||
        boot_shutdown_marker_parse(no_ckpt, strlen(no_ckpt), &got) ||
        boot_shutdown_marker_parse(garbage, strlen(garbage), &got);
    if (any_trusted) { printf("FAIL (parsed an untrusted marker)\n"); return 1; }
    printf("OK\n");
    return 0;
}

static int shutdown_marker_can_skip_case(void)
{
    printf("shutdown_marker can_skip decision matrix ... ");
    struct shutdown_clean_binding b = {
        .valid = true, .node_db_size = 4096, .change_counter = 7,
        .version_valid_for = 7, .schema_version = 25,
    };
    struct node_db_file_identity match = {
        .present = true, .size = 4096, .change_counter = 7,
        .version_valid_for = 7, .wal_present = false,
    };
    struct node_db_file_identity size_bad = match;   size_bad.size = 8192;
    struct node_db_file_identity cc_bad = match;      cc_bad.change_counter = 8;
    struct node_db_file_identity vvf_bad = match;     vvf_bad.version_valid_for = 8;
    struct node_db_file_identity wal_bad = match;     wal_bad.wal_present = true;
    struct node_db_file_identity absent = match;      absent.present = false;
    struct shutdown_clean_binding invalid = b;        invalid.valid = false;

    bool ok =
         boot_shutdown_marker_can_skip(&b, &match) &&
        !boot_shutdown_marker_can_skip(&b, &size_bad) &&
        !boot_shutdown_marker_can_skip(&b, &cc_bad) &&
        !boot_shutdown_marker_can_skip(&b, &vvf_bad) &&
        !boot_shutdown_marker_can_skip(&b, &wal_bad) &&
        !boot_shutdown_marker_can_skip(&b, &absent) &&
        !boot_shutdown_marker_can_skip(&invalid, &match);
    if (!ok) { printf("FAIL\n"); return 1; }
    printf("OK\n");
    return 0;
}

static int shutdown_marker_reject_non_sqlite(const char *path)
{
    /* A non-SQLite file must NOT be reported present. */
    int f2 = open(path, O_WRONLY | O_TRUNC);
    if (f2 >= 0) { (void)!write(f2, "not-sqlite-------", 16); close(f2); }
    struct node_db_file_identity id2;
    if (node_db_file_identity_read(path, &id2) || id2.present) {
        printf("FAIL (non-sqlite accepted)\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}

static int shutdown_marker_identity_read_case(void)
{
    printf("shutdown_marker file identity read ... ");
    char path[] = "/tmp/zcl_shutmark_iddb_XXXXXX";
    int fd = mkstemp(path);
    struct node_db_file_identity id;
    int failures = 0;
    if (fd < 0) { printf("FAIL (mkstemp)\n"); failures++; }
    else {
        close(fd);
        if (!write_fake_node_db(path, 65536, 0x11223344u, 0x11223344u)) {
            printf("FAIL (write)\n"); failures++;
        } else if (!node_db_file_identity_read(path, &id)) {
            printf("FAIL (read)\n"); failures++;
        } else if (!id.present || id.size != 65536 ||
                   id.change_counter != 0x11223344u ||
                   id.version_valid_for != 0x11223344u ||
                   id.wal_present) {
            printf("FAIL (fields cc=%08x sz=%lld)\n",
                   id.change_counter, (long long)id.size); failures++;
        } else {
            failures += shutdown_marker_reject_non_sqlite(path);
        }
        unlink(path);
    }
    return failures;
}

static bool shutdown_marker_skipped_or_not_deferred(void)
{
    return boot_shutdown_marker_quick_check_was_skipped() ||
           !boot_shutdown_marker_quick_check_was_deferred();
}

static int shutdown_marker_e2e_clean_skip(const char *dir, const char *ndb,
                                         const char *marker)
{
    boot_shutdown_marker_reset_for_test();
    boot_shutdown_marker_set_schema_version(25);
    if (!write_fake_node_db(ndb, 40960, 0x0A0B0C0Du, 0x0A0B0C0Du)) {
        printf("FAIL (fake node.db)\n");
        return 1;
    }

    /* Clean shutdown writes a bound marker. */
    if (!boot_shutdown_marker_write_clean(dir)) {
        printf("FAIL (write_clean)\n");
        return 1;
    }
    if (access(marker, F_OK) != 0) {
        printf("FAIL (marker absent after write_clean)\n");
        return 1;
    }

    /* Boot: detect_unclean caches the binding and DELETES the marker. */
    (void)boot_shutdown_marker_detect_unclean(dir);
    if (access(marker, F_OK) == 0) {
        printf("FAIL (marker not deleted by detect_unclean)\n");
        return 1;
    }

    /* Byte-identical node.db → verified-clean skip, and is single-use. */
    bool skip1 = boot_shutdown_marker_quick_check_probe(ndb);
    bool skip2 = boot_shutdown_marker_quick_check_probe(ndb);
    if (!skip1) {
        printf("FAIL (probe did not skip clean file)\n");
        return 1;
    }
    if (skip2) {
        printf("FAIL (probe not single-use)\n");
        return 1;
    }
    if (!boot_shutdown_marker_quick_check_was_skipped()) {
        printf("FAIL (was_skipped flag not set)\n");
        return 1;
    }
    if (boot_shutdown_marker_quick_check_was_deferred()) {
        printf("FAIL (clean skip must not also defer)\n");
        return 1;
    }
    return 0;
}

static int shutdown_marker_e2e_mutated_header(const char *dir, const char *ndb)
{
    /* Mutated header: blocking check is deferred, but verified-clean
     * skip (and therefore fast-restart node_db_clean) must stay false. */
    boot_shutdown_marker_reset_for_test();
    boot_shutdown_marker_set_schema_version(25);
    if (!boot_shutdown_marker_write_clean(dir)) {
        printf("FAIL (write_clean 2)\n");
        return 1;
    }
    (void)boot_shutdown_marker_detect_unclean(dir);
    /* Flip the change counter on disk. */
    if (!write_fake_node_db(ndb, 40960, 0x0A0B0C0Eu, 0x0A0B0C0Eu)) {
        printf("FAIL (corrupt rewrite)\n");
        return 1;
    }
    if (!boot_shutdown_marker_quick_check_probe(ndb)) {
        printf("FAIL (mutated node.db must defer blocking check)\n");
        return 1;
    }
    if (shutdown_marker_skipped_or_not_deferred()) {
        printf("FAIL (mutated node.db must defer, not verified-clean skip)\n");
        return 1;
    }
    return 0;
}

static int shutdown_marker_e2e_wal_present(const char *dir, const char *ndb,
                                          const char *wal)
{
    /* WAL present: same deferral, not verified-clean skip. */
    boot_shutdown_marker_reset_for_test();
    boot_shutdown_marker_set_schema_version(25);
    if (!write_fake_node_db(ndb, 40960, 0x0A0B0C0Du, 0x0A0B0C0Du) ||
        !boot_shutdown_marker_write_clean(dir)) {
        printf("FAIL (wal-case setup)\n");
        return 1;
    }
    (void)boot_shutdown_marker_detect_unclean(dir);
    { int wf = open(wal, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (wf >= 0) { (void)!write(wf, "wal-bytes", 9); close(wf); } }
    if (!boot_shutdown_marker_quick_check_probe(ndb)) {
        printf("FAIL (WAL-present existing db must defer)\n");
        return 1;
    }
    if (shutdown_marker_skipped_or_not_deferred()) {
        printf("FAIL (WAL-present must defer, not verified-clean skip)\n");
        return 1;
    }
    return 0;
}

static int shutdown_marker_e2e_unclean_and_absent(const char *dir,
                                                 const char *ndb,
                                                 const char *marker,
                                                 const char *wal)
{
    /* Unclean crash: WAL, no marker. Binding cache is empty; existing
     * node.db still defers so listen is not held hostage. */
    boot_shutdown_marker_reset_for_test();
    unlink(marker);
    { int wf = open(wal, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (wf >= 0) { (void)!write(wf, "wal-bytes", 9); close(wf); } }
    if (!boot_shutdown_marker_detect_unclean(dir)) {
        printf("FAIL (wal without marker should be unclean)\n");
        return 1;
    }
    if (!boot_shutdown_marker_quick_check_probe(ndb)) {
        printf("FAIL (unclean existing db must defer)\n");
        return 1;
    }
    if (shutdown_marker_skipped_or_not_deferred()) {
        printf("FAIL (unclean must defer, not verified-clean skip)\n");
        return 1;
    }
    if (boot_shutdown_marker_quick_check_probe(ndb)) {
        printf("FAIL (unclean deferral not single-use)\n");
        return 1;
    }

    /* Absent node.db: no skip and no deferral. */
    boot_shutdown_marker_reset_for_test();
    unlink(ndb);
    unlink(wal);
    if (boot_shutdown_marker_quick_check_probe(ndb) ||
        boot_shutdown_marker_quick_check_was_skipped() ||
        boot_shutdown_marker_quick_check_was_deferred()) {
        printf("FAIL (missing node.db must run blocking check)\n");
        return 1;
    }
    return 0;
}

static int shutdown_marker_e2e_case(void)
{
    printf("shutdown_marker end-to-end skip + corruption refusal ... ");
    char dir[] = "/tmp/zcl_shutmark_dir_XXXXXX";
    if (!mkdtemp(dir)) {
        printf("FAIL (mkdtemp)\n");
        return 1;
    }

    char ndb[512], marker[512], wal[512];
    snprintf(ndb, sizeof(ndb), "%s/node.db", dir);
    snprintf(marker, sizeof(marker), "%s/.shutdown_clean", dir);
    snprintf(wal, sizeof(wal), "%s/node.db-wal", dir);

    int failed = shutdown_marker_e2e_clean_skip(dir, ndb, marker)
        || shutdown_marker_e2e_mutated_header(dir, ndb)
        || shutdown_marker_e2e_wal_present(dir, ndb, wal)
        || shutdown_marker_e2e_unclean_and_absent(dir, ndb, marker, wal);
    if (!failed)
        printf("OK\n");

    unlink(ndb);
    unlink(marker);
    unlink(wal);
    rmdir(dir);
    boot_shutdown_marker_reset_for_test();
    return failed;
}

int test_shutdown_marker(void)
{
    int failures = 0;

    failures += shutdown_marker_progress_store_cases();

    failures += shutdown_marker_consensus_cases();

    /* (a) format → parse round-trip. */
    failures += shutdown_marker_format_parse_case();

    /* (b) corrupt / untrusted markers do NOT parse. */
    failures += shutdown_marker_untrusted_case();

    /* (c) can_skip decision matrix. */
    failures += shutdown_marker_can_skip_case();

    /* (d) node_db_file_identity_read off disk. */
    failures += shutdown_marker_identity_read_case();

    /* (e) end-to-end write_clean → detect_unclean → probe (single-use) +
     *     corruption refusal. */
    failures += shutdown_marker_e2e_case();

    return failures;
}
