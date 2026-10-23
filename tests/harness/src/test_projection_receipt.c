/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Projection clean-close receipt v3: the content digest is taken over fixed
 * chunks on a pool of threads, and its value must not depend on the pool size.
 * A small chunk size (test seam) lets a ~100 KiB progress.kv span many chunks.
 */

#include "test/test_core.h"

#include "platform/positioned_file.h"
#include "storage/projection_store.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PR_CHUNK 4096u

#define PR_CHECK(name, expr) do { \
    printf("projection_receipt: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool pr_defer_probe_yes(const char *path)
{
    return path != NULL;
}

static void pr_wipe(const char *dir)
{
    static const char *const names[] = {
        "progress.kv", "progress.kv-wal", "progress.kv-shm", "progress.kv.clean"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        (void)unlink(path);
    }
}

/* Seed a store large enough for many 4 KiB chunks, close it cleanly (which
 * writes the receipt), and leave the receipt in place. */
static bool pr_seed(const char *dir)
{
    pr_wipe(dir);
    if (!projection_store_open(dir))
        return false;
    sqlite3 *db = projection_store_db();
    bool ok = db &&
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS pr_rows"
                         "(k INTEGER PRIMARY KEY, v BLOB NOT NULL)",
                     NULL, NULL, NULL) == SQLITE_OK;
    for (int i = 0; ok && i < 200; i++) {
        char sql[160];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO pr_rows(k,v) VALUES (%d, randomblob(400))", i);
        ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    }
    projection_store_close();
    return ok;
}

static bool pr_read_all(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;
    size_t got = fread(buf, 1, cap - 1, fp);
    bool ok = !ferror(fp) && feof(fp) && got > 0;
    fclose(fp);
    buf[ok ? got : 0] = '\0';
    return ok;
}

static bool pr_flip_byte(const char *path, long offset)
{
    FILE *fp = fopen(path, "r+b");
    if (!fp)
        return false;
    int c = fseek(fp, offset, SEEK_SET) == 0 ? fgetc(fp) : EOF;
    bool ok = c != EOF && fseek(fp, offset, SEEK_SET) == 0 &&
              fputc(c ^ 0x5a, fp) != EOF;
    return fclose(fp) == 0 && ok;
}

/* Rewrite the receipt with the file's current timestamps (so only the digest
 * can reject it) and the given version line. */
static bool pr_rewrite_receipt(const char *path, const char *receipt,
                               unsigned version)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path))
        return false;
    bool ok = platform_positioned_file_snapshot(&file, &snap);
    platform_positioned_file_close(&file);
    char text[768];
    if (!ok || !pr_read_all(receipt, text, sizeof(text)))
        return false;
    FILE *fp = fopen(receipt, "wb");
    if (!fp)
        return false;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "version=", 8) == 0)
            fprintf(fp, "version=%u\n", version);
        else if (strncmp(line, "mtime_sec=", 10) == 0)
            fprintf(fp, "mtime_sec=%lld\n", (long long)snap.modified_seconds);
        else if (strncmp(line, "mtime_nsec=", 11) == 0)
            fprintf(fp, "mtime_nsec=%lld\n", (long long)snap.modified_nanoseconds);
        else if (strncmp(line, "ctime_sec=", 10) == 0)
            fprintf(fp, "ctime_sec=%lld\n", (long long)snap.changed_seconds);
        else if (strncmp(line, "ctime_nsec=", 11) == 0)
            fprintf(fp, "ctime_nsec=%lld\n", (long long)snap.changed_nanoseconds);
        else
            fprintf(fp, "%s\n", line);
    }
    return fclose(fp) == 0;
}

/* Reopen with the deferred-scan probe: the integrity scan is owed exactly when
 * no receipt was accepted. Always closes the store; the receipt is consumed. */
static bool pr_reopen_owes_scan(const char *dir, bool *owes)
{
    char pending[1024];
    projection_store_set_quick_check_defer_probe(pr_defer_probe_yes);
    bool opened = projection_store_open(dir);
    *owes = opened && projection_store_integrity_pending(pending,
                                                         sizeof(pending));
    projection_store_close();
    projection_store_set_quick_check_defer_probe(NULL);
    return opened;
}

static int pr_test_digest_independent_of_workers(const char *dir,
                                                 const char *fpath,
                                                 const char *receipt)
{
    int failures = 0;
    char d1[65], d3[65], d8[65], dflt[65], text[768];
    PR_CHECK("seed store spans many chunks",
             pr_seed(dir) && access(receipt, F_OK) == 0);
    struct stat st;
    PR_CHECK("fixture has at least 8 chunks",
             stat(fpath, &st) == 0 && st.st_size >= (off_t)(8 * PR_CHUNK));

    projection_store_receipt_chunk_bytes_for_test(0);
    PR_CHECK("default-chunk digest equals the receipt the close wrote",
             projection_store_receipt_digest_for_test(fpath, dflt) &&
             pr_read_all(receipt, text, sizeof(text)) &&
             strstr(text, "version=3\n") && strstr(text, dflt));

    projection_store_receipt_chunk_bytes_for_test(PR_CHUNK);
    projection_store_receipt_workers_for_test(1);
    bool a = projection_store_receipt_digest_for_test(fpath, d1);
    projection_store_receipt_workers_for_test(3);
    bool b = projection_store_receipt_digest_for_test(fpath, d3);
    projection_store_receipt_workers_for_test(8);
    bool c = projection_store_receipt_digest_for_test(fpath, d8);
    projection_store_receipt_workers_for_test(0);
    projection_store_receipt_chunk_bytes_for_test(0);
    PR_CHECK("digest computes with 1, 3 and 8 workers", a && b && c);
    PR_CHECK("1 worker and 8 workers give the same digest",
             a && c && strcmp(d1, d8) == 0);
    PR_CHECK("3 workers give the same digest", a && b && strcmp(d1, d3) == 0);
    PR_CHECK("the chunk size is part of the digest", strcmp(d1, dflt) != 0);
    return failures;
}

/* Flip one byte at `offset` and show both the digest and the receipt notice
 * it. Returns the failure count. */
static int pr_flip_case(const char *dir, const char *fpath,
                        const char *receipt, const char *name, int which)
{
    int failures = 0;
    char before[65], after[65], label[96];
    bool seeded = pr_seed(dir);
    struct stat st;
    long size = stat(fpath, &st) == 0 ? (long)st.st_size : 0;
    long offset = which == 0 ? 2000 : which == 1
        ? (size / 2 / PR_CHUNK) * PR_CHUNK + 17 : size - 1;
    bool d0 = projection_store_receipt_digest_for_test(fpath, before);
    bool flipped = pr_flip_byte(fpath, offset);
    bool d1 = projection_store_receipt_digest_for_test(fpath, after);
    snprintf(label, sizeof(label), "%s chunk: digest changes", name);
    PR_CHECK(label, seeded && d0 && flipped && d1 &&
                    strcmp(before, after) != 0);

    /* Isolate the digest: make the receipt agree with the file on every
     * timestamp, leaving the old digest. */
    bool owes = false;
    bool aligned = pr_rewrite_receipt(fpath, receipt, 3);
    bool opened = pr_reopen_owes_scan(dir, &owes);
    snprintf(label, sizeof(label), "%s chunk: receipt rejects, scan owed", name);
    PR_CHECK(label, aligned && opened && owes);
    snprintf(label, sizeof(label), "%s chunk: receipt consumed", name);
    PR_CHECK(label, access(receipt, F_OK) != 0);
    return failures;
}

static int pr_test_old_version_rejected(const char *dir, const char *fpath,
                                        const char *receipt)
{
    int failures = 0;
    bool seeded = pr_seed(dir);
    bool aligned = pr_rewrite_receipt(fpath, receipt, 2);
    bool owes = false;
    bool opened = pr_reopen_owes_scan(dir, &owes);
    PR_CHECK("a version=2 receipt with the right bytes is rejected",
             seeded && aligned && opened && owes);
    PR_CHECK("and consumed", access(receipt, F_OK) != 0);
    return failures;
}

static int pr_test_clean_roundtrip(const char *dir)
{
    int failures = 0;
    bool owes = true;
    bool seeded = pr_seed(dir);
    bool opened = pr_reopen_owes_scan(dir, &owes);
    PR_CHECK("clean close then reopen skips the quick_check",
             seeded && opened && !owes);
    return failures;
}

int test_projection_receipt(void)
{
    int failures = 0;
    char dir[256], fpath[512], receipt[544];
    test_make_tmpdir(dir, sizeof(dir), "projection_receipt", "v3");
    snprintf(fpath, sizeof(fpath), "%s/progress.kv", dir);
    snprintf(receipt, sizeof(receipt), "%s.clean", fpath);

    failures += pr_test_digest_independent_of_workers(dir, fpath, receipt);
    projection_store_receipt_chunk_bytes_for_test(PR_CHUNK);
    failures += pr_flip_case(dir, fpath, receipt, "first", 0);
    failures += pr_flip_case(dir, fpath, receipt, "middle", 1);
    failures += pr_flip_case(dir, fpath, receipt, "last", 2);
    projection_store_receipt_chunk_bytes_for_test(0);
    failures += pr_test_old_version_rejected(dir, fpath, receipt);
    failures += pr_test_clean_roundtrip(dir);
    test_cleanup_tmpdir(dir);
    return failures;
}
