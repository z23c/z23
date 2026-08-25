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

int test_shutdown_marker(void)
{
    int failures = 0;

    /* (a) format → parse round-trip. */
    printf("shutdown_marker format/parse round-trip ... ");
    {
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
    }

    /* (b) corrupt / untrusted markers do NOT parse. */
    printf("shutdown_marker corrupt marker not trusted ... ");
    {
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
        if (any_trusted) { printf("FAIL (parsed an untrusted marker)\n"); failures++; }
        else printf("OK\n");
    }

    /* (c) can_skip decision matrix. */
    printf("shutdown_marker can_skip decision matrix ... ");
    {
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
        if (!ok) { printf("FAIL\n"); failures++; }
        else printf("OK\n");
    }

    /* (d) node_db_file_identity_read off disk. */
    printf("shutdown_marker file identity read ... ");
    {
        char path[] = "/tmp/zcl_shutmark_iddb_XXXXXX";
        int fd = mkstemp(path);
        struct node_db_file_identity id;
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
                /* A non-SQLite file must NOT be reported present. */
                int f2 = open(path, O_WRONLY | O_TRUNC);
                if (f2 >= 0) { (void)!write(f2, "not-sqlite-------", 16); close(f2); }
                struct node_db_file_identity id2;
                if (node_db_file_identity_read(path, &id2) || id2.present)
                    { printf("FAIL (non-sqlite accepted)\n"); failures++; }
                else printf("OK\n");
            }
            unlink(path);
        }
    }

    /* (e) end-to-end write_clean → detect_unclean → probe (single-use) +
     *     corruption refusal. */
    printf("shutdown_marker end-to-end skip + corruption refusal ... ");
    {
        char dir[] = "/tmp/zcl_shutmark_dir_XXXXXX";
        if (!mkdtemp(dir)) { printf("FAIL (mkdtemp)\n"); failures++; goto done_e2e; }

        char ndb[512], marker[512], wal[512];
        snprintf(ndb, sizeof(ndb), "%s/node.db", dir);
        snprintf(marker, sizeof(marker), "%s/.shutdown_clean", dir);
        snprintf(wal, sizeof(wal), "%s/node.db-wal", dir);

        boot_shutdown_marker_reset_for_test();
        boot_shutdown_marker_set_schema_version(25);
        if (!write_fake_node_db(ndb, 40960, 0x0A0B0C0Du, 0x0A0B0C0Du)) {
            printf("FAIL (fake node.db)\n"); failures++; goto cleanup_e2e;
        }

        /* Clean shutdown writes a bound marker. */
        if (!boot_shutdown_marker_write_clean(dir)) {
            printf("FAIL (write_clean)\n"); failures++; goto cleanup_e2e;
        }
        if (access(marker, F_OK) != 0) {
            printf("FAIL (marker absent after write_clean)\n"); failures++; goto cleanup_e2e;
        }

        /* Boot: detect_unclean caches the binding and DELETES the marker. */
        (void)boot_shutdown_marker_detect_unclean(dir);
        if (access(marker, F_OK) == 0) {
            printf("FAIL (marker not deleted by detect_unclean)\n"); failures++; goto cleanup_e2e;
        }

        /* Byte-identical node.db → verified-clean skip, and is single-use. */
        bool skip1 = boot_shutdown_marker_quick_check_probe(ndb);
        bool skip2 = boot_shutdown_marker_quick_check_probe(ndb);
        if (!skip1) { printf("FAIL (probe did not skip clean file)\n"); failures++; goto cleanup_e2e; }
        if (skip2)  { printf("FAIL (probe not single-use)\n"); failures++; goto cleanup_e2e; }
        if (!boot_shutdown_marker_quick_check_was_skipped()) {
            printf("FAIL (was_skipped flag not set)\n"); failures++; goto cleanup_e2e;
        }
        if (boot_shutdown_marker_quick_check_was_deferred()) {
            printf("FAIL (clean skip must not also defer)\n"); failures++; goto cleanup_e2e;
        }

        /* Mutated header: blocking check is deferred, but verified-clean
         * skip (and therefore fast-restart node_db_clean) must stay false. */
        boot_shutdown_marker_reset_for_test();
        boot_shutdown_marker_set_schema_version(25);
        if (!boot_shutdown_marker_write_clean(dir)) {
            printf("FAIL (write_clean 2)\n"); failures++; goto cleanup_e2e;
        }
        (void)boot_shutdown_marker_detect_unclean(dir);
        /* Flip the change counter on disk. */
        if (!write_fake_node_db(ndb, 40960, 0x0A0B0C0Eu, 0x0A0B0C0Eu)) {
            printf("FAIL (corrupt rewrite)\n"); failures++; goto cleanup_e2e;
        }
        if (!boot_shutdown_marker_quick_check_probe(ndb)) {
            printf("FAIL (mutated node.db must defer blocking check)\n"); failures++; goto cleanup_e2e;
        }
        if (boot_shutdown_marker_quick_check_was_skipped() ||
            !boot_shutdown_marker_quick_check_was_deferred()) {
            printf("FAIL (mutated node.db must defer, not verified-clean skip)\n");
            failures++; goto cleanup_e2e;
        }

        /* WAL present: same deferral, not verified-clean skip. */
        boot_shutdown_marker_reset_for_test();
        boot_shutdown_marker_set_schema_version(25);
        if (!write_fake_node_db(ndb, 40960, 0x0A0B0C0Du, 0x0A0B0C0Du) ||
            !boot_shutdown_marker_write_clean(dir)) {
            printf("FAIL (wal-case setup)\n"); failures++; goto cleanup_e2e;
        }
        (void)boot_shutdown_marker_detect_unclean(dir);
        { int wf = open(wal, O_WRONLY | O_CREAT | O_TRUNC, 0644);
          if (wf >= 0) { (void)!write(wf, "wal-bytes", 9); close(wf); } }
        if (!boot_shutdown_marker_quick_check_probe(ndb)) {
            printf("FAIL (WAL-present existing db must defer)\n"); failures++; goto cleanup_e2e;
        }
        if (boot_shutdown_marker_quick_check_was_skipped() ||
            !boot_shutdown_marker_quick_check_was_deferred()) {
            printf("FAIL (WAL-present must defer, not verified-clean skip)\n");
            failures++; goto cleanup_e2e;
        }

        /* Unclean crash: WAL, no marker. Binding cache is empty; existing
         * node.db still defers so listen is not held hostage. */
        boot_shutdown_marker_reset_for_test();
        unlink(marker);
        { int wf = open(wal, O_WRONLY | O_CREAT | O_TRUNC, 0644);
          if (wf >= 0) { (void)!write(wf, "wal-bytes", 9); close(wf); } }
        if (!boot_shutdown_marker_detect_unclean(dir)) {
            printf("FAIL (wal without marker should be unclean)\n"); failures++; goto cleanup_e2e;
        }
        if (!boot_shutdown_marker_quick_check_probe(ndb)) {
            printf("FAIL (unclean existing db must defer)\n"); failures++; goto cleanup_e2e;
        }
        if (boot_shutdown_marker_quick_check_was_skipped() ||
            !boot_shutdown_marker_quick_check_was_deferred()) {
            printf("FAIL (unclean must defer, not verified-clean skip)\n");
            failures++; goto cleanup_e2e;
        }
        if (boot_shutdown_marker_quick_check_probe(ndb)) {
            printf("FAIL (unclean deferral not single-use)\n"); failures++; goto cleanup_e2e;
        }

        /* Absent node.db: no skip and no deferral. */
        boot_shutdown_marker_reset_for_test();
        unlink(ndb);
        unlink(wal);
        if (boot_shutdown_marker_quick_check_probe(ndb) ||
            boot_shutdown_marker_quick_check_was_skipped() ||
            boot_shutdown_marker_quick_check_was_deferred()) {
            printf("FAIL (missing node.db must run blocking check)\n");
            failures++; goto cleanup_e2e;
        }
        printf("OK\n");

cleanup_e2e:
        unlink(ndb); unlink(marker); unlink(wal);
        rmdir(dir);
        boot_shutdown_marker_reset_for_test();
done_e2e:;
    }

    return failures;
}
