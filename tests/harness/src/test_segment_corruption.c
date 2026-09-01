/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the segment_corruption healer's real detect + repair flow, driven
 * through its directory-scoped pure helpers (no running node): a bounded
 * round-robin spot-verify catches a tampered sealed segment, and the repair
 * unlinks it + rebuilds the manifest so the range is no longer served corrupt
 * (reads fall back to blk*.dat). The network-refetch seam is node-coupled and
 * is intentionally out of scope here.
 */

#include "test/test_core.h"

#include "conditions/segment_corruption.h"
#include "storage/chain_segment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SC_CHECK(name, expr) do {                                            \
    if (expr) { printf("  segment_corruption: %s... OK\n", (name)); }         \
    else { printf("  segment_corruption: %s... FAIL\n", (name)); failures++; }\
} while (0)

static bool tiny_body(void *user, uint32_t h, uint8_t **bytes, size_t *len)
{
    (void)user;
    size_t n = 24;
    uint8_t *b = malloc(n); // raw-alloc-ok:test
    if (!b) return false;
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(h * 7u + i);
    *bytes = b; *len = n;
    return true;
}

int test_segment_corruption(void);
int test_segment_corruption(void)
{
    printf("\n=== segment_corruption (detect + repair) ===\n");
    int failures = 0;
    char err[256];
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "segment_corruption", "flow");

    /* Two sealed segments: seg-0-10 (clean) and seg-500-7 (we corrupt it). */
    chain_segment_seal_range(dir, tiny_body, NULL, 0, 10, err, sizeof(err));
    chain_segment_seal_range(dir, tiny_body, NULL, 500, 7, err, sizeof(err));

    /* A clean spot-verify of index 0 reports OK and names the range. */
    uint32_t cursor = 0, first = 999, count = 999;
    enum cseg_status st = segment_corruption_scan_one(dir, &cursor, &first,
                                                      &count, err, sizeof(err));
    SC_CHECK("clean segment verifies OK", st == CSEG_OK &&
                                          first == 0 && count == 10);

    /* Corrupt seg-500-7.dat: flip a byte in its block-data region so the
     * whole-segment digest fails on open. */
    char path[512];
    snprintf(path, sizeof(path), "%s/seg-500-7.dat", dir);
    chmod(path, 0644);
    FILE *f = fopen(path, "r+b");
    bool tampered = false;
    if (f) {
        long off = 32 + 7 * 48 + 3; /* header + index(7*48) + into first body */
        fseek(f, off, SEEK_SET); int c = fgetc(f);
        fseek(f, off, SEEK_SET); fputc(c ^ 0xff, f);
        fclose(f); tampered = true;
    }
    SC_CHECK("tamper write", tampered);

    /* Spot-verify index 1 (round-robin cursor=1) now DETECTS corruption and
     * names the corrupt range — the real detect path. */
    cursor = 1; first = 999; count = 999;
    st = segment_corruption_scan_one(dir, &cursor, &first, &count,
                                     err, sizeof(err));
    SC_CHECK("corrupt segment detected",
             st != CSEG_OK && st != CSEG_ERR_NOT_FOUND &&
             first == 500 && count == 7);

    /* Repair: unlink the corrupt segment + rebuild the manifest. */
    st = segment_corruption_repair(dir, 500, 7, err, sizeof(err));
    SC_CHECK("repair returns ok", st == CSEG_OK);
    {
        struct stat sb;
        SC_CHECK("corrupt segment file removed", stat(path, &sb) != 0);
    }

    /* Witness-equivalent: the store no longer covers the corrupt range (reads
     * fall back to blk*.dat), and the surviving segment still verifies clean. */
    {
        struct chain_segment_store *store = NULL;
        enum cseg_status ost = chain_segment_store_open(dir, &store, err, sizeof(err));
        SC_CHECK("store reopen ok", ost == CSEG_OK && store != NULL);
        SC_CHECK("corrupt range no longer covered",
                 store && !chain_segment_store_covers(store, 500));
        SC_CHECK("survivor still covered + count 1",
                 store && chain_segment_store_covers(store, 0) &&
                 chain_segment_store_segment_count(store) == 1);
        SC_CHECK("survivor verifies clean",
                 store && chain_segment_store_verify_index(store, 0, err,
                                                           sizeof(err)) == CSEG_OK);
        chain_segment_store_close(store);
    }

    test_rm_rf_recursive(dir);
    printf("segment_corruption: %d failures\n", failures);
    return failures;
}
