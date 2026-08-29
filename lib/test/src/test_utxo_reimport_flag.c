/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the utxo_reimport_flag storage primitive
 * (lib/storage/src/utxo_reimport_flag.c).
 *
 * Coverage:
 *   1. Flag absent  → check_and_clear returns false, no side effect.
 *   2. Flag set '1' → check_and_clear returns true + removes file.
 *   3. Flag set '0' → check_and_clear returns false but STILL removes
 *      the file (unconditional clear preserves the prior behaviour).
 *   4. set → check_and_clear round-trip returns true and clears.
 *
 * Each case uses a unique temp directory under ./test-tmp/ and cleans
 * up after itself. Tests do not depend on each other.
 */

#include "test/test_core.h"
#include "storage/utxo_reimport_flag.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define URF_CHECK(name, expr) do {              \
    printf("urf: %s... ", (name));              \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

static bool urf_make_tmpdir(char *out, size_t cap)
{
    /* Unique suffix via a counter; path-build + stale-cleanup + mkdir
     * delegate to the shared helper. */
    static _Atomic int seq = 0;
    int s = atomic_fetch_add(&seq, 1);
    char tag[16];
    snprintf(tag, sizeof(tag), "%d", s);
    test_make_tmpdir(out, cap, "urf", tag);
    return true;
}

static bool urf_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static void urf_write_byte(const char *path, char c)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputc(c, f);
        fclose(f);
    }
}

int test_utxo_reimport_flag(void)
{
    printf("\n=== utxo_reimport_flag tests ===\n");
    int failures = 0;

    /* ── 1. Absent flag → false, no side effect ─────────────────── */
    {
        char dir[PATH_MAX];
        if (!urf_make_tmpdir(dir, sizeof(dir))) {
            printf("urf: mkdtemp FAIL\n");
            return 1;
        }
        char flag[128];
        snprintf(flag, sizeof(flag), "%s/needs_reimport", dir);

        bool found = utxo_reimport_flag_check_and_clear(dir);
        URF_CHECK("absent → false", !found);
        URF_CHECK("absent → file still absent", !urf_file_exists(flag));

        rmdir(dir);
    }

    /* ── 2. Set with '1' → true + cleared ───────────────────────── */
    {
        char dir[PATH_MAX];
        if (!urf_make_tmpdir(dir, sizeof(dir))) {
            printf("urf: mkdtemp FAIL\n");
            return 1;
        }
        char flag[128];
        snprintf(flag, sizeof(flag), "%s/needs_reimport", dir);
        urf_write_byte(flag, '1');

        bool found = utxo_reimport_flag_check_and_clear(dir);
        URF_CHECK("present '1' → true", found);
        URF_CHECK("present '1' → file removed", !urf_file_exists(flag));

        rmdir(dir);
    }

    /* ── 3. Set with '0' → false BUT cleared ────────────────────── */
    {
        char dir[PATH_MAX];
        if (!urf_make_tmpdir(dir, sizeof(dir))) {
            printf("urf: mkdtemp FAIL\n");
            return 1;
        }
        char flag[128];
        snprintf(flag, sizeof(flag), "%s/needs_reimport", dir);
        urf_write_byte(flag, '0');

        bool found = utxo_reimport_flag_check_and_clear(dir);
        URF_CHECK("present '0' → false", !found);
        URF_CHECK("present '0' → file still removed",
                  !urf_file_exists(flag));

        rmdir(dir);
    }

    /* ── 4. set() then check_and_clear round-trip ───────────────── */
    {
        char dir[PATH_MAX];
        if (!urf_make_tmpdir(dir, sizeof(dir))) {
            printf("urf: mkdtemp FAIL\n");
            return 1;
        }
        char flag[128];
        snprintf(flag, sizeof(flag), "%s/needs_reimport", dir);

        bool wrote = utxo_reimport_flag_set(dir);
        URF_CHECK("set() returns true", wrote);
        URF_CHECK("set() created the file", urf_file_exists(flag));

        bool found = utxo_reimport_flag_check_and_clear(dir);
        URF_CHECK("round-trip → true", found);
        URF_CHECK("round-trip → file removed", !urf_file_exists(flag));

        rmdir(dir);
    }

    /* ── 5. NULL datadir is rejected, not crashy ────────────────── */
    {
        bool r1 = utxo_reimport_flag_check_and_clear(NULL);
        bool r2 = utxo_reimport_flag_set(NULL);
        URF_CHECK("NULL datadir check → false", !r1);
        URF_CHECK("NULL datadir set → false", !r2);
    }

    if (failures == 0)
        printf("=== utxo_reimport_flag tests: ALL PASS ===\n\n");
    else
        printf("=== utxo_reimport_flag tests: %d FAILURE(S) ===\n\n",
               failures);
    return failures;
}
