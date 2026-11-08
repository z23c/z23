/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves a positioned_file read and a read_mapping of the same file
 * return identical bytes at the same offsets -- the two paths must agree,
 * since callers pick between them by platform. Writes its own fixture;
 * distinct step codes report which leg failed.
 *
 * Rehomed from tools/tests/test_read_mapping_positioned.c, which only ran
 * when a human invoked tools/scripts/winacceptance.sh. The probe body is the
 * original program verbatim; the fixture path it took as argv[1] now comes
 * from the suite's own 0700 temp directory. */
#include "test/test_core.h"

#include "platform/positioned_file.h"
#include "platform/read_mapping.h"

#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

static bool mapping_short_hints(struct platform_read_mapping *mapping, const uint8_t *expected, size_t size)
{
    bool ok = true;
    size_t start = SIZE_MAX, end = SIZE_MAX;
    if (ok) {
        bool hinted = platform_read_mapping_advise_reverse(mapping, 7, 4, &start, &end);
        ok = hinted && start == 0 && end == size;
        ok = ok && !platform_read_mapping_advise_reverse(mapping, SIZE_MAX, 4, &start, &end) &&
            !platform_read_mapping_advise_reverse(mapping, 0, 0, &start, &end) &&
            memcmp(mapping->data, expected, size) == 0;
    }
    return ok;
}

static bool mapping_same_identity(const struct platform_positioned_file_snapshot *before,
    const struct platform_positioned_file_snapshot *after)
{
    return before->volume == after->volume && before->file_low == after->file_low &&
        before->file_high == after->file_high && before->size == after->size;
}

static int read_mapping_positioned_probe(const char *fixture)
{
    static const uint8_t expected[] = {0x24, 0xe9, 0x27, 0x64,
                                       0x08, 0x00, 0x00, 0x00};

    FILE *out = fopen(fixture, "wb");
    if (!out || fwrite(expected, 1, sizeof(expected), out) !=
                    sizeof(expected) || fclose(out) != 0)
        return 3;

    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    platform_read_mapping_init(&mapping);
    bool ok = platform_positioned_file_open(&file, fixture) &&
              platform_positioned_file_snapshot(&file, &before) &&
              before.size == sizeof(expected) &&
              platform_read_mapping_open_positioned(
                  &mapping, &file, sizeof(expected)) &&
              mapping.size == sizeof(expected) &&
              memcmp(mapping.data, expected, sizeof(expected)) == 0 &&
              platform_positioned_file_snapshot(&file, &after) &&
              mapping_same_identity(&before, &after);
    if (ok) ok = mapping_short_hints(&mapping, expected, sizeof(expected));
    platform_read_mapping_close(&mapping);
    platform_positioned_file_close(&file);
    (void)remove(fixture);
    return ok ? 0 : 1;
}

static bool mapping_reverse_index_bounds(bool ok, size_t i, size_t start, size_t end,
    size_t page, size_t window, size_t size)
{
        if (i == 0) ok = ok && start == 0 && end == page;
        if (i == 1) ok = ok && start == 0 && end == 2 * page;
        if (i == 2 && window % page == 0)
            ok = ok && start == 0 && end == window + page;
        if (i == 3) ok = ok && end == size;
    return ok;
}

static bool mapping_reverse_windows(struct platform_read_mapping *mapping, size_t page, size_t window, size_t size)
{
    bool ok = true;
    size_t offsets[] = {0, page, window, size - 1};
    for (size_t i = 0; ok && i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        size_t offset = offsets[i], start = SIZE_MAX, end = SIZE_MAX;
        ok = platform_read_mapping_advise_reverse(mapping, offset, window, &start, &end) &&
             start <= offset && offset < end && end <= size && start % page == 0 &&
             (end == size || end % page == 0) && end - start <= window + 2 * page;
        ok = mapping_reverse_index_bounds(ok, i, start, end, page, window, size);
    }
    return ok;
}

static bool mapping_reverse_edges(struct platform_read_mapping *mapping, size_t window, size_t size)
{
    bool ok = true;
    size_t start = SIZE_MAX, end = SIZE_MAX;
    ok = ok && platform_read_mapping_advise_reverse(mapping, size - 1, SIZE_MAX, &start, &end) &&
         start == 0 && end == size && mapping->data[size - 1] == 0x5a && mapping->data[0] == 0 &&
         !platform_read_mapping_advise_reverse(mapping, size, window, &start, &end) &&
         !platform_read_mapping_advise_reverse(mapping, 0, window, NULL, &end);
    return ok;
}

static int reverse_window_probe(const char *fixture)
{
#if defined(_WIN32)
    SYSTEM_INFO info; GetSystemInfo(&info);
    size_t page = (size_t)info.dwPageSize;
#else
    long page_value = sysconf(_SC_PAGESIZE);
    if (page_value <= 0) return 1;
    size_t page = (size_t)page_value;
#endif
    const size_t size = 3u * 1024u * 1024u, window = 1024u * 1024u;
    if (!page || page >= size) return 1;
    FILE *out = fopen(fixture, "wb");
    if (!out) return 1;
    bool ok = fseek(out, (long)(size - 1), SEEK_SET) == 0 && fputc(0x5a, out) != EOF;
    if (fclose(out) != 0 || !ok) return 1;
    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    platform_positioned_file_init(&file); platform_read_mapping_init(&mapping);
    ok = platform_positioned_file_open(&file, fixture) &&
         platform_read_mapping_open_positioned(&mapping, &file, size);
    if (ok) ok = mapping_reverse_windows(&mapping, page, window, size);
    if (ok) ok = mapping_reverse_edges(&mapping, window, size);
    platform_read_mapping_close(&mapping); platform_positioned_file_close(&file);
    (void)remove(fixture);
    return ok ? 0 : 1;
}

int test_read_mapping_positioned(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "read_mapping_positioned", "agree");
    char fixture[512];
    int n = snprintf(fixture, sizeof(fixture), "%s/fixture.bin", dir);

    printf("read_mapping_positioned: mapping and positioned read agree "
           "byte-for-byte over a stable identity... ");
    if (n <= 0 || (size_t)n >= sizeof(fixture)) {
        printf("FAIL (fixture path did not fit)\n");
        failures++;
    } else {
        int rc = read_mapping_positioned_probe(fixture);
        if (rc == 0) {
            printf("OK\n");
        } else {
            printf("FAIL (step %d)\n", rc);
            failures++;
        }
    }
    if (n > 0 && (size_t)n < sizeof(fixture) && reverse_window_probe(fixture) != 0) {
        printf("read_mapping_positioned: reverse window bounds FAIL\n");
        failures++;
    }
    test_rm_rf_recursive(dir);
    return failures;
}
