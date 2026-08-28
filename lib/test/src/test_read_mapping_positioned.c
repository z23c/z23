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
              before.volume == after.volume &&
              before.file_low == after.file_low &&
              before.file_high == after.file_high &&
              before.size == after.size;
    platform_read_mapping_close(&mapping);
    platform_positioned_file_close(&file);
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
    test_rm_rf_recursive(dir);
    return failures;
}
