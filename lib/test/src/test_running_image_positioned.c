/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves the positioned-file seam can read this process own running
 * executable end to end with no cursor, and that the file identity, size and
 * timestamps are unchanged across the entire read.
 *
 * Rehomed from tools/tests/test_running_image_positioned.c, which only ran
 * when a human invoked tools/scripts/winacceptance.sh. The subject is now the
 * suite binary itself rather than a one-file standalone, which is a strictly
 * larger image to read; the probe body is the original verbatim. */
#include "test/test_core.h"

#include "platform/os_proc.h"
#include "platform/positioned_file.h"

#include <stdint.h>

static int running_image_positioned_probe(void)
{
    char path[4096];
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    if (!os_proc_exe_path(path, sizeof(path)) ||
        !platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) || before.size == 0)
        return 1;
    uint8_t bytes[32768];
    uint64_t offset = 0;
    uint8_t any = 0;
    while (offset < before.size) {
        size_t want = before.size - offset < sizeof(bytes)
                          ? (size_t)(before.size - offset)
                          : sizeof(bytes);
        if (platform_positioned_file_read(&file, bytes, want, offset) !=
            (int64_t)want) {
            platform_positioned_file_close(&file);
            return 2;
        }
        for (size_t i = 0; i < want; i++)
            any |= bytes[i];
        offset += want;
    }
    bool stable = any && platform_positioned_file_snapshot(&file, &after) &&
                  before.size == after.size && before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high &&
                  before.modified_seconds == after.modified_seconds &&
                  before.changed_seconds == after.changed_seconds;
    platform_positioned_file_close(&file);
    return stable ? 0 : 3;
}

int test_running_image_positioned(void)
{
    int failures = 0;
    int rc = running_image_positioned_probe();
    printf("running_image_positioned: whole running image reads with a "
           "stable identity... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    return failures;
}
