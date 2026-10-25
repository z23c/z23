/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves the positioned-file seam can read this process own running
 * executable end to end with no cursor, and that the file identity, size and
 * timestamps are unchanged across the entire read.
 *
 * Reads the running executable of this process. */
#include "test/test_core.h"

#include "base/bytes.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"

#include <stdint.h>

static bool running_image_positioned_open_and_snapshot(
    struct platform_positioned_file *file, char *path, size_t path_size,
    struct platform_positioned_file_snapshot *before)
{
    return os_proc_exe_path(path, path_size) &&
           platform_positioned_file_open(file, path) &&
           platform_positioned_file_snapshot(file, before) &&
           before->size != 0;
}

static bool running_image_positioned_read_all(
    struct platform_positioned_file *file, uint64_t size, bool *any)
{
    uint8_t bytes[32768];
    uint64_t offset = 0;
    while (offset < size) {
        size_t want = size - offset < sizeof(bytes)
                          ? (size_t)(size - offset)
                          : sizeof(bytes);
        if (platform_positioned_file_read(file, bytes, want, offset) !=
            (int64_t)want)
            return false;
        *any |= zcl_bytes_any_set(bytes, want);
        offset += want;
    }
    return true;
}

static bool running_image_positioned_identity_stable(
    bool any, struct platform_positioned_file *file,
    struct platform_positioned_file_snapshot *before,
    struct platform_positioned_file_snapshot *after)
{
    return any && platform_positioned_file_snapshot(file, after) &&
           before->size == after->size && before->volume == after->volume &&
           before->file_low == after->file_low &&
           before->file_high == after->file_high &&
           before->modified_seconds == after->modified_seconds &&
           before->changed_seconds == after->changed_seconds;
}

static int running_image_positioned_probe(void)
{
    char path[4096];
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    if (!running_image_positioned_open_and_snapshot(&file, path, sizeof(path),
                                                    &before))
        return 1;
    bool any = false;
    if (!running_image_positioned_read_all(&file, before.size, &any)) {
        platform_positioned_file_close(&file);
        return 2;
    }
    bool stable = running_image_positioned_identity_stable(any, &file,
                                                           &before, &after);
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
