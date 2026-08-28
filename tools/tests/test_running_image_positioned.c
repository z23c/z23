/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves the positioned-file seam can read this process own
 * running executable end to end with no cursor, and that the file identity,
 * size and timestamps are unchanged across the entire read. */
#include "platform/os_proc.h"
#include "platform/positioned_file.h"

#include <stdint.h>

int main(void)
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
            (int64_t)want)
            return 2;
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
