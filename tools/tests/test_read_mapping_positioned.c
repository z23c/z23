/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: standalone proof that a positioned_file read and a read_mapping
 * of the same file return identical bytes at the same offsets -- the two
 * paths must agree, since callers pick between them by platform. Writes its
 * own fixture to argv[1]; distinct exit codes report which step failed. */
#include "platform/positioned_file.h"
#include "platform/read_mapping.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    static const uint8_t expected[] = {0x24, 0xe9, 0x27, 0x64,
                                       0x08, 0x00, 0x00, 0x00};
    if (argc != 2)
        return 2;

    FILE *out = fopen(argv[1], "wb");
    if (!out || fwrite(expected, 1, sizeof(expected), out) !=
                    sizeof(expected) || fclose(out) != 0)
        return 3;

    struct platform_positioned_file file;
    struct platform_read_mapping mapping;
    struct platform_positioned_file_snapshot before;
    struct platform_positioned_file_snapshot after;
    platform_positioned_file_init(&file);
    platform_read_mapping_init(&mapping);
    bool ok = platform_positioned_file_open(&file, argv[1]) &&
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
    (void)remove(argv[1]);
    return ok ? 0 : 1;
}
