/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify private-file linking never replaces an existing target. */
#include "platform/private_file.h"

#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    struct platform_private_file source;
    struct platform_private_file_identity identity;
    platform_private_file_init(&source);
    static const char bytes[] = "immutable-block-fixture";
    if (!platform_private_file_create(argv[1], &source) ||
        !platform_private_file_write_at(&source, bytes, sizeof(bytes), 0) ||
        !platform_private_file_flush(&source) ||
        !platform_private_file_identity(&source, &identity))
        return 3;

    struct platform_private_file_identity wrong = identity;
    wrong.file ^= UINT64_C(1);
    bool same = false;
    if (platform_private_file_link_no_clobber(argv[1], argv[2], &wrong,
                                               &same) || same ||
        !platform_private_path_absent(argv[2]))
        return 4;
    if (!platform_private_file_link_no_clobber(argv[1], argv[2], &identity,
                                                &same) || same)
        return 5;
    same = false;
    if (!platform_private_file_link_no_clobber(argv[1], argv[2], &identity,
                                                &same) || !same)
        return 6;
    platform_private_file_close(&source);
    return platform_private_file_unlink_missing_ok(argv[2]) &&
                   platform_private_file_unlink_missing_ok(argv[1])
               ? 0
               : 7;
}
