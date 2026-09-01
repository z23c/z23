/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves platform_private_file_link_no_clobber() publishes a source
 * to a destination only under the caller VERIFIED file identity -- a
 * deliberately corrupted identity is refused with the destination left
 * absent, and the correct identity is idempotent across repeats, never
 * replacing an existing target.
 *
 * Rehomed from tools/tests/test_private_link_no_clobber.c, which only ran
 * when a human invoked tools/scripts/winacceptance.sh. The two paths the
 * standalone program took as argv[1]/argv[2] now come from the suite's own
 * 0700 temp directory; every assertion below is the original verbatim. */
#include "test/test_core.h"

#include "platform/private_file.h"

#include <string.h>

static int private_link_no_clobber_probe(const char *source_path,
                                         const char *target_path)
{
    struct platform_private_file source;
    struct platform_private_file_identity identity;
    platform_private_file_init(&source);
    static const char bytes[] = "immutable-block-fixture";
    if (!platform_private_file_create(source_path, &source) ||
        !platform_private_file_write_at(&source, bytes, sizeof(bytes), 0) ||
        !platform_private_file_flush(&source) ||
        !platform_private_file_identity(&source, &identity))
        return 3;

    struct platform_private_file_identity wrong = identity;
    wrong.file ^= UINT64_C(1);
    bool same = false;
    if (platform_private_file_link_no_clobber(source_path, target_path, &wrong,
                                               &same) || same ||
        !platform_private_path_absent(target_path))
        return 4;
    if (!platform_private_file_link_no_clobber(source_path, target_path,
                                                &identity, &same) || same)
        return 5;
    same = false;
    if (!platform_private_file_link_no_clobber(source_path, target_path,
                                                &identity, &same) || !same)
        return 6;
    platform_private_file_close(&source);
    return platform_private_file_unlink_missing_ok(target_path) &&
                   platform_private_file_unlink_missing_ok(source_path)
               ? 0
               : 7;
}

int test_private_link_no_clobber(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "private_link_no_clobber", "publish");
    char source[512];
    char target[512];
    int source_n = snprintf(source, sizeof(source), "%s/source.bin", dir);
    int target_n = snprintf(target, sizeof(target), "%s/target.bin", dir);

    printf("private_link_no_clobber: identity-verified publish is "
           "idempotent and never clobbers... ");
    if (source_n <= 0 || (size_t)source_n >= sizeof(source) ||
        target_n <= 0 || (size_t)target_n >= sizeof(target)) {
        printf("FAIL (fixture paths did not fit)\n");
        failures++;
    } else {
        int rc = private_link_no_clobber_probe(source, target);
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
