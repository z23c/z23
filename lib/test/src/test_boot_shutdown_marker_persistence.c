/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves the clean-shutdown marker round-trips privately and
 * atomically under a scratch datadir: written owner-only, read back as clean
 * rather than unclean, and removed so the path is absent again.
 *
 * Rehomed from tools/tests/test_boot_shutdown_marker_persistence.c, which
 * only ran when a human invoked tools/scripts/winacceptance.sh. The
 * standalone program stubbed zcl_log_level_get() and event_emitf() purely so
 * it could link on its own; in the suite the production definitions are
 * present, so the stubs are gone and the real emit path runs. Every
 * assertion is the original verbatim. */
#include "test/test_core.h"

#include "config/boot_shutdown_marker.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <stdio.h>

static int boot_shutdown_marker_persistence_probe(const char *datadir)
{
    if (!platform_private_directory_ensure(datadir))
        return 2;
    char marker[1024];
    if (snprintf(marker, sizeof(marker), "%s/.shutdown_clean", datadir) <= 0)
        return 3;
    if (!boot_shutdown_marker_write_clean(datadir))
        return 4;
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    bool private_marker = platform_positioned_file_open(&file, marker) &&
                          platform_positioned_file_is_private(&file);
    platform_positioned_file_close(&file);
    if (!private_marker || boot_shutdown_marker_detect_unclean(datadir) ||
        !platform_private_path_absent(marker))
        return 5;
    if (!boot_shutdown_marker_write_clean(datadir) ||
        !boot_shutdown_marker_remove_clean(datadir) ||
        !platform_private_path_absent(marker))
        return 6;
    return 0;
}

int test_boot_shutdown_marker_persistence(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_shutdown_marker_persistence",
                     "roundtrip");
    printf("boot_shutdown_marker_persistence: clean marker is private, "
           "consumed by detect, and removable... ");
    int rc = boot_shutdown_marker_persistence_probe(dir);
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    test_rm_rf_recursive(dir);
    return failures;
}
