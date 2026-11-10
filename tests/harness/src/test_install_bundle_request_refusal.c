/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_install_bundle_request_refusal — boot_install_bundle_request_refused
 * (engine/composition/src/boot_auto_install_bundle.c).
 *
 * An absent install_bundle_request stays quiet: the call returns false and
 * does not latch a boot error. The bytes bad\n are not a readable request,
 * so the call returns true and reports BOOT_INSTALL_BUNDLE_REQUEST_REFUSED
 * with phase install.request and evidence stage=install_request_unusable.
 * A NULL datadir is the same refusal (ibr_path fails closed as IBR_INVALID),
 * not the quiet case.
 */

#include "test/test_core.h"

#include "config/boot_error.h"
#include "config/consensus_state_install_runtime.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define IBRR_CHECK(name, expr) do {                                 \
    printf("  install_bundle_request_refusal: %s... ", (name));     \
    if (expr) printf("OK\n");                                       \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

static bool ibrr_write_bad(const char *dir)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/install_bundle_request", dir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool wrote = fwrite("bad\n", 1, 4, f) == 4;
    bool closed = fclose(f) == 0;
    if (!wrote || !closed) return false;
    return chmod(path, 0600) == 0;
}

static bool ibrr_names_refusal(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return n > 0 &&
           boot_error_reported() &&
           strcmp(boot_error_first_code(),
                  "BOOT_INSTALL_BUNDLE_REQUEST_REFUSED") == 0 &&
           strstr(rendered, "phase:    install.request") != NULL &&
           strstr(rendered, "stage=install_request_unusable") != NULL;
}

int test_install_bundle_request_refusal(void);
int test_install_bundle_request_refusal(void)
{
    test_reset_shared_globals();
    printf("\n=== install_bundle_request_refusal tests ===\n");
    int failures = 0;
    char dir[256];

    boot_error_reset_for_testing();
    test_make_tmpdir(dir, sizeof(dir), "ibr_refuse", "quiet");
    bool quiet = boot_install_bundle_request_refused(dir);
    IBRR_CHECK("absent request does not refuse", quiet == false);
    IBRR_CHECK("absent request does not latch", boot_error_reported() == false);

    boot_error_reset_for_testing();
    bool wrote = ibrr_write_bad(dir);
    IBRR_CHECK("malformed request writes", wrote);
    bool refused = wrote && boot_install_bundle_request_refused(dir);
    IBRR_CHECK("malformed request refuses", refused == true);
    IBRR_CHECK("malformed request names stage", refused && ibrr_names_refusal());

    boot_error_reset_for_testing();
    bool null_refused = boot_install_bundle_request_refused(NULL);
    IBRR_CHECK("NULL datadir refuses", null_refused == true);
    IBRR_CHECK("NULL datadir names stage", null_refused && ibrr_names_refusal());

    boot_error_reset_for_testing();
    test_rm_rf_recursive(dir);
    return failures;
}
