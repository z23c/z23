/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mint_anchor_normal_boot_gate: an in-progress mint marker must make
 * boot_mint_anchor_normal_boot_gate return false and latch the typed boot
 * refusal. A clean serving store stays allowed and latches nothing.
 */

#include "test/test_core.h"
#include "config/boot.h"
#include "config/boot_error.h"
#include "config/mint_anchor_progress.h"
#include "storage/progress_store.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int manbg_expect(const char *name, bool ok)
{
    printf("  mint_anchor_normal_boot_gate: %s... %s\n",
           name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool manbg_open(char *dir, size_t cap, const char *tag)
{
    if (!test_ensure_tmproot())
        return false;
    test_fmt_tmpdir(dir, cap, "mint_anchor_normal_boot_gate", tag);
    if (mkdir(dir, 0700) != 0)
        return false;
    return progress_store_open(dir);
}

static int manbg_render_names_refusal(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return manbg_expect(
        "render names code, phase, and in-progress marker",
        n > 0 &&
        strstr(rendered, "BOOT_MINT_ANCHOR_NORMAL_BOOT_REFUSED") != NULL &&
        strstr(rendered, "mint.anchor") != NULL &&
        strstr(rendered, "in-progress marker") != NULL);
}

static int manbg_marker_refused(void)
{
    char dir[PATH_MAX];
    int failures = 0;
    uint8_t marker[48];
    sqlite3 *db = NULL;
    const char *code = NULL;

    failures += manbg_expect("marker datadir opens",
                             manbg_open(dir, sizeof(dir), "marker"));
    memset(marker, 0, sizeof(marker));
    memcpy(marker, "ZAM1", 4);
    db = progress_store_db();
    failures += manbg_expect(
        "in-progress marker writes",
        db && progress_meta_set(db, MINT_ANCHOR_IN_PROGRESS_KEY,
                                marker, sizeof(marker)));
    boot_error_reset_for_testing();
    failures += manbg_expect(
        "gate refuses in-progress marker",
        !boot_mint_anchor_normal_boot_gate(progress_store_db()));
    failures += manbg_expect("typed refusal is latched",
                             boot_error_reported());
    code = boot_error_first_code();
    failures += manbg_expect(
        "code is BOOT_MINT_ANCHOR_NORMAL_BOOT_REFUSED",
        code && strcmp(code, "BOOT_MINT_ANCHOR_NORMAL_BOOT_REFUSED") == 0);
    failures += manbg_render_names_refusal();
    progress_store_close();
    return failures;
}

static int manbg_clean_allowed(void)
{
    char dir[PATH_MAX];
    int failures = 0;

    boot_error_reset_for_testing();
    failures += manbg_expect("clean datadir opens",
                             manbg_open(dir, sizeof(dir), "clean"));
    failures += manbg_expect(
        "clean store allows normal boot",
        boot_mint_anchor_normal_boot_gate(progress_store_db()));
    failures += manbg_expect("clean store latches no refusal",
                             !boot_error_reported());
    progress_store_close();
    return failures;
}

int test_mint_anchor_normal_boot_gate(void)
{
    int failures = 0;

    printf("\n=== test_mint_anchor_normal_boot_gate ===\n");
    failures += manbg_marker_refused();
    failures += manbg_clean_allowed();
    printf("=== test_mint_anchor_normal_boot_gate complete: %d failure(s) ===\n",
           failures);
    return failures;
}
