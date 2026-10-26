/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"
#include "validation/sync_evidence_policy.h"

#include <stdio.h>
#include <string.h>

static int checkpoint_case_1(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(-1, 0, &r);
    if (ok && r && strcmp(r, "no_tip") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int checkpoint_case_2(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(100, 200, &r);
    if (ok && r && strcmp(r, "no_disconnect") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int checkpoint_case_3(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(100, 100, &r);
    if (ok)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int checkpoint_case_4(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(100, 99, &r);
    if (ok && r && strcmp(r, "within_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int checkpoint_case_5(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(1000, 1000 - MAX_REORG_LENGTH, &r);
    if (ok && r && strcmp(r, "within_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int checkpoint_case_6(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(1000, 1000 - MAX_REORG_LENGTH - 1, &r);
    if (!ok && r && strcmp(r, "below_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int checkpoint_case_7(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(3000000, 1000, &r);
    if (!ok && r && strcmp(r, "below_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int checkpoint_case_8(void)
{
    int failures = 0;
    if (height_is_immutable(1000, 500))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int checkpoint_case_9(void)
{
    int failures = 0;
    if (!height_is_immutable(1000, 1000))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int checkpoint_case_10(void)
{
    int failures = 0;
    if (!height_is_immutable(1000, 1000 - MAX_REORG_LENGTH + 1))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int checkpoint_case_11(void)
{
    int failures = 0;
    if (zcl_finality_depth() == 10 &&
        zcl_immutable_height(1000) == 990 &&
        zcl_is_finality_safe_anchor(990, 1000) &&
        !zcl_is_finality_safe_anchor(991, 1000))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int checkpoint_case_12(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = zcl_reorg_allowed(2000, 1500, true, &r);
    bool bad = zcl_reorg_allowed(2000, 999, true, NULL);
    if (ok && r && strcmp(r, "ibd_reorg_allowed") == 0 && !bad)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

int test_checkpoint(void)
{
    int failures = 0;

    printf("reorg_is_allowed: no tip allows... ");
    failures += checkpoint_case_1();

    printf("reorg_is_allowed: target above tip is no-op... ");
    failures += checkpoint_case_2();

    printf("reorg_is_allowed: target = tip is allowed (forward)... ");
    failures += checkpoint_case_3();

    printf("reorg_is_allowed: 1-deep reorg allowed... ");
    failures += checkpoint_case_4();

    printf("reorg_is_allowed: MAX_REORG_LENGTH-deep allowed... ");
    failures += checkpoint_case_5();

    printf("reorg_is_allowed: MAX_REORG_LENGTH+1 deep refused... ");
    failures += checkpoint_case_6();

    printf("reorg_is_allowed: very deep refused... ");
    failures += checkpoint_case_7();

    printf("height_is_immutable: below floor is immutable... ");
    failures += checkpoint_case_8();

    printf("height_is_immutable: tip itself is mutable... ");
    failures += checkpoint_case_9();

    printf("height_is_immutable: tip - MAX_REORG_LENGTH boundary mutable... ");
    failures += checkpoint_case_10();

    printf("sync_evidence_policy: immutable height is tip minus finality... ");
    failures += checkpoint_case_11();

    printf("sync_evidence_policy: IBD reorg exception is bounded... ");
    failures += checkpoint_case_12();

    return failures;
}
