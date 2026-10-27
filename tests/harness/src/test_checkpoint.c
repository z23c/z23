/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"
#include "validation/sync_evidence_policy.h"

#include <stdio.h>
#include <string.h>

static int check_reorg_no_tip_allowed(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(-1, 0, &r);
    if (ok && r && strcmp(r, "no_tip") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int check_reorg_target_above_tip_noop(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(100, 200, &r);
    if (ok && r && strcmp(r, "no_disconnect") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int check_reorg_target_equals_tip_allowed(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(100, 100, &r);
    if (ok)
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int check_reorg_one_deep_allowed(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(100, 99, &r);
    if (ok && r && strcmp(r, "within_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int check_reorg_max_depth_allowed(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(1000, 1000 - MAX_REORG_LENGTH, &r);
    if (ok && r && strcmp(r, "within_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int check_reorg_max_depth_plus_one_refused(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(1000, 1000 - MAX_REORG_LENGTH - 1, &r);
    if (!ok && r && strcmp(r, "below_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int check_reorg_very_deep_refused(void)
{
    int failures = 0;
    const char *r = NULL;
    bool ok = reorg_is_allowed(3000000, 1000, &r);
    if (!ok && r && strcmp(r, "below_finality_depth") == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); failures++; }
    return failures;
}

static int check_height_below_floor_immutable(void)
{
    int failures = 0;
    if (height_is_immutable(1000, 500))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int check_height_tip_is_mutable(void)
{
    int failures = 0;
    if (!height_is_immutable(1000, 1000))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int check_height_boundary_is_mutable(void)
{
    int failures = 0;
    if (!height_is_immutable(1000, 1000 - MAX_REORG_LENGTH + 1))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int check_finality_immutable_height(void)
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

static int check_ibd_reorg_bounded(void)
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
    failures += check_reorg_no_tip_allowed();

    printf("reorg_is_allowed: target above tip is no-op... ");
    failures += check_reorg_target_above_tip_noop();

    printf("reorg_is_allowed: target = tip is allowed (forward)... ");
    failures += check_reorg_target_equals_tip_allowed();

    printf("reorg_is_allowed: 1-deep reorg allowed... ");
    failures += check_reorg_one_deep_allowed();

    printf("reorg_is_allowed: MAX_REORG_LENGTH-deep allowed... ");
    failures += check_reorg_max_depth_allowed();

    printf("reorg_is_allowed: MAX_REORG_LENGTH+1 deep refused... ");
    failures += check_reorg_max_depth_plus_one_refused();

    printf("reorg_is_allowed: very deep refused... ");
    failures += check_reorg_very_deep_refused();

    printf("height_is_immutable: below floor is immutable... ");
    failures += check_height_below_floor_immutable();

    printf("height_is_immutable: tip itself is mutable... ");
    failures += check_height_tip_is_mutable();

    printf("height_is_immutable: tip - MAX_REORG_LENGTH boundary mutable... ");
    failures += check_height_boundary_is_mutable();

    printf("sync_evidence_policy: immutable height is tip minus finality... ");
    failures += check_finality_immutable_height();

    printf("sync_evidence_policy: IBD reorg exception is bounded... ");
    failures += check_ibd_reorg_bounded();

    return failures;
}
