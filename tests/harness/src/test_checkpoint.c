/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "validation/checkpoint.h"
#include "validation/main_constants.h"
#include "validation/sync_evidence_policy.h"

#include <stdio.h>
#include <string.h>

static int check_reorg_reason_matches(int tip, int target, bool want_ok,
                                      const char *want_reason)
{
    const char *r = NULL;
    bool ok = reorg_is_allowed(tip, target, &r);
    if (ok == want_ok && r && strcmp(r, want_reason) == 0)
        printf("OK\n");
    else { printf("FAIL (ok=%d r=%s)\n", ok, r ? r : "(null)"); return 1; }
    return 0;
}

static int check_reorg_forward_ok(int tip, int target)
{
    const char *r = NULL;
    bool ok = reorg_is_allowed(tip, target, &r);
    if (ok)
        printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int check_immutable_height_flag(int tip, int height, bool want_immutable)
{
    if (height_is_immutable(tip, height) == want_immutable)
        printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int check_finality_policy_invariants(void)
{
    if (zcl_finality_depth() == 10 &&
        zcl_immutable_height(1000) == 990 &&
        zcl_is_finality_safe_anchor(990, 1000) &&
        !zcl_is_finality_safe_anchor(991, 1000))
        printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

static int check_ibd_reorg_exception_bounds(void)
{
    const char *r = NULL;
    bool ok = zcl_reorg_allowed(2000, 1500, true, &r);
    bool bad = zcl_reorg_allowed(2000, 999, true, NULL);
    if (ok && r && strcmp(r, "ibd_reorg_allowed") == 0 && !bad)
        printf("OK\n");
    else { printf("FAIL\n"); return 1; }
    return 0;
}

int test_checkpoint(void)
{
    int failures = 0;

    printf("reorg_is_allowed: no tip allows... ");
    failures += check_reorg_reason_matches(-1, 0, true, "no_tip");

    printf("reorg_is_allowed: target above tip is no-op... ");
    failures += check_reorg_reason_matches(100, 200, true, "no_disconnect");

    printf("reorg_is_allowed: target = tip is allowed (forward)... ");
    failures += check_reorg_forward_ok(100, 100);

    printf("reorg_is_allowed: 1-deep reorg allowed... ");
    failures += check_reorg_reason_matches(100, 99, true, "within_finality_depth");

    printf("reorg_is_allowed: MAX_REORG_LENGTH-deep allowed... ");
    failures += check_reorg_reason_matches(1000, 1000 - MAX_REORG_LENGTH, true,
                                           "within_finality_depth");

    printf("reorg_is_allowed: MAX_REORG_LENGTH+1 deep refused... ");
    failures += check_reorg_reason_matches(1000, 1000 - MAX_REORG_LENGTH - 1,
                                           false, "below_finality_depth");

    printf("reorg_is_allowed: very deep refused... ");
    failures += check_reorg_reason_matches(3000000, 1000, false,
                                           "below_finality_depth");

    printf("height_is_immutable: below floor is immutable... ");
    failures += check_immutable_height_flag(1000, 500, true);

    printf("height_is_immutable: tip itself is mutable... ");
    failures += check_immutable_height_flag(1000, 1000, false);

    printf("height_is_immutable: tip - MAX_REORG_LENGTH boundary mutable... ");
    failures += check_immutable_height_flag(1000, 1000 - MAX_REORG_LENGTH + 1,
                                            false);

    printf("sync_evidence_policy: immutable height is tip minus finality... ");
    failures += check_finality_policy_invariants();

    printf("sync_evidence_policy: IBD reorg exception is bounded... ");
    failures += check_ibd_reorg_exception_bounds();

    return failures;
}
