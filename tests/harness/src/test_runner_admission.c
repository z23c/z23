/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the pure admission rules test_parallel forks under
 * (tests/harness/src/runner_admission.c). */
#include "test/test_core.h"
#include "test/runner_admission.h"

#include <stdio.h>

#define RA_MIB(n) (INT64_C(1024) * 1024 * (n))

#define RA_CHECK(name, expr) do { \
    printf("runner_admission: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_runner_admission(void)
{
    int failures = 0;

    /* Never deadlock: with nothing running one group is admitted even when
     * it is far heavier than the whole headroom, or the headroom is gone. */
    RA_CHECK("zero running admits a group heavier than the headroom",
             runner_admission_admit(0, 0, RA_MIB(10), 0, RA_MIB(8192)));
    RA_CHECK("zero running admits with no headroom at all",
             runner_admission_admit(0, 0, 0, RA_MIB(500), RA_MIB(512)));
    RA_CHECK("one running does not get the deadlock exemption",
             !runner_admission_admit(1, 0, RA_MIB(10), 0, RA_MIB(512)));

    /* Headroom: estimate plus reserve must fit. */
    RA_CHECK("headroom covering estimate plus reserve admits",
             runner_admission_admit(2, 0, RA_MIB(768), 0, RA_MIB(512)));
    RA_CHECK("headroom one byte short of estimate plus reserve refuses",
             !runner_admission_admit(2, 0, RA_MIB(768) - 1, 0, RA_MIB(512)));
    RA_CHECK("pending growth of running groups is charged",
             !runner_admission_admit(2, 0, RA_MIB(1000), RA_MIB(300),
                                     RA_MIB(512)));
    RA_CHECK("pending beyond the headroom clamps and refuses",
             !runner_admission_admit(2, 0, RA_MIB(100), RA_MIB(900), 0 + 1));
    RA_CHECK("unknown headroom (no cgroup limit) admits",
             runner_admission_admit(5, 0, -1, RA_MIB(900), RA_MIB(512)));

    /* Young cap. */
    RA_CHECK("below the young cap admits",
             runner_admission_admit(3, RUNNER_ADMIT_MAX_YOUNG - 1, -1, 0,
                                    RA_MIB(512)));
    RA_CHECK("at the young cap refuses despite ample headroom",
             !runner_admission_admit(3, RUNNER_ADMIT_MAX_YOUNG,
                                     RA_MIB(65536), 0, RA_MIB(512)));
    RA_CHECK("at the young cap refuses with unknown headroom",
             !runner_admission_admit(3, RUNNER_ADMIT_MAX_YOUNG, -1, 0, 0));
    RA_CHECK("group younger than the ramp is young",
             runner_admission_is_young(RUNNER_ADMIT_RAMP_US - 1, 0));
    RA_CHECK("group at the ramp age is no longer young",
             !runner_admission_is_young(RUNNER_ADMIT_RAMP_US, 0));

    /* Estimates: static, learned peak, 1.5x heaviest. */
    RA_CHECK("unmeasured pool gives the static figure",
             runner_admission_estimate(RA_MIB(512), 0, 0) == RA_MIB(512));
    RA_CHECK("learned peak above the static figure replaces it",
             runner_admission_estimate(RA_MIB(512), RA_MIB(2048),
                                       RA_MIB(2048)) == RA_MIB(2048));
    RA_CHECK("learned peak below the static figure does not shrink it",
             runner_admission_estimate(RA_MIB(512), RA_MIB(100), 0) ==
                 RA_MIB(512));
    RA_CHECK("unmeasured group is charged 1.5x the heaviest seen",
             runner_admission_estimate(RA_MIB(512), 0, RA_MIB(2048)) ==
                 RA_MIB(3072));
    RA_CHECK("a light pool peak leaves the static figure",
             runner_admission_estimate(RA_MIB(512), 0, RA_MIB(300)) ==
                 RA_MIB(512));
    RA_CHECK("pending growth is estimate less live peak",
             runner_admission_pending(RA_MIB(512), RA_MIB(200)) == RA_MIB(312));
    RA_CHECK("pending growth never goes negative",
             runner_admission_pending(RA_MIB(512), RA_MIB(900)) == 0);

    /* Peak accounting: live samples raise only the live and pool peaks, the
     * wait4 figure also raises the finished peak. */
    {
        int64_t peak = 0, done = 0, pool = RA_MIB(700);
        runner_admission_note_peak(RA_MIB(300), false, &peak, &done, &pool);
        RA_CHECK("live sample raises the group peak only",
                 peak == RA_MIB(300) && done == 0 && pool == RA_MIB(700));
        runner_admission_note_peak(RA_MIB(900), true, &peak, &done, &pool);
        RA_CHECK("reaped peak raises group, finished and pool peaks",
                 peak == RA_MIB(900) && done == RA_MIB(900) &&
                     pool == RA_MIB(900));
        runner_admission_note_peak(RA_MIB(100), true, &peak, &done, &pool);
        RA_CHECK("a smaller later peak lowers nothing",
                 peak == RA_MIB(900) && done == RA_MIB(900) &&
                     pool == RA_MIB(900));
    }
    return failures;
}
