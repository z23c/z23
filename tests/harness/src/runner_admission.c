/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure memory-admission decisions for test_parallel; see
 * test/runner_admission.h. */
#include "test/runner_admission.h"

#include "platform/logical_cpu.h"

int64_t runner_admission_estimate(int64_t static_bytes, int64_t done_bytes,
                                  int64_t pool_peak_bytes)
{
    if (done_bytes > static_bytes) return done_bytes;
    int64_t pool = pool_peak_bytes + pool_peak_bytes / 2;
    return pool > static_bytes ? pool : static_bytes;
}

bool runner_admission_is_young(int64_t now_us, int64_t start_us)
{
    return now_us - start_us < RUNNER_ADMIT_RAMP_US;
}

int64_t runner_admission_pending(int64_t estimate_bytes, int64_t live_peak_bytes)
{
    int64_t grow = estimate_bytes - live_peak_bytes;
    return grow > 0 ? grow : 0;
}

bool runner_admission_admit(int running, int young, int64_t headroom_bytes,
                            int64_t pending_bytes, int64_t estimate_bytes)
{
    if (running <= 0) return true;
    if (young >= RUNNER_ADMIT_MAX_YOUNG) return false;
    if (headroom_bytes >= 0) {
        headroom_bytes -= pending_bytes;
        if (headroom_bytes < 0) headroom_bytes = 0;
    }
    return platform_memory_admit(headroom_bytes, estimate_bytes,
                                 RUNNER_ADMIT_RESERVE_BYTES);
}

void runner_admission_note_peak(int64_t peak_bytes, bool finished,
                                int64_t *group_peak, int64_t *group_done,
                                int64_t *pool_peak)
{
    if (peak_bytes > *group_peak) *group_peak = peak_bytes;
    if (finished && peak_bytes > *group_done) *group_done = peak_bytes;
    if (peak_bytes > *pool_peak) *pool_peak = peak_bytes;
}
