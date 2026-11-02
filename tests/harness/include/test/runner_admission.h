/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The pure decision logic behind test_parallel's memory-aware fork
 * admission. Every input is a value (headroom, running estimates, ages,
 * peaks), so the runner and test_runner_admission link the same code and the
 * rules (never deadlock, young-group cap, learned peaks) can be exercised
 * without forking anything. */
#ifndef ZCL_TEST_RUNNER_ADMISSION_H
#define ZCL_TEST_RUNNER_ADMISSION_H

#include <stdbool.h>
#include <stdint.h>

/* Memory held back from the cgroup headroom when admitting a fork. */
#define RUNNER_ADMIT_RESERVE_BYTES (INT64_C(256) * 1024 * 1024)
/* A just-forked child has not grown yet, so memory.current under-reports it;
 * its estimate stays charged this long. */
#define RUNNER_ADMIT_RAMP_US INT64_C(3000000)
/* No more than this many ramping groups at a time, so the first wave cannot
 * outrun the measurements. */
#define RUNNER_ADMIT_MAX_YOUNG 3

/* What a group is expected to peak at: its finished peak from an earlier run
 * (done_bytes) when that exceeds the static figure, else the larger of the
 * static figure and 1.5x the heaviest group seen (pool_peak_bytes). */
int64_t runner_admission_estimate(int64_t static_bytes, int64_t done_bytes,
                                  int64_t pool_peak_bytes);

/* True while a group forked at start_us is still ramping at now_us. */
bool runner_admission_is_young(int64_t now_us, int64_t start_us);

/* Growth a running group is still expected to make: estimate less the peak
 * seen live so far, never negative. */
int64_t runner_admission_pending(int64_t estimate_bytes, int64_t live_peak_bytes);

/* May a group estimated at estimate_bytes fork now? Admits when nothing is
 * running (never deadlock); else when headroom less pending growth and the
 * reserve covers the estimate and fewer than RUNNER_ADMIT_MAX_YOUNG groups
 * are ramping. A negative headroom means no cgroup limit is known. */
bool runner_admission_admit(int running, int young, int64_t headroom_bytes,
                            int64_t pending_bytes, int64_t estimate_bytes);

/* Fold a measured peak (live VmHWM or wait4 ru_maxrss) into a group's live
 * peak and the pool peak; finished is true for the wait4 figure, which also
 * raises the group's finished peak. */
void runner_admission_note_peak(int64_t peak_bytes, bool finished,
                                int64_t *group_peak, int64_t *group_done,
                                int64_t *pool_peak);

#endif
