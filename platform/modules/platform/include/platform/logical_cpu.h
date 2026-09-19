/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded online logical-processor count across host platforms. */
#ifndef ZCL_PLATFORM_LOGICAL_CPU_H
#define ZCL_PLATFORM_LOGICAL_CPU_H

#include <stdbool.h>
#include <stdint.h>

/* Count online logical processors.
 *
 * On Windows this spans every processor group when the build's API floor
 * allows it (_WIN32_WINNT >= 0x0601); at this project's actual 0x0600 floor
 * it reports the calling thread's group only, which undercounts above 64
 * logical processors rather than over-reporting. Callers size worker pools
 * from this, so the error direction is the safe one.
 *
 * The result is always in [1, UINT32_MAX]; unavailable or invalid host data
 * deterministically falls back to one. */
uint32_t platform_logical_cpu_count(void);

/* Count the logical processors this PROCESS is actually allowed to run on.
 *
 * platform_logical_cpu_count() answers "how big is the host", which is the
 * wrong question for sizing a build: a process launched under taskset, a
 * systemd scope with AllowedCPUs, or a container CPU set sees every online
 * processor through sysconf() while the kernel will only ever schedule it on
 * the subset in its affinity mask. Sizing a job pool from the host count
 * oversubscribes exactly the cores that were deliberately withheld.
 *
 * On Linux the answer is CPU_COUNT() of sched_getaffinity(0, ...). Everywhere
 * else -- including Windows -- this delegates to platform_logical_cpu_count():
 * Win32 has no process-wide equivalent (SetProcessAffinityMask's companion
 * getter reports a mask this codebase never sets, and real placement control
 * there is the per-thread group-affinity API), and no Z23 caller runs under a
 * taskset-equivalent wrapper on Windows. A separate Windows implementation
 * would be untested surface, so it waits for a caller that needs it.
 *
 * The result is always in [1, UINT32_MAX]; an unavailable or empty mask
 * deterministically falls back to platform_logical_cpu_count(). */
uint32_t platform_available_cpu_count(void);


/* ── The one build-parallelism answer this repository uses ────────────────
 *
 * WHY THIS IS SHARED. Before it existed, twenty-eight hard-coded `-jN`
 * literals across eight different values decided how wide this tree built,
 * and almost none of them said why. They did not merely disagree; one of
 * them took the whole judged-unit pipeline down. A gate whose build budget
 * was 90 s ran `make test_parallel` with no `-j` at all -- 137 s measured,
 * 18 s at -j28 -- so no file unit could be judged at all, while the proof
 * clamped itself to a compiled-in 16 and the landing leaf spawned a bare
 * -j8, on a host that grants 28 processors. Every caller that spawns make
 * asks here and gets ONE answer. A constant that survives elsewhere must
 * carry the measurement that chose it; an unexplained number is the defect,
 * whether or not the number happens to be right. */

/* The smaller of two limits, as a job count in [1, available_cpus].
 *
 * `available_cpus` is what platform_available_cpu_count() reports -- the
 * affinity mask, not the box. `memory_budget_bytes` is what the grant will
 * actually let this process tree hold, or <= 0 when the host will not say,
 * in which case the CPU limit stands alone. Inventing a ceiling out of
 * silence is precisely how the compiled-in 16 this replaces came to exist.
 *
 * Pure: no syscalls, no environment, same inputs give the same answer on
 * every host. Exposed rather than folded into platform_build_jobs_arg()
 * because a number this load-bearing deserves a test that does not need a
 * host with a particular CPU count or memory ceiling. */
uint32_t platform_build_job_count(uint32_t available_cpus,
                                  int64_t memory_budget_bytes);

/* The memory this process tree may actually hold, in bytes, or -1 when the
 * host publishes no limit worth dividing by. Prefers the cgroup v2 ceiling
 * the build actually runs under over the size of the machine, because on a
 * scheduled build host those are different numbers and only the first one
 * will be enforced. */
int64_t platform_build_memory_budget_bytes(void);

/* Write the `-jN` argument a spawned make should carry into `out` (at most
 * 15 characters plus the terminator). Returns false only when the number
 * would not fit, which no count a real host reports can cause.
 *
 * This is platform_build_job_count() over platform_available_cpu_count() and
 * platform_build_memory_budget_bytes(). Callers take the formatted argument
 * rather than the number so that three spawn sites cannot drift over how
 * they spell it. */
bool platform_build_jobs_arg(char out[16]);
#endif
