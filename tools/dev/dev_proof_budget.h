/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Size each proof step from its own history and kill only a step
 * that has stopped producing output. */

#ifndef ZCL_TOOLS_DEV_PROOF_BUDGET_H
#define ZCL_TOOLS_DEV_PROOF_BUDGET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The hard ceiling. No step may run past this however healthy it looks.
 * ZCL_PROOF_TIMEOUT_MS in the environment may only RAISE the ceiling, never
 * lower it, and never past PROOF_TIMEOUT_MAX_MS. */
#define PROOF_TIMEOUT_MS 3600000
#define PROOF_TIMEOUT_MAX_MS 7200000

/* A step is dead only when its log has stopped growing for this long AND its
 * own budget is already spent. 600 s is deliberately longer than the test
 * harness's 300 s per-group watchdog so the harness always speaks first. */
#define PROOF_NO_PROGRESS_MS 600000

/* Compiled-in allowances, used until this checkout has measured its own. */
#define PROOF_TEST_GROUP_DEFAULT_MS 120000
#define PROOF_TEST_FLOOR_MS 300000
#define PROOF_STEP_FLOOR_MS 300000

/* How many wall times per key the rolling table remembers. */
#define PROOF_HISTORY_MAX 8u
#define PROOF_TIMING_KEY_MAX 128u

enum zcl_dev_proof_kill_cause {
    ZCL_DEV_PROOF_KILL_NONE = 0,
    ZCL_DEV_PROOF_KILL_NO_PROGRESS,
    ZCL_DEV_PROOF_KILL_HARD_CEILING,
};

struct zcl_dev_proof_budget {
    int64_t budget_ms;      /* what this step was planned to need */
    int64_t ceiling_ms;     /* the hard stop */
    int64_t no_progress_ms; /* silence that counts as death */
};

struct zcl_dev_proof_step_report {
    int64_t budget_ms;
    int64_t elapsed_ms;
    int64_t last_progress_age_ms;
    enum zcl_dev_proof_kill_cause cause;
    int rc;
};

const char *zcl_dev_proof_kill_cause_name(enum zcl_dev_proof_kill_cause cause);

/* The ceiling this machine will honour, after the environment has had its
 * (raise-only) say. */
int64_t zcl_dev_proof_ceiling_ms(void);

/* Clamp a planned budget into [floor, ceiling]. */
struct zcl_dev_proof_budget zcl_dev_proof_budget_make(int64_t planned_ms,
                                                      int64_t floor_ms);

/* The whole kill decision, as a pure function of the clock. */
enum zcl_dev_proof_kill_cause zcl_dev_proof_budget_verdict(
    const struct zcl_dev_proof_budget *budget, int64_t elapsed_ms,
    int64_t last_progress_age_ms);

/* Rolling per-key wall-time history under <state_dir>/timing/table.tsv. */
bool zcl_dev_proof_timing_note(const char *state_dir, const char *key,
                               int64_t observed_ms);
/* The allowance history argues for, or fallback_ms when this key is unknown. */
int64_t zcl_dev_proof_timing_allowance_ms(const char *state_dir,
                                          const char *key, int64_t fallback_ms);
/* Fold every `==== <group> (PASS, Ns) ====` banner in a finished test log into
 * the table. Returns how many groups were recorded. */
size_t zcl_dev_proof_timing_ingest_test_log(const char *state_dir,
                                            const char *log_path);
/* Parse one banner line. Returns false for any line that is not a passing
 * group banner. */
bool zcl_dev_proof_timing_parse_group_line(const char *line, char *group,
                                           size_t group_size, int64_t *ms);

/* Budgets. The test dimension grows with the groups it will actually run. */
struct zcl_dev_proof_budget zcl_dev_proof_test_budget(const char *state_dir,
                                                      const char *groups_csv,
                                                      uint32_t groups);
struct zcl_dev_proof_budget zcl_dev_proof_step_budget(const char *state_dir,
                                                      const char *key,
                                                      int64_t fallback_ms);

/* Append one accounted step to phases.txt. */
bool zcl_dev_proof_phase_record(const char *phases_path, const char *step,
                                const struct zcl_dev_proof_step_report *report);

#if !defined(_WIN32)
/* Run argv in its own session with stdout+stderr on log_path, watching the log
 * for growth. Returns the child's exit status, 124 when the watch killed it,
 * or -1 when the step could not be started or reaped. */
int zcl_dev_proof_run_watched(const char *root, const char *log_path,
                              const char *const argv[],
                              const struct zcl_dev_proof_budget *budget,
                              struct zcl_dev_proof_step_report *report);
#endif

#endif
