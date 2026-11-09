/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the cheap local lint precheck `dev land submit` and `dev land send`
 *          run before anything is queued or packaged.
 *
 * Ten of twenty failed land rows in a week were deterministic lint failures
 * a local check would have caught. The gate set is a fixed core list plus
 * every check-* gate named in the detail or note of a lint row that failed
 * in the last 7 days of <land state>/outcomes.jsonl (the last line per seq
 * wins), so the precheck learns from the ledger. Each gate runs through the
 * lane worktree's own build/bin/z23-lint with the worktree as cwd.
 * Retained native failures from canonical <land>/wt are unioned with that
 * ledger: only FAILURE-class lint digests requested within the last seven
 * days (and not in the future) establish definitely recent failures. Older
 * request starts cannot date settlement. Uncertain/incomplete history is
 * explicitly unproven; incomplete reads contribute no historical gates.
 * The core list also holds the cheap candidate-content ratchets (kpi floor,
 * describe budget, hardening ratchet). check-file-size-ceiling, which is a
 * make target and not a z23-lint gate, runs the lane's build/bin/file_size_policy
 * when `z23-lint --list` does not name it; a missing binary is unproven.
 * A gate whose lane file is absent (check-cookbook needs build/bin/z23-dev,
 * check-windows-cross-syntax the generated guest-kernel TU) would report a
 * false red in a lane gated on a host, so it is unproven as well. A gate that
 * runs past the budget still refuses PRECHECK_TIMEOUT: a wedged gate must fail.
 * Learned check-ship-remote-transaction uses its fixed three-command adapter,
 * even without a native lint entry. Missing prerequisites are unproven;
 * any nonzero executed script verdict, including exit 2, refuses submission.
 */
#ifndef ZCL_NATIVE_DEV_LAND_PRECHECK_H
#define ZCL_NATIVE_DEV_LAND_PRECHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_command_reply;
struct json_value;
bool zcl_dev_land_precheck_input_valid(const struct json_value *input,
                                      bool checked_elsewhere, struct zcl_command_reply *reply);

#define ZCL_LAND_PRECHECK_BUDGET_MS (180 * 1000)
/* The budget is the 180 s base times the host's oversubscription: the learned
 * gates run one after another under one shared deadline, and on a host whose
 * 5-minute load average is N times its CPU count a single link-heavy gate
 * (check-standalone-tools-link: 169 s inside a green `make lint`) uses the
 * whole base. Scaling is monotone, never below the base, and capped at four
 * times it so a wedged gate still fails. */
#define ZCL_LAND_PRECHECK_BUDGET_MAX_SCALE 4

#define ZCL_LAND_PRECHECK_MAX_GATES 48u
#define ZCL_LAND_PRECHECK_GATE_MAX 64u
#define ZCL_LAND_PRECHECK_WINDOW_S (7 * 24 * 3600)
#define ZCL_LAND_PRECHECK_SHOW_LINES 20u
#define ZCL_LAND_PRECHECK_SKIP_SUFFIX " [precheck skipped]"

struct zcl_land_precheck_gates {
    char name[ZCL_LAND_PRECHECK_MAX_GATES][ZCL_LAND_PRECHECK_GATE_MAX];
    size_t count;
};

/* The gate set: the core list, then every check-* name in the detail or note
 * of a failed lint row of outcomes_path newer than now_s minus 7 days. A
 * missing or unreadable ledger leaves the core list. */
void zcl_land_precheck_gate_set(const char *outcomes_path, int64_t now_s,
                                struct zcl_land_precheck_gates *out);

/* The precheck budget in ms for a host with `cpus` logical CPUs and a
 * 5-minute load average of load5_centi/100: base * load5/cpus, clamped to
 * [base, base * ZCL_LAND_PRECHECK_BUDGET_MAX_SCALE]. An unknown (negative or
 * zero) input gives the base. Pure. */
int64_t zcl_land_precheck_budget_ms(int64_t cpus, int64_t load5_centi);
/* Validated explicit floor; zero preserves the automatic budget. */
int64_t zcl_land_precheck_budget_floor(int64_t automatic_ms, int64_t floor_ms);

/* Run the precheck for `leaf` ("dev.land" or "dev.land.send") in the lane
 * worktree `wt`. `mode` is the caller's precheck input: NULL or "run" runs
 * the gates, "skip" appends ZCL_LAND_PRECHECK_SKIP_SUFFIX to `note` (a buffer
 * of `cap` bytes holding the current note) and runs nothing; any other value
 * is refused BAD_INPUT, on every path. `checked_elsewhere` is an internal
 * flag, never an input key: true when the gates already ran for this exact
 * tree (--qualify's full lint, or the sending host on the receive path), so
 * "run" runs nothing, while the mode check and the skip marker still apply.
 * `tip`, when not NULL, must equal the HEAD of `wt` for "run" to lint it
 * (PRECHECK_TIP_NOT_HEAD otherwise). `land_dir` is the land state directory;
 * NULL resolves the default one. Returns true to go on; false fills `reply`
 * with the refusal and the caller queues or packages nothing. Under the
 * landing proof stub (tests) the gates are not run unless a test forces
 * them. On success reply->data gains precheck_ran / precheck_skipped. */
bool zcl_dev_land_precheck(const char *leaf, const char *wt,
                           const char *land_dir, const char *mode,
                           const char *tip, bool checked_elsewhere, char *note,
                           size_t cap, struct zcl_command_reply *reply);
bool zcl_dev_land_precheck_budgeted(const char *leaf, const char *wt,
                           const char *land_dir, const char *mode,
                           const char *tip, bool checked_elsewhere, char *note,
                           size_t cap, int64_t floor_ms, struct zcl_command_reply *reply);

#if defined(ZCL_TESTING)
/* Run the gates even while the landing proof stub is set. */
void zcl_dev_land_precheck_test_force(bool on);
/* Override precheck ledger/history window time only; nonpositive restores real time. */
void zcl_dev_land_precheck_test_now(int64_t now_s);
/* Override the thread-local test budget; nonpositive restores production. */
void zcl_dev_land_precheck_test_budget(int64_t budget_ms);
/* Advance a synthetic monotonic clock by step_ms at each deadline read. */
void zcl_dev_land_precheck_test_clock(int64_t step_ms);
#endif

#endif
