/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.train.* internals shared between the four hand-driven verbs
 *          (tools/command/native_dev_train_command.c) and the unattended
 *          keeper (tools/command/native_dev_train_keep.c).
 *
 * The keeper is a second file rather than a fifth verb inside the first one
 * for the same reason native_dev_land_prepare.c is separate from
 * native_dev_land.c: one file owns one job. What the two files genuinely
 * share is a small, exact set of primitives — the no-shell git runner, the
 * baseline-pin subject skip list, and the source-root resolution — and sharing
 * them here is what keeps the skip list a SINGLE source of truth. A second
 * copy of that list in the keeper would be a second policy that drifts.
 *
 * Every declaration below exists only in a dev or test build: the release
 * build compiles the dev arms of both files out entirely.
 */
#ifndef ZCL_NATIVE_DEV_TRAIN_COMMAND_H
#define ZCL_NATIVE_DEV_TRAIN_COMMAND_H

#include <stdbool.h>
#include <stddef.h>

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

struct zcl_command_request;

/* Run one git command. `dir` is passed as `-C <dir>` (omitted when empty).
 * `out`/`out_cap` may be NULL/0 when the caller only wants the exit status.
 * No shell is involved: argv goes straight to execvp through util/spawn.h.
 * Returns the child's exit status (0 on success). */
int zcl_dev_train_git(const char *dir, const char *const args[], char *out,
                      size_t out_cap, int timeout_ms);

/* Strip trailing CR/LF from `s` in place. */
void zcl_dev_train_strip(char *s);

/* True iff `path` names a real directory (never a symlink to one). */
bool zcl_dev_train_is_dir(const char *path);

/* True iff a commit with this subject is a baseline-pin commit that a train
 * assembler must NOT cherry-pick: a pin describes one lane's tree, never the
 * assembled train's, and an assembler never rewrites a baseline. A lane's
 * regenerated-doc commit is NOT skipped; it is picked like any other. This is
 * the single source of truth for that list; both the hand-driven `dev train build` and the unattended
 * `dev train keep` ask this one function. */
bool zcl_dev_train_skip_subject(const char *subject);

/* The checkout this request is about: the request context's source root,
 * else $ZCL_DEV_SOURCE_ROOT, else ".". Never NULL. */
const char *zcl_dev_train_source_root(const struct zcl_command_request *request);

/* <platform_state_root>/land — the directory dev.land owns. The keeper and
 * `dev train status` both read the queue and outcome ledgers from here, and
 * neither may hardcode a path: dev.land derives this from
 * platform_state_root() and so must they. Returns false when the state root
 * cannot be resolved or does not fit. */
bool zcl_dev_train_land_dir(char *out, size_t cap);
/* Resolve the same path only from an existing private state root. Never
 * create directories or repair permissions while inspecting a preview. */
bool zcl_dev_train_land_dir_existing(char *out, size_t cap);

/* ── gated check (native_dev_train_gate.c) ─────────────────────────────── */

struct json_value;
struct zcl_devloop_process_result;

#define ZCL_DEV_TRAIN_GATE_FAST 1u
#define ZCL_DEV_TRAIN_GATE_LINT 2u
#define ZCL_DEV_TRAIN_GATE_VERIFY 4u

/* Parse a `--gates` list ("fast", "lint", "verify", comma separated) into a
 * bit mask. False, with an explanatory `why`, for an unknown or empty list. */
bool zcl_dev_train_gates_parse(const char *csv, unsigned *mask, char *why,
                               size_t why_cap);

/* What one gated check produced. `gates` and `attribution` point at arrays
 * the caller json_init()ed and json_set_array()ed and later json_free()s:
 * `gates` receives {gate, verdict, wall_ms, log_path} per gate run;
 * `attribution` receives {group, guilty | candidates[]} per failed group
 * after a red verify. */
struct zcl_dev_train_gate_report {
    bool ok;
    int64_t wall_ms;
    char log_path[4096];
    char gates_failed_csv[4096];
    const char *attribution_from;
    struct json_value *gates;
    struct json_value *attribution;
};

/* Run the selected gates in the order fast, lint, verify inside `stack_dir`
 * under the checkout-wide build lock, stopping at the first red one. */
void zcl_dev_train_run_gates(const char *stack_dir, const char *root,
                             unsigned mask, int timeout_ms,
                             struct zcl_dev_train_gate_report *report);

/* Record each build source (dir or ref, and its original tip) in the stack
 * worktree's git dir, so a red verify can name the guilty source. */
void zcl_dev_train_record_sources(const char *stack_dir, const char *root,
                                  const char *sources_csv);

/* Test seam: replace how a gate's make runs and how a source's groups are
 * selected. NULL members (and a NULL table) restore the real ones. */
struct zcl_dev_train_gate_hooks {
    bool (*run)(const char *stack_dir, const char *gate,
                const char *const argv[], int timeout_ms,
                struct zcl_devloop_process_result *out);
    bool (*select)(const char *source_root, const char *tip, char *groups,
                   size_t groups_cap, bool *universal);
};
void zcl_dev_train_gate_hooks_set(const struct zcl_dev_train_gate_hooks *hooks);

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#endif /* ZCL_NATIVE_DEV_TRAIN_COMMAND_H */
