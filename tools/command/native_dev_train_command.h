/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.train.* internals shared between the four hand-driven verbs
 *          (tools/command/native_dev_train_command.c) and the unattended
 *          keeper (tools/command/native_dev_train_keep.c).
 *
 * The keeper is a second file rather than a fifth verb inside the first one
 * for the same reason native_dev_land_regen.c is separate from
 * native_dev_land.c: one file owns one job. What the two files genuinely
 * share is a small, exact set of primitives — the no-shell git runner, the
 * doc-regen subject skip list, and the source-root resolution — and sharing
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

/* True iff a commit with this subject is a doc-regen-only commit that a
 * train assembler must NOT cherry-pick, because the assembler regenerates
 * the same artifacts once at the end. This is the single source of truth
 * for that list; both the hand-driven `dev train build` and the unattended
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

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

#endif /* ZCL_NATIVE_DEV_TRAIN_COMMAND_H */
