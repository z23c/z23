/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_TEST_GROUP_HISTORY_H
#define ZCL_TEST_GROUP_HISTORY_H

#include <stdbool.h>
#include <stddef.h>

/* Persistent per-group outcome ledger (schema zcl.test_group_history.v1).
 *
 * last-run.json is a single rename-overwritten snapshot, so failure
 * evidence evaporates the moment the next run starts. This feed appends
 * one JSON line per EXECUTED group instead — same runner, same moment,
 * same directory — and dev.test.history reads it back. See
 * tests/harness/src/group_history.c for the row contract. */

/* 40 hex digits plus the NUL, the honest-empty variant included. */
#define ZCL_GROUP_HISTORY_TREE_LEN 41u

/* One executed group, as the parallel runner observed it. `rc` mirrors
 * the timing row (signaled groups carry the negated signal); `pass` is
 * tally_group's rule (!signaled && exit_code == 0), so a load-flaky
 * alone-rerun PASS is a PASS here with load_flaky set. */
struct zcl_group_history_row {
    const char *group;
    int rc;
    bool pass;
    bool timing_valid;
    long long wall_ms;
    int load_flaky;
};

/* Render one ledger line (WITHOUT the trailing newline) into buf.
 * Returns the line length excluding the NUL, or 0 when the buffer is too
 * small — never a truncated guess. */
size_t zcl_group_history_line(char *buf, size_t cap,
                              const struct zcl_group_history_row *row,
                              const char *ts, const char *tree);

/* Append `count` lines to `path` (created as needed): one open, one
 * write() per line so concurrent runners interleave at line boundaries.
 * Returns the number of lines appended, or -1 with errno on failure.
 * count == 0 touches no file. */
int zcl_group_history_append(const char *path, const char *ts,
                             const char *tree,
                             const struct zcl_group_history_row *rows,
                             size_t count);

/* Resolve the worktree HEAD of `root` into a 40-hex commit id (out holds
 * ZCL_GROUP_HISTORY_TREE_LEN bytes). Unresolvable means EMPTY — an
 * unknown tree is reported as unknown, never guessed: git resolves HEAD
 * through .git (dir, or the `gitdir:` file of a linked worktree), the
 * loose ref, the worktree's commondir, and packed-refs, exactly as git
 * does, reading only those small files. */
void zcl_group_history_tree(const char *root, char *out, size_t cap);

#endif /* ZCL_TEST_GROUP_HISTORY_H */
