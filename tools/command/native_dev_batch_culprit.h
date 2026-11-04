/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the failure-log half of dev.batch.culprit (native_dev_batch_
 *          culprit_paths.c): which files a gate failure log names, with the
 *          filters drop_culprit() in the gate-submit.sh bridge applies, and
 *          the small sorted string set the leaf keeps them in. Nothing
 *          outside native_dev_batch_culprit*.c and its test includes it. */

#ifndef ZCL_NATIVE_DEV_BATCH_CULPRIT_H
#define ZCL_NATIVE_DEV_BATCH_CULPRIT_H

#include "command/native_dev_batch.h"

/* A set of strings, each held once. */
struct cp_set {
    char **v;
    size_t n, cap;
};

void cp_set_free(struct cp_set *s);
/* Adds s[0..len) unless held; false only when out of memory. */
bool cp_set_add(struct cp_set *s, const char *str, size_t len);
bool cp_set_has(const struct cp_set *s, const char *str);
void cp_set_sort(struct cp_set *s);

/* The tools/lint baseline, budget and floor .txt files: the shared ratchet
 * files every change touches, which never name a culprit and never make two
 * commits dependent. */
bool cp_is_ratchet(const char *path);

/* The log prints its own fix (a stale baseline row, a capability row): the
 * autofix round takes it and no commit is dropped. */
bool cp_log_fix_printed(const struct db_text *log);

/* The files the failure lines name, sorted, ratchet files left out. Which
 * lines count follows the stage (agent-verify reads the whole file). False
 * only when out of memory. */
bool cp_log_paths(const struct db_text *log, bool agent_verify,
                  struct cp_set *out);

#ifdef ZCL_TESTING
/* Test probe: parses `git log` text as the leaf does and returns the typed
 * refusal code that failure would give ("" when it parses). */
const char *dev_batch_culprit_test_parse_code(const char *log_text);
#endif

#endif
