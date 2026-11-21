/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: tell the author of a failed proof when the failing test group or
 *          lint gate is probably main itself, not their change. Read-only
 *          and advisory: derived at read time from the outcomes ledger rows
 *          the status reader already streams, with no state of its own.
 *
 * RULE. A failure key is one test group plus the place it failed (the first
 * line of the row's detail, minus the log path), or one lint gate. A key is
 * suspect when at least DLMR_K distinct candidates (distinct worktree)
 * failed it in a chain whose neighbours are at most DLMR_GAP outcome rows
 * apart, the newest failure is itself within DLMR_GAP rows of the end of
 * the ledger, and no landed row follows that newest failure. A landed row
 * after the newest failure may be the repair, so it clears the suspicion;
 * the next failure on the key raises it again. The rule never blocks,
 * reorders or refuses a submission, and it is a hint: two authors who both
 * break the same gate in their own change are indistinguishable from a red
 * main in the ledger. */

#ifndef ZCL_NATIVE_DEV_LAND_MAIN_RED_H
#define ZCL_NATIVE_DEV_LAND_MAIN_RED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json/json.h"

#define DLMR_WINDOW 200u
#define DLMR_K 2u
#define DLMR_GAP 40u
#define DLMR_GROUP_MAX 72u
#define DLMR_ROWS_MAX 8u
#define DLMR_SUSPECTS_MAX 8u

struct dlmr_entry {
    long long seq;
    size_t pos; /* index of the row among every row folded in */
    uint64_t candidate;
    uint64_t site; /* where a test failed; 0 for a lint gate */
    unsigned char kind; /* 1 landed, 2 failed on a named group */
    char dimension[8];  /* "test" or "lint" when kind == 2 */
    char group[DLMR_GROUP_MAX];
};

/* The last DLMR_WINDOW signal rows, oldest first. Zero-initialise it. */
struct dlmr_window {
    struct dlmr_entry e[DLMR_WINDOW];
    size_t count;
    size_t seen; /* every row folded in, signal or not */
};

struct dlmr_suspect {
    char dimension[8];
    char group[DLMR_GROUP_MAX];
    long long rows[DLMR_ROWS_MAX]; /* the first failing row, then the newest */
    size_t nrows;                  /* kept in rows[] */
    size_t total;                  /* failing rows in the chain */
    long long first_seq;
};

/* Fold one outcome row in, in file order. Rows that are neither landed nor a
 * failure naming a group still advance the row count. */
void dlmr_note(struct dlmr_window *w, long long seq, const char *state,
               const char *dimension, const char *worktree, const char *tip,
               const char *detail);

/* The suspect keys, ordered by their newest failure; returns how many. */
size_t dlmr_suspects(const struct dlmr_window *w, struct dlmr_suspect *out,
                     size_t cap);

/* "main may be red for <group>: rows 3279, 3284 failed it; land the repair
 * first". Returns the length written, 0 when it does not fit. */
size_t dlmr_line(const struct dlmr_suspect *s, char *out, size_t cap);

/* The hint for one failed row: the line of the suspect that lists `seq`, or
 * "" when the row is not on a suspect key. */
void dlmr_row_hint(const struct dlmr_suspect *sus, size_t n, long long seq,
                   char *out, size_t cap);

/* The group a failed row names; false and "" when it names none. */
bool dlmr_group_of(const char *dimension, const char *detail, char *out,
                   size_t cap);

/* Push the "main_red" array (empty when nothing is suspect) onto the status
 * reply's data object. */
bool dlmr_push_status(struct json_value *data, const struct dlmr_suspect *sus,
                      size_t n);

/* Push "main_red_hint" onto one outcome item when its row is on a suspect
 * key; pushes nothing otherwise. False only when the push itself fails. */
bool dlmr_push_row_hint(struct json_value *item, const struct dlmr_suspect *sus,
                        size_t n, long long seq);

/* One "  main may be red ..." screen line per suspect, appended at *used. */
bool dlmr_screen(const struct dlmr_suspect *sus, size_t n, char *screen,
                 size_t cap, size_t *used);

#endif
