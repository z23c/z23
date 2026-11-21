/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: tell the author of a failed proof when the failing test group or
 *          lint gate is probably main itself, not their change. Read-only
 *          and advisory: derived at read time from the outcomes ledger rows
 *          the status reader already streams, with no state of its own.
 *
 * RULE. A failure key is one test group plus the place it failed (the first
 * line of the row's detail, minus the log path), or one lint gate plus the
 * site its verdict names (a source file, else the named failing check or
 * metric). A lint row whose detail names no site (an old timing-only row, a
 * bare "FAIL check-x 40 ms (rc=1)") has no key and never raises the signal:
 * replaying the real ledger showed gate name alone flags unrelated authors
 * who each broke the same gate in their own change. A key is suspect when
 * at least DLMR_K distinct candidates (distinct worktree) failed it in a
 * chain whose neighbours are at most DLMR_GAP outcome rows apart, the newest
 * failure is itself within DLMR_GAP rows of the end of the ledger, and no
 * landed row follows that newest failure. A landed row after the newest
 * failure may be the repair, so it clears the suspicion; the failed rows
 * then keep a "was suspect" marking (main_red_was_suspect) until
 * DLMR_AFTER outcome rows have passed since that landing, so the author
 * reading their own row after the clearing landing still sees it. The marking
 * is not a main_red entry and says only that a landing followed. The rule
 * never blocks, reorders or refuses a submission, and it is a hint: two
 * authors who both break the same gate at the same site in their own change
 * are indistinguishable from a red main in the ledger. */

#ifndef ZCL_NATIVE_DEV_LAND_MAIN_RED_H
#define ZCL_NATIVE_DEV_LAND_MAIN_RED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json/json.h"

#define DLMR_WINDOW 200u
#define DLMR_K 2u
#define DLMR_GAP 40u
#define DLMR_AFTER 40u
#define DLMR_GROUP_MAX 72u
#define DLMR_ROWS_MAX 8u
#define DLMR_SUSPECTS_MAX 8u

struct dlmr_entry {
    long long seq;
    size_t pos; /* index of the row among every row folded in */
    uint64_t candidate;
    uint64_t site; /* where it failed; 0 for a lint row naming no site */
    uint64_t tip;  /* hash of the row's tip */
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
    uint64_t tips[DLMR_ROWS_MAX];  /* tip hash of each kept row */
    size_t nrows;                  /* kept in rows[] */
    size_t total;                  /* failing rows in the chain */
    long long first_seq;
    bool cleared; /* a landing followed: only a "was suspect" marking */
};

/* Fold one outcome row in, in file order. Rows that are neither landed nor a
 * failure naming a keyed group still advance the row count. */
void dlmr_note(struct dlmr_window *w, long long seq, const char *state,
               const char *dimension, const char *worktree, const char *tip,
               const char *detail);

/* The suspect keys, ordered by their newest failure; returns how many.
 * Entries with cleared set are "was suspect" markings, not current signals. */
size_t dlmr_suspects(const struct dlmr_window *w, struct dlmr_suspect *out,
                     size_t cap);

/* "main may be red for <group>: rows 3279, 3284 failed it; check main before
 * resubmitting", or for a cleared suspect "main may have been red for
 * <group>: ...; a landing followed, check whether it repaired main before
 * resubmitting". Returns the length written, 0 when it does not fit. */
size_t dlmr_line(const struct dlmr_suspect *s, char *out, size_t cap);

/* The hint for one failed row: the line of the current suspect that lists
 * the row (seq and tip must both match), or "" when the row is not on one. */
void dlmr_row_hint(const struct dlmr_suspect *sus, size_t n, long long seq,
                   const char *tip, char *out, size_t cap);

/* The same for a cleared suspect: the "was suspect" line, or "". */
void dlmr_row_was_suspect(const struct dlmr_suspect *sus, size_t n,
                          long long seq, const char *tip, char *out,
                          size_t cap);

/* The group a failed row names; false and "" when it names none. */
bool dlmr_group_of(const char *dimension, const char *detail, char *out,
                   size_t cap);

/* The site a lint verdict names, hashed; 0 when the detail names none. */
uint64_t dlmr_lint_site(const char *detail);

/* Push the "main_red" array of current suspects (empty when nothing is
 * suspect) onto the status reply's data object. */
bool dlmr_push_status(struct json_value *data, const struct dlmr_suspect *sus,
                      size_t n);

/* Push "main_red_hint" (current) or "main_red_was_suspect" (cleared) onto one
 * outcome item when its row is on a suspect key; pushes nothing otherwise.
 * False only when the push itself fails. */
bool dlmr_push_row_hint(struct json_value *item, const struct dlmr_suspect *sus,
                        size_t n, long long seq, const char *tip);

/* One "  main may be red ..." screen line per current suspect, appended at
 * *used. */
bool dlmr_screen(const struct dlmr_suspect *sus, size_t n, char *screen,
                 size_t cap, size_t *used);

#endif
