/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the red-main circuit breaker of the land driver. When main itself
 *          is red on one test group, rows whose proof fails only that group
 *          are parked instead of failed, and a train failing it proves its
 *          members alone instead of bisecting; a proof that passes the
 *          group, or evidence that ages out, requeues every parked row
 *          for a fresh full proof.
 *
 * RULE. A settled proof failure names test group G (its first evidence line
 * reads "test G: FAIL ...", and G is the only group its test log lists as
 * failed). The breaker trips on that failure when the
 * outcomes ledger already holds K (ZCL_LAND_RED_MAIN_K, default 2)
 * failed rows naming G, recorded within the age bound
 * (ZCL_LAND_RED_MAIN_AGE_S, default 7200 s) and after the last landing that
 * cleared G, whose lanes (worktree plus note) differ from each other and
 * from the failing row, and whose changed-file sets are disjoint from each
 * other and from the failing row's. A lane failing its own change again, or
 * two rows touching the same file, never counts. A failure on G also parks
 * while G is already red (a parked row on G was parked within the age
 * bound) or when the row itself was parked on G before and released by an
 * age-out within ZCL_LAND_RED_MAIN_MAX_S (default 43200 s) of the episode's
 * first evidence. A row whose own change touches tests/harness/src/G.c (a
 * likely fix) is never parked: it fails or bisects as before.
 *
 * STATE. One authority each: the ledger holds the trip evidence and the
 * clearing landing ("red_main":"cleared:..." on a landed row); the queue
 * holds the parked rows (state "queued", phase "parked",
 * "red_main":"parked:G:<since seq>:<since unix>:<parked unix>"). Status,
 * the alert and every release are derived from those rows; there is no
 * other flag.
 *
 * CLEAR. A proof that passes and whose test log shows a group passing clears
 * it, whether or not rows are parked on it: every group the queue parks or
 * remembers and every group with a failure in the age window is checked, and
 * the passing row carries one cleared marker ("cleared:G1+G2:...") to its
 * landing, so the evidence before that landing never counts toward a new trip
 * (a lane that breaks G itself after a fix landed fails normally). A fix
 * that skips or deletes G runs no proof of it and clears nothing: the
 * episode ages out. Every row parked on or remembering a cleared group
 * returns to the queue (phase "rebase") to rebase onto main and
 * take a complete fresh proof; a rebase conflict is the normal conflict
 * state. When the newest parked row on G is older than the age bound, or
 * the episode began more than the maximum ago, the parked rows are
 * released the same way, so a stale episode cannot park rows forever.
 *
 * NO WAIVER. Parking only defers a row; it is never a verdict and never a
 * landing. Every row still lands only after its own full green proof, no
 * group is skipped or excused, and consensus and custody groups are treated
 * exactly like every other group: the breaker can only delay a row, never
 * admit one. ZCL_LAND_RED_MAIN=0 turns the breaker off. */

#ifndef ZCL_NATIVE_DEV_LAND_RED_BREAKER_H
#define ZCL_NATIVE_DEV_LAND_RED_BREAKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "command/native_dev_land_internal.h"
#include "json/json.h"

#define DLRB_GROUP_MAX 72u
#define DLRB_FILES_MAX 128u
#define DLRB_CANDS 16u
#define DLRB_EPISODES 8u
/* Distinct recently failed groups one pass can check; beyond it the pass is
 * conservative (see dlrb_groups.overflow). */
#define DLRB_RECENT_MAX 64u
#define DLRB_PHASE "parked"

struct dlrb_policy {
    bool enabled;
    unsigned k;
    long long age_s;
    long long max_s;
};

/* The parsed "red_main" row field. */
struct dlrb_mark {
    bool cleared;
    char group[DLRB_GROUP_MAX];
    long long since;    /* seq of the episode's first evidence row */
    long long since_at; /* unix time of that evidence */
    long long at;       /* unix time this row was parked or cleared */
};

/* A changed-file set as path hashes; known is false when it overflowed or
 * could not be read, and an unknown set is never disjoint from anything. */
struct dlrb_files {
    uint64_t h[DLRB_FILES_MAX];
    size_t n;
    bool known;
};

struct dlrb_fail {
    long long seq;
    long long at;
    uint64_t lane;
    struct dlrb_files files;
};

struct dlrb_episode {
    char group[DLRB_GROUP_MAX];
    long long since;
    long long since_at;
    long long newest_at;
    size_t parked;
};

/* ── pure policy ─────────────────────────────────────────────────────── */

void dlrb_policy_read(struct dlrb_policy *p);
long long dlrb_now(void);
/* "" is a valid absent field; anything else must parse. */
bool dlrb_field_ok(const char *field);
bool dlrb_mark_parse(const char *field, struct dlrb_mark *m);
bool dlrb_mark_format(const struct dlrb_mark *m, char *out, size_t cap);
uint64_t dlrb_lane(const char *worktree, const char *note);
void dlrb_files_add(struct dlrb_files *f, const char *path, size_t len);
/* Newline-separated paths; an empty list is a known empty set. */
void dlrb_files_parse(struct dlrb_files *f, const char *lines);
bool dlrb_files_has(const struct dlrb_files *f, const char *path);
bool dlrb_files_disjoint(const struct dlrb_files *a,
                         const struct dlrb_files *b);
/* Newest-first candidates on the same group; the qualifying ones chosen
 * greedily, at most k. Returns how many qualified; *since / *since_at name
 * the oldest chosen. */
size_t dlrb_trip_pick(const struct dlrb_fail *cands, size_t n,
                      const struct dlrb_fail *cur, unsigned k,
                      long long *since, long long *since_at);
/* Is `group` the only failed group of the settled attempt's retained test
 * log (row->failed_proof root and attempt)? False when unreadable. */
/* The distinct groups a landing pass may have cleared. */
struct dlrb_groups {
    char g[DLRB_RECENT_MAX][DLRB_GROUP_MAX];
    size_t n;
    bool overflow; /* a group did not fit: treat the set as not reset */
};
void dlrb_groups_add(struct dlrb_groups *gs, const char *group);
/* Append to a '+'-joined list; false (list unchanged) when it does not fit. */
bool dlrb_list_add(char *list, size_t cap, const char *group);
bool dlrb_failed_only(const struct dl_row *row, const char *group);
/* Does a retained attempt of the pair (local, base) under worktree `wt`
 * show `group` passing in its test log? */
bool dlrb_attempts_show(const char *wt, const char *local, const char *base,
                        const char *group);
/* Does the test log at `path` name `group` as its only failed group (the
 * runner's last "Failed groups:" list)? False when unreadable. */
bool dlrb_log_only_group(const char *path, const char *group);
bool dlrb_is_parked(const struct dl_row *r);
/* One entry per group with parked rows. */
size_t dlrb_episodes(const struct dl_row *rows, size_t n,
                     struct dlrb_episode *out, size_t cap);
bool dlrb_episode_live(const struct dlrb_episode *e,
                       const struct dlrb_policy *p, long long now);

/* ── driver glue ─────────────────────────────────────────────────────── */

/* Append ,"red_main":"..." to an encoded row when the field is set. */
size_t dlrb_append(const struct dl_row *r, char *out, size_t cap,
                   size_t size);
/* A settled failure naming `group` (may be ""): true when the breaker
 * parked the row (and its train) and wrote the step reply. */
bool dlrb_on_failure(const struct dl_dirs *d, struct dl_row *row,
                     const char *group, const char *detail,
                     struct zcl_command_reply *reply);
/* A passed proof: clears every group its test log shows passing. */
void dlrb_on_pass(const struct dl_dirs *d, struct dl_row *row);
/* Release the parked rows of every episode that is no longer live. */
void dlrb_tend(const struct dl_dirs *d);
bool dlrb_push_status(struct json_value *data, const struct dl_row *rows,
                      size_t n);
bool dlrb_screen(const struct dl_row *rows, size_t n, char *screen,
                 size_t cap, size_t *used);
#if defined(ZCL_TESTING)
/* Test stub "red": FAIL on ZCL_LAND_PROOF_STUB_RED_GROUP unless the pair's
 * tree holds red-fix (passes, running the group) or red-skip (passes
 * without running it); red-break in the tree fails it even so. 1 pass, 2 fail,
 * 0 not this stub. */
int dlrb_stub_read(const char *stub, const char *wt, const char *local,
                   char *dimension, size_t dim_cap, char *detail,
                   size_t cap);
#endif

#endif
