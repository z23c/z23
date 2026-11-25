/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the compact outcome projection of `dev land status`. An agent polls
 *          status many times per landing, so the default reply carries only the
 *          newest DLSC_ROWS outcome rows, each reduced to what decides the next
 *          step. `json:true` keeps every machine consumer on the full rows. */

#ifndef ZCL_NATIVE_DEV_LAND_STATUS_COMPACT_H
#define ZCL_NATIVE_DEV_LAND_STATUS_COMPACT_H

#include <stdbool.h>
#include <stddef.h>

#include "command/native_dev_land_internal.h"
#include "json/json.h"

#define DLSC_ROWS 3u
#define DLSC_DETAIL_MAX 200u

/* Index of the first of `n` oldest-first outcome rows the compact form keeps. */
size_t dlsc_first(size_t n);

/* Append one compact row: seq, state, tip(12), attempt; tip_pushed(12) when
 * landed; dimension, detail (capped, never split mid-character) and log_path
 * for every other state. */
bool dlsc_push_row(struct json_value *arr, const struct dl_row *r);

/* Add outcomes_omitted (the rows the full form would show beyond the kept
 * ones) and outcomes_full (the command that returns them). */
bool dlsc_push_notes(struct json_value *data, size_t nrows);

/* "Did MY submission land?" The caller names its row by seq (what submit
 * returned), else by tip (full or >= 12 hex prefix of the SUBMITTED commit),
 * else by note. The lookup spans the live queue and the whole outcome ledger,
 * so the answer never depends on how many rows landed since. */
enum dlsc_where { DLSC_UNKNOWN, DLSC_QUEUED, DLSC_IN_FLIGHT, DLSC_OUTCOME };

struct dlsc_hit {
    bool active;
    long long seq;      /* by-seq lookup, 0 when absent */
    char tip[65];       /* by-tip lookup prefix, "" when absent */
    char note[DL_NOTE_MAX + 1];
    bool bad_tip;       /* a tip key that is not >= 12 hex characters */
    bool q_found;
    long long q_seq;
    char q_state[16];
    bool o_found;
    struct dl_row o_row;
};

/* Read seq, tip and note from the request input (all optional). */
void dlsc_hit_init(struct dlsc_hit *hit, const struct json_value *input);
/* Offer one live queue row. */
void dlsc_hit_queue(struct dlsc_hit *hit, const struct dl_row *r);
/* Offer one outcome ledger row; the newest match wins. */
void dlsc_hit_outcome(struct dlsc_hit *hit, const struct dl_row *r);
/* Where the submission is now: the newest of the queue and ledger matches. */
enum dlsc_where dlsc_hit_where(const struct dlsc_hit *hit);
/* True when outcome row `r` is the hit row that the reply lists first. */
bool dlsc_hit_is_listed(const struct dlsc_hit *hit, const struct dl_row *r);
/* Append the `mine` object {seq, where, state, hint}; no-op when inactive. */
bool dlsc_push_mine(struct json_value *data, const struct dlsc_hit *hit);
/* The brief reply for a poller that only wants the answer: replaces `data`
 * with {leaf, queued_count, in_flight {seq, phase, elapsed_s}, mine}. The
 * outcome tail, screen, steer and notes are dropped; ask without brief for
 * them. Leaves `data` untouched and returns false when it cannot encode. */
bool dlsc_brief_replace(struct json_value *data);

#endif
