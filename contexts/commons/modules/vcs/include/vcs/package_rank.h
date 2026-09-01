/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_rank — the ZCODE Rankings (slice 9): daily / weekly / monthly /
 * all-time contributor leaderboards, a REBUILDABLE PROJECTION over the
 * slice-8 reward-history ledger (contexts/commons/modules/vcs/package_reward.*) — never a
 * second truth. The projection reads only SETTLED earned-score facts; a
 * rebuild from the durable wires reproduces it exactly.
 *
 * THE RANKING RULE (owner directive, absolute): rank EARNED ZCODE SCORE,
 * never a wallet token balance. Purchased or transferred ZCODE must never
 * move developer rankings — and structurally CANNOT here: no balance or
 * transfer record kind exists anywhere in the reward ledger, so there is
 * no balance field for this projection to read. earned_score (settled
 * score points — the ranking input), token_rewards_received (the
 * SIMULATED placeholder-token tally), and current_token_balance (always
 * zero/unavailable in the v1 simulation — balances arrive only with the
 * owner-reviewed real token, slice 14) are DISTINCT fields wherever
 * surfaced.
 *
 * PERIOD WINDOWS (exact and deterministic): a window is a range of CIVIL
 * DAY NUMBERS (days since 1970-01-01 UTC, unix_seconds / 86400 floor) —
 * UTC days, ISO-8601 weeks (Monday..Sunday; week 1 holds the year's first
 * Thursday), and calendar months. Window arithmetic is PURE: no
 * wall-clock, no libc time — the caller passes "today" as a civil day
 * number, so the same ledger + the same today always yields the same
 * leaderboard. ALL_TIME is the unbounded window.
 *
 * CATEGORIES (owner directive, frozen order — it appears in typed JSON):
 * overall contribution, new packages, package improvements, bugs fixed,
 * tests added, security fixes, independent reviews, reproducible builds,
 * maintenance, verified bytes served, distinct package users. The last
 * two need P2P facts that do not exist until slices 11-12: they are in
 * the schema, vcs_rank_category_available() names them UNAVAILABLE, and
 * they report zero honestly — no fake data, ever.
 *
 * TIE-BREAK (deterministic): points descending, then contributor pubkey
 * ascending (lexicographic over the 33 compressed bytes). Ranks are
 * strict 1..N — a tie in points is always resolved by the key, never by
 * input order.
 *
 * This layer computes; it has no filesystem, network, wall-clock, or
 * wallet authority. The ledger read goes through the public
 * vcs_reward_ledger_fact_at() accessor; the pure core
 * (vcs_rank_projection_from_facts) takes its facts explicitly so the
 * window/category/tie-break logic is testable without a store. */

#ifndef ZCL_VCS_PACKAGE_RANK_H
#define ZCL_VCS_PACKAGE_RANK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vcs/package_reward.h"

/* ── bounds (frozen) ────────────────────────────────────────────────── */

#define VCS_RANK_MAX_CONTRIBUTORS 4096u /* distinct keys per projection */
#define VCS_RANK_MAX_INPUT_FACTS 65536u /* facts per projection call */
#define VCS_RANK_MAX_PAGE_ROWS 32u      /* leaderboard page cap */

/* ── periods ────────────────────────────────────────────────────────── */

/* The enum order is frozen: it appears in typed JSON. */
enum vcs_rank_period {
    VCS_RANK_PERIOD_DAILY = 0, /* one UTC day */
    VCS_RANK_PERIOD_WEEKLY,    /* the ISO-8601 week (Mon..Sun) */
    VCS_RANK_PERIOD_MONTHLY,   /* the calendar month */
    VCS_RANK_PERIOD_ALL_TIME,  /* unbounded */
};

const char *vcs_rank_period_string(enum vcs_rank_period period);

/* ── categories ─────────────────────────────────────────────────────── */

/* The owner-directive ranking categories. The enum order is frozen: it
 * appears in typed JSON and in per-row breakdown objects. */
enum vcs_rank_category {
    VCS_RANK_CATEGORY_OVERALL = 0, /* sum over every available category */
    VCS_RANK_CATEGORY_NEW_PACKAGES,
    VCS_RANK_CATEGORY_PACKAGE_IMPROVEMENTS,
    VCS_RANK_CATEGORY_BUGS_FIXED,
    VCS_RANK_CATEGORY_TESTS_ADDED,
    VCS_RANK_CATEGORY_SECURITY_FIXES,
    VCS_RANK_CATEGORY_INDEPENDENT_REVIEWS,
    VCS_RANK_CATEGORY_REPRODUCIBLE_BUILDS,
    VCS_RANK_CATEGORY_MAINTENANCE,
    VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED, /* UNAVAILABLE: slice 11-12
                                                P2P fact — always zero */
    VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS,/* UNAVAILABLE: slice 11-12
                                                P2P fact — always zero */
    VCS_RANK_CATEGORY_COUNT
};

const char *vcs_rank_category_string(enum vcs_rank_category category);

/* Parse a category string ("overall", "security-fixes", ...). False on
 * an unknown name (no logging — an input-validation no). */
bool vcs_rank_category_from_string(const char *name,
                                   enum vcs_rank_category *out);

/* True when the category has a fact source in v1. The two P2P-service
 * categories are UNAVAILABLE until slices 11-12: their rows are honestly
 * zero and surfaces must say so. */
bool vcs_rank_category_available(enum vcs_rank_category category);

/* The ranking category a settled reward-ledger category feeds
 * (new-package → new-packages, package-update → package-improvements,
 * bug-fix-with-regression-test → bugs-fixed, test-contribution →
 * tests-added, security-fix → security-fixes, independent-review →
 * independent-reviews, independent-build-reproduction →
 * reproducible-builds, maintenance-90-day → maintenance). Out-of-range
 * input yields VCS_RANK_CATEGORY_COUNT (an invalid marker — never
 * silently folded into a real category). */
enum vcs_rank_category vcs_rank_category_from_reward(
    enum vcs_reward_category category);

/* ── pure window arithmetic (no wall-clock, no libc time) ───────────── */

/* The civil day number of a unix timestamp (floor division — a negative
 * pre-epoch timestamp rounds DOWN, so 1969-12-31 23:59:59 is day -1). */
int64_t vcs_rank_day_from_unix(int64_t unix_seconds);

/* Civil conversions (proleptic Gregorian; Howard Hinnant's algorithms,
 * exact over the full int64 day range). */
int64_t vcs_rank_day_from_civil(int64_t year, unsigned month,
                                unsigned day_of_month);
void vcs_rank_civil_from_day(int64_t day, int64_t *year_out,
                             unsigned *month_out, unsigned *day_out);

/* ISO-8601 weekday of a civil day: 1 = Monday .. 7 = Sunday. */
unsigned vcs_rank_iso_weekday(int64_t day);

/* The ISO-8601 week date of a civil day (week 1 holds the year's first
 * Thursday; a Gregorian year boundary can sit mid-week — 2021-01-01 is
 * ISO 2020-W53-5). */
void vcs_rank_iso_week_from_day(int64_t day, int64_t *iso_year_out,
                                unsigned *iso_week_out);

/* A period window: an inclusive range of civil day numbers plus the
 * human-meaningful descriptors of the period containing `today_day`. */
struct vcs_rank_window {
    enum vcs_rank_period period;
    bool bounded;      /* false for ALL_TIME (first/last are the int64
                          extremes and membership is always true) */
    int64_t first_day; /* inclusive */
    int64_t last_day;  /* inclusive */
    /* Descriptors (zero-filled when not meaningful for the period): */
    int64_t year;          /* DAILY/MONTHLY: the Gregorian year */
    unsigned month;        /* DAILY/MONTHLY: 1..12 */
    unsigned day_of_month; /* DAILY: 1..31 */
    int64_t iso_year;      /* WEEKLY: the ISO week-numbering year */
    unsigned iso_week;     /* WEEKLY: 1..53 */
};

/* Compute the window of `period` containing `today_day`. Pure. False
 * (logged) on a NULL out or an out-of-range period. */
bool vcs_rank_window_for(enum vcs_rank_period period, int64_t today_day,
                         struct vcs_rank_window *out);

/* Membership: an unbounded (ALL_TIME) window contains every day. */
bool vcs_rank_window_contains(const struct vcs_rank_window *window,
                              int64_t day);

/* ── the projection ─────────────────────────────────────────────────── */

struct vcs_rank_projection;

/* One input fact for the pure core: a settled earned-score record.
 * `category` must be an AVAILABLE ranking category (unavailable ones are
 * dropped, counted in facts_dropped). */
struct vcs_rank_fact_input {
    uint8_t contributor[33]; /* compressed secp256k1 pubkey */
    enum vcs_rank_category category;
    uint64_t points;
    int64_t day;
};

/* Build a projection from explicit facts (the pure core — no ledger, no
 * I/O). Facts outside the window, with an unavailable/OVERALL/out-of-
 * range category, or with zero points are dropped and counted. NULL on
 * allocation failure (logged). */
struct vcs_rank_projection *vcs_rank_projection_from_facts(
    const struct vcs_rank_fact_input *facts, size_t fact_count,
    const struct vcs_rank_window *window);

/* Build a projection over the slice-8 reward-history ledger: every
 * SETTLED fact inside the window, categories mapped by
 * vcs_rank_category_from_reward. This is the ONLY production builder —
 * the leaderboard is this projection, rebuilt on every call. NULL on
 * allocation failure (logged). */
struct vcs_rank_projection *vcs_rank_projection_build(
    const struct vcs_reward_ledger *ledger,
    const struct vcs_rank_window *window);

void vcs_rank_projection_free(struct vcs_rank_projection *p);

size_t vcs_rank_projection_contributor_count(
    const struct vcs_rank_projection *p);
size_t vcs_rank_projection_facts_used(const struct vcs_rank_projection *p);
size_t vcs_rank_projection_facts_dropped(
    const struct vcs_rank_projection *p);
/* True when distinct contributors exceeded VCS_RANK_MAX_CONTRIBUTORS and
 * the tail was dropped (bounded; under-reporting is the safe direction). */
bool vcs_rank_projection_truncated(const struct vcs_rank_projection *p);

/* One ranked row. `rank` is strict 1..N by (points desc, contributor
 * asc). earned_score and token_rewards_received are SEPARATE facts (the
 * v1 simulation settles 1 point = 1 simulated placeholder ZCODE; neither
 * is a balance). category_points is the full per-category breakdown —
 * the two unavailable P2P categories are always zero here. */
struct vcs_rank_entry {
    uint64_t rank;
    uint8_t contributor[33];
    uint64_t points; /* the ranked category's points (the sort key) */
    uint64_t earned_score;
    uint64_t token_rewards_received;
    uint64_t category_points[VCS_RANK_CATEGORY_COUNT];
};

/* Fill `out` (cap entries) with the top of the table for `category`:
 * every contributor with >0 points in that category, ranked 1..N.
 * Returns the TOTAL ranked count (may exceed cap — page with it).
 * Contributors tie ONLY on points; the pubkey order resolves every tie,
 * so the table is a total order. `category` OVERALL ranks earned_score;
 * an unavailable category ranks nobody (returns 0). */
size_t vcs_rank_table(const struct vcs_rank_projection *p,
                      enum vcs_rank_category category,
                      struct vcs_rank_entry *out, size_t cap);

/* The rank of one contributor in `category`. False when the contributor
 * has no points in that category (unranked — not an error). */
bool vcs_rank_contributor(const struct vcs_rank_projection *p,
                          enum vcs_rank_category category,
                          const uint8_t contributor[33],
                          struct vcs_rank_entry *out);

#endif /* ZCL_VCS_PACKAGE_RANK_H */
