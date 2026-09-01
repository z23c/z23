/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the slice-9 `zcode leaderboard` leaves — the ZCODE
 * Rankings over the SIMULATED reward ledger:
 *
 *   zcode leaderboard daily    ranked contributors for the UTC day
 *   zcode leaderboard weekly   ranked contributors for the ISO-8601 week
 *   zcode leaderboard monthly  ranked contributors for the calendar month
 *   zcode leaderboard all      the all-time table
 *
 * THE RANKING RULE (owner directive, absolute): rank EARNED ZCODE SCORE,
 * never a wallet token balance. There is no balance or transfer record
 * kind anywhere in the slice-8 reward ledger, so purchased or transferred
 * ZCODE structurally cannot appear here — the projection reads SETTLED
 * earned-score facts only. Rows keep the facts separate: earned_score
 * (the ranking input), token_rewards_received (the SIMULATED
 * placeholder-token tally), and current_token_balance (always
 * "unavailable" in v1 — balances arrive with the owner-reviewed real
 * token, slice 14).
 *
 * The leaderboard is a REBUILDABLE PROJECTION (contexts/commons/modules/vcs/package_rank.*)
 * over the durable reward-history ledger under <datadir>/zcode/rewards —
 * the ledger is replayed and the projection rebuilt on every call, never
 * a second truth. The window is shown explicitly (first/last civil day
 * plus the period descriptors); the caller passes "today" via `day`
 * (a civil day number — the window arithmetic itself is pure, no
 * wall-clock; only an omitted `day` defaults to the host clock).
 *
 * Categories (owner directive): overall, new-packages,
 * package-improvements, bugs-fixed, tests-added, security-fixes,
 * independent-reviews, reproducible-builds, maintenance are ranked from
 * the ledger; verified-bytes-served and distinct-package-users are named
 * UNAVAILABLE until the slices 11-12 P2P facts exist — they report zero
 * honestly, never fake data. */

#include "base/hex.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/package_rank.h"
#include "vcs/package_reward.h"

#include <stdio.h>
#include <string.h>

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zl_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zl_datadir(const struct zcl_command_request *request)
{
    const char *dd = zl_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static void zl_push_window(struct json_value *obj,
                           const struct vcs_rank_window *w)
{
    struct json_value jw;
    json_init(&jw);
    json_set_object(&jw);
    (void)json_push_kv_str(&jw, "period", vcs_rank_period_string(w->period));
    (void)json_push_kv_bool(&jw, "bounded", w->bounded);
    if (w->bounded) {
        (void)json_push_kv_int(&jw, "first_day", w->first_day);
        (void)json_push_kv_int(&jw, "last_day", w->last_day);
        (void)json_push_kv_int(&jw, "days",
                               w->last_day - w->first_day + 1);
    }
    switch (w->period) {
    case VCS_RANK_PERIOD_DAILY:
        (void)json_push_kv_int(&jw, "year", w->year);
        (void)json_push_kv_int(&jw, "month", (int64_t)w->month);
        (void)json_push_kv_int(&jw, "day_of_month",
                               (int64_t)w->day_of_month);
        break;
    case VCS_RANK_PERIOD_WEEKLY:
        (void)json_push_kv_int(&jw, "iso_year", w->iso_year);
        (void)json_push_kv_int(&jw, "iso_week", (int64_t)w->iso_week);
        break;
    case VCS_RANK_PERIOD_MONTHLY:
        (void)json_push_kv_int(&jw, "year", w->year);
        (void)json_push_kv_int(&jw, "month", (int64_t)w->month);
        break;
    case VCS_RANK_PERIOD_ALL_TIME:
        break;
    }
    (void)json_push_kv_str(
        &jw, "arithmetic",
        "windows are inclusive civil-day ranges (days since 1970-01-01 "
        "UTC): UTC days, ISO-8601 weeks (Mon..Sun), calendar months; "
        "pure — the caller passes today");
    (void)json_push_kv(obj, "window", &jw);
    json_free(&jw);
}

static void zl_push_unavailable(struct json_value *obj)
{
    struct json_value ua;
    json_init(&ua);
    json_set_array(&ua);
    for (size_t i = 0; i < VCS_RANK_CATEGORY_COUNT; i++) {
        enum vcs_rank_category c = (enum vcs_rank_category)i;
        if (vcs_rank_category_available(c))
            continue;
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "category",
                               vcs_rank_category_string(c));
        (void)json_push_kv_bool(&row, "available", false);
        (void)json_push_kv_str(&row, "reason",
                               "P2P service facts arrive with slices "
                               "11-12; honestly zero until then — never "
                               "faked");
        (void)json_push_back(&ua, &row);
        json_free(&row);
    }
    (void)json_push_kv(obj, "unavailable_categories", &ua);
    json_free(&ua);
}

/* The shared handler: rank one period's window. */
static void zl_leaderboard(const struct zcl_command_request *request,
                           struct zcl_command_reply *reply,
                           enum vcs_rank_period period, const char *command)
{
    const char *datadir = zl_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return;
    }
    char zcode_dir[4400];
    int zn = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (zn < 0 || (size_t)zn >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return;
    }

    enum vcs_rank_category category = VCS_RANK_CATEGORY_OVERALL;
    const char *cat_name = zl_input_str(request->input, "category");
    if (cat_name && cat_name[0] &&
        !vcs_rank_category_from_string(cat_name, &category)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_CATEGORY",
                               "normalize", false, false,
                               "unknown ranking category (overall, "
                               "new-packages, package-improvements, "
                               "bugs-fixed, tests-added, security-fixes, "
                               "independent-reviews, reproducible-builds, "
                               "maintenance, verified-bytes-served, "
                               "distinct-package-users)",
                               cat_name);
        return;
    }

    /* "Today": explicit civil `day` when given (pure window arithmetic);
     * the host clock only when omitted. */
    int64_t today = 0;
    const struct json_value *dv = json_get(request->input, "day");
    if (dv)
        today = json_get_int(dv);
    else
        today = vcs_rank_day_from_unix(platform_time_wall_unix());

    struct vcs_rank_window window;
    if (!vcs_rank_window_for(period, today, &window)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "WINDOW",
                               "execute", false, false,
                               "the period window could not be computed",
                               command);
        return;
    }

    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    if (!ledger) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "LEDGER_LOAD",
                               "execute", false, false,
                               "the reward ledger could not be replayed",
                               zcode_dir);
        return;
    }
    struct vcs_rank_projection *proj =
        vcs_rank_projection_build(ledger, &window);
    vcs_reward_ledger_free(ledger);
    if (!proj) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "PROJECTION",
                               "execute", false, false,
                               "the rankings projection could not be built",
                               zcode_dir);
        return;
    }

    bool category_available = vcs_rank_category_available(category);
    size_t total = 0;
    struct vcs_rank_entry entries[VCS_RANK_MAX_PAGE_ROWS];
    if (category_available)
        total = vcs_rank_table(proj, category, entries,
                               VCS_RANK_MAX_PAGE_ROWS);

    /* Page bounds: offset shifts into the table beyond the first page by
     * re-running the bounded sort with a wider cap. */
    size_t offset = 0;
    const struct json_value *ov = json_get(request->input, "offset");
    if (ov && json_get_int(ov) > 0)
        offset = (size_t)json_get_int(ov);
    size_t limit = 16;
    const struct json_value *lv = json_get(request->input, "limit");
    if (lv && json_get_int(lv) > 0)
        limit = (size_t)json_get_int(lv);
    if (limit > VCS_RANK_MAX_PAGE_ROWS)
        limit = VCS_RANK_MAX_PAGE_ROWS;

    struct vcs_rank_entry *page = entries;
    size_t page_count = total < VCS_RANK_MAX_PAGE_ROWS
        ? total : VCS_RANK_MAX_PAGE_ROWS;
    struct vcs_rank_entry *wide = NULL;
    if (offset > 0 && category_available && offset < total) {
        /* Re-rank with a cap covering offset + limit (bounded by the
         * projection's contributor bound). */
        size_t cap = offset + limit;
        if (cap > VCS_RANK_MAX_CONTRIBUTORS)
            cap = VCS_RANK_MAX_CONTRIBUTORS;
        wide = zcl_malloc(cap * sizeof(*wide), "zl_leaderboard_page");
        if (!wide) {
            vcs_rank_projection_free(proj);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                                   "execute", false, false,
                                   "leaderboard page buffer", command);
            return;
        }
        (void)vcs_rank_table(proj, category, wide, cap);
        page = wide;
        page_count = total < cap ? total : cap;
    }

    size_t rendered = 0;
    if (offset < page_count) {
        rendered = page_count - offset;
        if (rendered > limit)
            rendered = limit;
    }

    bool breakdown = false;
    const struct json_value *bv = json_get(request->input, "breakdown");
    if (bv)
        breakdown = json_get_bool(bv);

    (void)json_push_kv_str(&reply->data, "period",
                           vcs_rank_period_string(period));
    zl_push_window(&reply->data, &window);
    (void)json_push_kv_str(&reply->data, "category",
                           vcs_rank_category_string(category));
    (void)json_push_kv_bool(&reply->data, "category_available",
                            category_available);
    if (!category_available)
        (void)json_push_kv_str(
            &reply->data, "category_note",
            "this category's facts are P2P service credit (slices 11-12); "
            "it ranks nobody and reports zero honestly in v1");

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < rendered; i++) {
        const struct vcs_rank_entry *e = &page[offset + i];
        char pub_hex[67];
        zcl_hex_encode(e->contributor, 33, pub_hex);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_int(&row, "rank", (int64_t)e->rank);
        (void)json_push_kv_str(&row, "contributor", pub_hex);
        (void)json_push_kv_int(&row, "points", (int64_t)e->points);
        (void)json_push_kv_int(&row, "earned_score",
                               (int64_t)e->earned_score);
        (void)json_push_kv_int(&row, "token_rewards_received",
                               (int64_t)e->token_rewards_received);
        if (breakdown) {
            struct json_value bd;
            json_init(&bd);
            json_set_object(&bd);
            for (size_t c = 0; c < VCS_RANK_CATEGORY_COUNT; c++) {
                enum vcs_rank_category cc = (enum vcs_rank_category)c;
                if (cc == VCS_RANK_CATEGORY_OVERALL)
                    continue;
                (void)json_push_kv_int(&bd, vcs_rank_category_string(cc),
                                       (int64_t)e->category_points[c]);
            }
            (void)json_push_kv(&row, "category_breakdown", &bd);
            json_free(&bd);
        }
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    free(wide);

    (void)json_push_kv_int(&reply->data, "total_ranked", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_int(&reply->data, "offset", (int64_t)offset);
    (void)json_push_kv_bool(&reply->data, "items_truncated",
                            offset + rendered < total);
    (void)json_push_kv_int(
        &reply->data, "contributors_in_window",
        (int64_t)vcs_rank_projection_contributor_count(proj));
    (void)json_push_kv_int(&reply->data, "facts_used",
                           (int64_t)vcs_rank_projection_facts_used(proj));
    (void)json_push_kv_int(
        &reply->data, "facts_dropped",
        (int64_t)vcs_rank_projection_facts_dropped(proj));
    (void)json_push_kv_bool(&reply->data, "projection_truncated",
                            vcs_rank_projection_truncated(proj));
    zl_push_unavailable(&reply->data);
    (void)json_push_kv_str(&reply->data, "current_token_balance",
                           "unavailable");
    (void)json_push_kv_str(
        &reply->data, "ranking_note",
        "rank is EARNED ZCODE SCORE only: the projection reads settled "
        "earned-score facts from the reward-history ledger (rebuilt on "
        "every call, never a second truth); no balance or transfer record "
        "kind exists, so purchased/transferred tokens cannot move "
        "rankings; token_rewards_received is the SIMULATED "
        "placeholder-token tally — a separate fact; current_token_balance "
        "is unavailable in v1 (balances arrive with the real token, "
        "slice 14)");
    vcs_rank_projection_free(proj);
}

void zcl_native_handle_zcode_leaderboard_daily(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    zl_leaderboard(request, reply, VCS_RANK_PERIOD_DAILY,
                   "zcode.leaderboard.daily");
}

void zcl_native_handle_zcode_leaderboard_weekly(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    zl_leaderboard(request, reply, VCS_RANK_PERIOD_WEEKLY,
                   "zcode.leaderboard.weekly");
}

void zcl_native_handle_zcode_leaderboard_monthly(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    zl_leaderboard(request, reply, VCS_RANK_PERIOD_MONTHLY,
                   "zcode.leaderboard.monthly");
}

void zcl_native_handle_zcode_leaderboard_all(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    zl_leaderboard(request, reply, VCS_RANK_PERIOD_ALL_TIME,
                   "zcode.leaderboard.all");
}
