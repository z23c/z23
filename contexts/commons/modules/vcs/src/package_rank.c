/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_rank — implementation of the ZCODE Rankings projection declared
 * in vcs/package_rank.h (slice 9).
 *
 * Two halves, strictly separated:
 *
 *   1. PURE WINDOW ARITHMETIC — civil day numbers, proleptic Gregorian
 *      calendar conversions (Howard Hinnant's public-domain algorithms,
 *      exact over the full int64 range, no libc time), ISO-8601 week
 *      dates. UTC days, ISO weeks (Monday start, week 1 holds the first
 *      Thursday), calendar months. No wall-clock anywhere: the caller
 *      passes "today".
 *
 *   2. THE PROJECTION — aggregate settled earned-score facts per
 *      contributor inside the window, rank by (points desc, contributor
 *      pubkey asc). A rebuildable projection over the slice-8 ledger,
 *      never a second truth: vcs_rank_projection_build() reads the ledger
 *      through vcs_reward_ledger_fact_at() and feeds the same pure core
 *      the tests drive directly.
 *
 * No balances: the input facts carry contributor + category + points +
 * day and nothing else. There is no balance or transfer record kind in
 * the ledger for this code to read even accidentally. */

#include "vcs/package_rank.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define RANK_LOG "vcs.rank"

/* ── small pure helpers ─────────────────────────────────────────────── */

/* Floor division for a positive divisor (C truncation rounds toward
 * zero; windows need floor semantics across the epoch). */
static int64_t rank_floor_div(int64_t a, int64_t b)
{
    int64_t q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0)))
        q--;
    return q;
}

/* ── periods ────────────────────────────────────────────────────────── */

const char *vcs_rank_period_string(enum vcs_rank_period period)
{
    switch (period) {
    case VCS_RANK_PERIOD_DAILY:    return "daily";
    case VCS_RANK_PERIOD_WEEKLY:   return "weekly";
    case VCS_RANK_PERIOD_MONTHLY:  return "monthly";
    case VCS_RANK_PERIOD_ALL_TIME: return "all-time";
    }
    return "unknown";
}

/* ── categories ─────────────────────────────────────────────────────── */

static const char *const k_category_names[VCS_RANK_CATEGORY_COUNT] = {
    [VCS_RANK_CATEGORY_OVERALL] = "overall",
    [VCS_RANK_CATEGORY_NEW_PACKAGES] = "new-packages",
    [VCS_RANK_CATEGORY_PACKAGE_IMPROVEMENTS] = "package-improvements",
    [VCS_RANK_CATEGORY_BUGS_FIXED] = "bugs-fixed",
    [VCS_RANK_CATEGORY_TESTS_ADDED] = "tests-added",
    [VCS_RANK_CATEGORY_SECURITY_FIXES] = "security-fixes",
    [VCS_RANK_CATEGORY_INDEPENDENT_REVIEWS] = "independent-reviews",
    [VCS_RANK_CATEGORY_REPRODUCIBLE_BUILDS] = "reproducible-builds",
    [VCS_RANK_CATEGORY_MAINTENANCE] = "maintenance",
    [VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED] = "verified-bytes-served",
    [VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS] = "distinct-package-users",
};

const char *vcs_rank_category_string(enum vcs_rank_category category)
{
    if (category < 0 || category >= VCS_RANK_CATEGORY_COUNT)
        return "unknown";
    return k_category_names[category];
}

bool vcs_rank_category_from_string(const char *name,
                                   enum vcs_rank_category *out)
{
    if (!name || !out)
        return false;
    for (size_t i = 0; i < VCS_RANK_CATEGORY_COUNT; i++) {
        if (strcmp(name, k_category_names[i]) == 0) {
            *out = (enum vcs_rank_category)i;
            return true;
        }
    }
    return false;
}

bool vcs_rank_category_available(enum vcs_rank_category category)
{
    return category >= VCS_RANK_CATEGORY_OVERALL &&
           category <= VCS_RANK_CATEGORY_MAINTENANCE;
}

enum vcs_rank_category vcs_rank_category_from_reward(
    enum vcs_reward_category category)
{
    switch (category) {
    case VCS_REWARD_CATEGORY_NEW_PACKAGE:
        return VCS_RANK_CATEGORY_NEW_PACKAGES;
    case VCS_REWARD_CATEGORY_PACKAGE_UPDATE:
        return VCS_RANK_CATEGORY_PACKAGE_IMPROVEMENTS;
    case VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION:
        return VCS_RANK_CATEGORY_BUGS_FIXED;
    case VCS_REWARD_CATEGORY_TEST_CONTRIBUTION:
        return VCS_RANK_CATEGORY_TESTS_ADDED;
    case VCS_REWARD_CATEGORY_BUILD_REPRODUCTION:
        return VCS_RANK_CATEGORY_REPRODUCIBLE_BUILDS;
    case VCS_REWARD_CATEGORY_SECURITY_FIX:
        return VCS_RANK_CATEGORY_SECURITY_FIXES;
    case VCS_REWARD_CATEGORY_MAINTENANCE_90_DAY:
        return VCS_RANK_CATEGORY_MAINTENANCE;
    case VCS_REWARD_CATEGORY_REVIEW:
        return VCS_RANK_CATEGORY_INDEPENDENT_REVIEWS;
    case VCS_REWARD_CATEGORY_COUNT:
        break;
    }
    return VCS_RANK_CATEGORY_COUNT;
}

/* ── pure window arithmetic ─────────────────────────────────────────── */

int64_t vcs_rank_day_from_unix(int64_t unix_seconds)
{
    return rank_floor_div(unix_seconds, 86400);
}

int64_t vcs_rank_day_from_civil(int64_t year, unsigned month,
                                unsigned day_of_month)
{
    int64_t y = year - (month <= 2 ? 1 : 0);
    int64_t era = rank_floor_div(y, 400);
    int64_t yoe = y - era * 400; /* [0, 399] */
    int64_t mp = ((int64_t)month + 9) % 12; /* Mar=0 .. Feb=11 */
    int64_t doy = (153 * mp + 2) / 5 + (int64_t)day_of_month - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

void vcs_rank_civil_from_day(int64_t day, int64_t *year_out,
                             unsigned *month_out, unsigned *day_out)
{
    int64_t z = day + 719468;
    int64_t era = rank_floor_div(z, 146097);
    int64_t doe = z - era * 146097; /* [0, 146096] */
    int64_t yoe =
        (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; /* [0,399] */
    int64_t y = yoe + era * 400;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100); /* [0, 365] */
    int64_t mp = (5 * doy + 2) / 153; /* [0, 11] */
    int64_t d = doy - (153 * mp + 2) / 5 + 1; /* [1, 31] */
    int64_t m = mp + (mp < 10 ? 3 : -9); /* [1, 12] */
    y += (m <= 2 ? 1 : 0);
    if (year_out)
        *year_out = y;
    if (month_out)
        *month_out = (unsigned)m;
    if (day_out)
        *day_out = (unsigned)d;
}

unsigned vcs_rank_iso_weekday(int64_t day)
{
    /* 1970-01-01 (day 0) was a Thursday (4). */
    int64_t w = (day + 3) % 7;
    if (w < 0)
        w += 7;
    return (unsigned)w + 1u;
}

void vcs_rank_iso_week_from_day(int64_t day, int64_t *iso_year_out,
                                unsigned *iso_week_out)
{
    /* The ISO week-numbering year is the Gregorian year of the week's
     * Thursday. */
    unsigned wd = vcs_rank_iso_weekday(day);
    int64_t thursday = day - ((int64_t)wd - 1) + 3;
    int64_t iso_year = 0;
    vcs_rank_civil_from_day(thursday, &iso_year, NULL, NULL);
    /* Week 1's Monday: the Monday of the week holding January 4. */
    int64_t jan4 = vcs_rank_day_from_civil(iso_year, 1, 4);
    int64_t week1_monday = jan4 - ((int64_t)vcs_rank_iso_weekday(jan4) - 1);
    if (iso_year_out)
        *iso_year_out = iso_year;
    if (iso_week_out)
        *iso_week_out = (unsigned)((day - week1_monday) / 7 + 1);
}

bool vcs_rank_window_for(enum vcs_rank_period period, int64_t today_day,
                         struct vcs_rank_window *out)
{
    if (!out)
        LOG_FAIL(RANK_LOG, "window_for: NULL out");
    memset(out, 0, sizeof(*out));
    out->period = period;
    out->bounded = true;
    switch (period) {
    case VCS_RANK_PERIOD_DAILY:
        out->first_day = today_day;
        out->last_day = today_day;
        vcs_rank_civil_from_day(today_day, &out->year, &out->month,
                                &out->day_of_month);
        return true;
    case VCS_RANK_PERIOD_WEEKLY: {
        int64_t monday =
            today_day - ((int64_t)vcs_rank_iso_weekday(today_day) - 1);
        out->first_day = monday;
        out->last_day = monday + 6;
        vcs_rank_iso_week_from_day(today_day, &out->iso_year,
                                   &out->iso_week);
        return true;
    }
    case VCS_RANK_PERIOD_MONTHLY: {
        int64_t y = 0;
        unsigned m = 0;
        vcs_rank_civil_from_day(today_day, &y, &m, NULL);
        out->year = y;
        out->month = m;
        out->first_day = vcs_rank_day_from_civil(y, m, 1);
        out->last_day =
            vcs_rank_day_from_civil(m == 12 ? y + 1 : y, m == 12 ? 1 : m + 1,
                                    1) -
            1;
        return true;
    }
    case VCS_RANK_PERIOD_ALL_TIME:
        out->bounded = false;
        out->first_day = INT64_MIN;
        out->last_day = INT64_MAX;
        return true;
    }
    LOG_FAIL(RANK_LOG, "window_for: period %d out of range", (int)period);
}

bool vcs_rank_window_contains(const struct vcs_rank_window *window,
                              int64_t day)
{
    if (!window)
        return false;
    if (!window->bounded)
        return true;
    return day >= window->first_day && day <= window->last_day;
}

/* ── the projection ─────────────────────────────────────────────────── */

struct vcs_rank_contributor {
    uint8_t contributor[33];
    uint64_t category_points[VCS_RANK_CATEGORY_COUNT];
};

struct vcs_rank_projection {
    struct vcs_rank_window window;
    struct vcs_rank_contributor *rows; /* sorted contributor-pubkey asc */
    size_t count;
    size_t facts_used;
    size_t facts_dropped;
    bool truncated;
};

/* A sortable (contributor, category, points) scratch fact. */
struct rank_sort_fact {
    uint8_t contributor[33];
    uint32_t category;
    uint64_t points;
};

static int rank_sort_fact_cmp(const void *a, const void *b)
{
    const struct rank_sort_fact *fa = a;
    const struct rank_sort_fact *fb = b;
    int c = memcmp(fa->contributor, fb->contributor, 33);
    if (c != 0)
        return c;
    if (fa->category != fb->category)
        return fa->category < fb->category ? -1 : 1;
    return 0;
}

struct vcs_rank_projection *vcs_rank_projection_from_facts(
    const struct vcs_rank_fact_input *facts, size_t fact_count,
    const struct vcs_rank_window *window)
{
    if (!window)
        LOG_NULL(RANK_LOG, "from_facts: NULL window");
    if (!facts && fact_count > 0)
        LOG_NULL(RANK_LOG, "from_facts: NULL facts with count %zu",
                 fact_count);
    struct vcs_rank_projection *p =
        zcl_calloc(1, sizeof(*p), "rank_projection");
    if (!p)
        LOG_NULL(RANK_LOG, "projection alloc");
    p->window = *window;
    if (fact_count == 0)
        return p;
    if (fact_count > VCS_RANK_MAX_INPUT_FACTS) {
        p->facts_dropped += fact_count - VCS_RANK_MAX_INPUT_FACTS;
        fact_count = VCS_RANK_MAX_INPUT_FACTS;
        p->truncated = true;
    }

    /* Filter into a sortable scratch array, then aggregate sorted runs —
     * O(n log n) with a deterministic total order. */
    struct rank_sort_fact *kept =
        zcl_malloc(fact_count * sizeof(*kept), "rank_sort_facts");
    if (!kept) {
        free(p);
        LOG_NULL(RANK_LOG, "sort facts alloc (%zu)", fact_count);
    }
    size_t kept_count = 0;
    for (size_t i = 0; i < fact_count; i++) {
        const struct vcs_rank_fact_input *f = &facts[i];
        if (f->points == 0 || !vcs_rank_window_contains(window, f->day) ||
            !vcs_rank_category_available(f->category) ||
            f->category == VCS_RANK_CATEGORY_OVERALL) {
            p->facts_dropped++;
            continue;
        }
        memcpy(kept[kept_count].contributor, f->contributor, 33);
        kept[kept_count].category = (uint32_t)f->category;
        kept[kept_count].points = f->points;
        kept_count++;
    }
    qsort(kept, kept_count, sizeof(*kept), rank_sort_fact_cmp);

    p->rows = zcl_malloc(
        (kept_count ? kept_count : 1) * sizeof(*p->rows), "rank_rows");
    if (!p->rows) {
        free(kept);
        free(p);
        LOG_NULL(RANK_LOG, "rows alloc (%zu)", kept_count);
    }
    for (size_t i = 0; i < kept_count; i++) {
        if (p->count > 0 &&
            memcmp(p->rows[p->count - 1].contributor,
                   kept[i].contributor, 33) == 0) {
            p->rows[p->count - 1].category_points[kept[i].category] +=
                kept[i].points;
            p->facts_used++;
            continue;
        }
        if (p->count == VCS_RANK_MAX_CONTRIBUTORS) {
            p->truncated = true;
            p->facts_dropped += kept_count - i;
            break;
        }
        struct vcs_rank_contributor *row = &p->rows[p->count++];
        memset(row, 0, sizeof(*row));
        memcpy(row->contributor, kept[i].contributor, 33);
        row->category_points[kept[i].category] = kept[i].points;
        p->facts_used++;
    }
    free(kept);

    /* OVERALL is the sum over the available categories. */
    for (size_t i = 0; i < p->count; i++) {
        uint64_t overall = 0;
        for (size_t c = VCS_RANK_CATEGORY_NEW_PACKAGES;
             c < VCS_RANK_CATEGORY_COUNT; c++)
            overall += p->rows[i].category_points[c];
        p->rows[i].category_points[VCS_RANK_CATEGORY_OVERALL] = overall;
    }
    return p;
}

struct vcs_rank_projection *vcs_rank_projection_build(
    const struct vcs_reward_ledger *ledger,
    const struct vcs_rank_window *window)
{
    if (!ledger)
        LOG_NULL(RANK_LOG, "build: NULL ledger");
    if (!window)
        LOG_NULL(RANK_LOG, "build: NULL window");
    size_t fact_count = vcs_reward_ledger_fact_count(ledger);
    struct vcs_rank_fact_input *inputs = NULL;
    if (fact_count > 0) {
        inputs = zcl_malloc(fact_count * sizeof(*inputs),
                            "rank_ledger_facts");
        if (!inputs)
            LOG_NULL(RANK_LOG, "ledger facts alloc (%zu)", fact_count);
    }
    for (size_t i = 0; i < fact_count; i++) {
        struct vcs_reward_fact_view view;
        if (!vcs_reward_ledger_fact_at(ledger, i, &view)) {
            free(inputs);
            LOG_NULL(RANK_LOG, "fact %zu unreadable", i);
        }
        memcpy(inputs[i].contributor, view.contributor, 33);
        inputs[i].category = vcs_rank_category_from_reward(view.category);
        inputs[i].points = view.points;
        inputs[i].day = view.day;
    }
    struct vcs_rank_projection *p =
        vcs_rank_projection_from_facts(inputs, fact_count, window);
    free(inputs);
    return p;
}

void vcs_rank_projection_free(struct vcs_rank_projection *p)
{
    if (!p)
        return;
    free(p->rows);
    free(p);
}

size_t vcs_rank_projection_contributor_count(
    const struct vcs_rank_projection *p)
{
    return p ? p->count : 0;
}

size_t vcs_rank_projection_facts_used(const struct vcs_rank_projection *p)
{
    return p ? p->facts_used : 0;
}

size_t vcs_rank_projection_facts_dropped(
    const struct vcs_rank_projection *p)
{
    return p ? p->facts_dropped : 0;
}

bool vcs_rank_projection_truncated(const struct vcs_rank_projection *p)
{
    return p ? p->truncated : true;
}

/* ── ranking ────────────────────────────────────────────────────────── */

static uint64_t rank_points_of(const struct vcs_rank_contributor *row,
                               enum vcs_rank_category category)
{
    if (category < 0 || category >= VCS_RANK_CATEGORY_COUNT)
        return 0;
    return row->category_points[category];
}

static void rank_fill_entry(const struct vcs_rank_contributor *row,
                            enum vcs_rank_category category, uint64_t rank,
                            struct vcs_rank_entry *out)
{
    memset(out, 0, sizeof(*out));
    out->rank = rank;
    memcpy(out->contributor, row->contributor, 33);
    out->points = rank_points_of(row, category);
    out->earned_score = row->category_points[VCS_RANK_CATEGORY_OVERALL];
    /* v1 simulation: 1 score point = 1 simulated placeholder ZCODE. The
     * two facts stay SEPARATE fields by owner directive; neither is a
     * balance (vcs_rank_entry carries no balance field at all). */
    out->token_rewards_received = out->earned_score;
    memcpy(out->category_points, row->category_points,
           sizeof(out->category_points));
}

/* A rankable scratch row for the table sort (points cached). */
struct rank_order {
    const struct vcs_rank_contributor *row;
    uint64_t points;
};

/* The ranking sort: points descending, contributor pubkey ascending — a
 * total order, so qsort instability can never leak into the output. */
static int rank_order_cmp(const void *a, const void *b)
{
    const struct rank_order *oa = a;
    const struct rank_order *ob = b;
    if (oa->points != ob->points)
        return oa->points > ob->points ? -1 : 1;
    return memcmp(oa->row->contributor, ob->row->contributor, 33);
}

size_t vcs_rank_table(const struct vcs_rank_projection *p,
                      enum vcs_rank_category category,
                      struct vcs_rank_entry *out, size_t cap)
{
    if (!p || category < 0 || category >= VCS_RANK_CATEGORY_COUNT)
        return 0;
    if (!vcs_rank_category_available(category))
        return 0; /* the two P2P categories rank nobody in v1 — zero,
                     honestly (their fact source is slices 11-12) */
    size_t rankable = 0;
    for (size_t i = 0; i < p->count; i++)
        if (rank_points_of(&p->rows[i], category) > 0)
            rankable++;
    if (rankable == 0 || !out || cap == 0)
        return rankable;

    struct rank_order *order =
        zcl_malloc(rankable * sizeof(*order), "rank_order");
    if (!order) {
        LOG_ERROR(RANK_LOG, "order alloc (%zu)", rankable);
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < p->count; i++) {
        uint64_t pts = rank_points_of(&p->rows[i], category);
        if (pts == 0)
            continue;
        order[n].row = &p->rows[i];
        order[n].points = pts;
        n++;
    }
    qsort(order, n, sizeof(*order), rank_order_cmp);
    size_t render = n < cap ? n : cap;
    for (size_t i = 0; i < render; i++)
        rank_fill_entry(order[i].row, category, i + 1, &out[i]);
    free(order);
    return rankable;
}

bool vcs_rank_contributor(const struct vcs_rank_projection *p,
                          enum vcs_rank_category category,
                          const uint8_t contributor[33],
                          struct vcs_rank_entry *out)
{
    if (!p || !contributor || category < 0 ||
        category >= VCS_RANK_CATEGORY_COUNT)
        return false;
    if (!vcs_rank_category_available(category))
        return false;
    const struct vcs_rank_contributor *self = NULL;
    for (size_t i = 0; i < p->count; i++) {
        if (memcmp(p->rows[i].contributor, contributor, 33) == 0) {
            self = &p->rows[i];
            break;
        }
    }
    if (!self || rank_points_of(self, category) == 0)
        return false;
    /* Rank = 1 + the number of rows strictly ahead under the total order
     * (more points, or equal points with a smaller pubkey). */
    uint64_t ahead = 0;
    uint64_t my = rank_points_of(self, category);
    for (size_t i = 0; i < p->count; i++) {
        const struct vcs_rank_contributor *row = &p->rows[i];
        if (memcmp(row->contributor, contributor, 33) == 0)
            continue;
        uint64_t pts = rank_points_of(row, category);
        if (pts > my ||
            (pts == my && pts > 0 &&
             memcmp(row->contributor, contributor, 33) < 0))
            ahead++;
    }
    if (out)
        rank_fill_entry(self, category, ahead + 1, out);
    return true;
}
