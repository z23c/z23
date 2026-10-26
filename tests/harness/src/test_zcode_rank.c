/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_rank — the ZCODE Rankings (slice 9:
 * contexts/commons/modules/vcs/package_rank.*, the zcode leaderboard daily/weekly/monthly/all
 * handlers in tools/command/native_zcode_leaderboard_command.c, and the
 * contributor.show rankings integration).
 *
 * Coverage (adversarial first):
 *   1. Window arithmetic edges: 23:59:59 vs 00:00:00 (unix 86399 vs
 *      86400, and negative pre-epoch timestamps), civil roundtrips
 *      across the epoch, ISO weeks crossing the Gregorian year
 *      (2019-12-30 is ISO 2020-W01; 2021-01-01 is ISO 2020-W53), month
 *      lengths (leap February 29, common February 28, 30/31-day months,
 *      the December→January boundary), the Monday..Sunday weekly window.
 *   2. Transferred/purchased tokens cannot appear: a fake "transfer"
 *      fact wire (a record kind the ledger has NO representation for)
 *      injected into the durable ledger dir is rejected as corrupt on
 *      replay and the rankings are byte-identical to the clean ledger's;
 *      rows carry earned_score / token_rewards_received as separate
 *      facts and no balance field exists anywhere.
 *   3. Projection determinism: tie-break is points desc then contributor
 *      pubkey asc (a total order); a rebuild from the reloaded ledger
 *      equals the pre-crash projection exactly.
 *   4. Period boundaries over settled facts: an entry settled on the
 *      Sunday of one ISO week vs the Monday of the next; the leap-day
 *      month edge; the daily edge. Zero-activity periods return empty
 *      honestly.
 *   5. The two P2P categories (verified-bytes-served,
 *      distinct-package-users) are named unavailable and report zero —
 *      no fake data.
 *   6. Commands over a fixture datadir: the four period leaves, window
 *      fields explicit, category filter, BAD_CATEGORY, unavailable
 *      category honesty, paging, breakdown, and contributor.show
 *      surfacing current-period ranks from the same projection. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "json/json.h"
#include "util/safe_alloc.h"
#include "vcs/package_rank.h"
#include "vcs/package_reward.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZK_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_rank: %s... OK\n", (name)); }         \
    else { printf("  zcode_rank: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── small fixtures (the test_zcode_reward pattern) ─────────────────── */

static void zk_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zk_mkdir_p(const char *path)
{
    char buf[4400];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool zk_rm_rf(const char *path)
{
    char normalized[768];
    struct stat st;
    /* A path that is already absent counts as removed. On POSIX hosts the
     * probe uses lstat on the normalized name, which does not follow the
     * final component. Where lstat is an alias of stat (Windows) that does
     * not hold, and this branch is not tested there. */
    if (test_cleanup_path(path, normalized) &&
        lstat(normalized, &st) != 0 && errno == ENOENT)
        return true;
    return test_rm_rf_recursive(path) == 0;
}

static void zk_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
    if (out[0] == 0)
        out[0] = 1;
}

static void zk_pub(uint8_t seed, uint8_t out[33])
{
    out[0] = 0x02;
    for (size_t i = 1; i < 33; i++)
        out[i] = (uint8_t)(seed + i);
}

static void zk_facts(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(0xf0 - seed - i);
    if (out[0] == 0)
        out[0] = 0xaa;
}

/* Enqueue one auto reward. */
static enum vcs_reward_enqueue_error zk_auto(struct vcs_reward_ledger *l,
                                             uint8_t root_seed,
                                             uint8_t pub_seed,
                                             enum vcs_reward_category cat,
                                             uint32_t points,
                                             uint8_t facts_seed,
                                             uint8_t id_out[32])
{
    uint8_t root[32], pub[33], facts[32];
    zk_root(root_seed, root);
    zk_pub(pub_seed, pub);
    zk_facts(facts_seed, facts);
    return vcs_reward_enqueue_auto(l, root, pub, cat, points, facts,
                                   id_out);
}

/* Settle every queued entry in one window (plan + persist + commit). */
static enum vcs_reward_commit_error zk_settle(struct vcs_reward_ledger *l,
                                              int64_t day)
{
    struct vcs_reward_plan plan;
    if (!vcs_reward_plan_build(l, day, &plan))
        return VCS_REWARD_COMMIT_IO;
    uint8_t plan_id[32];
    memcpy(plan_id, plan.plan_id, 32);
    enum vcs_reward_plan_persist_error perr =
        vcs_reward_plan_persist(l, &plan);
    vcs_reward_plan_free(&plan);
    if (perr != VCS_REWARD_PLAN_PERSIST_OK &&
        perr != VCS_REWARD_PLAN_PERSIST_DUPLICATE)
        return VCS_REWARD_COMMIT_IO;
    struct vcs_reward_commit_result result;
    char detail[256];
    return vcs_reward_commit(l, plan_id, &result, detail, sizeof(detail));
}

/* Serialize a ranked table (for rebuild/immunity equality checks). */
static void zk_table_dump(const struct vcs_rank_projection *p,
                          enum vcs_rank_category cat, char *out,
                          size_t out_size)
{
    size_t off = 0;
    off += (size_t)snprintf(out + off, out_size - off, "cat=%d;used=%zu;"
                            "drop=%zu;", (int)cat,
                            vcs_rank_projection_facts_used(p),
                            vcs_rank_projection_facts_dropped(p));
    struct vcs_rank_entry rows[128];
    size_t total = vcs_rank_table(p, cat, rows, 128);
    off += (size_t)snprintf(out + off, out_size - off, "total=%zu;",
                            total);
    size_t render = total < 128 ? total : 128;
    for (size_t i = 0; i < render; i++) {
        char hex[67];
        zk_hex_enc(rows[i].contributor, 33, hex);
        off += (size_t)snprintf(
            out + off, out_size - off, "%llu:%s:%llu:%llu:%llu;",
            (unsigned long long)rows[i].rank, hex,
            (unsigned long long)rows[i].points,
            (unsigned long long)rows[i].earned_score,
            (unsigned long long)rows[i].token_rewards_received);
        for (size_t c = 0; c < VCS_RANK_CATEGORY_COUNT; c++)
            off += (size_t)snprintf(out + off, out_size - off, "%llu,",
                                    (unsigned long long)
                                        rows[i].category_points[c]);
    }
}

/* ── 1. window arithmetic (pure; adversarial edges first) ───────────── */

/* The day boundary is exact: 23:59:59 vs 00:00:00. */
static int zk_windows_day_edges(void)
{
    int failures = 0;

    ZK_CHECK("windows: unix 0 is day 0", vcs_rank_day_from_unix(0) == 0);
    ZK_CHECK("windows: 23:59:59 is still day 0",
             vcs_rank_day_from_unix(86399) == 0);
    ZK_CHECK("windows: 00:00:00 next day is day 1",
             vcs_rank_day_from_unix(86400) == 1);
    ZK_CHECK("windows: pre-epoch floors down",
             vcs_rank_day_from_unix(-1) == -1 &&
             vcs_rank_day_from_unix(-86400) == -1 &&
             vcs_rank_day_from_unix(-86401) == -2);
    return failures;
}

/* Civil anchors + roundtrip identity across the epoch. */
static int zk_windows_civil_roundtrip(void)
{
    int failures = 0;

    ZK_CHECK("windows: 1970-01-01 is day 0",
             vcs_rank_day_from_civil(1970, 1, 1) == 0);
    {
        static const int64_t days[] = { -40000, -1000, -367, -1, 0, 1,
                                        365, 366, 10000, 18262, 2932896 };
        bool rt = true;
        for (size_t i = 0; i < sizeof(days) / sizeof(days[0]); i++) {
            int64_t y = 0;
            unsigned m = 0, d = 0;
            vcs_rank_civil_from_day(days[i], &y, &m, &d);
            if (vcs_rank_day_from_civil(y, m, d) != days[i])
                rt = false;
        }
        ZK_CHECK("windows: civil roundtrip identity", rt);
    }
    return failures;
}

/* ISO weekday: day 0 (1970-01-01) was a Thursday. */
static int zk_windows_iso_weekday(void)
{
    int failures = 0;

    ZK_CHECK("windows: day 0 is Thursday",
             vcs_rank_iso_weekday(0) == 4 &&
             vcs_rank_iso_weekday(3) == 7 /* 1970-01-04 Sunday */ &&
             vcs_rank_iso_weekday(4) == 1 /* 1970-01-05 Monday */ &&
             vcs_rank_iso_weekday(-3) == 1 /* 1969-12-29 Monday */);
    return failures;
}

/* ISO weeks crossing the Gregorian year. */
static int zk_windows_iso_weeks(void)
{
    int failures = 0;

    {
        int64_t iso_year = 0;
        unsigned iso_week = 0;
        vcs_rank_iso_week_from_day(vcs_rank_day_from_civil(2019, 12, 30),
                                   &iso_year, &iso_week);
        ZK_CHECK("windows: 2019-12-30 is ISO 2020-W01",
                 iso_year == 2020 && iso_week == 1);
        vcs_rank_iso_week_from_day(vcs_rank_day_from_civil(2020, 12, 31),
                                   &iso_year, &iso_week);
        ZK_CHECK("windows: 2020-12-31 is ISO 2020-W53",
                 iso_year == 2020 && iso_week == 53);
        vcs_rank_iso_week_from_day(vcs_rank_day_from_civil(2021, 1, 1),
                                   &iso_year, &iso_week);
        ZK_CHECK("windows: 2021-01-01 is still ISO 2020-W53",
                 iso_year == 2020 && iso_week == 53);
        vcs_rank_iso_week_from_day(vcs_rank_day_from_civil(2021, 1, 4),
                                   &iso_year, &iso_week);
        ZK_CHECK("windows: 2021-01-04 is ISO 2021-W01",
                 iso_year == 2021 && iso_week == 1);
    }
    return failures;
}

/* Daily window. */
static int zk_windows_daily_window(void)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        int64_t day = vcs_rank_day_from_civil(2024, 7, 27);
        ZK_CHECK("windows: daily window is the single UTC day",
                 vcs_rank_window_for(VCS_RANK_PERIOD_DAILY, day, &w) &&
                 w.bounded && w.first_day == day && w.last_day == day &&
                 w.year == 2024 && w.month == 7 && w.day_of_month == 27 &&
                 vcs_rank_window_contains(&w, day) &&
                 !vcs_rank_window_contains(&w, day - 1) &&
                 !vcs_rank_window_contains(&w, day + 1));
    }
    return failures;
}

/* Weekly window: Monday..Sunday, crossing the Gregorian year. */
static int zk_windows_weekly_window(void)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        int64_t friday = vcs_rank_day_from_civil(2021, 1, 1);
        ZK_CHECK("windows: weekly window Mon..Sun across the year",
                 vcs_rank_window_for(VCS_RANK_PERIOD_WEEKLY, friday, &w) &&
                 w.first_day == vcs_rank_day_from_civil(2020, 12, 28) &&
                 w.last_day == vcs_rank_day_from_civil(2021, 1, 3) &&
                 w.last_day - w.first_day == 6 &&
                 w.iso_year == 2020 && w.iso_week == 53 &&
                 vcs_rank_window_contains(
                     &w, vcs_rank_day_from_civil(2020, 12, 28)) &&
                 vcs_rank_window_contains(
                     &w, vcs_rank_day_from_civil(2021, 1, 3)) &&
                 !vcs_rank_window_contains(
                     &w, vcs_rank_day_from_civil(2021, 1, 4)));
    }
    return failures;
}

/* Monthly windows: exact lengths. */
static int zk_windows_monthly_windows(void)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        ZK_CHECK("windows: leap February has 29 days",
                 vcs_rank_window_for(
                     VCS_RANK_PERIOD_MONTHLY,
                     vcs_rank_day_from_civil(2024, 2, 15), &w) &&
                 w.first_day == vcs_rank_day_from_civil(2024, 2, 1) &&
                 w.last_day == vcs_rank_day_from_civil(2024, 2, 29) &&
                 w.last_day - w.first_day + 1 == 29);
        ZK_CHECK("windows: common February has 28 days",
                 vcs_rank_window_for(
                     VCS_RANK_PERIOD_MONTHLY,
                     vcs_rank_day_from_civil(2023, 2, 15), &w) &&
                 w.last_day == vcs_rank_day_from_civil(2023, 2, 28) &&
                 w.last_day - w.first_day + 1 == 28);
        ZK_CHECK("windows: January has 31 days",
                 vcs_rank_window_for(
                     VCS_RANK_PERIOD_MONTHLY,
                     vcs_rank_day_from_civil(2024, 1, 31), &w) &&
                 w.last_day - w.first_day + 1 == 31);
        ZK_CHECK("windows: April has 30 days",
                 vcs_rank_window_for(
                     VCS_RANK_PERIOD_MONTHLY,
                     vcs_rank_day_from_civil(2024, 4, 1), &w) &&
                 w.last_day - w.first_day + 1 == 30);
        ZK_CHECK("windows: December crosses into January exactly",
                 vcs_rank_window_for(
                     VCS_RANK_PERIOD_MONTHLY,
                     vcs_rank_day_from_civil(2024, 12, 31), &w) &&
                 w.first_day == vcs_rank_day_from_civil(2024, 12, 1) &&
                 w.last_day == vcs_rank_day_from_civil(2024, 12, 31) &&
                 w.last_day + 1 == vcs_rank_day_from_civil(2025, 1, 1));
    }
    return failures;
}

/* All-time is unbounded and contains everything. */
static int zk_windows_all_time(void)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        ZK_CHECK("windows: all-time is unbounded",
                 vcs_rank_window_for(VCS_RANK_PERIOD_ALL_TIME, 0, &w) &&
                 !w.bounded &&
                 vcs_rank_window_contains(&w, INT64_MIN) &&
                 vcs_rank_window_contains(&w, INT64_MAX) &&
                 vcs_rank_window_contains(&w, 0));
        ZK_CHECK("windows: invalid period rejected",
                 !vcs_rank_window_for((enum vcs_rank_period)77, 0, &w));
    }
    return failures;
}

/* Category names, availability, and the reward-category mapping. */
static int zk_windows_category_names(void)
{
    int failures = 0;

    {
        ZK_CHECK("windows: P2P categories named unavailable",
                 !vcs_rank_category_available(
                     VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED) &&
                 !vcs_rank_category_available(
                     VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS) &&
                 vcs_rank_category_available(VCS_RANK_CATEGORY_OVERALL) &&
                 vcs_rank_category_available(
                     VCS_RANK_CATEGORY_SECURITY_FIXES));
        ZK_CHECK("windows: unavailable names are honest",
                 strcmp(vcs_rank_category_string(
                            VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED),
                        "verified-bytes-served") == 0 &&
                 strcmp(vcs_rank_category_string(
                            VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS),
                        "distinct-package-users") == 0);
        enum vcs_rank_category c;
        ZK_CHECK("windows: category strings round-trip",
                 vcs_rank_category_from_string("security-fixes", &c) &&
                 c == VCS_RANK_CATEGORY_SECURITY_FIXES &&
                 vcs_rank_category_from_string("overall", &c) &&
                 c == VCS_RANK_CATEGORY_OVERALL &&
                 !vcs_rank_category_from_string("bogus", &c));
    }
    return failures;
}

static int zk_windows_category_mapping(void)
{
    int failures = 0;

    {
        ZK_CHECK("windows: reward categories map to rank categories",
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_NEW_PACKAGE) ==
                     VCS_RANK_CATEGORY_NEW_PACKAGES &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_PACKAGE_UPDATE) ==
                     VCS_RANK_CATEGORY_PACKAGE_IMPROVEMENTS &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION) ==
                     VCS_RANK_CATEGORY_BUGS_FIXED &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_TEST_CONTRIBUTION) ==
                     VCS_RANK_CATEGORY_TESTS_ADDED &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_SECURITY_FIX) ==
                     VCS_RANK_CATEGORY_SECURITY_FIXES &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_REVIEW) ==
                     VCS_RANK_CATEGORY_INDEPENDENT_REVIEWS &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_BUILD_REPRODUCTION) ==
                     VCS_RANK_CATEGORY_REPRODUCIBLE_BUILDS &&
                 vcs_rank_category_from_reward(
                     VCS_REWARD_CATEGORY_MAINTENANCE_90_DAY) ==
                     VCS_RANK_CATEGORY_MAINTENANCE &&
                 vcs_rank_category_from_reward(VCS_REWARD_CATEGORY_COUNT) ==
                     VCS_RANK_CATEGORY_COUNT);
    }
    return failures;
}

static int t_windows(void)
{
    int failures = 0;

    failures += zk_windows_day_edges();
    failures += zk_windows_civil_roundtrip();
    failures += zk_windows_iso_weekday();
    failures += zk_windows_iso_weeks();
    failures += zk_windows_daily_window();
    failures += zk_windows_weekly_window();
    failures += zk_windows_monthly_windows();
    failures += zk_windows_all_time();
    failures += zk_windows_category_names();
    failures += zk_windows_category_mapping();
    return failures;
}

/* ── 2/3/5. the pure projection core ────────────────────────────────── */

/* Three contributors on adjacent days; B and C tie on points with
 * C holding the lexicographically smaller pubkey. */
static int zk_projection_fixture_keys(uint8_t pub_a[33], uint8_t pub_b[33],
                                      uint8_t pub_c[33])
{
    int failures = 0;

    zk_pub(10, pub_a);
    zk_pub(30, pub_b); /* larger pubkey bytes */
    zk_pub(20, pub_c); /* smaller than B, ties B on points */
    ZK_CHECK("projection: fixture key order",
             memcmp(pub_c, pub_b, 33) < 0 &&
             memcmp(pub_a, pub_c, 33) < 0);
    return failures;
}

static size_t zk_projection_fill_facts(struct vcs_rank_fact_input *facts,
                                       uint8_t pub_a[33], uint8_t pub_b[33],
                                       uint8_t pub_c[33])
{
    size_t n = 0;
    memcpy(facts[n].contributor, pub_a, 33);
    facts[n].category = VCS_RANK_CATEGORY_NEW_PACKAGES;
    facts[n].points = 100;
    facts[n].day = 10;
    n++;
    memcpy(facts[n].contributor, pub_b, 33);
    facts[n].category = VCS_RANK_CATEGORY_SECURITY_FIXES;
    facts[n].points = 150;
    facts[n].day = 10;
    n++;
    memcpy(facts[n].contributor, pub_c, 33);
    facts[n].category = VCS_RANK_CATEGORY_TESTS_ADDED;
    facts[n].points = 150;
    facts[n].day = 11;
    n++;
    /* Drops: outside the window, zero points, OVERALL as an input
     * category, an unavailable P2P category. */
    memcpy(facts[n].contributor, pub_a, 33);
    facts[n].category = VCS_RANK_CATEGORY_BUGS_FIXED;
    facts[n].points = 500;
    facts[n].day = 99; /* outside any window used below except all-time */
    n++;
    memcpy(facts[n].contributor, pub_a, 33);
    facts[n].category = VCS_RANK_CATEGORY_MAINTENANCE;
    facts[n].points = 0;
    facts[n].day = 10;
    n++;
    memcpy(facts[n].contributor, pub_b, 33);
    facts[n].category = VCS_RANK_CATEGORY_OVERALL;
    facts[n].points = 50;
    facts[n].day = 10;
    n++;
    memcpy(facts[n].contributor, pub_b, 33);
    facts[n].category = VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED;
    facts[n].points = 700;
    facts[n].day = 10;
    n++;
    memcpy(facts[n].contributor, pub_c, 33);
    facts[n].category = VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS;
    facts[n].points = 900;
    facts[n].day = 10;
    n++;
    return n;
}

/* Daily window day 10: the rank table and its facts accounting. */
static int zk_projection_daily_table(struct vcs_rank_projection *p,
                                     struct vcs_rank_entry *rows,
                                     uint8_t pub_a[33], uint8_t pub_b[33])
{
    int failures = 0;

    size_t total =
        vcs_rank_table(p, VCS_RANK_CATEGORY_OVERALL, rows, 4);
    ZK_CHECK("projection: daily table ranks B then A",
             total == 2 && rows[0].rank == 1 &&
                 rows[0].points == 150 &&
                 memcmp(rows[0].contributor, pub_b, 33) == 0 &&
                 rows[1].rank == 2 && rows[1].points == 100 &&
                 memcmp(rows[1].contributor, pub_a, 33) == 0);
    ZK_CHECK("projection: facts accounted exactly",
             vcs_rank_projection_facts_used(p) == 2 &&
             vcs_rank_projection_facts_dropped(p) == 6 &&
             vcs_rank_projection_contributor_count(p) == 2);
    return failures;
}

/* Daily window day 10: unavailable categories, filters and rows. */
static int zk_projection_daily_filters(struct vcs_rank_projection *p,
                                       struct vcs_rank_entry *rows,
                                       uint8_t pub_b[33])
{
    int failures = 0;

    ZK_CHECK("projection: unavailable categories rank nobody",
             vcs_rank_table(p,
                            VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED,
                            rows, 4) == 0 &&
             vcs_rank_table(p,
                            VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS,
                            rows, 4) == 0);
    ZK_CHECK("projection: category filter ranks only its facts",
             vcs_rank_table(p, VCS_RANK_CATEGORY_SECURITY_FIXES,
                            rows, 4) == 1 &&
                 rows[0].points == 150 &&
                 memcmp(rows[0].contributor, pub_b, 33) == 0);
    ZK_CHECK("projection: rows keep the unavailable zeros honest",
             rows[0].category_points[
                 VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED] == 0 &&
             rows[0].category_points[
                 VCS_RANK_CATEGORY_DISTINCT_PACKAGE_USERS] == 0);
    ZK_CHECK("projection: separate facts, no balance field",
             rows[0].earned_score == 150 &&
             rows[0].token_rewards_received == 150);
    return failures;
}

/* Daily window day 10: C is absent (settled day 11). */
static int zk_projection_daily(struct vcs_rank_fact_input *facts, size_t n,
                               uint8_t pub_a[33], uint8_t pub_b[33])
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_DAILY, 10, &w);
        struct vcs_rank_projection *p =
            vcs_rank_projection_from_facts(facts, n, &w);
        ZK_CHECK("projection: daily build", p != NULL);
        if (p) {
            struct vcs_rank_entry rows[4];
            failures += zk_projection_daily_table(p, rows, pub_a, pub_b);
            failures += zk_projection_daily_filters(p, rows, pub_b);
            vcs_rank_projection_free(p);
        }
    }
    return failures;
}

/* All-time: the rank table and its tie-break order. */
static int zk_projection_all_time_ranks(struct vcs_rank_projection *p,
                                        uint8_t pub_a[33], uint8_t pub_b[33],
                                        uint8_t pub_c[33])
{
    int failures = 0;

    struct vcs_rank_entry rows[4];
    size_t total =
        vcs_rank_table(p, VCS_RANK_CATEGORY_OVERALL, rows, 4);
    /* A: 100 + 500 (bugs-fixed day 99) = 600; B: 150; C: 150.
     * Order: A, then the tie — C's smaller pubkey wins. */
    ZK_CHECK("projection: overall sums categories",
             total == 3 && rows[0].points == 600 &&
                 memcmp(rows[0].contributor, pub_a, 33) == 0 &&
                 rows[0].category_points[
                     VCS_RANK_CATEGORY_BUGS_FIXED] == 500 &&
                 rows[0].category_points[
                     VCS_RANK_CATEGORY_NEW_PACKAGES] == 100);
    ZK_CHECK("projection: tie-break is pubkey ascending",
             rows[1].rank == 2 && rows[1].points == 150 &&
                 memcmp(rows[1].contributor, pub_c, 33) == 0 &&
                 rows[2].rank == 3 && rows[2].points == 150 &&
                 memcmp(rows[2].contributor, pub_b, 33) == 0);
    return failures;
}

/* All-time: single-contributor rank lookups. */
static int zk_projection_all_time_lookups(struct vcs_rank_projection *p,
                                          uint8_t pub_b[33],
                                          uint8_t pub_c[33])
{
    int failures = 0;

    struct vcs_rank_entry one;
    ZK_CHECK("projection: contributor rank lookup",
             vcs_rank_contributor(p, VCS_RANK_CATEGORY_OVERALL,
                                  pub_c, &one) &&
                 one.rank == 2 && one.points == 150);
    ZK_CHECK("projection: contributor rank in a category",
             vcs_rank_contributor(p,
                                  VCS_RANK_CATEGORY_SECURITY_FIXES,
                                  pub_b, &one) &&
                 one.rank == 1);
    ZK_CHECK("projection: unranked contributor named",
             !vcs_rank_contributor(p, VCS_RANK_CATEGORY_BUGS_FIXED,
                                   pub_b, &one) &&
             !vcs_rank_contributor(
                 p, VCS_RANK_CATEGORY_VERIFIED_BYTES_SERVED, pub_b,
                 &one));
    return failures;
}

/* All-time: the deterministic tie-break (C before B on equal
 * points), overall sums categories, single-contributor ranks. */
static int zk_projection_all_time(struct vcs_rank_fact_input *facts, size_t n,
                                  uint8_t pub_a[33], uint8_t pub_b[33],
                                  uint8_t pub_c[33])
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_ALL_TIME, 0, &w);
        struct vcs_rank_projection *p =
            vcs_rank_projection_from_facts(facts, n, &w);
        ZK_CHECK("projection: all-time build", p != NULL);
        if (p) {
            failures += zk_projection_all_time_ranks(p, pub_a, pub_b,
                                                     pub_c);
            failures += zk_projection_all_time_lookups(p, pub_b, pub_c);
            vcs_rank_projection_free(p);
        }
    }
    return failures;
}

/* Zero-activity period: honestly empty. */
static int zk_projection_zero_activity(struct vcs_rank_fact_input *facts,
                                       size_t n)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_DAILY, 12345, &w);
        struct vcs_rank_projection *p =
            vcs_rank_projection_from_facts(facts, n, &w);
        ZK_CHECK("projection: zero-activity period is honestly empty",
                 p != NULL &&
                     vcs_rank_projection_contributor_count(p) == 0 &&
                     vcs_rank_projection_facts_used(p) == 0 &&
                     vcs_rank_table(p, VCS_RANK_CATEGORY_OVERALL, NULL,
                                    0) == 0);
        vcs_rank_projection_free(p);
    }
    return failures;
}

/* Same inputs, same projection (determinism). */
static int zk_projection_determinism(struct vcs_rank_fact_input *facts,
                                     size_t n)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_ALL_TIME, 0, &w);
        struct vcs_rank_projection *p1 =
            vcs_rank_projection_from_facts(facts, n, &w);
        struct vcs_rank_projection *p2 =
            vcs_rank_projection_from_facts(facts, n, &w);
        char dump1[8192], dump2[8192];
        zk_table_dump(p1, VCS_RANK_CATEGORY_OVERALL, dump1,
                      sizeof(dump1));
        zk_table_dump(p2, VCS_RANK_CATEGORY_OVERALL, dump2,
                      sizeof(dump2));
        ZK_CHECK("projection: identical inputs reproduce byte-identically",
                 p1 && p2 && strcmp(dump1, dump2) == 0);
        vcs_rank_projection_free(p1);
        vcs_rank_projection_free(p2);
    }
    return failures;
}

static int t_projection(void)
{
    int failures = 0;

    uint8_t pub_a[33], pub_b[33], pub_c[33];
    failures += zk_projection_fixture_keys(pub_a, pub_b, pub_c);

    struct vcs_rank_fact_input facts[8];
    memset(facts, 0, sizeof(facts));
    size_t n = zk_projection_fill_facts(facts, pub_a, pub_b, pub_c);

    failures += zk_projection_daily(facts, n, pub_a, pub_b);
    failures += zk_projection_all_time(facts, n, pub_a, pub_b, pub_c);
    failures += zk_projection_zero_activity(facts, n);
    failures += zk_projection_determinism(facts, n);
    return failures;
}

/* ── 2. transfer/balance immunity at the durable-ledger level ───────── */

static int t_transfer_immunity(void)
{
    int failures = 0;
    char store[4400];
    snprintf(store, sizeof(store), "test-tmp/zk_xfer_%ld/zcode",
             (long)getpid());
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zk_xfer_%ld",
             (long)getpid());
    zk_rm_rf(datadir);

    /* A clean ledger: two contributors, earned facts only. */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        uint8_t id[32];
        ZK_CHECK("xfer: fixture enqueues",
                 zk_auto(l, 40, 40, VCS_REWARD_CATEGORY_NEW_PACKAGE, 700,
                         40, id) == VCS_REWARD_ENQUEUE_OK &&
                 zk_auto(l, 41, 41, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                         300, 41, id) == VCS_REWARD_ENQUEUE_OK);
        ZK_CHECK("xfer: fixture settles",
                 zk_settle(l, 200) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    struct vcs_rank_window w;
    (void)vcs_rank_window_for(VCS_RANK_PERIOD_ALL_TIME, 0, &w);
    char clean[8192];
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        struct vcs_rank_projection *p =
            vcs_rank_projection_build(l, &w);
        ZK_CHECK("xfer: clean projection builds",
                 p && vcs_rank_projection_facts_used(p) == 2);
        if (p)
            zk_table_dump(p, VCS_RANK_CATEGORY_OVERALL, clean,
                          sizeof(clean));
        ZK_CHECK("xfer: clean ledger has no corrupt wires",
                 vcs_reward_ledger_corrupt_count(l) == 0);
        vcs_rank_projection_free(p);
        vcs_reward_ledger_free(l);
    }

    /* Inject a fake "transfer" fact wire: the ledger has NO transfer or
     * balance record kind, so the closest possible forgery is a fact
     * wire whose kind byte names neither AUTO nor CLAIM — the decoder
     * must reject it. Layout mirrors the durable fact wire (181 bytes):
     * magic 0-3, i64 day 4-11, kind 12, category 13, pad 14-15, u32
     * points 16-19, entry id 20-51, release root 52-83, contributor
     * 84-116, facts hash 117-148, plan id 149-180. */
    {
        uint8_t wire[181];
        memset(wire, 0, sizeof(wire));
        memcpy(wire, "ZRF1", 4);
        wire[12] = 7; /* the forged "transfer" kind — no such kind */
        wire[13] = 0;
        wire[16] = 0xff; /* a huge forged points payload... */
        wire[17] = 0xff;
        wire[18] = 0xff;
        wire[19] = 0xff;
        uint8_t pub[33];
        zk_pub(41, pub); /* ...credited straight to contributor 41 */
        memcpy(wire + 84, pub, 33);
        for (size_t i = 0; i < 32; i++)
            wire[20 + i] = (uint8_t)(0x55 + i); /* entry id */
        uint8_t id_hex[65];
        zk_hex_enc(wire + 20, 32, (char *)id_hex);
        char dir[4400], path[4400];
        snprintf(dir, sizeof(dir), "%s/rewards/ledger", store);
        snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
        ZK_CHECK("xfer: forged wire directory ready", zk_mkdir_p(dir));
        FILE *f = fopen(path, "wb");
        ZK_CHECK("xfer: forged wire written",
                 f && fwrite(wire, 1, sizeof(wire), f) == sizeof(wire));
        if (f)
            fclose(f);
    }

    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        ZK_CHECK("xfer: the forgery is rejected as corrupt",
                 vcs_reward_ledger_corrupt_count(l) == 1 &&
                 vcs_reward_ledger_fact_count(l) == 2);
        struct vcs_rank_projection *p =
            vcs_rank_projection_build(l, &w);
        char forged[8192];
        if (p)
            zk_table_dump(p, VCS_RANK_CATEGORY_OVERALL, forged,
                          sizeof(forged));
        ZK_CHECK("xfer: rankings identical with the forgery rejected",
                 p && strcmp(clean, forged) == 0);
        vcs_rank_projection_free(p);
        vcs_reward_ledger_free(l);
    }
    zk_rm_rf(datadir);
    return failures;
}

/* ── 3. projection rebuild from the durable wires ───────────────────── */

static int t_rebuild(void)
{
    int failures = 0;
    char store[4400];
    snprintf(store, sizeof(store), "test-tmp/zk_rebuild_%ld/zcode",
             (long)getpid());
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zk_rebuild_%ld",
             (long)getpid());
    zk_rm_rf(datadir);

    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        uint8_t id[32];
        (void)zk_auto(l, 50, 50, VCS_REWARD_CATEGORY_NEW_PACKAGE, 500, 50,
                      id);
        (void)zk_auto(l, 51, 51, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 200,
                      51, id);
        ZK_CHECK("rebuild: day-100 batch settles",
                 zk_settle(l, 100) == VCS_REWARD_COMMIT_OK);
        (void)zk_auto(l, 52, 50, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 250,
                      52, id);
        (void)zk_auto(l, 53, 52, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                      300, 53, id);
        ZK_CHECK("rebuild: day-101 batch settles",
                 zk_settle(l, 101) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    struct vcs_rank_window w;
    (void)vcs_rank_window_for(VCS_RANK_PERIOD_WEEKLY, 100, &w);
    char before[8192], after[8192];
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        struct vcs_rank_projection *p =
            vcs_rank_projection_build(l, &w);
        ZK_CHECK("rebuild: weekly projection uses all four facts",
                 p && vcs_rank_projection_facts_used(p) == 4 &&
                     vcs_rank_projection_contributor_count(p) == 3);
        if (p)
            zk_table_dump(p, VCS_RANK_CATEGORY_OVERALL, before,
                          sizeof(before));
        vcs_rank_projection_free(p);
        vcs_reward_ledger_free(l);
    }
    /* The "crash": every in-memory structure is gone; reload from the
     * durable wires and rebuild. */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        struct vcs_rank_projection *p =
            vcs_rank_projection_build(l, &w);
        if (p)
            zk_table_dump(p, VCS_RANK_CATEGORY_OVERALL, after,
                          sizeof(after));
        vcs_rank_projection_free(p);
        vcs_reward_ledger_free(l);
    }
    ZK_CHECK("rebuild: rebuilt projection equals the pre-crash one",
             strcmp(before, after) == 0);
    zk_rm_rf(datadir);
    return failures;
}

/* ── 4. period boundaries over settled facts ────────────────────────── */

/* Settle four facts on the boundary days and close the ledger. */
static int zk_bounds_settle_facts(char *store, int64_t sunday,
                                  int64_t monday, int64_t leap_day,
                                  int64_t march_1)
{
    int failures = 0;

    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        uint8_t id[32];
        (void)zk_auto(l, 70, 70, VCS_REWARD_CATEGORY_NEW_PACKAGE, 600, 70,
                      id);
        ZK_CHECK("bounds: E1 settles Sunday",
                 zk_settle(l, sunday) == VCS_REWARD_COMMIT_OK);
        (void)zk_auto(l, 71, 71, VCS_REWARD_CATEGORY_NEW_PACKAGE, 400, 71,
                      id);
        ZK_CHECK("bounds: E2 settles Monday",
                 zk_settle(l, monday) == VCS_REWARD_COMMIT_OK);
        (void)zk_auto(l, 72, 72, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 150,
                      72, id);
        ZK_CHECK("bounds: E3 settles on the leap day",
                 zk_settle(l, leap_day) == VCS_REWARD_COMMIT_OK);
        (void)zk_auto(l, 73, 73, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                      350, 73, id);
        ZK_CHECK("bounds: E4 settles on March 1",
                 zk_settle(l, march_1) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }
    return failures;
}

/* The fact accessor round-trips day/category/points. */
static int zk_bounds_fact_accessor(struct vcs_reward_ledger *l,
                                   int64_t sunday, int64_t monday)
{
    int failures = 0;

    {
        bool seen_sunday = false, seen_monday = false;
        for (size_t i = 0; i < vcs_reward_ledger_fact_count(l); i++) {
            struct vcs_reward_fact_view v;
            if (!vcs_reward_ledger_fact_at(l, i, &v))
                continue;
            if (v.day == sunday && v.points == 600 &&
                v.category == VCS_REWARD_CATEGORY_NEW_PACKAGE)
                seen_sunday = true;
            if (v.day == monday && v.points == 400)
                seen_monday = true;
        }
        ZK_CHECK("bounds: fact accessor round-trips",
                 seen_sunday && seen_monday);
    }
    return failures;
}

/* ISO week edge: the week of the Sunday holds E1 only; the week of
 * the Monday holds E2 only. */
static int zk_bounds_adjacent_weeks(struct vcs_reward_ledger *l,
                                    int64_t sunday, int64_t monday)
{
    int failures = 0;

    {
        struct vcs_rank_window w0, w1;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_WEEKLY, sunday, &w0);
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_WEEKLY, monday, &w1);
        ZK_CHECK("bounds: adjacent ISO weeks are disjoint",
                 w0.last_day + 1 == w1.first_day && w0.iso_week == 53 &&
                 w0.iso_year == 2020 && w1.iso_week == 1 &&
                 w1.iso_year == 2021);
        struct vcs_rank_projection *p0 =
            vcs_rank_projection_build(l, &w0);
        struct vcs_rank_projection *p1 =
            vcs_rank_projection_build(l, &w1);
        struct vcs_rank_entry rows[2];
        ZK_CHECK("bounds: Sunday's week ranks only E1",
                 p0 && vcs_rank_table(p0, VCS_RANK_CATEGORY_OVERALL, rows,
                                      2) == 1 &&
                     rows[0].points == 600);
        ZK_CHECK("bounds: Monday's week ranks only E2",
                 p1 && vcs_rank_table(p1, VCS_RANK_CATEGORY_OVERALL, rows,
                                      2) == 1 &&
                     rows[0].points == 400);
        vcs_rank_projection_free(p0);
        vcs_rank_projection_free(p1);
    }
    return failures;
}

/* Month edge: February 2024 holds the leap-day fact; March holds
 * the March-1 fact; the daily edge holds each on its own day. */
static int zk_bounds_month_and_day_edges(struct vcs_reward_ledger *l,
                                         int64_t leap_day, int64_t march_1)
{
    int failures = 0;

    {
        struct vcs_rank_window feb, mar, day_w;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_MONTHLY, leap_day, &feb);
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_MONTHLY, march_1, &mar);
        struct vcs_rank_projection *pf =
            vcs_rank_projection_build(l, &feb);
        struct vcs_rank_projection *pm =
            vcs_rank_projection_build(l, &mar);
        struct vcs_rank_entry rows[2];
        ZK_CHECK("bounds: leap February ranks only the leap-day fact",
                 pf && feb.last_day == leap_day &&
                     vcs_rank_table(pf, VCS_RANK_CATEGORY_OVERALL, rows,
                                    2) == 1 &&
                     rows[0].points == 150);
        ZK_CHECK("bounds: March ranks only the March fact",
                 pm && mar.first_day == march_1 &&
                     vcs_rank_table(pm, VCS_RANK_CATEGORY_OVERALL, rows,
                                    2) == 1 &&
                     rows[0].points == 350);
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_DAILY, leap_day,
                                  &day_w);
        struct vcs_rank_projection *pd =
            vcs_rank_projection_build(l, &day_w);
        ZK_CHECK("bounds: daily edge includes only its own day",
                 pd &&
                     vcs_rank_table(pd, VCS_RANK_CATEGORY_OVERALL, rows,
                                    2) == 1 &&
                     rows[0].points == 150 &&
                     !vcs_rank_window_contains(&day_w, leap_day - 1) &&
                     !vcs_rank_window_contains(&day_w, march_1));
        vcs_rank_projection_free(pf);
        vcs_rank_projection_free(pm);
        vcs_rank_projection_free(pd);
    }
    return failures;
}

/* A period with no activity: honestly empty. */
static int zk_bounds_zero_activity(struct vcs_reward_ledger *l)
{
    int failures = 0;

    {
        struct vcs_rank_window w;
        (void)vcs_rank_window_for(VCS_RANK_PERIOD_DAILY,
                                  vcs_rank_day_from_civil(1999, 12, 31),
                                  &w);
        struct vcs_rank_projection *p =
            vcs_rank_projection_build(l, &w);
        ZK_CHECK("bounds: zero-activity period empty",
                 p && vcs_rank_projection_contributor_count(p) == 0 &&
                     vcs_rank_table(p, VCS_RANK_CATEGORY_OVERALL, NULL,
                                    0) == 0);
        vcs_rank_projection_free(p);
    }
    return failures;
}

static int t_period_boundaries(void)
{
    int failures = 0;
    char store[4400];
    snprintf(store, sizeof(store), "test-tmp/zk_bounds_%ld/zcode",
             (long)getpid());
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zk_bounds_%ld",
             (long)getpid());
    zk_rm_rf(datadir);

    /* E1 settles on the Sunday of ISO 2020-W53 (2021-01-03); E2 settles
     * on the Monday of ISO 2021-W01 (2021-01-04). E3 settles on the leap
     * day 2024-02-29; E4 on 2024-03-01. */
    int64_t sunday = vcs_rank_day_from_civil(2021, 1, 3);
    int64_t monday = vcs_rank_day_from_civil(2021, 1, 4);
    int64_t leap_day = vcs_rank_day_from_civil(2024, 2, 29);
    int64_t march_1 = vcs_rank_day_from_civil(2024, 3, 1);
    failures += zk_bounds_settle_facts(store, sunday, monday, leap_day,
                                       march_1);

    struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
    ZK_CHECK("bounds: four durable facts",
             vcs_reward_ledger_fact_count(l) == 4);
    failures += zk_bounds_fact_accessor(l, sunday, monday);
    failures += zk_bounds_adjacent_weeks(l, sunday, monday);
    failures += zk_bounds_month_and_day_edges(l, leap_day, march_1);
    failures += zk_bounds_zero_activity(l);
    vcs_reward_ledger_free(l);
    zk_rm_rf(datadir);
    return failures;
}

/* ── 6. the typed commands over a fixture datadir ───────────────────── */

struct zk_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zk_cmd_init(struct zk_cmd *c, const char *datadir)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_rank_test.v1");
    (void)json_push_kv_str(&c->input, "datadir", datadir);
}

static void zk_cmd_free(struct zk_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Three contributors settle on day 20000 (two tie on 400 with the
 * tie-break deciding), one more on day 20007. */
static int zk_commands_fixture_keys(uint8_t pub1[33], uint8_t pub2[33],
                                    uint8_t pub3[33], uint8_t pub4[33])
{
    int failures = 0;

    zk_pub(81, pub1);
    zk_pub(83, pub2); /* ties pub3 at 400, larger pubkey */
    zk_pub(82, pub3); /* ties pub2 at 400, smaller pubkey */
    zk_pub(84, pub4);
    ZK_CHECK("commands: fixture key order",
             memcmp(pub3, pub2, 33) < 0);
    return failures;
}

static int zk_commands_settle(char *store)
{
    int failures = 0;

    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        uint8_t id[32];
        (void)zk_auto(l, 81, 81, VCS_REWARD_CATEGORY_NEW_PACKAGE, 900, 81,
                      id);
        (void)zk_auto(l, 82, 83, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 400,
                      82, id);
        (void)zk_auto(l, 83, 82, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                      400, 83, id);
        ZK_CHECK("commands: day-20000 batch settles",
                 zk_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        (void)zk_auto(l, 84, 84, VCS_REWARD_CATEGORY_NEW_PACKAGE, 100, 84,
                      id);
        ZK_CHECK("commands: day-20007 batch settles",
                 zk_settle(l, 20007) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }
    return failures;
}

static int zk_commands_daily_window(const struct json_value *window)
{
    int failures = 0;

    ZK_CHECK("commands: daily window is explicit",
             window &&
             json_get_int(json_get(window, "first_day")) == 20000 &&
             json_get_int(json_get(window, "last_day")) == 20000 &&
             json_get_int(json_get(window, "days")) == 1 &&
             json_get_int(json_get(window, "year")) == 2024 &&
             json_get_int(json_get(window, "month")) == 10 &&
             json_get_int(json_get(window, "day_of_month")) == 4 &&
             json_get_bool(json_get(window, "bounded")));
    return failures;
}

static int zk_commands_daily_ranking(struct zk_cmd *c,
                                     const struct json_value *rows)
{
    int failures = 0;

    ZK_CHECK("commands: daily rows ranked with the tie-break",
             json_get_int(json_get(&c->reply.data, "total_ranked")) ==
                 3 &&
             rows && json_at(rows, 0) && json_at(rows, 2) &&
             json_get_int(json_get(json_at(rows, 0), "rank")) == 1 &&
             json_get_int(json_get(json_at(rows, 0), "points")) ==
                 900 &&
             json_get_int(json_get(json_at(rows, 1), "rank")) == 2 &&
             json_get_int(json_get(json_at(rows, 2), "rank")) == 3 &&
             json_get_int(json_get(json_at(rows, 1), "points")) ==
                 400 &&
             json_get_int(json_get(json_at(rows, 2), "points")) ==
                 400);
    return failures;
}

static int zk_commands_daily_tie(const struct json_value *rows,
                                 uint8_t pub3[33])
{
    int failures = 0;

    const char *second =
        json_get_str(json_get(json_at(rows, 1), "contributor"));
    char pub3_hex[67];
    zk_hex_enc(pub3, 33, pub3_hex);
    ZK_CHECK("commands: tie resolved by pubkey ascending",
             second && strcmp(second, pub3_hex) == 0);
    return failures;
}

static int zk_commands_daily_facts(struct zk_cmd *c,
                                   const struct json_value *rows)
{
    int failures = 0;

    ZK_CHECK("commands: rows keep the facts separate",
             json_get_int(json_get(json_at(rows, 0),
                                   "earned_score")) == 900 &&
             json_get_int(json_get(json_at(rows, 0),
                                   "token_rewards_received")) == 900);
    ZK_CHECK("commands: balance honestly unavailable",
             strcmp(json_get_str(json_get(&c->reply.data,
                                          "current_token_balance"))
                        ? json_get_str(json_get(
                              &c->reply.data, "current_token_balance"))
                        : "",
                    "unavailable") == 0);
    return failures;
}

/* daily: rows ranked, tie-break applied, window explicit. */
static int zk_commands_daily(const char *datadir, uint8_t pub3[33])
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_leaderboard_daily(&c.request, &c.reply);
        const struct json_value *window =
            json_get(&c.reply.data, "window");
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        failures += zk_commands_daily_window(window);
        failures += zk_commands_daily_ranking(&c, rows);
        failures += zk_commands_daily_tie(rows, pub3);
        failures += zk_commands_daily_facts(&c, rows);
        zk_cmd_free(&c);
    }
    return failures;
}

/* weekly/monthly/all: window descriptors. 20000 = 2024-10-04, a
 * Friday of ISO 2024-W40; day 20007 is the Friday of W41. */
static int zk_commands_weekly_window(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_leaderboard_weekly(&c.request, &c.reply);
        const struct json_value *window =
            json_get(&c.reply.data, "window");
        ZK_CHECK("commands: weekly window names the ISO week",
                 window &&
                 json_get_int(json_get(window, "iso_year")) == 2024 &&
                 json_get_int(json_get(window, "iso_week")) == 40 &&
                 json_get_int(json_get(window, "days")) == 7 &&
                 json_get_int(json_get(&c.reply.data,
                                       "total_ranked")) == 3);
        zk_cmd_free(&c);
    }
    return failures;
}

static int zk_commands_monthly_window(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_leaderboard_monthly(&c.request, &c.reply);
        const struct json_value *window =
            json_get(&c.reply.data, "window");
        ZK_CHECK("commands: monthly window names the month",
                 window &&
                 json_get_int(json_get(window, "year")) == 2024 &&
                 json_get_int(json_get(window, "month")) == 10 &&
                 json_get_int(json_get(window, "days")) == 31 &&
                 json_get_int(json_get(&c.reply.data,
                                       "total_ranked")) == 4);
        zk_cmd_free(&c);
    }
    return failures;
}

static int zk_commands_all_time_window(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
        const struct json_value *window =
            json_get(&c.reply.data, "window");
        ZK_CHECK("commands: all-time is unbounded with four ranked",
                 window &&
                 !json_get_bool(json_get(window, "bounded")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "total_ranked")) == 4);
        ZK_CHECK("commands: unavailable categories named in the schema",
                 json_get(&c.reply.data, "unavailable_categories") &&
                 json_at(json_get(&c.reply.data,
                                  "unavailable_categories"), 0));
        zk_cmd_free(&c);
    }
    return failures;
}

/* category filter + rejection naming. */
static int zk_commands_category_filter(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "category", "new-packages");
        zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        ZK_CHECK("commands: category filter ranks only that category",
                 json_get_int(json_get(&c.reply.data, "total_ranked")) ==
                     2 && rows && json_at(rows, 0) &&
                 json_get_int(json_get(json_at(rows, 0), "points")) ==
                     900 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "category_available")));
        zk_cmd_free(&c);
    }
    return failures;
}

static int zk_commands_bad_category(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "category", "bogus");
        zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
        ZK_CHECK("commands: BAD_CATEGORY named",
                 strcmp(c.reply.error.code, "BAD_CATEGORY") == 0);
        zk_cmd_free(&c);
    }
    return failures;
}

static int zk_commands_unavailable_category(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "category",
                               "verified-bytes-served");
        zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
        ZK_CHECK("commands: unavailable category reports zero honestly",
                 !json_get_bool(json_get(&c.reply.data,
                                         "category_available")) &&
                 json_get_int(json_get(&c.reply.data, "total_ranked")) ==
                     0 &&
                 json_get_str(json_get(&c.reply.data, "category_note")) &&
                 json_get_int(json_get(&c.reply.data, "rendered")) == 0);
        zk_cmd_free(&c);
    }
    return failures;
}

/* paging + breakdown. */
static int zk_commands_paging(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "limit", 1);
        zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
        ZK_CHECK("commands: limit pages the table",
                 json_get_int(json_get(&c.reply.data, "rendered")) == 1 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "items_truncated")));
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const char *first_value =
            json_get_str(json_get(json_at(rows, 0), "contributor"));
        char first[128] = { 0 };
        if (first_value)
            (void)snprintf(first, sizeof(first), "%s", first_value);
        zk_cmd_free(&c);

        struct zk_cmd c2;
        zk_cmd_init(&c2, datadir);
        (void)json_push_kv_int(&c2.input, "limit", 1);
        (void)json_push_kv_int(&c2.input, "offset", 1);
        zcl_native_handle_zcode_leaderboard_all(&c2.request, &c2.reply);
        const struct json_value *rows2 = json_get(&c2.reply.data, "rows");
        const char *second =
            json_get_str(json_get(json_at(rows2, 0), "contributor"));
        ZK_CHECK("commands: offset continues the page",
                 json_get_int(json_get(&c2.reply.data, "rendered")) == 1 &&
                 first[0] && second && strcmp(first, second) != 0 &&
                 json_get_int(json_get(json_at(rows2, 0), "rank")) == 2);
        zk_cmd_free(&c2);
    }
    return failures;
}

static int zk_commands_breakdown(const char *datadir)
{
    int failures = 0;

    {
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_bool(&c.input, "breakdown", true);
        zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        const struct json_value *bd =
            rows && json_at(rows, 0)
                ? json_get(json_at(rows, 0), "category_breakdown")
                : NULL;
        ZK_CHECK("commands: breakdown carries every category honestly",
                 bd &&
                 json_get_int(json_get(bd, "new-packages")) == 900 &&
                 json_get_int(json_get(bd, "verified-bytes-served")) ==
                     0 &&
                 json_get_int(json_get(bd, "distinct-package-users")) ==
                     0);
        zk_cmd_free(&c);
    }
    return failures;
}

/* contributor.show: current-period ranks from the same projection. */
static int zk_commands_contributor_show(const char *datadir,
                                        uint8_t pub1[33])
{
    int failures = 0;

    {
        char pub1_hex[67];
        zk_hex_enc(pub1, 33, pub1_hex);
        struct zk_cmd c;
        zk_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "pubkey", pub1_hex);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_contributor_show(&c.request, &c.reply);
        const struct json_value *ranks =
            json_get(&c.reply.data, "rankings");
        const struct json_value *daily =
            json_get(json_get(ranks, "periods"), "daily");
        const struct json_value *all_time =
            json_get(json_get(ranks, "periods"), "all-time");
        ZK_CHECK("commands: contributor.show carries period ranks",
                 ranks && daily &&
                 json_get_bool(json_get(daily, "ranked")) &&
                 json_get_int(json_get(daily, "rank")) == 1 &&
                 json_get_int(json_get(daily, "points")) == 900 &&
                 json_get_int(json_get(daily, "first_day")) == 20000 &&
                 all_time &&
                 json_get_int(json_get(all_time, "total_ranked")) == 4);
        zk_cmd_free(&c);

        /* A contributor with no points inside the window: unranked,
         * honestly. */
        struct zk_cmd c2;
        zk_cmd_init(&c2, datadir);
        (void)json_push_kv_str(&c2.input, "pubkey", pub1_hex);
        (void)json_push_kv_int(&c2.input, "day", 19999);
        zcl_native_handle_zcode_contributor_show(&c2.request, &c2.reply);
        const struct json_value *daily2 = json_get(
            json_get(&c2.reply.data, "rankings"), "periods");
        ZK_CHECK("commands: no-activity window ranks nobody",
                 daily2 &&
                 !json_get_bool(json_get(json_get(daily2, "daily"),
                                         "ranked")) &&
                 json_get_int(json_get(json_get(daily2, "daily"),
                                       "total_ranked")) == 0);
        zk_cmd_free(&c2);
    }
    return failures;
}

static int t_commands(void)
{
    int failures = 0;
    char datadir[4400], store[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zk_cmd_%ld",
             (long)getpid());
    snprintf(store, sizeof(store), "%s/zcode", datadir);
    zk_rm_rf(datadir);
    ZK_CHECK("commands: datadir created", zk_mkdir_p(store));

    uint8_t pub1[33], pub2[33], pub3[33], pub4[33];
    failures += zk_commands_fixture_keys(pub1, pub2, pub3, pub4);
    failures += zk_commands_settle(store);
    failures += zk_commands_daily(datadir, pub3);
    failures += zk_commands_weekly_window(datadir);
    failures += zk_commands_monthly_window(datadir);
    failures += zk_commands_all_time_window(datadir);
    failures += zk_commands_category_filter(datadir);
    failures += zk_commands_bad_category(datadir);
    failures += zk_commands_unavailable_category(datadir);
    failures += zk_commands_paging(datadir);
    failures += zk_commands_breakdown(datadir);
    failures += zk_commands_contributor_show(datadir, pub1);
    zk_rm_rf(datadir);
    return failures;
}

#if !defined(_WIN32)
/* Controls for zk_rm_rf. Each case builds <base>/target/keep and the symbolic
 * link <base>/link -> target (a relative sibling name, so the link can only
 * resolve to the directory the case just created), runs the remover on the
 * link, and requires the link gone with the directory and the sentinel
 * content intact. The trailing-separator case passes "<base>/link/". The
 * case cleanup unlinks the link first, then removes the sentinel and the
 * two directories with non-recursive calls. */
static const char zk_nofollow_text[] = "keep-me";

static bool zk_nofollow_fixture(const char *target, const char *keep,
                                 const char *link)
{
    if (mkdir(target, 0700) != 0)
        return false;
    FILE *f = fopen(keep, "wb");
    if (!f)
        return false;
    size_t want = sizeof(zk_nofollow_text) - 1;
    bool wrote = fwrite(zk_nofollow_text, 1, want, f) == want;
    if (fclose(f) != 0 || !wrote)
        return false;
    return symlink("target", link) == 0;
}

static bool zk_nofollow_text_intact(const char *keep)
{
    char buf[32];
    FILE *f = fopen(keep, "rb");
    if (!f)
        return false;
    size_t got = fread(buf, 1, sizeof(buf), f);
    bool read_ok = ferror(f) == 0;
    bool closed = fclose(f) == 0;
    size_t want = sizeof(zk_nofollow_text) - 1;
    return read_ok && closed && got == want &&
           memcmp(buf, zk_nofollow_text, want) == 0;
}

static bool zk_nofollow_cleanup(const char *base, const char *target,
                                 const char *keep, const char *link)
{
    struct stat st;
    bool ok = true;
    if (lstat(link, &st) == 0 && unlink(link) != 0)
        ok = false;
    if (unlink(keep) != 0)
        ok = false;
    if (rmdir(target) != 0)
        ok = false;
    if (rmdir(base) != 0)
        ok = false;
    return ok;
}

static bool zk_nofollow_run(bool trailing_sep)
{
    char base[512], target[640], keep[704], link[640], arg[648];
    test_make_tmpdir(base, sizeof(base), "zcode_rank",
                     trailing_sep ? "nofollow_slash" : "nofollow_link");
    snprintf(target, sizeof(target), "%s/target", base);
    snprintf(keep, sizeof(keep), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", base);
    snprintf(arg, sizeof(arg), trailing_sep ? "%s/" : "%s", link);

    bool linked = zk_nofollow_fixture(target, keep, link);
    bool removed = false;
    if (linked)
        removed = zk_rm_rf(arg);

    struct stat st;
    bool link_gone = lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = zk_nofollow_text_intact(keep);
    bool target_kept = stat(target, &st) == 0 && S_ISDIR(st.st_mode);
    bool clean = zk_nofollow_cleanup(base, target, keep, link);

    bool ok = linked & removed & link_gone & kept & target_kept & clean;
    if (!ok)
        printf("  zcode_rank: nofollow (%s) linked=%d removed=%d link_gone=%d "
               "kept=%d target_kept=%d clean=%d\n",
               trailing_sep ? "trailing separator" : "plain link", linked,
               removed, link_gone, kept, target_kept, clean);
    return ok;
}

static int zk_nofollow_plain_link(void)
{
    int failures = 0;
    ZK_CHECK("remover unlinks a symbolic link and keeps its target",
          zk_nofollow_run(false));
    return failures;
}

static int zk_nofollow_trailing_sep(void)
{
    int failures = 0;
    ZK_CHECK("remover keeps the target of a symbolic link named with a trailing separator",
          zk_nofollow_run(true));
    return failures;
}
#endif /* !_WIN32 */

int test_zcode_rank(void)
{
    printf("\n=== zcode_rank: ZCODE Rankings (slice 9) ===\n");
    int failures = 0;
    failures += t_windows();
    failures += t_projection();
    failures += t_transfer_immunity();
    failures += t_rebuild();
    failures += t_period_boundaries();
    failures += t_commands();
#if !defined(_WIN32)
    failures += zk_nofollow_plain_link();
    failures += zk_nofollow_trailing_sep();
#endif
    printf("=== zcode_rank complete: %d failure(s) ===\n", failures);
    return failures;
}
