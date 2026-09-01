/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_badge_eligible — ZCODE Badge eligibility and the plan/commit
 * issuance flow (slice 10). See vcs/package_badge_eligible.h for the
 * frozen contract. The evaluator is pure (facts + "today" in, verdict
 * out); the facts builder derives from the slice-3 package index, the
 * slice-8 reward ledger, and the slice-9 rank projections; the issue
 * commit re-validates against CURRENT facts and the CURRENT store
 * before writing, persists signed badge wires (dedup by badge id), and
 * writes the commit record LAST. Signing happens through the caller's
 * callback — private keys never enter contexts/commons/modules/vcs. */

#include "vcs/package_badge_eligible.h"

#include "crypto/sha3.h"
#include "base/hex.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/package_rank.h"

#include "vcs_priv.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BELIG_LOG "vcs.badge_eligible"

static const uint8_t k_domain_evidence[] = "zcl.zcode_badge_evidence.v1";

void vcs_badge_evidence_hash(enum vcs_badge_type type,
                             const uint8_t contributor[33],
                             int64_t period_first, int64_t period_last,
                             uint64_t quantity, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, k_domain_evidence, sizeof(k_domain_evidence));
    uint8_t b[8];
    b[0] = (uint8_t)type;
    sha3_256_write(&c, b, 1);
    sha3_256_write(&c, contributor, 33);
    vcs_wr_u64le(b, (uint64_t)period_first);
    sha3_256_write(&c, b, 8);
    vcs_wr_u64le(b, (uint64_t)period_last);
    sha3_256_write(&c, b, 8);
    vcs_wr_u64le(b, quantity);
    sha3_256_write(&c, b, 8);
    sha3_256_finalize(&c, out);
}

/* ── the facts builder ──────────────────────────────────────────────── */

struct belig_pub_release {
    uint64_t sequence;
    uint8_t root[32];
};

static int belig_pub_release_cmp(const void *a, const void *b)
{
    const struct belig_pub_release *ra = a;
    const struct belig_pub_release *rb = b;
    if (ra->sequence != rb->sequence)
        return ra->sequence < rb->sequence ? -1 : 1;
    return memcmp(ra->root, rb->root, 32);
}

/* Publish facts: the contributor's releases in sequence order; the first
 * package root and the 10th DISTINCT root by first appearance. */
static void belig_facts_publish(const uint8_t contributor[33],
                                const struct vcs_package_index *index,
                                struct vcs_badge_facts *out)
{
    if (!index)
        return;
    char pub_hex[67];
    zcl_hex_encode(contributor, 33, pub_hex);
    size_t count = vcs_package_index_count(index);
    struct belig_pub_release *rels =
        zcl_calloc(count ? count : 1, sizeof(*rels), "belig_pub_releases");
    if (!rels) {
        LOG_ERROR(BELIG_LOG, "alloc %zu publish rows", count);
        return;
    }
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        const struct vcs_package_index_entry *e =
            vcs_package_index_at(index, i);
        if (!e || strcmp(e->publisher_hex, pub_hex) != 0)
            continue;
        rels[n].sequence = e->publisher_sequence;
        if (!zcl_hex_decode_lower(e->package_root_hex, rels[n].root, 32))
            continue;
        n++;
    }
    qsort(rels, n, sizeof(*rels), belig_pub_release_cmp);
    out->release_count = (uint32_t)n;
    uint8_t distinct[VCS_BADGE_TEN_PACKAGES_COUNT][32];
    size_t distinct_count = 0;
    for (size_t i = 0; i < n; i++) {
        bool seen = false;
        for (size_t j = 0; j < distinct_count && !seen; j++)
            seen = memcmp(distinct[j], rels[i].root, 32) == 0;
        if (seen)
            continue;
        if (distinct_count == 0) {
            out->has_first_package = true;
            memcpy(out->first_package_root, rels[i].root, 32);
        }
        if (distinct_count < VCS_BADGE_TEN_PACKAGES_COUNT)
            memcpy(distinct[distinct_count], rels[i].root, 32);
        distinct_count++;
        if (distinct_count == VCS_BADGE_TEN_PACKAGES_COUNT &&
            !out->has_tenth_package) {
            out->has_tenth_package = true;
            memcpy(out->tenth_package_root, rels[i].root, 32);
        }
    }
    out->distinct_package_count = (uint32_t)distinct_count;
    free(rels);
}

struct belig_test_fact {
    int64_t day;
    uint8_t entry_id[32];
    uint8_t release_root[32];
    uint32_t points;
};

static int belig_test_fact_cmp(const void *a, const void *b)
{
    const struct belig_test_fact *fa = a;
    const struct belig_test_fact *fb = b;
    if (fa->day != fb->day)
        return fa->day < fb->day ? -1 : 1;
    return memcmp(fa->entry_id, fb->entry_id, 32);
}

/* The earliest settled fact of `category` by (day, entry id). */
static void belig_earliest_category(
    const struct vcs_reward_fact_view *facts, const bool *mine,
    size_t fact_count, enum vcs_reward_category category, bool *has_out,
    int64_t *day_out, uint8_t root_out[32])
{
    int64_t best_day = INT64_MAX;
    const uint8_t *best_id = NULL;
    const uint8_t *best_root = NULL;
    for (size_t i = 0; i < fact_count; i++) {
        if (!mine[i] || facts[i].category != category)
            continue;
        if (facts[i].day < best_day ||
            (facts[i].day == best_day &&
             memcmp(facts[i].entry_id, best_id, 32) < 0)) {
            best_day = facts[i].day;
            best_id = facts[i].entry_id;
            best_root = facts[i].release_root;
        }
    }
    if (best_root) {
        *has_out = true;
        *day_out = best_day;
        memcpy(root_out, best_root, 32);
    }
}

/* Ledger facts: spans, thresholds, per-category firsts, and the
 * whole-ledger earliest day. */
static void belig_facts_ledger(const uint8_t contributor[33],
                               const struct vcs_reward_ledger *ledger,
                               struct vcs_badge_facts *out)
{
    if (!ledger)
        return;
    size_t fact_count = vcs_reward_ledger_fact_count(ledger);
    if (fact_count == 0)
        return;
    struct vcs_reward_fact_view *facts =
        zcl_calloc(fact_count, sizeof(*facts), "belig_facts");
    bool *mine = zcl_calloc(fact_count, sizeof(*mine), "belig_mine");
    struct belig_test_fact *tests =
        zcl_calloc(fact_count, sizeof(*tests), "belig_tests");
    if (!facts || !mine || !tests) {
        LOG_ERROR(BELIG_LOG, "alloc %zu fact rows", fact_count);
        free(facts);
        free(mine);
        free(tests);
        return;
    }
    size_t test_count = 0;
    out->ledger_any = true;
    out->ledger_earliest_day = INT64_MAX;
    for (size_t i = 0; i < fact_count; i++) {
        if (!vcs_reward_ledger_fact_at(ledger, i, &facts[i]))
            continue;
        if (facts[i].day < out->ledger_earliest_day)
            out->ledger_earliest_day = facts[i].day;
        if (memcmp(facts[i].contributor, contributor, 33) != 0)
            continue;
        mine[i] = true;
        if (!out->has_settled) {
            out->has_settled = true;
            out->earliest_settled_day = facts[i].day;
            out->latest_settled_day = facts[i].day;
        } else {
            if (facts[i].day < out->earliest_settled_day)
                out->earliest_settled_day = facts[i].day;
            if (facts[i].day > out->latest_settled_day)
                out->latest_settled_day = facts[i].day;
        }
        if (facts[i].category == VCS_REWARD_CATEGORY_TEST_CONTRIBUTION) {
            struct belig_test_fact *t = &tests[test_count++];
            t->day = facts[i].day;
            memcpy(t->entry_id, facts[i].entry_id, 32);
            memcpy(t->release_root, facts[i].release_root, 32);
            t->points = facts[i].points;
            out->test_points_total += facts[i].points;
        }
    }
    /* The hundred-tests crossing: cumulative settled test points in
     * (day, entry id) order; the first day the threshold is reached. */
    qsort(tests, test_count, sizeof(*tests), belig_test_fact_cmp);
    uint64_t cumulative = 0;
    for (size_t i = 0; i < test_count && !out->hundred_tests_crossed; i++) {
        cumulative += tests[i].points;
        if (cumulative >= VCS_BADGE_HUNDRED_TESTS_POINTS) {
            out->hundred_tests_crossed = true;
            out->hundred_tests_day = tests[i].day;
            memcpy(out->hundred_tests_root, tests[i].release_root, 32);
        }
    }
    belig_earliest_category(facts, mine, fact_count,
                            VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION,
                            &out->has_bug_fix, &out->bug_fix_day,
                            out->bug_fix_root);
    belig_earliest_category(facts, mine, fact_count,
                            VCS_REWARD_CATEGORY_SECURITY_FIX,
                            &out->has_security_fix, &out->security_fix_day,
                            out->security_fix_root);
    belig_earliest_category(facts, mine, fact_count,
                            VCS_REWARD_CATEGORY_BUILD_REPRODUCTION,
                            &out->has_reproduction, &out->reproduction_day,
                            out->reproduction_root);
    free(facts);
    free(mine);
    free(tests);
}

/* Rank-1 facts: true when the contributor holds rank 1 overall in the
 * `period` window containing `today_day` (the same projection the
 * leaderboard leaves serve). */
static void belig_facts_rank_one(const uint8_t contributor[33],
                                 const struct vcs_reward_ledger *ledger,
                                 enum vcs_rank_period period,
                                 int64_t today_day, bool *top_out,
                                 uint64_t *points_out)
{
    *top_out = false;
    *points_out = 0;
    if (!ledger)
        return;
    struct vcs_rank_window window;
    if (!vcs_rank_window_for(period, today_day, &window))
        return;
    struct vcs_rank_projection *p =
        vcs_rank_projection_build(ledger, &window);
    if (!p)
        return;
    struct vcs_rank_entry first;
    size_t total = vcs_rank_table(p, VCS_RANK_CATEGORY_OVERALL, &first, 1);
    if (total > 0 && memcmp(first.contributor, contributor, 33) == 0) {
        *top_out = true;
        *points_out = first.points;
    }
    vcs_rank_projection_free(p);
}

void vcs_badge_facts_build(const uint8_t contributor[33],
                           const struct vcs_package_index *index,
                           const struct vcs_reward_ledger *ledger,
                           int64_t today_day, struct vcs_badge_facts *out)
{
    if (!contributor || !out) {
        LOG_ERROR(BELIG_LOG, "null facts build");
        return;
    }
    memset(out, 0, sizeof(*out));
    belig_facts_publish(contributor, index, out);
    belig_facts_ledger(contributor, ledger, out);
    belig_facts_rank_one(contributor, ledger, VCS_RANK_PERIOD_DAILY,
                         today_day, &out->top_daily,
                         &out->top_daily_points);
    belig_facts_rank_one(contributor, ledger, VCS_RANK_PERIOD_WEEKLY,
                         today_day, &out->top_weekly,
                         &out->top_weekly_points);
    belig_facts_rank_one(contributor, ledger, VCS_RANK_PERIOD_MONTHLY,
                         today_day, &out->top_monthly,
                         &out->top_monthly_points);
}

/* ── the pure evaluator ─────────────────────────────────────────────── */

static void belig_eval_period(struct vcs_badge_eval *out, int64_t first,
                              int64_t last)
{
    out->period_first = first;
    out->period_last = last;
}

static void belig_eval_unavailable(struct vcs_badge_eval *out,
                                   const char *reason)
{
    out->available = false;
    out->eligible = false;
    snprintf(out->detail, sizeof(out->detail), "%s", reason);
}

static void belig_eval_no(struct vcs_badge_eval *out, const char *fmt, ...)
{
    out->eligible = false;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out->detail, sizeof(out->detail), fmt, ap);
    va_end(ap);
}

bool vcs_badge_evaluate(enum vcs_badge_type type,
                        const uint8_t contributor[33],
                        const struct vcs_badge_facts *facts,
                        int64_t today_day, struct vcs_badge_eval *out)
{
    if (!contributor || !facts || !out)
        LOG_RETURN(false, BELIG_LOG, "null evaluate");
    if (type < VCS_BADGE_FIRST_PACKAGE || type >= VCS_BADGE_TYPE_COUNT)
        LOG_RETURN(false, BELIG_LOG, "badge type %d out of range",
                   (int)type);
    memset(out, 0, sizeof(*out));
    out->type = type;
    out->available = vcs_badge_type_available(type);
    out->period_first = VCS_BADGE_PERIOD_NONE;
    out->period_last = VCS_BADGE_PERIOD_NONE;
    snprintf(out->detail, sizeof(out->detail), "not eligible");
    if (!out->available) {
        belig_eval_unavailable(
            out, "needs P2P facts that arrive with slices 11-12; "
                 "honestly unavailable in v1 — never faked");
        return true;
    }

    switch (type) {
    case VCS_BADGE_FIRST_PACKAGE:
        if (!facts->has_first_package) {
            belig_eval_no(out, "no published releases");
            return true;
        }
        out->eligible = true;
        memcpy(out->evidence_root, facts->first_package_root, 32);
        snprintf(out->detail, sizeof(out->detail),
                 "%u release(s) published", facts->release_count);
        return true;

    case VCS_BADGE_TEN_PACKAGES:
        if (!facts->has_tenth_package) {
            belig_eval_no(out, "%u distinct packages (need %u)",
                          facts->distinct_package_count,
                          (unsigned)VCS_BADGE_TEN_PACKAGES_COUNT);
            return true;
        }
        out->eligible = true;
        memcpy(out->evidence_root, facts->tenth_package_root, 32);
        snprintf(out->detail, sizeof(out->detail),
                 "%u distinct packages published",
                 facts->distinct_package_count);
        return true;

    case VCS_BADGE_HUNDRED_TESTS:
        if (!facts->hundred_tests_crossed) {
            belig_eval_no(out, "%llu settled test points (need %u)",
                          (unsigned long long)facts->test_points_total,
                          (unsigned)VCS_BADGE_HUNDRED_TESTS_POINTS);
            return true;
        }
        out->eligible = true;
        belig_eval_period(out, facts->hundred_tests_day,
                          facts->hundred_tests_day);
        memcpy(out->evidence_root, facts->hundred_tests_root, 32);
        snprintf(out->detail, sizeof(out->detail),
                 "%llu settled test points crossed %u on day %lld",
                 (unsigned long long)facts->test_points_total,
                 (unsigned)VCS_BADGE_HUNDRED_TESTS_POINTS,
                 (long long)facts->hundred_tests_day);
        return true;

    case VCS_BADGE_BUG_HUNTER:
        if (!facts->has_bug_fix) {
            belig_eval_no(out, "no settled bug-fix-with-regression-test "
                               "reward (manual categories settle after "
                               "owner review, slice 14)");
            return true;
        }
        out->eligible = true;
        belig_eval_period(out, facts->bug_fix_day, facts->bug_fix_day);
        memcpy(out->evidence_root, facts->bug_fix_root, 32);
        snprintf(out->detail, sizeof(out->detail),
                 "first settled bug fix on day %lld",
                 (long long)facts->bug_fix_day);
        return true;

    case VCS_BADGE_SECURITY_RESEARCHER:
        if (!facts->has_security_fix) {
            belig_eval_no(out, "no settled security-fix reward (manual "
                               "categories settle after owner review, "
                               "slice 14)");
            return true;
        }
        out->eligible = true;
        belig_eval_period(out, facts->security_fix_day,
                          facts->security_fix_day);
        memcpy(out->evidence_root, facts->security_fix_root, 32);
        snprintf(out->detail, sizeof(out->detail),
                 "first settled security fix on day %lld",
                 (long long)facts->security_fix_day);
        return true;

    case VCS_BADGE_REPRODUCIBLE_BUILDER:
        if (!facts->has_reproduction) {
            belig_eval_no(out, "no settled independent-build-reproduction "
                               "reward (manual categories settle after "
                               "owner review, slice 14)");
            return true;
        }
        out->eligible = true;
        belig_eval_period(out, facts->reproduction_day,
                          facts->reproduction_day);
        memcpy(out->evidence_root, facts->reproduction_root, 32);
        snprintf(out->detail, sizeof(out->detail),
                 "first settled build reproduction on day %lld",
                 (long long)facts->reproduction_day);
        return true;

    case VCS_BADGE_TOP_DAILY:
    case VCS_BADGE_TOP_WEEKLY:
    case VCS_BADGE_TOP_MONTHLY: {
        enum vcs_rank_period period =
            type == VCS_BADGE_TOP_DAILY    ? VCS_RANK_PERIOD_DAILY
            : type == VCS_BADGE_TOP_WEEKLY ? VCS_RANK_PERIOD_WEEKLY
                                           : VCS_RANK_PERIOD_MONTHLY;
        bool top = type == VCS_BADGE_TOP_DAILY    ? facts->top_daily
                   : type == VCS_BADGE_TOP_WEEKLY ? facts->top_weekly
                                                  : facts->top_monthly;
        uint64_t points =
            type == VCS_BADGE_TOP_DAILY    ? facts->top_daily_points
            : type == VCS_BADGE_TOP_WEEKLY ? facts->top_weekly_points
                                           : facts->top_monthly_points;
        const char *label = type == VCS_BADGE_TOP_DAILY    ? "day"
                            : type == VCS_BADGE_TOP_WEEKLY ? "ISO week"
                                                           : "month";
        if (!top) {
            belig_eval_no(out, "not rank 1 overall for the current %s",
                          label);
            return true;
        }
        struct vcs_rank_window window;
        if (!vcs_rank_window_for(period, today_day, &window))
            LOG_RETURN(false, BELIG_LOG, "window for %s", label);
        out->eligible = true;
        belig_eval_period(out, window.first_day, window.last_day);
        vcs_badge_evidence_hash(type, contributor, window.first_day,
                                window.last_day, points,
                                out->evidence_root);
        snprintf(out->detail, sizeof(out->detail),
                 "rank 1 overall with %llu points for the %s",
                 (unsigned long long)points, label);
        return true;
    }

    case VCS_BADGE_ONE_YEAR_MAINTAINER:
        if (!facts->has_settled ||
            facts->latest_settled_day - facts->earliest_settled_day <
                VCS_BADGE_ONE_YEAR_SPAN_DAYS) {
            belig_eval_no(out, "settled span %lld days (need %d)",
                          (long long)(facts->has_settled
                                          ? facts->latest_settled_day -
                                                facts->earliest_settled_day
                                          : 0),
                          VCS_BADGE_ONE_YEAR_SPAN_DAYS);
            return true;
        }
        {
            int64_t achievement_day =
                facts->earliest_settled_day + VCS_BADGE_ONE_YEAR_SPAN_DAYS;
            int64_t span =
                facts->latest_settled_day - facts->earliest_settled_day;
            out->eligible = true;
            belig_eval_period(out, achievement_day, achievement_day);
            vcs_badge_evidence_hash(type, contributor, achievement_day,
                                    achievement_day, (uint64_t)span,
                                    out->evidence_root);
            snprintf(out->detail, sizeof(out->detail),
                     "maintained %lld days (settled days %lld..%lld)",
                     (long long)span,
                     (long long)facts->earliest_settled_day,
                     (long long)facts->latest_settled_day);
        }
        return true;

    case VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR:
        if (!facts->has_settled || !facts->ledger_any ||
            facts->earliest_settled_day >
                facts->ledger_earliest_day + VCS_BADGE_EARLY_WINDOW_DAYS) {
            belig_eval_no(out,
                          facts->has_settled
                              ? "first settled day %lld is outside the "
                                "%d-day pioneer window of the ledger's "
                                "first settled day %lld"
                              : "no settled rewards",
                          (long long)facts->earliest_settled_day,
                          VCS_BADGE_EARLY_WINDOW_DAYS,
                          (long long)facts->ledger_earliest_day);
            return true;
        }
        out->eligible = true;
        vcs_badge_evidence_hash(type, contributor, VCS_BADGE_PERIOD_NONE,
                                VCS_BADGE_PERIOD_NONE,
                                (uint64_t)facts->earliest_settled_day,
                                out->evidence_root);
        snprintf(out->detail, sizeof(out->detail),
                 "first settled day %lld within %d days of the ledger's "
                 "first settled day %lld",
                 (long long)facts->earliest_settled_day,
                 VCS_BADGE_EARLY_WINDOW_DAYS,
                 (long long)facts->ledger_earliest_day);
        return true;

    case VCS_BADGE_POPULAR_PACKAGE:
    case VCS_BADGE_RARE_PACKAGE_SEEDER:
    case VCS_BADGE_TYPE_COUNT:
        break; /* handled by the availability check above */
    }
    return true;
}

/* ── plan build ─────────────────────────────────────────────────────── */

bool vcs_badge_plan_build(const struct vcs_badge_store *store,
                          const struct vcs_badge_policy *policy,
                          const uint8_t contributor[33],
                          const struct vcs_badge_facts *facts,
                          int64_t today_day, struct vcs_badge_plan *out,
                          struct vcs_badge_plan_exclusion *exclusions,
                          size_t *exclusion_count_out)
{
    if (!store || !policy || !contributor || !facts || !out ||
        !exclusions || !exclusion_count_out)
        LOG_RETURN(false, BELIG_LOG, "null plan build");
    struct vcs_badge_plan_row rows[VCS_BADGE_TYPE_COUNT];
    size_t row_count = 0;
    size_t exclusion_count = 0;
    uint64_t next_sequence =
        vcs_badge_store_max_sequence(store, policy->issuer_pubkey) + 1;
    for (size_t i = 0; i < VCS_BADGE_TYPE_COUNT; i++) {
        enum vcs_badge_type type = (enum vcs_badge_type)i;
        struct vcs_badge_eval eval;
        if (!vcs_badge_evaluate(type, contributor, facts, today_day,
                                &eval))
            LOG_RETURN(false, BELIG_LOG, "evaluate type %zu", i);
        struct vcs_badge_plan_exclusion *ex =
            &exclusions[exclusion_count];
        if (!eval.available) {
            ex->type = type;
            snprintf(ex->rule, sizeof(ex->rule), "%s",
                     VCS_BADGE_RULE_UNAVAILABLE);
            snprintf(ex->detail, sizeof(ex->detail), "%s", eval.detail);
            exclusion_count++;
            continue;
        }
        if (!eval.eligible) {
            ex->type = type;
            snprintf(ex->rule, sizeof(ex->rule), "%s",
                     VCS_BADGE_RULE_NOT_ELIGIBLE);
            snprintf(ex->detail, sizeof(ex->detail), "%s", eval.detail);
            exclusion_count++;
            continue;
        }
        if (vcs_badge_store_dedup_hit(store, policy, contributor, type,
                                      eval.period_first,
                                      eval.period_last)) {
            ex->type = type;
            snprintf(ex->rule, sizeof(ex->rule), "%s",
                     VCS_BADGE_RULE_DUPLICATE);
            snprintf(ex->detail, sizeof(ex->detail),
                     "already issued for this contributor and period: %s",
                     eval.detail);
            exclusion_count++;
            continue;
        }
        struct vcs_badge_plan_row *row = &rows[row_count++];
        memcpy(row->contributor, contributor, 33);
        row->type = type;
        row->period_first = eval.period_first;
        row->period_last = eval.period_last;
        memcpy(row->evidence_root, eval.evidence_root, 32);
        row->sequence = next_sequence++;
    }
    *exclusion_count_out = exclusion_count;
    return vcs_badge_plan_assemble(policy->policy_id,
                                   policy->issuer_pubkey, today_day, rows,
                                   row_count, out);
}

/* ── issue ──────────────────────────────────────────────────────────── */

const char *vcs_badge_issue_error_string(enum vcs_badge_issue_error err)
{
    switch (err) {
    case VCS_BADGE_ISSUE_OK: return "ok";
    case VCS_BADGE_ISSUE_UNKNOWN_PLAN: return "unknown-plan";
    case VCS_BADGE_ISSUE_ALREADY_ISSUED: return "already-issued";
    case VCS_BADGE_ISSUE_PLAN_CORRUPT: return "plan-corrupt";
    case VCS_BADGE_ISSUE_POLICY_MISMATCH: return "policy-mismatch";
    case VCS_BADGE_ISSUE_STALE: return "stale-plan";
    case VCS_BADGE_ISSUE_SIGN: return "sign-failure";
    case VCS_BADGE_ISSUE_IO: return "io-failure";
    }
    return "unknown-error";
}

enum vcs_badge_issue_error vcs_badge_issue(
    struct vcs_badge_store *store, const struct vcs_badge_policy *policy,
    const uint8_t plan_id[32], const struct vcs_package_index *index,
    const struct vcs_reward_ledger *ledger, vcs_badge_sign_fn sign,
    void *sign_ctx, struct vcs_badge_issue_result *out, char *detail,
    size_t detail_size)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (detail && detail_size > 0)
        detail[0] = '\0';
    if (!store || !policy || !plan_id || !sign || !out)
        LOG_RETURN(VCS_BADGE_ISSUE_IO, BELIG_LOG, "null issue");
    if (vcs_badge_commit_known(store, plan_id))
        return VCS_BADGE_ISSUE_ALREADY_ISSUED;
    struct vcs_badge_plan plan;
    int read = vcs_badge_plan_read(store, plan_id, &plan);
    if (read != 0)
        return read > 0 ? VCS_BADGE_ISSUE_UNKNOWN_PLAN
                        : VCS_BADGE_ISSUE_PLAN_CORRUPT;
    if (memcmp(plan.policy_id, policy->policy_id, 32) != 0 ||
        memcmp(plan.issuer_pubkey, policy->issuer_pubkey, 33) != 0) {
        if (detail && detail_size > 0)
            snprintf(detail, detail_size,
                     "the plan's policy id or issuer key is not the "
                     "configured badge policy");
        return VCS_BADGE_ISSUE_POLICY_MISMATCH;
    }

    /* PASS 1 — re-validate every row against CURRENT facts (rebuilt at
     * the plan's recorded day, never the wall clock) and the CURRENT
     * store. Rows are sorted by contributor, so the facts rebuild runs
     * once per distinct contributor. Nothing is written in this pass. */
    {
        struct vcs_badge_facts facts;
        bool facts_valid = false;
        uint8_t facts_contributor[33];
        memset(facts_contributor, 0, sizeof(facts_contributor));
        for (size_t i = 0; i < plan.row_count; i++) {
            const struct vcs_badge_plan_row *r = &plan.rows[i];
            if (!facts_valid ||
                memcmp(facts_contributor, r->contributor, 33) != 0) {
                vcs_badge_facts_build(r->contributor, index, ledger,
                                      plan.planned_day, &facts);
                memcpy(facts_contributor, r->contributor, 33);
                facts_valid = true;
            }
            struct vcs_badge_eval eval;
            if (!vcs_badge_evaluate(r->type, r->contributor, &facts,
                                    plan.planned_day, &eval))
                LOG_RETURN(VCS_BADGE_ISSUE_IO, BELIG_LOG,
                           "re-evaluate row %zu", i);
            /* The would-be badge id first: a row whose EXACT badge is
             * already durable is a crash replay, not a duplicate — the
             * dedup rule and the sequence check apply only to fresh
             * content. */
            struct vcs_badge would;
            memset(&would, 0, sizeof(would));
            would.schema_version = VCS_PACKAGE_BADGE_VERSION;
            would.type = (uint8_t)r->type;
            memcpy(would.recipient, r->contributor, 33);
            would.period_first_day = r->period_first;
            would.period_last_day = r->period_last;
            memcpy(would.evidence_root, r->evidence_root, 32);
            memcpy(would.policy_id, plan.policy_id, 32);
            would.sequence = r->sequence;
            memcpy(would.issuer_pubkey, plan.issuer_pubkey, 33);
            uint8_t would_id[32];
            if (vcs_badge_id(&would, would_id) != VCS_BADGE_OK)
                LOG_RETURN(VCS_BADGE_ISSUE_IO, BELIG_LOG,
                           "badge id for row %zu", i);
            const char *rule = NULL;
            if (!eval.available || !eval.eligible)
                rule = VCS_BADGE_RULE_NOT_ELIGIBLE;
            else if (eval.period_first != r->period_first ||
                     eval.period_last != r->period_last)
                rule = VCS_BADGE_RULE_PERIOD_CHANGED;
            else if (memcmp(eval.evidence_root, r->evidence_root, 32) != 0)
                rule = VCS_BADGE_RULE_EVIDENCE_CHANGED;
            else if (!vcs_badge_store_find(store, would_id) &&
                     vcs_badge_store_dedup_hit(store, policy,
                                               r->contributor, r->type,
                                               r->period_first,
                                               r->period_last))
                rule = VCS_BADGE_RULE_DUPLICATE;
            if (rule) {
                if (detail && detail_size > 0)
                    snprintf(detail, detail_size,
                             "row %zu (%s): %s", i,
                             vcs_badge_type_string(r->type), rule);
                return VCS_BADGE_ISSUE_STALE;
            }
            /* Sequence conflict: a persisted badge by this issuer already
             * carries this sequence with DIFFERENT content (the identical
             * badge id is the crash replay, accepted above). */
            if (!vcs_badge_store_find(store, would_id)) {
                for (size_t j = 0; j < vcs_badge_store_badge_count(store);
                     j++) {
                    const struct vcs_badge *b =
                        vcs_badge_store_at(store, j);
                    if (b->sequence == r->sequence &&
                        memcmp(b->issuer_pubkey, plan.issuer_pubkey, 33) ==
                            0) {
                        if (detail && detail_size > 0)
                            snprintf(detail, detail_size,
                                     "row %zu (%s): sequence-conflict", i,
                                     vcs_badge_type_string(r->type));
                        return VCS_BADGE_ISSUE_STALE;
                    }
                }
            }
        }
    }

    /* PASS 2 — sign and persist every fresh badge (dedup by badge id:
     * a crash replay writes nothing twice), then the commit record
     * LAST. */
    uint8_t (*badge_ids)[32] = NULL;
    if (plan.row_count > 0) {
        badge_ids = zcl_calloc(plan.row_count, sizeof(*badge_ids),
                               "badge_issue_ids");
        if (!badge_ids)
            LOG_RETURN(VCS_BADGE_ISSUE_IO, BELIG_LOG,
                       "alloc %zu badge ids", plan.row_count);
    }
    enum vcs_badge_issue_error err = VCS_BADGE_ISSUE_OK;
    uint32_t issued = 0, replayed = 0;
    for (size_t i = 0; i < plan.row_count; i++) {
        const struct vcs_badge_plan_row *r = &plan.rows[i];
        struct vcs_badge badge;
        memset(&badge, 0, sizeof(badge));
        badge.schema_version = VCS_PACKAGE_BADGE_VERSION;
        badge.type = (uint8_t)r->type;
        memcpy(badge.recipient, r->contributor, 33);
        badge.period_first_day = r->period_first;
        badge.period_last_day = r->period_last;
        memcpy(badge.evidence_root, r->evidence_root, 32);
        memcpy(badge.policy_id, plan.policy_id, 32);
        badge.sequence = r->sequence;
        memcpy(badge.issuer_pubkey, plan.issuer_pubkey, 33);
        uint8_t badge_id[32];
        if (vcs_badge_id(&badge, badge_id) != VCS_BADGE_OK) {
            err = VCS_BADGE_ISSUE_IO;
            goto done;
        }
        memcpy(badge_ids[i], badge_id, 32);
        if (vcs_badge_store_find(store, badge_id)) {
            replayed++;
            continue; /* crash resume: the identical badge is durable */
        }
        if (!sign(&badge, badge_id, sign_ctx) ||
            vcs_badge_verify(&badge) != VCS_BADGE_OK) {
            if (detail && detail_size > 0)
                snprintf(detail, detail_size,
                         "row %zu (%s): the signer failed or produced a "
                         "bad signature", i,
                         vcs_badge_type_string(r->type));
            err = VCS_BADGE_ISSUE_SIGN;
            goto done;
        }
        uint8_t persisted_id[32];
        enum vcs_badge_persist_error perr =
            vcs_badge_store_persist(store, &badge, persisted_id);
        if (perr == VCS_BADGE_PERSIST_DUPLICATE) {
            replayed++;
            continue;
        }
        if (perr != VCS_BADGE_PERSIST_OK) {
            if (detail && detail_size > 0)
                snprintf(detail, detail_size, "row %zu (%s): persist: %s",
                         i, vcs_badge_type_string(r->type),
                         vcs_badge_persist_error_string(perr));
            err = VCS_BADGE_ISSUE_IO;
            goto done;
        }
        issued++;
    }
    if (!vcs_badge_commit_record_write(store, plan_id, badge_ids,
                                       plan.row_count))
        err = VCS_BADGE_ISSUE_IO;

done:
    if (err == VCS_BADGE_ISSUE_OK) {
        out->issued_count = issued + replayed;
        out->replayed_count = replayed;
        out->resumed = replayed > 0;
    }
    free(badge_ids);
    return err;
}
