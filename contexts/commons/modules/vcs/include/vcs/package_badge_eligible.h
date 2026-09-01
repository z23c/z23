/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_badge_eligible — ZCODE Badge eligibility (slice 10): which
 * badge a contributor qualifies for RIGHT NOW, derived from EXISTING
 * facts only — the slice-8 reward-history ledger (settled earned-score
 * facts), the slice-9 rankings projection, and the slice-3 publish
 * history (the package index). Plus the plan/commit issuance flow on
 * top of the package_badge.* persistence primitives.
 *
 * THE HONESTY RULE: badge types whose evidence needs P2P facts that do
 * not exist yet (POPULAR_PACKAGE, RARE_PACKAGE_SEEDER — slices 11-12)
 * are named UNAVAILABLE and are never eligible — no fake data, ever.
 * Manual reward categories (bug-fix, security-fix, build reproduction)
 * settle only after owner review (slice 14), so BUG_HUNTER,
 * SECURITY_RESEARCHER, and REPRODUCIBLE_BUILDER read SETTLED facts only
 * and are honestly not-eligible until those facts exist.
 *
 * THE PURE CORE: vcs_badge_evaluate() is pure — no filesystem, no
 * wall-clock; the caller passes the facts and "today". The production
 * facts builder (vcs_badge_facts_build) derives the same struct from
 * the index + ledger + rank projections.
 *
 * PERMANENCE + DEDUP (owner directive): a badge is PERMANENT historical
 * evidence — a later rank loss never revokes it (the badge store is
 * append-only; nothing here ever deletes). The same badge is never
 * issued twice for the same contributor + achievement period: the plan
 * layer excludes dedup hits with the named rule duplicate-badge, and
 * the issue commit re-checks dedup against the CURRENT store before
 * writing anything.
 *
 * SIMULATION ONLY: no real ZSLP mint, no wallet call, no on-chain
 * asset — the owner-reviewed real badge issuance is slice 15. Signing
 * happens through the caller-supplied callback; private keys never
 * enter contexts/commons/modules/vcs. */

#ifndef ZCL_VCS_PACKAGE_BADGE_ELIGIBLE_H
#define ZCL_VCS_PACKAGE_BADGE_ELIGIBLE_H

#include "vcs/package_badge.h"
#include "vcs/package_index.h"
#include "vcs/package_reward.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The pioneer window for EARLY_ZCODE_CONTRIBUTOR: the contributor's
 * earliest settled reward day must fall within this many days of the
 * earliest settled day in the whole local ledger. Frozen policy
 * constant. */
#define VCS_BADGE_EARLY_WINDOW_DAYS 30

/* The maintenance span for ONE_YEAR_MAINTAINER: earliest-to-latest
 * settled day must reach this many days. Frozen policy constant. */
#define VCS_BADGE_ONE_YEAR_SPAN_DAYS 365

/* The settled test-points threshold for HUNDRED_TESTS. Frozen. */
#define VCS_BADGE_HUNDRED_TESTS_POINTS 100u

/* The distinct-package threshold for TEN_PACKAGES. Frozen. */
#define VCS_BADGE_TEN_PACKAGES_COUNT 10u

/* ── the facts (the evaluator's whole input) ────────────────────────── */

struct vcs_badge_facts {
    /* Publish history (from the package index; zeros when none). */
    uint32_t release_count;
    uint32_t distinct_package_count;
    bool has_first_package;
    uint8_t first_package_root[32];  /* earliest-sequence release */
    bool has_tenth_package;
    uint8_t tenth_package_root[32];  /* 10th distinct root by sequence */

    /* This contributor's settled ledger facts. */
    bool has_settled;
    int64_t earliest_settled_day;
    int64_t latest_settled_day;
    uint64_t test_points_total;
    bool hundred_tests_crossed;
    int64_t hundred_tests_day;       /* the crossing settlement day */
    uint8_t hundred_tests_root[32];  /* the crossing fact's release */
    bool has_bug_fix;
    int64_t bug_fix_day;             /* earliest settled bug-fix day */
    uint8_t bug_fix_root[32];
    bool has_security_fix;
    int64_t security_fix_day;
    uint8_t security_fix_root[32];
    bool has_reproduction;
    int64_t reproduction_day;
    uint8_t reproduction_root[32];

    /* Whole-ledger fact (for EARLY_ZCODE_CONTRIBUTOR). */
    bool ledger_any;
    int64_t ledger_earliest_day;

    /* Current-period rank-1 facts (overall category; the caller computes
     * them via the slice-9 projections at "today"). */
    bool top_daily;
    uint64_t top_daily_points;
    bool top_weekly;
    uint64_t top_weekly_points;
    bool top_monthly;
    uint64_t top_monthly_points;
};

/* Derive the facts for one contributor from the package index (publish
 * history; NULL/empty = no releases) and the reward-history ledger
 * (settled facts + the rank-1 projections for the windows containing
 * `today_day`). Pure over its inputs — no filesystem, no wall-clock. */
void vcs_badge_facts_build(const uint8_t contributor[33],
                           const struct vcs_package_index *index,
                           const struct vcs_reward_ledger *ledger,
                           int64_t today_day,
                           struct vcs_badge_facts *out);

/* ── the evaluator (pure core) ──────────────────────────────────────── */

#define VCS_BADGE_DETAIL_MAX 160u

struct vcs_badge_eval {
    enum vcs_badge_type type;
    bool available;  /* false: named unavailable, never eligible */
    bool eligible;
    int64_t period_first; /* VCS_BADGE_PERIOD_NONE when non-periodic */
    int64_t period_last;
    uint8_t evidence_root[32]; /* zero when not eligible */
    char detail[VCS_BADGE_DETAIL_MAX]; /* the evidence fact, human form */
};

/* Evaluate one badge type for one contributor against explicit facts at
 * `today_day` (a civil day number). Pure. False (logged) only on NULL
 * inputs or an out-of-range type; an UNAVAILABLE type is not an error:
 * out->available is false and out->detail says why. */
bool vcs_badge_evaluate(enum vcs_badge_type type,
                        const uint8_t contributor[33],
                        const struct vcs_badge_facts *facts,
                        int64_t today_day, struct vcs_badge_eval *out);

/* The evidence commitment for badges without a package root (rank and
 * threshold badges): SHA3-256 over the frozen domain, the type, the
 * contributor, the period, and the achievement quantity. Deterministic
 * — plan and issue recompute it identically from the same facts. */
void vcs_badge_evidence_hash(enum vcs_badge_type type,
                             const uint8_t contributor[33],
                             int64_t period_first, int64_t period_last,
                             uint64_t quantity, uint8_t out[32]);

/* ── plan (assemble one issuance batch, dedup-checked) ──────────────── */

struct vcs_badge_plan_exclusion {
    enum vcs_badge_type type;
    char rule[VCS_BADGE_RULE_MAX];   /* duplicate-badge, not-eligible,
                                        unavailable */
    char detail[VCS_BADGE_DETAIL_MAX];
};

/* Assemble the issuance batch for one contributor: every badge type is
 * evaluated; eligible types not already issued (the dedup rule against
 * the CURRENT store under the configured policy) become plan rows with
 * fresh per-issuer sequences (store max + 1, consecutive); every
 * excluded type is named with its rule. Pure over its inputs — the only
 * mutation ever made by planning is vcs_badge_plan_persist (the caller's
 * choice). False (logged) on bad input. */
bool vcs_badge_plan_build(const struct vcs_badge_store *store,
                          const struct vcs_badge_policy *policy,
                          const uint8_t contributor[33],
                          const struct vcs_badge_facts *facts,
                          int64_t today_day, struct vcs_badge_plan *out,
                          struct vcs_badge_plan_exclusion *exclusions,
                          size_t *exclusion_count_out);

/* ── issue (commit a planned batch, SIMULATED, idempotent) ──────────── */

enum vcs_badge_issue_error {
    VCS_BADGE_ISSUE_OK = 0,
    VCS_BADGE_ISSUE_UNKNOWN_PLAN,   /* no plan wire for this id */
    VCS_BADGE_ISSUE_ALREADY_ISSUED, /* commit record exists: a duplicate,
                                       never a double-issue */
    VCS_BADGE_ISSUE_PLAN_CORRUPT,   /* the plan wire is unreadable or
                                       commits a different id */
    VCS_BADGE_ISSUE_POLICY_MISMATCH,/* the plan's policy id or issuer key
                                       is not the configured policy */
    VCS_BADGE_ISSUE_STALE,          /* revalidation against CURRENT facts
                                       failed (detail names the rule:
                                       not-eligible, period-changed,
                                       evidence-changed, duplicate-badge,
                                       sequence-conflict) */
    VCS_BADGE_ISSUE_SIGN,           /* the signer callback failed or
                                       produced a bad signature */
    VCS_BADGE_ISSUE_IO,             /* durable write failed (logged) */
};

const char *vcs_badge_issue_error_string(enum vcs_badge_issue_error err);

/* The signer callback: receives the fully-formed badge (signature
 * zeroed) and the badge id; must fill badge->signature with the 64-byte
 * compact low-S secp256k1 signature over the id. Private keys stay with
 * the caller — contexts/commons/modules/vcs only verifies. */
typedef bool (*vcs_badge_sign_fn)(struct vcs_badge *badge,
                                  const uint8_t badge_id[32], void *ctx);

struct vcs_badge_issue_result {
    uint32_t issued_count;   /* badge wires durable after this call */
    uint32_t replayed_count; /* rows whose badge was already durable
                                (a crash resume) */
    bool resumed;            /* a previous interrupted attempt replayed */
};

/* Commit a planned batch SIMULATED: re-validates EVERY planned row
 * against the CURRENT facts (rebuilt from `index` + `ledger` at the
 * plan's recorded day — never the wall clock) and the CURRENT store
 * (dedup, sequence conflicts), signs each fresh badge through `sign`,
 * persists the signed badge wires (dedup by badge id — a crash replay
 * is a no-op), and writes the commit record LAST (the idempotence
 * authority). Replay-safe: a crash before the commit record leaves a
 * resumable partial state (resumed:true on the finishing issue);
 * re-issuing a completed plan is ALREADY_ISSUED — a named duplicate,
 * never a double-issue. On STALE/POLICY_MISMATCH/SIGN nothing is
 * written. `detail` (when non-NULL, detail_size bytes) names the
 * offending row/rule. */
enum vcs_badge_issue_error vcs_badge_issue(
    struct vcs_badge_store *store, const struct vcs_badge_policy *policy,
    const uint8_t plan_id[32], const struct vcs_package_index *index,
    const struct vcs_reward_ledger *ledger, vcs_badge_sign_fn sign,
    void *sign_ctx, struct vcs_badge_issue_result *out, char *detail,
    size_t detail_size);

#endif /* ZCL_VCS_PACKAGE_BADGE_ELIGIBLE_H */
