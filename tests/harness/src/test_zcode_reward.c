/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_reward — the SIMULATED ZCODE reward ledger and daily
 * settlement queue (slice 8: contexts/commons/modules/vcs/package_reward.* and the
 * zcode reward queue/plan/commit/receipt handlers in
 * tools/command/native_zcode_reward_settle_command.c, plus the
 * contributor.show rewards integration).
 *
 * Coverage (adversarial first — idempotence is the heart of the slice):
 *   1. Enqueue validation: auto vs claim categories, claim bands exact
 *      (security-fix 500-5000, bug-fix 250, review 50-500, reproduction
 *      100, maintenance 100), zero points, missing evidence root, auto
 *      over the per-release cap, deterministic entry ids (redelivery is
 *      a duplicate).
 *   2. Replay: wires survive a reload byte-for-byte; the placeholder
 *      token id is the frozen 32 ASCII bytes.
 *   3. Roundtrip: queue/plan/commit/receipt with per-state tallies and
 *      derived planned states.
 *   4. Idempotence: repeated settlement of the same batch is a named
 *      duplicate, NEVER a double-pay; crash between commit and ledger
 *      write (commit record deleted) replays safely with the identical
 *      receipt and no duplicated facts.
 *   5. Period caps read the durable LEDGER across reloads: weekly cap
 *      clamps then exhausts, trailing-window edges exact; the daily
 *      rewarded-release cap defers the 11th same-day release.
 *   6. Double-reward attacks: same (release, contributor, category)
 *      twice in one window (within-batch) and across windows (from the
 *      ledger) are both excluded with duplicate-reward.
 *   7. Claims: blocked from settlement with owner-review-required; the
 *      evidence root is bound and visible.
 *   8. Plan determinism: the same window re-planned over the same ledger
 *      is the byte-identical plan id (dedup persist).
 *   9. Commands over a fixture datadir: queue pages/filters, plan
 *      exclusions named, commit + ALREADY_SETTLED/UNKNOWN_PLAN/
 *      BAD_PLAN_ID, receipt + NOT_SETTLED, and contributor.show surfacing
 *      the ledger facts exactly (earned_score vs token_rewards_received
 *      separate; no balances). */

#include "test/test_core.h"

#include "command/native_command.h"

#include "json/json.h"
#include "util/safe_alloc.h"
#include "vcs/package_reward.h"
#include "vcs/package_score.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZR_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_reward: %s... OK\n", (name)); }       \
    else { printf("  zcode_reward: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── small fixtures (the test_zcode_score pattern) ──────────────────── */

static void zr_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zr_mkdir_p(const char *path)
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

static bool zr_rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[4400];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!zr_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
}

/* Deterministic byte-pattern fixtures. */
static void zr_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
    if (out[0] == 0)
        out[0] = 1; /* never all-zero */
}

static void zr_pub(uint8_t seed, uint8_t out[33])
{
    out[0] = 0x02;
    for (size_t i = 1; i < 33; i++)
        out[i] = (uint8_t)(seed + i);
}

static void zr_facts(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(0xf0 - seed - i);
    if (out[0] == 0)
        out[0] = 0xaa;
}

/* A scratch store path under test-tmp (one per test, pid-namespaced). */
static void zr_store(char *out, size_t out_size, const char *tag)
{
    snprintf(out, out_size, "test-tmp/zr_%s_%ld/zcode", tag,
             (long)getpid());
}

/* Enqueue an auto reward in one call. */
static enum vcs_reward_enqueue_error zr_auto(struct vcs_reward_ledger *l,
                                             uint8_t root_seed,
                                             uint8_t pub_seed,
                                             enum vcs_reward_category cat,
                                             uint32_t points,
                                             uint8_t facts_seed,
                                             uint8_t id_out[32])
{
    uint8_t root[32], pub[33], facts[32];
    zr_root(root_seed, root);
    zr_pub(pub_seed, pub);
    zr_facts(facts_seed, facts);
    return vcs_reward_enqueue_auto(l, root, pub, cat, points, facts,
                                   id_out);
}

static enum vcs_reward_enqueue_error zr_claim(struct vcs_reward_ledger *l,
                                              uint8_t root_seed,
                                              uint8_t pub_seed,
                                              enum vcs_reward_category cat,
                                              uint32_t points,
                                              uint8_t evidence_seed,
                                              uint8_t id_out[32])
{
    uint8_t root[32], pub[33], ev[32];
    zr_root(root_seed, root);
    zr_pub(pub_seed, pub);
    zr_facts(evidence_seed, ev);
    return vcs_reward_enqueue_claim(l, root, pub, cat, points, ev, id_out);
}

/* Plan + persist + commit in one call (returns the commit error). */
static enum vcs_reward_commit_error zr_settle(struct vcs_reward_ledger *l,
                                              int64_t day,
                                              uint8_t plan_id_out[32],
                                              struct vcs_reward_commit_result
                                                  *result_out)
{
    struct vcs_reward_plan plan;
    if (!vcs_reward_plan_build(l, day, &plan))
        return VCS_REWARD_COMMIT_IO;
    memcpy(plan_id_out, plan.plan_id, 32);
    enum vcs_reward_plan_persist_error perr =
        vcs_reward_plan_persist(l, &plan);
    vcs_reward_plan_free(&plan);
    if (perr != VCS_REWARD_PLAN_PERSIST_OK &&
        perr != VCS_REWARD_PLAN_PERSIST_DUPLICATE)
        return VCS_REWARD_COMMIT_IO;
    char detail[256];
    return vcs_reward_commit(l, plan_id_out, result_out, detail,
                             sizeof(detail));
}

/* ── 1. enqueue validation (record kinds, bands, evidence) ──────────── */

static int t_enqueue(void)
{
    int failures = 0;
    char store[4400];
    zr_store(store, sizeof(store), "enqueue");
    zr_rm_rf("test-tmp/zr_enqueue_x"); /* no-op guard */
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zr_enqueue_%ld",
             (long)getpid());
    zr_rm_rf(datadir);

    struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
    ZR_CHECK("enqueue: empty store loads", l != NULL);
    if (!l)
        return failures + 1;

    uint8_t id[32], id2[32];
    ZR_CHECK("enqueue: auto new-package 508",
             zr_auto(l, 1, 1, VCS_REWARD_CATEGORY_NEW_PACKAGE, 508, 1,
                     id) == VCS_REWARD_ENQUEUE_OK);
    ZR_CHECK("enqueue: redelivery is a duplicate with the same id",
             zr_auto(l, 1, 1, VCS_REWARD_CATEGORY_NEW_PACKAGE, 508, 1,
                     id2) == VCS_REWARD_ENQUEUE_DUPLICATE &&
             memcmp(id, id2, 32) == 0);
    ZR_CHECK("enqueue: auto with a manual category named",
             zr_auto(l, 2, 1, VCS_REWARD_CATEGORY_SECURITY_FIX, 1000, 2,
                     id) == VCS_REWARD_ENQUEUE_BAD_CATEGORY);
    ZR_CHECK("enqueue: claim with an automatic category named",
             zr_claim(l, 2, 1, VCS_REWARD_CATEGORY_NEW_PACKAGE, 500, 2,
                      id) == VCS_REWARD_ENQUEUE_BAD_CATEGORY);

    /* Bands are exact. */
    ZR_CHECK("enqueue: security-fix 499 below band",
             zr_claim(l, 3, 1, VCS_REWARD_CATEGORY_SECURITY_FIX, 499, 3,
                      id) == VCS_REWARD_ENQUEUE_BAND);
    ZR_CHECK("enqueue: security-fix 5001 above band",
             zr_claim(l, 3, 1, VCS_REWARD_CATEGORY_SECURITY_FIX, 5001, 3,
                      id) == VCS_REWARD_ENQUEUE_BAND);
    ZR_CHECK("enqueue: security-fix 500 and 5000 in band",
             zr_claim(l, 3, 1, VCS_REWARD_CATEGORY_SECURITY_FIX, 500, 3,
                      id) == VCS_REWARD_ENQUEUE_OK &&
             zr_claim(l, 4, 1, VCS_REWARD_CATEGORY_SECURITY_FIX, 5000, 4,
                      id) == VCS_REWARD_ENQUEUE_OK);
    ZR_CHECK("enqueue: bug-fix is exactly 250",
             zr_claim(l, 5, 1, VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION, 249,
                      5, id) == VCS_REWARD_ENQUEUE_BAND &&
             zr_claim(l, 5, 1, VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION, 250,
                      5, id) == VCS_REWARD_ENQUEUE_OK);
    ZR_CHECK("enqueue: review band 50..500",
             zr_claim(l, 6, 1, VCS_REWARD_CATEGORY_REVIEW, 49, 6,
                      id) == VCS_REWARD_ENQUEUE_BAND &&
             zr_claim(l, 6, 1, VCS_REWARD_CATEGORY_REVIEW, 501, 6,
                      id) == VCS_REWARD_ENQUEUE_BAND &&
             zr_claim(l, 6, 1, VCS_REWARD_CATEGORY_REVIEW, 50, 6,
                      id) == VCS_REWARD_ENQUEUE_OK);
    ZR_CHECK("enqueue: reproduction + maintenance are exactly 100",
             zr_claim(l, 7, 1, VCS_REWARD_CATEGORY_BUILD_REPRODUCTION, 101,
                      7, id) == VCS_REWARD_ENQUEUE_BAND &&
             zr_claim(l, 7, 1, VCS_REWARD_CATEGORY_BUILD_REPRODUCTION, 100,
                      7, id) == VCS_REWARD_ENQUEUE_OK &&
             zr_claim(l, 8, 1, VCS_REWARD_CATEGORY_MAINTENANCE_90_DAY, 100,
                      8, id) == VCS_REWARD_ENQUEUE_OK);

    /* Evidence root and points. */
    {
        uint8_t root[32], pub[33], zero[32] = {0};
        zr_root(9, root);
        zr_pub(9, pub);
        ZR_CHECK("enqueue: claim without an evidence root rejected",
                 vcs_reward_enqueue_claim(
                     l, root, pub, VCS_REWARD_CATEGORY_SECURITY_FIX, 1000,
                     zero, id) == VCS_REWARD_ENQUEUE_EVIDENCE);
        uint8_t ev[32];
        zr_facts(9, ev);
        ZR_CHECK("enqueue: zero-point claim rejected",
                 vcs_reward_enqueue_claim(
                     l, root, pub, VCS_REWARD_CATEGORY_SECURITY_FIX, 0, ev,
                     id) == VCS_REWARD_ENQUEUE_ZERO_POINTS);
        ZR_CHECK("enqueue: zero-point auto rejected",
                 vcs_reward_enqueue_auto(
                     l, root, pub, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 0,
                     ev, id) == VCS_REWARD_ENQUEUE_ZERO_POINTS);
        ZR_CHECK("enqueue: auto over the per-release cap named",
                 vcs_reward_enqueue_auto(
                     l, root, pub, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                     VCS_SCORE_MAX_TOTAL_PER_RELEASE + 1u, ev,
                     id) == VCS_REWARD_ENQUEUE_BAND);
        ZR_CHECK("enqueue: auto with a zero facts hash rejected",
                 vcs_reward_enqueue_auto(
                     l, root, pub, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 100,
                     zero, id) == VCS_REWARD_ENQUEUE_BAD_INPUT);
    }

    /* Claim facts hash binds category + points + evidence: the same
     * claim redelivered is the same entry id. */
    ZR_CHECK("enqueue: same claim redelivered is a duplicate",
             zr_claim(l, 3, 1, VCS_REWARD_CATEGORY_SECURITY_FIX, 500, 3,
                      id2) == VCS_REWARD_ENQUEUE_DUPLICATE);

    /* Strings + band reflection (frozen names from the scoring table). */
    ZR_CHECK("enqueue: category strings are the scoring-table names",
             strcmp(vcs_reward_category_string(
                        VCS_REWARD_CATEGORY_BUG_FIX_REGRESSION),
                    "bug-fix-with-regression-test") == 0 &&
             strcmp(vcs_reward_category_string(
                        VCS_REWARD_CATEGORY_SECURITY_FIX),
                    "security-fix") == 0 &&
             strcmp(vcs_reward_category_string(VCS_REWARD_CATEGORY_REVIEW),
                    "independent-review") == 0 &&
             strcmp(vcs_reward_state_string(VCS_REWARD_STATE_PLANNED),
                    "planned") == 0 &&
             strcmp(vcs_reward_kind_string(VCS_REWARD_KIND_CLAIM),
                    "claim") == 0);
    {
        uint32_t lo = 0, hi = 0;
        bool automatic = true;
        vcs_reward_category_band(VCS_REWARD_CATEGORY_SECURITY_FIX, &lo,
                                 &hi, &automatic);
        ZR_CHECK("enqueue: security-fix band reflects the table",
                 lo == 500 && hi == 5000 && !automatic);
    }
    vcs_reward_ledger_free(l);

    /* The placeholder token id is the frozen 32 ASCII bytes. */
    {
        const uint8_t *id_bytes = vcs_reward_placeholder_token_id();
        char hex[65];
        vcs_reward_placeholder_token_id_hex(hex);
        ZR_CHECK("enqueue: placeholder token id is the frozen constant",
                 memcmp(id_bytes, VCS_REWARD_PLACEHOLDER_TOKEN_ID_TEXT,
                        32) == 0 &&
                 strlen(VCS_REWARD_PLACEHOLDER_TOKEN_ID_TEXT) == 32 &&
                 strlen(hex) == 64);
    }
    zr_rm_rf(datadir);
    return failures;
}

/* ── 2. replay + 3. roundtrip (library) ─────────────────────────────── */

static int t_roundtrip(void)
{
    int failures = 0;
    char store[4400], datadir[4400];
    zr_store(store, sizeof(store), "roundtrip");
    snprintf(datadir, sizeof(datadir), "test-tmp/zr_roundtrip_%ld",
             (long)getpid());
    zr_rm_rf(datadir);

    uint8_t id_auto1[32], id_auto2[32], id_claim[32];
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        ZR_CHECK("roundtrip: two autos + one claim queue",
                 zr_auto(l, 10, 10, VCS_REWARD_CATEGORY_NEW_PACKAGE, 600,
                         10, id_auto1) == VCS_REWARD_ENQUEUE_OK &&
                 zr_auto(l, 11, 11, VCS_REWARD_CATEGORY_PACKAGE_UPDATE,
                         250, 11, id_auto2) == VCS_REWARD_ENQUEUE_OK &&
                 zr_claim(l, 12, 12, VCS_REWARD_CATEGORY_REVIEW, 200, 12,
                          id_claim) == VCS_REWARD_ENQUEUE_OK);
        vcs_reward_ledger_free(l);
    }

    /* Replay: the wires rebuild exactly. */
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
    struct vcs_reward_queue_tally tally;
    vcs_reward_queue_tally(l, &tally);
    ZR_CHECK("roundtrip: replay tallies 3 queued",
             vcs_reward_ledger_entry_count(l) == 3 && tally.queued == 3 &&
             tally.planned == 0 && tally.settled == 0 &&
             vcs_reward_ledger_corrupt_count(l) == 0);
    {
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(l, id_claim);
        ZR_CHECK("roundtrip: claim replays with its evidence root",
                 e && e->kind == VCS_REWARD_KIND_CLAIM &&
                 e->has_evidence_root && e->points == 200 &&
                 e->category == VCS_REWARD_CATEGORY_REVIEW &&
                 e->state == VCS_REWARD_STATE_QUEUED);
    }

    /* Plan: the claim is blocked, the autos planned. */
    struct vcs_reward_plan plan;
    ZR_CHECK("roundtrip: plan builds",
             vcs_reward_plan_build(l, 100, &plan));
    ZR_CHECK("roundtrip: claim blocked with the named rule",
             plan.planned_count == 2 && plan.blocked_count == 1 &&
             plan.points_total == 850);
    {
        bool claim_blocked = false;
        for (size_t i = 0; i < plan.row_count; i++) {
            if (plan.rows[i].disposition == VCS_REWARD_DISP_BLOCKED &&
                memcmp(plan.rows[i].entry_id, id_claim, 32) == 0 &&
                strcmp(plan.rows[i].rule, VCS_REWARD_RULE_OWNER_REVIEW) ==
                    0)
                claim_blocked = true;
        }
        ZR_CHECK("roundtrip: blocked row names owner-review-required",
                 claim_blocked);
    }
    uint8_t plan_id[32];
    memcpy(plan_id, plan.plan_id, 32);
    ZR_CHECK("roundtrip: plan persists",
             vcs_reward_plan_persist(l, &plan) ==
                 VCS_REWARD_PLAN_PERSIST_OK);
    vcs_reward_plan_free(&plan);

    /* Determinism: same window, same ledger -> byte-identical plan id. */
    {
        struct vcs_reward_plan again;
        ZR_CHECK("roundtrip: re-plan builds",
                 vcs_reward_plan_build(l, 100, &again));
        ZR_CHECK("roundtrip: same window reproduces the plan id",
                 memcmp(again.plan_id, plan_id, 32) == 0 &&
                 again.planned_count == 2 && again.points_total == 850);
        ZR_CHECK("roundtrip: re-persist is a dedup no-op",
                 vcs_reward_plan_persist(l, &again) ==
                     VCS_REWARD_PLAN_PERSIST_DUPLICATE);
        vcs_reward_plan_free(&again);
    }
    vcs_reward_ledger_free(l);

    /* Derived planned states survive a reload. */
    l = vcs_reward_ledger_load(store);
    vcs_reward_queue_tally(l, &tally);
    ZR_CHECK("roundtrip: planned states derive after reload",
             tally.planned == 2 && tally.queued == 1);
    {
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(l, id_auto1);
        ZR_CHECK("roundtrip: planned entry names its plan",
                 e && e->state == VCS_REWARD_STATE_PLANNED &&
                 memcmp(e->planned_by, plan_id, 32) == 0);
    }

    /* Commit, then receipt. */
    struct vcs_reward_commit_result result;
    char detail[256];
    ZR_CHECK("roundtrip: commit settles",
             vcs_reward_commit(l, plan_id, &result, detail,
                               sizeof(detail)) == VCS_REWARD_COMMIT_OK &&
             result.settled_count == 2 && result.rejected_count == 0 &&
             result.points_settled == 850 && !result.resumed);
    struct vcs_reward_receipt receipt;
    ZR_CHECK("roundtrip: receipt reads",
             vcs_reward_receipt_load(l, plan_id, &receipt) ==
                 VCS_REWARD_RECEIPT_OK);
    ZR_CHECK("roundtrip: receipt content",
             receipt.day == 100 && receipt.settled_count == 2 &&
             receipt.points_total == 850 &&
             memcmp(receipt.token_id,
                    vcs_reward_placeholder_token_id(), 32) == 0);
    {
        uint32_t sum = 0;
        for (size_t i = 0; i < receipt.row_count; i++)
            sum += receipt.rows[i].points;
        ZR_CHECK("roundtrip: receipt rows sum to the batch", sum == 850);
    }
    vcs_reward_receipt_free(&receipt);
    vcs_reward_ledger_free(l);

    /* Settled states + facts are durable. */
    l = vcs_reward_ledger_load(store);
    vcs_reward_queue_tally(l, &tally);
    ZR_CHECK("roundtrip: settled tallies after reload",
             tally.settled == 2 && tally.queued == 1 &&
             vcs_reward_ledger_fact_count(l) == 2);
    {
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(l, id_auto2);
        ZR_CHECK("roundtrip: settled entry names window + plan",
                 e && e->state == VCS_REWARD_STATE_SETTLED &&
                 e->settled_day == 100 &&
                 memcmp(e->settled_by_plan, plan_id, 32) == 0);
    }

    /* Repeated settlement is a named duplicate, never a double-pay. */
    memset(&result, 0, sizeof(result));
    ZR_CHECK("roundtrip: re-settle is ALREADY_SETTLED (no double-pay)",
             vcs_reward_commit(l, plan_id, &result, detail,
                               sizeof(detail)) ==
                 VCS_REWARD_COMMIT_ALREADY_SETTLED &&
             vcs_reward_ledger_fact_count(l) == 2);
    ZR_CHECK("roundtrip: receipt still the original batch",
             vcs_reward_receipt_load(l, plan_id, &receipt) ==
                 VCS_REWARD_RECEIPT_OK &&
             receipt.points_total == 850);
    vcs_reward_receipt_free(&receipt);
    vcs_reward_ledger_free(l);
    zr_rm_rf(datadir);
    return failures;
}

/* ── 4. crash between commit and ledger write: replay-safe ──────────── */

static int t_crash_replay(void)
{
    int failures = 0;
    char store[4400], datadir[4400];
    zr_store(store, sizeof(store), "crash");
    snprintf(datadir, sizeof(datadir), "test-tmp/zr_crash_%ld",
             (long)getpid());
    zr_rm_rf(datadir);

    struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
    uint8_t plan_id[32];
    struct vcs_reward_commit_result result;
    ZR_CHECK("crash: fixture settles",
             zr_auto(l, 20, 20, VCS_REWARD_CATEGORY_NEW_PACKAGE, 700, 20,
                     plan_id) == VCS_REWARD_ENQUEUE_OK &&
             zr_auto(l, 21, 20, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 300,
                     21, plan_id) == VCS_REWARD_ENQUEUE_OK &&
             zr_auto(l, 22, 21, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 150,
                     22, plan_id) == VCS_REWARD_ENQUEUE_OK &&
             zr_settle(l, 300, plan_id, &result) ==
                 VCS_REWARD_COMMIT_OK &&
             result.settled_count == 3 && result.points_settled == 1150);
    vcs_reward_ledger_free(l);

    /* The receipt of the completed commit. */
    l = vcs_reward_ledger_load(store);
    struct vcs_reward_receipt before;
    ZR_CHECK("crash: original receipt",
             vcs_reward_receipt_load(l, plan_id, &before) ==
                 VCS_REWARD_RECEIPT_OK);
    vcs_reward_ledger_free(l);

    /* Simulate the crash: facts + queue transitions durable, the commit
     * record (written LAST) lost. Re-commit must resume, not double-pay. */
    char hex[65], path[4400];
    zr_hex_enc(plan_id, 32, hex);
    snprintf(path, sizeof(path), "%s/rewards/commits/%s", store, hex);
    ZR_CHECK("crash: commit record deleted (the simulated crash)",
             unlink(path) == 0);

    l = vcs_reward_ledger_load(store);
    ZR_CHECK("crash: replay sees facts without the commit record",
             vcs_reward_ledger_fact_count(l) == 3);
    memset(&result, 0, sizeof(result));
    ZR_CHECK("crash: re-commit resumes with the identical outcome",
             vcs_reward_commit(l, plan_id, &result, path /*detail*/,
                               sizeof(path)) == VCS_REWARD_COMMIT_OK &&
             result.resumed && result.settled_count == 3 &&
             result.points_settled == 1150);
    ZR_CHECK("crash: no duplicated facts after resume",
             vcs_reward_ledger_fact_count(l) == 3);
    struct vcs_reward_receipt after;
    ZR_CHECK("crash: receipt identical across the resume",
             vcs_reward_receipt_load(l, plan_id, &after) ==
                 VCS_REWARD_RECEIPT_OK &&
             after.day == before.day &&
             after.settled_count == before.settled_count &&
             after.points_total == before.points_total &&
             after.row_count == before.row_count &&
             memcmp(after.rows[0].entry_id, before.rows[0].entry_id, 32) ==
                 0 &&
             after.rows[0].points == before.rows[0].points &&
             memcmp(after.token_id, before.token_id, 32) == 0);
    vcs_reward_receipt_free(&before);
    vcs_reward_receipt_free(&after);

    /* And the resumed commit is itself idempotent now. */
    ZR_CHECK("crash: third commit is ALREADY_SETTLED",
             vcs_reward_commit(l, plan_id, &result, path, sizeof(path)) ==
                 VCS_REWARD_COMMIT_ALREADY_SETTLED &&
             vcs_reward_ledger_fact_count(l) == 3);
    vcs_reward_ledger_free(l);
    zr_rm_rf(datadir);
    return failures;
}

/* ── 5. period caps read the durable ledger ─────────────────────────── */

static int t_caps_from_ledger(void)
{
    int failures = 0;
    char store[4400], datadir[4400];
    zr_store(store, sizeof(store), "caps");
    snprintf(datadir, sizeof(datadir), "test-tmp/zr_caps_%ld",
             (long)getpid());
    zr_rm_rf(datadir);

    /* Weekly cap: 9800 settles on day 100; day 101 clamps to 200; day
     * 102 exhausts (deferred); day 107 leaves the trailing window. */
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
    uint8_t id[32], plan_id[32];
    struct vcs_reward_commit_result result;
    ZR_CHECK("caps: 9800 settles on day 100",
             zr_auto(l, 30, 30, VCS_REWARD_CATEGORY_NEW_PACKAGE, 5000, 30,
                     id) == VCS_REWARD_ENQUEUE_OK &&
             zr_auto(l, 31, 30, VCS_REWARD_CATEGORY_NEW_PACKAGE, 4800, 31,
                     id) == VCS_REWARD_ENQUEUE_OK &&
             zr_settle(l, 100, plan_id, &result) == VCS_REWARD_COMMIT_OK &&
             result.points_settled == 9800);
    vcs_reward_ledger_free(l);

    l = vcs_reward_ledger_load(store);
    ZR_CHECK("caps: candidate queues for day 101",
             zr_auto(l, 32, 30, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 500, 32,
                     id) == VCS_REWARD_ENQUEUE_OK);
    struct vcs_reward_plan plan;
    ZR_CHECK("caps: day-101 plan builds from the reloaded ledger",
             vcs_reward_plan_build(l, 101, &plan));
    ZR_CHECK("caps: weekly cap clamps to the remaining 200",
             plan.planned_count == 1 && plan.row_count == 1 &&
             plan.rows[0].points_requested == 500 &&
             plan.rows[0].points_settled == 200 &&
             plan.rows[0].weekly_cap_clamped);
    ZR_CHECK("caps: clamped plan settles",
             vcs_reward_plan_persist(l, &plan) ==
                 VCS_REWARD_PLAN_PERSIST_OK &&
             vcs_reward_commit(l, plan.plan_id, &result, NULL, 0) ==
                 VCS_REWARD_COMMIT_OK &&
             result.points_settled == 200);
    vcs_reward_plan_free(&plan);
    vcs_reward_ledger_free(l);

    l = vcs_reward_ledger_load(store);
    ZR_CHECK("caps: candidate queues for day 102",
             zr_auto(l, 33, 30, VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 500, 33,
                     id) == VCS_REWARD_ENQUEUE_OK);
    ZR_CHECK("caps: day-102 plan builds",
             vcs_reward_plan_build(l, 102, &plan));
    ZR_CHECK("caps: exhausted week defers with the named rule",
             plan.planned_count == 0 && plan.deferred_count == 1 &&
             strcmp(plan.rows[0].rule, VCS_REWARD_RULE_WEEKLY_CAP) == 0);
    vcs_reward_plan_free(&plan);

    /* The deferred entry stays queued; day 107 (window 101..107 drops
     * day 100's 9800) leaves room again. */
    ZR_CHECK("caps: day-107 plan builds",
             vcs_reward_plan_build(l, 107, &plan));
    ZR_CHECK("caps: trailing-window edge frees the entry on day 107",
             plan.planned_count == 1 &&
             plan.rows[0].points_settled == 500 &&
             !plan.rows[0].weekly_cap_clamped);
    vcs_reward_plan_free(&plan);
    vcs_reward_ledger_free(l);

    /* Daily release-count cap: the 11th same-day release defers. */
    zr_rm_rf(datadir);
    l = vcs_reward_ledger_load(store);
    for (uint8_t i = 0; i < 11; i++) {
        ZR_CHECK("caps: daily fixture entry queues",
                 zr_auto(l, (uint8_t)(40 + i), 40,
                         VCS_REWARD_CATEGORY_PACKAGE_UPDATE, 100,
                         (uint8_t)(40 + i), id) == VCS_REWARD_ENQUEUE_OK);
    }
    ZR_CHECK("caps: day-200 plan builds",
             vcs_reward_plan_build(l, 200, &plan));
    ZR_CHECK("caps: 10 settle, the 11th defers with the named rule",
             plan.planned_count == VCS_SCORE_MAX_RELEASES_PER_DAY &&
             plan.deferred_count == 1 &&
             plan.points_total == 1000);
    {
        bool daily_named = false;
        for (size_t i = 0; i < plan.row_count; i++)
            if (plan.rows[i].disposition == VCS_REWARD_DISP_DEFERRED &&
                strcmp(plan.rows[i].rule, VCS_REWARD_RULE_DAILY_CAP) == 0)
                daily_named = true;
        ZR_CHECK("caps: deferred row names daily-release-cap",
                 daily_named);
    }
    ZR_CHECK("caps: day-200 batch commits",
             vcs_reward_plan_persist(l, &plan) ==
                 VCS_REWARD_PLAN_PERSIST_OK &&
             vcs_reward_commit(l, plan.plan_id, &result, NULL, 0) ==
                 VCS_REWARD_COMMIT_OK &&
             result.settled_count == 10);
    vcs_reward_plan_free(&plan);

    /* The leftover settles the next day. */
    ZR_CHECK("caps: day-201 plan builds",
             vcs_reward_plan_build(l, 201, &plan));
    ZR_CHECK("caps: leftover release settles the next day",
             plan.planned_count == 1 && plan.rows[0].points_settled == 100);
    vcs_reward_plan_free(&plan);
    vcs_reward_ledger_free(l);
    zr_rm_rf(datadir);
    return failures;
}

/* ── 6. double-reward attacks ───────────────────────────────────────── */

static int t_double_reward(void)
{
    int failures = 0;
    char store[4400], datadir[4400];
    zr_store(store, sizeof(store), "double");
    snprintf(datadir, sizeof(datadir), "test-tmp/zr_double_%ld",
             (long)getpid());
    zr_rm_rf(datadir);

    struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
    uint8_t id1[32], id2[32], plan_id[32];
    struct vcs_reward_commit_result result;

    /* Within one window: two entries claiming the same
     * (release, contributor, category) with different facts hashes. */
    {
        uint8_t root[32], pub[33], facts1[32], facts2[32];
        zr_root(50, root);
        zr_pub(50, pub);
        zr_facts(50, facts1);
        zr_facts(51, facts2);
        ZR_CHECK("double: two claims on one release queue",
                 vcs_reward_enqueue_auto(
                     l, root, pub, VCS_REWARD_CATEGORY_NEW_PACKAGE, 500,
                     facts1, id1) == VCS_REWARD_ENQUEUE_OK &&
                 vcs_reward_enqueue_auto(
                     l, root, pub, VCS_REWARD_CATEGORY_NEW_PACKAGE, 500,
                     facts2, id2) == VCS_REWARD_ENQUEUE_OK &&
                 memcmp(id1, id2, 32) != 0);
    }
    struct vcs_reward_plan plan;
    ZR_CHECK("double: plan builds",
             vcs_reward_plan_build(l, 400, &plan));
    ZR_CHECK("double: within-batch twin excluded with the named rule",
             plan.planned_count == 1 && plan.duplicate_count == 1);
    {
        bool dup_named = false;
        for (size_t i = 0; i < plan.row_count; i++)
            if (plan.rows[i].disposition == VCS_REWARD_DISP_DUPLICATE &&
                strcmp(plan.rows[i].rule, VCS_REWARD_RULE_DUPLICATE) == 0)
                dup_named = true;
        ZR_CHECK("double: exclusion names duplicate-reward", dup_named);
    }
    memcpy(plan_id, plan.plan_id, 32);
    ZR_CHECK("double: batch settles exactly one reward",
             vcs_reward_plan_persist(l, &plan) ==
                 VCS_REWARD_PLAN_PERSIST_OK &&
             vcs_reward_commit(l, plan_id, &result, NULL, 0) ==
                 VCS_REWARD_COMMIT_OK &&
             result.settled_count == 1 && result.points_settled == 500);
    vcs_reward_plan_free(&plan);
    vcs_reward_ledger_free(l);

    /* Across windows: the twin is now a ledger duplicate, excluded from
     * every later plan (and it can never settle). */
    l = vcs_reward_ledger_load(store);
    ZR_CHECK("double: later-window plan builds",
             vcs_reward_plan_build(l, 401, &plan));
    ZR_CHECK("double: ledger duplicate excluded the next window",
             plan.planned_count == 0 && plan.duplicate_count == 1);
    vcs_reward_plan_free(&plan);
    ZR_CHECK("double: exactly one fact exists",
             vcs_reward_ledger_fact_count(l) == 1);
    vcs_reward_ledger_free(l);
    zr_rm_rf(datadir);
    return failures;
}

/* ── 7-9. commands over a fixture datadir ───────────────────────────── */

struct zr_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zr_cmd_init(struct zr_cmd *c, const char *datadir)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_reward_test.v1");
    (void)json_push_kv_str(&c->input, "datadir", datadir);
}

static void zr_cmd_free(struct zr_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* True when some row of a JSON array carries key=value (string). */
static bool zr_rows_have(const struct json_value *arr, const char *key,
                         const char *value)
{
    for (size_t i = 0; arr && json_at(arr, i); i++) {
        const char *v = json_get_str(json_get(json_at(arr, i), key));
        if (v && strcmp(v, value) == 0)
            return true;
    }
    return false;
}

static int t_commands(void)
{
    int failures = 0;
    char datadir[4400], store[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zr_cmd_%ld",
             (long)getpid());
    snprintf(store, sizeof(store), "%s/zcode", datadir);
    zr_rm_rf(datadir);
    ZR_CHECK("commands: datadir created", zr_mkdir_p(store));

    /* Seed the queue through the library (two autos + one claim). */
    uint8_t pub1[33], pub2[33];
    zr_pub(60, pub1);
    zr_pub(61, pub2);
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(store);
        uint8_t id[32];
        ZR_CHECK("commands: fixture queues",
                 zr_auto(l, 60, 60, VCS_REWARD_CATEGORY_NEW_PACKAGE, 900,
                         60, id) == VCS_REWARD_ENQUEUE_OK &&
                 zr_auto(l, 61, 61, VCS_REWARD_CATEGORY_PACKAGE_UPDATE,
                         400, 61, id) == VCS_REWARD_ENQUEUE_OK &&
                 zr_claim(l, 62, 61, VCS_REWARD_CATEGORY_SECURITY_FIX,
                          1200, 62, id) == VCS_REWARD_ENQUEUE_OK);
        vcs_reward_ledger_free(l);
    }

    /* queue: tallies + rows + claim evidence root. */
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        zcl_native_handle_zcode_reward_queue(&c.request, &c.reply);
        const struct json_value *tallies =
            json_get(&c.reply.data, "tallies");
        ZR_CHECK("commands: queue tallies 3 queued",
                 json_get_int(json_get(tallies, "queued")) == 3 &&
                 json_get_int(json_get(&c.reply.data,
                                       "total_entries")) == 3);
        const struct json_value *rows = json_get(&c.reply.data, "rows");
        ZR_CHECK("commands: queue rows carry kind + state",
                 zr_rows_have(rows, "kind", "claim") &&
                 zr_rows_have(rows, "state", "queued"));
        bool evidence = false;
        for (size_t i = 0; rows && json_at(rows, i); i++)
            if (json_get_str(json_get(json_at(rows, i), "evidence_root")))
                evidence = true;
        ZR_CHECK("commands: claim row carries its evidence root",
                 evidence);
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "state", "settled");
        zcl_native_handle_zcode_reward_queue(&c.request, &c.reply);
        ZR_CHECK("commands: state filter matches nothing yet",
                 json_get_int(json_get(&c.reply.data,
                                       "total_matches")) == 0);
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "state", "bogus");
        zcl_native_handle_zcode_reward_queue(&c.request, &c.reply);
        ZR_CHECK("commands: BAD_STATE_FILTER named",
                 strcmp(c.reply.error.code, "BAD_STATE_FILTER") == 0);
        zr_cmd_free(&c);
    }

    /* plan: input validation, exclusions named, determinism. */
    char plan_hex[65];
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        zcl_native_handle_zcode_reward_plan(&c.request, &c.reply);
        ZR_CHECK("commands: plan MISSING_DAY named",
                 strcmp(c.reply.error.code, "MISSING_DAY") == 0);
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", -1);
        zcl_native_handle_zcode_reward_plan(&c.request, &c.reply);
        ZR_CHECK("commands: plan BAD_DAY named",
                 strcmp(c.reply.error.code, "BAD_DAY") == 0);
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 500);
        zcl_native_handle_zcode_reward_plan(&c.request, &c.reply);
        const char *pid = json_get_str(json_get(&c.reply.data, "plan_id"));
        ZR_CHECK("commands: plan assembles the batch",
                 pid && strlen(pid) == 64 &&
                 json_get_int(json_get(&c.reply.data,
                                       "entries_planned")) == 2 &&
                 json_get_int(json_get(&c.reply.data,
                                       "entries_blocked")) == 1 &&
                 json_get_int(json_get(&c.reply.data, "recipients")) == 2 &&
                 json_get_int(json_get(&c.reply.data,
                                       "points_total")) == 1300 &&
                 json_get_bool(json_get(&c.reply.data, "simulated")));
        if (pid)
            snprintf(plan_hex, sizeof(plan_hex), "%s", pid);
        const struct json_value *exclusions =
            json_get(&c.reply.data, "exclusions");
        ZR_CHECK("commands: plan names owner-review-required",
                 zr_rows_have(exclusions, "rule",
                              VCS_REWARD_RULE_OWNER_REVIEW));
        const char *token =
            json_get_str(json_get(&c.reply.data, "placeholder_token_id"));
        char want_hex[65];
        vcs_reward_placeholder_token_id_hex(want_hex);
        ZR_CHECK("commands: plan carries the placeholder token id",
                 token && strcmp(token, want_hex) == 0);
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 500);
        zcl_native_handle_zcode_reward_plan(&c.request, &c.reply);
        const char *pid = json_get_str(json_get(&c.reply.data, "plan_id"));
        ZR_CHECK("commands: same window reproduces the plan id",
                 pid && strcmp(pid, plan_hex) == 0 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "already_persisted")));
        zr_cmd_free(&c);
    }

    /* queue: planned states derive from the persisted plan. */
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        zcl_native_handle_zcode_reward_queue(&c.request, &c.reply);
        const struct json_value *tallies =
            json_get(&c.reply.data, "tallies");
        ZR_CHECK("commands: queue tallies 2 planned after planning",
                 json_get_int(json_get(tallies, "planned")) == 2 &&
                 json_get_int(json_get(tallies, "queued")) == 1);
        zr_cmd_free(&c);
    }

    /* commit: rejections first, then the settle. */
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", "zz");
        zcl_native_handle_zcode_reward_commit(&c.request, &c.reply);
        ZR_CHECK("commands: commit BAD_PLAN_ID named",
                 strcmp(c.reply.error.code, "BAD_PLAN_ID") == 0);
        zr_cmd_free(&c);
    }
    {
        uint8_t unknown[32];
        for (size_t i = 0; i < 32; i++)
            unknown[i] = (uint8_t)(0x77 + i);
        char unknown_hex[65];
        zr_hex_enc(unknown, 32, unknown_hex);
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", unknown_hex);
        zcl_native_handle_zcode_reward_commit(&c.request, &c.reply);
        ZR_CHECK("commands: commit UNKNOWN_PLAN named",
                 strcmp(c.reply.error.code, "UNKNOWN_PLAN") == 0);
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", plan_hex);
        zcl_native_handle_zcode_reward_commit(&c.request, &c.reply);
        ZR_CHECK("commands: commit settles the batch",
                 json_get_int(json_get(&c.reply.data,
                                       "settled_count")) == 2 &&
                 json_get_int(json_get(&c.reply.data,
                                       "points_settled")) == 1300 &&
                 json_get_int(json_get(&c.reply.data, "day")) == 500 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "receipt_available")) &&
                 !json_get_bool(json_get(&c.reply.data, "resumed")));
        zr_cmd_free(&c);
    }
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", plan_hex);
        zcl_native_handle_zcode_reward_commit(&c.request, &c.reply);
        ZR_CHECK("commands: re-settle is ALREADY_SETTLED",
                 strcmp(c.reply.error.code, "ALREADY_SETTLED") == 0);
        zr_cmd_free(&c);
    }

    /* receipt: the durable evidence. */
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", plan_hex);
        zcl_native_handle_zcode_reward_receipt(&c.request, &c.reply);
        const struct json_value *rows = json_get(&c.reply.data, "entries");
        const char *token =
            json_get_str(json_get(&c.reply.data, "placeholder_token_id"));
        char want_hex[65];
        vcs_reward_placeholder_token_id_hex(want_hex);
        ZR_CHECK("commands: receipt carries the settled batch",
                 json_get_int(json_get(&c.reply.data,
                                       "settled_count")) == 2 &&
                 json_get_int(json_get(&c.reply.data,
                                       "points_total")) == 1300 &&
                 json_get_int(json_get(&c.reply.data, "day")) == 500 &&
                 token && strcmp(token, want_hex) == 0 &&
                 zr_rows_have(rows, "outcome", "settled") &&
                 zr_rows_have(rows, "category", "new-package") &&
                 zr_rows_have(rows, "category", "package-update"));
        zr_cmd_free(&c);
    }
    {
        /* A second, uncommitted plan: NOT_SETTLED. */
        char plan2_hex[65] = {0};
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_int(&c.input, "day", 501);
        zcl_native_handle_zcode_reward_plan(&c.request, &c.reply);
        const char *pid = json_get_str(json_get(&c.reply.data, "plan_id"));
        if (pid)
            snprintf(plan2_hex, sizeof(plan2_hex), "%s", pid);
        zr_cmd_free(&c);
        struct zr_cmd c2;
        zr_cmd_init(&c2, datadir);
        (void)json_push_kv_str(&c2.input, "plan_id", plan2_hex);
        zcl_native_handle_zcode_reward_receipt(&c2.request, &c2.reply);
        ZR_CHECK("commands: receipt NOT_SETTLED for an open plan",
                 strcmp(c2.reply.error.code, "NOT_SETTLED") == 0);
        zr_cmd_free(&c2);
        uint8_t unknown[32];
        for (size_t i = 0; i < 32; i++)
            unknown[i] = (uint8_t)(0x99 - i);
        char unknown_hex[65];
        zr_hex_enc(unknown, 32, unknown_hex);
        struct zr_cmd c3;
        zr_cmd_init(&c3, datadir);
        (void)json_push_kv_str(&c3.input, "plan_id", unknown_hex);
        zcl_native_handle_zcode_reward_receipt(&c3.request, &c3.reply);
        ZR_CHECK("commands: receipt UNKNOWN_PLAN named",
                 strcmp(c3.reply.error.code, "UNKNOWN_PLAN") == 0);
        zr_cmd_free(&c3);
    }

    /* queue after settlement: the claim still waits for owner review. */
    {
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        zcl_native_handle_zcode_reward_queue(&c.request, &c.reply);
        const struct json_value *tallies =
            json_get(&c.reply.data, "tallies");
        ZR_CHECK("commands: post-settle tallies",
                 json_get_int(json_get(tallies, "settled")) == 2 &&
                 json_get_int(json_get(tallies, "queued")) == 1 &&
                 json_get_int(json_get(&c.reply.data,
                                       "settled_facts")) == 2);
        zr_cmd_free(&c);
    }

    /* contributor.show surfaces the ledger facts exactly. */
    {
        char pub1_hex[67], pub2_hex[67];
        zr_hex_enc(pub1, 33, pub1_hex);
        zr_hex_enc(pub2, 33, pub2_hex);
        struct zr_cmd c;
        zr_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "pubkey", pub1_hex);
        zcl_native_handle_zcode_contributor_show(&c.request, &c.reply);
        const struct json_value *rw = json_get(&c.reply.data, "rewards");
        ZR_CHECK("commands: contributor earned_score from the ledger",
                 rw && json_get_int(json_get(rw, "earned_score")) == 900 &&
                 json_get_int(json_get(rw, "settled_entries")) == 1 &&
                 json_get_int(json_get(rw, "queued_entries")) == 0 &&
                 json_get_int(json_get(rw, "rejected_entries")) == 0 &&
                 json_get_bool(json_get(rw, "simulated")));
        ZR_CHECK("commands: earned_score and token facts stay separate",
                 rw && json_get_int(json_get(
                           rw, "token_rewards_received")) == 900 &&
                 json_get(rw, "balance") == NULL &&
                 json_get(rw, "current_token_balance") == NULL);
        zr_cmd_free(&c);

        struct zr_cmd c2;
        zr_cmd_init(&c2, datadir);
        (void)json_push_kv_str(&c2.input, "pubkey", pub2_hex);
        zcl_native_handle_zcode_contributor_show(&c2.request, &c2.reply);
        const struct json_value *rw2 = json_get(&c2.reply.data, "rewards");
        ZR_CHECK("commands: second contributor reflects queued + settled",
                 rw2 && json_get_int(json_get(rw2, "earned_score")) ==
                            400 &&
                 json_get_int(json_get(rw2, "settled_entries")) == 1 &&
                 json_get_int(json_get(rw2, "queued_entries")) == 1 &&
                 json_get_int(json_get(rw2, "queued_points")) == 1200);
        zr_cmd_free(&c2);

        /* A key with no facts at all: zeros, stable schema. */
        uint8_t pub3[33];
        zr_pub(63, pub3);
        char pub3_hex[67];
        zr_hex_enc(pub3, 33, pub3_hex);
        struct zr_cmd c3;
        zr_cmd_init(&c3, datadir);
        (void)json_push_kv_str(&c3.input, "pubkey", pub3_hex);
        zcl_native_handle_zcode_contributor_show(&c3.request, &c3.reply);
        const struct json_value *rw3 = json_get(&c3.reply.data, "rewards");
        ZR_CHECK("commands: unknown contributor shows zero facts",
                 rw3 && json_get_int(json_get(rw3, "earned_score")) == 0 &&
                 json_get_int(json_get(rw3, "queued_entries")) == 0 &&
                 !json_get_bool(json_get(&c3.reply.data, "has_published")));
        zr_cmd_free(&c3);
    }
    zr_rm_rf(datadir);
    return failures;
}

int test_zcode_reward(void)
{
    printf("\n=== zcode_reward: simulated reward ledger + settlement ===\n");
    int failures = 0;
    failures += t_enqueue();
    failures += t_roundtrip();
    failures += t_crash_replay();
    failures += t_caps_from_ledger();
    failures += t_double_reward();
    failures += t_commands();
    printf("=== zcode_reward complete: %d failure(s) ===\n", failures);
    return failures;
}
