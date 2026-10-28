/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_badge — the SIMULATED ZCODE Badges (slice 10:
 * contexts/commons/modules/vcs/package_badge.*, contexts/commons/modules/vcs/package_badge_eligible.*, the
 * zcode badge eligible/plan/issue + zcode contributor badges handlers
 * in tools/command/native_zcode_badge_command.c).
 *
 * Coverage (adversarial first):
 *   1. Codec: roundtrip; forged signature, high-S malleation, wrong
 *      issuer key, and every field rule named (type, period pair,
 *      zero evidence/policy, sequence 0, off-curve keys, bad magic,
 *      bad length).
 *   2. The pure evaluator: every badge type's eligible/not-eligible
 *      transitions, periods derived from the FACTS (the crossing day,
 *      never "today"), deterministic evidence hashes, unavailable types
 *      named honestly.
 *   3. The store: persist/reload; a forged badge (bad issuer signature)
 *      rejected on load; a filename that commits a different id
 *      rejected; a foreign-issuer badge never satisfies dedup and never
 *      lists as earned; dedup is (contributor + type + period) exact —
 *      a different period or a different contributor is allowed; .tmp
 *      crash artifacts skipped.
 *   4. Plan/issue: DOUBLE-ISSUE rejected on BOTH paths (re-plan
 *      excludes with duplicate-badge; re-issue is ALREADY_ISSUED, never
 *      a double-issue); unknown/stale plans named; wrong-period and
 *      wrong-evidence rows rejected at commit revalidation; sequence
 *      conflicts named; policy/issuer mismatch rejected; signer
 *      failure writes nothing; crash resume finishes an interrupted
 *      issue (resumed, replayed, never duplicated).
 *   5. Permanence + cross-period dedup: a TOP_DAILY badge survives the
 *      contributor falling off the board; TOP_DAILY on two different
 *      days is allowed (different achievement periods).
 *   6. Commands over fixture datadirs: eligible (evidence facts,
 *      unavailable named), plan (rows + exclusions + idempotent
 *      re-plan), issue (happy path, ALREADY_ISSUED, UNKNOWN_PLAN,
 *      ISSUER_KEY_MISMATCH), contributor badges (permanent listing),
 *      NO_BADGE_POLICY. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "core/uint256.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/package_badge.h"
#include "vcs/package_badge_eligible.h"
#include "vcs/package_rank.h"
#include "vcs/package_reward.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZB_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_badge: %s... OK\n", (name)); }         \
    else { printf("  zcode_badge: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── small fixtures (the test_zcode_rank / test_zcode_verify pattern) ── */

static void zb_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zb_mkdir_p(const char *path)
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

static bool zb_rm_rf(const char *path)
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

/* Real secp256k1 keypairs (badge pubkeys must parse on the curve). */
static bool zb_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static void zb_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
    if (out[0] == 0)
        out[0] = 1;
}

static void zb_facts_hash(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(0xf0 - seed - i);
    if (out[0] == 0)
        out[0] = 0xaa;
}

/* Sign a fully-formed badge (signature zeroed on entry). */
static bool zb_sign(struct privkey *sk, struct vcs_badge *badge)
{
    uint8_t id[VCS_PACKAGE_BADGE_ID_BYTES];
    if (vcs_badge_id(badge, id) != VCS_BADGE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(badge->signature, compact + 1, VCS_PACKAGE_BADGE_SIGNATURE_BYTES);
    return true;
}

/* Build + sign a badge. */
static bool zb_make_badge(struct privkey *issuer_sk,
                          const uint8_t issuer_pk[33],
                          const uint8_t recipient[33],
                          enum vcs_badge_type type, int64_t first,
                          int64_t last, uint8_t evidence_seed,
                          uint8_t policy_seed, uint64_t sequence,
                          struct vcs_badge *out)
{
    memset(out, 0, sizeof(*out));
    out->schema_version = VCS_PACKAGE_BADGE_VERSION;
    out->type = (uint8_t)type;
    memcpy(out->recipient, recipient, 33);
    out->period_first_day = first;
    out->period_last_day = last;
    zb_root(evidence_seed, out->evidence_root);
    zb_root(policy_seed, out->policy_id);
    out->sequence = sequence;
    memcpy(out->issuer_pubkey, issuer_pk, 33);
    return zb_sign(issuer_sk, out);
}

/* Write the <zcode>/badge_policy file (policy id line 1, issuer pubkey
 * line 2). */
static bool zb_write_policy(const char *zcode_dir, uint8_t policy_seed,
                            const uint8_t issuer_pk[33])
{
    char path[4400];
    snprintf(path, sizeof(path), "%s/badge_policy", zcode_dir);
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    uint8_t policy_id[32];
    zb_root(policy_seed, policy_id);
    char hex[67];
    zb_hex_enc(policy_id, 32, hex);
    fprintf(f, "%s\n", hex);
    zb_hex_enc(issuer_pk, 33, hex);
    fprintf(f, "%s\n", hex);
    return fclose(f) == 0;
}

/* Reward-ledger helpers (the test_zcode_rank pattern, with real pubkeys). */
static enum vcs_reward_enqueue_error zb_auto(struct vcs_reward_ledger *l,
                                             uint8_t root_seed,
                                             const uint8_t pub[33],
                                             enum vcs_reward_category cat,
                                             uint32_t points,
                                             uint8_t facts_seed,
                                             uint8_t id_out[32])
{
    uint8_t root[32], facts[32];
    zb_root(root_seed, root);
    zb_facts_hash(facts_seed, facts);
    return vcs_reward_enqueue_auto(l, root, pub, cat, points, facts,
                                   id_out);
}

static enum vcs_reward_commit_error zb_settle(struct vcs_reward_ledger *l,
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

/* The issue-signer closure bound to a real secret key. */
static bool zb_issue_sign(struct vcs_badge *badge,
                          const uint8_t badge_id[32], void *ctx)
{
    struct privkey *sk = ctx;
    struct uint256 hash;
    memcpy(hash.data, badge_id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(badge->signature, compact + 1, VCS_PACKAGE_BADGE_SIGNATURE_BYTES);
    return true;
}

static bool zb_fail_sign(struct vcs_badge *badge,
                         const uint8_t badge_id[32], void *ctx)
{
    (void)badge;
    (void)badge_id;
    (void)ctx;
    return false;
}

/* ── 1. the codec ───────────────────────────────────────────────────── */

/* The wire codec on a signed badge: roundtrip, then the named magic and
 * length rejections. */
static int t_codec_wire(struct vcs_badge *badge)
{
    int failures = 0;
    uint8_t wire[VCS_PACKAGE_BADGE_WIRE_BYTES];
    struct vcs_badge back;
    ZB_CHECK("codec: serialize/parse roundtrip",
             vcs_badge_serialize(badge, wire, sizeof(wire)) ==
                     VCS_BADGE_OK &&
                 vcs_badge_parse(wire, sizeof(wire), &back) ==
                     VCS_BADGE_OK &&
                 memcmp(&back, badge, sizeof(*badge)) == 0 &&
                 vcs_badge_verify(&back) == VCS_BADGE_OK);
    wire[0] ^= 0x01;
    ZB_CHECK("codec: bad magic named",
             vcs_badge_parse(wire, sizeof(wire), &back) ==
                 VCS_BADGE_ERR_WIRE_MAGIC);
    uint8_t longer[VCS_PACKAGE_BADGE_WIRE_BYTES + 1];
    memset(longer, 0, sizeof(longer));
    ZB_CHECK("codec: wrong length named",
             vcs_badge_parse(longer, sizeof(longer), &back) ==
                 VCS_BADGE_ERR_WIRE_OVERSIZE);
    return failures;
}

/* A forged signature and a badge signed by a foreign key are rejected. */
static int t_codec_forgery(struct vcs_badge *badge, struct privkey *other_sk,
                           const struct pubkey *issuer_pk,
                           const struct pubkey *recipient_pk)
{
    int failures = 0;
    struct vcs_badge forged = *badge;
    forged.signature[10] ^= 0x01;
    ZB_CHECK("codec: forged signature rejected",
             vcs_badge_verify(&forged) == VCS_BADGE_ERR_SIG_VERIFY);
    memset(forged.signature + 32, 0xff, 32); /* s > n/2 */
    ZB_CHECK("codec: high-S malleation named",
             vcs_badge_verify(&forged) == VCS_BADGE_ERR_SIG_LOW_S);

    struct vcs_badge wrong;
    ZB_CHECK("codec: built with the foreign key",
             zb_make_badge(other_sk, issuer_pk->vch, recipient_pk->vch,
                           VCS_BADGE_TOP_DAILY, 20000, 20000, 0x20,
                           0x30, 7, &wrong));
    ZB_CHECK("codec: wrong issuer key rejected",
             vcs_badge_verify(&wrong) == VCS_BADGE_ERR_SIG_VERIFY);
    return failures;
}

/* Field rules, each named. */
static int t_codec_field_rules(const struct vcs_badge *badge)
{
    int failures = 0;
    struct vcs_badge b = *badge;
    b.type = 99;
    ZB_CHECK("codec: unknown type named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_TYPE);
    b = *badge;
    b.period_first_day = 20001;
    b.period_last_day = 20000;
    ZB_CHECK("codec: inverted period named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_PERIOD);
    b = *badge;
    b.period_last_day = VCS_BADGE_PERIOD_NONE; /* exactly one -1 */
    ZB_CHECK("codec: half-sentinel period named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_PERIOD);
    b = *badge;
    memset(b.evidence_root, 0, 32);
    ZB_CHECK("codec: zero evidence root named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_EVIDENCE_ROOT);
    b = *badge;
    memset(b.policy_id, 0, 32);
    ZB_CHECK("codec: zero policy id named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_POLICY_ID);
    b = *badge;
    b.sequence = 0;
    ZB_CHECK("codec: sequence zero named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_SEQUENCE);
    b = *badge;
    memset(b.recipient, 0, 33);
    ZB_CHECK("codec: off-curve recipient named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_RECIPIENT);
    b = *badge;
    memset(b.issuer_pubkey, 0, 33);
    ZB_CHECK("codec: off-curve issuer named",
             vcs_badge_validate(&b) == VCS_BADGE_ERR_ISSUER);
    return failures;
}

/* The non-periodic sentinel pair is valid (once-ever badges). */
static int t_codec_non_periodic(struct privkey *issuer_sk,
                                const struct pubkey *issuer_pk,
                                const struct pubkey *recipient_pk)
{
    int failures = 0;
    struct vcs_badge once;
    ZB_CHECK("codec: non-periodic badge verifies",
             zb_make_badge(issuer_sk, issuer_pk->vch, recipient_pk->vch,
                           VCS_BADGE_FIRST_PACKAGE,
                           VCS_BADGE_PERIOD_NONE, VCS_BADGE_PERIOD_NONE,
                           0x21, 0x30, 1, &once) &&
                 vcs_badge_is_non_periodic(&once) &&
                 vcs_badge_verify(&once) == VCS_BADGE_OK);
    return failures;
}

/* Type strings round-trip; availability honest. */
static int t_codec_type_names(void)
{
    int failures = 0;
    enum vcs_badge_type t;
    ZB_CHECK("codec: type strings round-trip",
             vcs_badge_type_from_string("top-daily", &t) &&
                 t == VCS_BADGE_TOP_DAILY &&
                 vcs_badge_type_from_string("bug-hunter", &t) &&
                 t == VCS_BADGE_BUG_HUNTER &&
                 !vcs_badge_type_from_string("bogus", &t));
    ZB_CHECK("codec: availability honest",
             vcs_badge_type_available(VCS_BADGE_FIRST_PACKAGE) &&
                 !vcs_badge_type_available(VCS_BADGE_POPULAR_PACKAGE) &&
                 !vcs_badge_type_available(VCS_BADGE_RARE_PACKAGE_SEEDER));
    return failures;
}

static int t_codec(void)
{
    int failures = 0;
    struct privkey issuer_sk, other_sk;
    struct pubkey issuer_pk, other_pk, recipient_pk;
    ZB_CHECK("codec: keypairs", zb_keypair(1, &issuer_sk, &issuer_pk) &&
                                  zb_keypair(4, &other_sk, &other_pk) &&
                                  zb_keypair(5, &other_sk, &recipient_pk));

    struct vcs_badge badge;
    ZB_CHECK("codec: signed badge verifies",
             zb_make_badge(&issuer_sk, issuer_pk.vch, recipient_pk.vch,
                           VCS_BADGE_TOP_DAILY, 20000, 20000, 0x20, 0x30,
                           7, &badge) &&
                 vcs_badge_verify(&badge) == VCS_BADGE_OK);

    /* The id is deterministic and independent of the signature. */
    uint8_t id1[32], id2[32];
    ZB_CHECK("codec: id deterministic",
             vcs_badge_id(&badge, id1) == VCS_BADGE_OK &&
                 vcs_badge_id(&badge, id2) == VCS_BADGE_OK &&
                 memcmp(id1, id2, 32) == 0);
    {
        struct vcs_badge nosig = badge;
        memset(nosig.signature, 0, 64);
        uint8_t id3[32];
        ZB_CHECK("codec: id excludes the signature",
                 vcs_badge_id(&nosig, id3) == VCS_BADGE_OK &&
                     memcmp(id1, id3, 32) == 0);
    }

    failures += t_codec_wire(&badge);
    failures += t_codec_forgery(&badge, &other_sk, &issuer_pk,
                                &recipient_pk);
    failures += t_codec_field_rules(&badge);
    failures += t_codec_non_periodic(&issuer_sk, &issuer_pk, &recipient_pk);
    failures += t_codec_type_names();
    return failures;
}

/* ── 2. the pure evaluator ──────────────────────────────────────────── */

/* Every badge type that is eligible on the first-package and ten-packages
 * facts. */
static int t_eval_packages(const struct vcs_badge_facts *facts,
                           const uint8_t *pk, int64_t today,
                           struct vcs_badge_eval *ev)
{
    int failures = 0;
    ZB_CHECK("eval: first-package eligible with the package root",
             vcs_badge_evaluate(VCS_BADGE_FIRST_PACKAGE, pk, facts, today,
                                ev) &&
                 ev->available && ev->eligible &&
                 ev->period_first == VCS_BADGE_PERIOD_NONE &&
                 memcmp(ev->evidence_root, facts->first_package_root, 32) ==
                     0);
    ZB_CHECK("eval: ten-packages honestly short",
             vcs_badge_evaluate(VCS_BADGE_TEN_PACKAGES, pk, facts, today,
                                ev) &&
                 ev->available && !ev->eligible &&
                 strstr(ev->detail, "9 distinct packages") != NULL);
    return failures;
}

/* WRONG-PERIOD guard: the achievement period is the crossing day from the
 * facts, never "today". */
static int t_eval_hundred_tests(const struct vcs_badge_facts *facts,
                                const uint8_t *pk, int64_t today,
                                struct vcs_badge_eval *ev)
{
    int failures = 0;
    ZB_CHECK("eval: hundred-tests period is the crossing day",
             vcs_badge_evaluate(VCS_BADGE_HUNDRED_TESTS, pk, facts, today,
                                ev) &&
                 ev->eligible && ev->period_first == 100 &&
                 ev->period_last == 100 && ev->period_first != today &&
                 memcmp(ev->evidence_root, facts->hundred_tests_root, 32) ==
                     0);
    return failures;
}

/* The report badges take the day of the first fix or reproduction. */
static int t_eval_fix_reports(const struct vcs_badge_facts *facts,
                              const uint8_t *pk, int64_t today,
                              struct vcs_badge_eval *ev)
{
    int failures = 0;
    ZB_CHECK("eval: bug-hunter period is the first fix day",
             vcs_badge_evaluate(VCS_BADGE_BUG_HUNTER, pk, facts, today,
                                ev) &&
                 ev->eligible && ev->period_first == 50 &&
                 memcmp(ev->evidence_root, facts->bug_fix_root, 32) == 0);
    ZB_CHECK("eval: security-researcher eligible",
             vcs_badge_evaluate(VCS_BADGE_SECURITY_RESEARCHER, pk, facts,
                                today, ev) &&
                 ev->eligible && ev->period_first == 60);
    ZB_CHECK("eval: reproducible-builder eligible",
             vcs_badge_evaluate(VCS_BADGE_REPRODUCIBLE_BUILDER, pk, facts,
                                today, ev) &&
                 ev->eligible && ev->period_first == 70);
    return failures;
}

/* Rank badges: the period is the window containing today. Day 20000 is
 * 2024-10-04 (a Friday of ISO 2024-W40: days 19996..20002; October 2024 is
 * days 19997..20027). */
static int t_eval_windows(const struct vcs_badge_facts *facts,
                          const uint8_t *pk, int64_t today,
                          struct vcs_badge_eval *ev)
{
    int failures = 0;
    ZB_CHECK("eval: top-daily window",
             vcs_badge_evaluate(VCS_BADGE_TOP_DAILY, pk, facts, today, ev) &&
                 ev->eligible && ev->period_first == 20000 &&
                 ev->period_last == 20000);
    {
        uint8_t check[32];
        vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk, 20000, 20000, 900,
                                check);
        ZB_CHECK("eval: top-daily evidence is the deterministic hash",
                 memcmp(ev->evidence_root, check, 32) == 0);
    }
    ZB_CHECK("eval: top-weekly window",
             vcs_badge_evaluate(VCS_BADGE_TOP_WEEKLY, pk, facts, today, ev) &&
                 ev->eligible && ev->period_first == 19996 &&
                 ev->period_last == 20002);
    ZB_CHECK("eval: top-monthly window",
             vcs_badge_evaluate(VCS_BADGE_TOP_MONTHLY, pk, facts, today,
                                ev) &&
                 ev->eligible && ev->period_first == 19997 &&
                 ev->period_last == 20027);
    return failures;
}

/* The one-year and early-contributor achievement days. */
static int t_eval_achievement(const struct vcs_badge_facts *facts,
                              const uint8_t *pk, int64_t today,
                              struct vcs_badge_eval *ev)
{
    int failures = 0;
    ZB_CHECK("eval: one-year-maintainer achievement day",
             vcs_badge_evaluate(VCS_BADGE_ONE_YEAR_MAINTAINER, pk, facts,
                                today, ev) &&
                 ev->eligible && ev->period_first == 10 + 365 &&
                 ev->period_last == 10 + 365);
    ZB_CHECK("eval: early contributor inside the pioneer window",
             vcs_badge_evaluate(VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR, pk, facts,
                                today, ev) &&
                 ev->eligible &&
                 ev->period_first == VCS_BADGE_PERIOD_NONE);
    return failures;
}

/* The P2P badges are named unavailable, never eligible. */
static int t_eval_unavailable(const struct vcs_badge_facts *facts,
                              const uint8_t *pk, int64_t today,
                              struct vcs_badge_eval *ev)
{
    int failures = 0;
    ZB_CHECK("eval: P2P badges named unavailable",
             vcs_badge_evaluate(VCS_BADGE_POPULAR_PACKAGE, pk, facts, today,
                                ev) &&
                 !ev->available && !ev->eligible &&
                 strstr(ev->detail, "unavailable") != NULL &&
             vcs_badge_evaluate(VCS_BADGE_RARE_PACKAGE_SEEDER, pk, facts,
                                today, ev) &&
                 !ev->available && !ev->eligible);
    return failures;
}

/* Empty facts: everything available honestly not eligible. */
static int t_eval_empty_facts(const uint8_t *pk, int64_t today)
{
    int failures = 0;
    struct vcs_badge_facts empty;
    memset(&empty, 0, sizeof(empty));
    bool any_eligible = false;
    for (size_t i = 0; i < VCS_BADGE_TYPE_COUNT; i++) {
        struct vcs_badge_eval e2;
        if (!vcs_badge_evaluate((enum vcs_badge_type)i, pk, &empty, today,
                                &e2))
            continue;
        if (e2.eligible)
            any_eligible = true;
    }
    ZB_CHECK("eval: empty facts qualify for nothing", !any_eligible);
    return failures;
}

/* Pioneer window edge: first settled day 41 with ledger earliest 10 is
 * outside (10 + 30). */
static int t_eval_pioneer(const struct vcs_badge_facts *facts,
                          const uint8_t *pk, int64_t today,
                          struct vcs_badge_eval *ev)
{
    int failures = 0;
    struct vcs_badge_facts late = *facts;
    late.earliest_settled_day = 41;
    ZB_CHECK("eval: outside the pioneer window",
             vcs_badge_evaluate(VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR, pk, &late,
                                today, ev) &&
                 !ev->eligible);
    late.earliest_settled_day = 40;
    ZB_CHECK("eval: pioneer window boundary inclusive",
             vcs_badge_evaluate(VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR, pk, &late,
                                today, ev) &&
                 ev->eligible);
    return failures;
}

/* Evidence hash: deterministic and period-sensitive. */
static int t_eval_hash_period(const uint8_t *pk)
{
    int failures = 0;
    uint8_t h1[32], h2[32], h3[32];
    vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk, 20000, 20000, 900, h1);
    vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk, 20000, 20000, 900, h2);
    vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk, 20001, 20001, 900, h3);
    ZB_CHECK("eval: evidence hash deterministic + period-sensitive",
             memcmp(h1, h2, 32) == 0 && memcmp(h1, h3, 32) != 0);
    return failures;
}

static int t_evaluator(void)
{
    int failures = 0;
    struct privkey sk;
    struct pubkey pk;
    ZB_CHECK("eval: keypair", zb_keypair(2, &sk, &pk));
    const int64_t today = 20000;

    struct vcs_badge_facts facts;
    memset(&facts, 0, sizeof(facts));
    facts.release_count = 3;
    facts.distinct_package_count = 9;
    facts.has_first_package = true;
    zb_root(0x40, facts.first_package_root);
    facts.has_settled = true;
    facts.earliest_settled_day = 10;
    facts.latest_settled_day = 400;
    facts.test_points_total = 110;
    facts.hundred_tests_crossed = true;
    facts.hundred_tests_day = 100;
    zb_root(0x41, facts.hundred_tests_root);
    facts.has_bug_fix = true;
    facts.bug_fix_day = 50;
    zb_root(0x42, facts.bug_fix_root);
    facts.has_security_fix = true;
    facts.security_fix_day = 60;
    zb_root(0x43, facts.security_fix_root);
    facts.has_reproduction = true;
    facts.reproduction_day = 70;
    zb_root(0x44, facts.reproduction_root);
    facts.ledger_any = true;
    facts.ledger_earliest_day = 10;
    facts.top_daily = true;
    facts.top_daily_points = 900;
    facts.top_weekly = true;
    facts.top_weekly_points = 900;
    facts.top_monthly = true;
    facts.top_monthly_points = 900;

    struct vcs_badge_eval ev;
    failures += t_eval_packages(&facts, pk.vch, today, &ev);
    failures += t_eval_hundred_tests(&facts, pk.vch, today, &ev);
    failures += t_eval_fix_reports(&facts, pk.vch, today, &ev);
    failures += t_eval_windows(&facts, pk.vch, today, &ev);
    failures += t_eval_achievement(&facts, pk.vch, today, &ev);
    failures += t_eval_unavailable(&facts, pk.vch, today, &ev);
    failures += t_eval_empty_facts(pk.vch, today);
    failures += t_eval_pioneer(&facts, pk.vch, today, &ev);
    failures += t_eval_hash_period(pk.vch);
    return failures;
}

/* ── 3. the store ───────────────────────────────────────────────────── */

static int zb_linked_policy_regression(const char *zcode)
{
    int failures = 0;
    char leaf[4400], outside[4400];
    snprintf(leaf, sizeof(leaf), "%s/badge_policy", zcode);
    snprintf(outside, sizeof(outside), "%s/outside-policy", zcode);
    bool linked = rename(leaf, outside) == 0 &&
                  symlink("outside-policy", leaf) == 0;
    ZB_CHECK("store: valid policy linked from outside is prepared", linked);
    if (linked) {
        struct vcs_badge_policy linked_policy;
        ZB_CHECK("store: linked policy cannot set badge trust",
                 !vcs_badge_policy_load(zcode, &linked_policy));
        bool restored = unlink(leaf) == 0 && rename(outside, leaf) == 0;
        ZB_CHECK("store: same policy as real leaf loads",
                 restored && vcs_badge_policy_load(zcode, &linked_policy));
    }
    return failures;
}

/* The keys and the policy the store checks share. */
struct zb_store_fx {
    struct privkey issuer_sk, foreign_sk;
    struct pubkey issuer_pk, foreign_pk, c_pk, d_pk;
    struct vcs_badge_policy policy;
    struct vcs_badge b1, b2, b3;
};

static int zb_store_setup(const char *zcode, struct zb_store_fx *fx)
{
    int failures = 0;
    struct privkey sk2, sk3;
    ZB_CHECK("store: keypairs",
             zb_keypair(1, &fx->issuer_sk, &fx->issuer_pk) &&
                 zb_keypair(4, &fx->foreign_sk, &fx->foreign_pk) &&
                 zb_keypair(2, &sk2, &fx->c_pk) &&
                 zb_keypair(3, &sk3, &fx->d_pk));
    ZB_CHECK("store: policy file written",
             zb_write_policy(zcode, 0x30, fx->issuer_pk.vch));
    ZB_CHECK("store: policy loads",
             vcs_badge_policy_load(zcode, &fx->policy) &&
                 memcmp(fx->policy.issuer_pubkey, fx->issuer_pk.vch, 33) ==
                     0);
    return failures;
}

static int zb_store_build_badges(struct zb_store_fx *fx)
{
    int failures = 0;
    ZB_CHECK("store: badges built",
             zb_make_badge(&fx->issuer_sk, fx->issuer_pk.vch, fx->c_pk.vch,
                           VCS_BADGE_FIRST_PACKAGE, VCS_BADGE_PERIOD_NONE,
                           VCS_BADGE_PERIOD_NONE, 0x50, 0x30, 1, &fx->b1) &&
                 zb_make_badge(&fx->issuer_sk, fx->issuer_pk.vch,
                               fx->c_pk.vch, VCS_BADGE_TOP_DAILY, 20000,
                               20000, 0x51, 0x30, 2, &fx->b2) &&
                 zb_make_badge(&fx->issuer_sk, fx->issuer_pk.vch,
                               fx->d_pk.vch, VCS_BADGE_TOP_DAILY, 20000,
                               20000, 0x52, 0x30, 3, &fx->b3));
    return failures;
}

/* Persist the three badges, a dedup no-op, and refuse an invalid badge. */
static int zb_store_persist_badges(const char *zcode,
                                   struct zb_store_fx *fx)
{
    int failures = 0;
    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: empty store loads", s != NULL);
    uint8_t id1[32], id1b[32];
    ZB_CHECK("store: persist + dedup no-op",
             vcs_badge_store_persist(s, &fx->b1, id1) ==
                     VCS_BADGE_PERSIST_OK &&
                 vcs_badge_store_persist(s, &fx->b1, id1b) ==
                     VCS_BADGE_PERSIST_DUPLICATE &&
                 memcmp(id1, id1b, 32) == 0);
    uint8_t id_scratch[32];
    ZB_CHECK("store: persist rest",
             vcs_badge_store_persist(s, &fx->b2, id_scratch) ==
                     VCS_BADGE_PERSIST_OK &&
                 vcs_badge_store_persist(s, &fx->b3, id_scratch) ==
                     VCS_BADGE_PERSIST_OK);
    /* An unsigned/invalid badge is never persisted. */
    {
        struct vcs_badge bad = fx->b1;
        bad.signature[0] ^= 0x01;
        ZB_CHECK("store: invalid badge refused at persist",
                 vcs_badge_store_persist(s, &bad, id_scratch) ==
                     VCS_BADGE_PERSIST_INVALID);
    }
    vcs_badge_store_free(s);
    return failures;
}

/* Reload: replayed from the durable wires; dedup, sequences and the
 * contributor listing. */
static int zb_store_reload_checks(const char *zcode,
                                  const struct zb_store_fx *fx)
{
    int failures = 0;
    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: reload replays three badges",
             s && vcs_badge_store_badge_count(s) == 3 &&
                 vcs_badge_store_corrupt_count(s) == 0);
    ZB_CHECK("store: dedup exact (contributor + type + period)",
             vcs_badge_store_dedup_hit(s, &fx->policy, fx->c_pk.vch,
                                       VCS_BADGE_FIRST_PACKAGE,
                                       VCS_BADGE_PERIOD_NONE,
                                       VCS_BADGE_PERIOD_NONE) &&
             vcs_badge_store_dedup_hit(s, &fx->policy, fx->c_pk.vch,
                                       VCS_BADGE_TOP_DAILY, 20000,
                                       20000) &&
             !vcs_badge_store_dedup_hit(s, &fx->policy, fx->c_pk.vch,
                                        VCS_BADGE_TOP_DAILY, 20001,
                                        20001) &&
             !vcs_badge_store_dedup_hit(s, &fx->policy, fx->c_pk.vch,
                                        VCS_BADGE_TOP_WEEKLY, 20000,
                                        20000));
    ZB_CHECK("store: same type+period for another contributor allowed",
             !vcs_badge_store_dedup_hit(s, &fx->policy, fx->c_pk.vch,
                                        VCS_BADGE_TOP_DAILY, 20000,
                                        20000) ||
                 vcs_badge_store_dedup_hit(s, &fx->policy, fx->d_pk.vch,
                                           VCS_BADGE_TOP_DAILY, 20000,
                                           20000));
    ZB_CHECK("store: max sequence per issuer",
             vcs_badge_store_max_sequence(s, fx->issuer_pk.vch) == 3 &&
                 vcs_badge_store_max_sequence(s, fx->foreign_pk.vch) == 0);
    {
        struct vcs_badge earned[8];
        size_t total = vcs_badge_store_contributor_badges(
            s, &fx->policy, fx->c_pk.vch, earned, 8);
        ZB_CHECK("store: contributor badges in issuance order",
                 total == 2 && earned[0].sequence == 1 &&
                     earned[1].sequence == 2 &&
                     earned[0].type == VCS_BADGE_FIRST_PACKAGE &&
                     earned[1].type == VCS_BADGE_TOP_DAILY);
    }
    vcs_badge_store_free(s);
    return failures;
}

/* Plant the wire of a badge under the name it is filed as, then load: the
 * planted file is counted corrupt and the three good badges are kept. */
static int zb_store_plant_wire(const char *zcode,
                               const struct vcs_badge *wire_badge,
                               const uint8_t name[32],
                               const char *serialized_msg,
                               const char *planted_msg,
                               const char *rejected_msg,
                               const char *removed_msg)
{
    int failures = 0;
    uint8_t wire[VCS_PACKAGE_BADGE_WIRE_BYTES];
    ZB_CHECK(serialized_msg,
             vcs_badge_serialize(wire_badge, wire, sizeof(wire)) ==
                 VCS_BADGE_OK);
    char hex[65], path[4400];
    zb_hex_enc(name, 32, hex);
    snprintf(path, sizeof(path), "%s/badges/%s", zcode, hex);
    FILE *f = fopen(path, "wb");
    ZB_CHECK(planted_msg,
             f && fwrite(wire, 1, sizeof(wire), f) == sizeof(wire) &&
                 fclose(f) == 0);
    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    ZB_CHECK(rejected_msg,
             s && vcs_badge_store_badge_count(s) == 3 &&
                 vcs_badge_store_corrupt_count(s) == 1);
    vcs_badge_store_free(s);
    ZB_CHECK(removed_msg, unlink(path) == 0);
    return failures;
}

/* A FORGED badge (bad issuer signature) and a filename that commits a
 * DIFFERENT id are both rejected on load. */
static int zb_store_wire_cases(const char *zcode,
                               const struct zb_store_fx *fx)
{
    int failures = 0;
    struct vcs_badge forged = fx->b2;
    forged.sequence = 9; /* distinct content -> distinct id */
    uint8_t fid[32];
    (void)vcs_badge_id(&forged, fid);
    forged.signature[10] ^= 0x01; /* the forgery */
    failures += zb_store_plant_wire(zcode, &forged, fid,
                                    "store: forged wire serializes",
                                    "store: forged wire planted",
                                    "store: forged badge rejected on load",
                                    "store: forged plant removed");

    struct vcs_badge renamed = fx->b2;
    renamed.sequence = 10; /* content id != the name it is filed as */
    uint8_t wrong_name[32];
    zb_root(0x7f, wrong_name);
    failures += zb_store_plant_wire(zcode, &renamed, wrong_name,
                                    "store: renamed wire serializes",
                                    "store: renamed wire planted",
                                    "store: id-mismatched wire rejected on load",
                                    "store: renamed plant removed");
    return failures;
}

/* A FOREIGN-ISSUER badge loads (its signature is valid) but never
 * satisfies dedup and never lists as earned. */
static int zb_store_foreign(const char *zcode, struct zb_store_fx *fx)
{
    int failures = 0;
    uint8_t id_scratch[32];
    struct vcs_badge foreign;
    ZB_CHECK("store: foreign badge built",
             zb_make_badge(&fx->foreign_sk, fx->foreign_pk.vch,
                           fx->d_pk.vch, VCS_BADGE_BUG_HUNTER, 50, 50, 0x53,
                           0x30, 1, &foreign));
    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: foreign badge persists",
             vcs_badge_store_persist(s, &foreign, id_scratch) ==
                 VCS_BADGE_PERSIST_OK);
    vcs_badge_store_free(s);
    s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: foreign badge loads but is not recognized",
             s && vcs_badge_store_badge_count(s) == 4 &&
                 !vcs_badge_recognized(&foreign, &fx->policy) &&
                 !vcs_badge_store_dedup_hit(s, &fx->policy, fx->d_pk.vch,
                                            VCS_BADGE_BUG_HUNTER, 50, 50));
    struct vcs_badge earned[8];
    ZB_CHECK("store: foreign badge never lists as earned",
             vcs_badge_store_contributor_badges(s, &fx->policy,
                                                fx->d_pk.vch, earned, 8) ==
                     1 &&
                 earned[0].type == VCS_BADGE_TOP_DAILY);
    vcs_badge_store_free(s);
    return failures;
}

/* A leftover atomic-write temp is a crash artifact, not corruption. */
static int zb_store_temp_artifact(const char *zcode)
{
    int failures = 0;
    char path[4400];
    snprintf(path, sizeof(path), "%s/badges/zz.tmp.1.1", zcode);
    FILE *f = fopen(path, "wb");
    ZB_CHECK("store: temp artifact planted", f && fclose(f) == 0);
    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: temp artifact skipped, not corrupt",
             s && vcs_badge_store_badge_count(s) == 4 &&
                 vcs_badge_store_corrupt_count(s) == 0);
    vcs_badge_store_free(s);
    return failures;
}

/* A malformed policy file fails closed. */
static int zb_store_bad_policy(const char *zcode)
{
    int failures = 0;
    char path[4400];
    snprintf(path, sizeof(path), "%s/badge_policy", zcode);
    FILE *f = fopen(path, "wb");
    ZB_CHECK("store: malformed policy planted",
             f && fputs("not-hex-at-all\n", f) >= 0 && fclose(f) == 0);
    struct vcs_badge_policy bad;
    ZB_CHECK("store: malformed policy rejected",
             !vcs_badge_policy_load(zcode, &bad));
    return failures;
}

static int t_store(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_store_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("store: datadir created", zb_mkdir_p(zcode));

    struct zb_store_fx fx;
    failures += zb_store_setup(zcode, &fx);
    failures += zb_linked_policy_regression(zcode);
    failures += zb_store_build_badges(&fx);
    failures += zb_store_persist_badges(zcode, &fx);
    failures += zb_store_reload_checks(zcode, &fx);
    failures += zb_store_wire_cases(zcode, &fx);
    failures += zb_store_foreign(zcode, &fx);
    failures += zb_store_temp_artifact(zcode);
    failures += zb_store_bad_policy(zcode);

    zb_rm_rf(datadir);
    return failures;
}

/* ── 4. plan + issue (the adversarial core) ─────────────────────────── */

/* The fixture state the plan/issue and permanence checks share. */
struct zb_issue_ctx {
    const char *zcode;
    struct privkey issuer_sk;
    struct pubkey issuer_pk, c_pk, d_pk, e_pk, f_pk;
    struct vcs_badge_policy policy;
    struct vcs_badge_store *s;
    struct vcs_reward_ledger *l;
    struct vcs_badge_facts facts;
    struct vcs_badge_plan plan;
    struct vcs_badge_plan_exclusion exclusions[VCS_BADGE_TYPE_COUNT];
    size_t exclusion_count;
    uint8_t c_plan_id[32];
};

static int zb_pi_setup(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct privkey sk2, sk3, sk5, sk6;
    ZB_CHECK("plan: keypairs",
             zb_keypair(1, &ctx->issuer_sk, &ctx->issuer_pk) &&
                 zb_keypair(2, &sk2, &ctx->c_pk) &&
                 zb_keypair(3, &sk3, &ctx->d_pk) &&
                 zb_keypair(5, &sk5, &ctx->e_pk) &&
                 zb_keypair(6, &sk6, &ctx->f_pk));
    ZB_CHECK("plan: policy file written",
             zb_write_policy(ctx->zcode, 0x30, ctx->issuer_pk.vch));
    ZB_CHECK("plan: policy loads",
             vcs_badge_policy_load(ctx->zcode, &ctx->policy));
    return failures;
}

/* Facts: C crosses 100 settled test points at day 20000 (60 + 50) and is
 * the only contributor that day; E settles 50 at 20001. */
static int zb_pi_seed_ledger(const struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(ctx->zcode);
    uint8_t id[32];
    ZB_CHECK("plan: rewards queued",
             zb_auto(l, 0x10, ctx->c_pk.vch,
                     VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 60, 0x10, id) ==
                     VCS_REWARD_ENQUEUE_OK &&
                 zb_auto(l, 0x11, ctx->c_pk.vch,
                         VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 50, 0x11,
                         id) == VCS_REWARD_ENQUEUE_OK);
    ZB_CHECK("plan: day-20000 window settles",
             zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
    /* A settle commits EVERYTHING pending at that day — E's entry is queued
     * after the day-20000 settle so it lands on day 20001. */
    ZB_CHECK("plan: E's reward queued",
             zb_auto(l, 0x12, ctx->e_pk.vch,
                     VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 50, 0x12, id) ==
                 VCS_REWARD_ENQUEUE_OK);
    ZB_CHECK("plan: day-20001 window settles",
             zb_settle(l, 20001) == VCS_REWARD_COMMIT_OK);
    vcs_reward_ledger_free(l);
    return failures;
}

/* The facts builder derives every fact from the ledger. */
static int zb_pi_check_facts(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    vcs_badge_facts_build(ctx->c_pk.vch, NULL, ctx->l, 20000, &ctx->facts);
    ZB_CHECK("plan: facts derived (crossing day, rank 1, pioneer)",
             ctx->facts.has_settled && ctx->facts.hundred_tests_crossed &&
                 ctx->facts.hundred_tests_day == 20000 &&
                 ctx->facts.test_points_total == 110 &&
                 ctx->facts.top_daily && ctx->facts.top_daily_points == 110 &&
                 ctx->facts.top_weekly && ctx->facts.top_monthly &&
                 ctx->facts.ledger_any &&
                 ctx->facts.ledger_earliest_day == 20000 &&
                 !ctx->facts.has_bug_fix && !ctx->facts.has_security_fix &&
                 !ctx->facts.has_reproduction && !ctx->facts.has_first_package);
    return failures;
}

/* PLAN: the five eligible types become rows; the rest are named
 * exclusions. */
static int zb_pi_plan_batch(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    ZB_CHECK("plan: batch assembled",
             vcs_badge_plan_build(ctx->s, &ctx->policy, ctx->c_pk.vch,
                                  &ctx->facts, 20000, &ctx->plan,
                                  ctx->exclusions, &ctx->exclusion_count));
    ZB_CHECK("plan: five rows planned",
             ctx->plan.row_count == 5 && ctx->exclusion_count == 8);
    return failures;
}

struct zb_plan_seen {
    bool hundred, daily, weekly, monthly, early;
    uint64_t seq_sum;
};

static void zb_pi_scan_rows(const struct vcs_badge_plan *plan,
                            struct zb_plan_seen *seen)
{
    memset(seen, 0, sizeof(*seen));
    for (size_t i = 0; i < plan->row_count; i++) {
        const struct vcs_badge_plan_row *r = &plan->rows[i];
        seen->seq_sum += r->sequence;
        switch (r->type) {
        case VCS_BADGE_HUNDRED_TESTS:
            seen->hundred = r->period_first == 20000;
            break;
        case VCS_BADGE_TOP_DAILY:
            seen->daily = r->period_first == 20000 &&
                          r->period_last == 20000;
            break;
        case VCS_BADGE_TOP_WEEKLY:
            seen->weekly = r->period_first == 19996 &&
                           r->period_last == 20002;
            break;
        case VCS_BADGE_TOP_MONTHLY:
            seen->monthly = r->period_first == 19997 &&
                            r->period_last == 20027;
            break;
        case VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR:
            seen->early = r->period_first == VCS_BADGE_PERIOD_NONE;
            break;
        default: break;
        }
    }
}

static int zb_pi_exclusions_named(const struct zb_issue_ctx *ctx)
{
    int failures = 0;
    bool bug_named = false, popular_named = false;
    for (size_t i = 0; i < ctx->exclusion_count; i++) {
        if (ctx->exclusions[i].type == VCS_BADGE_BUG_HUNTER &&
            strcmp(ctx->exclusions[i].rule, VCS_BADGE_RULE_NOT_ELIGIBLE) ==
                0)
            bug_named = true;
        if (ctx->exclusions[i].type == VCS_BADGE_POPULAR_PACKAGE &&
            strcmp(ctx->exclusions[i].rule, VCS_BADGE_RULE_UNAVAILABLE) ==
                0)
            popular_named = true;
    }
    ZB_CHECK("plan: exclusions name the rules", bug_named && popular_named);
    return failures;
}

static int zb_pi_plan_rows(const struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct zb_plan_seen seen;
    zb_pi_scan_rows(&ctx->plan, &seen);
    ZB_CHECK("plan: rows carry the right types + periods",
             seen.hundred && seen.daily && seen.weekly && seen.monthly &&
                 seen.early);
    ZB_CHECK("plan: sequences are 1..5", seen.seq_sum == 1 + 2 + 3 + 4 + 5);
    failures += zb_pi_exclusions_named(ctx);
    return failures;
}

static int zb_pi_plan_persist(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    ZB_CHECK("plan: persist + idempotent re-persist",
             vcs_badge_plan_persist(ctx->s, &ctx->plan) ==
                     VCS_BADGE_PLAN_PERSIST_OK &&
                 vcs_badge_plan_persist(ctx->s, &ctx->plan) ==
                     VCS_BADGE_PLAN_PERSIST_DUPLICATE);
    memcpy(ctx->c_plan_id, ctx->plan.plan_id, 32);
    return failures;
}

/* ISSUE: the happy path persists five signed badges; a replay is a named
 * duplicate, never a double-issue. */
static int zb_pi_issue_commit(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK("issue: batch commits",
             vcs_badge_issue(ctx->s, &ctx->policy, ctx->c_plan_id, NULL,
                             ctx->l, zb_issue_sign, &ctx->issuer_sk, &result,
                             detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_OK &&
                 result.issued_count == 5 && result.replayed_count == 0 &&
                 !result.resumed);
    ZB_CHECK("issue: badges durable + verified",
             vcs_badge_store_badge_count(ctx->s) == 5);
    ZB_CHECK("issue: replay is a named duplicate",
             vcs_badge_issue(ctx->s, &ctx->policy, ctx->c_plan_id, NULL,
                             ctx->l, zb_issue_sign, &ctx->issuer_sk, &result,
                             detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_ALREADY_ISSUED &&
                 vcs_badge_store_badge_count(ctx->s) == 5);
    return failures;
}

/* DOUBLE-ISSUE, plan path: every eligible type now dedup-excluded. Then an
 * unknown plan is named. */
static int zb_pi_replan_and_unknown(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_badge_plan again;
    size_t again_exclusions = 0;
    ZB_CHECK("issue: re-plan dedup-excludes everything",
             vcs_badge_plan_build(ctx->s, &ctx->policy, ctx->c_pk.vch,
                                  &ctx->facts, 20000, &again,
                                  ctx->exclusions, &again_exclusions) &&
                 again.row_count == 0 && again_exclusions == 13);
    bool dup_named = false;
    for (size_t i = 0; i < again_exclusions; i++)
        if (strcmp(ctx->exclusions[i].rule, VCS_BADGE_RULE_DUPLICATE) == 0)
            dup_named = true;
    ZB_CHECK("issue: duplicate-badge rule named", dup_named);

    uint8_t unknown[32];
    zb_root(0x60, unknown);
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK("issue: unknown plan named",
             vcs_badge_issue(ctx->s, &ctx->policy, unknown, NULL, ctx->l,
                             zb_issue_sign, &ctx->issuer_sk, &result, detail,
                             sizeof(detail)) == VCS_BADGE_ISSUE_UNKNOWN_PLAN);
    return failures;
}

/* A plan row that differs from the facts assembles and persists, then is
 * refused at commit revalidation with the STALE code and the named rule. */
static int zb_pi_reject_row(struct zb_issue_ctx *ctx,
                            const struct vcs_badge_plan_row *row,
                            int64_t plan_day, const char *assembled_msg,
                            const char *refused_msg, const char *rule)
{
    int failures = 0;
    struct vcs_badge_plan tampered;
    ZB_CHECK(assembled_msg,
             vcs_badge_plan_assemble(ctx->policy.policy_id,
                                     ctx->policy.issuer_pubkey, plan_day,
                                     row, 1, &tampered) &&
                 vcs_badge_plan_persist(ctx->s, &tampered) ==
                     VCS_BADGE_PLAN_PERSIST_OK);
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK(refused_msg,
             vcs_badge_issue(ctx->s, &ctx->policy, tampered.plan_id, NULL,
                             ctx->l, zb_issue_sign, &ctx->issuer_sk, &result,
                             detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_STALE &&
                 strstr(detail, rule) != NULL &&
                 vcs_badge_store_badge_count(ctx->s) == 5);
    return failures;
}

/* WRONG-PERIOD and WRONG-EVIDENCE rows are rejected at revalidation. */
static int zb_pi_stale_rows(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_badge_plan_row row;
    memset(&row, 0, sizeof(row));
    memcpy(row.contributor, ctx->c_pk.vch, 33);
    row.type = VCS_BADGE_TOP_DAILY;
    row.period_first = 20001; /* the facts say 20000 */
    row.period_last = 20001;
    zb_root(0x61, row.evidence_root);
    row.sequence = 6;
    failures += zb_pi_reject_row(ctx, &row, 20000,
                                 "issue: wrong-period plan assembles",
                                 "issue: wrong-period row rejected",
                                 VCS_BADGE_RULE_PERIOD_CHANGED);

    memset(&row, 0, sizeof(row));
    memcpy(row.contributor, ctx->c_pk.vch, 33);
    row.type = VCS_BADGE_TOP_DAILY;
    row.period_first = 20000;
    row.period_last = 20000;
    zb_root(0x62, row.evidence_root); /* not the facts' hash */
    row.sequence = 6;
    failures += zb_pi_reject_row(ctx, &row, 20000,
                                 "issue: wrong-evidence plan assembles",
                                 "issue: wrong-evidence row rejected",
                                 VCS_BADGE_RULE_EVIDENCE_CHANGED);
    return failures;
}

/* SEQUENCE CONFLICT: a used sequence with different content. */
static int zb_pi_sequence_conflict(struct zb_issue_ctx *ctx)
{
    struct vcs_badge_plan_row row;
    memset(&row, 0, sizeof(row));
    memcpy(row.contributor, ctx->e_pk.vch, 33);
    row.type = VCS_BADGE_TOP_DAILY;
    row.period_first = 20001;
    row.period_last = 20001;
    vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, ctx->e_pk.vch, 20001, 20001,
                            50, row.evidence_root);
    row.sequence = 1; /* already used by C's first-package badge */
    return zb_pi_reject_row(ctx, &row, 20001,
                            "issue: sequence-conflict plan assembles",
                            "issue: sequence conflict named",
                            "sequence-conflict");
}

/* SIGN FAILURE: nothing is written, no commit record. CRASH RESUME: one
 * badge already durable (a simulated partial issue), no commit record — the
 * finishing issue replays it. */
static int zb_pi_sign_and_resume(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_badge_facts efacts;
    vcs_badge_facts_build(ctx->e_pk.vch, NULL, ctx->l, 20001, &efacts);
    struct vcs_badge_plan eplan;
    size_t eexcl = 0;
    ZB_CHECK("issue: E's plan assembles",
             vcs_badge_plan_build(ctx->s, &ctx->policy, ctx->e_pk.vch,
                                  &efacts, 20001, &eplan, ctx->exclusions,
                                  &eexcl) &&
                 eplan.row_count == 2 /* top-daily + early */ &&
                 vcs_badge_plan_persist(ctx->s, &eplan) ==
                     VCS_BADGE_PLAN_PERSIST_OK);
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK("issue: signer failure writes nothing",
             vcs_badge_issue(ctx->s, &ctx->policy, eplan.plan_id, NULL,
                             ctx->l, zb_fail_sign, NULL, &result, detail,
                             sizeof(detail)) ==
                     VCS_BADGE_ISSUE_SIGN &&
                 vcs_badge_store_badge_count(ctx->s) == 5 &&
                 !vcs_badge_commit_known(ctx->s, eplan.plan_id));

    const struct vcs_badge_plan_row *r0 = &eplan.rows[0];
    struct vcs_badge partial;
    memset(&partial, 0, sizeof(partial));
    partial.schema_version = VCS_PACKAGE_BADGE_VERSION;
    partial.type = (uint8_t)r0->type;
    memcpy(partial.recipient, r0->contributor, 33);
    partial.period_first_day = r0->period_first;
    partial.period_last_day = r0->period_last;
    memcpy(partial.evidence_root, r0->evidence_root, 32);
    memcpy(partial.policy_id, ctx->policy.policy_id, 32);
    partial.sequence = r0->sequence;
    memcpy(partial.issuer_pubkey, ctx->policy.issuer_pubkey, 33);
    uint8_t pid[32];
    ZB_CHECK("issue: partial badge persisted (crash state)",
             zb_sign(&ctx->issuer_sk, &partial) &&
                 vcs_badge_store_persist(ctx->s, &partial, pid) ==
                     VCS_BADGE_PERSIST_OK);
    memset(&result, 0, sizeof(result));
    ZB_CHECK("issue: interrupted issue resumes",
             vcs_badge_issue(ctx->s, &ctx->policy, eplan.plan_id, NULL,
                             ctx->l, zb_issue_sign, &ctx->issuer_sk, &result,
                             detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_OK &&
                 result.resumed && result.replayed_count == 1 &&
                 result.issued_count == 2 &&
                 vcs_badge_store_badge_count(ctx->s) == 7);
    return failures;
}

/* STALE: the facts moved since the plan (a rank overtake), then the policy
 * is rewritten and the plan's issuer no longer matches it. */
static int zb_pi_stale_overtake(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    /* F is rank 1 at day 20002 with 10 points until D2 lands 5000. */
    struct vcs_reward_ledger *lw = vcs_reward_ledger_load(ctx->zcode);
    uint8_t id[32];
    (void)zb_auto(lw, 0x13, ctx->f_pk.vch,
                  VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 10, 0x13, id);
    (void)zb_settle(lw, 20002);
    vcs_reward_ledger_free(lw);
    struct vcs_reward_ledger *l2 = vcs_reward_ledger_load(ctx->zcode);
    struct vcs_badge_facts ffacts;
    vcs_badge_facts_build(ctx->f_pk.vch, NULL, l2, 20002, &ffacts);
    ZB_CHECK("issue: F is rank 1 before the overtake",
             ffacts.top_daily && ffacts.top_daily_points == 10);
    struct vcs_badge_plan fplan;
    size_t fexcl = 0;
    ZB_CHECK("issue: F's plan assembles",
             vcs_badge_plan_build(ctx->s, &ctx->policy, ctx->f_pk.vch,
                                  &ffacts, 20002, &fplan, ctx->exclusions,
                                  &fexcl) &&
                 fplan.row_count == 2 &&
                 vcs_badge_plan_persist(ctx->s, &fplan) ==
                     VCS_BADGE_PLAN_PERSIST_OK);
    vcs_reward_ledger_free(l2);

    struct vcs_reward_ledger *lw2 = vcs_reward_ledger_load(ctx->zcode);
    (void)zb_auto(lw2, 0x14, ctx->d_pk.vch,
                  VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 5000, 0x14, id);
    (void)zb_settle(lw2, 20002);
    vcs_reward_ledger_free(lw2);
    struct vcs_reward_ledger *l3 = vcs_reward_ledger_load(ctx->zcode);
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK("issue: stale plan named after the overtake",
             vcs_badge_issue(ctx->s, &ctx->policy, fplan.plan_id, NULL, l3,
                             zb_issue_sign, &ctx->issuer_sk, &result, detail,
                             sizeof(detail)) ==
                     VCS_BADGE_ISSUE_STALE &&
                 strstr(detail, VCS_BADGE_RULE_NOT_ELIGIBLE) != NULL &&
                 !vcs_badge_commit_known(ctx->s, fplan.plan_id));

    /* POLICY MISMATCH: the plan's issuer is not the configured policy any
     * more. Checked BEFORE row revalidation. */
    ZB_CHECK("issue: policy rewritten",
             zb_write_policy(ctx->zcode, 0x31, ctx->d_pk.vch));
    struct vcs_badge_policy other_policy;
    ZB_CHECK("issue: foreign policy loads",
             vcs_badge_policy_load(ctx->zcode, &other_policy));
    ZB_CHECK("issue: policy mismatch named",
             vcs_badge_issue(ctx->s, &other_policy, fplan.plan_id, NULL, l3,
                             zb_issue_sign, &ctx->issuer_sk, &result, detail,
                             sizeof(detail)) ==
                 VCS_BADGE_ISSUE_POLICY_MISMATCH);
    vcs_reward_ledger_free(l3);
    return failures;
}

static int t_plan_issue(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_plan_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("plan: datadir created", zb_mkdir_p(zcode));

    struct zb_issue_ctx ctx = {0};
    ctx.zcode = zcode;
    failures += zb_pi_setup(&ctx);
    failures += zb_pi_seed_ledger(&ctx);
    ctx.s = vcs_badge_store_load(zcode);
    ctx.l = vcs_reward_ledger_load(zcode);
    ZB_CHECK("plan: store + ledger loaded", ctx.s && ctx.l);
    failures += zb_pi_check_facts(&ctx);
    failures += zb_pi_plan_batch(&ctx);
    failures += zb_pi_plan_rows(&ctx);
    failures += zb_pi_plan_persist(&ctx);
    failures += zb_pi_issue_commit(&ctx);
    failures += zb_pi_replan_and_unknown(&ctx);
    failures += zb_pi_stale_rows(&ctx);
    failures += zb_pi_sequence_conflict(&ctx);
    failures += zb_pi_sign_and_resume(&ctx);
    failures += zb_pi_stale_overtake(&ctx);

    vcs_reward_ledger_free(ctx.l);
    vcs_badge_store_free(ctx.s);
    zb_rm_rf(datadir);
    return failures;
}

/* ── 5. permanence + cross-period dedup ─────────────────────────────── */

/* Issue the day-20000 badges for C (top-daily among them). */
static int zb_perm_issue_day20000(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_badge_facts facts;
    vcs_badge_facts_build(ctx->c_pk.vch, NULL, ctx->l, 20000, &facts);
    struct vcs_badge_plan plan;
    size_t excl = 0;
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK("perm: day-20000 badge issued",
             vcs_badge_plan_build(ctx->s, &ctx->policy, ctx->c_pk.vch,
                                  &facts, 20000, &plan, ctx->exclusions,
                                  &excl) &&
                 vcs_badge_plan_persist(ctx->s, &plan) ==
                     VCS_BADGE_PLAN_PERSIST_OK &&
                 vcs_badge_issue(ctx->s, &ctx->policy, plan.plan_id, NULL,
                                 ctx->l, zb_issue_sign, &ctx->issuer_sk,
                                 &result, detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_OK);
    return failures;
}

/* CROSS-PERIOD DEDUP: TOP_DAILY on day 20001 is a DIFFERENT achievement
 * period — allowed. */
static int zb_perm_cross_period(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_badge_facts facts;
    vcs_badge_facts_build(ctx->c_pk.vch, NULL, ctx->l, 20001, &facts);
    ZB_CHECK("perm: C is rank 1 on day 20001 too",
             facts.top_daily && facts.top_daily_points == 100);
    struct vcs_badge_plan plan;
    size_t excl = 0;
    ZB_CHECK("perm: day-20001 plan keeps top-daily",
             vcs_badge_plan_build(ctx->s, &ctx->policy, ctx->c_pk.vch,
                                  &facts, 20001, &plan, ctx->exclusions,
                                  &excl));
    bool has_daily = false;
    for (size_t i = 0; i < plan.row_count; i++)
        if (plan.rows[i].type == VCS_BADGE_TOP_DAILY &&
            plan.rows[i].period_first == 20001)
            has_daily = true;
    ZB_CHECK("perm: top-daily on a second day allowed", has_daily);
    struct vcs_badge_issue_result result;
    char detail[256];
    ZB_CHECK("perm: day-20001 badge issued",
             vcs_badge_plan_persist(ctx->s, &plan) ==
                     VCS_BADGE_PLAN_PERSIST_OK &&
                 vcs_badge_issue(ctx->s, &ctx->policy, plan.plan_id, NULL,
                                 ctx->l, zb_issue_sign, &ctx->issuer_sk,
                                 &result, detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_OK);
    return failures;
}

/* The contributor's top-daily badge count over the (capped) listing;
 * *total receives the full earned count. */
static int zb_perm_daily_count(struct vcs_badge_store *s,
                               const struct vcs_badge_policy *policy,
                               const uint8_t pk[33], size_t *total)
{
    struct vcs_badge earned[16];
    *total = vcs_badge_store_contributor_badges(s, policy, pk, earned, 16);
    int dailies = 0;
    for (size_t i = 0; i < *total && i < 16; i++)
        if (earned[i].type == VCS_BADGE_TOP_DAILY)
            dailies++;
    return dailies;
}

/* RANK LOSS: D2 lands 9000 points on day 20010 — C falls off the board.
 * The badges are PERMANENT historical evidence. */
static int zb_perm_rank_loss(struct zb_issue_ctx *ctx)
{
    int failures = 0;
    struct vcs_reward_ledger *lw = vcs_reward_ledger_load(ctx->zcode);
    uint8_t id[32];
    (void)zb_auto(lw, 0x12, ctx->d_pk.vch, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                  2500, 0x12, id);
    (void)zb_auto(lw, 0x13, ctx->d_pk.vch, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                  2500, 0x13, id);
    ZB_CHECK("perm: day-20010 overtake settles",
             zb_settle(lw, 20010) == VCS_REWARD_COMMIT_OK);
    vcs_reward_ledger_free(lw);
    vcs_reward_ledger_free(ctx->l);
    ctx->l = vcs_reward_ledger_load(ctx->zcode);
    struct vcs_badge_facts facts;
    vcs_badge_facts_build(ctx->c_pk.vch, NULL, ctx->l, 20010, &facts);
    ZB_CHECK("perm: C is honestly off the board on day 20010",
             !facts.top_daily && !facts.top_weekly && !facts.top_monthly);
    struct vcs_badge_eval eval;
    ZB_CHECK("perm: top-daily no longer eligible",
             vcs_badge_evaluate(VCS_BADGE_TOP_DAILY, ctx->c_pk.vch, &facts,
                                20010, &eval) &&
                 !eval.eligible);

    /* The badge SURVIVES the rank loss: still stored, still listed. */
    vcs_badge_store_free(ctx->s);
    ctx->s = vcs_badge_store_load(ctx->zcode);
    size_t total = 0;
    int dailies = zb_perm_daily_count(ctx->s, &ctx->policy, ctx->c_pk.vch,
                                      &total);
    ZB_CHECK("perm: badges survive the rank loss",
             total > 0 && dailies == 2);
    return failures;
}

static int t_permanence_dedup(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_perm_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("perm: datadir created", zb_mkdir_p(zcode));

    struct zb_issue_ctx ctx = {0};
    ctx.zcode = zcode;
    struct privkey sk2, sk3;
    ZB_CHECK("perm: keypairs",
             zb_keypair(1, &ctx.issuer_sk, &ctx.issuer_pk) &&
                 zb_keypair(2, &sk2, &ctx.c_pk) &&
                 zb_keypair(3, &sk3, &ctx.d_pk));
    ZB_CHECK("perm: policy written",
             zb_write_policy(zcode, 0x30, ctx.issuer_pk.vch));
    ZB_CHECK("perm: policy loads", vcs_badge_policy_load(zcode, &ctx.policy));

    /* C is rank 1 on days 20000 and 20001 (100 settled test points each);
     * D2 buries the board on day 20010. */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode);
        uint8_t id[32];
        (void)zb_auto(l, 0x10, ctx.c_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 100, 0x10, id);
        ZB_CHECK("perm: day-20000 settles",
                 zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        (void)zb_auto(l, 0x11, ctx.c_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 100, 0x11, id);
        ZB_CHECK("perm: day-20001 settles",
                 zb_settle(l, 20001) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    ctx.s = vcs_badge_store_load(zcode);
    ctx.l = vcs_reward_ledger_load(zcode);
    ZB_CHECK("perm: store + ledger loaded", ctx.s && ctx.l);

    failures += zb_perm_issue_day20000(&ctx);
    failures += zb_perm_cross_period(&ctx);

    /* Two TOP_DAILY badges for the two distinct days now exist. */
    {
        size_t total = 0;
        int dailies = zb_perm_daily_count(ctx.s, &ctx.policy, ctx.c_pk.vch,
                                          &total);
        ZB_CHECK("perm: two top-daily badges (two days)", dailies == 2);
    }

    failures += zb_perm_rank_loss(&ctx);

    vcs_reward_ledger_free(ctx.l);
    vcs_badge_store_free(ctx.s);
    zb_rm_rf(datadir);
    return failures;
}

/* ── 6. the typed commands over a fixture datadir ───────────────────── */

struct zb_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zb_cmd_init(struct zb_cmd *c, const char *datadir)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_badge_test.v1");
    (void)json_push_kv_str(&c->input, "datadir", datadir);
}

static void zb_cmd_free(struct zb_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* eligible: the reply lists every type and its counts. */
static int zb_cmd_eligible_types(const struct json_value *rows)
{
    int failures = 0;
    bool daily_ok = false, hundred_ok = false, popular_named = false;
    for (size_t i = 0; i < 13; i++) {
        const struct json_value *row = json_at(rows, i);
        const char *type = json_get_str(json_get(row, "type"));
        if (!type)
            continue;
        if (strcmp(type, "top-daily") == 0)
            daily_ok =
                json_get_bool(json_get(row, "eligible")) &&
                json_get_int(json_get(row, "period_first_day")) ==
                    20000 &&
                json_get_str(json_get(row, "evidence_root")) != NULL;
        if (strcmp(type, "hundred-tests") == 0)
            hundred_ok =
                json_get_bool(json_get(row, "eligible")) &&
                json_get_int(json_get(row, "period_first_day")) ==
                    20000;
        if (strcmp(type, "popular-package") == 0)
            popular_named =
                !json_get_bool(json_get(row, "available")) &&
                !json_get_bool(json_get(row, "eligible"));
    }
    ZB_CHECK("commands: eligible carries evidence facts",
             daily_ok && hundred_ok && popular_named);
    return failures;
}

/* eligible: all 13 types reported; unavailable named; evidence facts
 * carried. */
static int zb_cmd_eligible(const char *datadir, const char *c_hex)
{
    int failures = 0;
    struct zb_cmd c;
    zb_cmd_init(&c, datadir);
    (void)json_push_kv_str(&c.input, "pubkey", c_hex);
    (void)json_push_kv_int(&c.input, "day", 20000);
    zcl_native_handle_zcode_badge_eligible(&c.request, &c.reply);
    const struct json_value *rows = json_get(&c.reply.data, "badges");
    ZB_CHECK("commands: eligible reports every type",
             rows && json_at(rows, 12) != NULL &&
                 json_get_int(json_get(&c.reply.data,
                                       "eligible_count")) == 5 &&
                 json_get_int(json_get(&c.reply.data,
                                       "unavailable_count")) == 2);
    failures += zb_cmd_eligible_types(rows);
    zb_cmd_free(&c);
    return failures;
}

/* plan exclusions: the bug-hunter and the P2P badge are named. */
static int zb_cmd_plan_exclusions(const struct json_value *data)
{
    int failures = 0;
    const struct json_value *excl = json_get(data, "exclusions");
    bool bug_named = false, popular_named = false;
    for (size_t i = 0; excl && json_at(excl, i); i++) {
        const struct json_value *row = json_at(excl, i);
        const char *type = json_get_str(json_get(row, "type"));
        const char *rule = json_get_str(json_get(row, "rule"));
        if (type && rule && strcmp(type, "bug-hunter") == 0 &&
            strcmp(rule, "not-eligible") == 0)
            bug_named = true;
        if (type && rule && strcmp(type, "popular-package") == 0 &&
            strcmp(rule, "unavailable") == 0)
            popular_named = true;
    }
    ZB_CHECK("commands: plan exclusions name the rules",
             bug_named && popular_named);
    return failures;
}

/* plan: five rows, exclusions named; the plan id is returned in
 * plan_id_hex. */
static int zb_cmd_plan_first(const char *datadir, const char *c_hex,
                             char plan_id_hex[65])
{
    int failures = 0;
    struct zb_cmd c;
    zb_cmd_init(&c, datadir);
    (void)json_push_kv_str(&c.input, "pubkey", c_hex);
    (void)json_push_kv_int(&c.input, "day", 20000);
    zcl_native_handle_zcode_badge_plan(&c.request, &c.reply);
    const char *pid = json_get_str(json_get(&c.reply.data, "plan_id"));
    ZB_CHECK("commands: plan id returned",
             pid && strlen(pid) == 64 &&
                 json_get_int(json_get(&c.reply.data,
                                       "rows_planned")) == 5 &&
                 json_get_int(json_get(&c.reply.data,
                                       "rows_excluded")) == 8 &&
                 !json_get_bool(json_get(&c.reply.data,
                                         "already_persisted")));
    if (pid)
        snprintf(plan_id_hex, 65, "%s", pid);
    failures += zb_cmd_plan_exclusions(&c.reply.data);
    zb_cmd_free(&c);
    return failures;
}

/* re-plan: the idempotent same plan id. */
static int zb_cmd_replan(const char *datadir, const char *c_hex,
                         const char *plan_id_hex)
{
    int failures = 0;
    struct zb_cmd c2;
    zb_cmd_init(&c2, datadir);
    (void)json_push_kv_str(&c2.input, "pubkey", c_hex);
    (void)json_push_kv_int(&c2.input, "day", 20000);
    zcl_native_handle_zcode_badge_plan(&c2.request, &c2.reply);
    ZB_CHECK("commands: re-plan is the idempotent same id",
             json_get_bool(json_get(&c2.reply.data, "already_persisted")) &&
                 strcmp(json_get_str(json_get(&c2.reply.data, "plan_id"))
                            ? json_get_str(json_get(&c2.reply.data,
                                                    "plan_id"))
                            : "",
                        plan_id_hex) == 0);
    zb_cmd_free(&c2);
    return failures;
}

/* issue: a non-policy issuer key and an unknown plan are both rejected. */
static int zb_cmd_issue_rejects(const char *datadir,
                                const char *plan_id_hex,
                                const struct privkey *issuer_sk,
                                const struct privkey *foreign_sk)
{
    int failures = 0;
    char secret_hex[65];
    zb_hex_enc(foreign_sk->vch, 32, secret_hex);
    struct zb_cmd c;
    zb_cmd_init(&c, datadir);
    (void)json_push_kv_str(&c.input, "plan_id", plan_id_hex);
    (void)json_push_kv_str(&c.input, "issuer_secret", secret_hex);
    zcl_native_handle_zcode_badge_issue(&c.request, &c.reply);
    ZB_CHECK("commands: non-policy issuer key rejected",
             strcmp(c.reply.error.code, "ISSUER_KEY_MISMATCH") == 0);
    zb_cmd_free(&c);

    uint8_t unknown[32];
    zb_root(0x60, unknown);
    char unknown_hex[65];
    zb_hex_enc(unknown, 32, unknown_hex);
    zb_hex_enc(issuer_sk->vch, 32, secret_hex);
    struct zb_cmd c2;
    zb_cmd_init(&c2, datadir);
    (void)json_push_kv_str(&c2.input, "plan_id", unknown_hex);
    (void)json_push_kv_str(&c2.input, "issuer_secret", secret_hex);
    zcl_native_handle_zcode_badge_issue(&c2.request, &c2.reply);
    ZB_CHECK("commands: unknown plan named",
             strcmp(c2.reply.error.code, "UNKNOWN_PLAN") == 0);
    zb_cmd_free(&c2);
    return failures;
}

/* issue: the happy path commits the batch; a replay is ALREADY_ISSUED. */
static int zb_cmd_issue_commit(const char *datadir, const char *plan_id_hex,
                               const struct privkey *issuer_sk)
{
    int failures = 0;
    char secret_hex[65];
    zb_hex_enc(issuer_sk->vch, 32, secret_hex);
    struct zb_cmd c;
    zb_cmd_init(&c, datadir);
    (void)json_push_kv_str(&c.input, "plan_id", plan_id_hex);
    (void)json_push_kv_str(&c.input, "issuer_secret", secret_hex);
    zcl_native_handle_zcode_badge_issue(&c.request, &c.reply);
    ZB_CHECK("commands: issue commits the batch",
             json_get_int(json_get(&c.reply.data, "issued_count")) == 5 &&
                 json_get_bool(json_get(&c.reply.data, "simulated")));
    const struct json_value *badges = json_get(&c.reply.data, "badges");
    ZB_CHECK("commands: issued badges listed with ids",
             badges && json_at(badges, 4) != NULL &&
                 json_get_str(json_get(json_at(badges, 0), "badge_id")) !=
                     NULL);
    zb_cmd_free(&c);

    /* Replay: ALREADY_ISSUED, never a double-issue. */
    struct zb_cmd c2;
    zb_cmd_init(&c2, datadir);
    (void)json_push_kv_str(&c2.input, "plan_id", plan_id_hex);
    (void)json_push_kv_str(&c2.input, "issuer_secret", secret_hex);
    zcl_native_handle_zcode_badge_issue(&c2.request, &c2.reply);
    ZB_CHECK("commands: replay is ALREADY_ISSUED",
             strcmp(c2.reply.error.code, "ALREADY_ISSUED") == 0);
    zb_cmd_free(&c2);
    return failures;
}

/* Run the contributor-badges command for one pubkey hex. */
static void zb_cmd_contributor(struct zb_cmd *c, const char *datadir,
                               const char *pubkey_hex)
{
    zb_cmd_init(c, datadir);
    (void)json_push_kv_str(&c->input, "pubkey", pubkey_hex);
    zcl_native_handle_zcode_contributor_badges(&c->request, &c->reply);
}

/* contributor badges: the earned badges, permanent:true. */
static int zb_cmd_contributor_listing(const char *datadir,
                                      const char *c_hex)
{
    int failures = 0;
    struct zb_cmd c;
    zb_cmd_contributor(&c, datadir, c_hex);
    const struct json_value *badges = json_get(&c.reply.data, "badges");
    ZB_CHECK("commands: contributor badges listed",
             badges &&
                 json_get_int(json_get(&c.reply.data, "total_badges")) == 5 &&
                 json_at(badges, 4) != NULL &&
                 json_get_bool(json_get(json_at(badges, 0), "permanent")));
    zb_cmd_free(&c);
    return failures;
}

/* A contributor with no badges: honestly empty. */
static int zb_cmd_no_badges(const char *datadir)
{
    int failures = 0;
    struct privkey sk9;
    struct pubkey nobody_pk;
    ZB_CHECK("commands: nobody keypair",
             zb_keypair(9, &sk9, &nobody_pk));
    char nobody_hex[67];
    zb_hex_enc(nobody_pk.vch, 33, nobody_hex);
    struct zb_cmd c;
    zb_cmd_contributor(&c, datadir, nobody_hex);
    ZB_CHECK("commands: no badges honestly empty",
             json_get_int(json_get(&c.reply.data, "total_badges")) == 0);
    zb_cmd_free(&c);
    return failures;
}

static int t_commands(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_cmd_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("commands: datadir created", zb_mkdir_p(zcode));

    struct privkey issuer_sk, foreign_sk, sk2;
    struct pubkey issuer_pk, foreign_pk, c_pk;
    ZB_CHECK("commands: keypairs",
             zb_keypair(1, &issuer_sk, &issuer_pk) &&
                 zb_keypair(4, &foreign_sk, &foreign_pk) &&
                 zb_keypair(2, &sk2, &c_pk));
    char c_hex[67];
    zb_hex_enc(c_pk.vch, 33, c_hex);

    /* Facts: C settles exactly 100 test points at day 20000 (rank 1). */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode);
        uint8_t id[32];
        (void)zb_auto(l, 0x10, c_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 100, 0x10, id);
        ZB_CHECK("commands: day-20000 settles",
                 zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    failures += zb_cmd_eligible(datadir, c_hex);

    /* plan WITHOUT a policy: NO_BADGE_POLICY named. */
    {
        struct zb_cmd c;
        zb_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "pubkey", c_hex);
        (void)json_push_kv_int(&c.input, "day", 20000);
        zcl_native_handle_zcode_badge_plan(&c.request, &c.reply);
        ZB_CHECK("commands: NO_BADGE_POLICY named",
                 strcmp(c.reply.error.code, "NO_BADGE_POLICY") == 0);
        zb_cmd_free(&c);
    }

    ZB_CHECK("commands: policy written",
             zb_write_policy(zcode, 0x30, issuer_pk.vch));

    char plan_id_hex[65];
    plan_id_hex[0] = '\0';
    failures += zb_cmd_plan_first(datadir, c_hex, plan_id_hex);
    failures += zb_cmd_replan(datadir, c_hex, plan_id_hex);
    failures += zb_cmd_issue_rejects(datadir, plan_id_hex, &issuer_sk,
                                     &foreign_sk);
    failures += zb_cmd_issue_commit(datadir, plan_id_hex, &issuer_sk);
    failures += zb_cmd_contributor_listing(datadir, c_hex);
    failures += zb_cmd_no_badges(datadir);

    zb_rm_rf(datadir);
    return failures;
}

#if !defined(_WIN32)
/* Controls for zb_rm_rf. Each case builds <base>/target/keep and the symbolic
 * link <base>/link -> target (a relative sibling name, so the link can only
 * resolve to the directory the case just created), runs the remover on the
 * link, and requires the link gone with the directory and the sentinel
 * content intact. The trailing-separator case passes "<base>/link/". The
 * case cleanup unlinks the link first, then removes the sentinel and the
 * two directories with non-recursive calls. */
static const char zb_nofollow_text[] = "keep-me";

static bool zb_nofollow_fixture(const char *target, const char *keep,
                                 const char *link)
{
    if (mkdir(target, 0700) != 0)
        return false;
    FILE *f = fopen(keep, "wb");
    if (!f)
        return false;
    size_t want = sizeof(zb_nofollow_text) - 1;
    bool wrote = fwrite(zb_nofollow_text, 1, want, f) == want;
    if (fclose(f) != 0 || !wrote)
        return false;
    return symlink("target", link) == 0;
}

static bool zb_nofollow_text_intact(const char *keep)
{
    char buf[32];
    FILE *f = fopen(keep, "rb");
    if (!f)
        return false;
    size_t got = fread(buf, 1, sizeof(buf), f);
    bool read_ok = ferror(f) == 0;
    bool closed = fclose(f) == 0;
    size_t want = sizeof(zb_nofollow_text) - 1;
    return read_ok && closed && got == want &&
           memcmp(buf, zb_nofollow_text, want) == 0;
}

static bool zb_nofollow_cleanup(const char *base, const char *target,
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

static bool zb_nofollow_run(bool trailing_sep)
{
    char base[512], target[640], keep[704], link[640], arg[648];
    test_make_tmpdir(base, sizeof(base), "zcode_badge",
                     trailing_sep ? "nofollow_slash" : "nofollow_link");
    snprintf(target, sizeof(target), "%s/target", base);
    snprintf(keep, sizeof(keep), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", base);
    snprintf(arg, sizeof(arg), trailing_sep ? "%s/" : "%s", link);

    bool linked = zb_nofollow_fixture(target, keep, link);
    bool removed = false;
    if (linked)
        removed = zb_rm_rf(arg);

    struct stat st;
    bool link_gone = lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = zb_nofollow_text_intact(keep);
    bool target_kept = stat(target, &st) == 0 && S_ISDIR(st.st_mode);
    bool clean = zb_nofollow_cleanup(base, target, keep, link);

    bool ok = linked & removed & link_gone & kept & target_kept & clean;
    if (!ok)
        printf("  zcode_badge: nofollow (%s) linked=%d removed=%d link_gone=%d "
               "kept=%d target_kept=%d clean=%d\n",
               trailing_sep ? "trailing separator" : "plain link", linked,
               removed, link_gone, kept, target_kept, clean);
    return ok;
}

static int zb_nofollow_plain_link(void)
{
    int failures = 0;
    ZB_CHECK("remover unlinks a symbolic link and keeps its target",
          zb_nofollow_run(false));
    return failures;
}

static int zb_nofollow_trailing_sep(void)
{
    int failures = 0;
    ZB_CHECK("remover keeps the target of a symbolic link named with a trailing separator",
          zb_nofollow_run(true));
    return failures;
}
#endif /* !_WIN32 */

/* Settle days out of order and distinguish the same-day crossing roots. */
static int t_hundred_tests_order(void)
{
    int failures = 0;
    char dir[4400], zcode[4400];
    snprintf(dir, sizeof(dir), "test-tmp/zb_order_%ld", (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", dir);
    zb_rm_rf(dir);
    bool ready = zb_mkdir_p(zcode);
    struct privkey sk;
    struct pubkey pk;
    ready = ready && zb_keypair(2, &sk, &pk);
    struct vcs_reward_ledger *l = ready ? vcs_reward_ledger_load(zcode) : NULL;
    uint8_t id_a[32], id_b[32], id_early[32];
    ready = l &&
        zb_auto(l, 0x31, pk.vch, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                50, 0x31, id_a) == VCS_REWARD_ENQUEUE_OK &&
        zb_auto(l, 0x32, pk.vch, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                50, 0x32, id_b) == VCS_REWARD_ENQUEUE_OK &&
        zb_settle(l, 20001) == VCS_REWARD_COMMIT_OK &&
        zb_auto(l, 0x33, pk.vch, VCS_REWARD_CATEGORY_TEST_CONTRIBUTION,
                50, 0x33, id_early) == VCS_REWARD_ENQUEUE_OK &&
        zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK;
    ZB_CHECK("crossing: out-of-order days and same-day facts settled", ready);
    if (ready) {
        struct vcs_badge_facts facts;
        uint8_t expected[32];
        zb_root(memcmp(id_a, id_b, 32) < 0 ? 0x31 : 0x32, expected);
        vcs_badge_facts_build(pk.vch, NULL, l, 20001, &facts);
        ZB_CHECK("crossing: exact 100 selects earliest day and entry id root",
                 facts.hundred_tests_crossed &&
                 facts.hundred_tests_day == 20001 &&
                 facts.test_points_total == 150 &&
                 memcmp(facts.hundred_tests_root, expected, 32) == 0);
    }
    vcs_reward_ledger_free(l);
    zb_rm_rf(dir);
    return failures;
}

int test_zcode_badge(void)
{
    printf("\n=== zcode_badge: SIMULATED ZCODE Badges (slice 10) ===\n");
    int failures = 0;
    failures += t_codec();
    failures += t_evaluator();
    failures += t_hundred_tests_order();
    failures += t_store();
    failures += t_plan_issue();
    failures += t_permanence_dedup();
    failures += t_commands();
#if !defined(_WIN32)
    failures += zb_nofollow_plain_link();
    failures += zb_nofollow_trailing_sep();
#endif
    printf("=== zcode_badge complete: %d failure(s) ===\n", failures);
    return failures;
}
