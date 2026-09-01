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
        if (!zb_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
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

    /* Serialize/parse roundtrip. */
    {
        uint8_t wire[VCS_PACKAGE_BADGE_WIRE_BYTES];
        struct vcs_badge back;
        ZB_CHECK("codec: serialize/parse roundtrip",
                 vcs_badge_serialize(&badge, wire, sizeof(wire)) ==
                         VCS_BADGE_OK &&
                     vcs_badge_parse(wire, sizeof(wire), &back) ==
                         VCS_BADGE_OK &&
                     memcmp(&back, &badge, sizeof(badge)) == 0 &&
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
    }

    /* Forged signature. */
    {
        struct vcs_badge forged = badge;
        forged.signature[10] ^= 0x01;
        ZB_CHECK("codec: forged signature rejected",
                 vcs_badge_verify(&forged) == VCS_BADGE_ERR_SIG_VERIFY);
        memset(forged.signature + 32, 0xff, 32); /* s > n/2 */
        ZB_CHECK("codec: high-S malleation named",
                 vcs_badge_verify(&forged) == VCS_BADGE_ERR_SIG_LOW_S);
    }

    /* Signed by another key than the embedded issuer pubkey. */
    {
        struct vcs_badge wrong;
        ZB_CHECK("codec: built with the foreign key",
                 zb_make_badge(&other_sk, issuer_pk.vch, recipient_pk.vch,
                               VCS_BADGE_TOP_DAILY, 20000, 20000, 0x20,
                               0x30, 7, &wrong));
        ZB_CHECK("codec: wrong issuer key rejected",
                 vcs_badge_verify(&wrong) == VCS_BADGE_ERR_SIG_VERIFY);
    }

    /* Field rules, each named. */
    {
        struct vcs_badge b = badge;
        b.type = 99;
        ZB_CHECK("codec: unknown type named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_TYPE);
        b = badge;
        b.period_first_day = 20001;
        b.period_last_day = 20000;
        ZB_CHECK("codec: inverted period named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_PERIOD);
        b = badge;
        b.period_last_day = VCS_BADGE_PERIOD_NONE; /* exactly one -1 */
        ZB_CHECK("codec: half-sentinel period named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_PERIOD);
        b = badge;
        memset(b.evidence_root, 0, 32);
        ZB_CHECK("codec: zero evidence root named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_EVIDENCE_ROOT);
        b = badge;
        memset(b.policy_id, 0, 32);
        ZB_CHECK("codec: zero policy id named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_POLICY_ID);
        b = badge;
        b.sequence = 0;
        ZB_CHECK("codec: sequence zero named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_SEQUENCE);
        b = badge;
        memset(b.recipient, 0, 33);
        ZB_CHECK("codec: off-curve recipient named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_RECIPIENT);
        b = badge;
        memset(b.issuer_pubkey, 0, 33);
        ZB_CHECK("codec: off-curve issuer named",
                 vcs_badge_validate(&b) == VCS_BADGE_ERR_ISSUER);
    }

    /* The non-periodic sentinel pair is valid (once-ever badges). */
    {
        struct vcs_badge once;
        ZB_CHECK("codec: non-periodic badge verifies",
                 zb_make_badge(&issuer_sk, issuer_pk.vch, recipient_pk.vch,
                               VCS_BADGE_FIRST_PACKAGE,
                               VCS_BADGE_PERIOD_NONE, VCS_BADGE_PERIOD_NONE,
                               0x21, 0x30, 1, &once) &&
                     vcs_badge_is_non_periodic(&once) &&
                     vcs_badge_verify(&once) == VCS_BADGE_OK);
    }

    /* Type strings round-trip; availability honest. */
    {
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
    }
    return failures;
}

/* ── 2. the pure evaluator ──────────────────────────────────────────── */

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

    ZB_CHECK("eval: first-package eligible with the package root",
             vcs_badge_evaluate(VCS_BADGE_FIRST_PACKAGE, pk.vch, &facts,
                                today, &ev) &&
                 ev.available && ev.eligible &&
                 ev.period_first == VCS_BADGE_PERIOD_NONE &&
                 memcmp(ev.evidence_root, facts.first_package_root, 32) ==
                     0);

    ZB_CHECK("eval: ten-packages honestly short",
             vcs_badge_evaluate(VCS_BADGE_TEN_PACKAGES, pk.vch, &facts,
                                today, &ev) &&
                 ev.available && !ev.eligible &&
                 strstr(ev.detail, "9 distinct packages") != NULL);

    /* WRONG-PERIOD guard: the achievement period is the crossing day
     * from the facts, never "today". */
    ZB_CHECK("eval: hundred-tests period is the crossing day",
             vcs_badge_evaluate(VCS_BADGE_HUNDRED_TESTS, pk.vch, &facts,
                                today, &ev) &&
                 ev.eligible && ev.period_first == 100 &&
                 ev.period_last == 100 && ev.period_first != today &&
                 memcmp(ev.evidence_root, facts.hundred_tests_root, 32) ==
                     0);

    ZB_CHECK("eval: bug-hunter period is the first fix day",
             vcs_badge_evaluate(VCS_BADGE_BUG_HUNTER, pk.vch, &facts,
                                today, &ev) &&
                 ev.eligible && ev.period_first == 50 &&
                 memcmp(ev.evidence_root, facts.bug_fix_root, 32) == 0);
    ZB_CHECK("eval: security-researcher eligible",
             vcs_badge_evaluate(VCS_BADGE_SECURITY_RESEARCHER, pk.vch,
                                &facts, today, &ev) &&
                 ev.eligible && ev.period_first == 60);
    ZB_CHECK("eval: reproducible-builder eligible",
             vcs_badge_evaluate(VCS_BADGE_REPRODUCIBLE_BUILDER, pk.vch,
                                &facts, today, &ev) &&
                 ev.eligible && ev.period_first == 70);

    /* Rank badges: the period is the window containing today. Day 20000
     * is 2024-10-04 (a Friday of ISO 2024-W40: days 19996..20002;
     * October 2024 is days 19997..20027). */
    ZB_CHECK("eval: top-daily window",
             vcs_badge_evaluate(VCS_BADGE_TOP_DAILY, pk.vch, &facts,
                                today, &ev) &&
                 ev.eligible && ev.period_first == 20000 &&
                 ev.period_last == 20000);
    {
        uint8_t check[32];
        vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk.vch, 20000, 20000,
                                900, check);
        ZB_CHECK("eval: top-daily evidence is the deterministic hash",
                 memcmp(ev.evidence_root, check, 32) == 0);
    }
    ZB_CHECK("eval: top-weekly window",
             vcs_badge_evaluate(VCS_BADGE_TOP_WEEKLY, pk.vch, &facts,
                                today, &ev) &&
                 ev.eligible && ev.period_first == 19996 &&
                 ev.period_last == 20002);
    ZB_CHECK("eval: top-monthly window",
             vcs_badge_evaluate(VCS_BADGE_TOP_MONTHLY, pk.vch, &facts,
                                today, &ev) &&
                 ev.eligible && ev.period_first == 19997 &&
                 ev.period_last == 20027);

    ZB_CHECK("eval: one-year-maintainer achievement day",
             vcs_badge_evaluate(VCS_BADGE_ONE_YEAR_MAINTAINER, pk.vch,
                                &facts, today, &ev) &&
                 ev.eligible && ev.period_first == 10 + 365 &&
                 ev.period_last == 10 + 365);
    ZB_CHECK("eval: early contributor inside the pioneer window",
             vcs_badge_evaluate(VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR, pk.vch,
                                &facts, today, &ev) &&
                 ev.eligible &&
                 ev.period_first == VCS_BADGE_PERIOD_NONE);

    ZB_CHECK("eval: P2P badges named unavailable",
             vcs_badge_evaluate(VCS_BADGE_POPULAR_PACKAGE, pk.vch, &facts,
                                today, &ev) &&
                 !ev.available && !ev.eligible &&
                 strstr(ev.detail, "unavailable") != NULL &&
             vcs_badge_evaluate(VCS_BADGE_RARE_PACKAGE_SEEDER, pk.vch,
                                &facts, today, &ev) &&
                 !ev.available && !ev.eligible);

    /* Empty facts: everything available honestly not eligible. */
    {
        struct vcs_badge_facts empty;
        memset(&empty, 0, sizeof(empty));
        bool any_eligible = false;
        for (size_t i = 0; i < VCS_BADGE_TYPE_COUNT; i++) {
            struct vcs_badge_eval e2;
            if (!vcs_badge_evaluate((enum vcs_badge_type)i, pk.vch,
                                    &empty, today, &e2))
                continue;
            if (e2.eligible)
                any_eligible = true;
        }
        ZB_CHECK("eval: empty facts qualify for nothing", !any_eligible);
    }

    /* Pioneer window edge: first settled day 41 with ledger earliest 10
     * is outside (10 + 30). */
    {
        struct vcs_badge_facts late = facts;
        late.earliest_settled_day = 41;
        ZB_CHECK("eval: outside the pioneer window",
                 vcs_badge_evaluate(VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR,
                                    pk.vch, &late, today, &ev) &&
                     !ev.eligible);
        late.earliest_settled_day = 40;
        ZB_CHECK("eval: pioneer window boundary inclusive",
                 vcs_badge_evaluate(VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR,
                                    pk.vch, &late, today, &ev) &&
                     ev.eligible);
    }

    /* Evidence hash: deterministic and period-sensitive. */
    {
        uint8_t h1[32], h2[32], h3[32];
        vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk.vch, 20000, 20000,
                                900, h1);
        vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk.vch, 20000, 20000,
                                900, h2);
        vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, pk.vch, 20001, 20001,
                                900, h3);
        ZB_CHECK("eval: evidence hash deterministic + period-sensitive",
                 memcmp(h1, h2, 32) == 0 && memcmp(h1, h3, 32) != 0);
    }
    return failures;
}

/* ── 3. the store ───────────────────────────────────────────────────── */

static int t_store(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_store_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("store: datadir created", zb_mkdir_p(zcode));

    struct privkey issuer_sk, foreign_sk, sk2, sk3;
    struct pubkey issuer_pk, foreign_pk, c_pk, d_pk;
    ZB_CHECK("store: keypairs",
             zb_keypair(1, &issuer_sk, &issuer_pk) &&
                 zb_keypair(4, &foreign_sk, &foreign_pk) &&
                 zb_keypair(2, &sk2, &c_pk) &&
                 zb_keypair(3, &sk3, &d_pk));
    ZB_CHECK("store: policy file written",
             zb_write_policy(zcode, 0x30, issuer_pk.vch));

    struct vcs_badge_policy policy;
    ZB_CHECK("store: policy loads",
             vcs_badge_policy_load(zcode, &policy) &&
                 memcmp(policy.issuer_pubkey, issuer_pk.vch, 33) == 0);

    struct vcs_badge b1 = {0}, b2 = {0}, b3 = {0};
    ZB_CHECK("store: badges built",
             zb_make_badge(&issuer_sk, issuer_pk.vch, c_pk.vch,
                           VCS_BADGE_FIRST_PACKAGE, VCS_BADGE_PERIOD_NONE,
                           VCS_BADGE_PERIOD_NONE, 0x50, 0x30, 1, &b1) &&
                 zb_make_badge(&issuer_sk, issuer_pk.vch, c_pk.vch,
                               VCS_BADGE_TOP_DAILY, 20000, 20000, 0x51,
                               0x30, 2, &b2) &&
                 zb_make_badge(&issuer_sk, issuer_pk.vch, d_pk.vch,
                               VCS_BADGE_TOP_DAILY, 20000, 20000, 0x52,
                               0x30, 3, &b3));

    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: empty store loads", s != NULL);
    uint8_t id1[32], id1b[32];
    ZB_CHECK("store: persist + dedup no-op",
             vcs_badge_store_persist(s, &b1, id1) ==
                     VCS_BADGE_PERSIST_OK &&
                 vcs_badge_store_persist(s, &b1, id1b) ==
                     VCS_BADGE_PERSIST_DUPLICATE &&
                 memcmp(id1, id1b, 32) == 0);
    uint8_t id_scratch[32];
    ZB_CHECK("store: persist rest",
             vcs_badge_store_persist(s, &b2, id_scratch) ==
                     VCS_BADGE_PERSIST_OK &&
                 vcs_badge_store_persist(s, &b3, id_scratch) ==
                     VCS_BADGE_PERSIST_OK);
    /* An unsigned/invalid badge is never persisted. */
    {
        struct vcs_badge bad = b1;
        bad.signature[0] ^= 0x01;
        ZB_CHECK("store: invalid badge refused at persist",
                 vcs_badge_store_persist(s, &bad, id_scratch) ==
                     VCS_BADGE_PERSIST_INVALID);
    }
    vcs_badge_store_free(s);

    /* Reload: replayed from the durable wires. */
    s = vcs_badge_store_load(zcode);
    ZB_CHECK("store: reload replays three badges",
             s && vcs_badge_store_badge_count(s) == 3 &&
                 vcs_badge_store_corrupt_count(s) == 0);
    ZB_CHECK("store: dedup exact (contributor + type + period)",
             vcs_badge_store_dedup_hit(s, &policy, c_pk.vch,
                                       VCS_BADGE_FIRST_PACKAGE,
                                       VCS_BADGE_PERIOD_NONE,
                                       VCS_BADGE_PERIOD_NONE) &&
             vcs_badge_store_dedup_hit(s, &policy, c_pk.vch,
                                       VCS_BADGE_TOP_DAILY, 20000,
                                       20000) &&
             !vcs_badge_store_dedup_hit(s, &policy, c_pk.vch,
                                        VCS_BADGE_TOP_DAILY, 20001,
                                        20001) &&
             !vcs_badge_store_dedup_hit(s, &policy, c_pk.vch,
                                        VCS_BADGE_TOP_WEEKLY, 20000,
                                        20000));
    ZB_CHECK("store: same type+period for another contributor allowed",
             !vcs_badge_store_dedup_hit(s, &policy, c_pk.vch,
                                        VCS_BADGE_TOP_DAILY, 20000,
                                        20000) ||
                 vcs_badge_store_dedup_hit(s, &policy, d_pk.vch,
                                           VCS_BADGE_TOP_DAILY, 20000,
                                           20000));
    ZB_CHECK("store: max sequence per issuer",
             vcs_badge_store_max_sequence(s, issuer_pk.vch) == 3 &&
                 vcs_badge_store_max_sequence(s, foreign_pk.vch) == 0);
    {
        struct vcs_badge earned[8];
        size_t total = vcs_badge_store_contributor_badges(
            s, &policy, c_pk.vch, earned, 8);
        ZB_CHECK("store: contributor badges in issuance order",
                 total == 2 && earned[0].sequence == 1 &&
                     earned[1].sequence == 2 &&
                     earned[0].type == VCS_BADGE_FIRST_PACKAGE &&
                     earned[1].type == VCS_BADGE_TOP_DAILY);
    }
    vcs_badge_store_free(s);

    /* A FORGED badge (bad issuer signature) is rejected on load. */
    {
        uint8_t wire[VCS_PACKAGE_BADGE_WIRE_BYTES];
        struct vcs_badge forged = b2;
        forged.sequence = 9; /* distinct content -> distinct id */
        uint8_t fid[32];
        (void)vcs_badge_id(&forged, fid);
        forged.signature[10] ^= 0x01; /* the forgery */
        ZB_CHECK("store: forged wire serializes",
                 vcs_badge_serialize(&forged, wire, sizeof(wire)) ==
                     VCS_BADGE_OK);
        char hex[65], path[4400];
        zb_hex_enc(fid, 32, hex);
        snprintf(path, sizeof(path), "%s/badges/%s", zcode, hex);
        FILE *f = fopen(path, "wb");
        ZB_CHECK("store: forged wire planted",
                 f && fwrite(wire, 1, sizeof(wire), f) == sizeof(wire) &&
                     fclose(f) == 0);
        s = vcs_badge_store_load(zcode);
        ZB_CHECK("store: forged badge rejected on load",
                 s && vcs_badge_store_badge_count(s) == 3 &&
                     vcs_badge_store_corrupt_count(s) == 1);
        vcs_badge_store_free(s);
        ZB_CHECK("store: forged plant removed", unlink(path) == 0);
    }

    /* A filename that commits a DIFFERENT id is rejected on load. */
    {
        uint8_t wire[VCS_PACKAGE_BADGE_WIRE_BYTES];
        struct vcs_badge renamed = b2;
        renamed.sequence = 10; /* content id != the name it is filed as */
        ZB_CHECK("store: renamed wire serializes",
                 vcs_badge_serialize(&renamed, wire, sizeof(wire)) ==
                     VCS_BADGE_OK);
        uint8_t wrong_name[32];
        zb_root(0x7f, wrong_name);
        char hex[65], path[4400];
        zb_hex_enc(wrong_name, 32, hex);
        snprintf(path, sizeof(path), "%s/badges/%s", zcode, hex);
        FILE *f = fopen(path, "wb");
        ZB_CHECK("store: renamed wire planted",
                 f && fwrite(wire, 1, sizeof(wire), f) == sizeof(wire) &&
                     fclose(f) == 0);
        s = vcs_badge_store_load(zcode);
        ZB_CHECK("store: id-mismatched wire rejected on load",
                 s && vcs_badge_store_badge_count(s) == 3 &&
                     vcs_badge_store_corrupt_count(s) == 1);
        vcs_badge_store_free(s);
        ZB_CHECK("store: renamed plant removed", unlink(path) == 0);
    }

    /* A FOREIGN-ISSUER badge loads (its signature is valid) but never
     * satisfies dedup and never lists as earned. */
    {
        struct vcs_badge foreign;
        ZB_CHECK("store: foreign badge built",
                 zb_make_badge(&foreign_sk, foreign_pk.vch, d_pk.vch,
                               VCS_BADGE_BUG_HUNTER, 50, 50, 0x53, 0x30,
                               1, &foreign));
        s = vcs_badge_store_load(zcode);
        ZB_CHECK("store: foreign badge persists",
                 vcs_badge_store_persist(s, &foreign, id_scratch) ==
                     VCS_BADGE_PERSIST_OK);
        vcs_badge_store_free(s);
        s = vcs_badge_store_load(zcode);
        ZB_CHECK("store: foreign badge loads but is not recognized",
                 s && vcs_badge_store_badge_count(s) == 4 &&
                     !vcs_badge_recognized(&foreign, &policy) &&
                     !vcs_badge_store_dedup_hit(s, &policy, d_pk.vch,
                                                VCS_BADGE_BUG_HUNTER, 50,
                                                50));
        struct vcs_badge earned[8];
        ZB_CHECK("store: foreign badge never lists as earned",
                 vcs_badge_store_contributor_badges(s, &policy, d_pk.vch,
                                                    earned, 8) == 1 &&
                     earned[0].type == VCS_BADGE_TOP_DAILY);
        vcs_badge_store_free(s);
    }

    /* A leftover atomic-write temp is a crash artifact, not corruption. */
    {
        char path[4400];
        snprintf(path, sizeof(path), "%s/badges/zz.tmp.1.1", zcode);
        FILE *f = fopen(path, "wb");
        ZB_CHECK("store: temp artifact planted", f && fclose(f) == 0);
        s = vcs_badge_store_load(zcode);
        ZB_CHECK("store: temp artifact skipped, not corrupt",
                 s && vcs_badge_store_badge_count(s) == 4 &&
                     vcs_badge_store_corrupt_count(s) == 0);
        vcs_badge_store_free(s);
    }

    /* A malformed policy file fails closed. */
    {
        char path[4400];
        snprintf(path, sizeof(path), "%s/badge_policy", zcode);
        FILE *f = fopen(path, "wb");
        ZB_CHECK("store: malformed policy planted",
                 f && fputs("not-hex-at-all\n", f) >= 0 &&
                     fclose(f) == 0);
        struct vcs_badge_policy bad;
        ZB_CHECK("store: malformed policy rejected",
                 !vcs_badge_policy_load(zcode, &bad));
    }

    zb_rm_rf(datadir);
    return failures;
}

/* ── 4. plan + issue (the adversarial core) ─────────────────────────── */

static int t_plan_issue(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_plan_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("plan: datadir created", zb_mkdir_p(zcode));

    struct privkey issuer_sk, sk2, sk3, sk5, sk6;
    struct pubkey issuer_pk, c_pk, d_pk, e_pk, f_pk;
    ZB_CHECK("plan: keypairs",
             zb_keypair(1, &issuer_sk, &issuer_pk) &&
                 zb_keypair(2, &sk2, &c_pk) && zb_keypair(3, &sk3, &d_pk) &&
                 zb_keypair(5, &sk5, &e_pk) && zb_keypair(6, &sk6, &f_pk));
    ZB_CHECK("plan: policy file written",
             zb_write_policy(zcode, 0x30, issuer_pk.vch));
    struct vcs_badge_policy policy;
    ZB_CHECK("plan: policy loads",
             vcs_badge_policy_load(zcode, &policy));

    /* Facts: C crosses 100 settled test points at day 20000 (60 + 50)
     * and is the only contributor that day; E settles 50 at 20001. */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode);
        uint8_t id[32];
        ZB_CHECK("plan: rewards queued",
                 zb_auto(l, 0x10, c_pk.vch,
                         VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 60, 0x10,
                         id) == VCS_REWARD_ENQUEUE_OK &&
                     zb_auto(l, 0x11, c_pk.vch,
                             VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 50,
                             0x11, id) == VCS_REWARD_ENQUEUE_OK);
        ZB_CHECK("plan: day-20000 window settles",
                 zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        /* A settle commits EVERYTHING pending at that day — E's entry is
         * queued after the day-20000 settle so it lands on day 20001. */
        ZB_CHECK("plan: E's reward queued",
                 zb_auto(l, 0x12, e_pk.vch,
                         VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 50, 0x12,
                         id) == VCS_REWARD_ENQUEUE_OK);
        ZB_CHECK("plan: day-20001 window settles",
                 zb_settle(l, 20001) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode);
    ZB_CHECK("plan: store + ledger loaded", s && l);

    /* The facts builder derives every fact from the ledger. */
    struct vcs_badge_facts facts;
    vcs_badge_facts_build(c_pk.vch, NULL, l, 20000, &facts);
    ZB_CHECK("plan: facts derived (crossing day, rank 1, pioneer)",
             facts.has_settled && facts.hundred_tests_crossed &&
                 facts.hundred_tests_day == 20000 &&
                 facts.test_points_total == 110 && facts.top_daily &&
                 facts.top_daily_points == 110 && facts.top_weekly &&
                 facts.top_monthly && facts.ledger_any &&
                 facts.ledger_earliest_day == 20000 &&
                 !facts.has_bug_fix && !facts.has_security_fix &&
                 !facts.has_reproduction && !facts.has_first_package);

    /* PLAN: the five eligible types become rows; the rest are named
     * exclusions. */
    struct vcs_badge_plan plan;
    struct vcs_badge_plan_exclusion exclusions[VCS_BADGE_TYPE_COUNT];
    size_t exclusion_count = 0;
    ZB_CHECK("plan: batch assembled",
             vcs_badge_plan_build(s, &policy, c_pk.vch, &facts, 20000,
                                  &plan, exclusions, &exclusion_count));
    ZB_CHECK("plan: five rows planned",
             plan.row_count == 5 && exclusion_count == 8);
    {
        bool saw_hundred = false, saw_daily = false, saw_weekly = false,
             saw_monthly = false, saw_early = false;
        uint64_t seq_sum = 0;
        for (size_t i = 0; i < plan.row_count; i++) {
            const struct vcs_badge_plan_row *r = &plan.rows[i];
            seq_sum += r->sequence;
            switch (r->type) {
            case VCS_BADGE_HUNDRED_TESTS:
                saw_hundred = r->period_first == 20000;
                break;
            case VCS_BADGE_TOP_DAILY:
                saw_daily = r->period_first == 20000 &&
                            r->period_last == 20000;
                break;
            case VCS_BADGE_TOP_WEEKLY:
                saw_weekly = r->period_first == 19996 &&
                             r->period_last == 20002;
                break;
            case VCS_BADGE_TOP_MONTHLY:
                saw_monthly = r->period_first == 19997 &&
                              r->period_last == 20027;
                break;
            case VCS_BADGE_EARLY_ZCODE_CONTRIBUTOR:
                saw_early = r->period_first == VCS_BADGE_PERIOD_NONE;
                break;
            default: break;
            }
        }
        ZB_CHECK("plan: rows carry the right types + periods",
                 saw_hundred && saw_daily && saw_weekly && saw_monthly &&
                     saw_early);
        ZB_CHECK("plan: sequences are 1..5", seq_sum == 1 + 2 + 3 + 4 + 5);
        bool bug_named = false, popular_named = false;
        for (size_t i = 0; i < exclusion_count; i++) {
            if (exclusions[i].type == VCS_BADGE_BUG_HUNTER &&
                strcmp(exclusions[i].rule, VCS_BADGE_RULE_NOT_ELIGIBLE) ==
                    0)
                bug_named = true;
            if (exclusions[i].type == VCS_BADGE_POPULAR_PACKAGE &&
                strcmp(exclusions[i].rule, VCS_BADGE_RULE_UNAVAILABLE) ==
                    0)
                popular_named = true;
        }
        ZB_CHECK("plan: exclusions name the rules",
                 bug_named && popular_named);
    }
    ZB_CHECK("plan: persist + idempotent re-persist",
             vcs_badge_plan_persist(s, &plan) ==
                     VCS_BADGE_PLAN_PERSIST_OK &&
                 vcs_badge_plan_persist(s, &plan) ==
                     VCS_BADGE_PLAN_PERSIST_DUPLICATE);
    uint8_t c_plan_id[32];
    memcpy(c_plan_id, plan.plan_id, 32);

    /* ISSUE: the happy path persists five signed badges. */
    {
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: batch commits",
                 vcs_badge_issue(s, &policy, c_plan_id, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_OK &&
                     result.issued_count == 5 &&
                     result.replayed_count == 0 && !result.resumed);
        ZB_CHECK("issue: badges durable + verified",
                 vcs_badge_store_badge_count(s) == 5);
    }

    /* DOUBLE-ISSUE, replay path: ALREADY_ISSUED, never a double-issue. */
    {
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: replay is a named duplicate",
                 vcs_badge_issue(s, &policy, c_plan_id, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_ALREADY_ISSUED &&
                     vcs_badge_store_badge_count(s) == 5);
    }

    /* DOUBLE-ISSUE, plan path: every eligible type now dedup-excluded. */
    {
        struct vcs_badge_plan again;
        size_t again_exclusions = 0;
        ZB_CHECK("issue: re-plan dedup-excludes everything",
                 vcs_badge_plan_build(s, &policy, c_pk.vch, &facts, 20000,
                                      &again, exclusions,
                                      &again_exclusions) &&
                     again.row_count == 0 && again_exclusions == 13);
        bool dup_named = false;
        for (size_t i = 0; i < again_exclusions; i++)
            if (strcmp(exclusions[i].rule, VCS_BADGE_RULE_DUPLICATE) == 0)
                dup_named = true;
        ZB_CHECK("issue: duplicate-badge rule named", dup_named);
    }

    /* UNKNOWN_PLAN. */
    {
        uint8_t unknown[32];
        zb_root(0x60, unknown);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: unknown plan named",
                 vcs_badge_issue(s, &policy, unknown, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_UNKNOWN_PLAN);
    }

    /* WRONG-PERIOD: a plan row whose period is not the fact-derived
     * period is rejected at commit revalidation. */
    {
        struct vcs_badge_plan_row row;
        memset(&row, 0, sizeof(row));
        memcpy(row.contributor, c_pk.vch, 33);
        row.type = VCS_BADGE_TOP_DAILY;
        row.period_first = 20001; /* the facts say 20000 */
        row.period_last = 20001;
        zb_root(0x61, row.evidence_root);
        row.sequence = 6;
        struct vcs_badge_plan tampered;
        ZB_CHECK("issue: wrong-period plan assembles",
                 vcs_badge_plan_assemble(policy.policy_id,
                                         policy.issuer_pubkey, 20000,
                                         &row, 1, &tampered) &&
                     vcs_badge_plan_persist(s, &tampered) ==
                         VCS_BADGE_PLAN_PERSIST_OK);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: wrong-period row rejected",
                 vcs_badge_issue(s, &policy, tampered.plan_id, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_STALE &&
                     strstr(detail, VCS_BADGE_RULE_PERIOD_CHANGED) !=
                         NULL &&
                     vcs_badge_store_badge_count(s) == 5);
    }

    /* WRONG-EVIDENCE: same for the evidence root. */
    {
        struct vcs_badge_plan_row row;
        memset(&row, 0, sizeof(row));
        memcpy(row.contributor, c_pk.vch, 33);
        row.type = VCS_BADGE_TOP_DAILY;
        row.period_first = 20000;
        row.period_last = 20000;
        zb_root(0x62, row.evidence_root); /* not the facts' hash */
        row.sequence = 6;
        struct vcs_badge_plan tampered;
        ZB_CHECK("issue: wrong-evidence plan assembles",
                 vcs_badge_plan_assemble(policy.policy_id,
                                         policy.issuer_pubkey, 20000,
                                         &row, 1, &tampered) &&
                     vcs_badge_plan_persist(s, &tampered) ==
                         VCS_BADGE_PLAN_PERSIST_OK);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: wrong-evidence row rejected",
                 vcs_badge_issue(s, &policy, tampered.plan_id, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_STALE &&
                     strstr(detail, VCS_BADGE_RULE_EVIDENCE_CHANGED) !=
                         NULL &&
                     vcs_badge_store_badge_count(s) == 5);
    }

    /* SEQUENCE CONFLICT: a used sequence with different content. */
    {
        struct vcs_badge_plan_row row;
        memset(&row, 0, sizeof(row));
        memcpy(row.contributor, e_pk.vch, 33);
        row.type = VCS_BADGE_TOP_DAILY;
        row.period_first = 20001;
        row.period_last = 20001;
        vcs_badge_evidence_hash(VCS_BADGE_TOP_DAILY, e_pk.vch, 20001,
                                20001, 50, row.evidence_root);
        row.sequence = 1; /* already used by C's first-package badge */
        struct vcs_badge_plan conflict;
        ZB_CHECK("issue: sequence-conflict plan assembles",
                 vcs_badge_plan_assemble(policy.policy_id,
                                         policy.issuer_pubkey, 20001,
                                         &row, 1, &conflict) &&
                     vcs_badge_plan_persist(s, &conflict) ==
                         VCS_BADGE_PLAN_PERSIST_OK);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: sequence conflict named",
                 vcs_badge_issue(s, &policy, conflict.plan_id, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_STALE &&
                     strstr(detail, "sequence-conflict") != NULL &&
                     vcs_badge_store_badge_count(s) == 5);
    }

    /* SIGN FAILURE: nothing is written, no commit record. */
    {
        struct vcs_badge_facts efacts;
        vcs_badge_facts_build(e_pk.vch, NULL, l, 20001, &efacts);
        struct vcs_badge_plan eplan;
        size_t eexcl = 0;
        ZB_CHECK("issue: E's plan assembles",
                 vcs_badge_plan_build(s, &policy, e_pk.vch, &efacts,
                                      20001, &eplan, exclusions, &eexcl) &&
                     eplan.row_count == 2 /* top-daily + early */ &&
                     vcs_badge_plan_persist(s, &eplan) ==
                         VCS_BADGE_PLAN_PERSIST_OK);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: signer failure writes nothing",
                 vcs_badge_issue(s, &policy, eplan.plan_id, NULL, l,
                                 zb_fail_sign, NULL, &result, detail,
                                 sizeof(detail)) ==
                         VCS_BADGE_ISSUE_SIGN &&
                     vcs_badge_store_badge_count(s) == 5 &&
                     !vcs_badge_commit_known(s, eplan.plan_id));

        /* CRASH RESUME: one badge already durable (a simulated partial
         * issue), no commit record — the finishing issue replays it. */
        const struct vcs_badge_plan_row *r0 = &eplan.rows[0];
        struct vcs_badge partial;
        memset(&partial, 0, sizeof(partial));
        partial.schema_version = VCS_PACKAGE_BADGE_VERSION;
        partial.type = (uint8_t)r0->type;
        memcpy(partial.recipient, r0->contributor, 33);
        partial.period_first_day = r0->period_first;
        partial.period_last_day = r0->period_last;
        memcpy(partial.evidence_root, r0->evidence_root, 32);
        memcpy(partial.policy_id, policy.policy_id, 32);
        partial.sequence = r0->sequence;
        memcpy(partial.issuer_pubkey, policy.issuer_pubkey, 33);
        uint8_t pid[32];
        ZB_CHECK("issue: partial badge persisted (crash state)",
                 zb_sign(&issuer_sk, &partial) &&
                     vcs_badge_store_persist(s, &partial, pid) ==
                         VCS_BADGE_PERSIST_OK);
        memset(&result, 0, sizeof(result));
        ZB_CHECK("issue: interrupted issue resumes",
                 vcs_badge_issue(s, &policy, eplan.plan_id, NULL, l,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_OK &&
                     result.resumed && result.replayed_count == 1 &&
                     result.issued_count == 2 &&
                     vcs_badge_store_badge_count(s) == 7);
    }

    /* STALE: the facts moved since the plan (a rank overtake). */
    {
        /* F is rank 1 at day 20002 with 10 points until D2 lands 5000. */
        struct vcs_reward_ledger *lw = vcs_reward_ledger_load(zcode);
        uint8_t id[32];
        (void)zb_auto(lw, 0x13, f_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 10, 0x13,
                      id);
        (void)zb_settle(lw, 20002);
        vcs_reward_ledger_free(lw);
        struct vcs_reward_ledger *l2 = vcs_reward_ledger_load(zcode);
        struct vcs_badge_facts ffacts;
        vcs_badge_facts_build(f_pk.vch, NULL, l2, 20002, &ffacts);
        ZB_CHECK("issue: F is rank 1 before the overtake",
                 ffacts.top_daily && ffacts.top_daily_points == 10);
        struct vcs_badge_plan fplan;
        size_t fexcl = 0;
        ZB_CHECK("issue: F's plan assembles",
                 vcs_badge_plan_build(s, &policy, f_pk.vch, &ffacts,
                                      20002, &fplan, exclusions,
                                      &fexcl) &&
                     fplan.row_count == 2 &&
                     vcs_badge_plan_persist(s, &fplan) ==
                         VCS_BADGE_PLAN_PERSIST_OK);
        vcs_reward_ledger_free(l2);

        struct vcs_reward_ledger *lw2 = vcs_reward_ledger_load(zcode);
        (void)zb_auto(lw2, 0x14, d_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 5000, 0x14,
                      id);
        (void)zb_settle(lw2, 20002);
        vcs_reward_ledger_free(lw2);
        struct vcs_reward_ledger *l3 = vcs_reward_ledger_load(zcode);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("issue: stale plan named after the overtake",
                 vcs_badge_issue(s, &policy, fplan.plan_id, NULL, l3,
                                 zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_STALE &&
                     strstr(detail, VCS_BADGE_RULE_NOT_ELIGIBLE) !=
                         NULL &&
                     !vcs_badge_commit_known(s, fplan.plan_id));

        /* POLICY MISMATCH: the plan's issuer is not the configured
         * policy any more. Checked BEFORE row revalidation. */
        ZB_CHECK("issue: policy rewritten",
                 zb_write_policy(zcode, 0x31, d_pk.vch));
        struct vcs_badge_policy other_policy;
        ZB_CHECK("issue: foreign policy loads",
                 vcs_badge_policy_load(zcode, &other_policy));
        ZB_CHECK("issue: policy mismatch named",
                 vcs_badge_issue(s, &other_policy, fplan.plan_id, NULL,
                                 l3, zb_issue_sign, &issuer_sk, &result,
                                 detail, sizeof(detail)) ==
                     VCS_BADGE_ISSUE_POLICY_MISMATCH);
        vcs_reward_ledger_free(l3);
    }

    vcs_reward_ledger_free(l);
    vcs_badge_store_free(s);
    zb_rm_rf(datadir);
    return failures;
}

/* ── 5. permanence + cross-period dedup ─────────────────────────────── */

static int t_permanence_dedup(void)
{
    int failures = 0;
    char datadir[4400], zcode[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zb_perm_%ld",
             (long)getpid());
    snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    zb_rm_rf(datadir);
    ZB_CHECK("perm: datadir created", zb_mkdir_p(zcode));

    struct privkey issuer_sk, sk2, sk3;
    struct pubkey issuer_pk, c_pk, d_pk;
    ZB_CHECK("perm: keypairs",
             zb_keypair(1, &issuer_sk, &issuer_pk) &&
                 zb_keypair(2, &sk2, &c_pk) && zb_keypair(3, &sk3, &d_pk));
    ZB_CHECK("perm: policy written",
             zb_write_policy(zcode, 0x30, issuer_pk.vch));
    struct vcs_badge_policy policy;
    ZB_CHECK("perm: policy loads", vcs_badge_policy_load(zcode, &policy));

    /* C is rank 1 on days 20000 and 20001 (100 settled test points
     * each); D2 buries the board on day 20010. */
    {
        struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode);
        uint8_t id[32];
        (void)zb_auto(l, 0x10, c_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 100, 0x10,
                      id);
        ZB_CHECK("perm: day-20000 settles",
                 zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        (void)zb_auto(l, 0x11, c_pk.vch,
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 100, 0x11,
                      id);
        ZB_CHECK("perm: day-20001 settles",
                 zb_settle(l, 20001) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    struct vcs_badge_store *s = vcs_badge_store_load(zcode);
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode);
    ZB_CHECK("perm: store + ledger loaded", s && l);

    /* Issue C's day-20000 badges (top-daily among them). */
    struct vcs_badge_plan_exclusion exclusions[VCS_BADGE_TYPE_COUNT];
    {
        struct vcs_badge_facts facts;
        vcs_badge_facts_build(c_pk.vch, NULL, l, 20000, &facts);
        struct vcs_badge_plan plan;
        size_t excl = 0;
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("perm: day-20000 badge issued",
                 vcs_badge_plan_build(s, &policy, c_pk.vch, &facts, 20000,
                                      &plan, exclusions, &excl) &&
                     vcs_badge_plan_persist(s, &plan) ==
                         VCS_BADGE_PLAN_PERSIST_OK &&
                     vcs_badge_issue(s, &policy, plan.plan_id, NULL, l,
                                     zb_issue_sign, &issuer_sk, &result,
                                     detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_OK);
    }

    /* CROSS-PERIOD DEDUP: TOP_DAILY on day 20001 is a DIFFERENT
     * achievement period — allowed. */
    {
        struct vcs_badge_facts facts;
        vcs_badge_facts_build(c_pk.vch, NULL, l, 20001, &facts);
        ZB_CHECK("perm: C is rank 1 on day 20001 too",
                 facts.top_daily && facts.top_daily_points == 100);
        struct vcs_badge_plan plan;
        size_t excl = 0;
        ZB_CHECK("perm: day-20001 plan keeps top-daily",
                 vcs_badge_plan_build(s, &policy, c_pk.vch, &facts, 20001,
                                      &plan, exclusions, &excl));
        bool has_daily = false;
        for (size_t i = 0; i < plan.row_count; i++)
            if (plan.rows[i].type == VCS_BADGE_TOP_DAILY &&
                plan.rows[i].period_first == 20001)
                has_daily = true;
        ZB_CHECK("perm: top-daily on a second day allowed", has_daily);
        struct vcs_badge_issue_result result;
        char detail[256];
        ZB_CHECK("perm: day-20001 badge issued",
                 vcs_badge_plan_persist(s, &plan) ==
                         VCS_BADGE_PLAN_PERSIST_OK &&
                     vcs_badge_issue(s, &policy, plan.plan_id, NULL, l,
                                     zb_issue_sign, &issuer_sk, &result,
                                     detail, sizeof(detail)) ==
                         VCS_BADGE_ISSUE_OK);
    }

    /* Two TOP_DAILY badges for the two distinct days now exist. */
    {
        struct vcs_badge earned[16];
        size_t total = vcs_badge_store_contributor_badges(
            s, &policy, c_pk.vch, earned, 16);
        int dailies = 0;
        for (size_t i = 0; i < total && i < 16; i++)
            if (earned[i].type == VCS_BADGE_TOP_DAILY)
                dailies++;
        ZB_CHECK("perm: two top-daily badges (two days)",
                 dailies == 2);
    }

    /* RANK LOSS: D2 lands 9000 points on day 20010 — C falls off the
     * board. The badges are PERMANENT historical evidence. */
    {
        struct vcs_reward_ledger *lw = vcs_reward_ledger_load(zcode);
        uint8_t id[32];
        (void)zb_auto(lw, 0x12, d_pk.vch, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                      2500, 0x12, id);
        (void)zb_auto(lw, 0x13, d_pk.vch, VCS_REWARD_CATEGORY_NEW_PACKAGE,
                      2500, 0x13, id);
        ZB_CHECK("perm: day-20010 overtake settles",
                 zb_settle(lw, 20010) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(lw);
        vcs_reward_ledger_free(l);
        l = vcs_reward_ledger_load(zcode);
        struct vcs_badge_facts facts;
        vcs_badge_facts_build(c_pk.vch, NULL, l, 20010, &facts);
        ZB_CHECK("perm: C is honestly off the board on day 20010",
                 !facts.top_daily && !facts.top_weekly &&
                     !facts.top_monthly);
        struct vcs_badge_eval eval;
        ZB_CHECK("perm: top-daily no longer eligible",
                 vcs_badge_evaluate(VCS_BADGE_TOP_DAILY, c_pk.vch, &facts,
                                    20010, &eval) &&
                     !eval.eligible);

        /* The badge SURVIVES the rank loss: still stored, still listed. */
        vcs_badge_store_free(s);
        s = vcs_badge_store_load(zcode);
        struct vcs_badge earned[16];
        size_t total = vcs_badge_store_contributor_badges(
            s, &policy, c_pk.vch, earned, 16);
        int dailies = 0;
        for (size_t i = 0; i < total && i < 16; i++)
            if (earned[i].type == VCS_BADGE_TOP_DAILY)
                dailies++;
        ZB_CHECK("perm: badges survive the rank loss",
                 total > 0 && dailies == 2);
    }

    vcs_reward_ledger_free(l);
    vcs_badge_store_free(s);
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
                      VCS_REWARD_CATEGORY_TEST_CONTRIBUTION, 100, 0x10,
                      id);
        ZB_CHECK("commands: day-20000 settles",
                 zb_settle(l, 20000) == VCS_REWARD_COMMIT_OK);
        vcs_reward_ledger_free(l);
    }

    /* eligible: all 13 types reported; unavailable named; evidence
     * facts carried. */
    {
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
        zb_cmd_free(&c);
    }

    /* plan WITHOUT a policy: NO_BADGE_POLICY named. */
    char plan_id_hex[65];
    plan_id_hex[0] = '\0';
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

    /* plan: five rows, exclusions named, idempotent re-plan. */
    {
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
            snprintf(plan_id_hex, sizeof(plan_id_hex), "%s", pid);
        const struct json_value *excl =
            json_get(&c.reply.data, "exclusions");
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
        zb_cmd_free(&c);

        struct zb_cmd c2;
        zb_cmd_init(&c2, datadir);
        (void)json_push_kv_str(&c2.input, "pubkey", c_hex);
        (void)json_push_kv_int(&c2.input, "day", 20000);
        zcl_native_handle_zcode_badge_plan(&c2.request, &c2.reply);
        ZB_CHECK("commands: re-plan is the idempotent same id",
                 json_get_bool(json_get(&c2.reply.data,
                                        "already_persisted")) &&
                     strcmp(json_get_str(json_get(&c2.reply.data,
                                                  "plan_id"))
                                ? json_get_str(json_get(&c2.reply.data,
                                                        "plan_id"))
                                : "",
                            plan_id_hex) == 0);
        zb_cmd_free(&c2);
    }

    /* issue: wrong issuer secret rejected; unknown plan rejected;
     * happy path; replay a named duplicate. */
    {
        char secret_hex[65];
        zb_hex_enc(foreign_sk.vch, 32, secret_hex);
        struct zb_cmd c;
        zb_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", plan_id_hex);
        (void)json_push_kv_str(&c.input, "issuer_secret", secret_hex);
        zcl_native_handle_zcode_badge_issue(&c.request, &c.reply);
        ZB_CHECK("commands: non-policy issuer key rejected",
                 strcmp(c.reply.error.code, "ISSUER_KEY_MISMATCH") == 0);
        zb_cmd_free(&c);
    }
    {
        uint8_t unknown[32];
        zb_root(0x60, unknown);
        char unknown_hex[65], secret_hex[65];
        zb_hex_enc(unknown, 32, unknown_hex);
        zb_hex_enc(issuer_sk.vch, 32, secret_hex);
        struct zb_cmd c;
        zb_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", unknown_hex);
        (void)json_push_kv_str(&c.input, "issuer_secret", secret_hex);
        zcl_native_handle_zcode_badge_issue(&c.request, &c.reply);
        ZB_CHECK("commands: unknown plan named",
                 strcmp(c.reply.error.code, "UNKNOWN_PLAN") == 0);
        zb_cmd_free(&c);
    }
    {
        char secret_hex[65];
        zb_hex_enc(issuer_sk.vch, 32, secret_hex);
        struct zb_cmd c;
        zb_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "plan_id", plan_id_hex);
        (void)json_push_kv_str(&c.input, "issuer_secret", secret_hex);
        zcl_native_handle_zcode_badge_issue(&c.request, &c.reply);
        ZB_CHECK("commands: issue commits the batch",
                 json_get_int(json_get(&c.reply.data, "issued_count")) ==
                         5 &&
                     json_get_bool(json_get(&c.reply.data, "simulated")));
        const struct json_value *badges =
            json_get(&c.reply.data, "badges");
        ZB_CHECK("commands: issued badges listed with ids",
                 badges && json_at(badges, 4) != NULL &&
                     json_get_str(json_get(json_at(badges, 0),
                                           "badge_id")) != NULL);
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
    }

    /* contributor badges: the earned badges, permanent:true. */
    {
        struct zb_cmd c;
        zb_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "pubkey", c_hex);
        zcl_native_handle_zcode_contributor_badges(&c.request, &c.reply);
        const struct json_value *badges =
            json_get(&c.reply.data, "badges");
        ZB_CHECK("commands: contributor badges listed",
                 badges &&
                     json_get_int(json_get(&c.reply.data,
                                           "total_badges")) == 5 &&
                     json_at(badges, 4) != NULL &&
                     json_get_bool(json_get(json_at(badges, 0),
                                            "permanent")));
        zb_cmd_free(&c);
    }

    /* A contributor with no badges: honestly empty. */
    {
        struct privkey sk9;
        struct pubkey nobody_pk;
        ZB_CHECK("commands: nobody keypair",
                 zb_keypair(9, &sk9, &nobody_pk));
        char nobody_hex[67];
        zb_hex_enc(nobody_pk.vch, 33, nobody_hex);
        struct zb_cmd c;
        zb_cmd_init(&c, datadir);
        (void)json_push_kv_str(&c.input, "pubkey", nobody_hex);
        zcl_native_handle_zcode_contributor_badges(&c.request, &c.reply);
        ZB_CHECK("commands: no badges honestly empty",
                 json_get_int(json_get(&c.reply.data, "total_badges")) ==
                     0);
        zb_cmd_free(&c);
    }

    zb_rm_rf(datadir);
    return failures;
}

int test_zcode_badge(void)
{
    printf("\n=== zcode_badge: SIMULATED ZCODE Badges (slice 10) ===\n");
    int failures = 0;
    failures += t_codec();
    failures += t_evaluator();
    failures += t_store();
    failures += t_plan_issue();
    failures += t_permanence_dedup();
    failures += t_commands();
    printf("=== zcode_badge complete: %d failure(s) ===\n", failures);
    return failures;
}
