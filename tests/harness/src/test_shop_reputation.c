/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for `app shop reputation` (slice C of docs/work/SHOP_COMMAND.md;
 * handler in contexts/market/controllers/src/shop_native_reputation.c).
 *
 * Covered:
 *   1. an unknown publisher on a populated store renders every evidence
 *      class as "no_record" (and the two source-less classes as
 *      "unavailable") — never a zero, never a recorded row
 *   2. a datadir with no zcode store at all answers the same way, with
 *      zcode_store_present false — absence is a state, not a failure
 *   3. a fully populated fixture store renders each row with its count and
 *      evidence class: 1 signed release/package, 241 days observed from
 *      the local mtime, 2 matching reproduction receipts, 2 distinct
 *      attestation signer keys (a foreign-root attestation is ignored),
 *      1 dependent package from a root-committed declaration, 1 simulated
 *      settlement
 *   4. the reply contains none of the forbidden vocabulary: no
 *      "independent", no "trust", no "score", no "rating", no "star" —
 *      the readout is provable facts, never an adjective
 *   5. input validation: a missing/malformed publisher key is the named
 *      BAD_PUBLISHER_INPUT refusal
 *   6. the populated reply serializes inside the CLI's real reply budget
 *      (ZCL_COMMAND_LIST_BUDGET + 1) through the real registry
 *
 * Every case runs in-process against a fixture datadir under ./test-tmp;
 * the fixtures are real signed objects (releases, attestations signed with
 * fixture secp256k1 keys; build receipts; a reward-ledger settlement) laid
 * out exactly where the node files them under <datadir>/zcode. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"     /* zcl_command_catalog */
#include "controllers/shop_native_handler.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include "base/hex.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/package_attest.h"
#include "vcs/package_build.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/package_reward.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>

#define SR_CHECK(name, expr) do {                                       \
    printf("shop_reputation: %s... ", (name));                          \
    if (expr) { printf("OK\n"); }                                       \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

/* The fixture observation window: the subject's release envelope is
 * backdated to SR_BASE_UNIX and the query runs 241 days later. */
#define SR_BASE_UNIX 1700000000LL
#define SR_DAYS_OBSERVED 241LL

/* ── small fixtures ─────────────────────────────────────────────────── */

static bool sr_mkdir_p(const char *path)
{
    char tmp[4400];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp))
        return false;
    memcpy(tmp, path, len + 1);
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] != '/')
            continue;
        tmp[i] = '\0';
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
            return false;
        tmp[i] = '/';
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

static bool sr_write_file(const char *path, const void *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    fclose(f);
    return ok;
}

static bool sr_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static void sr_pattern_root(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
}

/* A signed release by the given key naming (package_root, recipe_root). */
static bool sr_release(struct vcs_package_release *r, uint8_t key_seed,
                       uint64_t sequence, const char *name,
                       const uint8_t package_root[32],
                       const uint8_t recipe_root[32])
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!sr_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    /* reward_address stays empty (0 printable bytes is a legal v1 value). */
    snprintf(r->license, sizeof(r->license), "MIT");
    memcpy(r->recipe_root, recipe_root, 32);
    r->has_znam = false;
    snprintf(r->chain_id, sizeof(r->chain_id), "main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

/* Persist a release under <zcode>/releases/<release-id-hex> (the store's
 * own filing convention), optionally backdating the envelope's mtime. */
static bool sr_store_release(const char *zcode_dir,
                             const struct vcs_package_release *r,
                             int64_t mtime)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_release_serialize(r, &wire, &wire_len) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    bool ok = vcs_package_release_id(r, id) == VCS_PACKAGE_RELEASE_OK;
    if (ok) {
        char id_hex[65];
        zcl_hex_encode(id, 32, id_hex);
        char dir[4400], path[4400];
        int n = snprintf(dir, sizeof(dir), "%s/releases", zcode_dir);
        ok = n > 0 && (size_t)n < sizeof(dir) && sr_mkdir_p(dir);
        n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
        ok = ok && n > 0 && (size_t)n < sizeof(path) &&
             sr_write_file(path, wire, wire_len);
        if (ok && mtime > 0) {
            struct utimbuf times = { .actime = mtime, .modtime = mtime };
            ok = utime(path, &times) == 0;
        }
    }
    free(wire);
    return ok;
}

/* A signed test-pass attestation over (package, release, recipe) by the
 * given verifier key, persisted under <zcode>/attestations/<id-hex>. */
static bool sr_store_attestation(const char *zcode_dir,
                                 const uint8_t package_root[32],
                                 const uint8_t release_id[32],
                                 const uint8_t recipe_root[32],
                                 uint8_t signer_seed)
{
    struct privkey sk;
    struct pubkey pk;
    if (!sr_keypair(signer_seed, &sk, &pk))
        return false;
    struct vcs_package_attest a;
    memset(&a, 0, sizeof(a));
    a.schema_version = VCS_PACKAGE_ATTEST_VERSION;
    memcpy(a.package_root, package_root, 32);
    memcpy(a.release_id, release_id, 32);
    memcpy(a.recipe_root, recipe_root, 32);
    a.result_class = VCS_PACKAGE_ATTEST_RESULT_TEST_PASS;
    snprintf(a.compilers[0].id, sizeof(a.compilers[0].id), "clang");
    snprintf(a.compilers[0].version, sizeof(a.compilers[0].version),
             "18.1.3");
    a.compiler_count = 1;
    a.compilers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a.test_ran = true;
    a.isolation = VCS_PACKAGE_ATTEST_ISOLATION_FULL;
    memcpy(a.verifier_pubkey, pk.vch, 33);
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    if (vcs_package_attest_id(&a, id) != VCS_PACKAGE_ATTEST_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(a.signature, compact + 1, VCS_PACKAGE_ATTEST_SIGNATURE_BYTES);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_attest_serialize(&a, &wire, &wire_len) !=
        VCS_PACKAGE_ATTEST_OK)
        return false;
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    char dir[4400], path[4400];
    int n = snprintf(dir, sizeof(dir), "%s/attestations", zcode_dir);
    bool ok = n > 0 && (size_t)n < sizeof(dir) && sr_mkdir_p(dir);
    n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    ok = ok && n > 0 && (size_t)n < sizeof(path) &&
         sr_write_file(path, wire, wire_len);
    free(wire);
    return ok;
}

/* One installable build receipt (same output set per out_seed; the
 * compiler version varies the receipt id — a distinct build event). */
static bool sr_store_receipt(const char *zcode_dir,
                             const uint8_t package_root[32],
                             const uint8_t recipe_root[32],
                             const char *compiler_version, uint8_t out_seed)
{
    struct vcs_package_build_receipt r;
    vcs_package_build_receipt_init(&r);
    memcpy(r.package_root, package_root, 32);
    memcpy(r.recipe_root, recipe_root, 32);
    sr_pattern_root(0x77, r.lock_root);
    snprintf(r.compiler_id, sizeof(r.compiler_id), "gcc");
    snprintf(r.compiler_version, sizeof(r.compiler_version), "%s",
             compiler_version);
    snprintf(r.flags, sizeof(r.flags), "-std=c23 -O1");
    r.result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
    r.isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
    r.test_ran = true;
    uint8_t h1[32], h2[32];
    sr_pattern_root(out_seed, h1);
    sr_pattern_root((uint8_t)(out_seed + 1u), h2);
    if (vcs_package_build_add_output(&r, "include/add.h", h1, 100) !=
            VCS_PACKAGE_BUILD_OK ||
        vcs_package_build_add_output(&r, "lib/libaddpkg.a", h2, 4096) !=
            VCS_PACKAGE_BUILD_OK)
        return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_build_serialize(&r, &wire, &wire_len) !=
        VCS_PACKAGE_BUILD_OK)
        return false;
    uint8_t id[32];
    bool ok = vcs_package_build_id(&r, id) == VCS_PACKAGE_BUILD_OK;
    if (ok) {
        char id_hex[65];
        zcl_hex_encode(id, 32, id_hex);
        char dir[4400], path[4400];
        int n = snprintf(dir, sizeof(dir), "%s/receipts", zcode_dir);
        ok = n > 0 && (size_t)n < sizeof(dir) && sr_mkdir_p(dir);
        n = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
        ok = ok && n > 0 && (size_t)n < sizeof(path) &&
             sr_write_file(path, wire, wire_len);
    }
    free(wire);
    return ok;
}

/* Persist one package's manifest + its zcode-package.json declaration
 * chunk (single-chunk member), so the declaration is locally readable
 * and root-committed. The manifest root — which IS the package root the
 * release must name — is returned in root_out. decl may be NULL (no
 * declaration member at all). */
static bool sr_store_declaration(const char *zcode_dir,
                                 const char *decl, uint8_t root_out[32])
{
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t chunk_hash[32];
    bool ok = true;
    size_t decl_len = decl ? strlen(decl) : 0;
    if (decl) {
        struct sha3_256_ctx sha;
        sha3_256_init(&sha);
        sha3_256_write(&sha, (const uint8_t *)decl, decl_len);
        sha3_256_finalize(&sha, chunk_hash);
        ok = vcs_package_manifest_add(&manifest, VCS_PACKAGE_DEPS_META_PATH,
                                      VCS_PACKAGE_MODE_FILE, decl_len,
                                      chunk_hash, 1);
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (ok)
        ok = vcs_package_manifest_serialize(&manifest, &wire, &wire_len);
    if (ok)
        ok = vcs_package_manifest_root(&manifest, root_out);
    vcs_package_manifest_free(&manifest);
    if (!ok)
        return false;
    char root_hex[65];
    zcl_hex_encode(root_out, 32, root_hex);
    char dir[4400], path[4400];
    int n = snprintf(dir, sizeof(dir), "%s/manifests", zcode_dir);
    ok = n > 0 && (size_t)n < sizeof(dir) && sr_mkdir_p(dir);
    n = snprintf(path, sizeof(path), "%s/%s", dir, root_hex);
    ok = ok && n > 0 && (size_t)n < sizeof(path) &&
         sr_write_file(path, wire, wire_len);
    free(wire);
    if (ok && decl) {
        char chunk_hex[65];
        zcl_hex_encode(chunk_hash, 32, chunk_hex);
        n = snprintf(dir, sizeof(dir), "%s/cas/sha3/%.2s", zcode_dir,
                     chunk_hex);
        ok = n > 0 && (size_t)n < sizeof(dir) && sr_mkdir_p(dir);
        n = snprintf(path, sizeof(path), "%s/%s", dir, chunk_hex);
        ok = ok && n > 0 && (size_t)n < sizeof(path) &&
             sr_write_file(path, decl, decl_len);
    }
    return ok;
}

/* Settle one simulated reward to the contributor key through the real
 * ledger flow (enqueue -> plan -> persist -> commit), so the settled fact
 * is exactly what the node would have written. */
static bool sr_settle_one_reward(const char *zcode_dir,
                                 const uint8_t release_root[32],
                                 const uint8_t contributor[33])
{
    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    if (!ledger)
        return false;
    uint8_t facts_hash[32];
    sr_pattern_root(0x55, facts_hash);
    uint8_t entry_id[32];
    bool ok = vcs_reward_enqueue_auto(
                  ledger, release_root, contributor,
                  VCS_REWARD_CATEGORY_NEW_PACKAGE, 5, facts_hash,
                  entry_id) == VCS_REWARD_ENQUEUE_OK;
    struct vcs_reward_plan plan;
    if (ok)
        ok = vcs_reward_plan_build(ledger, 1, &plan);
    if (ok)
        ok = vcs_reward_plan_persist(ledger, &plan) ==
             VCS_REWARD_PLAN_PERSIST_OK;
    struct vcs_reward_commit_result result;
    if (ok)
        ok = vcs_reward_commit(ledger, plan.plan_id, &result, NULL, 0) ==
             VCS_REWARD_COMMIT_OK && result.settled_count == 1;
    if (ok)
        vcs_reward_plan_free(&plan);
    vcs_reward_ledger_free(ledger);
    return ok;
}

/* ── handler plumbing ───────────────────────────────────────────────── */
static void sr_call(struct json_value *input, struct zcl_command_reply *reply)
{
    struct zcl_command_request request = { .input = input };
    zcl_command_reply_init(reply, "zcl.test.v1");
    zcl_native_handle_shop_reputation(&request, reply);
}

static const struct json_value *sr_row(const struct zcl_command_reply *reply,
                                       const char *fact)
{
    const struct json_value *rows = json_get(&reply->data, "evidence");
    if (!rows || rows->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < rows->num_children; i++) {
        const char *f = json_get_str(json_get(&rows->children[i], "fact"));
        if (f && strcmp(f, fact) == 0)
            return &rows->children[i];
    }
    return NULL;
}

static const char *sr_str(const struct json_value *obj, const char *key)
{
    const char *s = json_get_str(json_get(obj, key));
    return s ? s : "";
}

/* Row `fact` is in the expected state, and (when has_value) carries the
 * expected count. */
static bool sr_row_is(const struct zcl_command_reply *reply,
                      const char *fact, const char *state,
                      bool has_value, int64_t value)
{
    const struct json_value *row = sr_row(reply, fact);
    if (!row)
        return false;
    if (strcmp(sr_str(row, "state"), state) != 0)
        return false;
    if (!has_value)
        return true;
    return json_get_int(json_get(row, "value")) == value;
}

/* The populated fixture store: subject publisher (seed 0x11) with one
 * signed release (backdated), two byte-identical build receipts, two
 * signer-distinct attestations plus one foreign attestation, a dependent
 * package by a second publisher (seed 0x22) declaring a root-committed
 * dependency on the subject's package, and one settled simulated reward. */
#define SR_SUBJECT_SEED 0x11
#define SR_FOREIGN_SEED 0x66

static bool sr_populate(const char *dir, char zcode_dir[4400],
                        uint8_t package_root[32], uint8_t recipe_root[32],
                        char publisher_hex[67])
{
    int n = snprintf(zcode_dir, 4400, "%s/zcode", dir);
    if (n < 0 || (size_t)n >= 4400)
        return false;
    sr_pattern_root(0xa1, package_root);
    sr_pattern_root(0xa2, recipe_root);
    struct pubkey subject_pk;
    struct privkey subject_sk;
    if (!sr_keypair(SR_SUBJECT_SEED, &subject_sk, &subject_pk))
        return false;
    zcl_hex_encode(subject_pk.vch, 33, publisher_hex);

    struct vcs_package_release rel;
    if (!sr_release(&rel, SR_SUBJECT_SEED, 1, "alice/ring", package_root,
                    recipe_root))
        return false;
    uint8_t release_id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, release_id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    if (!sr_store_release(zcode_dir, &rel, SR_BASE_UNIX))
        return false;

    /* Two byte-identical output sets, distinct receipt ids. */
    if (!sr_store_receipt(zcode_dir, package_root, recipe_root, "14.2.0",
                          0x40) ||
        !sr_store_receipt(zcode_dir, package_root, recipe_root, "15.1.0",
                          0x40))
        return false;

    /* Two distinct signer keys over the subject's package, plus one
     * attestation over a FOREIGN package root that must not count. */
    if (!sr_store_attestation(zcode_dir, package_root, release_id,
                              recipe_root, 0x42) ||
        !sr_store_attestation(zcode_dir, package_root, release_id,
                              recipe_root, 0x43))
        return false;
    uint8_t foreign_pkg[32], foreign_recipe[32], foreign_rel_id[32];
    sr_pattern_root(0xf1, foreign_pkg);
    sr_pattern_root(0xf2, foreign_recipe);
    sr_pattern_root(0xf3, foreign_rel_id);
    if (!sr_store_attestation(zcode_dir, foreign_pkg, foreign_rel_id,
                              foreign_recipe, SR_FOREIGN_SEED))
        return false;

    /* The dependent package: bob's "bob/hammer" declares a root-committed
     * dependency on the subject's package root. The declaration manifest
     * is built first — its root IS the package root bob's release names. */
    char subject_root_hex[65];
    zcl_hex_encode(package_root, 32, subject_root_hex);
    char decl[256];
    n = snprintf(decl, sizeof(decl),
                 "{\"schema\":1,\"dependencies\":[{\"root\":\"%s\","
                 "\"name\":\"alice/ring\",\"semver\":\"1.0.0\"}]}",
                 subject_root_hex);
    if (n < 0 || (size_t)n >= sizeof(decl))
        return false;
    uint8_t bob_pkg[32], bob_recipe[32];
    sr_pattern_root(0xb2, bob_recipe);
    if (!sr_store_declaration(zcode_dir, decl, bob_pkg))
        return false;
    struct vcs_package_release bob_rel;
    if (!sr_release(&bob_rel, 0x22, 1, "bob/hammer", bob_pkg, bob_recipe) ||
        !sr_store_release(zcode_dir, &bob_rel, 0))
        return false;

    /* One settled simulated reward to the subject's key. */
    return sr_settle_one_reward(zcode_dir, package_root, subject_pk.vch);
}

/* ── 1. unknown publisher: every row no_record / unavailable ────────── */
static int shop_rep_unknown_publisher(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shoprep", "unknown");
    char zcode_dir[4400];
    uint8_t package_root[32], recipe_root[32];
    char publisher_hex[67];
    SR_CHECK("fixture store populated",
             sr_populate(dir, zcode_dir, package_root, recipe_root,
                         publisher_hex));

    /* A key that has published nothing (seed 0x99). */
    struct privkey sk;
    struct pubkey pk;
    SR_CHECK("unknown keypair", sr_keypair(0x99, &sk, &pk));
    char unknown_hex[67];
    zcl_hex_encode(pk.vch, 33, unknown_hex);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "publisher", unknown_hex);
    struct zcl_command_reply reply;
    sr_call(&input, &reply);

    SR_CHECK("an unknown publisher still passes the read",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SR_CHECK("the store is reported present",
             json_get_bool(json_get(&reply.data, "zcode_store_present")));
    SR_CHECK("releases: no record, not zero",
             sr_row_is(&reply, "releases_published", "no_record", false, 0));
    SR_CHECK("packages: no record",
             sr_row_is(&reply, "packages_published", "no_record", false, 0));
    SR_CHECK("days observed: no record",
             sr_row_is(&reply, "days_observed", "no_record", false, 0));
    SR_CHECK("reproductions: no record",
             sr_row_is(&reply, "reproductions", "no_record", false, 0));
    SR_CHECK("signing identities: no record",
             sr_row_is(&reply, "distinct_signing_identities", "no_record",
                       false, 0));
    SR_CHECK("dependents: no record",
             sr_row_is(&reply, "dependent_packages", "no_record", false, 0));
    SR_CHECK("settlements: no record",
             sr_row_is(&reply, "simulated_settlements", "no_record",
                       false, 0));
    SR_CHECK("availability: unavailable, never fabricated",
             sr_row_is(&reply, "availability_challenges", "unavailable",
                       false, 0));
    SR_CHECK("paid fulfillments: unavailable, never fabricated",
             sr_row_is(&reply, "paid_fulfillments", "unavailable",
                       false, 0));
    /* A no_record row carries no value field at all — absence, not 0. */
    const struct json_value *row = sr_row(&reply, "releases_published");
    SR_CHECK("a no_record row has no value member",
             row && !json_get(row, "value"));

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 2. no zcode store at all ───────────────────────────────────────── */
static int shop_rep_no_store(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shoprep", "nostore");

    struct privkey sk;
    struct pubkey pk;
    SR_CHECK("keypair", sr_keypair(0x99, &sk, &pk));
    char hex[67];
    zcl_hex_encode(pk.vch, 33, hex);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "publisher", hex);
    struct zcl_command_reply reply;
    sr_call(&input, &reply);

    SR_CHECK("no store still passes the read",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SR_CHECK("the missing store is named",
             !json_get_bool(json_get(&reply.data, "zcode_store_present")));
    SR_CHECK("releases: no record on a store-less datadir",
             sr_row_is(&reply, "releases_published", "no_record", false, 0));
    SR_CHECK("availability: unavailable",
             sr_row_is(&reply, "availability_challenges", "unavailable",
                       false, 0));

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 2b. a present-but-unreadable store refuses by name ─────────────── */
static int shop_rep_unreadable_store(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shoprep", "unreadable");

    /* <datadir>/zcode/manifests as a plain FILE: the store member is
     * present and unmistakably not a directory — the state that must
     * refuse rather than read as an empty store. */
    char path[640];
    int n = snprintf(path, sizeof(path), "%s/zcode", dir);
    SR_CHECK("fixture zcode dir", n > 0 && (size_t)n < sizeof(path) &&
             sr_mkdir_p(path));
    n = snprintf(path, sizeof(path), "%s/zcode/manifests", dir);
    SR_CHECK("store member broken", n > 0 && (size_t)n < sizeof(path) &&
             sr_write_file(path, "not a directory", 15));

    struct privkey sk;
    struct pubkey pk;
    SR_CHECK("keypair", sr_keypair(0x99, &sk, &pk));
    char hex[67];
    zcl_hex_encode(pk.vch, 33, hex);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "publisher", hex);
    struct zcl_command_reply reply;
    sr_call(&input, &reply);

    SR_CHECK("an unreadable store member is ZCODE_STORE_UNREADABLE",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "ZCODE_STORE_UNREADABLE") == 0 &&
             reply.error.message[0] != '\0');
    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 3. populated store: every row renders its count + evidence class ── */
static int shop_rep_populated_rows(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shoprep", "populated");
    char zcode_dir[4400];
    uint8_t package_root[32], recipe_root[32];
    char publisher_hex[67];
    SR_CHECK("fixture store populated",
             sr_populate(dir, zcode_dir, package_root, recipe_root,
                         publisher_hex));

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "publisher", publisher_hex);
    (void)json_push_kv_int(&input, "now_unix",
                           SR_BASE_UNIX + SR_DAYS_OBSERVED * 86400);
    struct zcl_command_reply reply;
    sr_call(&input, &reply);

    SR_CHECK("the populated read passes",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SR_CHECK("releases: 1 signed envelope",
             sr_row_is(&reply, "releases_published", "recorded", true, 1));
    SR_CHECK("packages: 1 package root",
             sr_row_is(&reply, "packages_published", "recorded", true, 1));
    SR_CHECK("days observed: the backdated window",
             sr_row_is(&reply, "days_observed", "recorded", true,
                       SR_DAYS_OBSERVED));
    SR_CHECK("reproductions: 2 matching receipts",
             sr_row_is(&reply, "reproductions", "recorded", true, 2));
    SR_CHECK("signing identities: 2 distinct verifier keys",
             sr_row_is(&reply, "distinct_signing_identities", "recorded",
                       true, 2));
    SR_CHECK("dependents: 1 package declares the subject's root",
             sr_row_is(&reply, "dependent_packages", "recorded", true, 1));
    SR_CHECK("settlements: 1 simulated settlement",
             sr_row_is(&reply, "simulated_settlements", "recorded", true, 1));

    /* Every recorded row names its evidence class and window. */
    const struct json_value *rows = json_get(&reply.data, "evidence");
    bool all_labeled = rows && rows->type == JSON_ARR &&
                       rows->num_children == 9;
    for (size_t i = 0; all_labeled && i < rows->num_children; i++) {
        const struct json_value *r = &rows->children[i];
        all_labeled = sr_str(r, "evidence_class")[0] != '\0' &&
                      sr_str(r, "window")[0] != '\0' &&
                      sr_str(r, "detail")[0] != '\0';
    }
    SR_CHECK("every row carries class, window, and detail", all_labeled);

    /* The observation row says plainly that mtimes are unsigned. */
    const struct json_value *obs = sr_row(&reply, "days_observed");
    SR_CHECK("the observation window is labeled unsigned",
             obs && strstr(sr_str(obs, "evidence_class"),
                           "unsigned") != NULL &&
                 strstr(sr_str(obs, "detail"),
                        "not a signed timestamp") != NULL);
    /* The reproduction row says plainly that who built is unknown. */
    const struct json_value *rep = sr_row(&reply, "reproductions");
    SR_CHECK("the reproduction row names its limit",
             rep && strstr(sr_str(rep, "detail"),
                           "no signer identity") != NULL);

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 4. forbidden vocabulary never appears in the reply ─────────────── */
static int shop_rep_forbidden_vocabulary(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shoprep", "vocab");
    char zcode_dir[4400];
    uint8_t package_root[32], recipe_root[32];
    char publisher_hex[67];
    SR_CHECK("fixture store populated",
             sr_populate(dir, zcode_dir, package_root, recipe_root,
                         publisher_hex));

    /* Through the REAL registry, so the serialized envelope is scanned
     * too — not just the handler's data object. */
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = NULL;
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, "app.shop.reputation") == 0)
            spec = &reg->commands[i];
    SR_CHECK("the app.shop.reputation leaf is in the catalog", spec != NULL);
    if (!spec) {
        test_rm_rf(dir);
        return failures;
    }
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "publisher", publisher_hex);
    (void)json_push_kv_int(&input, "now_unix",
                           SR_BASE_UNIX + SR_DAYS_OBSERVED * 86400);
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, "normal",
                                                 0, 0, NULL, out, sizeof(out),
                                                 &code);
    json_free(&input);
    SR_CHECK("the populated reply serializes inside the reply budget",
             n > 0 && n <= ZCL_COMMAND_LIST_BUDGET &&
             strstr(out, "RESPONSE_BUDGET_EXCEEDED") == NULL);

    static const char *const forbidden[] = {
        "independen",   /* independent / independently */
        "trust",        /* trust, trustworthy, trusted */
        "score",
        "rating",
        "star",
        "reliable",
        "reputable",
    };
    bool clean = true;
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        if (strstr(out, forbidden[i]) != NULL) {
            printf("  (forbidden vocabulary present: \"%s\")\n",
                   forbidden[i]);
            clean = false;
        }
    }
    SR_CHECK("no inferred-reputation vocabulary in the reply", clean);

    struct json_value doc;
    json_init(&doc);
    if (n > 0 && json_read(&doc, out, n) && doc.type == JSON_OBJ) {
        const struct json_value *data = json_get(&doc, "data");
        SR_CHECK("the serialized reply carries the evidence rows",
                 data && json_get(data, "evidence") != NULL);
    } else {
        SR_CHECK("the serialized reply parses", false);
    }
    json_free(&doc);
    test_rm_rf(dir);
    return failures;
}

/* ── 5. input validation ────────────────────────────────────────────── */
static int shop_rep_input_validation(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shoprep", "badinput");

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    struct zcl_command_reply reply;
    sr_call(&input, &reply);
    SR_CHECK("a missing publisher is BAD_PUBLISHER_INPUT",
             reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(reply.error.code, "BAD_PUBLISHER_INPUT") == 0 &&
             reply.error.message[0] != '\0');
    zcl_command_reply_free(&reply);

    (void)json_push_kv_str(&input, "publisher", "02ab");   /* not 66-hex */
    sr_call(&input, &reply);
    SR_CHECK("a short publisher is BAD_PUBLISHER_INPUT",
             strcmp(reply.error.code, "BAD_PUBLISHER_INPUT") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

int test_shop_reputation(void)
{
    int failures = 0;
    failures += shop_rep_unknown_publisher();
    failures += shop_rep_no_store();
    failures += shop_rep_unreadable_store();
    failures += shop_rep_populated_rows();
    failures += shop_rep_forbidden_vocabulary();
    failures += shop_rep_input_validation();
    return failures;
}
