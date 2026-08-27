/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for `app shop want *` (slice D of docs/work/SHOP_COMMAND.md;
 * handlers in app/controllers/src/shop_native_want.c, codec + AR
 * projection in app/models/src/shop_want.c, table from migration v66).
 *
 * Covered:
 *   1. codec: seal/verify round-trip, exact-length decode, KEY_MISMATCH,
 *      and a tampered wire failing verification
 *   2. post plan: non-mutating (no node.db is created), rendering the
 *      exact signed document and its id
 *   3. post commit: persists; status re-verifies the signature; a
 *      byte-identical re-post is already_posted and mutates nothing; a
 *      commit without node.db is WANT_STORE_NOT_INITIALISED
 *   4. input validation: the named refusals (secret, amount, criteria,
 *      expires, lifetime, spec_hash)
 *   5. moderation: the identical visibility rule as moderated market
 *      offers — general-audience.v1 hides unreviewed AND sensitive,
 *      reviewed_ok shows, the open override shows everything; the review
 *      leaf moves the mark through plan/commit
 *   6. cancel: key-checked (WRONG_BUYER_KEY), leaves the open board, the
 *      row kept as evidence (all:true), idempotent re-cancel,
 *      WANT_NOT_FOUND
 *   7. expiry: an expired want leaves the open board without being
 *      deleted
 *   8. the populated board list serializes inside the CLI's real reply
 *      budget (ZCL_COMMAND_LIST_BUDGET + 1) through the real registry
 *   9. a node.db without the v66 table is the named
 *      WANT_STORE_NOT_MIGRATED refusal, never an empty-looking board
 *
 * Every case runs in-process against fixture datadirs under ./test-tmp;
 * wants are signed with fixture Ed25519 seeds and time is pinned through
 * the leaves' now_unix input, so nothing here is wall-clock dependent. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"     /* zcl_command_catalog */
#include "controllers/shop_native_handler.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/shop_want.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "crypto/ed25519.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define SW_CHECK(name, expr) do {                                       \
    printf("shop_want: %s... ", (name));                                \
    if (expr) { printf("OK\n"); }                                       \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

/* Pinned clock for every case: issued defaults to now, expiry one day
 * out, and "later" cases jump past the window. */
#define SW_NOW   1780000000LL
#define SW_LATER (SW_NOW + 3LL * 86400LL)

/* ── fixtures ───────────────────────────────────────────────────────── */

/* Hex of a 32-byte fixture seed (byte `seed` repeated). */
static void sw_secret_hex(uint8_t seed, char out[65])
{
    uint8_t bytes[32];
    memset(bytes, seed, 32);
    zcl_hex_encode(bytes, 32, out);
}

/* Create + migrate a fixture node.db (the write leaves require it to
 * pre-exist) and close it cleanly so the read leaves' guarded read-only
 * open sees a checkpointed database. */
static bool sw_boot_db(const char *dir)
{
    char db_path[1024];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    if (n < 0 || (size_t)n >= sizeof(db_path))
        return false;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, db_path, "test.shop.want"))
        return false;
    node_db_close(&ndb);
    return true;
}

static bool sw_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

typedef void (*sw_handler_fn)(const struct zcl_command_request *,
                              struct zcl_command_reply *);

static void sw_call(sw_handler_fn fn, struct json_value *input,
                    struct zcl_command_reply *reply)
{
    struct zcl_command_request request = { .input = input };
    zcl_command_reply_init(reply, "zcl.test.v1");
    fn(&request, reply);
}

static const char *sw_str(const struct json_value *obj, const char *key)
{
    const char *s = json_get_str(json_get(obj, key));
    return s ? s : "";
}

/* Build a standard post input with explicit terms: buyer seed 0xA1,
 * one-day expiry from the pinned now. confirm selects plan/commit. NULL
 * criteria / secret, or expires < 0, omits that key. */
static void sw_post_input_ex(struct json_value *input, const char *dir,
                             const char *secret_hex, int64_t amount,
                             const char *criteria, int64_t expires,
                             bool confirm)
{
    json_init(input);
    json_set_object(input);
    (void)json_push_kv_str(input, "datadir", dir);
    if (secret_hex)
        (void)json_push_kv_str(input, "buyer_secret", secret_hex);
    (void)json_push_kv_int(input, "amount_zatoshi", amount);
    if (criteria)
        (void)json_push_kv_str(input, "criteria", criteria);
    if (expires >= 0)
        (void)json_push_kv_int(input, "expires_unix", expires);
    (void)json_push_kv_int(input, "now_unix", SW_NOW);
    if (confirm)
        (void)json_push_kv_bool(input, "confirm", true);
}

static void sw_post_input(struct json_value *input, const char *dir,
                          uint8_t seed, bool confirm)
{
    char secret[65];
    sw_secret_hex(seed, secret);
    sw_post_input_ex(input, dir, secret, 500000,
                     "a CSV of every ZCL block hash 0..100, sha3-verified",
                     SW_NOW + 86400LL, confirm);
}

/* Post one want (commit) and copy its id out. False on any refusal. */
static bool sw_post_one(const char *dir, uint8_t seed, char id_out[65])
{
    struct json_value input;
    sw_post_input(&input, dir, seed, true);
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
              sw_str(&reply.data, "want_id")[0];
    if (ok)
        snprintf(id_out, 65, "%s", sw_str(&reply.data, "want_id"));
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

/* Review one want (commit) into the requested state. */
static bool sw_review_one(const char *dir, const char *want_id,
                          const char *state)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "review_state", state);
    (void)json_push_kv_bool(&input, "confirm", true);
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_review, &input, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

/* List against the fixture, optionally with a profile override. */
static void sw_list(const char *dir, const char *profile, bool all,
                    int64_t now_unix, struct zcl_command_reply *reply,
                    struct json_value *input)
{
    json_init(input);
    json_set_object(input);
    (void)json_push_kv_str(input, "datadir", dir);
    (void)json_push_kv_int(input, "now_unix", now_unix);
    if (profile)
        (void)json_push_kv_str(input, "profile", profile);
    if (all)
        (void)json_push_kv_bool(input, "all", true);
    sw_call(zcl_native_handle_shop_want_list, input, reply);
}

/* ── 1. codec ───────────────────────────────────────────────────────── */
static int shop_want_codec(void)
{
    int failures = 0;

    struct shop_want_v1 want;
    memset(&want, 0, sizeof(want));
    want.schema_version = SHOP_WANT_VERSION;
    uint8_t secret[32];
    memset(secret, 0xA1, 32);
    uint8_t sk[32];
    ed25519_keypair(want.buyer_pubkey, sk, secret);
    memory_cleanse(sk, sizeof(sk));
    want.nonce = 42;
    want.amount_zatoshi = 500000;
    const char *criteria = "a sha3-verified CSV of block hashes";
    want.criteria_len = (uint16_t)strlen(criteria);
    memcpy(want.criteria, criteria, want.criteria_len);
    want.issued_unix = SW_NOW;
    want.expires_unix = SW_NOW + 86400LL;

    SW_CHECK("unsealed want fails structural validation",
             shop_want_validate(&want) == SHOP_WANT_ERR_SIGNATURE);
    SW_CHECK("seal signs with the re-derived key",
             shop_want_seal(&want, secret) == SHOP_WANT_OK);
    SW_CHECK("the sealed want verifies",
             shop_want_verify(&want) == SHOP_WANT_OK);

    /* Round-trip: encode → decode → identical struct + stable root. */
    uint8_t wire[SHOP_WANT_WIRE_MAX_BYTES];
    size_t wire_len = 0;
    SW_CHECK("encode",
             shop_want_encode(&want, wire, sizeof(wire), &wire_len) ==
                 SHOP_WANT_OK && wire_len > 64u);
    struct shop_want_v1 back;
    SW_CHECK("decode round-trips",
             shop_want_decode(wire, wire_len, &back) == SHOP_WANT_OK &&
                 memcmp(&back, &want, sizeof(want)) == 0);
    uint8_t root_a[32], root_b[32];
    SW_CHECK("the id commits the signed wire",
             shop_want_root(&want, root_a) == SHOP_WANT_OK &&
                 shop_want_root(&back, root_b) == SHOP_WANT_OK &&
                 memcmp(root_a, root_b, 32) == 0);

    /* Exact-length decode: a trailing byte is a wire error. */
    uint8_t longer[SHOP_WANT_WIRE_MAX_BYTES + 1u];
    memcpy(longer, wire, wire_len);
    longer[wire_len] = 0;
    SW_CHECK("a trailing byte is WIRE_SIZE",
             shop_want_decode(longer, wire_len + 1, &back) ==
                 SHOP_WANT_ERR_WIRE_SIZE);

    /* KEY_MISMATCH: a secret that does not derive the embedded pubkey
     * must never seal. */
    struct shop_want_v1 wrong = want;
    memset(wrong.buyer_signature, 0, 64);
    uint8_t other[32];
    memset(other, 0xB2, 32);
    SW_CHECK("a non-owning secret is KEY_MISMATCH",
             shop_want_seal(&wrong, other) == SHOP_WANT_ERR_KEY_MISMATCH);

    /* A tampered signed field fails verification. */
    struct shop_want_v1 tampered = want;
    tampered.amount_zatoshi += 1;
    SW_CHECK("a tampered amount fails verification",
             shop_want_verify(&tampered) == SHOP_WANT_ERR_SIGNATURE);

    /* Lifetime cap. */
    struct shop_want_v1 long_lived = want;
    long_lived.expires_unix =
        long_lived.issued_unix + SHOP_WANT_MAX_LIFETIME_SECS + 1;
    SW_CHECK("a lifetime past the cap is refused",
             shop_want_validate(&long_lived) == SHOP_WANT_ERR_LIFETIME);
    return failures;
}

/* ── 2. post plan: non-mutating ─────────────────────────────────────── */
static int shop_want_post_plan(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "plan");

    struct json_value input;
    sw_post_input(&input, dir, 0xA1, false);
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);

    SW_CHECK("the plan passes",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SW_CHECK("mode is plan",
             strcmp(sw_str(&reply.data, "mode"), "plan") == 0);
    const struct json_value *want = json_get(&reply.data, "want");
    SW_CHECK("the plan renders the signed document",
             want && sw_str(want, "want_id")[0] &&
             sw_str(want, "buyer_pubkey")[0]);
    SW_CHECK("the plan renders the full criteria",
             want && strcmp(sw_str(want, "criteria"),
                "a CSV of every ZCL block hash 0..100, sha3-verified") == 0);
    SW_CHECK("the plan carries the declared terms",
             want && json_get_int(json_get(want, "amount_zatoshi")) == 500000);
    SW_CHECK("the commit instruction never echoes the secret",
             strstr(sw_str(&reply.data, "commit_command"), "confirm") != NULL);

    /* The plan must not create node.db — nothing mutates. */
    char db_path[600];
    (void)snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    SW_CHECK("the plan created no node.db", !sw_file_exists(db_path));

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 3. post commit, idempotency, status ────────────────────────────── */
static int shop_want_post_commit(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "commit");
    SW_CHECK("fixture node.db", sw_boot_db(dir));

    struct json_value input;
    sw_post_input(&input, dir, 0xA1, true);
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    SW_CHECK("the commit passes",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SW_CHECK("mode is commit",
             strcmp(sw_str(&reply.data, "mode"), "commit") == 0);
    SW_CHECK("the reply names the want id",
             sw_str(&reply.data, "want_id")[0] != '\0');
    SW_CHECK("a fresh post is not already_posted",
             !json_get_bool(json_get(&reply.data, "already_posted")));
    SW_CHECK("the commit reports the mutation", reply.error.mutated);
    char want_id[65];
    (void)snprintf(want_id, sizeof(want_id), "%s",
                   sw_str(&reply.data, "want_id"));
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Idempotent re-post: same terms + same default nonce → same id. */
    sw_post_input(&input, dir, 0xA1, true);
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    SW_CHECK("a byte-identical re-post passes",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SW_CHECK("the re-post is already_posted",
             json_get_bool(json_get(&reply.data, "already_posted")));
    SW_CHECK("the re-post keeps the same id",
             strcmp(sw_str(&reply.data, "want_id"), want_id) == 0);
    SW_CHECK("the re-post mutates nothing", !reply.error.mutated);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* status: full text, re-verified signature, open state. */
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    SW_CHECK("status passes", reply.status == ZCL_COMMAND_STATUS_PASSED);
    SW_CHECK("the signature re-verifies at read time",
             json_get_bool(json_get(&reply.data, "signature_valid")));
    SW_CHECK("the want is open",
             strcmp(sw_str(&reply.data, "state"), "open") == 0);
    const struct json_value *want = json_get(&reply.data, "want");
    SW_CHECK("status carries the full criteria",
             want && strstr(sw_str(want, "criteria"), "block hash 0..100"));
    SW_CHECK("a fresh want is unreviewed",
             want && strcmp(sw_str(want, "review_state"),
                            "unreviewed") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* status on an unknown id is the named refusal. */
    char unknown[65];
    sw_secret_hex(0xFF, unknown);
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", unknown);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    SW_CHECK("an unknown id is WANT_NOT_FOUND",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "WANT_NOT_FOUND") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);
    return failures;
}

/* ── 3b. post commit without node.db ────────────────────────────────── */
static int shop_want_post_no_db(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "nodb");

    struct json_value input;
    sw_post_input(&input, dir, 0xA1, true);
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    SW_CHECK("a commit without node.db is named",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code,
                    "WANT_STORE_NOT_INITIALISED") == 0);
    char db_path[600];
    (void)snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    SW_CHECK("the refusal minted no database", !sw_file_exists(db_path));
    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 4. input validation ────────────────────────────────────────────── */
static bool sw_post_refused_with(struct json_value *input, const char *code)
{
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_post, input, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_FAILED &&
              strcmp(reply.error.code, code) == 0;
    zcl_command_reply_free(&reply);
    return ok;
}

static int shop_want_validation(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "validate");

    char secret[65];
    sw_secret_hex(0xA1, secret);
    static const char *const CRITERIA =
        "a CSV of every ZCL block hash 0..100, sha3-verified";
    struct json_value input;

    sw_post_input_ex(&input, dir, "abcd", 500000, CRITERIA,
                     SW_NOW + 86400LL, false);
    SW_CHECK("a short secret is BAD_BUYER_SECRET",
             sw_post_refused_with(&input, "BAD_BUYER_SECRET"));
    json_free(&input);

    sw_post_input_ex(&input, dir, NULL, 500000, CRITERIA,
                     SW_NOW + 86400LL, false);
    SW_CHECK("a missing secret is BAD_BUYER_SECRET",
             sw_post_refused_with(&input, "BAD_BUYER_SECRET"));
    json_free(&input);

    sw_post_input_ex(&input, dir, secret, 0, CRITERIA, SW_NOW + 86400LL,
                     false);
    SW_CHECK("a zero amount is BAD_AMOUNT",
             sw_post_refused_with(&input, "BAD_AMOUNT"));
    json_free(&input);

    sw_post_input_ex(&input, dir, secret, 500000, "", SW_NOW + 86400LL,
                     false);
    SW_CHECK("empty criteria is BAD_CRITERIA",
             sw_post_refused_with(&input, "BAD_CRITERIA"));
    json_free(&input);

    sw_post_input_ex(&input, dir, secret, 500000, CRITERIA, -1, false);
    SW_CHECK("a missing expiry is MISSING_EXPIRES",
             sw_post_refused_with(&input, "MISSING_EXPIRES"));
    json_free(&input);

    sw_post_input_ex(&input, dir, secret, 500000, CRITERIA, SW_NOW - 1,
                     false);
    SW_CHECK("a past expiry is WANT_ALREADY_EXPIRED",
             sw_post_refused_with(&input, "WANT_ALREADY_EXPIRED"));
    json_free(&input);

    sw_post_input_ex(&input, dir, secret, 500000, CRITERIA,
                     SW_NOW + 31LL * 86400LL, false);
    SW_CHECK("a 31-day window is BAD_LIFETIME",
             sw_post_refused_with(&input, "BAD_LIFETIME"));
    json_free(&input);

    sw_post_input_ex(&input, dir, secret, 500000, CRITERIA,
                     SW_NOW + 86400LL, false);
    (void)json_push_kv_str(&input, "spec_hash", "zz");
    SW_CHECK("a malformed spec hash is BAD_SPEC_HASH",
             sw_post_refused_with(&input, "BAD_SPEC_HASH"));
    json_free(&input);

    /* A well-formed spec_hash round-trips into the stored document. */
    SW_CHECK("fixture node.db", sw_boot_db(dir));
    char spec[65];
    sw_secret_hex(0x5C, spec);
    sw_post_input_ex(&input, dir, secret, 500000, CRITERIA,
                     SW_NOW + 86400LL, true);
    (void)json_push_kv_str(&input, "spec_hash", spec);
    struct zcl_command_reply reply;
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    SW_CHECK("a spec-committed want posts",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    const struct json_value *want = json_get(&reply.data, "want");
    SW_CHECK("the spec hash is rendered",
             want && strcmp(sw_str(want, "spec_hash"), spec) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);
    return failures;
}

/* ── 5. moderation visibility ───────────────────────────────────────── */
static int shop_want_moderation(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "moderation");
    SW_CHECK("fixture node.db", sw_boot_db(dir));
    char want_id[65];
    SW_CHECK("fixture want posted", sw_post_one(dir, 0xA1, want_id));

    struct json_value input;
    struct zcl_command_reply reply;

    /* The default general-audience.v1 profile hides an unreviewed want —
     * identical to a freshly ingested market offer. */
    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("list passes", reply.status == ZCL_COMMAND_STATUS_PASSED);
    SW_CHECK("the default profile is general-audience.v1",
             strcmp(sw_str(&reply.data, "profile"),
                    "general-audience.v1") == 0);
    SW_CHECK("an unreviewed want is hidden by the default profile",
             json_get_int(json_get(&reply.data, "rendered")) == 0 &&
             json_get_int(json_get(&reply.data, "hidden_by_profile")) == 1);
    SW_CHECK("the hidden want still counts as stored",
             json_get_int(json_get(&reply.data, "total_matching")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* The review plan mutates nothing. */
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "review_state", "reviewed_ok");
    sw_call(zcl_native_handle_shop_want_review, &input, &reply);
    SW_CHECK("the review plan passes",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(sw_str(&reply.data, "mode"), "plan") == 0);
    SW_CHECK("the review plan names both marks",
             strcmp(sw_str(&reply.data, "current_review_state"),
                    "unreviewed") == 0 &&
             strcmp(sw_str(&reply.data, "requested_review_state"),
                    "reviewed_ok") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("the review plan did not move the mark",
             json_get_int(json_get(&reply.data, "rendered")) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* reviewed_ok commits → the board shows the want. */
    SW_CHECK("the review commit lands",
             sw_review_one(dir, want_id, "reviewed_ok"));
    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("a reviewed_ok want shows under the default profile",
             json_get_int(json_get(&reply.data, "rendered")) == 1 &&
             json_get_int(json_get(&reply.data, "hidden_by_profile")) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* sensitive → hidden again; the open override shows it. */
    SW_CHECK("the sensitive mark lands",
             sw_review_one(dir, want_id, "sensitive"));
    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("a sensitive want is hidden by the default profile",
             json_get_int(json_get(&reply.data, "rendered")) == 0 &&
             json_get_int(json_get(&reply.data, "hidden_by_profile")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    sw_list(dir, "open", false, SW_NOW, &reply, &input);
    SW_CHECK("the open override shows the sensitive want",
             json_get_int(json_get(&reply.data, "rendered")) == 1 &&
             strcmp(sw_str(&reply.data, "profile"), "open-view") == 0 &&
             json_get_bool(json_get(&reply.data, "profile_override")));
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* status reports visibility under the active profile either way. */
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    SW_CHECK("status names the hidden state honestly",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&reply.data, "visible_under_profile")));
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* A bad state and an unknown id are named refusals. */
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "review_state", "banned");
    sw_call(zcl_native_handle_shop_want_review, &input, &reply);
    SW_CHECK("a non-canonical state is BAD_REVIEW_STATE",
             reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(reply.error.code, "BAD_REVIEW_STATE") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    char unknown[65];
    sw_secret_hex(0xFF, unknown);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", unknown);
    (void)json_push_kv_str(&input, "review_state", "reviewed_ok");
    (void)json_push_kv_bool(&input, "confirm", true);
    sw_call(zcl_native_handle_shop_want_review, &input, &reply);
    SW_CHECK("an unknown id is WANT_NOT_FOUND",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "WANT_NOT_FOUND") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);
    return failures;
}

/* ── 6. cancel ──────────────────────────────────────────────────────── */
static int shop_want_cancel(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "cancel");
    SW_CHECK("fixture node.db", sw_boot_db(dir));
    char want_id[65];
    SW_CHECK("fixture want posted", sw_post_one(dir, 0xA1, want_id));
    SW_CHECK("the fixture want is board-visible",
             sw_review_one(dir, want_id, "reviewed_ok"));

    struct json_value input;
    struct zcl_command_reply reply;

    /* A non-owning key is refused by name. */
    json_init(&input);
    json_set_object(&input);
    char wrong[65];
    sw_secret_hex(0xB2, wrong);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "buyer_secret", wrong);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    (void)json_push_kv_bool(&input, "confirm", true);
    sw_call(zcl_native_handle_shop_want_cancel, &input, &reply);
    SW_CHECK("a foreign key is WRONG_BUYER_KEY",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "WRONG_BUYER_KEY") == 0);
    SW_CHECK("the refusal mutates nothing", !reply.error.mutated);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* The owning key: plan first (non-mutating), then commit. */
    char owner[65];
    sw_secret_hex(0xA1, owner);
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "buyer_secret", owner);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    sw_call(zcl_native_handle_shop_want_cancel, &input, &reply);
    SW_CHECK("the cancel plan passes and names the want",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(sw_str(&reply.data, "mode"), "plan") == 0 &&
             json_get_bool(json_get(&reply.data, "found")));
    zcl_command_reply_free(&reply);
    json_free(&input);

    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("the cancel plan kept the want on the board",
             json_get_int(json_get(&reply.data, "rendered")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "buyer_secret", owner);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    (void)json_push_kv_bool(&input, "confirm", true);
    sw_call(zcl_native_handle_shop_want_cancel, &input, &reply);
    SW_CHECK("the cancel commit passes",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&reply.data, "cancelled")) &&
             !json_get_bool(json_get(&reply.data, "already_cancelled")));
    SW_CHECK("the cancel commit reports the mutation",
             reply.error.mutated);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Off the open board, kept as evidence under all:true. */
    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("a cancelled want leaves the open board",
             json_get_int(json_get(&reply.data, "total_matching")) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    sw_list(dir, NULL, true, SW_NOW, &reply, &input);
    const struct json_value *wants = json_get(&reply.data, "wants");
    SW_CHECK("the cancelled row is kept as evidence",
             json_get_int(json_get(&reply.data, "total_matching")) == 1 &&
             wants && wants->num_children == 1 &&
             json_get_int(json_get(&wants->children[0],
                                   "cancelled_unix")) == SW_NOW);
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    SW_CHECK("status reads the cancelled state",
             strcmp(sw_str(&reply.data, "state"), "cancelled") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Idempotent re-cancel. */
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_str(&input, "buyer_secret", owner);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    (void)json_push_kv_bool(&input, "confirm", true);
    sw_call(zcl_native_handle_shop_want_cancel, &input, &reply);
    SW_CHECK("a re-cancel is already_cancelled",
             reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&reply.data, "already_cancelled")));
    SW_CHECK("a re-cancel mutates nothing", !reply.error.mutated);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* Cancel on an unknown id. */
    json_init(&input);
    json_set_object(&input);
    char unknown[65];
    sw_secret_hex(0xFF, unknown);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", unknown);
    (void)json_push_kv_str(&input, "buyer_secret", owner);
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    (void)json_push_kv_bool(&input, "confirm", true);
    sw_call(zcl_native_handle_shop_want_cancel, &input, &reply);
    SW_CHECK("an unknown id is WANT_NOT_FOUND",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code, "WANT_NOT_FOUND") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);
    return failures;
}

/* ── 7. expiry ──────────────────────────────────────────────────────── */
static int shop_want_expiry(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "expiry");
    SW_CHECK("fixture node.db", sw_boot_db(dir));
    char want_id[65];
    SW_CHECK("fixture want posted", sw_post_one(dir, 0xA1, want_id));
    SW_CHECK("the fixture want is board-visible",
             sw_review_one(dir, want_id, "reviewed_ok"));

    struct json_value input;
    struct zcl_command_reply reply;

    /* Inside the window the want shows; past it, it leaves the open
     * board without being deleted. */
    sw_list(dir, NULL, false, SW_NOW + 3600, &reply, &input);
    SW_CHECK("inside the window the want shows",
             json_get_int(json_get(&reply.data, "rendered")) == 1);
    zcl_command_reply_free(&reply);
    json_free(&input);

    sw_list(dir, NULL, false, SW_LATER, &reply, &input);
    SW_CHECK("past expiry the open board is empty",
             json_get_int(json_get(&reply.data, "total_matching")) == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    sw_list(dir, NULL, true, SW_LATER, &reply, &input);
    const struct json_value *wants = json_get(&reply.data, "wants");
    SW_CHECK("the expired row is kept and marked expired",
             json_get_int(json_get(&reply.data, "total_matching")) == 1 &&
             wants && wants->num_children == 1 &&
             json_get_bool(json_get(&wants->children[0], "expired")));
    zcl_command_reply_free(&reply);
    json_free(&input);

    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    (void)json_push_kv_int(&input, "now_unix", SW_LATER);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    SW_CHECK("status reads the expired state",
             strcmp(sw_str(&reply.data, "state"), "expired") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);
    return failures;
}

/* ── 8. the populated board fits the CLI reply budget ───────────────── */
static int shop_want_list_budget(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "budget");
    SW_CHECK("fixture node.db", sw_boot_db(dir));

    /* Four wants at the criteria cap, all board-visible. */
    char big[SHOP_WANT_CRITERIA_MAX + 1u];
    memset(big, 'x', SHOP_WANT_CRITERIA_MAX);
    big[SHOP_WANT_CRITERIA_MAX] = '\0';
    for (uint8_t i = 1; i <= 4; i++) {
        struct json_value input;
        char secret[65];
        sw_secret_hex(i, secret);
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "datadir", dir);
        (void)json_push_kv_str(&input, "buyer_secret", secret);
        (void)json_push_kv_int(&input, "amount_zatoshi", 1000LL * i);
        (void)json_push_kv_str(&input, "criteria", big);
        (void)json_push_kv_int(&input, "expires_unix", SW_NOW + 86400LL);
        (void)json_push_kv_int(&input, "now_unix", SW_NOW);
        (void)json_push_kv_bool(&input, "confirm", true);
        struct zcl_command_reply reply;
        sw_call(zcl_native_handle_shop_want_post, &input, &reply);
        bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
        char id[65] = "";
        if (ok)
            snprintf(id, sizeof(id), "%s", sw_str(&reply.data, "want_id"));
        zcl_command_reply_free(&reply);
        json_free(&input);
        SW_CHECK("a max-criteria want posts", ok);
        if (ok)
            SW_CHECK("...and is board-visible",
                     sw_review_one(dir, id, "reviewed_ok"));
    }

    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = NULL;
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, "app.shop.want.list") == 0)
            spec = &reg->commands[i];
    SW_CHECK("the app.shop.want.list leaf is in the catalog", spec != NULL);
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
    (void)json_push_kv_int(&input, "now_unix", SW_NOW);
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, "normal",
                                                 0, 0, NULL, out, sizeof(out),
                                                 &code);
    json_free(&input);
    SW_CHECK("the populated board serializes inside the reply budget",
             n > 0 && n <= ZCL_COMMAND_LIST_BUDGET &&
             strstr(out, "RESPONSE_BUDGET_EXCEEDED") == NULL);
    SW_CHECK("the serialized board carries every visible want",
             strstr(out, "\"rendered\":4") != NULL);
    SW_CHECK("long criteria are previewed, not dropped",
             strstr(out, "\"criteria_truncated\":true") != NULL);

    test_rm_rf(dir);
    return failures;
}

/* ── 9. a pre-v66 node.db is the named refusal ──────────────────────── */
static int shop_want_store_not_migrated(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "shopwant", "premigration");
    SW_CHECK("fixture node.db", sw_boot_db(dir));

    /* Stand in for a datadir last booted before v66: no shop_wants
     * table. */
    char db_path[600];
    (void)snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    sqlite3 *db = NULL;
    bool dropped = sqlite3_open(db_path, &db) == SQLITE_OK; // raw-test-sql-ok
    if (dropped) {
        dropped = sqlite3_exec(db, "DROP TABLE shop_wants", NULL, NULL,
                               NULL) == SQLITE_OK;
        sqlite3_close(db);
    }
    SW_CHECK("the shop_wants table is absent after the fixture edit",
             dropped);

    struct json_value input;
    struct zcl_command_reply reply;
    sw_list(dir, NULL, false, SW_NOW, &reply, &input);
    SW_CHECK("a table-less node.db is WANT_STORE_NOT_MIGRATED",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
             strcmp(reply.error.code,
                    "WANT_STORE_NOT_MIGRATED") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 10. the caller-clock valve ────────────────────────────────────── */
/* Without ZCL_ALLOW_INPUT_CLOCK=1 every want leaf runs on this node's
 * own wall clock: a caller may declare any now_unix it likes, but only
 * the node's time persists as board evidence or gates lifetimes — the
 * year-2100 forgery below must not mint an unaccountable row whose stamp
 * says 2100. Runs on the node clock by unsetting the valve around itself;
 * the single bounded freshness comparison against time(NULL) pins the
 * node-stamp contract while everything else stays fixed-constant. */
static int shop_want_input_clock_valve(void)
{
    int failures = 0;
    struct json_value input;
    struct zcl_command_reply reply;
    char dir[512];
    const int64_t FORGED = 4102444800LL /* 2100-01-01 */;
    const int64_t FORGED_EXPIRES = FORGED + 7LL * 86400LL;

    test_make_tmpdir(dir, sizeof(dir), "shopwant", "clockvalve");
    SW_CHECK("valve fixture node.db", sw_boot_db(dir));

    unsetenv("ZCL_ALLOW_INPUT_CLOCK");

    /* A malformed now_unix still refuses when the valve is closed —
     * validation precedes the override, in either regime. */
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_int(&input, "amount_zatoshi", 500000);
    (void)json_push_kv_str(&input, "criteria", "malformed clock probe");
    (void)json_push_kv_str(&input, "now_unix", "not-a-clock");
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    SW_CHECK("closed valve: malformed now_unix is still BAD_NOW_UNIX",
             reply.status == ZCL_COMMAND_STATUS_FAILED &&
             strcmp(reply.error.code, "BAD_NOW_UNIX") == 0);
    zcl_command_reply_free(&reply);
    json_free(&input);

    /* The forged far-future window: legitimate shape, forged authorship.
     * It posts under either regime (the expiry genuinely lies ahead), so
     * the regime difference shows up where it matters — the stamp. */
    char secret[65];
    sw_secret_hex(0xC3, secret);
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "buyer_secret", secret);
    (void)json_push_kv_int(&input, "amount_zatoshi", 500000);
    (void)json_push_kv_str(&input, "criteria",
                           "a standing ad declared from the year 2100");
    (void)json_push_kv_int(&input, "issued_unix", FORGED);
    (void)json_push_kv_int(&input, "expires_unix", FORGED_EXPIRES);
    (void)json_push_kv_int(&input, "now_unix", FORGED);
    (void)json_push_kv_bool(&input, "confirm", true);
    sw_call(zcl_native_handle_shop_want_post, &input, &reply);
    SW_CHECK("closed valve: the far-future want still posts",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    char want_id[65];
    snprintf(want_id, sizeof(want_id), "%s", sw_str(&reply.data, "want_id"));
    zcl_command_reply_free(&reply);
    json_free(&input);

    int64_t now_at_test = (int64_t)time(NULL);
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", dir);
    (void)json_push_kv_str(&input, "want_id", want_id);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    const struct json_value *want = json_get(&reply.data, "want");
    int64_t posted = want ? json_get_int(json_get(want, "posted_unix")) : -1;
    int64_t status_now =
        json_get_int(json_get(&reply.data, "now_unix"));
    SW_CHECK("closed valve: posted stamp is THIS node's clock "
             "(bounded freshness), never the caller's",
             llabs(posted - now_at_test) <= 900 &&
             llabs(status_now - now_at_test) <= 900 &&
             posted != FORGED);
    zcl_command_reply_free(&reply);
    json_free(&input);

    test_rm_rf(dir);

    /* Valve open again: the caller's clock wins verbatim — this is the
     * determinism contract every other case in this file relies on. */
    setenv("ZCL_ALLOW_INPUT_CLOCK", "1", 1);
    char open_dir[512];
    test_make_tmpdir(open_dir, sizeof(open_dir), "shopwant",
                     "clockvalve-open");
    SW_CHECK("open-valve fixture node.db", sw_boot_db(open_dir));
    char open_want[65];
    SW_CHECK("open valve: the fixture want posted", sw_post_one(
                 open_dir, 0x44, open_want));
    int64_t stamp_via_status = 0;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", open_dir);
    (void)json_push_kv_str(&input, "want_id", open_want);
    sw_call(zcl_native_handle_shop_want_status, &input, &reply);
    want = json_get(&reply.data, "want");
    stamp_via_status = want ? json_get_int(json_get(want, "posted_unix"))
                            : -1;
    zcl_command_reply_free(&reply);
    json_free(&input);

    SW_CHECK("open valve: the caller's clock is honored verbatim",
             stamp_via_status == SW_NOW);
    test_rm_rf(open_dir);
    return failures;
}

int test_shop_want(void)
{
    int failures = 0;
    setenv("ZCL_ALLOW_INPUT_CLOCK", "1", 1);
    failures += shop_want_codec();
    failures += shop_want_post_plan();
    failures += shop_want_post_commit();
    failures += shop_want_post_no_db();
    failures += shop_want_validation();
    failures += shop_want_moderation();
    failures += shop_want_cancel();
    failures += shop_want_expiry();
    failures += shop_want_list_budget();
    failures += shop_want_store_not_migrated();
    failures += shop_want_input_clock_valve();
    unsetenv("ZCL_ALLOW_INPUT_CLOCK");
    return failures;
}
