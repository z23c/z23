/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for per-node marketplace moderation: immutable visibility
 * profiles, policy-file persistence, the local-only review_state store,
 * the listing view filter (hidden_count), the SERVE gate and its
 * fail-closed matrix, the separately-defaulted RELAY leg, and the
 * signed-wire-untouched invariant. Ingest and storage are asserted
 * unaffected and nothing is ever deleted. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "controllers/file_market_controller.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "net/file_market.h"
#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"
#include "base/hex.h"
#include "json/json.h"
#include "rpc/server.h"
#include "crypto/ed25519.h"
#include "sapling/sapling.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool mmt_signed_offer(struct file_offer *offer, uint8_t root_byte,
                             uint64_t nonce, int64_t now_unix)
{
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    memset(offer, 0, sizeof(*offer));
    memset(seed, (int)(root_byte ^ 0x5a), sizeof(seed));
    memset(offer->root_hash, root_byte, sizeof(offer->root_hash));
    memset(offer->network_genesis, 0x42, sizeof(offer->network_genesis));
    ed25519_keypair(offer->seller_pubkey, secret, seed);
    snprintf(offer->filename, sizeof(offer->filename), "mmt-%02x.dat",
             root_byte);
    offer->size_bytes = FILE_MARKET_CHUNK_SIZE + 1u;
    offer->num_chunks = 2;
    offer->price_per_mb = 1200;
    for (uint8_t d = 1; ; d++) {
        memset(offer->z_addr, 0, sizeof(offer->z_addr));
        offer->z_addr[0] = d;
        if (sapling_diversifier_to_gd(&payment_key, offer->z_addr))
            break;
        if (d == UINT8_MAX)
            return false;
    }
    jub_to_bytes(offer->z_addr + 11, &payment_key);
    offer->peer_ip[15] = root_byte ? root_byte : 1;
    offer->peer_port = 18034;
    offer->ttl = FILE_MARKET_MAX_TTL;
    offer->last_seen = now_unix;
    offer->auth_version = FILE_MARKET_OFFER_VERSION;
    offer->nonce = nonce;
    offer->issued_unix = now_unix;
    offer->expires_unix = now_unix + 600;
    return file_offer_auth_seal(offer, seed) == FILE_OFFER_AUTH_OK;
}

static int mmt_offer_rows(const struct json_value *listing)
{
    const struct json_value *offers = json_get(listing, "offers");
    return offers && offers->type == JSON_ARR ? (int)offers->num_children
                                              : -1;
}

static int64_t mmt_kv_int(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static const char *mmt_kv_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool mmt_kv_bool(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static const char *mmt_row_review(const struct json_value *listing,
                                  const char *offer_id_hex)
{
    const struct json_value *offers = json_get(listing, "offers");
    if (!offers || offers->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < offers->num_children; i++) {
        const struct json_value *row = &offers->children[i];
        const struct json_value *id = json_get(row, "offer_id");
        if (id && id->type == JSON_STR &&
            strcmp(json_get_str(id), offer_id_hex) == 0) {
            const struct json_value *rs = json_get(row, "review_state");
            return rs && rs->type == JSON_STR ? json_get_str(rs) : NULL;
        }
    }
    return NULL;
}

/* ── 1. Immutable profile matrix ─────────────────────────────────── */

static int test_mmt_profile_matrix(void)
{
    int failures = 0;
    TEST("market moderation: immutable profile visibility matrix") {
        const struct market_moderation_view_service_v1 *view =
            market_moderation_view_service_builtin();
        struct market_moderation_decision_result_v1 decision;
        ASSERT(view->decide(MARKET_MODERATION_PROFILE_DEFAULT,
                            MARKET_REVIEW_UNREVIEWED, &decision));
        ASSERT(decision.valid && !decision.visible);
        ASSERT(view->decide(MARKET_MODERATION_PROFILE_DEFAULT,
                            MARKET_REVIEW_SENSITIVE, &decision));
        ASSERT(decision.valid && !decision.visible);
        ASSERT(view->decide(MARKET_MODERATION_PROFILE_DEFAULT,
                            MARKET_REVIEW_REVIEWED_OK, &decision));
        ASSERT(decision.valid && decision.visible);
        for (int s = 0; s < MARKET_REVIEW_STATE_COUNT; s++) {
            ASSERT(view->decide(MARKET_MODERATION_PROFILE_OPEN, s,
                                &decision));
            ASSERT(decision.valid && decision.visible);
        }
        ASSERT(view->decide(99, MARKET_REVIEW_REVIEWED_OK, &decision));
        ASSERT(!decision.valid && !decision.visible);
        ASSERT(view->decide(MARKET_MODERATION_PROFILE_OPEN, 99, &decision));
        ASSERT(!decision.valid && !decision.visible);

        ASSERT(market_moderation_profile_from_string(
                   "general-audience.v1") == MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(market_moderation_profile_from_string("open-view") ==
               MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(market_moderation_profile_from_string("anything-else") == -1);
        ASSERT(market_review_state_from_string("unreviewed") ==
               MARKET_REVIEW_UNREVIEWED);
        ASSERT(market_review_state_from_string("reviewed_ok") ==
               MARKET_REVIEW_REVIEWED_OK);
        ASSERT(market_review_state_from_string("sensitive") ==
               MARKET_REVIEW_SENSITIVE);
        ASSERT(market_review_state_from_string("banned") == -1);

        int resolved = -1;
        ASSERT(view->resolve_profile(NULL, MARKET_MODERATION_PROFILE_DEFAULT,
                                     &resolved));
        ASSERT(resolved == MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(view->resolve_profile("open",
                                     MARKET_MODERATION_PROFILE_DEFAULT,
                                     &resolved));
        ASSERT(resolved == MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(view->resolve_profile("open-view",
                                     MARKET_MODERATION_PROFILE_DEFAULT,
                                     &resolved));
        ASSERT(resolved == MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(view->resolve_profile("general",
                                     MARKET_MODERATION_PROFILE_OPEN,
                                     &resolved));
        ASSERT(resolved == MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!view->resolve_profile("bogus",
                                      MARKET_MODERATION_PROFILE_DEFAULT,
                                      &resolved));
        PASS();
    }
    _test_next:;
    return failures;
}

/* ── 2. Policy-file persistence across reload ────────────────────── */

static void mmt_cleanup_datadir(const char *datadir)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", datadir,
                   MARKET_MODERATION_POLICY_FILE);
    (void)unlink(path);
    (void)snprintf(path, sizeof(path), "%s/market", datadir);
    (void)rmdir(path);
    (void)rmdir(datadir);
}

static int test_mmt_profile_persistence(void)
{
    int failures = 0;
    TEST("market moderation: profile persists across policy-file reload") {
        char datadir[] = "test-tmp/market_moderation_XXXXXX";
        ASSERT(mkdtemp(datadir) != NULL);
        char error[192] = {0};
        bool ok = false;
        enum market_moderation_relay_rule relay = MARKET_MODERATION_RELAY_ALL;

        /* Absent file: the immutable boot default, no directories made. */
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(ok);
        char probe[512];
        (void)snprintf(probe, sizeof(probe), "%s/market", datadir);
        struct stat st;
        ASSERT(stat(probe, &st) != 0);

        /* Opt-in profile survives a reload. */
        ASSERT(market_moderation_profile_save(
                   datadir, MARKET_MODERATION_PROFILE_OPEN,
                   MARKET_MODERATION_RELAY_ALL).ok);
        ok = false;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(ok);
        char path[512];
        (void)snprintf(path, sizeof(path), "%s/%s", datadir,
                       MARKET_MODERATION_POLICY_FILE);
        ASSERT(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);

        /* Tamper: a hand-edit to an unknown profile is loud, never
         * silently widened — load fails and reports the default. */
        int fd = open(path, O_RDWR | O_CLOEXEC);
        ASSERT(fd >= 0);
        char byte = 0;
        ASSERT(pread(fd, &byte, 1, (off_t)(st.st_size - 3)) == 1);
        byte ^= 1;
        ASSERT(pwrite(fd, &byte, 1, (off_t)(st.st_size - 3)) == 1);
        ASSERT(close(fd) == 0);
        ok = true;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!ok);
        ASSERT(relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* Recovery: a canonical save reloads cleanly. */
        ASSERT(market_moderation_profile_save(
                   datadir, MARKET_MODERATION_PROFILE_DEFAULT,
                   MARKET_MODERATION_RELAY_ALL).ok);
        ok = false;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(ok);
        mmt_cleanup_datadir(datadir);
        PASS();
    }
    _test_next:;
    return failures;
}

/* ── 3. View filter + review marks + wire untouched ──────────────── */

static bool mmt_rpc(struct rpc_table *t, const char *method,
                    const char *params_json, struct json_value *result)
{
    json_init(result);
    struct json_value params;
    bool parsed = params_json
                      ? json_read(&params, params_json,
                                  strlen(params_json))
                      : false;
    if (params_json && !parsed)
        return false;
    bool ok = rpc_table_execute(t, method,
                                params_json ? &params : NULL, result);
    if (params_json)
        json_free(&params);
    return ok;
}

static int test_mmt_view_filter(void)
{
    int failures = 0;
    TEST("market moderation: default profile hides, open-view annotates, "
         "wire untouched") {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, ":memory:") && ndb.open);
        rpc_market_set_state(&ndb);
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_DEFAULT).ok);

        int64_t now = (int64_t)platform_time_wall_time_t();
        struct file_offer offer_a, offer_b, offer_c;
        ASSERT(mmt_signed_offer(&offer_a, 0xa1, 11, now));
        ASSERT(mmt_signed_offer(&offer_b, 0xb2, 22, now));
        ASSERT(mmt_signed_offer(&offer_c, 0xc3, 33, now));
        char id_a[65], id_b[65], id_c[65];
        zcl_hex_encode(offer_a.offer_id, 32, id_a);
        zcl_hex_encode(offer_b.offer_id, 32, id_b);
        zcl_hex_encode(offer_c.offer_id, 32, id_c);

        /* The signed wire BEFORE any local mark — the reference for the
         * wire-untouched invariant. */
        uint8_t wire_b_before[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
        size_t wire_b_len = 0;
        ASSERT(file_offer_auth_encode_into(&offer_b, wire_b_before,
                                           sizeof(wire_b_before),
                                           &wire_b_len) == FILE_OFFER_AUTH_OK);

        /* Ingest is untouched: offers enter cache AND persistence while
         * still hidden from the default listing view. */
        ASSERT(file_market_add_offer(&offer_a));
        ASSERT(file_market_add_offer(&offer_b));
        ASSERT(file_market_add_offer(&offer_c));
        ASSERT(db_file_offer_save(&ndb, &offer_a));
        ASSERT(db_file_offer_save(&ndb, &offer_b));
        ASSERT(db_file_offer_save(&ndb, &offer_c));

        struct rpc_table table;
        rpc_table_init(&table);
        register_market_rpc_commands(&table);
        set_rpc_warmup_finished();

        struct json_value listing;
        ASSERT(mmt_rpc(&table, "zmarket_list", NULL, &listing));
        ASSERT_EQ(mmt_kv_int(&listing, "offer_count"), 0);
        ASSERT_EQ(mmt_kv_int(&listing, "hidden_count"), 3);
        ASSERT_EQ(mmt_offer_rows(&listing), 0);
        const struct json_value *profile = json_get(&listing, "profile");
        ASSERT(profile && profile->type == JSON_STR &&
               strcmp(json_get_str(profile), "general-audience.v1") == 0);
        json_free(&listing);

        /* The node's own curation marks: A reviewed_ok, B sensitive.
         * Same exact two-step as the posture setters: plan mints a token
         * bound to (offer, current mark, target) and never mutates;
         * commit requires that exact token. */
        struct json_value mark;
        char params[300];
        snprintf(params, sizeof(params), "[\"%s\",\"reviewed_ok\",\"plan\"]",
                 id_a);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        /* Copy the token out before mark is freed below — the pointer
         * into the JSON value does not survive a json_free. */
        const char *token_a = mmt_kv_str(&mark, "plan_token");
        char tok_a[65];
        ASSERT(token_a && strlen(token_a) == 64 &&
               snprintf(tok_a, sizeof(tok_a), "%s", token_a) == 64);
        ASSERT(!mmt_kv_bool(&mark, "committed"));
        ASSERT(strcmp(mmt_kv_str(&mark, "status"), "planned") == 0);
        ASSERT(strcmp(mmt_kv_str(&mark, "previous_review_state"),
                      "unreviewed") == 0);
        const struct json_value *local = json_get(&mark, "local_only");
        ASSERT(local && local->type == JSON_BOOL && json_get_bool(local));
        const struct json_value *gossiped = json_get(&mark, "gossiped");
        ASSERT(gossiped && gossiped->type == JSON_BOOL &&
               !json_get_bool(gossiped));
        /* The plan changed nothing: A is still unreviewed underneath. */
        ASSERT(market_moderation_review_state_for_offer_id(offer_a.offer_id) ==
               MARKET_REVIEW_UNREVIEWED);
        json_free(&mark);

        /* Commit without the minted token is refused; so is a garbage
         * one. Neither leaves a mark behind. */
        snprintf(params, sizeof(params), "[\"%s\",\"reviewed_ok\",\"commit\"]",
                 id_a);
        ASSERT(!mmt_rpc(&table, "zmarket_review_set", params, &mark));
        json_free(&mark);
        snprintf(params, sizeof(params),
                 "[\"%s\",\"reviewed_ok\",\"commit\","
                 "\"00000000000000000000000000000000"
                 "00000000000000000000000000000000\"]", id_a);
        ASSERT(!mmt_rpc(&table, "zmarket_review_set", params, &mark));
        json_free(&mark);
        ASSERT(market_moderation_review_state_for_offer_id(offer_a.offer_id) ==
               MARKET_REVIEW_UNREVIEWED);

        /* The real commit carries the planned token. */
        snprintf(params, sizeof(params),
                 "[\"%s\",\"reviewed_ok\",\"commit\",\"%s\"]", id_a, tok_a);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        ASSERT(mmt_kv_bool(&mark, "committed"));
        ASSERT(strcmp(mmt_kv_str(&mark, "status"), "marked") == 0);
        ASSERT(strcmp(mmt_kv_str(&mark, "previous_review_state"),
                      "unreviewed") == 0);
        json_free(&mark);

        /* B sensitive: compact two-step through the same flow. */
        snprintf(params, sizeof(params), "[\"%s\",\"sensitive\",\"plan\"]",
                 id_b);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        const char *token_b = mmt_kv_str(&mark, "plan_token");
        ASSERT(token_b && strlen(token_b) == 64);
        snprintf(params, sizeof(params),
                 "[\"%s\",\"sensitive\",\"commit\",\"%s\"]", id_b, token_b);
        json_free(&mark);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        ASSERT(mmt_kv_bool(&mark, "committed"));
        json_free(&mark);

        /* Bad states are refused at plan time, before any token exists. */
        snprintf(params, sizeof(params), "[\"%s\",\"banned\",\"plan\"]", id_a);
        ASSERT(!mmt_rpc(&table, "zmarket_review_set", params, &mark));
        json_free(&mark);

        /* An id no signed offer carries: PLAN succeeds without mutating
         * (the write stays the one authority on existence — its token
         * simply commits nothing useful), COMMIT is refused by name of
         * the write. */
        char unknown_id[65];
        memset(unknown_id, 'f', 64);
        unknown_id[64] = '\0';
        snprintf(params, sizeof(params), "[\"%s\",\"sensitive\",\"plan\"]",
                 unknown_id);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        ASSERT(!mmt_kv_bool(&mark, "committed"));
        json_free(&mark);
        snprintf(params, sizeof(params),
                 "[\"%s\",\"sensitive\",\"commit\","
                 "\"11111111111111111111111111111111"
                 "11111111111111111111111111111111\"]", unknown_id);
        ASSERT(!mmt_rpc(&table, "zmarket_review_set", params, &mark));
        json_free(&mark);

        /* A mark moved between plan and commit stales the plan's token:
         * C plans reviewed_ok, an operator marks it sensitive through
         * the service directly, and the old token no longer commits. */
        snprintf(params, sizeof(params), "[\"%s\",\"reviewed_ok\",\"plan\"]",
                 id_c);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        const char *stale_token = mmt_kv_str(&mark, "plan_token");
        char tok_c_stale[65];
        ASSERT(stale_token && strlen(stale_token) == 64 &&
               snprintf(tok_c_stale, sizeof(tok_c_stale), "%s",
                        stale_token) == 64);
        json_free(&mark);
        ASSERT(market_moderation_set_review_state(
                   offer_c.offer_id, MARKET_REVIEW_SENSITIVE).ok);
        snprintf(params, sizeof(params),
                 "[\"%s\",\"reviewed_ok\",\"commit\",\"%s\"]", id_c,
                 tok_c_stale);
        ASSERT(!mmt_rpc(&table, "zmarket_review_set", params, &mark));
        json_free(&mark);
        /* ...and the fresh plan re-plans honestly from the moved mark. */
        snprintf(params, sizeof(params), "[\"%s\",\"reviewed_ok\",\"plan\"]",
                 id_c);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        const char *fresh_token = mmt_kv_str(&mark, "plan_token");
        char tok_c_fresh[65];
        ASSERT(fresh_token && strlen(fresh_token) == 64 &&
               strcmp(fresh_token, tok_c_stale) != 0 &&
               snprintf(tok_c_fresh, sizeof(tok_c_fresh), "%s",
                        fresh_token) == 64);
        ASSERT(strcmp(mmt_kv_str(&mark, "previous_review_state"),
                      "sensitive") == 0);
        snprintf(params, sizeof(params),
                 "[\"%s\",\"reviewed_ok\",\"commit\",\"%s\"]", id_c,
                 tok_c_fresh);
        json_free(&mark);
        ASSERT(mmt_rpc(&table, "zmarket_review_set", params, &mark));
        ASSERT(mmt_kv_bool(&mark, "committed"));
        json_free(&mark);

        /* Restore C so the listing/count assertions below keep their
         * fixture meaning: one mark per state — unreviewed (C),
         * reviewed_ok (A), sensitive (B). */
        ASSERT(market_moderation_set_review_state(
                   offer_c.offer_id, MARKET_REVIEW_UNREVIEWED).ok);

        /* Default view: only reviewed_ok shows; hidden_count is honest. */
        ASSERT(mmt_rpc(&table, "zmarket_list", NULL, &listing));
        ASSERT_EQ(mmt_kv_int(&listing, "offer_count"), 1);
        ASSERT_EQ(mmt_kv_int(&listing, "hidden_count"), 2);
        ASSERT_EQ(mmt_offer_rows(&listing), 1);
        const char *rs = mmt_row_review(&listing, id_a);
        ASSERT(rs && strcmp(rs, "reviewed_ok") == 0);
        json_free(&listing);

        /* Open view: everything ingested, annotated per row. */
        ASSERT(mmt_rpc(&table, "zmarket_list", "[\"open\"]", &listing));
        ASSERT_EQ(mmt_kv_int(&listing, "offer_count"), 3);
        ASSERT_EQ(mmt_kv_int(&listing, "hidden_count"), 0);
        ASSERT_EQ(mmt_offer_rows(&listing), 3);
        rs = mmt_row_review(&listing, id_a);
        ASSERT(rs && strcmp(rs, "reviewed_ok") == 0);
        rs = mmt_row_review(&listing, id_b);
        ASSERT(rs && strcmp(rs, "sensitive") == 0);
        rs = mmt_row_review(&listing, id_c);
        ASSERT(rs && strcmp(rs, "unreviewed") == 0);
        json_free(&listing);
        ASSERT(mmt_rpc(&table, "zmarket_list", "[{\"profile\":\"open-view\"}]",
                       &listing));
        ASSERT_EQ(mmt_kv_int(&listing, "offer_count"), 3);
        json_free(&listing);
        ASSERT(!mmt_rpc(&table, "zmarket_list", "[\"bogus\"]", &listing));
        json_free(&listing);

        /* Counts by review_state, service-side and RPC-side. */
        int64_t counts[MARKET_REVIEW_STATE_COUNT] = {0, 0, 0};
        ASSERT(market_moderation_review_counts(counts).ok);
        ASSERT_EQ(counts[MARKET_REVIEW_UNREVIEWED], 1);
        ASSERT_EQ(counts[MARKET_REVIEW_REVIEWED_OK], 1);
        ASSERT_EQ(counts[MARKET_REVIEW_SENSITIVE], 1);
        struct json_value status;
        ASSERT(mmt_rpc(&table, "zmarket_moderation_status", NULL, &status));
        const struct json_value *rc = json_get(&status, "review_counts");
        ASSERT(rc && rc->type == JSON_OBJ);
        ASSERT_EQ(mmt_kv_int(rc, "unreviewed"), 1);
        ASSERT_EQ(mmt_kv_int(rc, "reviewed_ok"), 1);
        ASSERT_EQ(mmt_kv_int(rc, "sensitive"), 1);
        const struct json_value *ap = json_get(&status, "active_profile");
        ASSERT(ap && ap->type == JSON_STR &&
               strcmp(json_get_str(ap), "general-audience.v1") == 0);
        json_free(&status);

        /* Ingest unaffected: every hidden offer is still stored. */
        struct file_offer refetched;
        ASSERT(db_file_offer_find(&ndb, offer_b.root_hash, &refetched));
        ASSERT(db_file_offer_find(&ndb, offer_c.root_hash, &refetched));

        /* Signed wire untouched: re-encoding the sensitive-marked offer
         * reproduces the exact pre-mark wire and still verifies. */
        uint8_t wire_b_after[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
        size_t wire_b_after_len = 0;
        ASSERT(file_offer_auth_encode_into(&offer_b, wire_b_after,
                                           sizeof(wire_b_after),
                                           &wire_b_after_len) ==
               FILE_OFFER_AUTH_OK);
        ASSERT(wire_b_after_len == wire_b_len &&
               memcmp(wire_b_before, wire_b_after, wire_b_len) == 0);
        ASSERT(file_offer_auth_verify_signature(&offer_b) ==
               FILE_OFFER_AUTH_OK);

        /* Profile set: exact plan/commit. A stale token is rejected. */
        struct json_value plan;
        ASSERT(mmt_rpc(&table, "zmarket_moderation_profile_set",
                       "[\"open-view\",\"plan\"]", &plan));
        const struct json_value *token = json_get(&plan, "plan_token");
        ASSERT(token && token->type == JSON_STR &&
               strlen(json_get_str(token)) == 64);
        const struct json_value *committed = json_get(&plan, "committed");
        ASSERT(committed && committed->type == JSON_BOOL &&
               !json_get_bool(committed));
        char commit_params[256];
        snprintf(commit_params, sizeof(commit_params),
                 "[\"open-view\",\"commit\",\"%s\"]", json_get_str(token));
        json_free(&plan);
        struct json_value commit;
        ASSERT(!mmt_rpc(&table, "zmarket_moderation_profile_set",
                        "[\"open-view\",\"commit\","
                        "\"00000000000000000000000000000000"
                        "00000000000000000000000000000000\"]",
                        &commit));
        json_free(&commit);
        ASSERT(mmt_rpc(&table, "zmarket_moderation_profile_set",
                       commit_params, &commit));
        committed = json_get(&commit, "committed");
        ASSERT(committed && committed->type == JSON_BOOL &&
               json_get_bool(committed));
        json_free(&commit);
        ASSERT(market_moderation_active_profile() ==
               MARKET_MODERATION_PROFILE_OPEN);

        /* The active profile now shows everything by default. */
        ASSERT(mmt_rpc(&table, "zmarket_list", NULL, &listing));
        ASSERT_EQ(mmt_kv_int(&listing, "offer_count"), 3);
        ASSERT_EQ(mmt_kv_int(&listing, "hidden_count"), 0);
        json_free(&listing);

        /* Back to the boot default; unreviewed/sensitive hide again. */
        ASSERT(mmt_rpc(&table, "zmarket_moderation_profile_set",
                       "[\"general-audience.v1\",\"plan\"]", &plan));
        token = json_get(&plan, "plan_token");
        snprintf(commit_params, sizeof(commit_params),
                 "[\"general-audience.v1\",\"commit\",\"%s\"]",
                 json_get_str(token));
        json_free(&plan);
        ASSERT(mmt_rpc(&table, "zmarket_moderation_profile_set",
                       commit_params, &commit));
        json_free(&commit);
        ASSERT(mmt_rpc(&table, "zmarket_list", NULL, &listing));
        ASSERT_EQ(mmt_kv_int(&listing, "offer_count"), 1);
        ASSERT_EQ(mmt_kv_int(&listing, "hidden_count"), 2);
        json_free(&listing);

        /* dumpstate dumper reflects the same posture. */
        struct json_value dump;
        json_init(&dump);
        ASSERT(market_moderation_dump_state_json(&dump, NULL));
        const struct json_value *dap = json_get(&dump, "active_profile");
        ASSERT(dap && dap->type == JSON_STR &&
               strcmp(json_get_str(dap), "general-audience.v1") == 0);
        const struct json_value *drc = json_get(&dump, "review_counts");
        ASSERT(drc && drc->type == JSON_OBJ &&
               mmt_kv_int(drc, "sensitive") == 1);
        json_free(&dump);

        node_db_close(&ndb);
        PASS();
    }
    _test_next:;
    return failures;
}

/* ── The serving gate fails closed on every failure class ──────────
 *
 * The gate decides whether this node hands content to another party. A
 * moderation system that answers "serve" on an error is worse than none,
 * because it advertises a protection it does not provide. Every class of
 * failure below is therefore asserted to answer "do not serve":
 *
 *   1. no bound node context at all (boot has not run / db closed)
 *   2. a content id the review store has never heard of
 *   3. an offer id no signed offer carries
 *   4. a NULL id
 *   5. an unreviewed mark under the boot-default profile
 *   6. a sensitive mark under the boot-default profile
 *   7. an unreadable / corrupt / foreign-owned policy file
 *   8. a profile name that is not one of the immutable named profiles
 *
 * The only inputs that answer "serve" are an explicit reviewed_ok mark,
 * or the operator's explicit open-view opt-in. */
static int test_mmt_serving_gate_fails_closed(void)
{
    int failures = 0;
    TEST("market moderation: the serving gate fails closed on every "
         "failure class") {
        uint8_t unknown_root[32], unknown_offer[32];
        memset(unknown_root, 0x77, sizeof(unknown_root));
        memset(unknown_offer, 0x88, sizeof(unknown_offer));

        /* (1) No context bound: nothing is served. Detaching the db is
         * the state a node is in before boot wires the market, and a
         * node that cannot ask its own store must not hand bytes out. */
        rpc_market_set_state(NULL);
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_DEFAULT).ok);
        ASSERT(!market_moderation_may_serve_root(unknown_root));
        ASSERT(!market_moderation_may_serve_offer_id(unknown_offer));
        /* (4) A NULL id is a refusal, never a wildcard. */
        ASSERT(!market_moderation_may_serve_root(NULL));
        ASSERT(!market_moderation_may_serve_offer_id(NULL));

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, ":memory:") && ndb.open);
        rpc_market_set_state(&ndb);
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_DEFAULT).ok);

        /* (2)(3) Ids the store has never seen read as unreviewed, which
         * the boot-default profile hides. An unknown id must never be a
         * hole in the gate. */
        ASSERT(!market_moderation_may_serve_root(unknown_root));
        ASSERT(!market_moderation_may_serve_offer_id(unknown_offer));
        ASSERT_EQ(market_moderation_review_state_for_offer_id(unknown_offer),
                  MARKET_REVIEW_UNREVIEWED);

        int64_t now = (int64_t)platform_time_wall_time_t();
        struct file_offer offer_ok, offer_sensitive, offer_new;
        ASSERT(mmt_signed_offer(&offer_ok, 0xd4, 44, now));
        ASSERT(mmt_signed_offer(&offer_sensitive, 0xe5, 55, now));
        ASSERT(mmt_signed_offer(&offer_new, 0xf6, 66, now));
        ASSERT(db_file_offer_save(&ndb, &offer_ok));
        ASSERT(db_file_offer_save(&ndb, &offer_sensitive));
        ASSERT(db_file_offer_save(&ndb, &offer_new));

        /* (5) Ingested but unreviewed: stored, and not served. */
        ASSERT(!market_moderation_may_serve_root(offer_new.root_hash));
        ASSERT(!market_moderation_may_serve_offer_id(offer_new.offer_id));

        ASSERT(market_moderation_set_review_state(
                   offer_ok.offer_id, MARKET_REVIEW_REVIEWED_OK).ok);
        ASSERT(market_moderation_set_review_state(
                   offer_sensitive.offer_id, MARKET_REVIEW_SENSITIVE).ok);

        /* The one affirmative case: an explicit sign-off by this node. */
        ASSERT(market_moderation_may_serve_root(offer_ok.root_hash));
        ASSERT(market_moderation_may_serve_offer_id(offer_ok.offer_id));
        ASSERT_EQ(market_moderation_review_state_for_offer_id(
                      offer_ok.offer_id), MARKET_REVIEW_REVIEWED_OK);

        /* (6) Marked sensitive: still stored, never served. */
        ASSERT(!market_moderation_may_serve_root(offer_sensitive.root_hash));
        ASSERT(!market_moderation_may_serve_offer_id(
                   offer_sensitive.offer_id));
        struct file_offer refetched;
        ASSERT(db_file_offer_find(&ndb, offer_sensitive.root_hash,
                                  &refetched));

        /* The operator's explicit opt-in is the ONLY thing that widens
         * the gate — and it widens it for every one of them. */
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_OPEN).ok);
        ASSERT(market_moderation_may_serve_root(offer_sensitive.root_hash));
        ASSERT(market_moderation_may_serve_root(offer_new.root_hash));
        ASSERT(market_moderation_may_serve_root(unknown_root));
        /* Even wide open, a NULL id is still a refusal. */
        ASSERT(!market_moderation_may_serve_root(NULL));
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_DEFAULT).ok);

        /* (8) A name that is not an immutable named profile never
         * resolves, so it can never become the active profile. */
        ASSERT(market_moderation_profile_from_string("open-viewer") < 0);
        ASSERT(market_moderation_profile_from_string("") < 0);
        ASSERT(market_moderation_profile_from_string(NULL) < 0);
        ASSERT(!market_moderation_profile_valid(-1));
        ASSERT(!market_moderation_profile_valid(
                   MARKET_MODERATION_PROFILE_COUNT));
        ASSERT(!market_moderation_set_active_profile(
                   (enum market_moderation_profile)99).ok);
        /* A refused set leaves the previous profile in force, not a
         * half-applied one. */
        ASSERT(market_moderation_active_profile() ==
               MARKET_MODERATION_PROFILE_DEFAULT);

        node_db_close(&ndb);
        rpc_market_set_state(NULL);
        PASS();
    }
    _test_next:;
    return failures;
}

/* (7) An unreadable, corrupt, or wrong-moded policy file must not be
 * able to widen the view. Load reports the failure AND answers the
 * boot-default profile, so a tampered file loses the operator's
 * open-view opt-in rather than silently keeping or forging one. */
static int test_mmt_policy_file_fails_closed(void)
{
    int failures = 0;
    TEST("market moderation: an unreadable policy file loses open-view "
         "and takes the strict side of BOTH legs") {
        char datadir[] = "test-tmp/market_moderation_closed_XXXXXX";
        ASSERT(mkdtemp(datadir) != NULL);
        char market_dir[640], policy[768];
        snprintf(market_dir, sizeof(market_dir), "%s/market", datadir);
        snprintf(policy, sizeof(policy), "%s/market/moderation.v1", datadir);
        (void)mkdir(market_dir, 0700);

        bool ok = false;
        char error[192];
        enum market_moderation_relay_rule relay = MARKET_MODERATION_RELAY_ALL;

        /* Absent file: the documented first-boot case — default, and it
         * is NOT an error. */
        (void)unlink(policy);
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(ok);
        /* Absent means NEVER CONFIGURED, so each leg gets its own
         * default — and the relay default is permissive. */
        ASSERT(relay == MARKET_MODERATION_RELAY_ALL);

        /* A real open-view opt-in round-trips. */
        ASSERT(market_moderation_profile_save(
                   datadir, MARKET_MODERATION_PROFILE_OPEN,
                   MARKET_MODERATION_RELAY_ALL).ok);
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(ok);

        /* Corrupt content naming a profile that does not exist: refused,
         * and the answer is the closed default rather than the last
         * good value or the forged one. */
        int fd = open(policy, O_WRONLY | O_TRUNC | O_CLOEXEC);
        ASSERT(fd >= 0);
        static const char forged[] =
            "zcl.market.moderation.v1\nprofile=serve-everything\n";
        ASSERT(write(fd, forged, sizeof(forged) - 1) ==
               (ssize_t)(sizeof(forged) - 1));
        ASSERT(close(fd) == 0);
        ok = true;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!ok && error[0]);
        /* Present but unparseable: EVERY leg takes its strict side. */
        ASSERT(relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* A world-readable file is refused on mode alone: a policy an
         * unprivileged process could rewrite is not a policy. */
        ASSERT(market_moderation_profile_save(
                   datadir, MARKET_MODERATION_PROFILE_OPEN,
                   MARKET_MODERATION_RELAY_ALL).ok);
        ASSERT(chmod(policy, 0644) == 0);
        ok = true;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!ok);
        ASSERT(relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* An empty file is not "no opinion" — it is a refusal. */
        ASSERT(chmod(policy, 0600) == 0);
        fd = open(policy, O_WRONLY | O_TRUNC | O_CLOEXEC);
        ASSERT(fd >= 0 && close(fd) == 0);
        ok = true;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!ok);
        ASSERT(relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* A missing datadir cannot be read into a permissive answer. */
        ok = true;
        ASSERT(market_moderation_profile_load(NULL, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!ok);
        ASSERT(relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        (void)unlink(policy);
        (void)rmdir(market_dir);
        (void)rmdir(datadir);
        PASS();
    }
    _test_next:;
    return failures;
}

/* ── The RELAY leg: a separate setting with the opposite default ────
 *
 * Serving hands over content; relaying forwards a pointer to somebody
 * else's. They are different acts with different failure costs, so they
 * are two settings with two defaults, and this pins both halves:
 *
 *   - relay is permissive by default, so a node that has reviewed
 *     nothing still forwards an honest seller's announcement;
 *   - the serve gate is unaffected by that, so the permissive relay
 *     default can never be mistaken for permission to hand out bytes;
 *   - neither setter moves the other leg;
 *   - once an operator has deliberately closed relay, a corrupt policy
 *     file resolves to the STRICT side rather than re-opening it. That
 *     last one is the case a serve-only matrix structurally cannot
 *     reach, because there the strict side and the default coincide. */
static int test_mmt_relay_leg_defaults_open_and_stays_closed(void)
{
    int failures = 0;
    TEST("market moderation: relay defaults open, is set separately, and "
         "a corrupt policy never re-opens an operator's closed relay") {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, ":memory:") && ndb.open);
        rpc_market_set_state(&ndb);
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_DEFAULT).ok);
        ASSERT(market_moderation_set_active_relay_rule(
                   MARKET_MODERATION_RELAY_ALL).ok);

        int64_t now = (int64_t)platform_time_wall_time_t();
        struct file_offer stranger, signed_off;
        ASSERT(mmt_signed_offer(&stranger, 0x31, 77, now));
        ASSERT(mmt_signed_offer(&signed_off, 0x42, 88, now));
        ASSERT(db_file_offer_save(&ndb, &stranger));
        ASSERT(db_file_offer_save(&ndb, &signed_off));
        ASSERT(market_moderation_set_review_state(
                   signed_off.offer_id, MARKET_REVIEW_REVIEWED_OK).ok);

        /* The default: an unreviewed stranger's offer is FORWARDED. This
         * is the whole point — gating it would shrink that seller's reach
         * to whoever has a reviewer awake. */
        ASSERT(market_moderation_active_relay_rule() ==
               MARKET_MODERATION_RELAY_ALL);
        ASSERT(market_moderation_may_relay_root(stranger.root_hash));
        ASSERT(market_moderation_may_relay_root(signed_off.root_hash));

        /* ...and the serve leg is untouched by that permissiveness. The
         * two legs disagreeing here is exactly the intended shape. */
        ASSERT(!market_moderation_may_serve_root(stranger.root_hash));
        ASSERT(market_moderation_may_serve_root(signed_off.root_hash));

        /* A malformed id is rejected as input under BOTH rules — that is
         * not the relay rule being permissive about nothing. */
        ASSERT(!market_moderation_may_relay_root(NULL));

        /* The operator's opt-in narrows relay to the same test the serve
         * leg applies, and every fail-closed class comes with it. */
        ASSERT(market_moderation_set_active_relay_rule(
                   MARKET_MODERATION_RELAY_REVIEWED_ONLY).ok);
        ASSERT(!market_moderation_may_relay_root(stranger.root_hash));
        ASSERT(market_moderation_may_relay_root(signed_off.root_hash));
        ASSERT(!market_moderation_may_relay_root(NULL));

        /* Setting one leg never moves the other, in either direction. */
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_OPEN).ok);
        ASSERT(market_moderation_active_relay_rule() ==
               MARKET_MODERATION_RELAY_REVIEWED_ONLY);
        ASSERT(market_moderation_set_active_relay_rule(
                   MARKET_MODERATION_RELAY_ALL).ok);
        ASSERT(market_moderation_active_profile() ==
               MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(market_moderation_set_active_profile(
                   MARKET_MODERATION_PROFILE_DEFAULT).ok);
        ASSERT(market_moderation_active_relay_rule() ==
               MARKET_MODERATION_RELAY_ALL);

        /* An unnameable rule is refused and leaves the active one alone. */
        ASSERT(!market_moderation_set_active_relay_rule(
                   (enum market_moderation_relay_rule)99).ok);
        ASSERT(market_moderation_active_relay_rule() ==
               MARKET_MODERATION_RELAY_ALL);
        ASSERT(market_moderation_relay_rule_from_string("relay-none") < 0);
        ASSERT(market_moderation_relay_rule_from_string("") < 0);
        ASSERT(market_moderation_relay_rule_from_string(NULL) < 0);
        ASSERT(!market_moderation_relay_rule_valid(-1));
        ASSERT(!market_moderation_relay_rule_valid(
                   MARKET_MODERATION_RELAY_RULE_COUNT));

        node_db_close(&ndb);
        rpc_market_set_state(NULL);

        /* ── The control a serve-only matrix cannot express ───────────
         * An operator deliberately closes relay. The policy file is then
         * corrupted. Reload must NOT hand relay back to its permissive
         * default: a broken file is an operator statement we cannot
         * hear, not the absence of one. */
        char datadir[] = "test-tmp/market_moderation_relay_XXXXXX";
        ASSERT(mkdtemp(datadir) != NULL);
        char market_dir[640], policy[768];
        snprintf(market_dir, sizeof(market_dir), "%s/market", datadir);
        snprintf(policy, sizeof(policy), "%s/market/moderation.v1", datadir);
        (void)mkdir(market_dir, 0700);

        bool ok = false;
        char error[192];
        enum market_moderation_relay_rule relay = MARKET_MODERATION_RELAY_ALL;

        /* Both legs round-trip independently: an operator who wants a
         * wide-open view AND a strict relay can have exactly that, and
         * the file states both rules rather than implying one. */
        ASSERT(market_moderation_profile_save(
                   datadir, MARKET_MODERATION_PROFILE_OPEN,
                   MARKET_MODERATION_RELAY_REVIEWED_ONLY).ok);
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(ok && relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* Now corrupt it. Relay must stay closed. */
        int fd = open(policy, O_WRONLY | O_TRUNC | O_CLOEXEC);
        ASSERT(fd >= 0);
        static const char forged[] =
            "zcl.market.moderation.v1\nprofile=open-view\nrelay=relay-any\n";
        ASSERT(write(fd, forged, sizeof(forged) - 1) ==
               (ssize_t)(sizeof(forged) - 1));
        ASSERT(close(fd) == 0);
        ok = true;
        relay = MARKET_MODERATION_RELAY_ALL;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(!ok);
        ASSERT(relay == MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* And the same through the live boot path, since that is where a
         * real node reads it: binding a context to the corrupt datadir
         * must leave BOTH legs strict, not just the serve one. */
        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, ":memory:") && ndb.open);
        market_moderation_set_context(&ndb, datadir);
        ASSERT(market_moderation_active_profile() ==
               MARKET_MODERATION_PROFILE_DEFAULT);
        ASSERT(market_moderation_active_relay_rule() ==
               MARKET_MODERATION_RELAY_REVIEWED_ONLY);

        /* A pre-relay policy file is legal and means relay-all.v1: it was
         * written before the relay leg existed, so it never expressed
         * strictness and must not be read as having done so. */
        fd = open(policy, O_WRONLY | O_TRUNC | O_CLOEXEC);
        ASSERT(fd >= 0);
        static const char legacy[] =
            "zcl.market.moderation.v1\nprofile=open-view\n";
        ASSERT(write(fd, legacy, sizeof(legacy) - 1) ==
               (ssize_t)(sizeof(legacy) - 1));
        ASSERT(close(fd) == 0);
        ok = false;
        relay = MARKET_MODERATION_RELAY_REVIEWED_ONLY;
        ASSERT(market_moderation_profile_load(datadir, &relay, &ok, error,
                                              sizeof(error)) ==
               MARKET_MODERATION_PROFILE_OPEN);
        ASSERT(ok && relay == MARKET_MODERATION_RELAY_ALL);

        node_db_close(&ndb);
        rpc_market_set_state(NULL);
        (void)unlink(policy);
        (void)rmdir(market_dir);
        (void)rmdir(datadir);
        PASS();
    }
    _test_next:;
    return failures;
}

int test_file_market_moderation(void)
{
    int failures = 0;
    printf("\n=== File Market Moderation Tests ===\n");
    failures += test_mmt_profile_matrix();
    failures += test_mmt_profile_persistence();
    failures += test_mmt_view_filter();
    failures += test_mmt_serving_gate_fails_closed();
    failures += test_mmt_policy_file_fails_closed();
    failures += test_mmt_relay_leg_defaults_open_and_stays_closed();
    printf("=== file_market_moderation: %d failures ===\n", failures);
    return failures;
}
