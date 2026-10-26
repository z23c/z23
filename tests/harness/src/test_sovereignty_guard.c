/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for the sovereignty guard (controllers/sovereignty_controller.h):
 * the operational-vs-sovereign trust split enforced at the mint/mining entry
 * (mining_controller.c) and the wallet-spend entry (wallet_shielded_send.c
 * rpc_z_sendmany), per docs/node/shielded-history-importer.md §5.
 *
 * Three scenarios, same shape as test_coins_kv_sovereign_gate.c:
 *   - bare (no migration stamp): G-SOV part 3's first disjunct
 *     (!proven_authority) holds regardless of self_folded — mint/spend
 *     allowed, trust_mode == "bare".
 *   - borrowed (migration stamped, no self_folded marker): the
 *     release_assisted trap — mint refused, wallet spend refused,
 *     tip-following (the dumper's tip_following_allowed) stays true,
 *     trust_mode == "release_assisted".
 *   - sovereign (self_folded marker present): mint allowed, wallet spend
 *     allowed, snapshot/bundle export allowed, trust_mode == "sovereign".
 *
 * Also covers the durable t_ready/t_sovereign transition stamps
 * (SOVEREIGNTY_T_READY_KEY / SOVEREIGNTY_T_SOVEREIGN_KEY): t_ready stamps
 * the first time the dumper/guard observe a serving-capable trust state
 * (bare already qualifies here, since ARTIFACT_VERIFIED grants
 * SERVE_VALIDATED_TIP); t_sovereign stamps only once self_derived truly
 * holds; re-evaluation never rewrites either stamp; a later posture
 * regression keeps the historical stamp. */

#include "test/test_core.h"

#include "controllers/sovereignty_controller.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_view_internal.h"
#include "controllers/zslp_controller.h"
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "rpc/server.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SG_CHECK(name, expr) do {                                           \
    if (expr) { printf("  sovereignty_guard: %s... OK\n", (name)); }         \
    else { printf("  sovereignty_guard: %s... FAIL\n", (name)); failures++; }\
} while (0)

/* Mirrors what the borrowed-seed path stamps (coins_kv_seed_from_node_db) —
 * see test_coins_kv_sovereign_gate.c's identical helper. */
static bool sg_stamp_migration(sqlite3 *db)
{
    uint8_t one = 1;
    return progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
}

static bool sg_set_applied(sqlite3 *db, int32_t h)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, h)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

static bool sg_coins_schema_ready(sqlite3 *db)
{
    return db && coins_kv_ensure_schema(db);
}

static bool sg_meta_read_absent(sqlite3 *db, const char *key,
                                uint8_t *blob, size_t cap,
                                size_t *n, bool *found)
{
    return progress_meta_get_blob_exact(db, key, blob, cap, n, found)
           && !*found;
}

static bool sg_meta_raw_full(sqlite3 *db, const char *key,
                             uint8_t *raw, size_t cap,
                             size_t *n, bool *found)
{
    return progress_meta_get_blob_exact(db, key, raw, cap, n, found)
           && *found && *n == cap;
}

static bool sg_raw_same(size_t n1, const uint8_t *raw1,
                        size_t n2, const uint8_t *raw2)
{
    return n1 == n2 && memcmp(raw1, raw2, n1) == 0;
}

static bool sg_json_str_eq(const struct json_value *v, const char *expect)
{
    return v && strcmp(json_get_str(v), expect) == 0;
}

static bool sg_gated_flag_is(const struct json_value *gated, const char *key,
                             bool expect)
{
    return gated && (json_get_bool(json_get(gated, key)) == expect);
}

static bool sg_stamp_present(const struct json_value *stamp)
{
    return stamp && !json_is_null(stamp);
}

static bool sg_stamp_epoch_is(const struct json_value *stamp, int64_t epoch)
{
    return stamp && !json_is_null(stamp) &&
           json_get_int(json_get(stamp, "epoch")) == epoch;
}

static bool sg_stamp_field_nonempty(const struct json_value *stamp,
                                    const char *field)
{
    return stamp &&
           strlen(json_get_str(json_get(stamp, field))) > 0;
}

static void sg_capture_stamp_epochs(const struct json_value *t_ready,
                                    const struct json_value *t_sovereign,
                                    int64_t *ready_epoch, int64_t *sov_epoch)
{
    if (t_ready)
        *ready_epoch = json_get_int(json_get(t_ready, "epoch"));
    if (t_sovereign)
        *sov_epoch = json_get_int(json_get(t_sovereign, "epoch"));
}

static bool sg_rpc_body_has(const struct json_value *result,
                            const char *needle)
{
    return result->type == JSON_STR &&
           strstr(json_get_str(result), needle) != NULL;
}

static bool sg_rpc_failed_without(const struct rpc_table *tbl,
                                  const char *method,
                                  const struct json_value *params,
                                  struct json_value *result,
                                  const char *needle)
{
    return !rpc_table_execute(tbl, method, params, result) &&
           result->type == JSON_STR &&
           strstr(json_get_str(result), needle) == NULL;
}

static void sg_terminate_page(uint8_t *page, size_t cap, size_t n)
{
    page[n < cap ? n : cap - 1] = '\0';
}

static bool sg_page_substrings_match(const char *page, size_t n,
                                     const char *a, bool a_present,
                                     const char *b, bool b_present)
{
    return n > 0 &&
           (strstr(page, a) != NULL) == a_present &&
           (strstr(page, b) != NULL) == b_present;
}

static bool sg_page_has_any(const char *page, size_t n,
                            const char *a, const char *b, const char *c)
{
    return n > 0 &&
           (strstr(page, a) != NULL ||
            strstr(page, b) != NULL ||
            strstr(page, c) != NULL);
}

static bool sg_export_cap_matches_gated(const struct json_value *caps,
                                        const struct json_value *gated)
{
    const struct json_value *exp_cap =
        caps ? json_get(caps, "export_bundle") : NULL;
    return exp_cap && gated &&
           json_get_bool(json_get(exp_cap, "allowed")) ==
           json_get_bool(json_get(gated, "snapshot_bundle_export_allowed"));
}

static bool sg_mine_spend_seed_agree(const struct json_value *caps)
{
    const struct json_value *mine_cap =
        caps ? json_get(caps, "mine") : NULL;
    const struct json_value *spend_cap =
        caps ? json_get(caps, "wallet_spend") : NULL;
    const struct json_value *seed_cap =
        caps ? json_get(caps, "seed_bundle") : NULL;
    return mine_cap && spend_cap && seed_cap &&
           json_get_bool(json_get(mine_cap, "allowed")) ==
               json_get_bool(json_get(spend_cap, "allowed")) &&
           json_get_bool(json_get(spend_cap, "allowed")) ==
               json_get_bool(json_get(seed_cap, "allowed"));
}

int test_sovereignty_guard(void);
int test_sovereignty_guard(void)
{
    printf("\n=== sovereignty guard (mint/spend release_assisted gate) tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "sovereignty_guard", "main");

    SG_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    SG_CHECK("db handle", db != NULL);
    SG_CHECK("coins_kv schema", sg_coins_schema_ready(db));

    /* Pin H*=50 for the whole test — a real boot only ever advances this
     * cached atomic under progress_store_tx_lock at the tip_finalize sites;
     * test_parallel forks one child process per group, so no cross-test
     * leakage, but reset at the end anyway (hygiene, matches
     * test_refold_retro_validate.c's convention). */
    reducer_frontier_provable_tip_set(50);

    struct uint256 t1;
    uint256_set_null(&t1);
    t1.data[0] = 0x51;
    t1.data[31] = 0x77;
    unsigned char sc[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    SG_CHECK("add t1.0", coins_kv_add(db, t1.data, 0, 1234, 50, true, sc,
                                      sizeof(sc)));
    SG_CHECK("seed applied_height=51 (== hstar+1)", sg_set_applied(db, 51));

    /* ── t_ready/t_sovereign start absent — no guard/dumper call has
     * happened yet, so no transition has been observed. */
    {
        uint8_t blob[8] = {0};
        size_t n = 0;
        bool found = false;
        SG_CHECK("t_ready absent before first observation",
                 sg_meta_read_absent(db, SOVEREIGNTY_T_READY_KEY,
                                     blob, sizeof(blob), &n, &found));
        SG_CHECK("t_sovereign absent before first observation",
                 sg_meta_read_absent(db, SOVEREIGNTY_T_SOVEREIGN_KEY,
                                     blob, sizeof(blob), &n, &found));
    }

    /* ── bare: applied==hstar+1, no migration stamp yet. G-SOV part 3's
     * first disjunct holds (!proven_authority), so self_derived is already
     * true here — trust_st is ARTIFACT_VERIFIED, which grants
     * SERVE_VALIDATED_TIP (stamps t_ready) and IS one of the two S states
     * (stamps t_sovereign) — both durable stamps set on this very first
     * observation. */
    int64_t ready_epoch1 = 0;
    int64_t sov_epoch1 = 0;
    {
        char reason[96] = {0};
        SG_CHECK("bare: mint allowed",
                 sovereignty_guard_allow("mint", reason, sizeof(reason)));
        SG_CHECK("bare: wallet_spend allowed",
                 sovereignty_guard_allow("wallet_spend", reason,
                                         sizeof(reason)));
    }
    {
        struct json_value out = {0};
        SG_CHECK("bare: dumper ok", sovereignty_dump_state_json(&out, NULL));
        const struct json_value *tm = json_get(&out, "trust_mode");
        SG_CHECK("bare: trust_mode == bare",
                 sg_json_str_eq(tm, "bare"));
        const struct json_value *gated = json_get(&out, "gated");
        SG_CHECK("bare: tip_following_allowed",
                 sg_gated_flag_is(gated, "tip_following_allowed", true));
        const struct json_value *t_ready = json_get(&out, "t_ready");
        const struct json_value *t_sovereign = json_get(&out, "t_sovereign");
        SG_CHECK("bare: t_ready stamped (non-null)",
                 sg_stamp_present(t_ready));
        SG_CHECK("bare: t_sovereign stamped (non-null)",
                 sg_stamp_present(t_sovereign));
        sg_capture_stamp_epochs(t_ready, t_sovereign,
                                &ready_epoch1, &sov_epoch1);
        SG_CHECK("bare: t_ready epoch > 0", ready_epoch1 > 0);
        SG_CHECK("bare: t_sovereign epoch > 0", sov_epoch1 > 0);
        SG_CHECK("bare: t_ready has a non-empty iso8601 string",
                 sg_stamp_field_nonempty(t_ready, "iso8601"));
        json_free(&out);
    }

    /* ── stamp-once: re-evaluating the SAME posture must not rewrite the
     * raw stored blob (byte-identical, not just JSON-equal — proves the
     * check-then-set path never re-issues the write once found). */
    {
        uint8_t raw1[8] = {0};
        uint8_t raw2[8] = {0};
        size_t n1 = 0;
        size_t n2 = 0;
        bool f1 = false;
        bool f2 = false;
        SG_CHECK("t_sovereign raw read #1",
                 sg_meta_raw_full(db, SOVEREIGNTY_T_SOVEREIGN_KEY,
                                  raw1, sizeof(raw1), &n1, &f1));
        char reason[96] = {0};
        sovereignty_guard_allow("mint", reason, sizeof(reason));
        sovereignty_guard_allow("wallet_spend", reason, sizeof(reason));
        struct json_value redump = {0};
        sovereignty_dump_state_json(&redump, NULL);
        json_free(&redump);
        SG_CHECK("t_sovereign raw read #2 (after re-evaluation)",
                 sg_meta_raw_full(db, SOVEREIGNTY_T_SOVEREIGN_KEY,
                                  raw2, sizeof(raw2), &n2, &f2));
        SG_CHECK("t_sovereign byte-identical across re-evaluation (never "
                 "rewritten)",
                 sg_raw_same(n1, raw1, n2, raw2));
    }

    /* ── borrowed: stamp migration (proven_authority=true), no self_folded
     * marker — the release_assisted trap this guard exists to close. */
    SG_CHECK("stamp migration", sg_stamp_migration(db));
    {
        char reason[96] = {0};
        SG_CHECK("borrowed: mint refused",
                 !sovereignty_guard_allow("mint", reason, sizeof(reason)));
        SG_CHECK("borrowed: mint reason names release_assisted",
                 strstr(reason, "release_assisted") != NULL);
        SG_CHECK("borrowed: wallet_spend refused",
                 !sovereignty_guard_allow("wallet_spend", reason,
                                          sizeof(reason)));
        SG_CHECK("borrowed: wallet_spend reason names release_assisted",
                 strstr(reason, "release_assisted") != NULL);
    }
    {
        struct json_value out = {0};
        SG_CHECK("borrowed: dumper ok", sovereignty_dump_state_json(&out, NULL));
        const struct json_value *tm = json_get(&out, "trust_mode");
        SG_CHECK("borrowed: trust_mode == release_assisted",
                 sg_json_str_eq(tm, "release_assisted"));
        const struct json_value *posture =
            json_get(&out, "authority_posture");
        SG_CHECK("borrowed: authority_posture == proven_but_not_self_folded",
                 sg_json_str_eq(posture, "proven_but_not_self_folded"));
        const struct json_value *gated = json_get(&out, "gated");
        SG_CHECK("borrowed: mint_mining_allowed == false",
                 sg_gated_flag_is(gated, "mint_mining_allowed", false));
        SG_CHECK("borrowed: wallet_spend_allowed == false",
                 sg_gated_flag_is(gated, "wallet_spend_allowed", false));
        SG_CHECK("borrowed: snapshot_bundle_export_allowed == false",
                 sg_gated_flag_is(gated, "snapshot_bundle_export_allowed",
                                  false));
        SG_CHECK("borrowed: tip_following_allowed stays true (not gated)",
                 sg_gated_flag_is(gated, "tip_following_allowed", true));

        /* Regression semantics: this posture no longer holds S (self_derived
         * is false — borrowed_stamped && !self_folded), so trust_st dropped
         * out of SOVEREIGN/ARTIFACT_VERIFIED — but t_sovereign records
         * FIRST-reached, not current, so it must survive unchanged. t_ready
         * stays stamped too (RELEASE_ASSISTED_READY still grants
         * SERVE_VALIDATED_TIP). */
        const struct json_value *t_ready = json_get(&out, "t_ready");
        const struct json_value *t_sovereign = json_get(&out, "t_sovereign");
        SG_CHECK("borrowed: t_ready still stamped, unchanged (monotonic)",
                 sg_stamp_epoch_is(t_ready, ready_epoch1));
        SG_CHECK("borrowed: t_sovereign survives the posture regression "
                 "unchanged (first-reached, not current)",
                 sg_stamp_epoch_is(t_sovereign, sov_epoch1));
        json_free(&out);
    }

    /* ── borrowed call sites: every spend entry point must refuse with the
     * same release_assisted reason. The guard fires before wallet/context/
     * param checks (z_sendmany doctrine), so no wallet fixture is needed.
     * sendtoaddress backs core.wallet.transaction.send and vault.send;
     * zslp_send stands for the three ZSLP write verbs that share
     * zslp_sovereignty_spend_guard (createtoken/send/mint). */
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_wallet_rpc_commands(&tbl);
        register_zslp_rpc_commands(&tbl);
        set_rpc_warmup_finished();
        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_init(&result);
        json_set_array(&params);
        SG_CHECK("borrowed: sendtoaddress RPC refused",
                 !rpc_table_execute(&tbl, "sendtoaddress", &params, &result));
        SG_CHECK("borrowed: sendtoaddress body names release_assisted",
                 sg_rpc_body_has(&result, "release_assisted"));
        json_free(&result);
        json_init(&result);
        SG_CHECK("borrowed: sendmany RPC refused",
                 !rpc_table_execute(&tbl, "sendmany", &params, &result));
        SG_CHECK("borrowed: sendmany body names release_assisted",
                 sg_rpc_body_has(&result, "release_assisted"));
        json_free(&result);
        json_init(&result);
        /* zslp_send's usage/arity gate runs before the sovereignty guard
         * (help must always work), so pass a well-formed (dummy) triple —
         * the guard fires before request parsing, values never read. */
        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        {
            struct json_value tid = {0}, addr = {0}, amt = {0};
            json_init(&tid);
            json_init(&addr);
            json_init(&amt);
            json_set_str(&tid, "deadbeef");
            json_set_str(&addr, "t1dummy");
            json_set_int(&amt, 1);
            json_push_back(&params, &tid);
            json_push_back(&params, &addr);
            json_push_back(&params, &amt);
        }
        SG_CHECK("borrowed: zslp_send RPC refused",
                 !rpc_table_execute(&tbl, "zslp_send", &params, &result));
        SG_CHECK("borrowed: zslp_send body names release_assisted",
                 sg_rpc_body_has(&result, "release_assisted"));
        json_free(&result);
        json_free(&params);
    }

    /* ── the web-UI send FORM. Its transparent branch calls
     * wallet_direct_sendtoaddress (guarded), but its shielded branch reaches
     * z_sendmany over wv_rpc_call — so while the tip is release_assisted the
     * same form used to refuse a t-address send and complete a zs1 one.
     * serve_send_confirm now guards ahead of the transparent/shielded split, so
     * ONE check on the shared path covers both branches: reaching the guard at
     * all is what proves the split cannot be reached ungated.
     *
     * The address must be checksum-valid or the form stops at its own
     * validation stage and the assertion would pass for the wrong reason —
     * hence the real t-address (the one test_wallet_view.c uses), and hence
     * asserting on "release_assisted" specifically rather than on any refusal.
     * Asserted on the rendered HTML the browser receives, not on an internal
     * predicate. */
    {
        static uint8_t page[262144];
        static const char body[] =
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=1.0";
        memset(page, 0, 4096);
        size_t n = serve_send_confirm(page, sizeof(page),
                                      (const uint8_t *)body, strlen(body));
        sg_terminate_page(page, sizeof(page), n);
        SG_CHECK("borrowed: web-UI send form refuses, naming release_assisted",
                 sg_page_substrings_match((const char *)page, n,
                                          "release_assisted", true,
                                          "Spend Refused", true));
        /* And it never reached the send path. */
        SG_CHECK("borrowed: web-UI send form never reached the send path",
                 sg_page_substrings_match((const char *)page, n,
                                          "Node Offline", false,
                                          "Send Failed", false));
    }

    /* ── sovereign: stamp self_folded — everything unlocks. */
    SG_CHECK("mark_self_folded", coins_kv_mark_self_folded(db));
    {
        char reason[96] = {0};
        SG_CHECK("sovereign: mint allowed",
                 sovereignty_guard_allow("mint", reason, sizeof(reason)));
        SG_CHECK("sovereign: wallet_spend allowed",
                 sovereignty_guard_allow("wallet_spend", reason,
                                         sizeof(reason)));
    }
    {
        struct json_value out = {0};
        SG_CHECK("sovereign: dumper ok",
                 sovereignty_dump_state_json(&out, NULL));
        const struct json_value *tm = json_get(&out, "trust_mode");
        SG_CHECK("sovereign: trust_mode == sovereign",
                 sg_json_str_eq(tm, "sovereign"));
        const struct json_value *gated = json_get(&out, "gated");
        SG_CHECK("sovereign: mint_mining_allowed == true",
                 sg_gated_flag_is(gated, "mint_mining_allowed", true));
        SG_CHECK("sovereign: wallet_spend_allowed == true",
                 sg_gated_flag_is(gated, "wallet_spend_allowed", true));
        SG_CHECK("sovereign: snapshot_bundle_export_allowed == true",
                 sg_gated_flag_is(gated, "snapshot_bundle_export_allowed",
                                  true));

        /* v2 schema + central trust→capability table view. Assert only the
         * hstar-INDEPENDENT invariants: the dumper's self_derived (part 2) needs
         * a compute_hstar this unit fixture does not seed, so trust_state and
         * the S-gated caps (mine/spend/seed) are not deterministic here — but:
         *   • schema is v2;
         *   • export_bundle.allowed == gated.snapshot_bundle_export_allowed
         *     (both are X = proven && self_folded, independent of hstar);
         *   • mine.allowed == wallet_spend.allowed == seed_bundle.allowed
         *     (all three are exactly S, so equal whatever S resolves to);
         *   • t_ready / t_sovereign carry the SAME epoch stamped back in the
         *     "bare" block — never rewritten, regardless of what this call's
         *     own (possibly hstar-nondeterministic) trust_st resolves to. */
        const struct json_value *schema = json_get(&out, "schema");
        SG_CHECK("sovereign: schema == zcl.sovereignty.v2",
                 sg_json_str_eq(schema, "zcl.sovereignty.v2"));
        const struct json_value *caps = json_get(&out, "capabilities");
        SG_CHECK("sovereign: capabilities.export_bundle.allowed == "
                 "gated.snapshot_bundle_export_allowed",
                 sg_export_cap_matches_gated(caps, gated));
        SG_CHECK("sovereign: mine/spend/seed caps all agree (== S)",
                 sg_mine_spend_seed_agree(caps));
        const struct json_value *t_ready = json_get(&out, "t_ready");
        const struct json_value *t_sovereign = json_get(&out, "t_sovereign");
        SG_CHECK("sovereign: t_ready epoch unchanged since bare (monotonic)",
                 sg_stamp_epoch_is(t_ready, ready_epoch1));
        SG_CHECK("sovereign: t_sovereign epoch unchanged since bare (never "
                 "rewritten, even back inside SOVEREIGN again)",
                 sg_stamp_epoch_is(t_sovereign, sov_epoch1));
        json_free(&out);
    }

    /* ── sovereign call sites: the guard no longer refuses — each RPC fails
     * later (params/context/wallet), never with release_assisted. Proves the
     * new call-site guards open again after self_folded. */
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_wallet_rpc_commands(&tbl);
        register_zslp_rpc_commands(&tbl);
        struct json_value params = {0};
        struct json_value result = {0};
        json_init(&params);
        json_init(&result);
        json_set_array(&params);
        SG_CHECK("sovereign: sendtoaddress failure is NOT release_assisted",
                 sg_rpc_failed_without(&tbl, "sendtoaddress", &params, &result,
                                       "release_assisted"));
        json_free(&result);
        json_init(&result);
        /* Same well-formed dummy triple as the borrowed block — gets past
         * the usage/arity gate so the (now-open) sovereignty guard and the
         * context check decide the outcome. */
        json_free(&params);
        json_init(&params);
        json_set_array(&params);
        {
            struct json_value tid = {0}, addr = {0}, amt = {0};
            json_init(&tid);
            json_init(&addr);
            json_init(&amt);
            json_set_str(&tid, "deadbeef");
            json_set_str(&addr, "t1dummy");
            json_set_int(&amt, 1);
            json_push_back(&params, &tid);
            json_push_back(&params, &addr);
            json_push_back(&params, &amt);
        }
        SG_CHECK("sovereign: zslp_send failure is NOT release_assisted",
                 sg_rpc_failed_without(&tbl, "zslp_send", &params, &result,
                                       "release_assisted"));
        json_free(&result);
        json_free(&params);
    }

    /* ── the web-UI send form opens again too, and degrades to the node being
     * absent rather than to a refusal. This is the assertion
     * test_wallet_view.c cannot make (that file runs with no datadir, so it has
     * no progress store and the guard correctly fails closed there); the
     * sovereign fixture here is the only place the offline path is reachable. */
    {
        static uint8_t page[262144];
        static const char body[] =
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01";
        memset(page, 0, 4096);
        size_t n = serve_send_confirm(page, sizeof(page),
                                      (const uint8_t *)body, strlen(body));
        sg_terminate_page(page, sizeof(page), n);
        SG_CHECK("sovereign: web-UI send form is no longer refused",
                 sg_page_substrings_match((const char *)page, n,
                                          "Spend Refused", false,
                                          "release_assisted", false));
        SG_CHECK("sovereign: web-UI send form degrades to node-absent",
                 sg_page_has_any((const char *)page, n,
                                 "Node Offline", "Send Failed",
                                 "Unknown Response"));
    }

    /* ── NULL-input hardening. */
    SG_CHECK("dump_state_json(NULL) -> false",
             !sovereignty_dump_state_json(NULL, NULL));

    reducer_frontier_provable_tip_reset();
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
