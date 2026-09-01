/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The node used to answer one blurry question ("are you ready?") when an
 * operator was really asking four different ones. These tests pin the four
 * facts apart on the chain-only `core status brief` surface, and pin the one
 * thing that makes the
 * cold-sync target reachable at all: a node that is following the network
 * tip while still missing old block bodies must say exactly that.
 *
 * Everything here drives the real `core.status.brief` leaf through the
 * registry, with the `agent` RPC answered from a fixture — no live node is
 * contacted. Root `status` composes these facts with custody readiness.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "controllers/agent_operator_contracts.h"
#include "json/json.h"
#include "controllers/rpc_client.h"

#include <string.h>

static const struct zcl_command_spec *rt_find_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static bool rt_exec_leaf(const struct zcl_command_registry *reg,
                         const struct zcl_command_spec *spec,
                         char *out, size_t out_size,
                         enum zcl_command_exit *exit_code)
{
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, "normal",
                                                 0, 0, NULL, out, out_size,
                                                 exit_code);
    json_free(&input);
    return n > 0;
}

static const char *g_rt_agent_fixture;

static char *rt_mock_rpc(const char *method, const char *params_json)
{
    (void)params_json;
    if (strcmp(method, "agent") == 0 && g_rt_agent_fixture)
        return strdup(g_rt_agent_fixture);
    return NULL;
}

/* The v3 core, minus the five readiness keys, so each case below can add
 * exactly the keys it is about. Mirrors the producer's document shape
 * (event_agent_summary.c / api_controller_status.c). */
#define RT_V3_CORE \
    "\"partial_result\":false," \
    "\"served_height\":3117073,\"header_height\":3117074," \
    "\"served_height_known\":true,\"header_height_known\":true," \
    "\"gap\":1,\"peer_best_height\":3117074," \
    "\"peer_best_height_known\":true," \
    "\"target_height\":3117074,\"target_height_known\":true," \
    "\"chain_evidence_consistent\":true," \
    "\"sync_state\":\"at_tip\",\"serving\":true," \
    "\"healthy\":true,\"primary_blocker\":\"none\"," \
    "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\"," \
        "\"budget_ms\":250,\"partial_result\":false," \
        "\"budget_exceeded\":false}," \
    "\"peers\":{\"total\":1}," \
    "\"conditions\":{\"schema\":\"zcl.condition_engine_summary.v2\"," \
        "\"active_count\":0}," \
    "\"resources\":{\"schema\":\"zcl.node_resources.v1\",\"rss_mb\":512}," \
    "\"reducer\":{\"tip_advance_age_seconds\":3}," \
    "\"security_posture\":{\"schema\":\"zcl.security_posture.v1\"," \
        "\"anchor_backfill_gap\":false," \
        "\"nullifier_backfill_gap\":false}"

static bool rt_status_data(const char *fixture, char *out, size_t out_size,
                           struct json_value *root,
                           const struct json_value **data)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = rt_find_spec(reg, "core.status.brief");
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;

    if (!s)
        return false;
    g_rt_agent_fixture = fixture;
    if (!rt_exec_leaf(reg, s, out, out_size, &code))
        return false;
    if (code != ZCL_COMMAND_EXIT_OK)
        return false;
    if (!json_read(root, out, strlen(out)) || root->type != JSON_OBJ)
        return false;
    *data = json_get(root, "data");
    return *data != NULL && (*data)->type == JSON_OBJ;
}

/* THE regression: the four facts are reported SEPARATELY, and an incomplete
 * archive coexists with tip-following.
 *
 * A complete block archive is ~13 GB while a 600-second cold sync over a
 * 100 Mbps line can move ~7.5 GB total and needs only ~242 MB of it to reach
 * the tip. So archive completeness can NEVER be a precondition for
 * tip-following readiness, or the target becomes arithmetically
 * unreachable. This test is the guard on that decoupling. */
static int test_status_readiness_four_facts_are_separate(void)
{
    int failures = 0;
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("status reports tip_follow, wallet view/spend, archive, and replay "
         "as four separate facts") {
        node_rpc_client_set_test_hook(rt_mock_rpc);

        /* Following the tip, archive NOT complete, wallet viewable but in
         * NO-SPEND mode, history not yet replay-verified. Every one of those
         * is a legitimate state of a healthy, syncing node. */
        static const char following_but_thin[] =
            "{\"schema\":\"zcl.public_status.v3\"," RT_V3_CORE ","
            "\"tip_follow\":true,"
            "\"wallet_view_ready\":true,"
            "\"wallet_spend_allowed\":false,"
            "\"archive_complete\":\"incomplete\","
            "\"full_replay_verified\":false}";

        struct json_value root;
        const struct json_value *data = NULL;
        ASSERT(rt_status_data(following_but_thin, out, sizeof(out), &root,
                              &data));

        /* Each fact is present under its own name. */
        ASSERT(json_get(data, "tip_follow") != NULL);
        ASSERT(json_get(data, "wallet_view_ready") != NULL);
        ASSERT(json_get(data, "wallet_spend_allowed") != NULL);
        ASSERT(json_get(data, "archive_complete") != NULL);
        ASSERT(json_get(data, "full_replay_verified") != NULL);

        /* THE COEXISTENCE that makes the cold-sync target reachable. */
        ASSERT(json_get_bool(json_get(data, "tip_follow")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "archive_complete")),
                      "incomplete");

        /* Wallet view and wallet spend are DISTINCT: a no-spend node is
         * viewable. If these two were ever collapsed into one bit, this
         * pair could not hold opposite values. */
        ASSERT(json_get_bool(json_get(data, "wallet_view_ready")));
        ASSERT(!json_get_bool(json_get(data, "wallet_spend_allowed")));

        /* Replay verification is its own axis too — not implied by
         * tip_follow. */
        ASSERT(!json_get_bool(json_get(data, "full_replay_verified")));

        /* And none of the above cost the node its healthy verdict: a thin
         * archive and a no-spend wallet are not faults. */
        ASSERT(json_get_bool(json_get(data, "serving")));
        ASSERT(json_get_bool(json_get(data, "healthy")));
        /* A recognized v3 document is NOT a degraded/skewed read. */
        ASSERT(json_get(data, "schema_skew") == NULL);
        json_free(&root);
        PASS();
    } _test_next:;
    g_rt_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* The four facts vary INDEPENDENTLY. Collapsing any two of them back
 * together (the mutation this test is written to catch) makes one of these
 * cases report the other's value. */
static int test_status_readiness_facts_vary_independently(void)
{
    int failures = 0;
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("each readiness fact carries its own value, in both directions") {
        node_rpc_client_set_test_hook(rt_mock_rpc);

        /* The mirror image of the case above: archive complete and history
         * replay-verified, but NOT currently following the tip, and a wallet
         * that may spend. If tip_follow were derived from archive_complete
         * (or vice versa) this document could not round-trip. */
        static const char complete_but_behind[] =
            "{\"schema\":\"zcl.public_status.v3\"," RT_V3_CORE ","
            "\"tip_follow\":false,"
            "\"wallet_view_ready\":true,"
            "\"wallet_spend_allowed\":true,"
            "\"archive_complete\":\"complete\","
            "\"full_replay_verified\":true}";

        struct json_value root;
        const struct json_value *data = NULL;
        ASSERT(rt_status_data(complete_but_behind, out, sizeof(out), &root,
                              &data));
        ASSERT(!json_get_bool(json_get(data, "tip_follow")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "archive_complete")),
                      "complete");
        ASSERT(json_get_bool(json_get(data, "wallet_spend_allowed")));
        ASSERT(json_get_bool(json_get(data, "full_replay_verified")));
        json_free(&root);

        /* archive_complete is a TRI-state and `unknown` is reachable: a node
         * that has not established coverage says so instead of guessing
         * "complete". */
        static const char archive_unknown[] =
            "{\"schema\":\"zcl.public_status.v3\"," RT_V3_CORE ","
            "\"tip_follow\":true,"
            "\"wallet_view_ready\":true,"
            "\"wallet_spend_allowed\":false,"
            "\"archive_complete\":\"unknown\","
            "\"full_replay_verified\":false}";
        ASSERT(rt_status_data(archive_unknown, out, sizeof(out), &root,
                             &data));
        ASSERT_STR_EQ(json_get_str(json_get(data, "archive_complete")),
                      "unknown");
        /* Not knowing the archive answer still does not deny tip-following. */
        ASSERT(json_get_bool(json_get(data, "tip_follow")));
        json_free(&root);

        /* A word outside the three defined values is runtime skew and is
         * dropped rather than passed through as if it were a real verdict. */
        static const char archive_bogus[] =
            "{\"schema\":\"zcl.public_status.v3\"," RT_V3_CORE ","
            "\"tip_follow\":true,\"archive_complete\":\"probably\"}";
        ASSERT(rt_status_data(archive_bogus, out, sizeof(out), &root, &data));
        ASSERT(json_get(data, "archive_complete") == NULL);
        ASSERT(json_get_bool(json_get(data, "tip_follow")));
        json_free(&root);
        PASS();
    } _test_next:;
    g_rt_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* The schema bump keeps a WORKING v2 reader: an older node's document still
 * validates strictly and still yields a complete brief. It simply carries
 * none of the five v3 keys, and those are OMITTED rather than invented. */
static int test_status_readiness_v2_reader_retained(void)
{
    int failures = 0;
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("a v2 status document still reads strictly, without the v3 facts") {
        node_rpc_client_set_test_hook(rt_mock_rpc);

        static const char v2_doc[] =
            "{\"schema\":\"zcl.public_status.v2\"," RT_V3_CORE "}";

        struct json_value root;
        const struct json_value *data = NULL;
        ASSERT(rt_status_data(v2_doc, out, sizeof(out), &root, &data));

        /* Strict read, not the degraded schema-skew path. */
        ASSERT(json_get(data, "schema_skew") == NULL);
        ASSERT(strstr(out, "missing/invalid field") == NULL);
        /* The always-present v2 core still comes through. */
        ASSERT_EQ(json_get_int(json_get(data, "hstar")), (int64_t)3117073);
        ASSERT_EQ(json_get_int(json_get(data, "gap")), (int64_t)1);
        ASSERT_STR_EQ(json_get_str(json_get(data, "sync_state")), "at_tip");
        ASSERT(json_get_bool(json_get(data, "serving")));

        /* And the v3 facts are absent — omitted, never defaulted to a
         * cheerier value. In particular archive_complete must not appear as
         * "complete" on a node that never reported it. */
        ASSERT(json_get(data, "tip_follow") == NULL);
        ASSERT(json_get(data, "wallet_view_ready") == NULL);
        ASSERT(json_get(data, "wallet_spend_allowed") == NULL);
        ASSERT(json_get(data, "archive_complete") == NULL);
        ASSERT(json_get(data, "full_replay_verified") == NULL);
        json_free(&root);
        PASS();
    } _test_next:;
    g_rt_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* The PRODUCER side of fail-closed: a never-run or failed archive census
 * leaves the facts view zeroed, and a zeroed view must emit "unknown". If
 * the tri-state were ever reordered so that 0 meant COMPLETE, a node that
 * has established nothing would start claiming a complete archive. */
static int test_status_readiness_archive_fails_closed_to_unknown(void)
{
    int failures = 0;
    TEST("an unestablished archive census emits unknown, never complete") {
        /* The names, including the out-of-range guard. */
        ASSERT_STR_EQ(status_archive_completeness_name(STATUS_ARCHIVE_UNKNOWN),
                      "unknown");
        ASSERT_STR_EQ(
            status_archive_completeness_name(STATUS_ARCHIVE_INCOMPLETE),
            "incomplete");
        ASSERT_STR_EQ(status_archive_completeness_name(STATUS_ARCHIVE_COMPLETE),
                      "complete");
        ASSERT_STR_EQ(status_archive_completeness_name(
                          (enum status_archive_completeness)99), "unknown");

        /* Zero-initialization — what a failed collect leaves behind — is
         * "unknown" and an unverified replay, not a green verdict. */
        struct status_readiness_facts_view zeroed = {0};
        ASSERT_EQ((int)zeroed.archive_complete, (int)STATUS_ARCHIVE_UNKNOWN);
        ASSERT(!zeroed.full_replay_verified);

        struct json_value doc;
        json_init(&doc);
        json_set_object(&doc);
        status_push_readiness_facts_json(&doc, &zeroed);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "archive_complete")),
                      "unknown");
        ASSERT(!json_get_bool(json_get(&doc, "full_replay_verified")));
        /* tip_follow is emitted as its own key even when false — the facts
         * are never elided into each other. */
        ASSERT(json_get(&doc, "tip_follow") != NULL);
        ASSERT(json_get(&doc, "wallet_view_ready") != NULL);
        ASSERT(json_get(&doc, "wallet_spend_allowed") != NULL);
        json_free(&doc);
        PASS();
    } _test_next:;
    return failures;
}

int test_status_readiness_truth(void)
{
    int failures = 0;
    failures += test_status_readiness_four_facts_are_separate();
    failures += test_status_readiness_facts_vary_independently();
    failures += test_status_readiness_v2_reader_retained();
    failures += test_status_readiness_archive_fails_closed_to_unknown();
    return failures;
}
