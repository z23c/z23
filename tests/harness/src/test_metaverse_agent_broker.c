/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The confined-agent boundary (session/agent_broker.h), tested adversarially.
 *
 * The claim under test is NOT "our code chooses not to read the wallet". It is
 * "a hostile confined process CANNOT read it", and "a process that is not the
 * agent CANNOT be answered as if it were". So the reachability assertions run a
 * real spawned child that deliberately tries, and they require the kernel's
 * EACCES — never ENOENT, which would prove only that a file happened to be
 * missing.
 *
 * Coverage:
 *   (a) wire codec: round-trip, and every malformed frame rejected
 *   (b) grant evaluator: one assertion per refusal reason
 *   (c) audit log: hash-chained + signed, and each way of tampering detected
 *   (d) SO_PEERCRED, as a predicate: an expectation that constrains nothing
 *       fails closed, and a self-asserted uid changes nothing. Plus the trap
 *       the option carries — on a socketpair it names the socket's CREATOR, so
 *       a broker trusting it would be verifying itself; the broker identifies
 *       the peer from the kernel's per-message credentials instead.
 *   (e) SO_PEERCRED, END TO END over a real listening socket: a live local
 *       process that is not the expected agent is refused — once on uid, once
 *       on pid — before a single verb is dispatched, even though the request it
 *       sent was well-formed and inside the grant. The same request from the
 *       expected peer is then served, so the refusal is discriminating rather
 *       than blanket.
 *   (f) a REAL confined child: Landlock denies /etc/passwd, /etc/shadow, /root
 *       and /home with EACCES, and denies the BROKER's own directory — the
 *       audit key and an operator secret sitting one directory away
 *   (g) the grant is absent from the child's /proc/<pid>/environ and
 *       /proc/<pid>/cmdline, read from the PARENT while the child is alive
 *   (h) the broker refuses an out-of-scope property and a disallowed action
 *       even though the wire happily carried both
 *   (i) idempotency: a replayed request_id mints no second receipt
 *
 * Every destructive confinement assertion happens in the SPAWNED child, so the
 * test-group process is never confined and later assertions still run.
 */

#define _GNU_SOURCE

#include "test/test_core.h"
#include "platform/socket_compat.h"

#include "controllers/rpc_client.h"
#include "platform/os_proc.h"
#include "platform/clock.h"
#include "platform/os_sandbox.h"
#include "platform/time_compat.h"
#include "services/metaverse_agent_service.h"
#include "session/agent_broker.h"
#include "session/agent_broker_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#define MB_CHECK(name, expr) do { \
    printf("agent_broker: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static char g_dir[256];
static bool g_money_unavailable;
static bool g_money_duplicate;
static _Atomic long g_money_connect_ms;
static _Atomic long g_money_total_ms;
static _Atomic int g_money_rpc_active;
static _Atomic int g_money_rpc_max_active;
static _Atomic int g_money_rpc_delay_ms;
static bool g_liquidity_params_ok;

/* The grant id the demo grant carries. The child must never see this string —
 * (g) greps for exactly it. */
#define MB_GRANT_ID "lane3-demo-grant"

/* What the operator keeps in the broker's own directory, next to the audit key.
 * The confined agent is told to try to open it; the kernel must refuse. */
#define MB_SECRET_LEAF "operator-secret.txt"

static int64_t mb_now_ms(void) { return 1800000000000LL; }

static void mb_subdir(char *out, size_t cap, const char *leaf)
{
    snprintf(out, cap, "%s/%s", g_dir, leaf);
    (void)mkdir(out, 0700);
}

static void mb_money_liquidity_reply(char *out, const char *params, bool dev,
                                     const char *id)
{
    g_liquidity_params_ok =
        strstr(params, "\"recipient_value_zat\":1000") &&
        strstr(params, "\"maximum_fee_zat\":10000") &&
        strstr(params, "\"concurrency\":10");
    (void)snprintf(out, 4096,
        "{\"ok\":true,\"schema\":\"zcl.wallet_liquidity.v1\","
        "\"wallet_scope\":\"%s\",\"wallet_instance_id\":\"%s\","
        "\"network_genesis\":\"%064x\",\"money_status\":\"CURRENT\","
        "\"money_reason\":\"fixture\",\"money_snapshot_root\":\"%064x\","
        "\"observed_at\":%lld,\"status\":\"NEEDS_FANOUT\","
        "\"reason\":\"fixture fanout\",\"amounts_known\":true,"
        "\"requested_concurrency\":10,\"current_independent_slots\":1,"
        "\"current_inputs_used\":1,\"recipient_value_zat\":1000,"
        "\"maximum_fee_zat\":10000,\"required_per_slot_zat\":11000,"
        "\"future_total_required_zat\":110000,"
        "\"transparent_available_zat\":5000000,"
        "\"agent_available_zat\":5000000,\"ready_now\":false,"
        "\"fanout_recommended\":true,\"fanout_possible\":true,"
        "\"advisory\":true,\"next_command\":\"vault.intent.fanout-plan\","
        "\"fanout\":{\"automatic\":false,\"output_count\":10,"
        "\"output_value_zat\":11000,\"outputs_total_zat\":110000,"
        "\"maximum_fee_zat\":10000,\"maximum_slots_under_policy\":50,"
        "\"prepare_command\":\"vault.intent.fanout-plan\","
        "\"plan_command\":\"vault.intent.fanout-plan\","
        "\"commit_command\":\"vault.intent.commit\","
        "\"route\":\"transparent\",\"owner_commit_required\":true},"
        "\"node_datadir\":\"/secret/leak\",\"address\":\"t1-secret\"}",
        dev ? "dev" : "prod", id, 0x42, 0x77,
        (long long)platform_time_wall_time_t());
}

static void mb_money_portfolio_reply(char *out, bool dev, const char *id,
                                     int64_t confirmed, int64_t available)
{
    (void)snprintf(out, 4096,
        "{\"snapshot\":{\"wallet_scope\":\"%s\","
        "\"wallet_instance_id\":\"%s\","
        "\"network_genesis\":\"%064x\",\"status\":\"CURRENT\","
        "\"complete\":true,\"reason\":\"fixture\","
        "\"confirmed_zcl\":\"%s\",\"pending_zcl\":\"0.00000000\","
        "\"encumbered_zcl\":\"0.00000000\","
        "\"intent_reserved_zcl\":\"0.00000000\","
        "\"agent_available_zcl\":\"%s\",\"confirmed_zat\":%lld,"
        "\"pending_zat\":0,\"encumbered_zat\":0,"
        "\"intent_reserved_zat\":0,\"agent_available_zat\":%lld,"
        "\"tip_height\":3200000,\"tip_hash\":\"%064x\","
        "\"observed_at\":%lld,\"snapshot_root\":\"%064x\"}}",
        dev ? "dev" : "prod", id, 0x42,
        dev ? "0.30000000" : "0.00000000",
        dev ? "0.05000000" : "0.00000000",
        (long long)confirmed, (long long)available, 0x55,
        (long long)platform_time_wall_time_t(), dev ? 0x61 : 0x62);
}

static char *mb_money_rpc(const char *method, const char *params)
{
    if (g_money_unavailable || strcmp(method, "agentsession") != 0)
        return NULL;
    const bool dev = params && strstr(params, "\"dev\"") != NULL;
    const char *id = dev || g_money_duplicate
        ? "11111111111111111111111111111111"
        : "22222222222222222222222222222222";
    const int64_t confirmed = dev ? 30000000 : 0;
    const int64_t available = dev ? 5000000 : 0;
    char *out = malloc(4096);
    if (!out)
        return NULL;
    if (params && strstr(params, "\"liquidity\"") != NULL) {
        mb_money_liquidity_reply(out, params, dev, id);
        return out;
    }
    mb_money_portfolio_reply(out, dev, id, confirmed, available);
    return out;
}

static char *mb_money_transport(const char *datadir, int rpc_port,
                                const char *method, const char *params,
                                long connect_ms, long total_ms)
{
    (void)datadir;
    (void)rpc_port;
    atomic_store(&g_money_connect_ms, connect_ms);
    atomic_store(&g_money_total_ms, total_ms);
    int active = atomic_fetch_add(&g_money_rpc_active, 1) + 1;
    int seen = atomic_load(&g_money_rpc_max_active);
    while (active > seen &&
           !atomic_compare_exchange_weak(&g_money_rpc_max_active,
                                         &seen, active)) {}
    int delay_ms = atomic_load(&g_money_rpc_delay_ms);
    if (delay_ms > 0)
        platform_sleep_ms(delay_ms);
    char *reply = node_rpc_call_deadline(method, params, connect_ms, total_ms);
    (void)atomic_fetch_sub(&g_money_rpc_active, 1);
    return reply;
}

static bool mb_money_dev_prod_ok(bool ok, size_t n, const char *doc)
{
    return ok && n > 0 &&
           strstr(doc, "\"portfolio_confirmed_zcl\":\"0.30000000\"") &&
           strstr(doc, "\"wallet_scope\":\"dev\"") &&
           strstr(doc, "\"confirmed_zcl\":\"0.30000000\"") &&
           strstr(doc, "\"wallet_scope\":\"prod\"") &&
           strstr(doc, "\"confirmed_zcl\":\"0.00000000\"") &&
           !strstr(doc, "/secret/") && !strstr(doc, "rpc_port");
}

static bool mb_money_deadline_ok(void)
{
    return atomic_load(&g_money_connect_ms) == 500 &&
           atomic_load(&g_money_total_ms) == 30000;
}

static bool mb_money_liquidity_plan_ok(bool ok, const char *doc)
{
    return ok && g_liquidity_params_ok &&
           strstr(doc, "\"schema\":\"zcl.metaverse_agent_liquidity.v1\"") &&
           strstr(doc, "\"status\":\"NEEDS_FANOUT\"") &&
           strstr(doc, "\"current_independent_slots\":1") &&
           strstr(doc, "\"output_count\":10") &&
           strstr(doc, "\"automatic_rebalance\":false");
}

static bool mb_money_liquidity_stripped(const char *doc)
{
    return !strstr(doc, "/secret/") && !strstr(doc, "t1-secret") &&
           !strstr(doc, "node_datadir") && !strstr(doc, "rpc_port") &&
           !strstr(doc, "outpoint");
}

static bool mb_money_conflict_ok(bool ok, const char *doc, const char *field)
{
    return ok && strstr(doc, "CONFLICTED") &&
           strstr(doc, "duplicate wallet_instance_id") &&
           strstr(doc, field);
}

static bool mb_money_unknown_ok(bool ok, const char *doc, const char *reason,
                                const char *zero)
{
    return ok && strstr(doc, "UNKNOWN") && strstr(doc, reason) &&
           !strstr(doc, zero);
}

static int mb_money_portfolio(void)
{
    int failures = 0;
    char dir[320], path[400], absolute[PATH_MAX];
    mb_subdir(dir, sizeof(dir), "money");
    MB_CHECK("custody broker directory resolves absolutely",
             realpath(dir, absolute) != NULL);
    snprintf(path, sizeof(path), "%s/money-bindings.json", dir);
    FILE *f = fopen(path, "we");
    MB_CHECK("private custody binding fixture opens", f != NULL);
    if (!f)
        return failures;
    (void)fprintf(f,
        "{\"schema\":\"zcl.agent_money_bindings.v1\",\"wallets\":["
        "{\"scope\":\"dev\",\"wallet_instance_id\":"
        "\"11111111111111111111111111111111\",\"network_genesis\":"
        "\"%064x\",\"node_datadir\":\"/secret/dev-wallet\",\"rpc_port\":1},"
        "{\"scope\":\"prod\",\"wallet_instance_id\":"
        "\"22222222222222222222222222222222\",\"network_genesis\":"
        "\"%064x\",\"node_datadir\":\"/secret/prod-wallet\",\"rpc_port\":2}]}",
        0x42, 0x42);
    (void)fclose(f);
    node_rpc_client_set_test_hook(mb_money_rpc);
    atomic_store(&g_money_rpc_max_active, 0);
    atomic_store(&g_money_rpc_delay_ms, 25);
    char doc[16384]; size_t n = 0;
    struct zcl_result r = metaverse_agent_service_money(
        absolute, mb_money_transport, doc, sizeof(doc), &n);
    atomic_store(&g_money_rpc_delay_ms, 0);
    MB_CHECK("dev 0.3 and prod zero remain identified, not conflated",
             mb_money_dev_prod_ok(r.ok, n, doc));
    MB_CHECK("custody reader keeps a bounded contention-tolerant deadline",
             mb_money_deadline_ok());
    MB_CHECK("dev and prod custody authorities are read concurrently",
             atomic_load(&g_money_rpc_max_active) == 2);

    r = metaverse_agent_service_liquidity(
        absolute, "dev", 1000, 10000, 10, mb_money_transport,
        doc, sizeof(doc), &n);
    MB_CHECK("liquidity planner binds exact request and returns aggregate fanout",
             mb_money_liquidity_plan_ok(r.ok, doc));
    MB_CHECK("liquidity output strips endpoint, datadir, address, and outpoint fields",
             mb_money_liquidity_stripped(doc));

    g_money_duplicate = true;
    r = metaverse_agent_service_money(
        absolute, mb_money_transport, doc, sizeof(doc), &n);
    MB_CHECK("a copied wallet id across endpoints is CONFLICTED, never zero",
             mb_money_conflict_ok(r.ok, doc, "\"portfolio_total_known\":false"));
    r = metaverse_agent_service_liquidity(
        absolute, "dev", 1000, 10000, 10, mb_money_transport,
        doc, sizeof(doc), &n);
    MB_CHECK("liquidity also refuses duplicate active wallet identities",
             mb_money_conflict_ok(r.ok, doc, "\"amounts_known\":false"));
    g_money_duplicate = false;
    g_money_unavailable = true;
    r = metaverse_agent_service_money(
        absolute, mb_money_transport, doc, sizeof(doc), &n);
    MB_CHECK("unreachable wallet readers report UNKNOWN, never numeric zero",
             mb_money_unknown_ok(r.ok, doc,
                                 "bound wallet endpoint is unreachable",
                                 "\"confirmed_zat\":0"));
    r = metaverse_agent_service_liquidity(
        absolute, "dev", 1000, 10000, 10, mb_money_transport,
        doc, sizeof(doc), &n);
    MB_CHECK("unreachable liquidity reader is UNKNOWN and never a zero plan",
             mb_money_unknown_ok(r.ok, doc, "\"amounts_known\":false",
                                 "\"future_total_required_zat\":0"));
    g_money_unavailable = false;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* ── (a) the wire codec ─────────────────────────────────────────────────── */

/* mvap_request_encode() writes a 4-byte frame prefix and mvap_request_decode()
 * takes the record WITHOUT it — the caller frames. Everything below therefore
 * decodes from `+ MVAP_FRAME_PREFIX`, and the byte offsets the tamper cases
 * poke are record-relative for the same reason. */
static int mb_codec(void)
{
    int failures = 0;
    struct mvap_request in, out;
    memset(&in, 0, sizeof(in));
    in.verb = MVAP_VERB_HOST;
    in.request_id = 77;
    in.value_zats = 123456789ULL;
    in.kind = MVAP_KIND_CONTENT;
    agent_broker_fixture_property_id(0, in.property_id);
    snprintf(in.param, sizeof(in.param), "some-safe-token.v1");

    uint8_t buf[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t n = mvap_request_encode(&in, buf, sizeof(buf));
    MB_CHECK("request encodes", n > MVAP_FRAME_PREFIX && n <= sizeof(buf));

    uint8_t *rec = buf + MVAP_FRAME_PREFIX;
    size_t rec_len = n > MVAP_FRAME_PREFIX ? n - MVAP_FRAME_PREFIX : 0;

    MB_CHECK("the frame prefix declares the record length",
             rec_len > 0 && mvap_frame_length(buf, n) == (uint32_t)rec_len);
    MB_CHECK("request round-trips",
             rec_len > 0 && mvap_request_decode(rec, rec_len, &out) &&
             out.verb == in.verb && out.request_id == in.request_id &&
             out.value_zats == in.value_zats && out.kind == in.kind &&
             memcmp(out.property_id, in.property_id, sizeof(in.property_id)) == 0 &&
             strcmp(out.param, in.param) == 0);

    if (rec_len > 0) {
        uint8_t bad[MVAP_MAX_FRAME];
        memcpy(bad, rec, rec_len);
        bad[0] ^= 0xFFu;                       /* magic */
        MB_CHECK("wrong magic rejected", !mvap_request_decode(bad, rec_len, &out));
        memcpy(bad, rec, rec_len);
        bad[4] = 0xFEu; bad[5] = 0xFFu;        /* version */
        MB_CHECK("wrong version rejected", !mvap_request_decode(bad, rec_len, &out));
        memcpy(bad, rec, rec_len);
        bad[6] = 0xFFu; bad[7] = 0xFFu;        /* verb */
        MB_CHECK("out-of-range verb rejected", !mvap_request_decode(bad, rec_len, &out));
        memcpy(bad, rec, rec_len);
        bad[52] = 0xFFu; bad[53] = 0xFFu;      /* kind */
        MB_CHECK("out-of-range kind rejected", !mvap_request_decode(bad, rec_len, &out));
        memcpy(bad, rec, rec_len);
        bad[54] = 0xFFu; bad[55] = 0x00u;      /* declared param length */
        MB_CHECK("a param length that disagrees with the record is rejected",
                 !mvap_request_decode(bad, rec_len, &out));
        MB_CHECK("truncated frame rejected",
                 !mvap_request_decode(rec, rec_len - 1, &out));
        MB_CHECK("empty frame rejected", !mvap_request_decode(rec, 0, &out));

        /* A frame that smuggles a path into `param` does not decode, so the
         * broker never sees a request naming a file. */
        memcpy(bad, rec, rec_len);
        memcpy(bad + MVAP_REQ_FIXED, "/etc/passwd_____.x", 18);
        MB_CHECK("a param carrying a path is rejected at decode",
                 !mvap_request_decode(bad, rec_len, &out));
    }

    struct mvap_response r_in, r_out;
    memset(&r_in, 0, sizeof(r_in));
    r_in.verb = MVAP_VERB_INSPECT;
    r_in.request_id = 5;
    r_in.status = MVAP_ERR_DENIED_BUDGET;
    snprintf(r_in.body, sizeof(r_in.body), "{\"ok\":false}");
    size_t rn = mvap_response_encode(&r_in, buf, sizeof(buf));
    MB_CHECK("response round-trips",
             rn > MVAP_FRAME_PREFIX &&
             mvap_response_decode(buf + MVAP_FRAME_PREFIX,
                                  rn - MVAP_FRAME_PREFIX, &r_out) &&
             r_out.status == r_in.status &&
             strcmp(r_out.body, r_in.body) == 0);

    /* The wire cannot carry a path or a shell word. This is the property that
     * makes the protocol typed rather than merely validated. */
    MB_CHECK("param rejects an absolute path", !mvap_param_is_safe("/etc/passwd"));
    MB_CHECK("param rejects traversal", !mvap_param_is_safe("../../etc/passwd"));
    MB_CHECK("param rejects a shell word", !mvap_param_is_safe("a;rm -rf b"));
    MB_CHECK("param rejects a quote", !mvap_param_is_safe("a'b"));
    MB_CHECK("param accepts a safe token", mvap_param_is_safe("content.v1-a_b"));
    return failures;
}

/* ── (b) the grant evaluator ────────────────────────────────────────────── */

static void mb_demo_grant(struct agent_grant *g)
{
    memset(g, 0, sizeof(*g));
    snprintf(g->grant_id, sizeof(g->grant_id), "%s", MB_GRANT_ID);
    snprintf(g->principal, sizeof(g->principal), "lane3-seller");
    agent_grant_allow_action(g, MVAP_VERB_INSPECT);
    agent_grant_allow_action(g, MVAP_VERB_LIST);
    agent_grant_allow_action(g, MVAP_VERB_HOST);
    agent_grant_allow_action(g, MVAP_VERB_SELL);
    agent_grant_allow_kind(g, MVAP_KIND_CONTENT);
    agent_grant_allow_kind(g, MVAP_KIND_ANY);
    uint8_t id[MVAP_PROPERTY_ID_LEN];
    agent_broker_fixture_property_id(0, id);
    (void)agent_grant_add_property(g, id);
    g->max_value_zats = 100000000ULL;
    g->budget_zats = 150000000ULL;
    g->expires_unix_ms = mb_now_ms() + 3600000;
    g->rate_limit = 64;
    g->window_seconds = 60;
    /* Space-separated, which is the form allowlist_contains() splits on. */
    snprintf(g->counterparty_allowlist, sizeof(g->counterparty_allowlist),
             "buyer-one buyer-two");
}

/* Bind a session to the demo grant THROUGH THE PROVIDER, which is the only way
 * a session can acquire authority now: `struct agent_broker_session` holds no
 * grant to assign one to. The reference is a file static deliberately — the
 * session borrows it and must not outlive it.
 *
 * The authority itself lives in the fixture provider, so the revocation and
 * clock tests below move the REAL authority a running session reads, not a
 * copy the session took at bind time. */
static struct agent_authority_ref mb_authority;

static bool mb_bind_demo(struct agent_broker_session *s)
{
    struct agent_grant g;
    mb_demo_grant(&g);
    agent_broker_install_fixture_provider();
    agent_broker_fixture_set_grant(&g);
    char why[192];
    if (!agent_broker_session_bind(s, &mb_authority, why, sizeof(why))) {
        printf("agent_broker: could not bind the demo authority (%s)\n", why);
        return false;
    }
    return true;
}

static void mb_req(struct mvap_request *r, uint32_t verb, size_t prop_index)
{
    memset(r, 0, sizeof(*r));
    r->verb = verb;
    r->request_id = 1;
    if (prop_index < AGENT_BROKER_FIXTURE_PROPERTIES)
        agent_broker_fixture_property_id(prop_index, r->property_id);
}

static int mb_grant(void)
{
    int failures = 0;
    struct agent_grant g;
    struct mvap_request r;

    mb_demo_grant(&g);
    mb_req(&r, MVAP_VERB_INSPECT, 0);
    MB_CHECK("in-scope inspect allowed",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_OK);

    mb_req(&r, MVAP_VERB_INSPECT, 1);
    MB_CHECK("out-of-scope property refused",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_ERR_DENIED_PROPERTY);

    mb_req(&r, MVAP_VERB_TRANSFER, 0);
    MB_CHECK("disallowed action refused",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_ERR_DENIED_ACTION);

    mb_req(&r, MVAP_VERB_INSPECT, 0);
    r.kind = MVAP_KIND_NAME;
    MB_CHECK("out-of-scope kind refused",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_ERR_DENIED_KIND);

    mb_req(&r, MVAP_VERB_INSPECT, 0);
    MB_CHECK("expired grant refused",
             agent_grant_authorize(&g, &r, g.expires_unix_ms + 1) ==
                 MVAP_ERR_DENIED_EXPIRED);

    mb_demo_grant(&g);
    g.revoked = true;
    mb_req(&r, MVAP_VERB_INSPECT, 0);
    MB_CHECK("revoked grant refuses every action",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_ERR_DENIED_REVOKED);

    mb_demo_grant(&g);
    mb_req(&r, MVAP_VERB_SELL, 0);
    r.value_zats = g.max_value_zats + 1;
    snprintf(r.param, sizeof(r.param), "buyer-one");
    MB_CHECK("over-value action refused",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_ERR_DENIED_VALUE);

    mb_req(&r, MVAP_VERB_SELL, 0);
    r.value_zats = g.max_value_zats;
    snprintf(r.param, sizeof(r.param), "buyer-one");
    MB_CHECK("at-limit action allowed once",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_OK);
    agent_grant_commit_debit(&g, &r, mb_now_ms());
    MB_CHECK("the second identical action exhausts the budget",
             agent_grant_authorize(&g, &r, mb_now_ms()) == MVAP_ERR_DENIED_BUDGET);

    mb_demo_grant(&g);
    mb_req(&r, MVAP_VERB_SELL, 0);
    r.value_zats = 1;
    snprintf(r.param, sizeof(r.param), "stranger");
    MB_CHECK("off-allowlist counterparty refused",
             agent_grant_authorize(&g, &r, mb_now_ms()) ==
                 MVAP_ERR_DENIED_COUNTERPARTY);

    mb_demo_grant(&g);
    mb_req(&r, MVAP_VERB_DELEGATE, 0);
    MB_CHECK("delegation refused when the grant forbids it",
             agent_grant_authorize(&g, &r, mb_now_ms()) != MVAP_OK);

    /* The fingerprint identifies the AUTHORITY, so spending against it must
     * not change it — otherwise `metaverse agent status` would report a
     * different grant after every action. */
    struct agent_grant a, b;
    mb_demo_grant(&a);
    mb_demo_grant(&b);
    uint8_t fa[32], fb[32];
    agent_grant_fingerprint(&a, fa);
    mb_req(&r, MVAP_VERB_SELL, 0);
    r.value_zats = 10;
    snprintf(r.param, sizeof(r.param), "buyer-one");
    agent_grant_commit_debit(&b, &r, mb_now_ms());
    agent_grant_fingerprint(&b, fb);
    MB_CHECK("fingerprint is stable across spending",
             memcmp(fa, fb, sizeof(fa)) == 0);
    b.revoked = true;
    agent_grant_fingerprint(&b, fb);
    MB_CHECK("fingerprint changes when the authority changes",
             memcmp(fa, fb, sizeof(fa)) != 0);
    return failures;
}

/* ── (c) the audit chain ────────────────────────────────────────────────── */

static bool mb_copy_file(const char *src, const char *dst)
{
    FILE *s = fopen(src, "re");
    if (!s)
        return false;
    FILE *d = fopen(dst, "we");
    if (!d) {
        (void)fclose(s);
        return false;
    }
    char b[512];
    size_t got;
    bool ok = true;
    while ((got = fread(b, 1, sizeof(b), s)) > 0)
        ok = ok && fwrite(b, 1, got, d) == got;
    (void)fclose(s);
    ok = fclose(d) == 0 && ok;
    return ok;
}

static int mb_audit_append_rows(struct agent_audit_log *log)
{
    int failures = 0;
    for (uint32_t i = 0; i < 4; i++) {
        struct agent_receipt r;
        memset(&r, 0, sizeof(r));
        /* One synthetic legacy row proves the v2 digest remains readable;
         * the append default used by every broker-created row is v3. */
        if (i == 0)
            r.receipt_version = 2;
        r.verb = MVAP_VERB_INSPECT;
        r.request_id = i + 1;
        r.status = MVAP_OK;
        snprintf(r.principal, sizeof(r.principal), "lane3-seller");
        snprintf(r.grant_id, sizeof(r.grant_id), "%s", MB_GRANT_ID);
        snprintf(r.detail, sizeof(r.detail), "receipt %u", i);
        agent_broker_fixture_property_id(0, r.property_id);
        if (!agent_audit_append(log, &r))
            failures++;
    }
    return failures;
}

static bool mb_audit_intact_ok(const char *dir, struct agent_audit_verdict *v)
{
    return agent_audit_verify_dir(dir, v) && v->ok && v->rows == 4 &&
           v->chain_breaks == 0 && v->bad_signatures == 0 &&
           v->malformed == 0;
}

static bool mb_audit_render_ok(size_t rendered_len, const char *rendered,
                               const char *dir)
{
    return rendered_len > 0 &&
           strstr(rendered, "\"receipt_version\":3") != NULL &&
           strstr(rendered, "\"money_snapshot_status\":\"UNKNOWN\"") != NULL &&
           strstr(rendered, "\"money_snapshot_root\":\"0000000000000000") !=
               NULL &&
           strstr(rendered, dir) == NULL;
}

static size_t mb_audit_read_rows(const char *path, char lines[8][2048])
{
    size_t n_lines = 0;
    FILE *in = fopen(path, "re");
    if (in) {
        while (n_lines < 8 && fgets(lines[n_lines], sizeof(lines[0]), in))
            n_lines++;
        (void)fclose(in);
    }
    return n_lines;
}

static void mb_audit_write_tampered(FILE *o, const char *how,
                                    char lines[8][2048], size_t n_lines)
{
    if (strcmp(how, "swap") == 0) {
        /* Reorder rows 0 and 1: every id is still a genuine broker
         * signature, but the chain links no longer follow. */
        (void)fputs(lines[1], o);
        (void)fputs(lines[0], o);
        for (size_t i = 2; i < n_lines; i++)
            (void)fputs(lines[i], o);
    } else {
        for (size_t i = 0; i < n_lines; i++) {
            if (strcmp(how, "drop") == 0 && i == 1)
                continue;              /* delete a row from the middle   */
            if (strcmp(how, "edit") == 0 && i == 2) {
                char *p = strstr(lines[i], "receipt 2");
                if (p)
                    p[8] = '9';        /* rewrite detail, keep the length */
            }
            (void)fputs(lines[i], o);
        }
        if (strcmp(how, "garbage") == 0)
            (void)fputs("{not a receipt at all}\n", o);
    }
}

static bool mb_audit_tamper_ok(const char *tdir, struct agent_audit_verdict *tv)
{
    return agent_audit_verify_dir(tdir, tv) && !tv->ok &&
           (tv->chain_breaks > 0 || tv->bad_signatures > 0 ||
            tv->malformed > 0);
}

static bool mb_audit_unverifiable_ok(const char *dir,
                                     struct agent_audit_verdict *nv)
{
    return !agent_audit_verify_dir(dir, nv) && !nv->ok;
}

static int mb_audit(void)
{
    int failures = 0;
    char dir[320];
    mb_subdir(dir, sizeof(dir), "audit-ok");

    struct agent_audit_log log;
    memset(&log, 0, sizeof(log));
    MB_CHECK("audit log opens", agent_audit_open(&log, dir));

    failures += mb_audit_append_rows(&log);

    struct agent_audit_verdict v;
    memset(&v, 0, sizeof(v));
    MB_CHECK("intact log verifies", mb_audit_intact_ok(dir, &v));
    char rendered[8192];
    size_t rendered_len = agent_audit_render_json(
        dir, 8, rendered, sizeof(rendered));
    MB_CHECK("every new receipt commits an explicit money status and root",
             mb_audit_render_ok(rendered_len, rendered, dir));

    /* A second broker must not fork the chain under a key it cannot sign for. */
    struct agent_audit_log again;
    memset(&again, 0, sizeof(again));
    MB_CHECK("a second broker refuses to extend an existing chain",
             !agent_audit_open(&again, dir));

    char src[400];
    snprintf(src, sizeof(src), "%s/audit.log", dir);
    char pub_src[400];
    snprintf(pub_src, sizeof(pub_src), "%s/audit.pub", dir);

    /* Four separate tampered copies. Each is a different way a log can be
     * wrong, and the verdict must name which way rather than reporting a bare
     * "not ok". */
    static const char *const how[] = { "edit", "drop", "swap", "garbage" };
    for (size_t c = 0; c < sizeof(how) / sizeof(how[0]); c++) {
        char tdir[320];
        mb_subdir(tdir, sizeof(tdir), how[c]);

        char lines[8][2048];
        size_t n_lines = mb_audit_read_rows(src, lines);
        char tpath[400];
        snprintf(tpath, sizeof(tpath), "%s/audit.log", tdir);
        FILE *o = fopen(tpath, "we");
        if (!o || n_lines < 4) {
            failures++;
            if (o)
                (void)fclose(o);
            continue;
        }
        mb_audit_write_tampered(o, how[c], lines, n_lines);
        (void)fclose(o);

        /* The public key travels with the log; without it nothing verifies. */
        char pub_dst[400];
        snprintf(pub_dst, sizeof(pub_dst), "%s/audit.pub", tdir);
        if (!mb_copy_file(pub_src, pub_dst))
            failures++;

        struct agent_audit_verdict tv;
        memset(&tv, 0, sizeof(tv));
        char label[96];
        snprintf(label, sizeof(label), "tampered log (%s) fails verification",
                 how[c]);
        MB_CHECK(label, mb_audit_tamper_ok(tdir, &tv));
    }

    /* A log with no key next to it is unverifiable, and says so rather than
     * reporting a clean verdict over rows nobody can check. */
    char nokey[320];
    mb_subdir(nokey, sizeof(nokey), "audit-nokey");
    char nokey_log[400];
    snprintf(nokey_log, sizeof(nokey_log), "%s/audit.log", nokey);
    if (!mb_copy_file(src, nokey_log))
        failures++;
    struct agent_audit_verdict nv;
    memset(&nv, 0, sizeof(nv));
    MB_CHECK("a log with no public key beside it does not verify",
             mb_audit_unverifiable_ok(nokey, &nv));
    return failures;
}

static bool mb_status_dir(char out[512], size_t target)
{
    size_t used = strlen(g_dir);
    if (used >= target || target >= 512)
        return false;
    memcpy(out, g_dir, used + 1);
    while (used < target) {
        size_t remaining = target - used;
        if (remaining < 2)
            return false;
        size_t part = remaining - 1;
        if (part > 200)
            part = remaining == 202 ? 199 : 200;
        out[used++] = '/';
        memset(out + used, 'a', part);
        used += part;
        out[used] = '\0';
        if (mkdir(out, 0700) != 0 && errno != EEXIST)
            return false;
    }
    return true;
}

static int mb_status_path_bounds(void)
{
    int failures = 0;
    char dir[512], path[520], doc[512];
    for (size_t length = 499; length <= 500; ++length) {
        if (!mb_status_dir(dir, length)) {
            printf("agent_broker: status path fixture setup failed\n");
            return failures + 1;
        }
        snprintf(path, sizeof(path), "%s/%s", dir,
                 length == 499 ? "broker.json" : "broker.jso");
        FILE *f = fopen(path, "wb");
        if (!f)
            return failures + 1;
        bool written = fwrite("{}", 1, 2, f) == 2;
        int closed = fclose(f);
        if (!written || closed != 0)
            return failures + 1;
        memset(doc, 'Z', sizeof(doc));
        size_t n = agent_broker_render_status_json(dir, doc, sizeof(doc));
        if (length == 499) {
            MB_CHECK("499-byte directory reads the complete broker.json path",
                     n > 0 && n < sizeof(doc) &&
                     strstr(doc, "\"broker_state_present\":true") != NULL);
            char tiny = 'Z';
            MB_CHECK("zero output capacity returns zero without writing",
                     agent_broker_render_status_json(dir, &tiny, 0) == 0 &&
                     tiny == 'Z');
            MB_CHECK("one-byte output preserves the would-be length",
                     agent_broker_render_status_json(dir, &tiny, 1) == n &&
                     tiny == '\0');
        } else {
            MB_CHECK("500-byte directory refuses the broker.jso decoy",
                     n == 0 && doc[0] == 'Z');
        }
        MB_CHECK("status path fixture file cleanup succeeds", unlink(path) == 0);
    }
    return failures;
}

/* ── (d) SO_PEERCRED as a predicate ─────────────────────────────────────── */

#if !defined(_WIN32)

static int mb_peercred(void)
{
    int failures = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("agent_broker: socketpair failed — skipping peercred\n");
        return 1;
    }
    struct agent_peer_cred c;
    memset(&c, 0, sizeof(c));
    MB_CHECK("peercred reads the kernel's attribution",
             agent_broker_peercred(sv[0], &c) && c.valid &&
             c.uid == getuid() && c.pid == getpid());

    struct agent_peer_expectation e;
    memset(&e, 0, sizeof(e));
    char why[160];

    /* An expectation that constrains nothing must FAIL CLOSED: an unbounded
     * "expectation" accepting every caller is the bug this check exists to
     * prevent. */
    MB_CHECK("an empty expectation is refused",
             !agent_broker_peer_authorized(&c, &e, why, sizeof(why)) &&
             why[0] != '\0');

    e.require_uid = true; e.uid = getuid();
    e.require_pid = true; e.pid = getpid();
    MB_CHECK("the real peer is accepted",
             agent_broker_peer_authorized(&c, &e, why, sizeof(why)));

    e.pid = getpid() + 100000;
    MB_CHECK("a peer with the wrong pid is refused",
             !agent_broker_peer_authorized(&c, &e, why, sizeof(why)) &&
             strstr(why, "pid mismatch") != NULL);

    e.pid = getpid();
    e.uid = getuid() + 1;
    MB_CHECK("a peer with the wrong uid is refused",
             !agent_broker_peer_authorized(&c, &e, why, sizeof(why)) &&
             strstr(why, "uid mismatch") != NULL);

    /* A peer that claims an identity in its own payload changes nothing: the
     * credentials come from the kernel, not the wire. */
    struct agent_peer_cred forged = c;
    forged.uid = 0;
    e.uid = getuid();
    MB_CHECK("a self-claimed uid does not satisfy the expectation",
             !agent_broker_peer_authorized(&forged, &e, why, sizeof(why)));

    /* A socket the kernel supplied no credentials for is refused, not trusted
     * by default. */
    struct agent_peer_cred none;
    memset(&none, 0, sizeof(none));
    none.uid = getuid();
    none.pid = getpid();
    MB_CHECK("credentials the kernel never supplied are refused",
             !agent_broker_peer_authorized(&none, &e, why, sizeof(why)));

    (void)close(sv[0]);
    (void)close(sv[1]);
    return failures;
}

/* ── (d2) the socketpair trap: SO_PEERCRED names the socket's CREATOR ───── */

/* On an accept()ed connection SO_PEERCRED names the peer, which is the answer
 * the broker wants. On a socketpair(2) it names whoever called socketpair() —
 * the broker, on BOTH ends — so a broker that trusted it would be verifying
 * itself and would accept any process holding the other end. This proves the
 * trap is real on this kernel AND that the broker does not fall into it. */
static int mb_sender_cred(void)
{
#if defined(__APPLE__)
    printf("agent_broker: macOS exposes peer uid/gid but no per-message "
           "sender pid; Linux sender-credential trap is not applicable\n");
    return 0;
#else
    int failures = 0;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("agent_broker: socketpair failed — skipping sender credentials\n");
        return 1;
    }
    /* Enabled before the fork, exactly as agent_broker_spawn_confined does. */
    int on = 1;
    if (setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
        printf("agent_broker: SO_PASSCRED unsupported — skipping\n");
        (void)close(sv[0]);
        (void)close(sv[1]);
        return 1;
    }

    pid_t kid = fork();
    if (kid == 0) {
        (void)close(sv[0]);
        ssize_t w = write(sv[1], "x", 1);
        (void)close(sv[1]);
        _exit(w == 1 ? 0 : 1);
    }
    if (kid < 0) {
        printf("agent_broker: fork failed — skipping sender credentials\n");
        (void)close(sv[0]);
        (void)close(sv[1]);
        return 1;
    }
    (void)close(sv[1]);

    struct agent_peer_cred sock_cred, msg_cred, chosen;
    memset(&sock_cred, 0, sizeof(sock_cred));
    memset(&msg_cred, 0, sizeof(msg_cred));
    memset(&chosen, 0, sizeof(chosen));

    MB_CHECK("SO_PEERCRED on a socketpair names its creator, not the peer",
             agent_broker_peercred(sv[0], &sock_cred) && sock_cred.valid &&
             sock_cred.pid == getpid() && sock_cred.pid != kid);
    MB_CHECK("the message credentials name the process that actually sent",
             agent_broker_sender_cred(sv[0], &msg_cred) && msg_cred.valid &&
             msg_cred.pid == kid && msg_cred.uid == getuid());
    MB_CHECK("the broker identifies the sender rather than itself",
             agent_broker_identify_peer(sv[0], &chosen) && chosen.valid &&
             chosen.pid == kid);

    /* Peeking must not eat the byte the caller still has to read. */
    char b = 0;
    MB_CHECK("identifying the peer did not consume its message",
             read(sv[0], &b, 1) == 1 && b == 'x');

    (void)close(sv[0]);
    int st = 0;
    (void)waitpid(kid, &st, 0);
    return failures;
#endif
}

/* ── (e) SO_PEERCRED end to end over a real listening socket ────────────── */

static int mb_connect(const char *path)
{
    int fd = platform_socket_open(AF_UNIX, SOCK_STREAM, 0, true, false);
    if (fd < 0)
        return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strnlen(path, sizeof(sa.sun_path)) >= sizeof(sa.sun_path)) {
        (void)close(fd);
        return -1;
    }
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* Send one well-formed, fully in-grant INSPECT and read whatever comes back.
 * Returns the response status, or MVAP_ERR_INTERNAL when nothing decoded. */
static int32_t mb_client_inspect(int fd, uint32_t request_id)
{
    struct mvap_request req;
    memset(&req, 0, sizeof(req));
    req.verb = MVAP_VERB_INSPECT;
    req.request_id = request_id;
    agent_broker_fixture_property_id(0, req.property_id);

    uint8_t frame[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t n = mvap_request_encode(&req, frame, sizeof(frame));
    if (n == 0 || write(fd, frame, n) != (ssize_t)n)
        return MVAP_ERR_INTERNAL;
    /* Half-close so the broker's serve loop sees EOF after this one request
     * instead of blocking for a second. */
    (void)shutdown(fd, SHUT_WR);
    return MVAP_OK;
}

static int32_t mb_client_read_status(int fd)
{
    uint8_t prefix[MVAP_FRAME_PREFIX];
    size_t got = 0;
    while (got < sizeof(prefix)) {
        ssize_t r = read(fd, prefix + got, sizeof(prefix) - got);
        if (r <= 0)
            return MVAP_ERR_INTERNAL;
        got += (size_t)r;
    }
    uint32_t rec = mvap_frame_length(prefix, sizeof(prefix));
    if (rec == 0)
        return MVAP_ERR_INTERNAL;
    uint8_t buf[MVAP_MAX_FRAME];
    got = 0;
    while (got < rec) {
        ssize_t r = read(fd, buf + got, rec - got);
        if (r <= 0)
            return MVAP_ERR_INTERNAL;
        got += (size_t)r;
    }
    struct mvap_response resp;
    if (!mvap_response_decode(buf, rec, &resp))
        return MVAP_ERR_INTERNAL;
    return resp.status;
}

/* One round against the listener: connect as THIS process, send an in-grant
 * request, and let the broker apply `expect`. */
static int mb_listen_round(const char *sock, int lfd,
                           struct agent_audit_log *log,
                           const struct agent_peer_expectation *expect,
                           uint32_t request_id, int32_t want_status,
                           bool want_dispatch, const char *label)
{
    int failures = 0;
    struct agent_broker_session s;
    memset(&s, 0, sizeof(s));
    if (!mb_bind_demo(&s))
        return 1;
    s.audit = log;
    s.expect = *expect;

    int c = mb_connect(sock);
    if (c < 0) {
        printf("agent_broker: %s — connect failed\n", label);
        return 1;
    }
    if (mb_client_inspect(c, request_id) != MVAP_OK) {
        printf("agent_broker: %s — could not send the request\n", label);
        (void)close(c);
        return 1;
    }

    (void)agent_broker_accept_once(&s, lfd, 5000);
    int32_t status = mb_client_read_status(c);
    (void)close(c);

    char name[160];
    snprintf(name, sizeof(name), "%s: the peer got %s", label,
             mvap_status_name(want_status));
    MB_CHECK(name, status == want_status);

    snprintf(name, sizeof(name), "%s: %s", label,
             want_dispatch ? "the verb was dispatched"
                           : "no verb was ever dispatched");
    MB_CHECK(name, want_dispatch ? s.requests_served == 1
                                 : s.requests_served == 0);

    /* Whatever the verdict, the kernel — not the wire — named the peer. */
    snprintf(name, sizeof(name), "%s: the kernel attributed this process",
             label);
    MB_CHECK(name, s.peer.valid && s.peer.pid == getpid() &&
             s.peer.uid == getuid());
    return failures;
}

static int mb_socket_identity(void)
{
    int failures = 0;
    char dir[320];
    mb_subdir(dir, sizeof(dir), "listener");

    /* AF_UNIX caps a bound path at sizeof(sun_path) (108) and
     * agent_broker_listen() refuses a longer one outright — correctly. The
     * audit log can sit at any depth, but the socket cannot, so it gets its
     * own short-named directory instead of nesting under the group root;
     * otherwise a deep checkout path alone defeats the identity round. */
    char sockdir[PATH_MAX], sock[PATH_MAX];
    test_fmt_tmpdir(sockdir, sizeof(sockdir), "mvs", "l");
    (void)mkdir(sockdir, 0700);
    snprintf(sock, sizeof(sock), "%s/a.sock", sockdir);
    int lfd = agent_broker_listen(sock);
    if (lfd < 0) {
        printf("agent_broker: cannot listen on %s — skipping the socket "
               "identity round\n", sock);
        return 1;
    }

    struct agent_audit_log log;
    memset(&log, 0, sizeof(log));
    MB_CHECK("the listener's audit log opens", agent_audit_open(&log, dir));

    /* A listening socket is reachable by ANY local process, which is exactly
     * why the credential check runs before the verb dispatch. This process is
     * that arbitrary local process. */
    struct agent_peer_expectation e;

    memset(&e, 0, sizeof(e));
    e.require_uid = true;
    e.uid = getuid() + 1;              /* the broker expects a different uid */
    failures += mb_listen_round(sock, lfd, &log, &e, 5101,
                                MVAP_ERR_DENIED_PEER_IDENTITY, false,
                                "a peer of the wrong uid");

    memset(&e, 0, sizeof(e));
    e.require_uid = true;
    e.uid = getuid();
    e.require_pid = true;
    e.pid = getpid() + 1;              /* right uid, wrong process          */
    failures += mb_listen_round(sock, lfd, &log, &e, 5102,
                                MVAP_ERR_DENIED_PEER_IDENTITY, false,
                                "a peer of the right uid but the wrong pid");

    memset(&e, 0, sizeof(e));
    e.require_uid = true;
    e.uid = getuid();
    e.require_pid = true;
    e.pid = getpid();                  /* the peer the broker is expecting  */
    failures += mb_listen_round(sock, lfd, &log, &e, 5103, MVAP_OK, true,
                                "the expected peer");

    (void)close(lfd);
    (void)unlink(sock);
    (void)rmdir(sockdir);

    /* Both refusals are on the record, and the record still verifies. */
    struct agent_audit_verdict v;
    memset(&v, 0, sizeof(v));
    MB_CHECK("both refusals were audited and the log verifies",
             agent_audit_verify_dir(dir, &v) && v.ok && v.rows == 2);

    char doc[8192];
    size_t n = agent_audit_render_json(dir, 16, doc, sizeof(doc));
    MB_CHECK("the audit render names WHY the peers were refused",
             n > 0 && strstr(doc, "DENIED_PEER_IDENTITY") != NULL &&
             strstr(doc, "uid mismatch") != NULL &&
             strstr(doc, "pid mismatch") != NULL);
    return failures;
}

/* ── (f)(g)(h)(i) a real confined child ─────────────────────────────────── */

/* Read a file into `buf` (NUL-terminated). Returns bytes read, 0 on failure. */
static size_t mb_slurp(const char *path, char *buf, size_t cap)
{
    if (cap == 0)
        return 0;
    buf[0] = '\0';
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    size_t got = 0;
    while (got + 1 < cap) {
        ssize_t r = read(fd, buf + got, cap - 1 - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    buf[got] = '\0';
    (void)close(fd);
    return got;
}

/* /proc/<pid>/environ and cmdline are NUL-separated; search the whole region
 * rather than treating it as one C string. */
static bool mb_region_contains(const char *buf, size_t len, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || len < nl)
        return false;
    for (size_t i = 0; i + nl <= len; i++)
        if (memcmp(buf + i, needle, nl) == 0)
            return true;
    return false;
}

struct mb_child_run {
    char report[6144];    /* the child's self-report                        */
    int  exit_code;       /* negative == killed by that signal              */
    bool grant_leaked;    /* the grant id appeared in the child's own /proc */
    bool spawned;
};

static bool mb_run_child_spawn_ok(const struct agent_spawn_request *sreq,
                                  struct agent_spawn_result *sres)
{
    return agent_broker_spawn_confined(sreq, sres) && sres->pid > 0;
}

static bool mb_run_child_peer_ok(const struct agent_broker_session *s,
                                 pid_t pid)
{
    return s->peer.valid && s->peer.pid == pid && s->peer.uid == getuid();
}

static bool mb_run_child_replay_ok(const struct agent_broker_session *s)
{
    return s->requests_served == 4 && s->receipts_written == 1;
}

static bool mb_run_child_refusal_ok(const struct agent_broker_session *s)
{
    return s->requests_denied == 2 && s->requests_served == 2;
}

static bool mb_run_child_receipts_ok(const char *broker_dir,
                                     struct agent_audit_verdict *v)
{
    return agent_audit_verify_dir(broker_dir, v) && v->ok;
}

static bool mb_run_child_status_ok(const char *broker_dir, char *doc,
                                   size_t cap)
{
    return agent_broker_render_status_json(broker_dir, doc, cap) > 0 &&
           strstr(doc, "\"broker_state_present\":true") != NULL;
}

/* Stand a whole boundary up under `<g_dir>/<leaf>`:
 *
 *   <leaf>/broker    the privileged side — audit key, receipts, and a file
 *                    standing in for the wallet/RPC cookie. NOT granted to the
 *                    child, which is the point.
 *   <leaf>/scratch   the child's ONLY writable Landlock grant.
 */
static int mb_run_child(const char *self_exe, const char *leaf,
                        const char *script, uint64_t max_requests,
                        struct mb_child_run *run)
{
    int failures = 0;
    memset(run, 0, sizeof(*run));
    run->exit_code = -1;

    char base[320], broker_dir[400], scratch[400], secret[512];
    mb_subdir(base, sizeof(base), leaf);
    snprintf(broker_dir, sizeof(broker_dir), "%s/broker", base);
    snprintf(scratch, sizeof(scratch), "%s/scratch", base);
    (void)mkdir(broker_dir, 0700);
    (void)mkdir(scratch, 0700);
    snprintf(secret, sizeof(secret), "%s/%s", broker_dir, MB_SECRET_LEAF);

    /* The canary must exist BEFORE the child probes it, or an ENOENT would
     * masquerade as confinement. It is created here, not by the broker, for
     * exactly that reason. */
    FILE *sf = fopen(secret, "we");
    if (!sf)
        return 1;
    (void)fputs("operator material the confined agent must not reach\n", sf);
    if (fclose(sf) != 0)
        return 1;

    struct agent_spawn_request sreq;
    memset(&sreq, 0, sizeof(sreq));
    sreq.self_exe = self_exe;
    sreq.scratch_dir = scratch;
    sreq.script = script;
    sreq.canary = secret;
    sreq.confined_uid = 0;   /* 0 == do not attempt a switch */
    sreq.confined_gid = 0;

    struct agent_spawn_result sres;
    memset(&sres, 0, sizeof(sres));
    if (!mb_run_child_spawn_ok(&sreq, &sres)) {
        printf("agent_broker: spawn failed for script '%s'\n", script);
        return 1;
    }
    run->spawned = true;

    /* (g) Read the child's OWN /proc while it is alive. The grant is built
     * BELOW this point, after the fork, which is what makes this hold. */
    char ppath[64], pbuf[8192];
    snprintf(ppath, sizeof(ppath), "/proc/%d/environ", (int)sres.pid);
    size_t env_len = mb_slurp(ppath, pbuf, sizeof(pbuf));
    if (mb_region_contains(pbuf, env_len, MB_GRANT_ID))
        run->grant_leaked = true;
    snprintf(ppath, sizeof(ppath), "/proc/%d/cmdline", (int)sres.pid);
    size_t cmd_len = mb_slurp(ppath, pbuf, sizeof(pbuf));
    if (mb_region_contains(pbuf, cmd_len, MB_GRANT_ID))
        run->grant_leaked = true;

    /* Only NOW does anything secret exist in this process. */
    struct agent_audit_log log;
    memset(&log, 0, sizeof(log));
    (void)agent_audit_open(&log, broker_dir);

    struct agent_broker_session s;
    memset(&s, 0, sizeof(s));
    if (!mb_bind_demo(&s)) {
        (void)close(sres.sock);
        return 1;
    }
    s.audit = &log;
    s.expect.require_uid = true; s.expect.uid = getuid();
    s.expect.require_pid = true; s.expect.pid = sres.pid;

    (void)agent_broker_serve_fd(&s, sres.sock, max_requests);
    (void)close(sres.sock);

    int st = 0;
    if (waitpid(sres.pid, &st, 0) == sres.pid)
        run->exit_code = WIFSIGNALED(st) ? -WTERMSIG(st) : WEXITSTATUS(st);

    char rpath[512];
    snprintf(rpath, sizeof(rpath), "%s/agent_report.json", scratch);
    (void)mb_slurp(rpath, run->report, sizeof(run->report));

    /* Printed unconditionally: when a confinement assertion fails, the child's
     * fate is the first thing anyone reading the log needs. */
    printf("agent_broker: %s child pid=%d exit=%d (negative == signal) "
           "report=%zu bytes\n", script, (int)sres.pid, run->exit_code,
           strlen(run->report));

    agent_broker_write_status(broker_dir, &s, sres.pid, NULL);

    MB_CHECK("the kernel named the exact process the broker forked",
             mb_run_child_peer_ok(&s, sres.pid));

    /* Fail-closed custody documents: a session that cannot attest what it
     * holds must RETIRE any bindings file left standing, not leave a prior
     * session's grants readable as today's fact. The demo authority carries
     * no money_bindings provider, so this exercise takes exactly the
     * cannot-attest branch the retirement was added for. */
    {
        char mpath[512];
        snprintf(mpath, sizeof(mpath), "%s/money-bindings.json", broker_dir);
        FILE *mf = fopen(mpath, "we");
        if (mf) {
            (void)fprintf(mf,
                          "{\"schema\":\"zcl.agent_money_bindings.v1\","
                          "\"wallets\":[]}");
            (void)fclose(mf);
        }
        agent_broker_write_status(broker_dir, &s, sres.pid, NULL);
        struct stat mst;
        MB_CHECK("unattestable custody retires the standing bindings doc",
                 stat(mpath, &mst) != 0 && errno == ENOENT);
    }

    if (strcmp(script, "inspect") == 0) {
        MB_CHECK("the confined agent's requests were served",
                 s.requests_served >= 3);
        /* (i) four requests, three distinct ids, one mutation -> one receipt. */
        MB_CHECK("a replayed request_id mints no second receipt",
                 mb_run_child_replay_ok(&s));
    }
    if (strcmp(script, "hostile") == 0) {
        /* (h) both asks crossed the wire fine; the BROKER is what refused. */
        MB_CHECK("the broker refused the hostile agent's asks",
                 mb_run_child_refusal_ok(&s));
    }

    struct agent_audit_verdict v;
    memset(&v, 0, sizeof(v));
    char label[128];
    snprintf(label, sizeof(label), "the %s session's receipts verify", script);
    MB_CHECK(label, mb_run_child_receipts_ok(broker_dir, &v));

    char doc[8192];
    snprintf(label, sizeof(label), "status renders for the %s broker directory",
             script);
    MB_CHECK(label, mb_run_child_status_ok(broker_dir, doc, sizeof(doc)));
    return failures;
}

/* Every assertion that only holds when the kernel really enforced something. */
static int mb_confinement_assertions(const struct mb_child_run *run,
                                     const char *script)
{
    int failures = 0;
    char label[160];
    const char *r = run->report;

    snprintf(label, sizeof(label), "%s child exits cleanly (refused, not "
             "crashed)", script);
    MB_CHECK(label, run->exit_code == 0);

    snprintf(label, sizeof(label),
             "the grant never reached the %s child's environ or cmdline",
             script);
    MB_CHECK(label, !run->grant_leaked);

    snprintf(label, sizeof(label),
             "the %s child confirms its own environ is empty", script);
    MB_CHECK(label, strstr(r, "\"environ_bytes\":0") != NULL);

    snprintf(label, sizeof(label), "landlock was applied to the %s child",
             script);
    MB_CHECK(label, strstr(r, "\"landlock_applied\":true") != NULL);

    snprintf(label, sizeof(label), "seccomp was applied to the %s child",
             script);
    MB_CHECK(label, strstr(r, "\"seccomp_applied\":true") != NULL);

    snprintf(label, sizeof(label), "rlimits were applied to the %s child",
             script);
    MB_CHECK(label, strstr(r, "\"rlimits_applied\":true") != NULL);

    /* The heart of the claim, against the broker's OWN directory: a file that
     * exists, that this uid owns, one directory away — DENIED, not absent. */
    snprintf(label, sizeof(label),
             "the %s child cannot read the broker's operator secret (EACCES)",
             script);
    MB_CHECK(label, strstr(r, MB_SECRET_LEAF) != NULL &&
             strstr(r, "\"canary_result\":\"EACCES\"") != NULL);
    return failures;
}

#else /* _WIN32 */

/* Cases (d)(e) need AF_UNIX + SO_PEERCRED, which do not exist on Windows
 * (production agent_broker_listen/agent_broker_accept_once refuse there),
 * and (f)-(i) spawn Landlock-confined children, which the os_sandbox stub
 * refuses on Windows. The portable codec/grant/audit/custody cases still
 * run. */
static int mb_peercred(void)
{
    printf("agent_broker: SKIP (Windows): SO_PEERCRED predicate case needs "
           "AF_UNIX\n");
    return 0;
}

static int mb_sender_cred(void)
{
    printf("agent_broker: SKIP (Windows): socketpair-credential trap case "
           "needs AF_UNIX + fork\n");
    return 0;
}

static int mb_socket_identity(void)
{
    printf("agent_broker: SKIP (Windows): end-to-end peer-identity case "
           "needs AF_UNIX + SO_PEERCRED\n");
    return 0;
}

#endif /* !_WIN32 */

#if !defined(_WIN32)
static int64_t mb_scratch_clock(void *self)
{
    (void)self;
    return mb_now_ms();
}

static const clock_iface_t mb_scratch_clock_iface = {
    .now_monotonic_ns = mb_scratch_clock,
    .now_wall_ms = mb_scratch_clock,
};

static int mb_scratch_mode(char **args, char *error, size_t cap)
{
    char capture_path[PATH_MAX];
    int fd = test_mkstemp(capture_path, sizeof(capture_path), "mbscratch");
    if (fd < 0)
        return -1;
    FILE *capture = fdopen(fd, "w+");
    if (!capture) {
        (void)close(fd);
        (void)unlink(capture_path);
        return -1;
    }
    int saved = dup(STDERR_FILENO);
    (void)fflush(stderr);
    int result = -1;
    if (saved >= 0 && dup2(fd, STDERR_FILENO) >= 0)
        result = agent_broker_mode_main(3, args);
    (void)fflush(stderr);
    if (saved >= 0) {
        if (dup2(saved, STDERR_FILENO) < 0)
            result = -1;
        (void)close(saved);
    }
    rewind(capture);
    size_t got = fread(error, 1, cap - 1, capture);
    error[got] = '\0';
    if (ferror(capture) || !feof(capture))
        result = -1;
    if (fclose(capture) != 0)
        result = -1;
    if (unlink(capture_path) != 0)
        result = -1;
    return result;
}

/* Make only the parents: both broker leaves must be absent at entry. */
static bool mb_scratch_fixture(char *dir)
{
    size_t used = strlen(g_dir);
    if (used >= 431)
        return false;
    memcpy(dir, g_dir, used + 1);
    while (used < 434) {
        dir[used++] = '/';
        size_t end = used + 100;
        if (end > 434)
            end = 434;
        if (end >= 432 && end < 434)
            end = 431;
        while (used < end)
            dir[used++] = 'a';
        dir[used] = '\0';
        if (used < 434 && mkdir(dir, 0700) != 0) {
            printf("agent_broker: scratch fixture mkdir failed: %s\n", strerror(errno));
            return false;
        }
    }
    return true;
}

static int mb_scratch_oversized(char *dir)
{
    int failures = 0;
    char option[448], scratch[460], shortened[460], error[8192];
    snprintf(option, sizeof(option), "--broker-dir=%s", dir);
    snprintf(scratch, sizeof(scratch), "%s/agent-scratch", dir);
    snprintf(shortened, sizeof(shortened), "%s/agent-scratc", dir);
    char *args[] = { "broker", option, "--listen", NULL };
    int result = mb_scratch_mode(args, error, sizeof(error));
    struct stat st;
    MB_CHECK("oversized scratch gets named preflight refusal",
             result == 3 && strstr(error, "broker: scratch pathname too long") != NULL);
    MB_CHECK("oversized scratch creates no broker directory",
             lstat(dir, &st) != 0 && errno == ENOENT);
    MB_CHECK("oversized scratch creates no intended directory",
             lstat(scratch, &st) != 0 && errno == ENOENT);
    MB_CHECK("oversized scratch creates no shortened directory",
             lstat(shortened, &st) != 0 && errno == ENOENT);
    return failures;
}

static int mb_scratch_fitting(char *dir)
{
    int failures = 0;
    char option[448], scratch[460], shortened[460], error[8192];
    snprintf(option, sizeof(option), "--broker-dir=%s", dir);
    snprintf(scratch, sizeof(scratch), "%s/agent-scratch", dir);
    snprintf(shortened, sizeof(shortened), "%s/agent-scratc", dir);
    char *args[] = { "broker", option, "--listen", NULL };
    int result = mb_scratch_mode(args, error, sizeof(error));
    struct stat st;
    MB_CHECK("fitting scratch directory is created intact",
             stat(scratch, &st) == 0 && S_ISDIR(st.st_mode));
    MB_CHECK("fitting scratch creates no shortened directory",
             lstat(shortened, &st) != 0 && errno == ENOENT);
    MB_CHECK("fitting scratch reaches separate socket refusal",
             result == 6 && strstr(error, "broker: cannot listen on ") != NULL &&
             strstr(error, "scratch pathname too long") == NULL);
    return failures;
}
#endif

static int mb_scratch_path_bounds(void)
{
    int failures = 0;
#if !defined(_WIN32)
    char dir[435];
    bool ready = mb_scratch_fixture(dir);
    MB_CHECK("create scratch boundary fixture parents", ready);
    if (!ready)
        return failures;
    const clock_iface_t *saved_clock = clock_default();
    clock_set_default(&mb_scratch_clock_iface);
    failures += mb_scratch_oversized(dir);
    dir[433] = '\0';
    failures += mb_scratch_fitting(dir);
    clock_set_default(saved_clock);
#endif
    return failures;
}

#if !defined(_WIN32)
static int mb_identity_invalid(char *dir_arg, const char *prefix,
                               unsigned long long limit)
{
    int failures = 0;
    const char *bad[] = { "7junk", "-1", "+7", " 7", "7 ", "",
                         "18446744073709551616" };
    char option[96];
    char *args[] = { "z23", "--metaverse-broker", dir_arg, option, "--listen" };
    for (size_t b = 0; b < sizeof(bad) / sizeof(bad[0]); b++) {
        snprintf(option, sizeof(option), "%s%s", prefix, bad[b]);
        for (int argc = 4; argc <= 5; argc++)
            MB_CHECK(option, agent_broker_mode_main(argc, args) == 2);
    }
    if (limit < ULLONG_MAX) {
        snprintf(option, sizeof(option), "%s%llu", prefix, limit + 1);
        MB_CHECK("identity above native range refuses pair setup",
                 agent_broker_mode_main(4, args) == 2);
        MB_CHECK("identity above native range refuses listener setup",
                 agent_broker_mode_main(5, args) == 2);
    }
    return failures;
}

static int mb_identity_valid(char *dir_arg, const char *prefix,
                             unsigned long long limit)
{
    int failures = 0;
    unsigned long long good[] = { 0, 7, limit };
    char option[96];
    char *args[] = { "z23", "--metaverse-broker", dir_arg, option, "--listen" };
    MB_CHECK("omitted identity reaches mkdir", agent_broker_mode_main(3, args) == 3);
    for (size_t b = 0; b < sizeof(good) / sizeof(good[0]); b++) {
        snprintf(option, sizeof(option), "%s%llu", prefix, good[b]);
        MB_CHECK("valid identity reaches pair mkdir", agent_broker_mode_main(4, args) == 3);
        MB_CHECK("valid identity reaches listener mkdir", agent_broker_mode_main(5, args) == 3);
    }
    return failures;
}
#endif

static int mb_identity_options(void)
{
    int failures = 0;
#if !defined(_WIN32)
    char parent[PATH_MAX], dir[PATH_MAX + 16], dir_arg[PATH_MAX + 32];
    int fd = test_mkstemp(parent, sizeof(parent), "broker-identity");
    MB_CHECK("identity fixture file", fd >= 0);
    if (fd < 0)
        return failures;
    MB_CHECK("identity fixture close", close(fd) == 0);
    /* A regular-file parent makes setup return 3 before spawning or listening. */
    snprintf(dir, sizeof(dir), "%s/child", parent);
    snprintf(dir_arg, sizeof(dir_arg), "--broker-dir=%s", dir);
    unsigned long long uid_max = (uid_t)-1, gid_max = (gid_t)-1;
    unsigned long long agent_max = uid_max < gid_max ? uid_max : gid_max;
    failures += mb_identity_invalid(dir_arg, "--agent-uid=", agent_max);
    failures += mb_identity_invalid(dir_arg, "--expect-uid=", uid_max);
    failures += mb_identity_valid(dir_arg, "--agent-uid=", agent_max);
    failures += mb_identity_valid(dir_arg, "--expect-uid=", uid_max);
    struct stat st;
    MB_CHECK("identity fixture remains a file", lstat(parent, &st) == 0 && S_ISREG(st.st_mode));
    MB_CHECK("identity creates no child directory", lstat(dir, &st) < 0 && errno == ENOTDIR);
    MB_CHECK("identity fixture removed", unlink(parent) == 0);
#endif
    return failures;
}

int test_metaverse_agent_broker(void)
{
    printf("\n=== metaverse confined-agent broker (adversarial) ===\n");
    int failures = 0;

    test_make_tmpdir(g_dir, sizeof(g_dir), "mvagent", "root");

    failures += mb_identity_options();
    failures += mb_scratch_path_bounds();

    failures += mb_codec();
    failures += mb_grant();
    failures += mb_audit();
    failures += mb_money_portfolio();
    failures += mb_status_path_bounds();
    failures += mb_peercred();
    failures += mb_sender_cred();
    failures += mb_socket_identity();

    int abi = os_sandbox_landlock_abi();
    bool seccomp = os_sandbox_seccomp_supported();
    printf("agent_broker: landlock ABI = %d, seccomp = %d\n", abi, (int)seccomp);

#if !defined(_WIN32)
    char self_exe[512] = { 0 };
    bool have_self = os_proc_exe_path(self_exe, sizeof(self_exe));

    if (abi >= 1 && seccomp && have_self && self_exe[0]) {
        struct mb_child_run run;

        /* (f)(g)(h): the hostile script probes what it must not reach. */
        failures += mb_run_child(self_exe, "hostile", "hostile", 2, &run);
        if (run.spawned) {
            failures += mb_confinement_assertions(&run, "hostile");
            /* DENIED, never merely absent — an ENOENT here would prove only
             * that a file happened to be missing. */
            MB_CHECK("/etc/passwd denied with EACCES",
                     strstr(run.report, "\"/etc/passwd\":\"EACCES\"") != NULL);
            MB_CHECK("/etc/shadow denied with EACCES",
                     strstr(run.report, "\"/etc/shadow\":\"EACCES\"") != NULL);
            MB_CHECK("/root denied with EACCES",
                     strstr(run.report, "\"/root\":\"EACCES\"") != NULL);
            MB_CHECK("/home denied with EACCES",
                     strstr(run.report, "\"/home\":\"EACCES\"") != NULL);
        }

        /* (i) the well-behaved script, including the replay. */
        failures += mb_run_child(self_exe, "inspect", "inspect", 4, &run);
        if (run.spawned)
            failures += mb_confinement_assertions(&run, "inspect");

        char doc[8192];
        MB_CHECK("status names a directory that never hosted a broker",
                 agent_broker_render_status_json(g_dir, doc, sizeof(doc)) > 0 &&
                 strstr(doc, "\"broker_state_present\":false") != NULL);
    } else {
        printf("agent_broker: kernel lacks Landlock+seccomp (or no self exe) — "
               "skipping the confinement assertions; the boundary is not "
               "claimed on such a host\n");
    }
#else
    printf("agent_broker: SKIP (Windows): confined-child boundary assertions "
           "need Landlock + seccomp + fork\n");
#endif

    (void)test_rm_rf_recursive(g_dir);
    printf("=== metaverse confined-agent broker complete: %d failure(s) ===\n",
           failures);
    return failures;
}
