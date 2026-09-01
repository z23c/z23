/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The fixture property catalog and the demo grant — TEST BUILDS ONLY.
 *
 * These used to be reachable from `--metaverse-broker` in a shipped binary:
 * agent_broker_fixture_ops() answered PLAN and COMMIT out of a static array,
 * and build_demo_grant() minted an authority over it. A production operator
 * running the broker therefore got a working-looking broker that authorized
 * actions against two properties that do not exist, with a grant nobody
 * issued. The guard below is what makes that impossible rather than merely
 * discouraged: outside a -DZCL_TESTING build the symbols are not compiled and
 * not declared, so the production path cannot name them, and
 * agent_broker_mode_main() refuses to serve without a registered provider.
 *
 * The only thing that survives into a production build is
 * agent_broker_fixture_property_id(), which derives a deterministic identifier
 * and confers no authority and no behaviour; the confined-agent demo scripts
 * use it to name a target.
 */

#include "session/agent_broker.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "crypto/sha3.h"
#include "platform/rng.h"
#include "session/agent_broker_vocab.h"

#include <stdio.h>
#include <string.h>

#define FIXTURE_TAG "agent.fixture"

const bool agent_broker_fixtures_compiled_in =
#ifdef ZCL_TESTING
    true;
#else
    false;
#endif

void agent_broker_fixture_property_id(size_t index,
                                      uint8_t out[MVAP_PROPERTY_ID_LEN])
{
    if (!out)
        return;
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)"zcl.agent_fixture.property", 26);
    unsigned char i8 = (unsigned char)index;
    sha3_256_write(&c, &i8, 1);
    sha3_256_finalize(&c, out);
}

#ifdef ZCL_TESTING

struct fixture_state {
    uint64_t revision[AGENT_BROKER_FIXTURE_PROPERTIES];
    bool     listed[AGENT_BROKER_FIXTURE_PROPERTIES];
    bool     hosted[AGENT_BROKER_FIXTURE_PROPERTIES];
};
static struct fixture_state g_fixture;

static int fixture_index_of(const uint8_t id[MVAP_PROPERTY_ID_LEN])
{
    for (size_t i = 0; i < AGENT_BROKER_FIXTURE_PROPERTIES; i++) {
        uint8_t want[MVAP_PROPERTY_ID_LEN];
        agent_broker_fixture_property_id(i, want);
        if (memcmp(want, id, MVAP_PROPERTY_ID_LEN) == 0)
            return (int)i;
    }
    return -1;
}

static bool fixture_resolve(const struct mvap_request *req,
                            struct agent_plan *out)
{
    memset(out, 0, sizeof(*out));

    if (mvap_property_id_is_zero(req->property_id)) {
        out->found = true;
        out->kind  = req->kind;
        snprintf(out->detail, sizeof(out->detail), "catalog=fixture count=%d",
                 AGENT_BROKER_FIXTURE_PROPERTIES);
        return true;
    }
    int idx = fixture_index_of(req->property_id);
    if (idx < 0) {
        snprintf(out->detail, sizeof(out->detail),
                 "no property with that id in the fixture catalog");
        return true;                          /* resolved: not found */
    }
    out->found         = true;
    out->kind          = (uint16_t)(idx == 1 ? MVAP_KIND_ZCODE
                                             : MVAP_KIND_CONTENT);
    out->revision      = g_fixture.revision[idx];
    out->owner_matches = true;
    agent_broker_fixture_property_id((size_t)idx, out->content_root);
    snprintf(out->detail, sizeof(out->detail), "fixture index=%d revision=%llu",
             idx, (unsigned long long)out->revision);
    return true;
}

/* A QUERY resolves and nothing more — there is no branch in here that could
 * write, because the fixture's writes live in fixture_commit alone. */
static bool fixture_query(void *ctx, const struct mvap_request *req,
                          struct agent_plan *out)
{
    (void)ctx;
    if (!req || !out)
        LOG_FAIL(FIXTURE_TAG, "null argument in fixture query");
    return fixture_resolve(req, out);
}

static bool fixture_plan(void *ctx, const struct mvap_request *req,
                         struct agent_plan *out)
{
    (void)ctx;
    if (!req || !out)
        LOG_FAIL(FIXTURE_TAG, "null argument in fixture plan");
    return fixture_resolve(req, out);
}

static bool fixture_commit(void *ctx, const struct mvap_request *req,
                           const struct agent_plan *plan,
                           struct agent_commit_outcome *out)
{
    (void)ctx;
    if (!req || !plan || !out)
        LOG_FAIL(FIXTURE_TAG, "null argument in fixture commit");
    memset(out, 0, sizeof(*out));

    int idx = fixture_index_of(req->property_id);
    if (idx < 0)
        LOG_FAIL(FIXTURE_TAG, "commit for a property absent from the fixture");

    /* The commit-time recheck the owner's spec requires: if the revision moved
     * between PLAN and COMMIT the caller planned against a stale view. */
    if (g_fixture.revision[idx] != plan->revision)
        LOG_FAIL(FIXTURE_TAG, "revision moved %llu -> %llu between plan and commit",
                 (unsigned long long)plan->revision,
                 (unsigned long long)g_fixture.revision[idx]);

    /* Effects, keyed by the CANONICAL action rather than by the wire verb, so
     * the fixture cannot invent an effect the vocabulary does not have. The
     * old fixture had `case MVAP_VERB_SELL: listed = true`, which conflated
     * selling with advertising; canonically SELL transfers for value and
     * LIST (list-for-sale) is what advertises. */
    enum metaverse_action action;
    if (!mvap_verb_to_action(req->verb, &action))
        LOG_FAIL(FIXTURE_TAG, "commit for a verb with no canonical action");
    switch (action) {
    case METAVERSE_ACTION_HOST:              g_fixture.hosted[idx] = true; break;
    case METAVERSE_ACTION_LIST_FOR_SALE:     g_fixture.listed[idx] = true; break;
    case METAVERSE_ACTION_PUBLISH_REVISION:
    case METAVERSE_ACTION_UPDATE_POINTER:    g_fixture.revision[idx]++;    break;
    default:                                                               break;
    }

    char root[65];
    zcl_hex_encode(plan->content_root, 32, root);

    int n = snprintf(out->body, sizeof(out->body),
        "{\"kind\":\"%s\",\"revision\":%llu,\"content_root\":\"%s\","
        "\"hosted\":%s,\"listed\":%s}",
        mvap_kind_name(plan->kind),
        (unsigned long long)g_fixture.revision[idx], root,
        g_fixture.hosted[idx] ? "true" : "false",
        g_fixture.listed[idx] ? "true" : "false");
    if (n < 0 || (size_t)n >= sizeof(out->body))
        LOG_FAIL(FIXTURE_TAG, "commit body does not fit %zu bytes",
                 sizeof(out->body));

    /* The fixture is not the property grant service and mints no canonical
     * receipt. Leaving the id zero is the honest answer; the confinement
     * envelope then records "no canonical action receipt" rather than
     * pretending to commit to one. */
    return true;
}

struct agent_broker_node_ops agent_broker_fixture_ops(void)
{
    return (struct agent_broker_node_ops){
        .query = fixture_query, .plan = fixture_plan,
        .commit = fixture_commit, .ctx = NULL };
}

/* ── the demo authority ─────────────────────────────────────────────────── */

/* THE FIXTURE'S AUTHORITY LIVES HERE, NOT IN THE SESSION. That is not a
 * detail of where a variable sits: a session that held its own copy would go
 * on answering out of it after this one was revoked, which is precisely the
 * defect the live-authority seam exists to remove. Every authorize below reads
 * `g_authority` at the instant of the call, so agent_broker_fixture_revoke()
 * and agent_broker_fixture_advance_clock() land on sessions that are already
 * running. */
static struct agent_grant g_authority;
static bool     g_authority_set;
static int64_t  g_clock_skew_ms;
static uint64_t g_authority_generation;

/* INSPECT/LIST as queries plus HOST/PUBLISH_REVISION/SELL as actions, over
 * exactly ONE fixture property. Deliberately narrow — the hostile script's
 * attempts to touch the OTHER property and to TRANSFER are refusals this grant
 * produces by construction, not by a special case in the broker. */
static bool build_demo_grant(struct agent_grant *g)
{
    memset(g, 0, sizeof(*g));
    uint8_t r[8];
    if (!rng_fill(r, sizeof(r)))
        LOG_FAIL(FIXTURE_TAG, "rng_fill refused: cannot mint a demo grant id");
    char id[17];
    zcl_hex_encode(r, sizeof(r), id);
    snprintf(g->grant_id, sizeof(g->grant_id), "%s", id);
    snprintf(g->principal, sizeof(g->principal), "confined-seller-agent");

    uint8_t prop[MVAP_PROPERTY_ID_LEN];
    agent_broker_fixture_property_id(0, prop);
    (void)agent_grant_add_property(g, prop);

    agent_grant_allow_action(g, MVAP_VERB_INSPECT);
    agent_grant_allow_action(g, MVAP_VERB_LIST);
    agent_grant_allow_action(g, MVAP_VERB_HOST);
    agent_grant_allow_action(g, MVAP_VERB_PUBLISH_REVISION);
    agent_grant_allow_action(g, MVAP_VERB_SELL);
    agent_grant_allow_kind(g, MVAP_KIND_CONTENT);
    agent_grant_allow_kind(g, MVAP_KIND_ANY);

    g->max_value_zats       = 100000000;
    g->budget_zats          = 500000000;
    g->rate_limit           = 64;
    g->window_seconds       = 60;
    g->may_delegate         = false;
    g->max_delegation_depth = 0;
    return true;
}

void agent_broker_fixture_set_grant(const struct agent_grant *g)
{
    if (!g)
        return;
    g_authority = *g;
    g_authority_set = true;
    g_clock_skew_ms = 0;
    g_authority_generation++;
}

void agent_broker_fixture_get_grant(struct agent_grant *out)
{
    if (!out)
        return;
    *out = g_authority;
}

void agent_broker_fixture_revoke(void)
{
    if (!g_authority_set)
        return;
    g_authority.revoked = true;
    g_authority.revocation_generation++;
    g_authority_generation++;
}

void agent_broker_fixture_advance_clock(int64_t ms)
{
    g_clock_skew_ms += ms;
    g_authority_generation++;
}

static bool fixture_bind(void *ctx, struct agent_authority_ref *out, char *why,
                         size_t why_cap)
{
    (void)ctx;
    if (!out)
        LOG_FAIL(FIXTURE_TAG, "null authority reference out");
    if (!g_authority_set && !build_demo_grant(&g_authority)) {
        if (why && why_cap)
            snprintf(why, why_cap, "the fixture could not mint a demo grant");
        return false;
    }
    g_authority_set = true;
    memset(out, 0, sizeof(*out));
    snprintf(out->canonical_grant_id, sizeof(out->canonical_grant_id), "%s",
             g_authority.grant_id);
    snprintf(out->principal, sizeof(out->principal), "%s",
             g_authority.principal);
    /* Derived from the grant, never written twice (A6). */
    agent_broker_scope_from_grant(&g_authority, &out->scope);
    out->bound = true;
    return true;
}

static int32_t fixture_authorize(void *ctx,
                                 const struct agent_authority_ref *ref,
                                 const struct mvap_request *req,
                                 int64_t now_ms)
{
    (void)ctx;
    if (!ref || !req)
        return MVAP_ERR_INTERNAL;
    if (!g_authority_set)
        return MVAP_ERR_DENIED_NO_GRANT;
    /* Re-read at the instant of the call. The reference names WHICH authority;
     * the authority itself is read here, so a revoke that landed one
     * microsecond ago is seen. */
    return agent_grant_authorize(&g_authority, req, now_ms + g_clock_skew_ms);
}

static bool fixture_debit(void *ctx, const struct agent_authority_ref *ref,
                          const struct mvap_request *req, int64_t now_ms)
{
    (void)ctx;
    if (!ref || !req || !g_authority_set)
        return false;
    agent_grant_commit_debit(&g_authority, req, now_ms + g_clock_skew_ms);
    g_authority_generation++;
    return true;
}

static bool fixture_status(void *ctx, const struct agent_authority_ref *ref,
                           struct agent_authority_status *out)
{
    (void)ctx;
    if (!ref || !out)
        return false;
    memset(out, 0, sizeof(*out));
    snprintf(out->authority_source, sizeof(out->authority_source), "%s",
             "fixture (test build only)");
    snprintf(out->canonical_grant_id, sizeof(out->canonical_grant_id), "%s",
             g_authority.grant_id);
    snprintf(out->principal, sizeof(out->principal), "%s",
             g_authority.principal);
    out->live_authority = true;
    out->ephemeral = true;
    out->revoked = g_authority.revoked;
    out->budget_zat = g_authority.budget_zats;
    out->spent_zat = g_authority.spent_zats;
    out->authority_generation = g_authority_generation;
    agent_grant_fingerprint(&g_authority, out->fingerprint);
    return true;
}

static struct agent_broker_node_ops fixture_ops_fn(void *ctx)
{
    (void)ctx;
    return agent_broker_fixture_ops();
}

void agent_broker_install_fixture_provider(void)
{
    /* STATIC LIFETIME, deliberately: agent_broker_provider_install() borrows
     * this pointer and the session's authority reference borrows it again. */
    static const struct agent_broker_provider p = {
        .bind      = fixture_bind,
        .authorize = fixture_authorize,
        .debit     = fixture_debit,
        .status    = fixture_status,
        .ops       = fixture_ops_fn,
        .ctx       = NULL,
        .name      = "fixture (test build only)",
    };
    agent_broker_provider_install(&p);
}

#endif /* ZCL_TESTING */
