/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The broker's authority end to end: a real temporary datadir, content
 * property, property catalog and grant store, with a live canonical
 * decision on every request and no fixture symbol or data on the path.
 *
 * Converse claim: an authority the operator changes while a broker session
 * is running changes that session's very next answer. A broker that
 * snapshotted its grant at bind time would pass every positive test and
 * fail the negatives; t6_stale_snapshot_would_pass() shows the same rules
 * over a pre-revoke snapshot still say YES.
 *
 *   T1  a real content property inspected through the real catalog under
 *       a real canonical grant
 *   T2  the production path names no fixture symbol and resolves no fixture id
 *   T3  no grant source => fail closed; registration alone grants nothing
 *   T4  revoke while the SAME session runs => the next request is DENIED
 *   T5  the authority clock moves past expiry => the next request is DENIED
 *   T6  why a snapshotting implementation would pass T4/T5 anyway
 *   T10 fork order: no grant and no signing key exist before the child is
 *       spawned; source order is spawn -> audit -> bind
 *   T11 no datadir or catalog work runs under the grant-store mutex
 *   T12 a mutation refuses by name and mints NO canonical receipt
 *   T13 the authority-generation recheck fires, retries once, then declines
 *   T15 ENUMERATE_PROPERTIES is never served as INSPECT_PROPERTY
 *
 * T14 is a pin in test_metaverse_vocabulary.c.
 */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "base/hex.h"
#include "json/json.h"
#include "metaverse/property_action.h"
#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "services/agent_broker_provider.h"
#include "services/property_catalog.h"
#include "services/property_grant_service.h"
#include "session/agent_broker.h"
#include "session/agent_broker_proto.h"
#include "session/agent_broker_vocab.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BA_CHECK(name, expr) do { \
    printf("broker_authority: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* The principal the canonical grant names; the broker takes the actor from
 * the bound grant, never the wire. */
#define BA_HOLDER "w1d-inspecting-agent"

/* ── the authority clock ─────────────────────────────────────────────────────
 * Expiry is measured against the grant service's clock; tests move this
 * offset instead of sleeping. */
static int64_t g_now_unix = 1800000000LL;
static int64_t g_height;

static void ba_clock(int64_t *now_unix, int64_t *height, void *ctx)
{
    (void)ctx;
    if (now_unix) *now_unix = g_now_unix;
    if (height) *height = g_height;
}

/* ── the real property ───────────────────────────────────────────────────────
 * A real blob in a real store under a temporary datadir; its id is the
 * store's own manifest root. */
struct ba_fixture {
    char dd[256];
    uint8_t root[32];
    struct metaverse_property_id id;
    char id_text[METAVERSE_ID_TEXT_MAX];
};

static bool ba_make_property(struct ba_fixture *f, const char *tag)
{
    static const uint8_t bytes[] =
        "w1d: a real content property, owned by nobody and provable by anyone";
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dd, sizeof(f->dd), "broker_authority", tag);

    struct vcs_package_store *store =
        vcs_package_store_open(f->dd, 4u * 1024u * 1024u);
    if (!store)
        return false;
    bool ok = vcs_blob_put_to(store, bytes, sizeof(bytes) - 1, f->root) ==
              VCS_BLOB_OK;
    vcs_package_store_close(store);
    if (!ok)
        return false;

    char hex[65];
    zcl_hex_encode(f->root, 32, hex);
    snprintf(f->id_text, sizeof(f->id_text), "content:%s", hex);
    return metaverse_property_id_parse(f->id_text, &f->id);
}

/* One canonical grant over exactly that property (SCOPE_IDS). */
static void ba_grant(struct metaverse_grant *g, const struct ba_fixture *f,
                     metaverse_query_set queries, metaverse_action_set actions)
{
    memset(g, 0, sizeof(g[0]));
    snprintf(g->holder, sizeof(g->holder), "%s", BA_HOLDER);
    snprintf(g->issuer, sizeof(g->issuer), "w1d-operator");
    g->scope_form = METAVERSE_SCOPE_IDS;
    g->ids[0] = f->id;
    g->id_count = 1;
    g->queries = queries;
    g->actions = actions;
    g->max_value_zat = 100000000;
    g->created_unix = g_now_unix;
}

static void ba_req(struct mvap_request *r, uint32_t verb,
                   const struct ba_fixture *f, uint32_t request_id)
{
    memset(r, 0, sizeof(*r));
    r->verb = verb;
    r->request_id = request_id;
    r->kind = MVAP_KIND_CONTENT;
    if (f)
        memcpy(r->property_id, f->root, MVAP_PROPERTY_ID_LEN);
}

/* Bind a session to the composed production provider. The reference is a
 * file static because the session borrows it. */
static struct agent_authority_ref g_authority;

static bool ba_bind(struct agent_broker_session *s, char *why, size_t why_cap)
{
    memset(s, 0, sizeof(*s));
    return agent_broker_session_bind(s, &g_authority, why, why_cap);
}

/* Read source text; unreadable or NUL-bearing input is a failure, never a skip. */
static size_t ba_slurp(const char *path, char *out, size_t cap)
{
    FILE *fp = fopen(path, "re");
    if (!fp)
        return 0;
    size_t n = fread(out, 1, cap - 1, fp);
    (void)fclose(fp);
    out[n] = '\0';
    if (memchr(out, '\0', n) != NULL)
        return 0;
    return n;
}

static int t2_source_text_refuses_nul(void)
{
    int failures = 0;
    static const char nul_source[] =
        "/* clean */\n\0agent_broker_fixture_ops\n";
    static const char ascii_source[] = "/* clean */\n";
    const char *const sources[] = { nul_source, ascii_source };
    const size_t lengths[] = { sizeof(nul_source) - 1,
                               sizeof(ascii_source) - 1 };
    char dd[256], path[512], out[64];
    test_make_tmpdir(dd, sizeof(dd), "broker_authority", "t2_source_text");
    snprintf(path, sizeof(path), "%s/source.c", dd);
    for (size_t i = 0; i < 2; i++) {
        FILE *fp = fopen(path, "wb");
        BA_CHECK("T2: source-text fixture opens", fp != NULL);
        if (!fp)
            break;
        bool written = fwrite(sources[i], 1, lengths[i], fp) == lengths[i];
        int closed = fclose(fp);
        BA_CHECK("T2: source-text fixture writes and closes",
                 written && closed == 0);
        if (!written || closed != 0)
            break;
        size_t n = ba_slurp(path, out, sizeof(out));
        if (i == 0) {
            BA_CHECK("T2: embedded NUL refuses before substring decisions",
                     n == 0);
        } else {
            BA_CHECK("T2: ordinary ASCII source remains readable",
                     n == lengths[i] &&
                     memcmp(out, ascii_source, sizeof(ascii_source)) == 0);
        }
    }
    BA_CHECK("T2: source-text fixture cleanup succeeds",
             test_rm_rf_recursive(dd) == 0);
    return failures;
}

/* ── T1 ─────────────────────────────────────────────────────────────────────*/

static int t1_real_property_inspect(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t1")) {
        BA_CHECK("T1: the real content fixture was created", false);
        return failures;
    }

    /* The catalog answers about it directly, so a later broker answer can
     * be compared against the authority. */
    struct metaverse_property_view view;
    struct zcl_result r = property_catalog_show(f.dd, &f.id, &view);
    BA_CHECK("T1: the real catalog reports the blob present",
             r.ok && view.status == METAVERSE_STATUS_PRESENT &&
             view.determined);

    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY, 0);
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T1: the canonical grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    agent_broker_provider_compose_explicit(f.dd, g.grant_id, NULL);
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T1: the production provider binds the named grant",
             ba_bind(&s, why, sizeof(why)));

    struct mvap_request req;
    ba_req(&req, MVAP_VERB_INSPECT, &f, 1);
    struct mvap_response resp;
    agent_broker_handle(&s, &req, &resp);

    BA_CHECK("T1: a confined INSPECT of the real property is SERVED",
             resp.status == MVAP_OK);
    BA_CHECK("T1: the answer names the catalog's kind, not the agent's claim",
             strstr(resp.body, "\"kind\":\"content\"") != NULL);
    /* The detail is the real projection's language (authority and evidence
     * grade); no fixture consults vcs.blob_store. */
    BA_CHECK("T1: the answer carries the real authority source",
             strstr(resp.body, "authority=vcs.blob_store") != NULL);
    BA_CHECK("T1: the answer carries the real settlement class",
             strstr(resp.body, "settlement=content_addressed") != NULL);

    /* No fixture data: fixture ids are SHA3 over a fixed domain tag, so the
    uint8_t fix[MVAP_PROPERTY_ID_LEN];
     * served root must not be one. */
    uint8_t fix[MVAP_PROPERTY_ID_LEN];
    agent_broker_fixture_property_id(0, fix);
    BA_CHECK("T1: the property served is the store's root, not a fixture id",
             memcmp(fix, f.root, MVAP_PROPERTY_ID_LEN) != 0);

    /* A property the grant does not name is refused, so the above is a
     * decision and not a rubber stamp. */
    struct mvap_request other;
    ba_req(&other, MVAP_VERB_INSPECT, NULL, 2);
    memcpy(other.property_id, fix, MVAP_PROPERTY_ID_LEN);
    struct mvap_response oresp;
    agent_broker_handle(&s, &other, &oresp);
    BA_CHECK("T1: an out-of-scope property is refused by the same session",
             oresp.status != MVAP_OK);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T2 ─────────────────────────────────────────────────────────────────────*/

/* Two proofs: the source scan shows production units do not name the
 * fixture; the behavioural check shows the provider does not answer for it. */
static int t2_no_fixture_on_the_production_path(void)
{
    int failures = 0;
    static const char *const production[] = {
        "engine/entry/main.c",
        "cognition/services/src/agent_broker_provider.c",
        "cognition/services/src/agent_broker_catalog_seam.c",
    };
    static const char *const fixture_symbols[] = {
        "agent_broker_fixture_ops",
        "agent_broker_install_fixture_provider",
        "agent_broker_fixture_set_grant",
        "agent_broker_fixture_revoke",
    };
    static char buf[512 * 1024];

    for (size_t i = 0; i < sizeof(production) / sizeof(production[0]); i++) {
        char name[192];
        size_t n = ba_slurp(production[i], buf, sizeof(buf));
        snprintf(name, sizeof(name), "T2: %s is readable (run from the "
                                     "repository root)", production[i]);
        BA_CHECK(name, n > 0);
        if (!n)
            continue;
        for (size_t k = 0; k < sizeof(fixture_symbols) / sizeof(char *); k++) {
            snprintf(name, sizeof(name), "T2: %s never names %s",
                     production[i], fixture_symbols[k]);
            BA_CHECK(name, strstr(buf, fixture_symbols[k]) == NULL);
        }
    }

    /* Behavioural: a fixture property under a covering grant finds nothing
     * because the real catalog holds nothing at that root. */
    struct ba_fixture f;
    if (!ba_make_property(&f, "t2")) {
        BA_CHECK("T2: the real datadir was created", false);
        return failures;
    }
    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY, 0);
    /* Widen to KINDS so the refusal cannot be the id scope. */
    g.scope_form = METAVERSE_SCOPE_KINDS;
    g.id_count = 0;
    g.kinds = metaverse_kind_bit(METAVERSE_KIND_CONTENT);
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T2: the kind-scoped grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    agent_broker_provider_compose_explicit(f.dd, g.grant_id, NULL);
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T2: the production provider binds", ba_bind(&s, why, sizeof(why)));

    struct mvap_request req;
    ba_req(&req, MVAP_VERB_INSPECT, NULL, 1);
    agent_broker_fixture_property_id(0, req.property_id);
    struct mvap_response resp;
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T2: the production provider resolves NO fixture property",
             resp.status == MVAP_ERR_NOT_FOUND);

    /* The real property under the same grant is served, so the refusal
     * above is about the fixture. */
    struct mvap_request real_req;
    ba_req(&real_req, MVAP_VERB_INSPECT, &f, 2);
    struct mvap_response real_resp;
    agent_broker_handle(&s, &real_req, &real_resp);
    BA_CHECK("T2: the same grant still serves the REAL property",
             real_resp.status == MVAP_OK);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T3 ─────────────────────────────────────────────────────────────────────*/

static int t3_no_grant_source_fails_closed(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t3")) {
        BA_CHECK("T3: the real datadir was created", false);
        return failures;
    }
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });

    /* A grant exists in the store; the provider does not reach for it
     * unless the operator named it. */
    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY, 0);
    BA_CHECK("T3: a grant exists in the store",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    struct agent_broker_session s;
    char why[192];

    agent_broker_provider_compose_explicit(f.dd, NULL, NULL);
    BA_CHECK("T3: registration alone binds NO authority",
             !ba_bind(&s, why, sizeof(why)));
    BA_CHECK("T3: the refusal is named, not silent",
             strstr(why, "UNGRANTED") != NULL &&
             strstr(agent_broker_provider_last_refusal(), "UNGRANTED") != NULL);

    /* The ungranted session refuses a real property a stored grant would
     * have permitted. */
    struct mvap_request req;
    ba_req(&req, MVAP_VERB_INSPECT, &f, 1);
    struct mvap_response resp;
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T3: an ungranted session refuses with DENIED_NO_GRANT",
             resp.status == MVAP_ERR_DENIED_NO_GRANT);
    BA_CHECK("T3: nothing was dispatched", s.requests_denied == 1);

    /* Two named sources is a refusal; picking one would be guessing. */
    agent_broker_provider_compose_explicit(f.dd, g.grant_id, "/tmp/does-not-exist");
    BA_CHECK("T3: naming both a grant id and a grant spec is refused",
             !ba_bind(&s, why, sizeof(why)));

    /* A named grant id the store does not hold fails closed. */
    agent_broker_provider_compose_explicit(f.dd, "0123456789abcdef0123456789abcdef",
                                           NULL);
    BA_CHECK("T3: an unknown grant id binds nothing",
             !ba_bind(&s, why, sizeof(why)));

    /* No datadir is a refusal rather than a guess at the live node. */
    agent_broker_provider_compose_explicit(NULL, g.grant_id, NULL);
    BA_CHECK("T3: no datadir is refused rather than guessed",
             !ba_bind(&s, why, sizeof(why)) && strstr(why, "datadir") != NULL);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T4 / T5 / T6 ───────────────────────────────────────────────────────────*/

/* T4. Revoke the LIVE grant while this session object keeps running.
 *
 * A snapshotting session (T6) would keep authorizing from its bind-time
 * copy. The session instead holds `const struct agent_authority_ref *`,
 * an id plus refuse-only narrowing and no rights. */
static int t4_revoke_lands_on_a_running_session(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t4")) {
        BA_CHECK("T4: the real datadir was created", false);
        return failures;
    }
    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY, 0);
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T4: the grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    agent_broker_provider_compose_explicit(f.dd, g.grant_id, NULL);
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T4: the session binds", ba_bind(&s, why, sizeof(why)));

    struct mvap_request req;
    struct mvap_response resp;
    ba_req(&req, MVAP_VERB_INSPECT, &f, 1);
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T4: the first inspect is served", resp.status == MVAP_OK);

    /* The operator revokes. Nothing touches the session. */
    BA_CHECK("T4: the operator revokes the live grant",
             property_grant_service_revoke(g.grant_id) == PROPERTY_GRANT_OK);

    ba_req(&req, MVAP_VERB_INSPECT, &f, 2);
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T4: the SAME running session now refuses, by name",
             resp.status == MVAP_ERR_DENIED_REVOKED);
    BA_CHECK("T4: the refusal happened at authorize, before any catalog work",
             strstr(resp.body, "\"stage\":\"authorize\"") != NULL);

    /* T6: the pure rules over a pre-revoke snapshot still say OK; what
     * differs is that the decision path re-reads the store. */
    struct property_grant_authority_snapshot stale;
    memset(&stale, 0, sizeof(stale));
    stale.grant = g;                       /* the record as it was at bind */
    stale.grant.revoked = false;
    struct metaverse_query_request q;
    memset(&q, 0, sizeof(q));
    snprintf(q.actor, sizeof(q.actor), "%s", BA_HOLDER);
    q.property = f.id;
    q.query = METAVERSE_QUERY_INSPECT_PROPERTY;
    q.now_unix = g_now_unix;
    BA_CHECK("T6: the same rules over a PRE-revoke copy still say OK — which "
             "is what a snapshotting broker would have answered",
             metaverse_grant_query_check(&stale.grant, NULL, 0, &q) ==
                 METAVERSE_GRANT_OK);
    /* Over the CURRENT record they refuse, so the difference is the read. */
    struct metaverse_grant now;
    BA_CHECK("T6: the same rules over the CURRENT record refuse",
             property_grant_service_get(g.grant_id, &now) ==
                     PROPERTY_GRANT_OK &&
             metaverse_grant_query_check(&now, NULL, 0, &q) ==
                 METAVERSE_GRANT_REVOKED);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* T5. Expiry, on the authority's own clock: the provider takes the record
 * and the clock from the same snapshot on every call, so an expiry that
 * just passed is seen by the next request of a running session. */
static int t5_expiry_lands_on_a_running_session(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t5")) {
        BA_CHECK("T5: the real datadir was created", false);
        return failures;
    }
    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY, 0);
    g.expires_unix = g_now_unix + 3600;
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T5: the expiring grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    agent_broker_provider_compose_explicit(f.dd, g.grant_id, NULL);
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T5: the session binds", ba_bind(&s, why, sizeof(why)));

    struct mvap_request req;
    struct mvap_response resp;
    ba_req(&req, MVAP_VERB_INSPECT, &f, 1);
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T5: the inspect is served before expiry", resp.status == MVAP_OK);

    const int64_t saved = g_now_unix;
    g_now_unix += 7200;                     /* past the grant's expiry */

    ba_req(&req, MVAP_VERB_INSPECT, &f, 2);
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T5: the SAME running session refuses once the grant expired",
             resp.status == MVAP_ERR_DENIED_EXPIRED);

    g_now_unix = saved;
    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T10 ────────────────────────────────────────────────────────────────────*/

static int t10_fork_order(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t10")) {
        BA_CHECK("T10: the real datadir was created", false);
        return failures;
    }
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });

    /* A grant SPECIFICATION carries the most authority-shaped material;
     * composing it must still mint nothing. */
    char spec[512];
    snprintf(spec, sizeof(spec), "%s/grant.json", f.dd);
    FILE *fp = fopen(spec, "we");
    if (fp) {
        (void)fprintf(fp,
                      "{\"holder\":\"%s\",\"issuer\":\"w1d-operator\","
                      "\"scope\":\"ids\",\"ids\":[\"%s\"],"
                      "\"queries\":\"inspect_property\"}",
                      BA_HOLDER, f.id_text);
        (void)fclose(fp);
    }
    BA_CHECK("T10: the grant specification was written", fp != NULL);

    agent_broker_provider_compose_explicit(f.dd, NULL, spec);

    /* Before the fork the process holds no grant and no receipt signing key. */
    struct metaverse_grant listed[4];
    uint8_t pk[METAVERSE_PUBKEY_LEN];
    BA_CHECK("T10: composition mints NO grant",
             property_grant_service_list(NULL, listed, 4) == 0);
    BA_CHECK("T10: composition establishes NO receipt signing key",
             !property_grant_service_signer_pubkey(pk));

    /* Binding happens after the fork, and it is what mints. */
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T10: bind mints the grant the specification described",
             ba_bind(&s, why, sizeof(why)));
    BA_CHECK("T10: the grant exists only after bind",
             property_grant_service_list(NULL, listed, 4) == 1);

    struct mvap_request req;
    struct mvap_response resp;
    ba_req(&req, MVAP_VERB_INSPECT, &f, 1);
    agent_broker_handle(&s, &req, &resp);
    BA_CHECK("T10: the minted grant really authorizes the real property",
             resp.status == MVAP_OK);

    /* The order, read out of the mode's source: spawn the confined child,
     * open the audit log, bind the authority. */
    static char buf[512 * 1024];
    size_t n = ba_slurp("cognition/modules/session/src/agent_broker_modes.c", buf,
                        sizeof(buf));
    BA_CHECK("T10: the broker mode source is readable (run from the "
             "repository root)", n > 0);
    if (n > 0) {
        const char *spawn = strstr(buf, "agent_broker_spawn_confined(");
        const char *audit = strstr(buf, "agent_audit_open(");
        const char *bind  = strstr(buf, "broker_bind(argc, argv, &s, &authority)");
        const char *bind_helper = strstr(buf, "static void broker_bind(");
        const char *session_bind = bind_helper
            ? strstr(bind_helper, "agent_broker_session_bind(") : NULL;
        BA_CHECK("T10: the binding helper binds the live authority",
                 bind_helper && session_bind && bind && session_bind < bind);
        BA_CHECK("T10: the mode spawns, then audits, then binds",
                 spawn && audit && bind && spawn < audit && audit < bind);
    }

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T11 / T13 ──────────────────────────────────────────────────────────────*/

/* The catalog probe: records whether the grant-store mutex was held while
 * it ran (T11) and how many times it was called (T13). */
struct ba_probe {
    int calls;
    int lock_held_calls;
    int perturb_calls;      /* bump the authority generation on this many calls */
    char controller[METAVERSE_PRINCIPAL_MAX + 1];
    int64_t revision;
};

static bool ba_lookup(const struct metaverse_property_id *id,
                      struct metaverse_catalog_view *out, void *ctx)
{
    struct ba_probe *p = ctx;
    p->calls++;
    if (property_grant_service_test_store_lock_busy())
        p->lock_held_calls++;

    /* Deliberate perturbation, legal because the store mutex is not held
     * here (T11): minting a decoy grant moves the store-wide authority
     * generation without touching the grant under decision. */
    if (p->perturb_calls > 0) {
        p->perturb_calls--;
        struct metaverse_grant decoy;
        memset(&decoy, 0, sizeof(decoy));
        snprintf(decoy.holder, sizeof(decoy.holder), "decoy");
        snprintf(decoy.issuer, sizeof(decoy.issuer), "decoy");
        decoy.scope_form = METAVERSE_SCOPE_KINDS;
        decoy.kinds = metaverse_kind_bit(METAVERSE_KIND_CONTENT);
        decoy.queries = METAVERSE_QUERY_INSPECT_PROPERTY;
        (void)property_grant_service_mint(&decoy);
    }

    memset(out, 0, sizeof(*out));
    out->id = *id;
    snprintf(out->controller, sizeof(out->controller), "%s", p->controller);
    out->revision = p->revision;
    return true;
}

static int t11_no_catalog_work_under_the_lock(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t11")) {
        BA_CHECK("T11: the real datadir was created", false);
        return failures;
    }
    struct ba_probe probe;
    memset(&probe, 0, sizeof(probe));
    snprintf(probe.controller, sizeof(probe.controller), "%s", BA_HOLDER);
    probe.revision = 7;

    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY,
             metaverse_action_bit(METAVERSE_ACTION_HOST));
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .catalog_lookup = ba_lookup, .catalog_ctx = &probe,
        .clock = ba_clock });
    BA_CHECK("T11: the grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    struct metaverse_action_request areq;
    memset(&areq, 0, sizeof(areq));
    snprintf(areq.actor, sizeof(areq.actor), "%s", BA_HOLDER);
    areq.property = f.id;
    areq.action = METAVERSE_ACTION_HOST;

    struct property_grant_plan plan;
    BA_CHECK("T11: the plan is quoted",
             property_grant_service_plan(g.grant_id, &areq, &plan) ==
                 PROPERTY_GRANT_OK);
    struct property_grant_commit_result cr;
    BA_CHECK("T11: the plan commits",
             property_grant_service_commit(plan.plan_id, NULL, &cr) ==
                 PROPERTY_GRANT_OK);

    BA_CHECK("T11: the catalog was consulted by BOTH stages",
             probe.calls >= 2);
    BA_CHECK("T11: the grant-store mutex was NEVER held while the catalog ran",
             probe.lock_held_calls == 0);

    property_grant_service_reset();
    property_grant_service_configure(NULL);
    test_rm_rf_recursive(f.dd);
    return failures;
}

static int t13_authority_generation_recheck(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t13")) {
        BA_CHECK("T13: the real datadir was created", false);
        return failures;
    }
    struct metaverse_grant g;
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY,
             metaverse_action_bit(METAVERSE_ACTION_HOST));

    /* (a) The recheck itself: snapshot, move the store, recheck. */
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T13: the grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    struct property_grant_authority_snapshot snap;
    BA_CHECK("T13: a snapshot is taken",
             property_grant_service_snapshot(g.grant_id, &snap) ==
                 PROPERTY_GRANT_OK);
    BA_CHECK("T13: an unmoved store rechecks clean",
             property_grant_service_recheck(&snap) == PROPERTY_GRANT_OK);

    uint64_t before = property_grant_service_authority_generation();
    struct metaverse_grant decoy;
    ba_grant(&decoy, &f, METAVERSE_QUERY_INSPECT_PROPERTY, 0);
    BA_CHECK("T13: an unrelated mint moves the store-wide generation",
             property_grant_service_mint(&decoy) == PROPERTY_GRANT_OK &&
             property_grant_service_authority_generation() > before);
    BA_CHECK("T13: the recheck refuses a decision over the moved state",
             property_grant_service_recheck(&snap) ==
                 PROPERTY_GRANT_AUTHORITY_CHANGED);

    /* (b) ONE retry: perturb once from the catalog callback, so the first
     *     recheck fails and the second succeeds. */
    struct ba_probe probe;
    memset(&probe, 0, sizeof(probe));
    snprintf(probe.controller, sizeof(probe.controller), "%s", BA_HOLDER);
    probe.revision = 1;
    probe.perturb_calls = 1;
    property_grant_service_configure(&(struct property_grant_env){
        .catalog_lookup = ba_lookup, .catalog_ctx = &probe,
        .clock = ba_clock });

    struct metaverse_action_request areq;
    memset(&areq, 0, sizeof(areq));
    snprintf(areq.actor, sizeof(areq.actor), "%s", BA_HOLDER);
    areq.property = f.id;
    areq.action = METAVERSE_ACTION_HOST;

    struct property_grant_plan plan;
    BA_CHECK("T13: a decision disturbed ONCE retries and then succeeds",
             property_grant_service_plan(g.grant_id, &areq, &plan) ==
                 PROPERTY_GRANT_OK);
    BA_CHECK("T13: it really did run twice", probe.calls == 2);

    /* (c) Perturbed EVERY time, the service declines. */
    probe.calls = 0;
    probe.perturb_calls = 16;
    BA_CHECK("T13: a decision disturbed every time returns AUTHORITY_CHANGED",
             property_grant_service_plan(g.grant_id, &areq, &plan) ==
                 PROPERTY_GRANT_AUTHORITY_CHANGED);
    BA_CHECK("T13: and it tried exactly twice, never more", probe.calls == 2);
    BA_CHECK("T13: no catalog call ever saw the store mutex held",
             probe.lock_held_calls == 0);

    property_grant_service_reset();
    property_grant_service_configure(NULL);
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T12 ────────────────────────────────────────────────────────────────────*/

/* Nothing here executes a property mutation: the grant service authorizes,
 * debits a budget and seals a receipt only. HOST is therefore refused by
 * name, with no canonical receipt (a receipt is evidence something
 * happened). */
static int t12_mutation_refuses_and_mints_nothing(void)
{
    int failures = 0;
    struct ba_fixture f;
    if (!ba_make_property(&f, "t12")) {
        BA_CHECK("T12: the real datadir was created", false);
        return failures;
    }
    struct metaverse_grant g;
    /* The grant holds HOST, so the refusal is the missing executor, not
     * the grant. */
    ba_grant(&g, &f, METAVERSE_QUERY_INSPECT_PROPERTY,
             metaverse_action_bit(METAVERSE_ACTION_HOST));
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T12: the HOST-bearing grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    agent_broker_provider_compose_explicit(f.dd, g.grant_id, NULL);
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T12: the session binds", ba_bind(&s, why, sizeof(why)));

    struct mvap_request req;
    struct mvap_response resp;
    ba_req(&req, MVAP_VERB_HOST, &f, 1);
    agent_broker_handle(&s, &req, &resp);

    BA_CHECK("T12: the mutation is refused by its own name",
             resp.status == MVAP_ERR_ACTION_EXECUTOR_UNAVAILABLE);
    BA_CHECK("T12: that name is stable on the wire",
             strcmp(mvap_status_name(MVAP_ERR_ACTION_EXECUTOR_UNAVAILABLE),
                    "ACTION_EXECUTOR_UNAVAILABLE") == 0);
    BA_CHECK("T12: the refusal is not confused with a missing right",
             resp.status != MVAP_ERR_DENIED_ACTION);

    /* No evidence minted: an all-zero receipt id and an empty canonical
     * chain. */
    struct metaverse_receipt receipts[4];
    BA_CHECK("T12: no canonical action receipt exists for the grant",
             property_grant_service_receipts(g.grant_id, receipts, 4) == 0);
    uint8_t zero[MVAP_RECEIPT_ID_LEN];
    memset(zero, 0, sizeof(zero));
    BA_CHECK("T12: the response carries no receipt id",
             memcmp(resp.receipt_id, zero, sizeof(zero)) == 0);

    /* The grant's budget was not touched either. */
    struct metaverse_grant after;
    BA_CHECK("T12: nothing was charged to the grant",
             property_grant_service_get(g.grant_id, &after) ==
                     PROPERTY_GRANT_OK &&
             after.spent_zat == 0);

    /* A query under the same session still works. */
    struct mvap_request q;
    struct mvap_response qresp;
    ba_req(&q, MVAP_VERB_INSPECT, &f, 2);
    agent_broker_handle(&s, &q, &qresp);
    BA_CHECK("T12: the query slice is unaffected", qresp.status == MVAP_OK);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T15 ────────────────────────────────────────────────────────────────────*/

/* No row carries the reserved bit as its action. */
static bool t15_no_verb_dispatches_on_reserved_inspect_bit(void)
{
    bool reserved_bit_is_on_no_row = true;
    for (uint32_t w = 1; w < (uint32_t)MVAP_VERB__COUNT; w++) {
        enum metaverse_action a;
        if (mvap_verb_to_action(w, &a) &&
            (uint32_t)a == METAVERSE_ACTION_RESERVED_INSPECT)
            reserved_bit_is_on_no_row = false;
    }
    return reserved_bit_is_on_no_row;
}

/* Decode keeps them apart: two verbs in, two canonical queries out. */
static bool t15_probes_decode_to_distinct_queries(void)
{
    struct mvap_request probe_i, probe_l;
    memset(&probe_i, 0, sizeof(probe_i));
    probe_i.verb = MVAP_VERB_INSPECT;
    probe_i.kind = MVAP_KIND_CONTENT;
    for (size_t i = 0; i < MVAP_PROPERTY_ID_LEN; i++)
        probe_i.property_id[i] = (uint8_t)(i + 3);
    probe_l = probe_i;
    probe_l.verb = MVAP_VERB_LIST;
    struct metaverse_query_request qri, qrl;
    return mvap_request_to_query_request(&probe_i, BA_HOLDER, 1, 1, &qri) &&
           mvap_request_to_query_request(&probe_l, BA_HOLDER, 1, 1, &qrl) &&
           qri.query == METAVERSE_QUERY_INSPECT_PROPERTY &&
           qrl.query == METAVERSE_QUERY_ENUMERATE_PROPERTIES;
}

/* Enumeration is not inspection, and the property id does not decide which
 * is which.
 *
 * The proof is a 2x2: {INSPECT, ENUMERATE} x {no id, a real id}. The
 * grant is KINDS-scoped and carries BOTH reads, so only which query was
 * asked can refuse. */
static int t15_enumeration_is_never_served_as_inspection(void)
{
    int failures = 0;

    /* The vocabulary: the two reads are two values and neither presents
     * an action bit. */
    enum metaverse_query qi = METAVERSE_QUERY_NONE, ql = METAVERSE_QUERY_NONE;
    BA_CHECK("T15: INSPECT names the canonical INSPECT_PROPERTY",
             mvap_verb_to_query(MVAP_VERB_INSPECT, &qi) &&
                 qi == METAVERSE_QUERY_INSPECT_PROPERTY);
    BA_CHECK("T15: LIST names the canonical ENUMERATE_PROPERTIES",
             mvap_verb_to_query(MVAP_VERB_LIST, &ql) &&
                 ql == METAVERSE_QUERY_ENUMERATE_PROPERTIES);
    BA_CHECK("T15: the two reads are two different canonical values", qi != ql);

    enum metaverse_action ai, al;
    BA_CHECK("T15: neither read has an action bit to offer",
             !mvap_verb_to_action(MVAP_VERB_INSPECT, &ai) &&
                 !mvap_verb_to_action(MVAP_VERB_LIST, &al));
    BA_CHECK("T15: the reserved INSPECT bit encodes to no wire verb",
             mvap_verb_from_action(
                 (enum metaverse_action)METAVERSE_ACTION_RESERVED_INSPECT) ==
                 MVAP_VERB_NONE);

    BA_CHECK("T15: no wire verb dispatches on the reserved INSPECT bit",
             t15_no_verb_dispatches_on_reserved_inspect_bit());

    BA_CHECK("T15: the query projection carries WHICH query, not one bit",
             t15_probes_decode_to_distinct_queries());

    /* ── the 2x2, end to end through the real provider ── */
    struct ba_fixture f;
    if (!ba_make_property(&f, "t15")) {
        BA_CHECK("T15: the real content fixture was created", false);
        return failures;
    }

    struct metaverse_grant g;
    memset(&g, 0, sizeof(g));
    snprintf(g.holder, sizeof(g.holder), "%s", BA_HOLDER);
    snprintf(g.issuer, sizeof(g.issuer), "w1d-operator");
    g.scope_form = METAVERSE_SCOPE_KINDS;
    g.kinds = metaverse_kind_bit(METAVERSE_KIND_CONTENT);
    g.queries = METAVERSE_QUERY_ALL;      /* both reads, so scope cannot refuse */
    g.max_value_zat = 100000000;
    g.created_unix = g_now_unix;

    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = ba_clock });
    BA_CHECK("T15: the both-reads grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    agent_broker_provider_compose_explicit(f.dd, g.grant_id, NULL);
    struct agent_broker_session s;
    char why[192];
    BA_CHECK("T15: the session binds to the both-reads grant",
             ba_bind(&s, why, sizeof(why)));

    static const struct {
        const char *what;
        uint32_t    verb;
        bool        name_a_property;
        int32_t     want;
    } corners[4] = {
        { "an INSPECT that names a property is SERVED",
          MVAP_VERB_INSPECT, true,  MVAP_OK },
        { "an INSPECT that names no property is a PROPERTY refusal",
          MVAP_VERB_INSPECT, false, MVAP_ERR_DENIED_PROPERTY },
        { "an ENUMERATE that names no property is refused by name",
          MVAP_VERB_LIST,    false, MVAP_ERR_QUERY_UNAVAILABLE },
        { "an ENUMERATE that names a REAL property is refused by the same name",
          MVAP_VERB_LIST,    true,  MVAP_ERR_QUERY_UNAVAILABLE },
    };

    for (size_t i = 0; i < 4; i++) {
        struct mvap_request req;
        ba_req(&req, corners[i].verb,
               corners[i].name_a_property ? &f : NULL, (uint32_t)(150 + i));
        struct mvap_response resp;
        agent_broker_handle(&s, &req, &resp);

        char label[176];
        snprintf(label, sizeof(label), "T15: %s", corners[i].what);
        BA_CHECK(label, resp.status == corners[i].want);
    }

    /* An enumeration naming a real property must not come back carrying
     * that property's inspection answer. */
    struct mvap_request enumerate_named;
    ba_req(&enumerate_named, MVAP_VERB_LIST, &f, 160);
    struct mvap_response eresp;
    agent_broker_handle(&s, &enumerate_named, &eresp);
    BA_CHECK("T15: the refused enumeration returns no inspection answer",
             strstr(eresp.body, "authority=vcs.blob_store") == NULL &&
                 strstr(eresp.body, "\"kind\":\"content\"") == NULL);
    BA_CHECK("T15: and it names the refusal that actually applies",
             strstr(eresp.body, "QUERY_UNAVAILABLE") != NULL);

    /* The same session still serves that property's inspection, so the
     * refusals above are about which query was asked. */
    struct mvap_request inspect_named;
    ba_req(&inspect_named, MVAP_VERB_INSPECT, &f, 161);
    struct mvap_response iresp;
    agent_broker_handle(&s, &inspect_named, &iresp);
    BA_CHECK("T15: the same property is still inspectable in the same session",
             iresp.status == MVAP_OK &&
                 strstr(iresp.body, "\"kind\":\"content\"") != NULL);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── entry point ────────────────────────────────────────────────────────────*/

int test_metaverse_broker_authority(void)
{
    int failures = 0;
    printf("=== metaverse_broker_authority: the broker's LIVE authority ===\n");

    failures += t1_real_property_inspect();
    failures += t2_source_text_refuses_nul();
    failures += t2_no_fixture_on_the_production_path();
    failures += t3_no_grant_source_fails_closed();
    failures += t4_revoke_lands_on_a_running_session();
    failures += t5_expiry_lands_on_a_running_session();
    failures += t10_fork_order();
    failures += t11_no_catalog_work_under_the_lock();
    failures += t12_mutation_refuses_and_mints_nothing();
    failures += t13_authority_generation_recheck();
    failures += t15_enumeration_is_never_served_as_inspection();

    property_grant_service_reset();
    property_grant_service_configure(NULL);
    printf("=== metaverse_broker_authority complete: %d failure(s) ===\n",
           failures);
    return failures;
}
