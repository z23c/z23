/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FULL-REQUEST IDEMPOTENCY: what makes "the same request_id" mean "the same
 * request".
 *
 * THE DEFECT THESE TESTS PIN SHUT. The broker's replay ring used to match on
 * `request_id` alone, with the verb compared at the call site and nothing else
 * compared anywhere. Two things followed, and an ordinary well-behaved client
 * could reach both:
 *
 *   - request_id=7 INSPECT property A, then request_id=7 INSPECT property B,
 *     returned A's answer to a question about B. A confused-deputy read that
 *     the broker manufactured itself, with no refusal on any path.
 *   - Queries were cached, so repeating a request_id after a revocation
 *     returned the old OK without consulting the authority at all. Live
 *     authority, undone by a retry.
 *
 * Coverage, in the lane's numbering:
 *   B1  the canonical request digest: every field of the preimage changes it,
 *       and the two spellings of "the current protocol version" do not
 *   B2  a slot is served only when its stored FIELDS are the same request, so
 *       a digest collision is refused rather than answered
 *   T7  a request_id reused for another PROPERTY is refused by name
 *   T8  a request_id reused with a changed KIND, VALUE, PARAM, VERB or
 *       protocol version is refused; the byte-identical repeat is not
 *   T9  an old QUERY cannot outlive a revocation through the ring
 *   TR  a replay is DISTINGUISHABLE from a first execution in both the reply
 *       body and the audit row, executes nothing, and cannot be repointed
 *
 * T7-T9 run against the REAL production provider — a real /tmp datadir, real
 * content blobs, a real canonical grant, and the real property catalog. TR
 * needs a mutation that actually COMMITS in order to have a first execution to
 * distinguish a replay from, and no production seam in this tree executes a
 * property mutation (that is T12's subject in test_metaverse_broker_authority);
 * so TR, and only TR, drives the test-build fixture seam. That is stated here
 * rather than buried, because "which of these ran against the real thing" is
 * the first question worth asking of this file.
 */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "base/hex.h"
#include "metaverse/property_action.h"
#include "metaverse/property_grant.h"
#include "metaverse/property_id.h"
#include "services/agent_broker_provider.h"
#include "services/property_grant_service.h"
#include "session/agent_broker.h"
#include "session/agent_broker_proto.h"
#include "session/agent_broker_vocab.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BI_CHECK(name, expr) do { \
    printf("broker_idem: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define BI_HOLDER "w1d-idempotent-agent"

static int64_t g_now_unix = 1800000000LL;
static int64_t g_height;

static void bi_clock(int64_t *now_unix, int64_t *height, void *ctx)
{
    (void)ctx;
    if (now_unix) *now_unix = g_now_unix;
    if (height) *height = g_height;
}

/* ── two real properties in one real datadir ────────────────────────────────
 * Both roots are the blob store's OWN manifest roots, so nothing here mints an
 * identifier and the catalog answers about bytes that are actually on disk.
 * TWO of them, because T7's whole point is that the second question must not be
 * answered with the first one's answer — which requires both to be legitimately
 * in scope, so that the refusal can only be the idempotency layer talking. */
struct bi_fixture {
    char dd[256];
    uint8_t root[2][32];
    struct metaverse_property_id id[2];
};

static bool bi_make_properties(struct bi_fixture *f, const char *tag)
{
    static const char *const bytes[2] = {
        "w1d idempotency: the FIRST real content property",
        "w1d idempotency: the SECOND real content property, a different answer",
    };
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->dd, sizeof(f->dd), "broker_idem", tag);

    struct vcs_package_store *store =
        vcs_package_store_open(f->dd, 4u * 1024u * 1024u);
    if (!store)
        return false;
    bool ok = true;
    for (size_t i = 0; i < 2; i++)
        ok = ok && vcs_blob_put_to(store, (const uint8_t *)bytes[i],
                                   strlen(bytes[i]), f->root[i]) == VCS_BLOB_OK;
    vcs_package_store_close(store);
    if (!ok)
        return false;

    for (size_t i = 0; i < 2; i++) {
        char text[METAVERSE_ID_TEXT_MAX];
        char hex[65];
        zcl_hex_encode(f->root[i], 32, hex);
        snprintf(text, sizeof(text), "content:%s", hex);
        if (!metaverse_property_id_parse(text, &f->id[i]))
            return false;
    }
    /* Two DISTINCT properties, or T7 proves nothing. */
    return memcmp(f->root[0], f->root[1], 32) != 0;
}

/* One canonical grant over BOTH properties. */
static void bi_grant(struct metaverse_grant *g, const struct bi_fixture *f)
{
    memset(g, 0, sizeof(g[0]));
    snprintf(g->holder, sizeof(g->holder), "%s", BI_HOLDER);
    snprintf(g->issuer, sizeof(g->issuer), "w1d-operator");
    g->scope_form = METAVERSE_SCOPE_IDS;
    g->ids[0] = f->id[0];
    g->ids[1] = f->id[1];
    g->id_count = 2;
    g->queries = METAVERSE_QUERY_INSPECT_PROPERTY;
    g->actions = metaverse_action_bit(METAVERSE_ACTION_HOST);
    g->max_value_zat = 100000000;
    g->created_unix = g_now_unix;
}

static void bi_req(struct mvap_request *r, uint32_t verb,
                   const struct bi_fixture *f, size_t which,
                   uint32_t request_id)
{
    memset(r, 0, sizeof(*r));
    r->verb = verb;
    r->request_id = request_id;
    r->kind = MVAP_KIND_CONTENT;
    if (f)
        memcpy(r->property_id, f->root[which], MVAP_PROPERTY_ID_LEN);
}

/* The session borrows its authority reference and must not outlive it, so the
 * reference is a file static — there is no grant inside the session to hold
 * instead. */
static struct agent_authority_ref g_authority;

static bool bi_bind_production(struct agent_broker_session *s,
                               const struct bi_fixture *f,
                               const char *grant_id)
{
    agent_broker_provider_compose_explicit(f->dd, grant_id, NULL);
    memset(s, 0, sizeof(*s));
    char why[192];
    return agent_broker_session_bind(s, &g_authority, why, sizeof(why));
}

/* ── B1: the canonical request digest ───────────────────────────────────────*/

static int b1_digest_covers_every_field(void)
{
    int failures = 0;

    struct mvap_request base;
    memset(&base, 0, sizeof(base));
    base.verb       = MVAP_VERB_INSPECT;
    base.request_id = 4242;
    base.kind       = MVAP_KIND_CONTENT;
    base.value_zats = 7;
    base.version    = MVAP_VERSION;
    for (size_t i = 0; i < MVAP_PROPERTY_ID_LEN; i++)
        base.property_id[i] = (uint8_t)(i + 1);
    snprintf(base.param, sizeof(base.param), "counterparty-one");

    uint8_t d0[32];
    mvap_request_digest(&base, "grant-alpha", d0);

    /* Determinism first: without it every check below is meaningless. */
    struct mvap_request same = base;
    uint8_t dsame[32];
    mvap_request_digest(&same, "grant-alpha", dsame);
    BI_CHECK("B1: an identical request digests identically",
             memcmp(d0, dsame, 32) == 0);

    /* One perturbation per preimage field. Each must MOVE the digest — a field
     * that does not is a field an agent can change while keeping the id. */
    struct {
        const char *what;
        struct mvap_request req;
        const char *authority;
    } cases[7];
    for (size_t i = 0; i < 7; i++) {
        cases[i].req = base;
        cases[i].authority = "grant-alpha";
    }
    cases[0].what = "verb";           cases[0].req.verb = MVAP_VERB_HOST;
    cases[1].what = "request_id";     cases[1].req.request_id = 4243;
    cases[2].what = "kind";           cases[2].req.kind = MVAP_KIND_ZCODE;
    cases[3].what = "value_zats";     cases[3].req.value_zats = 8;
    cases[4].what = "property_id";    cases[4].req.property_id[31] ^= 0xFFu;
    cases[5].what = "param";
    snprintf(cases[5].req.param, sizeof(cases[5].req.param), "counterparty-two");
    cases[6].what = "authority id";   cases[6].authority = "grant-beta";

    for (size_t i = 0; i < 7; i++) {
        uint8_t d[32];
        mvap_request_digest(&cases[i].req, cases[i].authority, d);
        char label[128];
        snprintf(label, sizeof(label),
                 "B1: changing the %s changes the digest", cases[i].what);
        BI_CHECK(label, memcmp(d0, d, 32) != 0);
    }

    /* Version: 0 means "the current one" everywhere else on this wire, so the
     * two spellings of one request must digest alike — otherwise an in-process
     * request and the same request off the wire would collide as a conflict. */
    struct mvap_request implicit = base;
    implicit.version = 0;
    uint8_t dimp[32];
    mvap_request_digest(&implicit, "grant-alpha", dimp);
    BI_CHECK("B1: version 0 and the current version digest alike",
             memcmp(d0, dimp, 32) == 0);

    struct mvap_request v1 = base;
    v1.version = 1;
    uint8_t dv1[32];
    mvap_request_digest(&v1, "grant-alpha", dv1);
    BI_CHECK("B1: a different protocol version changes the digest",
             memcmp(d0, dv1, 32) != 0);

    /* The length prefixes: without them "ab" + "" and "a" + "b" would share a
     * preimage. Asserted on the two adjacent variable-length fields. */
    struct mvap_request split_a = base, split_b = base;
    snprintf(split_a.param, sizeof(split_a.param), "ab");
    snprintf(split_b.param, sizeof(split_b.param), "a");
    uint8_t da[32], db[32];
    mvap_request_digest(&split_a, "", da);
    mvap_request_digest(&split_b, "b", db);
    BI_CHECK("B1: the param/authority boundary is length-prefixed, not glued",
             memcmp(da, db, 32) != 0);

    /* A null authority is the ungranted case and must digest as the empty
     * string rather than as anything else. */
    uint8_t dnull[32], dempty[32];
    mvap_request_digest(&base, NULL, dnull);
    mvap_request_digest(&base, "", dempty);
    BI_CHECK("B1: a null authority digests as the empty one",
             memcmp(dnull, dempty, 32) == 0);
    return failures;
}

/* ── B2: a hit is confirmed against the FIELDS, not just the digest ─────────*/

/* THE GUARANTEE THAT WAS BORROWED RATHER THAN ESTABLISHED. The ring used to
 * decide "this is the same request" by comparing 32 digest bytes and nothing
 * else, because the slot held nothing else. Finding a second request with the
 * same SHA3-256 is not a practical attack — but "no two requests collide" was
 * then a property of SHA3-256, not of this broker, and the cost of making it
 * the broker's own is one comparison of fields it already had in hand.
 *
 * A real collision cannot be exhibited, so the test FORGES the state one would
 * produce: a slot whose digest is the incoming request's and whose stored
 * fields are a different request's. That is exactly what the ring would hold
 * the instant after a collision, and it is the only honest way to reach the
 * branch. The control case immediately after — same digest, same fields — is
 * served as a replay, which is what proves the refusal is the field comparison
 * talking and not the harness failing to reach the ring at all. */
static int b2_a_collision_is_not_a_replay(void)
{
    int failures = 0;

    /* No authority bound: the conflict check runs before authorization, so an
     * unbound session reaches it, and every OTHER outcome of this pipeline is
     * DENIED_NO_GRANT — which makes "was the forged answer served" a question
     * with an unambiguous answer. */
    struct agent_broker_session s;
    memset(&s, 0, sizeof(s));

    struct mvap_request a, b;
    memset(&a, 0, sizeof(a));
    a.verb       = MVAP_VERB_INSPECT;
    a.request_id = 77;
    a.kind       = MVAP_KIND_CONTENT;
    a.version    = MVAP_VERSION;
    memset(a.property_id, 0xAA, sizeof(a.property_id));
    b = a;
    memset(b.property_id, 0xBB, sizeof(b.property_id));

    struct agent_idem_identity ida, idb;
    uint8_t da[32], db[32];
    mvap_request_identity(&a, "", &ida);
    mvap_request_identity(&b, "", &idb);
    mvap_identity_digest(&ida, da);
    mvap_identity_digest(&idb, db);

    BI_CHECK("B2: two different requests have two different identities",
             !mvap_identity_equal(&ida, &idb) &&
                 mvap_identity_equal(&ida, &ida));
    BI_CHECK("B2: two different identities digest differently",
             memcmp(da, db, 32) != 0);

    /* The digest the wire path would compute for the same request must be the
     * digest of the stored identity, or the two halves of the check are not
     * describing one thing. */
    uint8_t via_request[32];
    mvap_request_digest(&a, "", via_request);
    BI_CHECK("B2: mvap_request_digest is identity-then-digest, composed",
             memcmp(via_request, da, 32) == 0);

    /* FORGE THE COLLISION: request B's digest over request A's fields, in the
     * slot request B's id would land in, marked COMMITTED with an answer no
     * legitimate execution here could produce. */
    struct agent_idem_slot *slot = &s.idem[b.request_id % AGENT_IDEMPOTENCY_SLOTS];
    memset(slot, 0, sizeof(*slot));
    slot->used       = true;
    slot->request_id = b.request_id;
    slot->identity   = ida;                 /* request A's fields   */
    memcpy(slot->digest, db, 32);           /* request B's digest   */
    slot->outcome    = AGENT_IDEM_OUTCOME_COMMITTED;
    slot->resp.status     = MVAP_OK;
    slot->resp.verb       = a.verb;
    slot->resp.request_id = a.request_id;
    snprintf(slot->resp.body, sizeof(slot->resp.body),
             "{\"forged\":\"the answer to a DIFFERENT request\"}");

    /* Seeded non-NULL on purpose: "the ring set it to NULL" is a claim, and a
     * variable that started NULL cannot support it. */
    const struct agent_idem_slot *hit = &s.idem[0];
    enum agent_idem_verdict v =
        agent_broker_idem_lookup(&s, &idb, db, &hit);
    BI_CHECK("B2: a slot whose digest matches over other fields is a CONFLICT",
             v == AGENT_IDEM_CONFLICT);
    BI_CHECK("B2: and the ring hands back no slot to serve from", hit == NULL);

    struct mvap_response resp;
    memset(&resp, 0, sizeof(resp));
    agent_broker_handle(&s, &b, &resp);
    BI_CHECK("B2: end to end, the collision is refused as a reused id",
             resp.status == MVAP_ERR_REQUEST_ID_REUSED);
    BI_CHECK("B2: the forged answer never reaches the wire",
             strstr(resp.body, "forged") == NULL);
    BI_CHECK("B2: and the broker counts it as an idempotency conflict",
             s.idempotency_conflicts == 1);

    /* THE CONTROL. Same slot, same digest, but now the stored fields ARE the
     * incoming request's. This must be served — otherwise the refusal above
     * would prove only that the harness cannot reach the replay path. */
    memset(&s, 0, sizeof(s));
    slot = &s.idem[b.request_id % AGENT_IDEMPOTENCY_SLOTS];
    slot->used       = true;
    slot->request_id = b.request_id;
    slot->identity   = idb;                 /* the SAME request now */
    memcpy(slot->digest, db, 32);
    slot->outcome    = AGENT_IDEM_OUTCOME_COMMITTED;
    slot->resp.status     = MVAP_OK;
    slot->resp.verb       = b.verb;
    slot->resp.request_id = b.request_id;
    snprintf(slot->resp.body, sizeof(slot->resp.body),
             "{\"legitimate\":\"the answer to THIS request\"}");

    hit = NULL;
    v = agent_broker_idem_lookup(&s, &idb, db, &hit);
    BI_CHECK("B2: control — matching fields and digest ARE a replay",
             v == AGENT_IDEM_REPLAY && hit == slot);

    struct mvap_response cresp;
    memset(&cresp, 0, sizeof(cresp));
    agent_broker_handle(&s, &b, &cresp);
    BI_CHECK("B2: control — the legitimate replay is served and labelled",
             cresp.status == MVAP_OK &&
                 strstr(cresp.body, "legitimate") != NULL &&
                 strstr(cresp.body, "\"replayed\":true") != NULL &&
                 s.replays_served == 1);
    return failures;
}

/* ── T7 ─────────────────────────────────────────────────────────────────────*/

/* THE EXACT DEFECT, executable: request_id=7 for property A, then request_id=7
 * for property B. Both are in the grant's scope, so nothing but the idempotency
 * layer can be doing the refusing. */
static int t7_reused_id_for_another_property(void)
{
    int failures = 0;
    struct bi_fixture f;
    if (!bi_make_properties(&f, "t7")) {
        BI_CHECK("T7: two real content properties were created", false);
        return failures;
    }

    struct metaverse_grant g;
    bi_grant(&g, &f);
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = bi_clock });
    BI_CHECK("T7: the two-property grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    struct agent_broker_session s;
    BI_CHECK("T7: the production provider binds", bi_bind_production(&s, &f,
                                                                     g.grant_id));

    struct mvap_request a, b;
    struct mvap_response ra, rb;
    bi_req(&a, MVAP_VERB_INSPECT, &f, 0, 7);
    agent_broker_handle(&s, &a, &ra);
    BI_CHECK("T7: property A is served under request_id 7",
             ra.status == MVAP_OK);

    /* The control: property B IS in scope, and a fresh id gets a real answer
     * that differs from A's. Without this the refusal below could be scope. */
    struct mvap_request b_fresh;
    struct mvap_response rb_fresh;
    bi_req(&b_fresh, MVAP_VERB_INSPECT, &f, 1, 8);
    agent_broker_handle(&s, &b_fresh, &rb_fresh);
    BI_CHECK("T7: property B is in scope and answerable under its own id",
             rb_fresh.status == MVAP_OK);

    bi_req(&b, MVAP_VERB_INSPECT, &f, 1, 7);
    agent_broker_handle(&s, &b, &rb);
    BI_CHECK("T7: property B under the SAME id is refused by name",
             rb.status == MVAP_ERR_REQUEST_ID_REUSED);
    BI_CHECK("T7: that name is stable on the wire",
             strcmp(mvap_status_name(MVAP_ERR_REQUEST_ID_REUSED),
                    "REQUEST_ID_REUSED") == 0);
    BI_CHECK("T7: the refusal names the idempotency stage",
             strstr(rb.body, "\"stage\":\"idempotency\"") != NULL);

    /* AND — the part that is the actual defect — it did not hand back A's
     * answer. A refusal that carried the wrong body would still be wrong. */
    BI_CHECK("T7: property A's answer was NOT returned for property B",
             strcmp(rb.body, ra.body) != 0 && rb.status != MVAP_OK);

    /* The conflict left the first record alone: the original request still
     * works, so a stray reuse cannot evict a legitimate id. */
    struct mvap_response ra2;
    agent_broker_handle(&s, &a, &ra2);
    BI_CHECK("T7: the original request under that id still works",
             ra2.status == MVAP_OK);
    BI_CHECK("T7: the conflict was counted as one",
             s.idempotency_conflicts == 1 && s.replays_served == 0);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T8 ─────────────────────────────────────────────────────────────────────*/

static int t8_reused_id_with_any_changed_field(void)
{
    int failures = 0;
    struct bi_fixture f;
    if (!bi_make_properties(&f, "t8")) {
        BI_CHECK("T8: two real content properties were created", false);
        return failures;
    }

    struct metaverse_grant g;
    bi_grant(&g, &f);
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = bi_clock });
    BI_CHECK("T8: the grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    struct agent_broker_session s;
    BI_CHECK("T8: the production provider binds",
             bi_bind_production(&s, &f, g.grant_id));

    struct mvap_request base;
    struct mvap_response resp;
    bi_req(&base, MVAP_VERB_INSPECT, &f, 0, 88);
    agent_broker_handle(&s, &base, &resp);
    BI_CHECK("T8: the base request is served", resp.status == MVAP_OK);

    /* One changed field per case, everything else byte-identical, all reusing
     * id 88. A conflict must not consume or repoint the slot, so they can run
     * back to back and the byte-identical repeat at the end must still pass. */
    struct { const char *what; struct mvap_request req; } cases[5];
    for (size_t i = 0; i < 5; i++)
        cases[i].req = base;
    cases[0].what = "KIND";     cases[0].req.kind = MVAP_KIND_ZCODE;
    cases[1].what = "VALUE";    cases[1].req.value_zats = 1;
    cases[2].what = "PARAM";
    snprintf(cases[2].req.param, sizeof(cases[2].req.param), "somebody");
    cases[3].what = "VERB";     cases[3].req.verb = MVAP_VERB_HOST;
    cases[4].what = "protocol version";
    cases[4].req.version = 1;

    for (size_t i = 0; i < 5; i++) {
        struct mvap_response r;
        agent_broker_handle(&s, &cases[i].req, &r);
        char label[128];
        snprintf(label, sizeof(label),
                 "T8: the same id with a changed %s is refused", cases[i].what);
        BI_CHECK(label, r.status == MVAP_ERR_REQUEST_ID_REUSED);
    }
    BI_CHECK("T8: every changed field was counted as a conflict",
             s.idempotency_conflicts == 5);

    /* THE CONTROL. A byte-identical repeat is NOT a conflict — it is the same
     * request, and a query is re-executed rather than replayed. Without this
     * the five checks above would also pass under a broker that refused every
     * repeat, which would be a different bug. */
    struct mvap_response again;
    agent_broker_handle(&s, &base, &again);
    BI_CHECK("T8: the byte-identical repeat is served, not refused",
             again.status == MVAP_OK && s.idempotency_conflicts == 5);
    BI_CHECK("T8: a re-executed query is not labelled a replay",
             strstr(again.body, "\"replayed\":true") == NULL &&
             s.replays_served == 0);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── T9 ─────────────────────────────────────────────────────────────────────*/

/* A QUERY IS A READ OF LIVE STATE, so its only correct cache lifetime is zero.
 * The old ring cached query answers, which meant an agent could hold a served
 * answer across a revocation simply by resending the same request_id — the
 * pre-plan authorize was never reached, so the revocation had nothing to land
 * on. This is the same escape T4 (test_metaverse_broker_authority) closes at
 * the authority level, reopened at the transport level; both have to be shut. */
static int t9_query_cannot_outlive_revocation(void)
{
    int failures = 0;
    struct bi_fixture f;
    if (!bi_make_properties(&f, "t9")) {
        BI_CHECK("T9: two real content properties were created", false);
        return failures;
    }

    struct metaverse_grant g;
    bi_grant(&g, &f);
    property_grant_service_reset();
    property_grant_service_configure(&(struct property_grant_env){
        .clock = bi_clock });
    BI_CHECK("T9: the grant mints",
             property_grant_service_mint(&g) == PROPERTY_GRANT_OK);

    struct agent_broker_session s;
    BI_CHECK("T9: the production provider binds",
             bi_bind_production(&s, &f, g.grant_id));

    struct mvap_request q;
    struct mvap_response first;
    bi_req(&q, MVAP_VERB_INSPECT, &f, 0, 99);
    agent_broker_handle(&s, &q, &first);
    BI_CHECK("T9: the query is served while the grant is live",
             first.status == MVAP_OK &&
             strstr(first.body, "\"kind\":\"content\"") != NULL);

    BI_CHECK("T9: the operator revokes the live grant",
             property_grant_service_revoke(g.grant_id) == PROPERTY_GRANT_OK);

    /* THE SAME BYTES, THE SAME ID. Nothing about the request changed; only the
     * authority did. */
    struct mvap_response after;
    agent_broker_handle(&s, &q, &after);
    BI_CHECK("T9: the repeated query is REFUSED, not served from the ring",
             after.status == MVAP_ERR_DENIED_REVOKED);
    BI_CHECK("T9: the refusal came from authorize, so the authority was read",
             strstr(after.body, "\"stage\":\"authorize\"") != NULL);
    BI_CHECK("T9: the served answer was not handed back",
             strcmp(after.body, first.body) != 0);
    BI_CHECK("T9: nothing was replayed and nothing conflicted",
             s.replays_served == 0 && s.idempotency_conflicts == 0);

    property_grant_service_reset();
    test_rm_rf_recursive(f.dd);
    return failures;
}

/* ── TR: a replay is distinguishable, and executes nothing ──────────────────*/

/* Needs a mutation that COMMITS, which no production seam in this tree does
 * (see T12 in test_metaverse_broker_authority: every action-class verb is
 * refused ACTION_EXECUTOR_UNAVAILABLE because nothing executes property
 * effects). So this one case, and only this one, drives the test-build fixture
 * seam — where PUBLISH_REVISION really does increment a revision, which is what
 * makes "the replay executed NOTHING" an observation rather than an assertion
 * about our own code. */
static int tr_replay_is_distinguishable(void)
{
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "broker_idem", "replay");

    struct agent_audit_log log;
    memset(&log, 0, sizeof(log));
    if (!agent_audit_open(&log, dir)) {
        BI_CHECK("TR: the audit log opens", false);
        test_rm_rf_recursive(dir);
        return failures;
    }

    struct agent_grant demo;
    memset(&demo, 0, sizeof(demo));
    snprintf(demo.grant_id, sizeof(demo.grant_id), "w1d-replay");
    snprintf(demo.principal, sizeof(demo.principal), "%s", BI_HOLDER);
    uint8_t prop[MVAP_PROPERTY_ID_LEN];
    agent_broker_fixture_property_id(0, prop);
    (void)agent_grant_add_property(&demo, prop);
    agent_grant_allow_action(&demo, MVAP_VERB_INSPECT);
    agent_grant_allow_action(&demo, MVAP_VERB_PUBLISH_REVISION);
    agent_grant_allow_kind(&demo, MVAP_KIND_CONTENT);
    agent_grant_allow_kind(&demo, MVAP_KIND_ANY);
    demo.max_value_zats = 1000;
    demo.budget_zats    = 1000;

    agent_broker_install_fixture_provider();
    agent_broker_fixture_set_grant(&demo);
    struct agent_broker_session s;
    memset(&s, 0, sizeof(s));
    char why[192];
    if (!agent_broker_session_bind(&s, &g_authority, why, sizeof(why))) {
        BI_CHECK("TR: the session binds to the fixture authority", false);
        test_rm_rf_recursive(dir);
        return failures;
    }
    s.audit = &log;

    struct mvap_request pub;
    memset(&pub, 0, sizeof(pub));
    pub.verb = MVAP_VERB_PUBLISH_REVISION;
    pub.request_id = 42;
    pub.kind = MVAP_KIND_CONTENT;
    memcpy(pub.property_id, prop, MVAP_PROPERTY_ID_LEN);

    struct mvap_response first;
    agent_broker_handle(&s, &pub, &first);
    BI_CHECK("TR: the first execution commits",
             first.status == MVAP_OK && s.receipts_written == 1);
    BI_CHECK("TR: the first execution carries a receipt",
             !mvap_property_id_is_zero(first.receipt_id));
    BI_CHECK("TR: the first execution is NOT labelled a replay",
             strstr(first.body, "\"replayed\":true") == NULL);

    /* What the revision stands at after ONE execution, read through a separate
     * request id so the ring plays no part in the reading. */
    struct mvap_request look;
    struct mvap_response looked;
    memset(&look, 0, sizeof(look));
    look.verb = MVAP_VERB_INSPECT;
    look.request_id = 43;
    look.kind = MVAP_KIND_CONTENT;
    memcpy(look.property_id, prop, MVAP_PROPERTY_ID_LEN);
    agent_broker_handle(&s, &look, &looked);
    char after_one[MVAP_BODY_MAX + 1];
    snprintf(after_one, sizeof(after_one), "%s", looked.body);
    BI_CHECK("TR: the first execution moved the property",
             looked.status == MVAP_OK &&
             strstr(after_one, "\"revision\":1") != NULL);

    /* ── THE REPLAY ── */
    struct mvap_response replay;
    agent_broker_handle(&s, &pub, &replay);

    BI_CHECK("TR: the replay returns the ORIGINAL receipt",
             memcmp(replay.receipt_id, first.receipt_id,
                    MVAP_RECEIPT_ID_LEN) == 0);
    BI_CHECK("TR: the replay returns the original status",
             replay.status == first.status);
    /* (1) DISTINGUISHABLE IN THE REPLY BODY. */
    BI_CHECK("TR: the reply body says it is a replay",
             strncmp(replay.body, "{\"replayed\":true", 16) == 0);
    BI_CHECK("TR: the original answer survives behind the label",
             strstr(replay.body, "\"content_root\"") != NULL);
    BI_CHECK("TR: the replay was counted as a replay, not as work",
             s.replays_served == 1 && s.receipts_written == 1);

    /* (2) IT EXECUTED NOTHING. The fixture's PUBLISH_REVISION increments a
     * revision, so a replay that re-executed would be visible as revision 2. */
    struct mvap_request look2;
    struct mvap_response looked2;
    memset(&look2, 0, sizeof(look2));
    look2.verb = MVAP_VERB_INSPECT;
    look2.request_id = 44;
    look2.kind = MVAP_KIND_CONTENT;
    memcpy(look2.property_id, prop, MVAP_PROPERTY_ID_LEN);
    agent_broker_handle(&s, &look2, &looked2);
    BI_CHECK("TR: the replay executed NOTHING — the revision did not move",
             looked2.status == MVAP_OK &&
             strstr(looked2.body, "\"revision\":1") != NULL);

    /* (3) DISTINGUISHABLE IN THE AUDIT ROW. */
    char doc[32768];
    size_t n = agent_audit_render_json(dir, 32, doc, sizeof(doc));
    BI_CHECK("TR: the audit log renders", n > 0);
    BI_CHECK("TR: the replay wrote its own row, labelled REPLAYED",
             strstr(doc, "REPLAYED request_id=42") != NULL);
    char first_hex[65];
    zcl_hex_encode(first.receipt_id, MVAP_RECEIPT_ID_LEN, first_hex);
    BI_CHECK("TR: the replay row names the receipt it is replaying",
             strstr(doc, first_hex) != NULL);

    struct agent_audit_verdict v;
    memset(&v, 0, sizeof(v));
    BI_CHECK("TR: the chain still verifies with the replay row in it",
             agent_audit_verify_dir(dir, &v) && v.ok && v.rows == 2 &&
             v.chain_breaks == 0 && v.bad_signatures == 0);

    /* (4) IT CANNOT BE REPOINTED. The same id aimed at the OTHER fixture
     * property must not hand back this receipt, and must not disturb it. */
    struct mvap_request repoint = pub;
    agent_broker_fixture_property_id(1, repoint.property_id);
    struct mvap_response rr;
    agent_broker_handle(&s, &repoint, &rr);
    /* It gets a refusal and its OWN confinement receipt — a boundary refusal
     * is auditable like any other. What it must not get is the committed
     * mutation's receipt. */
    BI_CHECK("TR: the same id aimed elsewhere is refused",
             rr.status == MVAP_ERR_REQUEST_ID_REUSED);
    BI_CHECK("TR: the refusal did not hand over the committed receipt",
             memcmp(rr.receipt_id, first.receipt_id,
                    MVAP_RECEIPT_ID_LEN) != 0);

    struct mvap_response replay2;
    agent_broker_handle(&s, &pub, &replay2);
    BI_CHECK("TR: the original replay is intact after the attempt",
             replay2.status == MVAP_OK &&
             memcmp(replay2.receipt_id, first.receipt_id,
                    MVAP_RECEIPT_ID_LEN) == 0 &&
             s.replays_served == 2);

    /* Leave no fixture provider installed for whatever runs next. */
    agent_broker_provider_install(NULL);
    test_rm_rf_recursive(dir);
    return failures;
}

/* ── entry point ────────────────────────────────────────────────────────────*/

int test_metaverse_broker_idempotency(void)
{
    int failures = 0;
    printf("=== metaverse_broker_idempotency: one id, one request ===\n");

    failures += b1_digest_covers_every_field();
    failures += b2_a_collision_is_not_a_replay();
    failures += t7_reused_id_for_another_property();
    failures += t8_reused_id_with_any_changed_field();
    failures += t9_query_cannot_outlive_revocation();
    failures += tr_replay_is_distinguishable();

    property_grant_service_reset();
    property_grant_service_configure(NULL);
    agent_broker_provider_install(NULL);
    printf("=== metaverse_broker_idempotency complete: %d failure(s) ===\n",
           failures);
    return failures;
}
