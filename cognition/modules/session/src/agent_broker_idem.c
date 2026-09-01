/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The broker's idempotency ring: what makes "the same request_id" mean "the
 * same request".
 *
 * THE DEFECT THIS FILE REPLACES. The ring used to be four lines inside
 * agent_broker.c: find a slot whose `request_id` matched, and — at the call
 * site, not here — compare the verb. Nothing else. Not the property, not the
 * kind, not the value, not the param, not the protocol version, not the
 * authority. Two consequences followed, and both were reachable by an ordinary
 * client with no hostile intent:
 *
 *   1. request_id=7 INSPECT property A, then request_id=7 INSPECT property B,
 *      returned A's answer to a question about B. The broker itself produced
 *      the confusion; nothing anywhere refused.
 *   2. Queries were cached, so a repeated request_id after a revocation
 *      returned the old OK without consulting the authority at all. Live
 *      authority, defeated by a retry.
 *
 * THE RULES NOW, in the order they matter:
 *
 *   - Identity is the REQUEST, not the number: the digest is the key, and the
 *     preimage FIELDS the slot also stores are what a hit is confirmed
 *     against. A repeat with any field changed is REQUEST_ID_REUSED, never
 *     another request's answer — and so is a repeat that merely hashes alike,
 *     which is why the guarantee is this file's and not SHA3-256's.
 *   - A CLAIM binds an id to a request and caches nothing. Every dispatched
 *     request claims its id — every query, and every mutation until it
 *     commits. An identical repeat is re-executed against the live authority.
 *     So a query is never answered from here (a cached read is stale by
 *     definition, and would let a retry outlive a revocation), and a refusal
 *     is never frozen — in particular it can never be turned into a permanent
 *     success, which is the direction that matters.
 *   - A COMMIT is the only thing that puts an answer in the ring. An identical
 *     repeat returns the original response and the original receipt, executes
 *     nothing, and is LABELLED, on the wire and in the audit log.
 *
 * The claim/commit split is two functions rather than one function with a
 * flag, because agent_broker_idem_claim() has no response parameter: there is
 * no argument a query answer could be passed as.
 */

#include "session/agent_broker.h"

#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdio.h>
#include <string.h>

#define IDEM_TAG "agent.idem"

/* ── the canonical request digest ───────────────────────────────────────── */

/* The preimage is written little-endian through base/serialize_le.h — the
 * node's one byte-order codec — so the layout is fixed by contract and neither
 * host byte order nor struct padding can enter it. These wrappers exist only
 * to return the width, which keeps the preimage below readable as a list of
 * fields rather than a running offset arithmetic. */
static size_t put_u16(uint8_t *p, uint16_t v)
{
    zcl_write_u16_le(p, v);
    return sizeof(uint16_t);
}

static size_t put_u32(uint8_t *p, uint32_t v)
{
    zcl_write_u32_le(p, v);
    return sizeof(uint32_t);
}

static size_t put_u64(uint8_t *p, uint64_t v)
{
    zcl_write_u64_le(p, v);
    return sizeof(uint64_t);
}

/* The preimage tag. Its length is spelled out so the compile-time bound below
 * cannot drift from it. */
#define IDEM_TAG_TEXT "zcl.mvap.request.v1"
#define IDEM_TAG_LEN  (sizeof(IDEM_TAG_TEXT) - 1)

/* Worst case: tag + version + verb + request_id + kind + value + property id
 * + two length-prefixed strings at their own maxima. Stated as an expression
 * so adding a field to the preimage without widening the buffer does not
 * build a silent truncation. */
#define IDEM_PREIMAGE_MAX                                                     \
    (IDEM_TAG_LEN + 4 + 4 + 4 + 2 + 8 + MVAP_PROPERTY_ID_LEN +                \
     2 + MVAP_PARAM_MAX + 2 + AGENT_GRANT_ID_MAX)

/* THE ONE PLACE THAT DECIDES WHAT A REQUEST'S IDENTITY IS. Everything else —
 * the digest, the ring's comparison — reads this struct, so there is no shape
 * in which the bytes hashed and the fields compared can describe different
 * things. */
void mvap_request_identity(const struct mvap_request *req,
                           const char *authority_id,
                           struct agent_idem_identity *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!req) {
        LOG_WARN(IDEM_TAG, "identity asked for a null request");
        return;
    }

    const char *auth = authority_id ? authority_id : "";
    size_t auth_len  = strnlen(auth, AGENT_GRANT_ID_MAX);
    size_t param_len = strnlen(req->param, MVAP_PARAM_MAX);

    /* 0 means "the current version" everywhere else on this wire (see
     * `version` in struct mvap_request), so the two spellings of the same
     * request must digest alike. Normalized HERE, once, so the stored identity
     * and the digest cannot disagree about which version was asked. */
    out->version    = req->version ? req->version : (uint32_t)MVAP_VERSION;
    out->verb       = req->verb;
    out->request_id = req->request_id;
    out->kind       = req->kind;
    out->value_zats = req->value_zats;
    memcpy(out->property_id, req->property_id, MVAP_PROPERTY_ID_LEN);
    out->param_len = (uint16_t)param_len;
    memcpy(out->param, req->param, param_len);
    out->authority_len = (uint16_t)auth_len;
    memcpy(out->authority_id, auth, auth_len);
}

void mvap_identity_digest(const struct agent_idem_identity *id, uint8_t out[32])
{
    if (!out)
        return;
    memset(out, 0, 32);
    if (!id) {
        LOG_WARN(IDEM_TAG, "digest asked for a null identity");
        return;
    }

    size_t param_len = id->param_len > MVAP_PARAM_MAX ? (size_t)MVAP_PARAM_MAX
                                                      : (size_t)id->param_len;
    size_t auth_len  = id->authority_len > AGENT_GRANT_ID_MAX
                           ? (size_t)AGENT_GRANT_ID_MAX
                           : (size_t)id->authority_len;

    uint8_t pre[IDEM_PREIMAGE_MAX];
    size_t n = 0;
    memcpy(pre + n, IDEM_TAG_TEXT, IDEM_TAG_LEN);       n += IDEM_TAG_LEN;
    n += put_u32(pre + n, id->version);
    n += put_u32(pre + n, id->verb);
    n += put_u32(pre + n, id->request_id);
    n += put_u16(pre + n, id->kind);
    n += put_u64(pre + n, id->value_zats);
    memcpy(pre + n, id->property_id, MVAP_PROPERTY_ID_LEN);
    n += MVAP_PROPERTY_ID_LEN;
    n += put_u16(pre + n, (uint16_t)param_len);
    memcpy(pre + n, id->param, param_len);              n += param_len;
    n += put_u16(pre + n, (uint16_t)auth_len);
    memcpy(pre + n, id->authority_id, auth_len);        n += auth_len;

    sha3_256(pre, n, out);
}

void mvap_request_digest(const struct mvap_request *req,
                         const char *authority_id, uint8_t out[32])
{
    struct agent_idem_identity id;
    mvap_request_identity(req, authority_id, &id);
    mvap_identity_digest(&id, out);
}

/* Field by field, and the assertion below is what keeps that list complete.
 * IDEM_IDENTITY_COVERED sums the size of exactly the members
 * mvap_identity_equal() compares, so a member added to the struct and not to
 * the comparison grows sizeof without growing the sum, and the build stops.
 *
 * HONEST LIMIT: 6 of the struct's 192 bytes are trailing alignment padding, so
 * a field small enough to fit inside them would not move sizeof and would not
 * be caught. That is the one case still on the reader; every other is a
 * compile error rather than a silently uncompared field. */
#define IDEM_IDENTITY_MEMBER(m_) sizeof(((struct agent_idem_identity *)0)->m_)
#define IDEM_IDENTITY_COVERED                                                 \
    (IDEM_IDENTITY_MEMBER(value_zats) + IDEM_IDENTITY_MEMBER(version) +       \
     IDEM_IDENTITY_MEMBER(verb) + IDEM_IDENTITY_MEMBER(request_id) +          \
     IDEM_IDENTITY_MEMBER(kind) + IDEM_IDENTITY_MEMBER(param_len) +           \
     IDEM_IDENTITY_MEMBER(authority_len) +                                    \
     IDEM_IDENTITY_MEMBER(property_id) + IDEM_IDENTITY_MEMBER(param) +        \
     IDEM_IDENTITY_MEMBER(authority_id))

_Static_assert(sizeof(struct agent_idem_identity) == IDEM_IDENTITY_COVERED + 6,
               "agent_idem_identity changed shape: add the new field to "
               "mvap_request_identity(), to the preimage in "
               "mvap_identity_digest(), to mvap_identity_equal(), and to "
               "IDEM_IDENTITY_COVERED above");

bool mvap_identity_equal(const struct agent_idem_identity *a,
                         const struct agent_idem_identity *b)
{
    if (!a || !b)
        return false;
    return a->value_zats    == b->value_zats &&
           a->version       == b->version &&
           a->verb          == b->verb &&
           a->request_id    == b->request_id &&
           a->kind          == b->kind &&
           a->param_len     == b->param_len &&
           a->authority_len == b->authority_len &&
           memcmp(a->property_id, b->property_id, MVAP_PROPERTY_ID_LEN) == 0 &&
           memcmp(a->param, b->param, MVAP_PARAM_MAX) == 0 &&
           memcmp(a->authority_id, b->authority_id, AGENT_GRANT_ID_MAX) == 0;
}

/* ── the ring ───────────────────────────────────────────────────────────── */

/* A slot is addressed by `request_id % AGENT_IDEMPOTENCY_SLOTS`, so one id
 * always occupies one slot and can never appear twice. The scan is over the
 * whole array anyway: it costs 32 comparisons and removes any dependence on
 * the store and the lookup agreeing about the index arithmetic. */
/* A slot is a HIT only when the digest matches AND the stored preimage fields
 * are the same request. The two together are what make "the same request_id"
 * mean "the same request" without borrowing the claim from SHA3-256: a digest
 * that matched over different fields would be a collision, and a collision
 * gets the same refusal as any other reuse of the id — it is not a replay,
 * because it is not the same request. */
static bool slot_is(const struct agent_idem_slot *slot,
                    const struct agent_idem_identity *id,
                    const uint8_t digest[32])
{
    return memcmp(slot->digest, digest, 32) == 0 &&
           mvap_identity_equal(&slot->identity, id);
}

static void slot_bind(struct agent_idem_slot *slot,
                      const struct agent_idem_identity *id,
                      const uint8_t digest[32])
{
    memset(slot, 0, sizeof(*slot));
    slot->used       = true;
    slot->request_id = id->request_id;
    slot->identity   = *id;
    memcpy(slot->digest, digest, 32);
}

enum agent_idem_verdict agent_broker_idem_lookup(
    const struct agent_broker_session *s,
    const struct agent_idem_identity *id, const uint8_t digest[32],
    const struct agent_idem_slot **slot_out)
{
    if (slot_out)
        *slot_out = NULL;
    if (!s || !id || !digest)
        return AGENT_IDEM_FRESH;

    for (size_t i = 0; i < AGENT_IDEMPOTENCY_SLOTS; i++) {
        const struct agent_idem_slot *slot = &s->idem[i];
        if (!slot->used || slot->request_id != id->request_id)
            continue;
        if (!slot_is(slot, id, digest))
            return AGENT_IDEM_CONFLICT;
        if (slot_out)
            *slot_out = slot;
        return slot->outcome == AGENT_IDEM_OUTCOME_COMMITTED
                   ? AGENT_IDEM_REPLAY
                   : AGENT_IDEM_CLAIMED;
    }
    return AGENT_IDEM_FRESH;
}

void agent_broker_idem_claim(struct agent_broker_session *s,
                             const struct agent_idem_identity *id,
                             const uint8_t digest[32])
{
    if (!s || !id || !digest)
        return;
    struct agent_idem_slot *slot =
        &s->idem[id->request_id % AGENT_IDEMPOTENCY_SLOTS];
    /* Re-claiming what is already committed would DISCARD the answer a replay
     * owes, so a claim never demotes a commit. */
    if (slot->used && slot->request_id == id->request_id &&
        slot->outcome == AGENT_IDEM_OUTCOME_COMMITTED &&
        slot_is(slot, id, digest))
        return;
    slot_bind(slot, id, digest);
    slot->outcome = AGENT_IDEM_OUTCOME_CLAIMED;
}

void agent_broker_idem_commit(struct agent_broker_session *s,
                              const struct agent_idem_identity *id,
                              const uint8_t digest[32],
                              const struct mvap_response *resp,
                              const uint8_t action_receipt_id[32])
{
    if (!s || !id || !digest || !resp)
        return;
    struct agent_idem_slot *slot =
        &s->idem[id->request_id % AGENT_IDEMPOTENCY_SLOTS];
    slot_bind(slot, id, digest);
    slot->outcome = AGENT_IDEM_OUTCOME_COMMITTED;
    slot->resp    = *resp;
    if (action_receipt_id)
        memcpy(slot->action_receipt_id, action_receipt_id, 32);
}

/* ── labelling a replay ─────────────────────────────────────────────────── */

void agent_broker_idem_label_replay(struct mvap_response *resp)
{
    if (!resp)
        return;

    static const char lead[] = "{\"replayed\":true";
    const char *body = resp->body;
    size_t body_len  = strnlen(body, sizeof(resp->body));

    char tmp[MVAP_BODY_MAX + 1];
    int n;
    if (body_len >= 2 && body[0] == '{' && body[body_len - 1] == '}') {
        /* Inject the label as the FIRST member of the original object, so the
         * agent still receives the original answer verbatim behind it. */
        n = (body_len == 2)
                ? snprintf(tmp, sizeof(tmp), "%s}", lead)
                : snprintf(tmp, sizeof(tmp), "%s,%s", lead, body + 1);
    } else {
        n = snprintf(tmp, sizeof(tmp), "%s,\"body\":\"%s\"}", lead, body);
    }
    /* A body that will not fit the label loses the BODY, never the label: an
     * unlabelled replay is an event an agent counts twice. */
    if (n < 0 || (size_t)n >= sizeof(tmp))
        (void)snprintf(tmp, sizeof(tmp),
                       "%s,\"body_omitted\":\"the labelled body exceeds the "
                       "%d-byte bound\"}", lead, (int)MVAP_BODY_MAX);
    (void)snprintf(resp->body, sizeof(resp->body), "%s", tmp);
}
