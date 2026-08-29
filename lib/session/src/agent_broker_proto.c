/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The typed agent-broker wire codec. See session/agent_broker_proto.h for the
 * contract; the only thing worth restating here is why every field is written
 * through base/serialize_le.h instead of memcpy'ing the struct: the struct has
 * padding and host endianness, the wire has neither, and a broker that trusts a
 * peer's struct layout is trusting the peer.
 */

#include "session/agent_broker_proto.h"

#include "base/log_macros.h"
#include "base/serialize_le.h"

#include <string.h>

#define MVAP_TAG "agent.proto"

/* ── validation ─────────────────────────────────────────────────────────── */

bool mvap_param_is_safe(const char *s)
{
    if (!s)
        return false;
    size_t n = strnlen(s, MVAP_PARAM_MAX + 1);
    if (n > MVAP_PARAM_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok)
            return false;
        /* ".." can only be a traversal attempt: rejected even though '/' is
         * already impossible, so the token stays safe if a future consumer
         * ever joins it onto a directory. */
        if (c == '.' && i + 1 < n && s[i + 1] == '.')
            return false;
    }
    return true;
}

bool mvap_property_id_is_zero(const uint8_t id[MVAP_PROPERTY_ID_LEN])
{
    if (!id)
        return true;
    uint8_t acc = 0;
    for (size_t i = 0; i < MVAP_PROPERTY_ID_LEN; i++)
        acc |= id[i];
    return acc == 0;
}

/* ── names ──────────────────────────────────────────────────────────────── */

/* Indexed by wire value, pasted straight from MVAP_VERB_TABLE so a verb can
 * never be added to the wire without a name (or named without existing). A
 * value the table does not define stays NULL and renders as "unknown". */
static const char *const k_verb_names[MVAP_VERB__COUNT] = {
    [MVAP_VERB_NONE] = "NONE",
#define MVAP_VERB_NAME(id_, value_, since_) [value_] = #id_,
    MVAP_VERB_TABLE(MVAP_VERB_NAME)
#undef MVAP_VERB_NAME
};

/* One name per wire kind, in wire order. Deliberately sized BY ITS
 * INITIALIZER rather than by MVAP_KIND__COUNT: written the other way, a kind
 * added to enum mvap_kind without a name here just grew the array by one NULL
 * and mvap_kind_name() started handing NULL to every caller that logs it. The
 * assertion below turns that omission into a build failure. It is written
 * from experience — adding character_sheet hit exactly that hole, and a test
 * run is a run too late for a name that reaches a log line. */
static const char *const k_kind_names[] = {
    "any", "content", "zcode", "name", "asset", "service", "endpoint",
    "product", "contract", "character",
};
_Static_assert(sizeof k_kind_names / sizeof k_kind_names[0] ==
                   (size_t)MVAP_KIND__COUNT,
               "every wire kind needs a name in k_kind_names, in wire order");

const char *mvap_verb_name(uint32_t verb)
{
    if (verb >= MVAP_VERB__COUNT || !k_verb_names[verb])
        return "unknown";
    return k_verb_names[verb];
}

const char *mvap_kind_name(uint16_t kind)
{
    if (kind >= MVAP_KIND__COUNT || !k_kind_names[kind])
        return "unknown";
    return k_kind_names[kind];
}

static bool ieq(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    for (;; a++, b++) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'a');
        if (ca != cb)
            return false;
        if (ca == 0)
            return true;
    }
}

uint32_t mvap_verb_from_name(const char *name)
{
    if (!name)
        return MVAP_VERB_NONE;
    for (uint32_t i = 1; i < MVAP_VERB__COUNT; i++)
        if (k_verb_names[i] && ieq(name, k_verb_names[i]))
            return i;
    return MVAP_VERB_NONE;
}

uint16_t mvap_kind_from_name(const char *name)
{
    if (!name)
        return MVAP_KIND_ANY;
    for (uint16_t i = 1; i < MVAP_KIND__COUNT; i++)
        if (ieq(name, k_kind_names[i]))
            return i;
    return MVAP_KIND_ANY;
}

/* Indexed by wire value; 0 means "no such verb". Pasted from the same table as
 * the enum and the names, so the three cannot disagree. */
static const uint32_t k_verb_since[MVAP_VERB__COUNT] = {
#define MVAP_VERB_SINCE(id_, value_, since_) [value_] = (uint32_t)(since_),
    MVAP_VERB_TABLE(MVAP_VERB_SINCE)
#undef MVAP_VERB_SINCE
};

bool mvap_verb_in_version(uint32_t verb, uint32_t version)
{
    if (verb == MVAP_VERB_NONE || verb >= MVAP_VERB__COUNT)
        return false;
    uint32_t since = k_verb_since[verb];
    if (since == 0)
        return false;
    return version >= since && version <= MVAP_VERSION;
}

const char *mvap_status_name(int32_t status)
{
    switch (status) {
    case MVAP_OK:                       return "ok";
    case MVAP_ERR_BAD_REQUEST:          return "BAD_REQUEST";
    case MVAP_ERR_UNKNOWN_VERB:         return "UNKNOWN_VERB";
    case MVAP_ERR_NOT_FOUND:            return "NOT_FOUND";
    case MVAP_ERR_INTERNAL:             return "INTERNAL";
    case MVAP_ERR_DENIED_NO_GRANT:      return "DENIED_NO_GRANT";
    case MVAP_ERR_DENIED_REVOKED:       return "DENIED_REVOKED";
    case MVAP_ERR_DENIED_EXPIRED:       return "DENIED_EXPIRED";
    case MVAP_ERR_DENIED_ACTION:        return "DENIED_ACTION";
    case MVAP_ERR_DENIED_PROPERTY:      return "DENIED_PROPERTY";
    case MVAP_ERR_DENIED_KIND:          return "DENIED_KIND";
    case MVAP_ERR_DENIED_VALUE:         return "DENIED_VALUE";
    case MVAP_ERR_DENIED_BUDGET:        return "DENIED_BUDGET";
    case MVAP_ERR_DENIED_RATE:          return "DENIED_RATE";
    case MVAP_ERR_DENIED_COUNTERPARTY:  return "DENIED_COUNTERPARTY";
    case MVAP_ERR_DENIED_DELEGATION:    return "DENIED_DELEGATION";
    case MVAP_ERR_DENIED_PEER_IDENTITY: return "DENIED_PEER_IDENTITY";
    case MVAP_ERR_PLAN_FAILED:          return "PLAN_FAILED";
    case MVAP_ERR_COMMIT_FAILED:        return "COMMIT_FAILED";
    case MVAP_ERR_REVISION_MOVED:       return "REVISION_MOVED";
    case MVAP_ERR_ACTION_EXECUTOR_UNAVAILABLE:
                                        return "ACTION_EXECUTOR_UNAVAILABLE";
    case MVAP_ERR_QUERY_UNAVAILABLE:    return "QUERY_UNAVAILABLE";
    case MVAP_ERR_AUTHORITY_CHANGED:    return "AUTHORITY_CHANGED";
    case MVAP_ERR_REQUEST_ID_REUSED:    return "REQUEST_ID_REUSED";
    default:                            return "unknown";
    }
}

/* ── framing ────────────────────────────────────────────────────────────── */

uint32_t mvap_frame_length(const uint8_t *in, size_t in_len)
{
    if (!in || in_len < MVAP_FRAME_PREFIX)
        return 0;
    uint32_t n = zcl_read_u32_le(in);
    if (n == 0 || n > MVAP_MAX_FRAME)
        return 0;
    return n;
}

/* ── protocol version ───────────────────────────────────────────────────── */

/* The version an encode writes. ZERO means "whatever this build speaks", so a
 * zero-initialized record encodes as MVAP_VERSION without any caller saying so.
 * Any other value outside [MVAP_VERSION_MIN, MVAP_VERSION] is REFUSED (0),
 * never quietly rewritten to the nearest supported one: a caller that asked to
 * speak version 3 to a peer must be told this build cannot, not handed a
 * version-2 frame it believes is a version-3 frame. Same bound as
 * accept_version below, applied in the same direction. */
static uint16_t encode_version(uint32_t requested)
{
    if (requested == 0)
        return (uint16_t)MVAP_VERSION;
    if (requested >= MVAP_VERSION_MIN && requested <= MVAP_VERSION)
        return (uint16_t)requested;
    return 0;
}

/* Accept a frame's declared version, or 0 for "this build does not speak it".
 * The BOUND is the whole compatibility story: exactly the closed set
 * [MVAP_VERSION_MIN, MVAP_VERSION], nothing outside it, and no clamping — an
 * unsupported version is refused, never rounded to the nearest one we know. */
static uint32_t accept_version(uint16_t declared)
{
    if (declared < MVAP_VERSION_MIN || declared > MVAP_VERSION)
        return 0;
    return declared;
}

/* ── request codec ──────────────────────────────────────────────────────── */

size_t mvap_request_encode(const struct mvap_request *req, uint8_t *out,
                           size_t out_cap)
{
    if (!req || !out)
        return 0;
    if (req->verb == MVAP_VERB_NONE || req->verb >= MVAP_VERB__COUNT)
        return 0;
    uint16_t version = encode_version(req->version);
    if (version == 0)
        return 0;                  /* a version this build does not speak */
    /* A verb that did not exist in the version being written cannot be
     * expressed in it. Refusing to encode is the only honest answer: writing
     * the value anyway would hand a v1 peer a number it will read as
     * out-of-range, and dropping to a "nearest" verb would silently change
     * what the agent asked for. */
    if (!mvap_verb_in_version(req->verb, version))
        return 0;
    if (req->kind >= MVAP_KIND__COUNT)
        return 0;
    if (!mvap_param_is_safe(req->param))
        return 0;

    size_t plen = strnlen(req->param, MVAP_PARAM_MAX);
    size_t rec = MVAP_REQ_FIXED + plen;
    if (rec > MVAP_MAX_FRAME || out_cap < MVAP_FRAME_PREFIX + rec)
        return 0;

    uint8_t *p = out + MVAP_FRAME_PREFIX;
    zcl_write_u32_le(out, (uint32_t)rec);
    zcl_write_u32_le(p + 0,  MVAP_MAGIC);
    zcl_write_u16_le(p + 4,  version);
    zcl_write_u16_le(p + 6,  (uint16_t)req->verb);
    zcl_write_u32_le(p + 8,  req->request_id);
    zcl_write_u64_le(p + 12, req->value_zats);
    memcpy(p + 20, req->property_id, MVAP_PROPERTY_ID_LEN);
    zcl_write_u16_le(p + 52, req->kind);
    zcl_write_u16_le(p + 54, (uint16_t)plen);
    if (plen)
        memcpy(p + MVAP_REQ_FIXED, req->param, plen);
    return MVAP_FRAME_PREFIX + rec;
}

bool mvap_request_decode(const uint8_t *in, size_t in_len,
                         struct mvap_request *out)
{
    if (!in || !out)
        LOG_FAIL(MVAP_TAG, "null argument in=%p out=%p", (const void *)in,
                 (void *)out);
    if (in_len < MVAP_REQ_FIXED)
        LOG_FAIL(MVAP_TAG, "short request record len=%zu need>=%d", in_len,
                 MVAP_REQ_FIXED);
    if (zcl_read_u32_le(in + 0) != MVAP_MAGIC)
        LOG_FAIL(MVAP_TAG, "bad magic 0x%08x", zcl_read_u32_le(in + 0));
    uint32_t version = accept_version(zcl_read_u16_le(in + 4));
    if (version == 0)
        LOG_FAIL(MVAP_TAG, "unsupported version %u (this build speaks %u..%u)",
                 zcl_read_u16_le(in + 4), MVAP_VERSION_MIN, MVAP_VERSION);

    uint16_t verb = zcl_read_u16_le(in + 6);
    /* Bounded by the frame's OWN version: a v1 peer cannot reach a verb that
     * v1 never defined, so an old client is decoded by exactly the v1 rules
     * rather than by today's wider ones. */
    if (!mvap_verb_in_version(verb, version))
        LOG_FAIL(MVAP_TAG, "verb %u is not in protocol version %u", verb,
                 version);
    uint16_t kind = zcl_read_u16_le(in + 52);
    if (kind >= MVAP_KIND__COUNT)
        LOG_FAIL(MVAP_TAG, "kind out of range %u", kind);
    uint16_t plen = zcl_read_u16_le(in + 54);
    if (plen > MVAP_PARAM_MAX || (size_t)MVAP_REQ_FIXED + plen != in_len)
        LOG_FAIL(MVAP_TAG, "param length %u inconsistent with record %zu",
                 plen, in_len);

    struct mvap_request r = { 0 };
    r.verb       = verb;
    r.version    = version;
    r.request_id = zcl_read_u32_le(in + 8);
    r.value_zats = zcl_read_u64_le(in + 12);
    memcpy(r.property_id, in + 20, MVAP_PROPERTY_ID_LEN);
    r.kind = kind;
    if (plen)
        memcpy(r.param, in + MVAP_REQ_FIXED, plen);
    r.param[plen] = '\0';
    if (!mvap_param_is_safe(r.param))
        LOG_FAIL(MVAP_TAG, "param rejected by safe-token rule (verb=%s)",
                 mvap_verb_name(verb));

    *out = r;
    return true;
}

/* ── response codec ─────────────────────────────────────────────────────── */

size_t mvap_response_encode(const struct mvap_response *resp, uint8_t *out,
                            size_t out_cap)
{
    if (!resp || !out)
        return 0;
    uint16_t version = encode_version(resp->version);
    if (version == 0)
        return 0;                  /* a version this build does not speak */
    size_t blen = strnlen(resp->body, MVAP_BODY_MAX);
    size_t rec = MVAP_RESP_FIXED + blen;
    if (rec > MVAP_MAX_FRAME || out_cap < MVAP_FRAME_PREFIX + rec)
        return 0;

    uint8_t *p = out + MVAP_FRAME_PREFIX;
    zcl_write_u32_le(out, (uint32_t)rec);
    zcl_write_u32_le(p + 0, MVAP_MAGIC);
    zcl_write_u16_le(p + 4, version);
    zcl_write_u16_le(p + 6, (uint16_t)resp->verb);
    zcl_write_u32_le(p + 8, resp->request_id);
    zcl_write_u32_le(p + 12, (uint32_t)resp->status);
    memcpy(p + 16, resp->receipt_id, MVAP_RECEIPT_ID_LEN);
    zcl_write_u16_le(p + 48, (uint16_t)blen);
    if (blen)
        memcpy(p + MVAP_RESP_FIXED, resp->body, blen);
    return MVAP_FRAME_PREFIX + rec;
}

bool mvap_response_decode(const uint8_t *in, size_t in_len,
                          struct mvap_response *out)
{
    if (!in || !out)
        LOG_FAIL(MVAP_TAG, "null argument in=%p out=%p", (const void *)in,
                 (void *)out);
    if (in_len < MVAP_RESP_FIXED)
        LOG_FAIL(MVAP_TAG, "short response record len=%zu need>=%d", in_len,
                 MVAP_RESP_FIXED);
    if (zcl_read_u32_le(in + 0) != MVAP_MAGIC)
        LOG_FAIL(MVAP_TAG, "bad magic 0x%08x", zcl_read_u32_le(in + 0));
    uint32_t version = accept_version(zcl_read_u16_le(in + 4));
    if (version == 0)
        LOG_FAIL(MVAP_TAG, "unsupported version %u (this build speaks %u..%u)",
                 zcl_read_u16_le(in + 4), MVAP_VERSION_MIN, MVAP_VERSION);

    uint16_t blen = zcl_read_u16_le(in + 48);
    if (blen > MVAP_BODY_MAX || (size_t)MVAP_RESP_FIXED + blen != in_len)
        LOG_FAIL(MVAP_TAG, "body length %u inconsistent with record %zu",
                 blen, in_len);

    struct mvap_response r = { 0 };
    r.verb       = zcl_read_u16_le(in + 6);
    r.version    = version;
    r.request_id = zcl_read_u32_le(in + 8);
    r.status     = (int32_t)zcl_read_u32_le(in + 12);
    memcpy(r.receipt_id, in + 16, MVAP_RECEIPT_ID_LEN);
    if (blen)
        memcpy(r.body, in + MVAP_RESP_FIXED, blen);
    r.body[blen] = '\0';

    *out = r;
    return true;
}
