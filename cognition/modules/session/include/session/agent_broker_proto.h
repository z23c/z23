/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent_broker_proto — the TYPED wire protocol a confined agent speaks to the
 * metaverse agent broker over a Unix-domain socket.
 *
 * THE INVARIANT OF THIS FILE: the wire cannot express a filesystem path, a
 * shell word, an SQL string, or an RPC method name. A request is a fixed-layout
 * record — a verb from a closed enum, a 32-byte property id, a kind, a value in
 * zatoshis, and ONE bounded `param` that mvap_param_is_safe() restricts to
 * [A-Za-z0-9_.-] with no '/' , no '\\' and no "..". There is therefore no
 * request an agent can compose that names a file, so path escape is not
 * mitigated here, it is unrepresentable.
 *
 * Encoding is explicit little-endian byte-at-a-time (never a struct memcpy),
 * length-prefixed, and bounded by MVAP_MAX_FRAME. Decode validates magic,
 * version, verb range, and every declared length against the remaining bytes
 * before it copies anything.
 *
 * Reconciliation note (parallel lanes): the property-kind enum and the
 * 32-byte property id are the shapes Lane 1 (property catalog) owns; the
 * receipt id echoed in a response is the shape Lane 2 (grant/receipt engine)
 * owns. Both are represented here by value, not by including their headers, so
 * this file compiles and is provable on its own.
 */

#ifndef ZCL_SESSION_AGENT_BROKER_PROTO_H
#define ZCL_SESSION_AGENT_BROKER_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* "MVA1" — magic + version guard the frame boundary, so a stray write from a
 * non-agent process on the socket is rejected before any field is trusted.
 *
 * VERSION 2 appends one verb (LIST_FOR_SALE) and renumbers nothing. A version-1
 * frame is still decoded, and it decodes to exactly the operation it always
 * meant: every value v1 defined kept both its number and its meaning, so the
 * compatibility rule is a membership test against the closed v1 verb set
 * (mvap_verb_in_version) and not a translation table. Encoding follows the
 * version the peer spoke — see `version` in struct mvap_request. */
#define MVAP_MAGIC          0x3141564Du
#define MVAP_VERSION        2u
#define MVAP_VERSION_MIN    1u

#define MVAP_PROPERTY_ID_LEN 32
#define MVAP_RECEIPT_ID_LEN  32
#define MVAP_PARAM_MAX       96
#define MVAP_BODY_MAX        1024

/* Wire-record sizes: fixed header + at most one bounded tail. */
#define MVAP_REQ_FIXED   56
#define MVAP_RESP_FIXED  50
#define MVAP_MAX_FRAME   (MVAP_RESP_FIXED + MVAP_BODY_MAX)

/* The closed wire vocabulary: one row per verb, carrying the wire VALUE and
 * the protocol version that first defined it. Values are wire constants —
 * APPEND ONLY, never renumbered, because a grant or a receipt written by an
 * older build carries them.
 *
 * This table is the wire fact and nothing more. Which of these verbs is a
 * read-only QUERY and which is a canonical metaverse ACTION — and which
 * canonical action bit each one carries — lives in exactly one other place,
 * MVAP_VERB_CANON_TABLE in session/agent_broker_vocab.h. Splitting them is
 * deliberate: this header stays free of any opinion about what a verb MEANS,
 * so the codec cannot drift from the vocabulary.
 *
 * INSPECT and LIST are the two QUERIES. LIST is "enumerate what exists" and
 * has always been that on this wire; listing a property FOR SALE is
 * LIST_FOR_SALE, the appended value 14. */
#define MVAP_VERB_TABLE(X)                                                   \
    /*  wire id            value  since version */                           \
    X(INSPECT,             1,     1)                                         \
    X(LIST,                2,     1)                                         \
    X(HOST,                3,     1)                                         \
    X(PUBLISH_REVISION,    4,     1)                                         \
    X(UPDATE_POINTER,      5,     1)                                         \
    X(SELL,                6,     1)                                         \
    X(BUY,                 7,     1)                                         \
    X(DELIVER,             8,     1)                                         \
    X(LEASE,               9,     1)                                         \
    X(TRANSFER,            10,    1)                                         \
    X(ACCEPT_PAYMENT,      11,    1)                                         \
    X(DELEGATE,            12,    1)                                         \
    X(REVOKE,              13,    1)                                         \
    X(LIST_FOR_SALE,       14,    2)

enum mvap_verb {
    MVAP_VERB_NONE = 0,
#define MVAP_VERB_ENUM(id_, value_, since_) MVAP_VERB_##id_ = value_,
    MVAP_VERB_TABLE(MVAP_VERB_ENUM)
#undef MVAP_VERB_ENUM
    MVAP_VERB__COUNT = 15,
};

/* Property kinds ON THE WIRE. The authoritative list is METAVERSE_KIND_TABLE
 * in metaverse/property_id.h; these values exist only so the codec has a
 * fixed-width field to validate, and they are numerically identical to the
 * canonical kinds row for row. session/agent_broker_vocab.c asserts that
 * identity per row at compile time, so a kind added on one side and forgotten
 * on the other does not build. Nothing here decides which kinds exist. */
enum mvap_kind {
    MVAP_KIND_ANY       = 0,
    MVAP_KIND_CONTENT   = 1,   /* ordinary content / blob                */
    MVAP_KIND_ZCODE     = 2,   /* ZCODE package                          */
    MVAP_KIND_NAME      = 3,   /* ZNAM name                              */
    MVAP_KIND_ASSET     = 4,   /* ZSLP asset or badge                    */
    MVAP_KIND_SERVICE   = 5,   /* hosted service                         */
    MVAP_KIND_ENDPOINT  = 6,   /* endpoint / onion site                  */
    MVAP_KIND_PRODUCT   = 7,   /* storefront product                     */
    MVAP_KIND_CONTRACT  = 8,   /* contract / swap                        */
    MVAP_KIND_CHARACTER = 9,   /* character sheet                        */
    MVAP_KIND__COUNT    = 10,
};

/* Response status. Negative values are refusals; every refusal names WHICH
 * check failed, because "denied" alone cannot be operated on. */
enum mvap_status {
    MVAP_OK                        = 0,
    MVAP_ERR_BAD_REQUEST           = -1,
    MVAP_ERR_UNKNOWN_VERB          = -2,
    MVAP_ERR_NOT_FOUND             = -3,
    MVAP_ERR_INTERNAL              = -4,
    MVAP_ERR_DENIED_NO_GRANT       = -5,
    MVAP_ERR_DENIED_REVOKED        = -6,
    MVAP_ERR_DENIED_EXPIRED        = -7,
    MVAP_ERR_DENIED_ACTION         = -8,   /* verb not in the grant's mask   */
    MVAP_ERR_DENIED_PROPERTY       = -9,   /* property id not in grant scope */
    MVAP_ERR_DENIED_KIND           = -10,  /* kind not in grant scope        */
    MVAP_ERR_DENIED_VALUE          = -11,  /* over the per-action ceiling    */
    MVAP_ERR_DENIED_BUDGET         = -12,  /* over the cumulative budget     */
    MVAP_ERR_DENIED_RATE           = -13,  /* over the rate/window limit     */
    MVAP_ERR_DENIED_COUNTERPARTY   = -14,  /* not on the allowlist           */
    MVAP_ERR_DENIED_DELEGATION     = -15,  /* delegation not permitted/depth */
    MVAP_ERR_DENIED_PEER_IDENTITY  = -16,  /* SO_PEERCRED check failed       */
    MVAP_ERR_PLAN_FAILED           = -17,
    MVAP_ERR_COMMIT_FAILED         = -18,
    MVAP_ERR_REVISION_MOVED        = -19,  /* commit-time recheck disagreed  */
    /* The authority said yes and there is NOTHING THAT EXECUTES the action.
     * A distinct refusal on purpose: reporting a mutation nobody performed as
     * COMMIT_FAILED reads like a transient error and invites a retry, and
     * reporting it as OK would be a receipt for an event that did not
     * happen. */
    MVAP_ERR_ACTION_EXECUTOR_UNAVAILABLE = -20,
    /* The query is in the vocabulary and this seam has no bounded result type
     * for it. Named rather than answered with a truncated or improvised
     * body. */
    MVAP_ERR_QUERY_UNAVAILABLE     = -21,
    /* The live authority moved WHILE the decision was being computed over it,
     * and the retry saw it move again. Not a denial and not an approval: the
     * broker declines to answer from a state it cannot prove was coherent. */
    MVAP_ERR_AUTHORITY_CHANGED     = -22,
    /* This request_id already names a DIFFERENT request. The idempotency key
     * is the agent's promise that a repeat is the same ask; a repeat that
     * changed the property, the kind, the value, the parameter, the verb, the
     * protocol version, or the authority is a different ask wearing an old
     * name. Answering it from the ring would hand one property's answer to a
     * question about another, so it is refused and the first request's record
     * is left exactly as it was. */
    MVAP_ERR_REQUEST_ID_REUSED     = -23,
};

/* One request. `param` is NUL-terminated after decode and always passes
 * mvap_param_is_safe(); `property_id` all-zero means "no specific property"
 * and which verbs accept that is the `allows_zero_property_id` column of
 * MVAP_VERB_CANON_TABLE, not a list kept here.
 *
 * `version` is the protocol version this record was decoded from, and the one
 * an encode will write back. Zero means "use the current version", so a
 * zero-initialized request encodes as MVAP_VERSION without the caller saying
 * so; a decoded request carries the peer's version, which is how a reply goes
 * back in the dialect the peer actually speaks. */
struct mvap_request {
    uint32_t verb;                                  /* enum mvap_verb   */
    uint32_t request_id;                            /* idempotency key  */
    uint64_t value_zats;
    uint8_t  property_id[MVAP_PROPERTY_ID_LEN];
    uint16_t kind;                                  /* enum mvap_kind   */
    uint32_t version;                               /* 0 == MVAP_VERSION */
    char     param[MVAP_PARAM_MAX + 1];
};

/* One response. `receipt_id` is all-zero for a query (no mutation, no
 * receipt); `body` is bounded JSON text. `version` follows the same rule as
 * the request's. */
struct mvap_response {
    uint32_t verb;
    uint32_t request_id;
    int32_t  status;                                /* enum mvap_status */
    uint32_t version;                               /* 0 == MVAP_VERSION */
    uint8_t  receipt_id[MVAP_RECEIPT_ID_LEN];
    char     body[MVAP_BODY_MAX + 1];
};

/* True iff `s` is a safe wire token: NUL-terminated, at most MVAP_PARAM_MAX
 * bytes, every byte in [A-Za-z0-9_.-], and no ".." anywhere. The '/' and '\\'
 * exclusions plus the ".." rejection are what make a path unrepresentable. An
 * empty string is safe (it means "no parameter"). */
bool mvap_param_is_safe(const char *s);

/* True iff every byte of `id` is zero — the "no specific property" sentinel. */
bool mvap_property_id_is_zero(const uint8_t id[MVAP_PROPERTY_ID_LEN]);

/* Stable names for the wire enums (used in receipts, audit rows, and replies).
 * Never NULL: an out-of-range value renders as "unknown". */
const char *mvap_verb_name(uint32_t verb);
const char *mvap_kind_name(uint16_t kind);
const char *mvap_status_name(int32_t status);

/* Parse a verb/kind name back to its wire value; returns MVAP_VERB_NONE /
 * MVAP_KIND_ANY on no match. Names are compared case-insensitively. */
uint32_t mvap_verb_from_name(const char *name);
uint16_t mvap_kind_from_name(const char *name);

/* True when `verb` is a verb a peer speaking protocol `version` may send —
 * that is, when the verb's MVAP_VERB_TABLE row was defined at or before it.
 * This is the WHOLE version-1 compatibility rule and its whole bound: a v1
 * frame may carry only the thirteen values v1 defined, and every one of them
 * decodes to exactly the operation it always meant, because no value has ever
 * been renumbered or reused. There is no v1-to-v2 translation table to get
 * wrong, and nothing outside [MVAP_VERSION_MIN, MVAP_VERSION] is accepted. */
bool mvap_verb_in_version(uint32_t verb, uint32_t version);

/* True when `verb` is an ACTION rather than a QUERY.
 *
 * This is NOT the broker's own opinion about what mutates, and it is not the
 * hand-written switch that used to live in agent_broker_proto.c beside the
 * codec. It is one read of the canonical join table in
 * session/agent_broker_vocab.h — the same table that maps the verb to its
 * metaverse action and is asserted row-for-row against the canonical action
 * enum at compile time — which is why it is DEFINED in agent_broker_vocab.c
 * and merely declared here, where every caller already looks for verb facts.
 * There is no way to answer it differently from the class column. */
bool mvap_verb_is_mutation(uint32_t verb);

/* Encode `req` into `out` (capacity `out_cap`). Writes the 4-byte little-endian
 * length prefix followed by the record. Returns the total bytes written, or 0
 * on a NULL argument, an unsafe param, or insufficient capacity. */
size_t mvap_request_encode(const struct mvap_request *req, uint8_t *out,
                           size_t out_cap);

/* Decode a request record from `in` (`in_len` bytes, WITHOUT the length
 * prefix — the caller has already framed it). Returns true and fills `out`
 * only when magic, version, verb range, kind range, and the declared param
 * length all validate and the param passes mvap_param_is_safe(). */
bool mvap_request_decode(const uint8_t *in, size_t in_len,
                         struct mvap_request *out);

/* Encode/decode a response, same framing contract as the request pair. */
size_t mvap_response_encode(const struct mvap_response *resp, uint8_t *out,
                            size_t out_cap);
bool mvap_response_decode(const uint8_t *in, size_t in_len,
                          struct mvap_response *out);

/* Read the 4-byte little-endian frame length at the head of `in`. Returns 0
 * when `in_len` < 4 or the declared length exceeds MVAP_MAX_FRAME — both are
 * "do not trust this stream" answers, never a silent clamp. */
uint32_t mvap_frame_length(const uint8_t *in, size_t in_len);

/* Frame prefix width, so callers need no magic 4. */
#define MVAP_FRAME_PREFIX 4

#endif /* ZCL_SESSION_AGENT_BROKER_PROTO_H */
