/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The bounded PULL wire for one App topic's signed events — the
 * request frame, the answer's length-framed rows, and the per-row decode
 * that hands every row to the App platform's own verifier before anybody
 * is told the row exists. See appsync/app_event_sync.h for the shape and
 * the reasons.
 */

#include "appsync/app_event_sync.h"

#include "base/serialize_le.h"

#include <string.h>

/* ── a bounded cursor over the bytes somebody else sent ──────────────── */

/* Every read goes through this. `bad` latches on the first read that would
 * have run past the end, so a decoder is written as a run of takes with one
 * check at the bottom rather than a check per field — which is the shape a
 * missing check hides in. */
struct sync_cursor {
    const uint8_t *in;
    size_t len;
    size_t at;
    bool bad;
};

static const uint8_t *sync_take(struct sync_cursor *c, size_t n)
{
    if (c->bad || n > c->len - c->at) {
        c->bad = true;
        return NULL;
    }
    const uint8_t *p = c->in + c->at;
    c->at += n;
    return p;
}

static uint16_t sync_take_u16_le(struct sync_cursor *c)
{
    const uint8_t *p = sync_take(c, 2);
    if (!p)
        return 0;
    return zcl_read_u16_le(p);
}

static uint32_t sync_take_u32_le(struct sync_cursor *c)
{
    const uint8_t *p = sync_take(c, 4);
    if (!p)
        return 0;
    return zcl_read_u32_le(p);
}

static uint64_t sync_take_u64_le(struct sync_cursor *c)
{
    const uint8_t *p = sync_take(c, 8);
    if (!p)
        return 0;
    return zcl_read_u64_le(p);
}

static void sync_take_bytes(struct sync_cursor *c, uint8_t *out, size_t n)
{
    const uint8_t *p = sync_take(c, n);
    if (p)
        memcpy(out, p, n);
}

/* A length-framed token copied into a NUL-terminated field. An empty token
 * and a token that does not fit are both refusals: a truncated topic names
 * a different topic, and a nameless one names none. */
static bool sync_take_token(struct sync_cursor *c, size_t n, char *out,
                            size_t cap)
{
    const uint8_t *p = sync_take(c, n);
    if (!p || n == 0 || n >= cap)
        return false;
    if (memchr(p, 0, n))
        return false;
    memcpy(out, p, n);
    out[n] = 0;
    return true;
}

/* ── refusal tokens ──────────────────────────────────────────────────── */

const char *zcl_app_sync_status_label(enum zcl_app_sync_status s)
{
    switch (s) {
    case ZCL_APP_SYNC_OK: return "ok";
    case ZCL_APP_SYNC_ARGUMENT: return "appsync_argument";
    case ZCL_APP_SYNC_MALFORMED: return "appsync_malformed";
    case ZCL_APP_SYNC_VERSION: return "appsync_version";
    case ZCL_APP_SYNC_ROW_TOO_LARGE: return "appsync_row_too_large";
    case ZCL_APP_SYNC_BATCH_FULL: return "appsync_batch_full";
    case ZCL_APP_SYNC_SCOPE: return "appsync_scope";
    case ZCL_APP_SYNC_SIG_INVALID: return "appsync_sig_invalid";
    case ZCL_APP_SYNC_NO_PEER: return "appsync_no_peer";
    case ZCL_APP_SYNC_STORE: return "appsync_store_refused";
    }
    return "appsync_unknown";
}

/* ── the PULL request ────────────────────────────────────────────────── */

/* The length of a NUL-terminated token, or 0 when it is empty, unterminated
 * within its bound, or carries a byte a token may not carry. */
static size_t sync_token_len(const char *value, size_t max_len)
{
    if (!value)
        return 0;
    const char *end = memchr(value, 0, max_len + 1);
    if (!end || end == value)
        return 0;
    return (size_t)(end - value);
}

enum zcl_app_sync_status zcl_app_sync_pull_encode(
    const struct zcl_app_sync_pull *pull, uint8_t *out, size_t cap,
    size_t *len)
{
    if (!pull || !out || !len)
        return ZCL_APP_SYNC_ARGUMENT;
    *len = 0;
    size_t app_len = sync_token_len(pull->app_id, ZCL_APP_ID_MAX);
    size_t topic_len = sync_token_len(pull->topic, ZCL_APP_TOPIC_MAX);
    if (app_len == 0 || topic_len == 0)
        return ZCL_APP_SYNC_ARGUMENT;
    size_t need = ZCL_APP_SYNC_PULL_HEAD_BYTES + app_len + topic_len;
    if (cap < need)
        return ZCL_APP_SYNC_ARGUMENT;
    out[0] = (uint8_t)ZCL_APP_SYNC_MSG_PULL;
    out[1] = (uint8_t)ZCL_APP_SYNC_WIRE_VERSION;
    memcpy(out + 2, pull->since_event_id, 32);
    out[34] = (uint8_t)app_len;
    out[35] = (uint8_t)topic_len;
    memcpy(out + ZCL_APP_SYNC_PULL_HEAD_BYTES, pull->app_id, app_len);
    memcpy(out + ZCL_APP_SYNC_PULL_HEAD_BYTES + app_len, pull->topic,
           topic_len);
    *len = need;
    return ZCL_APP_SYNC_OK;
}

enum zcl_app_sync_status zcl_app_sync_pull_decode(
    const uint8_t *in, size_t len, struct zcl_app_sync_pull *out)
{
    if (!in || !out)
        return ZCL_APP_SYNC_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (len < ZCL_APP_SYNC_PULL_HEAD_BYTES)
        return ZCL_APP_SYNC_MALFORMED;
    if (in[0] != (uint8_t)ZCL_APP_SYNC_MSG_PULL)
        return ZCL_APP_SYNC_MALFORMED;
    if (in[1] != (uint8_t)ZCL_APP_SYNC_WIRE_VERSION)
        return ZCL_APP_SYNC_VERSION;
    memcpy(out->since_event_id, in + 2, 32);
    size_t app_len = in[34];
    size_t topic_len = in[35];
    struct sync_cursor c = {
        .in = in, .len = len, .at = ZCL_APP_SYNC_PULL_HEAD_BYTES,
        .bad = false
    };
    if (app_len > ZCL_APP_ID_MAX || topic_len > ZCL_APP_TOPIC_MAX)
        return ZCL_APP_SYNC_MALFORMED;
    if (!sync_take_token(&c, app_len, out->app_id, sizeof(out->app_id)) ||
        !sync_take_token(&c, topic_len, out->topic, sizeof(out->topic)) ||
        c.bad || c.at != len) {
        memset(out, 0, sizeof(*out));
        return ZCL_APP_SYNC_MALFORMED;
    }
    return ZCL_APP_SYNC_OK;
}

/* ── writing an answer ───────────────────────────────────────────────── */

void zcl_app_sync_writer_init(struct zcl_app_sync_writer *w, uint8_t *out,
                              size_t cap)
{
    if (!w)
        return;
    w->out = out;
    w->cap = cap;
    w->len = 0;
    w->rows = 0;
}

enum zcl_app_sync_status zcl_app_sync_writer_append(
    struct zcl_app_sync_writer *w,
    const struct zcl_app_signed_event_v1 *event)
{
    if (!w || !w->out || !event)
        return ZCL_APP_SYNC_ARGUMENT;
    if (event->signature_len == 0 ||
        event->signature_len > ZCL_APP_EVENT_SIGNATURE_MAX)
        return ZCL_APP_SYNC_ARGUMENT;
    char why[128];
    size_t unsigned_len = 0;
    if (!zcl_app_signed_event_v1_canonical_unsigned(event, NULL, 0,
                                                    &unsigned_len, why,
                                                    sizeof(why)) &&
        unsigned_len == 0)
        return ZCL_APP_SYNC_ARGUMENT;
    size_t frame_len = unsigned_len + 2 + event->signature_len;
    if (frame_len > ZCL_APP_SYNC_EVENT_MAX_BYTES)
        return ZCL_APP_SYNC_ROW_TOO_LARGE;
    size_t need = ZCL_APP_SYNC_ROW_HEAD_BYTES + frame_len;
    if (w->rows >= ZCL_APP_SYNC_BATCH_MAX || need > w->cap - w->len)
        return ZCL_APP_SYNC_BATCH_FULL;

    uint8_t *row = w->out + w->len;
    zcl_write_u32_be(row, (uint32_t)frame_len);
    uint8_t *body = row + ZCL_APP_SYNC_ROW_HEAD_BYTES;
    size_t written = 0;
    if (!zcl_app_signed_event_v1_canonical_unsigned(
            event, body, frame_len, &written, why, sizeof(why)) ||
        written != unsigned_len)
        return ZCL_APP_SYNC_ARGUMENT;
    body[written] = (uint8_t)event->signature_len;
    body[written + 1] = (uint8_t)(event->signature_len >> 8);
    memcpy(body + written + 2, event->signature, event->signature_len);
    w->len += need;
    w->rows++;
    return ZCL_APP_SYNC_OK;
}

/* ── reading an answer ───────────────────────────────────────────────── */

void zcl_app_sync_reader_init(struct zcl_app_sync_reader *r,
                              const uint8_t *in, size_t len)
{
    if (!r)
        return;
    r->in = in;
    r->len = in ? len : 0;
    r->offset = 0;
    r->rows = 0;
}

bool zcl_app_sync_reader_more(const struct zcl_app_sync_reader *r)
{
    return r && r->in && r->offset < r->len;
}

/* The fields that come before the payload: everything of fixed width, plus
 * the two length-framed tokens. Split out so neither half of the decode
 * carries the other's branches. */
static bool sync_decode_head(struct sync_cursor *c,
                             struct zcl_app_signed_event_v1 *out)
{
    out->version = sync_take_u32_le(c);
    sync_take_bytes(c, out->chain_id, sizeof(out->chain_id));
    size_t app_len = sync_take_u16_le(c);
    if (c->bad || !sync_take_token(c, app_len, out->app_id,
                                   sizeof(out->app_id)))
        return false;
    size_t topic_len = sync_take_u16_le(c);
    if (c->bad || !sync_take_token(c, topic_len, out->topic,
                                   sizeof(out->topic)))
        return false;
    out->kind = sync_take_u32_le(c);
    sync_take_bytes(c, out->author_key_id, sizeof(out->author_key_id));
    sync_take_bytes(c, out->author_pubkey, sizeof(out->author_pubkey));
    out->sequence = sync_take_u64_le(c);
    out->created_at = sync_take_u64_le(c);
    sync_take_bytes(c, out->previous_event_id,
                    sizeof(out->previous_event_id));
    return !c->bad;
}

/* The payload and the signature that follow it. The payload is copied into
 * the caller's buffer and borrowed by `out`, which is the same ownership
 * rule the model's read path uses. */
static bool sync_decode_tail(struct sync_cursor *c,
                             struct zcl_app_signed_event_v1 *out,
                             uint8_t *payload, size_t payload_capacity)
{
    uint32_t payload_len = sync_take_u32_le(c);
    if (c->bad || payload_len > ZCL_APP_EVENT_PAYLOAD_MAX ||
        payload_len > payload_capacity)
        return false;
    if (payload_len > 0)
        sync_take_bytes(c, payload, payload_len);
    out->payload.data = payload_len > 0 ? payload : NULL;
    out->payload.len = payload_len;
    uint16_t sig_len = sync_take_u16_le(c);
    if (c->bad || sig_len == 0 || sig_len > ZCL_APP_EVENT_SIGNATURE_MAX)
        return false;
    sync_take_bytes(c, out->signature, sig_len);
    out->signature_len = sig_len;
    return !c->bad;
}

/* One canonical signed frame back into its fields. Shape only: no signature
 * is checked here, and no identity — that is the verifier's job, and having
 * two opinions about it is how they drift. A frame with bytes left over is
 * refused: this build wrote exactly one encoding of an event. */
static enum zcl_app_sync_status sync_decode_frame(
    const uint8_t *in, size_t len, struct zcl_app_signed_event_v1 *out,
    uint8_t *payload, size_t payload_capacity)
{
    struct sync_cursor c = { .in = in, .len = len, .at = 0, .bad = false };
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    if (!sync_decode_head(&c, out) ||
        !sync_decode_tail(&c, out, payload, payload_capacity) ||
        c.at != len)
        return ZCL_APP_SYNC_MALFORMED;
    return ZCL_APP_SYNC_OK;
}

/* Is this row in the topic that was asked for? Asked BEFORE any crypto so a
 * peer cannot spend this box's verification budget on rows nobody wanted;
 * the verifier asks the same question again from the scope, so dropping
 * this check would cost a refusal token, never a guarantee. */
static bool sync_row_in_scope(const struct zcl_app_signed_event_v1 *event,
                              const struct zcl_app_event_scope_v1 *scope)
{
    return strncmp(event->app_id, scope->app_id, ZCL_APP_ID_MAX) == 0 &&
        strncmp(event->topic, scope->topic, ZCL_APP_TOPIC_MAX) == 0;
}

/* Is there a whole row here, and is it one this answer is allowed to carry?
 * Every bound the wire declares, asked before a single byte of the row is
 * looked at. */
static enum zcl_app_sync_status sync_row_bounds(
    const struct zcl_app_sync_reader *r, uint32_t *frame_len)
{
    if (r->len - r->offset < ZCL_APP_SYNC_ROW_HEAD_BYTES)
        return ZCL_APP_SYNC_MALFORMED;
    *frame_len = zcl_read_u32_be(r->in + r->offset);
    if (*frame_len == 0 || *frame_len > ZCL_APP_SYNC_EVENT_MAX_BYTES)
        return ZCL_APP_SYNC_ROW_TOO_LARGE;
    if ((size_t)*frame_len > r->len - r->offset - ZCL_APP_SYNC_ROW_HEAD_BYTES)
        return ZCL_APP_SYNC_MALFORMED;
    if (r->rows >= ZCL_APP_SYNC_BATCH_MAX)
        return ZCL_APP_SYNC_BATCH_FULL;
    return ZCL_APP_SYNC_OK;
}

/* A decoded row's two admissions: it is in the topic that was asked for,
 * and the App platform stands behind its identity and its signature. The
 * event id is recomputed from the row's own bytes rather than trusted, and
 * the verifier compares the two. */
static enum zcl_app_sync_status sync_row_admit(
    struct zcl_app_signed_event_v1 *out,
    const struct zcl_app_event_scope_v1 *scope)
{
    if (!sync_row_in_scope(out, scope))
        return ZCL_APP_SYNC_SCOPE;
    char why[256];
    if (!zcl_app_signed_event_v1_id(out, out->event_id, why, sizeof(why)) ||
        !zcl_app_signed_event_v1_verify(out, scope, why, sizeof(why)))
        return ZCL_APP_SYNC_SIG_INVALID;
    return ZCL_APP_SYNC_OK;
}

enum zcl_app_sync_status zcl_app_sync_reader_next(
    struct zcl_app_sync_reader *r,
    const struct zcl_app_event_scope_v1 *scope,
    struct zcl_app_signed_event_v1 *out, uint8_t *payload,
    size_t payload_capacity)
{
    if (!r || !r->in || !scope || !out || (!payload && payload_capacity > 0))
        return ZCL_APP_SYNC_ARGUMENT;
    memset(out, 0, sizeof(*out));
    uint32_t frame_len = 0;
    enum zcl_app_sync_status st = sync_row_bounds(r, &frame_len);
    if (st != ZCL_APP_SYNC_OK)
        return st;

    const uint8_t *frame = r->in + r->offset + ZCL_APP_SYNC_ROW_HEAD_BYTES;
    st = sync_decode_frame(frame, frame_len, out, payload, payload_capacity);
    if (st == ZCL_APP_SYNC_OK)
        st = sync_row_admit(out, scope);
    if (st != ZCL_APP_SYNC_OK) {
        memset(out, 0, sizeof(*out));
        return st;
    }
    r->offset += ZCL_APP_SYNC_ROW_HEAD_BYTES + frame_len;
    r->rows++;
    return ZCL_APP_SYNC_OK;
}
