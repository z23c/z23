/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The fleet board/wiki post codec and gossip frames. See the header.
 *
 * Everything here is total and allocation-free. A decode either fills the
 * whole post or zeroes it and names one refusal; there is no half-decoded
 * state a caller could mistake for a post. */

#include "session/fleet_board_proto.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t k_zero_id[FLEET_BOARD_ID_BYTES] = {0};

/* Bounded string length. Written out rather than reached for through a
 * feature-test macro: every field here is a fixed array, and the codec must
 * behave the same on every target. */
static size_t fb_strnlen(const char *s, size_t cap)
{
    size_t n = 0;
    while (n < cap && s[n])
        n++;
    return n;
}

const char *fleet_board_result_string(enum fleet_board_result r)
{
    switch (r) {
    case FLEET_BOARD_OK:            return "ok";
    case FLEET_BOARD_ERR_ARGS:      return "missing argument";
    case FLEET_BOARD_ERR_KIND:      return "unknown post kind";
    case FLEET_BOARD_ERR_AGENT:     return "agent name too long or unprintable";
    case FLEET_BOARD_ERR_SLUG:      return "slug is not [a-z0-9-] within 64 bytes";
    case FLEET_BOARD_ERR_TITLE:     return "title too long or unprintable";
    case FLEET_BOARD_ERR_RECEIPT:   return "receipt too long or unprintable";
    case FLEET_BOARD_ERR_TEXT:      return "text is empty or over the kind's limit";
    case FLEET_BOARD_ERR_TTL:       return "ttl is zero or over the ceiling";
    case FLEET_BOARD_ERR_FUTURE:    return "created_at is in the future";
    case FLEET_BOARD_ERR_EXPIRED:   return "post has expired";
    case FLEET_BOARD_ERR_TRUNCATED: return "wire bytes end early";
    case FLEET_BOARD_ERR_TRAILING:  return "wire bytes carry trailing data";
    case FLEET_BOARD_ERR_CAPACITY:  return "output buffer too small";
    case FLEET_BOARD_ERR_ID:        return "id does not match the bytes";
    case FLEET_BOARD_ERR_SIGNATURE: return "signature does not verify";
    }
    return "unknown refusal";
}

static const char *const k_kind_names[FLEET_BOARD_KIND__COUNT] = {
    "none", "problem", "need", "offer", "claim", "result", "note", "wiki",
};

const char *fleet_board_kind_name(uint8_t kind)
{
    if (kind == 0 || kind >= FLEET_BOARD_KIND__COUNT)
        return "unknown";
    return k_kind_names[kind];
}

bool fleet_board_kind_from_name(const char *name, uint8_t *out)
{
    if (!name || !out)
        return false;
    for (uint8_t i = 1; i < FLEET_BOARD_KIND__COUNT; i++) {
        if (strcmp(name, k_kind_names[i]) == 0) {
            *out = i;
            return true;
        }
    }
    return false;
}

bool fleet_board_kind_is_open_question(uint8_t kind)
{
    return kind == FLEET_BOARD_KIND_PROBLEM || kind == FLEET_BOARD_KIND_NEED;
}

uint32_t fleet_board_text_max(uint8_t kind)
{
    return kind == FLEET_BOARD_KIND_WIKI ? (uint32_t)FLEET_BOARD_WIKI_TEXT_MAX
                                         : (uint32_t)FLEET_BOARD_TEXT_MAX;
}

/* Printable-ASCII plus tab and newline. Board text is read by people and by
 * line-oriented scripts, so a control byte or a raw NUL inside the signed
 * bytes is a refusal rather than something a renderer has to survive. */
static bool fb_text_ok(const char *s, size_t len, bool allow_newline)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\t' || (allow_newline && c == '\n'))
            continue;
        if (c < 0x20 || c == 0x7f)
            return false;
    }
    return true;
}

bool fleet_board_slug_valid(const char *slug)
{
    if (!slug)
        return false;
    size_t n = strlen(slug);
    if (n == 0 || n > FLEET_BOARD_SLUG_MAX)
        return false;
    if (slug[0] == '-' || slug[n - 1] == '-')
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = slug[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

void fleet_board_id_to_hex(const uint8_t id[32], char out[65])
{
    zcl_hex_encode(id, 32, out);
}

bool fleet_board_id_from_hex(const char *hex, uint8_t out[32])
{
    return zcl_hex_decode(hex, out, 32);
}

enum fleet_board_result fleet_board_post_validate(
    const struct fleet_board_post *post)
{
    if (!post)
        return FLEET_BOARD_ERR_ARGS;
    if (post->kind == 0 || post->kind >= FLEET_BOARD_KIND__COUNT)
        return FLEET_BOARD_ERR_KIND;
    if (post->ttl == 0 || post->ttl > (uint32_t)FLEET_BOARD_TTL_MAX)
        return FLEET_BOARD_ERR_TTL;

    size_t agent_len = fb_strnlen(post->agent, sizeof(post->agent));
    if (agent_len > FLEET_BOARD_AGENT_MAX ||
        !fb_text_ok(post->agent, agent_len, false))
        return FLEET_BOARD_ERR_AGENT;

    size_t receipt_len = fb_strnlen(post->receipt, sizeof(post->receipt));
    if (receipt_len > FLEET_BOARD_RECEIPT_MAX ||
        !fb_text_ok(post->receipt, receipt_len, false))
        return FLEET_BOARD_ERR_RECEIPT;

    size_t slug_len = fb_strnlen(post->slug, sizeof(post->slug));
    size_t title_len = fb_strnlen(post->title, sizeof(post->title));
    if (post->kind == FLEET_BOARD_KIND_WIKI) {
        /* A wiki revision is addressed by its slug; without one there is no
         * page for `wiki read` to resolve and the revision is unreachable. */
        if (!fleet_board_slug_valid(post->slug))
            return FLEET_BOARD_ERR_SLUG;
        if (title_len == 0 || title_len > FLEET_BOARD_TITLE_MAX ||
            !fb_text_ok(post->title, title_len, false))
            return FLEET_BOARD_ERR_TITLE;
    } else {
        if (slug_len != 0)
            return FLEET_BOARD_ERR_SLUG;
        if (title_len != 0)
            return FLEET_BOARD_ERR_TITLE;
        if (memcmp(post->supersedes, k_zero_id, sizeof(k_zero_id)) != 0)
            return FLEET_BOARD_ERR_SLUG;
    }

    if (post->text_len == 0 || post->text_len > fleet_board_text_max(post->kind))
        return FLEET_BOARD_ERR_TEXT;
    if (post->text_len != fb_strnlen(post->text, sizeof(post->text)))
        return FLEET_BOARD_ERR_TEXT;
    if (!fb_text_ok(post->text, post->text_len, true))
        return FLEET_BOARD_ERR_TEXT;
    return FLEET_BOARD_OK;
}

/* A tiny append cursor. Every writer checks capacity first, so a short buffer
 * can never produce a partly written body that still hashes to something. */
struct fb_cursor {
    uint8_t *p;
    size_t cap;
    size_t used;
    bool overflow;
};

static void fb_put(struct fb_cursor *c, const void *src, size_t n)
{
    if (c->used + n < c->used || c->used + n > c->cap) {
        c->overflow = true;
        c->used += n;
        return;
    }
    if (n && src)
        memcpy(c->p + c->used, src, n);
    c->used += n;
}

static void fb_put_u8(struct fb_cursor *c, uint8_t v) { fb_put(c, &v, 1); }

static void fb_put_u16(struct fb_cursor *c, uint16_t v)
{
    uint8_t b[2];
    zcl_write_u16_le(b, v);
    fb_put(c, b, sizeof(b));
}

static void fb_put_u32(struct fb_cursor *c, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_le(b, v);
    fb_put(c, b, sizeof(b));
}

static void fb_put_u64(struct fb_cursor *c, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    fb_put(c, b, sizeof(b));
}

/* Length-framed string: u16 length then the bytes, never a NUL terminator.
 * Framing every variable field means no two distinct posts can share a body. */
static void fb_put_str16(struct fb_cursor *c, const char *s, size_t n)
{
    fb_put_u16(c, (uint16_t)n);
    fb_put(c, s, n);
}

enum fleet_board_result fleet_board_post_canonical(
    const struct fleet_board_post *post, uint8_t *out, size_t out_capacity,
    size_t *out_len)
{
    if (!post || !out_len)
        return FLEET_BOARD_ERR_ARGS;
    enum fleet_board_result shape = fleet_board_post_validate(post);
    if (shape != FLEET_BOARD_OK)
        return shape;

    struct fb_cursor c = {.p = out, .cap = out ? out_capacity : 0};
    /* The domain is written WITH its NUL so no domain can prefix another. */
    fb_put(&c, FLEET_BOARD_POST_V1_DOMAIN, sizeof(FLEET_BOARD_POST_V1_DOMAIN));
    fb_put_u8(&c, post->kind);
    fb_put_u64(&c, post->created_at);
    fb_put_u32(&c, post->ttl);
    fb_put(&c, post->ref, FLEET_BOARD_ID_BYTES);
    fb_put(&c, post->host_pubkey, FLEET_BOARD_PUBKEY_BYTES);
    fb_put_str16(&c, post->agent, fb_strnlen(post->agent, sizeof(post->agent)));
    fb_put_str16(&c, post->slug, fb_strnlen(post->slug, sizeof(post->slug)));
    fb_put_str16(&c, post->title, fb_strnlen(post->title, sizeof(post->title)));
    fb_put(&c, post->supersedes, FLEET_BOARD_ID_BYTES);
    fb_put_str16(&c, post->receipt,
                 fb_strnlen(post->receipt, sizeof(post->receipt)));
    fb_put_u32(&c, post->text_len);
    fb_put(&c, post->text, post->text_len);

    /* A NULL/zero buffer is the size query: out_len is still exact and the
     * refusal is the ordinary short-buffer one, so a caller that only wants
     * the encoded size needs no buffer and no special case. */
    *out_len = c.used;
    return c.overflow ? FLEET_BOARD_ERR_CAPACITY : FLEET_BOARD_OK;
}

enum fleet_board_result fleet_board_post_compute_id(
    const struct fleet_board_post *post, uint8_t out_id[32])
{
    if (!post || !out_id)
        return FLEET_BOARD_ERR_ARGS;
    uint8_t body[FLEET_BOARD_BODY_MAX];
    size_t body_len = 0;
    enum fleet_board_result r =
        fleet_board_post_canonical(post, body, sizeof(body), &body_len);
    if (r != FLEET_BOARD_OK)
        return r;
    sha3_256(body, body_len, out_id);
    return FLEET_BOARD_OK;
}

/* The signature commits to the id, and the id commits to every signed byte,
 * so signing the id signs the post exactly once. */
static void fb_signing_digest(const uint8_t id[32], uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)FLEET_BOARD_POST_V1_SIG_DOMAIN,
                   sizeof(FLEET_BOARD_POST_V1_SIG_DOMAIN));
    sha3_256_write(&ctx, id, 32);
    sha3_256_finalize(&ctx, out);
}

enum fleet_board_result fleet_board_post_sign(
    struct fleet_board_post *post, const uint8_t secret_seed[32],
    const uint8_t host_pubkey[32])
{
    if (!post || !secret_seed || !host_pubkey)
        return FLEET_BOARD_ERR_ARGS;
    memcpy(post->host_pubkey, host_pubkey, FLEET_BOARD_PUBKEY_BYTES);
    enum fleet_board_result r = fleet_board_post_compute_id(post, post->id);
    if (r != FLEET_BOARD_OK)
        return r;
    uint8_t digest[32];
    fb_signing_digest(post->id, digest);
    ed25519_sign(post->signature, digest, sizeof(digest), secret_seed,
                 host_pubkey);
    return FLEET_BOARD_OK;
}

enum fleet_board_result fleet_board_post_verify(
    const struct fleet_board_post *post)
{
    if (!post)
        return FLEET_BOARD_ERR_ARGS;
    uint8_t id[32];
    enum fleet_board_result r = fleet_board_post_compute_id(post, id);
    if (r != FLEET_BOARD_OK)
        return r;
    /* Identity before cryptography: a mismatched id is a cheap refusal and
     * spends no curve arithmetic on a peer's chosen bytes. */
    if (memcmp(id, post->id, sizeof(id)) != 0)
        return FLEET_BOARD_ERR_ID;
    uint8_t digest[32];
    fb_signing_digest(id, digest);
    if (!ed25519_verify(post->signature, digest, sizeof(digest),
                        post->host_pubkey))
        return FLEET_BOARD_ERR_SIGNATURE;
    return FLEET_BOARD_OK;
}

enum fleet_board_result fleet_board_post_check_time(
    const struct fleet_board_post *post, int64_t now)
{
    if (!post)
        return FLEET_BOARD_ERR_ARGS;
    if (post->ttl == 0 || post->ttl > (uint32_t)FLEET_BOARD_TTL_MAX)
        return FLEET_BOARD_ERR_TTL;
    if (post->created_at > (uint64_t)INT64_MAX)
        return FLEET_BOARD_ERR_FUTURE;
    int64_t created = (int64_t)post->created_at;
    if (created > now + FLEET_BOARD_FUTURE_SKEW_MAX)
        return FLEET_BOARD_ERR_FUTURE;
    /* Wiki revisions are durable signed history. A fresh peer must still
     * reconstruct them after the original publisher and its TTL disappear. */
    if (post->kind != FLEET_BOARD_KIND_WIKI &&
        created + (int64_t)post->ttl <= now)
        return FLEET_BOARD_ERR_EXPIRED;
    return FLEET_BOARD_OK;
}

enum fleet_board_result fleet_board_post_encode(
    const struct fleet_board_post *post, uint8_t *out, size_t out_capacity,
    size_t *out_len)
{
    if (!post || !out || !out_len)
        return FLEET_BOARD_ERR_ARGS;
    size_t body_len = 0;
    enum fleet_board_result r =
        fleet_board_post_canonical(post, out, out_capacity, &body_len);
    if (r != FLEET_BOARD_OK) {
        *out_len = body_len + FLEET_BOARD_SIG_BYTES;
        return r;
    }
    if (body_len + FLEET_BOARD_SIG_BYTES > out_capacity) {
        *out_len = body_len + FLEET_BOARD_SIG_BYTES;
        return FLEET_BOARD_ERR_CAPACITY;
    }
    memcpy(out + body_len, post->signature, FLEET_BOARD_SIG_BYTES);
    *out_len = body_len + FLEET_BOARD_SIG_BYTES;
    return FLEET_BOARD_OK;
}

/* Read cursor mirroring fb_cursor. `bad` latches, so one short read poisons
 * the whole decode instead of letting later fields read stale memory. */
struct fb_reader {
    const uint8_t *p;
    size_t len;
    size_t pos;
    bool bad;
};

static bool fb_take(struct fb_reader *r, void *dst, size_t n)
{
    if (r->bad || r->pos + n < r->pos || r->pos + n > r->len) {
        r->bad = true;
        return false;
    }
    if (n && dst)
        memcpy(dst, r->p + r->pos, n);
    r->pos += n;
    return true;
}

static uint8_t fb_take_u8(struct fb_reader *r)
{
    uint8_t v = 0;
    (void)fb_take(r, &v, 1);
    return v;
}

static uint16_t fb_take_u16(struct fb_reader *r)
{
    uint8_t b[2] = {0};
    (void)fb_take(r, b, sizeof(b));
    return zcl_read_u16_le(b);
}

static uint32_t fb_take_u32(struct fb_reader *r)
{
    uint8_t b[4] = {0};
    (void)fb_take(r, b, sizeof(b));
    return zcl_read_u32_le(b);
}

static uint64_t fb_take_u64(struct fb_reader *r)
{
    uint8_t b[8] = {0};
    (void)fb_take(r, b, sizeof(b));
    return zcl_read_u64_le(b);
}

/* Length-framed string into a fixed field. A length over the field's capacity
 * is a decode refusal, never a silent truncation: truncating would change the
 * bytes and therefore the id, and the post would then fail its own check for
 * the wrong reason. */
static bool fb_take_str16(struct fb_reader *r, char *dst, size_t dst_capacity)
{
    uint16_t n = fb_take_u16(r);
    if (r->bad || (size_t)n >= dst_capacity) {
        r->bad = true;
        return false;
    }
    if (!fb_take(r, dst, n))
        return false;
    dst[n] = '\0';
    return true;
}

enum fleet_board_result fleet_board_post_decode(
    const uint8_t *wire, size_t wire_len, struct fleet_board_post *out)
{
    if (!wire || !out)
        return FLEET_BOARD_ERR_ARGS;
    memset(out, 0, sizeof(*out));

    struct fb_reader r = {.p = wire, .len = wire_len};
    char domain[sizeof(FLEET_BOARD_POST_V1_DOMAIN)] = {0};
    if (!fb_take(&r, domain, sizeof(domain)) ||
        memcmp(domain, FLEET_BOARD_POST_V1_DOMAIN, sizeof(domain)) != 0) {
        memset(out, 0, sizeof(*out));
        return r.bad ? FLEET_BOARD_ERR_TRUNCATED : FLEET_BOARD_ERR_KIND;
    }
    out->kind = fb_take_u8(&r);
    out->created_at = fb_take_u64(&r);
    out->ttl = fb_take_u32(&r);
    (void)fb_take(&r, out->ref, FLEET_BOARD_ID_BYTES);
    (void)fb_take(&r, out->host_pubkey, FLEET_BOARD_PUBKEY_BYTES);
    (void)fb_take_str16(&r, out->agent, sizeof(out->agent));
    (void)fb_take_str16(&r, out->slug, sizeof(out->slug));
    (void)fb_take_str16(&r, out->title, sizeof(out->title));
    (void)fb_take(&r, out->supersedes, FLEET_BOARD_ID_BYTES);
    (void)fb_take_str16(&r, out->receipt, sizeof(out->receipt));
    out->text_len = fb_take_u32(&r);
    if (!r.bad && out->text_len >= sizeof(out->text))
        r.bad = true;
    if (!r.bad && fb_take(&r, out->text, out->text_len))
        out->text[out->text_len] = '\0';
    if (!r.bad)
        (void)fb_take(&r, out->signature, FLEET_BOARD_SIG_BYTES);
    if (r.bad) {
        memset(out, 0, sizeof(*out));
        return FLEET_BOARD_ERR_TRUNCATED;
    }
    if (r.pos != r.len) {
        memset(out, 0, sizeof(*out));
        return FLEET_BOARD_ERR_TRAILING;
    }

    enum fleet_board_result shape = fleet_board_post_validate(out);
    if (shape != FLEET_BOARD_OK) {
        memset(out, 0, sizeof(*out));
        return shape;
    }
    enum fleet_board_result r_id = fleet_board_post_compute_id(out, out->id);
    if (r_id != FLEET_BOARD_OK) {
        memset(out, 0, sizeof(*out));
        return r_id;
    }
    enum fleet_board_result r_sig = fleet_board_post_verify(out);
    if (r_sig != FLEET_BOARD_OK) {
        memset(out, 0, sizeof(*out));
        return r_sig;
    }
    return FLEET_BOARD_OK;
}

/* ── frames ─────────────────────────────────────────────────────────── */

bool fleet_board_frame_is_board(const uint8_t *wire, size_t wire_len)
{
    return wire && wire_len >= FLEET_BOARD_FRAME_MAGIC_BYTES + 1 &&
           memcmp(wire, FLEET_BOARD_FRAME_MAGIC,
                  FLEET_BOARD_FRAME_MAGIC_BYTES) == 0;
}

uint8_t fleet_board_frame_type(const uint8_t *wire, size_t wire_len)
{
    if (!fleet_board_frame_is_board(wire, wire_len))
        return 0;
    return wire[FLEET_BOARD_FRAME_MAGIC_BYTES];
}

enum fleet_board_result fleet_board_frame_encode_ids(
    uint8_t type, const uint8_t (*ids)[32], size_t count, uint8_t *out,
    size_t out_capacity, size_t *out_len)
{
    if (!out || !out_len ||
        (type != FLEET_BOARD_FRAME_INV && type != FLEET_BOARD_FRAME_GET))
        return FLEET_BOARD_ERR_ARGS;
    if (count > FLEET_BOARD_FRAME_IDS_MAX || (count && !ids))
        return FLEET_BOARD_ERR_ARGS;
    struct fb_cursor c = {.p = out, .cap = out_capacity};
    fb_put(&c, FLEET_BOARD_FRAME_MAGIC, FLEET_BOARD_FRAME_MAGIC_BYTES);
    fb_put_u8(&c, type);
    fb_put_u16(&c, (uint16_t)count);
    for (size_t i = 0; i < count; i++)
        fb_put(&c, ids[i], 32);
    *out_len = c.used;
    return c.overflow ? FLEET_BOARD_ERR_CAPACITY : FLEET_BOARD_OK;
}

enum fleet_board_result fleet_board_frame_decode_ids(
    const uint8_t *wire, size_t wire_len, uint8_t *type_out,
    uint8_t (*ids)[32], size_t ids_capacity, size_t *count_out)
{
    if (!wire || !type_out || !count_out)
        return FLEET_BOARD_ERR_ARGS;
    *count_out = 0;
    if (!fleet_board_frame_is_board(wire, wire_len))
        return FLEET_BOARD_ERR_TRUNCATED;
    struct fb_reader r = {.p = wire, .len = wire_len};
    (void)fb_take(&r, NULL, FLEET_BOARD_FRAME_MAGIC_BYTES);
    uint8_t type = fb_take_u8(&r);
    if (type != FLEET_BOARD_FRAME_INV && type != FLEET_BOARD_FRAME_GET)
        return FLEET_BOARD_ERR_KIND;
    uint16_t count = fb_take_u16(&r);
    if (r.bad)
        return FLEET_BOARD_ERR_TRUNCATED;
    if (count > FLEET_BOARD_FRAME_IDS_MAX || (size_t)count > ids_capacity)
        return FLEET_BOARD_ERR_CAPACITY;
    for (uint16_t i = 0; i < count; i++) {
        if (!fb_take(&r, ids ? ids[i] : NULL, 32))
            return FLEET_BOARD_ERR_TRUNCATED;
    }
    if (r.pos != r.len)
        return FLEET_BOARD_ERR_TRAILING;
    *type_out = type;
    *count_out = count;
    return FLEET_BOARD_OK;
}

enum fleet_board_result fleet_board_frame_encode_post(
    const struct fleet_board_post *post, uint8_t *out, size_t out_capacity,
    size_t *out_len)
{
    if (!post || !out || !out_len)
        return FLEET_BOARD_ERR_ARGS;
    if (out_capacity < FLEET_BOARD_FRAME_MAGIC_BYTES + 1)
        return FLEET_BOARD_ERR_CAPACITY;
    memcpy(out, FLEET_BOARD_FRAME_MAGIC, FLEET_BOARD_FRAME_MAGIC_BYTES);
    out[FLEET_BOARD_FRAME_MAGIC_BYTES] = FLEET_BOARD_FRAME_POST;
    size_t header = FLEET_BOARD_FRAME_MAGIC_BYTES + 1;
    size_t body_len = 0;
    enum fleet_board_result r = fleet_board_post_encode(
        post, out + header, out_capacity - header, &body_len);
    *out_len = header + body_len;
    return r;
}

enum fleet_board_result fleet_board_frame_decode_post(
    const uint8_t *wire, size_t wire_len, struct fleet_board_post *out)
{
    if (!wire || !out)
        return FLEET_BOARD_ERR_ARGS;
    memset(out, 0, sizeof(*out));
    if (fleet_board_frame_type(wire, wire_len) != FLEET_BOARD_FRAME_POST)
        return FLEET_BOARD_ERR_KIND;
    size_t header = FLEET_BOARD_FRAME_MAGIC_BYTES + 1;
    return fleet_board_post_decode(wire + header, wire_len - header, out);
}

void fleet_board_chain_step(const uint8_t previous[32], const uint8_t id[32],
                            uint8_t out_chain[32])
{
    if (!out_chain)
        return;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)FLEET_BOARD_CHAIN_V1_DOMAIN,
                   sizeof(FLEET_BOARD_CHAIN_V1_DOMAIN));
    sha3_256_write(&ctx, previous ? previous : k_zero_id, 32);
    sha3_256_write(&ctx, id ? id : k_zero_id, 32);
    sha3_256_finalize(&ctx, out_chain);
}
