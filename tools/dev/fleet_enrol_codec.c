/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Wire codec and signatures for the three fleet enrolment records.
 *          See tools/dev/fleet_enrol.h for the contract.
 *
 * Every record is the same three parts: a body, an Ed25519 signature over
 * a DOMAIN STRING plus that body, and unpadded base64url around the whole
 * thing. The domain string is what stops a signature minted for one record
 * from being replayed as another; it is a compile-time constant per record
 * and is never taken from the wire.
 *
 * The decoders are the attack surface — every one of them runs on bytes an
 * owner pasted from somewhere. They therefore: refuse a length before
 * reading it, never trust a length field beyond the buffer it indexes,
 * accept only printable ASCII in any text field (these fields reach a
 * roster line and an ssh authorized_keys comment), and verify the signature
 * before the caller sees a single decoded field.
 */

#include "fleet_enrol.h"

#include "crypto/ed25519.h"
#include "net/acme_b64url.h"

#include <string.h>

#define FE_VERSION 1u
#define FE_DOMAIN_INVITE "z23-fleet-invite-v1"
#define FE_DOMAIN_RECEIPT "z23-fleet-enrol-v1"
#define FE_DOMAIN_MACHINE "z23-fleet-machine-v1"

/* One signing buffer: domain string, then body. Sized for the largest body
 * plus the longest domain. */
#define FE_SIGN_MAX (FLEET_ENROL_MACHINE_WIRE_MAX + 32)

static void fe_why(const char **why, const char *token)
{
    if (why) *why = token;
}

/* ── bounded writer ─────────────────────────────────────────────────────── */

struct fe_put {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool ok;
};

static void fe_put_raw(struct fe_put *p, const void *data, size_t n)
{
    if (!p->ok || n > p->cap - p->len) { p->ok = false; return; }
    if (n) memcpy(p->buf + p->len, data, n);
    p->len += n;
}

static void fe_put_u8(struct fe_put *p, uint8_t v) { fe_put_raw(p, &v, 1); }

static void fe_put_be(struct fe_put *p, uint64_t v, unsigned width)
{
    uint8_t tmp[8];
    for (unsigned i = 0; i < width; ++i)
        tmp[i] = (uint8_t)(v >> (8u * (width - 1u - i)));
    fe_put_raw(p, tmp, width);
}

/* A text field: one length byte then the bytes. Refuses anything that is
 * not printable ASCII rather than silently truncating, so a field that
 * cannot be rendered safely is a refusal at mint time, on this box, where
 * somebody can fix it. */
static void fe_put_str8(struct fe_put *p, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n > 255u) { p->ok = false; return; }
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20u || c > 0x7eu) { p->ok = false; return; }
    }
    fe_put_u8(p, (uint8_t)n);
    fe_put_raw(p, s, n);
}

static void fe_put_str16(struct fe_put *p, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n > 65535u) { p->ok = false; return; }
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20u || c > 0x7eu) { p->ok = false; return; }
    }
    fe_put_be(p, n, 2);
    fe_put_raw(p, s, n);
}

/* ── bounded reader ─────────────────────────────────────────────────────── */

struct fe_get {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    bool ok;
};

static const uint8_t *fe_get_raw(struct fe_get *g, size_t n)
{
    if (!g->ok || n > g->len - g->pos) { g->ok = false; return NULL; }
    const uint8_t *at = g->buf + g->pos;
    g->pos += n;
    return at;
}

static uint8_t fe_get_u8(struct fe_get *g)
{
    const uint8_t *at = fe_get_raw(g, 1);
    return at ? *at : 0u;
}

static uint64_t fe_get_be(struct fe_get *g, unsigned width)
{
    const uint8_t *at = fe_get_raw(g, width);
    uint64_t v = 0;
    if (!at) return 0;
    for (unsigned i = 0; i < width; ++i) v = (v << 8) | at[i];
    return v;
}

static void fe_get_bytes(struct fe_get *g, uint8_t *out, size_t n)
{
    const uint8_t *at = fe_get_raw(g, n);
    if (at) memcpy(out, at, n);
    else memset(out, 0, n);
}

/* Read a text field into a fixed buffer. A field longer than the buffer is
 * a refusal, never a truncation: a truncated hostname is a different fact,
 * and a truncated ssh key is a different key. */
static void fe_get_text(struct fe_get *g, char *out, size_t cap, unsigned width)
{
    size_t n = (size_t)fe_get_be(g, width);
    const uint8_t *at = fe_get_raw(g, n);
    if (!g->ok || n >= cap) { g->ok = false; out[0] = '\0'; return; }
    for (size_t i = 0; i < n; ++i) {
        if (at[i] < 0x20u || at[i] > 0x7eu) { g->ok = false; out[0] = '\0'; return; }
    }
    if (n) memcpy(out, at, n);
    out[n] = '\0';
}

/* ── seal / open ────────────────────────────────────────────────────────── */

/* Sign `body` under `domain` and emit base64url of body||signature. */
static bool fe_seal(const char *domain, const uint8_t *body, size_t body_len,
                    const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                    const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                    uint8_t *wire, size_t wire_cap, size_t *wire_len,
                    char *text, size_t text_cap, const char **why)
{
    uint8_t message[FE_SIGN_MAX];
    size_t domain_len = strlen(domain);
    if (body_len + domain_len > sizeof(message) ||
        body_len + FLEET_ENROL_SIG_BYTES > wire_cap) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    memcpy(message, domain, domain_len);
    memcpy(message + domain_len, body, body_len);
    memcpy(wire, body, body_len);
    ed25519_sign(wire + body_len, message, domain_len + body_len, seed, pubkey);
    *wire_len = body_len + FLEET_ENROL_SIG_BYTES;
    if (acme_b64url_encode(wire, *wire_len, text, text_cap) == 0) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    return true;
}

/* Decode base64url into `wire` and confirm the trailing signature over
 * domain||body by `pubkey`. Returns the body length through `body_len`. */
static bool fe_open(const char *text, const char *domain,
                    const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                    uint8_t *wire, size_t wire_cap, size_t *wire_len,
                    size_t *body_len, const char *malformed_why,
                    const char *signature_why, const char **why)
{
    uint8_t message[FE_SIGN_MAX];
    size_t decoded = 0, domain_len = strlen(domain);
    if (!text || !text[0] || !acme_b64url_decode(text, wire, wire_cap, &decoded) ||
        decoded <= FLEET_ENROL_SIG_BYTES) {
        fe_why(why, malformed_why);
        return false;
    }
    *wire_len = decoded;
    *body_len = decoded - FLEET_ENROL_SIG_BYTES;
    if (*body_len + domain_len > sizeof(message)) {
        fe_why(why, malformed_why);
        return false;
    }
    memcpy(message, domain, domain_len);
    memcpy(message + domain_len, wire, *body_len);
    if (!ed25519_verify(wire + *body_len, message, domain_len + *body_len,
                        pubkey)) {
        fe_why(why, signature_why);
        return false;
    }
    return true;
}

/* ── invite ─────────────────────────────────────────────────────────────── */

bool fleet_enrol_name_valid(const char *name)
{
    size_t n = name ? strlen(name) : 0;
    if (n < (size_t)FLEET_ENROL_NAME_MIN || n > (size_t)FLEET_ENROL_NAME_MAX)
        return false;
    for (size_t i = 0; i < n; ++i) {
        char c = name[i];
        bool alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        /* One spelling per name: lowercase letters, digits and interior
         * dashes only. A name a person can say out loud is the point, and
         * two names that differ by a dot or a capital would be two handles
         * for one machine in conversation. */
        if (!alnum && !(i > 0 && i + 1u < n && c == '-'))
            return false;
    }
    return true;
}

static bool fe_relay_valid(const char *relay)
{
    size_t n = relay ? strlen(relay) : 0;
    if (n > (size_t)FLEET_ENROL_RELAY_MAX) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)relay[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':' ||
                  c == '_' || c == '[' || c == ']';
        if (!ok) return false;
    }
    return true;
}

static void fe_invite_body(struct fe_put *p, const struct fleet_invite *inv)
{
    fe_put_u8(p, FE_VERSION);
    fe_put_str8(p, inv->name);
    fe_put_be(p, (uint64_t)inv->expires_unix, 8);
    fe_put_raw(p, inv->nonce, FLEET_ENROL_NONCE_BYTES);
    fe_put_str8(p, inv->relay);
    fe_put_raw(p, inv->operator_pubkey, FLEET_ENROL_PUBKEY_BYTES);
}

bool fleet_invite_mint(const char *name, int64_t ttl_hours, const char *relay,
                       const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                       const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                       int64_t now_unix, char *text, size_t text_cap,
                       struct fleet_invite *out, const char **why)
{
    uint8_t body[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t wire[FLEET_ENROL_INVITE_WIRE_MAX];
    struct fe_put p = { body, sizeof(body), 0, true };
    size_t wire_len = 0;
    fe_why(why, NULL);
    if (!fleet_enrol_name_valid(name)) {
        fe_why(why, FLEET_ENROL_WHY_NAME_INVALID);
        return false;
    }
    if (ttl_hours < FLEET_ENROL_TTL_HOURS_MIN ||
        ttl_hours > FLEET_ENROL_TTL_HOURS_MAX) {
        fe_why(why, FLEET_ENROL_WHY_TTL_INVALID);
        return false;
    }
    if (!fe_relay_valid(relay)) {
        fe_why(why, FLEET_ENROL_WHY_RELAY_INVALID);
        return false;
    }
    memset(out->name, 0, sizeof(out->name));
    memcpy(out->name, name, strlen(name));
    out->expires_unix = now_unix + ttl_hours * 3600;
    memset(out->relay, 0, sizeof(out->relay));
    if (relay) memcpy(out->relay, relay, strlen(relay));
    memcpy(out->operator_pubkey, pubkey, FLEET_ENROL_PUBKEY_BYTES);
    fe_invite_body(&p, out);
    if (!p.ok) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    if (!fe_seal(FE_DOMAIN_INVITE, body, p.len, seed, pubkey, wire,
                 sizeof(wire), &wire_len, text, text_cap, why))
        return false;
    memcpy(out->signature, wire + p.len, FLEET_ENROL_SIG_BYTES);
    return true;
}

bool fleet_invite_parse(const char *text, struct fleet_invite *out,
                        uint8_t *wire, size_t wire_cap, size_t *wire_len,
                        const char **why)
{
    uint8_t local[FLEET_ENROL_INVITE_WIRE_MAX];
    size_t decoded = 0, body_len = 0;
    struct fe_get g = { local, 0, 0, true };
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    fe_why(why, NULL);
    memset(out, 0, sizeof(*out));
    /* The operator key is inside the token, so the verify needs one pass to
     * find it and a second to check the signature. The first pass reads
     * ONLY the fixed-shape prefix, and reads it out of the same bounded
     * decode the second pass verifies. */
    if (!text || !text[0] ||
        !acme_b64url_decode(text, local, sizeof(local), &decoded) ||
        decoded <= FLEET_ENROL_SIG_BYTES ||
        decoded < FLEET_ENROL_SIG_BYTES + FLEET_ENROL_PUBKEY_BYTES) {
        fe_why(why, FLEET_ENROL_WHY_INVITE_MALFORMED);
        return false;
    }
    memcpy(operator_pubkey,
           local + decoded - FLEET_ENROL_SIG_BYTES - FLEET_ENROL_PUBKEY_BYTES,
           FLEET_ENROL_PUBKEY_BYTES);
    if (!fe_open(text, FE_DOMAIN_INVITE, operator_pubkey, local, sizeof(local),
                 &decoded, &body_len, FLEET_ENROL_WHY_INVITE_MALFORMED,
                 FLEET_ENROL_WHY_INVITE_SIGNATURE, why))
        return false;
    g.len = body_len;
    if (fe_get_u8(&g) != FE_VERSION) {
        fe_why(why, FLEET_ENROL_WHY_INVITE_MALFORMED);
        return false;
    }
    fe_get_text(&g, out->name, sizeof(out->name), 1);
    out->expires_unix = (int64_t)fe_get_be(&g, 8);
    fe_get_bytes(&g, out->nonce, FLEET_ENROL_NONCE_BYTES);
    fe_get_text(&g, out->relay, sizeof(out->relay), 1);
    fe_get_bytes(&g, out->operator_pubkey, FLEET_ENROL_PUBKEY_BYTES);
    /* Trailing bytes mean the sender encoded something this version does not
     * understand; admitting it would sign an interpretation nobody made. */
    if (!g.ok || g.pos != body_len || !fleet_enrol_name_valid(out->name)) {
        fe_why(why, FLEET_ENROL_WHY_INVITE_MALFORMED);
        return false;
    }
    memcpy(out->signature, local + body_len, FLEET_ENROL_SIG_BYTES);
    if (wire) {
        if (decoded > wire_cap) {
            fe_why(why, FLEET_ENROL_WHY_INVITE_MALFORMED);
            return false;
        }
        memcpy(wire, local, decoded);
        *wire_len = decoded;
    }
    return true;
}

/* ── receipt ────────────────────────────────────────────────────────────── */

static void fe_receipt_body(struct fe_put *p, const uint8_t *invite_wire,
                            size_t invite_wire_len,
                            const struct fleet_box_facts *f,
                            const char *ssh_pubkey,
                            const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES])
{
    fe_put_u8(p, FE_VERSION);
    fe_put_be(p, invite_wire_len, 2);
    fe_put_raw(p, invite_wire, invite_wire_len);
    fe_put_str8(p, f->hostname);
    fe_put_str8(p, f->os);
    fe_put_str8(p, f->os_version);
    fe_put_str8(p, f->arch);
    fe_put_str8(p, f->toolchain);
    fe_put_str8(p, f->git_head);
    fe_put_be(p, f->cores, 4);
    fe_put_be(p, f->ram_mb, 8);
    fe_put_be(p, f->disk_free_mb, 8);
    fe_put_str16(p, ssh_pubkey);
    fe_put_raw(p, pubkey, FLEET_ENROL_PUBKEY_BYTES);
}

bool fleet_receipt_mint(const uint8_t *invite_wire, size_t invite_wire_len,
                        const struct fleet_box_facts *facts,
                        const char *ssh_pubkey,
                        const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                        const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                        char *text, size_t text_cap, const char **why)
{
    uint8_t body[FLEET_ENROL_RECEIPT_WIRE_MAX];
    uint8_t wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    struct fe_put p = { body, sizeof(body), 0, true };
    size_t wire_len = 0;
    fe_why(why, NULL);
    if (invite_wire_len > (size_t)FLEET_ENROL_INVITE_WIRE_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    fe_receipt_body(&p, invite_wire, invite_wire_len, facts, ssh_pubkey,
                    pubkey);
    if (!p.ok) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    return fe_seal(FE_DOMAIN_RECEIPT, body, p.len, seed, pubkey, wire,
                   sizeof(wire), &wire_len, text, text_cap, why);
}

/* Decode a receipt body that has ALREADY had its box signature verified. */
static bool fe_receipt_fields(struct fe_get *g, size_t body_len,
                              struct fleet_receipt *out, const char **why)
{
    char invite_text[(FLEET_ENROL_INVITE_WIRE_MAX * 4) / 3 + 8];
    size_t invite_len = 0;
    const uint8_t *invite_at = NULL;
    if (fe_get_u8(g) != FE_VERSION) {
        fe_why(why, FLEET_ENROL_WHY_RECEIPT_MALFORMED);
        return false;
    }
    invite_len = (size_t)fe_get_be(g, 2);
    invite_at = fe_get_raw(g, invite_len);
    if (!g->ok || invite_len > (size_t)FLEET_ENROL_INVITE_WIRE_MAX) {
        fe_why(why, FLEET_ENROL_WHY_RECEIPT_MALFORMED);
        return false;
    }
    memcpy(out->invite_wire, invite_at, invite_len);
    out->invite_wire_len = invite_len;
    fe_get_text(g, out->facts.hostname, sizeof(out->facts.hostname), 1);
    fe_get_text(g, out->facts.os, sizeof(out->facts.os), 1);
    fe_get_text(g, out->facts.os_version, sizeof(out->facts.os_version), 1);
    fe_get_text(g, out->facts.arch, sizeof(out->facts.arch), 1);
    fe_get_text(g, out->facts.toolchain, sizeof(out->facts.toolchain), 1);
    fe_get_text(g, out->facts.git_head, sizeof(out->facts.git_head), 1);
    out->facts.cores = (uint32_t)fe_get_be(g, 4);
    out->facts.ram_mb = fe_get_be(g, 8);
    out->facts.disk_free_mb = fe_get_be(g, 8);
    fe_get_text(g, out->ssh_pubkey, sizeof(out->ssh_pubkey), 2);
    fe_get_bytes(g, out->box_pubkey, FLEET_ENROL_PUBKEY_BYTES);
    if (!g->ok || g->pos != body_len) {
        fe_why(why, FLEET_ENROL_WHY_RECEIPT_MALFORMED);
        return false;
    }
    /* The invite inside must itself verify against the operator key it
     * names. A receipt whose invite does not parse is refused as a bad
     * invite, which is the fact the operator needs. */
    if (acme_b64url_encode(out->invite_wire, invite_len, invite_text,
                           sizeof(invite_text)) == 0) {
        fe_why(why, FLEET_ENROL_WHY_RECEIPT_MALFORMED);
        return false;
    }
    return fleet_invite_parse(invite_text, &out->invite, NULL, 0, NULL, why);
}

bool fleet_receipt_parse(const char *text, struct fleet_receipt *out,
                         uint8_t *wire, size_t wire_cap, size_t *wire_len,
                         const char **why)
{
    uint8_t local[FLEET_ENROL_RECEIPT_WIRE_MAX];
    size_t decoded = 0, body_len = 0;
    struct fe_get g = { local, 0, 0, true };
    uint8_t box_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    fe_why(why, NULL);
    memset(out, 0, sizeof(*out));
    if (!text || !text[0] ||
        !acme_b64url_decode(text, local, sizeof(local), &decoded) ||
        decoded < FLEET_ENROL_SIG_BYTES + FLEET_ENROL_PUBKEY_BYTES + 1u) {
        fe_why(why, FLEET_ENROL_WHY_RECEIPT_MALFORMED);
        return false;
    }
    memcpy(box_pubkey,
           local + decoded - FLEET_ENROL_SIG_BYTES - FLEET_ENROL_PUBKEY_BYTES,
           FLEET_ENROL_PUBKEY_BYTES);
    if (!fe_open(text, FE_DOMAIN_RECEIPT, box_pubkey, local, sizeof(local),
                 &decoded, &body_len, FLEET_ENROL_WHY_RECEIPT_MALFORMED,
                 FLEET_ENROL_WHY_BOX_SIGNATURE, why))
        return false;
    g.len = body_len;
    if (!fe_receipt_fields(&g, body_len, out, why))
        return false;
    memcpy(out->signature, local + body_len, FLEET_ENROL_SIG_BYTES);
    if (wire) {
        if (decoded > wire_cap) {
            fe_why(why, FLEET_ENROL_WHY_RECEIPT_MALFORMED);
            return false;
        }
        memcpy(wire, local, decoded);
        *wire_len = decoded;
    }
    return true;
}

/* ── machine (one roster line) ──────────────────────────────────────────── */

bool fleet_machine_mint(const uint8_t *receipt_wire, size_t receipt_wire_len,
                        int64_t enrolled_at, uint16_t relay_port,
                        const uint8_t seed[FLEET_ENROL_SEED_BYTES],
                        const uint8_t pubkey[FLEET_ENROL_PUBKEY_BYTES],
                        char *text, size_t text_cap, const char **why)
{
    uint8_t body[FLEET_ENROL_MACHINE_WIRE_MAX];
    uint8_t wire[FLEET_ENROL_MACHINE_WIRE_MAX];
    struct fe_put p = { body, sizeof(body), 0, true };
    size_t wire_len = 0;
    fe_why(why, NULL);
    if (receipt_wire_len > (size_t)FLEET_ENROL_RECEIPT_WIRE_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    fe_put_u8(&p, FE_VERSION);
    fe_put_be(&p, receipt_wire_len, 2);
    fe_put_raw(&p, receipt_wire, receipt_wire_len);
    fe_put_be(&p, (uint64_t)enrolled_at, 8);
    fe_put_be(&p, relay_port, 2);
    if (!p.ok) {
        fe_why(why, FLEET_ENROL_WHY_ARGUMENTS);
        return false;
    }
    return fe_seal(FE_DOMAIN_MACHINE, body, p.len, seed, pubkey, wire,
                   sizeof(wire), &wire_len, text, text_cap, why);
}

bool fleet_machine_parse(const char *text,
                         const uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES],
                         struct fleet_machine *out, const char **why)
{
    uint8_t local[FLEET_ENROL_MACHINE_WIRE_MAX];
    char receipt_text[FLEET_ENROL_MACHINE_TEXT_MAX];
    size_t decoded = 0, body_len = 0, receipt_len = 0;
    const uint8_t *receipt_at = NULL;
    struct fe_get g = { local, 0, 0, true };
    fe_why(why, NULL);
    memset(out, 0, sizeof(*out));
    if (!fe_open(text, FE_DOMAIN_MACHINE, operator_pubkey, local,
                 sizeof(local), &decoded, &body_len,
                 FLEET_ENROL_WHY_ROSTER_UNREADABLE,
                 FLEET_ENROL_WHY_ROSTER_UNREADABLE, why))
        return false;
    g.len = body_len;
    if (fe_get_u8(&g) != FE_VERSION) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    receipt_len = (size_t)fe_get_be(&g, 2);
    receipt_at = fe_get_raw(&g, receipt_len);
    if (!g.ok || receipt_len > (size_t)FLEET_ENROL_RECEIPT_WIRE_MAX) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    memcpy(out->receipt_wire, receipt_at, receipt_len);
    out->receipt_wire_len = receipt_len;
    out->enrolled_at = (int64_t)fe_get_be(&g, 8);
    out->relay_port = (uint16_t)fe_get_be(&g, 2);
    if (!g.ok || g.pos != body_len) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    memcpy(out->signature, local + body_len, FLEET_ENROL_SIG_BYTES);
    if (acme_b64url_encode(out->receipt_wire, receipt_len, receipt_text,
                           sizeof(receipt_text)) == 0) {
        fe_why(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        return false;
    }
    /* The stored receipt is re-verified on every read: a roster line is
     * only ever as good as the box signature it carries, and re-checking
     * costs one verify per row on a list that is bounded by the port
     * range. */
    return fleet_receipt_parse(receipt_text, &out->receipt, NULL, 0, NULL, why);
}
