/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcl_fleet_front_hello.h — classify the first TLS record a public client
 * sends, WITHOUT terminating it, so the front can tell an ACME TLS-ALPN-01
 * validation (RFC 8737) apart from an ordinary visitor.
 *
 * WHY
 * ---
 * The node renews its own certificate by answering TLS-ALPN-01 on its HTTPS
 * listener: the CA opens a TLS connection offering ALPN "acme-tls/1" and
 * expects the node's challenge certificate. When the fleet front sits in
 * front of the node, that connection reaches the front first. Terminating it
 * here would present the ordinary certificate, the validation would fail,
 * and the certificate would lapse at its next expiry. So the front peeks at
 * the ClientHello and, when it offers acme-tls/1, hands the raw TCP stream to
 * the node untouched.
 *
 * CONTRACT
 * --------
 * Pure function over bytes the network sent: no I/O, no allocation, no
 * state. Every length is checked against the bytes actually present before
 * it is used, so a hostile length can only produce a verdict, never a read
 * past the buffer. It looks at the FIRST record only:
 *
 *   FF_HELLO_NEED_MORE  a valid prefix; wait for more bytes (bounded by the
 *                       caller's deadline and buffer).
 *   FF_HELLO_ACME       a whole ClientHello whose ALPN list names
 *                       "acme-tls/1" exactly.
 *   FF_HELLO_TLS        a well-formed ClientHello that does not, or one
 *                       fragmented across records (a validator never sends
 *                       one): terminate normally.
 *   FF_HELLO_REFUSE     not a TLS ClientHello, or a malformed one: close.
 *
 * Header-only so the harness can test the parser without the OpenSSL-linked
 * front binary (tests/harness/src/test_fleet_gateway.c).
 */
#ifndef ZCL_FLEET_FRONT_HELLO_H
#define ZCL_FLEET_FRONT_HELLO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* One TLS record: 5-byte header plus at most 2^14 bytes of plaintext
 * fragment (RFC 8446 §5.1). A caller's peek buffer of this size always holds
 * the whole first record. */
#define FF_HELLO_RECORD_MAX 16384u
#define FF_HELLO_PEEK_MAX (5u + FF_HELLO_RECORD_MAX)

enum ff_hello_verdict {
    FF_HELLO_NEED_MORE = 0,
    FF_HELLO_ACME,
    FF_HELLO_TLS,
    FF_HELLO_REFUSE,
};

/* A bounds-checked read cursor. Any read past the end sets bad and yields
 * zero, so callers check bad once instead of after every field. */
struct ff_hello_cur {
    const uint8_t *p;
    size_t n;
    bool bad;
};

static inline size_t ff_hello_take(struct ff_hello_cur *c, size_t width)
{
    size_t v = 0;
    size_t i;
    if (c->bad || c->n < width) {
        c->bad = true;
        return 0;
    }
    for (i = 0; i < width; i++)
        v = (v << 8) | c->p[i];
    c->p += width;
    c->n -= width;
    return v;
}

/* Split off the next len bytes as their own cursor. */
static inline struct ff_hello_cur ff_hello_sub(struct ff_hello_cur *c,
                                               size_t len)
{
    struct ff_hello_cur s = {c->p, 0, true};
    if (c->bad || c->n < len) {
        c->bad = true;
        return s;
    }
    s.n = len;
    s.bad = false;
    c->p += len;
    c->n -= len;
    return s;
}

/* A length-prefixed vector: width-byte length, then that many bytes. */
static inline struct ff_hello_cur ff_hello_vec(struct ff_hello_cur *c,
                                               size_t width)
{
    size_t len = ff_hello_take(c, width);
    return ff_hello_sub(c, len);
}

/* Does an ALPN extension body (RFC 7301 §3.1) name acme-tls/1? -1 when the
 * body is malformed, else 1 or 0. Empty names and an empty list are
 * malformed by the RFC. */
static inline int ff_hello_alpn_is_acme(struct ff_hello_cur body)
{
    static const char acme[] = "acme-tls/1";
    struct ff_hello_cur list = ff_hello_vec(&body, 2);
    int found = 0;
    if (body.bad || body.n != 0 || list.n == 0)
        return -1;
    while (list.n > 0) {
        struct ff_hello_cur name = ff_hello_vec(&list, 1);
        if (list.bad || name.n == 0)
            return -1;
        if (name.n == sizeof(acme) - 1 && memcmp(name.p, acme, name.n) == 0)
            found = 1;
    }
    return found;
}

/* Walk the extensions block. ALPN is extension type 16. */
static inline enum ff_hello_verdict ff_hello_extensions(struct ff_hello_cur ext)
{
    int acme = 0;
    while (ext.n > 0) {
        size_t type = ff_hello_take(&ext, 2);
        struct ff_hello_cur body = ff_hello_vec(&ext, 2);
        if (ext.bad)
            return FF_HELLO_REFUSE;
        if (type != 16)
            continue;
        if (acme != 0)
            return FF_HELLO_REFUSE;    /* a second ALPN extension */
        acme = ff_hello_alpn_is_acme(body);
        if (acme < 0)
            return FF_HELLO_REFUSE;
        acme = acme == 1 ? 1 : 2;      /* 2: seen, not acme */
    }
    return acme == 1 ? FF_HELLO_ACME : FF_HELLO_TLS;
}

/* Classify a complete ClientHello body (after the 4-byte handshake header). */
static inline enum ff_hello_verdict ff_hello_body(struct ff_hello_cur hello)
{
    struct ff_hello_cur sid;
    struct ff_hello_cur suites;
    struct ff_hello_cur comp;
    struct ff_hello_cur ext;
    (void)ff_hello_take(&hello, 2);            /* legacy_version */
    (void)ff_hello_sub(&hello, 32);            /* random */
    sid = ff_hello_vec(&hello, 1);
    suites = ff_hello_vec(&hello, 2);
    comp = ff_hello_vec(&hello, 1);
    if (hello.bad || sid.n > 32 || suites.n < 2 || (suites.n & 1u) != 0 ||
        comp.n < 1)
        return FF_HELLO_REFUSE;
    if (hello.n == 0)
        return FF_HELLO_TLS;                   /* no extensions at all */
    ext = ff_hello_vec(&hello, 2);
    if (hello.bad || hello.n != 0)
        return FF_HELLO_REFUSE;
    return ff_hello_extensions(ext);
}

/* The whole first record: header, handshake header, then the body. */
static inline enum ff_hello_verdict ff_hello_classify(const uint8_t *buf,
                                                      size_t len)
{
    struct ff_hello_cur rec = {buf, len, false};
    struct ff_hello_cur frag;
    size_t rec_len;
    size_t hs_len;
    if (len >= 1 && buf[0] != 22)
        return FF_HELLO_REFUSE;                /* not a handshake record */
    if (len >= 2 && buf[1] != 3)
        return FF_HELLO_REFUSE;                /* not TLS 1.x framing */
    if (len < 5)
        return FF_HELLO_NEED_MORE;
    (void)ff_hello_take(&rec, 3);
    rec_len = ff_hello_take(&rec, 2);
    if (rec_len < 4 || rec_len > FF_HELLO_RECORD_MAX)
        return FF_HELLO_REFUSE;
    if (rec.n < rec_len)
        return FF_HELLO_NEED_MORE;
    frag = ff_hello_sub(&rec, rec_len);
    if (ff_hello_take(&frag, 1) != 1)
        return FF_HELLO_REFUSE;                /* not a ClientHello */
    hs_len = ff_hello_take(&frag, 3);
    if (hs_len > frag.n)
        return FF_HELLO_TLS;                   /* spans records: not a validator */
    /* Bytes after the ClientHello in the same record are the TLS stack's
     * business, not this classifier's: only the message itself is read. */
    return ff_hello_body(ff_hello_sub(&frag, hs_len));
}

#endif /* ZCL_FLEET_FRONT_HELLO_H */
