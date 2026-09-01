/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Anchors (ZANC) — OP_RETURN parser and builder. The reference instance of
 * the overlay SDK: the lokad-tagged framing, the pedantic field reads, and the
 * bounded builder all come from overlay/overlay_codec.h, so ZANC hand-rolls
 * only its own field grammar (hash_type + digest + UTF-8 label). The wire bytes
 * are identical to the pre-SDK hand-rolled encoding. */

#include "zanc/zanc.h"
#include "overlay/overlay_codec.h"
#include "script/standard.h"
#include <string.h>

bool zanc_hash_type_valid(uint8_t t)
{
    return t == ZANC_HASH_SHA2_256 || t == ZANC_HASH_SHA3_256;
}

const char *zanc_hash_type_name(uint8_t t)
{
    switch (t) {
    case ZANC_HASH_SHA2_256: return "sha2-256";
    case ZANC_HASH_SHA3_256: return "sha3-256";
    default: return "unknown";
    }
}

/* Minimal RFC 3629 UTF-8 validator: rejects overlong forms, surrogates,
 * code points above U+10FFFF, embedded NUL, and C0 control bytes (<0x20). A
 * label is operator-facing metadata, so control bytes are disallowed too. */
bool zanc_label_valid(const char *label, size_t len)
{
    if (len > ZANC_LABEL_MAX) return false;
    if (len == 0) return true;
    if (!label) return false;

    const uint8_t *p = (const uint8_t *)label;
    size_t i = 0;
    while (i < len) {
        uint8_t c = p[i];
        if (c == 0x00) return false;
        if (c < 0x20) return false;              /* C0 control */
        if (c < 0x80) { i++; continue; }         /* ASCII */

        uint32_t cp;
        size_t extra;
        if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; extra = 1; }
        else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; extra = 2; }
        else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; extra = 3; }
        else return false;                       /* invalid lead byte */

        if (i + extra >= len) return false;
        for (size_t k = 1; k <= extra; k++) {
            uint8_t cc = p[i + k];
            if ((cc & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3f);
        }
        /* Reject overlong encodings and out-of-range/surrogate code points. */
        if (extra == 1 && cp < 0x80) return false;
        if (extra == 2 && cp < 0x800) return false;
        if (extra == 3 && cp < 0x10000) return false;
        if (cp > 0x10ffff) return false;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
        i += extra + 1;
    }
    return true;
}

bool zanc_parse(const uint8_t *script, size_t script_len,
                struct zanc_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));

    /* Fields 0-1: lokad "ZANC" + version — the shared overlay framing. */
    struct overlay_reader r;
    if (!overlay_reader_begin(&r, script, script_len, ZANC_LOKAD_BYTES))
        return false;
    if (!overlay_expect_u8(&r, ZANC_VERSION)) return false;
    msg->version = ZANC_VERSION;

    /* Field 2: hash_type (1 byte, must be a supported type). */
    if (!overlay_read_u8(&r, &msg->hash_type)) return false;
    if (!zanc_hash_type_valid(msg->hash_type)) return false;

    /* Field 3: digest (exactly 32 bytes). */
    if (!overlay_read_fixed(&r, msg->digest, ZANC_DIGEST_LEN)) return false;

    /* Field 4: label (0..32 bytes, UTF-8). */
    size_t label_len = 0;
    if (!overlay_read_bounded(&r, (uint8_t *)msg->label, ZANC_LABEL_MAX,
                              &label_len))
        return false;
    msg->label[label_len] = '\0';
    if (!zanc_label_valid(msg->label, label_len)) return false;
    msg->label_len = (uint8_t)label_len;

    /* No trailing bytes after the label push. */
    return overlay_reader_finish(&r);
}

size_t zanc_build_anchor(uint8_t *out, size_t out_len, uint8_t hash_type,
                         const uint8_t digest[ZANC_DIGEST_LEN],
                         const char *label)
{
    if (!out || !digest) return 0;
    if (!zanc_hash_type_valid(hash_type)) return 0;

    size_t label_len = label ? strlen(label) : 0;
    if (!zanc_label_valid(label, label_len)) return 0;

    struct overlay_writer w;
    overlay_writer_begin(&w, out, out_len, ZANC_LOKAD_BYTES);
    overlay_put_u8(&w, ZANC_VERSION);
    overlay_put_u8(&w, hash_type);
    overlay_put_field(&w, digest, ZANC_DIGEST_LEN);
    overlay_put_field(&w, (const uint8_t *)(label ? label : ""), label_len);

    size_t n = overlay_writer_finish(&w);
    /* Standard relay policy caps an OP_RETURN script at MAX_OP_RETURN_RELAY
     * (223) bytes; a longer script is non-standard and would never relay, so
     * never hand one back. The ZANC grammar tops out at 76 bytes today, so
     * this cannot fire — it is the explicit contract that keeps it true if
     * the grammar ever grows a field. Same shape as blog_anchor_script_build
     * (engine/services/src/blog_publication.c). */
    if (n > MAX_OP_RETURN_RELAY) return 0;
    return n;
}
