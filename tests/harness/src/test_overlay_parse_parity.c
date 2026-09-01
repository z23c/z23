/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Differential proof that moving ZNAM and ZSLP onto the shared overlay cursors
 * changed NOTHING on the wire.
 *
 * ZNAM name registrations and ZSLP token records are already in mainnet blocks.
 * A parse-behaviour change there is a chain-interpretation change, not a
 * refactor, so "the unit tests still pass" is not the bar. This file carries a
 * frozen byte-for-byte copy of the pre-migration hand-rolled parsers and
 * builders (the `ref_` functions below, lifted from the parent commit) and runs
 * both implementations over the same corpus:
 *
 *   - a valid record for every command / transaction type
 *   - every truncation of every valid record
 *   - every single-byte overwrite with each interesting push opcode
 *     (0x00 OP_0, 0x4b, 0x4c PUSHDATA1, 0x4d PUSHDATA2, 0x4e PUSHDATA4, 0xff)
 *   - an inserted empty push (both the OP_0 and the OP_PUSHDATA1/0 spelling)
 *     at every byte offset
 *   - trailing garbage appended
 *   - a whole-script re-encode with non-canonical (over-long) push prefixes
 *   - deterministic pseudo-random scripts, lokad-prefixed and not
 *
 * and asserts the accept/reject verdict AND the entire decoded struct match
 * byte for byte. Builders are compared byte for byte over a value grid.
 *
 * Part 4 settles a separate question: engine/controllers/src/blog_controller.c
 * used to carry a private fork of read_push that was missing the OP_0
 * (canonical empty push) branch and the NULL guards. The fork is deleted; this
 * proves the deletion could not have changed what that scan recovers, by
 * running the old fork and the real read_push through the identical scan loop
 * over the same corpus. It also COUNTS the inputs where the two primitives
 * disagree, so the equivalence is a measured result and not an empty win. */

#include "test/test_core.h"
#include "znam/znam.h"
#include "zslp/slp.h"
#include "script/op_return_push.h"
#include "core/uint256.h"

/* ══ The frozen pre-migration implementations ═══════════════════════════
 *
 * Copied verbatim from contexts/naming/modules/znam/src/znam.c and contexts/market/modules/zslp/src/slp.c at the
 * parent commit, with only the identifiers renamed and the observability log
 * in slp_copy_str_field dropped (it never affected the decode). Do not
 * "improve" anything below: its whole value is being the code that shipped. */

static uint64_t ref_be_to_u64(const uint8_t *data, size_t len)
{
    uint64_t val = 0;
    for (size_t i = 0; i < len && i < 8; i++)
        val = (val << 8) | data[i];
    return val;
}

static void ref_u64_to_be(uint8_t *out, uint64_t val)
{
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(val & 0xff);
        val >>= 8;
    }
}

static void ref_slp_copy_str_field(const uint8_t *data, size_t len,
                                   char *out, size_t out_len)
{
    if (len == 0) return;
    if (len >= out_len) return;
    memcpy(out, data, len);
    out[len] = '\0';
}

static bool ref_slp_parse(const uint8_t *script, size_t script_len,
                          struct slp_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));
    msg->type = SLP_TX_INVALID;

    if (!script || script_len == 0) return false;
    const uint8_t *p = script;
    const uint8_t *end = script + script_len;

    if (p >= end || *p != 0x6a) return false;
    p++;

    const uint8_t *data; size_t len;
    p = read_push(p, end, &data, &len);
    if (!p || len != 4 || memcmp(data, SLP_LOKAD_BYTES, 4) != 0)
        return false;

    p = read_push(p, end, &data, &len);
    if (!p || len < 1 || len > 2) return false;
    msg->token_type = (uint8_t)ref_be_to_u64(data, len);
    if (msg->token_type != SLP_TOKEN_TYPE_1) return false;

    p = read_push(p, end, &data, &len);
    if (!p) return false;

    if (len == 7 && memcmp(data, "GENESIS", 7) == 0) {
        msg->type = SLP_TX_GENESIS;

        p = read_push(p, end, &data, &len);
        if (!p) return false;
        ref_slp_copy_str_field(data, len, msg->ticker, sizeof(msg->ticker));

        p = read_push(p, end, &data, &len);
        if (!p) return false;
        ref_slp_copy_str_field(data, len, msg->name, sizeof(msg->name));

        p = read_push(p, end, &data, &len);
        if (!p) return false;
        ref_slp_copy_str_field(data, len, msg->document_url,
                               sizeof(msg->document_url));

        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len == 32) {
            memcpy(msg->document_hash, data, 32);
            msg->has_document_hash = true;
        }

        p = read_push(p, end, &data, &len);
        if (!p || len != 1 || data[0] > 9) return false;
        msg->decimals = data[0];

        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len == 1) {
            if (data[0] < 2) return false;
            msg->mint_baton_vout = data[0];
        }

        p = read_push(p, end, &data, &len);
        if (!p || len != 8) return false;
        msg->initial_quantity = ref_be_to_u64(data, 8);

        return true;

    } else if (len == 4 && memcmp(data, "MINT", 4) == 0) {
        msg->type = SLP_TX_MINT;

        p = read_push(p, end, &data, &len);
        if (!p || len != 32) return false;
        memcpy(msg->token_id.data, data, 32);

        p = read_push(p, end, &data, &len);
        if (!p) return false;
        if (len == 1) {
            if (data[0] < 2) return false;
            msg->mint_baton_vout = data[0];
        }

        p = read_push(p, end, &data, &len);
        if (!p || len != 8) return false;
        msg->additional_quantity = ref_be_to_u64(data, 8);

        return true;

    } else if (len == 4 && memcmp(data, "SEND", 4) == 0) {
        msg->type = SLP_TX_SEND;

        p = read_push(p, end, &data, &len);
        if (!p || len != 32) return false;
        memcpy(msg->token_id.data, data, 32);

        msg->num_outputs = 0;
        while (msg->num_outputs < 19) {
            const uint8_t *saved = p;
            p = read_push(p, end, &data, &len);
            if (!p || len != 8) {
                p = saved;
                break;
            }
            msg->output_quantities[msg->num_outputs++] =
                ref_be_to_u64(data, 8);
        }
        if (msg->num_outputs < 1) return false;

        return true;
    }

    return false;
}

static size_t ref_slp_build_genesis(uint8_t *out, size_t out_len,
                                    const char *ticker, const char *name,
                                    const char *document_url,
                                    const uint8_t *document_hash,
                                    uint8_t decimals, uint8_t mint_baton_vout,
                                    uint64_t initial_quantity)
{
    if (out_len < 1) return 0;
    size_t off = 0;
    out[off++] = 0x6a;

    bool ok = true;
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)SLP_LOKAD_BYTES, 4);
    uint8_t tt = 1;
    ok = ok && push_data_checked(out, &off, out_len, &tt, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)"GENESIS", 7);

    if (ticker && ticker[0])
        ok = ok && push_data_checked(out, &off, out_len,
                                     (const uint8_t *)ticker, strlen(ticker));
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    if (name && name[0])
        ok = ok && push_data_checked(out, &off, out_len,
                                     (const uint8_t *)name, strlen(name));
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    if (document_url && document_url[0])
        ok = ok && push_data_checked(out, &off, out_len,
                                     (const uint8_t *)document_url,
                                     strlen(document_url));
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    if (document_hash)
        ok = ok && push_data_checked(out, &off, out_len, document_hash, 32);
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    ok = ok && push_data_checked(out, &off, out_len, &decimals, 1);

    if (mint_baton_vout >= 2)
        ok = ok && push_data_checked(out, &off, out_len, &mint_baton_vout, 1);
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    uint8_t qty[8];
    ref_u64_to_be(qty, initial_quantity);
    ok = ok && push_data_checked(out, &off, out_len, qty, 8);

    return ok ? off : 0;
}

static size_t ref_slp_build_mint(uint8_t *out, size_t out_len,
                                 const struct uint256 *token_id,
                                 uint8_t mint_baton_vout,
                                 uint64_t additional_quantity)
{
    if (out_len < 1) return 0;
    size_t off = 0;
    out[off++] = 0x6a;

    bool ok = true;
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)SLP_LOKAD_BYTES, 4);
    uint8_t tt = 1;
    ok = ok && push_data_checked(out, &off, out_len, &tt, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)"MINT", 4);
    ok = ok && push_data_checked(out, &off, out_len, token_id->data, 32);

    if (mint_baton_vout >= 2)
        ok = ok && push_data_checked(out, &off, out_len, &mint_baton_vout, 1);
    else
        ok = ok && push_empty_checked(out, &off, out_len);

    uint8_t qty[8];
    ref_u64_to_be(qty, additional_quantity);
    ok = ok && push_data_checked(out, &off, out_len, qty, 8);

    return ok ? off : 0;
}

static size_t ref_slp_build_send(uint8_t *out, size_t out_len,
                                 const struct uint256 *token_id,
                                 const uint64_t *quantities, int num_outputs)
{
    if (num_outputs < 1 || num_outputs > 19) return 0;
    if (out_len < 1) return 0;

    size_t off = 0;
    out[off++] = 0x6a;

    bool ok = true;
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)SLP_LOKAD_BYTES, 4);
    uint8_t tt = 1;
    ok = ok && push_data_checked(out, &off, out_len, &tt, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)"SEND", 4);
    ok = ok && push_data_checked(out, &off, out_len, token_id->data, 32);

    for (int i = 0; i < num_outputs; i++) {
        uint8_t qty[8];
        ref_u64_to_be(qty, quantities[i]);
        ok = ok && push_data_checked(out, &off, out_len, qty, 8);
    }

    return ok ? off : 0;
}

static bool ref_znam_parse(const uint8_t *script, size_t script_len,
                           struct znam_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));
    msg->command = ZNAM_CMD_INVALID;

    if (!script || script_len == 0) return false;
    const uint8_t *p = script;
    const uint8_t *end = script + script_len;

    if (p >= end || *p != 0x6a) return false;
    p++;

    const uint8_t *data;
    size_t len;
    p = read_push(p, end, &data, &len);
    if (!p || len != 4 || memcmp(data, ZNAM_LOKAD_BYTES, 4) != 0)
        return false;

    p = read_push(p, end, &data, &len);
    if (!p || len != 1 || data[0] != 1) return false;

    p = read_push(p, end, &data, &len);
    if (!p || len != 1) return false;

    uint8_t cmd = data[0];
    if (cmd < 1 || cmd > 6) return false;
    msg->command = (enum znam_command)cmd;

    p = read_push(p, end, &data, &len);
    if (!p || len == 0 || len > ZNAM_NAME_MAX) return false;
    memcpy(msg->name, data, len);
    msg->name[len] = '\0';

    if (!znam_validate_name(msg->name)) {
        msg->command = ZNAM_CMD_INVALID;
        return false;
    }

    switch (msg->command) {
    case ZNAM_CMD_REGISTER:
    case ZNAM_CMD_UPDATE:
    case ZNAM_CMD_SET_RECORD:
        p = read_push(p, end, &data, &len);
        if (!p || len != 1) return false;
        if (data[0] < 1 || data[0] > ZNAM_TYPE_CONTENT) return false;
        msg->target_type = data[0];

        p = read_push(p, end, &data, &len);
        if (!p || len == 0 || len > ZNAM_VALUE_MAX) return false;
        memcpy(msg->target_value, data, len);
        msg->target_value[len] = '\0';
        return true;

    case ZNAM_CMD_TRANSFER:
        p = read_push(p, end, &data, &len);
        if (!p || len == 0 || len > 63) return false;
        memcpy(msg->new_owner, data, len);
        msg->new_owner[len] = '\0';
        return true;

    case ZNAM_CMD_RENEW:
        return true;

    case ZNAM_CMD_SET_TEXT:
        p = read_push(p, end, &data, &len);
        if (!p || len == 0 || len > ZNAM_TEXT_KEY_MAX) return false;
        memcpy(msg->text_key, data, len);
        msg->text_key[len] = '\0';

        p = read_push(p, end, &data, &len);
        if (!p || len > ZNAM_TEXT_VAL_MAX) return false;
        memcpy(msg->text_value, data, len);
        msg->text_value[len] = '\0';
        return true;

    default:
        return false;
    }
}

/* MAX_OP_RETURN_RELAY, restated so this file needs no node header. */
#define REF_MAX_OP_RETURN_RELAY 223

static bool ref_znam_build_header(uint8_t *out, size_t *off, size_t cap,
                                  uint8_t command, const char *name)
{
    if (cap < 1) return false;
    out[(*off)++] = 0x6a;

    if (!push_data_checked(out, off, cap,
                           (const uint8_t *)ZNAM_LOKAD_BYTES, 4))
        return false;

    uint8_t version = 1;
    if (!push_data_checked(out, off, cap, &version, 1)) return false;
    if (!push_data_checked(out, off, cap, &command, 1)) return false;

    return push_data_checked(out, off, cap,
                             (const uint8_t *)name, strlen(name));
}

static size_t ref_znam_build_finish(size_t off, bool ok)
{
    if (!ok || off > REF_MAX_OP_RETURN_RELAY) return 0;
    return off;
}

static size_t ref_znam_build_targeted(uint8_t *out, size_t out_len,
                                      uint8_t command, const char *name,
                                      uint8_t target_type,
                                      const char *target_value)
{
    if (!znam_validate_name(name) || !target_value) return 0;
    if (target_type < 1 || target_type > ZNAM_TYPE_CONTENT) return 0;

    size_t off = 0;
    bool ok = ref_znam_build_header(out, &off, out_len, command, name);
    ok = ok && push_data_checked(out, &off, out_len, &target_type, 1);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)target_value,
                                 strlen(target_value));
    return ref_znam_build_finish(off, ok);
}

static size_t ref_znam_build_transfer(uint8_t *out, size_t out_len,
                                      const char *name, const char *new_owner)
{
    if (!znam_validate_name(name) || !new_owner) return 0;

    size_t off = 0;
    bool ok = ref_znam_build_header(out, &off, out_len, ZNAM_CMD_TRANSFER,
                                    name);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)new_owner,
                                 strlen(new_owner));
    return ref_znam_build_finish(off, ok);
}

static size_t ref_znam_build_renew(uint8_t *out, size_t out_len,
                                   const char *name)
{
    if (!znam_validate_name(name)) return 0;

    size_t off = 0;
    bool ok = ref_znam_build_header(out, &off, out_len, ZNAM_CMD_RENEW, name);
    return ref_znam_build_finish(off, ok);
}

static size_t ref_znam_build_set_text(uint8_t *out, size_t out_len,
                                      const char *name, const char *key,
                                      const char *value)
{
    if (!znam_validate_name(name) || !key || !key[0]) return 0;
    if (strlen(key) > ZNAM_TEXT_KEY_MAX) return 0;
    if (value && strlen(value) > ZNAM_TEXT_VAL_MAX) return 0;

    size_t off = 0;
    bool ok = ref_znam_build_header(out, &off, out_len, ZNAM_CMD_SET_TEXT,
                                    name);
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)key, strlen(key));
    ok = ok && push_data_checked(out, &off, out_len,
                                 (const uint8_t *)(value ? value : ""),
                                 value ? strlen(value) : 0);
    return ref_znam_build_finish(off, ok);
}

/* The private fork that lived in engine/controllers/src/blog_controller.c: a copy
 * of read_push MINUS the OP_0 branch and MINUS the NULL-argument guards. */
static const uint8_t *ref_blog_read_push_field(const uint8_t *p,
                                               const uint8_t *end,
                                               const uint8_t **data,
                                               size_t *len)
{
    if (p >= end) return NULL;
    uint8_t opcode = *p++;
    if (opcode >= 0x01 && opcode <= 0x4b) {
        *len = opcode;
    } else if (opcode == 0x4c) {
        if (p >= end) return NULL;
        *len = *p++;
    } else if (opcode == 0x4d) {
        if (p + 2 > end) return NULL;
        *len = (size_t)p[0] | ((size_t)p[1] << 8);
        p += 2;
    } else {
        return NULL;
    }
    if (p + *len > end) return NULL;
    *data = p;
    return p + *len;
}

/* ══ Corpus machinery ═══════════════════════════════════════════════════ */

#define CORPUS_MAX 512

struct script_case {
    uint8_t bytes[CORPUS_MAX];
    size_t len;
};

/* xorshift64* — deterministic, self-contained, no node header. */
static uint64_t prng_state = 0x9E3779B97F4A7C15ULL;

static uint64_t prng_next(void)
{
    uint64_t x = prng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    prng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* Re-encode every push in a script with a deliberately over-long prefix, so
 * the corpus contains non-canonical encodings of otherwise valid records. */
static size_t reencode_noncanonical(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t cap)
{
    if (in_len == 0 || in[0] != 0x6a || cap < 1) return 0;
    size_t off = 0;
    out[off++] = 0x6a;

    const uint8_t *p = in + 1;
    const uint8_t *end = in + in_len;
    const uint8_t *data;
    size_t len;
    while (p < end) {
        p = read_push(p, end, &data, &len);
        if (!p) return 0;
        if (len > 0xff) return 0;
        if (off + 2 + len > cap) return 0;
        out[off++] = 0x4c;                 /* PUSHDATA1 for a short push */
        out[off++] = (uint8_t)len;
        memcpy(out + off, data, len);
        off += len;
    }
    return off;
}

/* ══ Part 1 — ZNAM parser parity ════════════════════════════════════════ */

typedef bool (*znam_parse_fn)(const uint8_t *, size_t, struct znam_message *);

static int znam_compare_one(const uint8_t *s, size_t n, long *checked)
{
    struct znam_message a, b;
    /* Poison both so an unwritten byte cannot hide behind a shared zero. */
    memset(&a, 0xa5, sizeof(a));
    memset(&b, 0x5c, sizeof(b));

    bool va = ref_znam_parse(s, n, &a);
    bool vb = znam_parse(s, n, &b);
    (*checked)++;

    if (va != vb) {
        printf("\n  ZNAM VERDICT SPLIT at len=%zu: old=%d new=%d\n",
               n, (int)va, (int)vb);
        return 1;
    }
    if (memcmp(&a, &b, sizeof(a)) != 0) {
        printf("\n  ZNAM DECODE SPLIT at len=%zu (verdict %d)\n", n, (int)va);
        return 1;
    }
    return 0;
}

/* ══ Part 2 — ZSLP parser parity ════════════════════════════════════════ */

static int slp_compare_one(const uint8_t *s, size_t n, long *checked)
{
    struct slp_message a, b;
    memset(&a, 0xa5, sizeof(a));
    memset(&b, 0x5c, sizeof(b));

    bool va = ref_slp_parse(s, n, &a);
    bool vb = slp_parse(s, n, &b);
    (*checked)++;

    if (va != vb) {
        printf("\n  ZSLP VERDICT SPLIT at len=%zu: old=%d new=%d\n",
               n, (int)va, (int)vb);
        return 1;
    }
    if (memcmp(&a, &b, sizeof(a)) != 0) {
        printf("\n  ZSLP DECODE SPLIT at len=%zu (verdict %d)\n", n, (int)va);
        return 1;
    }
    return 0;
}

/* Run every mutation of one seed script through both comparators. */
static int mutate_and_compare(const struct script_case *seed,
                              long *checked, int *splits)
{
    static const uint8_t opcodes[] = {
        0x00, 0x01, 0x02, 0x08, 0x20, 0x4b, 0x4c, 0x4d, 0x4e, 0x50, 0x7f, 0xff
    };
    uint8_t buf[CORPUS_MAX + 8];

    /* (a) the seed itself, and every truncation of it */
    for (size_t n = 0; n <= seed->len; n++) {
        *splits += znam_compare_one(seed->bytes, n, checked);
        *splits += slp_compare_one(seed->bytes, n, checked);
    }

    /* (b) every single-byte overwrite with each interesting opcode */
    for (size_t i = 0; i < seed->len; i++) {
        for (size_t k = 0; k < sizeof(opcodes); k++) {
            memcpy(buf, seed->bytes, seed->len);
            buf[i] = opcodes[k];
            *splits += znam_compare_one(buf, seed->len, checked);
            *splits += slp_compare_one(buf, seed->len, checked);
        }
    }

    /* (c) an inserted empty push at every offset, both spellings */
    for (size_t i = 1; i <= seed->len; i++) {
        /* OP_0 */
        memcpy(buf, seed->bytes, i);
        buf[i] = 0x00;
        memcpy(buf + i + 1, seed->bytes + i, seed->len - i);
        *splits += znam_compare_one(buf, seed->len + 1, checked);
        *splits += slp_compare_one(buf, seed->len + 1, checked);
        /* OP_PUSHDATA1 with length 0 */
        memcpy(buf, seed->bytes, i);
        buf[i] = 0x4c;
        buf[i + 1] = 0x00;
        memcpy(buf + i + 2, seed->bytes + i, seed->len - i);
        *splits += znam_compare_one(buf, seed->len + 2, checked);
        *splits += slp_compare_one(buf, seed->len + 2, checked);
    }

    /* (d) trailing garbage */
    static const uint8_t tails[][4] = {
        {0x00, 0, 0, 0}, {0x4c, 0x00, 0, 0}, {0x03, 'a', 'b', 'c'},
        {0xff, 0xff, 0xff, 0xff}
    };
    static const size_t tail_lens[] = { 1, 2, 4, 4 };
    for (size_t t = 0; t < 4; t++) {
        if (seed->len + tail_lens[t] > sizeof(buf)) continue;
        memcpy(buf, seed->bytes, seed->len);
        memcpy(buf + seed->len, tails[t], tail_lens[t]);
        *splits += znam_compare_one(buf, seed->len + tail_lens[t], checked);
        *splits += slp_compare_one(buf, seed->len + tail_lens[t], checked);
    }

    /* (e) the whole record re-encoded with non-canonical push prefixes */
    size_t nc = reencode_noncanonical(seed->bytes, seed->len, buf, sizeof(buf));
    if (nc) {
        *splits += znam_compare_one(buf, nc, checked);
        *splits += slp_compare_one(buf, nc, checked);
    }

    return *splits;
}

/* ══ Part 4 — the deleted blog fork ═════════════════════════════════════ */

/* Recover the trailing hostname the way blog_discover_onion_peers_wallet does,
 * given wherever the field-skipping loops left the cursor. */
static int blog_take_hostname(const uint8_t *p, const uint8_t *end,
                              char *host, size_t host_cap)
{
    host[0] = '\0';
    if (!p || p >= end) return 0;
    size_t hlen = (size_t)*p++;
    if (hlen > 0 && hlen < 63 && p + hlen <= end &&
        hlen > 6 && memcmp(p + hlen - 6, ".onion", 6) == 0) {
        if (hlen + 1 > host_cap) return 0;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        return 1;
    }
    return 0;
}

/* The onion-hostname scan from blog_discover_onion_peers_wallet, run with BOTH
 * push primitives in lockstep over one script. Fills host_fork/host_real with
 * what each recovers, and adds to *step_diffs once for every read the two
 * primitives answered differently — counted only at cursor positions the scan
 * actually reaches, so the number means "the missing branch was hit on a real
 * read", not "a 0x00 byte exists somewhere". */
static int blog_scan_both(const uint8_t *script, size_t script_len,
                          char *host_fork, char *host_real, size_t host_cap,
                          long *step_diffs)
{
    host_fork[0] = '\0';
    host_real[0] = '\0';

    struct slp_message msg;
    if (!slp_parse(script, script_len, &msg) || msg.type != SLP_TX_SEND)
        return 0;

    const uint8_t *end = script + script_len;
    const uint8_t *pf = script + 1;   /* fork cursor */
    const uint8_t *pr = script + 1;   /* real read_push cursor */
    const uint8_t *df = NULL, *dr = NULL;
    size_t lf = 0, lr = 0;

    /* Skip: lokad_id, token_type, "SEND", token_id */
    for (int i = 0; i < 4; i++) {
        const uint8_t *nf = pf ? ref_blog_read_push_field(pf, end, &df, &lf)
                               : NULL;
        const uint8_t *nr = read_push(pr, end, &dr, &lr);
        if (pf == pr && nf != nr) (*step_diffs)++;
        pf = nf;
        pr = nr;
    }

    /* Skip output quantities */
    bool run_f = true, run_r = true;
    for (int i = 0; i < 19; i++) {
        const uint8_t *sf = pf, *sr = pr;
        const uint8_t *nf = NULL, *nr = NULL;
        if (run_f && pf) nf = ref_blog_read_push_field(pf, end, &df, &lf);
        if (run_r && pr) nr = read_push(pr, end, &dr, &lr);
        if (run_f && run_r && pf == pr && pf && nf != nr) (*step_diffs)++;

        if (run_f) {
            if (!pf) run_f = false;
            else if (!nf || lf != 8) { pf = sf; run_f = false; }
            else pf = nf;
        }
        if (run_r) {
            if (!pr) run_r = false;
            else if (!nr || lr != 8) { pr = sr; run_r = false; }
            else pr = nr;
        }
        if (!run_f && !run_r) break;
    }

    int found_f = blog_take_hostname(pf, end, host_fork, host_cap);
    int found_r = blog_take_hostname(pr, end, host_real, host_cap);
    return found_f == found_r ? found_r : -1;
}

/* ══ The group ══════════════════════════════════════════════════════════ */

int test_overlay_parse_parity(void)
{
    int failures = 0;
    long checked = 0;
    int splits = 0;

    /* ── Seed corpus: one valid record per command / transaction type ── */
    struct script_case seeds[24];
    size_t nseeds = 0;

    {
        struct uint256 tid;
        for (int i = 0; i < 32; i++) tid.data[i] = (uint8_t)(i * 7 + 1);
        uint8_t dochash[32];
        for (int i = 0; i < 32; i++) dochash[i] = (uint8_t)(0xf0 - i);

        /* ZSLP GENESIS — with and without every optional field */
        seeds[nseeds].len = ref_slp_build_genesis(seeds[nseeds].bytes,
            CORPUS_MAX, "ZCL", "ZClassic Token", "https://zclassic.org",
            dochash, 8, 2, 1000000);
        nseeds++;
        seeds[nseeds].len = ref_slp_build_genesis(seeds[nseeds].bytes,
            CORPUS_MAX, "", "", "", NULL, 0, 0, 0);
        nseeds++;
        seeds[nseeds].len = ref_slp_build_genesis(seeds[nseeds].bytes,
            CORPUS_MAX, "ZCL23NODES", "ZClassic23 Node Registry", "", NULL,
            0, 2, 1);
        nseeds++;

        /* ZSLP MINT — with and without the baton */
        seeds[nseeds].len = ref_slp_build_mint(seeds[nseeds].bytes, CORPUS_MAX,
            &tid, 2, 500);
        nseeds++;
        seeds[nseeds].len = ref_slp_build_mint(seeds[nseeds].bytes, CORPUS_MAX,
            &tid, 0, 0);
        nseeds++;

        /* ZSLP SEND — 1, 2 and the maximum 19 outputs */
        uint64_t q[19];
        for (int i = 0; i < 19; i++) q[i] = (uint64_t)(i + 1) * 1000;
        seeds[nseeds].len = ref_slp_build_send(seeds[nseeds].bytes, CORPUS_MAX,
            &tid, q, 1);
        nseeds++;
        seeds[nseeds].len = ref_slp_build_send(seeds[nseeds].bytes, CORPUS_MAX,
            &tid, q, 2);
        nseeds++;
        seeds[nseeds].len = ref_slp_build_send(seeds[nseeds].bytes, CORPUS_MAX,
            &tid, q, 19);
        nseeds++;

        /* ZSLP SEND + appended .onion hostname — the shape the blog scan
         * exists to read, and the reason neither parser may reject trailing
         * bytes. */
        {
            size_t base = ref_slp_build_send(seeds[nseeds].bytes, CORPUS_MAX,
                                             &tid, q, 1);
            const char *host = "abcdefghijklmnopqrstuvwxyz234567"
                               "abcdefghijklmnopqrstuvwx.onion";
            size_t hl = strlen(host);
            seeds[nseeds].bytes[base] = (uint8_t)hl;
            memcpy(seeds[nseeds].bytes + base + 1, host, hl);
            seeds[nseeds].len = base + 1 + hl;
            nseeds++;
        }

        /* ZNAM — every command */
        seeds[nseeds].len = ref_znam_build_targeted(seeds[nseeds].bytes,
            CORPUS_MAX, ZNAM_CMD_REGISTER, "alice", ZNAM_TYPE_TADDR,
            "t1abcdefghijklmnop");
        nseeds++;
        seeds[nseeds].len = ref_znam_build_targeted(seeds[nseeds].bytes,
            CORPUS_MAX, ZNAM_CMD_UPDATE, "bob-node",
            ZNAM_TYPE_CONTENT, "deadbeef");
        nseeds++;
        seeds[nseeds].len = ref_znam_build_transfer(seeds[nseeds].bytes,
            CORPUS_MAX, "carol", "t1zzzzzzzzzzzzzzzzzz");
        nseeds++;
        seeds[nseeds].len = ref_znam_build_renew(seeds[nseeds].bytes,
            CORPUS_MAX, "dave2");
        nseeds++;
        seeds[nseeds].len = ref_znam_build_targeted(seeds[nseeds].bytes,
            CORPUS_MAX, ZNAM_CMD_SET_RECORD, "erin", 2, "1BtcAddress");
        nseeds++;
        seeds[nseeds].len = ref_znam_build_set_text(seeds[nseeds].bytes,
            CORPUS_MAX, "frank", "email", "frank@example.org");
        nseeds++;
        seeds[nseeds].len = ref_znam_build_set_text(seeds[nseeds].bytes,
            CORPUS_MAX, "grace", "url", "");
        nseeds++;
        /* A 63-char name — the maximum the grammar allows. */
        seeds[nseeds].len = ref_znam_build_renew(seeds[nseeds].bytes,
            CORPUS_MAX,
            "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffabc");
        nseeds++;
    }

    printf("overlay parse parity: seed corpus... ");
    {
        bool ok = true;
        for (size_t i = 0; i < nseeds; i++)
            if (seeds[i].len == 0) { ok = false; break; }
        if (ok && nseeds == 17) printf("OK (%zu records)\n", nseeds);
        else { printf("FAIL (nseeds=%zu)\n", nseeds); failures++; }
    }

    /* ── Parts 1+2: mutate every seed, compare both parsers ── */
    printf("overlay parse parity: znam+zslp mutation sweep... ");
    for (size_t i = 0; i < nseeds; i++)
        mutate_and_compare(&seeds[i], &checked, &splits);
    if (splits == 0) printf("OK (%ld inputs, 0 splits)\n", checked);
    else { printf("FAIL (%d splits)\n", splits); failures++; }

    /* ── Part 3: pseudo-random scripts, lokad-prefixed and not ── */
    printf("overlay parse parity: randomized sweep... ");
    {
        prng_state = 0x9E3779B97F4A7C15ULL;
        long before = checked;
        int rsplits = 0;
        uint8_t buf[96];
        for (int iter = 0; iter < 120000; iter++) {
            size_t n = 1 + (size_t)(prng_next() % (sizeof(buf) - 1));
            for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)prng_next();
            /* Half the samples get real framing so the deep field paths are
             * reached instead of dying at the lokad check. */
            if (iter % 2 == 0 && n >= 8) {
                buf[0] = 0x6a;
                buf[1] = 0x04;
                if (iter % 4 == 0)
                    memcpy(buf + 2, ZNAM_LOKAD_BYTES, 4);
                else
                    memcpy(buf + 2, SLP_LOKAD_BYTES, 4);
                buf[6] = 0x01;
                buf[7] = 0x01;
            } else {
                buf[0] = 0x6a;
            }
            rsplits += znam_compare_one(buf, n, &checked);
            rsplits += slp_compare_one(buf, n, &checked);
            if (rsplits) break;
        }
        if (rsplits == 0) printf("OK (%ld inputs, 0 splits)\n",
                                 checked - before);
        else { printf("FAIL (%d splits)\n", rsplits); failures++; }
    }

    /* ── Builder byte-identity ── */
    printf("overlay parse parity: builders byte-identical... ");
    {
        bool ok = true;
        uint8_t a[CORPUS_MAX], b[CORPUS_MAX];
        struct uint256 tid;
        for (int i = 0; i < 32; i++) tid.data[i] = (uint8_t)(i * 3 + 5);
        uint8_t dh[32];
        for (int i = 0; i < 32; i++) dh[i] = (uint8_t)(i ^ 0x5a);

        static const char *strs[] = { NULL, "", "Z", "ZClassic Token",
            "https://zclassic.org/a/very/long/document/url/that/keeps/going" };

        /* GENESIS: every optional field present and absent. */
        for (size_t t = 0; t < 5; t++)
        for (size_t nm = 0; nm < 5; nm++)
        for (size_t du = 0; du < 5; du++)
        for (int hh = 0; hh < 2; hh++)
        for (int baton = 0; baton < 4; baton++) {
            size_t la = ref_slp_build_genesis(a, sizeof(a), strs[t], strs[nm],
                strs[du], hh ? dh : NULL, 9, (uint8_t)baton, 0xdeadbeefULL);
            size_t lb = slp_build_genesis(b, sizeof(b), strs[t], strs[nm],
                strs[du], hh ? dh : NULL, 9, (uint8_t)baton, 0xdeadbeefULL);
            if (la != lb || (la && memcmp(a, b, la) != 0)) { ok = false; }
        }

        /* GENESIS into a too-small buffer at every capacity. */
        for (size_t cap = 0; cap <= 80 && ok; cap++) {
            size_t la = ref_slp_build_genesis(a, cap, "ZCL", "n", "u", dh,
                                              1, 2, 7);
            size_t lb = slp_build_genesis(b, cap, "ZCL", "n", "u", dh,
                                          1, 2, 7);
            if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
        }

        /* MINT + SEND across baton and output counts. */
        for (int baton = 0; baton < 4 && ok; baton++) {
            size_t la = ref_slp_build_mint(a, sizeof(a), &tid,
                                           (uint8_t)baton, 42);
            size_t lb = slp_build_mint(b, sizeof(b), &tid,
                                       (uint8_t)baton, 42);
            if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
        }
        {
            uint64_t q[19];
            for (int i = 0; i < 19; i++) q[i] = 0x0102030405060708ULL + i;
            for (int n = 0; n <= 20 && ok; n++) {
                size_t la = ref_slp_build_send(a, sizeof(a), &tid, q, n);
                size_t lb = slp_build_send(b, sizeof(b), &tid, q, n);
                if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
            }
            for (size_t cap = 0; cap <= 64 && ok; cap++) {
                size_t la = ref_slp_build_send(a, cap, &tid, q, 3);
                size_t lb = slp_build_send(b, cap, &tid, q, 3);
                if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
            }
        }

        /* ZNAM: every builder, including the over-relay-cap refusal. */
        static const char *names[] = { "a", "alice", "node-7",
            "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffabc",
            "-bad", "", "UPPER" };
        static const char *vals[] = { "", "t1abc", "1BitcoinAddr",
            ("0123456789012345678901234567890123456789012345678901234567890123"
             "4567890123456789012345678901234567890123456789012345678901234567") };
        for (size_t n = 0; n < 7 && ok; n++) {
            for (size_t v = 0; v < 4 && ok; v++) {
                for (int ty = 0; ty <= 8 && ok; ty++) {
                    size_t la = ref_znam_build_targeted(a, sizeof(a),
                        ZNAM_CMD_REGISTER, names[n], (uint8_t)ty, vals[v]);
                    size_t lb = znam_build_register(b, sizeof(b), names[n],
                        (uint8_t)ty, vals[v]);
                    if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;

                    la = ref_znam_build_targeted(a, sizeof(a),
                        ZNAM_CMD_UPDATE, names[n], (uint8_t)ty, vals[v]);
                    lb = znam_build_update(b, sizeof(b), names[n],
                        (uint8_t)ty, vals[v]);
                    if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;

                    la = ref_znam_build_targeted(a, sizeof(a),
                        ZNAM_CMD_SET_RECORD, names[n], (uint8_t)ty, vals[v]);
                    lb = znam_build_set_record(b, sizeof(b), names[n],
                        (uint8_t)ty, vals[v]);
                    if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
                }
                size_t la = ref_znam_build_transfer(a, sizeof(a), names[n],
                                                    vals[v]);
                size_t lb = znam_build_transfer(b, sizeof(b), names[n],
                                                vals[v]);
                if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;

                la = ref_znam_build_set_text(a, sizeof(a), names[n],
                                             "email", vals[v]);
                lb = znam_build_set_text(b, sizeof(b), names[n],
                                         "email", vals[v]);
                if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;

                la = ref_znam_build_set_text(a, sizeof(a), names[n],
                                             "email", NULL);
                lb = znam_build_set_text(b, sizeof(b), names[n],
                                         "email", NULL);
                if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
            }
            size_t la = ref_znam_build_renew(a, sizeof(a), names[n]);
            size_t lb = znam_build_renew(b, sizeof(b), names[n]);
            if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
        }
        for (size_t cap = 0; cap <= 64 && ok; cap++) {
            size_t la = ref_znam_build_renew(a, cap, "alice");
            size_t lb = znam_build_renew(b, cap, "alice");
            if (la != lb || (la && memcmp(a, b, la) != 0)) ok = false;
        }

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── ZSLP empty fields still encode as OP_PUSHDATA1/0, not OP_0 ── */
    printf("overlay parse parity: zslp empty push stays 0x4c 0x00... ");
    {
        uint8_t s[CORPUS_MAX];
        size_t n = slp_build_genesis(s, sizeof(s), "", "", "", NULL, 0, 0, 1);
        /* 0x6a, push(lokad,4)=5, push(tt,1)=2, push("GENESIS",7)=8 → offset 16
         * is the ticker field. */
        bool ok = n > 18 && s[16] == 0x4c && s[17] == 0x00;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── ZNAM empty text value stays the one-byte OP_0 ── */
    printf("overlay parse parity: znam empty text value stays 0x00... ");
    {
        uint8_t s[CORPUS_MAX];
        size_t n = znam_build_set_text(s, sizeof(s), "grace", "url", "");
        bool ok = n > 0 && s[n - 1] == 0x00;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Part 4: the deleted blog fork could not have mattered ── */
    printf("overlay parse parity: deleted blog push fork equivalent... ");
    {
        bool ok = true;
        long step_diffs = 0;
        long scans = 0;
        uint8_t buf[CORPUS_MAX + 8];
        char hf[128], hr[128];

        static const uint8_t opcodes[] = {
            0x00, 0x01, 0x08, 0x4b, 0x4c, 0x4d, 0x4e, 0xff
        };

#define BLOG_CMP(S, N)                                                        \
        do {                                                                  \
            scans++;                                                          \
            if (blog_scan_both((S), (N), hf, hr, sizeof(hf), &step_diffs) < 0 \
                || strcmp(hf, hr) != 0)                                       \
                ok = false;                                                   \
        } while (0)

        for (size_t si = 0; si < nseeds && ok; si++) {
            const struct script_case *seed = &seeds[si];

            for (size_t n = 0; n <= seed->len && ok; n++)
                BLOG_CMP(seed->bytes, n);

            for (size_t i = 0; i < seed->len && ok; i++)
                for (size_t k = 0; k < sizeof(opcodes) && ok; k++) {
                    memcpy(buf, seed->bytes, seed->len);
                    buf[i] = opcodes[k];
                    BLOG_CMP(buf, seed->len);
                }

            /* An OP_0 spliced in at every offset — the exact byte the fork
             * did not understand. */
            for (size_t i = 1; i <= seed->len && ok; i++) {
                memcpy(buf, seed->bytes, i);
                buf[i] = 0x00;
                memcpy(buf + i + 1, seed->bytes + i, seed->len - i);
                BLOG_CMP(buf, seed->len + 1);
            }
        }

        /* Randomized scripts framed as SEND, so the quantity loop is fed
         * adversarial terminators it was never built for. */
        prng_state = 0xD1B54A32D192ED03ULL;
        for (int iter = 0; iter < 60000 && ok; iter++) {
            struct uint256 tid;
            for (int i = 0; i < 32; i++) tid.data[i] = (uint8_t)prng_next();
            uint64_t q[4] = { prng_next(), prng_next(), prng_next(), 7 };
            size_t base = ref_slp_build_send(buf, sizeof(buf), &tid, q,
                                             1 + (int)(prng_next() % 4));
            if (!base) continue;
            size_t extra = (size_t)(prng_next() % 40);
            if (base + extra > sizeof(buf)) continue;
            for (size_t i = 0; i < extra; i++) {
                uint64_t r = prng_next();
                /* Bias hard toward the bytes that matter: push opcodes. */
                buf[base + i] = (r % 3 == 0) ? 0x00
                              : (r % 3 == 1) ? (uint8_t)(0x4b + (r >> 8) % 4)
                                             : (uint8_t)(r >> 16);
            }
            BLOG_CMP(buf, base + extra);
        }

#undef BLOG_CMP

        /* The equivalence is only meaningful if the corpus actually drove the
         * two primitives apart ON A READ THE SCAN PERFORMS. */
        if (step_diffs == 0) {
            printf("FAIL (corpus never exercised the missing branch)\n");
            failures++;
        } else if (!ok) {
            printf("FAIL (scan verdicts differ — the fork WAS reachable)\n");
            failures++;
        } else {
            printf("OK (%ld scans, %ld reads where the fork and the real "
                   "decoder disagreed, 0 recovered-hostname differences)\n",
                   scans, step_diffs);
        }
    }

    printf("overlay parse parity: %ld differential inputs compared\n", checked);
    return failures;
}
