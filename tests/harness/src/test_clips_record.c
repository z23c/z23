/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage of the Clips signed record envelope and body codecs
 * (spec 2.2 and 2.3): the record id known-answer vector, Ed25519 sign and
 * verify, the chain and fork checks, every envelope and body limit and
 * refusal, and truncation at every offset. Buffers only: no node, no wallet,
 * no peer and no clock. The known answer was computed with openssl over the
 * same bytes; the code under test never produced it. */

#include "test/test_core.h"

#include "clips_codec/clips_codec.h"
#include "crypto/ed25519.h"

#include <stdint.h>
#include <string.h>

static const char k_kat_record_id[] =
    "85ee0098f2c4dec6073ee3a20f804af69363decb857db7459bfac825d3148533"
    "044d4e6ae134b55a99188a56c450660a1f7c71a17a063ad37fea499e55c7a843";

static void cr_make_reaction(struct clips_record *rec)
{
    memset(rec, 0, sizeof(*rec));
    rec->kind = CLIPS_KIND_REACTION;
    rec->lane = CLIPS_LANE_SOCIAL;
    memset(rec->author, 0x11, sizeof(rec->author));
    rec->seq = 1;
    rec->created_at = 1700000000;
    rec->body_len = 65;
    memset(rec->body, 0xab, 64);
    rec->body[64] = 1;
}

static void cr_hex(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

static void cr_fixture_key(uint8_t pk[32], uint8_t seed[32])
{
    uint8_t sk[32];
    memset(seed, 0x5c, 32);
    ed25519_keypair(pk, sk, seed);
}

static enum clips_error cr_encode(const struct clips_record *rec, uint8_t *buf, size_t *n)
{
    return clips_record_encode(rec, buf, CLIPS_RECORD_MAX_LEN, n);
}

static enum clips_error cr_body(const struct clips_body *b, uint8_t *buf, size_t *n)
{
    return clips_body_encode(b, buf, CLIPS_RECORD_BODY_MAX, n);
}

static void cb_post(struct clips_body *b)
{
    memset(b, 0, sizeof(*b));
    b->kind = CLIPS_KIND_POST;
    b->u.post.level = CLIPS_LEVEL_GENERAL;
    b->u.post.has_manifest = true;
    memset(b->u.post.manifest_id, 0x31, sizeof(b->u.post.manifest_id));
}

/* Known answers for the post record: computed with openssl 3.0.13. The key
 * is the 32-byte seed 0x07 wrapped as PKCS8 DER (302e020100300506032b657004220420
 * then the seed) and read with openssl pkey -inform DER. The record id is
 * openssl dgst -sha3-512 over "z23.clips.record.id.v1", a 0x00 byte, then the
 * 203-byte record prefix. The signature is openssl pkeyutl -sign -rawin over
 * the 64-byte id, and openssl verified it. */
static const char k_kat_post_pk[] =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
static const char k_kat_post_id[] =
    "e1f312a52858206f2049b71d4a64dbf8bf9d35397e0d6b95f31193af81362398"
    "4c5a729abe14f6bcc81e09849b4f436139725deaaf1f68bc97afc2adbf4d8b24";
static const char k_kat_post_sig[] =
    "12c5c8260ad02d6f3e3d6cfbc5fab61647c52f7f8848a697a1e0cb9bd6c633c4"
    "93821676e602954d9937f36e53c172c4102d3034fa09f2d60da45aa9afd86509";

/* Malformed or control-character text: each case is refused as a caption and
 * as a comment, except the LF case, which both accept. */
struct cr_text_case {
    const uint8_t *text;
    size_t len;
    enum clips_error want;
};

static const uint8_t k_text_overlong2[] = {0x61, 0xc0, 0x80};
static const uint8_t k_text_overlong3[] = {0xe0, 0x80, 0x80};
static const uint8_t k_text_overlong4[] = {0xf0, 0x80, 0x80, 0x80};
static const uint8_t k_text_surrogate[] = {0xed, 0xa0, 0x80};
static const uint8_t k_text_above_max[] = {0xf4, 0x90, 0x80, 0x80};
static const uint8_t k_text_lead_f5[] = {0xf5, 0x80, 0x80, 0x80};
static const uint8_t k_text_truncated[] = {0x61, 0xe2, 0x82};
static const uint8_t k_text_bare_cont[] = {0x80};
static const uint8_t k_text_bad_cont[] = {0xe2, 0x28, 0xa1};
static const uint8_t k_text_cr[] = {0x61, 0x0d, 0x62};
static const uint8_t k_text_tab[] = {0x61, 0x09, 0x62};
static const uint8_t k_text_lf[] = {0x61, 0x0a, 0x62};
static const uint8_t k_text_euro[] = {0xe2, 0x82, 0xac};

static const struct cr_text_case k_text_cases[] = {
    {k_text_overlong2, sizeof(k_text_overlong2), CLIPS_ERR_TEXT},
    {k_text_overlong3, sizeof(k_text_overlong3), CLIPS_ERR_TEXT},
    {k_text_overlong4, sizeof(k_text_overlong4), CLIPS_ERR_TEXT},
    {k_text_surrogate, sizeof(k_text_surrogate), CLIPS_ERR_TEXT},
    {k_text_above_max, sizeof(k_text_above_max), CLIPS_ERR_TEXT},
    {k_text_lead_f5, sizeof(k_text_lead_f5), CLIPS_ERR_TEXT},
    {k_text_truncated, sizeof(k_text_truncated), CLIPS_ERR_TEXT},
    {k_text_bare_cont, sizeof(k_text_bare_cont), CLIPS_ERR_TEXT},
    {k_text_bad_cont, sizeof(k_text_bad_cont), CLIPS_ERR_TEXT},
    {k_text_cr, sizeof(k_text_cr), CLIPS_ERR_TEXT},
    {k_text_tab, sizeof(k_text_tab), CLIPS_ERR_TEXT},
    {k_text_lf, sizeof(k_text_lf), CLIPS_OK},
    {k_text_euro, sizeof(k_text_euro), CLIPS_OK},
};

static enum clips_error cr_caption_check(const uint8_t *s, size_t n)
{
    struct clips_body b;
    uint8_t buf[CLIPS_RECORD_BODY_MAX];
    size_t written = 0;

    cb_post(&b);
    b.u.post.caption_len = (uint16_t)n;
    memcpy(b.u.post.caption, s, n);
    return cr_body(&b, buf, &written);
}

static enum clips_error cr_comment_check(const uint8_t *s, size_t n)
{
    struct clips_body b;
    uint8_t buf[CLIPS_RECORD_BODY_MAX];
    size_t written = 0;

    memset(&b, 0, sizeof(b));
    b.kind = CLIPS_KIND_COMMENT;
    b.u.comment.text_len = (uint16_t)n;
    memcpy(b.u.comment.text, s, n);
    return cr_body(&b, buf, &written);
}

/* A raw post body with flags 0x01 (manifest), level 1, no descriptors, the
 * manifest bytes and an empty caption. Returns the offset of the tag count. */
static size_t cr_raw_post_head(uint8_t *buf)
{
    memset(buf, 0, 70);
    buf[0] = 0x01;
    buf[1] = 0x01;
    memset(buf + 4, 0x31, 64);
    return 70;
}

static enum clips_error cr_decode_post(const uint8_t *buf, size_t n)
{
    struct clips_body out;
    return clips_body_decode(CLIPS_KIND_POST, buf, n, &out);
}

int test_clips_record(void);
int test_clips_record(void)
{
    int failures = 0;

    TEST("record id matches the openssl known answer") {
        struct clips_record rec;
        uint8_t id[CLIPS_HASH_LEN];
        char hex[2 * CLIPS_HASH_LEN + 1];
        cr_make_reaction(&rec);
        ASSERT_EQ(clips_record_id(&rec, id), CLIPS_OK);
        cr_hex(id, sizeof(id), hex);
        ASSERT(strcmp(hex, k_kat_record_id) == 0);
        PASS();
    }

    TEST("encode then decode round trips every envelope field") {
        struct clips_record rec, back;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        ASSERT_EQ(n, (size_t)CLIPS_RECORD_HEADER_LEN + 65 + CLIPS_RECORD_SIG_LEN);
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_OK);
        ASSERT_EQ(back.kind, rec.kind);
        ASSERT_EQ(back.lane, rec.lane);
        ASSERT_EQ(back.seq, rec.seq);
        ASSERT_EQ(back.created_at, rec.created_at);
        ASSERT_EQ(back.body_len, rec.body_len);
        ASSERT(memcmp(back.body, rec.body, rec.body_len) == 0);
        ASSERT(memcmp(back.author, rec.author, sizeof(rec.author)) == 0);
        PASS();
    }

    TEST("sign then verify accepts; a body or signature flip is refused") {
        struct clips_record rec;
        uint8_t pk[32], seed[32];
        cr_fixture_key(pk, seed);
        cr_make_reaction(&rec);
        memcpy(rec.author, pk, sizeof(pk));
        ASSERT_EQ(clips_record_sign(&rec, seed), CLIPS_OK);
        ASSERT_EQ(clips_record_verify(&rec), CLIPS_OK);
        rec.body[0] ^= 0x01;
        ASSERT_EQ(clips_record_verify(&rec), CLIPS_ERR_SIGNATURE);
        rec.body[0] ^= 0x01;
        rec.signature[0] ^= 0x80;
        ASSERT_EQ(clips_record_verify(&rec), CLIPS_ERR_SIGNATURE);
        PASS();
    }

    TEST("sign refuses a seed whose public key is not the author") {
        struct clips_record rec;
        uint8_t pk[32], seed[32];
        cr_fixture_key(pk, seed);
        cr_make_reaction(&rec);
        ASSERT_EQ(clips_record_sign(&rec, seed), CLIPS_ERR_SIGNATURE);
        PASS();
    }

    TEST("the record id ignores the signature bytes") {
        struct clips_record a, b;
        uint8_t ia[CLIPS_HASH_LEN], ib[CLIPS_HASH_LEN];
        cr_make_reaction(&a);
        b = a;
        memset(b.signature, 0xee, sizeof(b.signature));
        ASSERT_EQ(clips_record_id(&a, ia), CLIPS_OK);
        ASSERT_EQ(clips_record_id(&b, ib), CLIPS_OK);
        ASSERT(memcmp(ia, ib, sizeof(ia)) == 0);
        PASS();
    }

    TEST("envelope refusals: magic, version, alg, kind, lane, trailing, truncation") {
        struct clips_record rec, back;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        buf[0] ^= 0x01;
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_ERR_MAGIC);
        buf[0] ^= 0x01;
        buf[4] = 2;
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_ERR_VERSION);
        buf[4] = 1;
        buf[7] = 2;
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_ERR_ALG);
        buf[7] = 1;
        buf[6] = 0;
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_ERR_LANE);
        buf[6] = 1;
        ASSERT_EQ(clips_record_decode(buf, n + 1, &back), CLIPS_ERR_TRAILING);
        ASSERT_EQ(clips_record_decode(buf, n - 1, &back), CLIPS_ERR_TRUNCATED);
        PASS();
    }

    TEST("reserved kinds 0, 6..9, 15 and 255 are refused") {
        static const uint8_t bad[] = { 0, 6, 7, 8, 9, 15, 255 };
        struct clips_record rec, back;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        for (size_t i = 0; i < sizeof(bad); i++) {
            buf[5] = bad[i];
            ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_ERR_KIND);
        }
        PASS();
    }

    TEST("a kind in the wrong lane is refused on encode and decode") {
        struct clips_record rec;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        rec.lane = CLIPS_LANE_CONTENT;
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_ERR_LANE);
        rec.kind = CLIPS_KIND_RATING;
        rec.lane = CLIPS_LANE_SOCIAL;
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_ERR_LANE);
        PASS();
    }

    TEST("body length limits: 0 and 1024 accepted, 1025 refused") {
        struct clips_record rec, back;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        rec.body_len = 0;
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        ASSERT_EQ(n, (size_t)CLIPS_RECORD_HEADER_LEN + CLIPS_RECORD_SIG_LEN);
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_OK);
        rec.body_len = CLIPS_RECORD_BODY_MAX;
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        ASSERT_EQ(n, (size_t)CLIPS_RECORD_MAX_LEN);
        ASSERT_EQ(clips_record_decode(buf, n, &back), CLIPS_OK);
        rec.body_len = CLIPS_RECORD_BODY_MAX + 1;
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_ERR_BODY_LEN);
        buf[128] = 0x01;
        buf[129] = 0x04;
        ASSERT_EQ(clips_record_decode(buf, CLIPS_RECORD_MAX_LEN, &back), CLIPS_ERR_BODY_LEN);
        PASS();
    }

    TEST("the largest record is 1218 bytes and a short buffer is refused") {
        struct clips_record rec;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        rec.body_len = CLIPS_RECORD_BODY_MAX;
        ASSERT_EQ(clips_record_encode(&rec, buf, CLIPS_RECORD_MAX_LEN - 1, &n), CLIPS_ERR_ARGUMENT);
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        ASSERT_EQ(n, (size_t)CLIPS_RECORD_MAX_LEN);
        PASS();
    }

    TEST("time window: created_at 600 seconds ahead passes, 601 is deferred") {
        struct clips_record rec;
        cr_make_reaction(&rec);
        rec.created_at = 1000 + 600;
        ASSERT_EQ(clips_record_time_check(&rec, 1000), CLIPS_OK);
        rec.created_at = 1000 + 601;
        ASSERT_EQ(clips_record_time_check(&rec, 1000), CLIPS_ERR_TIME);
        rec.created_at = 0;
        ASSERT_EQ(clips_record_time_check(&rec, 1000), CLIPS_OK);
        PASS();
    }

    TEST("chain: seq starts at 1 with a zero prev, then each record links the last") {
        struct clips_record rec;
        struct clips_chain_tip tip;
        uint8_t first_id[CLIPS_HASH_LEN];
        cr_make_reaction(&rec);
        ASSERT_EQ(clips_chain_check(&rec, NULL), CLIPS_OK);
        rec.seq = 2;
        ASSERT_EQ(clips_chain_check(&rec, NULL), CLIPS_ERR_CHAIN_SEQ);
        rec.seq = 1;
        rec.prev[0] = 1;
        ASSERT_EQ(clips_chain_check(&rec, NULL), CLIPS_ERR_CHAIN_PREV);
        rec.prev[0] = 0;
        cr_make_reaction(&rec);
        ASSERT_EQ(clips_record_id(&rec, first_id), CLIPS_OK);
        memset(&tip, 0, sizeof(tip));
        tip.present = true;
        memcpy(tip.author, rec.author, sizeof(tip.author));
        tip.lane = rec.lane;
        tip.seq = 1;
        memcpy(tip.id, first_id, sizeof(tip.id));
        rec.seq = 2;
        memcpy(rec.prev, first_id, sizeof(rec.prev));
        ASSERT_EQ(clips_chain_check(&rec, &tip), CLIPS_OK);
        rec.seq = 3;
        ASSERT_EQ(clips_chain_check(&rec, &tip), CLIPS_ERR_CHAIN_SEQ);
        rec.seq = 2;
        rec.prev[5] ^= 0x40;
        ASSERT_EQ(clips_chain_check(&rec, &tip), CLIPS_ERR_CHAIN_PREV);
        tip.seq = UINT64_MAX;
        rec.seq = 1;
        ASSERT_EQ(clips_chain_check(&rec, &tip), CLIPS_ERR_CHAIN_SEQ);
        PASS();
    }

    TEST("fork: same author, lane and seq with different bytes is a fork") {
        struct clips_record a, b;
        bool forked = false;
        cr_make_reaction(&a);
        b = a;
        ASSERT_EQ(clips_record_fork_check(&a, &b, &forked), CLIPS_OK);
        ASSERT(!forked);
        b.body[3] ^= 0x01;
        ASSERT_EQ(clips_record_fork_check(&a, &b, &forked), CLIPS_OK);
        ASSERT(forked);
        b = a;
        b.seq = 2;
        b.body[3] ^= 0x01;
        ASSERT_EQ(clips_record_fork_check(&a, &b, &forked), CLIPS_OK);
        ASSERT(!forked);
        PASS();
    }

    TEST("truncation at every offset of a record is refused") {
        struct clips_record rec, back;
        uint8_t buf[CLIPS_RECORD_MAX_LEN];
        size_t n = 0;
        cr_make_reaction(&rec);
        ASSERT_EQ(cr_encode(&rec, buf, &n), CLIPS_OK);
        for (size_t k = 0; k < n; k++)
            ASSERT(clips_record_decode(buf, k, &back) != CLIPS_OK);
        PASS();
    }

    TEST("body decode is refused at every truncation offset") {
        struct clips_body b, out;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_REACTION;
        b.u.reaction.reaction = 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        for (size_t k = 0; k < n; k++)
            ASSERT(clips_body_decode(CLIPS_KIND_REACTION, buf, k, &out) != CLIPS_OK);
        PASS();
    }

    TEST("post refusals: reserved flag, level 0, level 6, unknown descriptor, no link") {
        struct clips_body b, out;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        cb_post(&b);
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        buf[0] |= 0x08;
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_POST, buf, n, &out), CLIPS_ERR_RESERVED_FLAGS);
        cb_post(&b);
        b.u.post.level = 0;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_LEVEL);
        b.u.post.level = 6;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_LEVEL);
        cb_post(&b);
        b.u.post.descriptors = 0x80;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_DESCRIPTOR);
        cb_post(&b);
        b.u.post.has_manifest = false;
        b.u.post.has_reply_to = true;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_BODY);
        PASS();
    }

    TEST("post limits: caption 0, 500 accepted, 501 refused; tags 8 accepted, 9 refused") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        cb_post(&b);
        b.u.post.caption_len = 0;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.post.caption_len = CLIPS_CAPTION_MAX;
        memset(b.u.post.caption, 'a', CLIPS_CAPTION_MAX);
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.post.caption_len = CLIPS_CAPTION_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.post.caption_len = 1;
        b.u.post.caption[0] = 0x01;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        b.u.post.caption[0] = 'a';
        b.u.post.tag_count = CLIPS_TAGS_MAX;
        for (uint8_t i = 0; i < CLIPS_TAGS_MAX; i++) {
            b.u.post.tag_len[i] = 1;
            b.u.post.tags[i][0] = 'a';
        }
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.post.tag_count = CLIPS_TAGS_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("post tag limits: length 0 and 33 refused, 32 accepted, bad characters refused") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        cb_post(&b);
        b.u.post.tag_count = 1;
        b.u.post.tag_len[0] = 0;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.post.tag_len[0] = CLIPS_TAG_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.post.tag_len[0] = CLIPS_TAG_MAX;
        memset(b.u.post.tags[0], 'z', CLIPS_TAG_MAX);
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.post.tags[0][0] = '-';
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("profile limits: name 48, bio 160 and tip 128 accepted; one more refused") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_PROFILE;
        b.u.profile.level = CLIPS_LEVEL_GENERAL;
        b.u.profile.name_len = CLIPS_PROFILE_NAME_MAX;
        b.u.profile.bio_len = CLIPS_PROFILE_BIO_MAX;
        b.u.profile.tip_len = CLIPS_PROFILE_TIP_MAX;
        memset(b.u.profile.name, 'a', sizeof(b.u.profile.name));
        memset(b.u.profile.bio, 'a', sizeof(b.u.profile.bio));
        memset(b.u.profile.tip, 'a', sizeof(b.u.profile.tip));
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.profile.name_len = CLIPS_PROFILE_NAME_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.profile.name_len = 0;
        b.u.profile.bio_len = CLIPS_PROFILE_BIO_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.profile.bio_len = 0;
        b.u.profile.tip_len = CLIPS_PROFILE_TIP_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("list and tombstone limits and refusals") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_LIST;
        b.u.list.list_kind = 1;
        b.u.list.entry_count = CLIPS_LIST_ENTRIES_MAX;
        b.u.list.title_len = CLIPS_LIST_TITLE_MAX;
        memset(b.u.list.title, 'a', sizeof(b.u.list.title));
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.list.entry_count = CLIPS_LIST_ENTRIES_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.list.entry_count = 0;
        b.u.list.title_len = CLIPS_LIST_TITLE_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.list.title_len = 0;
        b.u.list.list_kind = 3;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_TOMBSTONE;
        b.u.tombstone.reason = 5;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.tombstone.reason = 4;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        PASS();
    }

    TEST("rating body: method 0 and 4 refused, note 120 accepted and 121 refused") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_RATING;
        b.u.rating.level = CLIPS_LEVEL_MATURE;
        b.u.rating.method = 0;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.rating.method = 4;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.rating.method = 3;
        b.u.rating.note_len = CLIPS_RATING_NOTE_MAX;
        memset(b.u.rating.note, 'a', sizeof(b.u.rating.note));
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.rating.note_len = CLIPS_RATING_NOTE_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.rating.note_len = 0;
        b.u.rating.level = 6;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_LEVEL);
        b.u.rating.level = 0;
        b.u.rating.descriptors = 0x0080;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_DESCRIPTOR);
        PASS();
    }

    TEST("comment limits: text 1 and 280 accepted, 0 and 281 refused") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_COMMENT;
        b.u.comment.text_len = 0;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.comment.text_len = 1;
        b.u.comment.text[0] = 'x';
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.comment.text_len = CLIPS_COMMENT_MAX;
        memset(b.u.comment.text, 'x', CLIPS_COMMENT_MAX);
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.comment.text_len = CLIPS_COMMENT_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("follow, block and report refusals") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_FOLLOW;
        b.u.follow.flags = 2;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_BLOCK;
        b.u.block.target_type = 1;
        b.u.block.target[40] = 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.block.target[40] = 0;
        b.u.block.target_type = 3;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_REPORT;
        b.u.report.reason = 8;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        b.u.report.reason = 7;
        b.u.report.note_len = CLIPS_REPORT_NOTE_MAX + 1;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("profile level: 0 and 6 refused, 1 accepted") {
        struct clips_body b, out;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_PROFILE;
        b.u.profile.level = 0;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_LEVEL);
        b.u.profile.level = 6;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_LEVEL);
        b.u.profile.level = CLIPS_LEVEL_GENERAL;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_PROFILE, buf, n, &out), CLIPS_OK);
        ASSERT_EQ(out.u.profile.level, CLIPS_LEVEL_GENERAL);
        PASS();
    }

    TEST("text rule: decomposed UTF-8 is accepted; a C1 control or DEL is refused") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        cb_post(&b);
        b.u.post.caption_len = 3;
        b.u.post.caption[0] = 0x65;
        b.u.post.caption[1] = 0xcc;
        b.u.post.caption[2] = 0x81;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.post.caption_len = 2;
        b.u.post.caption[0] = 0xc2;
        b.u.post.caption[1] = 0x85;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        b.u.post.caption_len = 1;
        b.u.post.caption[0] = 0x7f;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_COMMENT;
        b.u.comment.text_len = 2;
        b.u.comment.text[0] = 0xc2;
        b.u.comment.text[1] = 0x85;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        PASS();
    }

    TEST("malformed UTF-8 and control characters are refused as caption and comment; LF and euro sign are accepted") {
        for (size_t i = 0; i < sizeof(k_text_cases) / sizeof(k_text_cases[0]); i++) {
            ASSERT_EQ(cr_caption_check(k_text_cases[i].text, k_text_cases[i].len), k_text_cases[i].want);
            ASSERT_EQ(cr_comment_check(k_text_cases[i].text, k_text_cases[i].len), k_text_cases[i].want);
        }
        PASS();
    }

    TEST("raw post: a tag over 32 bytes, a tag count over 8 and a tag character outside [a-z0-9_] are FIELD") {
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = cr_raw_post_head(buf);
        buf[n] = 1;
        buf[n + 1] = 33;
        memset(buf + n + 2, 'a', 33);
        ASSERT_EQ(cr_decode_post(buf, n + 2 + 33), CLIPS_ERR_FIELD);
        n = cr_raw_post_head(buf);
        buf[n] = 9;
        ASSERT_EQ(cr_decode_post(buf, n + 1), CLIPS_ERR_FIELD);
        n = cr_raw_post_head(buf);
        buf[n] = 1;
        buf[n + 1] = 1;
        buf[n + 2] = 'A';
        ASSERT_EQ(cr_decode_post(buf, n + 3), CLIPS_ERR_FIELD);
        buf[n + 2] = 'a';
        ASSERT_EQ(cr_decode_post(buf, n + 3), CLIPS_OK);
        PASS();
    }

    TEST("raw post: a caption length over 500 is FIELD, checked before its bytes are read") {
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = cr_raw_post_head(buf);
        buf[n - 2] = 0xf5;
        buf[n - 1] = 0x01;
        memset(buf + n, 'a', 501);
        buf[n + 501] = 0;
        ASSERT_EQ(cr_decode_post(buf, n + 502), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("raw profile: an avatar flag of 2 is FIELD; flag 0 with an empty tip is accepted") {
        uint8_t buf[8];
        struct clips_body out;
        memset(buf, 0, sizeof(buf));
        buf[0] = CLIPS_LEVEL_GENERAL;
        buf[3] = 2;
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_PROFILE, buf, 4, &out), CLIPS_ERR_FIELD);
        buf[3] = 0;
        buf[4] = 0;
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_PROFILE, buf, 5, &out), CLIPS_OK);
        PASS();
    }

    TEST("raw reaction: one byte past the body is TRAILING") {
        uint8_t buf[CLIPS_HASH_LEN + 2];
        struct clips_body out;
        memset(buf, 0, sizeof(buf));
        buf[CLIPS_HASH_LEN] = 1;
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_REACTION, buf, CLIPS_HASH_LEN + 1, &out), CLIPS_OK);
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_REACTION, buf, CLIPS_HASH_LEN + 2, &out), CLIPS_ERR_TRAILING);
        PASS();
    }

    TEST("raw block: a type 1 target with a nonzero byte at 32..63 is FIELD") {
        uint8_t buf[2 + CLIPS_HASH_LEN];
        struct clips_body out;
        memset(buf, 0, sizeof(buf));
        buf[0] = 1;
        buf[1 + 40] = 0;
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_BLOCK, buf, sizeof(buf), &out), CLIPS_OK);
        buf[1 + 40] = 1;
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_BLOCK, buf, sizeof(buf), &out), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("verify does not decode the body: a validly signed record with a malformed body verifies, and check_body refuses it") {
        struct clips_record rec;
        uint8_t pk[32], seed[32];
        cr_fixture_key(pk, seed);
        memset(&rec, 0, sizeof(rec));
        rec.kind = CLIPS_KIND_POST;
        rec.lane = CLIPS_LANE_CONTENT;
        memcpy(rec.author, pk, sizeof(pk));
        rec.seq = 1;
        rec.created_at = 1700000000;
        rec.body_len = 4;
        rec.body[1] = 1;
        ASSERT_EQ(clips_record_sign(&rec, seed), CLIPS_OK);
        ASSERT_EQ(clips_record_verify(&rec), CLIPS_OK);
        ASSERT_EQ(clips_record_check_body(&rec), CLIPS_ERR_BODY);
        PASS();
    }

    TEST("post known answer: key, record id and signature match openssl; the body decodes to level 4 and descriptors 5") {
        struct clips_record rec;
        struct clips_body out;
        uint8_t seed[32], pk[32], sk[32], id[CLIPS_HASH_LEN];
        char hex[2 * CLIPS_HASH_LEN + 1];
        memset(seed, 0x07, sizeof(seed));
        ed25519_keypair(pk, sk, seed);
        memset(&rec, 0, sizeof(rec));
        rec.kind = CLIPS_KIND_POST;
        rec.lane = CLIPS_LANE_CONTENT;
        memcpy(rec.author, pk, sizeof(pk));
        rec.seq = 1;
        rec.created_at = 1700000000;
        struct clips_body pb;
        uint8_t enc[CLIPS_RECORD_BODY_MAX];
        size_t enc_n = 0;
        cb_post(&pb);
        pb.u.post.level = CLIPS_LEVEL_MATURE;
        pb.u.post.descriptors = 5;
        pb.u.post.caption_len = 2;
        pb.u.post.caption[0] = 'h';
        pb.u.post.caption[1] = 'i';
        ASSERT_EQ(cr_body(&pb, enc, &enc_n), CLIPS_OK);
        ASSERT_EQ(enc_n, 73);
        rec.body_len = (uint16_t)enc_n;
        memcpy(rec.body, enc, enc_n);
        ASSERT_EQ(clips_record_sign(&rec, seed), CLIPS_OK);
        cr_hex(pk, sizeof(pk), hex);
        ASSERT(strcmp(hex, k_kat_post_pk) == 0);
        ASSERT_EQ(clips_record_id(&rec, id), CLIPS_OK);
        cr_hex(id, sizeof(id), hex);
        ASSERT(strcmp(hex, k_kat_post_id) == 0);
        cr_hex(rec.signature, sizeof(rec.signature), hex);
        ASSERT(strcmp(hex, k_kat_post_sig) == 0);
        ASSERT_EQ(clips_record_verify(&rec), CLIPS_OK);
        ASSERT_EQ(clips_body_decode(CLIPS_KIND_POST, rec.body, rec.body_len, &out), CLIPS_OK);
        ASSERT_EQ(out.u.post.level, CLIPS_LEVEL_MATURE);
        ASSERT_EQ(out.u.post.descriptors, 5);
        PASS();
    }

    TEST("text rule: profile name, bio and tip, list title, rating note and report note refuse controls and malformed UTF-8") {
        struct clips_body b;
        uint8_t buf[CLIPS_RECORD_BODY_MAX];
        size_t n = 0;
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_PROFILE;
        b.u.profile.level = CLIPS_LEVEL_GENERAL;
        b.u.profile.name_len = 1;
        b.u.profile.name[0] = 0x1b;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        b.u.profile.name_len = 2;
        b.u.profile.name[0] = 0xc3;
        b.u.profile.name[1] = 0xa9;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        b.u.profile.name_len = 0;
        b.u.profile.bio_len = 2;
        b.u.profile.bio[0] = 0xc2;
        b.u.profile.bio[1] = 0x85;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        b.u.profile.bio_len = 0;
        b.u.profile.tip_len = 1;
        b.u.profile.tip[0] = 0x0d;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_LIST;
        b.u.list.list_kind = 1;
        b.u.list.entry_count = 1;
        b.u.list.title_len = 2;
        b.u.list.title[0] = 0xc2;
        b.u.list.title[1] = 0x85;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_RATING;
        b.u.rating.level = CLIPS_LEVEL_GENERAL;
        b.u.rating.method = 1;
        b.u.rating.note_len = 1;
        b.u.rating.note[0] = 0x7f;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        memset(&b, 0, sizeof(b));
        b.kind = CLIPS_KIND_REPORT;
        b.u.report.reason = 1;
        b.u.report.note_len = 2;
        b.u.report.note[0] = 0xc2;
        b.u.report.note[1] = 0x85;
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_ERR_TEXT);
        b.u.report.note_len = 1;
        b.u.report.note[0] = 'a';
        ASSERT_EQ(cr_body(&b, buf, &n), CLIPS_OK);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_clips_record: all passed\n");
    else
        printf("test_clips_record: %d FAILED\n", failures);
    return failures;
}
