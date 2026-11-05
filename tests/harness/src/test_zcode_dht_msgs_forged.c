/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hostile-frame cases for the ZCODE DHT message codec. Every payload check in
 * vcs_zcode_dht_msg_parse runs after the frame signature, so these cases
 * re-sign a tampered frame with the fixture's online key (a mirror of
 * sign_frame) and assert the exact error the intended check returns. Checks
 * that run before the signature (framing, counts, auth identity) are tampered
 * without re-signing. Entry point: zcode_dht_msgs_forged_tests(), called from
 * test_zcode_dht_msgs(). */

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "support/cleanse.h"
#include "vcs/zcode_dht_msgs.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define E_(x) VCS_ZCODE_DHT_ERR_##x
#define VCS_ZCODE_DHT_ERR_OK VCS_ZCODE_DHT_OK /* spelling shim for E_(OK) */
#define HDR VCS_ZCODE_DHT_MSGS_HEADER_BYTES
#define PAY (VCS_ZCODE_DHT_MSGS_HEADER_BYTES + VCS_ZCODE_DHT_MSGS_AUTH_BYTES)
#define SIG VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES
#define RW VCS_ZCODE_DHT_RECORD_WIRE_BYTES
#define MAXF (VCS_ZCODE_DHT_MAX_FRAME_BYTES + 16u)
#define O_GEN HDR
#define O_SENDER (HDR + 8u)
#define O_QUERY (HDR + 40u)
#define O_DELEG (HDR + 56u)
#define S_KIND PAY
#define S_LEN (PAY + 1u)
#define S_NS (PAY + 2u)
#define S_ROOT (PAY + 34u)
#define S_PAGE (PAY + 66u)
#define S_NEXT (PAY + 67u)
#define S_COUNT (PAY + 68u)
#define R_FIRST (PAY + 69u)

struct fx {
    uint8_t seed[32], secret[32], pub[32], transcript[32], node_id[32];
    struct vcs_zcode_dht_delegation delegation;
    struct vcs_zcode_dht_msg_verify_context verify;
    int chain_calls;
};

static bool chain_ok(void *ctx, const struct vcs_zcode_dht_delegation *d)
{
    (void)d;
    (*(int *)ctx)++;
    return true;
}

static bool fx_init(struct fx *f)
{
    memset(f, 0, sizeof(*f));
    uint8_t genesis[32], noise[32], beacon[32], master[32];
    memset(f->seed, 0x22, 32);
    ed25519_keypair(f->pub, f->secret, f->seed);
    memset(genesis, 1, 32);
    memset(noise, 0x33, 32);
    memset(beacon, 0x44, 32);
    memset(master, 0x55, 32);
    if (vcs_zcode_dht_delegation_sign(&f->delegation, genesis, f->pub, noise,
                                      120, beacon, 1000, 2000, 7, master) !=
            VCS_ZCODE_DHT_DELEGATION_OK ||
        !vcs_zcode_dht_delegation_node_id(f->node_id, &f->delegation))
        return false;
    memset(f->transcript, 0x77, 32);
    f->verify.noise_established = true;
    memcpy(f->verify.noise_transcript_hash, f->transcript, 32);
    memcpy(f->verify.remote_noise_static, noise, 32);
    memcpy(f->verify.network_genesis, genesis, 32);
    f->verify.session_generation = 9;
    f->verify.now_unix = 1500;
    f->verify.transport_verify = chain_ok;
    f->verify.transport_ctx = &f->chain_calls;
    f->verify.authority_verify = chain_ok;
    f->verify.authority_ctx = &f->chain_calls;
    return true;
}

/* Mirror of sign_frame: domain || transcript || wire[0..len-64). */
static void resign(const struct fx *f, uint8_t *wire, size_t len)
{
    uint8_t pre[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 + MAXF];
    size_t n = 0;
    memcpy(pre, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
           sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
    n += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
    memcpy(pre + n, f->transcript, 32);
    n += 32;
    memcpy(pre + n, wire, len - SIG);
    n += len - SIG;
    ed25519_sign(wire + len - SIG, pre, n, f->secret, f->pub);
}

static enum vcs_zcode_dht_error prs(const struct fx *f, const uint8_t *w,
                                    size_t len, struct vcs_zcode_dht_msg *out)
{
    return vcs_zcode_dht_msg_parse(w, len, &f->verify, out);
}

static void qfill(uint8_t q[16])
{
    for (size_t i = 0; i < 16; i++) q[i] = (uint8_t)(i + 1);
}

/* `f` may be a struct fx or a pointer to one. */
#define FXP_(x) _Generic((x), struct fx: &(x), default: (x))
#define AUTH_SET(m) do { \
    (m).session_generation = 9; \
    memcpy((m).sender_node_id, FXP_(f)->node_id, 32); \
    qfill((m).query_id); \
    (m).delegation = FXP_(f)->delegation; \
} while (0)

static void sel_default(struct vcs_zcode_dht_record_selector *s)
{
    memset(s, 0, sizeof(*s));
    s->kind = VCS_ZCODE_DHT_RECORD_POINTER;
    memcpy(s->namespace_name, "science.study", 13);
    memset(s->root, 0x61, 32);
}

static bool rec_make(const struct fx *f, struct vcs_zcode_dht_record *r,
                     uint64_t seq)
{
    memset(r, 0, sizeof(*r));
    r->kind = VCS_ZCODE_DHT_RECORD_POINTER;
    memcpy(r->namespace_name, "science.study", 13);
    memcpy(r->network_genesis, f->verify.network_genesis, 32);
    memset(r->semantic_root, 0x61, 32);
    memset(r->transport_root, 0x71, 32);
    memcpy(r->provider_node_id, f->node_id, 32);
    r->sequence = seq;
    r->not_before = 1200;
    r->expiry = 1800;
    r->delegation = f->delegation;
    return vcs_zcode_dht_record_sign(r, f->seed) == VCS_ZCODE_DHT_RECORD_OK;
}

/* ---- frame builders: each returns the wire length, 0 on failure ---- */

static size_t b_fn(const struct fx *f, uint8_t *w)
{
    struct vcs_zcode_dht_msg_find_node m;
    memset(&m, 0, sizeof(m));
    AUTH_SET(m);
    for (size_t i = 0; i < 32; i++) m.target_node_id[i] = (uint8_t)(i + 1);
    size_t len = 0;
    return vcs_zcode_dht_msg_serialize_find_node(&m, f->transcript, f->seed, w,
                                                 MAXF, &len) == E_(OK)
               ? len : 0;
}

static size_t b_nodes(const struct fx *f, uint8_t *w, uint32_t n)
{
    struct vcs_zcode_dht_msg_nodes m;
    memset(&m, 0, sizeof(m));
    AUTH_SET(m);
    m.contact_count = n;
    for (uint32_t i = 0; i < n && i < VCS_ZCODE_DHT_K; i++)
        memset(m.node_ids[i], (int)(i + 1), 32);
    size_t len = 0;
    return vcs_zcode_dht_msg_serialize_nodes(&m, f->transcript, f->seed, w,
                                             MAXF, &len) == E_(OK)
               ? len : 0;
}

static size_t b_fr(const struct fx *f, uint8_t *w)
{
    struct vcs_zcode_dht_msg_find_record m;
    memset(&m, 0, sizeof(m));
    AUTH_SET(m);
    sel_default(&m.selector);
    m.page_offset = 8;
    size_t len = 0;
    return vcs_zcode_dht_msg_serialize_find_record(&m, f->transcript, f->seed,
                                                   w, MAXF, &len) == E_(OK)
               ? len : 0;
}

static bool recs_fill(const struct fx *f, struct vcs_zcode_dht_msg_records *m,
                      uint32_t n, uint8_t page, uint8_t next)
{
    memset(m, 0, sizeof(*m));
    AUTH_SET(*m);
    sel_default(&m->selector);
    m->page_offset = page;
    m->next_offset = next;
    m->record_count = n;
    for (uint32_t i = 0; i < n && i < VCS_ZCODE_DHT_RECORDS_PER_FRAME; i++)
        if (!rec_make(f, &m->records[i], i + 1u)) return false;
    return true;
}

static size_t b_recs(const struct fx *f, uint8_t *w, uint32_t n, uint8_t page,
                     uint8_t next)
{
    struct vcs_zcode_dht_msg_records m;
    size_t len = 0;
    if (!recs_fill(f, &m, n, page, next)) return 0;
    return vcs_zcode_dht_msg_serialize_records(&m, f->transcript, f->seed, w,
                                               MAXF, &len) == E_(OK)
               ? len : 0;
}

static size_t b_store(const struct fx *f, uint8_t *w)
{
    struct vcs_zcode_dht_msg_store_record m;
    memset(&m, 0, sizeof(m));
    AUTH_SET(m);
    if (!rec_make(f, &m.record, 1)) return 0;
    size_t len = 0;
    return vcs_zcode_dht_msg_serialize_store_record(&m, f->transcript, f->seed,
                                                    w, MAXF, &len) == E_(OK)
               ? len : 0;
}

static size_t b_result(const struct fx *f, uint8_t *w)
{
    struct vcs_zcode_dht_msg_store_result m;
    memset(&m, 0, sizeof(m));
    AUTH_SET(m);
    m.status = VCS_ZCODE_DHT_STORE_STORED;
    for (size_t i = 0; i < 32; i++) m.record_digest[i] = (uint8_t)(i + 1);
    size_t len = 0;
    return vcs_zcode_dht_msg_serialize_store_result(&m, f->transcript, f->seed,
                                                    w, MAXF, &len) == E_(OK)
               ? len : 0;
}

/* ---- serializer: find_node auth, transcript and null guards ---- */

static enum vcs_zcode_dht_error ser_fn(
    const struct fx *f, const struct vcs_zcode_dht_msg_find_node *m,
    const uint8_t *transcript, uint8_t *w, size_t cap, size_t *len)
{
    return vcs_zcode_dht_msg_serialize_find_node(m, transcript, f->seed, w,
                                                 cap, len);
}

static int test_fn_roundtrip_and_auth(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: FIND_NODE round trip over garbage and auth refusals") {
        struct fx f; ASSERT(fx_init(&f));
        struct vcs_zcode_dht_msg_find_node m, bad;
        memset(&m, 0, sizeof(m));
        AUTH_SET(m);
        for (size_t i = 0; i < 32; i++) m.target_node_id[i] = (uint8_t)(i + 1);
        uint8_t w[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES]; size_t len = 99;
        memset(w, 0xA5, sizeof(w));
        ASSERT_EQ(ser_fn(&f, &m, f.transcript, w, sizeof(w), &len), E_(OK));
        ASSERT_EQ(len, VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES);
        struct vcs_zcode_dht_msg p;
        ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
        ASSERT_EQ(p.find_node.session_generation, 9);
        ASSERT(memcmp(p.find_node.sender_node_id, f.node_id, 32) == 0);
        ASSERT(memcmp(p.find_node.query_id, m.query_id, 16) == 0);
        ASSERT(memcmp(p.find_node.target_node_id, m.target_node_id, 32) == 0);
        ASSERT_EQ(ser_fn(&f, &m, f.transcript, w, sizeof(w) - 1, &len),
                  E_(WIRE_SIZE));
        ASSERT_EQ(len, 0);
        bad = m; bad.session_generation = 0; len = 99;
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(ID_ZERO));
        ASSERT_EQ(len, 0);
        bad = m; memset(bad.sender_node_id, 0, 32);
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(ID_ZERO));
        bad = m; memset(bad.sender_node_id, 0, 32); bad.sender_node_id[31] = 1;
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(DELEGATION));
        bad = m; bad.sender_node_id[31] ^= 1;
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(DELEGATION));
        bad = m; memset(bad.query_id, 0, 16);
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(QUERY_ID));
        bad = m; memset(bad.query_id, 0, 16); bad.query_id[15] = 1;
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(OK));
        bad = m; bad.delegation.mode = (typeof(bad.delegation.mode))99;
        ASSERT_EQ(ser_fn(&f, &bad, f.transcript, w, sizeof(w), &len), E_(DELEGATION));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fn_transcript_target_null(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: serialize transcript, target and NULL guards") {
        struct fx f; ASSERT(fx_init(&f));
        struct vcs_zcode_dht_msg_find_node m;
        memset(&m, 0, sizeof(m));
        AUTH_SET(m);
        memset(m.target_node_id, 0x99, 32);
        uint8_t w[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES]; size_t len = 99;
        uint8_t zero[33]; memset(zero, 0, sizeof(zero)); zero[32] = 0xff;
        ASSERT_EQ(ser_fn(&f, &m, zero, w, sizeof(w), &len), E_(SESSION));
        ASSERT_EQ(len, 0);
        zero[32] = 0; zero[31] = 1;
        ASSERT_EQ(ser_fn(&f, &m, zero, w, sizeof(w), &len), E_(OK));
        /* target: all zero refused, only the last byte set accepted */
        union { struct vcs_zcode_dht_msg_find_node m;
                uint8_t raw[sizeof(struct vcs_zcode_dht_msg_find_node) + 8]; } u;
        memset(&u, 0, sizeof(u));
        AUTH_SET(u.m);
        u.raw[offsetof(struct vcs_zcode_dht_msg_find_node, target_node_id) + 32] = 0xff;
        ASSERT_EQ(ser_fn(&f, &u.m, f.transcript, w, sizeof(w), &len), E_(ID_ZERO));
        u.m.target_node_id[31] = 1;
        ASSERT_EQ(ser_fn(&f, &u.m, f.transcript, w, sizeof(w), &len), E_(OK));
        /* NULL guards and a cleared length */
        len = 99;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, f.transcript, f.seed, w, sizeof(w), NULL), E_(NULL));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      NULL, f.transcript, f.seed, w, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(len, 0); len = 99;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, f.transcript, f.seed, NULL, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(len, 0); len = 99;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, NULL, f.seed, w, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(len, 0); len = 99;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &m, f.transcript, NULL, w, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(len, 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- serializer: NODES ---- */

static enum vcs_zcode_dht_error ser_nodes(
    const struct fx *f, const struct vcs_zcode_dht_msg_nodes *m, uint8_t *w,
    size_t cap, size_t *len)
{
    return vcs_zcode_dht_msg_serialize_nodes(m, f->transcript, f->seed, w, cap,
                                             len);
}

static int test_nodes_serialize_bounds(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: NODES serializer limits, order, id bytes and capacity") {
        struct fx f; ASSERT(fx_init(&f));
        struct vcs_zcode_dht_msg_nodes m, bad;
        memset(&m, 0, sizeof(m));
        AUTH_SET(m);
        m.contact_count = VCS_ZCODE_DHT_K;
        for (uint32_t i = 0; i < VCS_ZCODE_DHT_K; i++)
            m.node_ids[i][31] = (uint8_t)(i + 1); /* differ only in the last byte */
        uint8_t w[MAXF]; size_t len = 99;
        memset(w, 0xA5, sizeof(w));
        ASSERT_EQ(ser_nodes(&f, &m, w, VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES, &len),
                  E_(OK));
        ASSERT_EQ(len, VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES);
        struct vcs_zcode_dht_msg p;
        ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
        ASSERT_EQ(p.nodes.contact_count, VCS_ZCODE_DHT_K);
        for (uint32_t i = 0; i < VCS_ZCODE_DHT_K; i++)
            ASSERT(memcmp(p.nodes.node_ids[i], m.node_ids[i], 32) == 0);
        ASSERT_EQ(ser_nodes(&f, &m, w, VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES - 1, &len),
                  E_(WIRE_SIZE));
        ASSERT_EQ(len, 0);
        bad = m; bad.contact_count = VCS_ZCODE_DHT_K + 1; len = 99;
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(LIMIT));
        ASSERT_EQ(len, 0);
        bad = m; memset(bad.node_ids[0], 0, 32);
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(ID_ZERO));
        bad = m; memset(bad.node_ids[5], 0, 32);
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(ID_ZERO));
        bad = m; bad.node_ids[3][31] = 2; /* [2] holds 3: descending by one byte */
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.node_ids[3][31] = bad.node_ids[2][31]; /* equal neighbours */
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.contact_count = 0; len = 0;
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(OK));
        ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
        ASSERT_EQ(p.nodes.contact_count, 0);
        bad = m; bad.sender_node_id[31] ^= 1;
        ASSERT_EQ(ser_nodes(&f, &bad, w, sizeof(w), &len), E_(DELEGATION));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- serializer: selector (through FIND_RECORD) ---- */

static enum vcs_zcode_dht_error ser_fr(
    const struct fx *f, const struct vcs_zcode_dht_msg_find_record *m,
    uint8_t *w, size_t cap, size_t *len)
{
    return vcs_zcode_dht_msg_serialize_find_record(m, f->transcript, f->seed,
                                                   w, cap, len);
}

static void fr_with_name(const struct fx *f,
                         struct vcs_zcode_dht_msg_find_record *m,
                         const char name[32])
{
    memset(m, 0, sizeof(*m));
    AUTH_SET(*m);
    sel_default(&m->selector);
    memcpy(m->selector.namespace_name, name, 32);
    m->page_offset = 8;
}

struct name_case { char name[32]; bool ok; };

static const struct name_case g_names[] = {
    {"a", true}, {"z", true}, {"0", true}, {"9", true}, {".", true},
    {"_", true}, {"-", true}, {"a.z_0-9", true},
    {"", false}, {"A", false}, {"Z", false}, {"`", false}, {"{", false},
    {"/", false}, {":", false}, {"@", false}, {"[", false}, {" ", false},
    {"+", false}, {"aA", false}, {"Ab", false}, {"a b", false},
    {"\x7f", false}, {"\x80", false}, {"a/", false}, {"{a", false},
    {"a:", false}, {"ab\0c", false},
};

static int test_selector_name_table(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: selector namespace characters and padding") {
        struct fx f; ASSERT(fx_init(&f));
        uint8_t w[VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES]; size_t len = 0;
        struct vcs_zcode_dht_msg p;
        struct vcs_zcode_dht_msg_find_record m;
        for (size_t i = 0; i < sizeof(g_names) / sizeof(g_names[0]); i++) {
            fr_with_name(&f, &m, g_names[i].name);
            memset(w, 0xA5, sizeof(w));
            enum vcs_zcode_dht_error e = ser_fr(&f, &m, w, sizeof(w), &len);
            if (g_names[i].ok) {
                ASSERT_EQ(e, E_(OK));
                ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
                ASSERT(memcmp(p.find_record.selector.namespace_name,
                              g_names[i].name, 32) == 0);
                ASSERT(memcmp(p.find_record.selector.root, m.selector.root, 32) == 0);
                ASSERT_EQ(p.find_record.selector.kind, VCS_ZCODE_DHT_RECORD_POINTER);
            } else {
                ASSERT_EQ(e, E_(WIRE_ORDER));
                ASSERT_EQ(len, 0);
            }
        }
        char full[32];
        memset(full, 'a', 31); full[31] = 0;     /* 31 chars: the longest legal */
        fr_with_name(&f, &m, full);
        ASSERT_EQ(ser_fr(&f, &m, w, sizeof(w), &len), E_(OK));
        ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
        ASSERT(memcmp(p.find_record.selector.namespace_name, full, 32) == 0);
        memset(full, 'a', 32);                    /* 32 chars, no terminator */
        fr_with_name(&f, &m, full);
        ASSERT_EQ(ser_fr(&f, &m, w, sizeof(w), &len), E_(WIRE_ORDER));
        PASS();
    } _test_next:;
    return failures;
}

static int test_selector_kind_root_page(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: selector kind, root and page offset bounds") {
        struct fx f; ASSERT(fx_init(&f));
        uint8_t w[VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES]; size_t len = 0;
        struct vcs_zcode_dht_msg p;
        struct vcs_zcode_dht_msg_find_record m;
        const char ab[32] = "ab";
        fr_with_name(&f, &m, ab);
        const int ok_kinds[] = {1, 4}, bad_kinds[] = {0, 6, 255};
        for (size_t i = 0; i < 2; i++) {
            m.selector.kind = (enum vcs_zcode_dht_record_kind)ok_kinds[i];
            ASSERT_EQ(ser_fr(&f, &m, w, sizeof(w), &len), E_(OK));
            ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
            ASSERT_EQ((int)p.find_record.selector.kind, ok_kinds[i]);
        }
        for (size_t i = 0; i < 3; i++) {
            m.selector.kind = (enum vcs_zcode_dht_record_kind)bad_kinds[i];
            ASSERT_EQ(ser_fr(&f, &m, w, sizeof(w), &len), E_(WIRE_ORDER));
        }
        m.selector.kind = VCS_ZCODE_DHT_RECORD_POINTER;
        const uint8_t ok_pages[] = {0, 8, 56}, bad_pages[] = {1, 7, 9, 64, 72, 255};
        for (size_t i = 0; i < 3; i++) {
            m.page_offset = ok_pages[i];
            ASSERT_EQ(ser_fr(&f, &m, w, sizeof(w), &len), E_(OK));
            ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
            ASSERT_EQ(p.find_record.page_offset, ok_pages[i]);
        }
        for (size_t i = 0; i < 6; i++) {
            m.page_offset = bad_pages[i];
            ASSERT_EQ(ser_fr(&f, &m, w, sizeof(w), &len), E_(WIRE_ORDER));
        }
        m.page_offset = 8;
        union { struct vcs_zcode_dht_msg_find_record m;
                uint8_t raw[sizeof(struct vcs_zcode_dht_msg_find_record) + 8]; } u;
        memset(&u, 0, sizeof(u));
        u.m = m;
        memset(u.m.selector.root, 0, 32);   /* root zero, page_offset follows */
        ASSERT_EQ(ser_fr(&f, &u.m, w, sizeof(w), &len), E_(WIRE_ORDER));
        u.m.selector.root[31] = 1;          /* only the last byte set is legal */
        ASSERT_EQ(ser_fr(&f, &u.m, w, sizeof(w), &len), E_(OK));
        ASSERT_EQ(ser_fr(&f, &u.m, w, sizeof(w) - 1, &len), E_(WIRE_SIZE));
        ASSERT_EQ(len, 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- serializer: RECORDS ---- */

static enum vcs_zcode_dht_error ser_recs(
    const struct fx *f, const struct vcs_zcode_dht_msg_records *m, uint8_t *w,
    size_t cap, size_t *len)
{
    return vcs_zcode_dht_msg_serialize_records(m, f->transcript, f->seed, w,
                                               cap, len);
}

static int test_records_roundtrip(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: RECORDS pages of 0, 1 and 8 round trip and size exactly") {
        struct fx f; ASSERT(fx_init(&f));
        static uint8_t w[MAXF];
        struct vcs_zcode_dht_msg_records m;
        static struct vcs_zcode_dht_msg p;
        const uint32_t counts[] = {0, 1, 8};
        for (size_t c = 0; c < 3; c++) {
            ASSERT(recs_fill(&f, &m, counts[c], 16, counts[c] == 8 ? 24 : 0));
            size_t len = 99;
            memset(w, 0xA5, sizeof(w));
            ASSERT_EQ(ser_recs(&f, &m, w, sizeof(w), &len), E_(OK));
            ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
            ASSERT_EQ(p.records.record_count, counts[c]);
            ASSERT_EQ(p.records.page_offset, 16);
            ASSERT_EQ(p.records.next_offset, counts[c] == 8 ? 24 : 0);
            for (uint32_t i = 0; i < counts[c]; i++) {
                ASSERT_EQ(p.records.records[i].sequence, i + 1u);
                ASSERT(memcmp(p.records.records[i].signature,
                              m.records[i].signature, 64) == 0);
            }
            size_t full = len;
            ASSERT_EQ(ser_recs(&f, &m, w, full, &len), E_(OK));
            ASSERT_EQ(len, full);
            ASSERT_EQ(ser_recs(&f, &m, w, full - 1, &len), E_(WIRE_SIZE));
            ASSERT_EQ(len, 0);
        }
        ASSERT(recs_fill(&f, &m, 8, 0, 0));
        size_t len = 0;
        ASSERT_EQ(ser_recs(&f, &m, w, sizeof(w), &len),  E_(OK));
        ASSERT_EQ(len, VCS_ZCODE_DHT_RECORDS_MAX_WIRE_BYTES);
        PASS();
    } _test_next:;
    return failures;
}

static int test_records_refusals(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: RECORDS serializer refuses bad offsets, counts, order and networks") {
        struct fx f; ASSERT(fx_init(&f));
        static uint8_t w[MAXF];
        static struct vcs_zcode_dht_msg_records m, bad;
        size_t len = 99;
        ASSERT(recs_fill(&f, &m, 8, 0, 0));
        const uint8_t pages[] = {1, 7, 64, 72, 255};
        for (size_t i = 0; i < 5; i++) {
            bad = m; bad.page_offset = pages[i];
            ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
            ASSERT_EQ(len, 0); len = 99;
        }
        bad = m; bad.page_offset = 56; bad.next_offset = 64;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.page_offset = 56; bad.next_offset = 0;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(OK));
        bad = m; bad.next_offset = 16;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.next_offset = 9;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.next_offset = 8;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(OK));
        bad = m; bad.next_offset = 8; bad.record_count = 1;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(LIMIT));
        bad = m; bad.record_count = 9;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(LIMIT));
        bad = m; bad.selector.root[31] ^= 1;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.record_count = 2; bad.records[1] = bad.records[0];
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.record_count = 2;
        bad.records[0] = m.records[1]; bad.records[1] = m.records[0];
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.records[2].network_genesis[31] ^= 1;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(NETWORK));
        bad = m; memset(bad.records[2].signature, 0, 64);
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(WIRE_ORDER));
        bad = m; bad.sender_node_id[31] ^= 1;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(DELEGATION));
        bad = m; bad.session_generation = 0;
        ASSERT_EQ(ser_recs(&f, &bad, w, sizeof(w), &len), E_(ID_ZERO));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      &m, f.transcript, f.seed, w, sizeof(w), NULL), E_(NULL));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      NULL, f.transcript, f.seed, w, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(len, 0);
        uint8_t zero_t[32] = {0};
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      &m, zero_t, f.seed, w, sizeof(w), &len), E_(SESSION));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- serializer: STORE_RECORD, STORE_RESULT, and error propagation ---- */

static int test_store_serialize(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: STORE_RECORD and STORE_RESULT serializer bounds") {
        struct fx f; ASSERT(fx_init(&f));
        static uint8_t w[MAXF];
        struct vcs_zcode_dht_msg_store_record s, sb;
        memset(&s, 0, sizeof(s));
        AUTH_SET(s);
        ASSERT(rec_make(&f, &s.record, 1));
        size_t len = 99;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &s, f.transcript, f.seed, w,
                      VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES, &len), E_(OK));
        ASSERT_EQ(len, VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &s, f.transcript, f.seed, w,
                      VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES - 1, &len),
                  E_(WIRE_SIZE));
        ASSERT_EQ(len, 0);
        sb = s; sb.record.network_genesis[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &sb, f.transcript, f.seed, w, sizeof(w), &len), E_(NETWORK));
        sb = s; memset(sb.record.signature, 0, 64);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &sb, f.transcript, f.seed, w, sizeof(w), &len),
                  E_(WIRE_ORDER));
        sb = s; sb.session_generation = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &sb, f.transcript, f.seed, w, sizeof(w), &len), E_(ID_ZERO));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      NULL, f.transcript, f.seed, w, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &s, f.transcript, f.seed, w, sizeof(w), NULL), E_(NULL));
        uint8_t zero_t[32] = {0};
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &s, zero_t, f.seed, w, sizeof(w), &len), E_(SESSION));
        PASS();
    } _test_next:;
    return failures;
}

static int test_result_serialize(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: STORE_RESULT statuses, digest bytes and capacity") {
        struct fx f; ASSERT(fx_init(&f));
        uint8_t w[MAXF];
        struct vcs_zcode_dht_msg_store_result m, bad;
        struct vcs_zcode_dht_msg p;
        memset(&m, 0, sizeof(m));
        AUTH_SET(m);
        m.record_digest[31] = 1;                 /* only the last byte set */
        for (int st = 1; st <= 4; st++) {
            m.status = (enum vcs_zcode_dht_store_status)st;
            size_t len = 99;
            memset(w, 0xA5, sizeof(w));
            ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                          &m, f.transcript, f.seed, w,
                          VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES, &len), E_(OK));
            ASSERT_EQ(len, VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES);
            ASSERT_EQ(prs(&f, w, len, &p), E_(OK));
            ASSERT_EQ((int)p.store_result.status, st);
            ASSERT(memcmp(p.store_result.record_digest, m.record_digest, 32) == 0);
        }
        size_t len = 99;
        const int bad_status[] = {0, 5, 255};
        for (size_t i = 0; i < 3; i++) {
            bad = m; bad.status = (enum vcs_zcode_dht_store_status)bad_status[i];
            ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                          &bad, f.transcript, f.seed, w, sizeof(w), &len),
                      E_(WIRE_ORDER));
            ASSERT_EQ(len, 0);
        }
        bad = m; memset(bad.record_digest, 0, 32);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &bad, f.transcript, f.seed, w, sizeof(w), &len),
                  E_(WIRE_ORDER));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &m, f.transcript, f.seed, w,
                      VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES - 1, &len),
                  E_(WIRE_SIZE));
        bad = m; bad.query_id[0] = 0; memset(bad.query_id, 0, 16);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &bad, f.transcript, f.seed, w, sizeof(w), &len),
                  E_(QUERY_ID));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &m, f.transcript, f.seed, w, sizeof(w), NULL), E_(NULL));
        uint8_t zero_t[32] = {0};
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &m, zero_t, f.seed, w, sizeof(w), &len), E_(SESSION));
        PASS();
    } _test_next:;
    return failures;
}

static int test_serialize_error_propagation(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: every serializer returns the auth and signing error it hit") {
        struct fx f; ASSERT(fx_init(&f));
        static uint8_t w[MAXF];
        size_t len = 0;
        uint8_t zero_t[32] = {0}, other_seed[32];
        memset(other_seed, 0x23, 32);
        struct vcs_zcode_dht_msg_find_node fn; memset(&fn, 0, sizeof(fn));
        AUTH_SET(fn); memset(fn.target_node_id, 0x99, 32);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_node(
                      &fn, zero_t, f.seed, w, sizeof(w), &len), E_(SESSION));
        struct vcs_zcode_dht_msg_nodes nd; memset(&nd, 0, sizeof(nd));
        AUTH_SET(nd); nd.contact_count = 1; memset(nd.node_ids[0], 1, 32);
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_nodes(
                      &nd, zero_t, f.seed, w, sizeof(w), &len), E_(SESSION));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_nodes(
                      &nd, f.transcript, other_seed, w, sizeof(w), &len),
                  E_(IDENTITY));
        nd.session_generation = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_nodes(
                      &nd, f.transcript, f.seed, w, sizeof(w), &len), E_(ID_ZERO));
        struct vcs_zcode_dht_msg_find_record fr; memset(&fr, 0, sizeof(fr));
        AUTH_SET(fr); sel_default(&fr.selector); fr.page_offset = 8;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &fr, zero_t, f.seed, w, sizeof(w), &len), E_(SESSION));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &fr, f.transcript, other_seed, w, sizeof(w), &len),
                  E_(IDENTITY));
        fr.session_generation = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &fr, f.transcript, f.seed, w, sizeof(w), &len), E_(ID_ZERO));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      NULL, f.transcript, f.seed, w, sizeof(w), &len), E_(NULL));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_find_record(
                      &fr, f.transcript, f.seed, w, sizeof(w), NULL), E_(NULL));
        static struct vcs_zcode_dht_msg_records rc;
        ASSERT(recs_fill(&f, &rc, 1, 0, 0));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_records(
                      &rc, f.transcript, other_seed, w, sizeof(w), &len),
                  E_(IDENTITY));
        struct vcs_zcode_dht_msg_store_record sr; memset(&sr, 0, sizeof(sr));
        AUTH_SET(sr); ASSERT(rec_make(&f, &sr.record, 1));
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_record(
                      &sr, f.transcript, other_seed, w, sizeof(w), &len),
                  E_(IDENTITY));
        struct vcs_zcode_dht_msg_store_result rs; memset(&rs, 0, sizeof(rs));
        AUTH_SET(rs); rs.status = VCS_ZCODE_DHT_STORE_STORED; rs.record_digest[0] = 1;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &rs, f.transcript, other_seed, w, sizeof(w), &len),
                  E_(IDENTITY));
        rs.session_generation = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_serialize_store_result(
                      &rs, f.transcript, f.seed, w, sizeof(w), &len), E_(ID_ZERO));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- parser: framing and counts (all before the signature) ---- */

#define REC_GEN 44u
#define REC_PROV 140u
#define FR_COUNT 6

static uint8_t g_fw[FR_COUNT][MAXF];
static size_t g_fl[FR_COUNT];
static uint8_t g_tmp[MAXF];
static uint8_t g_big[1u << 18];
static struct vcs_zcode_dht_msg g_out, g_zero;

static bool build_all(const struct fx *f)
{
    g_fl[0] = b_fn(f, g_fw[0]);
    g_fl[1] = b_nodes(f, g_fw[1], 3);
    g_fl[2] = b_fr(f, g_fw[2]);
    g_fl[3] = b_recs(f, g_fw[3], 2, 0, 0);
    g_fl[4] = b_store(f, g_fw[4]);
    g_fl[5] = b_result(f, g_fw[5]);
    for (int i = 0; i < FR_COUNT; i++)
        if (!g_fl[i]) return false;
    memset(&g_zero, 0, sizeof(g_zero));
    return true;
}

static int test_parse_all_kinds_and_length(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: parse accepts each kind at its exact length only") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        const size_t fixed[FR_COUNT] = {
            VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES, 0,
            VCS_ZCODE_DHT_FIND_RECORD_WIRE_BYTES, 0,
            VCS_ZCODE_DHT_STORE_RECORD_WIRE_BYTES,
            VCS_ZCODE_DHT_STORE_RESULT_WIRE_BYTES };
        for (int a = 0; a < FR_COUNT; a++) {
            ASSERT_EQ(prs(&f, g_fw[a], g_fl[a], &g_out), E_(OK));
            ASSERT_EQ((int)g_out.kind, a + 1);
            memset(&g_out, 0xA5, sizeof(g_out));
            ASSERT_EQ(prs(&f, g_fw[a], g_fl[a] - 1, &g_out), E_(WIRE_SIZE));
            ASSERT(memcmp(&g_out, &g_zero, sizeof(g_out)) == 0);
            g_fw[a][g_fl[a]] = 0;
            ASSERT_EQ(prs(&f, g_fw[a], g_fl[a] + 1, &g_out), E_(WIRE_SIZE));
            for (int b = 0; b < FR_COUNT; b++) {
                if (b == a) continue;
                memcpy(g_tmp, g_fw[a], g_fl[a]);
                g_tmp[10] = (uint8_t)(b + 1);
                enum vcs_zcode_dht_error e = prs(&f, g_tmp, g_fl[a], &g_out);
                ASSERT(e != E_(OK));
                if (fixed[b] && fixed[b] != g_fl[a])
                    ASSERT_EQ(e, E_(WIRE_SIZE));
            }
        }
        ASSERT_EQ(g_out.kind, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_parse_header_and_nulls(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: parse magic, version, kind, minimum length and NULL guards") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        for (size_t i = 0; i < 8; i++) {
            memcpy(g_tmp, g_fw[0], g_fl[0]);
            g_tmp[i] ^= 1;
            ASSERT_EQ(prs(&f, g_tmp, g_fl[0], &g_out), E_(WIRE_MAGIC));
        }
        for (size_t i = 8; i < 10; i++) {
            memcpy(g_tmp, g_fw[0], g_fl[0]);
            g_tmp[i] ^= 1;
            ASSERT_EQ(prs(&f, g_tmp, g_fl[0], &g_out), E_(VERSION));
            g_tmp[0] ^= 1;
            ASSERT_EQ(prs(&f, g_tmp, g_fl[0], &g_out), E_(WIRE_MAGIC));
        }
        const uint8_t kinds[] = {0, 7, 255};
        for (size_t i = 0; i < 3; i++) {
            memcpy(g_tmp, g_fw[0], g_fl[0]);
            g_tmp[10] = kinds[i];
            ASSERT_EQ(prs(&f, g_tmp, g_fl[0], &g_out), E_(WIRE_KIND));
        }
        /* The shortest frame the header check lets through reaches the kind
         * check; one byte less is a size error. */
        const size_t minlen = PAY + SIG;
        memset(g_tmp, 0, sizeof(g_tmp));
        memcpy(g_tmp, g_fw[0], PAY);
        g_tmp[10] = 9;
        ASSERT_EQ(prs(&f, g_tmp, minlen, &g_out), E_(WIRE_KIND));
        ASSERT_EQ(prs(&f, g_tmp, minlen - 1, &g_out), E_(WIRE_SIZE));
        ASSERT_EQ(prs(&f, g_tmp, 0, &g_out), E_(WIRE_SIZE));
        ASSERT_EQ(vcs_zcode_dht_msg_parse(NULL, g_fl[0], &f.verify, &g_out), E_(NULL));
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], g_fl[0], NULL, &g_out), E_(NULL));
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], g_fl[0], &f.verify, NULL), E_(NULL));
        PASS();
    } _test_next:;
    return failures;
}

/* A frame of `total` zero bytes that keeps the first `keep` bytes of `base`
 * and carries `count` at `count_off`. */
static size_t shaped(const uint8_t *base, size_t keep, size_t total,
                     size_t count_off, uint8_t count)
{
    if (total > sizeof(g_big)) return 0;
    memset(g_big, 0, total);
    memcpy(g_big, base, keep);
    g_big[count_off] = count;
    return total;
}

static int test_parse_node_counts(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: NODES count and length are checked before the signature") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        struct { uint8_t count; unsigned len_for; enum vcs_zcode_dht_error want; }
        c[] = { {17, 17, E_(LIMIT)}, {255, 255, E_(LIMIT)}, {16, 16, E_(SIGNATURE)},
                {0, 0, E_(SIGNATURE)}, {1, 1, E_(SIGNATURE)}, {4, 3, E_(WIRE_SIZE)},
                {2, 3, E_(WIRE_SIZE)}, {0, 1, E_(WIRE_SIZE)} };
        for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
            size_t total = shaped(g_fw[1], PAY, PAY + 1u + c[i].len_for * 32u + SIG,
                                  PAY, c[i].count);
            ASSERT(total != 0);
            ASSERT_EQ(prs(&f, g_big, total, &g_out), c[i].want);
        }
        size_t t = shaped(g_fw[1], PAY, PAY + SIG, PAY, 0);
        ASSERT_EQ(prs(&f, g_big, t, &g_out), E_(WIRE_SIZE));
        PASS();
    } _test_next:;
    return failures;
}

static int test_parse_record_counts(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: RECORDS count and length are checked before the signature") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        struct { uint8_t count; unsigned len_for; enum vcs_zcode_dht_error want; }
        c[] = { {9, 9, E_(LIMIT)}, {255, 255, E_(LIMIT)}, {8, 8, E_(SIGNATURE)},
                {0, 0, E_(SIGNATURE)}, {1, 1, E_(SIGNATURE)}, {2, 1, E_(WIRE_SIZE)},
                {1, 2, E_(WIRE_SIZE)}, {8, 7, E_(WIRE_SIZE)} };
        for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
            size_t total = shaped(g_fw[3], S_COUNT,
                                  S_COUNT + 1u + (size_t)c[i].len_for * RW + SIG,
                                  S_COUNT, c[i].count);
            ASSERT(total != 0);
            ASSERT_EQ(prs(&f, g_big, total, &g_out), c[i].want);
        }
        size_t t = shaped(g_fw[3], S_COUNT, S_COUNT + SIG, S_COUNT, 0);
        ASSERT_EQ(prs(&f, g_big, t, &g_out), E_(WIRE_SIZE));
        PASS();
    } _test_next:;
    return failures;
}

/* ---- parser: authentication fields and the Noise/delegation context ---- */

static bool refuse(void *ctx, const struct vcs_zcode_dht_delegation *d)
{
    (void)d;
    (*(int *)ctx)++;
    return false;
}

static int test_parse_auth_fields(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: parse refuses zero ids, a foreign sender and a bad delegation") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        const size_t n = g_fl[0];
        memcpy(g_tmp, g_fw[0], n); memset(g_tmp + O_GEN, 0, 8);
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(ID_ZERO));
        memcpy(g_tmp, g_fw[0], n); memset(g_tmp + O_GEN, 0, 8); g_tmp[O_GEN + 7] = 1;
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(SIGNATURE));
        memcpy(g_tmp, g_fw[0], n); memset(g_tmp + O_SENDER, 0, 32);
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(ID_ZERO));
        g_tmp[O_SENDER + 31] = 1;
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(IDENTITY));
        memcpy(g_tmp, g_fw[0], n); g_tmp[O_SENDER + 31] ^= 1;
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(IDENTITY));
        memcpy(g_tmp, g_fw[0], n); g_tmp[O_SENDER] ^= 1;
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(IDENTITY));
        memcpy(g_tmp, g_fw[0], n); memset(g_tmp + O_QUERY, 0, 16);
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(QUERY_ID));
        g_tmp[O_QUERY + 15] = 1;
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(SIGNATURE));
        memcpy(g_tmp, g_fw[0], n);
        memset(g_tmp + O_DELEG, 0, VCS_ZCODE_DHT_DELEGATION_WIRE_BYTES);
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(DELEGATION));
        memset(&g_out, 0xA5, sizeof(g_out));
        ASSERT_EQ(prs(&f, g_tmp, n, &g_out), E_(DELEGATION));
        ASSERT(memcmp(&g_out, &g_zero, sizeof(g_out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_parse_session_context(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: parse session, transcript, network, time and trust roles") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        const size_t n = g_fl[0];
        struct vcs_zcode_dht_msg_verify_context v = f.verify;
        v.noise_established = false;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(SESSION));
        v.remote_noise_static[0] ^= 1;               /* session check precedes it */
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(SESSION));
        v = f.verify; memset(v.noise_transcript_hash, 0, 32);
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(SESSION));
        v.noise_transcript_hash[31] = 1;             /* set, so the signature decides */
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(SIGNATURE));
        v = f.verify; v.network_genesis[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(DELEGATION));
        v = f.verify; v.now_unix = 999;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(DELEGATION));
        v = f.verify; v.now_unix = 5000;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(DELEGATION));
        v = f.verify; v.remote_noise_static[31] ^= 1;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(DELEGATION));
        int refused = 0;
        v = f.verify; v.transport_verify = refuse; v.transport_ctx = &refused;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(DELEGATION));
        ASSERT_EQ(refused, 1);
        v = f.verify; v.transport_verify = NULL; f.chain_calls = 0;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(OK));
        ASSERT_EQ(f.chain_calls, 0);
        v = f.verify; v.session_generation = 8;
        ASSERT_EQ(vcs_zcode_dht_msg_parse(g_fw[0], n, &v, &g_out), E_(SESSION));
        ASSERT(memcmp(&g_out, &g_zero, sizeof(g_out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ---- parser: payload checks behind a valid signature ---- */

static enum vcs_zcode_dht_error forge(const struct fx *f, const uint8_t *base,
                                      size_t len, size_t off, const void *bytes,
                                      size_t n)
{
    memcpy(g_tmp, base, len);
    memcpy(g_tmp + off, bytes, n);
    resign(f, g_tmp, len);
    memset(&g_out, 0xA5, sizeof(g_out));
    return prs(f, g_tmp, len, &g_out);
}

static int test_forged_find_node_and_nodes(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: re-signed FIND_NODE and NODES payload refusals") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        uint8_t z[96] = {0};
        ASSERT_EQ(forge(&f, g_fw[0], g_fl[0], PAY, z, 32), E_(ID_ZERO));
        ASSERT(memcmp(&g_out, &g_zero, sizeof(g_out)) == 0);
        z[31] = 1;
        ASSERT_EQ(forge(&f, g_fw[0], g_fl[0], PAY, z, 32), E_(OK));
        ASSERT(memcmp(g_out.find_node.target_node_id, z, 32) == 0);
        memset(z, 0, 32);
        for (size_t i = 0; i < 3; i++)
            ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 1 + 32 * i, z, 32),
                      E_(ID_ZERO));
        uint8_t dup[32]; memset(dup, 1, 32);              /* equals ids[0] */
        ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 33, dup, 32), E_(WIRE_ORDER));
        uint8_t low[32] = {0}; low[31] = 1;               /* below ids[0] */
        ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 33, low, 32), E_(WIRE_ORDER));
        memset(z, 0, sizeof(z));
        z[31] = 1; z[63] = 2; z[95] = 3;                  /* differ in last byte only */
        ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 1, z, 96), E_(OK));
        ASSERT_EQ(g_out.nodes.contact_count, 3);
        ASSERT_EQ(g_out.nodes.node_ids[2][31], 3);
        z[63] = 1;
        ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 1, z, 96), E_(WIRE_ORDER));
        z[63] = 2; z[95] = 2;
        ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 1, z, 96), E_(WIRE_ORDER));
        z[95] = 3; z[31] = 3; z[63] = 2;
        ASSERT_EQ(forge(&f, g_fw[1], g_fl[1], PAY + 1, z, 96), E_(WIRE_ORDER));
        PASS();
    } _test_next:;
    return failures;
}

static int test_forged_find_record_selector(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: re-signed FIND_RECORD selector and page refusals") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        const size_t n = g_fl[2];
        const uint8_t kinds[] = {0, 6, 255}, lens[] = {0, 32, 255};
        for (size_t i = 0; i < 3; i++) {
            ASSERT_EQ(forge(&f, g_fw[2], n, S_KIND, &kinds[i], 1), E_(WIRE_ORDER));
            ASSERT_EQ(forge(&f, g_fw[2], n, S_LEN, &lens[i], 1), E_(WIRE_ORDER));
        }
        const uint8_t good_kinds[] = {1, 4};
        for (size_t i = 0; i < 2; i++) {
            ASSERT_EQ(forge(&f, g_fw[2], n, S_KIND, &good_kinds[i], 1), E_(OK));
            ASSERT_EQ((int)g_out.find_record.selector.kind, good_kinds[i]);
        }
        uint8_t nm[33]; memset(nm, 0, sizeof(nm));
        nm[0] = 31; memset(nm + 1, 'a', 31);               /* length 31, 31 chars */
        ASSERT_EQ(forge(&f, g_fw[2], n, S_LEN, nm, 33), E_(OK));
        ASSERT_EQ(strlen(g_out.find_record.selector.namespace_name), 31);
        memset(nm, 0, sizeof(nm)); nm[0] = 2; nm[1] = 'a'; nm[2] = 'b'; nm[3] = 'c';
        ASSERT_EQ(forge(&f, g_fw[2], n, S_LEN, nm, 33), E_(WIRE_ORDER)); /* pad at [len] */
        memset(nm, 0, sizeof(nm)); nm[0] = 2; nm[1] = 'a'; nm[2] = 'b'; nm[32] = 1;
        ASSERT_EQ(forge(&f, g_fw[2], n, S_LEN, nm, 33), E_(WIRE_ORDER)); /* pad at [31] */
        memset(nm, 0, sizeof(nm)); nm[0] = 2; nm[1] = 'A'; nm[2] = 'b';
        ASSERT_EQ(forge(&f, g_fw[2], n, S_LEN, nm, 33), E_(WIRE_ORDER));
        nm[1] = 'a'; nm[2] = 'B';
        ASSERT_EQ(forge(&f, g_fw[2], n, S_LEN, nm, 33), E_(WIRE_ORDER));
        uint8_t root[32] = {0};
        ASSERT_EQ(forge(&f, g_fw[2], n, S_ROOT, root, 32), E_(WIRE_ORDER));
        root[31] = 1;
        ASSERT_EQ(forge(&f, g_fw[2], n, S_ROOT, root, 32), E_(OK));
        const uint8_t bad_pages[] = {1, 7, 64, 255}, ok_pages[] = {0, 56};
        for (size_t i = 0; i < 4; i++)
            ASSERT_EQ(forge(&f, g_fw[2], n, S_PAGE, &bad_pages[i], 1),
                      E_(WIRE_ORDER));
        for (size_t i = 0; i < 2; i++) {
            ASSERT_EQ(forge(&f, g_fw[2], n, S_PAGE, &ok_pages[i], 1), E_(OK));
            ASSERT_EQ(g_out.find_record.page_offset, ok_pages[i]);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_forged_records_pages(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: re-signed RECORDS offsets, count pairing and ordering") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        static uint8_t r8[MAXF];
        size_t n8 = b_recs(&f, r8, 8, 0, 0);
        ASSERT(n8 != 0);
        const uint8_t eight = 8, sixteen = 16, nine = 9, c56 = 56, c64 = 64;
        const uint8_t one = 1, big = 255, zero = 0;
        ASSERT_EQ(forge(&f, g_fw[3], g_fl[3], S_NEXT, &eight, 1), E_(WIRE_ORDER));
        ASSERT_EQ(forge(&f, r8, n8, S_NEXT, &eight, 1), E_(OK));
        ASSERT_EQ(g_out.records.next_offset, 8);
        ASSERT_EQ(g_out.records.record_count, 8);
        ASSERT_EQ(forge(&f, r8, n8, S_NEXT, &sixteen, 1), E_(WIRE_ORDER));
        ASSERT_EQ(forge(&f, r8, n8, S_NEXT, &nine, 1), E_(WIRE_ORDER));
        ASSERT_EQ(forge(&f, r8, n8, S_PAGE, &c64, 1), E_(WIRE_ORDER));
        ASSERT_EQ(forge(&f, r8, n8, S_PAGE, &one, 1), E_(WIRE_ORDER));
        ASSERT_EQ(forge(&f, r8, n8, S_PAGE, &big, 1), E_(WIRE_ORDER));
        ASSERT_EQ(forge(&f, r8, n8, S_PAGE, &c56, 1), E_(OK));
        memcpy(g_big, r8, n8);                     /* page 56, next 64 */
        g_big[S_PAGE] = 56; g_big[S_NEXT] = 64;
        ASSERT_EQ(forge(&f, g_big, n8, S_NEXT, &c64, 1), E_(WIRE_ORDER));
        (void)zero;
        /* ordering of the records on the wire */
        memcpy(g_big, r8, n8);
        memcpy(g_big + R_FIRST, r8 + R_FIRST + RW, RW);
        memcpy(g_big + R_FIRST + RW, r8 + R_FIRST, RW);
        ASSERT_EQ(forge(&f, g_big, n8, R_FIRST, g_big + R_FIRST, 2 * RW),
                  E_(WIRE_ORDER));
        memcpy(g_big, r8, n8);
        ASSERT_EQ(forge(&f, g_big, n8, R_FIRST + RW, r8 + R_FIRST, RW),
                  E_(WIRE_ORDER));
        /* selector must match every record, down to the last root byte */
        uint8_t root[32]; memset(root, 0x61, 32); root[31] ^= 1;
        ASSERT_EQ(forge(&f, r8, n8, S_ROOT, root, 32), E_(WIRE_ORDER));
        const uint8_t ack = 4;
        ASSERT_EQ(forge(&f, r8, n8, S_KIND, &ack, 1), E_(WIRE_ORDER));
        uint8_t nm[33]; memset(nm, 0, sizeof(nm)); nm[0] = 2; nm[1] = 'a'; nm[2] = 'b';
        ASSERT_EQ(forge(&f, r8, n8, S_LEN, nm, 33), E_(WIRE_ORDER));
        PASS();
    } _test_next:;
    return failures;
}

static enum vcs_zcode_dht_error parse_at(const struct fx *f, const uint8_t *w,
                                         size_t n, uint64_t now)
{
    struct vcs_zcode_dht_msg_verify_context v = f->verify;
    v.now_unix = now;
    memset(&g_out, 0xA5, sizeof(g_out));
    return vcs_zcode_dht_msg_parse(w, n, &v, &g_out);
}

static int test_forged_record_errors(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: embedded record failures map to the frame error") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        static uint8_t r8[MAXF];
        size_t n8 = b_recs(&f, r8, 8, 0, 0);
        ASSERT(n8 != 0);
        const size_t rec[2] = {R_FIRST, g_fl[4] - SIG - RW};
        const uint8_t *fr[2] = {r8, g_fw[4]};
        const size_t fn[2] = {n8, g_fl[4]};
        for (int k = 0; k < 2; k++) {
            ASSERT_EQ(parse_at(&f, fr[k], fn[k], 1900), E_(EXPIRED));
            ASSERT_EQ(parse_at(&f, fr[k], fn[k], 1100), E_(DELEGATION));
            ASSERT_EQ(parse_at(&f, fr[k], fn[k], 1500), E_(OK));
            uint8_t flip = (uint8_t)(fr[k][rec[k] + RW - 1] ^ 1);
            ASSERT_EQ(forge(&f, fr[k], fn[k], rec[k] + RW - 1, &flip, 1),
                      E_(SIGNATURE));
            flip = (uint8_t)(fr[k][rec[k]] ^ 1);
            ASSERT_EQ(forge(&f, fr[k], fn[k], rec[k], &flip, 1), E_(WIRE_ORDER));
            uint8_t gen[32]; memset(gen, 2, 32);
            ASSERT_EQ(forge(&f, fr[k], fn[k], rec[k] + REC_GEN, gen, 32),
                      E_(NETWORK));
            uint8_t prov[32]; memcpy(prov, f.node_id, 32); prov[31] ^= 1;
            ASSERT_EQ(forge(&f, fr[k], fn[k], rec[k] + REC_PROV, prov, 32),
                      E_(IDENTITY));
        }
        /* a record that fails late leaves nothing behind in the output */
        uint8_t flip = (uint8_t)(r8[R_FIRST + 7 * RW + RW - 1] ^ 1);
        ASSERT_EQ(forge(&f, r8, n8, R_FIRST + 7 * RW + RW - 1, &flip, 1),
                  E_(SIGNATURE));
        ASSERT(memcmp(&g_out, &g_zero, sizeof(g_out)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

#define REC_NOT_BEFORE 180u
#define REC_DELEG 196u

static int test_forged_record_delegation_errors(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: every embedded delegation failure is a delegation error") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        const size_t rec = g_fl[4] - SIG - RW;
        /* the record starts before the delegation window opens */
        const uint8_t early[8] = {0x84, 0x03}; /* 900, little endian */
        ASSERT_EQ(forge(&f, g_fw[4], g_fl[4], rec + REC_NOT_BEFORE, early, 8),
                  E_(DELEGATION));
        /* the embedded delegation no longer decodes */
        uint8_t bad = (uint8_t)(g_fw[4][rec + REC_DELEG] ^ 0xFF);
        ASSERT_EQ(forge(&f, g_fw[4], g_fl[4], rec + REC_DELEG, &bad, 1),
                  E_(DELEGATION));
        PASS();
    } _test_next:;
    return failures;
}

static int test_forged_store_result(void)
{
    int failures = 0;
    TEST("zcode dht msgs forged: re-signed STORE_RESULT status and digest refusals") {
        struct fx f; ASSERT(fx_init(&f)); ASSERT(build_all(&f));
        const size_t n = g_fl[5];
        const uint8_t bad[] = {0, 5, 255}, good[] = {1, 4};
        for (size_t i = 0; i < 3; i++)
            ASSERT_EQ(forge(&f, g_fw[5], n, PAY, &bad[i], 1), E_(WIRE_ORDER));
        for (size_t i = 0; i < 2; i++) {
            ASSERT_EQ(forge(&f, g_fw[5], n, PAY, &good[i], 1), E_(OK));
            ASSERT_EQ((int)g_out.store_result.status, good[i]);
        }
        uint8_t d[32] = {0};
        ASSERT_EQ(forge(&f, g_fw[5], n, PAY + 1, d, 32), E_(WIRE_ORDER));
        d[31] = 1;
        ASSERT_EQ(forge(&f, g_fw[5], n, PAY + 1, d, 32), E_(OK));
        ASSERT(memcmp(g_out.store_result.record_digest, d, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int zcode_dht_msgs_forged_tests(void);

int zcode_dht_msgs_forged_tests(void)
{
    int failures = 0;
    failures += test_fn_roundtrip_and_auth();
    failures += test_fn_transcript_target_null();
    failures += test_nodes_serialize_bounds();
    failures += test_selector_name_table();
    failures += test_selector_kind_root_page();
    failures += test_records_roundtrip();
    failures += test_records_refusals();
    failures += test_store_serialize();
    failures += test_result_serialize();
    failures += test_serialize_error_propagation();
    failures += test_parse_all_kinds_and_length();
    failures += test_parse_header_and_nulls();
    failures += test_parse_node_counts();
    failures += test_parse_record_counts();
    failures += test_parse_auth_fields();
    failures += test_parse_session_context();
    failures += test_forged_find_node_and_nodes();
    failures += test_forged_find_record_selector();
    failures += test_forged_records_pages();
    failures += test_forged_record_errors();
    failures += test_forged_record_delegation_errors();
    failures += test_forged_store_result();
    return failures;
}
