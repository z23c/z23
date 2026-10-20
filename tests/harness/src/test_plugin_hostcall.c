/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the plugin host-call protocol library: the frame codec is
 * total and byte-exact, the method table matches the host ABI names, the
 * dispatcher refuses ungranted, planned, unknown and malformed calls with
 * distinct codes before any handler runs, and a deterministic mutation loop
 * over truncated and bit-flipped frames never crashes or mis-decodes. The
 * handlers are fakes; the library touches no node. */

#include "test/test_core.h"

#include "plugin/plugin_hostcall.h"
#include "plugin/plugin_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PHT_ALL (PLUGIN_HOSTCALL_CAP_CHAIN_READ | PLUGIN_HOSTCALL_CAP_STATE | \
                 PLUGIN_HOSTCALL_CAP_EVENTS | PLUGIN_HOSTCALL_CAP_WALLET)

struct pht_fake {
    unsigned calls[PLUGIN_HOSTCALL_METHOD_COUNT + 1];
    int fail;       /* handler returns nonzero */
    size_t overrun; /* handler claims this many bytes beyond out_cap */
};

/* Echoes the method id followed by the request payload. */
static int pht_echo(struct pht_fake *f, unsigned method, const uint8_t *in,
                    size_t in_len, uint8_t *out, size_t cap, size_t *out_len)
{
    f->calls[method]++;
    if (f->fail)
        return 1;
    if (f->overrun) {
        *out_len = cap + f->overrun;
        return 0;
    }
    if (in_len + 1 > cap)
        return 2;
    out[0] = (uint8_t)method;
    if (in_len > 0)
        memcpy(out + 1, in, in_len);
    *out_len = in_len + 1;
    return 0;
}

#define PHT_HANDLER(NAME, M) \
    static int NAME(void *c, const uint8_t *in, size_t n, uint8_t *o, size_t cap, size_t *ol) \
    { return pht_echo(c, M, in, n, o, cap, ol); }
PHT_HANDLER(pht_h1, 1)
PHT_HANDLER(pht_h2, 2)
PHT_HANDLER(pht_h3, 3)
PHT_HANDLER(pht_h4, 4)
PHT_HANDLER(pht_h5, 5)
PHT_HANDLER(pht_h6, 6)
PHT_HANDLER(pht_h7, 7)

static void pht_handlers(struct plugin_hostcall_handlers *h, struct pht_fake *f)
{
    memset(h, 0, sizeof *h);
    memset(f, 0, sizeof *f);
    h->context = f;
    h->method[0] = pht_h1;
    h->method[1] = pht_h2;
    h->method[2] = pht_h3;
    h->method[3] = pht_h4;
    h->method[4] = pht_h5;
    h->method[5] = pht_h6;
    h->method[6] = pht_h7;
}

/* Build a request, push it through encode, decode and dispatch, and decode
 * the reply. Returns the dispatch status. */
static enum plugin_hostcall_status pht_roundtrip(
    uint16_t method, const uint8_t *payload, size_t n, uint32_t granted,
    const struct plugin_hostcall_handlers *h, struct plugin_hostcall_frame *rep,
    uint8_t *replybuf, size_t replycap)
{
    uint8_t wire[PLUGIN_HOSTCALL_MAX_FRAME];
    size_t w = 0, used = 0, rl = 0, rc = 0;
    struct plugin_hostcall_frame req = { PLUGIN_HOSTCALL_KIND_REQUEST, 0xA1B2C3D4u, method, payload, n };
    struct plugin_hostcall_frame dec;
    if (plugin_hostcall_encode(&req, wire, sizeof wire, &w) != PLUGIN_HOSTCALL_OK)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    if (plugin_hostcall_decode(wire, w, &dec, &used) != PLUGIN_HOSTCALL_OK || used != w)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    enum plugin_hostcall_status s =
        plugin_hostcall_dispatch(&dec, granted, h, replybuf, replycap, &rl);
    if (rl > 0 && plugin_hostcall_decode(replybuf, rl, rep, &rc) != PLUGIN_HOSTCALL_OK)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    return s;
}

static int pht_case_table(void)
{
    int failures = 0;
    TEST_CASE("method table names, capabilities, bounds") {
        static const char *const names[] = {
            "chain.tip", "chain.header_by_height", "state.get", "state.put",
            "event.append", "log.write", "wallet.request" };
        for (size_t i = 0; i < PLUGIN_HOSTCALL_METHOD_COUNT; i++) {
            const struct plugin_hostcall_method_info *m = plugin_hostcall_method_at(i);
            ASSERT(m != NULL);
            ASSERT_EQ(m->id, i + 1);
            ASSERT_STR_EQ(m->name, names[i]);
            ASSERT(m->min_payload <= m->max_payload);
            ASSERT(m->max_payload <= PLUGIN_HOSTCALL_MAX_PAYLOAD);
            ASSERT(plugin_hostcall_method_by_name(names[i]) == m);
            ASSERT(plugin_hostcall_method_by_id(m->id) == m);
        }
        ASSERT(plugin_hostcall_method_at(PLUGIN_HOSTCALL_METHOD_COUNT) == NULL);
        ASSERT(plugin_hostcall_method_by_id(0) == NULL);
        ASSERT(plugin_hostcall_method_by_id(8) == NULL);
        ASSERT(plugin_hostcall_method_by_name("nope") == NULL);
        ASSERT(plugin_hostcall_method_by_name(NULL) == NULL);
        ASSERT(plugin_hostcall_method_by_id(7)->planned);
        ASSERT(!plugin_hostcall_method_by_id(6)->planned);
        ASSERT_EQ(plugin_hostcall_method_by_id(6)->capability, PLUGIN_HOSTCALL_CAP_NONE);
        ASSERT_EQ(plugin_hostcall_cap_from_name("chain.read"), PLUGIN_HOSTCALL_CAP_CHAIN_READ);
        ASSERT_EQ(plugin_hostcall_cap_from_name("fs.read"), 0u);
        ASSERT_EQ(plugin_hostcall_cap_from_name(NULL), 0u);
        /* Every host-call capability the manifest vocabulary names is in the mask. */
        ASSERT_EQ(plugin_hostcall_grants_from_manifest(~0u),
                  (uint32_t)(PLUGIN_HOSTCALL_CAP_CHAIN_READ | PLUGIN_HOSTCALL_CAP_STATE |
                             PLUGIN_HOSTCALL_CAP_EVENTS | PLUGIN_HOSTCALL_CAP_WALLET));
        ASSERT_EQ(plugin_hostcall_grants_from_manifest(1u << 7), PLUGIN_HOSTCALL_CAP_CHAIN_READ);
        ASSERT_EQ(plugin_hostcall_grants_from_manifest(0x7fu), 0u); /* the old vocabulary */
        ASSERT_STR_EQ(plugin_hostcall_status_code(PLUGIN_HOSTCALL_DENIED), "PLUGIN_HOSTCALL_DENIED");
        ASSERT_STR_EQ(plugin_hostcall_status_code((enum plugin_hostcall_status)999), "PLUGIN_HOSTCALL_UNKNOWN");
    } TEST_END
    return failures;
}

static int pht_case_status_text(void)
{
    int failures = 0;
    TEST_CASE("every status has a distinct code and a non-empty next action") {
        for (int a = 0; a <= PLUGIN_HOSTCALL_ERR_BUFFER; a++) {
            const char *code = plugin_hostcall_status_code((enum plugin_hostcall_status)a);
            const char *act = plugin_hostcall_status_next_action((enum plugin_hostcall_status)a);
            ASSERT(code != NULL && strncmp(code, "PLUGIN_HOSTCALL_", 16) == 0);
            ASSERT(act != NULL && act[0] != '\0');
            ASSERT(strcmp(code, "PLUGIN_HOSTCALL_UNKNOWN") != 0);
            for (int b = a + 1; b <= PLUGIN_HOSTCALL_ERR_BUFFER; b++)
                ASSERT(strcmp(code, plugin_hostcall_status_code((enum plugin_hostcall_status)b)) != 0);
        }
        ASSERT(plugin_hostcall_status_next_action((enum plugin_hostcall_status)999)[0] != '\0');
    } TEST_END
    return failures;
}

static int pht_case_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("every method round-trips through encode, decode, dispatch") {
        struct plugin_hostcall_handlers h;
        struct pht_fake f;
        pht_handlers(&h, &f);
        static const uint8_t pay[7][4] = {
            {0}, {0, 0, 1, 2}, {1, 'k'}, {1, 'k', 'v'}, {1, 't', 'e'}, {1, 'x'}, {0} };
        static const size_t len[7] = { 0, 4, 2, 3, 3, 2, 0 };
        for (uint16_t id = 1; id <= 6; id++) {
            uint8_t rb[256];
            struct plugin_hostcall_frame rep;
            enum plugin_hostcall_status s =
                pht_roundtrip(id, pay[id - 1], len[id - 1], PHT_ALL, &h, &rep, rb, sizeof rb);
            ASSERT_EQ(s, PLUGIN_HOSTCALL_OK);
            ASSERT_EQ(rep.kind, PLUGIN_HOSTCALL_KIND_REPLY);
            ASSERT_EQ(rep.id, 0xA1B2C3D4u);
            ASSERT_EQ(rep.code, PLUGIN_HOSTCALL_OK);
            ASSERT_EQ(rep.payload_len, len[id - 1] + 1);
            ASSERT_EQ(rep.payload[0], id);
            ASSERT(len[id - 1] == 0 || memcmp(rep.payload + 1, pay[id - 1], len[id - 1]) == 0);
            ASSERT_EQ(f.calls[id], 1u);
        }
    } TEST_END
    return failures;
}

static int pht_case_limits(void)
{
    int failures = 0;
    TEST_CASE("max payload frame round-trips and one more byte is refused") {
        static uint8_t big[PLUGIN_HOSTCALL_MAX_PAYLOAD + 1];
        static uint8_t wire[PLUGIN_HOSTCALL_MAX_FRAME + 8];
        memset(big, 0x5A, sizeof big);
        struct plugin_hostcall_frame fr = { PLUGIN_HOSTCALL_KIND_REPLY, 7, 0, big, PLUGIN_HOSTCALL_MAX_PAYLOAD };
        struct plugin_hostcall_frame d;
        size_t w = 0, u = 0;
        ASSERT_EQ(plugin_hostcall_encode(&fr, wire, sizeof wire, &w), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(w, PLUGIN_HOSTCALL_MAX_FRAME);
        ASSERT_EQ(plugin_hostcall_decode(wire, w, &d, &u), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(d.payload_len, PLUGIN_HOSTCALL_MAX_PAYLOAD);
        fr.payload_len = PLUGIN_HOSTCALL_MAX_PAYLOAD + 1;
        ASSERT_EQ(plugin_hostcall_encode(&fr, wire, sizeof wire, &w), PLUGIN_HOSTCALL_ERR_OVERSIZE);
        ASSERT_EQ(w, 0u);
    } TEST_END
    return failures;
}

static int pht_case_decode_refusals(void)
{
    int failures = 0;
    TEST_CASE("decode refuses each malformed frame with its own code") {
        struct plugin_hostcall_frame d;
        size_t u = 99;
        uint8_t good[16] = { 0, 0, 0, 8, 1, 1, 0, 0, 0, 1, 0, 1 };
        ASSERT_EQ(plugin_hostcall_decode(good, 12, &d, &u), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(u, 12u);
        ASSERT_EQ(plugin_hostcall_decode(NULL, 12, &d, &u), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_decode(good, 12, NULL, &u), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_decode(good, 12, &d, NULL), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_decode(good, 0, &d, &u), PLUGIN_HOSTCALL_ERR_TRUNCATED);
        ASSERT_EQ(plugin_hostcall_decode(good, 3, &d, &u), PLUGIN_HOSTCALL_ERR_TRUNCATED);
        ASSERT_EQ(u, 0u);
        ASSERT_EQ(plugin_hostcall_decode(good, 11, &d, &u), PLUGIN_HOSTCALL_ERR_TRUNCATED);
        uint8_t m[16];
        memcpy(m, good, sizeof m);
        m[3] = 7; /* below the fixed fields */
        ASSERT_EQ(plugin_hostcall_decode(m, 12, &d, &u), PLUGIN_HOSTCALL_ERR_UNDERSIZE);
        memcpy(m, good, sizeof m);
        m[0] = 0xFF; /* huge declared length, refused before waiting for bytes */
        ASSERT_EQ(plugin_hostcall_decode(m, 4, &d, &u), PLUGIN_HOSTCALL_ERR_OVERSIZE);
        memcpy(m, good, sizeof m);
        m[1] = 1; m[2] = 0; m[3] = 9; /* payload one byte over the maximum */
        ASSERT_EQ(plugin_hostcall_decode(m, 12, &d, &u), PLUGIN_HOSTCALL_ERR_OVERSIZE);
        memcpy(m, good, sizeof m);
        m[4] = 2;
        ASSERT_EQ(plugin_hostcall_decode(m, 12, &d, &u), PLUGIN_HOSTCALL_ERR_VERSION);
        m[4] = 0;
        ASSERT_EQ(plugin_hostcall_decode(m, 12, &d, &u), PLUGIN_HOSTCALL_ERR_VERSION);
        memcpy(m, good, sizeof m);
        m[5] = 0;
        ASSERT_EQ(plugin_hostcall_decode(m, 12, &d, &u), PLUGIN_HOSTCALL_ERR_KIND);
        m[5] = 3;
        ASSERT_EQ(plugin_hostcall_decode(m, 12, &d, &u), PLUGIN_HOSTCALL_ERR_KIND);
        /* trailing bytes belong to the next frame */
        memcpy(m, good, sizeof m);
        ASSERT_EQ(plugin_hostcall_decode(m, 16, &d, &u), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(u, 12u);
    } TEST_END
    return failures;
}

static int pht_case_encode_refusals(void)
{
    int failures = 0;
    TEST_CASE("encode refuses bad input") {
        uint8_t out[32];
        size_t w = 5;
        uint8_t p[2] = { 1, 2 };
        struct plugin_hostcall_frame fr = { PLUGIN_HOSTCALL_KIND_REQUEST, 1, 1, p, 2 };
        ASSERT_EQ(plugin_hostcall_encode(NULL, out, sizeof out, &w), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_encode(&fr, NULL, sizeof out, &w), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_encode(&fr, out, sizeof out, NULL), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_encode(&fr, out, 13, &w), PLUGIN_HOSTCALL_ERR_BUFFER);
        ASSERT_EQ(w, 0u);
        fr.kind = 9;
        ASSERT_EQ(plugin_hostcall_encode(&fr, out, sizeof out, &w), PLUGIN_HOSTCALL_ERR_KIND);
        fr.kind = PLUGIN_HOSTCALL_KIND_REQUEST;
        fr.payload = NULL;
        ASSERT_EQ(plugin_hostcall_encode(&fr, out, sizeof out, &w), PLUGIN_HOSTCALL_ERR_ARGUMENT);
    } TEST_END
    return failures;
}

static int pht_case_dispatch_refusals(void)
{
    int failures = 0;
    TEST_CASE("dispatch refuses before any handler runs") {
        struct plugin_hostcall_handlers h;
        struct pht_fake f;
        pht_handlers(&h, &f);
        uint8_t rb[64];
        struct plugin_hostcall_frame rep;
        static const uint8_t kv[3] = { 1, 'k', 'v' };
        /* Capability denial: the red/green witness. Each gated method with an
         * empty grant, then with only the wrong grant. */
        ASSERT_EQ(pht_roundtrip(1, NULL, 0, 0, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(rep.code, PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(rep.id, 0xA1B2C3D4u);
        ASSERT_EQ(rep.payload_len, 0u);
        ASSERT_EQ(pht_roundtrip(3, kv, 2, PLUGIN_HOSTCALL_CAP_CHAIN_READ, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(pht_roundtrip(4, kv, 3, PLUGIN_HOSTCALL_CAP_EVENTS, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(pht_roundtrip(5, kv, 3, PLUGIN_HOSTCALL_CAP_STATE, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(f.calls[1] + f.calls[3] + f.calls[4] + f.calls[5], 0u);
        /* log.write needs no grant */
        ASSERT_EQ(pht_roundtrip(6, kv, 2, 0, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_OK);
        /* denial wins over a bad payload size */
        ASSERT_EQ(pht_roundtrip(2, kv, 1, 0, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_DENIED);
        /* planned: refused even with every grant */
        ASSERT_EQ(pht_roundtrip(7, NULL, 0, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_PLANNED);
        ASSERT_EQ(f.calls[7], 0u);
        /* unknown method */
        ASSERT_EQ(pht_roundtrip(0, NULL, 0, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_METHOD);
        ASSERT_EQ(pht_roundtrip(8, NULL, 0, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_METHOD);
        ASSERT_EQ(pht_roundtrip(0xFFFF, NULL, 0, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_METHOD);
        /* payload bounds */
        ASSERT_EQ(pht_roundtrip(1, kv, 1, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_PAYLOAD);
        ASSERT_EQ(pht_roundtrip(2, kv, 3, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_PAYLOAD);
        ASSERT_EQ(pht_roundtrip(3, kv, 1, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_PAYLOAD);
        ASSERT_EQ(pht_roundtrip(6, kv, 1, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_PAYLOAD);
        ASSERT_EQ(f.calls[1] + f.calls[2] + f.calls[3], 0u);
        /* missing handler */
        h.method[2] = NULL;
        ASSERT_EQ(pht_roundtrip(3, kv, 2, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_UNAVAILABLE);
        h.method[2] = pht_h3;
        /* handler failure and contract breach */
        f.fail = 1;
        ASSERT_EQ(pht_roundtrip(3, kv, 2, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_HANDLER);
        f.fail = 0;
        f.overrun = 1;
        ASSERT_EQ(pht_roundtrip(3, kv, 2, PHT_ALL, &h, &rep, rb, sizeof rb), PLUGIN_HOSTCALL_ERR_HANDLER);
        f.overrun = 0;
        /* reply buffer too small: header only fits the refusal reply */
        ASSERT_EQ(pht_roundtrip(3, kv, 2, PHT_ALL, &h, &rep, rb, 8), PLUGIN_HOSTCALL_ERR_BUFFER);
    } TEST_END
    return failures;
}

static int pht_case_dispatch_shape(void)
{
    int failures = 0;
    TEST_CASE("dispatch refuses a bad call shape") {
        struct plugin_hostcall_handlers h;
        struct pht_fake f;
        pht_handlers(&h, &f);
        uint8_t rb[64];
        size_t rl = 1;
        struct plugin_hostcall_frame rq = { PLUGIN_HOSTCALL_KIND_REPLY, 1, 1, NULL, 0 };
        ASSERT_EQ(plugin_hostcall_dispatch(&rq, PHT_ALL, &h, rb, sizeof rb, &rl), PLUGIN_HOSTCALL_ERR_KIND);
        ASSERT_EQ(rl, 0u);
        rq.kind = PLUGIN_HOSTCALL_KIND_REQUEST;
        ASSERT_EQ(plugin_hostcall_dispatch(NULL, PHT_ALL, &h, rb, sizeof rb, &rl), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_dispatch(&rq, PHT_ALL, NULL, rb, sizeof rb, &rl), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_dispatch(&rq, PHT_ALL, &h, NULL, sizeof rb, &rl), PLUGIN_HOSTCALL_ERR_ARGUMENT);
        ASSERT_EQ(plugin_hostcall_dispatch(&rq, PHT_ALL, &h, rb, sizeof rb, NULL), PLUGIN_HOSTCALL_ERR_ARGUMENT);
    } TEST_END
    return failures;
}

static uint64_t pht_next(uint64_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    return *s;
}

/* Every frame is either refused or decoded and re-encoded byte-exact, and the
 * decoder never reads past len: the input sits at the end of an exact-size
 * heap-like buffer with a guard that a sanitizer build would trap on. */
static int pht_check_inner(const uint8_t *buf, size_t len)
{
    struct plugin_hostcall_frame d;
    size_t used = 0;
    enum plugin_hostcall_status s = plugin_hostcall_decode(buf, len, &d, &used);
    if (s != PLUGIN_HOSTCALL_OK)
        return used == 0 && s != PLUGIN_HOSTCALL_DENIED;
    if (used == 0 || used > len)
        return 0;
    uint8_t re[PLUGIN_HOSTCALL_MAX_FRAME];
    size_t w = 0;
    if (plugin_hostcall_encode(&d, re, sizeof re, &w) != PLUGIN_HOSTCALL_OK)
        return 0;
    if (w != used || memcmp(re, buf, used) != 0)
        return 0;
    /* a decoded request must also dispatch to some definite status */
    struct plugin_hostcall_handlers h;
    struct pht_fake f;
    pht_handlers(&h, &f);
    uint8_t rb[PLUGIN_HOSTCALL_MAX_FRAME];
    size_t rl = 0;
    if (d.kind == PLUGIN_HOSTCALL_KIND_REQUEST) {
        s = plugin_hostcall_dispatch(&d, PHT_ALL, &h, rb, sizeof rb, &rl);
        if (s == PLUGIN_HOSTCALL_OK && rl == 0)
            return 0;
    }
    return 1;
}

/* Decode from a heap block of exactly len bytes so a sanitizer build traps any
 * read past the end. */
static enum plugin_hostcall_status pht_decode_tight(
    const uint8_t *src, size_t len, struct plugin_hostcall_frame *d, size_t *u)
{
    uint8_t *tight = malloc(len ? len : 1);
    if (tight == NULL)
        return PLUGIN_HOSTCALL_OK; /* fails the caller's refusal assertion */
    if (len)
        memcpy(tight, src, len);
    enum plugin_hostcall_status s = plugin_hostcall_decode(tight, len, d, u);
    free(tight);
    return s;
}
static int pht_check_frame(const uint8_t *buf, size_t len)
{
    uint8_t *tight = malloc(len ? len : 1);
    if (tight == NULL)
        return 0;
    if (len)
        memcpy(tight, buf, len);
    int ok = pht_check_inner(tight, len);
    free(tight);
    return ok;
}


static int pht_case_mutation(void)
{
    int failures = 0;
    TEST_CASE("mutation loop: truncations and bit flips never crash or mis-decode") {
        uint64_t seed = 0x9E3779B97F4A7C15ull;
        unsigned checked = 0, decoded = 0;
        for (unsigned round = 0; round < 400; round++) {
            uint8_t payload[40];
            size_t pl = pht_next(&seed) % sizeof payload;
            for (size_t i = 0; i < pl; i++)
                payload[i] = (uint8_t)pht_next(&seed);
            uint8_t kind = (uint8_t)(1 + pht_next(&seed) % 2);
            uint32_t id = (uint32_t)pht_next(&seed);
            uint16_t method = (uint16_t)(1 + pht_next(&seed) % 7);
            struct plugin_hostcall_frame fr = { kind, id, method, payload, pl };
            uint8_t wire[64];
            size_t w = 0;
            ASSERT_EQ(plugin_hostcall_encode(&fr, wire, sizeof wire, &w), PLUGIN_HOSTCALL_OK);
            ASSERT(pht_check_frame(wire, w));
            for (size_t cut = 0; cut < w; cut++) {
                struct plugin_hostcall_frame d;
                size_t u = 0;
                ASSERT(pht_decode_tight(wire, cut, &d, &u) != PLUGIN_HOSTCALL_OK);
                checked++;
            }
            /* every single-bit flip, then three-bit bursts */
            for (size_t bit = 0; bit < w * 8; bit++) {
                uint8_t m[64];
                memcpy(m, wire, w);
                m[bit / 8] ^= (uint8_t)(1u << (bit % 8));
                ASSERT(pht_check_frame(m, w));
                checked++;
                struct plugin_hostcall_frame d;
                size_t u = 0;
                if (plugin_hostcall_decode(m, w, &d, &u) == PLUGIN_HOSTCALL_OK)
                    decoded++;
                for (int k = 0; k < 3; k++) {
                    size_t at = pht_next(&seed) % w;
                    unsigned shift = (unsigned)(pht_next(&seed) % 8);
                    m[at] ^= (uint8_t)(1u << shift);
                }
                ASSERT(pht_check_frame(m, w));
                checked++;
            }
        }
        ASSERT(checked > 10000);
        ASSERT(decoded > 0);
    } TEST_END
    return failures;
}

static int pht_case_random_bytes(void)
{
    int failures = 0;
    TEST_CASE("mutation loop: random bytes never crash the decoder") {
        uint64_t seed = 0x243F6A8885A308D3ull;
        for (unsigned round = 0; round < 3000; round++) {
            uint8_t buf[48];
            size_t len = pht_next(&seed) % sizeof buf;
            for (size_t i = 0; i < len; i++)
                buf[i] = (uint8_t)pht_next(&seed);
            if (len >= 12 && (round & 1)) { /* steer toward a plausible header */
                buf[0] = buf[1] = buf[2] = 0;
                buf[3] = (uint8_t)(8 + pht_next(&seed) % 40);
                buf[4] = 1;
                buf[5] = (uint8_t)(1 + pht_next(&seed) % 2);
            }
            ASSERT(pht_check_frame(buf, len));
        }
    } TEST_END
    return failures;
}

static int pht_case_wire(void)
{
    int failures = 0;
    TEST_CASE("a request encoded on the wire is dispatched and answered with its id") {
        struct plugin_hostcall_handlers h;
        struct pht_fake f;
        pht_handlers(&h, &f);
        uint8_t wire[32], reply[64];
        size_t w = 0, rl = 0, used = 0;
        static const uint8_t key[2] = { 1, 'k' };
        struct plugin_hostcall_frame req = { PLUGIN_HOSTCALL_KIND_REQUEST, 42, PLUGIN_HOSTCALL_M_STATE_GET, key, 2 };
        struct plugin_hostcall_frame in, out;
        ASSERT_EQ(plugin_hostcall_encode(&req, wire, sizeof wire, &w), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(plugin_hostcall_decode(wire, w, &in, &used), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(plugin_hostcall_dispatch(&in, PLUGIN_HOSTCALL_CAP_STATE, &h, reply, sizeof reply, &rl), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(plugin_hostcall_decode(reply, rl, &out, &used), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(out.id, 42u);
        ASSERT_EQ(out.kind, PLUGIN_HOSTCALL_KIND_REPLY);
        ASSERT_EQ(f.calls[PLUGIN_HOSTCALL_M_STATE_GET], 1u);
        ASSERT_EQ(plugin_hostcall_dispatch(&in, 0, &h, reply, sizeof reply, &rl), PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(f.calls[PLUGIN_HOSTCALL_M_STATE_GET], 1u);
    } TEST_END
    return failures;
}

int test_plugin_hostcall(void)
{
    int failures = 0;
    printf("\n=== Plugin host-call tests ===\n");
    failures += pht_case_table();
    failures += pht_case_wire();
    failures += pht_case_status_text();
    failures += pht_case_roundtrip();
    failures += pht_case_limits();
    failures += pht_case_decode_refusals();
    failures += pht_case_encode_refusals();
    failures += pht_case_dispatch_refusals();
    failures += pht_case_dispatch_shape();
    failures += pht_case_mutation();
    failures += pht_case_random_bytes();
    return failures;
}
