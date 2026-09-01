/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zendp — SIGNED ENDPOINT RECORDS: a node's address as something
 * it signed, with a key the chain vouches for
 * (docs/work/NAT_AND_ONION_TRANSPORT.md slice 1).
 *
 * Coverage:
 *   1. The body bound math and the size claim (a signed record is past
 *      the 223-byte OP_RETURN relay cap, so records are content).
 *   2. Body encode/decode round-trip across ALL seven endpoint
 *      combinations (onion / v4 / v6 and every mix).
 *   3. Pedantic decode negatives: bad tag, one byte short, one byte
 *      long (a trailing byte is a REJECT), unknown flag bits, flags
 *      claiming no endpoint at all, a length that disagrees with the
 *      flags, a bad hostname, 0.0.0.0, ::, port 0, a field set without
 *      its flag (canonical-encoding rule), NULL args, an undersized
 *      encode buffer.
 *   4. FROZEN GOLDEN VECTORS built BY HAND from the spec and byte
 *      compared — the body bytes, and the record key checked against a
 *      hand-built SHA3-256("ZIDE" ‖ blinded) preimage, so the vector
 *      pins the DERIVATION rather than snapshotting whatever the code
 *      returned.
 *   5. THE POINT OF THE SLICE — chain binding. Every anchor verdict
 *      gets its own named refusal: no lookup registered, lookup
 *      unavailable, key never anchored, key rotated away, key revoked.
 *      A record signed by a perfectly good key is refused unless the
 *      chain says ACTIVE.
 *   6. sign -> publish -> fetch -> verify end to end over a real
 *      vcs_package_store on ./test-tmp, plus tamper rejection, replay
 *      (lower and equal seq), expiry, not-yet-valid, and the period
 *      boundary fallback.
 *   7. The discovery projection: only in-window, only ACTIVE-anchored.
 *   8. The core/modules/net adapter: the rich endpoint narrows to the old
 *      two-field peer, a clearnet-only record is skipped rather than
 *      counted as malformed, and an expired or malformed one is
 *      dropped and counted.
 *
 * NOT covered because it is not true yet: that the party answering at
 * an advertised address holds the key. That needs the Noise
 * transport, which is default OFF. A record is a hint. */

#include "test/test_core.h"

#include "base/log_level.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "net/onion_discovery.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"
#include "vcs/zendp_swarm.h"
#include "zid/zendp.h"
#include "zid/zid.h"

#include <stdio.h>
#include <string.h>

#define ZE_CHECK(name, expr) do {                                    \
    if (expr) { printf("  zendp: %s... OK\n", (name)); }             \
    else { printf("  zendp: %s... FAIL\n", (name)); failures++; }    \
} while (0)

/* A valid v3 hostname: 56 chars from the base32 alphabet a-z2-7, then
 * ".onion". Written out in full so the length is auditable. */
#define ZE_ONION \
    "zclassictwothreesignedendpointrecordgoldenvectoraaaaaaaa.onion"
#define ZE_ONION_B \
    "zclassictwothreesignedendpointrecordgoldenvectorbbbbbbbb.onion"

#define ZE_NOT_BEFORE UINT64_C(1767225600)
/* 1767225600 / 86400 = 20454 whole days since the epoch. */
#define ZE_PERIOD     UINT64_C(20454)
#define ZE_EXPIRY     (ZE_NOT_BEFORE + UINT64_C(86400))
#define ZE_SERVICES   UINT64_C(0x0000000000000409)
#define ZE_HEIGHT     UINT32_C(3196556)

/* ── a test-owned chain oracle ─────────────────────────────────────
 *
 * Stands in for db_zid_identity_find. Deliberately dumb: one verdict,
 * set by the case under test, so a test can prove the REFUSAL, not
 * just the acceptance. */
static struct {
    bool available;                 /* false => the lookup itself fails */
    enum zendp_anchor_state state;
    int32_t anchor_height;
    int32_t updated_height;
} g_oracle;

static bool ze_oracle(void *ctx, const uint8_t pubkey[32],
                      struct zendp_anchor *out)
{
    (void)ctx;
    if (!pubkey || !out)
        return false;
    if (!g_oracle.available)
        return false;
    memset(out, 0, sizeof(*out));
    out->state = g_oracle.state;
    out->anchor_height = g_oracle.anchor_height;
    out->updated_height = g_oracle.updated_height;
    return true;
}

static void ze_oracle_set(enum zendp_anchor_state s)
{
    g_oracle.available = true;
    g_oracle.state = s;
    g_oracle.anchor_height = 3100000;
    g_oracle.updated_height = 3100000;
    zendp_set_anchor_lookup(ze_oracle, NULL);
}

/* ── helpers ───────────────────────────────────────────────────────── */

static void ze_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void ze_put_le32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static void ze_put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* Build a record carrying exactly the endpoints `flags` claims. */
static void ze_make(struct zendp *ep, uint8_t flags)
{
    memset(ep, 0, sizeof(*ep));
    ep->flags = flags;
    ep->services = ZE_SERVICES;
    ep->height = ZE_HEIGHT;
    ep->not_before = ZE_NOT_BEFORE;
    if (flags & ZENDP_HAS_ONION) {
        snprintf(ep->onion, sizeof(ep->onion), "%s", ZE_ONION);
        ep->onion_port = 8033;
    }
    if (flags & ZENDP_HAS_IPV4) {
        ep->ipv4[0] = 203; ep->ipv4[1] = 0; ep->ipv4[2] = 113; ep->ipv4[3] = 7;
        ep->ipv4_port = 8033;
    }
    if (flags & ZENDP_HAS_IPV6) {
        ep->ipv6[0] = 0x20; ep->ipv6[1] = 0x01; ep->ipv6[2] = 0x0d;
        ep->ipv6[3] = 0xb8; ep->ipv6[15] = 0x2a;
        ep->ipv6_port = 8034;
    }
}

static bool ze_eq(const struct zendp *a, const struct zendp *b)
{
    return a->flags == b->flags && a->services == b->services &&
           a->height == b->height && a->not_before == b->not_before &&
           strcmp(a->onion, b->onion) == 0 &&
           a->onion_port == b->onion_port &&
           memcmp(a->ipv4, b->ipv4, sizeof(a->ipv4)) == 0 &&
           a->ipv4_port == b->ipv4_port &&
           memcmp(a->ipv6, b->ipv6, sizeof(a->ipv6)) == 0 &&
           a->ipv6_port == b->ipv6_port;
}

/* ── 1 + 2 + 3: bounds, round-trip, pedantic negatives ─────────────── */

static int ze_case_body_codec(void)
{
    int failures = 0;
    uint8_t body[ZENDP_BODY_MAX + 8];

    ZE_CHECK("body: the bound math matches the frozen wire",
             ZENDP_BODY_MIN == 4 + 1 + 8 + 4 + 8 &&
             ZENDP_ONION_WIRE == 62 + 2 && ZENDP_IPV4_WIRE == 4 + 2 &&
             ZENDP_IPV6_WIRE == 16 + 2 &&
             ZENDP_BODY_MAX == 25 + 64 + 6 + 18 &&
             ZENDP_BODY_MAX <= ZID_BODY_MAX);
    /* The size claim the header makes: a signed record fits one blob
     * chunk and can never ride an OP_RETURN. */
    ZE_CHECK("body: a signed record is content, never an OP_RETURN",
             51 + ZENDP_BODY_MAX + 64 == 228 && 228 > 223 &&
             228 <= (int)VCS_BLOB_MAX_BYTES);
    ZE_CHECK("body: the golden hostname is exactly 62 chars",
             strlen(ZE_ONION) == (size_t)ZENDP_ONION_LEN &&
             strlen(ZE_ONION_B) == (size_t)ZENDP_ONION_LEN);

    int rt_bad = 0;
    for (uint8_t flags = 1; flags <= ZENDP_FLAGS_KNOWN; flags++) {
        struct zendp in, out;
        ze_make(&in, flags);
        size_t n = zendp_encode_body(body, sizeof(body), &in);
        bool ok = n == zendp_body_len(flags) &&
                  zendp_decode_body(&out, body, (uint16_t)n) &&
                  ze_eq(&in, &out);
        if (!ok) {
            printf("  zendp: body: round-trip at flags=0x%02x... FAIL\n",
                   (unsigned)flags);
            rt_bad++;
        }
    }
    ZE_CHECK("body: round-trip holds for every endpoint combination",
             rt_bad == 0);

    /* Negatives. Quiet the expected refusal spam. */
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    struct zendp ep, dec;
    ze_make(&ep, ZENDP_FLAGS_KNOWN);
    size_t full = zendp_encode_body(body, sizeof(body), &ep);

    ZE_CHECK("negative: NULL args are refused",
             zendp_encode_body(NULL, sizeof(body), &ep) == 0 &&
             zendp_encode_body(body, sizeof(body), NULL) == 0 &&
             !zendp_decode_body(NULL, body, (uint16_t)full) &&
             !zendp_decode_body(&dec, NULL, (uint16_t)full) &&
             !zendp_valid(NULL));
    ZE_CHECK("negative: an undersized encode buffer is refused",
             zendp_encode_body(body, full - 1, &ep) == 0);

    uint8_t tmp[ZENDP_BODY_MAX + 8];
    memcpy(tmp, body, full);
    tmp[3] = 'X';
    ZE_CHECK("negative: a bad tag is refused",
             !zendp_decode_body(&dec, tmp, (uint16_t)full));

    ZE_CHECK("negative: one byte short is refused",
             !zendp_decode_body(&dec, body, (uint16_t)(full - 1)));
    memcpy(tmp, body, full);
    tmp[full] = 0;
    ZE_CHECK("negative: one trailing byte is refused",
             !zendp_decode_body(&dec, tmp, (uint16_t)(full + 1)));

    memcpy(tmp, body, full);
    tmp[4] = 0x08; /* an unknown flag bit */
    ZE_CHECK("negative: an unknown flag bit is refused",
             !zendp_decode_body(&dec, tmp, (uint16_t)full) &&
             zendp_body_len(0x08) == 0);
    memcpy(tmp, body, full);
    tmp[4] = 0x00;
    ZE_CHECK("negative: flags claiming no endpoint at all are refused",
             !zendp_decode_body(&dec, tmp, (uint16_t)full) &&
             zendp_body_len(0) == 0);
    memcpy(tmp, body, full);
    tmp[4] = ZENDP_HAS_ONION; /* length now disagrees with the flags */
    ZE_CHECK("negative: a length that disagrees with the flags is refused",
             !zendp_decode_body(&dec, tmp, (uint16_t)full));

    /* Hostname / address / port shape, at the struct level. */
    struct zendp bad;
    ze_make(&bad, ZENDP_HAS_ONION);
    bad.onion[0] = '1';  /* not in the v3 base32 alphabet */
    ZE_CHECK("negative: a non-v3 hostname is refused",
             !zendp_valid(&bad) &&
             zendp_encode_body(body, sizeof(body), &bad) == 0);

    ze_make(&bad, ZENDP_HAS_ONION);
    bad.onion_port = 0;
    ZE_CHECK("negative: onion port 0 is refused", !zendp_valid(&bad));

    ze_make(&bad, ZENDP_HAS_IPV4);
    memset(bad.ipv4, 0, sizeof(bad.ipv4));
    ZE_CHECK("negative: 0.0.0.0 is refused", !zendp_valid(&bad));
    ze_make(&bad, ZENDP_HAS_IPV4);
    bad.ipv4_port = 0;
    ZE_CHECK("negative: ipv4 port 0 is refused", !zendp_valid(&bad));

    ze_make(&bad, ZENDP_HAS_IPV6);
    memset(bad.ipv6, 0, sizeof(bad.ipv6));
    ZE_CHECK("negative: :: is refused", !zendp_valid(&bad));
    ze_make(&bad, ZENDP_HAS_IPV6);
    bad.ipv6_port = 0;
    ZE_CHECK("negative: ipv6 port 0 is refused", !zendp_valid(&bad));

    /* The canonical-encoding rule: a field a flag does not claim must
     * be zero, so one endpoint set has exactly one encoding. */
    ze_make(&bad, ZENDP_HAS_ONION);
    bad.ipv4[0] = 10; bad.ipv4[3] = 1; bad.ipv4_port = 8033;
    ZE_CHECK("negative: an unclaimed ipv4 field breaks canonicality",
             !zendp_valid(&bad));
    ze_make(&bad, ZENDP_HAS_IPV4);
    snprintf(bad.onion, sizeof(bad.onion), "%s", ZE_ONION);
    ZE_CHECK("negative: an unclaimed hostname breaks canonicality",
             !zendp_valid(&bad));

    zcl_log_level_set(saved);
    return failures;
}

/* ── 4: frozen golden vectors, hand-built from the spec ────────────── */

static int ze_case_golden(void)
{
    int failures = 0;

    /* The body, byte for byte, assembled from the wire spec in
     * zid/zendp.h — not from the encoder. */
    uint8_t want[ZENDP_BODY_MAX];
    size_t n = 0;
    memcpy(want + n, "ZIDE", 4);          n += 4;
    want[n++] = (uint8_t)ZENDP_FLAGS_KNOWN;
    ze_put_le64(want + n, ZE_SERVICES);   n += 8;
    ze_put_le32(want + n, ZE_HEIGHT);     n += 4;
    ze_put_le64(want + n, ZE_NOT_BEFORE); n += 8;
    memcpy(want + n, ZE_ONION, ZENDP_ONION_LEN); n += ZENDP_ONION_LEN;
    ze_put_le16(want + n, 8033);          n += 2;
    want[n++] = 203; want[n++] = 0; want[n++] = 113; want[n++] = 7;
    ze_put_le16(want + n, 8033);          n += 2;
    memset(want + n, 0, 16);
    want[n] = 0x20; want[n + 1] = 0x01; want[n + 2] = 0x0d;
    want[n + 3] = 0xb8; want[n + 15] = 0x2a;
    n += 16;
    ze_put_le16(want + n, 8034);          n += 2;

    struct zendp ep;
    ze_make(&ep, ZENDP_FLAGS_KNOWN);
    uint8_t got[ZENDP_BODY_MAX];
    size_t got_len = zendp_encode_body(got, sizeof(got), &ep);

    ZE_CHECK("golden: the encoded body is byte-identical to the spec",
             got_len == n && n == (size_t)ZENDP_BODY_MAX &&
             memcmp(got, want, n) == 0);

    /* The record key pins the DERIVATION: SHA3-256("ZIDE" ‖ blinded),
     * where blinded is zid_blinded_key(pk, period). Built here from
     * the primitives, not read back from the function. */
    uint8_t pk[32], sk[32], seed[32];
    memset(seed, 0x5e, sizeof(seed));
    ed25519_keypair(pk, sk, seed);

    uint8_t blinded[32];
    zid_blinded_key(blinded, pk, ZE_PERIOD);
    uint8_t pre[4 + 32];
    memcpy(pre, "ZIDE", 4);
    memcpy(pre + 4, blinded, 32);
    uint8_t want_key[32];
    sha3_256(pre, sizeof(pre), want_key);

    uint8_t got_key[32];
    zendp_record_key(got_key, pk, ZE_PERIOD);
    ZE_CHECK("golden: the record key is SHA3(\"ZIDE\" || blinded key)",
             memcmp(got_key, want_key, 32) == 0);
    ZE_CHECK("golden: it differs from the raw blinded key (own address space)",
             memcmp(got_key, blinded, 32) != 0);
    ZE_CHECK("golden: the period derivation is the shared one",
             zdesc_period_at(ZE_NOT_BEFORE) == ZE_PERIOD &&
             zdesc_period_prev(ZE_PERIOD) == ZE_PERIOD - 1);
    return failures;
}

/* ── 5: THE POINT — every chain verdict has its own name ───────────── */

static int ze_case_chain_binding(void)
{
    int failures = 0;
    uint8_t pk[32], sk[32], seed[32];
    memset(seed, 0x11, sizeof(seed));
    ed25519_keypair(pk, sk, seed);

    struct zendp ep;
    ze_make(&ep, ZENDP_FLAGS_KNOWN);
    struct zid_doc doc;
    ZE_CHECK("chain: the record signs", zendp_sign(&doc, &ep, 1, ZE_EXPIRY,
                                                   seed));
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    ZE_CHECK("chain: the doc encodes", wire_len > 0);

    uint64_t now = ZE_NOT_BEFORE + 10;
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    struct zendp_directory dir;
    zendp_directory_init(&dir);

    /* No lookup at all: FAIL CLOSED. A perfectly valid signature over a
     * perfectly valid body is still not a peer hint. */
    zendp_set_anchor_lookup(NULL, NULL);
    ZE_CHECK("chain: with no lookup registered the record is refused by name",
             !zendp_anchor_lookup_registered() &&
             zendp_accept(&dir, wire, wire_len, now, NULL, NULL) ==
                 ZENDP_ERR_NO_ANCHOR_LOOKUP);

    /* Lookup registered but unable to answer. */
    g_oracle.available = false;
    zendp_set_anchor_lookup(ze_oracle, NULL);
    ZE_CHECK("chain: a lookup that cannot run is not a 'yes'",
             zendp_anchor_lookup_registered() &&
             zendp_accept(&dir, wire, wire_len, now, NULL, NULL) ==
                 ZENDP_ERR_ANCHOR_UNAVAILABLE);

    ze_oracle_set(ZENDP_ANCHOR_ABSENT);
    ZE_CHECK("chain: an unanchored key is refused NOT_ANCHORED",
             zendp_accept(&dir, wire, wire_len, now, NULL, NULL) ==
                 ZENDP_ERR_NOT_ANCHORED);

    ze_oracle_set(ZENDP_ANCHOR_ROTATED);
    ZE_CHECK("chain: a rotated key is refused ROTATED",
             zendp_accept(&dir, wire, wire_len, now, NULL, NULL) ==
                 ZENDP_ERR_ROTATED);

    ze_oracle_set(ZENDP_ANCHOR_REVOKED);
    ZE_CHECK("chain: a revoked key is refused REVOKED",
             zendp_accept(&dir, wire, wire_len, now, NULL, NULL) ==
                 ZENDP_ERR_REVOKED);

    ZE_CHECK("chain: every refusal so far left the directory empty",
             !zendp_directory_find(&dir, pk, NULL));

    ze_oracle_set(ZENDP_ANCHOR_ACTIVE);
    struct zendp got;
    uint8_t got_pk[32];
    ZE_CHECK("chain: an ACTIVE anchor accepts",
             zendp_accept(&dir, wire, wire_len, now, &got, got_pk) ==
                 ZENDP_OK &&
             ze_eq(&ep, &got) && memcmp(got_pk, pk, 32) == 0);
    ZE_CHECK("chain: the accepted record resolves by identity",
             zendp_directory_find(&dir, pk, NULL));

    /* Tampering: flip a byte of the body and the signature fails
     * BEFORE the chain is even consulted. */
    uint8_t bad[ZID_DOC_MAX];
    memcpy(bad, wire, wire_len);
    bad[60] ^= 0x01;
    struct zendp_directory dir2;
    zendp_directory_init(&dir2);
    ZE_CHECK("chain: a tampered record fails verification",
             zendp_accept(&dir2, bad, wire_len, now, NULL, NULL) ==
                 ZENDP_ERR_VERIFY);

    /* A doc whose body is a different record type. */
    struct zid_doc other;
    uint8_t junk[8] = { 'Z', 'I', 'D', 'X', 1, 2, 3, 4 };
    if (zid_doc_sign(&other, junk, (uint16_t)sizeof(junk), 1, ZE_EXPIRY,
                     seed)) {
        uint8_t owire[ZID_DOC_MAX];
        size_t olen = zid_doc_encode(owire, sizeof(owire), &other);
        ZE_CHECK("chain: a doc that is not a ZIDE body is refused by name",
                 olen > 0 &&
                 zendp_accept(&dir2, owire, olen, now, NULL, NULL) ==
                     ZENDP_ERR_BODY);
    }

    /* Expiry and not-yet-valid are per-record, from the record's own
     * signed window — there is no other freshness clock. */
    ZE_CHECK("chain: an expired record is refused",
             zendp_accept(&dir2, wire, wire_len, ZE_EXPIRY, NULL, NULL) ==
                 ZENDP_ERR_VERIFY);
    ZE_CHECK("chain: a not-yet-valid record is refused",
             zendp_accept(&dir2, wire, wire_len, ZE_NOT_BEFORE - 1, NULL,
                          NULL) == ZENDP_ERR_BODY);

    ZE_CHECK("chain: every result and anchor state has a name",
             strcmp(zendp_result_string(ZENDP_OK), "ok") == 0 &&
             strcmp(zendp_result_string(ZENDP_ERR_REVOKED), "unknown") != 0 &&
             strcmp(zendp_result_string(ZENDP_ERR_NO_ANCHOR_LOOKUP),
                    "unknown") != 0 &&
             strcmp(zendp_anchor_state_string(ZENDP_ANCHOR_ROTATED),
                    "rotated") == 0);

    zendp_set_anchor_lookup(NULL, NULL);
    zcl_log_level_set(saved);
    return failures;
}

/* ── 6 + 7: end to end over a real store, and the projection ───────── */

struct ze_fixture {
    char datadir[512];
    struct vcs_package_store *store;
    struct zendp_directory dir;
    uint8_t seed[32], pk[32], sk[32];
};

static bool ze_fixture_open(struct ze_fixture *f, const char *tag,
                            uint8_t seed_byte)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->datadir, sizeof(f->datadir), "zendp", tag);
    f->store = vcs_package_store_open(f->datadir,
                                      VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    zendp_directory_init(&f->dir);
    memset(f->seed, seed_byte, sizeof(f->seed));
    ed25519_keypair(f->pk, f->sk, f->seed);
    return f->store != NULL;
}

static void ze_fixture_close(struct ze_fixture *f)
{
    if (f->store)
        vcs_package_store_close(f->store);
    f->store = NULL;
    test_rm_rf(f->datadir);
}

static int ze_case_publish_fetch(void)
{
    int failures = 0;
    struct ze_fixture f;
    ZE_CHECK("e2e: store opens", ze_fixture_open(&f, "e2e", 0x21));
    if (!f.store) {
        ze_fixture_close(&f);
        return failures;
    }

    ze_oracle_set(ZENDP_ANCHOR_ACTIVE);
    uint64_t now = ZE_NOT_BEFORE + 60;

    struct zendp ep;
    ze_make(&ep, ZENDP_FLAGS_KNOWN);
    uint8_t root[32], pub[32];
    ZE_CHECK("e2e: publish stores the signed record as a blob",
             zendp_publish_to(f.store, &f.dir, &ep, 5, ZE_EXPIRY, f.seed, now,
                              root, pub) == ZENDP_OK &&
             memcmp(pub, f.pk, 32) == 0);

    struct zendp back;
    ZE_CHECK("e2e: fetch re-reads and re-verifies the stored bytes",
             zendp_fetch_from(f.store, &f.dir, f.pk, now, &back) == ZENDP_OK &&
             ze_eq(&ep, &back));

    /* The stored root is a pure function of the signed bytes, never a
     * claim: re-sign the same record and re-derive it independently. */
    struct zid_doc again;
    uint8_t again_wire[ZID_DOC_MAX], again_root[32];
    size_t again_len = 0;
    if (zendp_sign(&again, &ep, 5, ZE_EXPIRY, f.seed))
        again_len = zid_doc_encode(again_wire, sizeof(again_wire), &again);
    ZE_CHECK("e2e: the stored root is the content's root",
             again_len > 0 &&
             vcs_blob_root_of(again_wire, again_len, again_root) ==
                 VCS_BLOB_OK &&
             memcmp(again_root, root, 32) == 0);

    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    /* Replay: neither a lower nor an equal seq may displace what we
     * hold, at publish or at accept. */
    struct zendp older;
    ze_make(&older, ZENDP_HAS_ONION);
    ZE_CHECK("e2e: a lower seq is refused at publish",
             zendp_publish_to(f.store, &f.dir, &older, 4, ZE_EXPIRY, f.seed,
                              now, NULL, NULL) == ZENDP_ERR_STALE);
    ZE_CHECK("e2e: an equal seq is refused at publish",
             zendp_publish_to(f.store, &f.dir, &older, 5, ZE_EXPIRY, f.seed,
                              now, NULL, NULL) == ZENDP_ERR_STALE);
    ZE_CHECK("e2e: the held record is untouched after a refused replay",
             zendp_fetch_from(f.store, &f.dir, f.pk, now, &back) == ZENDP_OK &&
             ze_eq(&ep, &back));

    /* A strictly higher seq DOES supersede — rotation is free. */
    struct zendp rotated;
    ze_make(&rotated, ZENDP_HAS_ONION);
    snprintf(rotated.onion, sizeof(rotated.onion), "%s", ZE_ONION_B);
    ZE_CHECK("e2e: a higher seq supersedes",
             zendp_publish_to(f.store, &f.dir, &rotated, 6, ZE_EXPIRY, f.seed,
                              now, NULL, NULL) == ZENDP_OK &&
             zendp_fetch_from(f.store, &f.dir, f.pk, now, &back) == ZENDP_OK &&
             strcmp(back.onion, ZE_ONION_B) == 0);

    /* An unpublished identity is ABSENT, by name — not a silent zero. */
    uint8_t other_pk[32], other_sk[32], other_seed[32];
    memset(other_seed, 0x77, sizeof(other_seed));
    ed25519_keypair(other_pk, other_sk, other_seed);
    ZE_CHECK("e2e: an unknown identity resolves ABSENT",
             zendp_fetch_from(f.store, &f.dir, other_pk, now, NULL) ==
                 ZENDP_ERR_ABSENT);

    /* A record that names no endpoint never reaches the store. */
    struct zendp empty;
    memset(&empty, 0, sizeof(empty));
    empty.not_before = ZE_NOT_BEFORE;
    ZE_CHECK("e2e: a record naming no endpoint is refused at publish",
             zendp_publish_to(f.store, &f.dir, &empty, 9, ZE_EXPIRY, f.seed,
                              now, NULL, NULL) == ZENDP_ERR_SHAPE);

    zcl_log_level_set(saved);
    zendp_set_anchor_lookup(NULL, NULL);
    ze_fixture_close(&f);
    return failures;
}

static int ze_case_period_boundary(void)
{
    int failures = 0;
    struct ze_fixture f;
    ZE_CHECK("boundary: store opens", ze_fixture_open(&f, "period", 0x33));
    if (!f.store) {
        ze_fixture_close(&f);
        return failures;
    }
    ze_oracle_set(ZENDP_ANCHOR_ACTIVE);

    /* Publish 10 seconds before midnight; resolve 10 seconds after. */
    uint64_t before = (ZE_PERIOD + 1) * 86400 - 10;
    uint64_t after = before + 20;
    struct zendp ep;
    ze_make(&ep, ZENDP_HAS_ONION);
    ep.not_before = before - 100;
    ZE_CHECK("boundary: publish just before midnight",
             zendp_publish_to(f.store, &f.dir, &ep, 1, after + 3600, f.seed,
                              before, NULL, NULL) == ZENDP_OK);
    ZE_CHECK("boundary: it still resolves after midnight",
             zendp_fetch_from(f.store, &f.dir, f.pk, after, NULL) == ZENDP_OK);

    zendp_set_anchor_lookup(NULL, NULL);
    ze_fixture_close(&f);
    return failures;
}

static int ze_case_projection(void)
{
    int failures = 0;
    struct ze_fixture f;
    ZE_CHECK("projection: store opens", ze_fixture_open(&f, "proj", 0x44));
    if (!f.store) {
        ze_fixture_close(&f);
        return failures;
    }

    uint64_t now = ZE_NOT_BEFORE + 60;
    struct zendp ep;
    ze_make(&ep, ZENDP_FLAGS_KNOWN);
    struct zendp_record_view views[ZENDP_DIR_MAX];

    /* Published while the chain says the key is not live: stored and
     * addressable, but NEVER offered to discovery. */
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    ze_oracle_set(ZENDP_ANCHOR_REVOKED);
    ZE_CHECK("projection: publish with a revoked key still stores",
             zendp_publish_to(f.store, &f.dir, &ep, 1, ZE_EXPIRY, f.seed, now,
                              NULL, NULL) == ZENDP_OK);
    ZE_CHECK("projection: a non-ACTIVE record is not projected",
             zendp_directory_records(&f.dir, now, views, ZENDP_DIR_MAX) == 0);
    zcl_log_level_set(saved);

    /* Re-publish under an ACTIVE anchor: now it is discoverable. */
    ze_oracle_set(ZENDP_ANCHOR_ACTIVE);
    ZE_CHECK("projection: publish with an active anchor",
             zendp_publish_to(f.store, &f.dir, &ep, 2, ZE_EXPIRY, f.seed, now,
                              NULL, NULL) == ZENDP_OK);
    size_t n = zendp_directory_records(&f.dir, now, views, ZENDP_DIR_MAX);
    ZE_CHECK("projection: an ACTIVE in-window record is projected once",
             n == 1 && memcmp(views[0].master_pubkey, f.pk, 32) == 0 &&
             views[0].seq == 2 && views[0].expiry == ZE_EXPIRY &&
             views[0].anchor_height == 3100000 &&
             views[0].ep.onion_port == 8033 &&
             views[0].ep.services == ZE_SERVICES &&
             views[0].ep.height == ZE_HEIGHT);
    ZE_CHECK("projection: outside its own window it disappears",
             zendp_directory_records(&f.dir, ZE_EXPIRY, views,
                                     ZENDP_DIR_MAX) == 0 &&
             zendp_directory_records(&f.dir, ZE_NOT_BEFORE - 1, views,
                                     ZENDP_DIR_MAX) == 0);

    zendp_set_anchor_lookup(NULL, NULL);
    ze_fixture_close(&f);
    return failures;
}

/* ── 8: the core/modules/net adapter — rich type beside the narrow one ──────── */

static int ze_case_net_adapter(void)
{
    int failures = 0;
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    struct onion_endpoint eps[4];
    memset(eps, 0, sizeof(eps));

    /* 0: a full, live, anchored record. */
    snprintf(eps[0].hostname, sizeof(eps[0].hostname), "%s", ZE_ONION);
    eps[0].onion_port = 8033;
    eps[0].height = 3196556;
    eps[0].expiry = ZE_EXPIRY;
    eps[0].seq = 7;
    eps[0].anchor_height = 3100000;
    eps[0].provenance = ONION_PROV_ANCHORED;
    /* 1: clearnet-only — a legitimate record this narrow path cannot
     * carry. Skipped, NOT counted as malformed. */
    eps[1].ipv4[0] = 198; eps[1].ipv4[3] = 51; eps[1].ipv4_port = 8033;
    eps[1].expiry = ZE_EXPIRY;
    /* 2: expired. */
    snprintf(eps[2].hostname, sizeof(eps[2].hostname), "%s", ZE_ONION_B);
    eps[2].expiry = ZE_NOT_BEFORE;
    /* 3: malformed hostname. */
    snprintf(eps[3].hostname, sizeof(eps[3].hostname), "not-an-onion");
    eps[3].expiry = ZE_EXPIRY;

    uint64_t now = ZE_NOT_BEFORE + 60;

    struct onion_peer peer;
    ZE_CHECK("adapter: a rich endpoint narrows to the old two-field peer",
             onion_endpoint_to_peer(&eps[0], &peer) &&
             strcmp(peer.hostname, ZE_ONION) == 0 && peer.height == 3196556);
    ZE_CHECK("adapter: NULL args are refused",
             !onion_endpoint_to_peer(NULL, &peer) &&
             !onion_endpoint_to_peer(&eps[0], NULL) &&
             !onion_endpoint_live(NULL, now));
    ZE_CHECK("adapter: a clearnet-only endpoint has no onion_peer form",
             !onion_endpoint_to_peer(&eps[1], &peer));
    ZE_CHECK("adapter: liveness is the record's OWN window",
             onion_endpoint_live(&eps[0], now) &&
             !onion_endpoint_live(&eps[0], ZE_EXPIRY) &&
             !onion_endpoint_live(&eps[2], now));

    struct onion_endpoint none;
    memset(&none, 0, sizeof(none));
    ZE_CHECK("adapter: an endpoint naming no address at all is not live",
             !onion_endpoint_live(&none, now));

    struct onion_peer out[4];
    int rejected = -1;
    int kept = onion_endpoints_to_peers(eps, 4, out, 4, now, &rejected);
    ZE_CHECK("adapter: only the live onion survives, and the two bad ones "
             "are counted",
             kept == 1 && rejected == 2 &&
             strcmp(out[0].hostname, ZE_ONION) == 0);

    ZE_CHECK("adapter: zero capacity and NULL inputs return 0",
             onion_endpoints_to_peers(eps, 4, out, 0, now, NULL) == 0 &&
             onion_endpoints_to_peers(NULL, 4, out, 4, now, NULL) == 0 &&
             onion_endpoints_to_peers(eps, 0, out, 4, now, NULL) == 0);

    ZE_CHECK("adapter: every provenance has a name",
             strcmp(onion_peer_provenance_string(ONION_PROV_ANCHORED),
                    "anchored") == 0 &&
             strcmp(onion_peer_provenance_string(ONION_PROV_UNSIGNED),
                    "unsigned") == 0 &&
             strcmp(onion_peer_provenance_string(ONION_PROV_SIGNED),
                    "signed") == 0);

    zcl_log_level_set(saved);
    return failures;
}

int test_zendp(void)
{
    int failures = 0;
    printf("\n=== ZENDP: signed, chain-anchored endpoint records ===\n");
    printf("  (a verified record is a HINT about where to look — binding "
           "the session to the key needs Noise, default OFF)\n");
    failures += ze_case_body_codec();
    failures += ze_case_golden();
    failures += ze_case_chain_binding();
    failures += ze_case_publish_fetch();
    failures += ze_case_period_boundary();
    failures += ze_case_projection();
    failures += ze_case_net_adapter();
    printf("=== ZENDP: %d failure(s) ===\n", failures);
    return failures;
}
