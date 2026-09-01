/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zdesc — the onion-service descriptor domain: the flagship
 * application of the sovereign identity layer
 * (docs/spec/sovereign-identity-layer.md, "A1").
 *
 * Coverage:
 *   1. The v3 onion validity rule (zdesc_onion_valid), pinned against
 *      the same vectors core/modules/net's twin enforces.
 *   2. Body encode/decode round-trip at 0 and ZDESC_INTRO_MAX intros.
 *   3. Pedantic decode negatives: bad tag, one byte short, one byte
 *      long (a trailing byte is a REJECT), intro_count over the max,
 *      intro_count disagreeing with the length, a bad hostname in the
 *      service field and in an introduction point, NULL args, an
 *      undersized encode buffer.
 *   4. FROZEN GOLDEN VECTORS: the body bytes (built by hand from the
 *      spec, byte-compared) plus their SHA3-256; the period derivation;
 *      and the blinded record key, checked against a hand-built
 *      "ZIDB" ‖ pk ‖ period_le64 preimage hashed with sha3_256 directly
 *      — so the vector pins the DERIVATION, not a snapshot of whatever
 *      the function happened to return.
 *   5. sign -> publish -> fetch -> verify end to end over a real
 *      vcs_package_store on ./test-tmp.
 *   6. Tamper rejection (flipped byte in the stored wire) and
 *      key-mismatch rejection (verified against a different identity).
 *   7. Expiry and not-yet-valid rejection.
 *   8. Replay: a lower and an equal seq are both refused and the
 *      directory still holds the higher one.
 *   9. Period boundary: a descriptor published just before midnight
 *      still resolves after it, via the previous-period fallback.
 *  10. zdesc_directory_onions skips entries outside their window.
 *
 * NOT covered because it does not exist: chain binding. Everything here
 * verifies against a caller-supplied master key. */

#include "test/test_core.h"

#include "base/log_level.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "vcs/blob_store.h"
#include "vcs/package_store.h"
#include "vcs/zdesc_swarm.h"
#include "zid/zdesc.h"
#include "zid/zid.h"

#include <stdio.h>
#include <string.h>

#define ZD_CHECK(name, expr) do {                                    \
    if (expr) { printf("  zdesc: %s... OK\n", (name)); }             \
    else { printf("  zdesc: %s... FAIL\n", (name)); failures++; }    \
} while (0)

/* Two valid v3 hostnames: 56 chars from the base32 alphabet a-z2-7,
 * then ".onion". Written out in full so the length is auditable. */
#define ZD_SERVICE_ONION \
    "zclassictwothreesovereigndescriptorgoldenvectoraaaaaaaaa.onion"
#define ZD_INTRO_ONION \
    "zclassictwothreeintroductionpointgoldenvectorbbbbbbbbbbb.onion"

/* The frozen golden body input: service hostname above, not_before
 * pinned, one introduction point whose auth key is byte i = i. */
#define ZD_GOLDEN_NOT_BEFORE UINT64_C(1767225600)
/* 1767225600 / 86400 = 20454 whole days since the epoch. */
#define ZD_GOLDEN_PERIOD UINT64_C(20454)

/* SHA3-256 of the frozen golden body bytes. A wire contract: if this
 * changes, every already-published descriptor body changes with it. */
#define ZD_GOLDEN_BODY_SHA3 \
    "ed12f682cf033774e2aab7e6d044eed21899ab43d7a24e6aea919c37bd04b5d9"

static void zd_hex(const uint8_t *in, size_t n, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * n] = '\0';
}

static void zd_put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* An intro point whose hostname differs from ZD_INTRO_ONION only in its
 * last base32 char, so every intro in a multi-intro descriptor is
 * distinct without hand-writing eight 62-char literals. */
static void zd_make_intro(struct zdesc_intro *intro, unsigned i)
{
    snprintf(intro->onion, sizeof(intro->onion), "%s", ZD_INTRO_ONION);
    intro->onion[55] = (char)('a' + (i % 26u));
    for (size_t b = 0; b < 32; b++)
        intro->auth_key[b] = (uint8_t)(b + i * 17u);
}

static void zd_make_desc(struct zdesc *d, uint8_t intro_count,
                         uint64_t not_before)
{
    memset(d, 0, sizeof(*d));
    snprintf(d->onion, sizeof(d->onion), "%s", ZD_SERVICE_ONION);
    d->not_before = not_before;
    d->intro_count = intro_count;
    for (uint8_t i = 0; i < intro_count; i++)
        zd_make_intro(&d->intro[i], i);
}

static bool zd_desc_eq(const struct zdesc *a, const struct zdesc *b)
{
    if (strcmp(a->onion, b->onion) != 0)
        return false;
    if (a->not_before != b->not_before || a->intro_count != b->intro_count)
        return false;
    for (uint8_t i = 0; i < a->intro_count; i++) {
        if (strcmp(a->intro[i].onion, b->intro[i].onion) != 0)
            return false;
        if (memcmp(a->intro[i].auth_key, b->intro[i].auth_key, 32) != 0)
            return false;
    }
    return true;
}

/* ── 1: the v3 onion validity rule ──────────────────────────────── */

static int zd_case_onion_rule(void)
{
    int failures = 0;

    ZD_CHECK("onion: the service vector is exactly 62 chars",
             strlen(ZD_SERVICE_ONION) == (size_t)ZDESC_ONION_LEN &&
             strlen(ZD_INTRO_ONION) == (size_t)ZDESC_ONION_LEN);
    ZD_CHECK("onion: a well-formed v3 hostname is accepted",
             zdesc_onion_valid(ZD_SERVICE_ONION) &&
             zdesc_onion_valid(ZD_INTRO_ONION));
    ZD_CHECK("onion: NULL is refused", !zdesc_onion_valid(NULL));
    ZD_CHECK("onion: empty is refused", !zdesc_onion_valid(""));

    char h[80];
    snprintf(h, sizeof(h), "%s", ZD_SERVICE_ONION);
    h[61] = '\0'; /* 61 chars */
    ZD_CHECK("onion: one char short is refused", !zdesc_onion_valid(h));

    snprintf(h, sizeof(h), "%sx", ZD_SERVICE_ONION);
    ZD_CHECK("onion: one char long is refused", !zdesc_onion_valid(h));

    snprintf(h, sizeof(h), "%s", ZD_SERVICE_ONION);
    memcpy(h + 56, ".union", 6);
    ZD_CHECK("onion: wrong suffix is refused", !zdesc_onion_valid(h));

    /* 0, 1, 8, 9 are NOT in the v3 base32 alphabet; nor is uppercase. */
    const char bad_chars[] = {'0', '1', '8', '9', 'A', '.', '-', ' '};
    bool all_refused = true;
    for (size_t i = 0; i < sizeof(bad_chars); i++) {
        snprintf(h, sizeof(h), "%s", ZD_SERVICE_ONION);
        h[3] = bad_chars[i];
        if (zdesc_onion_valid(h))
            all_refused = false;
    }
    ZD_CHECK("onion: every out-of-alphabet char is refused", all_refused);
    return failures;
}

/* ── 2 + 3: body codec round-trip and pedantic negatives ────────── */

static int zd_case_body_codec(void)
{
    int failures = 0;
    uint8_t body[ZDESC_BODY_MAX + 8];

    ZD_CHECK("body: the bound math matches the frozen wire",
             ZDESC_BODY_MIN == 4 + 62 + 8 + 1 &&
             ZDESC_INTRO_WIRE == 62 + 32 &&
             ZDESC_BODY_MAX == 75 + 8 * 94 &&
             ZDESC_BODY_MAX <= ZID_BODY_MAX);
    /* The size claim the header makes: a signed descriptor fits one
     * blob chunk, and a USABLE one (>= 1 introduction point, since a
     * descriptor with none names no way to reach the service) is
     * already over the 223-byte OP_RETURN relay cap. */
    ZD_CHECK("body: signed doc fits a blob and never an OP_RETURN",
             51 + ZDESC_BODY_MAX + 64 == 942 &&
             942 <= (int)VCS_BLOB_MAX_BYTES &&
             51 + ZDESC_BODY_MIN + ZDESC_INTRO_WIRE + 64 == 284 &&
             284 > 223);

    int rt_bad = 0;
    for (uint8_t count = 0; count <= ZDESC_INTRO_MAX; count++) {
        struct zdesc in, out;
        zd_make_desc(&in, count, ZD_GOLDEN_NOT_BEFORE);
        size_t n = zdesc_encode_body(body, sizeof(body), &in);
        bool ok = n == (size_t)ZDESC_BODY_MIN +
                       (size_t)count * (size_t)ZDESC_INTRO_WIRE &&
                  zdesc_decode_body(&out, body, (uint16_t)n) &&
                  zd_desc_eq(&in, &out);
        if (!ok) {
            printf("  zdesc: body: round-trip at intro_count=%u... FAIL\n",
                   count);
            rt_bad++;
        }
    }
    ZD_CHECK("body: round-trips at every intro_count 0..MAX", rt_bad == 0);

    /* Negatives: log noise is expected, so mute the log floor. */
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    struct zdesc in, out;
    zd_make_desc(&in, 2, ZD_GOLDEN_NOT_BEFORE);
    size_t n = zdesc_encode_body(body, sizeof(body), &in);

    uint8_t tmp[ZDESC_BODY_MAX + 8];
    memcpy(tmp, body, n);
    tmp[0] = 'X';
    ZD_CHECK("body: bad tag is refused",
             !zdesc_decode_body(&out, tmp, (uint16_t)n));

    ZD_CHECK("body: one byte short is refused",
             !zdesc_decode_body(&out, body, (uint16_t)(n - 1)));
    ZD_CHECK("body: one trailing byte is refused (no slack)",
             !zdesc_decode_body(&out, body, (uint16_t)(n + 1)));
    ZD_CHECK("body: a length below the minimum is refused",
             !zdesc_decode_body(&out, body, (uint16_t)(ZDESC_BODY_MIN - 1)));

    memcpy(tmp, body, n);
    tmp[4 + ZDESC_ONION_LEN + 8] = ZDESC_INTRO_MAX + 1;
    ZD_CHECK("body: intro_count over the max is refused",
             !zdesc_decode_body(&out, tmp, (uint16_t)n));

    memcpy(tmp, body, n);
    tmp[4 + ZDESC_ONION_LEN + 8] = 1; /* declares 1, length says 2 */
    ZD_CHECK("body: intro_count disagreeing with the length is refused",
             !zdesc_decode_body(&out, tmp, (uint16_t)n));

    memcpy(tmp, body, n);
    tmp[6] = '0'; /* out-of-alphabet char in the service hostname */
    ZD_CHECK("body: a bad service hostname is refused after copy",
             !zdesc_decode_body(&out, tmp, (uint16_t)n));

    memcpy(tmp, body, n);
    tmp[ZDESC_BODY_MIN + 3] = '\x01'; /* control byte in intro 0's host */
    ZD_CHECK("body: a bad introduction-point hostname is refused",
             !zdesc_decode_body(&out, tmp, (uint16_t)n));

    ZD_CHECK("body: NULL args are refused",
             !zdesc_decode_body(NULL, body, (uint16_t)n) &&
             !zdesc_decode_body(&out, NULL, (uint16_t)n) &&
             zdesc_encode_body(NULL, sizeof(body), &in) == 0 &&
             zdesc_encode_body(body, sizeof(body), NULL) == 0);

    ZD_CHECK("body: an undersized encode buffer is refused",
             zdesc_encode_body(body, n - 1, &in) == 0);

    struct zdesc bad;
    zd_make_desc(&bad, 1, ZD_GOLDEN_NOT_BEFORE);
    bad.onion[0] = '9';
    ZD_CHECK("body: encoding a bad service hostname is refused",
             zdesc_encode_body(body, sizeof(body), &bad) == 0);
    zd_make_desc(&bad, 1, ZD_GOLDEN_NOT_BEFORE);
    bad.intro[0].onion[0] = '9';
    ZD_CHECK("body: encoding a bad intro hostname is refused",
             zdesc_encode_body(body, sizeof(body), &bad) == 0);
    zd_make_desc(&bad, 1, ZD_GOLDEN_NOT_BEFORE);
    bad.intro_count = ZDESC_INTRO_MAX + 1;
    ZD_CHECK("body: encoding intro_count over the max is refused",
             zdesc_encode_body(body, sizeof(body), &bad) == 0);

    zcl_log_level_set(saved);
    return failures;
}

/* ── 4: FROZEN GOLDEN VECTORS ───────────────────────────────────── */

static int zd_case_golden(void)
{
    int failures = 0;

    /* (a) The body bytes, built BY HAND straight from the frozen wire
     * in zid/zdesc.h — a second, independent construction. */
    struct zdesc d;
    zd_make_desc(&d, 1, ZD_GOLDEN_NOT_BEFORE);

    uint8_t hand[ZDESC_BODY_MIN + ZDESC_INTRO_WIRE];
    size_t at = 0;
    memcpy(hand + at, "ZIDD", 4);              at += 4;
    memcpy(hand + at, ZD_SERVICE_ONION, 62);   at += 62;
    zd_put_le64(hand + at, ZD_GOLDEN_NOT_BEFORE); at += 8;
    hand[at++] = 1;
    {
        struct zdesc_intro i0;
        zd_make_intro(&i0, 0);
        memcpy(hand + at, i0.onion, 62);       at += 62;
        memcpy(hand + at, i0.auth_key, 32);    at += 32;
    }

    uint8_t body[ZDESC_BODY_MAX];
    size_t n = zdesc_encode_body(body, sizeof(body), &d);
    ZD_CHECK("golden: encoded body equals the hand-built wire",
             n == at && n == sizeof(hand) && memcmp(body, hand, n) == 0);

    uint8_t digest[32];
    char digest_hex[65];
    sha3_256(body, n, digest);
    zd_hex(digest, 32, digest_hex);
    printf("  zdesc: golden body sha3 = %s\n", digest_hex);
    ZD_CHECK("golden: FROZEN body digest holds",
             strcmp(digest_hex, ZD_GOLDEN_BODY_SHA3) == 0);

    /* (b) The period derivation — a whole UTC day. */
    ZD_CHECK("golden: period is floor(unix/86400)",
             zdesc_period_at(ZD_GOLDEN_NOT_BEFORE) == ZD_GOLDEN_PERIOD &&
             zdesc_period_at(0) == 0 &&
             zdesc_period_at(ZDESC_PERIOD_SECONDS - 1) == 0 &&
             zdesc_period_at(ZDESC_PERIOD_SECONDS) == 1);
    ZD_CHECK("golden: the period boundary is exact",
             zdesc_period_at(ZD_GOLDEN_PERIOD * ZDESC_PERIOD_SECONDS) ==
                 ZD_GOLDEN_PERIOD &&
             zdesc_period_at(ZD_GOLDEN_PERIOD * ZDESC_PERIOD_SECONDS - 1) ==
                 ZD_GOLDEN_PERIOD - 1);
    ZD_CHECK("golden: period_prev steps back and floors at 0",
             zdesc_period_prev(ZD_GOLDEN_PERIOD) == ZD_GOLDEN_PERIOD - 1 &&
             zdesc_period_prev(1) == 0 && zdesc_period_prev(0) == 0);

    /* (c) The blinded record key, checked against a hand-built
     * "ZIDB" ‖ pk ‖ period_le64 preimage hashed directly. This pins the
     * DERIVATION: a changed tag, a changed field order, or big-endian
     * period bytes all fail here. */
    uint8_t seed[32], pk[32], sk[32];
    for (size_t i = 0; i < 32; i++)
        seed[i] = (uint8_t)(0x11u + i);
    ed25519_keypair(pk, sk, seed);

    uint8_t preimage[4 + 32 + 8];
    memcpy(preimage, "ZIDB", 4);
    memcpy(preimage + 4, pk, 32);
    zd_put_le64(preimage + 36, ZD_GOLDEN_PERIOD);
    uint8_t want_key[32], got_key[32];
    sha3_256(preimage, sizeof(preimage), want_key);
    zdesc_record_key(got_key, pk, ZD_GOLDEN_PERIOD);
    char key_hex[65];
    zd_hex(got_key, 32, key_hex);
    printf("  zdesc: golden record key = %s\n", key_hex);
    ZD_CHECK("golden: record key is SHA3(\"ZIDB\" | pk | period_le64)",
             memcmp(got_key, want_key, 32) == 0);

    /* Anti-enumeration in one assertion: the record key must not be the
     * master key, and it must change every period. */
    uint8_t next_key[32];
    zdesc_record_key(next_key, pk, ZD_GOLDEN_PERIOD + 1);
    ZD_CHECK("golden: the record key hides the master key and rotates",
             memcmp(got_key, pk, 32) != 0 &&
             memcmp(got_key, next_key, 32) != 0);

    /* The record key is also identity-separating: a different master
     * key at the same period addresses a different record. */
    uint8_t pk2[32], sk2[32], seed2[32], other_key[32];
    memset(seed2, 0x5a, sizeof(seed2));
    ed25519_keypair(pk2, sk2, seed2);
    zdesc_record_key(other_key, pk2, ZD_GOLDEN_PERIOD);
    ZD_CHECK("golden: a different identity gets a different record key",
             memcmp(got_key, other_key, 32) != 0);
    return failures;
}

/* ── 5-10: publish / fetch / accept over a real store ───────────── */

struct zd_fixture {
    char datadir[512];
    struct vcs_package_store *store;
    struct zdesc_directory dir;
    uint8_t seed[32], pk[32], sk[32];
};

static bool zd_fixture_open(struct zd_fixture *f, const char *tag,
                            uint8_t seed_byte)
{
    memset(f, 0, sizeof(*f));
    test_make_tmpdir(f->datadir, sizeof(f->datadir), "zdesc", tag);
    f->store = vcs_package_store_open(f->datadir,
                                      VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    zdesc_directory_init(&f->dir);
    memset(f->seed, seed_byte, sizeof(f->seed));
    ed25519_keypair(f->pk, f->sk, f->seed);
    return f->store != NULL;
}

static void zd_fixture_close(struct zd_fixture *f)
{
    if (f->store)
        vcs_package_store_close(f->store);
    f->store = NULL;
    test_rm_rf(f->datadir);
}

static int zd_case_publish_fetch(void)
{
    int failures = 0;
    struct zd_fixture f;
    ZD_CHECK("e2e: store opens", zd_fixture_open(&f, "e2e", 0x21));
    if (!f.store)
        return failures;

    /* Both times sit inside ONE period, so a window failure below is
     * unambiguously the doc's expiry and never period addressing. */
    const uint64_t now = ZD_GOLDEN_NOT_BEFORE + 3600;
    const uint64_t expiry = ZD_GOLDEN_NOT_BEFORE + 7200;

    struct zdesc pub;
    zd_make_desc(&pub, 3, ZD_GOLDEN_NOT_BEFORE);

    uint8_t root[32], out_pk[32];
    enum zdesc_result r = zdesc_publish_to(f.store, &f.dir, &pub, 7, expiry,
                                           f.seed, now, root, out_pk);
    ZD_CHECK("e2e: publish succeeds", r == ZDESC_OK);
    ZD_CHECK("e2e: publish reports the signing identity",
             memcmp(out_pk, f.pk, 32) == 0);

    /* The record is addressed by the BLINDED key for the period, and
     * the directory index agrees with an independent derivation. */
    uint8_t want_key[32];
    zdesc_record_key(want_key, f.pk, zdesc_period_at(now));
    const struct zdesc_entry *entry = NULL;
    ZD_CHECK("e2e: the record is indexed under the blinded key",
             zdesc_directory_lookup(&f.dir, want_key, &entry) &&
             entry != NULL && memcmp(entry->root, root, 32) == 0 &&
             entry->period == zdesc_period_at(now));

    /* The blob root is the CONTENT's: derivable from the doc bytes
     * alone, with no store involved. */
    struct zid_doc doc;
    ZD_CHECK("e2e: the doc verifies as a descriptor",
             entry && zdesc_verify(&entry->doc, NULL, now));
    if (entry)
        doc = entry->doc;
    else
        memset(&doc, 0, sizeof(doc));
    uint8_t wire[ZID_DOC_MAX];
    size_t wire_len = zid_doc_encode(wire, sizeof(wire), &doc);
    uint8_t pure_root[32];
    ZD_CHECK("e2e: the blob root is a pure function of the doc bytes",
             wire_len > 0 &&
             vcs_blob_root_of(wire, wire_len, pure_root) == VCS_BLOB_OK &&
             memcmp(pure_root, root, 32) == 0);
    ZD_CHECK("e2e: the signed doc really is under one blob chunk",
             wire_len <= (size_t)VCS_BLOB_MAX_BYTES && wire_len > 223);

    struct zdesc got;
    memset(&got, 0, sizeof(got));
    r = zdesc_fetch_from(f.store, &f.dir, f.pk, now, &got);
    ZD_CHECK("e2e: fetch resolves and verifies from the stored bytes",
             r == ZDESC_OK && zd_desc_eq(&pub, &got));

    /* ── tamper + key mismatch ── */
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    uint8_t bad_wire[ZID_DOC_MAX];
    memcpy(bad_wire, wire, wire_len);
    bad_wire[60] ^= 0x01; /* inside the signed body */
    struct zdesc_directory tdir;
    zdesc_directory_init(&tdir);
    ZD_CHECK("tamper: a flipped body byte fails verification",
             zdesc_accept(&tdir, f.pk, bad_wire, wire_len, now, NULL) ==
                 ZDESC_ERR_VERIFY);

    memcpy(bad_wire, wire, wire_len);
    bad_wire[wire_len - 1] ^= 0x01; /* inside the signature */
    ZD_CHECK("tamper: a flipped signature byte fails verification",
             zdesc_accept(&tdir, f.pk, bad_wire, wire_len, now, NULL) ==
                 ZDESC_ERR_VERIFY);

    uint8_t other_pk[32], other_sk[32], other_seed[32];
    memset(other_seed, 0x77, sizeof(other_seed));
    ed25519_keypair(other_pk, other_sk, other_seed);
    ZD_CHECK("key: verifying against another identity is refused by name",
             zdesc_accept(&tdir, other_pk, wire, wire_len, now, NULL) ==
                 ZDESC_ERR_KEY_MISMATCH);
    ZD_CHECK("key: fetching under an unknown identity is absent",
             zdesc_fetch_from(f.store, &f.dir, other_pk, now, NULL) ==
                 ZDESC_ERR_ABSENT);

    /* ── validity window ── */
    ZD_CHECK("window: at/after expiry is refused (same period)",
             zdesc_period_at(expiry) == zdesc_period_at(now) &&
             zdesc_fetch_from(f.store, &f.dir, f.pk, expiry, NULL) ==
                 ZDESC_ERR_VERIFY &&
             zdesc_fetch_from(f.store, &f.dir, f.pk, expiry + 1, NULL) ==
                 ZDESC_ERR_VERIFY);
    /* Before not_before the signature and expiry both hold, so the
     * refusal must come from the BODY's window, not the doc's. */
    ZD_CHECK("window: before not_before is refused",
             zdesc_accept(&tdir, f.pk, wire, wire_len,
                          ZD_GOLDEN_NOT_BEFORE - 1, NULL) == ZDESC_ERR_BODY);
    ZD_CHECK("window: exactly at not_before is accepted",
             zdesc_accept(&tdir, f.pk, wire, wire_len, ZD_GOLDEN_NOT_BEFORE,
                          NULL) == ZDESC_OK);

    /* A window that never opens is refused at SIGN time. */
    struct zid_doc junk;
    ZD_CHECK("window: expiry <= not_before is refused at sign",
             !zdesc_sign(&junk, &pub, 1, ZD_GOLDEN_NOT_BEFORE, f.seed) &&
             !zdesc_sign(&junk, &pub, 1, ZD_GOLDEN_NOT_BEFORE - 1, f.seed));

    /* ── replay: a lower or equal seq can never displace seq 7 ── */
    struct zdesc old_desc;
    zd_make_desc(&old_desc, 1, ZD_GOLDEN_NOT_BEFORE);
    struct zid_doc old_doc, same_doc;
    uint8_t old_wire[ZID_DOC_MAX], same_wire[ZID_DOC_MAX];
    size_t old_len = 0, same_len = 0;
    if (zdesc_sign(&old_doc, &old_desc, 4, expiry, f.seed))
        old_len = zid_doc_encode(old_wire, sizeof(old_wire), &old_doc);
    if (zdesc_sign(&same_doc, &old_desc, 7, expiry, f.seed))
        same_len = zid_doc_encode(same_wire, sizeof(same_wire), &same_doc);

    ZD_CHECK("replay: a lower seq is refused STALE",
             old_len > 0 &&
             zdesc_accept(&f.dir, f.pk, old_wire, old_len, now, NULL) ==
                 ZDESC_ERR_STALE);
    ZD_CHECK("replay: an equal seq is refused STALE",
             same_len > 0 &&
             zdesc_accept(&f.dir, f.pk, same_wire, same_len, now, NULL) ==
                 ZDESC_ERR_STALE);
    entry = NULL;
    ZD_CHECK("replay: the directory still holds seq 7",
             zdesc_directory_find(&f.dir, f.pk, &entry) && entry &&
             entry->doc.seq == 7 && entry->desc.intro_count == 3);
    ZD_CHECK("replay: a refused publish leaves the held descriptor alone",
             zdesc_publish_to(f.store, &f.dir, &old_desc, 6, expiry, f.seed,
                              now, NULL, NULL) == ZDESC_ERR_STALE &&
             zdesc_fetch_from(f.store, &f.dir, f.pk, now, &got) == ZDESC_OK &&
             got.intro_count == 3);

    /* A strictly higher seq DOES rotate — for free, no transaction. */
    struct zdesc rotated;
    zd_make_desc(&rotated, 5, ZD_GOLDEN_NOT_BEFORE);
    ZD_CHECK("rotate: a higher seq replaces the descriptor",
             zdesc_publish_to(f.store, &f.dir, &rotated, 8, expiry, f.seed,
                              now, NULL, NULL) == ZDESC_OK &&
             zdesc_fetch_from(f.store, &f.dir, f.pk, now, &got) == ZDESC_OK &&
             got.intro_count == 5);

    zcl_log_level_set(saved);
    zd_fixture_close(&f);
    return failures;
}

/* ── 9: the period boundary (previous-period fallback) ──────────── */

static int zd_case_period_boundary(void)
{
    int failures = 0;
    struct zd_fixture f;
    ZD_CHECK("boundary: store opens", zd_fixture_open(&f, "period", 0x33));
    if (!f.store)
        return failures;

    /* Publish 60 s before a period rollover, resolve 60 s after it. */
    const uint64_t roll = ZD_GOLDEN_PERIOD * ZDESC_PERIOD_SECONDS;
    const uint64_t before = roll - 60;
    const uint64_t after = roll + 60;

    struct zdesc pub;
    zd_make_desc(&pub, 2, before - 3600);
    ZD_CHECK("boundary: published in the previous period",
             zdesc_publish_to(f.store, &f.dir, &pub, 1, roll + 7 * 86400,
                              f.seed, before, NULL, NULL) == ZDESC_OK &&
             zdesc_period_at(before) == ZD_GOLDEN_PERIOD - 1 &&
             zdesc_period_at(after) == ZD_GOLDEN_PERIOD);

    struct zdesc got;
    ZD_CHECK("boundary: still resolves after the rollover",
             zdesc_fetch_from(f.store, &f.dir, f.pk, after, &got) ==
                 ZDESC_OK && zd_desc_eq(&pub, &got));

    /* Two periods on, the record is no longer addressable — the
     * publisher must republish, exactly as the header states. */
    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    ZD_CHECK("boundary: two periods on it is absent, by name",
             zdesc_fetch_from(f.store, &f.dir, f.pk,
                              roll + 2 * ZDESC_PERIOD_SECONDS, NULL) ==
                 ZDESC_ERR_ABSENT);
    zcl_log_level_set(saved);

    zd_fixture_close(&f);
    return failures;
}

/* ── 10: the discovery projection ───────────────────────────────── */

static int zd_case_discovery_projection(void)
{
    int failures = 0;
    struct zd_fixture f;
    ZD_CHECK("discovery: store opens", zd_fixture_open(&f, "discover", 0x44));
    if (!f.store)
        return failures;

    const uint64_t now = ZD_GOLDEN_NOT_BEFORE + 3600;
    const uint64_t expiry = ZD_GOLDEN_NOT_BEFORE + 86400;
    struct zdesc pub;
    zd_make_desc(&pub, 1, ZD_GOLDEN_NOT_BEFORE);

    char hosts[4][ZDESC_ONION_LEN + 1];
    ZD_CHECK("discovery: an empty directory yields nothing",
             zdesc_directory_onions(&f.dir, now, hosts, 4) == 0);

    ZD_CHECK("discovery: publish then list the service hostname",
             zdesc_publish_to(f.store, &f.dir, &pub, 1, expiry, f.seed, now,
                              NULL, NULL) == ZDESC_OK &&
             zdesc_directory_onions(&f.dir, now, hosts, 4) == 1 &&
             strcmp(hosts[0], ZD_SERVICE_ONION) == 0);

    ZD_CHECK("discovery: an entry past its expiry is skipped",
             zdesc_directory_onions(&f.dir, expiry, hosts, 4) == 0 &&
             zdesc_directory_onions(&f.dir, expiry + 99999, hosts, 4) == 0);
    ZD_CHECK("discovery: an entry before not_before is skipped",
             zdesc_directory_onions(&f.dir, ZD_GOLDEN_NOT_BEFORE - 1, hosts,
                                    4) == 0);

    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    ZD_CHECK("discovery: NULL args and zero capacity yield nothing",
             zdesc_directory_onions(NULL, now, hosts, 4) == 0 &&
             zdesc_directory_onions(&f.dir, now, hosts, 0) == 0);
    ZD_CHECK("discovery: swarm fetch refuses a NULL engine",
             zdesc_swarm_fetch(NULL, &f.dir, f.pk, 0, now) == ZDESC_ERR_NULL);
    ZD_CHECK("discovery: publish/accept/fetch refuse NULL arguments",
             zdesc_publish_to(NULL, &f.dir, &pub, 1, expiry, f.seed, now,
                              NULL, NULL) == ZDESC_ERR_NULL &&
             zdesc_accept(NULL, f.pk, NULL, 0, now, NULL) == ZDESC_ERR_NULL &&
             zdesc_fetch_from(NULL, &f.dir, f.pk, now, NULL) ==
                 ZDESC_ERR_NULL);
    struct zdesc bad_host;
    zd_make_desc(&bad_host, 0, ZD_GOLDEN_NOT_BEFORE);
    bad_host.onion[0] = '9';
    ZD_CHECK("discovery: a non-onion service hostname is refused at publish",
             zdesc_publish_to(f.store, &f.dir, &bad_host, 99, expiry, f.seed,
                              now, NULL, NULL) == ZDESC_ERR_ONION);
    ZD_CHECK("discovery: every result code has a name",
             strcmp(zdesc_result_string(ZDESC_OK), "ok") == 0 &&
             strcmp(zdesc_result_string(ZDESC_ERR_STALE), "unknown") != 0 &&
             strcmp(zdesc_result_string(ZDESC_ERR_KEY_MISMATCH),
                    "unknown") != 0);
    zcl_log_level_set(saved);

    zd_fixture_close(&f);
    return failures;
}

int test_zdesc(void)
{
    int failures = 0;
    printf("\n=== ZDESC: signed onion-service descriptors ===\n");
    printf("  (verified against a SUPPLIED master key — not chain-anchored)\n");
    failures += zd_case_onion_rule();
    failures += zd_case_body_codec();
    failures += zd_case_golden();
    failures += zd_case_publish_fetch();
    failures += zd_case_period_boundary();
    failures += zd_case_discovery_projection();
    printf("=== ZDESC: %d failure(s) ===\n", failures);
    return failures;
}
