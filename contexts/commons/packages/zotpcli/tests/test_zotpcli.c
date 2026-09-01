/* zotpcli tests.
 *
 * Known-answer vectors:
 *  - RFC 4226 "HOTP: An HMAC-Based One-Time Password Algorithm",
 *    Appendix D: secret "12345678901234567890" (20 ASCII bytes),
 *    6 digits, counters 0..9.
 *  - RFC 6238 "TOTP: Time-Based One-Time Password Algorithm",
 *    Appendix B: same secret for SHA-1, 8 digits, 30-second steps,
 *    at the RFC's sample Unix times.
 *
 * Plus: store encode/decode round-trip, tamper detection (flip a byte,
 * MAC verify fails), wrong-passphrase rejection, otpauth:// round-trip,
 * and bad-base32 rejection.
 */
#include "zotpcli/zotpcli.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int cond, const char *name)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static const uint8_t RFC_SECRET[20] = "12345678901234567890";
static const uint8_t TEST_SALT[ZOTPCLI_SALT_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static zotpcli_entry rfc_entry(unsigned digits, unsigned period)
{
    zotpcli_entry e;
    zotpcli_entry_init(&e);
    memcpy(e.label, "rfc", 4);
    memcpy(e.secret, RFC_SECRET, sizeof RFC_SECRET);
    e.secret_len = sizeof RFC_SECRET;
    e.digits = digits;
    e.period = period;
    return e;
}

/* RFC 4226 Appendix D. */
static void test_rfc4226_hotp(void)
{
    static const char *want[10] = {
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489"
    };
    zotpcli_entry e = rfc_entry(6, 30);
    e.kind = ZOTPCLI_HOTP;
    char out[7];
    for (uint64_t c = 0; c < 10; c++) {
        check(zotpcli_hotp_code(&e, c, out) == 1, "rfc4226 rc");
        check(strcmp(out, want[c]) == 0, want[c]);
    }
}

/* RFC 6238 Appendix B (SHA-1 column, 8 digits, X = 30). */
static void test_rfc6238_totp(void)
{
    static const struct {
        int64_t now;
        const char *code;
    } vec[] = {
        { 59,          "94287082" },
        { 1111111109,  "07081804" },
        { 1111111111,  "14050471" },
        { 1234567890,  "89005924" },
        { 2000000000,  "69279037" },
        { 20000000000, "65353130" },
    };
    zotpcli_entry e = rfc_entry(8, 30);
    char out[9];
    for (size_t i = 0; i < sizeof vec / sizeof vec[0]; i++) {
        check(zotpcli_totp_code(&e, vec[i].now, out) == 1, "rfc6238 rc");
        check(strcmp(out, vec[i].code) == 0, vec[i].code);
    }
}

static void test_totp_counter_boundaries(void)
{
    zotpcli_entry e = rfc_entry(6, 30);
    check(zotpcli_totp_counter(&e, 0) == 0, "ctr t=0");
    check(zotpcli_totp_counter(&e, 29) == 0, "ctr t=29");
    check(zotpcli_totp_counter(&e, 30) == 1, "ctr t=30");
    check(zotpcli_totp_counter(&e, 59) == 1, "ctr t=59");
    check(zotpcli_totp_counter(&e, 60) == 2, "ctr t=60");
    check(zotpcli_totp_code(&e, -1, (char[7]){0}) == 0,
          "negative now rejected");
}

static void test_base32(void)
{
    /* "Hello!\xde\xad\xbe\xef" is the RFC 4648-style example secret
     * rendered JBSWY3DPEHPK3PXP. */
    static const uint8_t want[10] = {
        'H', 'e', 'l', 'l', 'o', '!', 0xde, 0xad, 0xbe, 0xef
    };
    uint8_t out[16];
    size_t n = 0;
    check(zotpcli_b32_decode_secret("JBSWY3DPEHPK3PXP", out, sizeof out,
                                    &n) == ZOTPCLI_OK, "b32 rc");
    check(n == sizeof want && memcmp(out, want, n) == 0, "b32 bytes");
    /* lowercase and padded forms decode identically */
    check(zotpcli_b32_decode_secret("jbswy3dpehpk3pxp", out, sizeof out,
                                    &n) == ZOTPCLI_OK &&
          memcmp(out, want, 10) == 0, "b32 lowercase");
    check(zotpcli_b32_decode_secret("MZXW6===", out, sizeof out, &n) ==
              ZOTPCLI_OK &&
          n == 3 && memcmp(out, "foo", 3) == 0, "b32 padded foo");
    check(zotpcli_b32_decode_secret("MZXW6", out, sizeof out, &n) ==
              ZOTPCLI_OK &&
          n == 3 && memcmp(out, "foo", 3) == 0, "b32 unpadded foo");
    /* rejections */
    check(zotpcli_b32_decode_secret("MZXW6!", out, sizeof out, &n) ==
              ZOTPCLI_ERR_SECRET, "b32 bad char");
    check(zotpcli_b32_decode_secret("A", out, sizeof out, &n) ==
              ZOTPCLI_ERR_SECRET, "b32 impossible length");
    check(zotpcli_b32_decode_secret("", out, sizeof out, &n) ==
              ZOTPCLI_ERR_SECRET, "b32 empty");
    /* encode strips padding */
    char enc[32];
    check(zotpcli_b32_encode_secret(want, sizeof want, enc, sizeof enc) ==
              ZOTPCLI_OK &&
          strcmp(enc, "JBSWY3DPEHPK3PXP") == 0, "b32 encode");
}

static void test_otpauth_parse_classic(void)
{
    /* Google Authenticator KeyUriFormat example shape. */
    zotpcli_entry e;
    check(zotpcli_otpauth_parse(
              "otpauth://totp/ACME%20Co:john.doe%40email.com"
              "?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
              "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
              &e) == ZOTPCLI_OK, "uri rc");
    check(strcmp(e.label, "john.doe@email.com") == 0, "uri label");
    check(strcmp(e.issuer, "ACME Co") == 0, "uri issuer");
    check(e.kind == ZOTPCLI_TOTP && e.digits == 6 && e.period == 30,
          "uri params");
    check(e.secret_len == 20, "uri secret len");
}

static void entry_eq(const zotpcli_entry *a, const zotpcli_entry *b,
                     const char *name)
{
    check(strcmp(a->label, b->label) == 0 &&
          strcmp(a->issuer, b->issuer) == 0 &&
          a->secret_len == b->secret_len &&
          memcmp(a->secret, b->secret, a->secret_len) == 0 &&
          a->kind == b->kind && a->digits == b->digits &&
          a->period == b->period && a->counter == b->counter, name);
}

static void test_otpauth_roundtrip(void)
{
    zotpcli_entry e = rfc_entry(8, 45);
    memcpy(e.label, "alice@example.com", sizeof "alice@example.com");
    memcpy(e.issuer, "Example Co", sizeof "Example Co");

    char uri[ZOTPCLI_MAX_URI + 1];
    check(zotpcli_otpauth_format(&e, uri, sizeof uri) == ZOTPCLI_OK,
          "fmt rc");
    check(strstr(uri, "Example%20Co") != NULL, "fmt pct issuer");

    zotpcli_entry back;
    check(zotpcli_otpauth_parse(uri, &back) == ZOTPCLI_OK, "parse rc");
    entry_eq(&e, &back, "uri roundtrip totp");

    e.kind = ZOTPCLI_HOTP;
    e.counter = 42;
    check(zotpcli_otpauth_format(&e, uri, sizeof uri) == ZOTPCLI_OK,
          "fmt hotp rc");
    check(zotpcli_otpauth_parse(uri, &back) == ZOTPCLI_OK,
          "parse hotp rc");
    entry_eq(&e, &back, "uri roundtrip hotp");
}

static void test_otpauth_rejections(void)
{
    zotpcli_entry e;
    check(zotpcli_otpauth_parse(
              "otpauth://totp/x?secret=ABC!", &e) == ZOTPCLI_ERR_SECRET,
          "bad base32 rejected");
    check(zotpcli_otpauth_parse(
              "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
              &e) == ZOTPCLI_ERR_URI, "sha256 algorithm rejected");
    check(zotpcli_otpauth_parse("otpauth://totp/x", &e) ==
              ZOTPCLI_ERR_SECRET, "missing secret rejected");
    check(zotpcli_otpauth_parse(
              "https://totp/x?secret=JBSWY3DPEHPK3PXP", &e) ==
              ZOTPCLI_ERR_URI, "wrong scheme rejected");
    check(zotpcli_otpauth_parse(
              "otpauth://totp/?secret=JBSWY3DPEHPK3PXP", &e) ==
              ZOTPCLI_ERR_URI, "empty label rejected");
    check(zotpcli_otpauth_parse(
              "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&issuer=One"
              "&digits=9",
              &e) == ZOTPCLI_ERR_URI, "bad digits rejected");
}

/* Build a store with one TOTP and one HOTP entry, one with a
 * non-ASCII UTF-8 label. */
static void fill_store(zotpcli_store *s)
{
    zotpcli_entry a = rfc_entry(6, 30);
    memcpy(a.label, "alice", 6);
    memcpy(a.issuer, "Example", 8);

    zotpcli_entry b = rfc_entry(8, 60);
    b.kind = ZOTPCLI_HOTP;
    b.counter = 7;
    memcpy(b.label, "caf\xc3\xa9 \xe2\x98\x95", 9); /* "café ☕" */

    check(zotpcli_store_add(s, &a) == ZOTPCLI_OK, "fill add a");
    check(zotpcli_store_add(s, &b) == ZOTPCLI_OK, "fill add b");
}

static void test_store_roundtrip(void)
{
    zotpcli_store s, back;
    check(zotpcli_store_init(&s) == ZOTPCLI_OK, "rt init s");
    check(zotpcli_store_init(&back) == ZOTPCLI_OK, "rt init back");
    fill_store(&s);

    zbuf buf;
    check(zbuf_init(&buf, ZOTPCLI_MAX_FILE) == ZBUF_OK, "rt buf");
    check(zotpcli_store_encode(&s, "correct horse", TEST_SALT, &buf) ==
              ZOTPCLI_OK, "rt encode");
    check(zotpcli_store_decode(&back, buf.data, zbuf_len(&buf),
                               "correct horse") == ZOTPCLI_OK,
          "rt decode");

    check(zotpcli_store_count(&back) == 2, "rt count");
    entry_eq(zotpcli_store_get(&s, 0), zotpcli_store_get(&back, 0),
             "rt entry 0");
    entry_eq(zotpcli_store_get(&s, 1), zotpcli_store_get(&back, 1),
             "rt entry 1");

    /* codes survive the round trip */
    char c1[9], c2[9];
    const zotpcli_entry *ea = zotpcli_store_find(&s, "alice");
    const zotpcli_entry *eb = zotpcli_store_find(&back, "alice");
    check(ea && eb, "rt find");
    check(zotpcli_totp_code(ea, 1234567890, c1) == 1 &&
          zotpcli_totp_code(eb, 1234567890, c2) == 1 &&
          strcmp(c1, c2) == 0, "rt codes equal");

    zbuf_free(&buf);
    zotpcli_store_free(&s);
    zotpcli_store_free(&back);
}

static void test_tamper_and_wrong_passphrase(void)
{
    zotpcli_store s, back;
    check(zotpcli_store_init(&s) == ZOTPCLI_OK, "tm init s");
    check(zotpcli_store_init(&back) == ZOTPCLI_OK, "tm init back");
    fill_store(&s);

    zbuf buf;
    check(zbuf_init(&buf, ZOTPCLI_MAX_FILE) == ZBUF_OK, "tm buf");
    check(zotpcli_store_encode(&s, "correct horse", TEST_SALT, &buf) ==
              ZOTPCLI_OK, "tm encode");
    size_t len = zbuf_len(&buf);

    /* Flip one byte in the middle of the entry records. */
    buf.data[len / 2] ^= 0x01;
    check(zotpcli_store_decode(&back, buf.data, len, "correct horse") ==
              ZOTPCLI_ERR_MAC, "tampered byte detected");
    buf.data[len / 2] ^= 0x01;

    /* Wrong passphrase stretches to a different MAC key. */
    check(zotpcli_store_decode(&back, buf.data, len, "wrong") ==
              ZOTPCLI_ERR_MAC, "wrong passphrase detected");

    /* Truncation is a format error, not a crash. */
    check(zotpcli_store_decode(&back, buf.data, len - 3,
                               "correct horse") == ZOTPCLI_ERR_FORMAT,
          "truncation rejected");

    zbuf_free(&buf);
    zotpcli_store_free(&s);
    zotpcli_store_free(&back);
}

static void test_no_passphrase(void)
{
    zotpcli_store s, back;
    check(zotpcli_store_init(&s) == ZOTPCLI_OK, "np init s");
    check(zotpcli_store_init(&back) == ZOTPCLI_OK, "np init back");
    fill_store(&s);
    zbuf buf;
    check(zbuf_init(&buf, ZOTPCLI_MAX_FILE) == ZBUF_OK, "np buf");
    check(zotpcli_store_encode(&s, NULL, TEST_SALT, &buf) == ZOTPCLI_OK,
          "np encode");
    check(zotpcli_store_decode(&back, buf.data, zbuf_len(&buf), NULL) ==
              ZOTPCLI_OK, "np decode");
    check(zotpcli_store_count(&back) == 2, "np count");
    zbuf_free(&buf);
    zotpcli_store_free(&s);
    zotpcli_store_free(&back);
}

static void test_label_validation(void)
{
    zotpcli_store s;
    check(zotpcli_store_init(&s) == ZOTPCLI_OK, "lv init");
    zotpcli_entry e = rfc_entry(6, 30);

    e.label[0] = (char)0xff; /* not well-formed UTF-8 */
    e.label[1] = '\0';
    check(zotpcli_store_add(&s, &e) == ZOTPCLI_ERR_LABEL,
          "bad UTF-8 label rejected");
    memcpy(e.label, "dup", 4);
    check(zotpcli_store_add(&s, &e) == ZOTPCLI_OK, "first add");
    check(zotpcli_store_add(&s, &e) == ZOTPCLI_ERR_LABEL,
          "duplicate label rejected");
    e.label[0] = '\0';
    check(zotpcli_store_add(&s, &e) == ZOTPCLI_ERR_LABEL,
          "empty label rejected");
    check(zotpcli_store_remove(&s, "dup"), "remove");
    check(!zotpcli_store_remove(&s, "dup"), "remove absent");
    check(zotpcli_store_count(&s) == 0, "count after remove");
    zotpcli_store_free(&s);
}

static void test_hotp_counter_flow(void)
{
    /* zotpcli_code dispatches HOTP on the entry's own counter. */
    zotpcli_entry e = rfc_entry(6, 30);
    e.kind = ZOTPCLI_HOTP;
    e.counter = 0;
    char out[7];
    check(zotpcli_code(&e, 999999, out) == 1 &&
          strcmp(out, "755224") == 0, "hotp dispatch c=0");
    e.counter = 1;
    check(zotpcli_code(&e, 999999, out) == 1 &&
          strcmp(out, "287082") == 0, "hotp dispatch c=1");
}

int main(void)
{
    test_rfc4226_hotp();
    test_rfc6238_totp();
    test_totp_counter_boundaries();
    test_base32();
    test_otpauth_parse_classic();
    test_otpauth_roundtrip();
    test_otpauth_rejections();
    test_store_roundtrip();
    test_tamper_and_wrong_passphrase();
    test_no_passphrase();
    test_label_validation();
    test_hotp_counter_flow();
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("zotpcli: all tests passed");
    return 0;
}
