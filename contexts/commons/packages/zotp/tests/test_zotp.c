/* zotp tests — RFC 2202 HMAC-SHA1 cases and the RFC 4226 appendix D
 * HOTP table.
 *
 * RFC 2202 provides the HMAC-SHA1 known answers; RFC 4226 appendix D
 * provides the ten HOTP values for the ASCII secret
 * "12345678901234567890" at counters 0..9. Also covered: digit-width
 * rendering, argument validation, and truncation edge offsets.
 */
#include "zotp/zotp.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      failures++;                                                       \
    }                                                                   \
  } while (0)

static void hex_of(const uint8_t *d, size_t n, char *out)
{
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = h[d[i] >> 4];
        out[i * 2 + 1] = h[d[i] & 0xf];
    }
    out[n * 2] = '\0';
}

static void test_hmac_sha1_rfc2202(void)
{
    char got[41];

    /* Case 1: key = 20 x 0x0b, data = "Hi There". */
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    uint8_t d[20];
    zotp_hmac_sha1(key1, sizeof(key1), "Hi There", 8, d);
    hex_of(d, 20, got);
    CHECK(strcmp(got, "b617318655057264e28bc0b6fb378c8ef146be00") == 0);

    /* Case 2: key = "Jefe", data = "what do ya want for nothing?". */
    zotp_hmac_sha1("Jefe", 4, "what do ya want for nothing?", 28, d);
    hex_of(d, 20, got);
    CHECK(strcmp(got, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79") == 0);

    /* Case 6: key = 80 x 0xaa (longer than the block size). */
    uint8_t key6[80];
    memset(key6, 0xaa, sizeof(key6));
    zotp_hmac_sha1(key6, sizeof(key6),
                   "Test Using Larger Than Block-Size Key - Hash Key First",
                   54, d);
    hex_of(d, 20, got);
    CHECK(strcmp(got, "aa4ae5e15272d00e95705637ce8a3b55ed402112") == 0);
}

static void test_hotp_rfc4226_table(void)
{
    /* Appendix D: secret "12345678901234567890" (ASCII). */
    static const char *want[] = {
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489",
    };
    const char *secret = "12345678901234567890";
    for (uint64_t c = 0; c < 10; c++) {
        char out[16];
        CHECK(zotp_hotp(secret, 20, c, 6, out) == 1);
        if (strcmp(out, want[c]) != 0)
            fprintf(stderr, "  counter %llu: got %s, want %s\n",
                    (unsigned long long)c, out, want[c]);
        CHECK(strcmp(out, want[c]) == 0);
    }
}

static void test_digit_widths(void)
{
    const char *secret = "12345678901234567890";
    char out[16];

    /* Same counter, different widths: the wider rendering must end
     * with the narrower one. */
    CHECK(zotp_hotp(secret, 20, 0, 6, out) == 1);
    CHECK(strcmp(out, "755224") == 0);
    CHECK(zotp_hotp(secret, 20, 0, 8, out) == 1);
    CHECK(strlen(out) == 8);
    CHECK(strcmp(out + 2, "755224") == 0);
    CHECK(zotp_hotp(secret, 20, 0, 9, out) == 1);
    CHECK(strlen(out) == 9);
    CHECK(strcmp(out + 3, "755224") == 0);
}

static void test_args(void)
{
    const char *secret = "12345678901234567890";
    char out[16];
    CHECK(zotp_hotp(NULL, 20, 0, 6, out) == 0);
    CHECK(zotp_hotp(secret, 20, 0, 6, NULL) == 0);
    CHECK(zotp_hotp(secret, 20, 0, 5, out) == 0);   /* too few digits */
    CHECK(zotp_hotp(secret, 20, 0, 10, out) == 0);  /* too many */
    CHECK(zotp_hotp(secret, 20, 0, 6, out) == 1);
}

static void test_truncate_offsets(void)
{
    /* Force each of the 16 possible dynamic-truncation offsets and
     * confirm the selected 31-bit window. */
    for (unsigned off = 0; off < 16; off++) {
        uint8_t h[20];
        for (int i = 0; i < 20; i++) h[i] = (uint8_t)(0x80 + i);
        h[19] = (uint8_t)(0x80 | off); /* low nibble selects offset */
        uint32_t v = zotp_truncate(h);
        uint32_t want =
            ((uint32_t)(h[off] & 0x7f) << 24) |
            ((uint32_t)h[off + 1] << 16) |
            ((uint32_t)h[off + 2] << 8) |
            (uint32_t)h[off + 3];
        CHECK(v == want);
        CHECK((v & 0x80000000u) == 0); /* sign bit always cleared */
    }
}

int main(void)
{
    test_hmac_sha1_rfc2202();
    test_hotp_rfc4226_table();
    test_digit_widths();
    test_args();
    test_truncate_offsets();
    if (failures) {
        fprintf(stderr, "zotp: %d failure(s)\n", failures);
        return 1;
    }
    puts("zotp: all tests passed");
    return 0;
}
