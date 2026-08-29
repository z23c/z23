/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * base64url against the RFC 4648 §10 vectors, in the §5 alphabet with
 * padding stripped.
 *
 * This codec is the one piece of ACME vocabulary the NODE itself needs: the
 * TLS-ALPN-01 responder builds a key authorization, and that is a base64url
 * string. Everything else about ACME — the account key, the JWS, the order
 * flow, the trust store — lives in the separate `zclassic23-acme` worker and
 * is proven by its own selftest, which lib/test/src/test_acme_worker.c runs.
 */

#include "test/test_core.h"

#include "net/acme_b64url.h"

#include <stdio.h>
#include <string.h>

#define AB_CHECK(name, expr) do {                    \
    printf("acme_b64url: %s... ", (name));           \
    if (expr) { printf("OK\n"); }                    \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

static bool encodes_to(const char *plain, const char *expected)
{
    char out[64];
    const size_t n = acme_b64url_encode(plain, strlen(plain), out, sizeof(out));
    return n == strlen(expected) && strcmp(out, expected) == 0;
}

int test_acme_b64url(void)
{
    int failures = 0;

    /* ── RFC 4648 §10 vectors, in the §5 alphabet with padding stripped ── */
    AB_CHECK("b64url(\"\") is the empty string", encodes_to("", ""));
    AB_CHECK("b64url(\"f\") == \"Zg\"", encodes_to("f", "Zg"));
    AB_CHECK("b64url(\"fo\") == \"Zm8\"", encodes_to("fo", "Zm8"));
    AB_CHECK("b64url(\"foo\") == \"Zm9v\"", encodes_to("foo", "Zm9v"));
    AB_CHECK("b64url(\"foob\") == \"Zm9vYg\"", encodes_to("foob", "Zm9vYg"));
    AB_CHECK("b64url(\"fooba\") == \"Zm9vYmE\"", encodes_to("fooba", "Zm9vYmE"));
    AB_CHECK("b64url(\"foobar\") == \"Zm9vYmFy\"", encodes_to("foobar", "Zm9vYmFy"));

    /* The two characters that separate §5 from §4. Standard base64 of
     * {0xfb,0xff,0xbf} is "+/+/"; the URL alphabet must produce "-_-_". */
    {
        static const uint8_t bytes[] = {0xfb, 0xff, 0xbf};
        char out[16];
        AB_CHECK("62 and 63 encode as '-' and '_', never '+' and '/'",
                 acme_b64url_encode(bytes, sizeof(bytes), out, sizeof(out)) == 4 &&
                 strcmp(out, "-_-_") == 0);
    }
    {
        char out[16];
        AB_CHECK("no '=' padding is ever emitted",
                 acme_b64url_encode("f", 1, out, sizeof(out)) == 2 &&
                 strchr(out, '=') == NULL);
        /* "foobar" needs 8 characters plus a NUL; 8 bytes of room is one
         * short, and the encoder must refuse rather than drop the last
         * character — a truncated signature is a silently invalid one. */
        AB_CHECK("an output buffer one byte short refuses rather than truncates",
                 acme_b64url_encode("foobar", 6, out, 8) == 0 && out[0] == '\0');
        AB_CHECK("exactly enough room succeeds",
                 acme_b64url_encode("foobar", 6, out, 9) == 8);
    }
    {
        char tiny[3];
        AB_CHECK("a buffer that cannot hold the result plus NUL is refused",
                 acme_b64url_encode("foo", 3, tiny, sizeof(tiny)) == 0 &&
                 tiny[0] == '\0');
    }
    {
        bool agree = true;
        for (size_t i = 0; i <= 8; i++) {
            char out[32];
            const size_t n = acme_b64url_encode("abcdefgh", i, out, sizeof(out));
            if (n != acme_b64url_encoded_len(i) || strlen(out) != n)
                agree = false;
        }
        AB_CHECK("the sizing helper agrees with the encoder for 0..8 bytes", agree);
    }

    /* ── decoding ──────────────────────────────────────────────────── */
    {
        uint8_t buf[16];
        size_t n = 0;
        AB_CHECK("decode round-trips \"Zm9vYmFy\"",
                 acme_b64url_decode("Zm9vYmFy", buf, sizeof(buf), &n) &&
                 n == 6 && memcmp(buf, "foobar", 6) == 0);
        AB_CHECK("decode round-trips an unpadded 2-char group",
                 acme_b64url_decode("Zg", buf, sizeof(buf), &n) &&
                 n == 1 && buf[0] == 'f');
        AB_CHECK("'+' is refused (that is the §4 alphabet)",
                 !acme_b64url_decode("Zm+v", buf, sizeof(buf), &n));
        AB_CHECK("'/' is refused",
                 !acme_b64url_decode("Zm/v", buf, sizeof(buf), &n));
        AB_CHECK("'=' padding is refused",
                 !acme_b64url_decode("Zg==", buf, sizeof(buf), &n));
        AB_CHECK("a length of 1 mod 4 is refused (encodes no whole byte)",
                 !acme_b64url_decode("Zm9vY", buf, sizeof(buf), &n));
        AB_CHECK("a decode that would overflow the buffer is refused",
                 !acme_b64url_decode("Zm9vYmFy", buf, 2, &n));
        AB_CHECK("a non-empty decode requires an output buffer",
                 !acme_b64url_decode("Zg", NULL, 1, &n));
        AB_CHECK("non-canonical two-character pad bits are refused",
                 !acme_b64url_decode("Zh", buf, sizeof(buf), &n));
        AB_CHECK("non-canonical three-character pad bits are refused",
                 !acme_b64url_decode("Zm9", buf, sizeof(buf), &n));
        AB_CHECK("whitespace is refused",
                 !acme_b64url_decode("Zm9v YmFy", buf, sizeof(buf), &n));
    }

    return failures;
}
