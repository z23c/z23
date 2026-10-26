/* zotp CLI: print HOTP codes for a secret and counter range.
 *
 *   zotp SECRET COUNTER [COUNT [DIGITS]]
 *
 * SECRET is ASCII text (use a decoder like zbase32 for base32 secrets
 * from authenticator apps). Prints COUNT consecutive codes starting
 * at COUNTER, one per line. DIGITS defaults to 6.
 */
#include "zotp/zotp.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

static int parse_decimal(const char *text, uint64_t maximum, uint64_t *out)
{
    if (!text[0]) return 0;
    uint64_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        unsigned digit = (unsigned)(*p - '0');
        if (value > maximum / 10 ||
            (value == maximum / 10 && digit > maximum % 10)) return 0;
        value = value * 10 + digit;
    }
    *out = value;
    return 1;
}

static int parse_options(int argc, char **argv, uint64_t *counter,
                          unsigned *count, unsigned *digits)
{
    uint64_t n = 1, d = 6;
    if (!parse_decimal(argv[2], UINT64_MAX, counter) ||
        (argc > 3 && !parse_decimal(argv[3], UINT_MAX, &n)) ||
        (argc > 4 && !parse_decimal(argv[4], ZOTP_MAX_DIGITS, &d)) ||
        d < ZOTP_MIN_DIGITS)
        return 0;
    *count = (unsigned)n;
    *digits = (unsigned)d;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: zotp SECRET COUNTER [COUNT [DIGITS]]\n");
        return 2;
    }
    uint64_t counter;
    unsigned count, digits;
    if (!parse_options(argc, argv, &counter, &count, &digits)) {
        fprintf(stderr, "zotp: invalid decimal counter/count or digits (6..9)\n");
        return 2;
    }
    if (count > 0 && (uint64_t)(count - 1) > UINT64_MAX - counter) {
        fprintf(stderr, "zotp: counter range exceeds UINT64_MAX\n");
        return 2;
    }

    for (unsigned i = 0; i < count; i++) {
        char out[16];
        if (!zotp_hotp(argv[1], strlen(argv[1]), counter + i, digits, out)) {
            fprintf(stderr, "zotp: invalid arguments (digits 6..9)\n");
            return 1;
        }
        printf("%s\n", out);
    }
    return 0;
}
