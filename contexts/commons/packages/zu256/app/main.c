/* zu256 CLI: 256-bit unsigned arithmetic over hex or decimal args.
 *
 *   zu256 add|sub|mul A B     prints modular result (hex)
 *   zu256 div|mod A B         prints quotient / remainder
 *   zu256 shl|shr A N         prints shifted value
 *   zu256 dec A               prints decimal form
 *   zu256 hex A               prints canonical hex form
 *
 * A/B accept 0x-prefixed hex or plain decimal.
 */
#include "zu256/zu256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static int parse_shift(const char *text, unsigned *shift)
{
    const char *sign = text;
    while (isspace((unsigned char)*sign)) sign++;
    bool negative = *sign == '-';
    errno = 0;
    char *end;
    unsigned long long n = strtoull(text, &end, 10);
    if (end == text || *end || errno == ERANGE || (negative && n != 0))
        return 0;
    *shift = (unsigned)(n >= 256 ? 256 : n);
    return 1;
}

static int parse(const char *s, zu256256 *out)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return zu256_from_hex(s, out);
    /* plain hex if it has hex letters, else decimal */
    if (strpbrk(s, "abcdefABCDEF")) return zu256_from_hex(s, out);
    return zu256_from_dec(s, out);
}

static int finish_output(int written)
{
    if (written < 0 || fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "zu256: output write failed\n");
        return 1;
    }
    return 0;
}

static int show(zu256256 v)
{
    char h[65];
    zu256_to_hex(v, h);
    return finish_output(printf("0x%s\n", h));
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
            "usage: zu256 add|sub|mul|div|mod A B | shl|shr A N | dec|hex A\n");
        return 2;
    }
    zu256256 a, b;
    if (!parse(argv[2], &a)) {
        fprintf(stderr, "zu256: bad number %s\n", argv[2]);
        return 2;
    }
    if (strcmp(argv[1], "dec") == 0) {
        char buf[80];
        if (!zu256_to_dec(a, buf, sizeof buf)) return 1;
        return finish_output(puts(buf));
    }
    if (strcmp(argv[1], "hex") == 0) {
        return show(a);
    }
    if (argc < 4) {
        fprintf(stderr, "zu256: missing operand\n");
        return 2;
    }
    if (strcmp(argv[1], "shl") == 0 || strcmp(argv[1], "shr") == 0) {
        unsigned n;
        if (!parse_shift(argv[3], &n)) {
            fprintf(stderr, "zu256: shift count must be a nonnegative decimal within unsigned long long range\n");
            return 2;
        }
        return show(argv[1][2] == 'l' ? zu256_shl(a, n) : zu256_shr(a, n));
    }
    if (!parse(argv[3], &b)) {
        fprintf(stderr, "zu256: bad number %s\n", argv[3]);
        return 2;
    }
    if (strcmp(argv[1], "add") == 0) return show(zu256_add(a, b, NULL));
    else if (strcmp(argv[1], "sub") == 0) return show(zu256_sub(a, b, NULL));
    else if (strcmp(argv[1], "mul") == 0) return show(zu256_mul(a, b, NULL));
    else if (strcmp(argv[1], "div") == 0 || strcmp(argv[1], "mod") == 0) {
        zu256256 q, r;
        if (!zu256_divmod(a, b, &q, &r)) {
            fprintf(stderr, "zu256: division by zero\n");
            return 1;
        }
        return show(strcmp(argv[1], "div") == 0 ? q : r);
    } else {
        fprintf(stderr, "zu256: unknown op %s\n", argv[1]);
        return 2;
    }
}
