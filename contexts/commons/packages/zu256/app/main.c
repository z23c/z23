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

static int parse(const char *s, zu256256 *out)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return zu256_from_hex(s, out);
    /* plain hex if it has hex letters, else decimal */
    if (strpbrk(s, "abcdefABCDEF")) return zu256_from_hex(s, out);
    return zu256_from_dec(s, out);
}

static void show(zu256256 v)
{
    char h[65];
    zu256_to_hex(v, h);
    printf("0x%s\n", h);
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
        puts(buf);
        return 0;
    }
    if (strcmp(argv[1], "hex") == 0) {
        show(a);
        return 0;
    }
    if (argc < 4) {
        fprintf(stderr, "zu256: missing operand\n");
        return 2;
    }
    if (strcmp(argv[1], "shl") == 0 || strcmp(argv[1], "shr") == 0) {
        char *end = NULL;
        unsigned long n = strtoul(argv[3], &end, 10);
        if (!end || *end) return 2;
        show(argv[1][2] == 'l' ? zu256_shl(a, (unsigned)n)
                               : zu256_shr(a, (unsigned)n));
        return 0;
    }
    if (!parse(argv[3], &b)) {
        fprintf(stderr, "zu256: bad number %s\n", argv[3]);
        return 2;
    }
    char op = argv[1][0];
    if (op == 'a') show(zu256_add(a, b, NULL));
    else if (op == 's') show(zu256_sub(a, b, NULL));
    else if (op == 'm' && argv[1][1] == 'u') show(zu256_mul(a, b, NULL));
    else if (op == 'd' || op == 'm') {
        zu256256 q, r;
        if (!zu256_divmod(a, b, &q, &r)) {
            fprintf(stderr, "zu256: division by zero\n");
            return 1;
        }
        show(op == 'd' ? q : r);
    } else {
        fprintf(stderr, "zu256: unknown op %s\n", argv[1]);
        return 2;
    }
    return 0;
}
