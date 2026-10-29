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

static int binary_command(const char *op, zu256256 a, zu256256 b)
{
    if (strcmp(op, "add") == 0) return show(zu256_add(a, b, NULL));
    else if (strcmp(op, "sub") == 0) return show(zu256_sub(a, b, NULL));
    else if (strcmp(op, "mul") == 0) return show(zu256_mul(a, b, NULL));
    else if (strcmp(op, "div") == 0 || strcmp(op, "mod") == 0) {
        zu256256 q, r;
        if (!zu256_divmod(a, b, &q, &r)) {
            fprintf(stderr, "zu256: division by zero\n");
            return 1;
        }
        return show(strcmp(op, "div") == 0 ? q : r);
    } else {
        fprintf(stderr, "zu256: unknown op %s\n", op);
        return 2;
    }
}

/* A known op given more operands than it takes is refused only after its own
   operand checks pass, so every older error keeps its precedence. */
static bool surplus(int argc, char **argv, int want)
{
    if (argc <= want) return false;
    fprintf(stderr, "zu256: %s expects %d operand%s\n", argv[1], want - 2,
            want == 3 ? "" : "s");
    return true;
}

static bool known_binary(const char *op)
{
    static const char *const ops[] = {"add", "sub", "mul", "div", "mod"};
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        if (strcmp(op, ops[i]) == 0) return true;
    }
    return false;
}

static int unary_command(int argc, char **argv, zu256256 a)
{
    if (surplus(argc, argv, 3)) return 2;
    if (strcmp(argv[1], "hex") == 0) return show(a);
    char buf[80];
    if (!zu256_to_dec(a, buf, sizeof buf)) return 1;
    return finish_output(puts(buf));
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
    if (strcmp(argv[1], "dec") == 0 || strcmp(argv[1], "hex") == 0)
        return unary_command(argc, argv, a);
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
        if (surplus(argc, argv, 4)) return 2;
        return show(argv[1][2] == 'l' ? zu256_shl(a, n) : zu256_shr(a, n));
    }
    if (!parse(argv[3], &b)) {
        fprintf(stderr, "zu256: bad number %s\n", argv[3]);
        return 2;
    }
    if (known_binary(argv[1]) && surplus(argc, argv, 4)) return 2;
    return binary_command(argv[1], a, b);
}
