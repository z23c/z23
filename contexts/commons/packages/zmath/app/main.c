/* zmath CLI: checked arithmetic and number theory from the shell.
 *
 *   zmath add|sub|mul <a> <b>     checked; "overflow" on failure
 *   zmath gcd|lcm <a> <b>
 *   zmath pow <base> <exp>
 *   zmath div-ceil <a> <b>
 *   zmath digits <n>
 */
#include "zmath/zmath.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zmath <add|sub|mul|gcd|lcm|pow|div-ceil|digits> args...\n");
    return 2;
}

static int parse_u64(const char *s, uint64_t *out)
{
    if (!s || !out || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || value > UINT64_MAX)
        return 0;
    *out = (uint64_t)value;
    return 1;
}

static int pow_command(uint64_t a, const char *arg)
{
    uint64_t b, r;
    if (!parse_u64(arg, &b) || b > 1000000) return usage();
    if (!zmath_pow_u64(a, (unsigned)b, &r)) {
        puts("overflow");
        return 1;
    }
    printf("%llu\n", (unsigned long long)r);
    return 0;
}

static int binary_command(const char *op, uint64_t a, uint64_t b)
{
    uint64_t r;

    if (strcmp(op, "add") == 0) {
        if (!zmath_add_u64(a, b, &r)) { puts("overflow"); return 1; }
    } else if (strcmp(op, "sub") == 0) {
        if (!zmath_sub_u64(a, b, &r)) { puts("overflow"); return 1; }
    } else if (strcmp(op, "mul") == 0) {
        if (!zmath_mul_u64(a, b, &r)) { puts("overflow"); return 1; }
    } else if (strcmp(op, "gcd") == 0) {
        r = zmath_gcd(a, b);
    } else if (strcmp(op, "lcm") == 0) {
        if (!zmath_lcm(a, b, &r)) { puts("overflow"); return 1; }
    } else if (strcmp(op, "div-ceil") == 0) {
        if (b == 0) { fprintf(stderr, "zmath: division by zero\n"); return 2; }
        r = zmath_div_ceil_u64(a, b);
    } else {
        return usage();
    }
    printf("%llu\n", (unsigned long long)r);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();
    if (strcmp(argv[1], "digits") == 0) {
        uint64_t a;
        if (!parse_u64(argv[2], &a)) return usage();
        printf("%u\n", zmath_digits_u64(a));
        return 0;
    }
    if (argc < 4) return usage();
    uint64_t a, b;
    if (!parse_u64(argv[2], &a)) return usage();
    if (strcmp(argv[1], "pow") == 0) return pow_command(a, argv[3]);
    if (!parse_u64(argv[3], &b)) return usage();
    return binary_command(argv[1], a, b);
}
