/* zprng demo: print n uniform random numbers from a seed. */
#include "zprng/zprng.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

static int parse_unsigned(const char *s, uint64_t *out)
{
    if (!s || !out || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno == ERANGE || !end || *end || value > UINT64_MAX) return 0;
    *out = (uint64_t)value;
    return 1;
}

static int output_error(void)
{
    fprintf(stderr, "zprng: output write failed\n");
    return 1;
}

int main(int argc, char **argv)
{
    uint64_t seed = 42, requested_count = 5;
    if ((argc > 1 && !parse_unsigned(argv[1], &seed)) ||
        (argc > 2 && !parse_unsigned(argv[2], &requested_count)) ||
        requested_count > ULONG_MAX) {
        fprintf(stderr, "usage: zprng [seed [count]] (unsigned decimal)\n");
        return 2;
    }
    unsigned long count = (unsigned long)requested_count;
    zxoshiro256ss rng;

    zxoshiro256ss_init(&rng, seed);
    for (unsigned long i = 0; i < count; i++) {
        if (printf("%llu\n", (unsigned long long)zxoshiro256ss_next(&rng)) < 0)
            return output_error();
    }
    if (count && (fflush(stdout) != 0 || ferror(stdout))) return output_error();
    return 0;
}
