/* zrand CLI: deterministic random streams from a seed.
 *
 *   zrand u64 <seed> [count]     print count (default 1) uint64 draws
 *   zrand bounded <seed> <bound> [count]
 *   zrand double <seed> [count]
 *   zrand bytes <seed> <n>       n raw bytes to stdout
 *   zrand shuffle <seed> <item>...   shuffle the arguments
 */
#include "zrand/zrand.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zrand <u64|double> <seed> [count]\n"
        "       zrand bounded <seed> <bound> [count]\n"
        "       zrand bytes <seed> <n>\n"
        "       zrand shuffle <seed> <item>...\n");
    return 2;
}

static uint64_t parse_u64(const char *s, int *ok)
{
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 10);
    *ok = end && *end == '\0';
    return v;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();

    int ok = 0;
    uint64_t seed = parse_u64(argv[2], &ok);
    if (!ok) return usage();

    zrand r;
    zrand_seed(&r, seed);

    if (strcmp(argv[1], "u64") == 0 || strcmp(argv[1], "double") == 0) {
        uint64_t count = 1;
        if (argc > 3) {
            count = parse_u64(argv[3], &ok);
            if (!ok || count > 1000000) return usage();
        }
        int is_double = argv[1][0] == 'd';
        for (uint64_t i = 0; i < count; i++) {
            if (is_double) printf("%.17g\n", zrand_double(&r));
            else printf("%llu\n", (unsigned long long)zrand_u64(&r));
        }
        return 0;
    }

    if (strcmp(argv[1], "bounded") == 0) {
        if (argc < 4) return usage();
        uint64_t bound = parse_u64(argv[3], &ok);
        if (!ok) return usage();
        uint64_t count = 1;
        if (argc > 4) {
            count = parse_u64(argv[4], &ok);
            if (!ok || count > 1000000) return usage();
        }
        for (uint64_t i = 0; i < count; i++)
            printf("%llu\n", (unsigned long long)zrand_bounded(&r, bound));
        return 0;
    }

    if (strcmp(argv[1], "bytes") == 0) {
        if (argc < 4) return usage();
        uint64_t n = parse_u64(argv[3], &ok);
        if (!ok || n > 1u << 24) return usage();
        uint8_t buf[4096];
        uint64_t left = n;
        while (left > 0) {
            size_t chunk = left < sizeof buf ? (size_t)left : sizeof buf;
            zrand_bytes(&r, buf, chunk);
            fwrite(buf, 1, chunk, stdout);
            left -= chunk;
        }
        return 0;
    }

    if (strcmp(argv[1], "shuffle") == 0) {
        if (argc < 4) return usage();
        int n = argc - 3;
        char **items = argv + 3;
        zrand_shuffle(&r, items, (size_t)n, sizeof items[0]);
        for (int i = 0; i < n; i++) puts(items[i]);
        return 0;
    }

    return usage();
}
