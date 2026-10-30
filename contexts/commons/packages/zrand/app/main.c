/* zrand CLI: deterministic random streams from a seed.
 *
 *   zrand u64 <seed> [count]     print count (default 1) uint64 draws
 *   zrand bounded <seed> <bound> [count]
 *   zrand double <seed> [count]
 *   zrand bytes <seed> <n>       n raw bytes to stdout
 *   zrand shuffle <seed> <item>...   shuffle the arguments
 */
#include "zrand/zrand.h"

#include <errno.h>
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
    if (!ok) return 0;
    *ok = 0;
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno == ERANGE || !end || *end || v > UINT64_MAX) return 0;
    *ok = 1;
    return (uint64_t)v;
}

static int output_failed(void)
{
    fprintf(stderr, "zrand: output write failed\n");
    return 1;
}

static int output_status(void)
{
    return fflush(stdout) == EOF ? output_failed() : 0;
}

static int stream_draws(zrand *r, uint64_t count, int is_double)
{
    for (uint64_t i = 0; i < count; i++) {
        int written = is_double ? printf("%.17g\n", zrand_double(r))
                                : printf("%llu\n", (unsigned long long)zrand_u64(r));
        if (written < 0) return output_failed();
    }
    return output_status();
}

static int stream_bounded(zrand *r, uint64_t bound, uint64_t count)
{
    for (uint64_t i = 0; i < count; i++)
        if (printf("%llu\n", (unsigned long long)zrand_bounded(r, bound)) < 0)
            return output_failed();
    return output_status();
}

static int stream_bytes(zrand *r, uint64_t n)
{
    uint8_t buf[4096];
    uint64_t left = n;
    while (left > 0) {
        size_t chunk = left < sizeof buf ? (size_t)left : sizeof buf;
        zrand_bytes(r, buf, chunk);
        if (fwrite(buf, 1, chunk, stdout) != chunk) return output_failed();
        left -= chunk;
    }
    return output_status();
}

static int stream_shuffle(zrand *r, char **items, int n)
{
    zrand_shuffle(r, items, (size_t)n, sizeof items[0]);
    for (int i = 0; i < n; i++)
        if (puts(items[i]) == EOF) return output_failed();
    return output_status();
}

static int run_draws(int argc, char **argv, zrand *r)
{
    int ok = 0;
    uint64_t count = 1;
    if (argc > 3) {
        count = parse_u64(argv[3], &ok);
        if (!ok || count > 1000000) return usage();
    }
    return stream_draws(r, count, argv[1][0] == 'd');
}

static int run_zrand_bounded(int argc, char **argv, zrand *r)
{
    if (argc < 4) return usage();
    int ok = 0;
    uint64_t bound = parse_u64(argv[3], &ok);
    if (!ok) return usage();
    uint64_t count = 1;
    if (argc > 4) {
        count = parse_u64(argv[4], &ok);
        if (!ok || count > 1000000) return usage();
    }
    return stream_bounded(r, bound, count);
}

static int run_bytes(int argc, char **argv, zrand *r)
{
    if (argc < 4) return usage();
    int ok = 0;
    uint64_t n = parse_u64(argv[3], &ok);
    if (!ok || n > 1u << 24) return usage();
    return stream_bytes(r, n);
}

static int run_shuffle(int argc, char **argv, zrand *r)
{
    if (argc < 4) return usage();
    int n = argc - 3;
    char **items = argv + 3;
    return stream_shuffle(r, items, n);
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();

    int ok = 0;
    uint64_t seed = parse_u64(argv[2], &ok);
    if (!ok) return usage();

    zrand r;
    zrand_seed(&r, seed);

    if (strcmp(argv[1], "u64") == 0 || strcmp(argv[1], "double") == 0)
        return run_draws(argc, argv, &r);

    if (strcmp(argv[1], "bounded") == 0)
        return run_zrand_bounded(argc, argv, &r);

    if (strcmp(argv[1], "bytes") == 0)
        return run_bytes(argc, argv, &r);

    if (strcmp(argv[1], "shuffle") == 0)
        return run_shuffle(argc, argv, &r);

    return usage();
}
