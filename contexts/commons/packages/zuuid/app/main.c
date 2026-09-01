/* zuuid CLI: generate v4 UUIDs or validate/normalize input.
 *
 *   zuuid new [count]      print count (default 1) random v4 UUIDs
 *   zuuid parse <text>     validate and print canonical form
 *   zuuid nil              print the nil UUID
 *
 * Entropy comes from getrandom(2) via <sys/random.h>, falling back to
 * /dev/urandom.
 */
#include "zuuid/zuuid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

static int os_rng(void *ctx, uint8_t *buf, size_t n)
{
    (void)ctx;
    size_t got = 0;
    while (got < n) {
        ssize_t r = getrandom(buf + got, n - got, 0);
        if (r <= 0) {
            FILE *f = fopen("/dev/urandom", "rb");
            if (!f) return -1;
            size_t ok = fread(buf + got, 1, n - got, f);
            fclose(f);
            if (ok != n - got) return -1;
            return 0;
        }
        got += (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: zuuid <new [count]|parse <text>|nil>\n");
        return 2;
    }

    if (strcmp(argv[1], "nil") == 0) {
        zuuid n = zuuid_nil();
        char s[ZUUID_STR_LEN];
        zuuid_format(&n, s);
        puts(s);
        return 0;
    }

    if (strcmp(argv[1], "new") == 0) {
        long count = 1;
        if (argc > 2) {
            char *end = NULL;
            count = strtol(argv[2], &end, 10);
            if (!end || *end != '\0' || count < 1 || count > 100000) {
                fprintf(stderr, "zuuid: bad count\n");
                return 2;
            }
        }
        for (long i = 0; i < count; i++) {
            zuuid u;
            if (zuuid_generate_v4(&u, os_rng, NULL) != ZUUID_OK) {
                fprintf(stderr, "zuuid: random source failed\n");
                return 1;
            }
            char s[ZUUID_STR_LEN];
            zuuid_format(&u, s);
            puts(s);
        }
        return 0;
    }

    if (strcmp(argv[1], "parse") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: zuuid parse <text>\n");
            return 2;
        }
        zuuid u;
        zuuid_err e = zuuid_parse_lenient(argv[2], &u);
        if (e != ZUUID_OK) {
            fprintf(stderr, "zuuid: %s\n", zuuid_err_str(e));
            return 1;
        }
        char s[ZUUID_STR_LEN];
        zuuid_format(&u, s);
        puts(s);
        return 0;
    }

    fprintf(stderr, "usage: zuuid <new [count]|parse <text>|nil>\n");
    return 2;
}
