/* zhuman CLI: convert between machine and human forms.
 *
 *   zhuman bytes <n>          1536 -> "1.5 KiB"
 *   zhuman bytes --si <n>     1500 -> "1.5 kB"
 *   zhuman parse-bytes <s>    "1.5 KiB" -> 1536
 *   zhuman duration <ms>      90061 -> "1m 30.061s"
 *   zhuman parse-duration <s> "1h30m" -> 5400000
 */
#include "zhuman/zhuman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zhuman bytes [--si] <n>\n"
        "       zhuman parse-bytes <s>\n"
        "       zhuman duration <ms>\n"
        "       zhuman parse-duration <s>\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();

    if (strcmp(argv[1], "bytes") == 0) {
        int si = 0;
        const char *num = argv[2];
        if (argc > 3 && strcmp(argv[2], "--si") == 0) {
            si = 1;
            num = argv[3];
        }
        char *end = NULL;
        uint64_t v = strtoull(num, &end, 10);
        if (!end || *end != '\0') return usage();
        char out[32];
        zhuman_err e = si ? zhuman_format_bytes_si(v, out, sizeof out)
                          : zhuman_format_bytes_iec(v, out, sizeof out);
        if (e != ZHUMAN_OK) {
            fprintf(stderr, "zhuman: %s\n", zhuman_err_str(e));
            return 1;
        }
        puts(out);
        return 0;
    }

    if (strcmp(argv[1], "parse-bytes") == 0) {
        uint64_t v;
        zhuman_err e = zhuman_parse_bytes(argv[2], &v);
        if (e != ZHUMAN_OK) {
            fprintf(stderr, "zhuman: %s\n", zhuman_err_str(e));
            return 1;
        }
        printf("%llu\n", (unsigned long long)v);
        return 0;
    }

    if (strcmp(argv[1], "duration") == 0) {
        char *end = NULL;
        uint64_t ms = strtoull(argv[2], &end, 10);
        if (!end || *end != '\0') return usage();
        char out[64];
        zhuman_err e = zhuman_format_duration(ms, out, sizeof out);
        if (e != ZHUMAN_OK) {
            fprintf(stderr, "zhuman: %s\n", zhuman_err_str(e));
            return 1;
        }
        puts(out);
        return 0;
    }

    if (strcmp(argv[1], "parse-duration") == 0) {
        uint64_t ms;
        zhuman_err e = zhuman_parse_duration(argv[2], &ms);
        if (e != ZHUMAN_OK) {
            fprintf(stderr, "zhuman: %s\n", zhuman_err_str(e));
            return 1;
        }
        printf("%llu\n", (unsigned long long)ms);
        return 0;
    }

    return usage();
}
