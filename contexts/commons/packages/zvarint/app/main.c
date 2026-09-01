/* zvarint CLI: encode/decode decimal integers as LEB128 varints.
 *
 *   zvarint enc <n>...       unsigned decimal -> hex bytes
 *   zvarint encs <n>...      signed decimal (zigzag) -> hex bytes
 *   zvarint dec <hex>        decode a stream of unsigned varints
 *   zvarint decs <hex>       decode a stream of signed varints
 */
#include "zvarint/zvarint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int usage(void)
{
    fprintf(stderr, "usage: zvarint <enc|encs> <n>... | <dec|decs> <hex>\n");
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();

    int sign = 0;
    if (strcmp(argv[1], "enc") == 0 || strcmp(argv[1], "encs") == 0) {
        sign = argv[1][3] == 's';
        for (int i = 2; i < argc; i++) {
            char *end = NULL;
            uint8_t buf[ZVARINT_MAX_LEN];
            size_t n = 0;
            zvarint_err e;
            if (sign) {
                int64_t s = strtoll(argv[i], &end, 10);
                if (!end || *end != '\0') return usage();
                e = zvarint_encode_i64(s, buf, sizeof buf, &n);
            } else {
                uint64_t v = strtoull(argv[i], &end, 10);
                if (!end || *end != '\0') return usage();
                e = zvarint_encode_u64(v, buf, sizeof buf, &n);
            }
            if (e != ZVARINT_OK) {
                fprintf(stderr, "zvarint: %s\n", zvarint_err_str(e));
                return 1;
            }
            for (size_t j = 0; j < n; j++) printf("%02x", buf[j]);
            putchar('\n');
        }
        return 0;
    }

    if (strcmp(argv[1], "dec") == 0 || strcmp(argv[1], "decs") == 0) {
        sign = argv[1][3] == 's';
        const char *hex = argv[2];
        size_t hlen = strlen(hex);
        if (hlen % 2 != 0) {
            fprintf(stderr, "zvarint: hex input must have even length\n");
            return 1;
        }
        uint8_t *buf = malloc(hlen / 2 + 1);
        if (!buf) { fprintf(stderr, "zvarint: out of memory\n"); return 1; }
        for (size_t i = 0; i < hlen; i += 2) {
            int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
            if (hi < 0 || lo < 0) {
                fprintf(stderr, "zvarint: bad hex\n");
                free(buf);
                return 1;
            }
            buf[i / 2] = (uint8_t)((hi << 4) | lo);
        }
        size_t off = 0;
        while (off < hlen / 2) {
            size_t c = 0;
            zvarint_err e;
            if (sign) {
                int64_t s;
                e = zvarint_decode_i64(buf + off, hlen / 2 - off, &s, &c, 1);
                if (e == ZVARINT_OK) printf("%lld\n", (long long)s);
            } else {
                uint64_t v;
                e = zvarint_decode_u64(buf + off, hlen / 2 - off, &v, &c, 1);
                if (e == ZVARINT_OK) printf("%llu\n", (unsigned long long)v);
            }
            if (e != ZVARINT_OK) {
                fprintf(stderr, "zvarint: at byte %zu: %s\n",
                        off, zvarint_err_str(e));
                free(buf);
                return 1;
            }
            off += c;
        }
        free(buf);
        return 0;
    }

    return usage();
}
