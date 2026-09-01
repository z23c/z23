/* znetstring CLI: frame stdin as one netstring, or unframe one.
 *
 *   znetstring encode   binary stdin  -> netstring stdout
 *   znetstring decode   netstring stdin -> binary stdout
 *
 * decode requires the input to be exactly one netstring (a single
 * trailing newline is tolerated).
 */
#include "znetstring/znetstring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *read_all(FILE *f, size_t *out_len)
{
    size_t cap = 4096, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return NULL;
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            uint8_t *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
    }
    *out_len = len;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "encode") != 0 &&
                      strcmp(argv[1], "decode") != 0)) {
        fprintf(stderr, "usage: znetstring <encode|decode>\n");
        return 2;
    }

    size_t len = 0;
    uint8_t *data = read_all(stdin, &len);
    if (!data) { fprintf(stderr, "znetstring: out of memory\n"); return 1; }

    if (strcmp(argv[1], "encode") == 0) {
        size_t total = znetstring_encoded_len(len);
        if (total == 0) {
            fprintf(stderr, "znetstring: %s\n",
                    znetstring_err_str(ZNETSTRING_ERR_RANGE));
            free(data);
            return 1;
        }
        char *out = malloc(total);
        if (!out) { free(data); return 1; }
        size_t out_len = 0;
        znetstring_err e = znetstring_encode(data, len, out, total, &out_len);
        if (e != ZNETSTRING_OK) {
            fprintf(stderr, "znetstring: %s\n", znetstring_err_str(e));
            free(out);
            free(data);
            return 1;
        }
        fwrite(out, 1, out_len, stdout);
        free(out);
    } else {
        if (len > 0 && data[len - 1] == '\n') len--; /* tolerate newline */
        znetstring ns;
        znetstring_err e = znetstring_parse((const char *)data, len, &ns);
        if (e != ZNETSTRING_OK || ns.consumed != len) {
            fprintf(stderr, "znetstring: %s\n",
                    e == ZNETSTRING_OK ? "trailing bytes after netstring"
                                       : znetstring_err_str(e));
            free(data);
            return 1;
        }
        fwrite(ns.payload, 1, ns.payload_len, stdout);
    }
    free(data);
    return 0;
}
