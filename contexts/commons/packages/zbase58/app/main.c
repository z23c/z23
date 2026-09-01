/* zbase58 CLI: encode binary stdin to Base58, or decode back.
 *
 *   zbase58 encode    binary stdin -> Base58 stdout
 *   zbase58 decode    Base58 stdin -> binary stdout
 */
#include "zbase58/zbase58.h"

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
    if (argc < 2 || (strcmp(argv[1], "encode") != 0 && strcmp(argv[1], "decode") != 0)) {
        fprintf(stderr, "usage: zbase58 <encode|decode>\n");
        return 2;
    }

    size_t len = 0;
    uint8_t *data = read_all(stdin, &len);
    if (!data) { fprintf(stderr, "zbase58: out of memory\n"); return 1; }

    if (strcmp(argv[1], "encode") == 0) {
        size_t cap = zbase58_encoded_max(len) + 1;
        char *out = malloc(cap);
        if (!out) { free(data); return 1; }
        size_t n = 0;
        zbase58_err e = zbase58_encode(data, len, out, cap, &n);
        if (e != ZBASE58_OK) {
            fprintf(stderr, "zbase58: %s\n", zbase58_err_str(e));
            free(out);
            free(data);
            return 1;
        }
        fwrite(out, 1, n, stdout);
        fputc('\n', stdout);
        free(out);
    } else {
        if (len > 0 && data[len - 1] == '\n') len--;
        uint8_t *out = malloc(zbase58_decoded_max(len) + 1);
        if (!out) { free(data); return 1; }
        size_t n = 0, pos = 0;
        zbase58_err e = zbase58_decode((const char *)data, len, out,
                                       zbase58_decoded_max(len) + 1, &n, &pos);
        if (e != ZBASE58_OK) {
            fprintf(stderr, "zbase58: %s at position %zu\n",
                    zbase58_err_str(e), pos);
            free(out);
            free(data);
            return 1;
        }
        fwrite(out, 1, n, stdout);
        free(out);
    }
    free(data);
    return 0;
}
