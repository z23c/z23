/* zhex CLI: encode stdin to hex, or decode hex from stdin.
 *
 *   zhex encode [--upper]   binary stdin  -> hex stdout
 *   zhex decode             hex stdin     -> binary stdout
 *
 * Whitespace-free input expected for decode; a single trailing newline
 * is tolerated.
 */
#include "zhex/zhex.h"

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
        fprintf(stderr, "usage: zhex <encode [--upper]|decode>\n");
        return 2;
    }
    int upper = argc > 2 && strcmp(argv[2], "--upper") == 0;

    size_t len = 0;
    uint8_t *data = read_all(stdin, &len);
    if (!data) { fprintf(stderr, "zhex: out of memory\n"); return 1; }

    if (strcmp(argv[1], "encode") == 0) {
        char *out = malloc(zhex_encoded_len(len) + 1);
        if (!out) { free(data); return 1; }
        zhex_err e = upper ? zhex_encode_upper(data, len, out)
                           : zhex_encode(data, len, out);
        if (e != ZHEX_OK) {
            fprintf(stderr, "zhex: %s\n", zhex_err_str(e));
            free(out);
            free(data);
            return 1;
        }
        fwrite(out, 1, zhex_encoded_len(len), stdout);
        fputc('\n', stdout);
        free(out);
    } else {
        if (len > 0 && data[len - 1] == '\n') len--; /* tolerate trailing newline */
        uint8_t *out = malloc(zhex_decoded_len(len) + 1);
        if (!out) { free(data); return 1; }
        size_t bad = 0;
        zhex_err e = zhex_decode((const char *)data, len, out, &bad);
        if (e != ZHEX_OK) {
            fprintf(stderr, "zhex: %s at position %zu\n", zhex_err_str(e), bad);
            free(out);
            free(data);
            return 1;
        }
        fwrite(out, 1, zhex_decoded_len(len), stdout);
        free(out);
    }
    free(data);
    return 0;
}
