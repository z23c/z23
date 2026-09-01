/* zsha1 CLI: print the SHA-1 hex digest of files, or stdin.
 *
 *   zsha1              digest stdin
 *   zsha1 FILE...      digest each file, one "hex  FILE" line per file
 */
#include "zsha1/zsha1.h"

#include <stdio.h>
#include <stdlib.h>

static int digest_stream(FILE *f, char out[ZSHA1_HEX_LEN + 1])
{
    zsha1 ctx;
    zsha1_init(&ctx);
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        zsha1_update(&ctx, buf, n);
    if (ferror(f)) return -1;
    uint8_t d[ZSHA1_DIGEST_LEN];
    zsha1_final(&ctx, d);
    zsha1_hex(d, out);
    out[ZSHA1_HEX_LEN] = '\0';
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        char hex[ZSHA1_HEX_LEN + 1];
        if (digest_stream(stdin, hex) != 0) {
            fprintf(stderr, "zsha1: error reading stdin\n");
            return 1;
        }
        printf("%s\n", hex);
        return 0;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "zsha1: cannot open %s\n", argv[i]);
            rc = 1;
            continue;
        }
        char hex[ZSHA1_HEX_LEN + 1];
        if (digest_stream(f, hex) != 0) {
            fprintf(stderr, "zsha1: error reading %s\n", argv[i]);
            rc = 1;
        } else {
            printf("%s  %s\n", hex, argv[i]);
        }
        fclose(f);
    }
    return rc;
}
