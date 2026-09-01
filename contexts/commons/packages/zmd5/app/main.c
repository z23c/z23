/* zmd5 CLI: print the MD5 hex digest of files, or stdin with no args.
 *
 *   zmd5              digest stdin
 *   zmd5 FILE...      digest each file, one "hex  FILE" line per file
 */
#include "zmd5/zmd5.h"

#include <stdio.h>
#include <stdlib.h>

static int digest_stream(FILE *f, char out[ZMD5_HEX_LEN + 1])
{
    zmd5 ctx;
    zmd5_init(&ctx);
    uint8_t buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        zmd5_update(&ctx, buf, n);
    if (ferror(f)) return -1;
    uint8_t d[ZMD5_DIGEST_LEN];
    zmd5_final(&ctx, d);
    zmd5_hex(d, out);
    out[ZMD5_HEX_LEN] = '\0';
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        char hex[ZMD5_HEX_LEN + 1];
        if (digest_stream(stdin, hex) != 0) {
            fprintf(stderr, "zmd5: error reading stdin\n");
            return 1;
        }
        printf("%s\n", hex);
        return 0;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "zmd5: cannot open %s\n", argv[i]);
            rc = 1;
            continue;
        }
        char hex[ZMD5_HEX_LEN + 1];
        if (digest_stream(f, hex) != 0) {
            fprintf(stderr, "zmd5: error reading %s\n", argv[i]);
            rc = 1;
        } else {
            printf("%s  %s\n", hex, argv[i]);
        }
        fclose(f);
    }
    return rc;
}
