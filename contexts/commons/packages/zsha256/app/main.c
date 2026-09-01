/* zsha256 CLI: hash files or stdin, or compute HMAC.
 *
 *   zsha256 [file]...            hex digest per file ("-" = stdin)
 *   zsha256 --hmac <key> [file]  HMAC-SHA256 with the given key string
 */
#include "zsha256/zsha256.h"

#include <stdio.h>
#include <string.h>

static int hash_stream(FILE *f, const char *label)
{
    zsha256_ctx ctx;
    uint8_t buf[8192];
    uint8_t d[ZSHA256_DIGEST_LEN];
    size_t n;
    zsha256_init(&ctx);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        zsha256_update(&ctx, buf, n);
    if (ferror(f)) {
        fprintf(stderr, "zsha256: read error on %s\n", label);
        return 1;
    }
    zsha256_final(&ctx, d);
    static const char digits[] = "0123456789abcdef";
    char out[ZSHA256_HEX_LEN];
    for (int i = 0; i < ZSHA256_DIGEST_LEN; i++) {
        out[2 * i] = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 0x0f];
    }
    out[64] = '\0';
    printf("%s  %s\n", out, label);
    return 0;
}

static int hmac_stream(FILE *f, const char *label,
                       const char *key, size_t key_len)
{
    zsha256_hmac_ctx ctx;
    uint8_t buf[8192];
    uint8_t d[ZSHA256_DIGEST_LEN];
    size_t n;
    zsha256_hmac_init(&ctx, key, key_len);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        zsha256_hmac_update(&ctx, buf, n);
    if (ferror(f)) {
        fprintf(stderr, "zsha256: read error on %s\n", label);
        return 1;
    }
    zsha256_hmac_final(&ctx, d);
    static const char digits[] = "0123456789abcdef";
    char out[ZSHA256_HEX_LEN];
    for (int i = 0; i < ZSHA256_DIGEST_LEN; i++) {
        out[2 * i] = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 0x0f];
    }
    out[64] = '\0';
    printf("%s  %s\n", out, label);
    return 0;
}

int main(int argc, char **argv)
{
    const char *hmac_key = NULL;
    int first = 1;
    if (argc > 2 && strcmp(argv[1], "--hmac") == 0) {
        hmac_key = argv[2];
        first = 3;
    }

    if (first >= argc) {
        /* No files: read stdin. */
        if (hmac_key)
            return hmac_stream(stdin, "-", hmac_key, strlen(hmac_key));
        return hash_stream(stdin, "-");
    }

    int rc = 0;
    for (int i = first; i < argc; i++) {
        if (strcmp(argv[i], "-") == 0) {
            rc |= hmac_key ? hmac_stream(stdin, "-", hmac_key, strlen(hmac_key))
                           : hash_stream(stdin, "-");
            continue;
        }
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "zsha256: cannot open %s\n", argv[i]);
            rc = 1;
            continue;
        }
        rc |= hmac_key ? hmac_stream(f, argv[i], hmac_key, strlen(hmac_key))
                       : hash_stream(f, argv[i]);
        fclose(f);
    }
    return rc;
}
