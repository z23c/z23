/* zscrypt demo: hash a passphrase with scrypt (RFC 7914 parameters). */
#include "zscrypt/zscrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int parse_cost(const char *text, unsigned long *cost)
{
    if (!text[0]) return 0;
    for (const char *p = text; *p; p++)
        if (*p < '0' || *p > '9') return 0;
    errno = 0;
    char *end;
    unsigned long value = strtoul(text, &end, 10);
    if (errno == ERANGE || *end) return 0;
    *cost = value;
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t dk[32];

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "usage: %s <passphrase> [salt] [N]\n", argv[0]);
        return 2;
    }
    const char *salt = argc > 2 ? argv[2] : "zscrypt";
    unsigned long n = 16384;
    if (argc > 3 && !parse_cost(argv[3], &n)) {
        fprintf(stderr, "zscrypt: N must be an unsigned decimal integer within unsigned long range\n");
        return 2;
    }

    int rc = zscrypt(argv[1], strlen(argv[1]), salt, strlen(salt),
                     n, 8, 1, dk, sizeof dk);
    if (rc != 0) {
        fprintf(stderr, "scrypt failed (%d)\n", rc);
        return 1;
    }
    for (size_t i = 0; i < sizeof dk; i++)
        if (printf("%02x", dk[i]) < 0) goto output_error;
    if (putchar('\n') == EOF || fflush(stdout) != 0 || ferror(stdout))
        goto output_error;
    return 0;

output_error:
    fputs("zscrypt: output write failed\n", stderr);
    return 1;
}
