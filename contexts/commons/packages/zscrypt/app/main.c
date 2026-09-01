/* zscrypt demo: hash a passphrase with scrypt (RFC 7914 parameters). */
#include "zscrypt/zscrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t dk[32];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <passphrase> [salt] [N]\n", argv[0]);
        return 2;
    }
    const char *salt = argc > 2 ? argv[2] : "zscrypt";
    unsigned long n = argc > 3 ? strtoul(argv[3], NULL, 10) : 16384;

    int rc = zscrypt(argv[1], strlen(argv[1]), salt, strlen(salt),
                     n, 8, 1, dk, sizeof dk);
    if (rc != 0) {
        fprintf(stderr, "scrypt failed (%d)\n", rc);
        return 1;
    }
    for (size_t i = 0; i < sizeof dk; i++)
        printf("%02x", dk[i]);
    putchar('\n');
    return 0;
}
