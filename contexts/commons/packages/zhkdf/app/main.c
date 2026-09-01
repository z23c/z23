/* zhkdf demo: derive a 32-byte key from a passphrase with HKDF-SHA256. */
#include "zhkdf/zhkdf.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t okm[32];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <passphrase> [salt] [info]\n", argv[0]);
        return 2;
    }
    const char *salt = argc > 2 ? argv[2] : "";
    const char *info = argc > 3 ? argv[3] : "";

    if (zhkdf_sha256(salt, strlen(salt),
                     argv[1], strlen(argv[1]),
                     info, strlen(info),
                     okm, sizeof okm) != 0) {
        fprintf(stderr, "hkdf failed\n");
        return 1;
    }
    for (size_t i = 0; i < sizeof okm; i++)
        printf("%02x", okm[i]);
    putchar('\n');
    return 0;
}
