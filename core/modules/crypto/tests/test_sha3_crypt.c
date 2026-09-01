#include "crypto/sha3_crypt.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    uint8_t root[32], a[32], b[32], first[32], second[32];
    memset(root, 0x11, sizeof(root));
    memset(a, 0x22, sizeof(a));
    memset(b, 0x33, sizeof(b));
    sha3_crypt_derive_key(root, a, b, first);
    sha3_crypt_derive_key(root, b, a, second);
    if (memcmp(first, second, sizeof(first)) != 0)
        return 1;
    root[0] ^= 1u;
    sha3_crypt_derive_key(root, a, b, second);
    return memcmp(first, second, sizeof(first)) == 0;
}
