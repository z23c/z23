#include "sha3/sha3.h"

#include <stdint.h>

int main(void)
{
    static const uint8_t message[] = "zclassic23";
    uint8_t digest[SHA3_256_OUTPUT_SIZE];
    sha3_256(message, sizeof(message) - 1, digest);
    return digest[0] == 0xff ? 1 : 0;
}
