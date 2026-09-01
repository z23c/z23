#include "base/checked.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/serialize_le.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void package_base_cleanse_probe(uint8_t *buf, size_t len);

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "base test failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

int main(void)
{
    uint8_t bytes[8], decoded[8], secret[65];
    char hex[17];
    size_t sz = 7;
    uint64_t u = 7;

    zcl_write_u64_le(bytes, UINT64_C(0x0123456789abcdef));
    CHECK(memcmp(bytes, (uint8_t[]){0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01}, 8) == 0);
    CHECK(zcl_read_u64_le(bytes) == UINT64_C(0x0123456789abcdef));
    zcl_hex_encode(bytes, sizeof(bytes), hex);
    CHECK(strcmp(hex, "efcdab8967452301") == 0);
    CHECK(zcl_hex_decode(hex, decoded, sizeof(decoded)) &&
          memcmp(decoded, bytes, sizeof(bytes)) == 0);

    CHECK(zcl_size_add(SIZE_MAX - 1, 1, &sz) && sz == SIZE_MAX);
    CHECK(!zcl_size_add(SIZE_MAX, 1, &sz) && sz == 0);
    CHECK(zcl_size_mul(SIZE_MAX, 1, &sz) && sz == SIZE_MAX);
    CHECK(!zcl_size_mul(SIZE_MAX, 2, &sz) && sz == 0);
    CHECK(zcl_u64_add(UINT64_MAX - 1, 1, &u) && u == UINT64_MAX);
    CHECK(!zcl_u64_add(UINT64_MAX, 1, &u) && u == 0);
    CHECK(zcl_u64_mul(UINT64_MAX, 1, &u) && u == UINT64_MAX);
    CHECK(!zcl_u64_mul(UINT64_MAX, 2, &u) && u == 0);

    memset(secret, 0xa5, sizeof(secret));
    package_base_cleanse_probe(secret, sizeof(secret));
    for (size_t i = 0; i < sizeof(secret); i++)
        CHECK(secret[i] == 0);
    return 0;
}
