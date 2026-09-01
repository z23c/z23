#include "base/hex.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "sha3 test failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

int main(void)
{
    static const char *h256 =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    static const char *x128 =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    static const char *x256 =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    uint8_t want256[32], want128[32], wantx256[64];
    uint8_t got[402], prefix[169], message[169];

    CHECK(zcl_hex_decode_lower(h256, want256, sizeof(want256)));
    CHECK(zcl_hex_decode_lower(x128, want128, sizeof(want128)));
    CHECK(zcl_hex_decode_lower(x256, wantx256, sizeof(wantx256)));
    sha3_256(NULL, 0, got);
    CHECK(memcmp(got, want256, sizeof(want256)) == 0);
    CHECK(zcl_shake128(NULL, 0, got, sizeof(want128)) &&
          memcmp(got, want128, sizeof(want128)) == 0);
    CHECK(zcl_shake256(NULL, 0, got, sizeof(wantx256)) &&
          memcmp(got, wantx256, sizeof(wantx256)) == 0);

    memset(message, 0x3c, sizeof(message));
    memset(got, 0xa5, sizeof(got));
    CHECK(zcl_shake128(message, sizeof(message), got + 1, 400));
    CHECK(zcl_shake128(message, sizeof(message), prefix, sizeof(prefix)));
    CHECK(got[0] == 0xa5 && got[401] == 0xa5);
    CHECK(memcmp(got + 1, prefix, sizeof(prefix)) == 0);
    CHECK(zcl_shake128(NULL, 0, NULL, 0));
    CHECK(!zcl_shake128(NULL, 1, got, 1));
    CHECK(!zcl_shake256(message, sizeof(message), NULL, 1));
    return 0;
}
