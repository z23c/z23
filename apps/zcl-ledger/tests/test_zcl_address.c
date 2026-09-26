/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_address.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    const uint8_t generator[ZCL_COMPRESSED_PUBKEY_SIZE] = {
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
        0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
        0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
    };
    char address[ZCL_ADDRESS_SIZE];
    assert(zcl_address_from_pubkey(generator, address) == 0);
    assert(strcmp(address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs") == 0);
    uint8_t negative_generator[ZCL_COMPRESSED_PUBKEY_SIZE];
    memcpy(negative_generator, generator, sizeof negative_generator);
    negative_generator[0] = 3;
    assert(zcl_address_from_pubkey(negative_generator, address) == 0);
    assert(strcmp(address, "t1ZiwD6uYW8ku8DSCM4f11BwsDateqtG7yz") == 0);
    uint8_t invalid[ZCL_COMPRESSED_PUBKEY_SIZE] = {0};
    assert(zcl_address_from_pubkey(invalid, address) < 0);
    memcpy(invalid, generator, sizeof invalid);
    invalid[0] = 4;
    assert(zcl_address_from_pubkey(invalid, address) < 0);
    memset(invalid + 1, 0xff, sizeof invalid - 1);
    invalid[0] = 2;
    assert(zcl_address_from_pubkey(invalid, address) < 0);
    assert(zcl_address_from_pubkey(NULL, address) < 0);
    assert(zcl_address_from_pubkey(generator, NULL) < 0);
    return 0;
}
