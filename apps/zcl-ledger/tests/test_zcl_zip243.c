/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_zip243.h"
#include "crypto/blake2b.h"
#include "zcl_zip243_host.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static size_t read_vector(const char *path, uint8_t wire[8192]) {
    FILE *file = fopen(path, "r");
    assert(file);
    static char line[16384];
    while (fgets(line, sizeof line, file) && line[0] == '#') {}
    assert(!ferror(file) && line[0] != '#');
    size_t length = strcspn(line, "\r\n");
    assert(length % 2 == 0 && length > 0 && length <= 16384);
    for (size_t i = 0; i < length / 2; ++i) {
        int hi = nibble(line[2 * i]), lo = nibble(line[2 * i + 1]);
        assert(hi >= 0 && lo >= 0);
        wire[i] = (uint8_t)((hi << 4) | lo);
    }
    assert(fclose(file) == 0);
    return length / 2;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    static uint8_t wire[8192];
    struct blake2b_ctx context;
    zcl_zip243_hasher hasher = zcl_zip243_host_hasher(&context);
    size_t length = read_vector(argv[1], wire);
    assert(length == 4118);
    static const uint8_t expected[32] = {
        0x63, 0xd1, 0x85, 0x34, 0xde, 0x5f, 0x2d, 0x1c,
        0x9e, 0x16, 0x9b, 0x73, 0xf9, 0xc7, 0x83, 0x71,
        0x8a, 0xdb, 0xef, 0x5c, 0x8a, 0x7d, 0x55, 0xb5,
        0xe7, 0xa3, 0x7a, 0xff, 0xa1, 0xdd, 0x3f, 0xf3
    };
    uint8_t digest[32];
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) == 0);
    wire[length - 1] ^= 1;
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) == 0);
    wire[20] ^= 1;
    assert(zcl_zip243_shielded_digest(wire, length, 0x76b809bb,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) != 0);
    wire[20] ^= 1;
    assert(zcl_zip243_shielded_digest(wire, length, 0x930b540d,
                                      &hasher, digest) == 0);
    assert(memcmp(digest, expected, 32) != 0);
    assert(zcl_zip243_shielded_digest(wire, length - 1, 0x76b809bb,
                                      &hasher, digest) < 0);
    return 0;
}
