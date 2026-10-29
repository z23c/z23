/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "pairing.h"
#include "sha3/sha3.h"
#include <string.h>

bool zapp_pair_code(const char *descriptor, char code[7])
{
    static const char hex[] = "0123456789abcdef";
    size_t n = descriptor ? strcspn(descriptor, "\n") : 0;
    if (!n || n > 255) return false;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    zcl_sha3_256((const unsigned char *)descriptor, n, digest);
    for (size_t i = 0; i < 3; i++) { code[i * 2] = hex[digest[i] >> 4]; code[i * 2 + 1] = hex[digest[i] & 15]; }
    code[6] = 0;
    return true;
}
