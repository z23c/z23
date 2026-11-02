/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "core/uint256.h"
#include "encoding/utilstrencodings.h"
#include <stdio.h>
#include <ctype.h>

static void blob_get_hex(const uint8_t *data, unsigned int width, char *out)
{
    for (unsigned int i = 0; i < width; i++)
        snprintf(out + i * 2, 3, "%02x", data[width - i - 1]);
    out[width * 2] = '\0';
}

static void blob_set_hex(uint8_t *data, unsigned int width, const char *psz)
{
    memset(data, 0, width);

    while (isspace((unsigned char)*psz))
        psz++;

    if (psz[0] == '0' && (psz[1] == 'x' || psz[1] == 'X'))
        psz += 2;

    const char *pbegin = psz;
    while (HexDigit(*psz) != -1)
        psz++;
    psz--;

    uint8_t *p1 = data;
    uint8_t *pend = p1 + width;
    while (psz >= pbegin && p1 < pend) {
        *p1 = (uint8_t)HexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= (uint8_t)((uint8_t)HexDigit(*psz--) << 4);
            p1++;
        }
    }
}

void uint256_get_hex(const struct uint256 *v, char out[65])
{
    blob_get_hex(v->data, 32, out);
}

void uint256_set_hex(struct uint256 *v, const char *psz)
{
    blob_set_hex(v->data, 32, psz);
}


