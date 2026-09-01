/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "encoding/utilmoneystr.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void FormatMoney(CAmount n, char *out, size_t out_size)
{
    int64_t n_abs = n > 0 ? n : -n;
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%lld.%08lld",
                       (long long)quotient, (long long)remainder);

    while (len > 1 && buf[len - 1] == '0' && buf[len - 2] != '.')
        len--;
    buf[len] = '\0';

    if (n < 0)
        snprintf(out, out_size, "-%s", buf);
    else
        snprintf(out, out_size, "%s", buf);
}

bool ParseMoney(const char *pszIn, CAmount *nRet)
{
    int64_t nUnits = 0;
    const char *p = pszIn;
    while (isspace((unsigned char)*p))
        p++;

    char whole[32];
    int whole_len = 0;
    for (; *p; p++) {
        if (*p == '.') {
            p++;
            int64_t nMult = CENT * 10;
            while (isdigit((unsigned char)*p) && nMult > 0) {
                nUnits += nMult * (*p++ - '0');
                nMult /= 10;
            }
            break;
        }
        if (isspace((unsigned char)*p))
            break;
        if (!isdigit((unsigned char)*p))
            return false;
        if (whole_len < 31)
            whole[whole_len++] = *p;
    }
    whole[whole_len] = '\0';

    for (; *p; p++)
        if (!isspace((unsigned char)*p))
            return false;
    if (whole_len > 10)
        return false;
    if (nUnits < 0 || nUnits > COIN)
        return false;

    int64_t nWhole = strtoll(whole, NULL, 10);
    *nRet = nWhole * COIN + nUnits;
    return true;
}
