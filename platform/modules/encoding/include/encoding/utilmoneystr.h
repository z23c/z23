/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_UTILMONEYSTR_H
#define BITCOIN_UTILMONEYSTR_H

#include "core/amount.h"
#include <stdbool.h>
#include <stddef.h>

void FormatMoney(CAmount n, char *out, size_t out_size);
bool ParseMoney(const char *str, CAmount *nRet);

#endif
