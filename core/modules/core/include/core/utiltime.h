/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_UTILTIME_H
#define BITCOIN_UTILTIME_H

#include <stddef.h>
#include <stdint.h>

int64_t GetTime(void);
int64_t GetTimeMillis(void);
int64_t GetTimeMicros(void);


void DateTimeStrFormat(char *out, size_t out_size, const char *fmt, int64_t nTime);

#endif
