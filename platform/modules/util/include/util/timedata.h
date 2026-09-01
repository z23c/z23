/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_TIMEDATA_H
#define BITCOIN_TIMEDATA_H

#include <stdint.h>

/* Network-adjusted clock. The node samples peers' clock offsets and
 * derives a single median correction used in place of the raw OS clock
 * for consensus timestamp checks. All three are thread-safe (guarded by
 * an internal mutex). */

/* Current median peer offset in seconds (0 until enough samples, or if
 * the median exceeds the +/-70-minute sanity bound). */
int64_t GetTimeOffset(void);

/* Wall-clock GetTime() plus GetTimeOffset(): the network-adjusted time. */
int64_t GetAdjustedTime(void);

/* Record one peer's clock-offset sample, keyed by its address bytes.
 * Duplicate addresses and samples beyond an internal cap are ignored;
 * the running median (and thus GetTimeOffset) is recomputed as samples
 * accumulate. */
void AddTimeData(const unsigned char *ip, int ip_len, int64_t nOffsetSample);

#endif
