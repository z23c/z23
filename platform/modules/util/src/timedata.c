/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "util/timedata.h"
#include "util/sync.h"
#include "util/ui_interface.h"
#include "util/util.h"
#include "core/utiltime.h"
#include <stdlib.h>
#include <string.h>

#define MAX_SAMPLES 200
/* Wide enough for IPv6 textual form (max 45 chars) and Tor v3 .onion
 * names (62 chars). Callers pass node->addr_name, which may be a
 * hostname rather than a packed IP. The previous 16-byte buffer caused
 * a buffer-overflow abort (glibc FORTIFY) on any peer whose addr_name
 * exceeded 16 bytes — e.g. every Tor peer. */
#define ADDR_KEY_MAX 64

static zcl_mutex_t cs_nTimeOffset;
static int64_t nTimeOffset = 0;
static int time_data_initialized = 0;

static void ensure_init(void)
{
    if (!time_data_initialized) {
        zcl_mutex_init(&cs_nTimeOffset);
        time_data_initialized = 1;
    }
}

int64_t GetTimeOffset(void)
{
    ensure_init();
    LOCK(cs_nTimeOffset);
    int64_t r = nTimeOffset;
    UNLOCK(cs_nTimeOffset);
    return r;
}

int64_t GetAdjustedTime(void)
{
    return GetTime() + GetTimeOffset();
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t va = *(const int64_t *)a;
    int64_t vb = *(const int64_t *)b;
    return (va > vb) - (va < vb);
}

void AddTimeData(const unsigned char *ip, int ip_len, int64_t nOffsetSample)
{
    ensure_init();
    LOCK(cs_nTimeOffset);

    /* Track known IPs to ignore duplicates */
    static unsigned char known_ips[MAX_SAMPLES][ADDR_KEY_MAX];
    static int known_ip_lens[MAX_SAMPLES];
    static int nKnown = 0;

    /* Clamp to the dedup-key capacity. Two addresses sharing the same
     * truncated prefix will dedupe; the worst case is rejecting a few
     * legit samples, never a memory overflow. */
    int key_len = ip_len;
    if (key_len < 0) key_len = 0;
    if (key_len > ADDR_KEY_MAX) key_len = ADDR_KEY_MAX;

    /* Check for duplicate */
    for (int i = 0; i < nKnown; i++) {
        if (known_ip_lens[i] == key_len &&
            memcmp(known_ips[i], ip, (size_t)key_len) == 0) {
            UNLOCK(cs_nTimeOffset);
            return;
        }
    }
    if (nKnown >= MAX_SAMPLES) {
        UNLOCK(cs_nTimeOffset);
        return;
    }
    memcpy(known_ips[nKnown], ip, (size_t)key_len);
    known_ip_lens[nKnown] = key_len;
    nKnown++;

    /* Circular buffer for offsets */
    static int64_t offsets[MAX_SAMPLES];
    static int nOffsets = 0;

    if (nOffsets < MAX_SAMPLES)
        offsets[nOffsets++] = nOffsetSample;

    LogPrintf("Added time data, samples %d, offset %+lld (%+lld minutes)\n",
              nOffsets, (long long)nOffsetSample, (long long)(nOffsetSample / 60));

    if (nOffsets >= 5 && nOffsets % 2 == 1) {
        int64_t sorted[MAX_SAMPLES];
        memcpy(sorted, offsets, sizeof(int64_t) * (size_t)nOffsets);
        qsort(sorted, (size_t)nOffsets, sizeof(int64_t), cmp_i64);
        int64_t nMedian = sorted[nOffsets / 2];

        if (nMedian > -70 * 60 && nMedian < 70 * 60) {
            nTimeOffset = nMedian;
        } else {
            nTimeOffset = 0;
        }
        LogPrintf("nTimeOffset = %+lld  (%+lld minutes)\n",
                  (long long)nTimeOffset, (long long)(nTimeOffset / 60));
    }

    UNLOCK(cs_nTimeOffset);
}
