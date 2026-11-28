/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Drive the published Ironwood ping frame through shipped checks. */

#include "services/research_frame.h"

#include "base/hex.h"
#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

#define RF_CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "research_frame: %s\n", #cond); \
        return 1; \
    } \
} while (0)

static const char k_ping[] =
    "d41483fa70696e670000000000000000080000002502fa940102030405060708";

static int load_ping(uint8_t frame[32])
{
    static const uint8_t sum[4] = {0x25, 0x02, 0xfa, 0x94};
    RF_CHECK(zcl_hex_decode(k_ping, frame, 32));
    RF_CHECK(memcmp(frame + 20, sum, 4) == 0);
    RF_CHECK(memcmp(frame + 4, "ping", 4) == 0);
    return 0;
}

static int accept_published(const uint8_t magic[4], const uint8_t frame[32])
{
    char command[16];
    struct zcl_result r;
    memset(command, 'X', sizeof(command));
    r = research_frame_accept(frame, 32, magic, command, sizeof(command));
    RF_CHECK(r.ok);
    RF_CHECK(strcmp(command, "ping") == 0);
    printf("message_start=%02x%02x%02x%02x\n",
           magic[0], magic[1], magic[2], magic[3]);
    printf("command=%s\n", command);
    printf("checksum=%02x%02x%02x%02x\n",
           frame[20], frame[21], frame[22], frame[23]);
    printf("payload_octets=8\n");
    return 0;
}

static int refuse_foreign(const uint8_t magic[4], const uint8_t frame[32])
{
    uint8_t foreign[32];
    uint8_t other[4];
    char command[16];
    struct zcl_result r;
    memcpy(foreign, frame, sizeof(foreign));
    foreign[0] = (uint8_t)(foreign[0] ^ 0x01);
    memcpy(other, foreign, sizeof(other));
    memset(command, 'X', sizeof(command));
    r = research_frame_accept(foreign, sizeof(foreign), magic, command,
                              sizeof(command));
    RF_CHECK(!r.ok);
    RF_CHECK(strcmp(r.message, "Foreign network frame refused") == 0);
    RF_CHECK(command[0] == 'X');
    printf("foreign_network_frame_refused=1\n");
    r = research_frame_accept(foreign, sizeof(foreign), other, command,
                              sizeof(command));
    RF_CHECK(r.ok);
    RF_CHECK(strcmp(command, "ping") == 0);
    printf("foreign_checksum_still_valid=1\n");
    return 0;
}

static int refuse_checksum(const uint8_t magic[4], const uint8_t frame[32])
{
    uint8_t bad[32];
    char command[16];
    struct zcl_result r;
    memcpy(bad, frame, sizeof(bad));
    bad[31] = (uint8_t)(bad[31] ^ 0x01);
    memset(command, 'X', sizeof(command));
    r = research_frame_accept(bad, sizeof(bad), magic, command, sizeof(command));
    RF_CHECK(!r.ok);
    RF_CHECK(strcmp(r.message, "Frame checksum refused") == 0);
    RF_CHECK(command[0] == 'X');
    bad[16] = 7;
    r = research_frame_accept(bad, sizeof(bad), magic, command, sizeof(command));
    RF_CHECK(!r.ok);
    RF_CHECK(strcmp(r.message, "Frame length refused") == 0);
    r = research_frame_accept(frame, 23, magic, command, sizeof(command));
    RF_CHECK(!r.ok);
    RF_CHECK(strcmp(r.message, "Frame length refused") == 0);
    printf("bad_checksum_refused=1\n");
    printf("length_mismatch_refused=1\n");
    return 0;
}

int test_research_frame(void)
{
    const struct chain_research_descriptor *d;
    uint8_t frame[32];
    static const uint8_t published[4] = {0xd4, 0x14, 0x83, 0xfa};
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->chain) {
        fprintf(stderr, "research_frame: research descriptor is missing\n");
        return 1;
    }
    RF_CHECK(memcmp(d->chain->pchMessageStart, published, 4) == 0);
    if (load_ping(frame))
        return 1;
    if (accept_published(d->chain->pchMessageStart, frame))
        return 1;
    if (refuse_foreign(d->chain->pchMessageStart, frame))
        return 1;
    if (refuse_checksum(d->chain->pchMessageStart, frame))
        return 1;
    printf("research_frame: published ping accepted\n");
    return 0;
}
