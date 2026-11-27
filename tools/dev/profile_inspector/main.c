/* purpose: Inspect experimental offline regtest-shielded profile fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "common.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint8_t manifest[PROFILE_MAX + 1], genesis[GENESIS_SIZE + 1];
    size_t mlen = 0, glen = 0;
    struct profile p = {0};
    struct uint256 hash;
    struct miner_signal_schedule schedule;
    if ((argc != 3 && argc != 4) || !profile_read_file(argv[1], manifest, sizeof(manifest), &mlen) ||
        !profile_read_file(argv[2], genesis, sizeof(genesis), &glen) ||
        !profile_parse(manifest, mlen, &p) || !profile_inspect_genesis(genesis, glen, &p, &hash)) {
        fputs("invalid experimental profile or genesis\n", stderr);
        return 1;
    }
    memcpy(p.catalog.genesis, hash.data, 32);
    if (!miner_signal_catalog_select(&p.catalog, 0, &schedule).ok) {
        fputs("invalid experimental catalog\n", stderr);
        return 1;
    }
    uint8_t expected[32];
    if (argc == 4 && (!zcl_hex_decode(argv[3], expected, sizeof(expected)) ||
                      memcmp(expected, schedule.catalog, sizeof(expected)))) {
        fputs("expected catalog mismatch or invalid digest\n", stderr);
        return 1;
    }
    char display[65];
    uint256_get_hex(&hash, display);
    fputs("{\"format\":\"Z23-PROFILE-EXPERIMENT-1\",\"profile\":\"", stdout);
    profile_print_hex(p.digest, 32);
    fputs("\",\"magic\":\"", stdout); profile_print_hex(p.magic, 4);
    printf("\",\"genesis\":\"%s\",\"catalog\":\"", display);
    profile_print_hex(schedule.catalog, 32);
    printf("\",\"start\":%d,\"window\":%d,\"proposals\":%zu,\"rules\":[",
           p.catalog.start, p.catalog.window, p.catalog.count);
    for (size_t i = 0; i < p.catalog.count; i++) {
        if (i) putchar(',');
        fputs("{\"revision\":\"", stdout);
        profile_print_hex(p.entries[i].rule_revision, 32);
        printf("\",\"activation\":%d}", p.entries[i].activation);
    }
    puts("]}");
    return 0;
}
