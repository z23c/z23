/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood genesis header fields. */

#include "services/research_header.h"

#include "base/serialize_le.h"
#include "chain/chainparams.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int header_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_header: %s\n", cond);
        return 1;
    }
    return 0;
}

static int all_zero(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0)
            return 0;
    }
    return 1;
}

static int nonce_is_one(const unsigned char *p)
{
    size_t i;

    if (p[0] != 1)
        return 0;
    for (i = 1; i < 32; i++) {
        if (p[i] != 0)
            return 0;
    }
    return 1;
}

static int refuse_null(void)
{
    struct zcl_result r;

    r = research_header_read(0);
    return header_check("null header refused",
                        !r.ok && strcmp(r.message, "Missing header") == 0);
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    struct research_header h;
    const uint8_t *w;
    int genesis_differs;
    int wire_match;

    memset(&h, 0x5a, sizeof h);
    if (header_check("header read ok", research_header_read(&h).ok))
        return 1;
    w = d->genesis_wire;
    printf("header_version=%d\n", h.version);
    printf("header_time=%u\n", h.time);
    printf("header_bits=%08x\n", h.bits);
    printf("prev_zero=%d\n", all_zero(h.prev, 32));
    printf("sapling_zero=%d\n", all_zero(h.sapling_root, 32));
    printf("nonce_le=%d\n", nonce_is_one(h.nonce) ? 1 : 0);
    genesis_differs = memcmp(&main->consensus.hashGenesisBlock,
                             &d->chain->consensus.hashGenesisBlock,
                             sizeof main->consensus.hashGenesisBlock) != 0;
    printf("main_genesis_differs=%d\n", genesis_differs);
    wire_match = h.version == zcl_read_i32_le(w) &&
                 memcmp(h.prev, w + 4, 32) == 0 &&
                 memcmp(h.sapling_root, w + 68, 32) == 0 &&
                 h.time == zcl_read_u32_le(w + 100) &&
                 h.bits == zcl_read_u32_le(w + 104) &&
                 memcmp(h.nonce, w + 108, 32) == 0;
    if (header_check("header matches wire", wire_match))
        return 1;
    if (header_check("version", h.version == 4))
        return 1;
    if (header_check("time", h.time == 1795737600u))
        return 1;
    if (header_check("bits", h.bits == 0x200f0f0fu))
        return 1;
    if (header_check("zero parent", all_zero(h.prev, 32)))
        return 1;
    if (header_check("zero sapling root", all_zero(h.sapling_root, 32)))
        return 1;
    if (header_check("nonce", nonce_is_one(h.nonce)))
        return 1;
    return header_check("main genesis differs", genesis_differs);
}

int test_research_header(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (header_check("lookup starts unselected",
                     main && d && d->chain && d->genesis_wire &&
                     d->genesis_wire_len >= 140 && !current))
        return 1;
    if (refuse_null() || read_published(main, d))
        return 1;
    if (header_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_header: ironwood genesis header pinned\n");
    return 0;
}
