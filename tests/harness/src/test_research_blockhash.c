/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood genesis block hash. */

#include "services/research_blockhash.h"

#include "chain/chainparams.h"
#include "core/hash.h"
#include "primitives/block.h"

#include <stdio.h>
#include <string.h>

static const char published_blockhash[] =
    "0eadaa0b42b377b8d05d1a9b313f1795b8ac4553217a5d06b0f66cddff8c78e7";

static int blockhash_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_blockhash: %s\n", cond);
        return 1;
    }
    return 0;
}

static void display_hex(const unsigned char *raw, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < 32; i++) {
        unsigned char b = raw[31 - i];
        out[i * 2] = hexd[b / 16];
        out[i * 2 + 1] = hexd[b % 16];
    }
    out[64] = '\0';
}

static int still_marked(const unsigned char *raw)
{
    return raw[0] == 'X' && raw[1] == 'X' && raw[14] == 'X' && raw[15] == 'X';
}

static int refuse_null(void)
{
    struct zcl_result r = research_blockhash_read(NULL, 32);

    return blockhash_check("null blockhash refused",
                           !r.ok && strcmp(r.message, "Missing blockhash") == 0);
}

static int refuse_short(void)
{
    unsigned char raw[16];
    struct zcl_result r;

    memset(raw, 'X', sizeof raw);
    r = research_blockhash_read(raw, sizeof raw);
    if (blockhash_check("short blockhash refused", !r.ok &&
                        strcmp(r.message, "Blockhash cap refused") == 0))
        return 1;
    return blockhash_check("short blockhash writes nothing", still_marked(raw));
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    unsigned char raw[32];
    unsigned char once[32];
    unsigned int n;
    size_t prefix;
    char display[65];
    int genesis_differs;

    memset(raw, 0x5a, sizeof raw);
    if (blockhash_check("blockhash read ok",
                        research_blockhash_read(raw, sizeof raw).ok))
        return 1;
    n = d->genesis_wire[BLOCK_HEADER_SIZE];
    prefix = (size_t)BLOCK_HEADER_SIZE + 1u + n;
    hash256((const unsigned char *)d->genesis_wire, prefix, once);
    display_hex(raw, display);
    printf("blockhash_display=%s\n", display);
    genesis_differs = memcmp(&main->consensus.hashGenesisBlock,
                             &d->chain->consensus.hashGenesisBlock,
                             sizeof main->consensus.hashGenesisBlock) != 0;
    printf("main_genesis_differs=%d\n", genesis_differs);
    if (blockhash_check("blockhash matches wire",
                        prefix <= d->genesis_wire_len &&
                        memcmp(raw, once, 32) == 0 &&
                        memcmp(raw, d->chain->consensus.hashGenesisBlock.data,
                               32) == 0))
        return 1;
    if (blockhash_check("blockhash display",
                        strcmp(display, published_blockhash) == 0 &&
                        prefix == 177))
        return 1;
    return blockhash_check("main genesis differs", genesis_differs);
}

int test_research_blockhash(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (blockhash_check("lookup starts unselected",
                        main && d && d->chain && d->genesis_wire &&
                        d->genesis_wire_len == 276 && !current))
        return 1;
    if (refuse_null() || refuse_short() || read_published(main, d))
        return 1;
    if (blockhash_check("read does not select",
                        chain_params_get() == main &&
                        !chain_research_profile_current()))
        return 1;
    printf("research_blockhash: ironwood genesis block hash pinned\n");
    return 0;
}
