/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood genesis merkle root. */

#include "services/research_merkle.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static const char published_merkle[] =
    "5b311545eb0a91c0b813e94b62a1cff6b29fee9c948f0dc8bf3fee59747c860d";

static int merkle_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_merkle: %s\n", cond);
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

static int refuse_short(void)
{
    unsigned char raw[16];
    struct zcl_result r;

    memset(raw, 'X', sizeof raw);
    r = research_merkle_read(raw, sizeof raw);
    if (merkle_check("short merkle refused", !r.ok &&
                     strcmp(r.message, "Merkle cap refused") == 0))
        return 1;
    return merkle_check("short merkle writes nothing", still_marked(raw));
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    unsigned char raw[32];
    char display[65];
    int genesis_differs;

    memset(raw, 0x5a, sizeof raw);
    if (merkle_check("merkle read ok", research_merkle_read(raw, sizeof raw).ok))
        return 1;
    display_hex(raw, display);
    printf("merkle_display=%s\n", display);
    genesis_differs = memcmp(&main->consensus.hashGenesisBlock,
                             &d->chain->consensus.hashGenesisBlock,
                             sizeof main->consensus.hashGenesisBlock) != 0;
    printf("main_genesis_differs=%d\n", genesis_differs);
    if (merkle_check("merkle matches wire",
                     d->genesis_wire_len >= 68 &&
                     memcmp(raw, d->genesis_wire + 36, 32) == 0))
        return 1;
    if (merkle_check("merkle display", strcmp(display, published_merkle) == 0))
        return 1;
    return merkle_check("main genesis differs", genesis_differs);
}

int test_research_merkle(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (merkle_check("lookup starts unselected",
                     main && d && d->chain && d->genesis_wire && !current))
        return 1;
    if (refuse_short() || read_published(main, d))
        return 1;
    if (merkle_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_merkle: ironwood coinbase merkle pinned\n");
    return 0;
}
