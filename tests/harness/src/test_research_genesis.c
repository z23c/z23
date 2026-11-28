/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood genesis wire length and coinbase message. */

#include "services/research_genesis.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int genesis_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_genesis: %s\n", cond);
        return 1;
    }
    return 0;
}

static int message_still_marked(const char *message)
{
    return message[0] == 'X' && message[1] == 'X' && message[2] == 'X' &&
           message[3] == 'X';
}

static int wire_has(const uint8_t *wire, size_t wire_len, const char *message)
{
    size_t n = strlen(message);
    size_t i;

    if (n == 0 || n > wire_len)
        return 0;
    for (i = 0; i + n <= wire_len; i++) {
        if (memcmp(wire + i, message, n) == 0)
            return 1;
    }
    return 0;
}

static int refuse_short(void)
{
    char message[4];
    size_t wire_len = 99;
    struct zcl_result r;

    memset(message, 'X', sizeof message);
    r = research_genesis_read(&wire_len, message, sizeof message);
    if (genesis_check("short message refused", !r.ok &&
                      strcmp(r.message, "Genesis message refused") == 0))
        return 1;
    return genesis_check("short message writes nothing",
                         wire_len == 99 && message_still_marked(message));
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    char message[64];
    size_t wire_len = 99;
    struct zcl_result r;
    int genesis_differs;

    memset(message, 0, sizeof message);
    r = research_genesis_read(&wire_len, message, sizeof message);
    if (genesis_check("genesis read ok", r.ok))
        return 1;
    printf("genesis_wire_len=%zu\n", wire_len);
    printf("coinbase_message=%s\n", message);
    genesis_differs = memcmp(&main->consensus.hashGenesisBlock,
                             &d->chain->consensus.hashGenesisBlock,
                             sizeof main->consensus.hashGenesisBlock) != 0;
    printf("main_genesis_differs=%d\n", genesis_differs);
    if (genesis_check("wire length", wire_len == 276 &&
                      wire_len == d->genesis_wire_len))
        return 1;
    if (genesis_check("coinbase message",
                      strcmp(message, "Ironwood research testnet 2026-11-27") == 0 &&
                      wire_has(d->genesis_wire, d->genesis_wire_len, message)))
        return 1;
    return genesis_check("main genesis differs", genesis_differs);
}

int test_research_genesis(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (genesis_check("lookup starts unselected", main && d && d->chain && !current))
        return 1;
    if (refuse_short() || read_published(main, d))
        return 1;
    if (genesis_check("read does not select",
                      chain_params_get() == main &&
                      !chain_research_profile_current()))
        return 1;
    printf("research_genesis: ironwood coinbase message pinned\n");
    return 0;
}
