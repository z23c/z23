/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood genesis solution length. */

#include "services/research_solution.h"

#include "chain/chainparams.h"
#include "primitives/block.h"

#include <stdio.h>
#include <string.h>

enum { PUBLISHED_SOLUTION = 36, PUBLISHED_TXS = 1, PUBLISHED_PREFIX = 177 };

static int solution_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_solution: %s\n", cond);
        return 1;
    }
    return 0;
}

static int refuse_null(void)
{
    unsigned int solution_len = 99;
    unsigned int tx_count = 99;
    struct zcl_result r;

    r = research_solution_read(NULL, &tx_count);
    if (solution_check("null solution refused",
                       !r.ok && strcmp(r.message, "Missing solution") == 0))
        return 1;
    if (solution_check("null solution writes nothing", tx_count == 99))
        return 1;
    r = research_solution_read(&solution_len, NULL);
    if (solution_check("null count refused",
                       !r.ok && strcmp(r.message, "Missing solution") == 0))
        return 1;
    return solution_check("null count writes nothing", solution_len == 99);
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    unsigned int solution_len = 99;
    unsigned int tx_count = 99;
    size_t tx_off;
    int genesis_differs;

    if (solution_check("solution read ok",
                       research_solution_read(&solution_len, &tx_count).ok))
        return 1;
    tx_off = (size_t)BLOCK_HEADER_SIZE + 1u + solution_len;
    printf("solution_len=%u\n", solution_len);
    printf("tx_count=%u\n", tx_count);
    printf("header_with_solution=%zu\n", tx_off);
    genesis_differs = memcmp(&main->consensus.hashGenesisBlock,
                             &d->chain->consensus.hashGenesisBlock,
                             sizeof main->consensus.hashGenesisBlock) != 0;
    printf("main_genesis_differs=%d\n", genesis_differs);
    if (solution_check("solution matches wire",
                       d->genesis_wire_len > tx_off &&
                       d->genesis_wire[BLOCK_HEADER_SIZE] == solution_len &&
                       d->genesis_wire[tx_off] == tx_count))
        return 1;
    if (solution_check("published solution",
                       solution_len == PUBLISHED_SOLUTION &&
                       tx_count == PUBLISHED_TXS &&
                       tx_off == PUBLISHED_PREFIX))
        return 1;
    return solution_check("main genesis differs", genesis_differs);
}

int test_research_solution(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (solution_check("lookup starts unselected",
                       main && d && d->chain && d->genesis_wire &&
                       d->genesis_wire_len == 276 && !current))
        return 1;
    if (refuse_null() || read_published(main, d))
        return 1;
    if (solution_check("read does not select",
                       chain_params_get() == main &&
                       !chain_research_profile_current()))
        return 1;
    printf("research_solution: ironwood genesis solution pinned\n");
    return 0;
}
