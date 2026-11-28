/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood listen port, empty seeds, and payment namespace. */

#include "services/research_listen.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int listen_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_listen: %s\n", cond);
        return 1;
    }
    return 0;
}

static int refuse_short_hrp(void)
{
    int port = -1;
    size_t seeds = 99;
    char hrp[4];
    struct zcl_result r;
    memset(hrp, 'X', sizeof hrp);
    r = research_listen_read(&port, &seeds, hrp, sizeof hrp);
    if (listen_check("short hrp refused", !r.ok &&
                     strcmp(r.message, "Payment namespace refused") == 0))
        return 1;
    if (listen_check("short hrp writes nothing", port == -1 && seeds == 99 &&
                     hrp[0] == 'X'))
        return 1;
    return 0;
}

static int read_published(const struct chain_params *main)
{
    int port = -1;
    size_t seeds = 99;
    char hrp[32];
    struct zcl_result r;
    memset(hrp, 0, sizeof hrp);
    r = research_listen_read(&port, &seeds, hrp, sizeof hrp);
    if (listen_check("listen read ok", r.ok))
        return 1;
    printf("listen_port=%d\n", port);
    printf("seed_count=%zu\n", seeds);
    printf("payment_hrp=%s\n", hrp);
    printf("main_port_differs=%d\n", main->nDefaultPort != port);
    if (listen_check("published listen port", port == 28033))
        return 1;
    if (listen_check("no discovery seeds", seeds == 0))
        return 1;
    if (listen_check("payment namespace", strcmp(hrp, "zironsapling") == 0))
        return 1;
    if (listen_check("main port differs", main->nDefaultPort != port))
        return 1;
    return 0;
}

int test_research_listen(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;
    main = chain_params_get();
    current = chain_research_profile_current();
    if (listen_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_short_hrp() || read_published(main))
        return 1;
    if (listen_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_listen: ironwood listen identity pinned\n");
    return 0;
}
