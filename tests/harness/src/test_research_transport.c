/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood transport identity. */

#include "services/research_transport.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static const char published_magic[] = "d41483fa";
static const char published_datadir[] = "ironwood-research";

static int transport_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_transport: %s\n", cond);
        return 1;
    }
    return 0;
}

static void magic_hex(const unsigned char *raw, char out[9])
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < MESSAGE_START_SIZE; i++) {
        unsigned char b = raw[i];
        out[i * 2] = hexd[b / 16];
        out[i * 2 + 1] = hexd[b % 16];
    }
    out[8] = '\0';
}

static int refuse_null(void)
{
    unsigned char magic[MESSAGE_START_SIZE];
    int rpc_port = 99;
    char datadir[8];
    struct zcl_result r;

    memset(magic, 'X', sizeof magic);
    memset(datadir, 'Z', sizeof datadir);
    r = research_transport_read(NULL, sizeof magic, &rpc_port, datadir,
                               sizeof datadir);
    if (transport_check("null transport refused",
                        !r.ok && strcmp(r.message, "Missing transport") == 0))
        return 1;
    return transport_check("null transport writes nothing",
                           rpc_port == 99 && datadir[0] == 'Z');
}

static int refuse_short(void)
{
    unsigned char magic[MESSAGE_START_SIZE];
    int rpc_port = 99;
    char datadir[64];
    struct zcl_result r;

    memset(magic, 'X', sizeof magic);
    memset(datadir, 'Z', sizeof datadir);
    r = research_transport_read(magic, 2, &rpc_port, datadir, sizeof datadir);
    if (transport_check("short magic refused",
                        !r.ok && strcmp(r.message, "Magic cap refused") == 0))
        return 1;
    if (transport_check("short magic writes nothing",
                        magic[0] == 'X' && magic[1] == 'X' && rpc_port == 99 &&
                        datadir[0] == 'Z'))
        return 1;
    r = research_transport_read(magic, sizeof magic, &rpc_port, datadir, 4);
    if (transport_check("short datadir refused",
                        !r.ok && strcmp(r.message, "Datadir cap refused") == 0))
        return 1;
    return transport_check("short datadir writes nothing",
                           magic[0] == 'X' && rpc_port == 99 && datadir[0] == 'Z');
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    unsigned char magic[MESSAGE_START_SIZE];
    int rpc_port = 99;
    char datadir[64];
    char shown[9];
    int transport_differs;

    memset(magic, 'X', sizeof magic);
    memset(datadir, 'Z', sizeof datadir);
    if (transport_check("transport read ok",
                        research_transport_read(magic, sizeof magic, &rpc_port,
                                               datadir, sizeof datadir).ok))
        return 1;
    magic_hex(magic, shown);
    printf("magic=%s\n", shown);
    printf("rpc_port=%d\n", rpc_port);
    printf("datadir=%s\n", datadir);
    transport_differs = memcmp(main->pchMessageStart, d->chain->pchMessageStart,
                               MESSAGE_START_SIZE) != 0;
    printf("main_transport_differs=%d\n", transport_differs);
    if (transport_check("transport matches descriptor",
                        memcmp(magic, d->chain->pchMessageStart,
                               MESSAGE_START_SIZE) == 0 &&
                        rpc_port == d->base->nRPCPort &&
                        strcmp(datadir, d->base->strDataDir) == 0))
        return 1;
    if (transport_check("transport published",
                        strcmp(shown, published_magic) == 0 &&
                        rpc_port == 28023 &&
                        strcmp(datadir, published_datadir) == 0))
        return 1;
    return transport_check("main transport differs", transport_differs);
}

int test_research_transport(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (transport_check("lookup starts unselected",
                        main && d && d->chain && d->base && d->base->strDataDir &&
                        !current))
        return 1;
    if (refuse_null() || refuse_short() || read_published(main, d))
        return 1;
    if (transport_check("read does not select",
                        chain_params_get() == main &&
                        !chain_research_profile_current()))
        return 1;
    printf("research_transport: ironwood transport pinned\n");
    return 0;
}
