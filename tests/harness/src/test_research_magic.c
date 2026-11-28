/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the derived Ironwood message start. */

#include "services/research_magic.h"

#include "chain/chainparams.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static const char magic_label[] = "Z23/Ironwood/testnet/transport/v1";
static const char published_magic[] = "d41483fa";

static int magic_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_magic: %s\n", cond);
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
    struct zcl_result r = research_magic_read(NULL, MESSAGE_START_SIZE);

    return magic_check("null magic refused",
                       !r.ok && strcmp(r.message, "Missing magic") == 0);
}

static int refuse_short(void)
{
    unsigned char magic[MESSAGE_START_SIZE];
    struct zcl_result r;

    memset(magic, 'X', sizeof magic);
    r = research_magic_read(magic, 2);
    if (magic_check("short magic refused",
                    !r.ok && strcmp(r.message, "Magic cap refused") == 0))
        return 1;
    return magic_check("short magic writes nothing",
                       magic[0] == 'X' && magic[1] == 'X');
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    unsigned char magic[MESSAGE_START_SIZE];
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    char shown[9];
    int magic_differs;

    memset(magic, 'X', sizeof magic);
    if (magic_check("magic read ok",
                    research_magic_read(magic, sizeof magic).ok))
        return 1;
    sha3_256((const unsigned char *)magic_label, sizeof magic_label - 1,
             digest);
    magic_hex(magic, shown);
    printf("magic=%s\n", shown);
    magic_differs = memcmp(main->pchMessageStart, d->chain->pchMessageStart,
                           MESSAGE_START_SIZE) != 0;
    printf("main_magic_differs=%d\n", magic_differs);
    if (magic_check("magic matches label",
                    memcmp(magic, digest, MESSAGE_START_SIZE) == 0 &&
                    memcmp(magic, d->chain->pchMessageStart,
                           MESSAGE_START_SIZE) == 0))
        return 1;
    if (magic_check("magic published", strcmp(shown, published_magic) == 0))
        return 1;
    return magic_check("main magic differs", magic_differs);
}

int test_research_magic(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (magic_check("lookup starts unselected",
                    main && d && d->chain && !current))
        return 1;
    if (refuse_null() || refuse_short() || read_published(main, d))
        return 1;
    if (magic_check("read does not select",
                    chain_params_get() == main &&
                    !chain_research_profile_current()))
        return 1;
    printf("research_magic: ironwood message start derived\n");
    return 0;
}
