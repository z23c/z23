/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the derived Ironwood release fork identity. */

#include "services/research_fork.h"

#include "chain/chainparams.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static const char fork_label[] =
    "Z23/Ironwood/private-testnet/2026-11-29/release-1";
static const char published_fork[] =
    "def636460fec42410bf914fcc19541b050787dacd3638d2920ad49d64742ed35";

static int fork_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_fork: %s\n", cond);
        return 1;
    }
    return 0;
}

static void fork_hex(const unsigned char *raw, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < SHA3_256_OUTPUT_SIZE; i++) {
        unsigned char b = raw[i];
        out[i * 2] = hexd[b / 16];
        out[i * 2 + 1] = hexd[b % 16];
    }
    out[64] = '\0';
}

static int refuse_null(void)
{
    struct zcl_result r = research_fork_read(NULL, SHA3_256_OUTPUT_SIZE);

    return fork_check("null fork refused",
                      !r.ok && strcmp(r.message, "Missing fork identity") == 0);
}

static int refuse_short(void)
{
    unsigned char fork_id[SHA3_256_OUTPUT_SIZE];
    struct zcl_result r;

    memset(fork_id, 'X', sizeof fork_id);
    r = research_fork_read(fork_id, 16);
    if (fork_check("short fork refused",
                   !r.ok && strcmp(r.message, "Fork cap refused") == 0))
        return 1;
    return fork_check("short fork writes nothing",
                      fork_id[0] == 'X' && fork_id[31] == 'X');
}

static int read_published(void)
{
    unsigned char fork_id[SHA3_256_OUTPUT_SIZE];
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    char shown[65];

    memset(fork_id, 'X', sizeof fork_id);
    if (fork_check("fork read ok",
                   research_fork_read(fork_id, sizeof fork_id).ok))
        return 1;
    sha3_256((const unsigned char *)fork_label, sizeof fork_label - 1,
             digest);
    fork_hex(fork_id, shown);
    printf("fork_id=%s\n", shown);
    if (fork_check("fork matches label",
                   memcmp(fork_id, digest, SHA3_256_OUTPUT_SIZE) == 0))
        return 1;
    return fork_check("fork published", strcmp(shown, published_fork) == 0);
}

int test_research_fork(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    current = chain_research_profile_current();
    if (fork_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_null() || refuse_short() || read_published())
        return 1;
    if (fork_check("read does not select",
                   chain_params_get() == main &&
                   !chain_research_profile_current()))
        return 1;
    printf("research_fork: ironwood release fork identity derived\n");
    return 0;
}
