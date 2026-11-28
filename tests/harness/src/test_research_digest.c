/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood genesis block SHA-256. */

#include "services/research_digest.h"

#include "chain/chainparams.h"
#include "crypto/sha256.h"

#include <stdio.h>
#include <string.h>

static const char published_digest[] =
    "d205e8a42fcad376d3610c2a7203bd94840c21189f6075701953d50b01e7b91c";

static int digest_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_digest: %s\n", cond);
        return 1;
    }
    return 0;
}

static void digest_hex(const unsigned char *raw, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < 32; i++) {
        unsigned char b = raw[i];
        out[i * 2] = hexd[b / 16];
        out[i * 2 + 1] = hexd[b % 16];
    }
    out[64] = '\0';
}

static void wire_sha256(const unsigned char *data, size_t len,
                        unsigned char out[32])
{
    struct sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_write(&ctx, data, len);
    sha256_finalize(&ctx, out);
}

static int still_marked(const unsigned char *raw)
{
    return raw[0] == 'X' && raw[1] == 'X' && raw[14] == 'X' && raw[15] == 'X';
}

static int refuse_null(void)
{
    struct zcl_result r = research_digest_read(NULL, 32);

    return digest_check("null digest refused",
                        !r.ok && strcmp(r.message, "Missing digest") == 0);
}

static int refuse_short(void)
{
    unsigned char raw[16];
    struct zcl_result r;

    memset(raw, 'X', sizeof raw);
    r = research_digest_read(raw, sizeof raw);
    if (digest_check("short digest refused", !r.ok &&
                     strcmp(r.message, "Digest cap refused") == 0))
        return 1;
    return digest_check("short digest writes nothing", still_marked(raw));
}

static int read_published(const struct chain_params *main,
                          const struct chain_research_descriptor *d)
{
    unsigned char raw[32];
    unsigned char once[32];
    char shown[65];
    int genesis_differs;

    memset(raw, 0x5a, sizeof raw);
    if (digest_check("digest read ok",
                     research_digest_read(raw, sizeof raw).ok))
        return 1;
    wire_sha256((const unsigned char *)d->genesis_wire,
                d->genesis_wire_len, once);
    digest_hex(raw, shown);
    printf("digest_hex=%s\n", shown);
    genesis_differs = memcmp(&main->consensus.hashGenesisBlock,
                             &d->chain->consensus.hashGenesisBlock,
                             sizeof main->consensus.hashGenesisBlock) != 0;
    printf("main_genesis_differs=%d\n", genesis_differs);
    if (digest_check("digest matches wire", memcmp(raw, once, 32) == 0))
        return 1;
    if (digest_check("digest published", strcmp(shown, published_digest) == 0))
        return 1;
    return digest_check("main genesis differs", genesis_differs);
}

int test_research_digest(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *d;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    current = chain_research_profile_current();
    if (digest_check("lookup starts unselected",
                     main && d && d->chain && d->genesis_wire &&
                     d->genesis_wire_len == 276 && !current))
        return 1;
    if (refuse_null() || refuse_short() || read_published(main, d))
        return 1;
    if (digest_check("read does not select",
                     chain_params_get() == main &&
                     !chain_research_profile_current()))
        return 1;
    printf("research_digest: ironwood genesis sha256 pinned\n");
    return 0;
}
