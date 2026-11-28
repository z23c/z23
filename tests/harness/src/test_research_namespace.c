/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood address namespace and a refused short buffer. */

#include "services/research_namespace.h"

#include "chain/chainparams.h"

#include <stdio.h>
#include <string.h>

static int namespace_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_namespace: %s\n", cond);
        return 1;
    }
    return 0;
}

static void mark_namespace(struct research_namespace *n)
{
    memset(n, 'X', sizeof *n);
}

static int still_marked(const struct research_namespace *n)
{
    size_t i;
    size_t b;

    for (i = 0; i < RESEARCH_NAMESPACE_HRP_COUNT; i++) {
        for (b = 0; b < 4; b++) {
            if (n->hrp[i][b] != 'X')
                return 0;
        }
    }
    for (b = 0; b < RESEARCH_NAMESPACE_PREFIX_LEN; b++) {
        if (n->pubkey_prefix[b] != 'X')
            return 0;
    }
    return 1;
}

static int refuse_short(void)
{
    struct research_namespace n;
    struct zcl_result r;

    mark_namespace(&n);
    r = research_namespace_read(&n, 8);
    if (namespace_check("short hrp refused", !r.ok &&
                        strcmp(r.message, "Namespace refused") == 0))
        return 1;
    if (namespace_check("short hrp writes nothing", still_marked(&n)))
        return 1;
    mark_namespace(&n);
    r = research_namespace_read(&n, 0);
    if (namespace_check("zero cap refused", !r.ok &&
                        strcmp(r.message, "Namespace cap refused") == 0))
        return 1;
    return namespace_check("zero cap writes nothing", still_marked(&n));
}

static int check_hrps(const struct research_namespace *n)
{
    if (namespace_check("payment hrp",
                        strcmp(n->hrp[BECH32_SAPLING_PAYMENT_ADDRESS],
                               "zironsapling") == 0))
        return 1;
    if (namespace_check("full viewing hrp",
                        strcmp(n->hrp[BECH32_SAPLING_FULL_VIEWING_KEY],
                               "zviewironsapling") == 0))
        return 1;
    if (namespace_check("incoming viewing hrp",
                        strcmp(n->hrp[BECH32_SAPLING_INCOMING_VIEWING_KEY],
                               "zivkironsapling") == 0))
        return 1;
    return namespace_check("extended spend hrp",
                           strcmp(n->hrp[BECH32_SAPLING_EXTENDED_SPEND_KEY],
                                  "secret-extended-key-iron") == 0);
}

static int check_prefix(const struct research_namespace *n,
                        const struct chain_params *main)
{
    const unsigned char *main_prefix;
    size_t main_prefix_len = 0;

    if (namespace_check("pubkey prefix",
                        n->pubkey_prefix[0] == 0x23 &&
                        n->pubkey_prefix[1] == 0x49 &&
                        n->pubkey_prefix[2] == 0x52 &&
                        n->pubkey_prefix[3] == 0x10))
        return 1;
    main_prefix = chain_params_base58_prefix(main, B58_PUBKEY_ADDRESS,
                                             &main_prefix_len);
    return namespace_check("main prefix differs",
                           main_prefix && main_prefix_len > 0 &&
                           main_prefix[0] != n->pubkey_prefix[0]);
}

static int read_published(const struct chain_params *main)
{
    struct research_namespace n;
    struct zcl_result r;

    memset(&n, 0, sizeof n);
    r = research_namespace_read(&n, RESEARCH_NAMESPACE_HRP_CAP);
    if (namespace_check("namespace read ok", r.ok))
        return 1;
    printf("payment_hrp=%s\n", n.hrp[BECH32_SAPLING_PAYMENT_ADDRESS]);
    printf("full_viewing_hrp=%s\n", n.hrp[BECH32_SAPLING_FULL_VIEWING_KEY]);
    printf("incoming_viewing_hrp=%s\n",
           n.hrp[BECH32_SAPLING_INCOMING_VIEWING_KEY]);
    printf("extended_spend_hrp=%s\n", n.hrp[BECH32_SAPLING_EXTENDED_SPEND_KEY]);
    printf("pubkey_prefix=%02x%02x%02x%02x\n",
           n.pubkey_prefix[0], n.pubkey_prefix[1],
           n.pubkey_prefix[2], n.pubkey_prefix[3]);
    printf("main_payment_differs=%d\n",
           strcmp(main->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                  n.hrp[BECH32_SAPLING_PAYMENT_ADDRESS]) != 0);
    if (check_hrps(&n) || check_prefix(&n, main))
        return 1;
    return namespace_check("main payment differs",
                           strcmp(main->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
                                  n.hrp[BECH32_SAPLING_PAYMENT_ADDRESS]) != 0);
}

int test_research_namespace(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    current = chain_research_profile_current();
    if (namespace_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_short() || read_published(main))
        return 1;
    if (namespace_check("read does not select",
                        chain_params_get() == main &&
                        !chain_research_profile_current()))
        return 1;
    printf("research_namespace: ironwood address namespace pinned\n");
    return 0;
}
