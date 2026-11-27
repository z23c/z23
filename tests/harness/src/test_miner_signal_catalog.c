/* purpose: Verify canonical ballot catalog vectors and rejection behavior. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/miner_signal_catalog.h"
#include "base/hex.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define CAT_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "miner_signal_catalog line %d: %s\n", __LINE__, #x); return 1; \
} } while (0)

static bool catalog_digest_changed(const struct miner_signal_catalog *catalog, const uint8_t original[32])
{
    struct miner_signal_schedule selected;
    return miner_signal_catalog_select(catalog, 0, &selected).ok &&
           memcmp(original, selected.catalog, 32) != 0;
}

int test_miner_signal_catalog(void)
{
    static const char *expected = "be8027db90c73984db54173ba98edd05ec137fad214ee500ae3b9e117b2894fe";
    struct miner_signal_catalog_entry entries[2] = {0};
    struct miner_signal_catalog c = { .start = 100, .window = 20, .count = 2, .entries = entries };
    memset(c.network_id, 0x11, 32);
    memset(c.genesis, 0x22, 32);
    for (unsigned i = 0; i < 32; ++i) {
        entries[0].rule_revision[i] = (uint8_t)i;
        entries[1].rule_revision[i] = (uint8_t)(i + 32);
    }
    entries[0].activation = 122; entries[1].activation = 150;
    uint8_t want[32];
    CAT_CHECK(zcl_hex_decode(expected, want, sizeof(want)));
    struct miner_signal_schedule a = {0}, b = {0};
    CAT_CHECK(miner_signal_catalog_select(&c, 0, &a).ok);
    CAT_CHECK(memcmp(a.catalog, want, 32) == 0);
    CAT_CHECK(a.start == 100 && a.window == 20 && a.activation == 122 && a.slot == 0 && a.slots == 2);
    CAT_CHECK(miner_signal_catalog_select(&c, 1, &b).ok);
    CAT_CHECK(memcmp(a.catalog, b.catalog, 32) == 0 && b.slot == 1 && b.activation == 150);
    c.network_id[0] ^= 1;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.network_id[0] ^= 1; c.genesis[0] ^= 1;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.genesis[0] ^= 1; entries[1].activation++;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    entries[1].activation--; entries[1].rule_revision[0]++;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    entries[1].rule_revision[0]--;
    c.window--;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.window++;
    c.start--;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.start++;
    c.count = 1;
    CAT_CHECK(catalog_digest_changed(&c, a.catalog));
    c.count = 2;
    struct miner_signal_schedule before = a;
    CAT_CHECK(!miner_signal_catalog_select(&c, 2, &a).ok && memcmp(&a, &before, sizeof(a)) == 0);
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, NULL).ok);
    CAT_CHECK(!miner_signal_catalog_select(NULL, 0, &a).ok);
    c.count = 257; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.count = 0;
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.count = 2;
    c.entries = NULL; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.entries = entries;
    memset(c.network_id, 0, 32); CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    memset(c.network_id, 0x11, 32); memset(c.genesis, 0, 32);
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); memset(c.genesis, 0x22, 32);
    entries[0].activation = 120; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    entries[0].activation = 121; CAT_CHECK(miner_signal_catalog_select(&c, 0, &b).ok);
    entries[0].activation = 122; c.start = INT32_MAX;
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.start = 100;
    c.window = 0; CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok); c.window = 20;
    memcpy(entries[1].rule_revision, entries[0].rule_revision, 32);
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    entries[1].rule_revision[0] = 0; entries[0].rule_revision[0] = 1;
    CAT_CHECK(!miner_signal_catalog_select(&c, 0, &a).ok);
    CAT_CHECK(memcmp(&a, &before, sizeof(a)) == 0);
    static struct miner_signal_catalog_entry all[256];
    for (unsigned i = 0; i < 256; ++i) {
        all[i].rule_revision[31] = (uint8_t)i;
        all[i].activation = 122;
    }
    c.entries = all; c.count = 256;
    CAT_CHECK(miner_signal_catalog_select(&c, 255, &b).ok);
    CAT_CHECK(b.slots == 256 && b.slot == 255 && b.activation == 122);
    puts("miner_signal_catalog: vector, slot binding, mutations and rejection passed");
    return 0;
}
