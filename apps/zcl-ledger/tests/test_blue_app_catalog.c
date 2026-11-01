/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_app_catalog.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t page[74] = {1};
    page[1] = 72;
    page[2] = 0x12;
    page[3] = 0x34;
    page[4] = 0x56;
    page[5] = 0x78;
    for (size_t i = 0; i < 32; ++i) {
        page[6 + i] = (uint8_t)i;
        page[38 + i] = (uint8_t)(i + 32);
    }
    page[70] = 3;
    memcpy(page + 71, "ZCL", 3);
    blue_app_entry entries[1] = {0};
    size_t count = 99;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) == 0);
    assert(count == 1 && strcmp(entries[0].name, "ZCL") == 0);
    assert(entries[0].flags == 0x12345678);
    for (size_t i = 0; i < 32; ++i) {
        assert(entries[0].hash_code_data[i] == i);
        assert(entries[0].hash[i] == i + 32);
    }
    assert(blue_app_catalog_unique_hash(entries, 1, "ZCL",
                                        entries[0].hash));
    assert(!blue_app_catalog_unique_hash(entries, 1, "OTHER",
                                         entries[0].hash));
    uint8_t wrong[32];
    memcpy(wrong, entries[0].hash, sizeof wrong);
    wrong[31] ^= 1;
    assert(!blue_app_catalog_unique_hash(entries, 1, "ZCL", wrong));
    assert(!blue_app_catalog_unique_hash(entries, 0, "ZCL",
                                         entries[0].hash));
    assert(blue_app_catalog_parse(page, 0, entries, 1, &count) == 0);
    assert(count == 0);
    assert(blue_app_catalog_parse(page, sizeof page - 1,
                                  entries, 1, &count) < 0);
    assert(blue_app_catalog_parse(page, sizeof page, entries, 0,
                                  &count) < 0);
    page[1] = 71;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    page[1] = 73;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    page[1] = 72;
    page[1] = 69;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    page[1] = 72;
    page[70] = 0;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    page[70] = 3;
    uint8_t two[1 + 2 * (sizeof page - 1)] = {1};
    memcpy(two + 1, page + 1, sizeof page - 1);
    memcpy(two + sizeof page, page + 1, sizeof page - 1);
    blue_app_entry pair[2] = {0};
    assert(blue_app_catalog_parse(two, sizeof two, pair, 2,
                                  &count) == 0 && count == 2);
    assert(!blue_app_catalog_unique_hash(pair, count, "ZCL",
                                         entries[0].hash));
    pair[1].hash[0] ^= 1;
    assert(!blue_app_catalog_unique_hash(pair, count, "ZCL",
                                         entries[0].hash));
    int written = snprintf(pair[1].name, sizeof pair[1].name, "%s", "OTHER");
    assert(written == 5);
    assert(blue_app_catalog_unique_hash(pair, count, "ZCL",
                                        entries[0].hash));
    assert(blue_app_catalog_parse(two, sizeof two, entries, 1,
                                  &count) < 0);
    page[70] = 32;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    page[70] = 3;
    page[71] = '\n';
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    page[0] = 2;
    assert(blue_app_catalog_parse(page, sizeof page, entries, 1,
                                  &count) < 0);
    return 0;
}
