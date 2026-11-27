/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/migration_activation.h"
#include "primitives/transaction.h"
#include <stdio.h>
#include <string.h>
#define RESOLVE_RESULT(...) (migration_activation_resolve(__VA_ARGS__).code)
#define NEXT_RESULT(...) (migration_activation_next_from_parent(__VA_ARGS__).code)
#define CHECK(x) do { if (!(x)) { printf("migration_activation: line %d failed\n", __LINE__); ++failures; } } while (0)

static bool activation_step(struct miner_signal_tally tallies[3], int height,
                            struct uint256 *parent, struct transaction *coinbase)
{
    struct uint256 child = {{0}};
    child.data[0] = (uint8_t)height;
    child.data[1] = parent->data[1];
    for (unsigned i = 0; i < 3; ++i) {
        struct miner_signal_tally next;
        if (!miner_signal_connect(&tallies[i], height, parent, &child, coinbase, &next).ok)
            return false;
        tallies[i] = next;
    }
    *parent = child;
    return true;
}

static int activation_reject_cases(const struct miner_signal_catalog *catalog,
    struct miner_signal_tally a[3], const struct uint256 *parent_a,
    const struct uint256 *parent_b, const struct migration_activation_rule rules[4],
    const struct migration_activation_proposal proposals[3])
{
    int failures = 0;
    uint64_t active = 99;
#define REJECT(t, h, parent) NEXT_RESULT( \
    catalog, (t), 3, (h), (parent), rules, 4, proposals, 3, 0, 7, &active)
    CHECK(REJECT(a, 22, parent_b) == MIGRATION_ACTIVATION_INVALID && active == 99);
    a[1].schedule.slot = 0;
    CHECK(REJECT(a, 22, parent_a) == MIGRATION_ACTIVATION_INVALID && active == 99);
    a[1].schedule.slot = 1; a[1].votes = 21;
    CHECK(REJECT(a, 22, parent_a) == MIGRATION_ACTIVATION_INVALID && active == 99);
    a[1].votes = 19; a[2].schedule.catalog[0] ^= 1;
    CHECK(REJECT(a, 22, parent_a) == MIGRATION_ACTIVATION_INVALID && active == 99);
    a[2].schedule.catalog[0] ^= 1;
    CHECK(NEXT_RESULT(catalog, a, 2, 22, parent_a,
        rules, 4, proposals, 3, 0, 7, &active) == MIGRATION_ACTIVATION_INVALID && active == 99);
    CHECK(REJECT(a, INT32_MAX, parent_a) == MIGRATION_ACTIVATION_INVALID && active == 99);
#undef REJECT
    return failures;
}

static int activation_parent_cases(void)
{
    int failures = 0;
    struct miner_signal_catalog_entry entries[3] = {0};
    for (unsigned i = 0; i < 3; ++i) {
        memset(entries[i].rule_revision, 3 + (int)i, 32);
        entries[i].activation = i == 2 ? 25 : 23;
    }
    struct miner_signal_catalog catalog = {.start = 1, .window = 20, .count = 3, .entries = entries};
    memset(catalog.network_id, 1, 32); memset(catalog.genesis, 2, 32);
    struct miner_signal_tally a[3], b[3];
    struct uint256 parent_a = {{0}}, parent_b = {{0}};
    parent_b.data[1] = 1;
    for (unsigned i = 0; i < 3; ++i) {
        struct miner_signal_schedule schedule;
        CHECK(miner_signal_catalog_select(&catalog, i, &schedule).ok);
        CHECK(miner_signal_begin(&schedule, 0, &parent_a, &a[i]).ok);
        CHECK(miner_signal_begin(&schedule, 0, &parent_b, &b[i]).ok);
    }
    uint8_t bitmap[32] = {7};
    struct tx_in input = {0}; tx_in_init(&input);
    struct tx_out output = {0};
    struct transaction coinbase = {.vin = &input, .num_vin = 1, .vout = &output, .num_vout = 1};
    miner_signal_ballot_script(a[0].schedule.catalog, bitmap, output.script_pub_key.data);
    output.script_pub_key.size = MINER_SIGNAL_SCRIPT_BYTES;
    for (int h = 1; h <= 20; ++h) {
        output.value = h == 20;
        CHECK(activation_step(a, h, &parent_a, &coinbase));
        output.value = h >= 19;
        CHECK(activation_step(b, h, &parent_b, &coinbase));
    }
    output.value = 0;
    for (int h = 21; h <= 22; ++h) {
        CHECK(activation_step(a, h, &parent_a, &coinbase));
        CHECK(activation_step(b, h, &parent_b, &coinbase));
    }
    struct migration_activation_rule rules[] = {{0, 0, 0}, {1, 1, 0}, {2, 0, 0}, {3, 0, 0}};
    struct migration_activation_proposal proposals[3] = {0};
    for (unsigned i = 0; i < 3; ++i) memcpy(proposals[i].revision, entries[i].rule_revision, 32);
    proposals[0].members = 3; proposals[1].members = 4; proposals[2].members = 8;
    uint64_t active = 99;
#define NEXT(t, h, parent, prior, consent) NEXT_RESULT( \
    &catalog, (t), 3, (h), (parent), rules, 4, proposals, 3, (prior), (consent), &active)
    CHECK(NEXT(a, 22, &parent_a, 0, 7) == MIGRATION_ACTIVATION_OK && active == 7);
    active = 99;
    CHECK(NEXT(a, 22, &parent_a, 0, 3) == MIGRATION_ACTIVATION_NO_CONSENT && active == 99);
    CHECK(NEXT(b, 22, &parent_b, 0, 0) == MIGRATION_ACTIVATION_OK && active == 0);
    failures += activation_reject_cases(&catalog, a, &parent_a, &parent_b, rules, proposals);
    for (int h = 23; h <= 24; ++h) {
        CHECK(activation_step(a, h, &parent_a, &coinbase));
        CHECK(activation_step(b, h, &parent_b, &coinbase));
    }
    CHECK(NEXT(a, 24, &parent_a, 7, 8) == MIGRATION_ACTIVATION_OK && active == 15);
    CHECK(NEXT(b, 24, &parent_b, 0, 0) == MIGRATION_ACTIVATION_OK && active == 0);
#undef NEXT
    return failures;
}

static int activation_empty_registry_cases(void)
{
    int failures = 0;
    uint64_t active = 99;
    struct migration_activation_qualified q[] = {{.revision = {0}, .height = 23}};
    CHECK(RESOLVE_RESULT(NULL, 0, NULL, 0, 0, 0, q, 1, 22, &active) == MIGRATION_ACTIVATION_OK && active == 0);
    active = 99;
    CHECK(RESOLVE_RESULT(NULL, 0, NULL, 0, 0, 0, q, 1, 23, &active) == MIGRATION_ACTIVATION_UNKNOWN_REVISION && active == 99);
    CHECK(RESOLVE_RESULT(NULL, 0, NULL, 0, 1, 0, q, 1, 22, &active) == MIGRATION_ACTIVATION_INVALID && active == 99);
    return failures;
}

static int activation_result_api_cases(void)
{
    int failures = 0;
    uint64_t active = 99;
    struct migration_activation_rule rules[] = {{0, 0, 0}};
    struct migration_activation_proposal proposals[] = {{{1}, 1}};
    struct migration_activation_qualified q[] = {{{1}, 23}};
    struct zcl_result r = migration_activation_resolve(rules, 1, proposals, 1, 0, 1, q, 1, 23, &active);
    CHECK(r.ok && r.code == MIGRATION_ACTIVATION_OK && active == 1);
    active = 99;
    r = migration_activation_resolve(rules, 1, proposals, 1, 0, 0, q, 1, 23, &active);
    CHECK(!r.ok && r.code == MIGRATION_ACTIVATION_NO_CONSENT && r.message[0] && active == 99);
    q[0].revision[0] = 2;
    r = migration_activation_resolve(rules, 1, proposals, 1, 0, 1, q, 1, 23, &active);
    CHECK(!r.ok && r.code == MIGRATION_ACTIVATION_UNKNOWN_REVISION && r.message[0] && active == 99);
    r = migration_activation_resolve(rules, 1, proposals, 1, 0, 1, q, 1, 0, &active);
    CHECK(!r.ok && r.code == MIGRATION_ACTIVATION_INVALID && r.message[0] && active == 99);
    return failures;
}

int test_migration_activation(void)
{
    int failures = 0;
    struct migration_activation_rule rules[] = {{0, 0, 0}, {1, 1, 0}, {2, 0, 8}, {3, 0, 4}};
    struct migration_activation_proposal p[] = {
        {.revision = {2}, .members = 2}, {.revision = {1}, .members = 3},
        {.revision = {3}, .members = 4}, {.revision = {4}, .members = 8},
        {.revision = {0}, .members = 1}
    };
    struct migration_activation_qualified q[] = {
        {.revision = {3}, .height = 23}, {.revision = {2}, .height = 25},
        {.revision = {1}, .height = 23}, {.revision = {4}, .height = 23},
        {.revision = {9}, .height = 25}
    };
    uint64_t active = 99;
    /* Both conflicting proposals are pruned before consent; future unknown waits. */
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 3, q, 5, 23, &active) == MIGRATION_ACTIVATION_OK && active == 3);
    active = 99;
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 1, 3, q, 5, 25, &active) == MIGRATION_ACTIVATION_UNKNOWN_REVISION && active == 99);
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 1, 2, q, 4, 25, &active) == MIGRATION_ACTIVATION_OK && active == 3);
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 0, q, 5, 24, &active) == MIGRATION_ACTIVATION_OK && active == 0);
    active = 99;
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 1, q, 4, 23, &active) == MIGRATION_ACTIVATION_NO_CONSENT && active == 99);
    /* Already-active members need no new consent, including opaque zero revision. */
    struct migration_activation_qualified zero[] = {{.revision = {0}, .height = 23}};
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 1, 0, zero, 1, 23, &active) == MIGRATION_ACTIVATION_OK && active == 1);
    /* Two revisions can enable the same migration with one local consent bit. */
    struct migration_activation_qualified overlap[] = {
        {.revision = {0}, .height = 23}, {.revision = {1}, .height = 23}
    };
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 3, overlap, 2, 23, &active) == MIGRATION_ACTIVATION_OK && active == 3);
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 1, overlap, 2, 23, &active) == MIGRATION_ACTIVATION_NO_CONSENT && active == 3);
    q[1].revision[0] = 3;
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 15, q, 4, 23, &active) == MIGRATION_ACTIVATION_INVALID && active == 3);
    q[1].revision[0] = 2; rules[0].requires = 2;
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 15, q, 4, 23, &active) == MIGRATION_ACTIVATION_INVALID && active == 3);
    rules[0].requires = 0; p[1].members = 12;
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 15, q, 4, 23, &active) == MIGRATION_ACTIVATION_INVALID && active == 3);
    /* A proposal pruned for an unavailable prerequisite does not need consent. */
    p[1].members = 2;
    CHECK(RESOLVE_RESULT(rules, 4, p, 5, 0, 0, &q[2], 1, 23, &active) == MIGRATION_ACTIVATION_OK && active == 0);
    return failures + activation_parent_cases() + activation_empty_registry_cases() + activation_result_api_cases();
}
