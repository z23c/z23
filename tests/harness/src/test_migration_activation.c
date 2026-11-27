/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/migration_activation.h"
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { printf("migration_activation: line %d failed\n", __LINE__); ++failures; } } while (0)

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
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 3, q, 5, 23, &active) == MIGRATION_ACTIVATION_OK && active == 3);
    active = 99;
    CHECK(migration_activation_resolve(rules, 4, p, 5, 1, 3, q, 5, 25, &active) == MIGRATION_ACTIVATION_UNKNOWN_REVISION && active == 99);
    CHECK(migration_activation_resolve(rules, 4, p, 5, 1, 2, q, 4, 25, &active) == MIGRATION_ACTIVATION_OK && active == 3);
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 0, q, 5, 24, &active) == MIGRATION_ACTIVATION_OK && active == 0);
    active = 99;
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 1, q, 4, 23, &active) == MIGRATION_ACTIVATION_NO_CONSENT && active == 99);
    /* Already-active members need no new consent, including opaque zero revision. */
    struct migration_activation_qualified zero[] = {{.revision = {0}, .height = 23}};
    CHECK(migration_activation_resolve(rules, 4, p, 5, 1, 0, zero, 1, 23, &active) == MIGRATION_ACTIVATION_OK && active == 1);
    /* Two revisions can enable the same migration with one local consent bit. */
    struct migration_activation_qualified overlap[] = {
        {.revision = {0}, .height = 23}, {.revision = {1}, .height = 23}
    };
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 3, overlap, 2, 23, &active) == MIGRATION_ACTIVATION_OK && active == 3);
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 1, overlap, 2, 23, &active) == MIGRATION_ACTIVATION_NO_CONSENT && active == 3);
    q[1].revision[0] = 3;
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 15, q, 4, 23, &active) == MIGRATION_ACTIVATION_INVALID && active == 3);
    q[1].revision[0] = 2; rules[0].requires = 2;
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 15, q, 4, 23, &active) == MIGRATION_ACTIVATION_INVALID && active == 3);
    rules[0].requires = 0; p[1].members = 12;
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 15, q, 4, 23, &active) == MIGRATION_ACTIVATION_INVALID && active == 3);
    /* A proposal pruned for an unavailable prerequisite does not need consent. */
    p[1].members = 2;
    CHECK(migration_activation_resolve(rules, 4, p, 5, 0, 0, &q[2], 1, 23, &active) == MIGRATION_ACTIVATION_OK && active == 0);
    return failures;
}
