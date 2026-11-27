/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_MIGRATION_ACTIVATION_H
#define ZCL_MIGRATION_ACTIVATION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Migration IDs index bits, not array positions. Revision IDs are raw bytes. */
struct migration_activation_rule { uint8_t id; uint64_t requires, conflicts; };
struct migration_activation_proposal { uint8_t revision[32]; uint64_t members; };
struct migration_activation_qualified { uint8_t revision[32]; int32_t height; };
enum migration_activation_result {
    MIGRATION_ACTIVATION_OK, MIGRATION_ACTIVATION_INVALID,
    MIGRATION_ACTIVATION_UNKNOWN_REVISION, MIGRATION_ACTIVATION_NO_CONSENT
};
/* Pure resolution for one candidate height, using catalog-qualified entries
 * and a separate local revision-to-bundle registry. Unknown future revisions
 * do not block this height. Failure leaves *active unchanged. This neither
 * validates a chain nor activates rules. */
enum migration_activation_result migration_activation_resolve(
    const struct migration_activation_rule *rules, size_t rule_count,
    const struct migration_activation_proposal *proposals, size_t proposal_count,
    uint64_t prior, uint64_t consented_migrations, const struct migration_activation_qualified *qualified,
    size_t qualified_count, int32_t height, uint64_t *active);
#endif
