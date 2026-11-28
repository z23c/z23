/* purpose: Resolve conservative research policy for mining and transaction ingress. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_RESEARCH_RULES_TIP_H
#define ZCL_SERVICES_RESEARCH_RULES_TIP_H
#include <stdbool.h>
#include "primitives/transaction.h"

struct block_index;
struct research_tip_rules { bool freeze, capped; };

/* Current active tip; unavailable state fails closed. */
struct research_tip_rules research_rules_tip(void);
/* The parent of an already assembled template, not a newly sampled tip. */
struct research_tip_rules research_rules_tip_for_parent(const struct block_index *parent);
/* Sapling value_balance alone; v6 has no consensus parser on this base. A
 * future v6 parser must populate this field from its Sapling bundle; never
 * copy an Ironwood balance here or combine balances from different pools. */
static inline bool research_tip_deposit_frozen(struct research_tip_rules rules,
                                               const struct transaction *tx)
{
    return rules.freeze && tx && tx->value_balance < 0;
}
#endif
