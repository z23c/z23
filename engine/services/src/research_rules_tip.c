/* purpose: Resolve conservative research policy for the active chain tip. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/research_rules_tip.h"
#include "services/chain_state_service.h"
#include "services/research_rules.h"
#include "platform/time_compat.h"
#include "support/log_throttle.h"
#include "util/log_macros.h"
#include "util/util.h"
#include <limits.h>

static struct research_tip_rules tip_failed(const char *reason)
{
    static struct log_throttle throttle = LOG_THROTTLE_INIT;
    uint64_t reps = 0;
    if (log_throttle_should_emit(&throttle, 1, platform_time_wall_unix(), 60, &reps))
        LOG_WARN("research_policy", "tip rules unavailable: %s; enforcing both rules conservatively (%llu suppressed)",
                 reason, (unsigned long long)reps);
    return (struct research_tip_rules){ .freeze = true, .capped = true, .unavailable = true };
}

struct research_tip_rules research_rules_tip_for_parent(const struct block_index *parent)
{
    const struct research_rules_binding *binding = research_rules_binding();
    if (!binding) return (struct research_tip_rules){0};
    if (!parent) return tip_failed("chain tip unavailable");
    char datadir[PATH_MAX];
    GetDataDir(true, datadir, sizeof(datadir));
    struct research_rules_state state = {0};
    struct zcl_result r = research_rules_for_index(binding, parent, datadir, &state);
    if (!r.ok) return tip_failed(r.message);
    return (struct research_tip_rules){
        .freeze = state.active[RESEARCH_RULE_DEPOSIT_FREEZE],
        .capped = state.active[RESEARCH_RULE_BLOCK_CAP],
        .unavailable = false
    };
}

struct research_tip_rules research_rules_tip(void)
{
    if (!research_rules_binding()) return (struct research_tip_rules){0};
    struct chain_state_repository *csr = csr_instance();
    pthread_mutex_lock(&csr->lock);
    struct active_chain *chain = csr->initialized ? csr->chain_active : NULL;
    pthread_mutex_unlock(&csr->lock);
    /* active_chain_tip may consult progress authority; never hold csr->lock
     * across it (the repository snapshot contract forbids that lock edge). */
    struct block_index *tip = chain ? active_chain_tip(chain) : NULL;
    return research_rules_tip_for_parent(tip);
}
