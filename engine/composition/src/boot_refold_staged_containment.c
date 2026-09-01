/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fail-closed admission for the retired -refold-staged recovery verb. */
#include "config/boot.h"

#include "event/event.h"
#include "util/log_macros.h"

bool boot_refold_staged_preflight(bool refold_staged)
{
    if (!refold_staged)
        return true;
    LOG_WARN("boot",
             "-refold-staged is contained: its ordinary reducer replay cannot "
             "publish bounded Sprout/Sapling/nullifier completeness; use the "
             "copy-proven full-reindex cure");
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "refold_staged_contained shielded_history_unproven");
    return false;
}
