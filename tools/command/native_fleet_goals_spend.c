/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: G11 zero-spend reader. It scans the declared capabilities of the
 *          fleet leaves (fleet., ops.mesh., ops.slot., ops.release.) in the
 *          command registry it is given. A leaf that declares the wallet
 *          request capability is FAIL; none declaring it is PARTIAL, because
 *          a declaration is not a measurement of spend; no fleet leaves is
 *          UNMEASURED. PASS is unreachable by design.
 */

#include "command/native_fleet_goals_spend.h"

#include <stdio.h>
#include <string.h>

#define SPEND_SHOW 3u

static const char *const k_spend_prefixes[] = {
    "fleet.",
    "ops.mesh.",
    "ops.slot.",
    "ops.release.",
};

struct spend_scan {
    size_t leaves;                 /* in-scope READY leaves scanned */
    size_t wallet;                 /* of those, declaring WALLET_REQUEST */
    const char *first[SPEND_SHOW]; /* first wallet-declaring paths */
};

static bool spend_in_scope(const char *path)
{
    size_t n = sizeof(k_spend_prefixes) / sizeof(k_spend_prefixes[0]);
    for (size_t i = 0; i < n; i++) {
        if (strncmp(path, k_spend_prefixes[i], strlen(k_spend_prefixes[i])) == 0)
            return true;
    }
    return false;
}

static void spend_note(struct spend_scan *s, const struct zcl_command_spec *spec)
{
    if (!spec->path || spec->mode == ZCL_COMMAND_MODE_BRANCH ||
        !spend_in_scope(spec->path))
        return;
    s->leaves++;
    if ((spec->required_capabilities & ZCL_COMMAND_CAP_WALLET_REQUEST) == 0)
        return;
    if (s->wallet < SPEND_SHOW)
        s->first[s->wallet] = spec->path;
    s->wallet++;
}

static struct spend_scan spend_scan_registry(const struct zcl_command_registry *reg)
{
    struct spend_scan s = {0};
    for (size_t i = 0; i < reg->count; i++)
        spend_note(&s, &reg->commands[i]);
    return s;
}

/* Writes "a, b, c" for the first wallet-declaring paths; always NUL-ends. */
static void spend_list(const struct spend_scan *s, char *out, size_t cap)
{
    size_t used = 0;
    size_t shown = s->wallet < SPEND_SHOW ? s->wallet : SPEND_SHOW;
    out[0] = '\0';
    for (size_t i = 0; i < shown; i++) {
        int w = snprintf(out + used, cap - used, "%s%s", i ? ", " : "",
                         s->first[i]);
        if (w < 0 || (size_t)w >= cap - used)
            break;
        used += (size_t)w;
    }
}

static struct zcl_goal_result spend_fail(const struct spend_scan *s)
{
    char list[ZCL_GOALS_EVIDENCE_MAX];
    spend_list(s, list, sizeof(list));
    return zcl_goal_make(ZCL_GOAL_FAIL,
                         "card: drop ZCL_COMMAND_CAP_WALLET_REQUEST from the "
                         "leaves named in the evidence, or keep them off the "
                         "fee path",
                         "wallet capability declared by %zu of %zu fleet "
                         "leaves: %s",
                         s->wallet, s->leaves, list);
}

static struct zcl_goal_result spend_partial(const struct spend_scan *s)
{
    return zcl_goal_make(ZCL_GOAL_PARTIAL,
                         "card: a custody-checked ZCL ledger summary reader, "
                         "as a separate unit",
                         "declared-capability scan of %zu leaves, not a "
                         "measurement of actual spend",
                         s->leaves);
}

struct zcl_goal_result zcl_goals_spend_measure(
    const struct zcl_command_registry *reg)
{
    struct spend_scan s;
    if (!reg)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED,
                             "card: pass the live command registry to G11",
                             "no command registry was given");
    s = spend_scan_registry(reg);
    if (s.leaves == 0)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED,
                             "card: register the fleet leaves so the spend "
                             "scan has something to grade",
                             "no fleet leaves in the command registry");
    if (s.wallet > 0)
        return spend_fail(&s);
    return spend_partial(&s);
}
