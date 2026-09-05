/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The airship rule table, pasted from its .def (see the header).
 * Nothing here decides anything the table did not already say. */

#include "config/fleet_airship_rules.h"

#include <string.h>

/* The .def writes verification and confidence as tokens so the lint gate can
 * grade them without a compiler; these turn one token into its enum. A token
 * the table never declares fails to paste, which is the compiler refusing a
 * third value rather than a default quietly standing in for one. */
#define ZCL_AIRSHIP_V_PEER_VERIFIED FLEET_AIRSHIP_PEER_VERIFIED
#define ZCL_AIRSHIP_V_SELF_REPORTED FLEET_AIRSHIP_SELF_REPORTED
#define ZCL_AIRSHIP_C_OBSERVED FLEET_AIRSHIP_OBSERVED
#define ZCL_AIRSHIP_C_DOCTRINE FLEET_AIRSHIP_DOCTRINE
#define ZCL_AIRSHIP_V(token_) ZCL_AIRSHIP_V_##token_
#define ZCL_AIRSHIP_C(token_) ZCL_AIRSHIP_C_##token_

static const struct fleet_airship_fact_v1 g_facts[] = {
#define AIRSHIP_FACT(name_, verification_) {name_, ZCL_AIRSHIP_V(verification_)},
#include "../fleet_airship_rules.def"
#undef AIRSHIP_FACT
};

static const char *const g_assets[] = {
#define AIRSHIP_ASSET(name_) name_,
#include "../fleet_airship_rules.def"
#undef AIRSHIP_ASSET
};

static const struct fleet_airship_rule_v1 g_rules[] = {
#define AIRSHIP_RULE(fact_, asset_, per_node_, confidence_, why_) \
    {fact_, asset_, per_node_, ZCL_AIRSHIP_C(confidence_), why_},
#include "../fleet_airship_rules.def"
#undef AIRSHIP_RULE
};

size_t fleet_airship_fact_count(void)
{
    return sizeof(g_facts) / sizeof(g_facts[0]);
}

const struct fleet_airship_fact_v1 *fleet_airship_fact_at(size_t index)
{
    return index < fleet_airship_fact_count() ? &g_facts[index] : NULL;
}

size_t fleet_airship_asset_count(void)
{
    return sizeof(g_assets) / sizeof(g_assets[0]);
}

const char *fleet_airship_asset_at(size_t index)
{
    return index < fleet_airship_asset_count() ? g_assets[index] : NULL;
}

size_t fleet_airship_rule_count(void)
{
    return sizeof(g_rules) / sizeof(g_rules[0]);
}

const struct fleet_airship_rule_v1 *fleet_airship_rule_at(size_t index)
{
    return index < fleet_airship_rule_count() ? &g_rules[index] : NULL;
}

enum fleet_airship_verification fleet_airship_verification_of(const char *fact)
{
    if (!fact)
        return FLEET_AIRSHIP_SELF_REPORTED;
    for (size_t i = 0; i < fleet_airship_fact_count(); i++) {
        if (strcmp(g_facts[i].name, fact) == 0)
            return g_facts[i].verification;
    }
    /* A rule naming a fact no row declares is what the lint gate refuses.
     * Should one ever reach here it reads as self-reported, which pays
     * nothing — the safe direction. */
    return FLEET_AIRSHIP_SELF_REPORTED;
}

const char *fleet_airship_verification_name(
    enum fleet_airship_verification verification)
{
    return verification == FLEET_AIRSHIP_PEER_VERIFIED ? "peer_verified"
                                                       : "self_reported";
}

const char *fleet_airship_confidence_name(
    enum fleet_airship_confidence confidence)
{
    return confidence == FLEET_AIRSHIP_OBSERVED ? "observed" : "doctrine";
}

unsigned fleet_airship_award(const char *const *held, size_t held_count,
                             const char *asset)
{
    unsigned total = 0;

    if (!asset || (!held && held_count))
        return 0;
    for (size_t i = 0; i < fleet_airship_rule_count(); i++) {
        const struct fleet_airship_rule_v1 *rule = &g_rules[i];
        bool node_holds = false;

        if (strcmp(rule->asset, asset) != 0)
            continue;
        /* The second refusal: the table already gives every self-reported
         * fact a count of zero, and this never reads that count at all. */
        if (fleet_airship_verification_of(rule->fact) !=
            FLEET_AIRSHIP_PEER_VERIFIED)
            continue;
        for (size_t j = 0; j < held_count; j++) {
            if (held[j] && strcmp(held[j], rule->fact) == 0) {
                node_holds = true;
                break;
            }
        }
        if (node_holds)
            total += rule->per_node;
    }
    return total;
}
