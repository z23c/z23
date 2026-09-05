/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read engine/composition/fleet_airship_rules.def — the one table
 * saying what a fact about a fleet node earns it in a game.
 *
 * There is no policy here beyond the table. A consumer asks how many of an
 * asset a node earns and passes the facts a peer OBSERVED to hold for it;
 * everything else — which facts exist, which are peer-verified, what each
 * pays and why — comes from the .def and from nowhere else, so adding a
 * fact never means editing a consumer.
 *
 * The award refuses twice. The table already gives every self-reported
 * fact a count of zero and tools/lint/check_fleet_airship_rules.sh refuses
 * any edit that raises one; fleet_airship_award ALSO skips a rule whose
 * fact is self-reported, so a table that somehow shipped a paying
 * self-reported row still pays nothing at runtime. */

#ifndef ZCL_CONFIG_FLEET_AIRSHIP_RULES_H
#define ZCL_CONFIG_FLEET_AIRSHIP_RULES_H

#include <stdbool.h>
#include <stddef.h>

/* How a fact about a node is known. There is no third value: a fact whose
 * provenance nobody can name never enters the table. */
enum fleet_airship_verification {
    FLEET_AIRSHIP_SELF_REPORTED = 0, /* the node said so */
    FLEET_AIRSHIP_PEER_VERIFIED = 1, /* another machine observed it */
};

/* Where a rule's award comes from. */
enum fleet_airship_confidence {
    FLEET_AIRSHIP_DOCTRINE = 0, /* this table asserts it; today, the zeroes */
    FLEET_AIRSHIP_OBSERVED = 1, /* it follows from a peer's observation */
};

struct fleet_airship_fact_v1 {
    const char *name;
    enum fleet_airship_verification verification;
};

struct fleet_airship_rule_v1 {
    const char *fact;
    const char *asset;
    unsigned per_node;
    enum fleet_airship_confidence confidence;
    const char *why;
};

size_t fleet_airship_fact_count(void);
const struct fleet_airship_fact_v1 *fleet_airship_fact_at(size_t index);
size_t fleet_airship_asset_count(void);
const char *fleet_airship_asset_at(size_t index);
size_t fleet_airship_rule_count(void);
const struct fleet_airship_rule_v1 *fleet_airship_rule_at(size_t index);

/* How the named fact is known. A fact no row declares reads as
 * self-reported, the value that pays nothing. */
enum fleet_airship_verification fleet_airship_verification_of(const char *fact);

const char *fleet_airship_verification_name(
    enum fleet_airship_verification verification);
const char *fleet_airship_confidence_name(
    enum fleet_airship_confidence confidence);

/* How many of `asset` one node earns, given the facts a peer observed to
 * hold for it. A fact absent from `held` earns nothing — an unobserved
 * fact is not a false one, and neither pays. */
unsigned fleet_airship_award(const char *const *held, size_t held_count,
                             const char *asset);

#endif /* ZCL_CONFIG_FLEET_AIRSHIP_RULES_H */
