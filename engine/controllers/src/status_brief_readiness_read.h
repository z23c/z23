/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read side of the separately named readiness facts that
 * zcl.public_status.v3 added. Split out of status_brief_native_handler.c
 * (E1 file-size ceiling) — that file owns the projection, this one owns
 * reading the facts out of the node's `agent` document.
 */

#ifndef ZCL_STATUS_BRIEF_READINESS_READ_H
#define ZCL_STATUS_BRIEF_READINESS_READ_H

#include <stdbool.h>

struct json_value;

/* The separately named readiness facts, added by zcl.public_status.v3.
 * Read OPTIONALLY on both the strict and the lenient path — a v2 document
 * simply omits them and `known` stays false, exactly the same
 * optional-facet contract as blocker_registry / trust_tier.
 *
 * The whole point of these is that they are SEPARATE: a node keeping up with
 * the tip while still missing old block bodies reports tip_follow=true WITH
 * archive_complete="incomplete". Never fold one into another, and never let a
 * missing archive answer downgrade tip_follow. */
struct status_brief_readiness_facts {
    bool known;                 /* at least one of the five keys was present */
    bool tip_follow;            bool tip_follow_known;
    bool wallet_view_ready;     bool wallet_view_known;
    bool wallet_spend_allowed;  bool wallet_spend_known;
    /* "complete" | "incomplete" | "unknown"; points into the source doc. */
    const char *archive_complete;
    bool full_replay_verified;  bool full_replay_known;
};

/* `agent` may be NULL; every field is optional and absence is not an error. */
void status_brief_readiness_facts_read(
    const struct json_value *agent, struct status_brief_readiness_facts *out);

#endif /* ZCL_STATUS_BRIEF_READINESS_READ_H */
