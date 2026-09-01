/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 explain <topic>` — the operator/AI-readable composition surface.
 *
 * `explain` assembles, IN C, what an operator otherwise stitches together from
 * four separate diagnostic surfaces (reducer frontier, the typed blocker
 * registry, the self-heal condition engine, and the node health/sync RPCs) into
 * one short prose-like `text` block plus the structured fields behind it.
 *
 * The topic dispatch is a table (see explain_native_handlers.c g_explain_topics)
 * so a future topic is one entry. Current topics: sync, blockers, health.
 *
 * The composers are PURE: each takes already-parsed JSON inputs and fills one
 * result object (a `text` string + structured keys). They contact no node and
 * allocate nothing the caller does not own, so a test drives them with a
 * fabricated fixture (e.g. a blocker dump naming a known dominant blocker) and
 * asserts on the rendered text. `explain_build` is the node-contacting wrapper
 * that fetches the RPC bundle and dispatches to the topic composer.
 */

#ifndef ZCL_CONTROLLERS_EXPLAIN_NATIVE_HANDLERS_H
#define ZCL_CONTROLLERS_EXPLAIN_NATIVE_HANDLERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* Parsed inputs a topic composer reads. Any pointer may be NULL (that RPC was
 * unavailable); a composer degrades to "unknown"/omitted, never crashes. */
struct explain_inputs {
    const struct json_value *frontier;    /* dumpstate reducer_frontier .state */
    const struct json_value *blockers;    /* dumpstate blocker .state.blockers (array) */
    const struct json_value *conditions;  /* dumpstate condition_engine .state */
    const struct json_value *health;      /* healthcheck object */
    const struct json_value *sync;        /* syncstate object */
    const struct json_value *chain;       /* getblockchaininfo object */
    int64_t block_height;                 /* getblockcount */
    bool     block_height_known;
    int64_t  peer_best;                   /* max peer-advertised height */
    bool     peer_best_known;
};

/* Pure composers. `out` is filled via json_set_object; it always gains a
 * "text" string (the prose block) and topic-specific structured keys. */
void explain_compose_sync(const struct explain_inputs *in,
                          struct json_value *out);
void explain_compose_blockers(const struct explain_inputs *in,
                              struct json_value *out);
void explain_compose_health(const struct explain_inputs *in,
                            struct json_value *out);

/* Topic registry (for help/enumeration and the unknown-topic error). */
size_t explain_topic_count(void);
/* Comma-joined topic names into `out`; returns strlen written. */
size_t explain_topics_csv(char *out, size_t out_size);

/* Node-contacting entry point: resolve `topic`, fetch the RPC bundle via
 * node_rpc_call, dispatch to the composer, and fill `out` (object). Returns
 * false and fills out.error when the topic is unknown. The RPC client must be
 * initialised (bridge_ensure_rpc_client) by the caller. */
bool explain_build(const char *topic, struct json_value *out);

#endif /* ZCL_CONTROLLERS_EXPLAIN_NATIVE_HANDLERS_H */
