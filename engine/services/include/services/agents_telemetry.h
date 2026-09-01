/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `agents` telemetry domain's collector — the PROVIDER half of the typed
 * telemetry layer (util/telemetry_render.h). It fills a
 * `struct agents_snapshot` and does nothing else: it writes no JSON, decides
 * no health, and names no JSON key. Every field name in this domain is
 * spelled once, in platform/modules/util/include/util/telemetry/agents_fields.def.
 *
 * WHERE THE DATA COMES FROM, and why that shape. The grant store
 * (`agent_sessions`), the identity registry (`principals`), the login-nonce
 * store and the node's self-backtrace counters all live inside the NODE
 * process. A native command runs in a one-shot CLI process which has no
 * node.db (the same fact that makes vault.session.* go over RPC — see
 * controllers/agent_session_client.h). So this collector reads the node over
 * the loopback JSON-RPC surface: one bounded `agentsession list` page plus
 * three read-only `dumpstate` calls, each on an explicit short deadline.
 *
 * It therefore takes no lock and runs no query of its own — there is no
 * blocking primitive and no COUNT(*) here to find, and the counts it reports
 * are the node's own. It is bounded in the other direction too: the FIRST
 * call is a cheap probe, and when that fails every remaining leaf is set
 * UNAVAILABLE with a static reason token WITHOUT attempting the rest, so a
 * stopped node costs one connect timeout rather than four.
 *
 * NO CREDENTIAL EVER ENTERS THE SNAPSHOT, and that does not rest on the node
 * being careful. The node's `agentsession list` does redact every session id
 * before it leaves the process (agent_session_controller.c: a session id is a
 * BEARER grant), but the client header still documents the rows as carrying
 * the full token, so the collector treats them as if they did: it reads
 * session_id NEVER, and copies no account, address, nonce or public key into
 * a leaf either. Every leaf in this domain is a count, an age, a cap or an
 * outcome. See the field table's header for the standing rule.
 *
 * Returns void deliberately: there is no failure mode to report. A leaf that
 * could not be read is UNAVAILABLE with a reason, never absent and never a
 * plausible zero, so "the collector failed" is not a thing a caller could act
 * on differently from "the store was unreadable", which the snapshot already
 * says in machine-readable form. */

#ifndef ZCL_SERVICES_AGENTS_TELEMETRY_H
#define ZCL_SERVICES_AGENTS_TELEMETRY_H

#include "util/telemetry_snapshots.h"

/* Fill EVERY leaf of `snap`. The caller owns the struct and must zero it
 * (`= {0}`) first: zero is TELEMETRY_UNSET, which is the provider-defect
 * signal the render layer counts, and this function is contracted to leave
 * none behind. Reentrant; no node state, no lock, no local database. */
void agents_dump_state_fill(struct agents_snapshot *snap);

#endif /* ZCL_SERVICES_AGENTS_TELEMETRY_H */
