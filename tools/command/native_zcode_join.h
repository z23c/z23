/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One join recipe for C23 Commons package hosting and compile work. */

#ifndef ZCL_TOOLS_NATIVE_ZCODE_JOIN_H
#define ZCL_TOOLS_NATIVE_ZCODE_JOIN_H

#include "json/json.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_ZCODE_JOIN_FLAGS "-packagehost=1 -buildworker=1"
#define ZCL_ZCODE_HOSTING_REQUIREMENT \
    "run the full node with -packagehost=1 -buildworker=1"

struct zcl_zcode_join_posture {
    bool package_hosting;
    bool build_worker;
    bool joined;
    const char *join_flags;
    const char *hosting_requirement;
    const char *offline_next_command;
};

/* Reads this process's -packagehost / -buildworker flags and whether the
 * in-process work node has local compile capability. One-shot CLI processes
 * report joined=false unless those flags were passed to this process. */
bool zcl_zcode_join_posture_fill(struct zcl_zcode_join_posture *out);

/* Emits join_flags, package_hosting, build_worker, joined, and
 * hosting_requirement. */
bool zcl_zcode_join_posture_push_json(struct json_value *data,
                                      const struct zcl_zcode_join_posture *join);

/* ── the composed join verdict ─────────────────────────────────────────────
 *
 * A join verdict is a TUPLE, never a boolean, and speed is never one of its
 * terms.
 *
 * WHY THIS IS NOT A STYLE CHOICE. Every timeout encodes an economic
 * assumption about the hardware it was tuned on. A single pass/fail that
 * folds latency into the verdict grades a slow-but-honest machine "fail" —
 * and a seek-bound spinning-disk box under real IO pressure is exactly the
 * class of hardware a permissionless network must admit. A network does not
 * centralize by a policy decision; it centralizes by a constant. So latency
 * lives BESIDE the dimensions as a measured number, and no code path here
 * reads it when deciding anything.
 *
 * `reachable + slow + fresh` is a perfectly good verdict and must beat a bare
 * `fail`. A caller that wants a scalar derives one from the tuple and owns
 * that choice explicitly; this primitive never pre-collapses it. */
enum zcl_join_signal {
    /* The DEFAULT, and it is not "false": a dimension nobody has proven yet.
     * A zero-initialized verdict therefore claims nothing. */
    ZCL_JOIN_SIGNAL_UNCONFIRMED = 0,
    ZCL_JOIN_SIGNAL_CONFIRMED,
    ZCL_JOIN_SIGNAL_FAILED,
    /* Structurally invisible from THIS vantage point — a one-shot CLI cannot
     * see a resident node's Tor circuits. Distinct from UNCONFIRMED so a
     * report can say "nothing here can answer that" instead of implying the
     * check ran and came back empty. Never counts as CONFIRMED. */
    ZCL_JOIN_SIGNAL_UNOBSERVABLE,
};

struct zcl_join_verdict {
    enum zcl_join_signal reachable;    /* a peer can open a connection to us */
    enum zcl_join_signal responsive;   /* we answer what we are asked */
    enum zcl_join_signal fresh;        /* what we would serve is current */
    enum zcl_join_signal serving;      /* we are actually serving content */
    /* TELEMETRY, reported beside the dimensions and never folded into them.
     * Negative means not measured — which is not the same as fast or slow. */
    int64_t latency_ms;
    int64_t data_age_s;
    /* Plain words for what could see these dimensions, so an UNOBSERVABLE row
     * is actionable rather than mysterious. */
    const char *vantage;
};

/* ── announcements are promises ────────────────────────────────────────────
 *
 * READY is emitted only when ALL FOUR stages are CONFIRMED. Not three of
 * four, not "descriptor published and probably the rest".
 *
 * A slow node that announces READY early pays compound interest on the broken
 * promise: peers dial it, the dial fails, and it is scored down for the
 * honesty gap rather than for its speed. Making READY unreachable until the
 * last stage confirms is what stops a slow node from making that mistake.
 *
 * Each partial stage is separately nameable, so "still building circuits" is
 * a reportable state instead of a silent not-ready. */
struct zcl_join_readiness {
    enum zcl_join_signal descriptor_published;
    enum zcl_join_signal rendezvous_established;
    enum zcl_join_signal circuit_built;
    enum zcl_join_signal listener_accepting;
};

/* "confirmed" | "unconfirmed" | "failed" | "unobservable". */
const char *zcl_join_signal_name(enum zcl_join_signal signal);

/* "ready" ONLY when all four stages are CONFIRMED; otherwise the name of the
 * FIRST stage that is not: "publishing-descriptor",
 * "establishing-rendezvous", "building-circuit", "opening-listener".
 *
 * ⛔ This must stay REACHABLE. A gate whose passing condition can never be
 * met is worse than no gate, because it reports confidently — a mesh check
 * that required state=="active" read 0/4 for hours while onion P2P was in
 * fact working. test_zcode_node_command proves an all-CONFIRMED readiness
 * really does yield "ready". */
const char *zcl_join_readiness_state(const struct zcl_join_readiness *ready);

/* The SIGNAL of that same first outstanding stage — CONFIRMED only when all
 * four are. It exists because a stage name alone reads like progress:
 * "publishing-descriptor" sounds like work underway, when the truth may be
 * that this vantage point simply cannot see the stage at all. Reporting the
 * name and the signal side by side keeps "we do not know" distinct from
 * "in progress" and from "it failed". */
enum zcl_join_signal zcl_join_readiness_outstanding(
    const struct zcl_join_readiness *ready);

/* Emits `verdict` (the four dimensions plus latency_ms / data_age_s as
 * separate telemetry fields) and `announcement` (the four stages plus the
 * derived state name). Either pointer may be NULL to skip that half. */
bool zcl_join_verdict_push_json(struct json_value *data,
                                const struct zcl_join_verdict *verdict,
                                const struct zcl_join_readiness *ready);

#ifdef __cplusplus
}
#endif

#endif
