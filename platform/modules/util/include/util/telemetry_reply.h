/* Fitting a rendered telemetry document into a command reply's byte frame.
 *
 * Every ops.telemetry.* leaf has the same problem: it renders a domain at some
 * requested view, and the registry will only ship a document up to
 * zcl_command_spec.budget_bytes. Over-budget is not truncation — write_bounded_json()
 * in engine/modules/kernel/src/command_registry.c writes out[0]=0 and returns 0 — so a
 * controller that ships an oversized document ships NOTHING, and the CLI
 * reports it as a budget failure with an empty body. The reader cannot tell
 * that from "the subsystem had nothing to say".
 *
 * So the document is measured before it is shipped, and the view steps down
 * (full -> normal -> summary) until it fits. A stated downgrade is diagnosable;
 * an empty reply is not.
 *
 * This lives here, once, rather than in each domain's controller, because it
 * is entirely domain-agnostic and there are ten leaves that need it. The
 * per-domain copies this replaced also shared a bug worth stating plainly:
 * they returned the summary view unconditionally at the bottom of the ladder,
 * so a domain whose SUMMARY still overflowed produced exactly the empty reply
 * the whole mechanism exists to prevent — and reported success. Hence
 * telemetry_reply_fit.fits: the caller is told when nothing fit, and owes the
 * reader a typed error rather than a blank document.
 */
#ifndef ZCL_UTIL_TELEMETRY_REPLY_H
#define ZCL_UTIL_TELEMETRY_REPLY_H

#include <stdbool.h>
#include <stddef.h>

#include "util/telemetry_render.h"

struct json_value;

/* What happened when a document was fitted to a frame. */
struct telemetry_reply_fit {
    /* The view actually rendered — compare against the requested view to see
     * whether a downgrade happened, and say so in the reply. */
    enum telemetry_view view;
    /* telemetry_render() succeeded. When false, `doc` holds nothing usable
     * and the other fields are meaningless. */
    bool rendered;
    /* The rendered document is within the frame. When false, EVERY view was
     * tried and even the smallest overflowed: do not ship `doc`. Fail with a
     * typed error naming `bytes` and the frame instead. */
    bool fits;
    /* Serialized size of the document now in `doc`, as measured. */
    size_t bytes;
    /* Views tried, always >= 1. Useful in a `next[]` hint or a log line. */
    unsigned attempts;
};

/* Render `snap` under `schema` at the largest view that fits `frame` bytes,
 * starting at `want` and stepping down. `doc` must be an initialized
 * json_value owned by the caller; on return it holds the last document
 * rendered. Never returns a document known to overflow without also setting
 * fit.fits = false.
 *
 * `frame` is the space available for THIS document, which is the leaf's
 * budget_bytes less whatever the envelope around it costs — the caller knows
 * that, this does not.
 */
bool telemetry_reply_render_fitting(
    const struct telemetry_domain_schema *schema, const void *snap,
    enum telemetry_view want, size_t frame, struct json_value *doc,
    struct telemetry_reply_fit *out);

#endif /* ZCL_UTIL_TELEMETRY_REPLY_H */
