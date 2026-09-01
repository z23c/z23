/* See util/telemetry_reply.h for why this exists and what it guarantees. */

#include "util/telemetry_reply.h"

#include "json/json.h"
#include "util/log_macros.h"

/* The view ladder, largest first. Stepping is a table walk rather than a
 * chain of ternaries so that adding a tier is one row here and nothing else;
 * the previous per-controller copies encoded the ladder as
 * `v == TLV_FULL ? TLV_NORMAL : TLV_SUMMARY`, which silently does the wrong
 * thing the moment a fourth tier exists. */
static const enum telemetry_view k_ladder[] = {
    TLV_FULL,
    TLV_NORMAL,
    TLV_SUMMARY,
};
static const unsigned k_ladder_len =
    (unsigned)(sizeof k_ladder / sizeof k_ladder[0]);

/* Index of `v` in the ladder, or 0 (the largest) if it is not a ladder view —
 * an unknown view starts at the top and steps down like any other, rather
 * than being rejected, because refusing to answer is worse than answering
 * smaller. */
static unsigned ladder_index(enum telemetry_view v)
{
    for (unsigned i = 0; i < k_ladder_len; i++) {
        if (k_ladder[i] == v)
            return i;
    }
    return 0;
}

bool telemetry_reply_render_fitting(
    const struct telemetry_domain_schema *schema, const void *snap,
    enum telemetry_view want, size_t frame, struct json_value *doc,
    struct telemetry_reply_fit *out)
{
    if (!schema || !snap || !doc || !out)
        LOG_FAIL("telemetry_reply", "render_fitting: NULL argument");

    *out = (struct telemetry_reply_fit){
        .view = want, .rendered = false, .fits = false, .bytes = 0,
        .attempts = 0,
    };

    for (unsigned i = ladder_index(want); i < k_ladder_len; i++) {
        enum telemetry_view v = k_ladder[i];
        out->attempts++;
        out->view = v;

        if (!telemetry_render(schema, snap, v, NULL, doc)) {
            /* A render failure is not a size problem and stepping down will
             * not cure it. Report it as-is rather than burning the ladder. */
            out->rendered = false;
            out->fits = false;
            out->bytes = 0;
            LOG_FAIL("telemetry_reply",
                     "render_fitting: telemetry_render failed for domain "
                     "'%s' at view '%s'",
                     schema->domain ? schema->domain : "(null)",
                     telemetry_view_name(v));
        }
        out->rendered = true;

        /* json_write(doc, NULL, 0) measures without serializing into a
         * buffer. Measure every tier including the last: the caller is owed
         * the real size even when nothing fits, because that number is the
         * whole content of the error it has to raise. */
        size_t n = json_write(doc, NULL, 0);
        out->bytes = n;
        if (n <= frame) {
            out->fits = true;
            return true;
        }
    }

    /* Every tier overflowed. `doc` holds the smallest one; out->fits is false
     * and out->bytes says by how much it missed. Shipping this document would
     * produce an empty reply, so the caller must not — but that is the
     * caller's error to name, not ours to hide, and this is a successful
     * measurement of a bad situation rather than a failure to measure. */
    return true;
}
