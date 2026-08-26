/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_reproduce — implementation of the node-artifact reproduction verdict
 * declared in vcs/node_reproduce.h. Pure evaluation over two parsed
 * receipts plus a bounded text codec. No filesystem, no compiler, no
 * hashing, no network. */

#include "vcs/node_reproduce.h"

#include "base/hex.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

const char *vcs_node_producer_string(enum vcs_node_producer producer)
{
    switch (producer) {
    case VCS_NODE_PRODUCER_UNKNOWN: return "unknown";
    case VCS_NODE_PRODUCER_RECEIVED: return "received";
    case VCS_NODE_PRODUCER_LOCAL_REBUILD: return "local-rebuild";
    }
    return "unknown";
}

const char *vcs_node_repro_verdict_string(enum vcs_node_repro_verdict v)
{
    switch (v) {
    case VCS_NODE_REPRO_UNEVALUATED: return "unevaluated";
    case VCS_NODE_REPRO_MATCH: return "match";
    case VCS_NODE_REPRO_PARTIAL: return "partial";
    case VCS_NODE_REPRO_SOURCE_DIFFERS: return "source-differs";
    case VCS_NODE_REPRO_TOOLCHAIN_DIFFERS: return "toolchain-differs";
    case VCS_NODE_REPRO_CLAIM_FALSE: return "claim-false";
    case VCS_NODE_REPRO_UNDIAGNOSED: return "undiagnosed";
    case VCS_NODE_REPRO_NO_ARTIFACTS: return "no-artifacts";
    case VCS_NODE_REPRO_NOT_LOCAL: return "not-locally-rebuilt";
    case VCS_NODE_REPRO_RECEIPT_INVALID: return "receipt-invalid";
    }
    return "unknown-verdict";
}

const char *vcs_node_repro_rule_string(enum vcs_node_repro_rule rule)
{
    switch (rule) {
    case VCS_NODE_ROW_MATCH: return "match";
    case VCS_NODE_ROW_CONTENT_DIFFERS: return "content-differs";
    case VCS_NODE_ROW_SIZE_DIFFERS: return "size-differs";
    case VCS_NODE_ROW_MISSING_FROM_REBUILD: return "missing-from-rebuild";
    case VCS_NODE_ROW_MISSING_FROM_RECEIVED: return "missing-from-received";
    }
    return "unknown-rule";
}

/* ── report helpers ────────────────────────────────────────────────────── */

static void nr_verdict(struct vcs_node_repro_report *out,
                       enum vcs_node_repro_verdict v, const char *fmt, ...)
{
    out->verdict = (uint8_t)v;
    va_list ap;
    va_start(ap, fmt);
    if (fmt)
        (void)vsnprintf(out->detail, sizeof(out->detail), fmt, ap);
    else
        out->detail[0] = '\0';
    va_end(ap);
}

static void nr_row(struct vcs_node_repro_report *out, const char *path,
                   enum vcs_node_repro_rule rule, const char *fmt, ...)
{
    if (out->row_count >= sizeof(out->rows) / sizeof(out->rows[0]))
        return;
    struct vcs_node_repro_row *row = &out->rows[out->row_count++];
    (void)snprintf(row->path, sizeof(row->path), "%s", path ? path : "");
    row->rule = (uint8_t)rule;
    va_list ap;
    va_start(ap, fmt);
    if (fmt)
        (void)vsnprintf(row->detail, sizeof(row->detail), fmt, ap);
    else
        row->detail[0] = '\0';
    va_end(ap);
}

/* Copy one side's unverified components into the report's gap list. They
 * are carried by value so a renderer that only reads the report still
 * names every gap; dropping one is the failure mode this file forbids. */
static void nr_gaps(struct vcs_node_repro_report *out, const char *side,
                    const struct vcs_node_receipt *r)
{
    const size_t cap = sizeof(out->gaps) / sizeof(out->gaps[0]);
    for (size_t i = 0; i < r->unverified_count && out->gap_count < cap; i++) {
        struct vcs_node_unverified *g = &out->gaps[out->gap_count++];
        (void)snprintf(g->component, sizeof(g->component), "%s",
                       r->unverified[i].component);
        (void)snprintf(g->reason, sizeof(g->reason), "%s: %s", side,
                       r->unverified[i].reason);
    }
}

static const struct vcs_node_artifact *nr_find(
    const struct vcs_node_receipt *r, const char *path)
{
    for (size_t i = 0; i < r->artifact_count; i++)
        if (strcmp(r->artifacts[i].path, path) == 0)
            return &r->artifacts[i];
    return NULL;
}

/* First 16 hex characters of a digest — enough for a human to see two
 * values are different without pasting 64 characters into a report. */
static void nr_short(const uint8_t sha3[32], char out[17])
{
    char full[65];
    zcl_hex_encode(sha3, 32, full);
    memcpy(out, full, 16);
    out[16] = '\0';
}

static bool nr_hex64_set(const char *s)
{
    return s[0] != '\0';
}

/* ── the compare ───────────────────────────────────────────────────────── */

bool vcs_node_reproduce_compare(const struct vcs_node_receipt *received,
                                const struct vcs_node_receipt *rebuilt,
                                struct vcs_node_repro_report *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));

    if (!received || !rebuilt) {
        nr_verdict(out, VCS_NODE_REPRO_RECEIPT_INVALID,
                   "a receipt was not supplied");
        return false;
    }

    /* THE REFUSAL THAT MAKES THIS WORTH RUNNING. Comparing a publisher's
     * recorded hash against the same publisher's recorded hash is not a
     * check; it is the publisher agreeing with themselves. One side must
     * be what the user was handed, the other must be bytes this machine
     * produced, and nothing else is accepted. */
    if (received->producer != VCS_NODE_PRODUCER_RECEIVED ||
        rebuilt->producer != VCS_NODE_PRODUCER_LOCAL_REBUILD) {
        nr_verdict(out, VCS_NODE_REPRO_NOT_LOCAL,
                   "refusing to compare %s against %s: one side must be the "
                   "artifact you received and the other must be bytes this "
                   "machine built",
                   vcs_node_producer_string(
                       (enum vcs_node_producer)received->producer),
                   vcs_node_producer_string(
                       (enum vcs_node_producer)rebuilt->producer));
        return false;
    }

    /* Coverage first, so it is populated on every exit below. */
    nr_gaps(out, "received", received);
    nr_gaps(out, "rebuilt", rebuilt);
    out->unverified = (uint32_t)out->gap_count;

    out->source_id_known = nr_hex64_set(received->source_id) &&
                           nr_hex64_set(rebuilt->source_id);
    out->source_id_agrees =
        out->source_id_known &&
        strcmp(received->source_id, rebuilt->source_id) == 0;
    out->toolchain_known = nr_hex64_set(received->toolchain_id) &&
                           nr_hex64_set(rebuilt->toolchain_id);
    out->toolchain_agrees =
        out->toolchain_known &&
        strcmp(received->toolchain_id, rebuilt->toolchain_id) == 0;

    /* Rows over the UNION of both path sets. An artifact only one side
     * emitted is a reported gap, never a silent omission. */
    for (size_t i = 0; i < received->artifact_count; i++) {
        const struct vcs_node_artifact *a = &received->artifacts[i];
        const struct vcs_node_artifact *b = nr_find(rebuilt, a->path);
        out->compared++;
        if (!b) {
            out->differed++;
            nr_row(out, a->path, VCS_NODE_ROW_MISSING_FROM_REBUILD,
                   "this machine's build did not emit it");
            continue;
        }
        if (a->bytes != b->bytes) {
            out->differed++;
            nr_row(out, a->path, VCS_NODE_ROW_SIZE_DIFFERS,
                   "received %" PRIu64 " bytes, built %" PRIu64 " bytes",
                   a->bytes, b->bytes);
            continue;
        }
        if (memcmp(a->sha3, b->sha3, 32) != 0) {
            char sa[17], sb[17];
            nr_short(a->sha3, sa);
            nr_short(b->sha3, sb);
            out->differed++;
            nr_row(out, a->path, VCS_NODE_ROW_CONTENT_DIFFERS,
                   "same size, different bytes: received sha3 %s…, built %s…",
                   sa, sb);
            continue;
        }
        out->matched++;
        nr_row(out, a->path, VCS_NODE_ROW_MATCH, "");
    }
    for (size_t i = 0; i < rebuilt->artifact_count; i++) {
        const struct vcs_node_artifact *b = &rebuilt->artifacts[i];
        if (nr_find(received, b->path))
            continue;
        out->compared++;
        out->differed++;
        nr_row(out, b->path, VCS_NODE_ROW_MISSING_FROM_RECEIVED,
               "this machine's build emitted it and the artifact you "
               "received does not contain it");
    }

    if (out->compared == 0) {
        nr_verdict(out, VCS_NODE_REPRO_NO_ARTIFACTS,
                   "neither receipt committed an artifact, so nothing was "
                   "checked; this is not a pass");
        return false;
    }

    if (out->differed == 0) {
        if (out->unverified > 0) {
            nr_verdict(out, VCS_NODE_REPRO_PARTIAL,
                       "every one of the %u artifact(s) this machine could "
                       "rebuild is byte-identical, and %u component(s) could "
                       "not be rebuilt here and stay UNVERIFIED",
                       out->matched, out->unverified);
            return false;
        }
        nr_verdict(out, VCS_NODE_REPRO_MATCH,
                   "all %u artifact(s) byte-identical to the bytes this "
                   "machine built from source",
                   out->matched);
        return true;
    }

    /* Diagnosis, in evidence order. Source first: if we did not rebuild the
     * same source we have said nothing about the publisher at all. */
    if (!out->source_id_known) {
        nr_verdict(out, VCS_NODE_REPRO_UNDIAGNOSED,
                   "%u artifact(s) differ, but a source identity is missing "
                   "on one side (received=%s built=%s) so this cannot say "
                   "whether the source, the toolchain, or the claim is at "
                   "fault",
                   out->differed,
                   nr_hex64_set(received->source_id) ? "recorded" : "absent",
                   nr_hex64_set(rebuilt->source_id) ? "recorded" : "absent");
        return false;
    }
    if (!out->source_id_agrees) {
        nr_verdict(out, VCS_NODE_REPRO_SOURCE_DIFFERS,
                   "the source tree built here is not the source tree that "
                   "artifact came from (received %.16s…, built %.16s…) — "
                   "this says nothing about the publisher, only that a "
                   "different experiment was run",
                   received->source_id, rebuilt->source_id);
        return false;
    }
    if (!out->toolchain_known) {
        nr_verdict(out, VCS_NODE_REPRO_UNDIAGNOSED,
                   "same source, %u artifact(s) differ, and no toolchain "
                   "identity was recorded on %s — a toolchain gap and a false "
                   "publisher claim look identical from here",
                   out->differed,
                   nr_hex64_set(received->toolchain_id) ? "the rebuild"
                                                        : "the artifact");
        return false;
    }
    if (!out->toolchain_agrees) {
        nr_verdict(out, VCS_NODE_REPRO_TOOLCHAIN_DIFFERS,
                   "same source, but your toolchain differs from the "
                   "publisher's (%.16s… vs %.16s…): %u artifact(s) differ and "
                   "that difference explains them",
                   rebuilt->toolchain_id, received->toolchain_id,
                   out->differed);
        return false;
    }
    nr_verdict(out, VCS_NODE_REPRO_CLAIM_FALSE,
               "same source AND the same toolchain, and %u artifact(s) still "
               "differ: every declared input agrees, so the artifact you "
               "received is not what this source and toolchain produce",
               out->differed);
    return false;
}

/* ── the receipt text codec ────────────────────────────────────────────── */

static void nr_why(char *why, size_t cap, const char *fmt, ...)
{
    if (!why || cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, cap, fmt, ap);
    va_end(ap);
}

/* Advance past spaces and tabs. */
static const char *nr_skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t'))
        p++;
    return p;
}

/* Copy the token at *p into out (bounded); advance *p past it. Returns the
 * token length, or 0 when there is no token or it does not fit. */
static size_t nr_token(const char **p, const char *end, char *out,
                       size_t cap)
{
    const char *s = nr_skip_ws(*p, end);
    const char *t = s;
    while (t < end && *t != ' ' && *t != '\t')
        t++;
    size_t n = (size_t)(t - s);
    if (n == 0 || n >= cap)
        return 0;
    memcpy(out, s, n);
    out[n] = '\0';
    *p = t;
    return n;
}

/* Copy the rest of the line into out (bounded, trailing space trimmed). */
static bool nr_rest(const char *p, const char *end, char *out, size_t cap)
{
    p = nr_skip_ws(p, end);
    size_t n = (size_t)(end - p);
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
        n--;
    if (n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool nr_hex64(const char *s)
{
    if (strlen(s) != 64)
        return false;
    uint8_t tmp[32];
    return zcl_hex_decode_lower(s, tmp, sizeof(tmp));
}

static bool nr_u64(const char *s, uint64_t *out)
{
    if (!s[0])
        return false;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        if (v > (UINT64_MAX - (uint64_t)(*p - '0')) / 10u)
            return false;
        v = v * 10u + (uint64_t)(*p - '0');
    }
    *out = v;
    return true;
}

bool vcs_node_receipt_decode(const char *text, size_t len,
                             struct vcs_node_receipt *out, char *why,
                             size_t why_cap)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (why && why_cap)
        why[0] = '\0';
    if (!text) {
        nr_why(why, why_cap, "no receipt text");
        return false;
    }
    if (len > VCS_NODE_REPRO_MAX_WIRE_BYTES) {
        nr_why(why, why_cap, "receipt exceeds %u bytes",
               (unsigned)VCS_NODE_REPRO_MAX_WIRE_BYTES);
        return false;
    }

    bool saw_schema = false;
    bool saw_producer = false;
    size_t line_no = 0;
    const char *p = text;
    const char *stop = text + len;

    while (p < stop) {
        const char *nl = memchr(p, '\n', (size_t)(stop - p));
        const char *end = nl ? nl : stop;
        const char *line = p;
        p = nl ? nl + 1 : stop;
        line_no++;
        /* Tolerate CRLF. */
        if (end > line && end[-1] == '\r')
            end--;
        line = nr_skip_ws(line, end);
        if (line == end || *line == '#')
            continue;

        if (!saw_schema) {
            char schema[64];
            if (!nr_rest(line, end, schema, sizeof(schema)) ||
                strcmp(schema, VCS_NODE_REPRO_SCHEMA) != 0) {
                nr_why(why, why_cap,
                       "line %zu: first directive must be %s", line_no,
                       VCS_NODE_REPRO_SCHEMA);
                return false;
            }
            saw_schema = true;
            continue;
        }

        char key[32];
        const char *cur = line;
        if (!nr_token(&cur, end, key, sizeof(key))) {
            nr_why(why, why_cap, "line %zu: unreadable directive", line_no);
            return false;
        }

        if (strcmp(key, "producer") == 0) {
            char v[32];
            if (!nr_token(&cur, end, v, sizeof(v))) {
                nr_why(why, why_cap, "line %zu: producer needs a value",
                       line_no);
                return false;
            }
            if (strcmp(v, "received") == 0)
                out->producer = VCS_NODE_PRODUCER_RECEIVED;
            else if (strcmp(v, "local-rebuild") == 0)
                out->producer = VCS_NODE_PRODUCER_LOCAL_REBUILD;
            else {
                nr_why(why, why_cap,
                       "line %zu: producer must be received or local-rebuild",
                       line_no);
                return false;
            }
            saw_producer = true;
        } else if (strcmp(key, "source_id") == 0 ||
                   strcmp(key, "toolchain") == 0) {
            char v[80];
            if (!nr_token(&cur, end, v, sizeof(v)) || !nr_hex64(v)) {
                nr_why(why, why_cap,
                       "line %zu: %s must be 64 lowercase hex characters",
                       line_no, key);
                return false;
            }
            char *dst = key[0] == 's' ? out->source_id : out->toolchain_id;
            memcpy(dst, v, 65);
        } else if (strcmp(key, "toolchain_desc") == 0) {
            if (!nr_rest(cur, end, out->toolchain_desc,
                         sizeof(out->toolchain_desc))) {
                nr_why(why, why_cap, "line %zu: toolchain_desc too long",
                       line_no);
                return false;
            }
        } else if (strcmp(key, "artifact") == 0) {
            if (out->artifact_count >= VCS_NODE_REPRO_MAX_ARTIFACTS) {
                nr_why(why, why_cap,
                       "line %zu: more than %u artifacts; refusing rather "
                       "than dropping one", line_no,
                       (unsigned)VCS_NODE_REPRO_MAX_ARTIFACTS);
                return false;
            }
            struct vcs_node_artifact *a =
                &out->artifacts[out->artifact_count];
            char hex[80], size[32];
            if (!nr_token(&cur, end, hex, sizeof(hex)) || !nr_hex64(hex) ||
                !zcl_hex_decode_lower(hex, a->sha3, sizeof(a->sha3))) {
                nr_why(why, why_cap,
                       "line %zu: artifact needs a 64-lowercase-hex sha3-256",
                       line_no);
                return false;
            }
            if (!nr_token(&cur, end, size, sizeof(size)) ||
                !nr_u64(size, &a->bytes)) {
                nr_why(why, why_cap,
                       "line %zu: artifact needs a decimal byte count",
                       line_no);
                return false;
            }
            if (!nr_rest(cur, end, a->path, sizeof(a->path)) || !a->path[0]) {
                nr_why(why, why_cap,
                       "line %zu: artifact needs a relative path", line_no);
                return false;
            }
            out->artifact_count++;
        } else if (strcmp(key, "unverified") == 0) {
            if (out->unverified_count >= VCS_NODE_REPRO_MAX_UNVERIFIED) {
                nr_why(why, why_cap,
                       "line %zu: more than %u unverified components; "
                       "refusing rather than dropping one", line_no,
                       (unsigned)VCS_NODE_REPRO_MAX_UNVERIFIED);
                return false;
            }
            struct vcs_node_unverified *u =
                &out->unverified[out->unverified_count];
            if (!nr_token(&cur, end, u->component, sizeof(u->component))) {
                nr_why(why, why_cap,
                       "line %zu: unverified needs a component name",
                       line_no);
                return false;
            }
            if (!nr_rest(cur, end, u->reason, sizeof(u->reason)) ||
                !u->reason[0]) {
                nr_why(why, why_cap,
                       "line %zu: unverified needs a reason — a component "
                       "named without one cannot be judged", line_no);
                return false;
            }
            out->unverified_count++;
        } else {
            /* A directive this build does not understand may be exactly the
             * one that would have changed the verdict. Refuse. */
            nr_why(why, why_cap, "line %zu: unknown directive '%s'", line_no,
                   key);
            return false;
        }
    }

    if (!saw_schema) {
        nr_why(why, why_cap, "empty receipt (no %s line)",
               VCS_NODE_REPRO_SCHEMA);
        return false;
    }
    if (!saw_producer) {
        nr_why(why, why_cap,
               "receipt names no producer; a receipt that does not say who "
               "made the bytes cannot be compared");
        return false;
    }
    return true;
}

size_t vcs_node_receipt_encode(const struct vcs_node_receipt *receipt,
                               char *buf, size_t cap)
{
    if (!receipt || !buf || cap == 0)
        return 0;
    size_t n = 0;
    int w;

#define NR_APPEND(...)                                                       \
    do {                                                                     \
        w = snprintf(buf + n, cap - n, __VA_ARGS__);                         \
        if (w < 0 || (size_t)w >= cap - n)                                   \
            return 0;                                                        \
        n += (size_t)w;                                                      \
    } while (0)

    NR_APPEND("%s\n", VCS_NODE_REPRO_SCHEMA);
    NR_APPEND("producer %s\n",
              vcs_node_producer_string(
                  (enum vcs_node_producer)receipt->producer));
    if (receipt->source_id[0])
        NR_APPEND("source_id %s\n", receipt->source_id);
    if (receipt->toolchain_id[0])
        NR_APPEND("toolchain %s\n", receipt->toolchain_id);
    if (receipt->toolchain_desc[0])
        NR_APPEND("toolchain_desc %s\n", receipt->toolchain_desc);
    for (size_t i = 0; i < receipt->artifact_count; i++) {
        char hex[65];
        zcl_hex_encode(receipt->artifacts[i].sha3, 32, hex);
        NR_APPEND("artifact %s %" PRIu64 " %s\n", hex,
                  receipt->artifacts[i].bytes, receipt->artifacts[i].path);
    }
    for (size_t i = 0; i < receipt->unverified_count; i++)
        NR_APPEND("unverified %s %s\n", receipt->unverified[i].component,
                  receipt->unverified[i].reason);
#undef NR_APPEND
    return n;
}
