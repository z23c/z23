/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fixed-size text fields that cannot be cut silently.
 *
 * Why this exists
 * ----------------
 * `snprintf(field, sizeof field, "%s", src)` is memory-safe and honesty-unsafe.
 * It returns the length it WOULD have written, and a caller that discards that
 * return has thrown away the only evidence that the stored text is partial.
 * The reader then gets a sentence that stops mid-word and no indication that
 * anything is missing — a degraded diagnosis presented as a complete one.
 *
 * That matters most exactly where it hurts most: an operator-facing blocker
 * reason. A blocker's whole job is to say WHY progress stopped and what clears
 * it, and the "what clears it" clause is at the END of the sentence — the half
 * a silent cut always eats first. Measured examples in this tree exceeded
 * BLOCKER_REASON_MAX by 25-105 bytes on their live paths.
 *
 * The contract
 * -------------
 * These calls store as much as fits and, when the source did not fit:
 *   1. leave a VISIBLE in-band marker at the end of the stored text
 *      (`...[cut <src_len>/<cap>]`) so any reader — JSON dump, log line,
 *      terminal — can see the field is partial without consulting anything
 *      else, and
 *   2. emit one WARN line naming the field, the source length, the field
 *      capacity, and the FULL untruncated text, so nothing is actually lost.
 *
 * They NEVER abort, longjmp, allocate, or fail the caller. The return value is
 * advisory: `true` = stored whole, `false` = stored partial (or an argument was
 * unusable). A caller that ignores it behaves exactly as before, except the cut
 * is now visible. This is deliberate — a too-long reason must never turn a
 * recoverable stall into an error path, because these run on the diagnosis
 * side of a failure that has already happened.
 *
 * Header-only `static inline`, for the same reason as base/hex.h and
 * base/serialize_le.h: several small tools link explicit source lists, and
 * this keeps every one of them buildable without a new link edge.
 *
 * Usage
 * ------
 *   char reason[BLOCKER_REASON_MAX];
 *   (void)zcl_text_fit(reason, sizeof reason, long_text, "blocker", "reason");
 *
 *   // set-join accumulator (comma-separated warning list)
 *   (void)zcl_text_fit_append(field, sizeof field, ",", one_more,
 *                             "health", "warning_reasons");
 */

#ifndef ZCL_BASE_TEXT_FIT_H
#define ZCL_BASE_TEXT_FIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "base/log_macros.h"

/* Longest marker `zcl_text_fit_marker` can produce: the literal plus two
 * size_t decimal renderings. 64 is comfortably above the 20+20+11 worst case. */
#define ZCL_TEXT_FIT_MARKER_MAX 64

/* The stable substring a reader (or a test) can look for to know a field was
 * cut. Deliberately ASCII so it survives JSON, node.log, and a dumb terminal. */
#define ZCL_TEXT_FIT_MARKER_TAG "...[cut "

/* Render the marker for a source of `src_len` bytes that had to fit `cap`.
 * Both inputs are known before any packing decision, so the marker's own
 * length never depends on itself. Returns strlen(out). */
static inline size_t zcl_text_fit_marker(char *out, size_t out_cap,
                                         size_t src_len, size_t cap)
{
    int n = snprintf(out, out_cap, ZCL_TEXT_FIT_MARKER_TAG "%zu/%zu]",
                     src_len, cap);
    if (n < 0) {                       /* cannot happen for these inputs */
        out[0] = '\0';
        return 0;
    }
    size_t len = (size_t)n;
    return len < out_cap ? len : out_cap - 1;
}

/* The one truncation-reporting core. Packs `keep` bytes of `src` plus the
 * marker into `dst[cap]`, then reports. Every entry point below funnels here,
 * so there is exactly one place that decides what a cut looks like and exactly
 * one place that logs it. */
static inline void zcl_text_fit_store_cut(char *dst, size_t cap,
                                          size_t prefix_len,
                                          const char *src, size_t src_len,
                                          size_t intended_len,
                                          const char *text_kind,
                                          const char *domain, const char *field,
                                          const char *file, int line)
{
    char marker[ZCL_TEXT_FIT_MARKER_MAX];
    size_t mlen = zcl_text_fit_marker(marker, sizeof marker, intended_len, cap);

    size_t room = cap - 1;             /* bytes usable before the NUL */
    size_t kept = 0;                   /* bytes of the INTENDED text that survived */
    if (mlen >= room) {
        /* The field is too small to hold even the marker. Store the marker's
         * own prefix: a reader still sees "...[cut" and knows not to trust the
         * text, which beats a clean-looking fragment. */
        memcpy(dst, marker, room);
        dst[room] = '\0';
    } else {
        size_t body = room - mlen;
        if (body < prefix_len)
            prefix_len = body;         /* not even the existing text survives */
        size_t take = body - prefix_len;
        if (take > src_len)
            take = src_len;
        memcpy(dst + prefix_len, src, take);
        memcpy(dst + prefix_len + take, marker, mlen);
        dst[prefix_len + take + mlen] = '\0';
        kept = prefix_len + take;
    }

    /* Report it. WARN, not an error rank: the node is fine, the SENTENCE was
     * cut. The full text goes in the log line so nothing is actually lost —
     * the field shows the operator it is partial, the log shows them the rest.
     * `lost` counts bytes of the intended text, so it excludes the marker the
     * field spends on saying so. Emitted with the CALLER's file:line (passed
     * in), not this header's. */
    ZCL_LOG_EMIT_AT(ZCL_LOG_WARN,
                    "[%s] %s:%d zcl_text_fit(): field=%s did not fit: "
                    "intended_len=%zu capacity=%zu lost=%zu stored=\"%s\" "
                    "%s=\"%s\"\n",
                    domain ? domain : "text_fit", file ? file : "?", line,
                    field ? field : "?", intended_len, cap,
                    intended_len - kept, dst,
                    text_kind ? text_kind : "full", src ? src : "");
}

/* Copy `src` into the `cap`-byte field `dst`. See the header comment for the
 * contract. `domain` is a log domain ("blocker", "health", ...), `field` names
 * the struct member so the log line is actionable. */
static inline bool zcl_text_fit_impl(char *dst, size_t cap, const char *src,
                                     const char *domain, const char *field,
                                     const char *file, int line)
{
    if (!dst || cap == 0)
        return false;                  /* nowhere to store; nothing to say */
    if (!src) {
        dst[0] = '\0';
        return true;                   /* empty is a faithful copy of nothing */
    }
    size_t len = strlen(src);
    if (len < cap) {
        memcpy(dst, src, len + 1);
        return true;
    }
    zcl_text_fit_store_cut(dst, cap, 0, src, len, len, "full", domain, field,
                           file, line);
    return false;
}

/* Append `src` to whatever NUL-terminated text is already in `dst[cap]`,
 * inserting `sep` first when `dst` is non-empty (pass NULL/"" for none). Same
 * visible-marker + report contract; used by the comma-joined warning
 * accumulators, where a partial append otherwise makes a "7 warnings" count
 * sit next to a list that visibly holds five and a half. */
static inline bool zcl_text_fit_append_impl(char *dst, size_t cap,
                                            const char *sep, const char *src,
                                            const char *domain,
                                            const char *field,
                                            const char *file, int line)
{
    if (!dst || cap == 0)
        return false;
    if (!src || !src[0])
        return true;

    /* Bounded length, hand-rolled: this header must compile in a TU that has
     * not asked for POSIX 2008 (strnlen is not ISO C), because some tools link
     * their own explicit source lists with their own flags. */
    size_t used = 0;
    while (used < cap && dst[used] != '\0')
        used++;
    if (used >= cap) {                 /* caller handed us an unterminated field */
        dst[cap - 1] = '\0';
        used = cap - 1;
    }
    size_t seplen = (used && sep) ? strlen(sep) : 0;
    size_t srclen = strlen(src);
    size_t intended = used + seplen + srclen;

    if (intended < cap) {
        if (seplen)
            memcpy(dst + used, sep, seplen);
        memcpy(dst + used + seplen, src, srclen + 1);
        return true;
    }

    /* Cut. If the field ALREADY carries a marker it is already visibly partial,
     * so leave its bytes exactly as they are — re-packing would nest one marker
     * inside another and eat real text to make room for the duplicate. Report
     * the newly-dropped addition and stop. */
    if (strstr(dst, ZCL_TEXT_FIT_MARKER_TAG) != NULL) {
        ZCL_LOG_EMIT_AT(ZCL_LOG_WARN,
                        "[%s] %s:%d zcl_text_fit(): field=%s already full and "
                        "marked: intended_len=%zu capacity=%zu lost=%zu "
                        "stored=\"%s\" appended=\"%s\"\n",
                        domain ? domain : "text_fit", file ? file : "?", line,
                        field ? field : "?", intended, cap, seplen + srclen,
                        dst, src);
        return false;
    }

    /* The separator belongs to the tail being appended, so fold it in front of
     * `src` by writing it first when there is room for it at all. */
    size_t prefix = used;
    if (seplen && used + seplen < cap) {
        memcpy(dst + used, sep, seplen);
        prefix = used + seplen;
    }
    /* `appended` (not `full`): the field's earlier contents are visible in
     * `stored`, so the two together are the whole intended text. */
    zcl_text_fit_store_cut(dst, cap, prefix, src, srclen, intended,
                           "appended", domain, field, file, line);
    return false;
}

/* Public entry points. The macros exist only to capture the caller's
 * file:line, exactly like zcl_malloc in base/safe_alloc.h. */
#define zcl_text_fit(dst, cap, src, domain, field) \
    zcl_text_fit_impl((dst), (cap), (src), (domain), (field), \
                      __FILE__, __LINE__)

#define zcl_text_fit_append(dst, cap, sep, src, domain, field) \
    zcl_text_fit_append_impl((dst), (cap), (sep), (src), (domain), (field), \
                             __FILE__, __LINE__)

#endif /* ZCL_BASE_TEXT_FIT_H */
