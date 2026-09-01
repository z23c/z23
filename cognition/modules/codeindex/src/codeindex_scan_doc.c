/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the scanner's doc-comment layer — capturing each comment's first
 * substantive line, attributing a captured comment to the declaration that
 * follows it, and deriving the file's one-line purpose.
 *
 * Split out of codeindex_scan.c along the file-size ceiling seam at the
 * boundary that file already declared with its `── comment capture ──` and
 * `── file self-description ──` banners. codeindex_scan.c keeps the
 * tokenizer and the symbol classifier and calls in here from its
 * clean-buffer pass; every byte read here comes from offsets that pass
 * already recorded, so there is still NO second parse of the file. Contract
 * + rationale for the scanner as a whole live in codeindex_scan.c's header;
 * the scan state and the three symbols that cross the seam live in
 * codeindex_scan_internal.h.
 */

#include "codeindex_scan_internal.h"

#include "base/text_fit.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */

/* ── comment capture ────────────────────────────────────────────────── */

void capture_doc(struct scan_ctx *c, size_t content_start, size_t end)
{
    /* Find the first non-empty textual line inside [content_start,end),
     * stripping leading whitespace and comment-fill '*'. */
    char line[256];
    line[0] = '\0';
    size_t i = content_start;
    while (i < end) {
        /* skip leading whitespace + '*' + '/' fill */
        while (i < end && (c->src[i] == ' ' || c->src[i] == '\t' ||
                           c->src[i] == '*' || c->src[i] == '\r'))
            i++;
        if (i < end && c->src[i] == '\n') { i++; continue; }
        size_t j = i;
        while (j < end && c->src[j] != '\n') j++;
        /* trim trailing */
        size_t e = j;
        while (e > i && (c->src[e - 1] == ' ' || c->src[e - 1] == '\t' ||
                         c->src[e - 1] == '\r' || c->src[e - 1] == '*'))
            e--;
        if (e > i) {
            size_t n = e - i;
            if (n > sizeof(line) - 1) n = sizeof(line) - 1;
            memcpy(line, c->src + i, n);
            line[n] = '\0';
            break;
        }
        i = j + 1;
    }
    if (!line[0]) return;
    if (c->ncomments == c->cap_comments) {
        size_t ncap = c->cap_comments ? c->cap_comments * 2 : 64;
        void *nb = zcl_realloc(c->comments, ncap * sizeof(*c->comments),
                               "ci_comments");
        if (!nb) return;  /* best-effort: drop doc capture on OOM */
        c->comments = nb;
        c->cap_comments = ncap;
    }
    c->comments[c->ncomments].start_off = content_start;
    c->comments[c->ncomments].end_off = end;
    snprintf(c->comments[c->ncomments].firstline,
             sizeof(c->comments[c->ncomments].firstline), "%s", line);
    c->ncomments++;
}

/* Doc for a segment starting at seg_start whose first token is at tok_off:
 * the last comment fully inside [seg_start, tok_off). */
const char *doc_for(const struct scan_ctx *c, size_t seg_start,
                    size_t tok_off)
{
    const char *best = "";
    for (size_t i = 0; i < c->ncomments; i++) {
        if (c->comments[i].start_off >= seg_start &&
            c->comments[i].end_off <= tok_off)
            best = c->comments[i].firstline;
    }
    return best;
}

/* ── file self-description (§1.1 of docs/work/palace-design.md) ───────── */

/* License headers describe redistribution terms, not the file.  Keep this
 * deliberately prefix-based and narrow: a line that is not recognizable
 * boilerplate remains eligible as the file's purpose. */
static bool purpose_line_is_license(const char *line)
{
    static const char *const prefixes[] = {
        "Copyright",
        "SPDX-License-Identifier:",
        "Distributed under",
        "file COPYING",
        "Licensed under",
        "See the License",
        "All rights reserved.",
        NULL,
    };
    for (size_t i = 0; prefixes[i]; i++) {
        size_t n = strlen(prefixes[i]);
        if (strncasecmp(line, prefixes[i], n) == 0) return true;
    }
    return false;
}

/* Derive a file's one-line purpose from its EXISTING leading block comment:
 * the first substantive body line after skipping license boilerplate and blank
 * '*' fill, with a leading "<stem> [—:-] " prefix stripped so the stored
 * purpose is the bare description. An explicit "purpose: ..." body line
 * overrides (mirrors the // suffix-ok convention). Writes "" when no comment
 * precedes the first code token. Walks only the one leading comment's bytes via
 * the offsets already captured in c->comments[] — NO second file parse. */
void ci_file_purpose(const struct scan_ctx *c, char out[CI_FILE_PURPOSE_MAX])
{
    out[0] = '\0';
    if (c->ncomments == 0) return;

    /* first code token in the clean buffer (comments already blanked) */
    size_t code_off = 0;
    while (code_off < c->len && isspace((unsigned char)c->clean[code_off]))
        code_off++;
    /* the leading comment must precede the first code token, else the earliest
     * comment is an interior doc block, not a file-level purpose. */
    size_t start = c->comments[0].start_off;
    size_t end   = c->comments[0].end_off;
    if (start >= code_off) return;

    /* file stem = basename minus extension, for prefix stripping */
    char stem[128];
    {
        const char *base = strrchr(c->relpath, '/');
        base = base ? base + 1 : c->relpath;
        size_t n = 0;
        while (base[n] && base[n] != '.' && n + 1 < sizeof(stem))
            stem[n] = base[n], n++;
        stem[n] = '\0';
    }
    size_t sl = strlen(stem);

    /* walk body lines of [start,end), mirroring capture_doc's fill-stripping */
    size_t i = start;
    char line[CI_FILE_PURPOSE_CAPTURE_MAX];
    while (i < end) {
        while (i < end && (c->src[i] == ' ' || c->src[i] == '\t' ||
                           c->src[i] == '*' || c->src[i] == '\r'))
            i++;
        if (i < end && c->src[i] == '\n') { i++; continue; }
        size_t j = i;
        while (j < end && c->src[j] != '\n') j++;
        size_t e = j;
        while (e > i && (c->src[e - 1] == ' ' || c->src[e - 1] == '\t' ||
                         c->src[e - 1] == '\r' || c->src[e - 1] == '*'))
            e--;
        if (e > i) {
            size_t n = e - i;
            if (n > sizeof(line) - 1) n = sizeof(line) - 1;
            memcpy(line, c->src + i, n);
            line[n] = '\0';

            /* explicit override wins: "purpose: <text>" */
            if (strncasecmp(line, "purpose:", 8) == 0) {
                const char *p = line + 8;
                while (*p == ' ' || *p == '\t') p++;
                (void)zcl_text_fit(out, CI_FILE_PURPOSE_MAX, p, "codeindex", "file_purpose");
                return;
            }
            if (purpose_line_is_license(line)) { i = j + 1; continue; }

            /* first substantive line: strip a leading "<stem> [—:-] " prefix */
            const char *desc = line;
            if (sl > 0 && strncmp(line, stem, sl) == 0) {
                const char *p = line + sl;
                while (*p == ' ') p++;
                if ((unsigned char)p[0] == 0xE2 && (unsigned char)p[1] == 0x80 &&
                    (unsigned char)p[2] == 0x94) {          /* em-dash — */
                    p += 3; while (*p == ' ') p++; desc = p;
                } else if (p[0] == ':' || p[0] == '-') {    /* "stem:" / "stem -" */
                    p += 1; while (*p == ' ') p++; desc = p;
                }
            }
            (void)zcl_text_fit(out, CI_FILE_PURPOSE_MAX, desc, "codeindex", "file_purpose");
            return;
        }
        i = j + 1;
    }
}
