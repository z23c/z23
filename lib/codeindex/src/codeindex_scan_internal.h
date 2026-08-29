/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the C scanner's private cross-TU contract — the `struct scan_ctx`
 * scan state plus the three doc-comment entry points that the doc layer
 * defines and the tokenizer consumes.
 *
 * codeindex_scan.c owns the TOKENIZER and the symbol classifier: the
 * identifier/keyword vocabulary, the line + guard index, the clean-buffer
 * pass, segment classification, and the refs pass. codeindex_scan_doc.c owns
 * the DOC-COMMENT layer: capturing each block/line comment's first
 * substantive line, attributing a captured comment to the segment that
 * follows it, and deriving the file's one-line purpose (§1.1 of
 * docs/work/palace-design.md). The split happened when the combined file
 * passed the 800-line shape ceiling. The scan state and those three
 * declarations are all that crosses that seam, so they live here and nowhere
 * else — nothing outside those two translation units may include this header.
 */

#ifndef ZCL_CODEINDEX_SCAN_INTERNAL_H
#define ZCL_CODEINDEX_SCAN_INTERNAL_H

#include "codeindex_priv.h"

#include <stdbool.h>
#include <stddef.h>

/* ── line index ─────────────────────────────────────────────────────── */

struct scan_ctx {
    const char *src;
    const char *clean;
    size_t      len;
    size_t     *line_starts;   /* offset of each line start */
    size_t      nlines;
    char       *line_guard;    /* nlines * 128, guard active on each line */
    bool       *pp_line;       /* nlines, true for preprocessor lines */
    const char *relpath;
    bool        is_header;
    const char *group;
    ci_sym_cb   on_sym;
    ci_ref_cb   on_ref;
    void       *user;
    int         syms_emitted;
    int         refs_emitted;

    /* doc comments: end offset + first line */
    struct { size_t start_off; size_t end_off; char firstline[256]; } *comments;
    size_t      ncomments;
    size_t      cap_comments;

    /* function definitions in this file, in emit order: (def_line, name). Used
     * to attribute each call site's enclosing function (greatest def_line <=
     * ref_line). C functions do not nest, so this is exact for well-formed
     * source and best-effort otherwise. */
    struct { int def_line; char name[128]; } *funcs;
    size_t      nfuncs;
    size_t      cap_funcs;
};

/* ── the doc-comment layer (codeindex_scan_doc.c) ───────────────────── */

/* Record the first substantive line of the comment whose CONTENT spans
 * [content_start, end). Best-effort: silently drops the capture on OOM.
 * Called from the clean-buffer pass in codeindex_scan.c; promoted out of
 * file scope so the capture and the derivation can live in one file. */
void capture_doc(struct scan_ctx *c, size_t content_start, size_t end);

/* Doc for a segment starting at seg_start whose first token is at tok_off:
 * the last comment fully inside [seg_start, tok_off). */
const char *doc_for(const struct scan_ctx *c, size_t seg_start,
                    size_t tok_off);

/* Bytes the purpose derivation reads out of one comment line before it clips.
 * Deliberately ABOVE CI_FILE_PURPOSE_MAX: the stored field's own fit check is
 * then the thing that decides a cut, and it reports the cut. If this were the
 * smaller of the two, an over-long purpose would be clipped here in silence
 * and the field would never know it was handed a fragment. */
#define CI_FILE_PURPOSE_CAPTURE_MAX (CI_FILE_PURPOSE_MAX + 64)

/* Derive the file's one-line purpose from its leading block comment. */
void ci_file_purpose(const struct scan_ctx *c, char out[CI_FILE_PURPOSE_MAX]);

#endif /* ZCL_CODEINDEX_SCAN_INTERNAL_H */
