/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Markdown-subset to HTML renderer for C23 — streaming (output
 *          through a caller-supplied write callback), allocation-free,
 *          bounded, and fail-closed.
 *
 * Supported subset (everything else is literal text):
 *  - Blocks (column 0 only, no nesting):
 *      ATX headings '#' .. '######' with optional closing '#' run;
 *      paragraphs; fenced code blocks ``` (info string ignored; an
 *      unclosed fence runs to end of input); unordered lists ('- ' or
 *      '* '); ordered lists ('N. '); single-level blockquotes ('>');
 *      horizontal rules (3+ identical -, *, or _, spaces allowed);
 *      hard line breaks via two trailing spaces; other line ends are
 *      soft breaks (a newline in the output). Setext headings, tables,
 *      and indented code blocks are NOT supported.
 *  - Inline: **strong**, *em*, `code`, [link](url), ![image](url).
 *    Same-marker nesting is first-match (e.g. *a *b** does not nest);
 *    different markers nest (e.g. **a *b* c**). Any construct that does
 *    not parse — including every unclosed one — is literal escaped text.
 *  - NO raw HTML passthrough: all emitted text is escaped through zhtml,
 *    so markup in the source can never inject HTML. This is a safety
 *    feature, not a limitation.
 *  - URL policy for links and images: whitespace and control bytes are
 *    rejected; a scheme (the run before a ':' that precedes any '/',
 *    '?', or '#') must be http, https, or mailto, case-insensitively;
 *    schemeless relative URLs pass. A rejected URL degrades the whole
 *    construct to escaped literal source text.
 *
 * Input contract: md must be well-formed UTF-8 (validated with zutf8
 * before any output is produced) and at most ZMD_MAX_INPUT bytes. CRLF
 * line endings are accepted (the '\r' is stripped).
 */
#ifndef ZMD_H
#define ZMD_H

#include <stdbool.h>
#include <stddef.h>

#ifndef ZMD_MAX_INPUT
#define ZMD_MAX_INPUT (16u * 1024u * 1024u)
#endif

/* Output sink: write len bytes at data. Return false to abort the render. */
typedef bool (*zmd_write_fn)(void *ctx, const char *data, size_t len);

/* Render md[0..md_len) as HTML, streaming through write. Returns true on
 * success. Fails closed (false; output, if any, is partial) when:
 *  - write is NULL, or md is NULL with md_len > 0;
 *  - md_len exceeds ZMD_MAX_INPUT (checked before md is dereferenced);
 *  - md is not well-formed UTF-8;
 *  - the write callback reports failure.
 * md == NULL with md_len == 0 is a valid empty document. */
bool zmd_render_html(const char *md, size_t md_len, zmd_write_fn write,
                     void *ctx);

#endif /* ZMD_H */
