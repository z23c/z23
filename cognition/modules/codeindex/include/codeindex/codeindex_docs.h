/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read the prose and line-span rows of the code index: which docs
 * match some terms, and which function encloses a given path:line. */
#ifndef ZCL_CODEINDEX_DOCS_H
#define ZCL_CODEINDEX_DOCS_H

#include "codeindex/codeindex.h"

#include <stdbool.h>
#include <stdint.h>

/* One indexed prose file: docs tree .md, AGENTS.md or README.md. `title` is the
 * first level-1 heading, `summary` the first paragraph and `headings` every
 * heading joined by " | "; a field that outgrew its cap ends in "...".
 * `content_sha3` is the hash of the file bytes when it was indexed. */
struct ci_doc {
    char    path[256];
    char    title[256];
    char    summary[512];
    char    headings[1024];
    int     line_count;
    int     score;          /* codeindex_docs_match: higher is better */
    bool    stale;          /* the file no longer matches its indexed hash */
    uint8_t content_sha3[32];
};

/* Docs matching `terms` (whitespace or punctuation separated, case-blind):
 * a term scores 4 in the title, 3 in the path, 2 in the headings and 1 in
 * the first paragraph. Best first, ties by path, at most `cap` rows, only
 * rows with a nonzero score. Each returned row is re-checked against the
 * file on disk and flagged `stale` when it changed or vanished. Returns the
 * row count, or -1 on a bad argument or store failure. */
int codeindex_docs_match(struct codeindex *ci, const char *terms,
                         struct ci_doc *out, int cap);

/* The innermost function (kind 'T' or 't') whose definition spans
 * `path:line`, i.e. def_line <= line <= end_line. *found is false and the
 * call still succeeds when no function covers the line. */
bool codeindex_symbol_at(struct codeindex *ci, const char *path, int line,
                         struct ci_symbol *out, bool *found);

#endif /* ZCL_CODEINDEX_DOCS_H */
