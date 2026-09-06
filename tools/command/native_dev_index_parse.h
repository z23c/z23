/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.index per-format line parsing, shared by ingest (which
 * inserts the parsed fields) and by nothing else
 * (tools/command/native_dev_index_parse.c). Split out of
 * native_dev_index_ingest.c to keep that file under the file-size target. */
#ifndef ZCL_NATIVE_DEV_INDEX_PARSE_H
#define ZCL_NATIVE_DEV_INDEX_PARSE_H

#include "command/native_dev_index_catalog.h"

#include <stdbool.h>
#include <stddef.h>

#define DEV_INDEX_LINE_MAX 8192u
#define DEV_INDEX_TEXT_MAX 4000u
#define DEV_INDEX_KV_MAX 2048u

/* One line's extracted columns. `kv` holds every "key:value" term flattened
 * out of the line (space-separated), appended to the raw line at index
 * time to form the FTS5 document. */
struct dev_index_fields {
    char ts[32];
    char kind[32];
    char a[128];
    char b[128];
    char c[128];
    char kv[DEV_INDEX_KV_MAX];
};

/* Parse one already-newline-stripped line of `src`'s declared format into
 * `f` (zeroed first). Returns false for a line that should not become a
 * row at all (malformed JSON, the TSV header line, too few TSV columns) —
 * never fatal, the caller just skips that line. */
bool dev_index_parse_line(const struct dev_index_source *src,
                          const char *line, struct dev_index_fields *f);

#endif /* ZCL_NATIVE_DEV_INDEX_PARSE_H */
