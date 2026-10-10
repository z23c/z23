/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_findings — read the FINDING lines out of a reviewer's raw reply. A
 * pure parser: no I/O, no allocation, no clock. It is the link between a
 * reviewer who writes prose and the scorer (engine_review_score.h) that takes
 * findings (milestone D3, docs/work/DEVELOPMENT_MVP.md).
 *
 * THE LINE FORMAT (one finding per line, starting at column 0)
 *
 *   FINDING <CHANGE|CLAIM> <high|medium|low> <path>:<line> <text>
 *
 *   Fields are separated by single spaces. <path> has no space and no colon
 *   and is shorter than ERS_FILE_MAX. <line> is a positive decimal integer of
 *   at most EFD_LINE_MAX. <text> is the rest of the line and may be empty.
 *   A reply with no findings carries the line `NO FINDINGS`, alone on its
 *   line. Every other line is ignored, and so is a FINDING that is not at
 *   column 0. A line that starts with `FINDING ` but does not parse is
 *   counted as ill-formed, never as a finding. Lines end at \n or \r\n; the
 *   last line needs no terminator. The text is not assumed to be NUL
 *   terminated: nothing at or past `len` is read.
 */

#ifndef ZCL_ENGINE_FINDINGS_H
#define ZCL_ENGINE_FINDINGS_H

#include "engine/engine_review_score.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EFD_LINE_MAX 1000000000

enum efd_severity {
    EFD_SEV_HIGH = 0,
    EFD_SEV_MEDIUM,
    EFD_SEV_LOW
};

struct efd_finding {
    enum ers_kind     kind;
    enum efd_severity severity;
    char              path[ERS_FILE_MAX]; /* NUL terminated */
    int64_t           line;               /* 1..EFD_LINE_MAX */
    const char       *text;               /* into the reply, not terminated */
    size_t            text_len;
};

struct efd_result {
    size_t findings;   /* well-formed FINDING lines, exact even if truncated */
    size_t illformed;  /* lines that start with `FINDING ` and do not parse */
    bool   no_findings; /* a `NO FINDINGS` line was seen */
    bool   truncated;  /* more well-formed findings than `cap` */
};

/* Fills out[0..min(findings, cap)) in reply order. `out` may be NULL when cap
 * is 0. `text` may be NULL when len is 0. */
void efd_parse(const char *text, size_t len, struct efd_finding *out,
               size_t cap, struct efd_result *res);

#endif /* ZCL_ENGINE_FINDINGS_H */
