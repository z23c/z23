/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Parse fixed-worker output into bounded C23 repair coordinates. */
// one-result-type-ok:pure-bounded-feedback-parser — no I/O or fallible state;
// absence or an unrecognized line is the defined `present=false` result.

#include "services/build_fabric_worker_feedback.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void feedback_text(char *out, size_t cap,
                          const char *begin, size_t len)
{
    if (!out || cap == 0) return;
    size_t take = len < cap - 1u ? len : cap - 1u;
    for (size_t i = 0; i < take; i++) {
        unsigned char c = (unsigned char)begin[i];
        out[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
    }
    out[take] = '\0';
}

void build_fabric_worker_feedback_capture(
    struct build_fabric_worker_feedback *out, const char *capture,
    const char *source_root)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!capture) return;
    static const char build_marker[] = "build-failure-detail=";
    static const char test_marker[] = "test-failure-detail=";
    static const char sanitizer_marker[] =
        "zbuild-package-standard-refused=";
    const char *at = strstr(capture, build_marker);
    const char *stage = "compile";
    if (at) {
        at += sizeof(build_marker) - 1u;
    } else if ((at = strstr(capture, test_marker)) != NULL) {
        at += sizeof(test_marker) - 1u;
        stage = "test";
    } else if ((at = strstr(capture, sanitizer_marker)) != NULL) {
        const char *detail = strstr(at, " detail=");
        if (!detail) return;
        at = detail + 8u;
        stage = "sanitize";
    } else {
        return;
    }
    const char *end = strpbrk(at, "\r\n");
    if (!end) end = at + strlen(at);
    if (end == at) return;
    out->present = true;
    (void)snprintf(out->stage, sizeof(out->stage), "%s", stage);

    const char *cursor = at;
    const char *compiler_end = strchr(cursor, ':');
    if (compiler_end && compiler_end < end &&
        (size_t)(compiler_end - cursor) <= BUILD_FABRIC_FEEDBACK_COMPILER_MAX) {
        feedback_text(out->compiler, sizeof(out->compiler), cursor,
                      (size_t)(compiler_end - cursor));
        cursor = compiler_end + 1u;
        while (cursor < end && *cursor == ' ') cursor++;
    }
    if (strcmp(stage, "compile") == 0 &&
        strstr(cursor, "link timed out") != NULL)
        (void)snprintf(out->stage, sizeof(out->stage), "link");

    const char *path = cursor;
    size_t source_len = source_root ? strlen(source_root) : 0;
    if (source_len && (size_t)(end - path) > source_len + 1u &&
        memcmp(path, source_root, source_len) == 0 &&
        path[source_len] == '/')
        path += source_len + 1u;
    const char *line_sep = strchr(path, ':');
    char *line_end = NULL;
    unsigned long line = line_sep
        ? strtoul(line_sep + 1u, &line_end, 10) : 0;
    if (line_sep && line_end != line_sep + 1u && line_end < end &&
        (*line_end == ':' || *line_end == ' ')) {
        feedback_text(out->path, sizeof(out->path), path,
                      (size_t)(line_sep - path));
        out->line = line <= UINT32_MAX ? (uint32_t)line : 0;
        cursor = line_end;
        if (*cursor == ':') {
            char *column_end = NULL;
            unsigned long column = strtoul(cursor + 1u, &column_end, 10);
            if (column_end != cursor + 1u && column_end < end &&
                (*column_end == ':' || *column_end == ' ')) {
                out->column = column <= UINT32_MAX ? (uint32_t)column : 0;
                cursor = column_end;
            }
        }
        while (cursor < end && (*cursor == ':' || *cursor == ' ')) cursor++;
        if ((size_t)(end - cursor) > 7u &&
            strncmp(cursor, "error: ", 7u) == 0)
            cursor += 7u;
    } else {
        cursor = at;
    }
    feedback_text(out->message, sizeof(out->message), cursor,
                  (size_t)(end - cursor));
}
