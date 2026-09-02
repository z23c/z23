/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact bounded daily C23 growth reconstructed from Git evidence. */
#ifndef ZCL_SCIENCE_CODE_GROWTH_H
#define ZCL_SCIENCE_CODE_GROWTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SCIENCE_CODE_GROWTH_MAX_DAYS 512u
#define SCIENCE_CODE_GROWTH_GIT_BYTES_MAX (16u * 1024u * 1024u)

struct science_code_growth_day {
    char date[11];
    char head_commit[41];
    uint64_t epoch_day;
    uint32_t commits;
    uint64_t non_test_added;
    uint64_t non_test_deleted;
    uint64_t non_test_lines;
    uint64_t test_added;
    uint64_t test_deleted;
    uint64_t test_lines;
};

struct science_code_growth_history {
    struct science_code_growth_day days[SCIENCE_CODE_GROWTH_MAX_DAYS];
    size_t day_count;
    uint64_t non_test_lines;
    uint64_t test_lines;
};

/* Parse the machine-only stream emitted by science_code_growth_collect().
 * Commit headers are `@@<40-hex-sha>\t<unix-seconds>` and following numstat
 * rows are `<added>\t<deleted>\t<path>`. Days are UTC, including explicit
 * zero-change days between commits. Current maintained source-root and prune
 * rules decide scope; test paths use the capability inventory's
 * classification contract. */
bool science_code_growth_parse(const char *stream, size_t stream_len,
                               struct science_code_growth_history *out,
                               char *error, size_t error_cap);

/* Run Git directly through an argv-only spawn (never a shell), reconstruct
 * first-parent history with merge commits diffed against their first parent,
 * and require the final totals to equal a fresh maintained-tree walk. */
bool science_code_growth_collect(const char *root,
                                 struct science_code_growth_history *out,
                                 char *error, size_t error_cap);

#endif /* ZCL_SCIENCE_CODE_GROWTH_H */
