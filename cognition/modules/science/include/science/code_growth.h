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
    bool cache_hit;
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

/* Run Git directly through argv-only spawns (never a shell). A cold call
 * reconstructs first-parent history, requires the final totals to equal a
 * fresh maintained-tree walk, then may seal the raw Git stream in a local
 * cache. A warm call re-parses a digest-verified stream only while the exact
 * HEAD and maintained-root worktree remain unchanged. The root must be the
 * Git toplevel; nested roots refuse instead of reading a parent repository. */
bool science_code_growth_collect(const char *root,
                                 struct science_code_growth_history *out,
                                 char *error, size_t error_cap);

#endif /* ZCL_SCIENCE_CODE_GROWTH_H */
