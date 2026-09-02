/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Rank files a specialist should work next from recorded evidence.
 *
 * `code focus <specialist>` answers from evidence only: failed routed test
 * groups in the latest recorded run, git-log churn, open lessons/notes,
 * missing impact-rule routing, and checked-in issue bodies under docs/.
 * The specialist table is engine/composition/specialists.def. Scoring is
 * integer and deterministic; ties break by path. */

#ifndef ZCL_CODEINDEX_FOCUS_H
#define ZCL_CODEINDEX_FOCUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct codeindex;

enum {
    SPECIALIST_FOCUS_FAILED_CAP = 64,
    SPECIALIST_FOCUS_CHURN_CAP = 256,
    SPECIALIST_FOCUS_NOTE_CAP = 64,
    SPECIALIST_FOCUS_ISSUE_CAP = 64,
    SPECIALIST_FOCUS_HIT_CAP = 16,
    SPECIALIST_FOCUS_WORK_CAP = 512,
    SPECIALIST_NAME_MAX = 32,
    SPECIALIST_PATH_MAX = 256,
    SPECIALIST_REASON_MAX = 384,
    SPECIALIST_SOURCE_MAX = 160,
    SPECIALIST_GROUP_MAX = 64
};

struct specialist {
    const char *name;
    const char *territories;
    const char *gates;
    const char *test_groups;
    const char *fact_kinds;
};

struct specialist_focus_churn {
    char path[SPECIALIST_PATH_MAX];
    uint32_t recency;
};

struct specialist_focus_binding {
    char path[SPECIALIST_PATH_MAX];
    char source[SPECIALIST_SOURCE_MAX];
};

struct specialist_focus_evidence {
    char failed[SPECIALIST_FOCUS_FAILED_CAP][SPECIALIST_GROUP_MAX];
    size_t failed_count;
    struct specialist_focus_churn churn[SPECIALIST_FOCUS_CHURN_CAP];
    size_t churn_count;
    struct specialist_focus_binding notes[SPECIALIST_FOCUS_NOTE_CAP];
    size_t notes_count;
    struct specialist_focus_binding issues[SPECIALIST_FOCUS_ISSUE_CAP];
    size_t issues_count;
};

struct specialist_focus_hit {
    char path[SPECIALIST_PATH_MAX];
    int score;
    char reason[SPECIALIST_REASON_MAX];
};

/* Router port: fill out[] with the test groups a change to `path` routes to.
 * Return 0 when no rule routes the file (the unrouted signal). The
 * make_lint_gates floor is not a route. */
typedef size_t (*specialist_focus_route_fn)(const char *path,
                                            char (*out)[SPECIALIST_GROUP_MAX],
                                            size_t cap, void *user);

const struct specialist *specialist_table(size_t *count);
const struct specialist *specialist_find(const char *name);
bool specialist_path_in_territory(const struct specialist *spec,
                                  const char *path);

void specialist_focus_evidence_clear(struct specialist_focus_evidence *ev);

/* Missing artifacts are an honest empty set (true). Unreadable/corrupt
 * recorded runs return false after logging. */
bool specialist_focus_load_failed_groups(const char *root,
                                         struct specialist_focus_evidence *ev);
bool specialist_focus_load_notes(const char *root,
                                 struct specialist_focus_evidence *ev);
bool specialist_focus_load_issues(const char *root,
                                  struct specialist_focus_evidence *ev);
bool specialist_focus_load_churn(const char *root,
                                 struct specialist_focus_evidence *ev);

/* Rank files in spec->territory that have at least one cited reason.
 * Output is score-desc, path-asc. Returns the filled count (>=0), or -1
 * on hard error. *truncated is true when the working set overflowed cap. */
int specialist_focus_rank(struct codeindex *ci,
                          const struct specialist *spec,
                          const struct specialist_focus_evidence *ev,
                          specialist_focus_route_fn route, void *route_user,
                          struct specialist_focus_hit *out, int cap,
                          bool *truncated);

#endif /* ZCL_CODEINDEX_FOCUS_H */
