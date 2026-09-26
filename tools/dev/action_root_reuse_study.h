/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Shared types of the offline action-root reuse study
 * (tools/dev/action_root_reuse_study*.c). Not linked into any node binary.
 */

#ifndef ZCL_ACTION_ROOT_REUSE_STUDY_H
#define ZCL_ACTION_ROOT_REUSE_STUDY_H

#include "vcs/build_action.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ST_STAGE_KIND "c23.compile.dev-object"
#define ST_STAGE_VERSION 1u
#define ST_TIMEOUT_MS 1800000
#define ST_MAKE_CAP (96u * 1024u * 1024u)
#define ST_SMALL_CAP (1024u * 1024u)
#define ST_PROBE_CAP (8u * 1024u * 1024u)
#define ST_MAX_SNAP_TUS 8192u
#define ST_MAX_ARGS 1024u
#define ST_BATCH 32u
#define ST_MAX_PICKED 64u
#define ST_SYSDIR_MAX 32u
#define ST_REASON_MAX 64u
#define ST_CAUSE_SLOTS 65536u

/* ---- owned string lists and samples ------------------------------------ */

struct st_list {
    char **v;
    size_t n, cap;
};

bool st_list_push(struct st_list *l, const char *s);
void st_list_free(struct st_list *l);
bool st_list_has(const struct st_list *l, const char *s);

struct st_samples {
    int64_t *v;
    size_t n, cap;
};

void st_sample(struct st_samples *s, int64_t v);
int64_t st_pct(struct st_samples *s, unsigned pct);
int64_t st_sum(const struct st_samples *s);
double st_share(uint64_t part, uint64_t whole);

char *st_read_file(const char *path, size_t max, size_t *len);

/* ---- processes --------------------------------------------------------- */

struct st_proc {
    char *out;
    size_t len;
    int exit_code;
};

/* stdout+stderr captured; true only when the child exited 0. */
bool st_run(const char *const *argv, size_t cap, struct st_proc *p);
void st_proc_free(struct st_proc *p);
bool st_run_quiet(const char *const *argv);
bool st_run_line(const char *const *argv, char *out, size_t cap);
bool st_rm_rf(const char *path);
bool st_mkdir_p(const char *path);

/* ---- study context ----------------------------------------------------- */

struct st_toolchain {
    uint8_t root[32];
    uint8_t sysroot_objects[32];
    char sysroot[PATH_MAX];
    char dirs[ST_SYSDIR_MAX][PATH_MAX];
    const char *dir_ptr[ST_SYSDIR_MAX];
    size_t dir_count;
};

struct st_ctx {
    char repo[PATH_MAX];
    char scratch[PATH_MAX];
    char out[PATH_MAX];
    char build_obj[PATH_MAX];
    char test_obj[PATH_MAX];
    char test_bin[PATH_MAX];
    char main_ref[128];
    char main_sha[64];
    struct st_list picks; /* --pick=LABEL=REV, in order */
    unsigned corpus;
    unsigned jobs;
    unsigned invariance;
    unsigned max_actions; /* smoke runs only: first N actions; 0 = all */
    struct st_toolchain tc;
    FILE *log;
};

bool st_toolchain_capture(struct st_toolchain *t);

/* ---- snapshots and their compile actions ------------------------------- */

enum st_state { ST_NONE = 0, ST_ROOT, ST_MISS };

struct st_outcome {
    enum st_state state;
    uint8_t root[32];
    char reason[96];
    int64_t us;
    int64_t cpu_us;      /* thread CPU of the same derivation */
    int64_t warm_us;     /* an immediate repeat: every settled file memoized */
    int64_t warm_cpu_us;
};

struct st_tu {
    char *src;
    struct st_list argv;     /* action argv, declared outputs virtualized */
    size_t flag_lo, flag_hi; /* [lo, hi) of argv: the compiler flags */
    bool identity;           /* argv binds the whole-tree source identity */
    bool build_dep;          /* the study build wrote a depfile for it */
    bool lists_equal;        /* build depfile == snapshot preprocessor list */
    bool pp_ok;
    int64_t pp_us;
    struct st_outcome a;      /* build depfile, verified against snapshot */
    struct st_outcome b;      /* snapshot's own preprocessor depfile */
    struct st_outcome forced; /* build depfile, unverified (seeded edits) */
    uint8_t *pre;             /* B preimage, for invalidation causes */
    size_t pre_len;
    struct st_list deps;      /* B prerequisite list (kept on request) */
};

struct st_snap {
    char label[96];
    char sha[64];
    char dir[PATH_MAX];
    char tar[PATH_MAX];
    char depdir[PATH_MAX];
    bool ok;
    bool immutable;
    char why[256];
    struct st_tu *tu;
    size_t n;
    char *test_flags;
    int64_t archive_us, parse_us;
};

typedef bool (*st_mutate_fn)(const struct st_ctx *c, struct st_snap *s,
                             void *arg);

void st_snap_init(struct st_snap *s, const char *label, const char *sha);
/* Extract, run `mutate` (may be NULL), dry-run parse, verify, derive. */
bool st_snap_load(const struct st_ctx *c, struct st_snap *s,
                  st_mutate_fn mutate, void *arg, bool forced,
                  bool keep_deps);
void st_snap_drop(struct st_snap *s);
/* Ordered prerequisites of a depfile's first rule. */
bool st_depfile_list(const char *path, struct st_list *out);
void st_snap_free(struct st_snap *s);
const struct st_tu *st_find_tu(const struct st_snap *s, const char *src,
                               size_t hint);

/* ---- comparison and aggregation ---------------------------------------- */

struct st_reasons {
    char name[ST_REASON_MAX][96];
    uint64_t count[ST_REASON_MAX];
    size_t n;
};

void st_reason_add(struct st_reasons *r, const char *name);

struct st_tally {
    uint64_t total, reuse, changed, miss, added;
    struct st_reasons miss_reasons;
};

/* Changed inputs and the actions each one invalidated; also reused as a
 * plain path counter (header fan-in). */
struct st_causes {
    char *path[ST_CAUSE_SLOTS];
    uint64_t tus[ST_CAUSE_SLOTS];
    uint64_t pairs[ST_CAUSE_SLOTS];
    uint32_t last_pair[ST_CAUSE_SLOTS];
    uint64_t field[VCS_ACTION_FIELD_V2_COUNT];
};

void st_cause_add(struct st_causes *k, const char *path, uint32_t pair);
void st_causes_free(struct st_causes *k);

struct st_rank {
    const char *path;
    uint64_t n;
    uint64_t pairs;
};

size_t st_rank_build(const struct st_causes *k, struct st_rank **out);

enum st_verdict { ST_V_REUSE, ST_V_CHANGED, ST_V_MISS, ST_V_ADDED };

enum st_verdict st_compare(const struct st_outcome *p,
                           const struct st_outcome *q, bool have_parent,
                           const char **reason);

struct st_pair_result {
    struct st_tally a, b;
    uint64_t ab_violations; /* A and B both rooted but roots differ */
};

void st_pair_compare(const struct st_snap *parent, const struct st_snap *child,
                     struct st_pair_result *r, struct st_causes *k,
                     uint32_t pair);

/* ---- the existing content-keyed test cache ----------------------------- */

struct st_groups {
    struct st_list name;    /* every registered group, baseline order */
    struct st_list label;   /* baseline reason label */
    struct st_list harness; /* files the harness part of the key hashes */
    size_t cacheable;
    bool ok;
};

struct st_group_result {
    bool ok;
    bool toolkey_changed;
    bool harness_changed;
    size_t changed_paths;
    size_t probe_runs;
    uint64_t total, cacheable, unchanged, invalidated, uncacheable;
    uint64_t pairs_ok, pairs_failed; /* merged totals only */
    int64_t probe_us;
};

void st_groups_baseline(const struct st_ctx *c, struct st_groups *g);
void st_groups_free(struct st_groups *g);
void st_groups_pair(const struct st_ctx *c, const struct st_groups *g,
                    const struct st_snap *parent, const struct st_snap *child,
                    struct st_group_result *r);

/* ---- corpus ------------------------------------------------------------ */

struct st_pair {
    char label[96];
    char parent[64];
    char child[64];
};

bool st_rev_parse(const struct st_ctx *c, const char *rev, char out[64]);
bool st_corpus_chain(const struct st_ctx *c, struct st_list *chain);
size_t st_picked_load(const struct st_ctx *c, struct st_pair *out,
                      size_t cap);

/* ---- report ------------------------------------------------------------ */

struct st_totals {
    struct st_tally a, b;
    struct st_group_result g;
    uint64_t ab_violations;
    uint64_t snaps, snaps_immutable, actions, rooted_a, rooted_b, miss_a,
        miss_b;
    struct st_samples us_a, us_b, us_pp;
    struct st_samples cpu_b, warm_b, warm_cpu_b;
    struct st_reasons miss_snap_a, miss_snap_b;
};

void st_totals_free(struct st_totals *t);
void st_tally_merge(struct st_tally *into, const struct st_tally *t);
void st_group_merge(struct st_group_result *into,
                    const struct st_group_result *g);
void st_snap_account(struct st_totals *t, const struct st_snap *s,
                     FILE *out);
void st_pair_row(FILE *out, const char *set, const struct st_pair *p,
                 const struct st_pair_result *r,
                 const struct st_group_result *g);
void st_summary_totals(FILE *s, const char *set, struct st_totals *t);
void st_summary_causes(FILE *s, const struct st_causes *k);

/* ---- the study run ----------------------------------------------------- */

struct st_run {
    struct st_ctx *c;
    struct st_groups groups;
    struct st_causes *causes;
    struct st_totals corpus, picked;
    FILE *pairs, *snaps;
    uint32_t pair_seq;
};

void st_adversarial(struct st_run *r, const struct st_snap *base, FILE *out,
                    FILE *summary);

#endif /* ZCL_ACTION_ROOT_REUSE_STUDY_H */
