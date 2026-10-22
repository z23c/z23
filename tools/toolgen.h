/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared declarations for z23-toolgen, the build-time generator that
 *          expands one Z23_TOOL_V1 manifest comment into the generator-owned
 *          blocks of the command registry files. */

#ifndef Z23_TOOLGEN_H
#define Z23_TOOLGEN_H

#include <stdbool.h>
#include <stddef.h>

#define TG_SOURCE_MAX (256u * 1024u)
#define TG_MANIFEST_MAX (16u * 1024u)
#define TG_READ_CEILING (8u * 1024u * 1024u)
#define TG_MAX_MANIFESTS 256u
#define TG_MARKER "Z23_TOOL_V1"
#define TG_PROFILE "readonly-local-v1"

/* ---- diagnostics: the first failure wins and carries a stable code ---- */

struct tg_err {
    char code[40];
    char detail[480];
};

[[gnu::format(printf, 3, 4)]]
bool tg_fail(struct tg_err *e, const char *code, const char *fmt, ...);

/* Prefixes the recorded detail with `context`; always returns false. */
bool tg_err_context(struct tg_err *e, const char *context);

/* ---- growable text buffer ---- */

struct tg_sb {
    char *p;
    size_t n;
    size_t cap;
    bool oom;
};

void tg_sb_putn(struct tg_sb *s, const char *text, size_t n);
void tg_sb_put(struct tg_sb *s, const char *text);
[[gnu::format(printf, 2, 3)]]
void tg_sb_printf(struct tg_sb *s, const char *fmt, ...);
void tg_sb_free(struct tg_sb *s);

enum tg_read {
    TG_READ_OK,
    TG_READ_MISSING,
    TG_READ_NOT_REGULAR,
    TG_READ_TOO_LARGE,
    TG_READ_IO
};

/* Reads a regular file of at most `limit` bytes. Symlinks are refused. */
enum tg_read tg_read_file(const char *path, size_t limit, struct tg_sb *out);
bool tg_join(char *out, size_t cap, const char *a, const char *b);

/* ---- lexical view of a C source ---- */

enum tg_comment_kind { TG_COMMENT_BLOCK, TG_COMMENT_LINE };

struct tg_comment {
    size_t start; /* offset of the opening delimiter */
    size_t end;   /* offset one past the last byte (past the closing delimiter) */
    enum tg_comment_kind kind;
    unsigned cond_depth; /* open #if groups at the comment */
};

struct tg_lex {
    char *code;      /* comments blanked */
    char *masked;    /* comments, string and character literals blanked */
    size_t len;
    struct tg_comment *comments;
    size_t ncomments;
    size_t cap;
    bool unterminated;
};

bool tg_lex_run(const char *src, size_t n, struct tg_lex *out);
void tg_lex_free(struct tg_lex *lx);
bool tg_has_definition(const struct tg_lex *lx, const char *ret,
                       const char *name);

struct tg_marker {
    bool found;
    size_t body_off;
    size_t body_len;
};

bool tg_find_marker(const char *src, const struct tg_lex *lx,
                    struct tg_marker *m, struct tg_err *e);

/* ---- manifest ---- */

#define TG_TEXT_MAX 2200u

struct tg_manifest {
    char source[160];
    char path[100];
    char parent[100];
    char branch_summary[130];
    char handler[90];
    char summary[170];
    char semantics[TG_TEXT_MAX];
    char input_schema[100];
    char output_schema[100];
    char input_keys[200];
    char positional_keys[200];
    char example[170];
    char tags[420];
    char test_group[70];
    char authority[40];
    char latency[40];
    char cost[40];
    char caps[200];
    unsigned budget_bytes;
    bool has_branch;
    bool has_datadir;
    const struct tg_family *family;
};

bool tg_manifest_parse(const char *body, size_t len, struct tg_manifest *m,
                       struct tg_err *e);

/* ---- families, targets and rendering ---- */

struct tg_family {
    const char *root;
    const char *def;
    const char *header;
};

extern const struct tg_family tg_families[];
extern const size_t tg_family_count;

/* The remote permit table. Not a generated target: a leaf with no row there is
 * REMOTE_CLASS_NEVER, so the generator adds nothing to it; it is only read, to
 * refuse a manifest whose path already carries a hand-written permit row. */
extern const char tg_remote_path[];

enum tg_target_kind {
    TGT_DEF,
    TGT_HEADER,
    TGT_CATALOG,
    TGT_DATADIR
};

struct tg_target {
    enum tg_target_kind kind;
    const struct tg_family *family;
    const char *path;
    const char *id;
};

#define TG_MAX_TARGETS 16u

size_t tg_targets(struct tg_target *out, size_t max);
bool tg_applies(const struct tg_target *t, const struct tg_manifest *m);
void tg_render_unit(const struct tg_target *t, const struct tg_manifest *m,
                    struct tg_sb *sb);
void tg_render_body(const struct tg_target *t,
                    const struct tg_manifest *const *ms, size_t n,
                    const char *existing, size_t existing_len,
                    struct tg_sb *sb);

/* ---- managed blocks ---- */

struct tg_block {
    size_t body_start;
    size_t body_end;
};

bool tg_block_locate(const char *text, size_t len, const char *id,
                     const char *file, struct tg_block *b, struct tg_err *e);
bool tg_block_splice(const char *text, size_t len, const struct tg_block *b,
                     const char *body, size_t body_len, struct tg_sb *out);

/* ---- authored world and manifest set ---- */

struct tg_names {
    char **v;
    size_t n;
    size_t cap;
};

bool tg_names_add(struct tg_names *s, const char *name, size_t len);
bool tg_names_has(const struct tg_names *s, const char *name);
void tg_names_free(struct tg_names *s);
void tg_names_sort(struct tg_names *s);

struct tg_world {
    struct tg_names paths;
    struct tg_names branches;
    struct tg_names handlers;
    struct tg_names remote;
    struct tg_names groups;
};

struct tg_set {
    struct tg_manifest m[TG_MAX_MANIFESTS];
    size_t n;
};

bool tg_world_load(const char *root, struct tg_world *w, struct tg_err *e);
void tg_world_free(struct tg_world *w);
bool tg_gather(const char *root, struct tg_set *set, struct tg_err *e);

#endif /* Z23_TOOLGEN_H */
