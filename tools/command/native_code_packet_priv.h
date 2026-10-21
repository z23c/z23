/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private interface of the code.packet leaf's three translation units:
 * native_code_packet.c (input, gathering, JSON, handler),
 * native_code_packet_src.c (bounded source reads, verbatim excerpts, the
 * governed definition-file scans) and native_code_packet_md.c (the markdown
 * rendering). Nothing here is part of the public command surface. */

#ifndef ZCL_TOOLS_COMMAND_NATIVE_CODE_PACKET_PRIV_H
#define ZCL_TOOLS_COMMAND_NATIVE_CODE_PACKET_PRIV_H

#include "command/native_code_priv.h"

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>

/* ── bounds (the packet's contract; every one is enforced, none advisory) ── */
enum {
    PK_SYMBOLS_MAX = 8,
    PK_FILES_MAX = 8,
    PK_TOUCH_MAX = 16,        /* input files plus symbol definition files */
    PK_GOAL_MAX = 512,
    PK_CHANGE_MAX = 1024,
    PK_LINES_MIN = 20,
    PK_LINES_MAX = 120,
    PK_LINES_DEFAULT = 60,
    PK_CONTEXT_LINES = 3,
    PK_CACHE_N = 24,          /* distinct source files held at once */
    PK_GROUPS_MAX = 32,
    PK_TOP_NAMES = 5,
    PK_FILE_SYMS = 24,        /* symbol-map rows listed per file */
    PK_REFS_SCAN = 512,       /* refs examined when looking for a test case */
    PK_SB_MAX = 98304         /* hard cap on one rendered markdown section */
};
#define PK_READ_TOTAL_MAX ((size_t)4u << 20) /* file bytes read per request */
#define PK_READ_FILE_MAX ((size_t)1u << 20)  /* one file */

/* ── growable text, hard-capped; `over` is sticky and means "truncated" ── */
struct pk_sb {
    char *p;
    size_t len;
    size_t cap;
    bool over;
};
void pk_sb_free(struct pk_sb *sb);
void pk_sb_raw(struct pk_sb *sb, const char *s, size_t n);
void pk_sb_add(struct pk_sb *sb, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ── one cached source file ── */
struct pk_src {
    char path[256];
    char *text;
    size_t len;
    bool ok;
    const char *why;
};

struct pk_ctx {
    const char *root;
    struct codeindex *ci;
    int max_lines;
    size_t bytes_read;
    struct pk_src cache[PK_CACHE_N];
    int ncache;
    bool budget_hit;          /* a file was refused for the read budget */
};

/* The root-relative file, read once per request; NULL with *why set to a
 * stable token when it cannot be served. */
const struct pk_src *pk_load(struct pk_ctx *ctx, const char *rel,
                             const char **why);
void pk_ctx_free(struct pk_ctx *ctx);

/* 1-based line holding the first occurrence of `needle` at a line start after
 * optional blanks, or 0. */
int pk_find_line(const struct pk_src *src, const char *needle);

/* ── a verbatim excerpt of one definition ── */
struct pk_excerpt {
    char symbol[128];
    char kind;
    char file[256];
    const char *status;       /* ok | not_found | declaration_only | no_body |
                               * source_unreadable | read_budget */
    int site_line;            /* the indexed definition line */
    int end_line;             /* last line of the definition */
    int first, last;          /* the window actually shown */
    int elide_from, elide_to; /* inclusive elided range, 0 when none */
    int shown;                /* source lines shown (marker excluded) */
    struct pk_sb text;
};
void pk_excerpt_free(struct pk_excerpt *ex);
/* Fill `ex` from index symbol `s` (a found symbol). `context` is the number
 * of lines kept on each side; `max_lines` bounds the rendered line count. */
void pk_excerpt_symbol(struct pk_ctx *ctx, const struct ci_symbol *s,
                       int context, int max_lines, struct pk_excerpt *ex);
/* One bounded same-file window containing all requested body spans. The
 * caller guarantees last-first+1 <= max_lines; no symbol binding is inferred. */
void pk_excerpt_neighborhood(struct pk_ctx *ctx, const struct ci_symbol *s,
                             int first, int last, int max_lines,
                             struct pk_excerpt *ex);
/* Fill `ex` for lines [site-context, site+context] around one reference. */
void pk_excerpt_site(struct pk_ctx *ctx, const char *file, int line,
                     int context, struct pk_excerpt *ex);

/* ── the governed definition-file scans ── */
struct pk_row {
    bool found;
    int line;
    char source[96];          /* which def file the row came from */
    char caps[96];            /* capability list or remote class token */
    char note[200];
};
void pk_capability_row(struct pk_ctx *ctx, const char *path,
                       struct pk_row *row);
void pk_remote_class_row(struct pk_ctx *ctx, const char *command,
                         struct pk_row *row);
/* tools/dev/test_group_catalog.def line of a full group id, or 0. */
int pk_catalog_line(struct pk_ctx *ctx, const char *full_id);
/* HEAD of the checkout; false when it cannot be read from .git. */
bool pk_git_head(const struct pk_ctx *ctx, char *out, size_t cap);

/* ── what the gatherers hand the renderer ── */
struct pk_input {
    const char *goal;
    const char *change;
    char symbols[PK_SYMBOLS_MAX][128];
    int nsym;
    char files[PK_FILES_MAX][256];
    int nfile;
    int max_lines;
};

struct pk_group_line {
    char id[96];
    int catalog_line;
    char need[160];
};

struct pk_route_line {
    char file[256];
    char route[96];
    bool consensus_risk;
};

struct pk_facts {
    char head[65];            /* "" when unavailable */
    char source_hex[65];
    char dep_hex[65];
    char name[48];
    int nroute;
    struct pk_route_line route[PK_TOUCH_MAX];
    int ngroup;
    struct pk_group_line group[PK_GROUPS_MAX];
    int excerpt_lines;
    int max_dependents;
    int ntouch;
};

/* Packet-shape pieces (native_code_packet_md.c). */
enum {
    PK_TRAP_TESTS = 1u << 0,
    PK_TRAP_COMMAND = 1u << 1,
    PK_TRAP_DEF = 1u << 2,
    PK_TRAP_DOCS = 1u << 3,
    PK_TRAP_CORE = 1u << 4,
    PK_TRAP_ARM = 1u << 5,
    PK_GATE_LEN = 1280,
    PK_TRAP_LEN = 320,
    PK_GATES = 4,
    PK_TRAPS = 8
};
size_t pk_gate_lines(const struct pk_facts *f, char (*out)[PK_GATE_LEN]);
size_t pk_trap_lines(unsigned mask, char (*out)[PK_TRAP_LEN]);
/* The whole packet in PACKET_TEMPLATE field order. `files`, `keep`,
 * `authority` and `notes` are the already rendered section bodies. */
void pk_md_document(struct pk_sb *doc, const struct pk_input *in,
                    const struct pk_facts *f, const struct pk_sb *files,
                    const struct pk_sb *keep, const struct pk_sb *authority,
                    const struct pk_sb *notes);
void pk_slug(const char *goal, char *out, size_t cap);
const char *pk_size_class(int max_dependents);

#endif /* ZCL_TOOLS_COMMAND_NATIVE_CODE_PACKET_PRIV_H */
