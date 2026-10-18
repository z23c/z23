/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private interface of the docs knowledge tree (discover.wiki, discover.read):
 * confined docs/ access, bounded reads, and title/summary extraction. Defined
 * in native_wiki_docs.c; consumed by native_wiki_tree.c and native_wiki_read.c.
 */

#ifndef ZCL_TOOLS_COMMAND_NATIVE_WIKI_PRIV_H
#define ZCL_TOOLS_COMMAND_NATIVE_WIKI_PRIV_H

#include "command/native_command.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    WK_REL_MAX = 512,      /* longest topic or page path accepted */
    WK_PATH_MAX = 4096,    /* longest resolved filesystem path */
    WK_HEAD_MAX = 8192,    /* bytes read from a file for title and summary */
    WK_TEXT_MAX = 200,     /* title and summary byte cap */
    WK_NAME_MAX = 128,     /* longest directory entry name listed */
    WK_SCAN_MAX = 4096,    /* directory entries examined per topic */
    WK_CHUNK_DEFAULT = 4096,
    WK_CHUNK_MAX = 16384,
};

enum wk_status { WK_OK, WK_BAD, WK_ESCAPES, WK_MISSING, WK_NOMEM, WK_FULL };

struct wk_docs {
    char root[WK_PATH_MAX]; /* resolved docs directory */
};

struct wk_meta {
    char title[WK_TEXT_MAX + 1];
    char summary[WK_TEXT_MAX + 1];
};

struct wk_child {
    char name[WK_NAME_MAX];
    bool topic;
};

struct wk_children {
    struct wk_child *v;
    size_t n;
};

/* Resolve the docs root: the docsdir input alone when given; else
 * <source root>/docs, the executable's directory or up to three parents
 * holding docs/, then <prefix>/share/z23/docs. A root counts only with a
 * README.md. On failure the reply carries DOCS_UNAVAILABLE. */
bool wk_docs_open(const struct zcl_command_request *request,
                  struct wk_docs *docs, struct zcl_command_reply *reply);

/* Syntactic check of a docs-relative path; writes it without a trailing
 * slash. False for absolute, `.`/`..`, empty-segment, backslash or oversized
 * input. */
bool wk_rel_normalize(const char *in, char *out, size_t cap);

/* Resolve `rel` under the docs root, following symlinks. */
enum wk_status wk_resolve(const struct wk_docs *docs, const char *rel,
                          char *real, size_t cap);

/* Fail the reply with a typed resolve error (status FAILED, exit INVALID). */
void wk_fail(struct zcl_command_reply *reply, const char *code,
             const char *message, const char *evidence);

bool wk_is_file(const char *real);
bool wk_is_topic(const struct wk_docs *docs, const char *real);

/* Nearest ancestor of `rel` that is a topic; "" is the root. */
void wk_nearest_topic(const struct wk_docs *docs, const char *rel, char *out,
                      size_t cap);

/* Read at most cap-1 bytes from the start of `real` (NUL-terminated). */
bool wk_head(const char *real, char *buf, size_t cap, size_t *len);

/* Render Markdown inline syntax as plain text: `[text](target)` becomes
 * `text`; `**`, `__` and backticks are dropped. Writes at most cap-1 bytes
 * of whole UTF-8 sequences and a NUL; returns the bytes written. */
size_t wk_plain(char *dst, size_t cap, const char *src, size_t len);

/* First `# ` heading and first prose paragraph of a Markdown head. */
void wk_meta_scan(const char *buf, size_t len, struct wk_meta *meta);

/* Copy at most `max` bytes of `src` as whole UTF-8 sequences: invalid bytes
 * become '?', control bytes (newline and tab kept when keep_nl) become spaces.
 * force_first emits the first sequence even if it exceeds `max`. Returns the
 * bytes written, equal to the bytes consumed. */
size_t wk_clean(char *dst, size_t max, const char *src, size_t len,
                bool keep_nl, bool force_first);

/* Entries of a topic directory: sub-topics (directories with README.md) and
 * pages (.md files except README.md), sorted by name. */
enum wk_status wk_children_list(const struct wk_docs *docs, const char *real,
                                struct wk_children *out);
void wk_children_free(struct wk_children *c);

/* Read `want` bytes at `offset` of `real` plus 3 lookahead bytes. */
bool wk_read_at(const char *real, int64_t offset, size_t want, char *buf,
                size_t *got, int64_t *size);

#endif
