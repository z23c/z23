/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: libclang-side state of the optional semantic sensor (never linked into z23, z23-dev or core). */
#ifndef ZCL_TOOLS_SENSORS_CLANG_MANIFEST_H
#define ZCL_TOOLS_SENSORS_CLANG_MANIFEST_H

#include <clang-c/Index.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "clang_manifest_core.h"

/* Set by the Makefile's link probe: 1 when the libclang image exports
 * clang_getTypePrettyPrinted, 0 when it does not (Apple's libclang.dylib).
 * The two spell canonical types by different grammars; CM_TYPE_GRAMMAR is
 * the token the producer digest binds (clang_manifest_ast.c, cm_type_str). */
#ifndef CM_TYPE_PRETTY_PRINTED
#define CM_TYPE_PRETTY_PRINTED 0
#endif
#if CM_TYPE_PRETTY_PRINTED
#define CM_TYPE_GRAMMAR "clang_getTypePrettyPrinted:anon-tag-loc-off"
#else
#define CM_TYPE_GRAMMAR "clang_getTypeSpelling:anon-tag-loc-cut"
#endif

struct cm_tagname {
    CXCursor decl;
    char *name;
};

/* The walk over one definition (a function body or a variable
 * initializer): its identity, and the call sites already recorded so the
 * callee's DeclRefExpr is not also an address escape. */
struct cm_site {
    const char *id;
    struct cm_function *fn;
    CXSourceLocation *calls;
    size_t ncalls, capcalls;
};

struct cm_state {
    struct cm_core core;
    CXIndex index;
    CXTranslationUnit tu;
    CXPrintingPolicy policy;
    struct cm_tagname *tagnames;
    size_t ntagnames, captagnames;
    struct cm_site *site;
    /* The main file of this parse, by identity: with a preamble, libclang
     * reports a file included after it at depth 0 too, so depth alone does
     * not name the main file. */
    CXFile main_file;
};

char *cm_take_string(CXString s);
const struct cm_file *cm_file_of(struct cm_state *st, CXFile f);
const struct cm_file *cm_cursor_file(struct cm_state *st, CXCursor c,
                                     unsigned *line, unsigned *offset);

/* clang_manifest_tokens.c: mark each file's live lookup words and '#' by
 * clang's own lexing (cm_file.live); false when the TU is refused. */
bool cm_tokenize_files(struct cm_state *st, bool trigraphs);

/* clang_manifest_ast.c */
bool cm_walk(struct cm_state *st);

/* ---- one emit (clang_manifest.c), shared by `emit` and `session` ----------- */

/* The options of one emit, exactly as `emit` takes them on its command line. */
struct cm_opts {
    struct cm_cc_snapshot *cc_snapshot; /* private session lifetime; not a CLI option */
    const char *root;
    const char *source;
    const char *out;
    const char *tree;
    const char *cc;
    const char *toolchain_id;
    bool facts;
    uint32_t max_records;
    uint64_t max_section_bytes;
    char **argv;
    int argc;
};

/* The argv the front end parses (the caller's minus output-only controls and
 * the source, plus the -v suffix) and the normalized identity argv. */
struct cm_args {
    const char **parse;
    size_t nparse;
    char **identity;
    size_t nidentity;
};

/* How one emit obtains its translation unit. `parse` runs with the front
 * end's stderr captured (its -v report) and must set st->tu, or fail through
 * cm_fail. A front end that `owns_tu` has the TU and its index disposed when
 * the emit ends (the cold parse); otherwise the TU belongs to the caller (a
 * warm session entry) and survives the emit. No cursor, location or file
 * handle survives an emit either way: every extraction starts from a fresh
 * cm_state. */
struct cm_front {
    bool (*parse)(struct cm_state *st, const struct cm_opts *o,
                  const struct cm_args *args, void *ctx);
    void *ctx;
    bool owns_tu;
};

/* Parse (through front) and extract one manifest into *bytes (caller frees).
 * On refusal returns false with the reason in why. Never writes a file. */
bool cm_emit_bytes(const struct cm_opts *o, const struct cm_front *front,
                   uint8_t **bytes, size_t *len, char *why, size_t why_len);
/* The cold front end: a fresh index, a plain parse, disposed after the emit.
 * This is the oracle every warm manifest is compared against. */
extern const struct cm_front cm_cold_front;
/* Parse `emit`-style options from argv[first..argc). */
bool cm_parse_opts(int argc, char **argv, int first, struct cm_opts *o);

/* ---- warm session (clang_manifest_session.c) ------------------------------- */

/* `z23-clang-manifest session`: one process serves a batch of emits read
 * from stdin, keeping each TU warm between them. Contract:
 * docs/work/SEMANTIC_MANIFEST.md, "Warm session". */
int cm_session_main(int argc, char **argv);

#endif /* ZCL_TOOLS_SENSORS_CLANG_MANIFEST_H */
