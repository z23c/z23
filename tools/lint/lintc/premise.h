/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: base-relative premise selection core — the exact inputs a lint
 * unit's verdict can depend on, hashed at the candidate and at a verified
 * base commit, so a later slice can inherit a unit whose premise is equal.
 *
 * Nothing here is authority. A row this module computes is information: no
 * reader in this tree treats would_inherit as a verdict, and no premise root
 * is persisted between runs. Every input is either the candidate generation
 * directory (hashed here, byte by byte) or a base commit whose objects were
 * copied into a FRESH private Git store by `git fetch` — Git's own
 * index-pack re-derives every received object id from its bytes there, so a
 * planted or edited object in the persistent store fails the fetch instead
 * of faking an unchanged file. That is the same sanctioned path dev land's
 * remote observation uses (tools/dev/dev_git_tree.c): Git object ids are
 * opaque locators handed to Git, never hashed by z23 code, and every root
 * below is SHA3-256 over file bytes with the ZVCS blob tag.
 *
 * Premise of one unit (a translation unit of a per-TU gate, or one file of
 * a per-file gate):
 *   gate root    gate code bytes, the toolchain pin bytes, and the textual
 *                values of the Makefile variables the gate reads (plus every
 *                variable those values reference). Gate code is the declared
 *                gate files, where "dir/" names every path under dir, plus
 *                every path a word of those Makefile values names, plus the
 *                include closure of each .c/.h among them — so a gate run by
 *                a binary built from tree sources carries those sources and
 *                their headers. A computed include there means no unit of
 *                the gate inherits;
 *   path set     the sorted set of paths in the tree — it answers every
 *                "does this header exist" lookup, so an added shadowing
 *                header flips every unit;
 *   closure      the over-approximate textual include closure of the unit
 *                (every #include/#include_next/#embed, ignoring #if, each
 *                name resolved against EVERY tracked path it could name);
 *                a macro-computed include makes the unit never inheritable.
 *                A per-file gate (unit_self) reads only the unit's bytes, so
 *                its closure is the unit alone;
 *   baseline     the unit's own rows in the gate's baseline files.
 *
 * A catalog-row gate (premise_gate.catalog set) names units by row id.
 * Its unit closure is the union of the closures of every tree path the
 * row's variables name, the row's own variable text is part of the unit,
 * and the catalog residue (the lines no row owns) is part of the gate.
 */
#ifndef Z23_LINT_PREMISE_H
#define Z23_LINT_PREMISE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PREMISE_HASH_BYTES 32
#define PREMISE_REASON_MAX 192
#define PREMISE_OID_MAX 65
#define PREMISE_PATH_MAX 4096

struct premise_git;

struct premise_entry {
    char *path;
    char oid[PREMISE_OID_MAX];      /* base side: opaque Git locator */
    uint8_t hash[PREMISE_HASH_BYTES];
    bool hashed;
    bool present;                   /* hash attempt found the file */
    bool symlink;
    /* include-closure memo (candidate side only) */
    bool parsed;
    bool computed_include;
    size_t *deps;
    size_t ndeps;
    char **externals;
    size_t nexternals;
};

struct premise_tree {
    struct premise_entry *entries;  /* sorted by path after load */
    size_t count;
    size_t cap;
    char root[PREMISE_PATH_MAX];    /* candidate generation directory */
    struct premise_git *git;        /* base side: verified private store */
    uint8_t path_set_root[PREMISE_HASH_BYTES];
    size_t *by_base;                /* entry indexes sorted by basename */
};

struct premise_base_opts {
    const char *objects;   /* repository whose objects seed the fresh store */
    const char *remote;    /* locator whose ref tip must contain the base */
    const char *ref;       /* NULL: refs/heads/main */
    const char *base;      /* exact base commit (opaque Git locator) */
    const char *scratch;   /* private directory for the fresh store */
    unsigned depth;        /* 0: 256 commits below the tip */
};

struct premise_gate {
    const char *name;
    const char *const *gate_files;
    size_t n_gate_files;
    const char *const *make_vars;
    size_t n_make_vars;
    const char *const *baselines;
    size_t n_baselines;
    const char *makefile;  /* NULL: "Makefile" */
    const char *pin;       /* NULL: "tools/dev/toolchain.pin" */
    bool unit_self;        /* the unit's closure is its own bytes only */
    const char *catalog;   /* non-NULL: units are this catalog's row ids */
};

struct premise_unit {
    const char *unit;
    uint8_t action_root[PREMISE_HASH_BYTES];
    uint8_t base_root[PREMISE_HASH_BYTES];
    bool base_root_known;
    bool would_inherit;
    char reason[PREMISE_REASON_MAX];
};

struct premise_session {
    struct premise_tree cand;
    struct premise_tree base;
    bool base_verified;
    bool confined;
    char disabled[PREMISE_REASON_MAX];
};

/* Open a selection session: walk the candidate generation at root, and
 * verify opts->base (NULL opts: no base, selection disabled). A base that
 * cannot be verified DISABLES selection with a reason; it is not an error.
 * confined=false (no Landlock, or forced off) also disables inheritance.
 * Returns 0, or 2 when the candidate tree itself cannot be read. */
int premise_session_open(struct premise_session *s, const char *root,
                         const struct premise_base_opts *opts, bool confined,
                         FILE *err);

/* Compute every unit's action_root, base_root, would_inherit and reason.
 * units[i].unit must be set by the caller. Returns 0, or 2 on an
 * infrastructure failure (allocation, unreadable candidate file). */
int premise_gate_eval(struct premise_session *s, const struct premise_gate *g,
                      struct premise_unit *units, size_t n, FILE *err);

/* Print the unit's candidate premise as the unit-exec grant list: one
 * root-relative regular file per line (closure, gate code, pin, baselines,
 * Makefile). Returns 0, 1 when the unit has no finite premise (computed
 * include), or 2 on failure. */
int premise_unit_grants(struct premise_session *s, const struct premise_gate *g,
                        const char *unit, FILE *out, FILE *err);

void premise_session_close(struct premise_session *s);

/* ── internals shared by the premise_*.c files ─────────────────────────── */

int premise_tree_add(struct premise_tree *t, const char *path, const char *oid,
                     bool symlink);
int premise_tree_finish(struct premise_tree *t);
struct premise_entry *premise_tree_find(const struct premise_tree *t,
                                        const char *path);
int premise_tree_read(struct premise_tree *t, const char *path,
                      uint8_t **bytes, size_t *len, FILE *err);
int premise_tree_hash(struct premise_tree *t, struct premise_entry *e,
                      FILE *err);
int premise_tree_walk(struct premise_tree *t, const char *root, FILE *err);
void premise_tree_free(struct premise_tree *t);
bool premise_path_pruned(const char *path);

int premise_git_open(const struct premise_base_opts *opts,
                     struct premise_tree *base, char *why, size_t why_cap,
                     FILE *err);
int premise_git_blob(struct premise_git *g, const char *oid, uint8_t **bytes,
                     size_t *len);
void premise_git_close(struct premise_git *g);

int premise_include_closure(struct premise_tree *t, const char *unit,
                            size_t **out, size_t *nout, char ***ext,
                            size_t *next, bool *computed, FILE *err);

struct premise_make_value {
    char *name;
    char *text;
};
int premise_make_values(const uint8_t *mk, size_t len,
                        const char *const *vars, size_t nvars,
                        struct premise_make_value **out, size_t *nout);
void premise_make_values_free(struct premise_make_value *v, size_t n);
/* The makefile text minus every definition of an owned variable (a define
 * block whole) and minus comment lines outside define blocks. */
int premise_make_residue(const uint8_t *mk, size_t len,
                         const char *const *owned, size_t nowned, char **out,
                         size_t *out_len);

/* premise_catalog.c: catalog-row units (see the file comment there). */
struct premise_catalog {
    uint8_t *mk;
    size_t len;
    bool present;          /* the catalog file exists on this side */
    char **ids;            /* the literal row list, in catalog order */
    size_t nids;
};
/* 0 (an absent catalog is present=false with no rows), or 2 when the file
 * cannot be read or its row list is not a literal list of ids. */
int premise_catalog_open(struct premise_tree *t, const char *path,
                         struct premise_catalog *c, FILE *err);
void premise_catalog_close(struct premise_catalog *c);
bool premise_catalog_has(const struct premise_catalog *c, const char *id);
int premise_catalog_residue(const struct premise_catalog *c,
                            uint8_t out[PREMISE_HASH_BYTES]);
int premise_catalog_row_root(const struct premise_catalog *c, const char *id,
                             uint8_t out[PREMISE_HASH_BYTES], bool *computed);
/* Like premise_include_closure for one row id; 1 when the candidate
 * catalog has no such row. */
int premise_catalog_row_closure(struct premise_tree *t, const char *catalog,
                                const char *id, size_t **out, size_t *nout,
                                char ***ext, size_t *next, bool *computed,
                                FILE *err);


/* ── z23-lint subcommands (selection.c) ────────────────────────────────── */

int lint_select_main(int argc, char **argv);
int lint_premise_main(int argc, char **argv);

/* unit_exec.c */
int lint_unit_exec_main(int argc, char **argv);

#endif
