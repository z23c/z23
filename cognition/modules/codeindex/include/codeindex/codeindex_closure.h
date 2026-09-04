/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_closure — the input-closure digest of one unit of work.
 *
 * A "unit" is one thing a proof can admit by receipt instead of re-running: a
 * lint gate, a test group. The question a receipt has to answer is not "did the
 * tree change" but "did anything THIS unit can see change", and this is the one
 * place that question is turned into 32 bytes.
 *
 * ── Why it hangs off the Merkle tree ──
 * codeindex_merkle already holds a SHA3-256 digest for every indexed source
 * file AND for every directory that contains one. A unit whose inputs are a
 * directory subtree therefore costs ONE lookup — the directory node's digest
 * already binds every file below it, recursively — and reads no file bytes at
 * all. That is the whole speedup: a gate that scans engine/services/src is
 * keyed by one 32-byte node digest, not by hashing 400 files, and a commit that
 * touches only contexts/wallet cannot move it.
 *
 * ── What the Merkle tree does NOT cover, stated plainly ──
 * ci_enumerate_sources() walks .c/.h (plus registry files) under the roots in
 * source_roots.def. It does NOT see shell scripts, Makefiles, .md documents,
 * baseline/allowlist tables, or .def files outside those extensions. A unit
 * whose verdict depends on one of those MUST declare it with
 * ci_closure_add_raw(), which hashes the file's bytes directly. Declaring a
 * directory does not cover the non-source files inside it, and this module
 * cannot detect that mistake for you — ci_closure_cost() reports exactly what
 * was covered by which mechanism so a caller can be audited against reality.
 *
 * ── Fail-closed, everywhere ──
 * A declared scope that is absent from the tree is a hard refusal, never a
 * digest over nothing: an input that is not there means the closure is not the
 * one the caller declared. A duplicate scope is refused too — a caller that
 * lists the same directory twice does not know its own closure. Entries are
 * folded in canonical sorted order, so two callers that declare the same set in
 * different orders get the same digest and a caller cannot shop for one by
 * reordering.
 *
 * ── What this module is NOT ──
 * It computes a key. It does not decide whether a key admits anything; that
 * policy belongs to whoever owns the receipt store. Nothing here reads or
 * writes a receipt.
 */

#ifndef ZCL_CODEINDEX_CLOSURE_H
#define ZCL_CODEINDEX_CLOSURE_H

#include "codeindex/codeindex_merkle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    /* Declared inputs per unit. A gate or group that needs more than this many
     * distinct scopes has not bounded its inputs, and the refusal is the
     * honest answer. */
    CI_CLOSURE_MAX_ENTRIES = 256,
    /* Same width as ci_merkle_node.path, so any path the tree can name fits. */
    CI_CLOSURE_PATH_MAX    = 256,
};

/* How one declared input was answered. The kind is part of the preimage, so a
 * directory digest can never be replayed as a file digest. */
enum ci_closure_source {
    CI_CLOSURE_TREE_DIR  = 0, /* a Merkle directory node — no bytes read */
    CI_CLOSURE_TREE_FILE = 1, /* a Merkle leaf — no bytes read */
    CI_CLOSURE_RAW_FILE  = 2, /* a file the tree does not index — bytes hashed */
};

/* What the closure cost to compute, and what it actually covers. These are the
 * numbers that make the "directory digests are free" claim checkable instead of
 * asserted. */
struct ci_closure_cost {
    uint32_t entries;          /* declared scopes folded in */
    uint32_t dir_entries;      /* answered by a directory node digest */
    uint32_t file_entries;     /* answered by a leaf digest */
    uint32_t raw_entries;      /* answered by hashing bytes here */
    uint32_t files_covered;    /* indexed files bound, recursively, by the above */
    uint64_t bytes_covered;    /* indexed bytes bound, recursively */
    uint64_t bytes_hashed;     /* bytes this module actually read and hashed */
};

/* Under construction. Callers own the storage; nothing here allocates. */
struct ci_closure {
    char     domain[64];
    uint32_t nentries;
    bool     poisoned; /* a refused add; seal must fail */
    struct {
        char                   path[CI_CLOSURE_PATH_MAX];
        uint8_t                source; /* enum ci_closure_source */
        struct zcl_sha3_digest digest;
    } entry[CI_CLOSURE_MAX_ENTRIES];
    struct ci_closure_cost cost;
};

/* Start a closure. `domain` separates one kind of unit's keyspace from
 * another's ("zcl.lint.gate.closure.v1", "zcl.test.group.closure.v1"); it is
 * bound into the digest, so a lint key can never be read as a test key. */
bool ci_closure_init(struct ci_closure *c, const char *domain);

/* Declare a directory subtree. One node lookup, zero file reads: the node's
 * digest already binds every indexed file below it. Absent from the tree is a
 * refusal. "" / "." / "/" mean the whole indexed tree. */
bool ci_closure_add_dir(struct ci_closure *c, const struct ci_merkle *m,
                        const char *dirpath);

/* Declare one indexed source file. One leaf lookup, zero file reads. */
bool ci_closure_add_file(struct ci_closure *c, const struct ci_merkle *m,
                         const char *filepath);

/* Declare one input the Merkle tree does not index — a shell script, a
 * Makefile, a baseline table, a document. `root` is the checkout root and
 * `relpath` is repo-relative. The file's bytes ARE read and hashed. Missing or
 * unreadable is a refusal. */
bool ci_closure_add_raw(struct ci_closure *c, const char *root,
                        const char *relpath);

/* Fold everything declared so far into one digest, in canonical sorted order.
 * Refuses an empty closure (a unit with no declared inputs has not declared a
 * closure) and refuses a closure any add() already refused. */
bool ci_closure_seal(const struct ci_closure *c, struct zcl_sha3_digest *out);

/* What the closure covered and what it cost. */
void ci_closure_cost(const struct ci_closure *c, struct ci_closure_cost *out);

#endif /* ZCL_CODEINDEX_CLOSURE_H */
