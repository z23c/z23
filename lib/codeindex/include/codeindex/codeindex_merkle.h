/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_merkle — a SHA3-256 Merkle tree over the indexed source tree, so
 * "what does this checkout contain" is one 32-byte answer and "did lib/net
 * change" is one 32-byte comparison instead of a rescan.
 *
 * ── Shape ──
 * LEAF        one indexed source file (exactly the set ci_enumerate_sources()
 *             walks: the .c/.h under the configured lib/app/core/config/tools/
 *             domain/adapters/ports/src roots). Digest binds the file's
 *             repo-relative path, its byte length, and its bytes.
 * INTERNAL    one directory that has at least one indexed file below it. Digest
 *             binds the directory's repo-relative path and, in one fixed order,
 *             every direct child's kind, name, and digest.
 * ROOT        the internal node whose path is "" — the identity of the entire
 *             indexed source state.
 *
 * Child order is the ONLY thing that makes two machines agree, so it is fixed
 * and documented in one place (codeindex_merkle.c, `merkle_child_key`): direct
 * children are ordered by strcmp over the child's name for a file and over the
 * child's name followed by '/' for a directory. That is exactly the order in
 * which children first appear in ci_enumerate_sources()' sorted repo-relative
 * path stream, so the builder needs no second sort and cannot disagree with the
 * documented rule. The two orders coincide because each child's key is a PREFIX
 * of every full path that child contributes — "name" for a file, "name/" for a
 * directory — so the first position at which two children's paths differ is one
 * both keys already cover. A second implementation must reason from that prefix
 * property and NOT from the ASCII rank of '/': '/' is 0x2f, above '.' (0x2e)
 * but below every character legal in a C identifier, so an ASCII argument gets
 * `ab_z.c` versus a directory `ab` exactly backwards while the prefix argument
 * gets it right.
 * Nothing absolute-path-dependent enters any preimage: two copies of the same
 * tree in different directories produce the same root.
 *
 * ── Ground truth ──
 * The files on disk are authoritative; this is a CACHE and an IDENTITY. Nodes
 * are persisted at <root>/.codeindex/source_tree.merkle purely so a refresh
 * after editing N files re-reads N files instead of all of them. The complete
 * image is SHA3-sealed. A snapshot that is missing, truncated, of an older
 * source-policy format, or simply wrong is DISCARDED and recomputed. Every
 * refresh still enumerates and stats the live inventory before reusing bytes.
 * Deleting source_tree.merkle is always safe and costs only one full pass.
 *
 * ── Inclusion proofs ──
 * A directory node's digest says "this subtree is exactly this"; it does not
 * say "and that subtree belongs to the root you trust". ci_merkle_prove()
 * closes that gap: it emits a self-contained authentication path from one
 * indexed file or one directory node up to the root, and
 * ci_merkle_proof_verify() checks it with NO access to the repository and no
 * access to the tree it came from. That standalone property is the whole
 * point — it is what lets one machine ship a SECTION of the tree (a directory
 * node and its bytes) to a machine that already trusts a root, and have the
 * receiver accept it without holding the other 99% of the checkout.
 *
 * ── The cost this shape imposes, stated plainly ──
 * This tree is NOT binary. An internal node binds ALL of its direct children,
 * so an authentication path is not one sibling per level: at each level the
 * proof must carry EVERY other direct child's kind, name and digest, in the
 * canonical order, or the parent's preimage cannot be recomputed. Proof size
 * is therefore the SUM OF SIBLING COUNTS along the path, not log(n). On this
 * repository that is cheap for most paths and expensive for a few: a file
 * under a directory holding ~935 indexed siblings costs ~60 KB, while a file
 * in an ordinary module directory costs a few KB. Those are real measured
 * numbers (lib/test/src is the worst case here), not estimates, and they are
 * a property of the design, not a defect to be hidden. Making the tree binary
 * would fix it and would also change the root of every checkout, so it is not
 * on the table.
 *
 * Because the cost is unbounded in principle, the proof is bounded in
 * practice: CI_MERKLE_PROOF_MAX_LEVELS levels and CI_MERKLE_PROOF_MAX_CHILDREN
 * sibling records across the whole proof. Exceeding either is a LOUD FAILURE
 * from ci_merkle_prove() — never a short proof that would verify against
 * nothing, and never a silent truncation.
 *
 * ── What is bound, and by whom ──
 * The verifier recomputes each parent digest with `merkle_node_digest`, the
 * SAME function the builder calls to mint that digest in the first place —
 * there is exactly one statement of the interior preimage rule in this
 * library, and both sides go through it. A second hand-inlined copy in the
 * verifier is the one way a proof system silently becomes worthless, so there
 * isn't one.
 * Leaf and interior preimages are domain-separated at the source (tag 0x10
 * plus "zcl.codeindex.merkle.leaf.v1" versus tag 0x11 plus
 * "zcl.codeindex.merkle.node.v1"), so a leaf digest cannot be replayed as a
 * directory digest; the proof additionally carries each child's kind byte and
 * the proven path's own kind, and the verifier checks both.
 * The proven path is not an annotation: the verifier walks the level paths
 * upward and requires each level to be the exact parent directory of the one
 * below, and requires the named child at the recorded index to be the entry it
 * is folding. A proof minted for path A therefore cannot verify for path B.
 *
 * ── One input, one answer ──
 * Every path in a proof — the proven path, each level path, each child name —
 * must be in the single canonical shape the builder mints: no leading slash,
 * no trailing slash, no empty segment, no "." or ".." segment, every segment
 * inside CI_MERKLE_PROOF_NAME_MAX. The digest chain alone does NOT give this,
 * and the gap is not theoretical: taking the parent of "lib" and of "/lib"
 * yields the same parent and the same basename, so a proof for any TOP-LEVEL
 * entry, re-labelled with a leading slash, used to verify against the same
 * root with the same claimed digest. Two byte images, two reported paths, one
 * accepted answer. Deeper levels were never exposed — a level path is hashed
 * verbatim, so "/lib/net" cannot reproduce "lib/net"'s digest — which is
 * exactly why the hole was quiet. ci_merkle_proof_verify() now rejects any
 * non-canonical path outright, and requires the levels to tile the sibling
 * arena front to back with no gap and no overlap, so the set of proofs that
 * verify is exactly the set that can be written down and read back.
 */

#ifndef ZCL_CODEINDEX_MERKLE_H
#define ZCL_CODEINDEX_MERKLE_H

#include "core/zcl_ids.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One directory subtree, or the whole tree when `path` is "". Counts are
 * RECURSIVE (everything below the node); `direct_children` is not. */
struct ci_merkle_node {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint32_t               file_count;      /* indexed files below, recursive */
    uint32_t               dir_count;       /* directory nodes below, exclusive */
    uint32_t               direct_children; /* immediate files + subdirectories */
    uint64_t               total_bytes;     /* sum of indexed file sizes below */
};

/* One indexed source file. */
struct ci_merkle_leaf {
    char                   path[256];
    struct zcl_sha3_digest digest;
    uint64_t               size;
};

/* What the last refresh actually cost. Derived per call, never persisted —
 * these are the numbers that make the incrementality claim checkable instead
 * of asserted. */
struct ci_merkle_cost {
    uint32_t files_total;    /* leaves in the tree */
    uint32_t files_read;     /* leaves whose bytes were re-read this refresh */
    uint32_t leaves_reused;  /* leaves served from the snapshot (files_total-read) */
    uint64_t bytes_total;    /* total bytes represented by every leaf */
    uint64_t bytes_read;     /* file bytes hashed this refresh */
    uint32_t nodes_total;    /* directory nodes incl. the root */
    uint32_t nodes_hashed;   /* directory nodes whose digest was recomputed */
    uint32_t nodes_reused;   /* directory nodes served from the snapshot */
    bool     snapshot_used;  /* a usable snapshot was found and read */
    bool     snapshot_saved; /* a new snapshot was published this refresh */
    bool     inventory_changed; /* sorted live paths differ from snapshot */
    bool     full_rescan;     /* no snapshot, invalid/policy, or inventory drift */
};

/* An immutable in-memory Merkle tree. */
struct ci_merkle;

/* Build the tree for the checkout at `root`, reusing <root>/.codeindex/
 * source_tree.merkle for every file whose (dev,ino,size,mtime,ctime) cache key
 * is unchanged, and publishing an updated snapshot when anything moved.
 * `cost` (may be NULL) receives the accounting above. NULL on hard failure
 * (unreadable source root); a bad snapshot is never a failure. */
struct ci_merkle *ci_merkle_refresh(const char *root, struct ci_merkle_cost *cost);

/* Authority path for resident source epochs. Like refresh, but an inventory
 * change discards the just-updated cache and performs one complete byte pass.
 * This makes missing/invalid/policy/inventory cases share one explicit cold
 * fallback while the normal unchanged startup reads zero source bytes. */
struct ci_merkle *ci_merkle_refresh_reconciled(
    const char *root, struct ci_merkle_cost *cost);

/* Same, but never reads or writes the snapshot: every leaf is re-read. This is
 * the from-scratch reference path — determinism and incrementality are both
 * measured against it. */
struct ci_merkle *ci_merkle_build_cold(const char *root,
                                       struct ci_merkle_cost *cost);

void ci_merkle_free(struct ci_merkle *m);

/* The whole-tree root node (path ""). */
bool ci_merkle_root(const struct ci_merkle *m, struct ci_merkle_node *out);

/* Look up one directory subtree. `dirpath` is repo-relative with no trailing
 * slash; "", ".", and "/" all mean the whole tree. Absence is not an error:
 * *found is set false and true is returned. */
bool ci_merkle_node(const struct ci_merkle *m, const char *dirpath,
                    struct ci_merkle_node *out, bool *found);

/* Look up one indexed file's leaf. Absence is not an error. */
bool ci_merkle_leaf(const struct ci_merkle *m, const char *filepath,
                    struct ci_merkle_leaf *out, bool *found);

/* Hash one known changed path with the exact leaf preimage used by this tree,
 * without enumerating or refreshing the repository. Missing is an honest
 * result (*found=false); symlinks, path escapes, type changes, and bytes that
 * mutate during the read fail closed. This is the resident edit-epoch seam. */
bool ci_merkle_hash_changed_leaf(const char *root, const char *filepath,
                                 struct ci_merkle_leaf *out, bool *found);

/* Direct subdirectories of `dirpath`, in the documented child order. Fills up
 * to `cap` rows, returns the count of direct subdirectories that EXIST (which
 * may exceed `cap`, so a caller can report truncation), -1 on error. */
int ci_merkle_child_dirs(const struct ci_merkle *m, const char *dirpath,
                         struct ci_merkle_node *out, int cap);

/* Lowercase hex of a digest; `out` must hold 65 bytes. */
void ci_merkle_hex(const struct zcl_sha3_digest *d, char out[65]);

/* Remove the persisted snapshot for `root`. Always safe (derived data); a
 * missing snapshot is success. */
bool ci_merkle_forget(const char *root);


/* ── inclusion proofs ────────────────────────────────────────────────── */

enum {
    /* One level per directory between the proven path and the root. The build
     * refuses to nest deeper than this, so a legitimate proof can never need
     * more levels than the tree can contain. */
    CI_MERKLE_PROOF_MAX_LEVELS = 32,
    /* Every sibling record in the whole proof, summed across levels — not a
     * per-level cap. One flat arena keeps a proof one allocation and makes the
     * bound one number to reason about. 4096 is ~4x the widest path this
     * repository produces today (lib/test/src alone contributes ~935). */
    CI_MERKLE_PROOF_MAX_CHILDREN = 4096,
    /* Same limit the builder enforces on a basename (MERKLE_NAME_MAX): a
     * truncated name would let two distinct siblings hash alike. */
    CI_MERKLE_PROOF_NAME_MAX = 160,
    /* Ceiling for the serialized form; larger than the largest proof the
     * bounds above can express, so encoding never fails for a legal proof. */
    CI_MERKLE_PROOF_WIRE_MAX = 1048576u,
};

/* What a proof is about, and what each sibling record is. Same numbering the
 * interior preimage writes, so these ARE the bytes that get hashed. */
enum {
    CI_MERKLE_KIND_FILE = 0, /* an indexed source file (a leaf) */
    CI_MERKLE_KIND_DIR  = 1, /* a directory node */
};

/* One direct child of a directory node, exactly as the interior preimage
 * consumes it. The builder hashes this very type, so a proof cannot describe a
 * child in a shape the builder never mints. */
struct ci_merkle_proof_child {
    char                   name[CI_MERKLE_PROOF_NAME_MAX]; /* basename, no '/' */
    uint8_t                kind;                           /* CI_MERKLE_KIND_* */
    struct zcl_sha3_digest digest;
};

/* One directory on the path from the proven node to the root. `index` names
 * the child that carries the digest folded in from the level below. */
struct ci_merkle_proof_level {
    char     path[256];    /* the directory's repo-relative path; "" is the root */
    uint32_t first_child;  /* offset into ci_merkle_proof.children */
    uint32_t nchildren;    /* ALL direct children, in canonical order */
    uint32_t index;        /* < nchildren */
};

/* A self-contained authentication path. Levels run inward-to-outward: level 0
 * is the proven path's own parent directory and the last level is always the
 * root (""). A proof of the root itself has zero levels. ~800 KB when empty,
 * so allocate it, never stack it — ci_merkle_proof_alloc() does that. */
struct ci_merkle_proof {
    char     path[256]; /* the proven repo-relative path; "" is the whole tree */
    uint8_t  kind;      /* CI_MERKLE_KIND_* of the proven path */
    uint32_t nlevels;
    uint32_t nchildren; /* total sibling records used across all levels */
    struct ci_merkle_proof_level level[CI_MERKLE_PROOF_MAX_LEVELS];
    struct ci_merkle_proof_child children[CI_MERKLE_PROOF_MAX_CHILDREN];
};

/* Zeroed proof buffer; NULL only if allocation fails. */
struct ci_merkle_proof *ci_merkle_proof_alloc(void);
void ci_merkle_proof_free(struct ci_merkle_proof *p);

/* Emit the proof that `path` is bound into this tree's root. `path` may name
 * an indexed file or a directory node; "", ".", and "/" all mean the root.
 * `out_digest` (may be NULL) receives the digest the proof attests to, which
 * is what a receiver must be handed alongside the proof.
 * Absence is not an error: *found is set false and true is returned.
 * A path that would need more than CI_MERKLE_PROOF_MAX_LEVELS levels or more
 * than CI_MERKLE_PROOF_MAX_CHILDREN sibling records FAILS loudly — the proof
 * is never truncated. Before returning, the generator verifies its own output
 * against the tree root and refuses to emit a proof it cannot itself check. */
bool ci_merkle_prove(const struct ci_merkle *m, const char *path,
                     struct ci_merkle_proof *out,
                     struct zcl_sha3_digest *out_digest, bool *found);

/* Check a proof against a root, with no tree and no repository. Note what is
 * NOT in this signature: there is no struct ci_merkle here and there is no
 * root path, so a verifier cannot consult the thing it is meant to be
 * independent of. `claimed` is the digest the caller was told belongs to
 * proof->path; `root` is the root the caller already trusts.
 * A structurally malformed proof is an honest *ok = false, not an error. */
bool ci_merkle_proof_verify(const struct ci_merkle_proof *p,
                            const struct zcl_sha3_digest *claimed,
                            const struct zcl_sha3_digest *root, bool *ok);

/* Serialized bytes the proof would occupy — the number to quote when talking
 * about what a proof costs to ship. 0 if `p` is malformed. */
size_t ci_merkle_proof_wire_size(const struct ci_merkle_proof *p);

/* Serialize into `out`. Returns the byte count written, or 0 if `cap` is too
 * small or the proof is malformed — an explicit refusal, never a short write. */
size_t ci_merkle_proof_encode(const struct ci_merkle_proof *p,
                              unsigned char *out, size_t cap);

/* Parse bytes produced by ci_merkle_proof_encode. Every length is checked
 * against the bounds above before it is used. A malformed image is an honest
 * false, never a partially populated proof. */
bool ci_merkle_proof_decode(const unsigned char *in, size_t len,
                            struct ci_merkle_proof *out);

/* Decode and verify in one step: the shape a receiver actually uses, holding
 * nothing but a byte blob, a claimed digest, and a trusted root. `out_path`
 * (may be NULL, 256 bytes) and `out_kind` (may be NULL) report WHAT the proof
 * turned out to be about, so a caller can decide whether that is the thing it
 * asked for. Allocation failure is the only false return. */
bool ci_merkle_proof_verify_bytes(const unsigned char *in, size_t len,
                                  const struct zcl_sha3_digest *claimed,
                                  const struct zcl_sha3_digest *root,
                                  char out_path[256], uint8_t *out_kind,
                                  bool *ok);

#endif /* ZCL_CODEINDEX_MERKLE_H */
