/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core_seal — the sealed-consensus-core manifest tool (Wave 1.1 / W0).
 *
 * The sealed core (top-level core/) holds the consensus predicates and static
 * parameter tables that decide whether a block/tx is valid. Its integrity is
 * pinned by a SHA3-256 manifest at core/MANIFEST.sha3: a per-file digest of
 * every tracked file under core/ (excluding the manifest itself) plus a single
 * ROOT digest over the sorted (path, filehash) stream. Any change to a sealed
 * file changes ROOT, which `make core-seal-check` catches.
 *
 * This tool deliberately does NOT shell to git. The Makefile feeds it the file
 * list on stdin (NUL-separated, from `git ls-files -z core/`); the tool only
 * hashes file bytes and reads/writes the manifest. No external dependencies —
 * it links the in-tree FIPS-202 SHA3-256 (lib/sha3/src/sha3.c) plus
 * memory_cleanse (lib/base/src/cleanse.c), stock libc otherwise.
 *
 * Usage (paths on stdin, NUL-separated):
 *   core_seal seal  core/MANIFEST.sha3   < filelist   (writes the manifest)
 *   core_seal check core/MANIFEST.sha3   < filelist   (0=match, 1=drift, 2=error)
 *
 * ── THE SECTION TREE (added alongside ROOT, never instead of it) ───────────
 *
 * ROOT is a single flat SHA3-256 fold over every sealed (path, filehash) pair.
 * It answers exactly one question — "did anything under the sealed set move?"
 * — for the whole set at once. That is the right answer for the seal's
 * IDENTITY, and it is why ROOT is BYTE-FROZEN here: it is mirrored into
 * lib/hotswap/include/hotswap/core_seal_root.h, every hot-swap module pins it,
 * and redefining it would require the owner unseal ritual. Nothing in this
 * file may change the value ROOT computes for a given input.
 *
 * What the flat fold cannot do is say WHERE the set moved, or let a verifier
 * check one subtree without replaying all of it. So this tool ALSO derives a
 * directory Merkle tree over the same sealed files and writes it as extra
 * manifest lines (SECTION per directory, TREE for the whole set).
 *
 * ── IT IS NOT A NEW MERKLE DIALECT ────────────────────────────────────────
 *
 * lib/codeindex already defines a SHA3-256 Merkle tree over this repository's
 * source (lib/codeindex/src/codeindex_merkle.c, documented in
 * lib/codeindex/include/codeindex/codeindex_merkle.h), and in that tree a
 * DIRECTORY IS ALREADY A SECTION: ci_merkle_node(m, "core/consensus", …)
 * returns that subtree's digest today. A second Merkle over source files, with
 * its own preimage and its own child order, is the duplicated-ledger shape the
 * architecture rule exists to prevent — and two subtly different child
 * orderings would be a silent interop bug the first time anyone compared them.
 *
 * So core_seal speaks codeindex's dialect EXACTLY. The three rules below are
 * transcribed from codeindex_merkle.c; they are not re-derived here, and any
 * change there must be mirrored here until the two are unified behind one
 * implementation.
 *
 *   LEAF   (tag 0x10, domain "zcl.codeindex.merkle.leaf.v1")
 *       SHA3-256( 0x10
 *                 || "zcl.codeindex.merkle.leaf.v1" 0x00
 *                 || relpath 0x00
 *                 || u64le(stat size)
 *                 || file bytes )
 *
 *   NODE   (tag 0x11, domain "zcl.codeindex.merkle.node.v1")
 *       SHA3-256( 0x11
 *                 || "zcl.codeindex.merkle.node.v1" 0x00
 *                 || dirpath 0x00                (repo-relative, "" for root)
 *                 || u32le(direct child count)
 *                 || for each direct child, in canonical order:
 *                        kind (0x00 file, 0x01 directory)
 *                        || name 0x00            (basename only)
 *                        || digest[32] )
 *
 *   CHILD ORDER
 *       strcmp over the child's KEY: a file's own name; a directory's name
 *       followed by '/'. (codeindex_merkle.c, merkle_child_key — the single
 *       statement of the rule.) That key is a prefix of the child's full
 *       repo-relative path, so key order and full-path strcmp order agree for
 *       every pair; core_seal sorts children by the key explicitly rather than
 *       relying on its input stream's order.
 *
 * DOMAIN SEPARATION — codeindex already answers this, so we adopt its answer
 * rather than inventing one: a leaf and an internal node are separated BOTH by
 * a distinct leading tag byte (0x10 vs 0x11) AND by a distinct NUL-terminated
 * domain string, and both are separated from codeindex's other SHA3 uses
 * (0x01 symbol row, 0x02 whole-file content hash). An internal node can never
 * be replayed as a leaf.
 *
 * ODD NODE COUNT — codeindex's tree is N-ARY, not binary: a directory node
 * binds ALL of its direct children in ONE preimage, with the child count
 * written in as u32le. There is no pairing step, therefore no odd-node case,
 * therefore no Bitcoin CVE-2012-2459 duplicate-tail ambiguity to rule out: the
 * count is bound, and two children of one directory cannot share a name.
 *
 * NOTHING CAN BE DROPPED — a "loose" file is not a special case here either.
 * Every sealed file is a leaf under the directory node named by its own path,
 * so core/UNSEAL.md is simply a file child of the node "core". Placement is
 * asserted after the build (every entry became exactly one leaf; the root
 * node's recursive file count equals the entry count) and any shortfall is a
 * hard exit(2) — a tree covering less than ROOT covers would prove strictly
 * less than the flat fold it sits beside.
 *
 * SCOPE — core_seal's file set is the Makefile's CORE_SEAL_PATHS as tracked by
 * git; codeindex's is ci_enumerate_sources()' .c/.h/.def policy. The two sets
 * are NOT identical (core/UNSEAL.md is sealed but not indexed; lib/validation
 * holds indexed files that are not sealed), so the WHOLE-TREE roots differ by
 * construction. A directory node's digest is comparable between the two trees
 * exactly when that directory's file set is identical in both — which is the
 * measurement that decides whether this seal can become a pure view over the
 * codeindex tree.
 *
 * BACKWARD COMPATIBILITY — `check` treats a manifest with no SECTION/TREE
 * lines as valid: it verifies ROOT exactly as before and says section
 * verification was skipped. A manifest that HAS them must have every section
 * re-derived and matched, and any drift NAMES the offending directory —
 * "core/consensus/src drifted" localises the edit, "ROOT drifted" does not.
 *
 * See CLAUDE.md "Tenacity & recovery" and the plan
 * ~/.claude/plans/we-are-working-to-concurrent-melody.md (Pillar 1, Wave 1.1).
 */
#define _POSIX_C_SOURCE 200809L

#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define HSZ SHA3_256_OUTPUT_SIZE
#define HEXSZ (2 * HSZ + 1)

/* Mirrors codeindex_merkle.c: tag bytes and per-kind domain strings. */
#define MERKLE_TAG_LEAF 0x10u
#define MERKLE_TAG_NODE 0x11u
static const char merkle_leaf_domain[] = "zcl.codeindex.merkle.leaf.v1";
static const char merkle_node_domain[] = "zcl.codeindex.merkle.node.v1";

/* Mirrors struct ci_merkle_node.path[256] and MERKLE_NAME_MAX. */
#define MERKLE_PATH_MAX 256
#define MERKLE_NAME_MAX 160

/* One sealed-file record: path, its 32-byte SHA3-256 content digest (the ROOT
 * ingredient), its codeindex Merkle leaf digest, and its stat size. */
struct entry {
    char *path;
    unsigned char hash[HSZ];
    unsigned char leaf[HSZ];
    uint64_t size;
};

static void die(const char *msg)
{
    fprintf(stderr, "core_seal: %s\n", msg);
    if (errno)
        fprintf(stderr, "core_seal: errno: %s\n", strerror(errno));
    exit(2);
}

static void hex_of(const unsigned char *in, size_t n, char *out /* 2n+1 */)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

/* Exactly 64 lowercase hex characters and nothing else. */
static int is_hex64(const char *s)
{
    for (size_t i = 0; i < 2 * HSZ; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return s[2 * HSZ] == '\0';
}

static void write_u32le(struct sha3_256_ctx *ctx, uint32_t v)
{
    unsigned char b[4];
    zcl_write_u32_le(b, v);
    sha3_256_write(ctx, b, sizeof(b));
}

static void write_u64le(struct sha3_256_ctx *ctx, uint64_t v)
{
    unsigned char b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(ctx, b, sizeof(b));
}

/* One pass over the file's bytes feeding TWO digests:
 *   `out`  the frozen flat per-file SHA3-256 (unchanged: raw content only —
 *          this is what the manifest's per-file lines and ROOT consume), and
 *   `leaf` the codeindex Merkle leaf (tag + domain + relpath + u64le size,
 *          then the same bytes).
 * Returns 0 on success. Fails closed if the byte count does not match the
 * stat size the leaf preimage already committed to. */
static int hash_file(const char *path, unsigned char out[HSZ],
                     unsigned char leaf[HSZ], uint64_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(f);
        return -1;
    }

    struct sha3_256_ctx flat, lf;
    sha3_256_init(&flat);
    sha3_256_init(&lf);
    unsigned char tag = MERKLE_TAG_LEAF;
    sha3_256_write(&lf, &tag, 1);
    sha3_256_write(&lf, (const unsigned char *)merkle_leaf_domain,
                   sizeof(merkle_leaf_domain));
    sha3_256_write(&lf, (const unsigned char *)path, strlen(path) + 1);
    write_u64le(&lf, (uint64_t)st.st_size);

    unsigned char buf[65536];
    size_t r;
    uint64_t total = 0;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha3_256_write(&flat, buf, r);
        sha3_256_write(&lf, buf, r);
        total += (uint64_t)r;
    }
    int ferr = ferror(f);
    fclose(f);
    if (ferr || total != (uint64_t)st.st_size)
        return -1;
    sha3_256_finalize(&flat, out);
    sha3_256_finalize(&lf, leaf);
    *out_size = total;
    return 0;
}

static int cmp_entry(const void *a, const void *b)
{
    const struct entry *ea = a, *eb = b;
    return strcmp(ea->path, eb->path);
}

/* Read NUL-separated (or newline-separated) paths from stdin. Excludes the
 * manifest path itself. Hashes each file, returns a path-sorted array. */
static struct entry *read_and_hash(const char *manifest_path, size_t *out_n)
{
    /* Slurp stdin. */
    size_t cap = 65536, len = 0;
    char *data = malloc(cap); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    if (!data)
        die("out of memory reading stdin");
    for (;;) {
        if (len == cap) {
            cap *= 2;
            char *nd = realloc(data, cap); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
            if (!nd)
                die("out of memory reading stdin");
            data = nd;
        }
        size_t r = fread(data + len, 1, cap - len, stdin);
        len += r;
        if (r == 0)
            break;
    }

    struct entry *ents = NULL;
    size_t n = 0, ecap = 0;

    size_t i = 0;
    while (i < len) {
        /* A path token runs up to the next NUL or newline. */
        size_t j = i;
        while (j < len && data[j] != '\0' && data[j] != '\n')
            j++;
        size_t plen = j - i;
        if (plen > 0) {
            char *path = malloc(plen + 1); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
            if (!path)
                die("out of memory");
            memcpy(path, data + i, plen);
            path[plen] = '\0';
            /* Skip the manifest itself — it can never seal its own bytes. */
            if (strcmp(path, manifest_path) != 0) {
                if (n == ecap) {
                    ecap = ecap ? ecap * 2 : 64;
                    struct entry *ne = realloc(ents, ecap * sizeof(*ents)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
                    if (!ne)
                        die("out of memory");
                    ents = ne;
                }
                ents[n].path = path;
                if (hash_file(path, ents[n].hash, ents[n].leaf,
                              &ents[n].size) != 0) {
                    fprintf(stderr, "core_seal: cannot read sealed file '%s'\n",
                            path);
                    exit(2);
                }
                n++;
            } else {
                free(path);
            }
        }
        i = j + 1;
    }
    free(data);

    qsort(ents, n, sizeof(*ents), cmp_entry);
    *out_n = n;
    return ents;
}

/* ROOT = SHA3-256 over, for each sorted entry: path bytes, one NUL, 32 raw
 * hash bytes. Path-sorted so the digest is order-independent of the input.
 *
 * FROZEN. This preimage is the sealed core's identity: it is mirrored into
 * hotswap/core_seal_root.h and pinned by every hot-swap module. Changing it —
 * including "harmlessly" adding a tag byte — invalidates every packaged module
 * and requires the owner unseal ritual. The Merkle tree below reuses the same
 * file bytes; it does not redefine this. */
static void compute_root(const struct entry *ents, size_t n,
                         unsigned char root[HSZ])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    for (size_t i = 0; i < n; i++) {
        sha3_256_write(&ctx, (const unsigned char *)ents[i].path,
                       strlen(ents[i].path));
        unsigned char nul = 0;
        sha3_256_write(&ctx, &nul, 1);
        sha3_256_write(&ctx, ents[i].hash, HSZ);
    }
    sha3_256_finalize(&ctx, root);
}

/* ── the codeindex directory Merkle, over the sealed set ─────────────────
 *
 * A SECTION is a DIRECTORY, keyed by repo-relative directory path, exactly as
 * codeindex defines it. No prefix table, no catch-all: every sealed file is a
 * leaf under the directory node its own path names. */

struct dnode {
    char path[MERKLE_PATH_MAX];
    unsigned char digest[HSZ];
    uint64_t file_count;       /* recursive: indexed files below */
    uint32_t direct_children;  /* immediate files + subdirectories */
};

/* One direct child of a directory node, as codeindex hashes it. */
struct mchild {
    char name[MERKLE_NAME_MAX];
    unsigned char kind; /* 0 = file leaf, 1 = directory */
    unsigned char digest[HSZ];
    uint64_t file_count; /* files below a directory child; 1 for a file */
};

/* THE ordering rule, transcribed from codeindex_merkle.c's merkle_child_key:
 * a file's own name, a directory's name followed by '/'. */
static void child_key(const struct mchild *c, char out[MERKLE_NAME_MAX + 2])
{
    (void)snprintf(out, MERKLE_NAME_MAX + 2, "%s%s", c->name,
                   c->kind == 1 ? "/" : "");
}

static int cmp_child(const void *a, const void *b)
{
    char ka[MERKLE_NAME_MAX + 2], kb[MERKLE_NAME_MAX + 2];
    child_key(a, ka);
    child_key(b, kb);
    return strcmp(ka, kb);
}

/* codeindex_merkle.c's merkle_node_digest, byte for byte. */
static void node_digest(const char *path, const struct mchild *kids, uint32_t n,
                        unsigned char out[HSZ])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char tag = MERKLE_TAG_NODE;
    sha3_256_write(&ctx, &tag, 1);
    sha3_256_write(&ctx, (const unsigned char *)merkle_node_domain,
                   sizeof(merkle_node_domain));
    sha3_256_write(&ctx, (const unsigned char *)path, strlen(path) + 1);
    write_u32le(&ctx, n);
    for (uint32_t i = 0; i < n; i++) {
        sha3_256_write(&ctx, &kids[i].kind, 1);
        sha3_256_write(&ctx, (const unsigned char *)kids[i].name,
                       strlen(kids[i].name) + 1);
        sha3_256_write(&ctx, kids[i].digest, HSZ);
    }
    sha3_256_finalize(&ctx, out);
}

/* Repo-relative parent directory of `path` ("" when there is no slash). */
static void parent_of(const char *path, char out[MERKLE_PATH_MAX])
{
    const char *slash = strrchr(path, '/');
    if (!slash) {
        out[0] = '\0';
        return;
    }
    size_t len = (size_t)(slash - path);
    if (len >= MERKLE_PATH_MAX)
        die("sealed path's directory exceeds MERKLE_PATH_MAX");
    memcpy(out, path, len);
    out[len] = '\0';
}

static const char *base_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Build the directory Merkle over the sealed entries.
 *
 * Returns the node count (including the root node ""), writes the nodes into
 * *out_nodes (caller frees) sorted by path — index 0 is the root — and the
 * whole-set root digest into `tree`. n == 0 yields 0 nodes.
 *
 * Fail closed: every entry must land in exactly one directory node, and the
 * root node's recursive file count must equal n. */
static size_t compute_sections(const struct entry *ents, size_t n,
                               struct dnode **out_nodes, unsigned char tree[HSZ])
{
    *out_nodes = NULL;
    if (n == 0)
        return 0;

    /* 1. Every directory that has at least one sealed file below it, plus the
     *    root "" — i.e. every proper ancestor of every entry path. */
    size_t dcap = 0, dn = 0;
    char **dirs = NULL;
    for (size_t i = 0; i < n; i++) {
        char cur[MERKLE_PATH_MAX];
        if (strlen(ents[i].path) >= MERKLE_PATH_MAX)
            die("sealed path exceeds MERKLE_PATH_MAX");
        if (strlen(base_of(ents[i].path)) >= MERKLE_NAME_MAX)
            die("sealed file name exceeds MERKLE_NAME_MAX");
        parent_of(ents[i].path, cur);
        for (;;) {
            if (dn == dcap) {
                dcap = dcap ? dcap * 2 : 64;
                char **nd = realloc(dirs, dcap * sizeof(*dirs)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
                if (!nd)
                    die("out of memory collecting directories");
                dirs = nd;
            }
            char *copy = malloc(strlen(cur) + 1); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
            if (!copy)
                die("out of memory collecting directories");
            memcpy(copy, cur, strlen(cur) + 1);
            dirs[dn++] = copy;
            if (cur[0] == '\0')
                break;
            char up[MERKLE_PATH_MAX];
            parent_of(cur, up);
            memcpy(cur, up, strlen(up) + 1);
        }
    }
    qsort(dirs, dn, sizeof(*dirs), cmp_str);
    /* dedupe in place */
    size_t uniq = 0;
    for (size_t i = 0; i < dn; i++) {
        if (i > 0 && strcmp(dirs[i], dirs[uniq - 1]) == 0) {
            free(dirs[i]);
            continue;
        }
        dirs[uniq++] = dirs[i];
    }
    dn = uniq;

    struct dnode *nodes = calloc(dn, sizeof(*nodes)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    if (!nodes)
        die("out of memory building directory nodes");
    for (size_t i = 0; i < dn; i++)
        snprintf(nodes[i].path, sizeof(nodes[i].path), "%s", dirs[i]);

    /* 2. Digest each node. `dirs` is strcmp-sorted, and a parent is always a
     *    strict prefix of its children, so a parent always sorts BEFORE its
     *    descendants. Walking in REVERSE therefore finalizes every child
     *    before its parent, with no recursion and no second pass. */
    size_t kidcap = n + dn;
    struct mchild *kids = malloc(kidcap * sizeof(*kids)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    if (!kids)
        die("out of memory building node children");

    size_t placed = 0;
    for (size_t x = dn; x-- > 0;) {
        struct dnode *d = &nodes[x];
        uint32_t nk = 0;
        uint64_t below = 0;
        char par[MERKLE_PATH_MAX];

        for (size_t i = 0; i < n; i++) {
            parent_of(ents[i].path, par);
            if (strcmp(par, d->path) != 0)
                continue;
            if (nk == kidcap)
                die("internal error: child overflow");
            snprintf(kids[nk].name, sizeof(kids[nk].name), "%s",
                     base_of(ents[i].path));
            kids[nk].kind = 0;
            memcpy(kids[nk].digest, ents[i].leaf, HSZ);
            kids[nk].file_count = 1;
            nk++;
            below++;
            placed++;
        }
        for (size_t j = 0; j < dn; j++) {
            if (j == x || nodes[j].path[0] == '\0')
                continue;
            parent_of(nodes[j].path, par);
            if (strcmp(par, d->path) != 0)
                continue;
            if (nk == kidcap)
                die("internal error: child overflow");
            snprintf(kids[nk].name, sizeof(kids[nk].name), "%s",
                     base_of(nodes[j].path));
            kids[nk].kind = 1;
            memcpy(kids[nk].digest, nodes[j].digest, HSZ);
            kids[nk].file_count = nodes[j].file_count;
            nk++;
            below += nodes[j].file_count;
        }

        qsort(kids, nk, sizeof(*kids), cmp_child);
        for (uint32_t k = 1; k < nk; k++)
            if (cmp_child(&kids[k - 1], &kids[k]) >= 0)
                die("internal error: canonical child order violated");

        node_digest(d->path, kids, nk, d->digest);
        d->direct_children = nk;
        d->file_count = below;
    }
    free(kids);
    for (size_t i = 0; i < dn; i++)
        free(dirs[i]);
    free(dirs);

    /* 3. Fail closed. Nothing may be dropped: the tree must cover exactly
     *    what ROOT covers. */
    if (placed != n)
        die("internal error: a sealed file was not placed under any directory");
    if (nodes[0].path[0] != '\0')
        die("internal error: node 0 is not the root directory");
    if (nodes[0].file_count != (uint64_t)n)
        die("internal error: root file count does not equal the sealed count");

    memcpy(tree, nodes[0].digest, HSZ);
    *out_nodes = nodes;
    return dn;
}

static int do_seal(const char *manifest_path)
{
    size_t n = 0;
    struct entry *ents = read_and_hash(manifest_path, &n);
    unsigned char root[HSZ];
    compute_root(ents, n, root);

    struct dnode *nodes = NULL;
    unsigned char tree[HSZ];
    memset(tree, 0, sizeof(tree));
    size_t dn = compute_sections(ents, n, &nodes, tree);

    FILE *m = fopen(manifest_path, "wb");
    if (!m)
        die("cannot open manifest for writing");
    fprintf(m,
            "# Consensus seal — SHA3-256 manifest. AUTO-GENERATED by "
            "`make core-seal`.\n"
            "# Do not edit by hand. `make core-seal-check` fails loud if any "
            "sealed file drifts from this.\n"
            "# Sealed set: core/ (consensus predicates + parameter tables) plus\n"
            "# the block-connection ordering layer named in the Makefile's\n"
            "# CORE_SEAL_PATHS (an ordering bug forks exactly as hard as a\n"
            "# predicate bug — see docs/adr/0002-sealed-consensus-core.md).\n"
            "# Format, in emitted order:\n"
            "#   <sha3-256 hex>  <path>              one per sealed file, "
            "path-sorted.\n"
            "#   SECTION  <dir>  <files>  <hex>      one per directory holding "
            "sealed\n"
            "#       files, path-sorted; <files> is RECURSIVE. <hex> is that\n"
            "#       directory's node digest in lib/codeindex's source Merkle "
            "dialect\n"
            "#       (codeindex_merkle.c): leaf = SHA3-256(0x10 || "
            "\"zcl.codeindex.merkle.leaf.v1\\0\"\n"
            "#       || relpath\\0 || u64le(size) || bytes); node = "
            "SHA3-256(0x11 ||\n"
            "#       \"zcl.codeindex.merkle.node.v1\\0\" || dirpath\\0 || "
            "u32le(nkids) || for each\n"
            "#       child kind||name\\0||digest), children ordered by strcmp "
            "over the\n"
            "#       child's name, plus '/' for a directory. N-ary, so there is "
            "no\n"
            "#       leaf-pairing and no duplicate-tail ambiguity; tag 0x10 vs "
            "0x11 plus\n"
            "#       the domain strings separate leaves from interior nodes.\n"
            "#   TREE  <hex>                         the root node (dirpath "
            "\"\") over the\n"
            "#       whole sealed set, same dialect.\n"
            "#   ROOT  <hex>                         FINAL LINE. The flat fold "
            "over every\n"
            "#       sorted `path \\0 filehash` pair — the sealed core's "
            "identity, mirrored\n"
            "#       into hotswap/core_seal_root.h. FROZEN: SECTION/TREE are "
            "additive.\n");
    char hex[HEXSZ];
    for (size_t i = 0; i < n; i++) {
        hex_of(ents[i].hash, HSZ, hex);
        fprintf(m, "%s  %s\n", hex, ents[i].path);
    }
    /* Skip node 0 (the root, dirpath "") — it is the TREE line. */
    for (size_t k = 1; k < dn; k++) {
        hex_of(nodes[k].digest, HSZ, hex);
        fprintf(m, "SECTION  %s  %llu  %s\n", nodes[k].path,
                (unsigned long long)nodes[k].file_count, hex);
    }
    if (dn > 0) {
        hex_of(tree, HSZ, hex);
        fprintf(m, "TREE  %s\n", hex);
    }
    hex_of(root, HSZ, hex);
    fprintf(m, "ROOT  %s\n", hex);
    if (fclose(m) != 0)
        die("write error closing manifest");

    for (size_t k = 1; k < dn; k++) {
        hex_of(nodes[k].digest, HSZ, hex);
        fprintf(stderr, "core_seal:   section %-44s %3llu file(s)  %s\n",
                nodes[k].path, (unsigned long long)nodes[k].file_count, hex);
    }
    if (dn > 0) {
        hex_of(tree, HSZ, hex);
        fprintf(stderr, "core_seal:   TREE (%zu directory node(s)) %s\n", dn,
                hex);
    }
    hex_of(root, HSZ, hex);
    fprintf(stderr, "core_seal: sealed %zu file(s), ROOT %s\n", n, hex);
    free(nodes);
    for (size_t i = 0; i < n; i++)
        free(ents[i].path);
    free(ents);
    return 0;
}

/* ── manifest parsing ──────────────────────────────────────────────────── */

#define MAX_MAN_SECTIONS 512

struct man_section {
    char name[MERKLE_PATH_MAX];
    uint64_t count;
    char hex[HEXSZ];
};

struct manifest_view {
    char root_hex[HEXSZ];
    int have_root;
    struct man_section *sec;
    size_t nsec;
    char tree_hex[HEXSZ];
    int have_tree;
};

/* Parse ROOT, SECTION and TREE lines out of an existing manifest.
 * Returns 0 on success, -1 if the manifest cannot be opened, -2 if a
 * SECTION/TREE line is present but malformed. A manifest we cannot parse must
 * never be reported as "matching", so -2 is a hard error, not drift. */
static int read_manifest(const char *manifest_path, struct manifest_view *mv)
{
    memset(mv, 0, sizeof(*mv));
    mv->sec = calloc(MAX_MAN_SECTIONS, sizeof(*mv->sec)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    if (!mv->sec)
        die("out of memory reading manifest");
    FILE *m = fopen(manifest_path, "rb");
    if (!m)
        return -1;
    char line[4096];
    int rc = 0;
    while (fgets(line, sizeof(line), m)) {
        if (line[0] == '#')
            continue;
        if (strncmp(line, "ROOT ", 5) == 0) {
            const char *p = line + 5;
            while (*p == ' ' || *p == '\t')
                p++;
            char buf[HEXSZ];
            size_t k = 0;
            while (k < 2 * HSZ && p[k] && p[k] != '\n' && p[k] != '\r') {
                buf[k] = p[k];
                k++;
            }
            buf[k] = '\0';
            if (k == 2 * HSZ && is_hex64(buf)) {
                memcpy(mv->root_hex, buf, sizeof(buf));
                mv->have_root = 1;
            }
        } else if (strncmp(line, "SECTION ", 8) == 0) {
            char name[MERKLE_PATH_MAX], hex[HEXSZ];
            unsigned long long count = 0;
            if (sscanf(line, "SECTION %255s %llu %64s", name, &count, hex) != 3 ||
                !is_hex64(hex)) {
                fprintf(stderr,
                        "core_seal: FATAL — malformed SECTION line in '%s': %s",
                        manifest_path, line);
                rc = -2;
                continue;
            }
            if (mv->nsec == MAX_MAN_SECTIONS) {
                fprintf(stderr,
                        "core_seal: FATAL — more than %d SECTION lines in "
                        "'%s'\n",
                        MAX_MAN_SECTIONS, manifest_path);
                rc = -2;
                continue;
            }
            for (size_t k = 0; k < mv->nsec; k++)
                if (strcmp(mv->sec[k].name, name) == 0) {
                    fprintf(stderr,
                            "core_seal: FATAL — duplicate SECTION '%s' in "
                            "'%s'\n",
                            name, manifest_path);
                    rc = -2;
                }
            snprintf(mv->sec[mv->nsec].name, sizeof(mv->sec[mv->nsec].name),
                     "%s", name);
            mv->sec[mv->nsec].count = count;
            memcpy(mv->sec[mv->nsec].hex, hex, sizeof(hex));
            mv->nsec++;
        } else if (strncmp(line, "TREE ", 5) == 0) {
            char hex[HEXSZ];
            if (sscanf(line, "TREE %64s", hex) != 1 || !is_hex64(hex)) {
                fprintf(stderr,
                        "core_seal: FATAL — malformed TREE line in '%s': %s",
                        manifest_path, line);
                rc = -2;
                continue;
            }
            memcpy(mv->tree_hex, hex, sizeof(hex));
            mv->have_tree = 1;
        }
    }
    fclose(m);
    return rc;
}

/* Compare the manifest's SECTION/TREE lines against freshly derived ones.
 * 0 = match (or nothing to check), 1 = drift, 2 = malformed manifest.
 * Every drift message NAMES the directory, which is the point of the
 * structure: "core/consensus/src drifted" localises the edit; the DEEPEST
 * drifted directory is reported separately because every ancestor of a changed
 * file necessarily drifts with it. */
static int verify_sections(const char *manifest_path,
                           const struct manifest_view *mv,
                           const struct dnode *nodes, size_t dn,
                           const unsigned char tree[HSZ])
{
    if (mv->nsec == 0 && !mv->have_tree) {
        fprintf(stderr,
                "core_seal: section verification SKIPPED — '%s' carries no "
                "SECTION/TREE lines (pre-sectioned manifest; ROOT alone was "
                "verified). Run `make core-seal` to add the section tree.\n",
                manifest_path);
        return 0;
    }
    if (mv->nsec == 0 || !mv->have_tree) {
        fprintf(stderr,
                "core_seal: FATAL — '%s' has %zu SECTION line(s) and %s TREE "
                "line; a sectioned manifest needs both.\n",
                manifest_path, mv->nsec, mv->have_tree ? "a" : "no");
        return 2;
    }

    int rc = 0;
    char hex[HEXSZ];
    const char *deepest = NULL;
    size_t deepest_len = 0;

    for (size_t k = 1; k < dn; k++) { /* node 0 is the root; that is TREE */
        const struct man_section *found = NULL;
        for (size_t j = 0; j < mv->nsec; j++)
            if (strcmp(mv->sec[j].name, nodes[k].path) == 0)
                found = &mv->sec[j];
        if (!found) {
            fprintf(stderr,
                    "core_seal: DRIFT — section '%s' exists in the tree (%llu "
                    "file(s)) but has no SECTION line in the manifest.\n",
                    nodes[k].path, (unsigned long long)nodes[k].file_count);
            rc = 1;
            continue;
        }
        hex_of(nodes[k].digest, HSZ, hex);
        int bad = 0;
        if (found->count != nodes[k].file_count) {
            fprintf(stderr,
                    "core_seal: DRIFT — section '%s': file count changed "
                    "(manifest %llu, computed %llu).\n",
                    nodes[k].path, (unsigned long long)found->count,
                    (unsigned long long)nodes[k].file_count);
            bad = 1;
        }
        if (strcmp(found->hex, hex) != 0) {
            fprintf(stderr,
                    "core_seal: DRIFT — section '%s' drifted.\n"
                    "  manifest section root: %s\n"
                    "  computed section root: %s\n",
                    nodes[k].path, found->hex, hex);
            bad = 1;
        }
        if (bad) {
            rc = 1;
            size_t l = strlen(nodes[k].path);
            if (l > deepest_len) {
                deepest_len = l;
                deepest = nodes[k].path;
            }
        }
    }

    for (size_t j = 0; j < mv->nsec; j++) {
        int still_there = 0;
        for (size_t k = 1; k < dn; k++)
            if (strcmp(mv->sec[j].name, nodes[k].path) == 0)
                still_there = 1;
        if (!still_there) {
            fprintf(stderr,
                    "core_seal: DRIFT — section '%s' is in the manifest but no "
                    "longer holds any sealed file.\n",
                    mv->sec[j].name);
            rc = 1;
        }
    }

    hex_of(tree, HSZ, hex);
    if (strcmp(mv->tree_hex, hex) != 0) {
        fprintf(stderr,
                "core_seal: DRIFT — TREE root does not match.\n"
                "  manifest TREE: %s\n"
                "  computed TREE: %s\n",
                mv->tree_hex, hex);
        if (rc == 0)
            fprintf(stderr,
                    "  Every SECTION line matched, so the TREE line itself was "
                    "edited or a SECTION line was removed.\n");
        rc = 1;
    } else if (rc == 0) {
        fprintf(stderr,
                "core_seal: OK — %zu section(s) match TREE %s\n", dn - 1, hex);
    }
    if (deepest)
        fprintf(stderr,
                "core_seal: deepest drifted section: '%s' — the change is at or "
                "below it (every ancestor drifts with it).\n",
                deepest);
    return rc;
}

static int do_check(const char *manifest_path)
{
    struct manifest_view mv;
    int pr = read_manifest(manifest_path, &mv);
    if (pr == -1 || !mv.have_root) {
        fprintf(stderr,
                "core_seal: FATAL — no valid ROOT line in manifest '%s'.\n"
                "  Run `make core-seal` to (re)generate it.\n",
                manifest_path);
        free(mv.sec);
        return 2;
    }
    if (pr == -2) {
        fprintf(stderr,
                "core_seal: FATAL — manifest '%s' has malformed section "
                "lines; refusing to report a verdict.\n",
                manifest_path);
        free(mv.sec);
        return 2;
    }

    size_t n = 0;
    struct entry *ents = read_and_hash(manifest_path, &n);
    unsigned char root[HSZ];
    compute_root(ents, n, root);
    char now[HEXSZ];
    hex_of(root, HSZ, now);

    int rc = 0;
    if (strcmp(mv.root_hex, now) != 0) {
        fprintf(stderr,
                "core_seal: DRIFT — core/ does not match its seal.\n"
                "  manifest ROOT: %s\n"
                "  computed ROOT: %s\n",
                mv.root_hex, now);
        rc = 1;
    } else {
        fprintf(stderr, "core_seal: OK — %zu sealed file(s) match ROOT %s\n", n,
                now);
    }

    struct dnode *nodes = NULL;
    unsigned char tree[HSZ];
    memset(tree, 0, sizeof(tree));
    size_t dn = compute_sections(ents, n, &nodes, tree);
    int src = verify_sections(manifest_path, &mv, nodes, dn, tree);
    if (src == 2)
        rc = 2;
    else if (src == 1 && rc != 2)
        rc = 1;

    free(nodes);
    free(mv.sec);
    for (size_t i = 0; i < n; i++)
        free(ents[i].path);
    free(ents);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s <seal|check> <manifest-path>   (paths on stdin, "
                "NUL-separated)\n",
                argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *manifest = argv[2];
    if (strcmp(mode, "seal") == 0)
        return do_seal(manifest);
    if (strcmp(mode, "check") == 0)
        return do_check(manifest);
    fprintf(stderr, "core_seal: unknown mode '%s' (want seal|check)\n", mode);
    return 2;
}
