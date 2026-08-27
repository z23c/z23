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
 * manifest lines (SECTION per directory, TREE for the whole set). A section is
 * provable and replaceable on its own: changing one directory moves that
 * directory's node digest and its ancestors', and leaves every sibling
 * section's digest untouched.
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
 *       statement of the rule.)
 *
 *       WHY THE '/' SUFFIX. It is the PREFIX PROPERTY, not any claim about
 *       where '/' sits in ASCII: appending '/' makes a directory child's key
 *       exactly the prefix that every repo-relative path beneath it shares, so
 *       comparing two children's keys compares the same bytes that comparing
 *       their full paths would, and a directory's entries therefore occupy one
 *       CONTIGUOUS block of the path-sorted stream. (Any reasoning of the form
 *       "'/' sorts above every character legal in a name" is simply false —
 *       '/' is 0x2f and sorts BELOW every digit and letter — and it is not
 *       what makes the rule work. codeindex_merkle.c's merkle_child_key
 *       comment still carries that wrong reason; it is a comment defect there,
 *       not a behaviour difference, and the two implementations agree.)
 *
 *       core_seal sorts children by the key explicitly rather than relying on
 *       its input stream's order, and re-asserts strict ascending order after
 *       the sort.
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
 * ── UNAMBIGUOUS INPUT AND UNAMBIGUOUS SERIALISATION ────────────────────────
 *
 * A seal is only worth what its ENCODING is worth. Two rules, both enforced
 * here, both regression-tested by lib/test/src/test_core_seal.c:
 *
 *   1. ONE TOKENISATION OF THE INPUT STREAM. stdin is NUL-separated and
 *      nothing else. An earlier revision split a token at a NUL *or* a
 *      newline, which threw away the exact guarantee `git ls-files -z` exists
 *      to provide: the single path "core/a\nb.h" arrived as one NUL-terminated
 *      token and was silently split into the two paths "core/a" and "b.h".
 *      A newline inside a path is now a hard exit(2), never a re-tokenisation.
 *
 *   2. ONE PARSE OF EVERY MANIFEST LINE. The manifest is line-oriented text,
 *      and a sealed path may legally contain SPACES. An earlier revision wrote
 *      `SECTION  <dir>  <count>  <hex>` and read it back with
 *      `sscanf("SECTION %255s %llu %64s")`, i.e. whitespace-delimited fields
 *      whose FIRST field was the attacker-influenced one. That admits two
 *      structurally different section records with one parse: a directory
 *      literally named `x  7  <64 hex>` under core/ serialises to
 *      `SECTION  core/x  7  <hex>  <its count>  <its hex>`, which sscanf reads
 *      as name "core/x", count 7, digest <hex> — byte-for-byte the record a
 *      genuine `core/x` with 7 files would produce.
 *
 *      Fixed by putting the variable-length field LAST and LENGTH-PREFIXING
 *      it, so no delimiter is load-bearing:
 *
 *          SECTION  <files>  <pathlen>  <hex>  <path>
 *
 *      <files> and <pathlen> are canonical decimal (no leading zeros, so one
 *      value has one spelling), <hex> is exactly 64 lowercase hex, the field
 *      separator is exactly two spaces, and <path> is exactly <pathlen> bytes
 *      followed immediately by end of line. The reader takes the length from
 *      the line and CROSS-CHECKS it against the remaining bytes, so a
 *      truncated or extended line is rejected rather than silently reinterpreted.
 *
 *      Per-file lines keep their frozen `<64 hex><2 spaces><path>` shape; that
 *      one is unambiguous by the same argument — fixed-width digest first,
 *      variable-length path last, terminated by a newline a path may not
 *      contain.
 *
 * SEALABLE PATH — every path on stdin must be repo-relative, non-empty,
 * shorter than MERKLE_PATH_MAX, free of control bytes (which is what makes a
 * path representable on one manifest line at all), free of "." / ".." / empty
 * components and of a trailing '/', with every component shorter than
 * MERKLE_NAME_MAX. That last bound is what stops a long DIRECTORY name being
 * silently truncated into a node preimage: an earlier revision bounded only
 * the FILE basename, so a >=160-byte directory component was snprintf'd down
 * to 159 bytes and the parent node then committed to a name that was not the
 * child's. Duplicate paths in one stream are rejected too. Every violation is
 * a named exit(2); nothing is silently normalised.
 *
 * NO SILENT DOWNGRADE — `check` requires the manifest to carry both SECTION
 * and TREE lines. Deleting them is not a compatibility mode, it is a
 * downgrade: it would turn a structural gate green while proving strictly less.
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
 * STABILITY OF THE SEALED SET — every input to every digest here is content
 * derived: the repo-relative path, the file's byte length, and the file's
 * bytes. No mtime, no inode, no absolute path, no build id, no clock. The
 * sealed set itself (CORE_SEAL_PATHS, Makefile) is 70 tracked regular files;
 * none is generated by any make rule, none is gitignored, none is a symlink.
 * The one sealed file any tooling writes is core/UNSEAL.md, and only the
 * owner-run `make core-unseal` ritual writes it — immediately before the
 * `make core-seal` that re-freezes it.
 *
 * See CLAUDE.md "Tenacity & recovery" and the plan
 * ~/.claude/plans/we-are-working-to-concurrent-melody.md (Pillar 1, Wave 1.1).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

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

/* The manifest's field separator, in one place: writer and reader share it so
 * they cannot drift into two spellings of the same line. */
#define SEP "  "

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

/* The first 2*HSZ bytes of `s` are lowercase hex. Does not look past them. */
static int is_hex64_prefix(const char *s)
{
    for (size_t i = 0; i < 2 * HSZ; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* Exactly 64 lowercase hex characters and nothing else. */
static int is_hex64(const char *s)
{
    return is_hex64_prefix(s) && s[2 * HSZ] == '\0';
}

/* ── sealable-path policy ──────────────────────────────────────────────────
 *
 * Returns NULL when `p` may be sealed, else a short human reason. This is the
 * ONE place the policy lives; the tokeniser, the writer and the reader all
 * call it, so a path that cannot be written can never be read back either. */
static const char *path_reject_reason(const char *p)
{
    if (!p || p[0] == '\0')
        return "empty path";
    size_t len = strlen(p);
    if (len >= MERKLE_PATH_MAX)
        return "path is >= MERKLE_PATH_MAX bytes";
    if (p[0] == '/')
        return "absolute path (the seal is repo-relative)";
    if (p[len - 1] == '/')
        return "trailing '/' (a sealed path names a file, not a directory)";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        /* Control bytes are what make a path unrepresentable on one manifest
         * line; a newline in particular is the historical re-tokenisation bug. */
        if (c < 0x20u || c == 0x7fu)
            return "path contains a control byte (newline, tab, CR, ...)";
    }
    /* Component walk: no empty ("//"), no "." or "..", none over-long. */
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i != len && p[i] != '/')
            continue;
        size_t clen = i - start;
        if (clen == 0)
            return "empty path component (\"//\")";
        if (clen >= MERKLE_NAME_MAX)
            return "path component is >= MERKLE_NAME_MAX bytes";
        if (clen == 1 && p[start] == '.')
            return "\".\" path component";
        if (clen == 2 && p[start] == '.' && p[start + 1] == '.')
            return "\"..\" path component";
        start = i + 1;
    }
    return NULL;
}

static void die_path(const char *path, const char *why)
{
    errno = 0;
    fprintf(stderr, "core_seal: FATAL — refusing to seal path '%s': %s.\n",
            path, why);
    fprintf(stderr,
            "  The manifest is line-oriented text and its ROOT is frozen; a "
            "path it cannot encode\n"
            "  exactly once must not be sealed at all. Rename the path or "
            "remove it from CORE_SEAL_PATHS.\n");
    exit(2);
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

/* Read NUL-separated paths from stdin — NUL and nothing else, because that is
 * the one separator `git ls-files -z` guarantees cannot occur inside a path.
 * Excludes the manifest path itself. Hashes each file, returns a path-sorted
 * array with duplicates rejected. */
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
        /* A path token runs up to the next NUL. A newline is NOT a separator:
         * it is a byte a path may contain, and re-tokenising on it is the
         * dual-parse this tool refuses to have. */
        size_t j = i;
        while (j < len && data[j] != '\0')
            j++;
        size_t plen = j - i;
        if (plen > 0) {
            char *path = malloc(plen + 1); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
            if (!path)
                die("out of memory");
            memcpy(path, data + i, plen);
            path[plen] = '\0';
            const char *why = path_reject_reason(path);
            if (why)
                die_path(path, why);
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
    for (size_t k = 1; k < n; k++)
        if (strcmp(ents[k - 1].path, ents[k].path) == 0) {
            errno = 0;
            fprintf(stderr,
                    "core_seal: FATAL — path '%s' appears twice in the input "
                    "stream.\n"
                    "  ROOT would fold it twice and the section tree would see "
                    "two children of one\n"
                    "  name; neither is a defensible seal. Fix the file list.\n",
                    ents[k].path);
            exit(2);
        }
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
 * file bytes; it does not redefine this.
 *
 * It is unambiguous for the same reason the per-file manifest lines are: the
 * only delimiter is NUL, which a path may not contain, and the digest that
 * follows it is fixed width. */
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
 * a file's own name, a directory's name followed by '/'. See the prefix-property
 * paragraph in this file's header for why the '/' is there. */
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

/* Copy one basename into a child record. Length is a hard error, never a
 * truncation: a node preimage must commit to the child's REAL name. */
static void child_set_name(struct mchild *c, const char *name)
{
    size_t len = strlen(name);
    if (len == 0 || len >= MERKLE_NAME_MAX) {
        errno = 0;
        fprintf(stderr,
                "core_seal: FATAL — path component '%s' is %zu bytes; the "
                "codeindex node preimage\n"
                "  carries at most %d, and truncating it would bind a name "
                "that is not the child's.\n",
                name, len, MERKLE_NAME_MAX - 1);
        exit(2);
    }
    memcpy(c->name, name, len + 1);
}

/* codeindex_merkle.c's merkle_node_digest, byte for byte. Every variable-length
 * field is NUL-terminated over an alphabet that excludes NUL, the child count
 * is length-prefixed as u32le, and every digest is fixed width — so the
 * preimage has exactly one parse. */
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
     *    root "" — i.e. every proper ancestor of every entry path. Path shape
     *    (length, components, control bytes) was already settled by
     *    path_reject_reason() in read_and_hash; re-assert the two bounds the
     *    node records depend on so a future caller cannot skip the policy. */
    size_t dcap = 0, dn = 0;
    char **dirs = NULL;
    for (size_t i = 0; i < n; i++) {
        char cur[MERKLE_PATH_MAX];
        const char *why = path_reject_reason(ents[i].path);
        if (why)
            die_path(ents[i].path, why);
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
    for (size_t i = 0; i < dn; i++) {
        size_t l = strlen(dirs[i]);
        if (l >= MERKLE_PATH_MAX)
            die("internal error: directory path exceeds MERKLE_PATH_MAX");
        memcpy(nodes[i].path, dirs[i], l + 1);
    }

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
            child_set_name(&kids[nk], base_of(ents[i].path));
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
            child_set_name(&kids[nk], base_of(nodes[j].path));
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

/* ── manifest line codec ───────────────────────────────────────────────────
 *
 * Writer and reader are adjacent on purpose: they are one encoding, and
 * lib/test/src/test_core_seal.c round-trips them against the historical
 * whitespace-delimited spelling to prove the dual-parse is gone. */

/* Consume `lit` from the front of `p`; NULL if it is not there. */
static const char *skip_exact(const char *p, const char *lit)
{
    size_t k = strlen(lit);
    return strncmp(p, lit, k) == 0 ? p + k : NULL;
}

/* Canonical decimal: at least one digit, no leading zero unless the value is
 * exactly "0", no overflow. One value therefore has exactly one spelling. */
static const char *parse_u64_field(const char *p, uint64_t *out)
{
    if (*p < '0' || *p > '9')
        return NULL;
    if (p[0] == '0' && p[1] >= '0' && p[1] <= '9')
        return NULL;
    uint64_t v = 0;
    size_t digits = 0;
    while (*p >= '0' && *p <= '9') {
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - d) / 10)
            return NULL;
        v = v * 10 + d;
        p++;
        if (++digits > 20)
            return NULL;
    }
    *out = v;
    return p;
}

/* Bytes remaining on this physical line, i.e. up to CR, LF or NUL. */
static size_t line_rest_len(const char *p)
{
    return strcspn(p, "\r\n");
}

/* SECTION  <files>  <pathlen>  <hex>  <path>\n
 *
 * The one variable-length field is LAST and LENGTH-PREFIXED, so no delimiter
 * carries meaning and a path containing spaces round-trips exactly. Returns
 * the byte length written, or 0 if the record cannot be represented (which is
 * a caller error — the path policy already rejected such paths on input). */
static size_t section_line_format(char *out, size_t outsz, const char *path,
                                  uint64_t files, const char *hex)
{
    if (path_reject_reason(path) != NULL || !is_hex64(hex))
        return 0;
    int k = snprintf(out, outsz, "SECTION" SEP "%llu" SEP "%zu" SEP "%s" SEP "%s\n",
                     (unsigned long long)files, strlen(path), hex, path);
    if (k <= 0 || (size_t)k >= outsz)
        return 0;
    return (size_t)k;
}

/* Inverse of section_line_format. Returns 0 on success, -1 if `line` is not a
 * SECTION line at all, -2 if it is one but malformed. A malformed line is
 * never "not a section": silently ignoring it would let a manifest drop a
 * section and still be reported as matching. */
static int section_line_parse(const char *line, char path[MERKLE_PATH_MAX],
                              uint64_t *files, char hex[HEXSZ])
{
    const char *p = skip_exact(line, "SECTION");
    if (!p)
        return -1;
    p = skip_exact(p, SEP);
    if (!p)
        return -2;

    uint64_t nfiles = 0, plen = 0;
    p = parse_u64_field(p, &nfiles);
    if (!p)
        return -2;
    p = skip_exact(p, SEP);
    if (!p)
        return -2;
    p = parse_u64_field(p, &plen);
    if (!p)
        return -2;
    p = skip_exact(p, SEP);
    if (!p)
        return -2;
    if (line_rest_len(p) < 2 * HSZ || !is_hex64_prefix(p))
        return -2;
    char buf[HEXSZ];
    memcpy(buf, p, 2 * HSZ);
    buf[2 * HSZ] = '\0';
    p += 2 * HSZ;
    p = skip_exact(p, SEP);
    if (!p)
        return -2;

    /* The declared length must equal the bytes actually left on the line: a
     * truncated or extended line is rejected, never reinterpreted. */
    if (plen == 0 || plen >= MERKLE_PATH_MAX)
        return -2;
    if (line_rest_len(p) != (size_t)plen)
        return -2;
    memcpy(path, p, (size_t)plen);
    path[plen] = '\0';
    if (path_reject_reason(path) != NULL)
        return -2;

    memcpy(hex, buf, sizeof(buf));
    *files = nfiles;
    return 0;
}

/* `<keyword>  <64 hex>` and nothing else — used for TREE and ROOT. Returns 0
 * on success, -1 if the keyword does not match, -2 if it does but the rest is
 * malformed. */
static int hex_line_parse(const char *line, const char *keyword, char hex[HEXSZ])
{
    const char *p = skip_exact(line, keyword);
    if (!p)
        return -1;
    p = skip_exact(p, SEP);
    if (!p)
        return -2;
    if (line_rest_len(p) != 2 * HSZ || !is_hex64_prefix(p))
        return -2;
    memcpy(hex, p, 2 * HSZ);
    hex[2 * HSZ] = '\0';
    return 0;
}

/* `<64 hex>  <path>` — the frozen per-file line. Fixed-width digest first,
 * variable-length path last, terminated by a newline a sealable path may not
 * contain: one parse, no length prefix needed. */
static int file_line_parse(const char *line, char hex[HEXSZ],
                           char path[MERKLE_PATH_MAX])
{
    if (line_rest_len(line) < 2 * HSZ || !is_hex64_prefix(line))
        return -1;
    memcpy(hex, line, 2 * HSZ);
    hex[2 * HSZ] = '\0';
    const char *p = skip_exact(line + 2 * HSZ, SEP);
    if (!p)
        return -2;
    size_t plen = line_rest_len(p);
    if (plen == 0 || plen >= MERKLE_PATH_MAX)
        return -2;
    memcpy(path, p, plen);
    path[plen] = '\0';
    if (path_reject_reason(path) != NULL)
        return -2;
    return 0;
}

/* ── manifest parsing ──────────────────────────────────────────────────── */

#define MAX_MAN_SECTIONS 512
#define MAX_MAN_FILES 4096

struct man_section {
    char name[MERKLE_PATH_MAX];
    uint64_t count;
    char hex[HEXSZ];
};

struct man_file {
    char path[MERKLE_PATH_MAX];
    char hex[HEXSZ];
};

struct manifest_view {
    char root_hex[HEXSZ];
    int have_root;
    struct man_section *sec;
    size_t nsec;
    struct man_file *file;
    size_t nfile;
    char tree_hex[HEXSZ];
    int have_tree;
};

static void manifest_view_free(struct manifest_view *mv)
{
    free(mv->sec);
    free(mv->file);
    mv->sec = NULL;
    mv->file = NULL;
}

/* Parse the per-file, SECTION, TREE and ROOT lines out of an existing manifest.
 * Returns 0 on success, -1 if the manifest cannot be opened, -2 if any line is
 * present but malformed. A manifest we cannot parse must never be reported as
 * "matching", so -2 is a hard error, not drift. */
static int read_manifest(const char *manifest_path, struct manifest_view *mv)
{
    memset(mv, 0, sizeof(*mv));
    mv->sec = calloc(MAX_MAN_SECTIONS, sizeof(*mv->sec)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    mv->file = calloc(MAX_MAN_FILES, sizeof(*mv->file)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    if (!mv->sec || !mv->file)
        die("out of memory reading manifest");
    FILE *m = fopen(manifest_path, "rb");
    if (!m)
        return -1;
    char line[4096];
    int rc = 0;
    unsigned long lineno = 0;
    while (fgets(line, sizeof(line), m)) {
        lineno++;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;

        char hex[HEXSZ], name[MERKLE_PATH_MAX];
        uint64_t count = 0;
        int pr;

        pr = hex_line_parse(line, "ROOT", hex);
        if (pr == 0) {
            memcpy(mv->root_hex, hex, sizeof(hex));
            mv->have_root = 1;
            continue;
        }
        if (pr == -2) {
            fprintf(stderr,
                    "core_seal: FATAL — malformed ROOT line in '%s' line %lu: %s",
                    manifest_path, lineno, line);
            rc = -2;
            continue;
        }

        pr = hex_line_parse(line, "TREE", hex);
        if (pr == 0) {
            if (mv->have_tree) {
                fprintf(stderr,
                        "core_seal: FATAL — more than one TREE line in '%s'\n",
                        manifest_path);
                rc = -2;
            }
            memcpy(mv->tree_hex, hex, sizeof(hex));
            mv->have_tree = 1;
            continue;
        }
        if (pr == -2) {
            fprintf(stderr,
                    "core_seal: FATAL — malformed TREE line in '%s' line %lu: %s",
                    manifest_path, lineno, line);
            rc = -2;
            continue;
        }

        pr = section_line_parse(line, name, &count, hex);
        if (pr == -2) {
            fprintf(stderr,
                    "core_seal: FATAL — malformed SECTION line in '%s' line "
                    "%lu: %s",
                    manifest_path, lineno, line);
            rc = -2;
            continue;
        }
        if (pr == 0) {
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
            memcpy(mv->sec[mv->nsec].name, name, strlen(name) + 1);
            mv->sec[mv->nsec].count = count;
            memcpy(mv->sec[mv->nsec].hex, hex, sizeof(hex));
            mv->nsec++;
            continue;
        }

        pr = file_line_parse(line, hex, name);
        if (pr == 0) {
            if (mv->nfile == MAX_MAN_FILES) {
                fprintf(stderr,
                        "core_seal: FATAL — more than %d file lines in '%s'\n",
                        MAX_MAN_FILES, manifest_path);
                rc = -2;
                continue;
            }
            memcpy(mv->file[mv->nfile].path, name, strlen(name) + 1);
            memcpy(mv->file[mv->nfile].hex, hex, sizeof(hex));
            mv->nfile++;
            continue;
        }

        fprintf(stderr,
                "core_seal: FATAL — unrecognised line in '%s' line %lu: %s",
                manifest_path, lineno, line);
        rc = -2;
    }
    fclose(m);
    return rc;
}

/* ── verification ─────────────────────────────────────────────────────────*/

/* The manifest's per-file lines are not decoration: without this they could
 * name any digest at all while ROOT still matched, because ROOT is recomputed
 * from disk and never read back out of those lines. Both sides are path-sorted,
 * so this is a straight positional comparison. */
static int verify_files(const char *manifest_path, const struct manifest_view *mv,
                        const struct entry *ents, size_t n)
{
    int rc = 0;
    char hex[HEXSZ];
    if (mv->nfile != n) {
        fprintf(stderr,
                "core_seal: DRIFT — '%s' lists %zu sealed file line(s); the "
                "input stream has %zu.\n",
                manifest_path, mv->nfile, n);
        rc = 1;
    }
    size_t lim = mv->nfile < n ? mv->nfile : n;
    for (size_t i = 0; i < lim; i++) {
        if (strcmp(mv->file[i].path, ents[i].path) != 0) {
            fprintf(stderr,
                    "core_seal: DRIFT — sealed file %zu: manifest says '%s', "
                    "the input stream says '%s'.\n",
                    i, mv->file[i].path, ents[i].path);
            rc = 1;
            continue;
        }
        hex_of(ents[i].hash, HSZ, hex);
        if (strcmp(mv->file[i].hex, hex) != 0) {
            fprintf(stderr,
                    "core_seal: DRIFT — sealed file '%s' digest changed.\n"
                    "  manifest: %s\n"
                    "  on disk:  %s\n",
                    ents[i].path, mv->file[i].hex, hex);
            rc = 1;
        }
    }
    return rc;
}

/* Compare the manifest's SECTION/TREE lines against freshly derived ones.
 * 0 = match, 1 = drift, 2 = malformed/downgraded manifest.
 * Every drift message NAMES the directory, which is the point of the
 * structure: "core/consensus/src drifted" localises the edit; the DEEPEST
 * drifted directory is reported separately because every ancestor of a changed
 * file necessarily drifts with it. */
static int verify_sections(const char *manifest_path,
                           const struct manifest_view *mv,
                           const struct dnode *nodes, size_t dn,
                           const unsigned char tree[HSZ])
{
    if (mv->nsec == 0 || !mv->have_tree) {
        fprintf(stderr,
                "core_seal: FATAL — '%s' has %zu SECTION line(s) and %s TREE "
                "line.\n"
                "  A sectioned manifest needs both. Dropping them is not a "
                "compatibility mode: it\n"
                "  would turn this gate green while proving strictly less than "
                "the tree it replaced.\n"
                "  Run `make core-seal` to re-derive them (ROOT is frozen and "
                "will not move).\n",
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

/* ── seal / check ─────────────────────────────────────────────────────────*/

static const char *const manifest_header =
    "# Consensus seal — SHA3-256 manifest. AUTO-GENERATED by `make core-seal`.\n"
    "# Do not edit by hand. `make core-seal-check` fails loud if any sealed "
    "file drifts from this.\n"
    "# Sealed set: core/ (consensus predicates + parameter tables) plus\n"
    "# the block-connection ordering layer named in the Makefile's\n"
    "# CORE_SEAL_PATHS (an ordering bug forks exactly as hard as a\n"
    "# predicate bug — see docs/adr/0002-sealed-consensus-core.md).\n"
    "#\n"
    "# Format, in emitted order. Every line has exactly ONE parse: each\n"
    "# variable-length field is either last on its line or length-prefixed,\n"
    "# and a sealable path may not contain a control byte.\n"
    "#\n"
    "#   <sha3-256 hex>  <path>\n"
    "#       One per sealed file, path-sorted. 64 lowercase hex, two spaces,\n"
    "#       then the path as the rest of the line.\n"
    "#\n"
    "#   SECTION  <files>  <pathlen>  <hex>  <path>\n"
    "#       One per directory holding sealed files, path-sorted. <files> is\n"
    "#       RECURSIVE; <pathlen> is the exact byte length of <path>, which is\n"
    "#       the rest of the line (so a path containing spaces round-trips).\n"
    "#       <hex> is that directory's node digest in lib/codeindex's source\n"
    "#       Merkle dialect (codeindex_merkle.c):\n"
    "#         leaf = SHA3-256(0x10 || \"zcl.codeindex.merkle.leaf.v1\\0\"\n"
    "#                         || relpath\\0 || u64le(size) || bytes)\n"
    "#         node = SHA3-256(0x11 || \"zcl.codeindex.merkle.node.v1\\0\"\n"
    "#                         || dirpath\\0 || u32le(nkids)\n"
    "#                         || for each child: kind || name\\0 || digest)\n"
    "#       Children are ordered by strcmp over the child's name, plus '/'\n"
    "#       for a directory. N-ary, so there is no leaf-pairing and no\n"
    "#       duplicate-tail ambiguity; tag 0x10 vs 0x11 plus the domain\n"
    "#       strings separate leaves from interior nodes.\n"
    "#\n"
    "#   TREE  <hex>\n"
    "#       The root node (dirpath \"\") over the whole sealed set, same dialect.\n"
    "#\n"
    "#   ROOT  <hex>\n"
    "#       FINAL LINE. The flat fold over every sorted `path \\0 filehash`\n"
    "#       pair — the sealed core's identity, mirrored into\n"
    "#       hotswap/core_seal_root.h. FROZEN: SECTION/TREE are additive and\n"
    "#       do not enter this preimage.\n";

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
    fputs(manifest_header, m);

    char hex[HEXSZ];
    char line[4096];
    for (size_t i = 0; i < n; i++) {
        hex_of(ents[i].hash, HSZ, hex);
        fprintf(m, "%s" SEP "%s\n", hex, ents[i].path);
    }
    /* Skip node 0 (the root, dirpath "") — it is the TREE line. */
    for (size_t k = 1; k < dn; k++) {
        hex_of(nodes[k].digest, HSZ, hex);
        if (section_line_format(line, sizeof(line), nodes[k].path,
                                nodes[k].file_count, hex) == 0)
            die("internal error: a section could not be encoded");
        fputs(line, m);
    }
    if (dn > 0) {
        hex_of(tree, HSZ, hex);
        fprintf(m, "TREE" SEP "%s\n", hex);
    }
    hex_of(root, HSZ, hex);
    fprintf(m, "ROOT" SEP "%s\n", hex);
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

static int do_check(const char *manifest_path)
{
    struct manifest_view mv;
    int pr = read_manifest(manifest_path, &mv);
    if (pr == -1 || !mv.have_root) {
        fprintf(stderr,
                "core_seal: FATAL — no valid ROOT line in manifest '%s'.\n"
                "  Run `make core-seal` to (re)generate it.\n",
                manifest_path);
        manifest_view_free(&mv);
        return 2;
    }
    if (pr == -2) {
        fprintf(stderr,
                "core_seal: FATAL — manifest '%s' has malformed lines; "
                "refusing to report a verdict.\n",
                manifest_path);
        manifest_view_free(&mv);
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

    if (verify_files(manifest_path, &mv, ents, n) != 0)
        rc = 1;

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
    manifest_view_free(&mv);
    for (size_t i = 0; i < n; i++)
        free(ents[i].path);
    free(ents);
    return rc;
}

/* The CLI body, kept as a named function so lib/test/src/test_core_seal.c can
 * `#define CORE_SEAL_NO_MAIN` and include this translation unit whole. */
int core_seal_main(int argc, char **argv);
int core_seal_main(int argc, char **argv)
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

#ifndef CORE_SEAL_NO_MAIN
int main(int argc, char **argv)
{
    return core_seal_main(argc, argv);
}
#endif
