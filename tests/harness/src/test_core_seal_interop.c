/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_core_seal_interop — prove that the repository's two independent
 * implementations of the codeindex Merkle dialect agree: core_seal.c
 * (core/MANIFEST.sha3 SECTION/TREE lines) and
 * cognition/modules/codeindex/codeindex_merkle.c (source-tree Merkle and
 * inclusion proofs).
 *
 * The dialect:
 *   leaf = SHA3-256(0x10 || "zcl.codeindex.merkle.leaf.v1"0x00
 *                        || relpath 0x00 || u64le(size) || bytes)
 *   node = SHA3-256(0x11 || "zcl.codeindex.merkle.node.v1"0x00
 *                        || dirpath 0x00 || u32le(direct child count)
 *                        || for each child in canonical order:
 *                               kind(0=file,1=dir) || name 0x00 || digest[32])
 *   child order = strcmp over the child KEY: a file's own name, a directory's
 *                 name followed by '/'.
 * Each domain string is hashed including its NUL (sizeof, not strlen). A node
 * binds all direct children and the u32le count; the tree is n-ary, with no
 * pairing step.
 *
 * The two file sets differ: the sealer takes the git-tracked CORE_SEAL_PATHS
 * (everything under core/), codeindex takes ci_enumerate_sources() (.c, .h,
 * .def under fixed roots), so whole-tree roots differ by construction. The
 * test mirrors the sealed file set into a scratch tree and runs both
 * implementations over it. A section is compared only when every sealed file
 * below it is a codeindex leaf and codeindex reports no extra file; sections
 * that fail are named with the responsible files.
 *
 * Non-vacuity defences:
 *   1. A floor: csi_real_sections asserts a minimum number of compared
 *      sections.
 *   2. csi_dialect_discriminates re-folds a real node from codeindex's proof
 *      children through four wrong preimages (domain without NUL, u16le
 *      count, bare-name ordering, leaf domain in the node slot) and requires
 *      each to differ while the canonical fold matches.
 *   3. An ordering trap in the synthetic fixture: `ab.c`, directory `ab`,
 *      `ab_z.c` sort ab.c < ab/ < ab_z.c by key but ab < ab.c < ab_z.c by
 *      bare name ('/' is 0x2f, below digits, letters and '_').
 *
 * Scratch work happens under ./test-tmp/. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "codeindex/codeindex_merkle.h"

/* The sealer is included whole so the assertions exercise the shipping
 * preimage functions (node_digest, hash_file, compute_sections, read_and_hash,
 * compute_root), as test_core_seal.c does. */
#define CORE_SEAL_NO_MAIN 1
/* core_seal_main() is the tool's one external symbol under that guard;
 * test_core_seal.c includes the same translation unit into the same binary, so
 * it is renamed here. */
#define core_seal_main csi_unused_core_seal_main
#include "../../../tools/core_seal.c"
#undef core_seal_main

#define CSI_WORK   "test-tmp/core_seal_interop"
#define CSI_MIRROR CSI_WORK "/mirror"
#define CSI_SYNTH  CSI_WORK "/synthetic"
#define CSI_LIST   CSI_WORK "/paths.nul"

/* At least 90% of the manifest's derived sections must remain comparable with
 * codeindex; the fraction is derived from the manifest, so it scales with new
 * module subtrees. */
#define CSI_MIN_COMPARABLE_PERCENT 90U

static int csi_failures;

#define CSI_CHECK(name, expr)                                                  \
    do {                                                                       \
        printf("core_seal_interop: %s... ", (name));                           \
        if ((expr)) {                                                          \
            printf("OK\n");                                                    \
        } else {                                                               \
            printf("FAIL\n");                                                  \
            csi_failures++;                                                    \
        }                                                                      \
    } while (0)

/* ── small filesystem helpers ────────────────────────────────────────── */

static void csi_rmrf(const char *dir)
{
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "core_seal_interop: rm -rf '%s' failed\n", dir);
}

/* mkdir -p over every directory component of `path` except the last. */
static bool csi_mkdir_parents(const char *path)
{
    char buf[PATH_MAX];
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf))
        return false;
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
            *p = '/';
            return false;
        }
        *p = '/';
    }
    return true;
}

static bool csi_copy_file(const char *src, const char *dst)
{
    if (!csi_mkdir_parents(dst))
        return false;
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return false;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) {
        close(in);
        return false;
    }
    unsigned char buf[65536];
    bool ok = true;
    for (;;) {
        ssize_t got = read(in, buf, sizeof(buf));
        if (got < 0) {
            if (errno == EINTR)
                continue;
            ok = false;
            break;
        }
        if (got == 0)
            break;
        ssize_t done = 0;
        while (done < got) {
            ssize_t w = write(out, buf + done, (size_t)(got - done));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                ok = false;
                break;
            }
            done += w;
        }
        if (!ok)
            break;
    }
    close(in);
    if (close(out) != 0)
        ok = false;
    return ok;
}

static bool csi_write_file(const char *path, const char *content)
{
    if (!csi_mkdir_parents(path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t n = strlen(content);
    bool ok = n == 0 || fwrite(content, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

/* ── running the SEALER over an arbitrary mirror ─────────────────────── */

/* Everything one run of the sealer produced over one mirror. */
struct csi_seal_run {
    struct entry *ents;
    size_t        nents;
    struct dnode *nodes;   /* sorted by path; index 0 is the root ("") */
    size_t        nnodes;
    unsigned char tree[HSZ];
    unsigned char root[HSZ];
};

static void csi_seal_run_free(struct csi_seal_run *r)
{
    for (size_t i = 0; i < r->nents; i++)
        free(r->ents[i].path);
    free(r->ents);
    free(r->nodes);
    memset(r, 0, sizeof(*r));
}

/* Run tools/core_seal.c's sealing path over `mirror_abs`, driven by the
 * NUL-separated list at `list_abs` as the Makefile does with `git ls-files -z`.
 * read_and_hash() consumes `stdin` and opens paths relative to the cwd, so
 * stdin is redirected and the process chdir()s into the mirror; both are
 * restored before return. */
static bool csi_run_sealer(const char *mirror_abs, const char *list_abs,
                           struct csi_seal_run *out)
{
    memset(out, 0, sizeof(*out));

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;

    int list_fd = open(list_abs, O_RDONLY | O_CLOEXEC);
    if (list_fd < 0)
        return false;

    fflush(NULL);
    int saved_stdin = dup(STDIN_FILENO);
    if (saved_stdin < 0) {
        close(list_fd);
        return false;
    }
    bool ok = dup2(list_fd, STDIN_FILENO) >= 0;
    close(list_fd);
    clearerr(stdin);

    if (ok && chdir(mirror_abs) != 0)
        ok = false;

    if (ok) {
        /* The manifest path is excluded from the stream by read_and_hash; the
         * mirror never contains it, so this only names the exclusion. */
        out->ents = read_and_hash("core/MANIFEST.sha3", &out->nents);
        compute_root(out->ents, out->nents, out->root);
        out->nnodes = compute_sections(out->ents, out->nents, &out->nodes,
                                       out->tree);
    }

    if (chdir(cwd) != 0)
        ok = false;
    if (dup2(saved_stdin, STDIN_FILENO) < 0)
        ok = false;
    close(saved_stdin);
    clearerr(stdin);
    return ok;
}

/* The sealer's node record for one directory path, or NULL. */
static const struct dnode *csi_seal_node(const struct csi_seal_run *r,
                                         const char *path)
{
    for (size_t i = 0; i < r->nnodes; i++)
        if (strcmp(r->nodes[i].path, path) == 0)
            return &r->nodes[i];
    return NULL;
}

/* Write the NUL-separated path list the sealer reads. */
static bool csi_write_nul_list(const char *path, char *const *paths, size_t n)
{
    if (!csi_mkdir_parents(path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++) {
        size_t len = strlen(paths[i]) + 1; /* include the NUL */
        ok = fwrite(paths[i], 1, len, f) == len;
    }
    return fclose(f) == 0 && ok;
}

/* ── the deliberately WRONG preimages, for discrimination ────────────── */

enum csi_variant {
    CSI_V_CANONICAL = 0,     /* exactly the dialect */
    CSI_V_DOMAIN_NO_NUL,     /* domain hashed with strlen, not sizeof */
    CSI_V_COUNT_U16,         /* child count as u16le instead of u32le */
    CSI_V_ORDER_BARE_NAME,   /* children ordered by name, no '/' for a dir */
    CSI_V_LEAF_DOMAIN,       /* the leaf domain string in the node slot */
    CSI_V__COUNT
};

static const char *csi_variant_name(enum csi_variant v)
{
    switch (v) {
    case CSI_V_CANONICAL:      return "canonical";
    case CSI_V_DOMAIN_NO_NUL:  return "domain without its NUL";
    case CSI_V_COUNT_U16:      return "child count as u16le";
    case CSI_V_ORDER_BARE_NAME:return "children ordered by bare name";
    case CSI_V_LEAF_DOMAIN:    return "leaf domain in the node preimage";
    default:                   return "?";
    }
}

static int csi_cmp_child_bare(const void *a, const void *b)
{
    const struct ci_merkle_proof_child *ca = a, *cb = b;
    return strcmp(ca->name, cb->name);
}

/* Fold a directory node from codeindex's inclusion-proof children through the
 * sealer's preimage rule. The canonical variant calls the shipping
 * node_digest(); the others mis-spell exactly one clause of the dialect. */
static void csi_fold(enum csi_variant v, const char *dirpath,
                     const struct ci_merkle_proof_child *kids, uint32_t n,
                     unsigned char out[HSZ])
{
    struct ci_merkle_proof_child *work =
        calloc(n ? n : 1, sizeof(struct ci_merkle_proof_child));
    if (!work)
        die("out of memory folding node");
    memcpy(work, kids, (size_t)n * sizeof(*work));
    if (v == CSI_V_ORDER_BARE_NAME)
        qsort(work, n, sizeof(*work), csi_cmp_child_bare);

    if (v == CSI_V_CANONICAL) {
        /* The shipping sealer function, unmodified. */
        struct mchild *mk = calloc(n ? n : 1, sizeof(struct mchild));
        if (!mk)
            die("out of memory folding node");
        for (uint32_t i = 0; i < n; i++) {
            child_set_name(&mk[i], work[i].name);
            mk[i].kind = work[i].kind;
            memcpy(mk[i].digest, work[i].digest.bytes, HSZ);
        }
        node_digest(dirpath, mk, n, out);
        free(mk);
        free(work);
        return;
    }

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char tag = MERKLE_TAG_NODE;
    sha3_256_write(&ctx, &tag, 1);
    if (v == CSI_V_DOMAIN_NO_NUL)
        sha3_256_write(&ctx, (const unsigned char *)merkle_node_domain,
                       strlen(merkle_node_domain));
    else if (v == CSI_V_LEAF_DOMAIN)
        sha3_256_write(&ctx, (const unsigned char *)merkle_leaf_domain,
                       sizeof(merkle_leaf_domain));
    else
        sha3_256_write(&ctx, (const unsigned char *)merkle_node_domain,
                       sizeof(merkle_node_domain));
    sha3_256_write(&ctx, (const unsigned char *)dirpath, strlen(dirpath) + 1);
    if (v == CSI_V_COUNT_U16) {
        unsigned char b[2] = { (unsigned char)(n & 0xff),
                               (unsigned char)((n >> 8) & 0xff) };
        sha3_256_write(&ctx, b, sizeof(b));
    } else {
        write_u32le(&ctx, n);
    }
    for (uint32_t i = 0; i < n; i++) {
        sha3_256_write(&ctx, &work[i].kind, 1);
        sha3_256_write(&ctx, (const unsigned char *)work[i].name,
                       strlen(work[i].name) + 1);
        sha3_256_write(&ctx, work[i].digest.bytes, HSZ);
    }
    sha3_256_finalize(&ctx, out);
    free(work);
}

/* ── section comparability, MEASURED ─────────────────────────────────── */

/* Is `path` at or below directory `dir`? `dir` == "" means the whole tree. */
static bool csi_under(const char *path, const char *dir)
{
    if (dir[0] == '\0')
        return true;
    size_t n = strlen(dir);
    return strncmp(path, dir, n) == 0 && path[n] == '/';
}

struct csi_verdict {
    uint32_t sealed_files;    /* sealed files at or below this directory */
    uint32_t indexed_files;   /* of those, how many codeindex made leaves of */
    uint32_t ci_file_count;   /* codeindex's own recursive count for the node */
    bool     ci_found;
    bool     comparable;
};

/* Whether both implementations saw the same input for this directory: every
 * sealed file below it is a codeindex leaf, and codeindex's recursive file
 * count equals that number. */
static struct csi_verdict csi_classify(const struct ci_merkle *m,
                                       const struct csi_seal_run *seal,
                                       const char *dir)
{
    struct csi_verdict v = {0};
    for (size_t i = 0; i < seal->nents; i++) {
        if (!csi_under(seal->ents[i].path, dir))
            continue;
        v.sealed_files++;
        struct ci_merkle_leaf leaf;
        bool found = false;
        if (ci_merkle_leaf(m, seal->ents[i].path, &leaf, &found) && found)
            v.indexed_files++;
    }
    struct ci_merkle_node node;
    if (ci_merkle_node(m, dir, &node, &v.ci_found) && v.ci_found)
        v.ci_file_count = node.file_count;
    v.comparable = v.ci_found && v.indexed_files == v.sealed_files &&
                   v.ci_file_count == v.sealed_files;
    return v;
}

/* Name the sealed files codeindex refused, so an incomparable section is
 * explained rather than merely reported. */
static void csi_explain(const struct ci_merkle *m,
                        const struct csi_seal_run *seal, const char *dir)
{
    for (size_t i = 0; i < seal->nents; i++) {
        if (!csi_under(seal->ents[i].path, dir))
            continue;
        struct ci_merkle_leaf leaf;
        bool found = false;
        if (ci_merkle_leaf(m, seal->ents[i].path, &leaf, &found) && found)
            continue;
        printf("      not indexed by codeindex: %s\n", seal->ents[i].path);
    }
}

/* ── 1: the real sealed sections, count derived from the manifest ───── */

static bool csi_manifest_has_section_tree_root(const struct manifest_view *mv)
{
    return mv->nsec > 0 && mv->have_tree && mv->have_root && mv->nfile > 0;
}

static char **csi_calloc_paths(size_t n)
{
    char **list = calloc(n ? n : 1, sizeof(char *));
    if (!list)
        die("out of memory");
    return list;
}

static bool csi_sealer_covers_mirror(bool ran, const struct csi_seal_run *seal,
                                     size_t nfile)
{
    return ran && seal->nents == nfile;
}

static bool csi_mirror_is_faithful(const struct csi_seal_run *seal,
                                   const struct manifest_view *mv)
{
    bool faithful = true;
    for (size_t i = 0; i < seal->nents && faithful; i++) {
        char hex[HEXSZ];
        zcl_hex_encode(seal->ents[i].hash, HSZ, hex);
        /* mv.file[] and seal.ents[] are both path-sorted over the same set. */
        faithful = strcmp(seal->ents[i].path, mv->file[i].path) == 0 &&
                   strcmp(hex, mv->file[i].hex) == 0;
    }
    return faithful;
}

static void csi_check_manifest_roots(bool faithful,
                                     const struct csi_seal_run *seal,
                                     const struct manifest_view *mv)
{
    if (faithful) {
        char tree_hex[HEXSZ], root_hex[HEXSZ];
        zcl_hex_encode(seal->tree, HSZ, tree_hex);
        zcl_hex_encode(seal->root, HSZ, root_hex);
        CSI_CHECK("sealer reproduces the manifest TREE line",
                  strcmp(tree_hex, mv->tree_hex) == 0);
        CSI_CHECK("sealer reproduces the manifest ROOT line",
                  strcmp(root_hex, mv->root_hex) == 0);
    }
}

static bool csi_node_agrees(struct ci_merkle *m, const char *dir,
                            const struct dnode *sn, struct ci_merkle_node *cn,
                            bool *found)
{
    (void)ci_merkle_node(m, dir, cn, found);
    return *found && memcmp(sn->digest, cn->digest.bytes, HSZ) == 0;
}

static bool csi_manifest_hex_differs(bool faithful,
                                     const unsigned char digest[HSZ],
                                     const char *want)
{
    if (!faithful)
        return false;
    char hex[HEXSZ];
    zcl_hex_encode(digest, HSZ, hex);
    return strcmp(hex, want) != 0;
}

static void csi_node_hex_or_absent(bool found, struct ci_merkle_node *cn,
                                   char *b, size_t cap)
{
    if (found)
        ci_merkle_hex(&cn->digest, b);
    else
        snprintf(b, cap, "<absent>");
}

static bool csi_comparable_floor_met(const struct manifest_view *mv,
                                     size_t comparable)
{
    return mv->nsec > 0 &&
           comparable * 100U >= mv->nsec * CSI_MIN_COMPARABLE_PERCENT;
}

static bool csi_roots_incomparable(const struct csi_verdict *v)
{
    return !v->comparable && v->indexed_files < v->sealed_files;
}

static void csi_cross_fold_comparable(struct ci_merkle *m,
                                      const struct csi_seal_run *seal,
                                      const struct manifest_view *mv)
{
    /* Cross-implementation fold: re-fold codeindex's proof children for a
     * comparable section through the sealer's node_digest. */
    for (size_t s = 0; s < mv->nsec; s++) {
        const char *dir = mv->sec[s].name;
        struct csi_verdict v = csi_classify(m, seal, dir);
        if (!v.comparable)
            continue;
        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        if (!p)
            break;
        struct zcl_sha3_digest d;
        bool found = false;
        bool okp = ci_merkle_prove(m, dir, p, &d, &found) && found;
        if (okp && p->nlevels > 0) {
            /* Level 0 is `dir`'s parent; rebuild `dir`'s parent from its
             * children and require the sealer's fold to match codeindex's. */
            const struct ci_merkle_proof_level *lv = &p->level[0];
            unsigned char folded[HSZ];
            csi_fold(CSI_V_CANONICAL, lv->path, &p->children[lv->first_child],
                     lv->nchildren, folded);
            struct ci_merkle_node parent;
            bool pf = false;
            (void)ci_merkle_node(m, lv->path, &parent, &pf);
            char label[160];
            snprintf(label, sizeof(label),
                     "sealer folds codeindex's proof children for '%s'",
                     lv->path);
            CSI_CHECK(label,
                      pf && memcmp(folded, parent.digest.bytes, HSZ) == 0);
        }
        ci_merkle_proof_free(p);
        break;
    }
}

static void csi_real_sections(void)
{
    printf("\n  -- the real sealed sections, over a mirror of the sealed "
           "file set --\n");

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        CSI_CHECK("getcwd", false);
        return;
    }

    struct manifest_view mv;
    int rc = read_manifest("core/MANIFEST.sha3", &mv);
    CSI_CHECK("core/MANIFEST.sha3 parses", rc == 0);
    if (rc != 0) {
        manifest_view_free(&mv);
        return;
    }
    CSI_CHECK("manifest carries SECTION, TREE and ROOT",
              csi_manifest_has_section_tree_root(&mv));
    printf("     manifest: %zu sealed files, %zu SECTION lines\n", mv.nfile,
           mv.nsec);

    csi_rmrf(CSI_WORK);

    /* Mirror the sealed set: same repo-relative paths, same bytes. */
    bool mirrored = true;
    char **list = csi_calloc_paths(mv.nfile);
    for (size_t i = 0; i < mv.nfile && mirrored; i++) {
        char dst[PATH_MAX];
        snprintf(dst, sizeof(dst), "%s/%s", CSI_MIRROR, mv.file[i].path);
        mirrored = csi_copy_file(mv.file[i].path, dst);
        if (!mirrored)
            fprintf(stderr, "core_seal_interop: cannot mirror %s\n",
                    mv.file[i].path);
        list[i] = mv.file[i].path;
    }
    CSI_CHECK("every sealed file mirrored into the scratch tree", mirrored);
    if (!mirrored)
        goto done;

    CSI_CHECK("NUL path list written",
              csi_write_nul_list(CSI_LIST, list, mv.nfile));

    char mirror_abs[PATH_MAX], list_abs[PATH_MAX];
    snprintf(mirror_abs, sizeof(mirror_abs), "%s/%s", cwd, CSI_MIRROR);
    snprintf(list_abs, sizeof(list_abs), "%s/%s", cwd, CSI_LIST);

    /* Implementation A: tools/core_seal.c, over the mirror. */
    struct csi_seal_run seal;
    bool ran = csi_run_sealer(mirror_abs, list_abs, &seal);
    CSI_CHECK("sealer ran over the mirror",
              csi_sealer_covers_mirror(ran, &seal, mv.nfile));
    if (!ran)
        goto done;

    /* Implementation B: codeindex over the same mirror (build_cold, no
     * snapshot). */
    struct ci_merkle *m = ci_merkle_build_cold(mirror_abs, NULL);
    CSI_CHECK("codeindex built the mirror", m != NULL);
    if (!m) {
        csi_seal_run_free(&seal);
        goto done;
    }

    /* A faithful mirror (every file hashes to the manifest digest) must
     * reproduce the manifest's SECTION/TREE/ROOT lines byte for byte. The
     * cross-implementation leg stays unconditional; only manifest equality is
     * conditioned. */
    bool faithful = csi_mirror_is_faithful(&seal, &mv);
    printf("     mirror reproduces the manifest's per-file digests: %s\n",
           faithful ? "yes" : "NO (core/ edited since the last `make core-seal`)");

    csi_check_manifest_roots(faithful, &seal, &mv);

    /* One node per sealed directory, plus the root node "". */
    CSI_CHECK("sealer emits one node per SECTION line, plus the root",
              seal.nnodes == mv.nsec + 1);

    printf("\n     %-42s %6s %6s  %s\n", "section", "sealed", "indexed",
           "verdict");
    size_t comparable = 0, agreed = 0, disagreed = 0, skipped = 0;
    for (size_t s = 0; s < mv.nsec; s++) {
        const char *dir = mv.sec[s].name;
        struct csi_verdict v = csi_classify(m, &seal, dir);
        const struct dnode *sn = csi_seal_node(&seal, dir);
        if (!sn) {
            printf("     %-42s %6u %6u  NO SEALER NODE\n", dir, v.sealed_files,
                   v.indexed_files);
            csi_failures++;
            continue;
        }
        if (!v.comparable) {
            printf("     %-42s %6u %6u  input sets differ - not compared\n",
                   dir, v.sealed_files, v.indexed_files);
            csi_explain(m, &seal, dir);
            skipped++;
            continue;
        }
        struct ci_merkle_node cn;
        bool found = false;
        bool same = csi_node_agrees(m, dir, sn, &cn, &found);
        comparable++;
        if (same) {
            agreed++;
            /* A faithful mirror must also match the manifest's hex. */
            if (csi_manifest_hex_differs(faithful, sn->digest,
                                         mv.sec[s].hex)) {
                printf("     %-42s  MANIFEST HEX MISMATCH\n", dir);
                csi_failures++;
            }
            printf("     %-42s %6u %6u  AGREE\n", dir, v.sealed_files,
                   v.indexed_files);
        } else {
            disagreed++;
            char a[HEXSZ], b[HEXSZ];
            zcl_hex_encode(sn->digest, HSZ, a);
            csi_node_hex_or_absent(found, &cn, b, sizeof(b));
            printf("     %-42s %6u %6u  *** DISAGREE ***\n", dir,
                   v.sealed_files, v.indexed_files);
            printf("        core_seal : %s\n", a);
            printf("        codeindex : %s\n", b);
        }
    }

    printf("\n     compared %zu of %zu sections; %zu agreed, %zu disagreed, "
           "%zu not comparable\n",
           comparable, mv.nsec, agreed, disagreed, skipped);

    CSI_CHECK("every comparable section agrees", disagreed == 0);
    CSI_CHECK("at least 90% of sections were genuinely comparable",
              csi_comparable_floor_met(&mv, comparable));

    /* The whole-tree roots must differ because some sealed files are not
     * indexable source; equality would mean the input sets converged. */
    struct csi_verdict rootv = csi_classify(m, &seal, "");
    struct ci_merkle_node croot;
    bool rootfound = false;
    (void)ci_merkle_root(m, &croot);
    (void)ci_merkle_node(m, "", &croot, &rootfound);
    printf("     whole-tree root: sealed %u files, codeindex indexed %u of "
           "them\n", rootv.sealed_files, rootv.indexed_files);
    CSI_CHECK("the whole-tree roots are correctly NOT comparable",
              csi_roots_incomparable(&rootv));

    csi_cross_fold_comparable(m, &seal, &mv);

    ci_merkle_free(m);
    csi_seal_run_free(&seal);
done:
    free(list);
    manifest_view_free(&mv);
}

/* ── 2: a synthetic tree where the SETS ARE IDENTICAL BY CONSTRUCTION ── */

/* Every file uses an extension ci_enumerate_sources() admits under a root it
 * walks, so both sets are identical and the WHOLE-TREE ROOT can be compared.
 * Ordering trap: `ab.c`, directory `ab`, `ab_z.c` sort "ab.c" < "ab/" <
 * "ab_z.c" by key, but "ab" < "ab.c" < "ab_z.c" by bare name. */
static const char *const csi_synth_files[] = {
    "core/ab.c",
    "core/ab/z.c",
    "core/ab_z.c",
    "core/nest/deep/leafy.h",
    "core/table.def",
    "core/modules/validation/include/validation/v.h",
    "core/modules/validation/src/v.c",
};

static bool csi_synth_write_fixture(char **list, size_t n)
{
    bool built = true;
    for (size_t i = 0; i < n && built; i++) {
        char dst[PATH_MAX], body[256];
        snprintf(dst, sizeof(dst), "%s/%s", CSI_SYNTH, csi_synth_files[i]);
        /* Distinct content and lengths, so the u64le size field is
         * exercised. */
        snprintf(body, sizeof(body), "/* %s */\n%*sint x%zu(void){return %zu;}\n",
                 csi_synth_files[i], (int)i, "", i, i);
        built = csi_write_file(dst, body);
        list[i] = (char *)csi_synth_files[i];
    }
    return built;
}

static bool csi_synth_leaf_agrees(struct ci_merkle *m, const struct entry *e)
{
    struct ci_merkle_leaf l;
    bool found = false;
    return ci_merkle_leaf(m, e->path, &l, &found) && found &&
           memcmp(e->leaf, l.digest.bytes, HSZ) == 0;
}

static bool csi_synth_node_agrees(struct ci_merkle *m,
                                  const struct dnode *nd)
{
    struct ci_merkle_node cn;
    bool found = false;
    return ci_merkle_node(m, nd->path, &cn, &found) && found &&
           memcmp(nd->digest, cn.digest.bytes, HSZ) == 0;
}

static bool csi_synth_same_set(const struct csi_verdict *v, size_t n)
{
    return v->comparable && v->sealed_files == (uint32_t)n &&
           v->indexed_files == (uint32_t)n;
}

static void csi_synth_check_trap(struct ci_merkle *m)
{
    /* The two candidate ordering rules disagree for this fixture, so the
     * agreement above is not order-insensitivity. */
    struct ci_merkle_proof *p = ci_merkle_proof_alloc();
    if (p) {
        struct zcl_sha3_digest d;
        bool found = false;
        if (ci_merkle_prove(m, "core/ab.c", p, &d, &found) && found &&
            p->nlevels > 0) {
            const struct ci_merkle_proof_level *lv = &p->level[0];
            unsigned char canon[HSZ], bare[HSZ];
            csi_fold(CSI_V_CANONICAL, lv->path, &p->children[lv->first_child],
                     lv->nchildren, canon);
            csi_fold(CSI_V_ORDER_BARE_NAME, lv->path,
                     &p->children[lv->first_child], lv->nchildren, bare);
            CSI_CHECK("the ab.c / ab/ / ab_z.c ordering trap is live "
                      "(key order != bare-name order)",
                      lv->nchildren >= 3 && memcmp(canon, bare, HSZ) != 0);
        }
        ci_merkle_proof_free(p);
    }
}

static void csi_synthetic_tree(void)
{
    printf("\n  -- synthetic tree: identical input sets, so the ROOTS must "
           "match too --\n");

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        CSI_CHECK("getcwd", false);
        return;
    }

    csi_rmrf(CSI_SYNTH);
    size_t n = sizeof(csi_synth_files) / sizeof(csi_synth_files[0]);
    char **list = calloc(n, sizeof(char *));
    if (!list)
        die("out of memory");
    bool built = csi_synth_write_fixture(list, n);
    CSI_CHECK("synthetic fixture written", built);
    if (!built) {
        free(list);
        return;
    }

    char list_path[PATH_MAX];
    snprintf(list_path, sizeof(list_path), "%s/paths.nul", CSI_SYNTH);
    CSI_CHECK("synthetic NUL path list written",
              csi_write_nul_list(list_path, list, n));

    char root_abs[PATH_MAX], list_abs[PATH_MAX];
    snprintf(root_abs, sizeof(root_abs), "%s/%s", cwd, CSI_SYNTH);
    snprintf(list_abs, sizeof(list_abs), "%s/%s", cwd, list_path);

    struct csi_seal_run seal;
    bool ran = csi_run_sealer(root_abs, list_abs, &seal);
    CSI_CHECK("sealer ran over the synthetic tree", ran && seal.nents == n);
    if (!ran) {
        free(list);
        return;
    }

    struct ci_merkle *m = ci_merkle_build_cold(root_abs, NULL);
    CSI_CHECK("codeindex built the synthetic tree", m != NULL);
    if (!m) {
        csi_seal_run_free(&seal);
        free(list);
        return;
    }

    /* Same set, proved rather than assumed. */
    struct csi_verdict rootv = csi_classify(m, &seal, "");
    CSI_CHECK("both implementations saw the identical file set",
              csi_synth_same_set(&rootv, n));

    /* Every leaf. */
    size_t leaf_same = 0;
    for (size_t i = 0; i < seal.nents; i++) {
        if (csi_synth_leaf_agrees(m, &seal.ents[i]))
            leaf_same++;
        else
            printf("     LEAF DISAGREE: %s\n", seal.ents[i].path);
    }
    CSI_CHECK("every leaf digest agrees", leaf_same == seal.nents);

    /* Every directory node, root included. */
    size_t node_same = 0;
    for (size_t i = 0; i < seal.nnodes; i++) {
        if (csi_synth_node_agrees(m, &seal.nodes[i]))
            node_same++;
        else
            printf("     NODE DISAGREE: '%s'\n", seal.nodes[i].path);
    }
    CSI_CHECK("every directory node digest agrees",
              seal.nnodes > 0 && node_same == seal.nnodes);
    printf("     %zu leaves and %zu directory nodes compared\n", seal.nents,
           seal.nnodes);

    /* The headline: one 32-byte answer from two independent implementations. */
    struct ci_merkle_node croot;
    bool rf = false;
    bool got = ci_merkle_root(m, &croot);
    rf = got;
    char a[HEXSZ], b[HEXSZ];
    zcl_hex_encode(seal.tree, HSZ, a);
    if (rf)
        ci_merkle_hex(&croot.digest, b);
    else
        snprintf(b, sizeof(b), "<absent>");
    printf("     core_seal TREE : %s\n     codeindex ROOT : %s\n", a, b);
    CSI_CHECK("the whole-tree roots are byte-identical",
              rf && memcmp(seal.tree, croot.digest.bytes, HSZ) == 0);

    csi_synth_check_trap(m);

    ci_merkle_free(m);
    csi_seal_run_free(&seal);
    free(list);
}

/* ── 3: the equality above is sensitive to every clause of the dialect ── */

static bool csi_sealer_leaf_matches(const char *root_abs,
                                    const unsigned char want[HSZ])
{
    /* Canonical, via the sealer's own hash_file(). */
    char saved[PATH_MAX];
    unsigned char flat[HSZ], leaf[HSZ];
    uint64_t sz = 0;
    bool ok = getcwd(saved, sizeof(saved)) != NULL &&
              chdir(root_abs) == 0;
    if (ok) {
        ok = hash_file("core/ab.c", flat, leaf, &sz) == 0;
        if (chdir(saved) != 0)
            ok = false;
    }
    return ok && memcmp(leaf, want, HSZ) == 0;
}

static bool csi_leaf_no_nul_differs(const char *full, const struct stat *st,
                                    const unsigned char want[HSZ])
{
    /* Same bytes, leaf domain hashed without its NUL. */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char tag = MERKLE_TAG_LEAF;
    sha3_256_write(&ctx, &tag, 1);
    sha3_256_write(&ctx, (const unsigned char *)merkle_leaf_domain,
                   strlen(merkle_leaf_domain));
    sha3_256_write(&ctx, (const unsigned char *)"core/ab.c",
                   strlen("core/ab.c") + 1);
    write_u64le(&ctx, (uint64_t)st->st_size);
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    bool read_ok = fd >= 0;
    unsigned char buf[65536];
    while (read_ok) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got < 0) {
            if (errno == EINTR)
                continue;
            read_ok = false;
            break;
        }
        if (got == 0)
            break;
        sha3_256_write(&ctx, buf, (size_t)got);
    }
    if (fd >= 0)
        close(fd);
    unsigned char wrong[HSZ];
    sha3_256_finalize(&ctx, wrong);
    return read_ok && memcmp(wrong, want, HSZ) != 0;
}

static void csi_dialect_discriminates(void)
{
    printf("\n  -- discrimination: each dialect clause, spelled wrong, must "
           "break the match --\n");

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        CSI_CHECK("getcwd", false);
        return;
    }
    char root_abs[PATH_MAX];
    snprintf(root_abs, sizeof(root_abs), "%s/%s", cwd, CSI_SYNTH);

    struct ci_merkle *m = ci_merkle_build_cold(root_abs, NULL);
    CSI_CHECK("codeindex rebuilt the synthetic tree", m != NULL);
    if (!m)
        return;

    struct ci_merkle_proof *p = ci_merkle_proof_alloc();
    CSI_CHECK("proof allocated", p != NULL);
    if (!p) {
        ci_merkle_free(m);
        return;
    }

    struct zcl_sha3_digest d;
    bool found = false;
    bool okp = ci_merkle_prove(m, "core/ab.c", p, &d, &found) && found &&
               p->nlevels > 0;
    CSI_CHECK("codeindex proved core/ab.c", okp);
    if (okp) {
        const struct ci_merkle_proof_level *lv = &p->level[0];
        struct ci_merkle_node parent;
        bool pf = false;
        (void)ci_merkle_node(m, lv->path, &parent, &pf);
        CSI_CHECK("codeindex has the parent node", pf);

        for (int v = 0; v < CSI_V__COUNT && pf; v++) {
            unsigned char folded[HSZ];
            csi_fold((enum csi_variant)v, lv->path,
                     &p->children[lv->first_child], lv->nchildren, folded);
            bool matches = memcmp(folded, parent.digest.bytes, HSZ) == 0;
            char label[192];
            if (v == CSI_V_CANONICAL) {
                snprintf(label, sizeof(label),
                         "sealer's node_digest MATCHES codeindex (%s)",
                         csi_variant_name((enum csi_variant)v));
                CSI_CHECK(label, matches);
            } else {
                snprintf(label, sizeof(label),
                         "a wrong preimage FAILS to match: %s",
                         csi_variant_name((enum csi_variant)v));
                CSI_CHECK(label, !matches);
            }
        }
    }

    /* Leaf side: the size field and the domain NUL, shown to matter. */
    struct ci_merkle_leaf l;
    bool lf = false;
    if (ci_merkle_leaf(m, "core/ab.c", &l, &lf) && lf) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/core/ab.c", root_abs);
        struct stat st;
        if (stat(full, &st) == 0) {
            CSI_CHECK("sealer's hash_file MATCHES codeindex's leaf digest",
                      csi_sealer_leaf_matches(root_abs, l.digest.bytes));

            CSI_CHECK("a leaf domain without its NUL FAILS to match",
                      csi_leaf_no_nul_differs(full, &st, l.digest.bytes));
        }
    }

    ci_merkle_proof_free(p);
    ci_merkle_free(m);
}

/* ── entry point ─────────────────────────────────────────────────────── */

int test_core_seal_interop(void)
{
    printf("\n=== core_seal <-> codeindex Merkle dialect interop ===\n");
    csi_failures = 0;

    csi_real_sections();
    csi_synthetic_tree();
    csi_dialect_discriminates();

    csi_rmrf(CSI_WORK);

    printf("core_seal_interop: %d failure(s)\n", csi_failures);
    return csi_failures;
}
