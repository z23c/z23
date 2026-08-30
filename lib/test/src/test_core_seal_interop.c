/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_core_seal_interop — prove that this repository's TWO independent
 * implementations of the codeindex Merkle dialect actually agree.
 *
 * THE GAP THIS CLOSES. Two separate bodies of code compute digests in the same
 * dialect over the same kind of input:
 *
 *   tools/core_seal.c              mints the SECTION/TREE lines of
 *                                  core/MANIFEST.sha3.
 *   lib/codeindex/codeindex_merkle.c  builds the source-tree Merkle and emits
 *                                  and verifies inclusion proofs against it.
 *
 * core_seal.c's own header says its three rules are "transcribed from
 * codeindex_merkle.c" and "any change there must be mirrored here". Until this
 * file existed, NOTHING in the tree checked that. Two hand-mirrored preimage
 * rules with no equality test between them is a silent-drift shape: the day
 * they diverge, a SECTION digest means one thing to the sealer and another to
 * the proof code, and every guarantee layered on top is void — with both sides
 * still self-consistent and both test suites still green.
 *
 * THE DIALECT UNDER TEST, in full:
 *   leaf = SHA3-256(0x10 || "zcl.codeindex.merkle.leaf.v1"0x00
 *                        || relpath 0x00 || u64le(size) || bytes)
 *   node = SHA3-256(0x11 || "zcl.codeindex.merkle.node.v1"0x00
 *                        || dirpath 0x00 || u32le(direct child count)
 *                        || for each child in canonical order:
 *                               kind(0=file,1=dir) || name 0x00 || digest[32])
 *   child order = strcmp over the child KEY: a file's own name, a directory's
 *                 name followed by '/'.
 * Each domain string is hashed INCLUDING its NUL terminator (sizeof, not
 * strlen). A directory node binds ALL of its direct children, and the count is
 * bound as a u32le — the tree is n-ary, so there is no pairing step and no
 * duplicate-tail case.
 *
 * ── WHY THIS IS NOT A ONE-LINE COMPARISON: THE TWO FILE SETS DIFFER ──
 *
 * The sealer's input is the Makefile's CORE_SEAL_PATHS as tracked by git — 70
 * files: everything under core/ plus four named files in lib/validation.
 * codeindex's input is ci_enumerate_sources()' policy: .c, .h and .def under a
 * fixed set of roots. Those sets are NOT the same set, so the two WHOLE-TREE
 * roots differ by construction and comparing them directly would be a bug, not
 * a test.
 *
 * This file therefore controls for the input instead of assuming it away. It
 * MIRRORS exactly the sealed file set into a scratch tree and runs BOTH
 * implementations over that one mirror. Any surviving difference is then
 * algorithmic, which is the only thing worth measuring. Comparability is
 * decided per directory and MEASURED, never assumed: a section is compared
 * only when every sealed file below it is also a codeindex leaf AND codeindex
 * reports no extra file below it. The sections that fail that test are named
 * in the transcript together with the exact files responsible, so "we could
 * not compare N of them" is never a silent omission.
 *
 * ── HOW IT AVOIDS BEING VACUOUS ──
 *
 * A test that compares two things that cannot differ is worthless, and this one
 * is easy to write that way. Three defences:
 *
 *   1. A FLOOR. csi_real_sections asserts a minimum number of genuinely
 *      compared sections. If a policy change quietly makes every section
 *      incomparable, the group goes red instead of green-and-empty.
 *   2. A DISCRIMINATION LEG. csi_dialect_discriminates re-folds a REAL node
 *      from codeindex's own proof children through four deliberately WRONG
 *      preimages — domain without its NUL, count as u16le, children ordered by
 *      bare name, the leaf domain in the node slot — and requires each to
 *      differ from codeindex's answer, while the canonical fold matches. That
 *      pins every clause of the dialect individually.
 *   3. AN ORDERING TRAP in the synthetic fixture. The children `ab.c`, the
 *      directory `ab`, and `ab_z.c` sort as ab.c < ab/ < ab_z.c under the real
 *      rule and as ab < ab.c < ab_z.c under the plausible wrong rule (bare
 *      name). '/' is 0x2f, BELOW every digit, letter and '_' — so a second
 *      implementation reasoning from the ASCII rank of '/' rather than from
 *      the prefix property gets exactly this case backwards. The fixture makes
 *      that divergence observable instead of theoretical.
 *
 * Scratch work happens under ./test-tmp/ (project no-/tmp convention).
 */
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

/* The sealer is included whole rather than re-implemented, so the assertions
 * below exercise the SHIPPING preimage functions (node_digest, hash_file,
 * compute_sections, read_and_hash, compute_root) and not a copy of them that
 * could agree with codeindex while the real tool does not. This is the same
 * pattern lib/test/src/test_core_seal.c already uses. */
#define CORE_SEAL_NO_MAIN 1
/* core_seal_main() is the tool's ONE external symbol under that guard, and
 * lib/test/src/test_core_seal.c already includes this same translation unit
 * into the same binary. Renaming it here — rather than editing the sealer to
 * make it static — keeps tools/core_seal.c untouched and lets both tests hold
 * their own private copy of the sealer's file-local machinery. */
#define core_seal_main csi_unused_core_seal_main
#include "../../../tools/core_seal.c"
#undef core_seal_main

#define CSI_WORK   "test-tmp/core_seal_interop"
#define CSI_MIRROR CSI_WORK "/mirror"
#define CSI_SYNTH  CSI_WORK "/synthetic"
#define CSI_LIST   CSI_WORK "/paths.nul"

/* The number of the 23 sealed sections that are expected to be comparable at
 * all — i.e. whose sealed file set survives ci_enumerate_sources()' .c/.h/.def
 * policy intact. Three sealed files are not indexable source (core/UNSEAL.md,
 * core/consensus/src/oversize_grandfather_table.inc, core/params/module.cfg),
 * and they make exactly four sections incomparable: core, core/consensus,
 * core/consensus/src and core/params. This is a FLOOR, not an equality: if a
 * future extension-policy change makes MORE sections comparable that is fine,
 * but silently comparing fewer must go red. */
#define CSI_MIN_COMPARABLE 19

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

/* mkdir -p over every directory component of `path` EXCEPT the last one, which
 * is taken to be a file name. */
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

/* Run tools/core_seal.c's real sealing path over `mirror_abs`, driving it with
 * the NUL-separated path list at `list_abs` exactly as the Makefile drives it
 * with `git ls-files -z`. read_and_hash() consumes `stdin` and opens each path
 * relative to the working directory, so stdin is redirected and the process
 * chdir()s into the mirror for the duration — both restored before return.
 * (test_parallel gives every group its own fork()ed process, and test.c runs
 * groups sequentially, so neither is visible to another group.) */
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

/* Fold a directory node from children supplied by CODEINDEX (an inclusion
 * proof carries every direct child of every level, in canonical order) through
 * the SEALER's preimage rule. The canonical variant calls the shipping
 * node_digest() from tools/core_seal.c verbatim; the others re-spell exactly
 * one clause of the dialect wrongly. */
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

/* Decide, from evidence only, whether the two implementations were handed the
 * same input for this directory. Every sealed file below it must also be a
 * codeindex leaf (nothing dropped), and codeindex's own recursive file count
 * must equal that number (nothing added). */
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

/* ── 1: the 23 real sealed sections ──────────────────────────────────── */

static void csi_real_sections(void)
{
    printf("\n  -- the 23 real sealed sections, over a mirror of the sealed "
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
              mv.nsec > 0 && mv.have_tree && mv.have_root && mv.nfile > 0);
    printf("     manifest: %zu sealed files, %zu SECTION lines\n", mv.nfile,
           mv.nsec);

    csi_rmrf(CSI_WORK);

    /* Mirror the sealed set: same repo-relative paths, same bytes. That is the
     * whole point — from here on the two implementations see ONE input set. */
    bool mirrored = true;
    char **list = calloc(mv.nfile ? mv.nfile : 1, sizeof(char *));
    if (!list)
        die("out of memory");
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
    CSI_CHECK("sealer ran over the mirror", ran && seal.nents == mv.nfile);
    if (!ran)
        goto done;

    /* Implementation B: lib/codeindex, over the SAME mirror. build_cold reads
     * and writes no snapshot, so this is the from-scratch reference path. */
    struct ci_merkle *m = ci_merkle_build_cold(mirror_abs, NULL);
    CSI_CHECK("codeindex built the mirror", m != NULL);
    if (!m) {
        csi_seal_run_free(&seal);
        goto done;
    }

    /* The mirror is faithful when every mirrored file still hashes to the
     * digest the manifest recorded. When it does, the sealer's recomputation
     * must reproduce the manifest's own SECTION/TREE/ROOT lines byte for byte —
     * which pins that this test is measuring the SHIPPED seal and not some
     * drifted working-tree state. When core/ has been edited without a re-seal
     * the two implementations must still agree with EACH OTHER, so that leg
     * stays unconditional and only the manifest-equality leg is conditioned. */
    bool faithful = true;
    for (size_t i = 0; i < seal.nents && faithful; i++) {
        char hex[HEXSZ];
        zcl_hex_encode(seal.ents[i].hash, HSZ, hex);
        /* mv.file[] and seal.ents[] are both path-sorted over the same set. */
        faithful = strcmp(seal.ents[i].path, mv.file[i].path) == 0 &&
                   strcmp(hex, mv.file[i].hex) == 0;
    }
    printf("     mirror reproduces the manifest's per-file digests: %s\n",
           faithful ? "yes" : "NO (core/ edited since the last `make core-seal`)");

    if (faithful) {
        char tree_hex[HEXSZ], root_hex[HEXSZ];
        zcl_hex_encode(seal.tree, HSZ, tree_hex);
        zcl_hex_encode(seal.root, HSZ, root_hex);
        CSI_CHECK("sealer reproduces the manifest TREE line",
                  strcmp(tree_hex, mv.tree_hex) == 0);
        CSI_CHECK("sealer reproduces the manifest ROOT line",
                  strcmp(root_hex, mv.root_hex) == 0);
    }

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
        (void)ci_merkle_node(m, dir, &cn, &found);
        bool same = found && memcmp(sn->digest, cn.digest.bytes, HSZ) == 0;
        comparable++;
        if (same) {
            agreed++;
            /* When the mirror is faithful the shared answer must also be the
             * hex the manifest actually shipped. */
            if (faithful) {
                char hex[HEXSZ];
                zcl_hex_encode(sn->digest, HSZ, hex);
                if (strcmp(hex, mv.sec[s].hex) != 0) {
                    printf("     %-42s  MANIFEST HEX MISMATCH\n", dir);
                    csi_failures++;
                }
            }
            printf("     %-42s %6u %6u  AGREE\n", dir, v.sealed_files,
                   v.indexed_files);
        } else {
            disagreed++;
            char a[HEXSZ], b[HEXSZ];
            zcl_hex_encode(sn->digest, HSZ, a);
            if (found)
                ci_merkle_hex(&cn.digest, b);
            else
                snprintf(b, sizeof(b), "<absent>");
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
    CSI_CHECK("enough sections were genuinely comparable",
              comparable >= CSI_MIN_COMPARABLE);

    /* The whole-tree roots are expected NOT to be comparable: three sealed
     * files are not indexable source. Asserting that they differ is a positive
     * statement about WHY, not a shrug — if they ever became equal the input
     * sets would have converged and CSI_MIN_COMPARABLE should be 23. */
    struct csi_verdict rootv = csi_classify(m, &seal, "");
    struct ci_merkle_node croot;
    bool rootfound = false;
    (void)ci_merkle_root(m, &croot);
    (void)ci_merkle_node(m, "", &croot, &rootfound);
    printf("     whole-tree root: sealed %u files, codeindex indexed %u of "
           "them\n", rootv.sealed_files, rootv.indexed_files);
    CSI_CHECK("the whole-tree roots are correctly NOT comparable",
              !rootv.comparable && rootv.indexed_files < rootv.sealed_files);

    /* Cross-implementation fold: take codeindex's OWN proof children for a
     * comparable section and re-fold them through the sealer's node_digest.
     * The two implementations then meet inside one preimage. */
    for (size_t s = 0; s < mv.nsec; s++) {
        const char *dir = mv.sec[s].name;
        struct csi_verdict v = csi_classify(m, &seal, dir);
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

    ci_merkle_free(m);
    csi_seal_run_free(&seal);
done:
    free(list);
    manifest_view_free(&mv);
}

/* ── 2: a synthetic tree where the SETS ARE IDENTICAL BY CONSTRUCTION ── */

/* Every file below uses an extension ci_enumerate_sources() admits, and sits
 * under a root it walks, so the sealer's set and codeindex's set are the same
 * set — which lets this leg assert something the real sections cannot: that the
 * two implementations agree on the WHOLE-TREE ROOT, not merely on subtrees.
 *
 * The names are chosen to be the ordering trap: `ab.c`, the directory `ab`, and
 * `ab_z.c` under one parent. Keys "ab.c" < "ab/" < "ab_z.c"; bare names
 * "ab" < "ab.c" < "ab_z.c". The two rules give different child orders and
 * therefore different node digests, so agreement here is a real measurement. */
static const char *const csi_synth_files[] = {
    "core/ab.c",
    "core/ab/z.c",
    "core/ab_z.c",
    "core/nest/deep/leafy.h",
    "core/table.def",
    "lib/validation/include/validation/v.h",
    "lib/validation/src/v.c",
};

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
    bool built = true;
    char **list = calloc(n, sizeof(char *));
    if (!list)
        die("out of memory");
    for (size_t i = 0; i < n && built; i++) {
        char dst[PATH_MAX], body[256];
        snprintf(dst, sizeof(dst), "%s/%s", CSI_SYNTH, csi_synth_files[i]);
        /* Distinct, deterministic content, and deliberately distinct LENGTHS so
         * the u64le size field in the leaf preimage is exercised. */
        snprintf(body, sizeof(body), "/* %s */\n%*sint x%zu(void){return %zu;}\n",
                 csi_synth_files[i], (int)i, "", i, i);
        built = csi_write_file(dst, body);
        list[i] = (char *)csi_synth_files[i];
    }
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
              rootv.comparable && rootv.sealed_files == (uint32_t)n &&
                  rootv.indexed_files == (uint32_t)n);

    /* Every leaf. */
    size_t leaf_same = 0;
    for (size_t i = 0; i < seal.nents; i++) {
        struct ci_merkle_leaf l;
        bool found = false;
        if (ci_merkle_leaf(m, seal.ents[i].path, &l, &found) && found &&
            memcmp(seal.ents[i].leaf, l.digest.bytes, HSZ) == 0)
            leaf_same++;
        else
            printf("     LEAF DISAGREE: %s\n", seal.ents[i].path);
    }
    CSI_CHECK("every leaf digest agrees", leaf_same == seal.nents);

    /* Every directory node, root included. */
    size_t node_same = 0;
    for (size_t i = 0; i < seal.nnodes; i++) {
        struct ci_merkle_node cn;
        bool found = false;
        if (ci_merkle_node(m, seal.nodes[i].path, &cn, &found) && found &&
            memcmp(seal.nodes[i].digest, cn.digest.bytes, HSZ) == 0)
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

    /* The ordering trap actually is a trap: the two candidate rules disagree
     * for this fixture, so the agreement above is not a coincidence of the
     * fixture being order-insensitive. */
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

    ci_merkle_free(m);
    csi_seal_run_free(&seal);
    free(list);
}

/* ── 3: the equality above is sensitive to every clause of the dialect ── */

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
            CSI_CHECK("sealer's hash_file MATCHES codeindex's leaf digest",
                      ok && memcmp(leaf, l.digest.bytes, HSZ) == 0);

            /* Same bytes, leaf domain hashed without its NUL. */
            struct sha3_256_ctx ctx;
            sha3_256_init(&ctx);
            unsigned char tag = MERKLE_TAG_LEAF;
            sha3_256_write(&ctx, &tag, 1);
            sha3_256_write(&ctx, (const unsigned char *)merkle_leaf_domain,
                           strlen(merkle_leaf_domain));
            sha3_256_write(&ctx, (const unsigned char *)"core/ab.c",
                           strlen("core/ab.c") + 1);
            write_u64le(&ctx, (uint64_t)st.st_size);
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
            CSI_CHECK("a leaf domain without its NUL FAILS to match",
                      read_ok && memcmp(wrong, l.digest.bytes, HSZ) != 0);
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
