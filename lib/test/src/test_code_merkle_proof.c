/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_merkle inclusion-proof contract: can one machine hand another a
 * SECTION of the source tree plus a compact proof that the section belongs to
 * a root the receiver already trusts — with the receiver holding neither the
 * repository nor the tree?
 *
 * Coverage:
 *   1. round trip      — a leaf, a directory node, the root itself, and a deep
 *                        path each prove and verify; the wire form decodes to
 *                        something that verifies identically; and a proof built
 *                        from a COLD tree verifies against the COLD root, so
 *                        determinism is exercised rather than assumed.
 *   2. shape and cost  — a directory with many children produces a proof whose
 *                        sibling count is the SUM of sibling counts along the
 *                        path, not log(n). Measured and printed, because that
 *                        cost is a real property of a non-binary tree and the
 *                        number is the point.
 *   3. path binding    — a proof minted for path A does not verify for path B,
 *                        in either direction, and re-labelling the proof does
 *                        not rescue it.
 *   4. sibling binding — altering ANY sibling's name, kind, or digest breaks
 *                        verification, including siblings that are not on the
 *                        path. So does reordering two siblings.
 *   5. root binding    — a valid proof does not verify against a root it was
 *                        not built under.
 *   6. kind binding    — a leaf digest is not passable as an interior digest
 *                        and vice versa, which is what the source's tag/domain
 *                        separation (0x10 + merkle.leaf.v1 vs 0x11 +
 *                        merkle.node.v1) buys and what the proof's kind bytes
 *                        make checkable.
 *   7. wire hygiene    — truncated, over-long, wrong-domain, and bit-flipped
 *                        images decode false; encoding into a short buffer
 *                        refuses instead of writing a short proof.
 *   8. the real tree   — one real repo-relative path proved against a real
 *                        cold-built root, verified through the byte-only
 *                        verifier, with the measured sizes printed.
 *   9. child order     — a file, a directory, and a longer file sharing a
 *                        prefix (ab.c, ab/, ab_z.c) land in the canonical order
 *                        the PREFIX rule predicts, which is the OPPOSITE of what
 *                        an ASCII-rank-of-'/' argument predicts for the last
 *                        pair. The header states that reason; this pins it.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention).
 */

#include "test/test_core.h"

#include "codeindex/codeindex_merkle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CMP_FIX "test-tmp/code_merkle_proof_fix"

/* how many files go in the deliberately wide directory */
#define CMP_WIDE 64

/* Serialization scratch. Static rather than malloc so the test never has to
 * decide what to do about an allocation failure mid-assertion, and so the
 * "refuse a short buffer" case is one cap argument away. */
static unsigned char cmp_wire[CI_MERKLE_PROOF_WIRE_MAX];
static unsigned char cmp_wire2[CI_MERKLE_PROOF_WIRE_MAX];

static bool cmp_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    return fclose(f) == 0;
}

/* Real depth (lib/<mod>/include/<mod>/x.h is four directories deep), two
 * modules so locality is visible, a top-level root file, and one deliberately
 * WIDE directory so the sum-of-siblings cost is measurable rather than
 * asserted. Every root used here is one ci_enumerate_sources() actually walks;
 * tools/ is walked recursively, which is what makes tools/wide/ legal. */
static bool cmp_fixture(const char *dir)
{
    bool ok = true;
    ok = ok && cmp_write(dir, "lib/net/include/net/cmp_a.h",
                         "#ifndef CMP_A_H\n#define CMP_A_H\nint cmp_a(void);\n#endif\n");
    ok = ok && cmp_write(dir, "lib/net/src/cmp_a.c",
                         "/* cmp_a — proof fixture. */\n#include \"net/cmp_a.h\"\n"
                         "int cmp_a(void)\n{\n    return 1;\n}\n");
    ok = ok && cmp_write(dir, "lib/net/src/cmp_b.c",
                         "/* cmp_b — proof fixture. */\nint cmp_b(void)\n{\n"
                         "    return 2;\n}\n");
    ok = ok && cmp_write(dir, "lib/crypto/src/cmp_c.c",
                         "/* cmp_c — proof fixture. */\nint cmp_c(void)\n{\n"
                         "    return 3;\n}\n");
    ok = ok && cmp_write(dir, "core/cmp_core.c",
                         "/* cmp_core — proof fixture. */\nint cmp_core(void)\n{\n"
                         "    return 4;\n}\n");
    ok = ok && cmp_write(dir, "tools/cmp_tool.c",
                         "/* cmp_tool — proof fixture. */\nint cmp_tool(void)\n{\n"
                         "    return 5;\n}\n");
    for (int i = 0; ok && i < CMP_WIDE; i++) {
        char rel[128], body[128];
        snprintf(rel, sizeof(rel), "tools/wide/cmp_w%03d.c", i);
        snprintf(body, sizeof(body),
                 "/* cmp_w%03d — proof fixture. */\nint cmp_w%03d(void)\n{\n"
                 "    return %d;\n}\n", i, i, i);
        ok = cmp_write(dir, rel, body);
    }
    return ok;
}

static void cmp_reset(void)
{
    system("rm -rf " CMP_FIX);
}

/* Prove `path` and check the proof against the tree's own root through the
 * standalone verifier. Returns false if anything at all refused. */
static bool cmp_prove_ok(struct ci_merkle *m, const char *path,
                         struct ci_merkle_proof *p,
                         struct zcl_sha3_digest *digest,
                         struct zcl_sha3_digest *root)
{
    struct ci_merkle_node rn;
    bool found = false;
    if (!ci_merkle_root(m, &rn)) return false;
    *root = rn.digest;
    if (!ci_merkle_prove(m, path, p, digest, &found) || !found) return false;
    bool ok = false;
    return ci_merkle_proof_verify(p, digest, root, &ok) && ok;
}

/* A mutable duplicate, so a negative test can corrupt one field of a proof
 * that is known-good and change nothing else. */
static struct ci_merkle_proof *cmp_dup(const struct ci_merkle_proof *src)
{
    struct ci_merkle_proof *d = ci_merkle_proof_alloc();
    if (d) memcpy(d, src, sizeof(*d));
    return d;
}

static bool cmp_verifies(const struct ci_merkle_proof *p,
                         const struct zcl_sha3_digest *claimed,
                         const struct zcl_sha3_digest *root)
{
    bool ok = false;
    return ci_merkle_proof_verify(p, claimed, root, &ok) && ok;
}

/* ── 1: round trip over a leaf, a directory, the root, and a deep path ── */
static int test_cmp_round_trip(void)
{
    int failures = 0;
    TEST("code_merkle_proof: a leaf, a directory node, the root, and a deep "
         "path each prove and verify standalone, and survive the wire") {
        cmp_reset();
        ASSERT(cmp_fixture(CMP_FIX));

        struct ci_merkle *m = ci_merkle_build_cold(CMP_FIX, NULL);
        ASSERT(m);
        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        ASSERT(p);

        struct zcl_sha3_digest d, root;
        static const char *const paths[] = {
            "lib/net/src/cmp_a.c",          /* an ordinary leaf */
            "lib/net",                      /* a directory node */
            "",                             /* the root itself */
            "lib/net/include/net/cmp_a.h",  /* the deep path */
            "tools/wide",                   /* the wide directory node */
            "tools/wide/cmp_w000.c",        /* a leaf under it */
        };
        for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            ASSERT(cmp_prove_ok(m, paths[i], p, &d, &root));
            ASSERT(strcmp(p->path, paths[i]) == 0);
            /* the root is the one path with nothing above it */
            ASSERT((paths[i][0] == '\0') == (p->nlevels == 0));
            ASSERT(p->nlevels <= CI_MERKLE_PROOF_MAX_LEVELS);
            ASSERT(p->nchildren <= CI_MERKLE_PROOF_MAX_CHILDREN);

            /* the wire form is the shippable one: encode, decode, verify with
             * nothing but bytes + a claimed digest + a trusted root. */
            size_t want = ci_merkle_proof_wire_size(p);
            ASSERT(want > 0 && want <= CI_MERKLE_PROOF_WIRE_MAX);
            size_t n = ci_merkle_proof_encode(p, cmp_wire, want);
            ASSERT(n == want);
            char got_path[256];
            uint8_t got_kind = 0xff;
            bool ok = false;
            bool call = ci_merkle_proof_verify_bytes(cmp_wire, n, &d, &root,
                                                     got_path, &got_kind, &ok);
            ASSERT(call && ok);
            ASSERT(strcmp(got_path, paths[i]) == 0);
            ASSERT(got_kind == p->kind);
        }

        /* the deep path really is deep: four directories plus the root */
        ASSERT(cmp_prove_ok(m, "lib/net/include/net/cmp_a.h", p, &d, &root));
        ASSERT(p->nlevels == 5);
        ASSERT(strcmp(p->level[0].path, "lib/net/include/net") == 0);
        ASSERT(strcmp(p->level[1].path, "lib/net/include") == 0);
        ASSERT(strcmp(p->level[2].path, "lib/net") == 0);
        ASSERT(strcmp(p->level[3].path, "lib") == 0);
        ASSERT(strcmp(p->level[4].path, "") == 0);
        ASSERT(p->kind == CI_MERKLE_KIND_FILE);

        /* a directory node's proof is a directory's proof */
        ASSERT(cmp_prove_ok(m, "lib/net", p, &d, &root));
        ASSERT(p->kind == CI_MERKLE_KIND_DIR);

        /* an absent path is an answer, not a failure */
        bool found = true;
        ASSERT(ci_merkle_prove(m, "lib/net/src/nope.c", p, &d, &found));
        ASSERT(!found);

        ci_merkle_proof_free(p);
        ci_merkle_free(m);
        cmp_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 2: the cost of a non-binary tree, measured ── */
static int test_cmp_cost_is_sum_of_siblings(void)
{
    int failures = 0;
    TEST("code_merkle_proof: proof size is the SUM of sibling counts along the "
         "path, and a wide directory is where that bites") {
        cmp_reset();
        ASSERT(cmp_fixture(CMP_FIX));

        struct ci_merkle *m = ci_merkle_build_cold(CMP_FIX, NULL);
        ASSERT(m);
        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        ASSERT(p);
        struct zcl_sha3_digest d, root;

        /* narrow path: lib/net/src has 2 files; lib/net has 2 dirs; lib has 2
         * dirs; the root has 3 top-level dirs. */
        ASSERT(cmp_prove_ok(m, "lib/net/src/cmp_a.c", p, &d, &root));
        uint32_t narrow_kids = p->nchildren;
        size_t narrow_bytes = ci_merkle_proof_wire_size(p);
        ASSERT(p->nlevels == 4);
        uint32_t sum = 0;
        for (uint32_t i = 0; i < p->nlevels; i++) sum += p->level[i].nchildren;
        ASSERT(sum == narrow_kids);

        /* wide path: tools/wide holds CMP_WIDE files, so its level alone
         * contributes CMP_WIDE sibling records. */
        ASSERT(cmp_prove_ok(m, "tools/wide/cmp_w042.c", p, &d, &root));
        uint32_t wide_kids = p->nchildren;
        size_t wide_bytes = ci_merkle_proof_wire_size(p);
        ASSERT(p->nlevels == 3);
        ASSERT(p->level[0].nchildren == CMP_WIDE);
        ASSERT(wide_kids >= CMP_WIDE);
        /* the whole point: widening ONE directory widens the proof linearly */
        ASSERT(wide_kids > narrow_kids + 50);
        ASSERT(wide_bytes > narrow_bytes);

        printf("\n    [fixture cost] narrow leaf: %u siblings, %zu bytes"
               "  |  wide leaf (%d-file dir): %u siblings, %zu bytes\n    ",
               narrow_kids, narrow_bytes, CMP_WIDE, wide_kids, wide_bytes);

        ci_merkle_proof_free(p);
        ci_merkle_free(m);
        cmp_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3 + 5 + 6: path binding, root binding, kind binding ── */
static int test_cmp_path_root_kind_binding(void)
{
    int failures = 0;
    TEST("code_merkle_proof: a proof for path A does not verify for path B, "
         "against another root, or with leaf and directory kinds swapped") {
        cmp_reset();
        ASSERT(cmp_fixture(CMP_FIX));

        struct ci_merkle *m = ci_merkle_build_cold(CMP_FIX, NULL);
        ASSERT(m);
        struct ci_merkle_proof *pa = ci_merkle_proof_alloc();
        struct ci_merkle_proof *pb = ci_merkle_proof_alloc();
        struct ci_merkle_proof *pd = ci_merkle_proof_alloc();
        ASSERT(pa && pb && pd);

        struct zcl_sha3_digest da, db, dd, root;
        ASSERT(cmp_prove_ok(m, "lib/net/src/cmp_a.c", pa, &da, &root));
        ASSERT(cmp_prove_ok(m, "lib/net/src/cmp_b.c", pb, &db, &root));
        ASSERT(cmp_prove_ok(m, "lib/net", pd, &dd, &root));
        ASSERT(memcmp(da.bytes, db.bytes, 32) != 0);

        /* A's proof with B's digest, and B's proof with A's digest */
        ASSERT(!cmp_verifies(pa, &db, &root));
        ASSERT(!cmp_verifies(pb, &da, &root));

        /* Re-labelling A's proof as B does not rescue it: the child record at
         * the folded index still names cmp_a.c. */
        struct ci_merkle_proof *mut = cmp_dup(pa);
        ASSERT(mut);
        snprintf(mut->path, sizeof(mut->path), "%s", "lib/net/src/cmp_b.c");
        bool relabelled = cmp_verifies(mut, &da, &root) ||
                          cmp_verifies(mut, &db, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!relabelled);

        /* Moving the proof to a path in a different directory breaks the
         * level-is-my-parent chain outright. */
        mut = cmp_dup(pa);
        ASSERT(mut);
        snprintf(mut->path, sizeof(mut->path), "%s", "lib/crypto/src/cmp_c.c");
        bool moved = cmp_verifies(mut, &da, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!moved);

        /* a root the proof was not built under */
        struct zcl_sha3_digest other = root;
        other.bytes[0] ^= 0x01;
        ASSERT(!cmp_verifies(pa, &da, &other));
        ASSERT(!cmp_verifies(pd, &dd, &other));

        /* kind binding, both directions. A leaf digest presented as a
         * directory digest fails, and a directory digest presented as a leaf
         * fails, because the folded child record carries the kind byte that
         * went into the parent's preimage. */
        mut = cmp_dup(pa);
        ASSERT(mut);
        mut->kind = CI_MERKLE_KIND_DIR;
        bool leaf_as_dir = cmp_verifies(mut, &da, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!leaf_as_dir);

        mut = cmp_dup(pd);
        ASSERT(mut);
        mut->kind = CI_MERKLE_KIND_FILE;
        bool dir_as_leaf = cmp_verifies(mut, &dd, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!dir_as_leaf);

        /* and a directory's digest cannot be smuggled in as the leaf claim */
        ASSERT(!cmp_verifies(pa, &dd, &root));
        ASSERT(!cmp_verifies(pd, &da, &root));

        ci_merkle_proof_free(pa);
        ci_merkle_proof_free(pb);
        ci_merkle_proof_free(pd);
        ci_merkle_free(m);
        cmp_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: every sibling is bound — name, kind, digest, and order ── */
static int test_cmp_sibling_binding(void)
{
    int failures = 0;
    TEST("code_merkle_proof: altering any sibling's name, kind, or digest, or "
         "reordering two siblings, breaks verification") {
        cmp_reset();
        ASSERT(cmp_fixture(CMP_FIX));

        struct ci_merkle *m = ci_merkle_build_cold(CMP_FIX, NULL);
        ASSERT(m);
        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        ASSERT(p);
        struct zcl_sha3_digest d, root;
        /* the wide level gives many OFF-PATH siblings to attack */
        ASSERT(cmp_prove_ok(m, "tools/wide/cmp_w042.c", p, &d, &root));
        ASSERT(p->level[0].nchildren == CMP_WIDE);

        /* every sibling in the widest level, one at a time: flip one digest
         * bit and the proof must die. Counted, not asserted in prose. */
        uint32_t base = p->level[0].first_child;
        uint32_t survived = 0;
        for (uint32_t i = 0; i < p->level[0].nchildren; i++) {
            struct ci_merkle_proof *mut = cmp_dup(p);
            ASSERT(mut);
            mut->children[base + i].digest.bytes[7] ^= 0x01;
            if (cmp_verifies(mut, &d, &root)) survived++;
            ci_merkle_proof_free(mut);
        }
        ASSERT(survived == 0);

        /* an OFF-PATH sibling's name: renaming it changes the parent preimage
         * even though nothing on the path moved. Pick a neighbour, not the
         * folded slot, and keep the canonical order intact so the failure can
         * only come from the hash. */
        uint32_t victim = p->level[0].index == 0 ? 1u : 0u;
        struct ci_merkle_proof *mut = cmp_dup(p);
        ASSERT(mut);
        mut->children[base + victim].name[
            strlen(mut->children[base + victim].name) - 1] = 'Z';
        bool renamed = cmp_verifies(mut, &d, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!renamed);

        /* an off-path sibling's kind byte */
        mut = cmp_dup(p);
        ASSERT(mut);
        mut->children[base + victim].kind =
            mut->children[base + victim].kind == CI_MERKLE_KIND_FILE
                ? (uint8_t)CI_MERKLE_KIND_DIR
                : (uint8_t)CI_MERKLE_KIND_FILE;
        bool rekinded = cmp_verifies(mut, &d, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!rekinded);

        /* reordering two siblings: the child list IS the preimage, in one
         * fixed order, so a swap cannot be repaired by moving the index. */
        mut = cmp_dup(p);
        ASSERT(mut);
        struct ci_merkle_proof_child tmp = mut->children[base + 0];
        mut->children[base + 0] = mut->children[base + 1];
        mut->children[base + 1] = tmp;
        if (mut->level[0].index == 0) mut->level[0].index = 1;
        else if (mut->level[0].index == 1) mut->level[0].index = 0;
        bool reordered = cmp_verifies(mut, &d, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!reordered);

        /* dropping a sibling entirely */
        mut = cmp_dup(p);
        ASSERT(mut);
        uint32_t drop = mut->level[0].nchildren - 1;
        if (mut->level[0].index != drop) {
            mut->level[0].nchildren--;
            bool shortened = cmp_verifies(mut, &d, &root);
            ci_merkle_proof_free(mut);
            ASSERT(!shortened);
        } else {
            ci_merkle_proof_free(mut);
        }

        /* pointing the fold at a different (valid) sibling */
        mut = cmp_dup(p);
        ASSERT(mut);
        mut->level[0].index = (mut->level[0].index + 1) % mut->level[0].nchildren;
        bool misindexed = cmp_verifies(mut, &d, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!misindexed);

        /* and an out-of-range index is refused rather than read */
        mut = cmp_dup(p);
        ASSERT(mut);
        mut->level[0].index = mut->level[0].nchildren;
        bool oob = cmp_verifies(mut, &d, &root);
        ci_merkle_proof_free(mut);
        ASSERT(!oob);

        ci_merkle_proof_free(p);
        ci_merkle_free(m);
        cmp_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 7: the wire form refuses garbage instead of half-parsing it ── */
static int test_cmp_wire_hygiene(void)
{
    int failures = 0;
    TEST("code_merkle_proof: truncated, mis-domained, and bit-flipped proof "
         "images decode false, and a short buffer refuses to encode") {
        cmp_reset();
        ASSERT(cmp_fixture(CMP_FIX));

        struct ci_merkle *m = ci_merkle_build_cold(CMP_FIX, NULL);
        ASSERT(m);
        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        struct ci_merkle_proof *out = ci_merkle_proof_alloc();
        ASSERT(p && out);
        struct zcl_sha3_digest d, root;
        ASSERT(cmp_prove_ok(m, "lib/net/include/net/cmp_a.h", p, &d, &root));

        size_t want = ci_merkle_proof_wire_size(p);
        ASSERT(want > 0);
        ASSERT(ci_merkle_proof_encode(p, cmp_wire, want) == want);

        /* the honest image round-trips and re-verifies */
        ASSERT(ci_merkle_proof_decode(cmp_wire, want, out));
        ASSERT(cmp_verifies(out, &d, &root));
        ASSERT(strcmp(out->path, p->path) == 0);
        ASSERT(out->nlevels == p->nlevels && out->nchildren == p->nchildren);
        /* re-encoding the decoded proof is byte-identical: one canonical form */
        size_t n2 = ci_merkle_proof_encode(out, cmp_wire2, want);
        ASSERT(n2 == want && memcmp(cmp_wire2, cmp_wire, want) == 0);

        /* a short buffer is refused, never short-written */
        ASSERT(ci_merkle_proof_encode(p, cmp_wire, want - 1) == 0);
        ASSERT(ci_merkle_proof_encode(p, cmp_wire, 0) == 0);
        ASSERT(ci_merkle_proof_encode(p, cmp_wire, want) == want);

        /* every truncation of the image is rejected */
        uint32_t accepted = 0;
        for (size_t cut = 1; cut < want; cut += (want / 97) + 1) {
            if (ci_merkle_proof_decode(cmp_wire, cut, out)) accepted++;
        }
        ASSERT(accepted == 0);

        /* wrong domain string */
        cmp_wire[0] ^= 0x20;
        ASSERT(!ci_merkle_proof_decode(cmp_wire, want, out));
        cmp_wire[0] ^= 0x20;

        /* a flipped bit anywhere in the body either fails to decode or fails
         * to verify — it never silently verifies. */
        uint32_t silent = 0;
        for (size_t i = 0; i < want; i += (want / 211) + 1) {
            cmp_wire[i] ^= 0x01;
            if (ci_merkle_proof_decode(cmp_wire, want, out) &&
                cmp_verifies(out, &d, &root))
                silent++;
            cmp_wire[i] ^= 0x01;
        }
        ASSERT(silent == 0);

        ci_merkle_proof_free(out);
        ci_merkle_proof_free(p);
        ci_merkle_free(m);
        cmp_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 8: a real path, a real cold-built root, the byte-only verifier ── */
static int test_cmp_real_tree(void)
{
    int failures = 0;
    TEST("code_merkle_proof: a real repository path proves against a real "
         "cold-built root through the byte-only verifier") {
        struct ci_merkle *m = ci_merkle_build_cold(".", NULL);
        ASSERT(m);
        struct ci_merkle_node rn;
        ASSERT(ci_merkle_root(m, &rn));

        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        ASSERT(p);
        struct zcl_sha3_digest d;
        struct zcl_sha3_digest root = rn.digest;

        /* One narrow module path and one path under the widest directory in
         * the tree, so the reported numbers bracket the real cost. */
        static const char *const real_paths[] = {
            "lib/codeindex/src/codeindex_merkle.c",
            "lib/codeindex/include/codeindex/codeindex_merkle.h",
            "lib/codeindex",
            "lib/test/src/test_code_merkle_proof.c",
        };
        for (unsigned i = 0; i < sizeof(real_paths) / sizeof(real_paths[0]);
             i++) {
            bool found = false;
            ASSERT(ci_merkle_prove(m, real_paths[i], p, &d, &found));
            ASSERT(found);
            size_t want = ci_merkle_proof_wire_size(p);
            ASSERT(want > 0 && want <= CI_MERKLE_PROOF_WIRE_MAX);
            size_t n = ci_merkle_proof_encode(p, cmp_wire, want);
            ASSERT(n == want);

            /* the receiver holds bytes, a claimed digest, and a root — the
             * tree is not in scope and cannot be. */
            char got_path[256];
            uint8_t got_kind = 0xff;
            bool ok = false;
            bool call = ci_merkle_proof_verify_bytes(cmp_wire, n, &d, &root,
                                                     got_path, &got_kind, &ok);
            uint32_t widest = 0;
            for (uint32_t k = 0; k < p->nlevels; k++)
                if (p->level[k].nchildren > widest)
                    widest = p->level[k].nchildren;
            printf("\n    [real cost] %-52s levels=%u siblings=%u "
                   "widest_level=%u bytes=%zu",
                   real_paths[i], p->nlevels, p->nchildren, widest, want);
            ASSERT(call && ok);
            ASSERT(strcmp(got_path, real_paths[i]) == 0);

            /* the same proof under a root it was not built under */
            struct zcl_sha3_digest wrong = root;
            wrong.bytes[31] ^= 0x80;
            ASSERT(!cmp_verifies(p, &d, &wrong));
        }
        printf("\n    ");

        /* the whole tree proves itself with an empty path and zero levels */
        bool found = false;
        ASSERT(ci_merkle_prove(m, "", p, &d, &found));
        ASSERT(found && p->nlevels == 0);
        ASSERT(memcmp(d.bytes, root.bytes, 32) == 0);
        ASSERT(cmp_verifies(p, &d, &root));

        ci_merkle_proof_free(p);
        ci_merkle_free(m);
        PASS();
    } _test_next:;
    return failures;
}

/* ── 9: the child-order rule, on the case that discriminates the two possible
 * justifications for it ── */
static int test_cmp_child_order_prefix_property(void)
{
    int failures = 0;
    TEST("code_merkle_proof: a file, a directory, and a longer file sharing a "
         "prefix order by the prefix rule, not by the ASCII rank of '/'") {
        cmp_reset();
        /* `ab.c`, `ab/` and `ab_z.c` in one directory is the case where the
         * two candidate explanations of the child order disagree. The keys are
         * "ab.c" (0x2e at index 2), "ab/" (0x2f) and "ab_z.c" (0x5f), so the
         * canonical order is ab.c < ab < ab_z.c — which is what strcmp over
         * the children's FULL paths gives, and the opposite of what an "'/'
         * sorts above every identifier character" argument would give for the
         * last pair. The proof carries the child list verbatim, so this is
         * observable rather than inferred. */
        ASSERT(cmp_write(CMP_FIX, "core/ab.c",
                         "/* ab — order fixture. */\nint ab(void)\n{\n"
                         "    return 1;\n}\n"));
        ASSERT(cmp_write(CMP_FIX, "core/ab/inner.c",
                         "/* inner — order fixture. */\nint inner(void)\n{\n"
                         "    return 2;\n}\n"));
        ASSERT(cmp_write(CMP_FIX, "core/ab_z.c",
                         "/* ab_z — order fixture. */\nint ab_z(void)\n{\n"
                         "    return 3;\n}\n"));

        struct ci_merkle *m = ci_merkle_build_cold(CMP_FIX, NULL);
        ASSERT(m);
        struct ci_merkle_proof *p = ci_merkle_proof_alloc();
        ASSERT(p);
        struct zcl_sha3_digest d, root;

        ASSERT(cmp_prove_ok(m, "core/ab.c", p, &d, &root));
        ASSERT(p->nlevels == 2);
        ASSERT(strcmp(p->level[0].path, "core") == 0);
        ASSERT(p->level[0].nchildren == 3);
        uint32_t b = p->level[0].first_child;
        ASSERT(strcmp(p->children[b + 0].name, "ab.c") == 0);
        ASSERT(p->children[b + 0].kind == CI_MERKLE_KIND_FILE);
        ASSERT(strcmp(p->children[b + 1].name, "ab") == 0);
        ASSERT(p->children[b + 1].kind == CI_MERKLE_KIND_DIR);
        ASSERT(strcmp(p->children[b + 2].name, "ab_z.c") == 0);
        ASSERT(p->children[b + 2].kind == CI_MERKLE_KIND_FILE);
        ASSERT(p->level[0].index == 0);

        /* all three siblings prove and verify from the same root */
        ASSERT(cmp_prove_ok(m, "core/ab", p, &d, &root));
        ASSERT(p->kind == CI_MERKLE_KIND_DIR && p->level[0].index == 1);
        ASSERT(cmp_prove_ok(m, "core/ab_z.c", p, &d, &root));
        ASSERT(p->kind == CI_MERKLE_KIND_FILE && p->level[0].index == 2);
        ASSERT(cmp_prove_ok(m, "core/ab/inner.c", p, &d, &root));
        ASSERT(p->nlevels == 3);

        ci_merkle_proof_free(p);
        ci_merkle_free(m);
        cmp_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_code_merkle_proof(void)
{
    int failures = 0;
    failures += test_cmp_round_trip();
    failures += test_cmp_cost_is_sum_of_siblings();
    failures += test_cmp_path_root_kind_binding();
    failures += test_cmp_sibling_binding();
    failures += test_cmp_wire_hygiene();
    failures += test_cmp_child_order_prefix_property();
    failures += test_cmp_real_tree();
    return failures;
}
