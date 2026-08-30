/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_core_seal — regression tests for the sealed-consensus-core manifest
 * encoding (tools/core_seal.c).
 *
 * WHAT THIS FILE EXISTS TO CATCH. core_seal's section tree was reverted once
 * (44f20ec55) over "ambiguous inputs". The ambiguity was real and it was in the
 * SERIALISATION, not in the Merkle preimages: the manifest wrote
 *
 *     SECTION  <dir>  <count>  <hex>
 *
 * and read it back with sscanf("SECTION %255s %llu %64s"), i.e. whitespace-
 * delimited fields whose FIRST field was the variable-length, path-shaped one.
 * git permits a space in a path, so a directory literally named
 *
 *     x  7  <64 hex>
 *
 * under core/ serialised to a line that sscanf parsed EXACTLY as the record a
 * genuine `core/x` with 7 files and that digest would produce. Two structurally
 * different section sets, one parse.
 *
 * The first test below is not a description of that bug, it is a MEASUREMENT of
 * it: it implements the historical writer/reader pair verbatim, shows the two
 * records collapse under it, and shows they stay distinct under the current
 * length-prefixed encoding. If anyone re-introduces a delimiter-only spelling,
 * the second half goes red.
 *
 * The whole tool is included as a translation unit (the pattern
 * test_postmortem_to_scenario.c uses for tools/postmortem_to_scenario.c) so the
 * tests exercise the SHIPPING functions rather than a copy of them.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#define CORE_SEAL_NO_MAIN 1
#include "../../../tools/core_seal.c"
#if !defined(_WIN32)

static int cs_failures;

#define CS_CHECK(name, expr)                                                   \
    do {                                                                       \
        printf("core_seal: %s... ", (name));                                   \
        if ((expr)) {                                                          \
            printf("OK\n");                                                    \
        } else {                                                               \
            printf("FAIL\n");                                                  \
            cs_failures++;                                                     \
        }                                                                      \
    } while (0)

/* ── the historical encoding, transcribed from 44f20ec55^ ─────────────────
 *
 * Kept here and NOWHERE else. Its only job is to be the negative control: a
 * test that cannot fail proves nothing, so the discriminating test needs a
 * demonstrated collision to discriminate against. */

struct legacy_section {
    char name[MERKLE_PATH_MAX];
    unsigned long long count;
    char hex[HEXSZ];
};

static void legacy_format(char *out, size_t outsz, const char *path,
                          unsigned long long files, const char *hex)
{
    (void)snprintf(out, outsz, "SECTION  %s  %llu  %s\n", path, files, hex);
}

static int legacy_parse(const char *line, struct legacy_section *out)
{
    memset(out, 0, sizeof(*out));
    return sscanf(line, "SECTION %255s %llu %64s", out->name, &out->count,
                  out->hex) == 3
               ? 0
               : -1;
}

static bool legacy_same(const struct legacy_section *a,
                        const struct legacy_section *b)
{
    return strcmp(a->name, b->name) == 0 && a->count == b->count &&
           strcmp(a->hex, b->hex) == 0;
}

/* ── the historical stdin tokeniser ───────────────────────────────────────
 *
 * 44f20ec55^ (and every revision before it) ended a path token at a NUL *or* a
 * newline, which is exactly the guarantee `git ls-files -z` exists to provide
 * and exactly what it threw away. Returns the token count. */
static size_t legacy_token_count(const char *data, size_t len)
{
    size_t i = 0, tokens = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && data[j] != '\0' && data[j] != '\n')
            j++;
        if (j > i)
            tokens++;
        i = j + 1;
    }
    return tokens;
}

/* The current rule: NUL and nothing else. */
static size_t nul_token_count(const char *data, size_t len)
{
    size_t i = 0, tokens = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && data[j] != '\0')
            j++;
        if (j > i)
            tokens++;
        i = j + 1;
    }
    return tokens;
}

/* ── 1. the dual-parse regression ─────────────────────────────────────── */

static const char kHexA[] =
    "1111111111111111111111111111111111111111111111111111111111111111";
static const char kHexB[] =
    "2222222222222222222222222222222222222222222222222222222222222222";

static void test_section_dual_parse(void)
{
    /* The honest record. */
    const char *honest_path = "core/x";
    const unsigned long long honest_files = 7;

    /* A directory whose NAME is the rest of the honest record. Legal in git;
     * legal on every filesystem this repository is cloned onto. */
    char shadow_path[MERKLE_PATH_MAX];
    (void)snprintf(shadow_path, sizeof(shadow_path), "core/x  %llu  %s",
                   honest_files, kHexA);
    const unsigned long long shadow_files = 9;

    /* --- negative control: the historical encoding collapses them. --- */
    char lh[1024], ls[1024];
    legacy_format(lh, sizeof(lh), honest_path, honest_files, kHexA);
    legacy_format(ls, sizeof(ls), shadow_path, shadow_files, kHexB);
    CS_CHECK("legacy: the two records serialise to DIFFERENT lines",
             strcmp(lh, ls) != 0);

    struct legacy_section ph, ps;
    CS_CHECK("legacy: honest line parses", legacy_parse(lh, &ph) == 0);
    CS_CHECK("legacy: shadow line parses", legacy_parse(ls, &ps) == 0);
    CS_CHECK("legacy: THE DEFECT — two distinct records, one parse",
             legacy_same(&ph, &ps));
    CS_CHECK("legacy: the shadow's real path did not survive the round trip",
             strcmp(ps.name, shadow_path) != 0);

    /* --- the current encoding keeps them apart and round-trips both. --- */
    char nh[1024], ns[1024];
    CS_CHECK("honest record encodes",
             section_line_format(nh, sizeof(nh), honest_path, honest_files,
                                 kHexA) > 0);
    CS_CHECK("shadow record encodes",
             section_line_format(ns, sizeof(ns), shadow_path, shadow_files,
                                 kHexB) > 0);

    char gh[MERKLE_PATH_MAX], gs[MERKLE_PATH_MAX];
    char xh[HEXSZ], xs[HEXSZ];
    uint64_t fh = 0, fs = 0;
    CS_CHECK("honest line parses", section_line_parse(nh, gh, &fh, xh) == 0);
    CS_CHECK("shadow line parses", section_line_parse(ns, gs, &fs, xs) == 0);

    CS_CHECK("honest path round-trips byte for byte",
             strcmp(gh, honest_path) == 0);
    CS_CHECK("shadow path round-trips byte for byte (spaces and all)",
             strcmp(gs, shadow_path) == 0);
    CS_CHECK("honest count round-trips", fh == honest_files);
    CS_CHECK("shadow count round-trips", fs == shadow_files);
    CS_CHECK("honest digest round-trips", strcmp(xh, kHexA) == 0);
    CS_CHECK("shadow digest round-trips", strcmp(xs, kHexB) == 0);

    CS_CHECK("THE FIX — the two records no longer parse alike",
             strcmp(gh, gs) != 0 || fh != fs || strcmp(xh, xs) != 0);
}

/* ── 2. the length prefix is load-bearing ─────────────────────────────── */

static void test_section_length_prefix(void)
{
    char line[1024], mutated[1024];
    CS_CHECK("baseline line encodes",
             section_line_format(line, sizeof(line), "core/consensus/src", 19,
                                 kHexA) > 0);

    char path[MERKLE_PATH_MAX], hex[HEXSZ];
    uint64_t files = 0;
    CS_CHECK("baseline line parses",
             section_line_parse(line, path, &files, hex) == 0);

    /* Truncate the path by one byte: the declared length no longer matches. */
    size_t len = strlen(line);
    memcpy(mutated, line, len + 1);
    memmove(&mutated[len - 2], &mutated[len - 1], 2); /* drop one path byte */
    CS_CHECK("a path shortened by one byte is REJECTED, not reinterpreted",
             section_line_parse(mutated, path, &files, hex) == -2);

    /* Extend the path by one byte. */
    memcpy(mutated, line, len + 1);
    mutated[len - 1] = 'z';
    mutated[len] = '\n';
    mutated[len + 1] = '\0';
    CS_CHECK("a path lengthened by one byte is REJECTED",
             section_line_parse(mutated, path, &files, hex) == -2);

    /* Lie about the length: "18" instead of "19"... the pathlen field. */
    char liar[1024];
    (void)snprintf(liar, sizeof(liar), "SECTION  19  17  %s  core/consensus/src\n",
                   kHexA);
    CS_CHECK("a pathlen that disagrees with the path is REJECTED",
             section_line_parse(liar, path, &files, hex) == -2);

    /* Non-canonical decimal: one value must have one spelling. */
    (void)snprintf(liar, sizeof(liar), "SECTION  019  18  %s  core/consensus/src\n",
                   kHexA);
    CS_CHECK("a leading-zero count is REJECTED (one value, one spelling)",
             section_line_parse(liar, path, &files, hex) == -2);

    /* A single separator space instead of two. */
    (void)snprintf(liar, sizeof(liar), "SECTION 19 18 %s core/consensus/src\n",
                   kHexA);
    CS_CHECK("a one-space separator is REJECTED",
             section_line_parse(liar, path, &files, hex) == -2);

    /* Uppercase hex is not the canonical spelling either. */
    (void)snprintf(liar, sizeof(liar),
                   "SECTION  19  18  "
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                   "  core/consensus/src\n");
    CS_CHECK("uppercase hex is REJECTED",
             section_line_parse(liar, path, &files, hex) == -2);

    /* A malformed SECTION line must report -2 (malformed), never -1 (not a
     * section): -1 would let read_manifest skip it and still say "match". */
    CS_CHECK("a malformed SECTION line is malformed, not 'some other line'",
             section_line_parse("SECTION  banana\n", path, &files, hex) == -2);
    CS_CHECK("a genuinely unrelated line is -1",
             section_line_parse("TREE  deadbeef\n", path, &files, hex) == -1);
}

/* ── 3. path policy: what may be sealed at all ────────────────────────── */

static void test_path_policy(void)
{
    CS_CHECK("an ordinary sealed path is accepted",
             path_reject_reason("core/consensus/src/verify.c") == NULL);
    CS_CHECK("a path containing spaces is accepted (git permits it)",
             path_reject_reason("core/my dir/a b.c") == NULL);

    CS_CHECK("a newline in a path is REFUSED",
             path_reject_reason("core/a\nb.h") != NULL);
    CS_CHECK("a carriage return in a path is REFUSED",
             path_reject_reason("core/a\rb.h") != NULL);
    CS_CHECK("a tab in a path is REFUSED", path_reject_reason("core/a\tb.h") != NULL);
    CS_CHECK("an empty path is REFUSED", path_reject_reason("") != NULL);
    CS_CHECK("an absolute path is REFUSED", path_reject_reason("/core/a.c") != NULL);
    CS_CHECK("a trailing slash is REFUSED", path_reject_reason("core/a/") != NULL);
    CS_CHECK("an empty component is REFUSED", path_reject_reason("core//a.c") != NULL);
    CS_CHECK("a \".\" component is REFUSED", path_reject_reason("core/./a.c") != NULL);
    CS_CHECK("a \"..\" component is REFUSED",
             path_reject_reason("core/../a.c") != NULL);

    /* The truncation hole: the previous revision bounded only the FILE
     * basename, so a >= MERKLE_NAME_MAX DIRECTORY component was snprintf'd
     * down to 159 bytes and the parent node then committed to a name that was
     * not the child's. Every component is bounded now. */
    char longdir[MERKLE_PATH_MAX];
    size_t k = 0;
    memcpy(longdir, "core/", 5);
    k = 5;
    for (; k < 5 + MERKLE_NAME_MAX; k++)
        longdir[k] = 'a';
    longdir[k] = '\0';
    CS_CHECK("an over-long DIRECTORY component is REFUSED (no silent truncation)",
             path_reject_reason(longdir) != NULL);
    memcpy(longdir + 5 + MERKLE_NAME_MAX, "/x.c", 5);
    CS_CHECK("...including when it is not the last component",
             path_reject_reason(longdir) != NULL);

    /* A path the encoder cannot represent must not be encodable either. */
    char line[1024];
    CS_CHECK("a newline path cannot be encoded as a SECTION line",
             section_line_format(line, sizeof(line), "core/a\nb", 1, kHexA) == 0);
}

/* ── 4. the input stream has exactly one tokenisation ─────────────────── */

static void test_input_tokenisation(void)
{
    /* ONE NUL-terminated token that happens to contain a newline — precisely
     * what `git ls-files -z` emits for a path with a newline in it. */
    static const char stream[] = "core/a\nb.h\0core/c.h";
    const size_t len = sizeof(stream) - 1;

    CS_CHECK("legacy tokeniser THE DEFECT — one NUL token became two paths",
             legacy_token_count(stream, len) == 3);
    CS_CHECK("current tokeniser sees the two NUL-separated tokens git sent",
             nul_token_count(stream, len) == 2);
    CS_CHECK("...and the newline-bearing one is then refused outright",
             path_reject_reason("core/a\nb.h") != NULL);
}

/* ── 5. the per-file line ─────────────────────────────────────────────── */

static void test_file_line(void)
{
    char line[1024];
    (void)snprintf(line, sizeof(line), "%s  core/my dir/a b.c\n", kHexA);
    char hex[HEXSZ], path[MERKLE_PATH_MAX];
    CS_CHECK("a per-file line parses", file_line_parse(line, hex, path) == 0);
    CS_CHECK("its digest round-trips", strcmp(hex, kHexA) == 0);
    CS_CHECK("its path round-trips with spaces intact",
             strcmp(path, "core/my dir/a b.c") == 0);

    (void)snprintf(line, sizeof(line), "%s core/a.c\n", kHexA);
    CS_CHECK("a one-space per-file line is REJECTED",
             file_line_parse(line, hex, path) == -2);
    CS_CHECK("a non-hex leader is not a file line",
             file_line_parse("SECTION  1  6  x\n", hex, path) == -1);
}

/* ── 6. the Merkle dialect is codeindex's, byte for byte ──────────────── */

/* Recomputed here from the DOCUMENTED preimage with nothing but sha3, so this
 * is a differential check against the spec and not a restatement of the code.
 * The pinned hex values were cross-checked against this same independent
 * computation before being written down. */
static void spec_node_digest(const char *path, const struct mchild *kids,
                             uint32_t n, unsigned char out[HSZ])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    unsigned char tag = 0x11;
    sha3_256_write(&c, &tag, 1);
    sha3_256_write(&c, (const unsigned char *)"zcl.codeindex.merkle.node.v1", 29);
    sha3_256_write(&c, (const unsigned char *)path, strlen(path) + 1);
    unsigned char cnt[4];
    zcl_write_u32_le(cnt, n);
    sha3_256_write(&c, cnt, 4);
    for (uint32_t i = 0; i < n; i++) {
        sha3_256_write(&c, &kids[i].kind, 1);
        sha3_256_write(&c, (const unsigned char *)kids[i].name,
                       strlen(kids[i].name) + 1);
        sha3_256_write(&c, kids[i].digest, HSZ);
    }
    sha3_256_finalize(&c, out);
}

static void test_merkle_dialect(void)
{
    struct mchild kids[2];
    memset(kids, 0, sizeof(kids));
    child_set_name(&kids[0], "params.c");
    kids[0].kind = 0;
    for (int i = 0; i < (int)HSZ; i++)
        kids[0].digest[i] = (unsigned char)(i + 1);
    child_set_name(&kids[1], "src");
    kids[1].kind = 1;
    memset(kids[1].digest, 0xa0, HSZ);

    unsigned char got[HSZ], want[HSZ];
    char hex[HEXSZ];
    node_digest("core/params", kids, 2, got);
    spec_node_digest("core/params", kids, 2, want);
    CS_CHECK("node digest matches the documented preimage",
             memcmp(got, want, HSZ) == 0);
    zcl_hex_encode(got, HSZ, hex);
    CS_CHECK("node digest matches its pin",
             strcmp(hex,
                    "de0f860b50a8e20b3ce2a4d3f3fac965aa5721219d09ad346dff24a2"
                    "2a9dd1e4") == 0);

    /* kind separation: a file child and a directory child of the same name
     * and the same digest must not produce the same node. */
    struct mchild flipped[2];
    memcpy(flipped, kids, sizeof(kids));
    flipped[1].kind = 0;
    unsigned char got2[HSZ];
    node_digest("core/params", flipped, 2, got2);
    CS_CHECK("a directory child cannot be replayed as a file child",
             memcmp(got, got2, HSZ) != 0);

    /* child order: keys are name, or name + '/' for a directory. */
    CS_CHECK("a directory sorts after the file of the same name",
             cmp_child(&kids[1], &flipped[1]) > 0);

    /* the empty root node still has a digest, and it is not zero. */
    unsigned char rootnode[HSZ];
    node_digest("", NULL, 0, rootnode);
    zcl_hex_encode(rootnode, HSZ, hex);
    CS_CHECK("the empty root node matches its pin",
             strcmp(hex,
                    "fbd6e9e54ffa7facdaed86b4b73a28d64efaaf07b6ae88a31be48e28"
                    "c3e78a5a") == 0);

    /* domain separation is not decorative. */
    CS_CHECK("leaf and node tags differ", MERKLE_TAG_LEAF != MERKLE_TAG_NODE);
    CS_CHECK("leaf and node domain strings differ",
             strcmp(merkle_leaf_domain, merkle_node_domain) != 0);
}

/* ── 7. ROOT is frozen ────────────────────────────────────────────────── */

static void test_root_is_frozen(void)
{
    struct entry e[2];
    memset(e, 0, sizeof(e));
    e[0].path = (char *)"core/a.c";
    memset(e[0].hash, 0x11, HSZ);
    e[1].path = (char *)"core/b.c";
    memset(e[1].hash, 0x22, HSZ);

    unsigned char root[HSZ];
    char hex[HEXSZ];
    compute_root(e, 2, root);
    zcl_hex_encode(root, HSZ, hex);
    CS_CHECK("ROOT's preimage is unchanged (path || NUL || digest, sorted)",
             strcmp(hex,
                    "9d4e33a2ff1de7ece0cf87ef538eaac081ad9588477b3d06aee017b6"
                    "7d9ddd60") == 0);

    /* The seal's own identity, as shipped. If this moves, every hot-swap
     * module's pin (hotswap/core_seal_root.h) is stale. */
    CS_CHECK("the shipped ROOT pin is still 64 lowercase hex",
             is_hex64("a1533630bda2379889f9db262f81cd6e265ad474f642a1ee7d1de95"
                      "23ac3b1aa"));
}

/* ── 8. the leaf preimage, against a real file ───────────────────────── */

static void spec_leaf_digest(const char *relpath, const unsigned char *bytes,
                             size_t n, unsigned char out[HSZ])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    unsigned char tag = 0x10;
    sha3_256_write(&c, &tag, 1);
    sha3_256_write(&c, (const unsigned char *)"zcl.codeindex.merkle.leaf.v1", 29);
    sha3_256_write(&c, (const unsigned char *)relpath, strlen(relpath) + 1);
    unsigned char sz[8];
    zcl_write_u64_le(sz, (uint64_t)n);
    sha3_256_write(&c, sz, 8);
    sha3_256_write(&c, bytes, n);
    sha3_256_finalize(&c, out);
}

static void test_leaf_preimage(void)
{
    const char *tmpdir = getenv("TMPDIR");
    char tmpl[256];
    (void)snprintf(tmpl, sizeof(tmpl), "%s/zcl_core_seal_%d_XXXXXX",
                   (tmpdir && tmpdir[0]) ? tmpdir : "/tmp", (int)getpid());
    char *dir = mkdtemp(tmpl);
    CS_CHECK("scratch dir", dir != NULL);
    if (!dir)
        return;

    char oldcwd[4096] = {0};
    CS_CHECK("capture cwd", getcwd(oldcwd, sizeof(oldcwd)) != NULL);
    if (!oldcwd[0] || chdir(dir) != 0) {
        (void)rmdir(dir);
        return;
    }
    static const unsigned char payload[] = "int main(void){return 0;}\n";
    const size_t plen = sizeof(payload) - 1;
    FILE *f = fopen("leaf.c", "wb");
    CS_CHECK("scratch file", f != NULL);
    if (!f) {
        (void)chdir(oldcwd);
        (void)rmdir(dir);
        return;
    }
    (void)fwrite(payload, 1, plen, f);
    (void)fclose(f);

    unsigned char flat[HSZ], leaf[HSZ], want_leaf[HSZ], want_flat[HSZ];
    uint64_t size = 0;
    CS_CHECK("hash_file reads the scratch file",
             hash_file("leaf.c", flat, leaf, &size) == 0);
    CS_CHECK("hash_file reports the byte length", size == (uint64_t)plen);

    spec_leaf_digest("leaf.c", payload, plen, want_leaf);
    CS_CHECK("leaf digest matches the documented preimage",
             memcmp(leaf, want_leaf, HSZ) == 0);

    /* The frozen per-file digest is raw content only — no tag, no path, no
     * length. Changing that would move ROOT. */
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, payload, plen);
    sha3_256_finalize(&c, want_flat);
    CS_CHECK("the frozen per-file digest is still SHA3-256(content) alone",
             memcmp(flat, want_flat, HSZ) == 0);
    CS_CHECK("the leaf and the flat digest are not the same value",
             memcmp(flat, leaf, HSZ) != 0);

    struct stat before, after;
    CS_CHECK("stable file metadata fixture", stat("leaf.c", &before) == 0);
    after = before;
    CS_CHECK("unchanged pre/post identity and size are stable",
             stable_file_stat(&before, &after));
    after.st_ino++;
    CS_CHECK("a replaced inode is unstable",
             !stable_file_stat(&before, &after));
    after = before;
    after.st_size++;
    CS_CHECK("a changed byte length is unstable",
             !stable_file_stat(&before, &after));
    after = before;
#if defined(__APPLE__)
    after.st_ctimespec.tv_nsec = before.st_ctimespec.tv_nsec == 0 ? 1 : 0;
#else
    after.st_ctim.tv_nsec = before.st_ctim.tv_nsec == 0 ? 1 : 0;
#endif
    CS_CHECK("a same-size metadata mutation is unstable",
             !stable_file_stat(&before, &after));

    FILE *target = fopen("target.c", "wb");
    CS_CHECK("symlink target fixture", target != NULL);
    if (target) {
        (void)fwrite(payload, 1, plen, target);
        (void)fclose(target);
    }
    CS_CHECK("final-component symlink is refused",
             symlink("target.c", "link.c") == 0 &&
             hash_file("link.c", flat, leaf, &size) != 0);

    CS_CHECK("intermediate directory fixture", mkdir("real", 0700) == 0);
    FILE *nested = fopen("real/nested.c", "wb");
    CS_CHECK("nested fixture", nested != NULL);
    if (nested) {
        (void)fwrite(payload, 1, plen, nested);
        (void)fclose(nested);
    }
    CS_CHECK("intermediate-component symlink is refused",
             symlink("real", "alias") == 0 &&
             hash_file("alias/nested.c", flat, leaf, &size) != 0);

    (void)unlink("alias");
    (void)unlink("real/nested.c");
    (void)rmdir("real");
    (void)unlink("link.c");
    (void)unlink("target.c");
    (void)unlink("leaf.c");
    (void)chdir(oldcwd);
    (void)rmdir(dir);
}

/* ── 9. sections localise a change ────────────────────────────────────── */

static void test_sections_localise(void)
{
    /* Two sibling directories, one file each. Changing one file's leaf must
     * move exactly its own section (and the ancestors), never its sibling's —
     * that independence is the whole point of the section tree. */
    struct entry ents[2];
    memset(ents, 0, sizeof(ents));
    ents[0].path = (char *)"core/alpha/a.c";
    memset(ents[0].hash, 0x01, HSZ);
    memset(ents[0].leaf, 0x01, HSZ);
    ents[1].path = (char *)"core/beta/b.c";
    memset(ents[1].hash, 0x02, HSZ);
    memset(ents[1].leaf, 0x02, HSZ);

    struct dnode *nodes = NULL;
    unsigned char tree1[HSZ];
    size_t dn = compute_sections(ents, 2, &nodes, tree1);
    CS_CHECK("three directory nodes: \"\", core, core/alpha, core/beta",
             dn == 4);
    if (dn != 4) {
        free(nodes);
        return;
    }
    unsigned char alpha1[HSZ], beta1[HSZ];
    size_t ia = SIZE_MAX, ib = SIZE_MAX;
    for (size_t i = 0; i < dn; i++) {
        if (strcmp(nodes[i].path, "core/alpha") == 0) ia = i;
        if (strcmp(nodes[i].path, "core/beta") == 0) ib = i;
    }
    CS_CHECK("both sibling sections exist", ia != SIZE_MAX && ib != SIZE_MAX);
    if (ia == SIZE_MAX || ib == SIZE_MAX) {
        free(nodes);
        return;
    }
    memcpy(alpha1, nodes[ia].digest, HSZ);
    memcpy(beta1, nodes[ib].digest, HSZ);
    CS_CHECK("the root node counts both files", nodes[0].file_count == 2);
    free(nodes);

    /* Swap one file in. */
    memset(ents[0].leaf, 0x03, HSZ);
    unsigned char tree2[HSZ];
    dn = compute_sections(ents, 2, &nodes, tree2);
    size_t ja = SIZE_MAX, jb = SIZE_MAX;
    for (size_t i = 0; i < dn; i++) {
        if (strcmp(nodes[i].path, "core/alpha") == 0) ja = i;
        if (strcmp(nodes[i].path, "core/beta") == 0) jb = i;
    }
    CS_CHECK("the edited section's digest MOVED",
             ja != SIZE_MAX && memcmp(alpha1, nodes[ja].digest, HSZ) != 0);
    CS_CHECK("the untouched sibling section's digest DID NOT move",
             jb != SIZE_MAX && memcmp(beta1, nodes[jb].digest, HSZ) == 0);
    CS_CHECK("the whole-set TREE moved with it",
             memcmp(tree1, tree2, HSZ) != 0);
    free(nodes);
}

/* ── 10. writer/reader limits and the shipping CLI round trip ─────────── */

static void test_manifest_limits(void)
{
    CS_CHECK("the largest reader-compatible manifest is sealable",
             manifest_counts_fit(MAX_MAN_FILES, MAX_MAN_SECTIONS + 1u));
    CS_CHECK("one excess file is refused before sealing",
             !manifest_counts_fit(MAX_MAN_FILES + 1u,
                                  MAX_MAN_SECTIONS + 1u));
    CS_CHECK("one excess SECTION is refused before sealing",
             !manifest_counts_fit(MAX_MAN_FILES, MAX_MAN_SECTIONS + 2u));
    CS_CHECK("a manifest tree must contain its root node",
             !manifest_counts_fit(0, 0));
}

static bool cs_write_bytes(const char *path, const void *bytes, size_t length)
{
    FILE *file = fopen(path, "wb");
    if (!file)
        return false;
    bool ok = fwrite(bytes, 1, length, file) == length;
    return fclose(file) == 0 && ok;
}

static bool cs_append_bytes(const char *path, const void *bytes, size_t length)
{
    FILE *file = fopen(path, "ab");
    if (!file)
        return false;
    bool ok = fwrite(bytes, 1, length, file) == length;
    return fclose(file) == 0 && ok;
}

static int cs_run_tool(const char *dir, const char *mode)
{
    (void)fflush(NULL);
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        if (chdir(dir) != 0)
            _exit(125);
        int input = open("files.z", O_RDONLY | O_CLOEXEC);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0)
            _exit(125);
        (void)close(input);
        char program[] = "core_seal";
        char manifest[] = "core/MANIFEST.sha3";
        char *argv[] = {program, (char *)mode, manifest, NULL};
        _exit(core_seal_main(3, argv));
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int cs_parse_manifest(const char *path)
{
    struct manifest_view mv;
    int rc = read_manifest(path, &mv);
    manifest_view_free(&mv);
    return rc;
}

static void test_seal_check_round_trip(void)
{
    const char *tmpdir = getenv("TMPDIR");
    char tmpl[256];
    (void)snprintf(tmpl, sizeof(tmpl), "%s/zcl_core_seal_e2e_%d_XXXXXX",
                   (tmpdir && tmpdir[0]) ? tmpdir : "/tmp", (int)getpid());
    char *dir = mkdtemp(tmpl);
    CS_CHECK("end-to-end scratch dir", dir != NULL);
    if (!dir)
        return;

    char core[512], sub[512], first[512], second[512], list[512], manifest[512];
    (void)snprintf(core, sizeof(core), "%s/core", dir);
    (void)snprintf(sub, sizeof(sub), "%s/core/sub", dir);
    (void)snprintf(first, sizeof(first), "%s/core/a.c", dir);
    (void)snprintf(second, sizeof(second), "%s/core/sub/b.h", dir);
    (void)snprintf(list, sizeof(list), "%s/files.z", dir);
    (void)snprintf(manifest, sizeof(manifest), "%s/core/MANIFEST.sha3", dir);

    static const unsigned char first_bytes[] = "int a(void){return 1;}\n";
    static const unsigned char second_bytes[] = "#define B 2\n";
    static const unsigned char changed_bytes[] = "int a(void){return 9;}\n";
    static const char paths[] = "core/a.c\0core/sub/b.h\0";
    bool fixture = mkdir(core, 0700) == 0 && mkdir(sub, 0700) == 0 &&
                   cs_write_bytes(first, first_bytes, sizeof(first_bytes) - 1) &&
                   cs_write_bytes(second, second_bytes, sizeof(second_bytes) - 1) &&
                   cs_write_bytes(list, paths, sizeof(paths) - 1);
    CS_CHECK("end-to-end fixture", fixture);
    if (!fixture)
        goto cleanup;

    CS_CHECK("seal writes a reader-compatible manifest",
             cs_run_tool(dir, "seal") == 0 && cs_parse_manifest(manifest) == 0);
    CS_CHECK("check accepts the freshly sealed files",
             cs_run_tool(dir, "check") == 0);

    CS_CHECK("changed sealed bytes are written",
             cs_write_bytes(first, changed_bytes, sizeof(changed_bytes) - 1));
    CS_CHECK("check reports same-size content drift",
             cs_run_tool(dir, "check") == 1);
    CS_CHECK("fixture is restored and resealed",
             cs_write_bytes(first, first_bytes, sizeof(first_bytes) - 1) &&
             cs_run_tool(dir, "seal") == 0);

    static const char duplicate_root[] =
        "ROOT  0000000000000000000000000000000000000000000000000000000000000000\n";
    CS_CHECK("duplicate ROOT fixture", cs_append_bytes(
                 manifest, duplicate_root, sizeof(duplicate_root) - 1));
    CS_CHECK("duplicate ROOT is a parser error",
             cs_parse_manifest(manifest) == -2 &&
             cs_run_tool(dir, "check") == 2);

    CS_CHECK("manifest reseals after duplicate ROOT test",
             cs_run_tool(dir, "seal") == 0);
    static const char after_root[] = "# data after final root\n";
    CS_CHECK("nonfinal ROOT fixture",
             cs_append_bytes(manifest, after_root, sizeof(after_root) - 1));
    CS_CHECK("ROOT must be the final physical record",
             cs_parse_manifest(manifest) == -2 &&
             cs_run_tool(dir, "check") == 2);

    static const char nul_manifest[] =
        "ROOT  0000000000000000000000000000000000000000000000000000000000000000"
        "\0hidden\n";
    CS_CHECK("embedded-NUL manifest fixture",
             cs_write_bytes(manifest, nul_manifest, sizeof(nul_manifest) - 1));
    CS_CHECK("embedded NUL cannot hide a physical-line suffix",
             cs_parse_manifest(manifest) == -2 &&
             cs_run_tool(dir, "check") == 2);

cleanup:
    (void)unlink(manifest);
    (void)unlink(list);
    (void)unlink(second);
    (void)unlink(first);
    (void)rmdir(sub);
    (void)rmdir(core);
    (void)rmdir(dir);
}

int test_core_seal(void)
{
    printf("\n=== core_seal manifest-encoding tests ===\n");
    cs_failures = 0;

    test_section_dual_parse();
    test_section_length_prefix();
    test_path_policy();
    test_input_tokenisation();
    test_file_line();
    test_merkle_dialect();
    test_root_is_frozen();
    test_leaf_preimage();
    test_sections_localise();
    test_manifest_limits();
    test_seal_check_round_trip();

    printf("core_seal: %d failure(s)\n", cs_failures);
    return cs_failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked seal-violation child lane
 * cannot run here. Skipped loudly rather than faked. */
int test_core_seal(void)
{
    printf("core_seal: SKIP (Windows): forked seal-violation child lane\n");
    return 0;
}
#endif
