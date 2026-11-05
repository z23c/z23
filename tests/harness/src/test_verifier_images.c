#define _GNU_SOURCE
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 *
 * test_verifier_images — the fixed-result verifier's installed inputs,
 * built and checked without root.
 *
 * The source image is pinned byte for byte (its content root and the root
 * it will have once root owns it). The tool image is discovered twice, by
 * strace and by a static ELF/driver walk, and must come out identical; a
 * compile run entirely from the image through the image's own loader must
 * reproduce the cold result.o byte for byte and touch nothing outside the
 * image, snapshot and scratch. The seccomp filter's bytes are pinned, its
 * policy is checked in software, and the kernel is asked to enforce it on
 * a child that then compiles result.c. The RED fixtures change one input
 * each and assert a changed root or a named refusal. */
#include "test/test_core.h"

#if defined(__linux__) && defined(__x86_64__)
#include "platform/temp_directory.h"
#include "verify/fixed_result_image.h"
#include "verify/fixed_result_seccomp.h"
#include "verify/tree_closure.h"

#include "base/hex.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define VI_PROFILE "tools/verify/fixed_result_fast.args"
/* The test-fast result.o the other verifier lanes pin (10,128 bytes). */
#define VI_OBJECT_SHA3 \
    "268e7e07f6accd322fbe936ec00fcc65980a66c13c7f7962d5eb6d97b8425f11"
#define VI_OBJECT_BYTES 10128u
/* The source image: three pinned files plus the profile's -I directories. */
#define VI_SOURCE_CONTENT \
    "49f49ce09877b32a354d7dbbca756c36963d1950212f8d8e3a287f6590364894"
#define VI_SOURCE_ROOT_TREE \
    "2b5bc4f95a35e7e7fb3feb8cb049ffb7beff755b177413fe3e614faae2f47667"
#define VI_SOURCE_ENTRIES 288u
/* SHA3-256 of /etc/z23verify/fixed_result.seccomp.bpf. */
#define VI_SECCOMP_SHA3 \
    "6e764681d4ca638819faa76db1d9dcc1c520c34c70a6f73661d9a01a6c3482ec"

struct vi_world {
    char base[PLATFORM_TEMP_PATH_MAX];
    char repo[PATH_MAX], profile[PATH_MAX];
    char tool[PATH_MAX];
    struct zcl_fri_roots tool_roots;
    uint8_t cold_object[32];
    uint64_t cold_bytes;
    bool tool_built, cold_set;
};

static bool vi_path(char out[PATH_MAX], const char *base, const char *leaf)
{
    return snprintf(out, PATH_MAX, "%s/%s", base, leaf) < PATH_MAX;
}

/* A relative link target that climbs from dir to the filesystem root and
 * names /etc, an existing directory outside any image. The count of "../" is
 * the real depth of dir, so the link resolves to /etc at any depth: a fixed
 * count lands on a missing sibling of an ancestor (symlink_unresolved, not
 * symlink_escapes_root) when the fixture root is deeper than the count. */
static bool vi_escape_target(char out[PATH_MAX], const char *dir)
{
    char real[PATH_MAX];
    size_t len = 0;
    if (!realpath(dir, real)) return false;
    for (const char *p = real; *p; p++) {
        if (*p != '/') continue;
        if (len + 3 >= PATH_MAX) return false;
        memcpy(out + len, "../", 3);
        len += 3;
    }
    return snprintf(out + len, PATH_MAX - len, "etc") < (int)(PATH_MAX - len);
}

static bool vi_dir(char out[PATH_MAX], const char *base, const char *leaf)
{
    return vi_path(out, base, leaf) && mkdir(out, 0700) == 0;
}

static void vi_hex(const uint8_t in[32], char out[65])
{
    zcl_hex_encode(in, 32u, out);
}

static bool vi_write(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0) return false;
    size_t n = strlen(text);
    bool ok = write(fd, text, n) == (ssize_t)n && fchmod(fd, mode) == 0;
    return close(fd) == 0 && ok;
}

static bool vi_owner_root(const char *root, uint8_t out[32])
{
    struct zcl_tree_closure_roots r;
    uid_t zero = 0;
    if (zcl_tree_closure_hash(root, geteuid(), &zero, &r) != NULL) return false;
    memcpy(out, r.tree_sha3, 32u);
    return true;
}

static int vi_rm_one(const char *path, const struct stat *st, int flag,
                     struct FTW *ftw)
{
    (void)st;
    (void)ftw;
    if (flag == FTW_DP) (void)chmod(path, 0700);
    return flag == FTW_DP ? rmdir(path) : unlink(path);
}

static bool vi_world_open(struct vi_world *w)
{
    memset(w, 0, sizeof(*w));
    if (!getcwd(w->repo, sizeof(w->repo)) ||
        !vi_path(w->profile, w->repo, VI_PROFILE) ||
        !platform_temp_directory_create("z23-verifier-images-", w->base,
                                        sizeof(w->base)))
        return false;
    return vi_path(w->tool, w->base, "tool");
}

/* ── source image ──────────────────────────────────────────────────── */

static int test_vi_source(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: source image is pinned and deterministic") {
        char a[PATH_MAX], b[PATH_MAX], hex[65];
        struct zcl_fri_image ia, ib;
        struct zcl_fri_roots ra, rb;
        ASSERT(vi_path(a, w->base, "source-a") && vi_path(b, w->base, "source-b"));
        bool ok_a = zcl_fri_image_begin(&ia, a, NULL) &&
                    zcl_fri_build_source(&ia, w->repo, w->profile) &&
                    zcl_fri_image_finish(&ia, &ra);
        bool ok_b = zcl_fri_image_begin(&ib, b, NULL) &&
                    zcl_fri_build_source(&ib, w->repo, w->profile) &&
                    zcl_fri_image_finish(&ib, &rb);
        if (!ok_a) printf("[%s %s] ", ia.why, ia.why_path);
        zcl_fri_image_free(&ia);
        zcl_fri_image_free(&ib);
        ASSERT(ok_a && ok_b);
        ASSERT(memcmp(ra.tree_sha3, rb.tree_sha3, 32u) == 0);
        vi_hex(ra.content_sha3, hex);
        ASSERT_STR_EQ(hex, VI_SOURCE_CONTENT);
        vi_hex(ra.root_tree_sha3, hex);
        ASSERT_STR_EQ(hex, VI_SOURCE_ROOT_TREE);
        ASSERT_EQ(ra.entries, VI_SOURCE_ENTRIES);
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_source_header_red(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED an optional header in the snapshot changes the content root") {
        char a[PATH_MAX], hdr[PATH_MAX];
        struct zcl_fri_image img;
        struct zcl_fri_roots before, after;
        struct zcl_tree_closure_roots planted;
        ASSERT(vi_path(a, w->base, "source-red"));
        bool built = zcl_fri_image_begin(&img, a, NULL) &&
                     zcl_fri_build_source(&img, w->repo, w->profile) &&
                     zcl_fri_image_finish(&img, &before);
        /* engine/models/include precedes platform/modules/base/include on
         * the -I list, so this header would shadow the pinned one. */
        bool planted_ok = built &&
            vi_path(hdr, a, "engine/models/include/base") && mkdir(hdr, 0755) == 0 &&
            vi_path(hdr, a, "engine/models/include/base/result.h") &&
            vi_write(hdr, "#error shadowed\n", 0444) &&
            zcl_tree_closure_hash(a, geteuid(), NULL, &planted) == NULL;
        bool refused = planted_ok && !zcl_fri_image_finish(&img, &after);
        const char *why = img.why;
        zcl_fri_image_free(&img);
        ASSERT(planted_ok);
        ASSERT(memcmp(planted.content_sha3, before.content_sha3, 32u) != 0);
        ASSERT(memcmp(planted.tree_sha3, before.tree_sha3, 32u) != 0);
        ASSERT(refused && why && strcmp(why, ZCL_FRI_WHY_EXTRA) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_source_pin_red(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED a changed pinned source refuses input_pin_mismatch") {
        char fake[PATH_MAX], dir[PATH_MAX], file[PATH_MAX], out[PATH_MAX];
        ASSERT(vi_dir(fake, w->base, "fake-repo"));
        ASSERT(vi_path(dir, fake, "platform") && mkdir(dir, 0755) == 0 &&
               vi_path(dir, fake, "platform/modules") && mkdir(dir, 0755) == 0 &&
               vi_path(dir, fake, "platform/modules/base") && mkdir(dir, 0755) == 0 &&
               vi_path(dir, fake, "platform/modules/base/src") && mkdir(dir, 0755) == 0);
        ASSERT(vi_path(file, fake, "platform/modules/base/src/result.c") &&
               vi_write(file, "int changed;\n", 0644));
        struct zcl_fri_image img;
        ASSERT(vi_path(out, w->base, "source-pin"));
        bool ok = zcl_fri_image_begin(&img, out, NULL) &&
                  zcl_fri_build_source(&img, fake, w->profile);
        const char *why = img.why;
        zcl_fri_image_free(&img);
        ASSERT(!ok && why && strcmp(why, ZCL_FRI_WHY_PIN) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── tool image ────────────────────────────────────────────────────── */

static bool vi_build_tool(struct vi_world *w, const char *out, const char *leaf,
                          bool trace, struct zcl_fri_roots *roots,
                          struct zcl_fri_discovery *d)
{
    char scratch[PATH_MAX];
    struct zcl_fri_image img;
    if (!vi_dir(scratch, w->base, leaf)) return false;
    bool ok = zcl_fri_image_begin(&img, out, NULL) &&
              zcl_fri_build_tool(&img, w->profile, w->repo, scratch, trace, d) &&
              zcl_fri_image_finish(&img, roots);
    if (!ok) printf("[%s %s] ", img.why ? img.why : "?", img.why_path);
    zcl_fri_image_free(&img);
    return ok;
}

static int test_vi_tool(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: traced and static discovery build the same tool image") {
        struct zcl_fri_discovery traced, walked;
        struct zcl_fri_roots again;
        char other[PATH_MAX], tree[65], content[65];
        ASSERT(zcl_fri_strace_available());
        ASSERT(vi_build_tool(w, w->tool, "scratch-trace", true, &w->tool_roots,
                             &traced));
        w->tool_built = true;
        ASSERT(traced.traced && traced.trace_present > 0 && traced.trace_absent > 0);
        /* The kernel maps the ELF interpreter, so only the static walk sees
         * it; every file the compile opened was also named statically. */
        ASSERT_EQ(traced.trace_only, 0u);
        ASSERT_EQ(traced.static_only, 1u);
        ASSERT(strstr(traced.static_only_first, "ld-linux-x86-64.so.2") != NULL);
        ASSERT(vi_path(other, w->base, "tool-static"));
        ASSERT(vi_build_tool(w, other, "scratch-static", false, &again, &walked));
        ASSERT(!walked.traced);
        ASSERT(memcmp(again.root_tree_sha3, w->tool_roots.root_tree_sha3, 32u) == 0);
        ASSERT(memcmp(again.content_sha3, w->tool_roots.content_sha3, 32u) == 0);
        vi_hex(w->tool_roots.root_tree_sha3, tree);
        vi_hex(w->tool_roots.content_sha3, content);
        printf("[tool root_tree_sha3=%s content_sha3=%s entries=%u bytes=%llu] ",
               tree, content, w->tool_roots.entries,
               (unsigned long long)w->tool_roots.bytes);
        PASS();
    } _test_next:;
    return failures;
}

/* The reviewed GCC 14.2 object. A different driver must reproduce its own
 * cold object and is not rewritten onto that pin. */
static bool vi_object_pin(const char *hex, uint64_t size)
{
    if (size != (uint64_t)VI_OBJECT_BYTES) return true;
    return strcmp(hex, VI_OBJECT_SHA3) == 0;
}

static int test_vi_tool_prove(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: tool image is complete without root") {
        char scratch[PATH_MAX], hex[65];
        struct zcl_fri_proof p;
        ASSERT(w->tool_built && vi_dir(scratch, w->base, "prove"));
        bool ok = zcl_fri_prove(w->tool, w->repo, w->profile, scratch, &p);
        if (!ok) printf("[%s %s] ", p.why, p.why_path);
        ASSERT(ok);
        vi_hex(p.image_object, hex);
        ASSERT(memcmp(p.image_object, p.reference_object, 32u) == 0);
        ASSERT(p.object_equal && p.dep_equal && p.stderr_equal);
        ASSERT(vi_object_pin(hex, p.object_size));
        memcpy(w->cold_object, p.reference_object, 32u);
        w->cold_bytes = p.object_size;
        w->cold_set = true;
        ASSERT(p.traced && p.image_reads > 0);
        for (unsigned i = 0; i < p.leaks && i < ZCL_FRI_NAMED; i++)
            printf("[leak %s] ", p.leak[i]);
        ASSERT_EQ(p.leaks, 0u);
        for (unsigned i = 0; i < p.eq_mismatch && i < ZCL_FRI_NAMED; i++)
            printf("[mismatch %s] ", p.mismatch[i]);
        ASSERT_EQ(p.eq_mismatch, 0u);
        ASSERT(p.eq_present > 0 && p.eq_absent > 0);
        printf("[object_sha3=%s image_reads=%u absent_outside=%u "
               "equivalence=%u/%u] ", hex, p.image_reads, p.absent_outside,
               p.eq_present, p.eq_absent);
        PASS();
    } _test_next:;
    return failures;
}

/* The same question the image builder asks the host driver. */
static bool vi_cc_print(struct vi_world *w, const char *flag, char out[PATH_MAX])
{
    char path[PATH_MAX];
    char *argv[] = {"cc", (char *)flag, NULL};
    char *env[] = {"LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL};
    if (!vi_path(path, w->base, "cc-print.txt")) return false;
    struct zcl_fri_run r = {.argv = argv, .envp = env, .path = "/usr/bin/cc",
                            .cwd = w->repo, .out_path = path};
    int code = -1;
    if (!zcl_fri_run_wait(&r, &code) || code != 0) return false;
    FILE *fp = fopen(path, "re");
    bool ok = fp && fgets(out, PATH_MAX, fp) != NULL;
    if (fp) fclose(fp);
    if (!ok) return false;
    out[strcspn(out, "\n")] = '\0';
    return out[0] == '/';
}

/* A soname the image actually stored, on this host's loader search path. */
static bool vi_soname(const struct vi_world *w, const char *soname,
                      char rel[PATH_MAX])
{
    static const char *const dirs[] = {
        "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
        "/lib64", "/usr/lib64", "/lib", "/usr/lib"
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char host[PATH_MAX];
        if (snprintf(host, sizeof(host), "%s/%s", dirs[i], soname) >= PATH_MAX)
            return false;
        if (zcl_fri_image_lookup(w->tool, host, rel) == 'F') return true;
    }
    return false;
}

/* Swaps `rel` in the tool image for different bytes, returns both roots,
 * and puts the original back. */
static bool vi_swap_file(struct vi_world *w, const char *rel, bool create,
                         uint8_t changed[32], uint8_t restored[32])
{
    char path[PATH_MAX], saved[PATH_MAX];
    if (!vi_path(path, w->tool, rel) || !vi_path(saved, w->base, "swap.saved"))
        return false;
    if (!create && rename(path, saved) != 0) return false;
    bool ok = vi_write(path, "not the pinned bytes\n", create ? 0444 : 0555) &&
              vi_owner_root(w->tool, changed);
    ok = unlink(path) == 0 && ok;
    if (!create) ok = rename(saved, path) == 0 && ok;
    return vi_owner_root(w->tool, restored) && ok;
}

static int test_vi_tool_red(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED cc1 replaced with the driver unchanged changes the tool root") {
        uint8_t changed[32], restored[32], driver[32];
        char path[PATH_MAX], rel[PATH_MAX], cc1_host[PATH_MAX];
        ASSERT(w->tool_built);
        ASSERT(zcl_fri_image_lookup(w->tool, "/usr/bin/cc", rel) == 'F');
        ASSERT(vi_path(path, w->tool, rel) && zcl_fri_sha3_file(path, driver, NULL));
        ASSERT(vi_cc_print(w, "-print-prog-name=cc1", cc1_host));
        ASSERT(zcl_fri_image_lookup(w->tool, cc1_host, rel) == 'F');
        ASSERT(vi_swap_file(w, rel, false, changed, restored));
        uint8_t driver_after[32];
        ASSERT(zcl_fri_sha3_file(path, driver_after, NULL));
        ASSERT(memcmp(driver, driver_after, 32u) == 0);
        ASSERT(memcmp(changed, w->tool_roots.root_tree_sha3, 32u) != 0);
        ASSERT(memcmp(restored, w->tool_roots.root_tree_sha3, 32u) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_red_dso_spec(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED a changed DSO or a new spec file changes the tool root") {
        uint8_t changed[32], restored[32];
        char rel[PATH_MAX], cc1_host[PATH_MAX], specs[PATH_MAX];
        ASSERT(w->tool_built);
        ASSERT(vi_soname(w, "libz.so.1", rel));
        ASSERT(vi_swap_file(w, rel, false, changed, restored));
        ASSERT(memcmp(changed, w->tool_roots.root_tree_sha3, 32u) != 0);
        ASSERT(memcmp(restored, w->tool_roots.root_tree_sha3, 32u) == 0);
        /* Built-in specs: a specs file beside this driver's cc1 changes
         * the image root. The parent directory is the one the image stored. */
        ASSERT(vi_cc_print(w, "-print-prog-name=cc1", cc1_host));
        ASSERT(zcl_fri_image_lookup(w->tool, cc1_host, rel) == 'F');
        char *slash = strrchr(rel, '/');
        ASSERT(slash);
        ASSERT(snprintf(specs, sizeof(specs), "%.*s/specs",
                        (int)(slash - rel), rel) < (int)sizeof(specs));
        ASSERT(vi_swap_file(w, specs, true, changed, restored));
        ASSERT(memcmp(changed, w->tool_roots.root_tree_sha3, 32u) != 0);
        ASSERT(memcmp(restored, w->tool_roots.root_tree_sha3, 32u) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_red_image_escape(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED an escaping link or a special file in an image refuses") {
        char link[PATH_MAX], fifo[PATH_MAX], up[PATH_MAX], usr[PATH_MAX];
        struct zcl_tree_closure_roots r;
        ASSERT(w->tool_built);
        ASSERT(vi_path(usr, w->tool, "usr") && vi_escape_target(up, usr));
        ASSERT(vi_path(link, w->tool, "usr/escape") &&
               symlink(up, link) == 0);
        const char *why = zcl_tree_closure_hash(w->tool, geteuid(), NULL, &r);
        ASSERT(unlink(link) == 0);
        ASSERT(why && strcmp(why, "symlink_escapes_root") == 0);
        ASSERT(vi_path(fifo, w->tool, "usr/fifo") && mkfifo(fifo, 0444) == 0);
        why = zcl_tree_closure_hash(w->tool, geteuid(), NULL, &r);
        ASSERT(unlink(fifo) == 0);
        ASSERT(why && strcmp(why, "special_entry") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── builder refusals on a synthetic host ──────────────────────────── */

struct vi_host {
    char root[PATH_MAX];
    char changed[PATH_MAX];
};

static bool vi_host_link(const char *root, const char *rel, const char *target)
{
    char p[PATH_MAX];
    return vi_path(p, root, rel) && symlink(target, p) == 0;
}

static bool vi_host_file(const char *root, const char *rel, const char *text,
                         mode_t mode)
{
    char p[PATH_MAX];
    return vi_path(p, root, rel) && vi_write(p, text, mode);
}

static bool vi_host_make(struct vi_world *w, struct vi_host *h)
{
    char p[PATH_MAX];
    const char *dirs[] = {"usr", "usr/bin", "usr/lib", "etc", "etc/alternatives"};
    if (!vi_dir(h->root, w->base, "host")) return false;
    for (size_t i = 0; i < sizeof(dirs) / sizeof(*dirs); i++)
        if (!vi_path(p, h->root, dirs[i]) || mkdir(p, 0755) != 0) return false;
    return vi_host_file(h->root, "usr/bin/real", "real\n", 0755) &&
           vi_host_link(h->root, "etc/alternatives/cc", "/usr/bin/real") &&
           vi_host_link(h->root, "usr/bin/cc", "/etc/alternatives/cc") &&
           vi_host_link(h->root, "usr/bin/escape", "../../../etc/passwd") &&
           vi_path(p, h->root, "usr/bin/fifo") && mkfifo(p, 0644) == 0 &&
           vi_host_file(h->root, "usr/bin/locked", "x\n", 0000) &&
           vi_host_file(h->root, "usr/lib/libgrow.so", "v1\n", 0644);
}

static void vi_grow(void *ctx, const char *host_path)
{
    struct vi_host *h = ctx;
    if (strcmp(host_path, h->changed) != 0) return;
    int fd = open(host_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) {
        (void)!write(fd, "v2\n", 3);
        close(fd);
    }
}

static const char *vi_host_add(struct vi_world *w, struct vi_host *h,
                               const char *leaf, const char *path)
{
    static char why[64];
    char out[PATH_MAX];
    struct zcl_fri_image img;
    struct zcl_fri_roots roots;
    snprintf(why, sizeof(why), "built");
    if (!vi_path(out, w->base, leaf)) return "path";
    bool ok = zcl_fri_image_begin(&img, out, h->root);
    if (ok) {
        img.after_copy = vi_grow;
        img.hook_ctx = h;
        ok = zcl_fri_add_host_path(&img, path, NULL) &&
             zcl_fri_image_finish(&img, &roots);
    }
    if (!ok) snprintf(why, sizeof(why), "%s", img.why ? img.why : "?");
    zcl_fri_image_free(&img);
    return why;
}

static struct vi_host vi_fixture_host;

static int test_vi_links(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: absolute links are rewritten to resolve inside the image") {
        char out[PATH_MAX], target[PATH_MAX], rel[PATH_MAX];
        ASSERT(vi_host_make(w, &vi_fixture_host));
        ASSERT_STR_EQ(vi_host_add(w, &vi_fixture_host, "img-links", "/usr/bin/cc"), "built");
        ASSERT(vi_path(out, w->base, "img-links/usr/bin/cc"));
        ssize_t n = readlink(out, target, sizeof(target) - 1u);
        ASSERT(n > 0);
        target[n] = '\0';
        ASSERT_STR_EQ(target, "../../etc/alternatives/cc");
        ASSERT(vi_path(out, w->base, "img-links"));
        ASSERT(zcl_fri_image_lookup(out, "/usr/bin/cc", rel) == 'F');
        ASSERT_STR_EQ(rel, "usr/bin/real");
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_red_inputs(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED escaping, special, missing and unreadable inputs refuse") {
        ASSERT(vi_fixture_host.root[0]);
        ASSERT_STR_EQ(vi_host_add(w, &vi_fixture_host, "img-escape", "/usr/bin/escape"),
                      ZCL_FRI_WHY_ESCAPES);
        ASSERT_STR_EQ(vi_host_add(w, &vi_fixture_host, "img-fifo", "/usr/bin/fifo"),
                      ZCL_FRI_WHY_SPECIAL);
        ASSERT_STR_EQ(vi_host_add(w, &vi_fixture_host, "img-missing", "/usr/bin/absent"),
                      ZCL_FRI_WHY_MISSING);
        if (geteuid() != 0)
            ASSERT_STR_EQ(vi_host_add(w, &vi_fixture_host, "img-locked", "/usr/bin/locked"),
                          ZCL_FRI_WHY_UNREADABLE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_red_changed(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: RED an input changed during the build refuses on re-hash") {
        ASSERT(vi_fixture_host.root[0]);
        ASSERT(vi_path(vi_fixture_host.changed, vi_fixture_host.root,
                       "usr/lib/libgrow.so"));
        ASSERT_STR_EQ(vi_host_add(w, &vi_fixture_host, "img-grow", "/usr/lib/libgrow.so"),
                      ZCL_FRI_WHY_CHANGED);
        vi_fixture_host.changed[0] = '\0';
        PASS();
    } _test_next:;
    return failures;
}

static int test_vi_check_image(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: check image holds executables and their loader closure") {
        char out[PATH_MAX], exe[PATH_MAX], rel[PATH_MAX], bad[PATH_MAX];
        ASSERT(w->tool_built);
        ASSERT(zcl_fri_image_lookup(w->tool, "/usr/bin/cc", rel) == 'F');
        ASSERT(vi_path(exe, w->tool, rel));
        char spec[PATH_MAX + 32];
        snprintf(spec, sizeof(spec), "z23-demo=%s", exe);
        char *specs[] = {spec};
        struct zcl_fri_image img;
        struct zcl_fri_roots roots;
        ASSERT(vi_path(out, w->base, "check"));
        bool ok = zcl_fri_image_begin(&img, out, NULL) &&
                  zcl_fri_build_check(&img, specs, 1) &&
                  zcl_fri_image_finish(&img, &roots);
        const struct zcl_fri_entry *e = ok ? zcl_fri_find(&img, "usr/local/libexec/z23-demo")
                                           : NULL;
        bool exec_ok = e && e->kind == 'F' && e->mode == 0555;
        zcl_fri_image_free(&img);
        ASSERT(ok && exec_ok);
        ASSERT(zcl_fri_image_lookup(out, "/lib64/ld-linux-x86-64.so.2", rel) == 'F');
        ASSERT(vi_path(bad, w->base, "check-bad"));
        snprintf(spec, sizeof(spec), "z23-demo=%s", w->profile);
        ok = zcl_fri_image_begin(&img, bad, NULL) &&
             zcl_fri_build_check(&img, specs, 1);
        const char *why = img.why;
        zcl_fri_image_free(&img);
        ASSERT(!ok && why && strcmp(why, ZCL_FRI_WHY_ELF) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── seccomp ───────────────────────────────────────────────────────── */

static uint32_t vi_eval(const uint8_t *prog, size_t len, int nr, uint32_t arch,
                        uint64_t a0, uint64_t a1)
{
    struct zcl_frs_data d = {.nr = nr, .arch = arch, .args = {a0, a1}};
    return zcl_frs_eval(prog, len, &d);
}

static const int k_vi_denied[] = {
    SYS_socket, SYS_socketpair, SYS_connect, SYS_bind, SYS_listen,
    SYS_accept, SYS_accept4, SYS_sendto, SYS_ptrace, SYS_mount, SYS_umount2,
    SYS_pivot_root, SYS_chroot, SYS_unshare, SYS_setns, SYS_keyctl,
    SYS_add_key, SYS_request_key, SYS_bpf, SYS_userfaultfd,
    SYS_perf_event_open, SYS_io_uring_setup, SYS_io_uring_enter,
    SYS_io_uring_register, SYS_process_vm_readv, SYS_process_vm_writev,
    SYS_kexec_load, SYS_init_module, SYS_finit_module, SYS_delete_module,
    SYS_open_by_handle_at, SYS_name_to_handle_at, SYS_setuid, SYS_setgid,
    SYS_setresuid, SYS_setgroups, SYS_capset, SYS_personality, SYS_seccomp,
    SYS_execveat, SYS_memfd_create, SYS_fsopen, SYS_move_mount,
    SYS_open_tree, SYS_mknodat, SYS_symlink, SYS_link, SYS_rename,
    SYS_chmod, SYS_chown, SYS_iopl, SYS_ioperm, SYS_reboot, SYS_syslog
};

static int test_vi_seccomp_policy(void)
{
    int failures = 0;
    TEST("verifier images: seccomp filter bytes are pinned and the policy holds") {
        uint8_t prog[ZCL_FRS_MAX_BYTES], again[ZCL_FRS_MAX_BYTES], digest[32];
        size_t len = 0, len2 = 0, insns = 0;
        const char *why = NULL;
        char hex[65];
        ASSERT(zcl_frs_build(prog, &len, &why) && zcl_frs_build(again, &len2, &why));
        ASSERT(len == len2 && memcmp(prog, again, len) == 0);
        ASSERT(zcl_frs_sha3(digest, &insns, &why));
        vi_hex(digest, hex);
        ASSERT_STR_EQ(hex, VI_SECCOMP_SHA3);
        const uint32_t x86 = 0xc000003eu, eperm = ZCL_FRS_ERRNO | 1u;
        for (size_t i = 0; i < zcl_frs_allowed_count(); i++) {
            int nr;
            const char *name, *rule;
            ASSERT(zcl_frs_allowed(i, &nr, &name, &rule));
            if (strcmp(rule, "allow") == 0)
                ASSERT_EQ(vi_eval(prog, len, nr, x86, 0, 0), ZCL_FRS_ALLOW);
        }
        for (size_t i = 0; i < sizeof(k_vi_denied) / sizeof(*k_vi_denied); i++)
            ASSERT_EQ(vi_eval(prog, len, k_vi_denied[i], x86, 0, 0), eperm);
        ASSERT_EQ(vi_eval(prog, len, SYS_read, 0x40000003u, 0, 0),
                  ZCL_FRS_KILL_PROCESS);
        ASSERT_EQ(vi_eval(prog, len, (int)(0x40000000u | SYS_read), x86, 0, 0),
                  ZCL_FRS_KILL_PROCESS);
        ASSERT_EQ(vi_eval(prog, len, SYS_clone, x86, CLONE_NEWUSER | SIGCHLD, 0),
                  eperm);
        ASSERT_EQ(vi_eval(prog, len, SYS_clone, x86, CLONE_NEWNET | SIGCHLD, 0),
                  eperm);
        ASSERT_EQ(vi_eval(prog, len, SYS_clone, x86, SIGCHLD, 0), ZCL_FRS_ALLOW);
        ASSERT_EQ(vi_eval(prog, len, SYS_clone3, x86, 0, 0), ZCL_FRS_ERRNO | 38u);
        ASSERT_EQ(vi_eval(prog, len, SYS_ioctl, x86, 2, 0x5401u), ZCL_FRS_ALLOW);
        ASSERT_EQ(vi_eval(prog, len, SYS_ioctl, x86, 0, 0x5412u), eperm); /* TIOCSTI */
        ASSERT_EQ(vi_eval(prog, len, SYS_prctl, x86, PR_GET_SECCOMP, 0),
                  ZCL_FRS_ALLOW);
        ASSERT_EQ(vi_eval(prog, len, SYS_prctl, x86, PR_SET_SECCOMP, 0), eperm);
        ASSERT_EQ(vi_eval(prog, len, SYS_prctl, x86, PR_SET_DUMPABLE, 0), eperm);
        printf("[seccomp insns=%zu sha3=%s] ", insns, hex);
        PASS();
    } _test_next:;
    return failures;
}

enum {
    VI_SC_INSTALL = 1 << 0, VI_SC_MODE = 1 << 1, VI_SC_SOCKET = 1 << 2,
    VI_SC_PTRACE = 1 << 3, VI_SC_USERNS = 1 << 4, VI_SC_CLONE_NS = 1 << 5,
    VI_SC_MISC = 1 << 6, VI_SC_COMPILE = 1 << 7, VI_SC_OBJECT = 1 << 8
};

static bool vi_eperm(long rc) { return rc == -1 && errno == EPERM; }

static int vi_clone_child(void *arg)
{
    (void)arg;
    _exit(0);
}

/* Without a filter, socket, ptrace(TRACEME), setns(-1), the personality
 * query and memfd_create succeed or fail with another errno, so their EPERM
 * is the filter's. mount and the user-namespace calls can already be EPERM
 * for an unprivileged user (Ubuntu restricts user namespaces); they are
 * checked anyway, and discriminate when the test runs with privilege.
 * The filter's handling of calls glibc does not wrap (bpf, io_uring,
 * keyctl, userfaultfd, perf_event_open) is checked by the evaluator. */
static int vi_sc_refusals(void)
{
    static char stack[16384] __attribute__((aligned(16)));
    int bad = 0;
    if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) bad |= VI_SC_MODE;
    if (!vi_eperm(socket(AF_INET, SOCK_STREAM, 0)) ||
        !vi_eperm(socket(AF_UNIX, SOCK_STREAM, 0))) bad |= VI_SC_SOCKET;
    if (!vi_eperm(ptrace(PTRACE_TRACEME, 0, NULL, NULL))) bad |= VI_SC_PTRACE;
    if (!vi_eperm(unshare(CLONE_NEWUSER))) bad |= VI_SC_USERNS;
    if (!vi_eperm(clone(vi_clone_child, stack + sizeof(stack),
                        CLONE_NEWUSER | SIGCHLD, NULL)))
        bad |= VI_SC_CLONE_NS;
    if (!vi_eperm(setns(-1, CLONE_NEWNET)) ||
        !vi_eperm(personality(0xffffffffUL)) ||
        !vi_eperm(memfd_create("vi", 0)) ||
        !vi_eperm(mount("none", "/", "tmpfs", 0, NULL)))
        bad |= VI_SC_MISC;
    return bad;
}

/* In a forked child: install the filter, check refusals, then compile
 * result.c through the driver under it. The exit code is a bit set of
 * the checks that failed. */
static void vi_sc_child(const char *src, const char *out, const char *profile)
{
    uint8_t prog[ZCL_FRS_MAX_BYTES];
    size_t len = 0;
    const char *why = NULL;
    if (!zcl_frs_build(prog, &len, &why) || !zcl_frs_install(prog, len, &why))
        _exit(VI_SC_INSTALL);
    int bad = vi_sc_refusals();
    char obj[PATH_MAX], dep[PATH_MAX], err[PATH_MAX];
    struct zcl_fri_argv a;
    char *env[] = {"LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL};
    int code = -1;
    if (!vi_path(obj, out, "result.o") || !vi_path(dep, out, "deps.d") ||
        !vi_path(err, out, "stderr.bin") ||
        zcl_fri_argv_make(&a, profile, src, ZCL_FRI_TARGET, obj, dep, false))
        _exit(bad | VI_SC_COMPILE);
    struct zcl_fri_run r = {.argv = a.argv, .envp = env, .path = "/usr/bin/cc",
                            .cwd = src, .err_path = err};
    if (!zcl_fri_run_wait(&r, &code) || code != 0) bad |= VI_SC_COMPILE;
    _exit(bad);
}

/* Under AddressSanitizer this case cannot run. Its forked child installs the
 * seccomp filter and then runs code (the refusal probes, the compile driver),
 * and the filter denies sigaltstack. The ASan runtime calls
 * sigaltstack(nullptr, ...) when the child unwinds or exits
 * (__asan::PlatformUnpoisonStacks), gets -1, and aborts with
 * "CHECK failed: asan_posix.cpp:45 ((0)) == ((sigaltstack(nullptr,
 * &signal_stack)))" (measured in the ASan sweep, pfx-v.log, twice). The
 * filter is the subject of the case and is not widened; only the ASan build
 * skips it, every other build runs it unchanged. GCC defines
 * __SANITIZE_ADDRESS__; Clang reports it through
 * __has_feature(address_sanitizer). */
#if defined(__SANITIZE_ADDRESS__)
#define VI_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define VI_UNDER_ASAN 1
#endif
#endif

static int test_vi_seccomp_kernel(struct vi_world *w)
{
    int failures = 0;
#if defined(VI_UNDER_ASAN)
    (void)w;
    printf("verifier images: kernel enforces the filter and result.c compiles under it SKIP under AddressSanitizer (the filter denies sigaltstack, which the ASan runtime needs)\n");
    return failures;
#endif
    TEST("verifier images: kernel enforces the filter and result.c compiles under it") {
        char src[PATH_MAX], out[PATH_MAX];
        struct zcl_fri_image img;
        struct zcl_fri_roots roots;
        ASSERT(vi_path(src, w->base, "seccomp-src") && vi_dir(out, w->base, "seccomp-out"));
        bool ok = zcl_fri_image_begin(&img, src, NULL) &&
                  zcl_fri_build_source(&img, w->repo, w->profile) &&
                  zcl_fri_image_finish(&img, &roots);
        zcl_fri_image_free(&img);
        ASSERT(ok);
        fflush(stdout);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0) vi_sc_child(src, out, w->profile);
        int status = 0;
        pid_t done;
        do { done = waitpid(pid, &status, 0); } while (done < 0 && errno == EINTR);
        ASSERT(done == pid && WIFEXITED(status));
        if (WEXITSTATUS(status) != 0) printf("[failed checks 0x%x] ", WEXITSTATUS(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        char obj[PATH_MAX];
        uint8_t sha3[32];
        uint64_t size = 0;
        ASSERT(w->cold_set && vi_path(obj, out, "result.o"));
        ASSERT(zcl_fri_sha3_file(obj, sha3, &size));
        ASSERT(size == w->cold_bytes && memcmp(sha3, w->cold_object, 32u) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the CLIs root runs ────────────────────────────────────────────── */

static bool vi_cc(struct vi_world *w, const char *out, const char *const *srcs)
{
    char *argv[32];
    size_t n = 0;
    char *head[] = {"cc", "-std=c23", "-O1", "-Wall", "-Wextra", "-Werror",
                    "-pedantic", "-D_POSIX_C_SOURCE=200809L",
                    "-DZCL_TREE_CLOSURE_NO_MAIN", "-Itools",
                    "-Iplatform/modules/sha3/include",
                    "-Iplatform/modules/base/include", "-o", (char *)out};
    for (size_t i = 0; i < sizeof(head) / sizeof(*head); i++) argv[n++] = head[i];
    for (size_t i = 0; srcs[i]; i++) argv[n++] = (char *)srcs[i];
    argv[n] = NULL;
    char *env[] = {"LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/bin:/bin", NULL};
    struct zcl_fri_run r = {.argv = argv, .envp = env, .path = "/usr/bin/cc",
                            .cwd = w->repo};
    int code = -1;
    return zcl_fri_run_wait(&r, &code) && code == 0;
}

static bool vi_line(const char *path, const char *want)
{
    FILE *f = fopen(path, "re");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (!found && fgets(line, sizeof(line), f))
        found = strncmp(line, want, strlen(want)) == 0;
    fclose(f);
    return found;
}

static int test_vi_cli(struct vi_world *w)
{
    int failures = 0;
    TEST("verifier images: the standalone CLIs build and print the pinned roots") {
        char image_cli[PATH_MAX], seccomp_cli[PATH_MAX], out[PATH_MAX],
             print[PATH_MAX], bpf[PATH_MAX];
        const char *image_srcs[] = {
            "tools/verify/fixed_result_image_main.c",
            "tools/verify/fixed_result_image.c",
            "tools/verify/fixed_result_image_elf.c",
            "tools/verify/fixed_result_image_run.c",
            "tools/verify/fixed_result_image_build.c",
            "tools/verify/fixed_result_image_proof.c",
            "tools/verify/tree_closure.c", "platform/modules/sha3/src/sha3.c",
            "platform/modules/base/src/safe_alloc.c", NULL};
        const char *seccomp_srcs[] = {
            "tools/verify/fixed_result_seccomp_main.c",
            "tools/verify/fixed_result_seccomp.c",
            "platform/modules/sha3/src/sha3.c", NULL};
        ASSERT(vi_path(image_cli, w->base, "z23-fixed-result-image") &&
               vi_path(seccomp_cli, w->base, "z23-fixed-result-seccomp"));
        ASSERT(vi_cc(w, image_cli, image_srcs));
        ASSERT(vi_cc(w, seccomp_cli, seccomp_srcs));
        char *env[] = {"LC_ALL=C", "PATH=/usr/bin:/bin", NULL};
        ASSERT(vi_path(out, w->base, "cli-source") &&
               vi_path(print, w->base, "cli-source.txt"));
        char *src_argv[] = {image_cli, "source", "--repo", w->repo, "--profile",
                            w->profile, "--out", out, NULL};
        struct zcl_fri_run r = {.argv = src_argv, .envp = env, .path = image_cli,
                                .cwd = w->repo, .out_path = print};
        int code = -1;
        ASSERT(zcl_fri_run_wait(&r, &code) && code == 0);
        ASSERT(vi_line(print, "pin source_content_sha3=" VI_SOURCE_CONTENT));
        ASSERT(vi_line(print, "pin source_image_sha3=" VI_SOURCE_ROOT_TREE));
        char *sc_argv[] = {seccomp_cli, "print", NULL};
        r = (struct zcl_fri_run){.argv = sc_argv, .envp = env, .path = seccomp_cli,
                                 .cwd = w->repo, .out_path = print};
        ASSERT(zcl_fri_run_wait(&r, &code) && code == 0);
        ASSERT(vi_line(print, "pin seccomp_filter_sha3=" VI_SECCOMP_SHA3));
        ASSERT(vi_path(bpf, w->base, "fixed_result.seccomp.bpf"));
        char *emit_argv[] = {seccomp_cli, "emit", NULL};
        r = (struct zcl_fri_run){.argv = emit_argv, .envp = env, .path = seccomp_cli,
                                 .cwd = w->repo, .out_path = bpf};
        ASSERT(zcl_fri_run_wait(&r, &code) && code == 0);
        uint8_t sha3[32];
        char hex[65];
        ASSERT(zcl_fri_sha3_file(bpf, sha3, NULL));
        vi_hex(sha3, hex);
        ASSERT_STR_EQ(hex, VI_SECCOMP_SHA3);
        PASS();
    } _test_next:;
    return failures;
}

int test_verifier_images(void)
{
    struct vi_world w;
    int failures = 0;
    TEST("verifier images: fixture world") {
        ASSERT(vi_world_open(&w));
        PASS();
    } _test_next:;
    if (failures) return failures;
    failures += test_vi_source(&w);
    failures += test_vi_source_header_red(&w);
    failures += test_vi_source_pin_red(&w);
    failures += test_vi_tool(&w);
    failures += test_vi_tool_prove(&w);
    failures += test_vi_tool_red(&w);
    failures += test_vi_red_dso_spec(&w);
    failures += test_vi_red_image_escape(&w);
    failures += test_vi_links(&w);
    failures += test_vi_red_inputs(&w);
    failures += test_vi_red_changed(&w);
    failures += test_vi_check_image(&w);
    failures += test_vi_seccomp_policy();
    failures += test_vi_seccomp_kernel(&w);
    failures += test_vi_cli(&w);
    (void)nftw(w.base, vi_rm_one, 16, FTW_DEPTH | FTW_PHYS);
    return failures;
}

#else

int test_verifier_images(void)
{
    /* The images, the loader walk and the seccomp numbers are Linux
     * x86-64 artifacts; there is nothing to build on this host. */
    printf("verifier images: linux x86-64 only... OK\n");
    return 0;
}

#endif
