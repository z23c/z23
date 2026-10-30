/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_action_root — zcl.action_preimage.v2 (vcs/build_action.h) and its
 * compile derivation (tools/dev/devloop_action_root.h).
 *
 *   1. Codec (action_root_codec_checks.c): encode, strict decode, field
 *      roots, the 13-field change table, refusals, the v1 input-closure
 *      fill, and single-bit tamper.
 *   2. Derivation on a fixture tree: flags (-D add, -D value, reorder, -O),
 *      a #define in an included header, header content, a NEW shadowing
 *      header in an earlier search dir and in an includer dir (negative
 *      lookups, depfile unchanged), inclusion order, header removal, the
 *      toolchain capsule, the sysroot, the linker, generated inputs and
 *      their producers, harness/fixtures/policy, allowlisted vs
 *      non-allowlisted environment, and ABI generation each change the
 *      root in exactly their own field; restoring the input restores it.
 *   3. Identity: the same fixture at two absolute roots derives the SAME
 *      root; a stored preimage re-derives its root after load, a tampered
 *      stored object is refused.
 *   4. The hotload hook fills a receipt (first -> hit -> source) and the
 *      receipt JSON carries action_root; the HOT_FORK capsule hook ignores
 *      the temporary unity spelling and keys on its content.
 *   5. Missing data is a MISS, never a guessed root: a missing, malformed
 *      or stale depfile, an unreadable or out-of-tree dependency, and an
 *      unknown producer where one is required each yield no root and a
 *      stable miss code; the receipt JSON says action_root null.
 *   6. Snapshot, not commit: a dirty edit and its commit derive the same
 *      root, and so do two commits whose closure bytes are identical.
 *   7. Fail closed: argv is an allowlist (unknown include-dir flags,
 *      response files, plugins, relative forced includes, extra inputs
 *      miss), search-dir environment misses, climbing include names bind
 *      only beside their includer, and the hot-swap key asks the driver
 *      with the plan target flags, re-asks when a skipped dir appears and
 *      binds implicit link libraries.
 *
 * All fixture state lives under ./test-tmp/. */

#include "test/test_core.h"
#include "test/action_root_codec_checks.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "devloop.h"
#include "devloop_action_root.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/environment_compat.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/spawn.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int g_failures;

#define AR_CHECK(name, expr) do {                                         \
    if (expr) { printf("  action_root: %s... OK\n", (name)); }            \
    else { printf("  action_root: %s... FAIL\n", (name)); g_failures++; } \
} while (0)

static void ar_fill(uint8_t out[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + 7u * i + 1u);
}

/* ---- 2/3. derivation fixture ---------------------------------------- */

/* The test slot: entries before it are the base environment (the fixed
 * compile-cache switches included), NULL at it ends the list. */
#define FX_ENV_SLOT 5

struct fx {
    char root[PATH_MAX];
    char depfile[PATH_MAX];
    char obj[PATH_MAX];
    char so[PATH_MAX];
    char ld[PATH_MAX];
    char prefix_map[PATH_MAX + 64];
    char include_b[PATH_MAX + 8];
    char unity_in[PATH_MAX];
    char unity_text[PATH_MAX + 32]; /* build/gen/unity.c as written */
    const char *argv[24];
    const char *link_argv[8];
    const char *vfrom[3];
    const char *vto[3];
    const char *env[FX_ENV_SLOT + 2];
    const char *system_dirs[1];
    struct vcs_action_abi_v2 abi[1];
    struct zcl_action_root_producer producers[1];
    struct zcl_action_root_request req;
};

static bool fx_write(const char *root, const char *rel, const char *text)
{
    char full[PATH_MAX];
    if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full))
        return false;
    for (char *p = full + strlen(root) + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        (void)mkdir(full, 0700);
        *p = '/';
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool fx_remove(const char *root, const char *rel)
{
    char full[PATH_MAX];
    return snprintf(full, sizeof(full), "%s/%s", root, rel) <
               (int)sizeof(full) && unlink(full) == 0;
}

/* The depfile's prerequisites after "build/obj.o:"; "%R" is the root. */
static bool fx_depfile_text(struct fx *x, const char *deps)
{
    char text[4 * PATH_MAX];
    size_t o = (size_t)snprintf(text, sizeof(text), "build/obj.o:");
    for (const char *p = deps; *p && o + PATH_MAX + 2 < sizeof(text); p++) {
        if (p[0] == '%' && p[1] == 'R') {
            o += (size_t)snprintf(text + o, sizeof(text) - o, "%s", x->root);
            p++;
        } else {
            text[o++] = *p;
        }
    }
    text[o++] = '\n';
    text[o] = '\0';
    return fx_write(x->root, "build/unit.d", text);
}

static bool fx_depfile(struct fx *x, bool with_local)
{
    return fx_depfile_text(x, with_local
        ? " build/gen/unity.c %R/src/unit.c src/local.h \\\n inc_b/defs.h"
        : " build/gen/unity.c %R/src/unit.c \\\n inc_b/defs.h");
}

/* build/gen/local.h spells the checkout root and sits where the quote
 * include of local.h is probed, so a present generated probe must hash
 * root-independently for two worktrees to agree. */
static bool fx_tree(struct fx *x)
{
    char *unity = x->unity_text, gen[PATH_MAX + 64];
    (void)snprintf(unity, sizeof(x->unity_text), "#include \"%s/src/unit.c\"\n",
                   x->root);
    (void)snprintf(gen, sizeof(gen), "#define GEN_ROOT \"%s/build\"\n",
                   x->root);
    return fx_write(x->root, "inc_a/.keep", "") &&
           fx_write(x->root, "inc_b/defs.h", "#define X 1\n") &&
           fx_write(x->root, "src/local.h", "int local(void);\n") &&
           fx_write(x->root, "src/unit.c",
                    "#include \"local.h\"\n#include <defs.h>\n"
                    "int unit(void) { return X; }\n") &&
           fx_write(x->root, "build/gen/unity.c", unity) &&
           fx_write(x->root, "build/gen/local.h", gen) &&
           fx_write(x->root, "tools/ld", "fixture linker v1\n") &&
           fx_depfile(x, true);
}

static void fx_argv(struct fx *x)
{
    (void)snprintf(x->prefix_map, sizeof(x->prefix_map),
                   "-ffile-prefix-map=%s=/zclassic23", x->root);
    (void)snprintf(x->include_b, sizeof(x->include_b), "-I%s/inc_b",
                   x->root);
    (void)snprintf(x->obj, sizeof(x->obj), "%s/build/obj.o", x->root);
    (void)snprintf(x->so, sizeof(x->so), "%s/build/obj.so", x->root);
    (void)snprintf(x->ld, sizeof(x->ld), "%s/tools/ld", x->root);
    (void)snprintf(x->unity_in, sizeof(x->unity_in), "%s/build/gen/unity.c",
                   x->root);
    const char *argv[] = {
        "cc", "-std=c23", x->prefix_map, "-Iinc_a", x->include_b, "-DFOO=1",
        "-O2", "-MD", "-MF", x->depfile, "-c", "-o", x->obj, x->unity_in,
    };
    memcpy(x->argv, argv, sizeof(argv));
    x->req.argv = x->argv;
    x->req.argc = sizeof(argv) / sizeof(argv[0]);
    const char *link[] = { "cc", "-shared", "-o", x->so, x->obj };
    memcpy(x->link_argv, link, sizeof(link));
    x->req.linker = (struct zcl_action_root_linker){
        .links = true, .ld = x->ld, .collect2 = NULL,
        .argv = x->link_argv, .argc = sizeof(link) / sizeof(link[0]),
    };
}

static void fx_request(struct fx *x)
{
    struct zcl_action_root_request *r = &x->req;
    r->root = x->root;
    r->stage_kind = "c23.compile.fixture";
    r->stage_version = 1;
    r->virtual_from = x->vfrom;
    r->virtual_to = x->vto;
    r->virtual_count = 3;
    r->depfile = x->depfile;
    r->system_dirs = x->system_dirs;
    r->system_dir_count = 1;
    r->sysroot = NULL;
    ar_fill(r->sysroot_objects_sha3, 44);
    r->producers = x->producers;
    r->producer_count = 0;
    r->child_env = x->env;
    ar_fill(r->toolchain_root, 40);
    r->abi_generation = 1;
    r->abi = x->abi;
    r->abi_count = 1;
    r->harness.present = true;
    ar_fill(r->harness.root, 41);
    r->fixtures.present = true;
    ar_fill(r->fixtures.root, 42);
    r->policy.present = true;
    ar_fill(r->policy.root, 43);
}

static bool fx_init(struct fx *x, const char *tag)
{
    char raw[PATH_MAX];
    memset(x, 0, sizeof(*x));
    test_make_tmpdir(raw, sizeof(raw), "action_root", tag);
    if (!platform_directory_canonical_real(raw, x->root, sizeof(x->root)) ||
        snprintf(x->depfile, sizeof(x->depfile), "%s/build/unit.d",
                 x->root) >= (int)sizeof(x->depfile) ||
        !fx_tree(x))
        return false;
    fx_argv(x);
    x->vfrom[0] = x->obj;
    x->vto[0] = "@out/object";
    x->vfrom[1] = x->depfile;
    x->vto[1] = "@out/depfile";
    x->vfrom[2] = x->so;
    x->vto[2] = "@out/module";
    x->env[0] = "LANG=C";
    x->env[1] = "HOME=/srv/fixture-home";
    x->env[2] = "SOURCE_DATE_EPOCH=0";
    x->env[3] = "CCACHE_DISABLE=1";
    x->env[4] = "ZCC_DISABLE=1";
    x->env[FX_ENV_SLOT] = NULL;
    x->system_dirs[0] = "/usr/include";
    x->abi[0] = (struct vcs_action_abi_v2){ "fixture_abi", 1 };
    x->producers[0].path = "build/gen/unity.c";
    ar_fill(x->producers[0].action_key, 45);
    fx_request(x);
    return true;
}

static bool fx_derive(const struct fx *x, struct zcl_action_root_result *out)
{
    bool ok = zcl_action_root_derive(&x->req, out);
    if (!ok)
        printf("    derive refused: %s\n", out->why);
    return ok;
}

/* The derivation misses with exactly `code` and yields no root at all.
 * With `why` set, the human reason must also contain it: two different
 * guards may share one code. */
static bool fx_miss_why(const struct fx *x, const char *code, const char *why)
{
    struct zcl_action_root_result r = {0};
    bool missed = !zcl_action_root_derive(&x->req, &r);
    bool ok = missed && strcmp(r.miss, code) == 0 && !r.root_hex[0] &&
              !r.preimage && (!why || strstr(r.why, why) != NULL);
    if (!ok)
        printf("    expected miss %s (%s), got %s (%s)\n", code,
               why ? why : "any reason", missed ? r.miss : "a root", r.why);
    zcl_action_root_result_free(&r);
    return ok;
}

static bool fx_miss(const struct fx *x, const char *code)
{
    return fx_miss_why(x, code, NULL);
}

/* The derived root differs from `base` and the first differing field is
 * exactly `want`. */
static bool fx_differs(const struct fx *x,
                       const struct zcl_action_root_result *base,
                       enum vcs_action_field_v2 want)
{
    struct zcl_action_root_result r = {0};
    enum vcs_action_field_v2 field = VCS_ACTION_FIELD_V2_NONE;
    bool ok = fx_derive(x, &r) && memcmp(r.root, base->root, 32) != 0 &&
              vcs_action_preimage_v2_first_diff(base->preimage,
                                                base->preimage_len,
                                                r.preimage, r.preimage_len,
                                                &field) &&
              field == want;
    if (!ok && r.preimage)
        printf("    first differing field: %s\n",
               vcs_action_field_v2_name(field) ? vcs_action_field_v2_name(field)
                                               : "none");
    zcl_action_root_result_free(&r);
    return ok;
}

static bool fx_same(const struct fx *x,
                    const struct zcl_action_root_result *base)
{
    struct zcl_action_root_result r = {0};
    bool ok = fx_derive(x, &r) && memcmp(r.root, base->root, 32) == 0;
    zcl_action_root_result_free(&r);
    return ok;
}

static void fx_check_flag(struct fx *x, const struct zcl_action_root_result *b,
                          const char *name, size_t at, const char *value)
{
    const char *saved = x->argv[at];
    x->argv[at] = value;
    bool moved = fx_differs(x, b, VCS_ACTION_FIELD_V2_FLAGS);
    x->argv[at] = saved;
    AR_CHECK(name, moved && fx_same(x, b));
}

static void test_derive_flags(struct fx *x,
                              const struct zcl_action_root_result *b)
{
    fx_check_flag(x, b, "flags: changing a -D value moves the root", 5,
                  "-DFOO=2");
    fx_check_flag(x, b, "flags: changing -O moves the root", 6, "-O0");
    /* Reorder: swap -DFOO=1 and -O2. */
    x->argv[5] = "-O2";
    x->argv[6] = "-DFOO=1";
    bool reordered = fx_differs(x, b, VCS_ACTION_FIELD_V2_FLAGS);
    x->argv[5] = "-DFOO=1";
    x->argv[6] = "-O2";
    AR_CHECK("flags: reordering two flags moves the root",
             reordered && fx_same(x, b));
    /* Add a -D (argv grows by one before the input). */
    size_t argc = x->req.argc;
    x->argv[argc] = x->argv[argc - 1];
    x->argv[argc - 1] = "-DBAR";
    x->req.argc = argc + 1;
    bool added = fx_differs(x, b, VCS_ACTION_FIELD_V2_FLAGS);
    x->argv[argc - 1] = x->argv[argc];
    x->req.argc = argc;
    AR_CHECK("flags: adding a -D moves the root", added && fx_same(x, b));
}

static void test_derive_headers(struct fx *x,
                                const struct zcl_action_root_result *b)
{
    bool ok = fx_write(x->root, "inc_b/defs.h", "#define X 2\n") &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE) &&
              fx_write(x->root, "inc_b/defs.h", "#define X 1\n");
    AR_CHECK("macros: a #define in an included header moves the root",
             ok && fx_same(x, b));
    ok = fx_write(x->root, "src/local.h", "int local(int);\n") &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE) &&
         fx_write(x->root, "src/local.h", "int local(void);\n");
    AR_CHECK("headers: header content moves the root", ok && fx_same(x, b));
    ok = fx_write(x->root, "inc_a/defs.h", "#define X 3\n") &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
         fx_remove(x->root, "inc_a/defs.h");
    AR_CHECK("headers: a new shadowing header in an earlier search dir "
             "moves the root before any recompile", ok && fx_same(x, b));
}

/* Shadows in the includer's dir, a changed probed file, and removal. */
static void test_derive_shadow_and_removal(
    struct fx *x, const struct zcl_action_root_result *b)
{
    bool ok = fx_write(x->root, "src/defs.h", "#define X 4\n") &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
              fx_remove(x->root, "src/defs.h");
    AR_CHECK("headers: a new shadowing header in the includer's own dir "
             "moves the root", ok && fx_same(x, b));
    ok = fx_write(x->root, "build/gen/local.h", "#define GEN_ROOT 0\n") &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP);
    AR_CHECK("headers: a changed file at a probed location moves the root",
             ok);
    bool refused = fx_remove(x->root, "src/local.h") &&
                   fx_miss(x, "dependency_missing");
    AR_CHECK("headers: a removed header named by a stale depfile misses "
             "(dependency_missing)",
             refused);
    ok = fx_depfile(x, false) &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE) &&
         fx_write(x->root, "src/local.h", "int local(void);\n") &&
         fx_depfile(x, true) && fx_tree(x);
    AR_CHECK("headers: removing a header from the closure moves the root",
             ok && fx_same(x, b));
}

/* A __has_include name need not enter the depfile: it is a conditional
 * lookup probed at every includer and search dir. */
static const char k_ar_local_cond[] =
    "#if __has_include(\"opt.h\") && __has_include_next(<sys/opt.h>)\n"
    "#endif\nint local(void);\n";

static bool fx_cond_decodes(const struct zcl_action_root_result *r)
{
    struct vcs_action_preimage_v2_decoded dec = {0};
    char why[160] = {0};
    bool ok = vcs_action_preimage_v2_decode(r->preimage, r->preimage_len,
                                            &dec, why, sizeof(why));
    size_t conditional = 0;
    for (size_t i = 0; ok && i < dec.view.lookup_count; i++)
        if (!dec.view.lookups[i].hit_dir[0])
            conditional++;
    if (ok)
        vcs_action_preimage_v2_decoded_free(&dec);
    return ok && conditional == 2;
}

static void test_derive_conditional(struct fx *x,
                                    const struct zcl_action_root_result *b)
{
    struct zcl_action_root_result cond = {0};
    bool ok = fx_write(x->root, "src/local.h", k_ar_local_cond) &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE) &&
              fx_derive(x, &cond);
    AR_CHECK("conditional: literal __has_include names become decodable "
             "conditional lookups", ok && fx_cond_decodes(&cond));
    ok = ok && fx_write(x->root, "inc_b/opt.h", "#define OPT 1\n") &&
         fx_differs(x, &cond, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
         fx_remove(x->root, "inc_b/opt.h") && fx_same(x, &cond);
    AR_CHECK("conditional: a header appearing where __has_include looks "
             "moves the root though the depfile never named it", ok);
    ok = ok && fx_write(x->root, "src/opt.h", "#define OPT 2\n") &&
         fx_differs(x, &cond, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
         fx_remove(x->root, "src/opt.h") && fx_same(x, &cond);
    AR_CHECK("conditional: a header appearing beside the includer moves the "
             "root", ok);
    ok = fx_write(x->root, "src/local.h",
                  "#if __has_include(OPT_HEADER)\n#endif\n") &&
         fx_miss(x, "conditional_lookup_unbound");
    AR_CHECK("conditional: a macro-named __has_include misses "
             "(conditional_lookup_unbound)", ok);
    ok = fx_write(x->root, "src/local.h",
                  "#ifndef __has_include\n#define __has_include(x) 1\n"
                  "#endif\n#if defined(__has_include)\n#endif\n"
                  "int local(void);\n") &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE);
    AR_CHECK("conditional: defining or testing the word itself asks about "
             "no name", ok);
    ok = fx_write(x->root, "src/local.h", "int local(void);\n") &&
         fx_same(x, b);
    AR_CHECK("conditional: removing the tests restores the root", ok);
    zcl_action_root_result_free(&cond);
}

/* Lookups keep inclusion order. GCC names a header once per route that
 * reached it, so a repeated path is dropped (first occurrence kept); a dir
 * in two search classes is refused. */
static void test_derive_lookups(struct fx *x,
                                const struct zcl_action_root_result *b)
{
    bool ok = fx_depfile_text(x, " build/gen/unity.c inc_b/defs.h "
                                 "%R/src/unit.c src/local.h") &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
              fx_depfile(x, true);
    AR_CHECK("lookups: the same closure in another inclusion order moves "
             "the root", ok && fx_same(x, b));
    ok = fx_depfile_text(x, " build/gen/unity.c %R/src/unit.c src/local.h "
                            "inc_b/defs.h src/local.h") &&
         fx_same(x, b);
    AR_CHECK("lookups: a depfile naming one header twice derives the root "
             "of the depfile naming it once", ok && fx_depfile(x, true));
    ok = fx_depfile_text(x, " build/gen/unity.c %R/src/unit.c src/local.h "
                            "inc_b/defs.h %R/src/local.h %R/inc_b/defs.h") &&
         fx_same(x, b);
    AR_CHECK("lookups: a header repeated under another spelling of the same "
             "path derives the same root", ok && fx_depfile(x, true));
    const char *saved = x->argv[3];
    x->argv[3] = "-isysteminc_b";
    ok = fx_miss(x, "search_class_conflict");
    x->argv[3] = saved;
    AR_CHECK("lookups: a dir named in two search classes is refused", ok);
}

/* A built-in include dir is recorded by its exact spelling, so only a
 * spelling that is already absolute and lexically normal may enter the
 * preimage: "/usr/include/../include" or "/usr/include/" would otherwise be
 * silently rewritten, and an over-long one could only be truncated. */
static void test_derive_builtin_dirs(struct fx *x,
                                     const struct zcl_action_root_result *b)
{
    static char overlong[PATH_MAX + 16];
    memset(overlong, 'a', sizeof(overlong) - 1);
    memcpy(overlong, "/usr/include/", 13);
    overlong[sizeof(overlong) - 1] = '\0';
    const char *const bad[] = {
        "usr/include",          "/usr/include/../include",
        "/usr/include/",        "/usr//include",
        "/usr/./include",       overlong,
    };
    const char *saved = x->system_dirs[0];
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        x->system_dirs[0] = bad[i];
        ok = fx_miss(x, "builtin_dir_noncanonical") && ok;
    }
    x->system_dirs[0] = saved;
    AR_CHECK("builtin dirs: a relative, dot-dot, trailing-slash, "
             "doubled-slash, dot or over-long entry yields no root "
             "(builtin_dir_noncanonical)", ok && fx_same(x, b));
}

static void test_derive_sysroot(struct fx *x,
                                const struct zcl_action_root_result *b)
{
    struct vcs_toolchain_capsule_v1 capsule;
    memset(&capsule, 0, sizeof(capsule));
    ar_fill(capsule.compiler_driver_sha3, 50);
    ar_fill(capsule.sysroot_sha3, 51);
    (void)snprintf(capsule.target, sizeof(capsule.target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t saved[32];
    memcpy(saved, x->req.toolchain_root, 32);
    bool ok = vcs_toolchain_capsule_v1_root(&capsule, x->req.toolchain_root);
    struct zcl_action_root_result first = {0};
    ok = ok && fx_derive(x, &first);
    capsule.compiler_backend_sha3[3] ^= 0x40;
    ok = ok && vcs_toolchain_capsule_v1_root(&capsule, x->req.toolchain_root) &&
         fx_differs(x, &first, VCS_ACTION_FIELD_V2_TOOLCHAIN);
    capsule.compiler_backend_sha3[3] ^= 0x40;
    capsule.assembler_sha3[3] ^= 0x40;
    bool as_ok =
        ok &&
        vcs_toolchain_capsule_v1_root(&capsule, x->req.toolchain_root) &&
        fx_differs(x, &first, VCS_ACTION_FIELD_V2_TOOLCHAIN);
    zcl_action_root_result_free(&first);
    memcpy(x->req.toolchain_root, saved, 32);
    AR_CHECK("toolchain: a changed compiler backend moves the root",
             ok && fx_same(x, b));
    AR_CHECK("toolchain: a changed assembler identity moves the root",
             as_ok && fx_same(x, b));
    x->req.sysroot_objects_sha3[3] ^= 0x40;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_SYSROOT);
    x->req.sysroot_objects_sha3[3] ^= 0x40;
    AR_CHECK("sysroot: changed sysroot objects move the root",
             ok && fx_same(x, b));
    x->req.sysroot = "/opt/fixture-sdk";
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_SYSROOT);
    x->req.sysroot = "/srv/host-b/sdk";
    ok = ok && fx_miss(x, "sysroot_noncanonical");
    x->req.sysroot = NULL;
    AR_CHECK("sysroot: a driver sysroot moves the root; a host one is "
             "refused", ok && fx_same(x, b));
    test_derive_builtin_dirs(x, b);
}

static void test_derive_linker(struct fx *x,
                               const struct zcl_action_root_result *b)
{
    bool ok = fx_write(x->root, "tools/ld", "fixture linker v2\n") &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_LINKER) &&
              fx_write(x->root, "tools/ld", "fixture linker v1\n");
    AR_CHECK("linker: a different ld binary moves the root",
             ok && fx_same(x, b));
    x->req.linker.collect2 = x->ld;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_LINKER);
    x->req.linker.collect2 = NULL;
    AR_CHECK("linker: a collect2 the driver resolves moves the root",
             ok && fx_same(x, b));
    x->link_argv[1] = "-Wl,-z,now";
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_LINKER);
    x->link_argv[1] = "-fuse-ld=gold";
    ok = ok && fx_miss(x, "search_flag_unsupported");
    x->link_argv[1] = "-shared";
    AR_CHECK("linker: link flags move the root; -fuse-ld is refused",
             ok && fx_same(x, b));
    /* Each names a library, a search dir or an input whose bytes the root
     * never hashes. */
    static const char *const unbound[] = {
        "-static", "-lfoo", "-Ltools", "-Wl,-rpath,/opt/lib",
        "-Wl,-z,origin", "build/extra.o", "@build/link.rsp",
    };
    for (size_t i = 0; i < sizeof(unbound) / sizeof(unbound[0]); i++) {
        x->link_argv[1] = unbound[i];
        if (!fx_miss(x, "argv_unrecognised")) {
            printf("    link word admitted: %s\n", unbound[i]);
            ok = false;
        }
    }
    x->link_argv[1] = "-shared";
    AR_CHECK("linker: -static, -l, -L, unknown -Wl, items, extra inputs and "
             "response files miss (argv_unrecognised)", ok && fx_same(x, b));
    x->req.linker.links = false;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_LINKER);
    x->req.linker.links = true;
    x->req.linker.ld = "/srv/host-b/bin/ld";
    ok = ok && fx_miss(x, "linker_unavailable");
    x->req.linker.ld = x->ld;
    AR_CHECK("linker: a stage that stops at the object differs; a linker "
             "outside the checkout or system is refused", ok && fx_same(x, b));
}

static void test_derive_generated(struct fx *x,
                                  const struct zcl_action_root_result *b)
{
    x->req.producer_count = 1;
    bool ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_GENERATED);
    struct zcl_action_root_result known = {0};
    ok = ok && fx_derive(x, &known);
    x->producers[0].action_key[0] ^= 1;
    ok = ok && known.preimage &&
         fx_differs(x, &known, VCS_ACTION_FIELD_V2_GENERATED);
    x->producers[0].action_key[0] ^= 1;
    x->req.producer_count = 0;
    zcl_action_root_result_free(&known);
    AR_CHECK("generated: a known producer replaces the unknown-producer "
             "marker, and its key moves the root", ok && fx_same(x, b));
    char unity[PATH_MAX + 64];
    (void)snprintf(unity, sizeof(unity),
                   "#include \"%s/src/unit.c\"\n/* regenerated */\n",
                   x->root);
    ok = fx_write(x->root, "build/gen/unity.c", unity) &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_GENERATED) && fx_tree(x);
    AR_CHECK("generated: regenerated content moves the root",
             ok && fx_same(x, b));
}

static void test_derive_roots(struct fx *x,
                              const struct zcl_action_root_result *b)
{
    x->req.harness.root[0] ^= 1;
    bool ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_HARNESS);
    x->req.harness.root[0] ^= 1;
    AR_CHECK("harness: a changed harness root moves the root",
             ok && fx_same(x, b));
    x->req.fixtures.root[0] ^= 1;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_FIXTURES);
    x->req.fixtures.root[0] ^= 1;
    AR_CHECK("fixtures: a changed fixture root moves the root",
             ok && fx_same(x, b));
    x->req.policy.root[0] ^= 1;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_POLICY);
    x->req.policy.root[0] ^= 1;
    AR_CHECK("policy: a changed policy root moves the root",
             ok && fx_same(x, b));
    x->req.abi_generation = 2;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ABI);
    x->req.abi_generation = 1;
    x->abi[0].version = 2;
    ok = ok && fx_differs(x, b, VCS_ACTION_FIELD_V2_ABI);
    x->abi[0].version = 1;
    AR_CHECK("abi: a new ABI generation or component version moves the root",
             ok && fx_same(x, b));
}

static void test_derive_env(struct fx *x,
                            const struct zcl_action_root_result *b)
{
    x->env[2] = "SOURCE_DATE_EPOCH=1";
    bool ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ENV);
    x->env[2] = "SOURCE_DATE_EPOCH=0";
    AR_CHECK("env: an allowlisted variable change moves the root",
             ok && fx_same(x, b));
    x->env[FX_ENV_SLOT] = "TZ=";
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ENV);
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: an allowlisted variable set empty differs from unset",
             ok && fx_same(x, b));
    x->env[1] = "HOME=/srv/host-c";
    ok = fx_same(x, b);
    x->env[FX_ENV_SLOT] = "PATH=/opt/other/bin:/usr/bin";
    ok = ok && fx_same(x, b);
    x->env[1] = "HOME=/srv/fixture-home";
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: non-allowlisted variables never reach the root", ok);
    x->env[FX_ENV_SLOT] = "SDKROOT=/srv/host-b/sdk";
    ok = fx_miss(x, "env_noncanonical");
    x->env[FX_ENV_SLOT] = "LANG=C";
    ok = ok && fx_miss(x, "env_duplicate");
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: a host path value or a repeated allowlisted name is "
             "refused, not normalized", ok && fx_same(x, b));
    static const char *const search[] = {
        "CPATH=inc_b", "C_INCLUDE_PATH=inc_b", "LIBRARY_PATH=tools",
        "LIBRARY_PATH=", "COMPILER_PATH=tools", "GCC_EXEC_PREFIX=tools/",
    };
    ok = true;
    for (size_t i = 0; i < sizeof(search) / sizeof(search[0]); i++) {
        x->env[FX_ENV_SLOT] = search[i];
        ok = fx_miss(x, "env_search_unbound") && ok;
    }
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: a variable that adds include or library search dirs "
             "misses even when empty (env_search_unbound)",
             ok && fx_same(x, b));
}

/* The root binds exactly the environment it is given: every entry is an
 * allowlisted name (bound by value) or PATH, HOME, TMPDIR (passed through,
 * the programs PATH resolves bound by their bytes). Anything else could
 * steer the compile unbound, so it misses instead of being skipped. */
static void test_derive_env_unbound(struct fx *x,
                                    const struct zcl_action_root_result *b)
{
    static const char *const unbound[] = {
        "LD_RUN_PATH=/opt/fx", "LD_LIBRARY_PATH=/opt/fx",
        "CCC_OVERRIDE_OPTIONS=+-DFOO=2", "FX_UNKNOWN=1",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(unbound) / sizeof(unbound[0]); i++) {
        x->env[FX_ENV_SLOT] = unbound[i];
        ok = fx_miss(x, "env_unbound") && ok;
    }
    x->env[FX_ENV_SLOT] = "TMPDIR=/srv/fixture-tmp";
    ok = ok && fx_same(x, b);
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: a name neither allowlisted nor passed through misses "
             "(env_unbound); TMPDIR passes through", ok && fx_same(x, b));
}

/* A compile cache in the driver command (zcc, ccache) would answer the
 * compile from its own store: a root exists only for an environment that
 * carries exactly the fixed off switches, once each. */
static void test_derive_cache_off(struct fx *x,
                                  const struct zcl_action_root_result *b)
{
    x->env[3] = "CCACHE_DISABLE=0";
    bool ok = fx_miss(x, "compile_cache_unbound");
    x->env[3] = "CCACHE_DISABLE=1";
    x->env[4] = NULL;
    ok = fx_miss(x, "compile_cache_unbound") && ok;
    x->env[4] = "ZCC_DISABLE=1";
    x->env[FX_ENV_SLOT] = "ZCC_DISABLE=1";
    ok = fx_miss(x, "env_duplicate") && ok;
    x->env[FX_ENV_SLOT] = "ZCC_DISABLE=";
    ok = fx_miss(x, "compile_cache_unbound") && ok;
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: a root needs CCACHE_DISABLE=1 and ZCC_DISABLE=1, once "
             "each; any other value or a missing one misses "
             "(compile_cache_unbound)", ok && fx_same(x, b));
    static const char *const parent[] = {
        "ZCC_DISABLE=0", "CCACHE_DIR=/srv/fx-ccache", "ZCC_DIR=/srv/fx-zcc",
        "PATH=/usr/bin", "LANG=C", NULL,
    };
    struct zcl_action_root_child_env *env = zcl_calloc(1, sizeof(*env),
                                                       "test child env");
    ok = env && zcl_action_root_child_env(parent, env) && env->n == 4 &&
         strcmp(env->v[0], "PATH=/usr/bin") == 0 &&
         strcmp(env->v[1], "LANG=C") == 0 &&
         strcmp(env->v[2], "CCACHE_DISABLE=1") == 0 &&
         strcmp(env->v[3], "ZCC_DISABLE=1") == 0 && env->v[4] == NULL;
    free(env);
    AR_CHECK("env: the child environment drops the parent's compile-cache "
             "settings and carries the fixed off switches", ok);
}

/* execvp takes an empty or relative PATH element as the child's cwd (the
 * checkout), which no program the root resolves looks at. */
static void test_derive_path_relative(struct fx *x,
                                      const struct zcl_action_root_result *b)
{
    static const char *const bad[] = {
        "PATH=/usr/bin:", "PATH=:/usr/bin", "PATH=/usr/bin::/bin",
        "PATH=bin:/usr/bin", "PATH=.:/usr/bin", "PATH=",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        x->env[FX_ENV_SLOT] = bad[i];
        if (!fx_miss(x, "env_path_relative")) {
            printf("    PATH admitted: %s\n", bad[i]);
            ok = false;
        }
    }
    x->env[FX_ENV_SLOT] = "PATH=/usr/local/bin:/usr/bin";
    ok = ok && fx_same(x, b);
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("env: a PATH with an empty or relative element misses "
             "(env_path_relative); an absolute one passes through", ok);
}

static const char k_fx_embed[] =
    "#if __has_embed(\"blob.bin\" limit(4))\n#endif\nint local(void);\n";

/* __has_embed asks whether a resource resolves without the depfile ever
 * naming it: an earlier-dir data file appearing or disappearing moves the
 * root, and an operand that is not a literal name misses. */
static void test_derive_embed(struct fx *x,
                              const struct zcl_action_root_result *b)
{
    struct zcl_action_root_result emb = {0}, later = {0};
    bool ok = fx_write(x->root, "src/local.h", k_fx_embed) &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE) &&
              fx_derive(x, &emb) &&
              fx_write(x->root, "inc_b/blob.bin", "\x01\x02\x03") &&
              fx_differs(x, &emb, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
              fx_derive(x, &later) &&
              fx_write(x->root, "inc_a/blob.bin", "\x04\x05") &&
              fx_differs(x, &later, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
              fx_remove(x->root, "inc_a/blob.bin") && fx_same(x, &later) &&
              fx_remove(x->root, "inc_b/blob.bin") && fx_same(x, &emb);
    AR_CHECK("embed: a data file appearing or disappearing where "
             "__has_embed looks, earlier dir included, moves the root", ok);
    ok = fx_write(x->root, "src/local.h",
                  "#if __has_embed(BLOB_NAME)\n#endif\nint local(void);\n") &&
         fx_miss(x, "conditional_lookup_unbound") &&
         fx_write(x->root, "src/local.h", "int local(void);\n") &&
         fx_same(x, b);
    AR_CHECK("embed: a __has_embed operand that is not a literal name misses "
             "(conditional_lookup_unbound)", ok);
    zcl_action_root_result_free(&emb);
    zcl_action_root_result_free(&later);
}

/* A derivation after a compile binds only inputs that settled before it
 * started: an edit inside the compile window misses, even one reverted to
 * the exact bytes (the compiler may have read the edit). */
static void test_derive_compile_window(struct fx *x,
                                       const struct zcl_action_root_result *b)
{
    zcl_action_root_t0_take(&x->req.compile_t0);
    bool ok = fx_same(x, b);
    AR_CHECK("compile window: inputs settled before the compile derive the "
             "same root", ok);
    ok = fx_write(x->root, "src/local.h", "int local(long);\n") &&
         fx_miss(x, "input_changed_during_compile") &&
         fx_write(x->root, "src/local.h", "int local(void);\n") &&
         fx_miss(x, "input_changed_during_compile");
    AR_CHECK("compile window: a closure file edited after the compile "
             "started misses, even reverted to its exact bytes "
             "(input_changed_during_compile)", ok);
    zcl_action_root_t0_take(&x->req.compile_t0);
    ok = fx_same(x, b) && fx_write(x->root, "inc_a/defs.h", "#define X 9\n") &&
         fx_miss(x, "input_changed_during_compile") &&
         fx_remove(x->root, "inc_a/defs.h") && fx_same(x, b) &&
         fx_write(x->root, "build/gen/unity.c", x->unity_text) &&
         fx_miss(x, "input_changed_during_compile");
    x->req.compile_t0 = (struct zcl_action_root_t0){0};
    AR_CHECK("compile window: a header appearing earlier in the search, or a "
             "generated input rewritten, during the compile misses",
             ok && fx_same(x, b));
}

static void test_derive_refusals(struct fx *x)
{
    const char *saved = x->argv[3];
    x->argv[3] = "-I/srv/host-b/include";
    bool ok = fx_miss(x, "include_dir_outside_repo");
    x->argv[3] = saved;
    AR_CHECK("an include dir outside the checkout is refused", ok);
    char outside[PATH_MAX + 64], text[2 * PATH_MAX + 96];
    (void)snprintf(outside, sizeof(outside), "%s-outside/leak.h", x->root);
    (void)snprintf(text, sizeof(text), "build/obj.o: src/unit.c %s\n",
                   outside);
    ok = fx_write(x->root, "build/unit.d", text) &&
         fx_miss(x, "dependency_outside_repo") &&
         fx_depfile(x, true);
    AR_CHECK("miss: a dependency outside the checkout and every system "
             "prefix yields no root (dependency_outside_repo)", ok);
    x->argv[3] = "-nostdinc";
    ok = fx_miss(x, "search_flag_unsupported");
    x->argv[3] = saved;
    AR_CHECK("a flag that moves the built-in include search is refused", ok);
}

/* Argv is an allowlist: a word the derivation does not understand may add
 * a search dir it never probes or name a file it never hashes, so it
 * misses rather than hits. Each replaces -Iinc_a (and -Iinc_b for the
 * two-word forms). */
static void test_derive_allowlist(struct fx *x,
                                  const struct zcl_action_root_result *b)
{
    static const char *const one[] = {
        "--include-directory=inc_b", "-I=inc_b", "-isystem=inc_b",
        "-iquote=inc_b", "-idirafter=inc_b", "-isystem-after",
        "-iframeworkinc_b", "-Finc_b", "-cxx-isystem",
        "--system-header-prefix=inc_b", "@build/args.rsp",
        "-fplugin=tools/plugin.so", "-fplugin-arg-x-y", "-includesrc/local.h",
        "-include-pch", "-imacrossrc/local.h", "-m32", "--target=x86_64",
        "-Wp,-include,src/local.h", "-Wa,-I,inc_b", "-fsanitize=address",
        "-fprofile-use", "-specs=tools/specs", "src/other.c", "-xc++",
    };
    static const char *const two[][2] = {
        { "-include", "src/local.h" }, { "-imacros", "src/local.h" },
        { "-I", "=inc_b" }, { "-isystem", "=inc_b" }, { "-x", "c++" },
        { "-target", "x86_64" }, { "-iframework", "inc_b" },
    };
    const char *a3 = x->argv[3], *a4 = x->argv[4];
    bool ok = true;
    for (size_t i = 0; i < sizeof(one) / sizeof(one[0]); i++) {
        x->argv[3] = one[i];
        if (!fx_miss(x, strcmp(one[i], "-specs=tools/specs") == 0
                            ? "search_flag_unsupported"
                            : "argv_unrecognised")) {
            printf("    admitted: %s\n", one[i]);
            ok = false;
        }
    }
    for (size_t i = 0; i < sizeof(two) / sizeof(two[0]); i++) {
        x->argv[3] = two[i][0];
        x->argv[4] = two[i][1];
        if (!fx_miss(x, "argv_unrecognised")) {
            printf("    admitted: %s %s\n", two[i][0], two[i][1]);
            ok = false;
        }
    }
    x->argv[3] = a3;
    x->argv[4] = a4;
    AR_CHECK("argv: framework, sysroot-prefixed and unknown include-dir "
             "flags, response files, plugins, relative forced includes, "
             "target flags and inputs outside the closure miss", ok &&
                 fx_same(x, b));
    fx_check_flag(x, b, "argv: an allowlisted -march moves the flags", 6,
                  "-march=x86-64-v3");
    fx_check_flag(x, b, "argv: a -frandom-seed= string (every dev object "
                  "carries one) is bound by value and moves the flags", 6,
                  "-frandom-seed=src/unit.c");
    fx_check_flag(x, b, "argv: an allowlisted -mcpu (ARM plans) moves the "
                  "flags", 6, "-mcpu=cortex-a72");
}

/* A name that climbs ("../defs.h") is bound only as a quote name found
 * beside its includer; through a search dir, or as <...>, it misses. */
static void test_derive_climb(struct fx *x,
                              const struct zcl_action_root_result *b)
{
    bool ok = fx_write(x->root, "src/local.h",
                       "#include \"../inc_b/defs.h\"\nint local(void);\n") &&
              fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE);
    AR_CHECK("climb: a quote \"../\" name found beside its includer is bound",
             ok);
    static const char *const unbound[] = {
        "#include \"../defs.h\"\n", "#include <../inc_b/defs.h>\n",
        "#  include_next \"../inc_b/defs.h\"\n", "#embed \"../x.bin\"\n",
        "#include \"sub/../../defs.h\"\n", "#import \"..\\\\defs.h\"\n",
    };
    for (size_t i = 0; i < sizeof(unbound) / sizeof(unbound[0]); i++) {
        char text[256];
        (void)snprintf(text, sizeof(text), "%sint local(void);\n",
                       unbound[i]);
        if (!fx_write(x->root, "src/local.h", text) ||
            !fx_miss(x, "include_climb_unbound")) {
            printf("    climb admitted: %s", unbound[i]);
            ok = false;
        }
    }
    ok = ok && fx_write(x->root, "src/local.h",
                        "/* #include \"../defs.h\" */\nint local(void);\n"
                        "static const char *p = \"#include <../x.h>\";\n") &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE);
    ok = ok && fx_write(x->root, "src/local.h", "int local(void);\n");
    AR_CHECK("climb: through a search dir, as <...>, as include_next or "
             "embed it misses (include_climb_unbound); in a comment or a "
             "string it asks nothing", ok && fx_same(x, b));
}

/* Write `text` at root/rel as an executable. */
static bool fx_exec(const struct fx *x, const char *rel, const char *text)
{
    char path[PATH_MAX];
    return snprintf(path, sizeof(path), "%s/%s", x->root, rel) <
               (int)sizeof(path) &&
           fx_write(x->root, rel, text) && chmod(path, 0700) == 0;
}

/* The fixture backend: a cc1, and an assembler whose --version line stays
 * the same across builds that differ only in their bytes. */
static const char k_fx_cc1_v1[] = "#!/bin/sh\n# fixture cc1 v1\nexit 0\n";
static const char k_fx_cc1_v2[] = "#!/bin/sh\n# fixture cc1 v2\nexit 0\n";
static const char k_fx_as_v1[] =
    "#!/bin/sh\necho 'GNU assembler (fixture) 2.42'\n# build 1\n";
static const char k_fx_as_v2[] =
    "#!/bin/sh\necho 'GNU assembler (fixture) 2.42'\n# build 2\n";

/* A driver whose built-in list depends on -mtune=, that skips sysnew as
 * nonexistent until it exists, and whose libc.so lives in the checkout.
 * Asked what it runs (-###) it names tools/cc1 and tools/as, or prefix/as
 * once that exists in its own program prefix, as GCC would.
 * Like GCC, it reports a skipped dir before the search list, never inside
 * it (an entry that is not a canonical dir is refused). */
/* The fake driver's text: `line` is printed first when asked -###, and
 * `arg` is one more cc1 argument (both "" for the plain driver). */
static int fx_fake_driver_text(const struct fx *x, const char *line,
                               const char *arg, char *script, size_t cap)
{
    return snprintf(
        script, cap,
        "#!/bin/sh\nR='%s'\n"
        "case \" $* \" in\n"
        "*\" -print-prog-name=ld \"*) echo ld; exit 0;;\n"
        "*\" -print-sysroot \"*) echo; exit 0;;\n"
        "*\" -print-file-name=libc.so \"*) echo \"$R/lib/libc.so\"; exit 0;;\n"
        "*\" -### \"*)\n%s"
        "  a=\"$R/tools/as\"; [ -x \"$R/prefix/as\" ] && a=\"$R/prefix/as\"\n"
        "  echo \"COMPILER_PATH=$R/prefix/\"\n"
        "  echo \" \\\"$R/tools/cc1\\\" \\\"-quiet\\\" %s\\\"-o\\\" \\\"$R/x.s\\\"\"\n"
        "  echo \" $a --64 -o /dev/null $R/x.s\"; exit 0;;\n"
        "*\" -v \"*)\n"
        "  d=sysdef; case \" $* \" in *\" -mtune=alt \"*) d=sysalt;; esac\n"
        "  [ -d \"$R/sysnew\" ] ||\n"
        "    echo \"ignoring nonexistent directory \\\"$R/sysnew\\\"\"\n"
        "  echo '#include <...> search starts here:'\n"
        "  [ -d \"$R/sysnew\" ] && echo \" $R/sysnew\"\n"
        "  echo \" $R/$d\"; echo 'End of search list.'; exit 0;;\n"
        "esac\nfor a do shift; case \"$a\" in -mtune=*) ;;\n"
        "  *) set -- \"$@\" \"$a\";; esac; done\n"
        "exec cc \"$@\"\n", x->root, line, arg);
}

static bool fx_fake_driver(struct fx *x, char cc[PATH_MAX])
{
    char script[4 * PATH_MAX + 1024];
    int n = fx_fake_driver_text(x, "", "", script, sizeof(script));
    char path[PATH_MAX];
    return n > 0 && n < (int)sizeof(script) &&
           fx_write(x->root, "tools/tcc.sh", script) &&
           fx_write(x->root, "lib/libc.so", "GROUP ( libc.so.6 )\n") &&
           fx_exec(x, "tools/cc1", k_fx_cc1_v1) &&
           fx_exec(x, "tools/as", k_fx_as_v1) &&
           snprintf(path, sizeof(path), "%s/tools/tcc.sh", x->root) <
               (int)sizeof(path) &&
           chmod(path, 0700) == 0 &&
           snprintf(cc, PATH_MAX, "%s", path) < PATH_MAX;
}

/* The fake driver strips -mtune= (it only selects its built-in list); the
 * host driver is asked with plain flags. */
static const char *fx_key_cflags(const char *cc)
{
    return strcmp(cc, "cc") == 0 ? "-std=c23 -Iinc_a -Iinc_b -DFOO=1"
                                 : "-std=c23 -Iinc_a -Iinc_b -DFOO=1 -mtune=alt";
}

static bool fx_key(struct fx *x, const char *cc, char out[65])
{
    char miss[40] = {0};
    const char *cflags = fx_key_cflags(cc);
    bool ok = zcl_devloop_action_root_key(x->root, "src/unit.c", cc, cflags,
                                          "-shared", NULL, x->depfile, NULL, NULL,
                                          out, miss);
    if (!ok)
        printf("    key missed: %s\n", miss);
    return ok;
}

static bool fx_key_differs_then_same(struct fx *x, const char *cc,
                                     const char *k1, const char *k2,
                                     bool ok)
{
    char k3[65] = {0};
    return ok && fx_key(x, cc, k3) && strcmp(k1, k2) != 0 &&
           strcmp(k1, k3) == 0;
}

/* The hot-swap key asks the driver with the plan's target flags, re-asks
 * when a skipped built-in dir appears, and binds implicit link libraries. */
static void test_key_driver_targets(struct fx *x, const char *cc, char k1[65])
{
    char k2[65] = {0}, k3[65] = {0};
    bool ok = fx_write(x->root, "src/unit.c",
                       "#include \"local.h\"\n#include <defs.h>\n"
                       "#if __has_include(<zopt.h>)\n#endif\n"
                       "int unit(void) { return X; }\n") &&
              fx_key(x, cc, k1) && fx_write(x->root, "sysalt/zopt.h", "\n") &&
              fx_key(x, cc, k2) && fx_remove(x->root, "sysalt/zopt.h") &&
              fx_write(x->root, "sysdef/zopt.h", "\n") &&
              fx_key(x, cc, k3) && fx_remove(x->root, "sysdef/zopt.h");
    AR_CHECK("key: built-in dirs are asked with the plan's -mtune= "
             "(a header in that list moves the key, one in the default "
             "list does not)",
             ok && strcmp(k1, k2) != 0 && strcmp(k1, k3) == 0);
}

static void test_key_backend(struct fx *x, const char *cc);

static void test_key_driver_facts(struct fx *x)
{
    char cc[PATH_MAX], k1[65] = {0}, k2[65] = {0}, dir[PATH_MAX];
    if (!fx_fake_driver(x, cc)) {
        AR_CHECK("key: fake driver fixture", false);
        return;
    }
    test_key_driver_targets(x, cc, k1);
    (void)snprintf(dir, sizeof(dir), "%s/sysnew", x->root);
    bool ok = fx_write(x->root, "sysnew/zopt.h", "\n") && fx_key(x, cc, k2) &&
              fx_remove(x->root, "sysnew/zopt.h") && rmdir(dir) == 0;
    AR_CHECK("key: a built-in dir the driver skipped as nonexistent that "
             "appears re-asks the driver and moves the key",
             fx_key_differs_then_same(x, cc, k1, k2, ok));
    ok = fx_write(x->root, "lib/libc.so", "GROUP ( libc.so.7 )\n") &&
         fx_key(x, cc, k2) &&
         fx_write(x->root, "lib/libc.so", "GROUP ( libc.so.6 )\n");
    AR_CHECK("key: the bytes of an implicit link library move the key",
             fx_key_differs_then_same(x, cc, k1, k2, ok));
    char miss[40] = {0};
    ok = fx_write(x->root, "src/unit.c",
                  "#include \"local.h\"\n#include <defs.h>\n"
                  "int unit(void) { return X; }\n") &&
         !zcl_devloop_action_root_key(x->root, "src/unit.c", cc,
                                      "-std=c23 @build/args.rsp", "-shared",
                                      NULL, x->depfile, NULL, NULL, k2, miss) &&
         strcmp(miss, "argv_unrecognised") == 0;
    miss[0] = '\0';
    ok = ok && !zcl_devloop_action_root_key(x->root, "src/unit.c", cc,
                                            "-std=c23", "build/extra.o -shared",
                                            NULL, x->depfile, NULL, NULL, k2,
                                            miss) &&
         strcmp(miss, "argv_unrecognised") == 0;
    AR_CHECK("key: a plan that names a response file, or whose link flags "
             "start with an input, misses", ok);
    test_key_backend(x, cc);
}

/* `tools/as --version`, first line. */
static bool fx_as_version(const struct fx *x, char out[128])
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/tools/as", x->root) >=
        (int)sizeof(path))
        return false;
    const char *const argv[] = { path, "--version", NULL };
    if (zcl_spawn_capture(argv, out, 128, 10000) != 0)
        return false;
    out[strcspn(out, "\r\n")] = '\0';
    return out[0] != '\0';
}

static bool fx_key_miss(struct fx *x, const char *cc, const char *code)
{
    char key[65] = {0}, miss[40] = {0};
    const char *cflags = fx_key_cflags(cc);
    bool missed = !zcl_devloop_action_root_key(x->root, "src/unit.c", cc,
                                               cflags, "-shared", NULL,
                                               x->depfile, NULL, NULL, key, miss);
    bool ok = missed && strcmp(miss, code) == 0 && !key[0];
    if (!ok)
        printf("    expected key miss %s, got %s\n", code,
               missed ? miss : "a key");
    return ok;
}

static void test_key_sysroot_override(struct fx *x)
{
    static const char *const flags[] = {
        "-isysroot /tmp", "--sysroot=/tmp", "-sysroot /tmp",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        char key[65] = {0}, miss[40] = {0};
        ok = !zcl_devloop_action_root_key(
                 x->root, "src/unit.c", "cc", flags[i], "-shared", NULL,
                 x->depfile, NULL, NULL, key, miss) &&
             strcmp(miss, "driver_sysroot_override_unbound") == 0 &&
             !key[0] && ok;
    }
    char key[65] = {0}, miss[40] = {0};
    ok = !zcl_devloop_action_root_key(
             x->root, "src/unit.c", "cc", "-std=c23",
             "-shared -Wl,-syslibroot,/tmp", NULL, x->depfile,
             NULL, NULL, key, miss) &&
         strcmp(miss, "driver_sysroot_override_unbound") == 0 &&
         !key[0] && ok;
    AR_CHECK("driver facts: an explicit compile or link sysroot refuses "
             "before an action root can reuse default SDK facts", ok);
}

#if defined(__APPLE__)
static void test_key_sysroot_capsule_mismatch(struct fx *x)
{
    char cc[PATH_MAX], script[4 * PATH_MAX + 1024];
    const char *line =
        "  echo ' \"cc\" \"-cc1\" \"-isysroot\" \"/tmp\"'\n";
    int n = fx_fake_driver_text(x, line, "", script, sizeof(script));
    bool ok = n > 0 && n < (int)sizeof(script) &&
              fx_fake_driver(x, cc) &&
              fx_write(x->root, "tools/tcc.sh", script) &&
              fx_key_miss(x, cc, "driver_sysroot_capsule_mismatch") &&
              fx_fake_driver(x, cc);
    AR_CHECK("driver facts: a cc1 SDK outside the capsule refuses a key",
             ok);
}
#endif

/* A same-name program appearing in the driver's own prefix, then one the
 * driver would run that is gone. */
static void test_key_backend_unresolved(struct fx *x, const char *cc,
                                        const char *k1)
{
    char k2[65] = {0};
    bool ok = fx_exec(x, "prefix/as", k_fx_as_v2) && fx_key(x, cc, k2) &&
              fx_remove(x->root, "prefix/as");
    AR_CHECK("backend: an assembler appearing in the driver's own program "
             "prefix re-asks the driver and moves the key",
             fx_key_differs_then_same(x, cc, k1, k2, ok));
    ok = fx_exec(x, "prefix/ld", "#!/bin/sh\n") &&
         fx_key_miss(x, cc, "backend_unresolved") &&
         fx_remove(x->root, "prefix/ld") && fx_remove(x->root, "tools/cc1") &&
         fx_key_miss(x, cc, "backend_unresolved") &&
         fx_exec(x, "tools/cc1", k_fx_cc1_v1) && fx_key(x, cc, k2) &&
         strcmp(k1, k2) == 0;
    AR_CHECK("backend: a program the driver runs that does not resolve, or a "
             "same-name program its prefix search would take instead, misses "
             "(backend_unresolved)", ok);
}

/* The compile backend is whatever the plan's own driver runs, bound by its
 * bytes: never the host toolchain's cc1, never an assembler's --version. */
static void test_key_backend(struct fx *x, const char *cc)
{
    char k1[65] = {0}, k2[65] = {0}, v1[128] = {0}, v2[128] = {0};
    bool ok = fx_key(x, cc, k1) && fx_exec(x, "tools/cc1", k_fx_cc1_v2) &&
              fx_key(x, cc, k2) && fx_exec(x, "tools/cc1", k_fx_cc1_v1);
    AR_CHECK("backend: new bytes in the cc1 the plan driver runs move the key",
             fx_key_differs_then_same(x, cc, k1, k2, ok));
    ok = fx_as_version(x, v1) && fx_exec(x, "tools/as", k_fx_as_v2) &&
         fx_as_version(x, v2) && strcmp(v1, v2) == 0 && fx_key(x, cc, k2) &&
         fx_exec(x, "tools/as", k_fx_as_v1);
    AR_CHECK("backend: an assembler with new bytes and the same --version "
             "moves the key", fx_key_differs_then_same(x, cc, k1, k2, ok));
    test_key_backend_unresolved(x, cc, k1);
}

/* Names that steer a compiler, linker or loader never reach the compile
 * child; one present in the parent is a named miss, never a silent drop. */
static void test_key_env_influential(struct fx *x)
{
    static const struct { const char *name, *value, *code; } cases[] = {
        { "CCC_OVERRIDE_OPTIONS", "+-DZCL_FX=1", "env_influential_unbound" },
        { "LD_RUN_PATH", "/opt/fx-run", "env_influential_unbound" },
        { "LD_LIBRARY_PATH", "/opt/fx-lib", "env_influential_unbound" },
        { "GCC_COMPARE_DEBUG", "1", "env_influential_unbound" },
        { "CPLUS_INCLUDE_PATH", "inc_b", "env_search_unbound" },
    };
    char k1[65] = {0}, k2[65] = {0};
    bool ok = fx_key(x, "cc", k1);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bool had = getenv(cases[i].name) != NULL;
        ok = !had &&
             platform_environment_set(cases[i].name, cases[i].value, 1) == 0 &&
             fx_key_miss(x, "cc", cases[i].code) && ok;
        (void)unsetenv(cases[i].name);
    }
    AR_CHECK("env: CCC_OVERRIDE_OPTIONS, LD_RUN_PATH, LD_LIBRARY_PATH, "
             "GCC_COMPARE_DEBUG or a search variable in the parent misses "
             "by name", ok && fx_key(x, "cc", k2) && strcmp(k1, k2) == 0);
    ok = getenv("GCC_COLORS") == NULL &&
         platform_environment_set("GCC_COLORS", "error=01;31", 1) == 0 &&
         fx_key(x, "cc", k2) && strcmp(k1, k2) == 0;
    (void)unsetenv("GCC_COLORS");
    AR_CHECK("env: a diagnostics-only variable neither reaches the child nor "
             "moves the key", ok);
}

/* Install fake driver text as root/<dir>/fxinner. */
static bool fx_inner_driver(struct fx *x, const char *dir, const char *line,
                            const char *arg)
{
    char script[4 * PATH_MAX + 1024], rel[64];
    int n = fx_fake_driver_text(x, line, arg, script, sizeof(script));
    return n > 0 && n < (int)sizeof(script) &&
           snprintf(rel, sizeof(rel), "%s/fxinner", dir) < (int)sizeof(rel) &&
           fx_exec(x, rel, script);
}

/* Key the wrapper with root/<dir> first on PATH. */
static bool fx_key_inner(struct fx *x, const char *saved, const char *dir,
                         const char *cc, char out[65])
{
    char path[8192 + PATH_MAX];
    return snprintf(path, sizeof(path), "%s/%s:%s", x->root, dir, saved) <
               (int)sizeof(path) &&
           platform_environment_set("PATH", path, 1) == 0 &&
           fx_key(x, cc, out);
}

/* The wrapper and three inner drivers: d1 plain, d2 one -### argument more,
 * d3 announcing a Configuration file. */
static bool fx_inner_drivers(struct fx *x, char cc[PATH_MAX])
{
    return fx_exec(x, "tools/wrap.sh", "#!/bin/sh\nexec fxinner \"$@\"\n") &&
           snprintf(cc, PATH_MAX, "%s/tools/wrap.sh", x->root) < PATH_MAX &&
           fx_inner_driver(x, "d1", "", "") &&
           fx_inner_driver(x, "d2", "", "\\\"-fx-inner-spec\\\" ") &&
           fx_inner_driver(x, "d3",
                           "  echo 'Configuration file: /etc/fx.cfg'\n", "");
}

/* A wrapper (same bytes) runs an inner driver from PATH. Two inner drivers
 * that run the same programs but differ in one -### argument key apart;
 * one that reads a Configuration file misses (backend_config_unbound). */
static void test_key_backend_lines(struct fx *x)
{
    const char *path = getenv("PATH");
    char saved[8192], cc[PATH_MAX], k1[65] = {0}, k2[65] = {0};
    char k3[65] = {0}, with[8192 + PATH_MAX];
    bool ok = path && snprintf(saved, sizeof(saved), "%s", path) <
                          (int)sizeof(saved) &&
              fx_inner_drivers(x, cc) &&
              fx_key_inner(x, saved, "d1", cc, k1) &&
              fx_key_inner(x, saved, "d2", cc, k2) &&
              fx_key_inner(x, saved, "d1", cc, k3);
    AR_CHECK("backend: two inner drivers running the same programs, one -### "
             "argument apart, key apart; back to the first keys the same",
             ok && strcmp(k1, k2) != 0 && strcmp(k1, k3) == 0);
    ok = ok && snprintf(with, sizeof(with), "%s/d3:%s", x->root, saved) <
                   (int)sizeof(with) &&
         platform_environment_set("PATH", with, 1) == 0 &&
         fx_key_miss(x, cc, "backend_config_unbound");
    if (path)
        (void)platform_environment_set("PATH", saved, 1);
    AR_CHECK("backend: a driver that reads a Configuration file misses "
             "(backend_config_unbound)", ok);
}

/* The inner driver behind the same wrapper is replaced in place (an
 * update-alternatives flip, a rewritten exec target) with PATH, flags and
 * environment unchanged: the warm key must see the new -### lines, and an
 * inner driver that no longer answers must miss, never reuse the old facts. */
static void test_key_inner_replaced(struct fx *x)
{
    const char *path = getenv("PATH");
    char saved[8192], cc[PATH_MAX], k1[65] = {0}, k2[65] = {0};
    char k3[65] = {0};
    bool ok = path && snprintf(saved, sizeof(saved), "%s", path) <
                          (int)sizeof(saved) &&
              fx_inner_drivers(x, cc) &&
              fx_key_inner(x, saved, "d1", cc, k1) &&
              fx_inner_driver(x, "d1", "", "\\\"-fx-inner-spec\\\" ") &&
              fx_key(x, cc, k2) && fx_inner_driver(x, "d1", "", "") &&
              fx_key(x, cc, k3);
    AR_CHECK("backend: an inner driver replaced in place behind the same "
             "wrapper and PATH moves the warm key; restored, it returns",
             ok && strcmp(k1, k2) != 0 && strcmp(k1, k3) == 0);
    ok = ok && fx_exec(x, "d1/fxinner", "#!/bin/sh\nexit 1\n") &&
         fx_key_miss(x, cc, "driver_facts_unavailable") &&
         fx_inner_driver(x, "d1", "", "");
    if (path)
        (void)platform_environment_set("PATH", saved, 1);
    AR_CHECK("backend: an inner driver that stops answering -### misses "
             "instead of reusing its cached facts", ok);
}

/* gcc writes its temporaries under /tmp when TMPDIR names no directory. The
 * -### re-ask must still collapse them, or every warm key moves. */
static void test_key_tmpdir_missing(struct fx *x)
{
    const char *prior = getenv("TMPDIR");
    char saved[PATH_MAX] = {0}, gone[PATH_MAX], k1[65] = {0}, k2[65] = {0};
    bool had = prior != NULL;
    bool ok = snprintf(saved, sizeof(saved), "%s", had ? prior : "") <
                  (int)sizeof(saved) &&
              snprintf(gone, sizeof(gone), "%s/no-such-tmp", x->root) <
                  (int)sizeof(gone) &&
              platform_environment_set("TMPDIR", gone, 1) == 0 &&
              fx_key(x, "cc", k1) && fx_key(x, "cc", k2);
    if (had)
        (void)platform_environment_set("TMPDIR", saved, 1);
    else
        (void)unsetenv("TMPDIR");
    AR_CHECK("backend lines: a TMPDIR that names no directory still keys "
             "the same across two asks", ok && strcmp(k1, k2) == 0);
}

/* PATH=/usr/bin: with an `as` at the checkout root: the compile child's
 * execvp would run that one; the key misses by name instead. */
static void test_key_path_relative(struct fx *x)
{
    const char *path = getenv("PATH");
    char saved[8192], bad[8192];
    bool ok = path && snprintf(saved, sizeof(saved), "%s", path) <
                          (int)sizeof(saved) &&
              fx_exec(x, "as", k_fx_as_v2);
    static const char *const values[] = { "/usr/bin:/bin:", ":/usr/bin:/bin",
                                          "/usr/bin:.:/bin" };
    for (size_t i = 0; ok && i < sizeof(values) / sizeof(values[0]); i++)
        ok = snprintf(bad, sizeof(bad), "%s", values[i]) <
                 (int)sizeof(bad) &&
             platform_environment_set("PATH", bad, 1) == 0 &&
             fx_key_miss(x, "cc", "env_path_relative");
    if (path)
        (void)platform_environment_set("PATH", saved, 1);
    char k[65] = {0};
    ok = ok && fx_remove(x->root, "as") && fx_key(x, "cc", k);
    AR_CHECK("key: PATH=/usr/bin: with an `as` at the checkout root misses "
             "(env_path_relative)", ok);
}

/* sccache, distcc and the like answer a compile from state no fixed switch
 * turns off: as a driver-command word, or as a symlink to one, they miss. */
static void test_key_cache_opaque(struct fx *x)
{
    char cc[PATH_MAX * 2], link[PATH_MAX], target[PATH_MAX];
    bool ok = fx_exec(x, "tools/sccache", "#!/bin/sh\nexec \"$@\"\n") &&
              snprintf(cc, sizeof(cc), "%s/tools/sccache cc", x->root) <
                  (int)sizeof(cc) &&
              fx_key_miss(x, cc, "driver_cache_opaque") &&
              snprintf(target, sizeof(target), "%s/tools/sccache", x->root) <
                  (int)sizeof(target) &&
              snprintf(link, sizeof(link), "%s/tools/mcc", x->root) <
                  (int)sizeof(link) &&
              symlink(target, link) == 0 &&
              fx_key_miss(x, link, "driver_cache_opaque");
    (void)fx_remove(x->root, "tools/mcc");
    (void)fx_remove(x->root, "tools/sccache");
    AR_CHECK("key: a driver command that runs an opaque compile cache "
             "(sccache by name or by symlink) misses (driver_cache_opaque)",
             ok);
}

static bool fx_unit_key(struct fx *x, const char *unit, const char *dep,
                        char out[65])
{
    char depfile[PATH_MAX], miss[40] = {0};
    bool ok = snprintf(depfile, sizeof(depfile), "%s/%s", x->root, dep) <
                  (int)sizeof(depfile) &&
              zcl_devloop_action_root_key(x->root, unit, "cc",
                                          "-std=c23 -Iinc_a -Iinc_b -DFOO=1",
                                          "-shared", NULL, depfile, NULL, NULL,
                                          out, miss);
    if (!ok)
        printf("    %s key missed: %s\n", unit, miss);
    return ok;
}

static const char k_fx_same_a[] =
    "static int helper(void) { return 1; }\n"
    "int unit_a(void) { return helper(); }\n";
static const char k_fx_same_a2[] =
    "static int helper(void) { return 7; }\n"
    "int unit_a(void) { return helper(); }\n";
static const char k_fx_same_b[] =
    "static int helper(void) { return 2; }\n"
    "int unit_b(void)\n{\n    static int helper = 3;\n    return helper;\n}\n";

/* Edit TU a's static and back: a's key moves and returns, b's never does. */
static void test_key_same_name_edit(struct fx *x, const char *ka,
                                    const char *kb)
{
    char ka2[65] = {0}, kb2[65] = {0}, ka3[65] = {0};
    bool ok = fx_write(x->root, "src/a.c", k_fx_same_a2) &&
              fx_unit_key(x, "src/a.c", "build/a.d", ka2) &&
              fx_unit_key(x, "src/b.c", "build/b.d", kb2) &&
              fx_write(x->root, "src/a.c", k_fx_same_a) &&
              fx_unit_key(x, "src/a.c", "build/a.d", ka3);
    AR_CHECK("same name: editing one TU's static moves only its own key; the "
             "shadowing TU's key is unchanged",
             ok && strcmp(ka, ka2) != 0 && strcmp(kb, kb2) == 0 &&
                 strcmp(ka, ka3) == 0);
}

/* Falsification: two TUs define the same static function name (and one
 * shadows it with a block-scope static). Their keys never alias, and an
 * edit to one moves only its own key. */
static void test_key_same_name_static(struct fx *x)
{
    char ka[65] = {0}, kb[65] = {0}, kb2[65] = {0};
    bool ok = fx_write(x->root, "src/a.c", k_fx_same_a) &&
              fx_write(x->root, "src/b.c", k_fx_same_b) &&
              fx_write(x->root, "build/a.d", "build/a.o: src/a.c\n") &&
              fx_write(x->root, "build/b.d", "build/b.o: src/b.c\n") &&
              fx_unit_key(x, "src/a.c", "build/a.d", ka) &&
              fx_unit_key(x, "src/b.c", "build/b.d", kb);
    AR_CHECK("same name: two TUs defining the same static function key apart",
             ok && strcmp(ka, kb) != 0);
    if (ok)
        test_key_same_name_edit(x, ka, kb);
    ok = ok && fx_write(x->root, "src/b.c", k_fx_same_a) &&
         fx_unit_key(x, "src/b.c", "build/b.d", kb2) &&
         fx_write(x->root, "src/b.c", k_fx_same_b);
    AR_CHECK("same name: byte-identical TUs at two paths still key apart",
             ok && strcmp(kb2, ka) != 0 && strcmp(kb2, kb) != 0);
}

/* CPU of this thread plus every reaped child (the driver queries), us. */
static int64_t fx_cpu_us(void)
{
    struct timespec ts = {0};
    struct rusage kids = {0};
    (void)clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    (void)getrusage(RUSAGE_CHILDREN, &kids);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000 +
           ((int64_t)kids.ru_utime.tv_sec + kids.ru_stime.tv_sec) * 1000000 +
           kids.ru_utime.tv_usec + kids.ru_stime.tv_usec;
}

static int fx_i64_cmp(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

#define FX_COST_N 25

/* Extraction cost of the hot-swap key with the host's real driver: the
 * first call re-asks the driver, the rest are the resident watcher's warm
 * path. Printed as a measurement; asserted only to derive. */
static void test_key_cost(struct fx *x)
{
    int64_t wall[FX_COST_N], cpu[FX_COST_N];
    const char *cflags = "-std=c23 -Iinc_a -Iinc_b -DFOO=1";
    bool ok = true;
    for (size_t i = 0; i < FX_COST_N; i++) {
        char key[65] = {0}, miss[40] = {0};
        int64_t w = platform_time_monotonic_us(), c = fx_cpu_us();
        bool derived = zcl_devloop_action_root_key(
            x->root, "src/unit.c", "cc", cflags, "-shared", NULL,
            x->depfile, NULL, NULL, key, miss);
        if (!derived)
            printf("    key cost: iteration %zu missed %s\n", i, miss);
        ok = derived && ok;
        wall[i] = platform_time_monotonic_us() - w;
        cpu[i] = fx_cpu_us() - c;
    }
    qsort(wall + 1, FX_COST_N - 1, sizeof(wall[0]), fx_i64_cmp);
    qsort(cpu + 1, FX_COST_N - 1, sizeof(cpu[0]), fx_i64_cmp);
    size_t p50 = 1 + (FX_COST_N - 1) / 2, p95 = 1 + (FX_COST_N - 1) * 95 / 100;
    printf("    key cost: cold wall_us=%lld cpu_us=%lld | warm n=%d wall_us "
           "p50=%lld p95=%lld cpu_us p50=%lld p95=%lld\n",
           (long long)wall[0], (long long)cpu[0], FX_COST_N - 1,
           (long long)wall[p50], (long long)wall[p95], (long long)cpu[p50],
           (long long)cpu[p95]);
    AR_CHECK("key cost: the host driver derives a key on every call", ok);
}

/* Unreadable for this user: mode 000, or (as root, who reads anything) a
 * directory where the header was. `on` false restores the header. */
static bool fx_unreadable(struct fx *x, const char *rel, bool on)
{
    char full[PATH_MAX];
    if (snprintf(full, sizeof(full), "%s/%s", x->root, rel) >=
        (int)sizeof(full))
        return false;
    if (geteuid() != 0)
        return chmod(full, on ? 0 : 0600) == 0;
    if (on)
        return unlink(full) == 0 && mkdir(full, 0700) == 0;
    return rmdir(full) == 0 && fx_write(x->root, rel, "int local(void);\n");
}

/* A depfile this parser cannot read exactly is a miss, never a closure
 * that was cut short or a prerequisite spelling that was guessed. */
static void test_derive_bad_depfile(struct fx *x,
                                    const struct zcl_action_root_result *b)
{
    bool ok = fx_write(x->root, "build/unit.d", "no rule here\n") &&
              fx_miss(x, "depfile_malformed") && fx_depfile(x, true);
    AR_CHECK("miss: a depfile with no rule yields no root "
             "(depfile_malformed)", ok);
    ok = fx_depfile_text(x, " %R/src/unit.c foo\\ bar.h") &&
         fx_miss(x, "depfile_malformed") && fx_depfile(x, true);
    AR_CHECK("miss: a depfile token ending in a backslash (a GCC-escaped "
             "space, not a -MP phony target) yields no root, never a "
             "closure truncated early (depfile_malformed)", ok);
    ok = fx_depfile_text(x, " %R/src/unit.c src/local\\#h.h src/local.h") &&
         fx_miss(x, "depfile_malformed") && fx_depfile(x, true);
    AR_CHECK("miss: a depfile token carrying a backslash escape this "
             "parser does not decode yields no root, never a guessed "
             "spelling (depfile_malformed)", ok);
    char eof[PATH_MAX + 64];
    ok = snprintf(eof, sizeof(eof), "build/obj.o: %s/src/unit.c "
                  "src/local.h \\", x->root) < (int)sizeof(eof) &&
         fx_write(x->root, "build/unit.d", eof) &&
         fx_miss(x, "depfile_malformed") && fx_depfile(x, true);
    AR_CHECK("miss: a depfile that ends in a dangling continuation "
             "backslash yields no root (depfile_malformed)",
             ok && fx_same(x, b));
}

/* Missing data is a MISS: no root, an explicit reason, never a guess. */
static void test_derive_misses(struct fx *x,
                               const struct zcl_action_root_result *b)
{
    bool ok = fx_remove(x->root, "build/unit.d") &&
              fx_miss(x, "depfile_missing") && fx_depfile(x, true);
    AR_CHECK("miss: a missing depfile yields no root (depfile_missing)",
             ok && fx_same(x, b));
    test_derive_bad_depfile(x, b);
    ok = fx_depfile_text(x, " build/gen/unity.c %R/src/unit.c src/gone.h "
                            "src/local.h inc_b/defs.h") &&
         fx_miss(x, "dependency_missing") && fx_depfile(x, true);
    AR_CHECK("miss: a stale depfile naming a file that no longer exists "
             "yields no root (dependency_missing)", ok);
    ok = fx_unreadable(x, "src/local.h", true) &&
         fx_miss(x, "dependency_unreadable");
    ok = fx_unreadable(x, "src/local.h", false) && ok;
    AR_CHECK("miss: an unreadable dependency yields no root "
             "(dependency_unreadable)", ok && fx_same(x, b));
    struct zcl_action_root_result r = {0};
    x->req.require_producers = true;
    ok = fx_miss(x, "producer_unknown");
    x->req.producer_count = 1;
    ok = ok && fx_derive(x, &r);
    x->req.producer_count = 0;
    x->req.require_producers = false;
    zcl_action_root_result_free(&r);
    AR_CHECK("miss: a generated input with no known producer, where one is "
             "required, yields no root (producer_unknown)", ok);
    x->req.virtual_input_token = "src/unit-unity.c";
    x->req.virtual_input_path = x->unity_in;
    ok = fx_miss(x, "request_incomplete");
    x->req.virtual_input_token = NULL;
    x->req.virtual_input_path = NULL;
    AR_CHECK("miss: a virtual input outside build/ is refused", ok);
}


/* The fixture root is a temp dir, yet the root must be byte-stable: this
 * pins the ordinary fixture's root as derived before the reserved-namespace
 * and token-collision refusals existed. */
#define FX_PINNED_ROOT_HEX \
    "f36713a506c186612abe056bfceb4629220757eef6a2338a7909784070c52896"

/* token_collision (ar_dep_collision) has no case here: it is unreachable
 * through the public entry. ar_request_valid (devloop_action_root.c:2250)
 * requires a lexically normalized root, so a repo-relative spelling and an
 * absolute spelling of one file give the same fs string; system files are
 * tokenized "@sys"+path, which is injective; and a checkout file that could
 * alias that token ("@sys/..") is pre-empted by ar_reserved_rel (lines
 * 204-250) with reserved_namespace_path, before ar_dep_seen runs. The
 * virtual input bypasses ar_dep_add. The guard is defence in depth. */
#define FX_WHY_FILE "checkout path begins with the reserved"
#define FX_WHY_ARG "argument spells a reserved token namespace"
#define FX_WHY_ENV "environment value has no canonical spelling"

/* A file both spelled "@sys/..." inside the checkout and present under the
 * system prefix must never share one input identity. */
static bool fx_sys_header(char sys[PATH_MAX])
{
    static const char *const cand[] = { "/usr/include/stdio.h",
                                        "/usr/bin/env" };
    struct stat st;
    for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++)
        if (stat(cand[i], &st) == 0 && S_ISREG(st.st_mode)) {
            (void)snprintf(sys, PATH_MAX, "%s", cand[i]);
            return true;
        }
    return false;
}

static void test_derive_reserved_collision(struct fx *x)
{
    char sys[PATH_MAX], rel[PATH_MAX], deps[2 * PATH_MAX];
    bool ok = fx_sys_header(sys) &&
              snprintf(rel, sizeof(rel), "@sys%s", sys) < (int)sizeof(rel) &&
              fx_write(x->root, rel, "int shadow(void);\n");
    for (int order = 0; ok && order < 2; order++) {
        ok = snprintf(deps, sizeof(deps),
                      " build/gen/unity.c %%R/src/unit.c src/local.h "
                      "inc_b/defs.h %s %s", order ? rel : sys,
                      order ? sys : rel) < (int)sizeof(deps) &&
             fx_depfile_text(x, deps) &&
             fx_miss_why(x, "reserved_namespace_path", FX_WHY_FILE);
    }
    AR_CHECK("reserved: a checkout file under a directory named @sys and "
             "the system file it would alias are refused, in either "
             "order (reserved_namespace_path), never merged into one "
             "input", ok);
    ok = fx_depfile(x, true);
    (void)fx_remove(x->root, rel);
    AR_CHECK("reserved: the system file alone still derives", ok);
}

/* Each checkout file named by the depfile is refused by the depfile-path
 * guard; the depfile is restored to the healthy one afterwards. */
static bool fx_reserved_files(struct fx *x)
{
    static const char *const rels[] = { "@root/h.h", "@out/h.h", "@tmp/h.h" };
    bool ok = true;
    for (size_t i = 0; i < sizeof(rels) / sizeof(rels[0]); i++) {
        char deps[PATH_MAX];
        ok = ok && fx_write(x->root, rels[i], "int h(void);\n") &&
             snprintf(deps, sizeof(deps),
                      " build/gen/unity.c %%R/src/unit.c src/local.h "
                      "inc_b/defs.h %s", rels[i]) < (int)sizeof(deps) &&
             fx_depfile_text(x, deps) &&
             fx_miss_why(x, "reserved_namespace_path", FX_WHY_FILE) &&
             fx_remove(x->root, rels[i]);
    }
    return fx_depfile(x, true) && ok;
}

/* On the healthy fixture, an argv word spelling @root or @sys/ is refused
 * by the argument guard (not the depfile guard). */
static bool fx_reserved_args(struct fx *x)
{
    const char *saved = x->argv[5];
    x->argv[5] = "-DP=@root/x";
    bool ok = fx_miss_why(x, "reserved_namespace_path", FX_WHY_ARG);
    x->argv[5] = "-DP=@sys/usr/x";
    ok = fx_miss_why(x, "reserved_namespace_path", FX_WHY_ARG) && ok;
    x->argv[5] = saved;
    return ok;
}

static void test_derive_reserved_names(struct fx *x,
                                       const struct zcl_action_root_result *b)
{
    bool ok = fx_reserved_files(x);
    AR_CHECK("reserved: a checkout file under @root, @out or any other "
             "'@' directory is refused (reserved_namespace_path, "
             "checkout-path reason)", ok);
    AR_CHECK("reserved: fixture derives the base root again before the "
             "argument cases", fx_same(x, b));
    ok = fx_reserved_args(x);
    AR_CHECK("reserved: an argument spelling @root or @sys/ literally is "
             "refused by the argument guard, never bound as the real path",
             ok && fx_same(x, b));
}

/* An allowlisted variable whose value spells "@root" or "@sys/" literally
 * is refused (env_noncanonical, the same gate as a host path value): the
 * rewritten host path and the literal text would otherwise bind alike. */
static void test_derive_reserved_env(struct fx *x,
                                     const struct zcl_action_root_result *b)
{
    static const char *const lit[] = {
        "TZ=@root/x", "TZ=@root", "TZ=@sys/usr/x",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(lit) / sizeof(lit[0]); i++) {
        x->env[FX_ENV_SLOT] = lit[i];
        ok = fx_miss_why(x, "env_noncanonical", FX_WHY_ENV) && ok;
    }
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("reserved: an allowlisted variable whose value spells @root or "
             "@sys/ literally is refused (env_noncanonical)",
             ok && fx_same(x, b));
    x->env[FX_ENV_SLOT] = "TZ=UTC";
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ENV);
    x->env[FX_ENV_SLOT] = NULL;
    AR_CHECK("reserved: control, the same variable with an ordinary value "
             "derives a root that differs from unset",
             ok && fx_same(x, b));
}

static void test_derive_duplicate_deps(struct fx *x,
                                       const struct zcl_action_root_result *b)
{
    char deps[PATH_MAX + 256];
    bool ok = snprintf(deps, sizeof(deps),
                       " build/gen/unity.c %%R/src/unit.c src/local.h "
                       "inc_b/defs.h inc_b/defs.h ./inc_b/defs.h "
                       "src/../inc_b/defs.h %%R/inc_b/defs.h "
                       "%%R/src/unit.c") < (int)sizeof(deps) &&
              fx_depfile_text(x, deps) && fx_same(x, b);
    AR_CHECK("reserved: one file listed again, by a ./ or a/../ or an "
             "absolute spelling, is dropped silently and the root equals "
             "the single listing", ok && fx_depfile(x, true) &&
             fx_same(x, b));
}

static void test_derive_pinned(const struct zcl_action_root_result *b)
{
    AR_CHECK("pin: the ordinary fixture's root is unchanged by the "
             "reserved-namespace refusals",
             strcmp(b->root_hex, FX_PINNED_ROOT_HEX) == 0);
    if (strcmp(b->root_hex, FX_PINNED_ROOT_HEX) != 0)
        printf("    root is %s\n", b->root_hex);
}
/* git with a fixed identity and no hooks or signing; `out` gets stdout. */
static bool fx_git(const char *root, const char *const *args, char *out,
                   size_t cap)
{
    const char *argv[24] = {
        "git", "-C", root, "-c", "user.name=Z23 Test",
        "-c", "user.email=z23-test@example.invalid",
        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
    };
    size_t n = 11;
    for (size_t i = 0; args[i] && n + 1 < 24; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    char buf[4096] = {0};
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_observed(argv, buf, sizeof(buf), 30000,
                                               &timed_out);
    if (rc != 0 || timed_out)
        printf("    git %s: rc=%d %s\n", args[0], rc, buf);
    if (out)
        (void)snprintf(out, cap, "%.*s", (int)strcspn(buf, "\n"), buf);
    return rc == 0 && !timed_out;
}

/* Stage everything and commit it; `head` gets the new commit id. */
static bool fx_git_commit(const char *root, const char *message,
                          char head[128])
{
    static const char *const add[] = { "add", "-A", NULL };
    static const char *const rev[] = { "rev-parse", "HEAD", NULL };
    const char *commit[] = { "commit", "-q", "-m", message, NULL };
    return fx_git(root, add, NULL, 0) && fx_git(root, commit, NULL, 0) &&
           fx_git(root, rev, head, 128) && strlen(head) >= 40;
}

/* Roots derive from content bytes, never from commit or tree ids: a dirty
 * edit and its commit agree, and two commits with different trees but
 * identical closure bytes agree. */
static void test_derive_snapshot_not_commit(void)
{
    static const char *const init[] = { "init", "-q", NULL };
    struct fx *g = zcl_calloc(1, sizeof(*g), "action root git fixture");
    struct zcl_action_root_result dirty = {0};
    char c0[128] = {0}, c1[128] = {0}, c2[128] = {0};
    bool ok = g && fx_init(g, "git") && fx_git(g->root, init, NULL, 0) &&
              fx_git_commit(g->root, "one", c0) &&
              fx_write(g->root, "src/local.h", "int local(short);\n") &&
              fx_derive(g, &dirty) && fx_git_commit(g->root, "two", c1) &&
              fx_same(g, &dirty);
    AR_CHECK("snapshot: a dirty worktree edit and the commit of it derive "
             "the identical root", ok);
    ok = ok && fx_write(g->root, "NOTES.txt", "outside the closure\n") &&
         fx_git_commit(g->root, "one", c2) && strcmp(c1, c2) != 0 &&
         fx_same(g, &dirty);
    AR_CHECK("snapshot: two commits with different trees and identical "
             "closure bytes derive the identical root", ok);
    zcl_action_root_result_free(&dirty);
    if (g)
        test_rm_rf_recursive(g->root);
    free(g);
}

static void test_derive_cross_worktree(const struct zcl_action_root_result *a)
{
    struct fx *y = zcl_calloc(1, sizeof(*y), "action root fixture b");
    struct zcl_action_root_result r = {0};
    enum vcs_action_field_v2 field = VCS_ACTION_FIELD_V2_COUNT;
    bool derived = y && fx_init(y, "b") && fx_derive(y, &r);
    bool ok = derived && memcmp(r.root, a->root, 32) == 0 &&
              r.preimage_len == a->preimage_len &&
              memcmp(r.preimage, a->preimage, a->preimage_len) == 0;
    if (derived && !ok &&
        vcs_action_preimage_v2_first_diff(a->preimage, a->preimage_len,
                                          r.preimage, r.preimage_len, &field))
        printf("    cross-worktree first differing field: %s\n",
               vcs_action_field_v2_name(field) ? vcs_action_field_v2_name(field)
                                               : "none");
    AR_CHECK("cross-worktree: the same tree at another absolute root "
             "derives the identical root and preimage", ok);
    if (y)
        test_rm_rf_recursive(y->root);
    zcl_action_root_result_free(&r);
    free(y);
}

static void test_derive_store(const struct fx *x,
                              const struct zcl_action_root_result *b)
{
    char store[PATH_MAX], cause[24] = {0}, why[256] = {0};
    (void)snprintf(store, sizeof(store), "%s-store", x->root);
    test_rm_rf_recursive(store);
    uint8_t *bytes = NULL;
    size_t len = 0;
    uint8_t again[32];
    bool ok = mkdir(store, 0700) == 0 &&
              zcl_action_root_record(store, "src/unit.c", b, cause,
                                     sizeof(cause), why, sizeof(why)) &&
              strcmp(cause, "first") == 0 &&
              zcl_action_root_load(store, b->root_hex, &bytes, &len, why,
                                   sizeof(why)) &&
              vcs_action_root_v2_from_bytes(bytes, len, again, why,
                                            sizeof(why)) &&
              memcmp(again, b->root, 32) == 0;
    AR_CHECK("re-derivation: a stored preimage reloads and re-derives its "
             "root", ok);
    ok = zcl_action_root_record(store, "src/unit.c", b, cause, sizeof(cause),
                                why, sizeof(why)) &&
         strcmp(cause, "hit") == 0;
    AR_CHECK("an unchanged action reports cause=hit", ok);
    char path[PATH_MAX + 80];
    (void)snprintf(path, sizeof(path), "%s/%s.preimage", store, b->root_hex);
    FILE *f = bytes ? fopen(path, "wb") : NULL;
    if (f) {
        bytes[len - 1] ^= 1;
        (void)fwrite(bytes, 1, len, f);
        (void)fclose(f);
    }
    uint8_t *tampered = NULL;
    size_t tampered_len = 0;
    ok = f && !zcl_action_root_load(store, b->root_hex, &tampered,
                                    &tampered_len, why, sizeof(why));
    AR_CHECK("re-derivation: a tampered stored preimage is refused", ok);
    free(tampered);
    free(bytes);
    test_rm_rf_recursive(store);
}

static void test_derive_causes(struct fx *x,
                               const struct zcl_action_root_result *b)
{
    char store[PATH_MAX], cause[24] = {0}, why[256] = {0};
    (void)snprintf(store, sizeof(store), "%s-causes", x->root);
    test_rm_rf_recursive(store);
    struct zcl_action_root_result r = {0};
    bool ok = mkdir(store, 0700) == 0 &&
              zcl_action_root_record(store, "u", b, cause, sizeof(cause), why,
                                     sizeof(why));
    x->argv[6] = "-O3";
    ok = ok && fx_derive(x, &r) &&
         zcl_action_root_record(store, "u", &r, cause, sizeof(cause), why,
                                sizeof(why)) &&
         strcmp(cause, "flags") == 0;
    x->argv[6] = "-O2";
    zcl_action_root_result_free(&r);
    AR_CHECK("cause names the first differing field (flags)", ok);
    ok = fx_write(x->root, "inc_a/defs.h", "#define X 9\n") &&
         fx_derive(x, &r) &&
         zcl_action_root_record(store, "u", &r, cause, sizeof(cause), why,
                                sizeof(why)) &&
         strcmp(cause, "negative_lookup") == 0 &&
         fx_remove(x->root, "inc_a/defs.h");
    zcl_action_root_result_free(&r);
    AR_CHECK("cause names negative_lookup for a new shadowing header", ok);
    test_rm_rf_recursive(store);
}

/* ---- 4. hotload hook ------------------------------------------------ */

/* A build that did not complete, or whose depfile is gone, reports
 * action_root null with a miss reason; the receipt JSON says so. */
static void test_hook_misses(struct fx *x, const char *cflags)
{
    struct zcl_devloop_hotswap_build_receipt r = {0};
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", NULL, NULL, NULL, &r);
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    zcl_devloop_action_root_emit(&doc, &r);
    const struct json_value *root = json_get(&doc, "action_root");
    const char *cause = json_get_str(json_get(&doc, "action_root_cause"));
    const char *why = json_get_str(json_get(&doc, "action_root_miss_reason"));
    AR_CHECK("hook: a build that did not complete reports action_root null "
             "with miss_reason closure_unobserved",
             !r.action_root[0] && root && root->type == JSON_NULL &&
                 cause && strcmp(cause, "miss") == 0 && why &&
                 strcmp(why, "closure_unobserved") == 0 &&
                 r.action_root_miss_detail[0]);
    json_free(&doc);
    char gone[PATH_MAX + 16];
    (void)snprintf(gone, sizeof(gone), "%s/build/gone.d", x->root);
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", gone, NULL, NULL, &r);
    AR_CHECK("hook: a missing depfile reports miss_reason depfile_missing",
             !r.action_root[0] &&
                 strcmp(r.action_root_miss, "depfile_missing") == 0);
}

/* The HOT_FORK capsule compiles a unity from a temporary .resident-* path:
 * the temporary spelling never reaches the root, its content does. */
static void test_hotfork_hook(struct fx *x, const char *cflags)
{
    char dep[PATH_MAX + 16], a[PATH_MAX + 64], b[PATH_MAX + 64];
    char text[2 * PATH_MAX + 128], unity[PATH_MAX + 32];
    (void)snprintf(dep, sizeof(dep), "%s/build/hotfork.d", x->root);
    (void)snprintf(a, sizeof(a), "%s/build/hotswap-fast/.resident-aaaaaa.c",
                   x->root);
    (void)snprintf(b, sizeof(b), "%s/build/hotswap-fast/.resident-bbbbbb.c",
                   x->root);
    (void)snprintf(unity, sizeof(unity), "#include \"%s/src/unit.c\"\n",
                   x->root);
    (void)snprintf(text, sizeof(text), "build/obj.o: %s %s/src/unit.c "
                   "src/local.h inc_b/defs.h\n", a, x->root);
    struct zcl_devloop_hotswap_build_receipt h1 = {0}, h2 = {0}, h3 = {0};
    bool ok = fx_write(x->root, "build/hotfork.d", text) &&
              fx_write(x->root, "build/hotswap-fast/.resident-aaaaaa.c",
                       unity) &&
              fx_write(x->root, "build/hotswap-fast/.resident-bbbbbb.c",
                       unity);
    zcl_devloop_action_root_hotfork(x->root, "src/unit.c", "cc", cflags, a,
                                    dep, NULL, NULL, &h1);
    zcl_devloop_action_root_hotfork(x->root, "src/unit.c", "cc", cflags, b,
                                    dep, NULL, NULL, &h2);
    ok = ok && fx_write(x->root, "build/hotswap-fast/.resident-bbbbbb.c",
                        "/* adapter v2 */\n#include \"src/unit.c\"\n");
    zcl_devloop_action_root_hotfork(x->root, "src/unit.c", "cc", cflags, b,
                                    dep, NULL, NULL, &h3);
    if (!h1.action_root[0])
        printf("    hotfork hook missed: %s %s\n", h1.action_root_miss,
               h1.action_root_miss_detail);
    AR_CHECK("hotfork hook: first capsule compile reports cause=first",
             ok && strlen(h1.action_root) == 64 &&
                 strcmp(h1.action_root_cause, "first") == 0);
    AR_CHECK("hotfork hook: the same unity at another temporary path is a hit",
             strcmp(h2.action_root, h1.action_root) == 0 &&
                 strcmp(h2.action_root_cause, "hit") == 0);
    AR_CHECK("hotfork hook: a changed unity reports cause=generated",
             strlen(h3.action_root) == 64 &&
                 strcmp(h3.action_root_cause, "generated") == 0);
    zcl_devloop_action_root_hotfork(x->root, "src/unit.c", "cc", cflags, a,
                                    NULL, NULL, NULL, &h1);
    AR_CHECK("hotfork hook: a failed capsule build misses "
             "(closure_unobserved)",
             !h1.action_root[0] &&
                 strcmp(h1.action_root_miss, "closure_unobserved") == 0);
}

static bool hook_harness_matches(const char *root, uint64_t *image_bytes,
                                  uint8_t expected[32])
{
    *image_bytes = 0;
    char store[PATH_MAX], why[160] = {0};
    uint8_t *bytes = NULL;
    size_t len = 0;
    struct vcs_action_preimage_v2_decoded dec = {0};
    bool ok = zcl_action_root_store_dir(store, sizeof(store)) &&
              zcl_action_root_load(store, root, &bytes, &len, why,
                                   sizeof(why)) &&
              vcs_action_preimage_v2_decode(bytes, len, &dec, why,
                                            sizeof(why));
    if (ok && os_proc_self_exe_identity() ==
                  OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE) {
        static const char domain[] = "zcl.module_builder.running_image.v1";
        FILE *image = os_proc_open_self_exe();
        struct sha3_256_ctx hash;
        uint8_t buffer[16384];
        sha3_256_init(&hash);
        sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain));
        size_t n;
        while (image && (n = fread(buffer, 1, sizeof(buffer), image)) != 0) {
            *image_bytes += n;
            sha3_256_write(&hash, buffer, n);
        }
        ok = image && !ferror(image);
        sha3_256_finalize(&hash, expected);
        if (image)
            fclose(image);
        ok = ok && dec.view.harness.present &&
             memcmp(dec.view.harness.root, expected, 32) == 0;
    } else if (ok) {
        ok = !dec.view.harness.present;
    }
    vcs_action_preimage_v2_decoded_free(&dec);
    free(bytes);
    return ok;
}

static void hook_harness_work_checks(
    const struct zcl_devloop_hotswap_build_receipt *r1,
    const struct zcl_devloop_hotswap_build_receipt *r2)
{
    uint64_t image_bytes = 0;
    uint8_t expected[32] = {0};
    AR_CHECK("hook: emitted harness binds the executing image or stays absent",
             hook_harness_matches(r1->action_root, &image_bytes, expected));
    printf("    harness work: image_bytes=%llu cold_bytes=%llu cold_hashes=%u "
           "cold_hits=%u warm_bytes=%llu warm_hashes=%u warm_hits=%u\n",
           (unsigned long long)image_bytes,
           (unsigned long long)r1->action_root_harness_read_bytes,
           r1->action_root_harness_hashes, r1->action_root_harness_cache_hits,
           (unsigned long long)r2->action_root_harness_read_bytes,
           r2->action_root_harness_hashes, r2->action_root_harness_cache_hits);
    bool pinned = os_proc_self_exe_identity() ==
                      OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE;
    bool cached = false;
#if defined(__linux__) && ATOMIC_INT_LOCK_FREE == 2
    cached = pinned;
#endif
    AR_CHECK("hook: cold capture counts actual image bytes and hash launch",
             r1->action_root_harness_read_bytes == image_bytes &&
             r1->action_root_harness_hashes == (pinned ? 1u : 0u) &&
             r1->action_root_harness_cache_hits == 0);
    AR_CHECK("hook: warm request follows the supported image cache policy",
             r2->action_root_harness_read_bytes ==
                 (pinned && !cached ? image_bytes : 0) &&
             r2->action_root_harness_hashes == (pinned && !cached ? 1u : 0u) &&
             r2->action_root_harness_cache_hits == (cached ? 1u : 0u));
}

static void hook_receipt_checks(
    const struct zcl_devloop_hotswap_build_receipt *r1)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    zcl_devloop_action_root_emit(&doc, r1);
    const char *emitted = json_get_str(json_get(&doc, "action_root"));
    AR_CHECK("hook: the receipt JSON carries action_root and its cause",
             emitted && strcmp(emitted, r1->action_root) == 0 &&
                 json_get_str(json_get(&doc, "action_root_cause")) &&
                 json_get(&doc, "action_root_ms"));
    AR_CHECK("hook: existing JSON receipt exposes actual image work",
             json_get(&doc, "action_root_harness_read_bytes") &&
             json_get_int(json_get(&doc, "action_root_harness_read_bytes")) ==
                 (int64_t)r1->action_root_harness_read_bytes &&
             json_get(&doc, "action_root_harness_hashes") &&
             json_get_int(json_get(&doc, "action_root_harness_hashes")) ==
                 r1->action_root_harness_hashes &&
             json_get(&doc, "action_root_harness_cache_hits"));
    json_free(&doc);
}

static void test_hotswap_hook(struct fx *x)
{
    char cache[PATH_MAX], prior[PATH_MAX] = {0};
    const char *had = getenv("ZCL_DEV_ARTIFACT_CACHE");
    if (had)
        (void)snprintf(prior, sizeof(prior), "%s", had);
    (void)snprintf(cache, sizeof(cache), "%s-cache", x->root);
    test_rm_rf_recursive(cache);
    bool ok = mkdir(cache, 0700) == 0 &&
              platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", cache, 1) == 0;
    struct zcl_devloop_hotswap_build_receipt r1 = {0}, r2 = {0}, r3 = {0};
    const char *cflags = "-std=c23 -Iinc_a -Iinc_b -DFOO=1";
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", x->depfile, NULL, NULL, &r1);
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", x->depfile, NULL, NULL, &r2);
    ok = ok && fx_write(x->root, "src/local.h", "int local(long);\n");
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", x->depfile, NULL, NULL, &r3);
    ok = ok && fx_write(x->root, "src/local.h", "int local(void);\n");
    if (!r1.action_root[0])
        printf("    hook refused: %s\n", r1.action_root_miss_detail);
    printf("    hook: first=%s %lldus, again=%s %lldus, edit=%s %lldus, "
           "probes=%u present=%u\n", r1.action_root_cause,
           (long long)r1.action_root_us, r2.action_root_cause,
           (long long)r2.action_root_us, r3.action_root_cause,
           (long long)r3.action_root_us, r1.action_root_probes,
           r1.action_root_present);
    AR_CHECK("hook: first compile of a unit reports cause=first",
             ok && strlen(r1.action_root) == 64 &&
                 strcmp(r1.action_root_cause, "first") == 0);
    hook_harness_work_checks(&r1, &r2);
    AR_CHECK("hook: an unchanged recompile reports cause=hit",
             strcmp(r2.action_root, r1.action_root) == 0 &&
                 strcmp(r2.action_root_cause, "hit") == 0);
    AR_CHECK("hook: a header edit reports cause=source",
             strlen(r3.action_root) == 64 &&
                 strcmp(r3.action_root, r1.action_root) != 0 &&
                 strcmp(r3.action_root_cause, "source") == 0);
    hook_receipt_checks(&r1);
    test_hook_misses(x, cflags);
    test_hotfork_hook(x, cflags);
    if (prior[0])
        (void)platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", prior, 1);
    else
        (void)unsetenv("ZCL_DEV_ARTIFACT_CACHE");
    test_rm_rf_recursive(cache);
}

#if defined(__linux__) && ATOMIC_INT_LOCK_FREE == 2
struct image_hook_job {
    struct fx *fixture;
    atomic_bool *go;
    struct zcl_devloop_hotswap_build_receipt receipt;
};

static void image_hook(struct fx *x,
                       struct zcl_devloop_hotswap_build_receipt *r)
{
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc",
        "-std=c23 -Iinc_a -Iinc_b -DFOO=1", "-shared", x->depfile,
        NULL, NULL, r);
}

static void *image_hook_worker(void *argument)
{
    struct image_hook_job *job = argument;
    while (!atomic_load_explicit(job->go, memory_order_acquire))
        sched_yield();
    image_hook(job->fixture, &job->receipt);
    return NULL;
}

static bool image_directory_owned(const char *dir)
{
    struct stat st = {0};
    int rc = lstat(dir, &st);
    printf("    image directory: lstat=%d mode=%lo uid=%llu caller_uid=%llu\n",
           rc, (unsigned long)st.st_mode, (unsigned long long)st.st_uid,
           (unsigned long long)getuid());
    return rc == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == getuid() && (st.st_mode & 0777) == 0700;
}

static bool image_named_owned(const char *path)
{
    struct stat named = {0}, pinned = {0};
    FILE *image = os_proc_open_self_exe();
    int named_rc = lstat(path, &named);
    int pinned_rc = image ? fstat(fileno(image), &pinned) : -1;
    bool ok = named_rc == 0 && S_ISREG(named.st_mode) &&
        named.st_uid == getuid() && named.st_nlink == 1 &&
        (named.st_mode & 0777) == 0700 && image &&
        pinned_rc == 0 &&
        pinned.st_dev == named.st_dev && pinned.st_ino == named.st_ino;
    printf("    image inode: lstat=%d self_fstat=%d named_mode=%lo uid=%llu nlink=%llu "
           "named_dev=%llu named_ino=%llu pinned_dev=%llu pinned_ino=%llu\n",
           named_rc, pinned_rc, (unsigned long)named.st_mode, (unsigned long long)named.st_uid,
           (unsigned long long)named.st_nlink,
           (unsigned long long)named.st_dev, (unsigned long long)named.st_ino,
           (unsigned long long)pinned.st_dev, (unsigned long long)pinned.st_ino);
    if (image)
        fclose(image);
    return ok;
}

static bool image_locator_owned(const char *path)
{
    static const char prefix[] = "action_root_image_";
    char dir[PATH_MAX];
    if (!path || path[0] != '/' || strlen(path) >= sizeof(dir))
        return false;
    memcpy(dir, path, strlen(path) + 1);
    char *leaf = strrchr(dir, '/');
    if (!leaf || strcmp(leaf + 1, "image") != 0)
        return false;
    *leaf = '\0';
    const char *name = strrchr(dir, '/');
    name = name ? name + 1 : dir;
    printf("    image locator: leaf=image directory_leaf=%s length=%zu "
           "expected_length=%zu prefix_matches=%d\n", name, strlen(name),
           sizeof(prefix) - 1 + 6,
           strncmp(name, prefix, sizeof(prefix) - 1) == 0);
    return strncmp(name, prefix, sizeof(prefix) - 1) == 0 &&
        strlen(name) == sizeof(prefix) - 1 + 6 &&
        image_directory_owned(dir) && image_named_owned(path);
}

static bool image_copy(const char *path, bool append)
{
    FILE *in = os_proc_open_self_exe();
    FILE *out = fopen(path, "wb");
    struct stat st;
    bool ok = in && out && fstat(fileno(in), &st) == 0 &&
              st.st_size > 0 && st.st_size <= 1073741824;
    uint8_t buffer[16384];
    uint64_t bytes = 0;
    size_t n;
    while (ok && (n = fread(buffer, 1, sizeof(buffer), in)) != 0) {
        bytes += n;
        ok = fwrite(buffer, 1, n, out) == n;
    }
    ok = ok && !ferror(in) && bytes == (uint64_t)st.st_size;
    if (ok && append)
        ok = fputc(0, out) != EOF;
    if (in)
        fclose(in);
    if (out && fclose(out) != 0)
        ok = false;
    return ok && chmod(path, 0700) == 0;
}

static bool image_environment_restore(const char *const names[3], char *prior[3])
{
    bool ok = true;
    for (size_t i = 0; i < 3; ++i) {
        if (prior[i])
            ok = platform_environment_set(names[i], prior[i], 1) == 0 && ok;
        else
            ok = unsetenv(names[i]) == 0 && ok;
        free(prior[i]);
    }
    return ok;
}

/* Nested runner diagnostics must not impersonate the outer suite's verdict. */
static void image_role_output(const char *output)
{
    while (*output) {
        const char *end = strchr(output, '\n');
        size_t length = end ? (size_t)(end - output) : strlen(output);
        printf("    image child: %.*s\n", (int)length, output);
        if (!end) break;
        output = end + 1;
    }
}

static bool image_role_run(const char *path, const char *role,
                            const char *expected)
{
    const char *names[] = { "ZCL_ACTION_ROOT_IMAGE_ROLE",
                           "ZCL_ACTION_ROOT_IMAGE_PATH",
                           "ZCL_ACTION_ROOT_PARENT_HARNESS" };
    const char *values[] = { role, path, expected ? expected : "" };
    char *prior[3] = {0};
    bool ok = true;
    for (size_t i = 0; i < 3; ++i) {
        const char *old = getenv(names[i]);
        prior[i] = old ? strdup(old) : NULL;
        ok = ok && (!old || prior[i]);
    }
    if (!ok) {
        for (size_t i = 0; i < 3; ++i)
            free(prior[i]);
        return false;
    }
    for (size_t i = 0; i < 3; ++i)
        ok = platform_environment_set(names[i], values[i], 1) == 0 && ok;
    const char *argv[] = { path, "--exact=test_action_root", "--jobs=1",
                           "--no-cache", "--verbose", NULL };
    char output[16384] = {0};
    if (ok)
        ok = zcl_spawn_capture(argv, output, sizeof(output), 120000) == 0 &&
             strstr(output, "image controls completed") != NULL;
    image_role_output(output);
    return image_environment_restore(names, prior) && ok;
}

static void image_concurrent(struct fx *x)
{
    atomic_bool go = false;
    struct image_hook_job jobs[4] = {0};
    pthread_t threads[4];
    size_t started = 0;
    for (; started < 4; ++started) {
        jobs[started].fixture = x;
        jobs[started].go = &go;
        if (pthread_create(&threads[started], NULL, image_hook_worker,
                           &jobs[started]) != 0)
            break;
    }
    atomic_store_explicit(&go, true, memory_order_release);
    bool ok = started == 4;
    uint64_t reads = 0, image_bytes = 0;
    uint32_t hashes = 0, hits = 0;
    uint8_t expected[32] = {0};
    for (size_t i = 0; i < started; ++i) {
        ok = pthread_join(threads[i], NULL) == 0 && ok;
        reads += jobs[i].receipt.action_root_harness_read_bytes;
        hashes += jobs[i].receipt.action_root_harness_hashes;
        hits += jobs[i].receipt.action_root_harness_cache_hits;
        ok = hook_harness_matches(jobs[i].receipt.action_root, &image_bytes,
                                  expected) && ok;
        ok = strcmp(jobs[i].receipt.action_root,
                     jobs[0].receipt.action_root) == 0 && ok;
    }
    AR_CHECK("image: concurrent actual emitters publish one complete capture",
             ok && hashes == 1 && hits == 3 && reads == image_bytes);
}

static void image_metadata(struct fx *x, const char *path)
{
    struct stat named;
    bool own = image_locator_owned(path) && lstat(path, &named) == 0;
    struct zcl_devloop_hotswap_build_receipt r = {0};
    bool changed = own && chmod(path, named.st_mode ^ S_IXGRP) == 0;
    if (changed)
        image_hook(x, &r);
    uint64_t bytes = 0;
    uint8_t expected[32] = {0};
    AR_CHECK("image: changed metadata recaptures actual bytes after EOF",
             changed && hook_harness_matches(r.action_root, &bytes, expected) &&
             r.action_root_harness_read_bytes == bytes &&
             r.action_root_harness_hashes == 1 &&
             r.action_root_harness_cache_hits == 0);
    bool restored = own && chmod(path, named.st_mode) == 0;
    if (restored)
        image_hook(x, &r);
    AR_CHECK("image: metadata restoration remains eligible", restored &&
             hook_harness_matches(r.action_root, &bytes, expected));
}

static void image_child_refusal(struct fx *x)
{
    pid_t child = fork();
    if (child == 0) {
        char root[65] = {0}, miss[40] = {0};
        bool ok = !zcl_devloop_action_root_key(x->root, "src/unit.c", "cc",
            "-std=c23", "-shared", NULL, x->depfile, NULL, NULL, root, miss);
        _exit(ok && !root[0] &&
              memcmp(miss, "harness_fork_unavailable", 25) == 0 ? 0 : 1);
    }
    int status = 0;
    pid_t reaped;
    do {
        reaped = child > 0 ? waitpid(child, &status, 0) : -1;
    } while (reaped < 0 && errno == EINTR && child > 0);
    AR_CHECK("image: initialized inherited cache refuses before capture",
             child > 0 && reaped == child &&
             WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static bool image_descriptor_census(bool before[1024])
{
    FILE *reference = os_proc_open_self_exe();
    struct stat wanted, candidate;
    bool ok = reference && fstat(fileno(reference), &wanted) == 0;
    int matches = 0, occupied = 0;
    for (int i = 0; ok && i < 1024; ++i) {
        if (i != fileno(reference) && fcntl(i, F_GETFD) >= 0) {
            before[i] = true;
            ++occupied;
            if (fstat(i, &candidate) == 0 && candidate.st_dev == wanted.st_dev &&
                candidate.st_ino == wanted.st_ino)
                ++matches;
        }
    }
    if (reference)
        fclose(reference);
    printf("    image pre-capture descriptors: occupied=%d matching=%d observed=%d\n",
           occupied, matches, ok);
    return ok;
}

static int image_cached_descriptor(FILE *reference, const bool before[1024],
                                    int *observed_matches)
{
    struct stat wanted, candidate;
    int fd = -1, matches = 0, eligible = 0;
    bool ok = reference && fstat(fileno(reference), &wanted) == 0;
    for (int i = 0; ok && i < 1024; ++i) {
        if (i != fileno(reference) && fstat(i, &candidate) == 0 &&
            candidate.st_dev == wanted.st_dev &&
            candidate.st_ino == wanted.st_ino) {
            ++matches;
            int flags = fcntl(i, F_GETFD);
            printf("    image matching fd: fd=%d preexisting=%d flags=%d offset=%lld\n",
                   i, before[i], flags, (long long)lseek(i, 0, SEEK_CUR));
            if (!before[i] && flags >= 0 && (flags & FD_CLOEXEC)) {
                fd = i;
                ++eligible;
            }
        }
    }
    *observed_matches = matches;
    printf("    image newly captured descriptors: eligible=%d\n", eligible);
    return ok && eligible == 1 ? fd : -1;
}

static void image_retry_observe(int fd, int matches, int backup, int backup_errno,
    int close_rc, int close_errno, int restored, int restored_errno,
    const struct zcl_devloop_hotswap_build_receipt *bad,
    const struct zcl_devloop_hotswap_build_receipt *good)
{
    struct rlimit limits = {0};
    int limit_rc = getrlimit(RLIMIT_NOFILE, &limits);
    printf("    image descriptor limit: rc=%d soft=%llu hard=%llu\n", limit_rc,
           (unsigned long long)limits.rlim_cur,
           (unsigned long long)limits.rlim_max);
    printf("    image descriptor fault: matches=%d selected=%d backup=%d "
           "backup_errno=%d close_rc=%d close_errno=%d restored=%d restored_errno=%d\n",
           matches, fd, backup, backup_errno, close_rc, close_errno, restored,
           restored_errno);
    printf("    image descriptor bad: root_length=%zu miss=%s detail=%s "
           "bytes=%llu hashes=%u hits=%u\n", strlen(bad->action_root),
           bad->action_root_miss, bad->action_root_miss_detail,
           (unsigned long long)bad->action_root_harness_read_bytes,
           bad->action_root_harness_hashes, bad->action_root_harness_cache_hits);
    printf("    image descriptor repaired: root_length=%zu miss=%s detail=%s "
           "bytes=%llu hashes=%u hits=%u\n", strlen(good->action_root),
           good->action_root_miss, good->action_root_miss_detail,
           (unsigned long long)good->action_root_harness_read_bytes,
           good->action_root_harness_hashes, good->action_root_harness_cache_hits);
}

static void image_retry_checks(bool closed, bool restored,
    const struct zcl_devloop_hotswap_build_receipt *bad,
    const struct zcl_devloop_hotswap_build_receipt *good)
{
    AR_CHECK("image: unavailable retained descriptor gives contextual miss",
             closed && !bad->action_root[0] &&
             strcmp(bad->action_root_miss, "harness_image_unavailable") == 0 &&
             strstr(bad->action_root_miss_detail, "action root refused") == NULL);
    uint64_t bytes = 0;
    uint8_t expected[32] = {0};
    AR_CHECK("image: repaired fixture descriptor retries a full stable capture",
             restored &&
             hook_harness_matches(good->action_root, &bytes, expected) &&
             good->action_root_harness_hashes == 1 &&
             good->action_root_harness_read_bytes == bytes &&
             good->action_root_harness_cache_hits == 0);
}

static void image_retry(struct fx *x, const bool before[1024])
{
    FILE *reference = os_proc_open_self_exe();
    int matches = 0;
    int fd = image_cached_descriptor(reference, before, &matches);
    errno = 0;
    int backup = fd >= 0 ? fcntl(fd, F_DUPFD_CLOEXEC, fd + 1) : -1;
    int backup_errno = errno;
    errno = 0;
    int close_rc = backup >= 0 ? close(fd) : -1;
    int close_errno = errno;
    bool closed = backup >= 0 && close_rc == 0;
    struct zcl_devloop_hotswap_build_receipt bad = {0}, good = {0};
    if (closed)
        image_hook(x, &bad);
    errno = 0;
    int restored = closed ? fcntl(backup, F_DUPFD_CLOEXEC, fd) : -1;
    int restored_errno = errno;
    if (restored >= 0 && restored == fd)
        image_hook(x, &good);
    image_retry_observe(fd, matches, backup, backup_errno, close_rc, close_errno,
                        restored, restored_errno, &bad, &good);
    image_retry_checks(closed, restored == fd && fd >= 0, &bad, &good);
    if (restored >= 0 && restored != fd)
        close(restored);
    if (backup >= 0)
        close(backup);
    if (reference)
        fclose(reference);
}

static bool image_replacement_owned(const char *path,
                                     const struct stat *replacement, bool present)
{
    struct stat current;
    int rc = lstat(path, &current);
    bool absent = rc != 0 && errno == ENOENT && !present;
    bool owned = rc == 0 && present && S_ISREG(current.st_mode) &&
        current.st_uid == getuid() && current.st_nlink == 1 &&
        current.st_dev == replacement->st_dev &&
        current.st_ino == replacement->st_ino;
    return absent || owned;
}

static bool image_restore_locator(const char *path, const char *renamed,
                                   const struct stat *replacement, bool present)
{
    char dir[PATH_MAX];
    if (snprintf(dir, sizeof(dir), "%s", path) >= (int)sizeof(dir))
        return false;
    char *leaf = strrchr(dir, '/');
    if (!leaf || strcmp(leaf + 1, "image") != 0)
        return false;
    *leaf = '\0';
    if (!image_directory_owned(dir) || !image_named_owned(renamed))
        return false;
    return image_replacement_owned(path, replacement, present) &&
        rename(renamed, path) == 0;
}

static void image_rename(struct fx *x, const char *path)
{
    char renamed[PATH_MAX], expected_hex[65];
    struct zcl_devloop_hotswap_build_receipt before = {0}, after = {0};
    image_hook(x, &before);
    uint64_t bytes = 0;
    uint8_t expected[32] = {0};
    bool moved = image_locator_owned(path) &&
              hook_harness_matches(before.action_root, &bytes, expected) &&
              snprintf(renamed, sizeof(renamed), "%s.pinned", path) <
                  (int)sizeof(renamed) && rename(path, renamed) == 0;
    zcl_hex_encode(expected, 32, expected_hex);
    bool ok = moved && image_copy(path, true);
    struct stat replacement = {0};
    bool present = moved && lstat(path, &replacement) == 0;
    if (ok)
        image_hook(x, &after);
    AR_CHECK("image: replaced locator does not replace pinned harness bytes",
             ok && hook_harness_matches(after.action_root, &bytes, expected) &&
             strcmp(before.action_root, after.action_root) == 0);
    AR_CHECK("image: new exec captures the changed image instead of old cache",
             ok && image_role_run(path, "reexec", expected_hex));
    AR_CHECK("image: original private locator is restored after replacement",
             !moved || image_restore_locator(path, renamed, &replacement, present));
}

static void image_role_observe(const char *role, const char *path)
{
    printf("    image role: role=%s locator=%s\n", role, path ? path : "missing");
}

static void image_lifecycle(struct fx *x, const char *path)
{
    bool before[1024] = {false};
    AR_CHECK("image: isolated executable locator is supplied", path);
    bool observed = path && image_descriptor_census(before);
    AR_CHECK("image: pre-capture descriptor ownership census is observed", observed);
    if (observed) {
        image_concurrent(x);
        image_metadata(x, path);
        image_child_refusal(x);
        image_retry(x, before);
        image_rename(x, path);
    }
}

static int image_controls(const char *role)
{
    const char *path = getenv("ZCL_ACTION_ROOT_IMAGE_PATH");
    image_role_observe(role, path);
    bool locator_ok = image_locator_owned(path);
    AR_CHECK("image: role owns a single-link private copied executable", locator_ok);
    if (!locator_ok)
        return g_failures;
    struct fx *x = zcl_calloc(1, sizeof(*x), "image action fixture");
    bool ok = x && fx_init(x, "image");
    char cache[PATH_MAX] = {0};
    ok = ok && snprintf(cache, sizeof(cache), "%s/cache", x->root) <
                   (int)sizeof(cache) && mkdir(cache, 0700) == 0 &&
         platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", cache, 1) == 0;
    AR_CHECK("image: actual emitter fixture initialized", ok);
    if (ok && strcmp(role, "reexec") == 0) {
        struct zcl_devloop_hotswap_build_receipt r = {0};
        uint64_t bytes = 0;
        uint8_t expected[32] = {0};
        char hex[65];
        image_hook(x, &r);
        bool bound = hook_harness_matches(r.action_root, &bytes, expected);
        zcl_hex_encode(expected, 32, hex);
        const char *old = getenv("ZCL_ACTION_ROOT_PARENT_HARNESS");
        AR_CHECK("image: fresh exec binds independently changed bytes", bound &&
                 old && strcmp(old, hex) != 0 &&
                 r.action_root_harness_hashes == 1 &&
                 r.action_root_harness_read_bytes == bytes);
    } else if (ok) {
        image_lifecycle(x, path);
    }
    if (x) {
        test_rm_rf_recursive(x->root);
        free(x);
    }
    printf("image controls completed\n");
    return g_failures;
}

static void image_isolated_controls(void)
{
    char dir[] = "test-tmp/action_root_image_XXXXXX", path[PATH_MAX];
    char absolute[PATH_MAX];
    bool made = mkdtemp(dir) != NULL;
    bool ok = made &&
              snprintf(path, sizeof(path), "%s/image", dir) < (int)sizeof(path);
    ok = ok && image_copy(path, false);
    ok = ok && platform_directory_canonical_real(path, absolute,
                                                  sizeof(absolute));
    AR_CHECK("image: isolated real executable controls", ok &&
             image_role_run(absolute, "controls", NULL));
    if (made)
        test_rm_rf_recursive(dir);
}
#endif

static void test_derivation(void)
{
    struct fx *x = zcl_calloc(1, sizeof(*x), "action root fixture a");
    struct zcl_action_root_result base = {0};
    bool ok = x && fx_init(x, "a") && fx_derive(x, &base);
    AR_CHECK("fixture derives a root", ok && strlen(base.root_hex) == 64);
    if (ok) {
        printf("    fixture: %u sources, %u generated, %u lookups, "
               "%u probes, %u present, %zu preimage bytes, %lldus\n",
               base.source_count, base.generated_count, base.lookups,
               base.probes, base.present, base.preimage_len,
               (long long)base.derive_us);
        AR_CHECK("stability: deriving twice without change gives one root",
                 fx_same(x, &base));
        test_derive_flags(x, &base);
        test_derive_headers(x, &base);
        test_derive_shadow_and_removal(x, &base);
        test_derive_conditional(x, &base);
        test_derive_embed(x, &base);
        test_derive_lookups(x, &base);
        test_derive_sysroot(x, &base);
        test_derive_linker(x, &base);
        test_derive_generated(x, &base);
        test_derive_roots(x, &base);
        test_derive_env(x, &base);
        test_derive_env_unbound(x, &base);
        test_derive_cache_off(x, &base);
        test_derive_path_relative(x, &base);
        test_derive_refusals(x);
        test_derive_allowlist(x, &base);
        test_derive_climb(x, &base);
        test_derive_misses(x, &base);
        test_derive_reserved_collision(x);
        test_derive_reserved_names(x, &base);
        test_derive_reserved_env(x, &base);
        test_derive_duplicate_deps(x, &base);
        test_derive_pinned(&base);
        test_derive_compile_window(x, &base);
        test_derive_cross_worktree(&base);
        test_derive_store(x, &base);
        test_derive_causes(x, &base);
        test_hotswap_hook(x);
        test_key_driver_facts(x);
        test_key_sysroot_override(x);
#if defined(__APPLE__)
        test_key_sysroot_capsule_mismatch(x);
#endif
        test_key_env_influential(x);
        test_key_path_relative(x);
        test_key_cache_opaque(x);
        test_key_backend_lines(x);
        test_key_inner_replaced(x);
        test_key_tmpdir_missing(x);
        test_key_same_name_static(x);
        test_key_cost(x);
    }
    zcl_action_root_result_free(&base);
    if (x)
        test_rm_rf_recursive(x->root);
    free(x);
}

/* Only a driver temporary under TMPDIR collapses to @tmp; any other path
 * there stays literal, so two such paths never bind alike. */
static void test_canon_driver_word(void)
{
    static const struct { const char *word, *want; } cases[] = {
        { "/srv/fx-tmp/ccAb12Z9.s", "@tmp.s" },
        { "/srv/fx-tmp/null-8f2c1ab0.o", "@tmp.o" },
        { "/srv/fx-tmp/fxdata-one.h", "/srv/fx-tmp/fxdata-one.h" },
        { "/srv/fx-tmp/ccshort.s", "/srv/fx-tmp/ccshort.s" },
        { "/srv/fx-tmp/sub/ccAb12Z9.s", "/srv/fx-tmp/sub/ccAb12Z9.s" },
        { "-ffile-prefix-map=/srv/fx-root=/z", "-ffile-prefix-map=@root=/z" },
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char out[PATH_MAX];
        if (!zcl_action_root_canon_driver_word(cases[i].word, "/srv/fx-root",
                                               "/srv/fx-tmp", out,
                                               sizeof(out)) ||
            strcmp(out, cases[i].want) != 0) {
            printf("    canon %s -> %s\n", cases[i].word, out);
            ok = false;
        }
    }
    char a[PATH_MAX], b[PATH_MAX];
    ok = ok &&
         zcl_action_root_canon_driver_word("/srv/fx-tmp/fxdata-one.h", "/r",
                                           "/srv/fx-tmp", a, sizeof(a)) &&
         zcl_action_root_canon_driver_word("/srv/fx-tmp/fxdata-two.h", "/r",
                                           "/srv/fx-tmp", b, sizeof(b)) &&
         strcmp(a, b) != 0;
    AR_CHECK("backend lines: only a driver temporary under TMPDIR becomes "
             "@tmp; two other paths there stay distinct", ok);
}

/* A fake `cc -xc -E -v /dev/null` transcript is enough to prove the
 * built-in search-list parser refuses rather than truncates: real
 * compilers never emit these shapes, but a hostile or unusual driver
 * could, and a miss here means no root, never a partial one. */
static void test_builtin_dir_parse(void)
{
    char dirs[8][PATH_MAX];
    size_t count = 999;
    char miss[40];

    const char *noncanonical =
        "#include <...> search starts here:\n"
        " /usr/include\n"
        " relative/not/absolute\n"
        "End of search list.\n";
    bool ok = !zcl_action_root_parse_builtin_dirs(noncanonical, dirs, 8,
                                                  &count, miss) &&
             strcmp(miss, "builtin_dir_noncanonical") == 0;
    AR_CHECK("driver facts: a built-in search entry that is not an "
             "absolute path is a miss, never a silently dropped entry",
             ok);

    const char *const shapes[] = {
        " /usr/lib/gcc/x86_64-linux-gnu/14/../../../../include\n",
        " /usr/include/\n",
        " /usr/./include\n",
    };
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        char text[512];
        (void)snprintf(text, sizeof(text),
                       "#include <...> search starts here:\n"
                       " /usr/local/include\n%sEnd of search list.\n",
                       shapes[i]);
        bool refused =
            !zcl_action_root_parse_builtin_dirs(text, dirs, 8, &count,
                                                miss) &&
            strcmp(miss, "builtin_dir_noncanonical") == 0;
        AR_CHECK("driver facts: a dot-dot, trailing-slash or dot built-in "
                 "search entry is a miss, never a rewritten spelling",
                 refused);
    }

    size_t long_cap = PATH_MAX + 256;
    char *long_text = zcl_malloc(long_cap, "action root long builtin dir");
    AR_CHECK("driver facts: allocate the over-long transcript",
             long_text != NULL);
    if (long_text) {
        size_t w = (size_t)snprintf(long_text, long_cap,
                                    "#include <...> search starts here:\n"
                                    " /usr/include/");
        while (w < PATH_MAX + 40)
            long_text[w++] = 'a';
        (void)snprintf(long_text + w, long_cap - w,
                       "\n /usr/include\nEnd of search list.\n");
        ok = !zcl_action_root_parse_builtin_dirs(long_text, dirs, 8, &count,
                                                 miss) &&
             strcmp(miss, "builtin_dir_overflow") == 0;
        free(long_text);
        AR_CHECK("driver facts: a built-in search entry longer than a path "
                 "buffer is a miss, never a silently dropped entry", ok);
    }

    char many[8192];
    size_t o = (size_t)snprintf(many, sizeof(many),
                                "#include <...> search starts here:\n");
    for (int i = 0; i < 12; i++)
        o += (size_t)snprintf(many + o, sizeof(many) - o,
                              " /usr/include/fixture-dir-%d\n", i);
    o += (size_t)snprintf(many + o, sizeof(many) - o,
                          "End of search list.\n");
    count = 999;
    ok = !zcl_action_root_parse_builtin_dirs(many, dirs, 8, &count, miss) &&
        strcmp(miss, "builtin_dir_overflow") == 0;
    AR_CHECK("driver facts: more built-in search dirs than the hook's "
             "capacity holds is a miss, never a truncated list", ok);

    const char *fits =
        "#include <...> search starts here:\n"
        " /usr/include\n"
        " /usr/local/include\n"
        "End of search list.\n";
    count = 0;
    ok = zcl_action_root_parse_builtin_dirs(fits, dirs, 8, &count, miss) &&
        count == 2 && strcmp(dirs[0], "/usr/include") == 0 &&
        strcmp(dirs[1], "/usr/local/include") == 0;
    AR_CHECK("driver facts: a canonical, capacity-fitting list still "
             "parses", ok);
}

static void test_cc1_sysroot_parse(void)
{
    const char *valid =
        "Apple clang version 17\n"
        " \"/tool/clang\" \"-cc1\" \"-triple\" \"arm64-apple-macos\" "
        "\"-isysroot\" \"/SDK/MacOSX.sdk\" \"-x\" \"c\"\n";
    const char *missing =
        " \"/tool/clang\" \"-cc1\" \"-x\" \"c\"\n";
    const char *duplicate =
        " \"/tool/clang\" \"-cc1\" \"-isysroot\" \"/SDK/A\" "
        "\"-isysroot\" \"/SDK/B\"\n";
    const char *relative =
        " \"/tool/clang\" \"-cc1\" \"-isysroot\" \"SDK/A\"\n";
    const char *two_commands =
        " \"/tool/clang\" \"-cc1\" \"-isysroot\" \"/SDK/A\"\n"
        " \"/tool/clang\" \"-cc1\" \"-isysroot\" \"/SDK/B\"\n";
    const char *unquoted_bad =
        " /tool/clang -cc1 -isysroot /SDK/A\\broken\n";
    const char *other_command =
        " /tool/ld -isysroot /unused -isysroot /other\n"
        " /tool/clang -cc1 -isysroot /SDK/A\n";
    char sysroot[PATH_MAX];
    bool ok = zcl_action_root_parse_cc1_sysroot(valid, sysroot) &&
              strcmp(sysroot, "/SDK/MacOSX.sdk") == 0 &&
              !zcl_action_root_parse_cc1_sysroot(missing, sysroot) &&
              !zcl_action_root_parse_cc1_sysroot(duplicate, sysroot) &&
              !zcl_action_root_parse_cc1_sysroot(relative, sysroot) &&
              !zcl_action_root_parse_cc1_sysroot(two_commands, sysroot) &&
              !zcl_action_root_parse_cc1_sysroot(unquoted_bad, sysroot) &&
              zcl_action_root_parse_cc1_sysroot(other_command, sysroot) &&
              strcmp(sysroot, "/SDK/A") == 0;
    AR_CHECK("driver facts: only one absolute cc1 -isysroot may supply a "
             "driver that cannot answer -print-sysroot", ok);
}

int test_action_root(void)
{
#if defined(__linux__) && ATOMIC_INT_LOCK_FREE == 2
    const char *role = getenv("ZCL_ACTION_ROOT_IMAGE_ROLE");
    if (role && (strcmp(role, "controls") == 0 ||
                 strcmp(role, "reexec") == 0)) {
        g_failures = 0;
        return image_controls(role);
    }
#endif
    printf("action_root: zcl.action_preimage.v2 codec and derivation\n");
    int codec_failures = action_root_codec_checks();
    g_failures = 0;
    test_derivation();
    test_derive_snapshot_not_commit();
    test_builtin_dir_parse();
    test_cc1_sysroot_parse();
    test_canon_driver_word();
#if defined(__linux__) && ATOMIC_INT_LOCK_FREE == 2
    image_isolated_controls();
#endif
    return g_failures + codec_failures;
}
