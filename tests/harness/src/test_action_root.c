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
#include "util/spawn.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

struct fx {
    char root[PATH_MAX];
    char depfile[PATH_MAX];
    char obj[PATH_MAX];
    char so[PATH_MAX];
    char ld[PATH_MAX];
    char prefix_map[PATH_MAX + 64];
    char include_b[PATH_MAX + 8];
    char unity_in[PATH_MAX];
    const char *argv[24];
    const char *link_argv[8];
    const char *vfrom[3];
    const char *vto[3];
    const char *env[6];
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
    char unity[PATH_MAX + 32], gen[PATH_MAX + 64];
    (void)snprintf(unity, sizeof(unity), "#include \"%s/src/unit.c\"\n",
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
    r->environ = x->env;
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
    x->env[3] = NULL;
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

/* The derivation misses with exactly `code` and yields no root at all. */
static bool fx_miss(const struct fx *x, const char *code)
{
    struct zcl_action_root_result r = {0};
    bool missed = !zcl_action_root_derive(&x->req, &r);
    bool ok = missed && strcmp(r.miss, code) == 0 && !r.root_hex[0] &&
              !r.preimage;
    if (!ok)
        printf("    expected miss %s, got %s (%s)\n", code,
               missed ? r.miss : "a root", r.why);
    zcl_action_root_result_free(&r);
    return ok;
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
    x->link_argv[1] = "-static";
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_LINKER);
    x->link_argv[1] = "-fuse-ld=gold";
    ok = ok && fx_miss(x, "search_flag_unsupported");
    x->link_argv[1] = "-shared";
    AR_CHECK("linker: link flags move the root; -fuse-ld is refused",
             ok && fx_same(x, b));
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
    x->env[3] = "TZ=";
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ENV);
    x->env[3] = NULL;
    AR_CHECK("env: an allowlisted variable set empty differs from unset",
             ok && fx_same(x, b));
    x->env[1] = "HOME=/srv/host-c";
    ok = fx_same(x, b);
    x->env[3] = "PATH=/opt/other/bin:/usr/bin";
    ok = ok && fx_same(x, b);
    x->env[1] = "HOME=/srv/fixture-home";
    x->env[3] = NULL;
    AR_CHECK("env: non-allowlisted variables never reach the root", ok);
    x->env[3] = "CPATH=/srv/host-b/include";
    ok = fx_miss(x, "env_noncanonical");
    x->env[3] = "LANG=C";
    ok = ok && fx_miss(x, "env_duplicate");
    x->env[3] = NULL;
    AR_CHECK("env: a host path value or a repeated allowlisted name is "
             "refused, not normalized", ok && fx_same(x, b));
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

/* Missing data is a MISS: no root, an explicit reason, never a guess. */
static void test_derive_misses(struct fx *x,
                               const struct zcl_action_root_result *b)
{
    bool ok = fx_remove(x->root, "build/unit.d") &&
              fx_miss(x, "depfile_missing") && fx_depfile(x, true);
    AR_CHECK("miss: a missing depfile yields no root (depfile_missing)",
             ok && fx_same(x, b));
    ok = fx_write(x->root, "build/unit.d", "no rule here\n") &&
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
                                    "-shared", NULL, &r);
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
                                    "-shared", gone, &r);
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
                                    dep, &h1);
    zcl_devloop_action_root_hotfork(x->root, "src/unit.c", "cc", cflags, b,
                                    dep, &h2);
    ok = ok && fx_write(x->root, "build/hotswap-fast/.resident-bbbbbb.c",
                        "/* adapter v2 */\n#include \"src/unit.c\"\n");
    zcl_devloop_action_root_hotfork(x->root, "src/unit.c", "cc", cflags, b,
                                    dep, &h3);
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
                                    NULL, &h1);
    AR_CHECK("hotfork hook: a failed capsule build misses "
             "(closure_unobserved)",
             !h1.action_root[0] &&
                 strcmp(h1.action_root_miss, "closure_unobserved") == 0);
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
                                    "-shared", x->depfile, &r1);
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", x->depfile, &r2);
    ok = ok && fx_write(x->root, "src/local.h", "int local(long);\n");
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    "-shared", x->depfile, &r3);
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
    AR_CHECK("hook: an unchanged recompile reports cause=hit",
             strcmp(r2.action_root, r1.action_root) == 0 &&
                 strcmp(r2.action_root_cause, "hit") == 0);
    AR_CHECK("hook: a header edit reports cause=source",
             strlen(r3.action_root) == 64 &&
                 strcmp(r3.action_root, r1.action_root) != 0 &&
                 strcmp(r3.action_root_cause, "source") == 0);
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    zcl_devloop_action_root_emit(&doc, &r1);
    const char *emitted = json_get_str(json_get(&doc, "action_root"));
    AR_CHECK("hook: the receipt JSON carries action_root and its cause",
             emitted && strcmp(emitted, r1.action_root) == 0 &&
                 json_get_str(json_get(&doc, "action_root_cause")) &&
                 json_get(&doc, "action_root_ms"));
    json_free(&doc);
    test_hook_misses(x, cflags);
    test_hotfork_hook(x, cflags);
    if (prior[0])
        (void)platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", prior, 1);
    else
        (void)unsetenv("ZCL_DEV_ARTIFACT_CACHE");
    test_rm_rf_recursive(cache);
}

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
        test_derive_lookups(x, &base);
        test_derive_sysroot(x, &base);
        test_derive_linker(x, &base);
        test_derive_generated(x, &base);
        test_derive_roots(x, &base);
        test_derive_env(x, &base);
        test_derive_refusals(x);
        test_derive_misses(x, &base);
        test_derive_cross_worktree(&base);
        test_derive_store(x, &base);
        test_derive_causes(x, &base);
        test_hotswap_hook(x);
    }
    zcl_action_root_result_free(&base);
    if (x)
        test_rm_rf_recursive(x->root);
    free(x);
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

int test_action_root(void)
{
    printf("action_root: zcl.action_preimage.v2 codec and derivation\n");
    int codec_failures = action_root_codec_checks();
    g_failures = 0;
    test_derivation();
    test_derive_snapshot_not_commit();
    test_builtin_dir_parse();
    return g_failures + codec_failures;
}
