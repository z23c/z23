/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_action_root — zcl.action_preimage.v2 (vcs/build_action.h) and its
 * compile derivation (tools/dev/devloop_action_root.h).
 *
 *   1. Codec: canonical encode, strict decode, byte-exact re-encode, a
 *      single-field-change table over every field (root differs AND the
 *      first differing field is named), an empty harness distinct from a
 *      zero root, refusal of host paths / unsorted / unregistered inputs,
 *      and every single-bit tamper of a stored preimage either refused or
 *      given a different root.
 *   2. Derivation on a fixture tree: flags (-D add, -D value, reorder, -O),
 *      a #define in an included header, header content, a NEW shadowing
 *      header in an earlier search dir and in an includer dir (negative
 *      lookups, depfile unchanged), header removal, the capsule sysroot,
 *      harness/fixtures/policy, allowlisted vs non-allowlisted environment,
 *      and ABI generation each change the root; restoring the input
 *      restores the root.
 *   3. Identity: the same fixture at two absolute roots derives the SAME
 *      root; a stored preimage re-derives its root after load, a tampered
 *      stored object is refused.
 *   4. The hotload hook fills a receipt (first -> hit -> source) and the
 *      receipt JSON carries action_root.
 *
 * All fixture state lives under ./test-tmp/. */

#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "devloop.h"
#include "devloop_action_root.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/environment_compat.h"
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

/* ---- 1. codec ------------------------------------------------------- */

struct codec_fixture {
    struct vcs_action_input_v2 sources[2];
    struct vcs_action_input_v2 generated[1];
    const char *search[3];
    const char *includers[2];
    struct vcs_action_probe_v2 probes[2];
    struct vcs_action_present_v2 present[1];
    const char *argv[5];
    const char *env[2];
    struct vcs_action_abi_v2 abi[2];
    struct vcs_action_preimage_v2 p;
};

static void codec_fixture_init(struct codec_fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->sources[0].path = "inc/defs.h";
    ar_fill(f->sources[0].sha3, 1);
    f->sources[1].path = "src/unit.c";
    ar_fill(f->sources[1].sha3, 2);
    f->generated[0].path = "build/gen/unity.c";
    ar_fill(f->generated[0].sha3, 3);
    f->search[0] = "inc_a";
    f->search[1] = "inc";
    f->search[2] = "@sys/usr/include";
    f->includers[0] = "inc";
    f->includers[1] = "src";
    f->probes[0] = (struct vcs_action_probe_v2){ "defs.h", 1 };
    f->probes[1] = (struct vcs_action_probe_v2){ "unit.c", 0 };
    f->present[0] = (struct vcs_action_present_v2){
        .dir = "src", .name = "unit.c",
        .kind = VCS_ACTION_PRESENT_V2_REGULAR };
    ar_fill(f->present[0].sha3, 2);
    f->argv[0] = "cc";
    f->argv[1] = "-DFOO=1";
    f->argv[2] = "-ffile-prefix-map=@root=/zclassic23";
    f->argv[3] = "-o";
    f->argv[4] = "@out/object";
    f->env[0] = "LANG=C";
    f->env[1] = "SOURCE_DATE_EPOCH=0";
    f->abi[0] = (struct vcs_action_abi_v2){ "hotswap_module", 3 };
    f->abi[1] = (struct vcs_action_abi_v2){ "hotswap_service", 1 };
    struct vcs_action_preimage_v2 *p = &f->p;
    p->stage_kind = "c23.compile.test";
    p->stage_version = 1;
    p->sources = f->sources;
    p->source_count = 2;
    p->generated = f->generated;
    p->generated_count = 1;
    p->search_dirs = f->search;
    p->search_dir_count = 3;
    p->includer_dirs = f->includers;
    p->includer_dir_count = 2;
    p->probes = f->probes;
    p->probe_count = 2;
    p->present = f->present;
    p->present_count = 1;
    ar_fill(p->toolchain_root, 9);
    p->argv = f->argv;
    p->argc = 5;
    p->env = f->env;
    p->env_count = 2;
    p->abi = f->abi;
    p->abi_count = 2;
    p->harness.present = true;
    ar_fill(p->harness.root, 10);
    p->fixtures.present = true;
    ar_fill(p->fixtures.root, 11);
    p->policy.present = true;
    ar_fill(p->policy.root, 12);
}

static bool codec_root(const struct vcs_action_preimage_v2 *p,
                       uint8_t root[32], uint8_t **bytes, size_t *len)
{
    char why[256] = {0};
    uint8_t *b = NULL;
    size_t n = 0;
    bool ok = vcs_action_preimage_v2_encode(p, &b, &n, why, sizeof(why)) &&
              vcs_action_root_v2_from_bytes(b, n, root, why, sizeof(why));
    if (!ok)
        printf("    codec refusal: %s\n", why);
    if (ok && bytes) {
        *bytes = b;
        *len = n;
    } else {
        free(b);
    }
    return ok;
}

static bool codec_refused(const struct vcs_action_preimage_v2 *p)
{
    uint8_t *b = NULL;
    size_t n = 0;
    char why[256] = {0};
    bool encoded = vcs_action_preimage_v2_encode(p, &b, &n, why, sizeof(why));
    free(b);
    return !encoded && why[0] != '\0';
}

static void test_codec_roundtrip(void)
{
    struct codec_fixture f;
    codec_fixture_init(&f);
    uint8_t root[32], again[32];
    uint8_t *bytes = NULL, *re = NULL;
    size_t len = 0, re_len = 0;
    struct vcs_action_preimage_v2_decoded d = {0};
    char why[256] = {0};
    bool ok = codec_root(&f.p, root, &bytes, &len) &&
              vcs_action_preimage_v2_decode(bytes, len, &d, why,
                                            sizeof(why)) &&
              vcs_action_preimage_v2_encode(&d.view, &re, &re_len, why,
                                            sizeof(why)) &&
              re_len == len && memcmp(re, bytes, len) == 0 &&
              vcs_action_root_v2_from_bytes(re, re_len, again, why,
                                            sizeof(why)) &&
              memcmp(root, again, 32) == 0;
    AR_CHECK("decode then re-encode is byte-identical with the same root",
             ok);
    enum vcs_action_field_v2 field = VCS_ACTION_FIELD_V2_COUNT;
    AR_CHECK("identical preimages report no differing field",
             bytes && vcs_action_preimage_v2_first_diff(bytes, len, re,
                                                        re_len, &field) &&
                 field == VCS_ACTION_FIELD_V2_NONE);
    vcs_action_preimage_v2_decoded_free(&d);
    free(re);
    free(bytes);
}

typedef void (*codec_mutator)(struct codec_fixture *f);

static void mut_stage(struct codec_fixture *f) { f->p.stage_version = 2; }
static void mut_source(struct codec_fixture *f) { f->sources[1].sha3[5] ^= 1; }
static void mut_generated(struct codec_fixture *f)
{
    f->generated[0].sha3[0] ^= 1;
}
static void mut_negative(struct codec_fixture *f)
{
    f->probes[0].search_prefix = 0;
}
static void mut_toolchain(struct codec_fixture *f)
{
    f->p.toolchain_root[31] ^= 1;
}
static void mut_flags(struct codec_fixture *f) { f->argv[1] = "-DFOO=2"; }
static void mut_env(struct codec_fixture *f) { f->env[1] = "SOURCE_DATE_EPOCH=1"; }
static void mut_abi(struct codec_fixture *f) { f->abi[0].version = 4; }
static void mut_harness(struct codec_fixture *f) { f->p.harness.root[0] ^= 1; }
static void mut_fixtures(struct codec_fixture *f) { f->p.fixtures.root[0] ^= 1; }
static void mut_policy(struct codec_fixture *f) { f->p.policy.root[0] ^= 1; }

static void test_codec_field_table(void)
{
    static const struct {
        enum vcs_action_field_v2 field;
        codec_mutator mutate;
    } rows[] = {
        { VCS_ACTION_FIELD_V2_STAGE, mut_stage },
        { VCS_ACTION_FIELD_V2_SOURCE, mut_source },
        { VCS_ACTION_FIELD_V2_GENERATED, mut_generated },
        { VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP, mut_negative },
        { VCS_ACTION_FIELD_V2_TOOLCHAIN, mut_toolchain },
        { VCS_ACTION_FIELD_V2_FLAGS, mut_flags },
        { VCS_ACTION_FIELD_V2_ENV, mut_env },
        { VCS_ACTION_FIELD_V2_ABI, mut_abi },
        { VCS_ACTION_FIELD_V2_HARNESS, mut_harness },
        { VCS_ACTION_FIELD_V2_FIXTURES, mut_fixtures },
        { VCS_ACTION_FIELD_V2_POLICY, mut_policy },
    };
    struct codec_fixture base;
    codec_fixture_init(&base);
    uint8_t base_root[32];
    uint8_t *base_bytes = NULL;
    size_t base_len = 0;
    bool covered = codec_root(&base.p, base_root, &base_bytes, &base_len) &&
                   sizeof(rows) / sizeof(rows[0]) ==
                       VCS_ACTION_FIELD_V2_COUNT - 1;
    for (size_t i = 0; base_bytes && i < sizeof(rows) / sizeof(rows[0]); i++) {
        struct codec_fixture f;
        codec_fixture_init(&f);
        rows[i].mutate(&f);
        uint8_t root[32];
        uint8_t *bytes = NULL;
        size_t len = 0;
        enum vcs_action_field_v2 field = VCS_ACTION_FIELD_V2_NONE;
        bool ok = codec_root(&f.p, root, &bytes, &len) &&
                  memcmp(root, base_root, 32) != 0 &&
                  vcs_action_preimage_v2_first_diff(base_bytes, base_len,
                                                    bytes, len, &field) &&
                  field == rows[i].field;
        char name[96];
        (void)snprintf(name, sizeof(name),
                       "single-field change '%s' moves the root and is named",
                       vcs_action_field_v2_name(rows[i].field));
        AR_CHECK(name, ok);
        covered = covered && ok;
        free(bytes);
    }
    AR_CHECK("the field table covers every preimage field", covered);
    free(base_bytes);
}

static void test_codec_empty_is_not_zero(void)
{
    struct codec_fixture a, b;
    codec_fixture_init(&a);
    codec_fixture_init(&b);
    a.p.harness.present = false;
    b.p.harness.present = true;
    memset(b.p.harness.root, 0, 32);
    uint8_t ra[32], rb[32];
    AR_CHECK("an empty harness root hashes apart from a zero root",
             codec_root(&a.p, ra, NULL, NULL) &&
                 codec_root(&b.p, rb, NULL, NULL) && memcmp(ra, rb, 32) != 0);
}

static void test_codec_refusals(void)
{
    struct codec_fixture f;
    codec_fixture_init(&f);
    f.argv[1] = "-I/home/someone/include";
    AR_CHECK("an absolute host path in argv is refused", codec_refused(&f.p));
    codec_fixture_init(&f);
    f.argv[1] = "-DROOT=/home/someone";
    AR_CHECK("an absolute path after '=' is refused", codec_refused(&f.p));
    codec_fixture_init(&f);
    f.sources[0].path = "/home/someone/defs.h";
    AR_CHECK("an absolute source path is refused", codec_refused(&f.p));
    codec_fixture_init(&f);
    f.sources[0].path = "src/zz.h";
    AR_CHECK("an unsorted source list is refused", codec_refused(&f.p));
    codec_fixture_init(&f);
    f.search[1] = "inc_a";
    AR_CHECK("a repeated search dir is refused", codec_refused(&f.p));
    codec_fixture_init(&f);
    f.env[0] = "HOME=/zbuild/home";
    AR_CHECK("a non-allowlisted environment name is refused",
             codec_refused(&f.p));
    codec_fixture_init(&f);
    f.present[0].dir = "inc_a";
    f.present[0].name = "unit.c";
    AR_CHECK("a present location outside the probed set is refused",
             codec_refused(&f.p));
    codec_fixture_init(&f);
    f.p.argc = 0;
    AR_CHECK("an action without argv is refused", codec_refused(&f.p));
}

/* Every single-bit flip of a stored preimage is refused or re-roots. */
static void test_codec_tamper(void)
{
    struct codec_fixture f;
    codec_fixture_init(&f);
    uint8_t root[32];
    uint8_t *bytes = NULL;
    size_t len = 0;
    bool ok = codec_root(&f.p, root, &bytes, &len);
    size_t refused = 0, rerooted = 0;
    for (size_t i = 0; ok && i < len; i++) {
        for (unsigned bit = 0; bit < 8; bit++) {
            uint8_t other[32];
            bytes[i] ^= (uint8_t)(1u << bit);
            if (!vcs_action_root_v2_from_bytes(bytes, len, other, NULL, 0))
                refused++;
            else if (memcmp(other, root, 32) != 0)
                rerooted++;
            else
                ok = false;
            bytes[i] ^= (uint8_t)(1u << bit);
        }
    }
    uint8_t *longer = ok ? zcl_malloc(len + 1, "tamper fixture") : NULL;
    if (longer) {
        memcpy(longer, bytes, len);
        longer[len] = 0;
        uint8_t other[32];
        ok = !vcs_action_root_v2_from_bytes(longer, len + 1, other, NULL, 0);
    }
    printf("    tamper: %zu bytes, %zu flips refused, %zu re-rooted\n", len,
           refused, rerooted);
    AR_CHECK("every single-bit tamper is refused or re-rooted",
             ok && longer && refused + rerooted == len * 8);
    free(longer);
    free(bytes);
}

/* ---- 2/3. derivation fixture ---------------------------------------- */

struct fx {
    char root[PATH_MAX];
    char depfile[PATH_MAX];
    char obj[PATH_MAX];
    char prefix_map[PATH_MAX + 64];
    char include_b[PATH_MAX + 8];
    char unity_in[PATH_MAX];
    const char *argv[24];
    const char *vfrom[2];
    const char *vto[2];
    const char *env[5];
    const char *system_dirs[1];
    struct vcs_action_abi_v2 abi[1];
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

static bool fx_depfile(struct fx *x, bool with_local)
{
    char text[4 * PATH_MAX];
    (void)snprintf(text, sizeof(text),
                   "build/obj.o: build/gen/unity.c %s/src/unit.c%s \\\n"
                   " inc_b/defs.h\n",
                   x->root, with_local ? " src/local.h" : "");
    return fx_write(x->root, "build/unit.d", text);
}

static bool fx_tree(struct fx *x)
{
    char unity[PATH_MAX + 32];
    (void)snprintf(unity, sizeof(unity), "#include \"%s/src/unit.c\"\n",
                   x->root);
    return fx_write(x->root, "inc_a/.keep", "") &&
           fx_write(x->root, "inc_b/defs.h", "#define X 1\n") &&
           fx_write(x->root, "src/local.h", "int local(void);\n") &&
           fx_write(x->root, "src/unit.c",
                    "#include \"local.h\"\n#include <defs.h>\n"
                    "int unit(void) { return X; }\n") &&
           fx_write(x->root, "build/gen/unity.c", unity) &&
           fx_depfile(x, true);
}

static void fx_argv(struct fx *x)
{
    (void)snprintf(x->prefix_map, sizeof(x->prefix_map),
                   "-ffile-prefix-map=%s=/zclassic23", x->root);
    (void)snprintf(x->include_b, sizeof(x->include_b), "-I%s/inc_b",
                   x->root);
    (void)snprintf(x->obj, sizeof(x->obj), "%s/build/obj.o", x->root);
    (void)snprintf(x->unity_in, sizeof(x->unity_in), "%s/build/gen/unity.c",
                   x->root);
    const char *argv[] = {
        "cc", "-std=c23", x->prefix_map, "-Iinc_a", x->include_b, "-DFOO=1",
        "-O2", "-MD", "-MF", x->depfile, "-c", "-o", x->obj, x->unity_in,
    };
    memcpy(x->argv, argv, sizeof(argv));
    x->req.argv = x->argv;
    x->req.argc = sizeof(argv) / sizeof(argv[0]);
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
    x->env[0] = "LANG=C";
    x->env[1] = "HOME=/home/fixture-user";
    x->env[2] = "SOURCE_DATE_EPOCH=0";
    x->env[3] = NULL;
    x->system_dirs[0] = "/usr/include";
    x->abi[0] = (struct vcs_action_abi_v2){ "fixture_abi", 1 };
    struct zcl_action_root_request *r = &x->req;
    r->root = x->root;
    r->stage_kind = "c23.compile.fixture";
    r->stage_version = 1;
    r->virtual_from = x->vfrom;
    r->virtual_to = x->vto;
    r->virtual_count = 2;
    r->depfile = x->depfile;
    r->system_dirs = x->system_dirs;
    r->system_dir_count = 1;
    r->environ = x->env;
    ar_fill(r->toolchain_root, 40);
    r->abi = x->abi;
    r->abi_count = 1;
    r->harness.present = true;
    ar_fill(r->harness.root, 41);
    r->fixtures.present = true;
    ar_fill(r->fixtures.root, 42);
    r->policy.present = true;
    ar_fill(r->policy.root, 43);
    return true;
}

/* Derive; *field names the first difference from `base` when given. */
static bool fx_derive(const struct fx *x, struct zcl_action_root_result *out)
{
    bool ok = zcl_action_root_derive(&x->req, out);
    if (!ok)
        printf("    derive refused: %s\n", out->why);
    return ok;
}

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
    ok = fx_write(x->root, "src/defs.h", "#define X 4\n") &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP) &&
         fx_remove(x->root, "src/defs.h");
    AR_CHECK("headers: a new shadowing header in the includer's own dir "
             "moves the root", ok && fx_same(x, b));
    struct zcl_action_root_result stale = {0};
    bool refused = fx_remove(x->root, "src/local.h") &&
                   !zcl_action_root_derive(&x->req, &stale);
    AR_CHECK("headers: a removed header named by a stale depfile is refused",
             refused);
    ok = fx_depfile(x, false) &&
         fx_differs(x, b, VCS_ACTION_FIELD_V2_SOURCE) &&
         fx_write(x->root, "src/local.h", "int local(void);\n") &&
         fx_depfile(x, true);
    AR_CHECK("headers: removing a header from the closure moves the root",
             ok && fx_same(x, b));
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
    capsule.sysroot_sha3[3] ^= 0x40;
    ok = ok && vcs_toolchain_capsule_v1_root(&capsule, x->req.toolchain_root) &&
         fx_differs(x, &first, VCS_ACTION_FIELD_V2_TOOLCHAIN);
    zcl_action_root_result_free(&first);
    memcpy(x->req.toolchain_root, saved, 32);
    AR_CHECK("sysroot: a changed capsule sysroot_sha3 moves the root",
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
    x->abi[0].version = 2;
    ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ABI);
    x->abi[0].version = 1;
    AR_CHECK("abi: a new ABI generation moves the root", ok && fx_same(x, b));
}

static void test_derive_env(struct fx *x,
                            const struct zcl_action_root_result *b)
{
    x->env[2] = "SOURCE_DATE_EPOCH=1";
    bool ok = fx_differs(x, b, VCS_ACTION_FIELD_V2_ENV);
    x->env[2] = "SOURCE_DATE_EPOCH=0";
    AR_CHECK("env: an allowlisted variable change moves the root",
             ok && fx_same(x, b));
    x->env[1] = "HOME=/home/somebody-else";
    ok = fx_same(x, b);
    x->env[3] = "PATH=/opt/other/bin:/usr/bin";
    ok = ok && fx_same(x, b);
    x->env[1] = "HOME=/home/fixture-user";
    x->env[3] = NULL;
    AR_CHECK("env: non-allowlisted variables never reach the root", ok);
    x->env[3] = "CPATH=/home/somebody/include";
    struct zcl_action_root_result r = {0};
    ok = !zcl_action_root_derive(&x->req, &r);
    x->env[3] = NULL;
    AR_CHECK("env: an allowlisted value naming a host path is refused", ok);
}

static void test_derive_refusals(struct fx *x)
{
    struct zcl_action_root_result r = {0};
    const char *saved = x->argv[3];
    x->argv[3] = "-I/home/somebody/include";
    bool ok = !zcl_action_root_derive(&x->req, &r);
    x->argv[3] = saved;
    AR_CHECK("an include dir outside the checkout is refused", ok);
    char outside[PATH_MAX + 64], text[2 * PATH_MAX + 96];
    (void)snprintf(outside, sizeof(outside), "%s-outside/leak.h", x->root);
    (void)snprintf(text, sizeof(text), "build/obj.o: src/unit.c %s\n",
                   outside);
    ok = fx_write(x->root, "build/unit.d", text) &&
         !zcl_action_root_derive(&x->req, &r) && fx_depfile(x, true);
    AR_CHECK("a dependency outside the checkout is refused", ok);
    x->argv[3] = "-nostdinc";
    ok = !zcl_action_root_derive(&x->req, &r);
    x->argv[3] = saved;
    AR_CHECK("a flag that moves the built-in include search is refused", ok);
}

static void test_derive_cross_worktree(const struct zcl_action_root_result *a)
{
    struct fx *y = zcl_calloc(1, sizeof(*y), "action root fixture b");
    struct zcl_action_root_result r = {0};
    bool ok = y && fx_init(y, "b") && fx_derive(y, &r) &&
              memcmp(r.root, a->root, 32) == 0 &&
              r.preimage_len == a->preimage_len &&
              memcmp(r.preimage, a->preimage, a->preimage_len) == 0;
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
                                    x->depfile, &r1);
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    x->depfile, &r2);
    ok = ok && fx_write(x->root, "src/local.h", "int local(long);\n");
    zcl_devloop_action_root_hotswap(x->root, "src/unit.c", "cc", cflags,
                                    x->depfile, &r3);
    ok = ok && fx_write(x->root, "src/local.h", "int local(void);\n");
    if (!r1.action_root[0])
        printf("    hook refused: %s\n", r1.action_root_refused);
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
        printf("    fixture: %u sources, %u generated, %u names, "
               "%u probes, %u present, %zu preimage bytes, %lldus\n",
               base.source_count, base.generated_count, base.probe_names,
               base.probes, base.present, base.preimage_len,
               (long long)base.derive_us);
        AR_CHECK("stability: deriving twice without change gives one root",
                 fx_same(x, &base));
        test_derive_flags(x, &base);
        test_derive_headers(x, &base);
        test_derive_sysroot(x, &base);
        test_derive_roots(x, &base);
        test_derive_env(x, &base);
        test_derive_refusals(x);
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

int test_action_root(void)
{
    g_failures = 0;
    printf("action_root: zcl.action_preimage.v2 codec and derivation\n");
    test_codec_roundtrip();
    test_codec_field_table();
    test_codec_empty_is_not_zero();
    test_codec_refusals();
    test_codec_tamper();
    test_derivation();
    return g_failures;
}
