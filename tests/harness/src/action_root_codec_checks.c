/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Codec checks of the action_root group (test_action_root.c): canonical
 * encode, strict decode, byte-exact re-encode, per-field roots, a
 * single-field-change table over all 13 fields (root differs AND the first
 * differing field is named), absent spelled apart from zero / empty, a
 * refusal table (host paths, unsorted or duplicate sets, one path with two
 * content hashes, environment out of allowlist order or repeated, lookups
 * that miss or disagree with the search order), the fill of
 * vcs_build_input_closure_v1 from v2 field roots, and every single-bit
 * tamper of a stored preimage refused or re-rooted. */

#include "test/action_root_codec_checks.h"

#include "base/safe_alloc.h"
#include "vcs/build_action.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    struct vcs_action_generated_v2 generated[1];
    const char *search[3];
    const char *includers[3];
    struct vcs_action_present_v2 present[1];
    struct vcs_action_lookup_v2 lookups[3];
    const char *builtin[1];
    const char *link_argv[5];
    const char *argv[5];
    struct vcs_action_env_v2 env[16];
    struct vcs_action_abi_v2 abi[2];
    struct vcs_action_preimage_v2 p;
};

static void codec_env_init(struct codec_fixture *f)
{
    size_t n = 0;
    const char *const *allow = vcs_action_v2_env_allowlist(&n);
    for (size_t i = 0; i < n && i < 16; i++) {
        f->env[i] = (struct vcs_action_env_v2){ allow[i], false, NULL };
        if (strcmp(allow[i], "LANG") == 0)
            f->env[i] = (struct vcs_action_env_v2){ allow[i], true, "C" };
        if (strcmp(allow[i], "SOURCE_DATE_EPOCH") == 0)
            f->env[i] = (struct vcs_action_env_v2){ allow[i], true, "0" };
    }
    f->p.env = f->env;
    f->p.env_count = n;
}

static size_t codec_env_at(const struct codec_fixture *f, const char *name)
{
    for (size_t i = 0; i < f->p.env_count; i++)
        if (strcmp(f->env[i].name, name) == 0)
            return i;
    return 0;
}

/* Inputs inc/defs.h, src/unit.c and generated build/gen/unity.c; search
 * order inc_a, inc, @sys/usr/include; three lookups, one probe hit. */
static void codec_fixture_lookups(struct codec_fixture *f)
{
    f->search[0] = "inc_a";
    f->search[1] = "inc";
    f->search[2] = "@sys/usr/include";
    f->includers[0] = "build/gen";
    f->includers[1] = "inc";
    f->includers[2] = "src";
    f->present[0] = (struct vcs_action_present_v2){
        .slot = 1, .kind = VCS_ACTION_PRESENT_V2_REGULAR };
    ar_fill(f->present[0].sha3, 4);
    f->lookups[0] = (struct vcs_action_lookup_v2){ "unity.c", "build/gen", 0,
                                                   NULL, 0 };
    f->lookups[1] = (struct vcs_action_lookup_v2){ "unit.c", "src", 0,
                                                   f->present, 1 };
    f->lookups[2] = (struct vcs_action_lookup_v2){ "defs.h", "inc", 1,
                                                   NULL, 0 };
}

static void codec_fixture_init(struct codec_fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->sources[0].path = "inc/defs.h";
    ar_fill(f->sources[0].sha3, 1);
    f->sources[1].path = "src/unit.c";
    ar_fill(f->sources[1].sha3, 2);
    f->generated[0].path = "build/gen/unity.c";
    ar_fill(f->generated[0].sha3, 3);
    codec_fixture_lookups(f);
    f->builtin[0] = "@sys/usr/include";
    static const char *const link[] = { "cc", "-shared", "-o", "@out/module",
                                        "@out/object" };
    memcpy(f->link_argv, link, sizeof(link));
    static const char *const argv[] = { "cc", "-DFOO=1",
                                        "-ffile-prefix-map=@root=/zclassic23",
                                        "-o", "@out/object" };
    memcpy(f->argv, argv, sizeof(argv));
    f->abi[0] = (struct vcs_action_abi_v2){ "hotswap_module", 3 };
    f->abi[1] = (struct vcs_action_abi_v2){ "hotswap_service", 1 };
    struct vcs_action_preimage_v2 *p = &f->p;
    *p = (struct vcs_action_preimage_v2){
        .stage_kind = "c23.compile.test", .stage_version = 1,
        .sources = f->sources, .source_count = 2,
        .generated = f->generated, .generated_count = 1,
        .search_dirs = f->search, .search_dir_count = 3,
        .includer_dirs = f->includers, .includer_dir_count = 3,
        .lookups = f->lookups, .lookup_count = 3,
        .argv = f->argv, .argc = 5, .abi_generation = 4,
        .abi = f->abi, .abi_count = 2,
    };
    p->sysroot = (struct vcs_action_sysroot_v2){
        .sysroot = NULL, .builtin_dirs = f->builtin, .builtin_dir_count = 1 };
    ar_fill(p->sysroot.objects_sha3, 5);
    p->linker = (struct vcs_action_linker_v2){
        .links = true, .ld = "@sys/usr/bin/ld",
        .collect2 = "@sys/usr/libexec/gcc/collect2",
        .argv = f->link_argv, .argc = 5 };
    ar_fill(p->linker.ld_sha3, 6);
    ar_fill(p->linker.collect2_sha3, 7);
    ar_fill(p->toolchain_root, 9);
    codec_env_init(f);
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

/* A per-field root binds one field only: an env change leaves the flags
 * root alone and moves the env root. */
static void test_codec_field_roots(void)
{
    struct codec_fixture a, b;
    codec_fixture_init(&a);
    codec_fixture_init(&b);
    b.env[codec_env_at(&b, "LANG")].value = "C.UTF-8";
    uint8_t ra[32], rb[32], fa[32], fb[32], ea[32], eb[32];
    uint8_t *ba = NULL, *bb = NULL;
    size_t la = 0, lb = 0;
    bool ok = codec_root(&a.p, ra, &ba, &la) && codec_root(&b.p, rb, &bb, &lb) &&
              vcs_action_preimage_v2_field_root(ba, la,
                                                VCS_ACTION_FIELD_V2_FLAGS, fa) &&
              vcs_action_preimage_v2_field_root(bb, lb,
                                                VCS_ACTION_FIELD_V2_FLAGS, fb) &&
              vcs_action_preimage_v2_field_root(ba, la,
                                                VCS_ACTION_FIELD_V2_ENV, ea) &&
              vcs_action_preimage_v2_field_root(bb, lb,
                                                VCS_ACTION_FIELD_V2_ENV, eb) &&
              memcmp(fa, fb, 32) == 0 && memcmp(ea, eb, 32) != 0 &&
              memcmp(fa, ea, 32) != 0;
    AR_CHECK("field roots: an env change moves only the env field root", ok);
    AR_CHECK("field roots: a reserved or unknown field has no root",
             ba && !vcs_action_preimage_v2_field_root(
                       ba, la, VCS_ACTION_FIELD_V2_RESERVED_INVARIANTS, fa) &&
                 !vcs_action_preimage_v2_field_root(
                     ba, la, VCS_ACTION_FIELD_V2_NONE, fa));
    free(ba);
    free(bb);
}

typedef void (*codec_mutator)(struct codec_fixture *f);

static void mut_stage(struct codec_fixture *f) { f->p.stage_version = 2; }
static void mut_source(struct codec_fixture *f) { f->sources[1].sha3[5] ^= 1; }
static void mut_generated(struct codec_fixture *f)
{
    f->generated[0].producer_known = true;
    ar_fill(f->generated[0].producer_action_key, 13);
}
static void mut_negative(struct codec_fixture *f)
{
    f->present[0].kind = VCS_ACTION_PRESENT_V2_OTHER;
}
static void mut_toolchain(struct codec_fixture *f)
{
    f->p.toolchain_root[31] ^= 1;
}
static void mut_sysroot(struct codec_fixture *f)
{
    f->p.sysroot.objects_sha3[0] ^= 1;
}
static void mut_linker(struct codec_fixture *f) { f->p.linker.ld_sha3[0] ^= 1; }
static void mut_flags(struct codec_fixture *f) { f->argv[1] = "-DFOO=2"; }
static void mut_env(struct codec_fixture *f)
{
    f->env[codec_env_at(f, "TZ")] =
        (struct vcs_action_env_v2){ "TZ", true, "UTC" };
}
static void mut_abi(struct codec_fixture *f) { f->p.abi_generation = 5; }
static void mut_harness(struct codec_fixture *f) { f->p.harness.root[0] ^= 1; }
static void mut_fixtures(struct codec_fixture *f) { f->p.fixtures.root[0] ^= 1; }
static void mut_policy(struct codec_fixture *f) { f->p.policy.root[0] ^= 1; }

static const struct field_row {
    enum vcs_action_field_v2 field;
    codec_mutator mutate;
} g_field_rows[] = {
    { VCS_ACTION_FIELD_V2_STAGE, mut_stage },
    { VCS_ACTION_FIELD_V2_SOURCE, mut_source },
    { VCS_ACTION_FIELD_V2_GENERATED, mut_generated },
    { VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP, mut_negative },
    { VCS_ACTION_FIELD_V2_TOOLCHAIN, mut_toolchain },
    { VCS_ACTION_FIELD_V2_SYSROOT, mut_sysroot },
    { VCS_ACTION_FIELD_V2_LINKER, mut_linker },
    { VCS_ACTION_FIELD_V2_FLAGS, mut_flags },
    { VCS_ACTION_FIELD_V2_ENV, mut_env },
    { VCS_ACTION_FIELD_V2_ABI, mut_abi },
    { VCS_ACTION_FIELD_V2_HARNESS, mut_harness },
    { VCS_ACTION_FIELD_V2_FIXTURES, mut_fixtures },
    { VCS_ACTION_FIELD_V2_POLICY, mut_policy },
};
#define FIELD_ROWS (sizeof(g_field_rows) / sizeof(g_field_rows[0]))

static void test_codec_field_table(void)
{
    struct codec_fixture base;
    codec_fixture_init(&base);
    uint8_t base_root[32];
    uint8_t *base_bytes = NULL;
    size_t base_len = 0;
    bool covered = codec_root(&base.p, base_root, &base_bytes, &base_len) &&
                   FIELD_ROWS == VCS_ACTION_FIELD_V2_COUNT - 1;
    for (size_t i = 0; base_bytes && i < FIELD_ROWS; i++) {
        struct codec_fixture f;
        codec_fixture_init(&f);
        g_field_rows[i].mutate(&f);
        uint8_t root[32];
        uint8_t *bytes = NULL;
        size_t len = 0;
        enum vcs_action_field_v2 field = VCS_ACTION_FIELD_V2_NONE;
        bool ok = codec_root(&f.p, root, &bytes, &len) &&
                  memcmp(root, base_root, 32) != 0 &&
                  vcs_action_preimage_v2_first_diff(base_bytes, base_len,
                                                    bytes, len, &field) &&
                  field == g_field_rows[i].field;
        char name[96];
        (void)snprintf(name, sizeof(name),
                       "single-field change '%s' moves the root and is named",
                       vcs_action_field_v2_name(g_field_rows[i].field));
        AR_CHECK(name, ok);
        covered = covered && ok;
        free(bytes);
    }
    AR_CHECK("the field table covers every preimage field", covered);
    free(base_bytes);
}

static bool codec_roots_differ(const struct codec_fixture *a,
                               const struct codec_fixture *b)
{
    uint8_t ra[32], rb[32];
    return codec_root(&a->p, ra, NULL, NULL) &&
           codec_root(&b->p, rb, NULL, NULL) && memcmp(ra, rb, 32) != 0;
}

/* Absent is spelled as absent: an empty payload or an explicit marker,
 * never zeros, and never confused with an empty value. */
static void test_codec_empty_is_not_zero(void)
{
    struct codec_fixture a, b;
    codec_fixture_init(&a);
    codec_fixture_init(&b);
    a.p.harness.present = false;
    memset(b.p.harness.root, 0, 32);
    AR_CHECK("an empty harness root hashes apart from a zero root",
             codec_roots_differ(&a, &b));
    codec_fixture_init(&a);
    codec_fixture_init(&b);
    a.p.fixtures.present = false;
    b.p.harness.present = false;
    AR_CHECK("an absent fixtures root is not an absent harness root",
             codec_roots_differ(&a, &b));
    codec_fixture_init(&a);
    codec_fixture_init(&b);
    b.env[codec_env_at(&b, "TZ")] =
        (struct vcs_action_env_v2){ "TZ", true, "" };
    AR_CHECK("an unset allowlisted variable differs from one set empty",
             codec_roots_differ(&a, &b));
    codec_fixture_init(&a);
    codec_fixture_init(&b);
    a.p.linker = (struct vcs_action_linker_v2){ .links = false };
    AR_CHECK("a stage that does not link is its own linker spelling",
             codec_roots_differ(&a, &b));
    codec_fixture_init(&a);
    a.p.linker.collect2 = NULL;
    AR_CHECK("a driver without collect2 is its own linker spelling",
             codec_roots_differ(&a, &b));
    codec_fixture_init(&a);
    b.p.sysroot.sysroot = "@sys/opt/sysroot";
    AR_CHECK("a driver sysroot differs from none", codec_roots_differ(&a, &b));
}

static void refuse_env_order(struct codec_fixture *f)
{
    struct vcs_action_env_v2 t = f->env[0];
    f->env[0] = f->env[1];
    f->env[1] = t;
}
static void refuse_env_dup(struct codec_fixture *f) { f->env[1] = f->env[0]; }
static void refuse_env_short(struct codec_fixture *f) { f->p.env_count--; }
static void refuse_env_name(struct codec_fixture *f)
{
    f->env[0].name = "HOME";
}
static void refuse_env_value(struct codec_fixture *f)
{
    f->env[codec_env_at(f, "CPATH")] =
        (struct vcs_action_env_v2){ "CPATH", true, "/srv/host-a/inc" };
}
static void refuse_argv_abs(struct codec_fixture *f)
{
    f->argv[1] = "-I/srv/host-a/include";
}
static void refuse_argv_eq(struct codec_fixture *f)
{
    f->argv[1] = "-DROOT=/srv/host-a";
}
static void refuse_source_abs(struct codec_fixture *f)
{
    f->sources[0].path = "/srv/host-a/defs.h";
}
static void refuse_source_order(struct codec_fixture *f)
{
    f->sources[0].path = "src/zz.h";
}
static void refuse_source_conflict(struct codec_fixture *f)
{
    f->sources[0].path = "src/unit.c"; /* same path, another content hash */
}
static void refuse_search_dup(struct codec_fixture *f)
{
    f->search[1] = "inc_a";
}
static void refuse_includer_order(struct codec_fixture *f)
{
    f->includers[0] = "zz";
}
static void refuse_lookup_miss(struct codec_fixture *f)
{
    f->lookups[2].name = "nowhere.h";
}
static void refuse_lookup_dup(struct codec_fixture *f)
{
    f->lookups[1] = f->lookups[0];
}
static void refuse_lookup_hit_order(struct codec_fixture *f)
{
    f->lookups[2].search_prefix = 2;
}
static void refuse_present_beyond(struct codec_fixture *f)
{
    f->present[0].slot = 3; /* unit.c probes includer slots 0..2 only */
}
static void refuse_present_at_hit(struct codec_fixture *f)
{
    f->present[0].slot = 2; /* slot 2 is src, the hit itself */
}
static void refuse_producer_zero(struct codec_fixture *f)
{
    f->generated[0].producer_known = true;
}
static void refuse_abi_zero(struct codec_fixture *f) { f->p.abi_generation = 0; }
static void refuse_argc_zero(struct codec_fixture *f) { f->p.argc = 0; }
static void refuse_link_argc(struct codec_fixture *f) { f->p.linker.argc = 0; }
static void refuse_ld_abs(struct codec_fixture *f)
{
    f->p.linker.ld = "/srv/host-a/bin/ld";
}
static void refuse_sysroot_zero(struct codec_fixture *f)
{
    memset(f->p.sysroot.objects_sha3, 0, 32);
}
static void refuse_builtin_dup(struct codec_fixture *f)
{
    static const char *const dup[] = { "@sys/usr/include",
                                       "@sys/usr/include" };
    f->p.sysroot.builtin_dirs = dup;
    f->p.sysroot.builtin_dir_count = 2;
}

static void test_codec_refusals(void)
{
    static const struct {
        const char *name;
        codec_mutator mutate;
    } rows[] = {
        { "an absolute host path in argv", refuse_argv_abs },
        { "an absolute path after '='", refuse_argv_eq },
        { "an absolute source path", refuse_source_abs },
        { "an unsorted source list", refuse_source_order },
        { "one source path with two content hashes", refuse_source_conflict },
        { "a repeated search dir", refuse_search_dup },
        { "an unsorted includer list", refuse_includer_order },
        { "environment names out of allowlist order", refuse_env_order },
        { "a duplicate environment name", refuse_env_dup },
        { "an environment missing an allowlisted name", refuse_env_short },
        { "a non-allowlisted environment name", refuse_env_name },
        { "an environment value naming a host path", refuse_env_value },
        { "a lookup whose hit is not an input", refuse_lookup_miss },
        { "a repeated lookup", refuse_lookup_dup },
        { "a lookup whose hit disagrees with the search order",
          refuse_lookup_hit_order },
        { "a present slot beyond the probe sequence", refuse_present_beyond },
        { "a present entry at the hit itself", refuse_present_at_hit },
        { "a known producer with a zero action key", refuse_producer_zero },
        { "a zero ABI generation", refuse_abi_zero },
        { "an action without argv", refuse_argc_zero },
        { "a linking stage without link argv", refuse_link_argc },
        { "a linker at a host path", refuse_ld_abs },
        { "a zero sysroot object digest", refuse_sysroot_zero },
        { "a repeated builtin include dir", refuse_builtin_dup },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        struct codec_fixture f;
        codec_fixture_init(&f);
        rows[i].mutate(&f);
        char name[128];
        (void)snprintf(name, sizeof(name), "refused: %s", rows[i].name);
        AR_CHECK(name, codec_refused(&f.p));
    }
}


/* Every single-bit flip of a stored preimage is refused or re-roots. */
/* ---- v2 -> vcs_build_input_closure_v1 -------------------------------- */

static size_t closure_slot(enum vcs_action_field_v2 field)
{
    switch (field) {
    case VCS_ACTION_FIELD_V2_SOURCE: return 0;
    case VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP: return 1;
    case VCS_ACTION_FIELD_V2_GENERATED: return 2;
    case VCS_ACTION_FIELD_V2_HARNESS: return 4;
    case VCS_ACTION_FIELD_V2_POLICY: return 5;
    default: return 3; /* build graph */
    }
}

static const uint8_t *closure_at(const struct vcs_build_input_closure_v1 *c,
                                 size_t slot)
{
    const uint8_t *const at[6] = {
        c->positive_sha3, c->negative_sha3, c->generated_sha3,
        c->build_graph_sha3, c->harness_sha3, c->policy_sha3,
    };
    return at[slot];
}

static bool closure_of(const struct codec_fixture *f,
                       struct vcs_build_input_closure_v1 *c, uint8_t root[32])
{
    uint8_t v2[32], source[32];
    uint8_t *bytes = NULL;
    size_t len = 0;
    bool ok = codec_root(&f->p, v2, &bytes, &len) &&
              vcs_action_preimage_v2_input_closure(bytes, len, c, NULL, 0) &&
              vcs_build_input_closure_v1_root(c, root) &&
              vcs_action_preimage_v2_field_root(
                  bytes, len, VCS_ACTION_FIELD_V2_SOURCE, source) &&
              memcmp(source, c->positive_sha3, 32) == 0;
    free(bytes);
    return ok;
}

/* One v2 field change moves the v1 closure root and exactly its slot. */
static bool closure_row_moves(size_t row,
                              const struct vcs_build_input_closure_v1 *base,
                              const uint8_t base_root[32])
{
    struct codec_fixture f;
    struct vcs_build_input_closure_v1 c;
    uint8_t root[32];
    codec_fixture_init(&f);
    g_field_rows[row].mutate(&f);
    size_t want = closure_slot(g_field_rows[row].field);
    bool ok = closure_of(&f, &c, root) && memcmp(root, base_root, 32) != 0;
    for (size_t s = 0; ok && s < 6; s++)
        ok = (memcmp(closure_at(&c, s), closure_at(base, s), 32) != 0) ==
             (s == want);
    if (!ok)
        printf("    input closure: %s did not move exactly its slot\n",
               vcs_action_field_v2_name(g_field_rows[row].field));
    return ok;
}

static void test_codec_input_closure(void)
{
    struct codec_fixture f;
    struct vcs_build_input_closure_v1 base;
    uint8_t base_root[32];
    codec_fixture_init(&f);
    bool ok = closure_of(&f, &base, base_root);
    AR_CHECK("input closure: filled from v2 field roots and accepted by "
             "vcs_build_input_closure_v1_root", ok);
    for (size_t i = 0; ok && i < FIELD_ROWS; i++)
        ok = closure_row_moves(i, &base, base_root);
    AR_CHECK("input closure: a change in each v2 field moves the closure "
             "root and exactly its matching slot", ok);
    f.p.harness.present = false;
    ok = !closure_of(&f, &base, base_root);
    AR_CHECK("input closure: an absent harness root is refused, not filled",
             ok);
}

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


int action_root_codec_checks(void)
{
    g_failures = 0;
    test_codec_roundtrip();
    test_codec_field_roots();
    test_codec_field_table();
    test_codec_empty_is_not_zero();
    test_codec_refusals();
    test_codec_input_closure();
    test_codec_tamper();
    return g_failures;
}
