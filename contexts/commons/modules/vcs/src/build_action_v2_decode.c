/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Strict action preimage v2 decoder, roots, and field diff.
 *
 * The decoder accepts exactly the bytes build_action_v2.c would encode:
 * magic, every tag once in order, exact framing, flag bytes that are 0 or 1,
 * no trailing bytes, then the shared semantic check. Counts are bounded by
 * the bytes that remain before anything is allocated. */

#include "build_action_v2_priv.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdlib.h>
#include <string.h>

#define av2_why vcs_action_v2_set_why

struct av2_reader {
    const uint8_t *p;
    size_t len;
    size_t off;
    bool failed;
};

/* Owned storage behind a decoded view. Every list is one allocation except
 * the per-lookup present lists, which lookups[i].present owns. */
struct av2_storage {
    char *strings;
    size_t strings_used;
    size_t strings_cap;
    struct vcs_action_input_v2 *sources;
    struct vcs_action_generated_v2 *generated;
    const char **search_dirs;
    const char **includer_dirs;
    struct vcs_action_lookup_v2 *lookups;
    size_t lookup_count;
    const char **builtin_dirs;
    const char **link_argv;
    const char **argv;
    struct vcs_action_env_v2 *env;
    struct vcs_action_abi_v2 *abi;
};

static bool av2_take(struct av2_reader *r, void *dst, size_t n)
{
    if (r->failed || n > r->len - r->off) {
        r->failed = true;
        return false;
    }
    if (dst)
        memcpy(dst, r->p + r->off, n);
    r->off += n;
    return true;
}

static uint32_t av2_get_u32(struct av2_reader *r)
{
    uint8_t le[4] = {0};
    if (!av2_take(r, le, sizeof(le)))
        return 0;
    return (uint32_t)le[0] | ((uint32_t)le[1] << 8) |
           ((uint32_t)le[2] << 16) | ((uint32_t)le[3] << 24);
}

static uint8_t av2_get_u8(struct av2_reader *r)
{
    uint8_t v = 0;
    (void)av2_take(r, &v, 1);
    return v;
}

/* A flag byte: exactly 0 or 1. */
static bool av2_get_flag(struct av2_reader *r)
{
    uint8_t v = av2_get_u8(r);
    if (v > 1)
        r->failed = true;
    return v == 1;
}

static const char *av2_get_text_any(struct av2_reader *r,
                                    struct av2_storage *s, bool allow_empty)
{
    uint32_t n = av2_get_u32(r);
    if (r->failed || (n == 0 && !allow_empty) ||
        n >= VCS_ACTION_PREIMAGE_V2_MAX_TEXT || n > r->len - r->off ||
        s->strings_cap - s->strings_used < n + 1u ||
        memchr(r->p + r->off, 0, n) != NULL) {
        r->failed = true;
        return NULL;
    }
    char *dst = s->strings + s->strings_used;
    (void)av2_take(r, dst, n);
    dst[n] = '\0';
    s->strings_used += n + 1u;
    return dst;
}

static const char *av2_get_text(struct av2_reader *r, struct av2_storage *s)
{
    return av2_get_text_any(r, s, false);
}

/* Every item costs at least `min_item` wire bytes, so a count larger than
 * the remaining payload allows is refused before anything is allocated. */
static void *av2_get_array(struct av2_reader *r, size_t *count,
                           size_t elem, size_t min_item)
{
    uint32_t n = av2_get_u32(r);
    *count = 0;
    if (r->failed || n > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS ||
        (size_t)n > (r->len - r->off) / min_item) {
        r->failed = true;
        return NULL;
    }
    *count = n;
    if (n == 0)
        return NULL;
    void *v = zcl_calloc(n, elem, "action preimage decoded list");
    if (!v)
        r->failed = true;
    return v;
}

static const char **av2_get_texts(struct av2_reader *r,
                                  struct av2_storage *s, size_t *count)
{
    const char **v = av2_get_array(r, count, sizeof(*v), 5);
    for (size_t i = 0; v && i < *count; i++)
        v[i] = av2_get_text(r, s);
    return v;
}

/* ---- per-field readers -------------------------------------------------- */

typedef void (*av2_field_reader)(struct av2_reader *r, struct av2_storage *s,
                                 struct vcs_action_preimage_v2 *v);

static void av2_get_stage(struct av2_reader *r, struct av2_storage *s,
                          struct vcs_action_preimage_v2 *v)
{
    v->stage_kind = av2_get_text(r, s);
    v->stage_version = av2_get_u32(r);
}

static void av2_get_sources(struct av2_reader *r, struct av2_storage *s,
                            struct vcs_action_preimage_v2 *v)
{
    s->sources = av2_get_array(r, &v->source_count, sizeof(*s->sources),
                               5 + 32);
    for (size_t i = 0; s->sources && i < v->source_count; i++) {
        s->sources[i].path = av2_get_text(r, s);
        (void)av2_take(r, s->sources[i].sha3, 32);
    }
    v->sources = s->sources;
}

static void av2_get_generated(struct av2_reader *r, struct av2_storage *s,
                              struct vcs_action_preimage_v2 *v)
{
    s->generated = av2_get_array(r, &v->generated_count,
                                 sizeof(*s->generated), 5 + 32 + 1);
    for (size_t i = 0; s->generated && i < v->generated_count; i++) {
        struct vcs_action_generated_v2 *g = &s->generated[i];
        g->path = av2_get_text(r, s);
        (void)av2_take(r, g->sha3, 32);
        g->producer_known = av2_get_flag(r);
        if (g->producer_known)
            (void)av2_take(r, g->producer_action_key, 32);
    }
    v->generated = s->generated;
}

static void av2_get_lookup(struct av2_reader *r, struct av2_storage *s,
                           struct vcs_action_lookup_v2 *l)
{
    l->name = av2_get_text(r, s);
    l->hit_dir = av2_get_text(r, s);
    l->search_prefix = av2_get_u32(r);
    struct vcs_action_present_v2 *p =
        av2_get_array(r, &l->present_count, sizeof(*p), 5);
    for (size_t j = 0; p && j < l->present_count; j++) {
        p[j].slot = av2_get_u32(r);
        p[j].kind = av2_get_u8(r);
        if (p[j].kind == VCS_ACTION_PRESENT_V2_REGULAR)
            (void)av2_take(r, p[j].sha3, 32);
    }
    l->present = p;
}

static void av2_get_negative(struct av2_reader *r, struct av2_storage *s,
                             struct vcs_action_preimage_v2 *v)
{
    s->search_dirs = av2_get_texts(r, s, &v->search_dir_count);
    s->includer_dirs = av2_get_texts(r, s, &v->includer_dir_count);
    s->lookups = av2_get_array(r, &v->lookup_count, sizeof(*s->lookups), 18);
    s->lookup_count = s->lookups ? v->lookup_count : 0;
    for (size_t i = 0; s->lookups && i < v->lookup_count; i++)
        av2_get_lookup(r, s, &s->lookups[i]);
    v->search_dirs = s->search_dirs;
    v->includer_dirs = s->includer_dirs;
    v->lookups = s->lookups;
}

static void av2_get_toolchain(struct av2_reader *r, struct av2_storage *s,
                              struct vcs_action_preimage_v2 *v)
{
    (void)s;
    (void)av2_take(r, v->toolchain_root, 32);
}

static void av2_get_sysroot(struct av2_reader *r, struct av2_storage *s,
                            struct vcs_action_preimage_v2 *v)
{
    struct vcs_action_sysroot_v2 *out = &v->sysroot;
    out->sysroot = av2_get_flag(r) ? av2_get_text(r, s) : NULL;
    s->builtin_dirs = av2_get_texts(r, s, &out->builtin_dir_count);
    out->builtin_dirs = s->builtin_dirs;
    (void)av2_take(r, out->objects_sha3, 32);
}

static void av2_get_linker(struct av2_reader *r, struct av2_storage *s,
                           struct vcs_action_preimage_v2 *v)
{
    struct vcs_action_linker_v2 *l = &v->linker;
    l->links = r->len > 0;
    if (!l->links)
        return;
    l->ld = av2_get_text(r, s);
    (void)av2_take(r, l->ld_sha3, 32);
    if (av2_get_flag(r)) {
        l->collect2 = av2_get_text(r, s);
        (void)av2_take(r, l->collect2_sha3, 32);
    }
    s->link_argv = av2_get_texts(r, s, &l->argc);
    l->argv = s->link_argv;
}

static void av2_get_flags(struct av2_reader *r, struct av2_storage *s,
                          struct vcs_action_preimage_v2 *v)
{
    v->argv = s->argv = av2_get_texts(r, s, &v->argc);
}

static void av2_get_env(struct av2_reader *r, struct av2_storage *s,
                        struct vcs_action_preimage_v2 *v)
{
    s->env = av2_get_array(r, &v->env_count, sizeof(*s->env), 5 + 1);
    for (size_t i = 0; s->env && i < v->env_count; i++) {
        s->env[i].name = av2_get_text(r, s);
        s->env[i].set = av2_get_flag(r);
        if (s->env[i].set)
            s->env[i].value = av2_get_text_any(r, s, true);
    }
    v->env = s->env;
}

static void av2_get_abi(struct av2_reader *r, struct av2_storage *s,
                        struct vcs_action_preimage_v2 *v)
{
    v->abi_generation = av2_get_u32(r);
    s->abi = av2_get_array(r, &v->abi_count, sizeof(*s->abi), 9);
    for (size_t i = 0; s->abi && i < v->abi_count; i++) {
        s->abi[i].name = av2_get_text(r, s);
        s->abi[i].version = av2_get_u32(r);
    }
    v->abi = s->abi;
}

static void av2_get_ref(struct av2_reader *r,
                        struct vcs_action_root_ref_v2 *ref)
{
    ref->present = r->len == 32;
    if (r->len != 0 && r->len != 32)
        r->failed = true;
    else if (ref->present)
        (void)av2_take(r, ref->root, 32);
}

static void av2_get_harness(struct av2_reader *r, struct av2_storage *s,
                            struct vcs_action_preimage_v2 *v)
{
    (void)s;
    av2_get_ref(r, &v->harness);
}

static void av2_get_fixtures(struct av2_reader *r, struct av2_storage *s,
                             struct vcs_action_preimage_v2 *v)
{
    (void)s;
    av2_get_ref(r, &v->fixtures);
}

static void av2_get_policy(struct av2_reader *r, struct av2_storage *s,
                           struct vcs_action_preimage_v2 *v)
{
    (void)s;
    av2_get_ref(r, &v->policy);
}

static const av2_field_reader g_readers[VCS_ACTION_FIELD_V2_COUNT] = {
    [VCS_ACTION_FIELD_V2_STAGE] = av2_get_stage,
    [VCS_ACTION_FIELD_V2_SOURCE] = av2_get_sources,
    [VCS_ACTION_FIELD_V2_GENERATED] = av2_get_generated,
    [VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP] = av2_get_negative,
    [VCS_ACTION_FIELD_V2_TOOLCHAIN] = av2_get_toolchain,
    [VCS_ACTION_FIELD_V2_SYSROOT] = av2_get_sysroot,
    [VCS_ACTION_FIELD_V2_LINKER] = av2_get_linker,
    [VCS_ACTION_FIELD_V2_FLAGS] = av2_get_flags,
    [VCS_ACTION_FIELD_V2_ENV] = av2_get_env,
    [VCS_ACTION_FIELD_V2_ABI] = av2_get_abi,
    [VCS_ACTION_FIELD_V2_HARNESS] = av2_get_harness,
    [VCS_ACTION_FIELD_V2_FIXTURES] = av2_get_fixtures,
    [VCS_ACTION_FIELD_V2_POLICY] = av2_get_policy,
};

/* ---- framing ------------------------------------------------------------ */

/* Locate every field payload; checks magic, tag order and exact framing. */
static bool av2_spans(const uint8_t *bytes, size_t len,
                      size_t off[VCS_ACTION_FIELD_V2_COUNT],
                      size_t plen[VCS_ACTION_FIELD_V2_COUNT])
{
    if (!bytes || len < AV2_MAGIC_LEN ||
        len > VCS_ACTION_PREIMAGE_V2_MAX_BYTES ||
        memcmp(bytes, VCS_ACTION_PREIMAGE_V2_MAGIC, AV2_MAGIC_LEN) != 0)
        return false;
    struct av2_reader r = { bytes, len, AV2_MAGIC_LEN, false };
    for (int f = VCS_ACTION_FIELD_V2_STAGE; f < VCS_ACTION_FIELD_V2_COUNT;
         f++) {
        uint8_t tag = av2_get_u8(&r);
        uint32_t n = av2_get_u32(&r);
        if (r.failed || tag != (uint8_t)f || n > len - r.off)
            return false;
        off[f] = r.off;
        plen[f] = n;
        r.off += n;
    }
    return r.off == len;
}

static void av2_storage_free(struct av2_storage *s)
{
    if (!s)
        return;
    for (size_t i = 0; i < s->lookup_count; i++)
        free((void *)s->lookups[i].present);
    free(s->strings);
    free(s->sources);
    free(s->generated);
    free(s->search_dirs);
    free(s->includer_dirs);
    free(s->lookups);
    free(s->builtin_dirs);
    free(s->link_argv);
    free(s->argv);
    free(s->env);
    free(s->abi);
    free(s);
}

void vcs_action_preimage_v2_decoded_free(
    struct vcs_action_preimage_v2_decoded *decoded)
{
    if (!decoded)
        return;
    av2_storage_free(decoded->storage);
    memset(decoded, 0, sizeof(*decoded));
}

static bool av2_parse_fields(const uint8_t *bytes,
                             const size_t off[VCS_ACTION_FIELD_V2_COUNT],
                             const size_t plen[VCS_ACTION_FIELD_V2_COUNT],
                             struct av2_storage *s,
                             struct vcs_action_preimage_v2 *v)
{
    for (int f = VCS_ACTION_FIELD_V2_STAGE; f < VCS_ACTION_FIELD_V2_COUNT;
         f++) {
        struct av2_reader r = { bytes + off[f], plen[f], 0, false };
        g_readers[f](&r, s, v);
        if (r.failed || r.off != r.len)
            return false;
    }
    return true;
}

bool vcs_action_preimage_v2_decode(
    const uint8_t *bytes, size_t len,
    struct vcs_action_preimage_v2_decoded *out, char *why, size_t why_len)
{
    size_t off[VCS_ACTION_FIELD_V2_COUNT] = {0};
    size_t plen[VCS_ACTION_FIELD_V2_COUNT] = {0};
    if (!out) {
        av2_why(why, why_len, "decode output is missing", NULL);
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!av2_spans(bytes, len, off, plen)) {
        av2_why(why, why_len, "preimage framing is invalid", NULL);
        return false;
    }
    struct av2_storage *s = zcl_calloc(1, sizeof(*s), "action preimage");
    char *strings = s ? zcl_malloc(len + 1u, "action preimage strings")
                      : NULL;
    if (!s || !strings) {
        free(s);
        av2_why(why, why_len, "preimage decode allocation failed", NULL);
        return false;
    }
    s->strings = strings;
    s->strings_cap = len + 1u;
    out->storage = s;
    if (!av2_parse_fields(bytes, off, plen, s, &out->view)) {
        vcs_action_preimage_v2_decoded_free(out);
        av2_why(why, why_len, "preimage field payload is invalid", NULL);
        return false;
    }
    if (!vcs_action_preimage_v2_check(&out->view, why, why_len)) {
        vcs_action_preimage_v2_decoded_free(out);
        return false;
    }
    return true;
}

/* ---- roots -------------------------------------------------------------- */

static bool av2_valid(const uint8_t *bytes, size_t len, char *why,
                      size_t why_len)
{
    struct vcs_action_preimage_v2_decoded decoded;
    if (!vcs_action_preimage_v2_decode(bytes, len, &decoded, why, why_len))
        return false;
    vcs_action_preimage_v2_decoded_free(&decoded);
    return true;
}

bool vcs_action_root_v2_from_bytes(const uint8_t *bytes, size_t len,
                                   uint8_t out[32], char *why, size_t why_len)
{
    if (!out || !av2_valid(bytes, len, why, why_len))
        return false;
    static const char domain[] = VCS_ACTION_ROOT_V2_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, bytes, len);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_action_preimage_v2_field_root(const uint8_t *bytes, size_t len,
                                       enum vcs_action_field_v2 field,
                                       uint8_t out[32])
{
    size_t off[VCS_ACTION_FIELD_V2_COUNT] = {0};
    size_t plen[VCS_ACTION_FIELD_V2_COUNT] = {0};
    if (!out || field <= VCS_ACTION_FIELD_V2_NONE ||
        field >= VCS_ACTION_FIELD_V2_COUNT || !av2_valid(bytes, len, NULL, 0) ||
        !av2_spans(bytes, len, off, plen))
        return false;
    static const char domain[] = VCS_ACTION_FIELD_ROOT_V2_DOMAIN;
    uint8_t tag = (uint8_t)field;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, &tag, 1);
    sha3_256_write(&sha, bytes + off[field], plen[field]);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_action_preimage_v2_first_diff(const uint8_t *a, size_t a_len,
                                       const uint8_t *b, size_t b_len,
                                       enum vcs_action_field_v2 *out)
{
    size_t aoff[VCS_ACTION_FIELD_V2_COUNT] = {0};
    size_t alen[VCS_ACTION_FIELD_V2_COUNT] = {0};
    size_t boff[VCS_ACTION_FIELD_V2_COUNT] = {0};
    size_t blen[VCS_ACTION_FIELD_V2_COUNT] = {0};
    if (!out || !av2_valid(a, a_len, NULL, 0) ||
        !av2_valid(b, b_len, NULL, 0) || !av2_spans(a, a_len, aoff, alen) ||
        !av2_spans(b, b_len, boff, blen))
        return false;
    *out = VCS_ACTION_FIELD_V2_NONE;
    for (int f = VCS_ACTION_FIELD_V2_STAGE; f < VCS_ACTION_FIELD_V2_COUNT;
         f++) {
        if (alen[f] != blen[f] ||
            memcmp(a + aoff[f], b + boff[f], alen[f]) != 0) {
            *out = (enum vcs_action_field_v2)f;
            return true;
        }
    }
    return true;
}
