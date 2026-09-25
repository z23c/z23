/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical action preimage v2: token rules, validation, encoder.
 *
 * The wire and its rules are documented in vcs/build_action.h. One rule set
 * (vcs_action_preimage_v2_check) serves both directions: the encoder here
 * refuses what the decoder (build_action_v2_decode.c) would refuse, so
 * every accepted byte string has exactly one spelling and a receiver that
 * re-derives the root from stored bytes gets the root the producer
 * published, or a refusal. */

#include "build_action_v2_priv.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vcs_action_v2_set_why(char *why, size_t why_len, const char *what,
                           const char *detail)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s%s%.160s", what,
                       detail ? ": " : "", detail ? detail : "");
}

#define av2_why vcs_action_v2_set_why

const char *vcs_action_field_v2_name(enum vcs_action_field_v2 field)
{
    static const char *const names[VCS_ACTION_FIELD_V2_COUNT] = {
        NULL, "stage", "source", "generated", "negative_lookup",
        "toolchain", "sysroot", "linker", "flags", "env", "abi", "harness",
        "fixtures", "policy",
    };
    return (unsigned)field < VCS_ACTION_FIELD_V2_COUNT ? names[field] : NULL;
}

/* ---- canonical token rules -------------------------------------------- */

static bool av2_segment_ok(const char *seg, size_t n, bool allow_dotdot)
{
    if (n == 0 || (n == 1 && seg[0] == '.'))
        return false;
    if (n == 2 && seg[0] == '.' && seg[1] == '.')
        return allow_dotdot;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)seg[i];
        if (c < 0x21 || c > 0x7e || c == '\\')
            return false;
    }
    return true;
}

static bool av2_segments_ok(const char *p, bool allow_dotdot)
{
    if (!p || !p[0])
        return false;
    for (;;) {
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if (!av2_segment_ok(p, n, allow_dotdot))
            return false;
        if (!slash)
            return true;
        p = slash + 1;
    }
}

/* "C:" or "c:" leading a relative spelling is a drive-absolute path. */
static bool av2_drive_prefix(const char *p)
{
    return ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
           p[1] == ':';
}

bool vcs_action_v2_path_canonical(const char *path, bool allow_dot)
{
    if (!path || !path[0] ||
        strnlen(path, VCS_ACTION_PREIMAGE_V2_MAX_TEXT) >=
            VCS_ACTION_PREIMAGE_V2_MAX_TEXT)
        return false;
    if (strcmp(path, ".") == 0)
        return allow_dot;
    if (strncmp(path, "@sys/", 5) == 0)
        return av2_segments_ok(path + 5, false);
    if (path[0] == '@' || path[0] == '/' || path[0] == '~' ||
        av2_drive_prefix(path))
        return false;
    return av2_segments_ok(path, false);
}

bool vcs_action_v2_name_canonical(const char *name)
{
    if (!name || !name[0] ||
        strnlen(name, VCS_ACTION_PREIMAGE_V2_MAX_TEXT) >=
            VCS_ACTION_PREIMAGE_V2_MAX_TEXT ||
        name[0] == '@' || name[0] == '/' || name[0] == '~' ||
        av2_drive_prefix(name))
        return false;
    return av2_segments_ok(name, true);
}

/* Option spellings whose value may be glued to the option: "-I/usr". */
static bool av2_option_word(const char *s, size_t n)
{
    static const char *const words[] = {
        "I", "L", "B", "F", "o", "iquote", "isystem", "idirafter",
        "include", "imacros", "iprefix", "isysroot", "iwithprefix",
        "iwithprefixbefore", "MF", "MT", "MQ",
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        if (strlen(words[i]) == n && memcmp(words[i], s, n) == 0)
            return true;
    return false;
}

static bool av2_virtual_root_at(const char *s)
{
    static const char *const roots[] = { VCS_ACTION_V2_VIRTUAL_ROOTS };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        size_t n = strlen(roots[i]);
        if (strncmp(s, roots[i], n) == 0 &&
            (s[n] == '\0' || strchr("/=,:; ", s[n]) != NULL))
            return true;
    }
    return false;
}

bool vcs_action_v2_path_boundary(const char *s, size_t i)
{
    return s && (i == 0 || strchr("=,:;\"' ", s[i - 1]) != NULL ||
                 (s[0] == '-' && i > 1 && av2_option_word(s + 1, i - 1)));
}

/* True when an absolute or home-relative host path starts at s[i]. */
static bool av2_absolute_at(const char *s, size_t i)
{
    if (!vcs_action_v2_path_boundary(s, i))
        return false;
    if (s[i] == '~')
        return s[i + 1] == '/' || s[i + 1] == '\0';
    return s[i] == '/' && !av2_virtual_root_at(s + i);
}

bool vcs_action_v2_text_canonical(const char *text)
{
    size_t n = text ? strnlen(text, VCS_ACTION_PREIMAGE_V2_MAX_TEXT) : 0;
    if (n == 0 || n >= VCS_ACTION_PREIMAGE_V2_MAX_TEXT)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c < 0x20 || c > 0x7e || c == '\\' || av2_absolute_at(text, i))
            return false;
    }
    return true;
}

/* Variables a C driver consults while compiling and linking one unit, in
 * strict byte order. PATH and HOME are deliberately absent: the compiler
 * and linker identities are content digests, not whichever directory PATH
 * happened to name. */
static const char *const g_env_allow[] = {
    "COMPILER_PATH", "CPATH", "C_INCLUDE_PATH", "GCC_EXEC_PREFIX",
    "GCC_SPECS", "LANG", "LC_ALL", "LC_CTYPE", "MACOSX_DEPLOYMENT_TARGET",
    "SDKROOT", "SOURCE_DATE_EPOCH", "TZ",
};
#define AV2_ENV_ALLOW_COUNT (sizeof(g_env_allow) / sizeof(g_env_allow[0]))

const char *const *vcs_action_v2_env_allowlist(size_t *count)
{
    if (count)
        *count = AV2_ENV_ALLOW_COUNT;
    return g_env_allow;
}

bool vcs_action_v2_env_allowlisted(const char *name, size_t name_len)
{
    for (size_t i = 0; name && i < AV2_ENV_ALLOW_COUNT; i++)
        if (strlen(g_env_allow[i]) == name_len &&
            memcmp(g_env_allow[i], name, name_len) == 0)
            return true;
    return false;
}

static bool av2_word_ok(const char *w, bool allow_dot)
{
    if (!w || !w[0] || strnlen(w, 256) >= 256)
        return false;
    for (const char *c = w; *c; c++) {
        bool ok = (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') ||
                  *c == '_' || (allow_dot && (*c == '.' || *c == '-'));
        if (!ok)
            return false;
    }
    return true;
}

static bool av2_nonzero(const uint8_t digest[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= digest[i];
    return acc != 0;
}

static bool av2_list_ok(const void *v, size_t n, size_t max,
                        const char *label, char *why, size_t why_len)
{
    if (n > max || (n && !v)) {
        av2_why(why, why_len, "list out of bounds", label);
        return false;
    }
    return true;
}

/* ---- semantic validation (shared by encode and decode) ---------------- */

static bool av2_sources_ok(const struct vcs_action_preimage_v2 *in,
                           char *why, size_t why_len)
{
    if (!av2_list_ok(in->sources, in->source_count,
                     VCS_ACTION_PREIMAGE_V2_MAX_ITEMS, "source", why,
                     why_len))
        return false;
    for (size_t i = 0; i < in->source_count; i++) {
        const char *p = in->sources[i].path;
        if (!vcs_action_v2_path_canonical(p, false) ||
            (i && strcmp(in->sources[i - 1].path, p) >= 0)) {
            av2_why(why, why_len,
                    "source not canonical or not strictly sorted", p);
            return false;
        }
    }
    return true;
}

static bool av2_generated_ok(const struct vcs_action_preimage_v2 *in,
                             char *why, size_t why_len)
{
    if (!av2_list_ok(in->generated, in->generated_count,
                     VCS_ACTION_PREIMAGE_V2_MAX_ITEMS, "generated", why,
                     why_len))
        return false;
    for (size_t i = 0; i < in->generated_count; i++) {
        const struct vcs_action_generated_v2 *g = &in->generated[i];
        if (!vcs_action_v2_path_canonical(g->path, false) ||
            (i && strcmp(in->generated[i - 1].path, g->path) >= 0) ||
            (g->producer_known && !av2_nonzero(g->producer_action_key))) {
            av2_why(why, why_len,
                    "generated input not canonical or not strictly sorted",
                    g->path);
            return false;
        }
    }
    size_t i = 0, j = 0;
    while (i < in->source_count && j < in->generated_count) {
        int c = strcmp(in->sources[i].path, in->generated[j].path);
        if (c == 0) {
            av2_why(why, why_len, "path is both source and generated",
                    in->sources[i].path);
            return false;
        }
        if (c < 0) i++; else j++;
    }
    return true;
}

static int av2_str_ptr_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* An ordered dir list whose order is semantic: every entry canonical and
 * no entry repeated (a sorted copy proves uniqueness). */
static bool av2_ordered_dirs_ok(const char *const *v, size_t n,
                                const char *label, char *why, size_t why_len)
{
    if (!av2_list_ok(v, n, VCS_ACTION_PREIMAGE_V2_MAX_ITEMS, label, why,
                     why_len))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!vcs_action_v2_path_canonical(v[i], true)) {
            av2_why(why, why_len, "dir is not canonical", v[i]);
            return false;
        }
    if (n < 2)
        return true;
    const char **sorted = zcl_malloc(sizeof(char *) * n, "action dir index");
    if (!sorted) {
        av2_why(why, why_len, "dir index allocation failed", label);
        return false;
    }
    memcpy(sorted, v, sizeof(char *) * n);
    qsort(sorted, n, sizeof(char *), av2_str_ptr_cmp);
    bool ok = true;
    for (size_t i = 1; ok && i < n; i++)
        ok = strcmp(sorted[i - 1], sorted[i]) != 0;
    if (!ok)
        av2_why(why, why_len, "dir repeated in an ordered list", label);
    free(sorted);
    return ok;
}

static bool av2_sorted_dirs_ok(const char *const *v, size_t n,
                               const char *label, char *why, size_t why_len)
{
    if (!av2_list_ok(v, n, VCS_ACTION_PREIMAGE_V2_MAX_ITEMS, label, why,
                     why_len))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!vcs_action_v2_path_canonical(v[i], true) ||
            (i && strcmp(v[i - 1], v[i]) >= 0)) {
            av2_why(why, why_len, "dir not canonical or not strictly sorted",
                    v[i]);
            return false;
        }
    return true;
}

/* Index of key in a strictly sorted list, or -1. */
static long av2_sorted_find(const char *const *v, size_t n, const char *key)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(v[mid], key);
        if (c == 0) return (long)mid;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -1;
}

static bool av2_input_named(const struct vcs_action_preimage_v2 *in,
                            const char *path)
{
    size_t lo = 0, hi = in->source_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(in->sources[mid].path, path);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    lo = 0;
    hi = in->generated_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(in->generated[mid].path, path);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return false;
}

/* The lookup names a real input and its hit agrees with the search order,
 * or it is a conditional lookup (hit_dir "") over the whole search order. */
static bool av2_lookup_hit_ok(const struct vcs_action_preimage_v2 *in,
                              const struct vcs_action_lookup_v2 *l,
                              long *hit_includer)
{
    char joined[VCS_ACTION_PREIMAGE_V2_MAX_TEXT];
    if (l->hit_dir && !l->hit_dir[0]) {
        /* Conditional lookup: no hit, every search dir is probed. */
        *hit_includer = -1;
        return vcs_action_v2_name_canonical(l->name) &&
               l->search_prefix == in->search_dir_count;
    }
    if (!vcs_action_v2_name_canonical(l->name) ||
        !vcs_action_v2_path_canonical(l->hit_dir, true) ||
        l->search_prefix > in->search_dir_count)
        return false;
    bool dot = strcmp(l->hit_dir, ".") == 0;
    int n = snprintf(joined, sizeof(joined), "%s%s%s", dot ? "" : l->hit_dir,
                     dot ? "" : "/", l->name);
    if (n <= 0 || n >= (int)sizeof(joined) || !av2_input_named(in, joined))
        return false;
    *hit_includer = av2_sorted_find(in->includer_dirs, in->includer_dir_count,
                                    l->hit_dir);
    bool search_hit = l->search_prefix < in->search_dir_count &&
                      strcmp(in->search_dirs[l->search_prefix],
                             l->hit_dir) == 0;
    return search_hit || (l->search_prefix == 0 && *hit_includer >= 0);
}

static bool av2_lookup_ok(const struct vcs_action_preimage_v2 *in,
                          const struct vcs_action_lookup_v2 *l)
{
    long hit_includer = -1;
    if (!av2_lookup_hit_ok(in, l, &hit_includer) ||
        l->present_count > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS ||
        (l->present_count && !l->present))
        return false;
    size_t slots = in->includer_dir_count + l->search_prefix;
    for (size_t i = 0; i < l->present_count; i++) {
        const struct vcs_action_present_v2 *p = &l->present[i];
        bool kind_ok = p->kind == VCS_ACTION_PRESENT_V2_REGULAR ||
                       p->kind == VCS_ACTION_PRESENT_V2_OTHER;
        if (!kind_ok || p->slot >= slots ||
            (long)p->slot == hit_includer ||
            (i && l->present[i - 1].slot >= p->slot))
            return false;
    }
    return true;
}

static int av2_lookup_cmp(const void *a, const void *b)
{
    const struct vcs_action_lookup_v2 *x = *(const void *const *)a;
    const struct vcs_action_lookup_v2 *y = *(const void *const *)b;
    int c = strcmp(x->hit_dir, y->hit_dir);
    return c ? c : strcmp(x->name, y->name);
}

static bool av2_lookups_unique(const struct vcs_action_preimage_v2 *in,
                               char *why, size_t why_len)
{
    size_t n = in->lookup_count;
    if (n < 2)
        return true;
    const struct vcs_action_lookup_v2 **v =
        zcl_malloc(sizeof(*v) * n, "action lookup index");
    if (!v) {
        av2_why(why, why_len, "lookup index allocation failed", NULL);
        return false;
    }
    for (size_t i = 0; i < n; i++)
        v[i] = &in->lookups[i];
    qsort(v, n, sizeof(*v), av2_lookup_cmp);
    bool ok = true;
    for (size_t i = 1; ok && i < n; i++)
        ok = av2_lookup_cmp(&v[i - 1], &v[i]) != 0;
    if (!ok)
        av2_why(why, why_len, "include lookup repeated", NULL);
    free(v);
    return ok;
}

static bool av2_negative_ok(const struct vcs_action_preimage_v2 *in,
                            char *why, size_t why_len)
{
    if (!av2_ordered_dirs_ok(in->search_dirs, in->search_dir_count,
                             "search dirs", why, why_len) ||
        !av2_sorted_dirs_ok(in->includer_dirs, in->includer_dir_count,
                            "includer dirs", why, why_len) ||
        !av2_list_ok(in->lookups, in->lookup_count,
                     VCS_ACTION_PREIMAGE_V2_MAX_ITEMS, "lookups", why,
                     why_len))
        return false;
    for (size_t i = 0; i < in->lookup_count; i++)
        if (!av2_lookup_ok(in, &in->lookups[i])) {
            av2_why(why, why_len, "include lookup is not canonical",
                    in->lookups[i].name);
            return false;
        }
    return av2_lookups_unique(in, why, why_len);
}

static bool av2_texts_ok(const char *const *v, size_t n, const char *label,
                         char *why, size_t why_len)
{
    if (!av2_list_ok(v, n, VCS_ACTION_PREIMAGE_V2_MAX_ITEMS, label, why,
                     why_len))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!vcs_action_v2_text_canonical(v[i])) {
            av2_why(why, why_len, "argument is not canonical", v[i]);
            return false;
        }
    return true;
}

static bool av2_sysroot_ok(const struct vcs_action_sysroot_v2 *s,
                           char *why, size_t why_len)
{
    if (s->sysroot && !vcs_action_v2_path_canonical(s->sysroot, false)) {
        av2_why(why, why_len, "sysroot is not canonical", s->sysroot);
        return false;
    }
    if (!av2_nonzero(s->objects_sha3)) {
        av2_why(why, why_len, "sysroot object digest is absent", NULL);
        return false;
    }
    return av2_ordered_dirs_ok(s->builtin_dirs, s->builtin_dir_count,
                               "builtin include dirs", why, why_len);
}

static bool av2_linker_ok(const struct vcs_action_linker_v2 *l,
                          char *why, size_t why_len)
{
    if (!l->links)
        return true;
    if (!vcs_action_v2_path_canonical(l->ld, false) ||
        (l->collect2 && !vcs_action_v2_path_canonical(l->collect2, false)) ||
        l->argc == 0) {
        av2_why(why, why_len, "linker is not canonical",
                l->ld ? l->ld : "(null)");
        return false;
    }
    return av2_texts_ok(l->argv, l->argc, "link argv", why, why_len);
}

static bool av2_env_ok(const struct vcs_action_preimage_v2 *in,
                       char *why, size_t why_len)
{
    if (in->env_count != AV2_ENV_ALLOW_COUNT || !in->env) {
        av2_why(why, why_len, "environment does not name the allowlist",
                NULL);
        return false;
    }
    for (size_t i = 0; i < AV2_ENV_ALLOW_COUNT; i++) {
        const struct vcs_action_env_v2 *e = &in->env[i];
        bool ok = e->name && strcmp(e->name, g_env_allow[i]) == 0 &&
                  (!e->set || (e->value && (e->value[0] == '\0' ||
                               vcs_action_v2_text_canonical(e->value))));
        if (!ok) {
            av2_why(why, why_len, "environment entry is not canonical",
                    e->name ? e->name : g_env_allow[i]);
            return false;
        }
    }
    return true;
}

static bool av2_abi_ok(const struct vcs_action_preimage_v2 *in,
                       char *why, size_t why_len)
{
    if (in->abi_generation == 0 ||
        !av2_list_ok(in->abi, in->abi_count, 256, "abi", why, why_len)) {
        av2_why(why, why_len, "abi generation is absent", NULL);
        return false;
    }
    for (size_t i = 0; i < in->abi_count; i++) {
        const struct vcs_action_abi_v2 *a = &in->abi[i];
        if (!av2_word_ok(a->name, false) || a->version == 0 ||
            (i && strcmp(in->abi[i - 1].name, a->name) >= 0)) {
            av2_why(why, why_len, "abi entry is not canonical", a->name);
            return false;
        }
    }
    return true;
}

bool vcs_action_preimage_v2_check(const struct vcs_action_preimage_v2 *in,
                                  char *why, size_t why_len)
{
    if (!in || !av2_word_ok(in->stage_kind, true) || in->stage_version == 0) {
        av2_why(why, why_len, "stage kind/version is not canonical", NULL);
        return false;
    }
    if (!av2_nonzero(in->toolchain_root) || in->argc == 0) {
        av2_why(why, why_len, "toolchain root or argv is absent", NULL);
        return false;
    }
    return av2_sources_ok(in, why, why_len) &&
           av2_generated_ok(in, why, why_len) &&
           av2_negative_ok(in, why, why_len) &&
           av2_sysroot_ok(&in->sysroot, why, why_len) &&
           av2_linker_ok(&in->linker, why, why_len) &&
           av2_texts_ok(in->argv, in->argc, "argv", why, why_len) &&
           av2_env_ok(in, why, why_len) && av2_abi_ok(in, why, why_len);
}

/* ---- encoder ----------------------------------------------------------- */

struct av2_buf {
    uint8_t *data;
    size_t len;
    size_t cap;
    bool failed;
};

static void av2_put(struct av2_buf *b, const void *p, size_t n)
{
    if (b->failed || n == 0)
        return;
    if (n > VCS_ACTION_PREIMAGE_V2_MAX_BYTES - b->len) {
        b->failed = true;
        return;
    }
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n)
            cap *= 2;
        uint8_t *grown = zcl_realloc(b->data, cap, "action preimage buffer");
        if (!grown) {
            b->failed = true;
            return;
        }
        b->data = grown;
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void av2_put_u32(struct av2_buf *b, uint32_t v)
{
    uint8_t le[4];
    zcl_write_u32_le(le, v);
    av2_put(b, le, sizeof(le));
}

static void av2_put_u8(struct av2_buf *b, uint8_t v)
{
    av2_put(b, &v, 1);
}

static void av2_put_text(struct av2_buf *b, const char *s)
{
    size_t n = strlen(s);
    av2_put_u32(b, (uint32_t)n);
    av2_put(b, s, n);
}

static size_t av2_field_begin(struct av2_buf *b, enum vcs_action_field_v2 f)
{
    av2_put_u8(b, (uint8_t)f);
    size_t at = b->len;
    av2_put_u32(b, 0);
    return at;
}

static void av2_field_end(struct av2_buf *b, size_t at)
{
    if (!b->failed)
        zcl_write_u32_le(b->data + at, (uint32_t)(b->len - at - 4));
}

static void av2_put_texts(struct av2_buf *b, const char *const *v, size_t n)
{
    av2_put_u32(b, (uint32_t)n);
    for (size_t i = 0; i < n; i++)
        av2_put_text(b, v[i]);
}

static void av2_put_inputs(struct av2_buf *b,
                           const struct vcs_action_preimage_v2 *in)
{
    av2_put_u32(b, (uint32_t)in->source_count);
    for (size_t i = 0; i < in->source_count; i++) {
        av2_put_text(b, in->sources[i].path);
        av2_put(b, in->sources[i].sha3, 32);
    }
}

static void av2_put_generated(struct av2_buf *b,
                              const struct vcs_action_preimage_v2 *in)
{
    av2_put_u32(b, (uint32_t)in->generated_count);
    for (size_t i = 0; i < in->generated_count; i++) {
        const struct vcs_action_generated_v2 *g = &in->generated[i];
        av2_put_text(b, g->path);
        av2_put(b, g->sha3, 32);
        av2_put_u8(b, g->producer_known ? 1 : 0);
        if (g->producer_known)
            av2_put(b, g->producer_action_key, 32);
    }
}

static void av2_put_negative(struct av2_buf *b,
                             const struct vcs_action_preimage_v2 *in)
{
    av2_put_texts(b, in->search_dirs, in->search_dir_count);
    av2_put_texts(b, in->includer_dirs, in->includer_dir_count);
    av2_put_u32(b, (uint32_t)in->lookup_count);
    for (size_t i = 0; i < in->lookup_count; i++) {
        const struct vcs_action_lookup_v2 *l = &in->lookups[i];
        av2_put_text(b, l->name);
        av2_put_text(b, l->hit_dir);
        av2_put_u32(b, l->search_prefix);
        av2_put_u32(b, (uint32_t)l->present_count);
        for (size_t j = 0; j < l->present_count; j++) {
            av2_put_u32(b, l->present[j].slot);
            av2_put_u8(b, l->present[j].kind);
            if (l->present[j].kind == VCS_ACTION_PRESENT_V2_REGULAR)
                av2_put(b, l->present[j].sha3, 32);
        }
    }
}

static void av2_put_sysroot(struct av2_buf *b,
                            const struct vcs_action_sysroot_v2 *s)
{
    av2_put_u8(b, s->sysroot ? 1 : 0);
    if (s->sysroot)
        av2_put_text(b, s->sysroot);
    av2_put_texts(b, s->builtin_dirs, s->builtin_dir_count);
    av2_put(b, s->objects_sha3, 32);
}

static void av2_put_linker(struct av2_buf *b,
                           const struct vcs_action_linker_v2 *l)
{
    if (!l->links)
        return; /* a stage that does not link: empty payload */
    av2_put_text(b, l->ld);
    av2_put(b, l->ld_sha3, 32);
    av2_put_u8(b, l->collect2 ? 1 : 0);
    if (l->collect2) {
        av2_put_text(b, l->collect2);
        av2_put(b, l->collect2_sha3, 32);
    }
    av2_put_texts(b, l->argv, l->argc);
}

static void av2_put_env(struct av2_buf *b,
                        const struct vcs_action_preimage_v2 *in)
{
    av2_put_u32(b, (uint32_t)in->env_count);
    for (size_t i = 0; i < in->env_count; i++) {
        av2_put_text(b, in->env[i].name);
        av2_put_u8(b, in->env[i].set ? 1 : 0);
        if (in->env[i].set)
            av2_put_text(b, in->env[i].value); /* may be empty */
    }
}

static void av2_put_abi(struct av2_buf *b,
                        const struct vcs_action_preimage_v2 *in)
{
    av2_put_u32(b, in->abi_generation);
    av2_put_u32(b, (uint32_t)in->abi_count);
    for (size_t i = 0; i < in->abi_count; i++) {
        av2_put_text(b, in->abi[i].name);
        av2_put_u32(b, in->abi[i].version);
    }
}

static void av2_put_ref(struct av2_buf *b,
                        const struct vcs_action_root_ref_v2 *ref)
{
    if (ref->present)
        av2_put(b, ref->root, 32);
}

static void av2_put_field(struct av2_buf *b, enum vcs_action_field_v2 f,
                          const struct vcs_action_preimage_v2 *in)
{
    size_t at = av2_field_begin(b, f);
    switch (f) {
    case VCS_ACTION_FIELD_V2_STAGE:
        av2_put_text(b, in->stage_kind);
        av2_put_u32(b, in->stage_version);
        break;
    case VCS_ACTION_FIELD_V2_SOURCE: av2_put_inputs(b, in); break;
    case VCS_ACTION_FIELD_V2_GENERATED: av2_put_generated(b, in); break;
    case VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP: av2_put_negative(b, in); break;
    case VCS_ACTION_FIELD_V2_TOOLCHAIN: av2_put(b, in->toolchain_root, 32);
        break;
    case VCS_ACTION_FIELD_V2_SYSROOT: av2_put_sysroot(b, &in->sysroot); break;
    case VCS_ACTION_FIELD_V2_LINKER: av2_put_linker(b, &in->linker); break;
    case VCS_ACTION_FIELD_V2_FLAGS: av2_put_texts(b, in->argv, in->argc);
        break;
    case VCS_ACTION_FIELD_V2_ENV: av2_put_env(b, in); break;
    case VCS_ACTION_FIELD_V2_ABI: av2_put_abi(b, in); break;
    case VCS_ACTION_FIELD_V2_HARNESS: av2_put_ref(b, &in->harness); break;
    case VCS_ACTION_FIELD_V2_FIXTURES: av2_put_ref(b, &in->fixtures); break;
    default: av2_put_ref(b, &in->policy); break;
    }
    av2_field_end(b, at);
}

bool vcs_action_preimage_v2_encode(const struct vcs_action_preimage_v2 *in,
                                   uint8_t **out, size_t *out_len,
                                   char *why, size_t why_len)
{
    if (!out || !out_len) {
        av2_why(why, why_len, "encode output is missing", NULL);
        return false;
    }
    *out = NULL;
    *out_len = 0;
    if (!vcs_action_preimage_v2_check(in, why, why_len))
        return false;
    struct av2_buf b = {0};
    av2_put(&b, VCS_ACTION_PREIMAGE_V2_MAGIC, AV2_MAGIC_LEN);
    for (int f = VCS_ACTION_FIELD_V2_STAGE; f < VCS_ACTION_FIELD_V2_COUNT;
         f++)
        av2_put_field(&b, (enum vcs_action_field_v2)f, in);
    if (b.failed) {
        free(b.data);
        av2_why(why, why_len, "preimage exceeds its size bound", NULL);
        return false;
    }
    *out = b.data;
    *out_len = b.len;
    return true;
}
