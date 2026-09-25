/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical action preimage v2: encode, strict decode, and root.
 *
 * The wire and its rules are documented in vcs/build_action.h. One rule set
 * (av2_check) serves both directions: the encoder refuses what the decoder
 * would refuse, so every accepted byte string has exactly one spelling and
 * a receiver that re-derives the root from stored bytes gets the root the
 * producer published, or a refusal. */

#include "vcs/build_action.h"

#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AV2_MAGIC_LEN (sizeof(VCS_ACTION_PREIMAGE_V2_MAGIC))

static void av2_why(char *why, size_t why_len, const char *what,
                    const char *detail)
{
    if (why && why_len)
        (void)snprintf(why, why_len, "%s%s%.160s", what,
                       detail ? ": " : "", detail ? detail : "");
}

const char *vcs_action_field_v2_name(enum vcs_action_field_v2 field)
{
    static const char *const names[VCS_ACTION_FIELD_V2_COUNT] = {
        NULL, "stage", "source", "generated", "negative_lookup",
        "toolchain", "flags", "env", "abi", "harness", "fixtures", "policy",
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

bool vcs_action_v2_env_allowlisted(const char *name, size_t name_len)
{
    /* Variables a C driver consults while compiling one translation unit.
     * PATH and HOME are deliberately absent: the compiler identity is the
     * toolchain capsule, not whichever directory PATH happened to name. */
    static const char *const allow[] = {
        "COMPILER_PATH", "CPATH", "C_INCLUDE_PATH", "GCC_EXEC_PREFIX",
        "GCC_SPECS", "LANG", "LC_ALL", "LC_CTYPE", "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT", "SOURCE_DATE_EPOCH", "TZ",
    };
    for (size_t i = 0; name && i < sizeof(allow) / sizeof(allow[0]); i++)
        if (strlen(allow[i]) == name_len &&
            memcmp(allow[i], name, name_len) == 0)
            return true;
    return false;
}

static size_t av2_env_name_len(const char *entry)
{
    const char *eq = entry ? strchr(entry, '=') : NULL;
    if (!eq || eq == entry)
        return 0;
    for (const char *c = entry; c < eq; c++) {
        bool ok = (*c >= 'A' && *c <= 'Z') || *c == '_' ||
                  (c > entry && *c >= '0' && *c <= '9');
        if (!ok)
            return 0;
    }
    return (size_t)(eq - entry);
}

static bool av2_env_canonical(const char *entry)
{
    size_t n = av2_env_name_len(entry);
    if (n == 0 || !vcs_action_v2_env_allowlisted(entry, n))
        return false;
    const char *value = entry + n + 1;
    return value[0] == '\0' || vcs_action_v2_text_canonical(value);
}

static int av2_env_cmp(const char *a, const char *b)
{
    size_t an = av2_env_name_len(a), bn = av2_env_name_len(b);
    int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : (an > bn) - (an < bn);
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

/* ---- semantic validation (shared by encode and decode) ---------------- */

static bool av2_inputs_ok(const struct vcs_action_input_v2 *v, size_t n,
                          const char *label, char *why, size_t why_len)
{
    if (n > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS || (n && !v)) {
        av2_why(why, why_len, "input list out of bounds", label);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!vcs_action_v2_path_canonical(v[i].path, false)) {
            av2_why(why, why_len, "input path is not canonical", v[i].path);
            return false;
        }
        if (i && strcmp(v[i - 1].path, v[i].path) >= 0) {
            av2_why(why, why_len, "input list not strictly sorted", label);
            return false;
        }
    }
    return true;
}

static bool av2_inputs_disjoint(const struct vcs_action_preimage_v2 *in,
                                char *why, size_t why_len)
{
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

/* Search dirs keep compiler order; a sorted index proves uniqueness and
 * answers "which position is this dir" for present-probe validation. */
struct av2_dir_index {
    const char **sorted;
    size_t count;
};

static bool av2_dir_index_build(const struct vcs_action_preimage_v2 *in,
                                struct av2_dir_index *idx,
                                char *why, size_t why_len)
{
    idx->sorted = NULL;
    idx->count = in->search_dir_count;
    if (in->search_dir_count > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS ||
        (in->search_dir_count && !in->search_dirs)) {
        av2_why(why, why_len, "search dir list out of bounds", NULL);
        return false;
    }
    for (size_t i = 0; i < in->search_dir_count; i++)
        if (!vcs_action_v2_path_canonical(in->search_dirs[i], true)) {
            av2_why(why, why_len, "search dir is not canonical",
                    in->search_dirs[i]);
            return false;
        }
    if (!in->search_dir_count)
        return true;
    idx->sorted = zcl_malloc(sizeof(char *) * in->search_dir_count,
                             "action preimage search index");
    if (!idx->sorted) {
        av2_why(why, why_len, "search index allocation failed", NULL);
        return false;
    }
    memcpy(idx->sorted, in->search_dirs, sizeof(char *) * idx->count);
    qsort(idx->sorted, idx->count, sizeof(char *), av2_str_ptr_cmp);
    for (size_t i = 1; i < idx->count; i++)
        if (strcmp(idx->sorted[i - 1], idx->sorted[i]) == 0) {
            av2_why(why, why_len, "search dir repeated", idx->sorted[i]);
            return false;
        }
    return true;
}

static bool av2_sorted_contains(const char *const *v, size_t n,
                                const char *key)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(v[mid], key);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return false;
}

static bool av2_includers_ok(const struct vcs_action_preimage_v2 *in,
                             char *why, size_t why_len)
{
    if (in->includer_dir_count > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS ||
        (in->includer_dir_count && !in->includer_dirs)) {
        av2_why(why, why_len, "includer dir list out of bounds", NULL);
        return false;
    }
    for (size_t i = 0; i < in->includer_dir_count; i++) {
        const char *d = in->includer_dirs[i];
        if (!vcs_action_v2_path_canonical(d, true) ||
            (i && strcmp(in->includer_dirs[i - 1], d) >= 0)) {
            av2_why(why, why_len,
                    "includer dir not canonical or not strictly sorted", d);
            return false;
        }
    }
    return true;
}

static bool av2_probes_ok(const struct vcs_action_preimage_v2 *in,
                          char *why, size_t why_len)
{
    if (in->probe_count > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS ||
        (in->probe_count && !in->probes)) {
        av2_why(why, why_len, "probe list out of bounds", NULL);
        return false;
    }
    for (size_t i = 0; i < in->probe_count; i++) {
        const struct vcs_action_probe_v2 *p = &in->probes[i];
        bool probed = p->search_prefix > 0 || in->includer_dir_count > 0;
        if (!vcs_action_v2_name_canonical(p->name) ||
            p->search_prefix > in->search_dir_count || !probed ||
            (i && strcmp(in->probes[i - 1].name, p->name) >= 0)) {
            av2_why(why, why_len, "probe is not canonical", p->name);
            return false;
        }
    }
    return true;
}

static const struct vcs_action_probe_v2 *av2_probe_find(
    const struct vcs_action_preimage_v2 *in, const char *name)
{
    size_t lo = 0, hi = in->probe_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(in->probes[mid].name, name);
        if (c == 0) return &in->probes[mid];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

/* A present location must be one the probe set actually covers. */
static bool av2_present_probed(const struct vcs_action_preimage_v2 *in,
                               const struct vcs_action_present_v2 *p)
{
    const struct vcs_action_probe_v2 *probe = av2_probe_find(in, p->name);
    if (!probe)
        return false;
    if (av2_sorted_contains(in->includer_dirs, in->includer_dir_count,
                            p->dir))
        return true;
    for (uint32_t j = 0; j < probe->search_prefix; j++)
        if (strcmp(in->search_dirs[j], p->dir) == 0)
            return true;
    return false;
}

static int av2_present_cmp(const struct vcs_action_present_v2 *a,
                           const struct vcs_action_present_v2 *b)
{
    int c = strcmp(a->dir, b->dir);
    return c ? c : strcmp(a->name, b->name);
}

static bool av2_present_ok(const struct vcs_action_preimage_v2 *in,
                           char *why, size_t why_len)
{
    if (in->present_count > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS ||
        (in->present_count && !in->present)) {
        av2_why(why, why_len, "present list out of bounds", NULL);
        return false;
    }
    for (size_t i = 0; i < in->present_count; i++) {
        const struct vcs_action_present_v2 *p = &in->present[i];
        bool kind_ok = p->kind == VCS_ACTION_PRESENT_V2_REGULAR ||
                       p->kind == VCS_ACTION_PRESENT_V2_OTHER;
        if (!kind_ok || !p->dir || !p->name || !av2_present_probed(in, p) ||
            (i && av2_present_cmp(&in->present[i - 1], p) >= 0)) {
            av2_why(why, why_len, "present probe is not canonical",
                    p->name ? p->name : "(null)");
            return false;
        }
    }
    return true;
}

static bool av2_negative_ok(const struct vcs_action_preimage_v2 *in,
                            char *why, size_t why_len)
{
    struct av2_dir_index idx;
    bool ok = av2_dir_index_build(in, &idx, why, why_len) &&
              av2_includers_ok(in, why, why_len) &&
              av2_probes_ok(in, why, why_len) &&
              av2_present_ok(in, why, why_len);
    free(idx.sorted);
    return ok;
}

static bool av2_texts_ok(const char *const *v, size_t n, bool env,
                         char *why, size_t why_len)
{
    if (n > VCS_ACTION_PREIMAGE_V2_MAX_ITEMS || (n && !v)) {
        av2_why(why, why_len, "text list out of bounds", NULL);
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        bool ok = env ? av2_env_canonical(v[i])
                      : vcs_action_v2_text_canonical(v[i]);
        if (ok && env && i && av2_env_cmp(v[i - 1], v[i]) >= 0)
            ok = false;
        if (!ok) {
            av2_why(why, why_len,
                    env ? "environment entry is not canonical"
                        : "argument is not canonical", v[i]);
            return false;
        }
    }
    return true;
}

static bool av2_abi_ok(const struct vcs_action_preimage_v2 *in,
                       char *why, size_t why_len)
{
    if (in->abi_count > 256 || (in->abi_count && !in->abi)) {
        av2_why(why, why_len, "abi list out of bounds", NULL);
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

static bool av2_nonzero(const uint8_t digest[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= digest[i];
    return acc != 0;
}

static bool av2_check(const struct vcs_action_preimage_v2 *in,
                      char *why, size_t why_len)
{
    if (!in || !av2_word_ok(in->stage_kind, true) || in->stage_version == 0) {
        av2_why(why, why_len, "stage kind/version is not canonical", NULL);
        return false;
    }
    if (!av2_nonzero(in->toolchain_root)) {
        av2_why(why, why_len, "toolchain root is absent", NULL);
        return false;
    }
    if (in->argc == 0) {
        av2_why(why, why_len, "action has no argv", NULL);
        return false;
    }
    return av2_inputs_ok(in->sources, in->source_count, "source",
                         why, why_len) &&
           av2_inputs_ok(in->generated, in->generated_count, "generated",
                         why, why_len) &&
           av2_inputs_disjoint(in, why, why_len) &&
           av2_negative_ok(in, why, why_len) &&
           av2_texts_ok(in->argv, in->argc, false, why, why_len) &&
           av2_texts_ok(in->env, in->env_count, true, why, why_len) &&
           av2_abi_ok(in, why, why_len);
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

static void av2_u32_at(uint8_t *dst, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++)
        dst[i] = (uint8_t)((v >> (8U * i)) & 0xffU);
}

static void av2_put_u32(struct av2_buf *b, uint32_t v)
{
    uint8_t le[4];
    av2_u32_at(le, v);
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
        av2_u32_at(b->data + at, (uint32_t)(b->len - at - 4));
}

static void av2_put_inputs(struct av2_buf *b,
                           const struct vcs_action_input_v2 *v, size_t n)
{
    av2_put_u32(b, (uint32_t)n);
    for (size_t i = 0; i < n; i++) {
        av2_put_text(b, v[i].path);
        av2_put(b, v[i].sha3, 32);
    }
}

static void av2_put_texts(struct av2_buf *b, const char *const *v, size_t n)
{
    av2_put_u32(b, (uint32_t)n);
    for (size_t i = 0; i < n; i++)
        av2_put_text(b, v[i]);
}

static void av2_put_negative(struct av2_buf *b,
                             const struct vcs_action_preimage_v2 *in)
{
    av2_put_texts(b, in->search_dirs, in->search_dir_count);
    av2_put_texts(b, in->includer_dirs, in->includer_dir_count);
    av2_put_u32(b, (uint32_t)in->probe_count);
    for (size_t i = 0; i < in->probe_count; i++) {
        av2_put_text(b, in->probes[i].name);
        av2_put_u32(b, in->probes[i].search_prefix);
    }
    av2_put_u32(b, (uint32_t)in->present_count);
    for (size_t i = 0; i < in->present_count; i++) {
        const struct vcs_action_present_v2 *p = &in->present[i];
        av2_put_text(b, p->dir);
        av2_put_text(b, p->name);
        av2_put_u8(b, p->kind);
        if (p->kind == VCS_ACTION_PRESENT_V2_REGULAR)
            av2_put(b, p->sha3, 32);
    }
}

static void av2_put_ref(struct av2_buf *b, enum vcs_action_field_v2 f,
                        const struct vcs_action_root_ref_v2 *ref)
{
    size_t at = av2_field_begin(b, f);
    if (ref->present)
        av2_put(b, ref->root, 32);
    av2_field_end(b, at);
}

static void av2_put_fields(struct av2_buf *b,
                           const struct vcs_action_preimage_v2 *in)
{
    size_t at = av2_field_begin(b, VCS_ACTION_FIELD_V2_STAGE);
    av2_put_text(b, in->stage_kind);
    av2_put_u32(b, in->stage_version);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_SOURCE);
    av2_put_inputs(b, in->sources, in->source_count);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_GENERATED);
    av2_put_inputs(b, in->generated, in->generated_count);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP);
    av2_put_negative(b, in);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_TOOLCHAIN);
    av2_put(b, in->toolchain_root, 32);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_FLAGS);
    av2_put_texts(b, in->argv, in->argc);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_ENV);
    av2_put_texts(b, in->env, in->env_count);
    av2_field_end(b, at);
    at = av2_field_begin(b, VCS_ACTION_FIELD_V2_ABI);
    av2_put_u32(b, (uint32_t)in->abi_count);
    for (size_t i = 0; i < in->abi_count; i++) {
        av2_put_text(b, in->abi[i].name);
        av2_put_u32(b, in->abi[i].version);
    }
    av2_field_end(b, at);
    av2_put_ref(b, VCS_ACTION_FIELD_V2_HARNESS, &in->harness);
    av2_put_ref(b, VCS_ACTION_FIELD_V2_FIXTURES, &in->fixtures);
    av2_put_ref(b, VCS_ACTION_FIELD_V2_POLICY, &in->policy);
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
    if (!av2_check(in, why, why_len))
        return false;
    struct av2_buf b = {0};
    av2_put(&b, VCS_ACTION_PREIMAGE_V2_MAGIC, AV2_MAGIC_LEN);
    av2_put_fields(&b, in);
    if (b.failed) {
        free(b.data);
        av2_why(why, why_len, "preimage exceeds its size bound", NULL);
        return false;
    }
    *out = b.data;
    *out_len = b.len;
    return true;
}

/* ---- strict decoder ---------------------------------------------------- */

struct av2_reader {
    const uint8_t *p;
    size_t len;
    size_t off;
    bool failed;
};

/* Owned storage behind a decoded view. */
struct av2_storage {
    char *strings;
    size_t strings_used;
    size_t strings_cap;
    struct vcs_action_input_v2 *sources;
    struct vcs_action_input_v2 *generated;
    const char **search_dirs;
    const char **includer_dirs;
    struct vcs_action_probe_v2 *probes;
    struct vcs_action_present_v2 *present;
    const char **argv;
    const char **env;
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

static const char *av2_get_text(struct av2_reader *r, struct av2_storage *s)
{
    uint32_t n = av2_get_u32(r);
    if (r->failed || n == 0 || n >= VCS_ACTION_PREIMAGE_V2_MAX_TEXT ||
        n > r->len - r->off || s->strings_cap - s->strings_used < n + 1u ||
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

static struct vcs_action_input_v2 *av2_get_inputs(struct av2_reader *r,
                                                  struct av2_storage *s,
                                                  size_t *count)
{
    struct vcs_action_input_v2 *v =
        av2_get_array(r, count, sizeof(*v), 5 + 32);
    for (size_t i = 0; v && i < *count; i++) {
        v[i].path = av2_get_text(r, s);
        (void)av2_take(r, v[i].sha3, 32);
    }
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

static void av2_get_negative(struct av2_reader *r, struct av2_storage *s,
                             struct vcs_action_preimage_v2 *v)
{
    s->search_dirs = av2_get_texts(r, s, &v->search_dir_count);
    s->includer_dirs = av2_get_texts(r, s, &v->includer_dir_count);
    s->probes = av2_get_array(r, &v->probe_count, sizeof(*s->probes), 9);
    for (size_t i = 0; s->probes && i < v->probe_count; i++) {
        s->probes[i].name = av2_get_text(r, s);
        s->probes[i].search_prefix = av2_get_u32(r);
    }
    s->present = av2_get_array(r, &v->present_count, sizeof(*s->present),
                               11);
    for (size_t i = 0; s->present && i < v->present_count; i++) {
        struct vcs_action_present_v2 *p = &s->present[i];
        p->dir = av2_get_text(r, s);
        p->name = av2_get_text(r, s);
        p->kind = av2_get_u8(r);
        if (p->kind == VCS_ACTION_PRESENT_V2_REGULAR)
            (void)av2_take(r, p->sha3, 32);
    }
    v->search_dirs = s->search_dirs;
    v->includer_dirs = s->includer_dirs;
    v->probes = s->probes;
    v->present = s->present;
}

static void av2_get_ref(struct av2_reader *r,
                        struct vcs_action_root_ref_v2 *ref)
{
    size_t left = r->len - r->off;
    ref->present = left == 32;
    if (left != 0 && left != 32)
        r->failed = true;
    else if (ref->present)
        (void)av2_take(r, ref->root, 32);
}

static void av2_get_abi(struct av2_reader *r, struct av2_storage *s,
                        struct vcs_action_preimage_v2 *v)
{
    s->abi = av2_get_array(r, &v->abi_count, sizeof(*s->abi), 9);
    for (size_t i = 0; s->abi && i < v->abi_count; i++) {
        s->abi[i].name = av2_get_text(r, s);
        s->abi[i].version = av2_get_u32(r);
    }
    v->abi = s->abi;
}

static void av2_get_field(enum vcs_action_field_v2 f, struct av2_reader *r,
                          struct av2_storage *s,
                          struct vcs_action_preimage_v2 *v)
{
    switch (f) {
    case VCS_ACTION_FIELD_V2_STAGE:
        v->stage_kind = av2_get_text(r, s);
        v->stage_version = av2_get_u32(r);
        break;
    case VCS_ACTION_FIELD_V2_SOURCE:
        v->sources = s->sources = av2_get_inputs(r, s, &v->source_count);
        break;
    case VCS_ACTION_FIELD_V2_GENERATED:
        v->generated = s->generated =
            av2_get_inputs(r, s, &v->generated_count);
        break;
    case VCS_ACTION_FIELD_V2_NEGATIVE_LOOKUP:
        av2_get_negative(r, s, v);
        break;
    case VCS_ACTION_FIELD_V2_TOOLCHAIN:
        (void)av2_take(r, v->toolchain_root, 32);
        break;
    case VCS_ACTION_FIELD_V2_FLAGS:
        v->argv = s->argv = av2_get_texts(r, s, &v->argc);
        break;
    case VCS_ACTION_FIELD_V2_ENV:
        v->env = s->env = av2_get_texts(r, s, &v->env_count);
        break;
    case VCS_ACTION_FIELD_V2_ABI:
        av2_get_abi(r, s, v);
        break;
    case VCS_ACTION_FIELD_V2_HARNESS:
        av2_get_ref(r, &v->harness);
        break;
    case VCS_ACTION_FIELD_V2_FIXTURES:
        av2_get_ref(r, &v->fixtures);
        break;
    default:
        av2_get_ref(r, &v->policy);
        break;
    }
}

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
    free(s->strings);
    free(s->sources);
    free(s->generated);
    free(s->search_dirs);
    free(s->includer_dirs);
    free(s->probes);
    free(s->present);
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
        av2_get_field((enum vcs_action_field_v2)f, &r, s, v);
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
    if (!av2_check(&out->view, why, why_len)) {
        vcs_action_preimage_v2_decoded_free(out);
        return false;
    }
    return true;
}

bool vcs_action_root_v2_from_bytes(const uint8_t *bytes, size_t len,
                                   uint8_t out[32], char *why, size_t why_len)
{
    struct vcs_action_preimage_v2_decoded decoded;
    if (!out || !vcs_action_preimage_v2_decode(bytes, len, &decoded, why,
                                               why_len))
        return false;
    vcs_action_preimage_v2_decoded_free(&decoded);
    static const char domain[] = VCS_ACTION_ROOT_V2_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, bytes, len);
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
    uint8_t ignored[32];
    if (!out || !vcs_action_root_v2_from_bytes(a, a_len, ignored, NULL, 0) ||
        !vcs_action_root_v2_from_bytes(b, b_len, ignored, NULL, 0) ||
        !av2_spans(a, a_len, aoff, alen) || !av2_spans(b, b_len, boff, blen))
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
