/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: renders one HOT_FORK capsule's unity translation unit — the
 * owner TU set bracketed by its story adapter — for both the resident
 * builder (tools/dev/devloop_hotswap_build.c) and the lint gate that
 * compiles every unity (check-hotfork-stories). One renderer means the gate
 * checks exactly the text the reflex path compiles.
 *
 * A story adapter is ordinary C in tools/dev/hotfork_stories/, one file per
 * adapter_id in engine/composition/hotfork_capsules.def; its path is DERIVED
 * from the adapter_id (never listed a second time). The unity is:
 *
 *   #define ZCL_HOTFORK_EXERCISED_SURFACE "<exercised_surface>"
 *   #define ZCL_HOTFORK_STORY_PHASE 1      story prelude (before the owner)
 *   #include "<root>/tools/dev/hotfork_stories/<story>.inc"
 *   #undef ZCL_HOTFORK_STORY_PHASE
 *   #include "<root>/<owner TU>"           then each sibling TU
 *   #define ZCL_HOTFORK_STORY_PHASE 2      story body (after the owner)
 *   #include "<root>/tools/dev/hotfork_stories/<story>.inc"
 *
 * The story file is a real #include, so its bytes land in the compiler
 * depfile and therefore in the artifact cache key: editing a story changes
 * the key, and nothing else about it does.
 *
 * Every helper fails closed (false / -1) rather than rendering a shorter
 * unity: a capsule that silently dropped a sibling TU would resolve that
 * TU's rules from the RESIDENT binary and report STORY_GREEN for a
 * mutation it claims to catch.
 */
#ifndef ZCL_TOOLS_DEV_HOTFORK_UNITY_H
#define ZCL_TOOLS_DEV_HOTFORK_UNITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define ZCL_HOTFORK_STORY_DIR "tools/dev/hotfork_stories/"
#define ZCL_HOTFORK_STORY_SUFFIX ".inc"

enum {
    ZCL_HOTFORK_UNITY_TU_MAX = 256,     /* longest TU path a set may name */
    ZCL_HOTFORK_UNITY_SIBLING_MAX = 16, /* most siblings one capsule names */
    ZCL_HOTFORK_UNITY_MAX = 4096,       /* rendered unity text bound */
};

/* Number of entries in a '|'-separated TU list; 0 for NULL or "". */
static inline size_t zcl_hotfork_tu_list_count(const char *list)
{
    if (!list || !list[0])
        return 0;
    size_t count = 1;
    for (const char *sep = strchr(list, '|'); sep; sep = strchr(sep + 1, '|'))
        count++;
    return count;
}

/* Copies entry `index` of a '|'-separated TU list into `buf`. False when the
 * list has no such entry, the entry is empty, or it does not fit — every
 * caller treats that as "this capsule does not resolve", never as "no more
 * entries", so an over-long path fails closed instead of silently shortening
 * the set. */
static inline bool zcl_hotfork_tu_list_at(const char *list, size_t index,
                                          char *buf, size_t buf_size)
{
    const char *cursor = list ? list : "";
    for (size_t i = 0; i < index; i++) {
        const char *sep = strchr(cursor, '|');
        if (!sep)
            return false;
        cursor = sep + 1;
    }
    const char *sep = strchr(cursor, '|');
    size_t len = sep ? (size_t)(sep - cursor) : strlen(cursor);
    if (len == 0 || len >= buf_size)
        return false;
    memcpy(buf, cursor, len);
    buf[len] = 0;
    return true;
}

/* Repo-relative story adapter path for `adapter_id`: lowercase letters and
 * digits are kept, '-' and '.' become '_', anything else refuses. */
static inline bool zcl_hotfork_story_path(const char *adapter_id, char *out,
                                          size_t out_size)
{
    size_t dir_len = sizeof(ZCL_HOTFORK_STORY_DIR) - 1;
    size_t suffix_len = sizeof(ZCL_HOTFORK_STORY_SUFFIX) - 1;
    size_t id_len = adapter_id ? strlen(adapter_id) : 0;
    if (!out || id_len == 0 || dir_len + id_len + suffix_len >= out_size)
        return false;
    memcpy(out, ZCL_HOTFORK_STORY_DIR, dir_len);
    for (size_t i = 0; i < id_len; i++) {
        char c = adapter_id[i];
        bool keep = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!keep && c != '-' && c != '.')
            return false;
        out[dir_len + i] = keep ? c : '_';
    }
    memcpy(out + dir_len + id_len, ZCL_HOTFORK_STORY_SUFFIX, suffix_len + 1);
    return true;
}

/* True when `text` can sit inside a C string literal and an #include path
 * unchanged: printable ASCII without '"', '\\' or '%'. */
static inline bool zcl_hotfork_unity_text_ok(const char *text)
{
    if (!text)
        return false;
    for (const char *p = text; *p; p++)
        if (*p < 0x20 || *p > 0x7e || *p == '"' || *p == '\\' || *p == '%')
            return false;
    return true;
}

/* Appends `a` then `b` then `c` (any may be ""), or returns -1 once anything
 * has not fit. `used` carries the running length so callers stay linear. */
static inline int zcl_hotfork_unity_put(char *out, size_t out_size, int used,
                                        const char *a, const char *b,
                                        const char *c)
{
    if (used < 0 || (size_t)used >= out_size)
        return -1;
    int written = snprintf(out + used, out_size - (size_t)used, "%s%s%s", a,
                           b, c);
    if (written < 0 || (size_t)used + (size_t)written >= out_size)
        return -1;
    return used + written;
}

/* Appends `#include "<root><rel>"` for one repo-relative path. */
static inline int zcl_hotfork_unity_include(char *out, size_t out_size,
                                            int used, const char *root,
                                            const char *rel)
{
    if (!zcl_hotfork_unity_text_ok(rel) || strstr(rel, "..") || rel[0] == '/')
        return -1;
    used = zcl_hotfork_unity_put(out, out_size, used, "#include \"", root, rel);
    return zcl_hotfork_unity_put(out, out_size, used, "\"\n", "", "");
}

/* Renders the whole unity for one capsule. `root` is the absolute repository
 * root WITH its trailing '/'. Returns the text length, or -1 when any part
 * does not resolve or fit. */
static inline int zcl_hotfork_unity_render(const char *root,
                                           const char *owner_tu,
                                           const char *sibling_tus,
                                           const char *adapter_id,
                                           const char *exercised_surface,
                                           char *out, size_t out_size)
{
    char story[ZCL_HOTFORK_UNITY_TU_MAX], tu[ZCL_HOTFORK_UNITY_TU_MAX];
    size_t root_len = root ? strlen(root) : 0;
    size_t count = zcl_hotfork_tu_list_count(sibling_tus);
    if (!out || out_size == 0 || root_len < 2 || root[0] != '/' ||
        root[root_len - 1] != '/' || !zcl_hotfork_unity_text_ok(root) ||
        !zcl_hotfork_unity_text_ok(exercised_surface) || !owner_tu ||
        count > ZCL_HOTFORK_UNITY_SIBLING_MAX ||
        !zcl_hotfork_story_path(adapter_id, story, sizeof(story)))
        return -1;
    int used = zcl_hotfork_unity_put(
        out, out_size, 0, "/* zcl.dev.hotfork.unity.v2 */\n",
        "#define ZCL_HOTFORK_EXERCISED_SURFACE \"", exercised_surface);
    used = zcl_hotfork_unity_put(out, out_size, used, "\"\n",
                                 "#define ZCL_HOTFORK_STORY_PHASE 1\n", "");
    used = zcl_hotfork_unity_include(out, out_size, used, root, story);
    used = zcl_hotfork_unity_put(out, out_size, used,
                                 "#undef ZCL_HOTFORK_STORY_PHASE\n", "", "");
    used = zcl_hotfork_unity_include(out, out_size, used, root, owner_tu);
    for (size_t i = 0; used > 0 && i < count; i++)
        used = zcl_hotfork_tu_list_at(sibling_tus, i, tu, sizeof(tu))
            ? zcl_hotfork_unity_include(out, out_size, used, root, tu)
            : -1;
    used = zcl_hotfork_unity_put(out, out_size, used,
                                 "#define ZCL_HOTFORK_STORY_PHASE 2\n", "", "");
    used = zcl_hotfork_unity_include(out, out_size, used, root, story);
    if (used <= 0)
        out[0] = 0;
    return used <= 0 ? -1 : used;
}

#endif /* ZCL_TOOLS_DEV_HOTFORK_UNITY_H */
