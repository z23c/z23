/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The file-envelope parser. See engine/engine_patch.h for the protocol and
 * for the list of things it refuses.
 *
 * The scan is a plain line walk with one piece of state (inside an envelope
 * or not). It never recurses, never grows a buffer past a declared cap, and
 * treats the input as bytes with a length rather than as a C string, so a
 * reply is not truncated by whatever a vendor happened to put in it.
 */

#include "engine/engine_patch.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <string.h>

void engine_patch_free(struct engine_patch *p)
{
    if (!p)
        return;
    for (size_t i = 0; i < p->count; i++)
        free(p->entries[i].content);
    memset(p, 0, sizeof(*p));
}

bool engine_patch_path_ok(const char *path)
{
    if (!path || !path[0])
        return false;
    const size_t n = strlen(path);
    if (n >= ENGINE_PATCH_MAX_PATH)
        return false;
    if (path[0] == '/' || path[0] == '-' || path[0] == '.')
        return false;                       /* absolute, flag-like, or hidden */
    if (strncmp(path, ".git/", 5) == 0 || strstr(path, "/.git/") != NULL)
        return false;
    if (path[n - 1] == '/')
        return false;

    /* Segment walk: no empty segment (which is `//`), no `.` or `..`. */
    const char *seg = path;
    for (size_t i = 0; i <= n; i++) {
        if (i != n && path[i] != '/')
            continue;
        const size_t seg_len = (size_t)(&path[i] - seg);
        if (seg_len == 0)
            return false;
        if (seg_len == 1 && seg[0] == '.')
            return false;
        if (seg_len == 2 && seg[0] == '.' && seg[1] == '.')
            return false;
        seg = &path[i] + 1;
    }

    /* A deliberately narrow byte set. Everything this harness writes is
     * source, and source path names live inside it; anything else is either a
     * mistake or an attempt to reach somewhere. */
    for (size_t i = 0; i < n; i++) {
        const char c = path[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '.' || c == '_'
                        || c == '/' || c == '+' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

/* One line of the reply, as a bounded view. `len` excludes the newline. */
struct line_view {
    const char *p;
    size_t      len;
};

static bool line_is(const struct line_view *l, const char *lit)
{
    const size_t n = strlen(lit);
    return l->len == n && memcmp(l->p, lit, n) == 0;
}

static bool line_starts(const struct line_view *l, const char *lit)
{
    const size_t n = strlen(lit);
    return l->len >= n && memcmp(l->p, lit, n) == 0;
}

/* Copy the path argument of a marker line into `out`, refusing anything the
 * containment rule rejects. */
static bool take_path(const struct line_view *l, const char *marker,
                      const char *name, char *out)
{
    const size_t skip = strlen(marker);
    size_t n = l->len - skip;
    const char *s = l->p + skip;
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r'))
        n--;
    if (n == 0 || n >= ENGINE_PATCH_MAX_PATH)
        LOG_FAIL("engine", "refusing a %s marker with no usable path", name);
    memcpy(out, s, n);
    out[n] = '\0';
    if (!engine_patch_path_ok(out))
        LOG_FAIL("engine", "refusing the path a %s marker named: it is not a "
                           "contained relative source path", name);
    return true;
}

/* Index of the entry already holding `path`, or -1. A path is looked up by
 * name rather than tracked separately because ENGINE_PATCH_MAX_FILES bounds
 * the scan to a small, fixed size. */
static int path_index(const struct engine_patch *p, const char *path)
{
    for (size_t i = 0; i < p->count; i++) {
        if (strcmp(p->entries[i].path, path) == 0)
            return (int)i;
    }
    return -1;
}

/* Close an open envelope: copy [body, body_end) into an entry for `path`.
 * A path seen before in this same reply is superseded in place — the LAST
 * envelope for a path wins, not the first — rather than refusing the whole
 * reply; see the "A PATH NAMED TWICE" note in engine_patch.h. */
static bool commit_file(struct engine_patch *p, const char *path,
                        const char *body, const char *body_end)
{
    const size_t n = (size_t)(body_end - body);
    if (n > ENGINE_PATCH_MAX_FILE_BYTES)
        LOG_FAIL("engine", "refusing %zu bytes for %s: over the per-file cap",
                 n, path);

    char *content = zcl_malloc(n + 1, "engine_patch_content");
    if (!content)
        LOG_FAIL("engine", "cannot allocate %zu bytes for %s", n + 1, path);
    if (n)
        memcpy(content, body, n);
    content[n] = '\0';

    const int idx = path_index(p, path);
    if (idx >= 0) {
        LOG_WARN("engine", "a later envelope for %s supersedes an earlier "
                           "one in the same reply; applying the last one",
                 path);
        struct engine_patch_entry *e = &p->entries[idx];
        free(e->content);
        e->content = content;
        e->content_len = n;
        e->remove = false;
        return true;
    }

    if (p->count >= ENGINE_PATCH_MAX_FILES) {
        free(content);
        LOG_FAIL("engine", "refusing more than %u files in one patch",
                 (unsigned)ENGINE_PATCH_MAX_FILES);
    }
    struct engine_patch_entry *e = &p->entries[p->count];
    memcpy(e->path, path, strlen(path) + 1);
    e->content = content;
    e->content_len = n;
    e->remove = false;
    p->count++;
    return true;
}

/* A path seen before is superseded in place, exactly as commit_file() does —
 * a Z23-DELETE-FILE that follows an earlier write for the same path (or
 * precedes a later one) is just the last envelope for that path winning. */
static bool commit_delete(struct engine_patch *p, const char *path)
{
    const int idx = path_index(p, path);
    if (idx >= 0) {
        LOG_WARN("engine", "a later envelope for %s supersedes an earlier "
                           "one in the same reply; applying the last one",
                 path);
        struct engine_patch_entry *e = &p->entries[idx];
        free(e->content);
        e->content = NULL;
        e->content_len = 0;
        e->remove = true;
        return true;
    }

    if (p->count >= ENGINE_PATCH_MAX_FILES)
        LOG_FAIL("engine", "refusing more than %u files in one patch",
                 (unsigned)ENGINE_PATCH_MAX_FILES);
    struct engine_patch_entry *e = &p->entries[p->count];
    memcpy(e->path, path, strlen(path) + 1);
    e->content = NULL;
    e->content_len = 0;
    e->remove = true;
    p->count++;
    return true;
}

/* State carried across the line walk. */
struct patch_scan {
    bool        open;
    char        path[ENGINE_PATCH_MAX_PATH];
    const char *body;      /* first byte after the BEGIN line */
};

/* Handle one line. Returns false to abort the whole parse. */
static bool scan_line(struct engine_patch *p, struct patch_scan *st,
                      const struct line_view *l, const char *line_start)
{
    if (line_starts(l, ENGINE_PATCH_BEGIN)) {
        if (st->open)
            LOG_FAIL("engine", "refusing a nested Z23-BEGIN-FILE marker: the "
                               "envelope for %s was never closed", st->path);
        if (!take_path(l, ENGINE_PATCH_BEGIN, "Z23-BEGIN-FILE", st->path))
            return false;
        st->open = true;
        st->body = NULL;         /* set by the caller once the line is consumed */
        return true;
    }
    if (line_is(l, ENGINE_PATCH_END)) {
        if (!st->open)
            LOG_FAIL("engine", "refusing a %s marker with no open envelope",
                     ENGINE_PATCH_END);
        if (!commit_file(p, st->path, st->body, line_start))
            return false;
        st->open = false;
        return true;
    }
    if (!st->open && line_starts(l, ENGINE_PATCH_DELETE)) {
        char path[ENGINE_PATCH_MAX_PATH];
        if (!take_path(l, ENGINE_PATCH_DELETE, "Z23-DELETE-FILE", path))
            return false;
        return commit_delete(p, path);
    }
    return true;
}

bool engine_patch_parse(const char *text, size_t len, struct engine_patch *p)
{
    if (!p)
        return false;
    memset(p, 0, sizeof(*p));
    if (!text)
        LOG_FAIL("engine", "refusing to parse a null reply");
    if (memchr(text, 0, len) != NULL)
        LOG_FAIL("engine", "refusing a reply containing a NUL byte");

    struct patch_scan st = { .open = false, .path = {0}, .body = NULL };
    const char *cur = text;
    const char *end = text + len;
    bool ok = true;

    while (cur < end && ok) {
        const char *nl = memchr(cur, '\n', (size_t)(end - cur));
        const char *line_end = nl ? nl : end;
        size_t vis = (size_t)(line_end - cur);
        if (vis > 0 && cur[vis - 1] == '\r')
            vis--;                                /* tolerate CRLF transcripts */
        const struct line_view l = { .p = cur, .len = vis };

        ok = scan_line(p, &st, &l, cur);
        cur = nl ? nl + 1 : end;
        if (ok && st.open && st.body == NULL)
            st.body = cur;                        /* body starts after BEGIN */
    }

    if (ok && st.open) {
        LOG_WARN("engine",
                 "refusing a truncated reply: the envelope for %s was never "
                 "closed (an output-token limit looks exactly like this)",
                 st.path);
        ok = false;
    }
    if (!ok)
        engine_patch_free(p);
    return ok;
}

const char *engine_patch_protocol_text(void)
{
    return
"OUTPUT PROTOCOL — this is how your work reaches the tree. Nothing outside\n"
"an envelope is applied; prose before and after is fine and is ignored.\n"
"\n"
"For every file you create or replace, emit its COMPLETE new contents:\n"
"\n"
"Z23-BEGIN-FILE relative/path/to/file.c\n"
"<the entire file, verbatim, no fences, no line numbers, no elision>\n"
"Z23-END-FILE\n"
"\n"
"To delete a file, one line on its own:\n"
"\n"
"Z23-DELETE-FILE relative/path/to/file.c\n"
"\n"
"Rules the harness enforces and will refuse the WHOLE reply over:\n"
"  - each marker alone on its own line, spelled exactly as above;\n"
"  - paths are relative, contained, and contain no `..` segment;\n"
"  - no partial files. `// ... rest unchanged ...` destroys the file;\n"
"  - an unclosed envelope is treated as a truncated reply and discarded,\n"
"    so if you are running out of room, finish fewer files completely.\n";
}
