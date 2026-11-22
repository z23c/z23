/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: which members of a stacked land train a red lint-land names. The
 *          failure body's paths come from the dev.batch.culprit reader
 *          (cp_log_paths, the same filters drop_culprit() applies: no
 *          compiler command lines, no selftest lines, no shared ratchet
 *          files); each path is then mapped to the members whose own commits
 *          changed it. A mapping is returned only when it is unambiguous;
 *          every other failure (no path, a path no member touched, a
 *          truncated body, a printed fix, more than half the train) answers
 *          zero and the caller keeps halving the stack as before. */

#include "command/native_dev_land_internal.h"
#include "command/native_dev_batch_culprit.h"

#include <string.h>

#define DL_CULPRIT_PATHS 16

/* "FAIL <gate>: <body>", as the lint run renders its detail. */
static bool dl_culprit_split(char *detail, struct dl_culprit *out,
                             struct db_text *body)
{
    const char *gate = detail + 5, *colon;
    if (strncmp(detail, "FAIL ", 5) != 0)
        return false;
    colon = strchr(gate, ':');
    if (!colon || colon == gate || colon[1] != ' ' ||
        (size_t)(colon - gate) >= sizeof(out->gate))
        return false;
    memcpy(out->gate, gate, (size_t)(colon - gate));
    out->gate[colon - gate] = '\0';
    body->p = detail + 5 + (colon - gate) + 2;
    body->n = strlen(body->p);
    return true;
}

/* Does the member's own range change `path`? */
static bool dl_culprit_touched(const char *wt, const char *from, const char *to,
                               const char *path)
{
    char out[256];
    const char *args[] = { "diff", "--no-renames", "--name-only", from, to,
                           "--", path, NULL };
    return dl_git(wt, args, out, sizeof(out), DL_GIT_TIMEOUT_MS) == 0 &&
           out[0] != '\0';
}

/* Mark every member touching `path`; false when none does. */
static bool dl_culprit_mark(const char *wt, const char *const from[],
                            const char *const to[], size_t n, const char *path,
                            struct dl_culprit *out)
{
    bool any = false;
    for (size_t i = 0; i < n; i++) {
        if (!dl_culprit_touched(wt, from[i], to[i], path))
            continue;
        if (!out->hit[i])
            (void)snprintf(out->path[i], sizeof(out->path[i]), "%s", path);
        out->hit[i] = true;
        any = true;
    }
    return any;
}

size_t dl_train_culprits(const char *wt, char *detail, const char *const from[],
                         const char *const to[], size_t n,
                         struct dl_culprit *out)
{
    struct db_text body;
    struct cp_set paths = { 0 };
    size_t count = 0;
    bool ok;
    memset(out, 0, sizeof(*out));
    if (n < 2 || n > DL_CULPRIT_MAX || !dl_culprit_split(detail, out, &body) ||
        strstr(body.p, "[detail truncated]") || cp_log_fix_printed(&body))
        return 0;
    ok = cp_log_paths(&body, false, &paths) && paths.n > 0 &&
         paths.n <= DL_CULPRIT_PATHS;
    for (size_t i = 0; ok && i < paths.n; i++)
        ok = dl_culprit_mark(wt, from, to, n, paths.v[i], out);
    cp_set_free(&paths);
    for (size_t i = 0; ok && i < n; i++)
        count += out->hit[i];
    return ok && count * 2 <= n ? count : 0;
}
