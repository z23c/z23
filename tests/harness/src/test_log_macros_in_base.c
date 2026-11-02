/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_log_macros_in_base — the explicit-name LOG_*_IN forms in base/log_macros.h
 * print the same line the plain LOG_X prints from the named function.
 *
 * What is asserted
 * ----------------
 *   1. For each of WARN, INFO and ERROR, the line a helper prints through
 *      LOG_X_IN("orig", ...) equals, apart from the timestamp and the file:line
 *      token, the line the plain LOG_X prints from a function really named
 *      orig: same level, same `[domain]`, same `orig():`, same message.
 *   2. The base ERROR line has no " origin=" token, both from the plain
 *      LOG_ERROR and from LOG_ERROR_IN. The origin token belongs to util.
 *   3. Every dup, dup2 and close used to capture stderr is checked; a failed
 *      one fails the case.
 *
 * This file includes base/log_macros.h only, never util/log_macros.h.
 *
 * make t ONLY=log_macros_in_base
 */

#include "test/test_core.h"

#include "base/log_level.h"
#include "base/log_macros.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Plain forms: each function is "orig_x" so __func__ is the target name. */
static void orig_warn(void) { LOG_WARN("dom", "warn %d", 7); }
static void orig_info(void) { LOG_INFO("dom", "info %d", 7); }
static void orig_error(void) { LOG_ERROR("dom", "error %d", 7); }

/* Helpers: a different name, the _IN form naming the original. */
static void help_warn(void) { LOG_WARN_IN("orig_warn", "dom", "warn %d", 7); }
static void help_info(void) { LOG_INFO_IN("orig_info", "dom", "info %d", 7); }
static void help_error(void) { LOG_ERROR_IN("orig_error", "dom", "error %d", 7); }

/* Restores stderr from saved_fd and closes it; false when either call fails. */
static bool lmib_restore(int saved_fd)
{
    bool ok = dup2(saved_fd, STDERR_FILENO) >= 0;
    return close(saved_fd) == 0 && ok;
}

/* Undoes a capture that could not finish: the case fails through the false
 * return, so the close results need no further use. */
static void lmib_abort_capture(int saved_fd, FILE *capf, const char *path)
{
    if (capf)
        fclose(capf);
    if (saved_fd >= 0)
        close(saved_fd);
    unlink(path);
}

/* Runs fn with stderr sent to a file and copies that file into out. False
 * when any dup, dup2, fopen, fclose or close on the way fails. */
static bool lmib_capture(void (*fn)(void), char *out, size_t out_len)
{
    char path[256];
    out[0] = '\0';
    (void)mkdir("./test-tmp", 0755); /* EEXIST is expected; a missing dir fails fopen */
    snprintf(path, sizeof(path), "./test-tmp/log_macros_in_base_%d.log", (int)getpid());
    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    if (saved_fd < 0)
        return false;
    FILE *capf = fopen(path, "w+");
    if (!capf || dup2(fileno(capf), STDERR_FILENO) < 0) {
        lmib_abort_capture(saved_fd, capf, path);
        return false;
    }
    fn();
    fflush(stderr);
    bool restored = lmib_restore(saved_fd);
    rewind(capf);
    size_t got = fread(out, 1, out_len - 1, capf);
    out[got] = '\0';
    bool closed = fclose(capf) == 0;
    unlink(path);
    return restored && closed;
}

/* "TS LEVEL [dom] file:line fn(): msg" -> "LEVEL [dom] fn(): msg", dropping
 * the timestamp and the file:line token. */
static bool lmib_norm(const char *line, char *out, size_t cap)
{
    const char *lvl = strchr(line, ' ');
    const char *br = lvl ? strchr(lvl + 1, '[') : NULL;
    const char *sp1 = br ? strchr(br, ' ') : NULL;
    const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp2)
        return false;
    int n = snprintf(out, cap, "%.*s %.*s", (int)(sp1 - (lvl + 1)), lvl + 1,
                     (int)(strlen(sp2 + 1)), sp2 + 1);
    return n > 0 && (size_t)n < cap;
}

struct lmib_pair {
    const char *what;
    void (*plain)(void);
    void (*in)(void);
    const char *fn;
};

static const struct lmib_pair k_lmib_pairs[] = {
    { "LOG_WARN", orig_warn, help_warn, "orig_warn():" },
    { "LOG_INFO", orig_info, help_info, "orig_info():" },
    { "LOG_ERROR", orig_error, help_error, "orig_error():" },
};

/* The helper's line, normalised, equals the plain line from the original,
 * names the original, and does not name the helper. */
static bool lmib_pair_ok(const struct lmib_pair *p)
{
    char a[1024], b[1024], na[1024], nb[1024];
    if (!lmib_capture(p->plain, a, sizeof a) || !lmib_capture(p->in, b, sizeof b))
        return false;
    if (!lmib_norm(a, na, sizeof na) || !lmib_norm(b, nb, sizeof nb))
        return false;
    return strcmp(na, nb) == 0 && strstr(nb, p->fn) && !strstr(b, "help_") &&
           strstr(nb, "[dom]");
}

/* Base ERROR lines carry no origin token, plain or _IN. */
static bool lmib_no_origin_ok(void)
{
    char a[1024], b[1024];
    if (!lmib_capture(orig_error, a, sizeof a) || !lmib_capture(help_error, b, sizeof b))
        return false;
    return strstr(a, " origin=") == NULL && strstr(b, " origin=") == NULL &&
           strstr(b, "orig_error(): error 7") != NULL;
}

int test_log_macros_in_base(void)
{
    int failures = 0;
    enum zcl_log_level prev = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ALL);

    for (size_t i = 0; i < sizeof k_lmib_pairs / sizeof k_lmib_pairs[0]; i++) {
        bool ok = lmib_pair_ok(&k_lmib_pairs[i]);
        printf("log_macros_in_base: %s_IN line matches plain... %s\n", k_lmib_pairs[i].what,
               ok ? "OK" : "FAIL");
        failures += !ok;
    }

    bool no_origin = lmib_no_origin_ok();
    printf("log_macros_in_base: base LOG_ERROR and LOG_ERROR_IN carry no origin token... %s\n",
           no_origin ? "OK" : "FAIL");
    failures += !no_origin;

    zcl_log_level_set(prev);
    return failures;
}
