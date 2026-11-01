/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_log_macros_in — the explicit-name LOG_*_IN macros let a helper split
 * out of a function print the ORIGINAL function's name.
 *
 * What is asserted
 * ----------------
 *   1. For each of WARN, INFO and ERROR, the line a helper prints through
 *      LOG_X_IN("orig", ...) equals, apart from the timestamp and the file:line
 *      token, the line the plain LOG_X prints from a function really named
 *      orig: same `[domain]`, same `orig():`, same message, same origin token.
 *   2. The exact function token and origin token of LOG_ERROR_IN: the line
 *      reads "orig_error(): error 7 origin=test_log_macros_in.c:<the helper's
 *      line>", so the explicit name, not the helper's __func__, is printed.
 *   3. The plain returning forms (LOG_FAIL false, LOG_ERR -1, LOG_NULL NULL,
 *      LOG_RETURN the given value, GUARD false) return from the function that
 *      holds them. They have no _IN form: a helper returns a status instead.
 *   4. Every dup, dup2 and close used to capture stderr is checked; a failed
 *      one fails the case.
 *
 * make t ONLY=log_macros_in
 */

#include "test/test_core.h"

#include "base/log_level.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Plain forms: each function is "orig_x" so __func__ is the target name. */
static bool orig_fail(void) { LOG_FAIL("dom", "fail %d", 7); }
static int orig_err(void) { LOG_ERR("dom", "err %d", 7); }
static void *orig_null(void) { LOG_NULL("dom", "null %d", 7); }
static int orig_ret(void) { LOG_RETURN(42, "dom", "ret %d", 7); }
static void orig_warn(void) { LOG_WARN("dom", "warn %d", 7); }
static void orig_info(void) { LOG_INFO("dom", "info %d", 7); }
static void orig_error(void) { LOG_ERROR("dom", "error %d", 7); }
static bool orig_guard(void) { GUARD(false, "dom", "guard %d", 7); return true; }

/* Helpers: a different name, the _IN form naming the original. The helper
 * on the line after lmi_help_error_line holds the LOG_ERROR_IN whose origin
 * token the test expects. */
static void help_warn(void) { LOG_WARN_IN("orig_warn", "dom", "warn %d", 7); }
static void help_info(void) { LOG_INFO_IN("orig_info", "dom", "info %d", 7); }
enum { lmi_help_error_line = __LINE__ + 1 };
static void help_error(void) { LOG_ERROR_IN("orig_error", "dom", "error %d", 7); }

static bool g_lmi_bool;
static int g_lmi_int;
static void *g_lmi_ptr;
static void lmi_orig_fail(void) { g_lmi_bool = orig_fail(); }
static void lmi_orig_err(void) { g_lmi_int = orig_err(); }
static void lmi_orig_null(void) { g_lmi_ptr = orig_null(); }
static void lmi_orig_ret(void) { g_lmi_int = orig_ret(); }
static void lmi_orig_guard(void) { g_lmi_bool = orig_guard(); }

/* Restores stderr from saved_fd and closes it; false when either call fails. */
static bool lmi_restore(int saved_fd)
{
    bool ok = dup2(saved_fd, STDERR_FILENO) >= 0;
    return close(saved_fd) == 0 && ok;
}

/* Undoes a capture that could not finish: the case fails through the false
 * return, so the close results need no further use. */
static void lmi_abort_capture(int saved_fd, FILE *capf, const char *path)
{
    if (capf)
        fclose(capf);
    if (saved_fd >= 0)
        close(saved_fd);
    unlink(path);
}

/* Runs fn with stderr sent to a file and copies that file into out. False
 * when any dup, dup2, fopen, fclose or close on the way fails. */
static bool lmi_capture(void (*fn)(void), char *out, size_t out_len)
{
    char path[256];
    out[0] = '\0';
    (void)mkdir("./test-tmp", 0755); /* EEXIST is expected; a missing dir fails fopen */
    snprintf(path, sizeof(path), "./test-tmp/log_macros_in_%d.log", (int)getpid());
    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    if (saved_fd < 0)
        return false;
    FILE *capf = fopen(path, "w+");
    if (!capf || dup2(fileno(capf), STDERR_FILENO) < 0) {
        lmi_abort_capture(saved_fd, capf, path);
        return false;
    }
    fn();
    fflush(stderr);
    bool restored = lmi_restore(saved_fd);
    rewind(capf);
    size_t got = fread(out, 1, out_len - 1, capf);
    out[got] = '\0';
    bool closed = fclose(capf) == 0;
    unlink(path);
    return restored && closed;
}

/* "TS LEVEL [dom] file:line fn(): msg origin=f:l" -> "LEVEL [dom] fn(): msg",
 * dropping the timestamp, the file:line token and the origin line number. */
static bool lmi_norm(const char *line, char *out, size_t cap)
{
    const char *lvl = strchr(line, ' ');
    const char *br = lvl ? strchr(lvl + 1, '[') : NULL;
    const char *sp1 = br ? strchr(br, ' ') : NULL;
    const char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    if (!sp2)
        return false;
    const char *org = strstr(sp2, " origin=");
    int n = snprintf(out, cap, "%.*s %.*s", (int)(sp1 - (lvl + 1)), lvl + 1,
                     (int)((org ? org : sp2 + strlen(sp2)) - (sp2 + 1)), sp2 + 1);
    return n > 0 && (size_t)n < cap;
}

struct lmi_pair {
    const char *what;
    void (*plain)(void);
    void (*in)(void);
    const char *fn;
};

static const struct lmi_pair k_lmi_pairs[] = {
    { "LOG_WARN", orig_warn, help_warn, "orig_warn():" },
    { "LOG_INFO", orig_info, help_info, "orig_info():" },
    { "LOG_ERROR", orig_error, help_error, "orig_error():" },
};

static bool lmi_pair_ok(const struct lmi_pair *p)
{
    char a[1024], b[1024], na[1024], nb[1024];
    if (!lmi_capture(p->plain, a, sizeof a) || !lmi_capture(p->in, b, sizeof b))
        return false;
    if (!lmi_norm(a, na, sizeof na) || !lmi_norm(b, nb, sizeof nb))
        return false;
    return strcmp(na, nb) == 0 && strstr(nb, p->fn) && !strstr(b, "help_") &&
           strstr(nb, "[dom]");
}

/* LOG_ERROR_IN prints the explicit name as the function token and the origin
 * token of the helper's own line, in that order. */
static bool lmi_origin_ok(void)
{
    char b[1024], want[128];
    snprintf(want, sizeof want, "orig_error(): error 7 origin=test_log_macros_in.c:%d",
             (int)lmi_help_error_line);
    return lmi_capture(help_error, b, sizeof b) && strstr(b, want) != NULL &&
           strstr(b, "help_error") == NULL;
}

/* The plain returning forms return the plain macro's value from their own
 * function (they have no _IN form; see log_macros.h). */
static bool lmi_returns_ok(void)
{
    char sink[1024];
    bool ok = true;
    g_lmi_bool = true;
    ok = ok && lmi_capture(lmi_orig_fail, sink, sizeof sink) && g_lmi_bool == false;
    g_lmi_int = 0;
    ok = ok && lmi_capture(lmi_orig_err, sink, sizeof sink) && g_lmi_int == -1;
    g_lmi_ptr = &g_lmi_int;
    ok = ok && lmi_capture(lmi_orig_null, sink, sizeof sink) && g_lmi_ptr == NULL;
    g_lmi_int = 0;
    ok = ok && lmi_capture(lmi_orig_ret, sink, sizeof sink) && g_lmi_int == 42;
    g_lmi_bool = true;
    ok = ok && lmi_capture(lmi_orig_guard, sink, sizeof sink) && g_lmi_bool == false;
    return ok;
}

int test_log_macros_in(void)
{
    int failures = 0;
    enum zcl_log_level prev = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_ALL);

    for (size_t i = 0; i < sizeof k_lmi_pairs / sizeof k_lmi_pairs[0]; i++) {
        bool ok = lmi_pair_ok(&k_lmi_pairs[i]);
        printf("log_macros_in: %s_IN line matches plain... %s\n", k_lmi_pairs[i].what,
               ok ? "OK" : "FAIL");
        failures += !ok;
    }

    bool origin = lmi_origin_ok();
    printf("log_macros_in: LOG_ERROR_IN prints the explicit name and origin token... %s\n",
           origin ? "OK" : "FAIL");
    failures += !origin;

    bool rets = lmi_returns_ok();
    printf("log_macros_in: returning forms return the plain value... %s\n",
           rets ? "OK" : "FAIL");
    failures += !rets;

    zcl_log_level_set(prev);
    return failures;
}
