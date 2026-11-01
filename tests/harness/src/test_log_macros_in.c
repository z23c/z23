/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_log_macros_in — the explicit-name LOG_*_IN macros let a helper split
 * out of a function print the ORIGINAL function's name.
 *
 * What is asserted
 * ----------------
 *   1. For each of WARN, INFO, ERROR, FAIL, ERR, NULL, RETURN and GUARD, the
 *      line a helper prints through LOG_X_IN("orig", ...) equals, apart from
 *      the timestamp and the file:line token, the line the plain LOG_X prints
 *      from a function really named orig: same `[domain]`, same `orig():`,
 *      same message, same origin token.
 *   2. The returning forms return from the helper with the plain macro's
 *      value: LOG_FAIL_IN false, LOG_ERR_IN -1, LOG_NULL_IN NULL,
 *      LOG_RETURN_IN the given value.
 *   3. The helper's own name never appears in the line.
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

/* Helpers: a different name, the _IN form naming the original. */
static bool help_fail(void) { LOG_FAIL_IN("orig_fail", "dom", "fail %d", 7); }
static int help_err(void) { LOG_ERR_IN("orig_err", "dom", "err %d", 7); }
static void *help_null(void) { LOG_NULL_IN("orig_null", "dom", "null %d", 7); }
static int help_ret(void) { LOG_RETURN_IN(42, "orig_ret", "dom", "ret %d", 7); }
static void help_warn(void) { LOG_WARN_IN("orig_warn", "dom", "warn %d", 7); }
static void help_info(void) { LOG_INFO_IN("orig_info", "dom", "info %d", 7); }
static void help_error(void) { LOG_ERROR_IN("orig_error", "dom", "error %d", 7); }
static bool help_guard(void) { GUARD_IN(false, "orig_guard", "dom", "guard %d", 7); return true; }

static bool g_lmi_bool;
static int g_lmi_int;
static void *g_lmi_ptr;
static void lmi_orig_fail(void) { g_lmi_bool = orig_fail(); }
static void lmi_help_fail(void) { g_lmi_bool = help_fail(); }
static void lmi_orig_err(void) { g_lmi_int = orig_err(); }
static void lmi_help_err(void) { g_lmi_int = help_err(); }
static void lmi_orig_null(void) { g_lmi_ptr = orig_null(); }
static void lmi_help_null(void) { g_lmi_ptr = help_null(); }
static void lmi_orig_ret(void) { g_lmi_int = orig_ret(); }
static void lmi_help_ret(void) { g_lmi_int = help_ret(); }
static void lmi_orig_guard(void) { g_lmi_bool = orig_guard(); }
static void lmi_help_guard(void) { g_lmi_bool = help_guard(); }

static bool lmi_capture(void (*fn)(void), char *out, size_t out_len)
{
    char path[256];
    out[0] = '\0';
    mkdir("./test-tmp", 0755);
    snprintf(path, sizeof(path), "./test-tmp/log_macros_in_%d.log", (int)getpid());
    fflush(stderr);
    int saved_fd = dup(STDERR_FILENO);
    FILE *capf = (saved_fd >= 0) ? fopen(path, "w+") : NULL;
    if (!capf) {
        if (saved_fd >= 0)
            close(saved_fd);
        return false;
    }
    dup2(fileno(capf), STDERR_FILENO);
    fn();
    fflush(stderr);
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);
    rewind(capf);
    size_t got = fread(out, 1, out_len - 1, capf);
    out[got] = '\0';
    fclose(capf);
    unlink(path);
    return true;
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
    { "LOG_FAIL", lmi_orig_fail, lmi_help_fail, "orig_fail():" },
    { "LOG_ERR", lmi_orig_err, lmi_help_err, "orig_err():" },
    { "LOG_NULL", lmi_orig_null, lmi_help_null, "orig_null():" },
    { "LOG_RETURN", lmi_orig_ret, lmi_help_ret, "orig_ret():" },
    { "LOG_WARN", orig_warn, help_warn, "orig_warn():" },
    { "LOG_INFO", orig_info, help_info, "orig_info():" },
    { "LOG_ERROR", orig_error, help_error, "orig_error():" },
    { "GUARD", lmi_orig_guard, lmi_help_guard, "orig_guard():" },
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

    char sink[1024];
    g_lmi_bool = true;
    lmi_capture(lmi_help_fail, sink, sizeof sink);
    bool r1 = g_lmi_bool == false;
    g_lmi_int = 0;
    lmi_capture(lmi_help_err, sink, sizeof sink);
    bool r2 = g_lmi_int == -1;
    g_lmi_ptr = &g_lmi_int;
    lmi_capture(lmi_help_null, sink, sizeof sink);
    bool r3 = g_lmi_ptr == NULL;
    g_lmi_int = 0;
    lmi_capture(lmi_help_ret, sink, sizeof sink);
    bool r4 = g_lmi_int == 42;
    g_lmi_bool = true;
    lmi_capture(lmi_help_guard, sink, sizeof sink);
    bool r5 = g_lmi_bool == false;
    bool rets = r1 && r2 && r3 && r4 && r5;
    printf("log_macros_in: returning forms return the plain value... %s\n",
           rets ? "OK" : "FAIL");
    failures += !rets;

    zcl_log_level_set(prev);
    return failures;
}
