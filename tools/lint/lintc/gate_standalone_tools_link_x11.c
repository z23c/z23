/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the X11 runtime qualification of check-standalone-tools-link. A
 * missing libX11 runtime can excuse only the link of native_ui_driver, never
 * its strict compile. The probe command is derived from the actual Make rule
 * so compiler wrappers, command-line overrides, platform flags and future rule
 * changes cannot silently drift.
 * Status of stl_x11_linkable: 0 = linkable, 1 = confirmed absent with strict
 * object coverage, 2 = unproven (temporary storage, compiler, recipe or any
 * other linker failure).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_standalone_tools_link_priv.h"

static const char k_suffix[] = " -o $@ $< -Wl,-l:libX11.so.6";

int stl_wait(pid_t pid)
{
    int st = 0;
    pid_t w;
    while ((w = waitpid(pid, &st, 0)) < 0 && errno == EINTR)
        ;
    return (w == pid && WIFEXITED(st)) ? WEXITSTATUS(st) : -1;
}

int stl_mkdtemp(char *dir, size_t cap, const char *tag)
{
    if (ovf(snprintf(dir, cap, "%s/%s.XXXXXX", env_or("TMPDIR", "/tmp"), tag), cap))
        return -1;
    return mkdtemp(dir) ? 0 : -1;
}

int stl_nonempty(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 && sb.st_size > 0;
}

static int stl_in_dir_nonempty(const char *dir, const char *name)
{
    char p[STL_PATH];
    return !ovf(snprintf(p, sizeof p, "%s/%s", dir, name), sizeof p) &&
           stl_nonempty(p);
}

/* "\\\n" -> " " in place, then trailing newlines dropped (shell $(...)). */
static void stl_join_continuations(char *s)
{
    size_t o = 0;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '\\' && s[i + 1] == '\n') {
            s[o++] = ' ';
            i++;
        } else {
            s[o++] = s[i];
        }
    }
    while (o && s[o - 1] == '\n')
        o--;
    s[o] = '\0';
}

/* The $(CC) recipe lines of the NATIVE_UI_DRIVER_BIN rule, tabs removed. */
static int stl_x11_recipe(char *out, size_t cap)
{
    FILE *f = fopen("Makefile", "r");
    if (!f)
        return 2;
    struct stl_rd r = { .f = f };
    int rule = 0, cmd = 0, rc = 0;
    size_t o = 0;
    out[0] = '\0';
    while (rc == 0 && stl_rd_next(&r)) {
        if (strncmp(r.buf, "$(NATIVE_UI_DRIVER_BIN):", 24) == 0 && r.head) {
            rule = 1;
            continue;
        }
        if (!rule)
            continue;
        if (r.buf[0] != '\t')
            break;
        if (!cmd && strncmp(r.buf, "\t$(CC)", 6) == 0)
            cmd = 1;
        if (!cmd)
            continue;
        const char *body = r.buf + strspn(r.buf, "\t \t");
        int n = snprintf(out + o, cap - o, "%s\n", body);
        rc = ovf(n, cap - o) ? 2 : 0;
        o += rc ? 0 : (size_t)n;
    }
    fclose(f);
    stl_join_continuations(out);
    return rc;
}

static int stl_ends_with(const char *s, const char *tail)
{
    size_t sl = strlen(s), tl = strlen(tail);
    return sl >= tl && strcmp(s + sl - tl, tail) == 0;
}

/* link.log discipline: exactly one missing-SONAME diagnostic, nothing else
 * but the linker's own summary line. 1 = proven absent, 2 = unproven. */
static int stl_log_lines(FILE *f, int *missing)
{
    struct stl_rd r = { .f = f };
    while (stl_rd_next(&r)) {
        if (stl_ends_with(r.buf, "ld: cannot find -l:libX11.so.6: No such file or directory") ||
            stl_ends_with(r.buf, "ld.bfd: cannot find -l:libX11.so.6: No such file or directory") ||
            stl_ends_with(r.buf, "ld.lld: error: unable to find library -l:libX11.so.6"))
            (*missing)++;
        else if (strcmp(r.buf, "collect2: error: ld returned 1 exit status") != 0 &&
                 strcmp(r.buf, "clang: error: linker command failed with exit code 1 (use -v to see invocation)") != 0)
            return 2;
    }
    return 0;
}

int stl_x11_link_check(const char *dir)
{
    char lp[STL_PATH];
    int missing = 0;
    if (ovf(snprintf(lp, sizeof lp, "%s/link.log", dir), sizeof lp))
        return 2;
    FILE *f = fopen(lp, "r");
    if (!f)
        return 2;
    int rc = stl_log_lines(f, &missing);
    fclose(f);
    if (rc != 0 || missing != 1) {
        stl_copy_to(stderr, lp);
        return 2;
    }
    static const char *const hdrs[] = { "vendor/x11/include/X11/Xlib.h",
        "vendor/x11/include/X11/Xutil.h", "vendor/x11/include/X11/keysym.h" };
    for (size_t i = 0; i < sizeof hdrs / sizeof hdrs[0]; i++)
        if (!stl_nonempty(hdrs[i]))
            return 2;
    return 1;
}

/* make -f Makefile -f probe.mk <target>, its stdout sent to stderr. */
static int stl_x11_make(const char *dir, const char *target, const char *mk)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (dup2(2, 1) < 0 || setenv("z23_x11_probe_dir", dir, 1) != 0 ||
            setenv("LC_ALL", "C", 1) != 0)
            _exit(127);
        execlp("make", "make", "--no-print-directory", "-s", "-f", "Makefile",
               "-f", mk, target, (char *)NULL);
        _exit(127);
    }
    return stl_wait(pid);
}

static int stl_x11_write(const char *dir, const char *flags, char *mkp, size_t cap)
{
    static char mk[STL_TEXT];
    char p[STL_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/probe.c", dir), sizeof p) ||
        ovf(snprintf(mkp, cap, "%s/probe.mk", dir), cap))
        return 2;
    if (csr_write(p, "#ifndef __linux__\n#error native Linux compiler required\n"
                     "#endif\nint main(void){return 0;}\n") != 0)
        return 2;
    if (ovf(snprintf(mk, sizeof mk,
        ".PHONY: zcl-x11-baseline zcl-x11-cover\n"
        "zcl-x11-baseline:\n"
        "\t%s -o \"$$z23_x11_probe_dir/probe\" \"$$z23_x11_probe_dir/probe.c\""
        " && printf ok >\"$$z23_x11_probe_dir/compiled\" || exit 1\n"
        "\t\"$$z23_x11_probe_dir/probe\" && printf ok >\"$$z23_x11_probe_dir/ran\""
        " || exit 1\n"
        "\t@if %s -o \"$$z23_x11_probe_dir/x11\" \"$$z23_x11_probe_dir/probe.c\""
        " -Wl,-l:libX11.so.6 >\"$$z23_x11_probe_dir/link.log\" 2>&1; "
        "then printf present >\"$$z23_x11_probe_dir/state\"; "
        "else printf failed >\"$$z23_x11_probe_dir/state\"; fi\n"
        "zcl-x11-cover:\n"
        "\t%s -c tools/native_ui_driver.c"
        " -o \"$$z23_x11_probe_dir/native_ui_driver.o\""
        " && printf ok >\"$$z23_x11_probe_dir/covered\" || exit 1\n",
        flags, flags, flags), sizeof mk))
        return 2;
    return csr_write(mkp, mk) != 0 ? 2 : 0;
}

static int stl_x11_state_present(const char *dir)
{
    char p[STL_PATH], v[16] = "";
    if (ovf(snprintf(p, sizeof p, "%s/state", dir), sizeof p))
        return 0;
    FILE *f = fopen(p, "r");
    if (!f)
        return 0;
    size_t n = fread(v, 1, sizeof v - 1, f);
    fclose(f);
    v[n] = '\0';
    return strcmp(v, "present") == 0;
}

static int stl_x11_probe_dir(const char *dir)
{
    static char recipe[STL_LINE];
    char mkp[STL_PATH];
    if (stl_x11_recipe(recipe, sizeof recipe) != 0 ||
        strncmp(recipe, "$(CC) ", 6) != 0 || !stl_ends_with(recipe, k_suffix))
        return 2;
    recipe[strlen(recipe) - strlen(k_suffix)] = '\0';
    if (stl_x11_write(dir, recipe, mkp, sizeof mkp) != 0)
        return 2;
    /* Success must be recorded by each real shell command, independently of
     * make's status (MAKEFLAGS may carry -i) and of partial compiler output. */
    int rc = stl_x11_make(dir, "zcl-x11-baseline", mkp);
    if (rc != 0 || !stl_in_dir_nonempty(dir, "probe") ||
        !stl_in_dir_nonempty(dir, "state") || !stl_in_dir_nonempty(dir, "compiled") ||
        !stl_in_dir_nonempty(dir, "ran"))
        return 2;
    if (stl_x11_state_present(dir))
        return 0;
    rc = stl_x11_link_check(dir);
    if (rc != 1)
        return rc;
    rc = stl_x11_make(dir, "zcl-x11-cover", mkp);
    return (rc == 0 && stl_in_dir_nonempty(dir, "native_ui_driver.o") &&
            stl_in_dir_nonempty(dir, "covered")) ? 1 : 2;
}

int stl_x11_linkable(void)
{
    char dir[STL_PATH];
    if (stl_mkdtemp(dir, sizeof dir, "zcl-x11-probe") != 0)
        return 2;
    int rc = stl_x11_probe_dir(dir);
    rap_rm_rf(dir);
    return rc;
}
