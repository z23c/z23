/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23_doctor — one command that tells any machine what its C23 build
 * environment is missing, and the exact command that fixes each gap.
 *
 * WHY THIS FILE CANNOT USE THE BUILD. The boxes that need this program are
 * the boxes where `make` already fails: gcc 13 does not accept -std=c23,
 * a worktree has an empty vendor/tor, a gitlink has bytes but no .git.
 * Linking against this tree's headers or libraries would make the doctor
 * unusable on the machine it exists to diagnose. Compile with a plain cc:
 *
 *     cc -std=c2x -o z23_doctor tools/dev/z23_doctor.c
 *
 * -std=c2x (not c23) is load-bearing: gcc 13 understands c2x and is the
 * compiler this tool is written to run under. `make doctor-env` is the
 * front door; it is listed in ZCL_PORTABLE_FRONTDOOR_GOALS so the
 * parse-time -std=c23 toolchain gate does not fire first.
 *
 * Headers: C standard plus one platform header (unistd.h or windows.h).
 * POSIX extras (dirent, stat, statvfs, resource, wait) are the unistd.h
 * counterparts of facilities windows.h already provides; there are no
 * project headers and no project libraries.
 */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#elif defined(__APPLE__)
#  ifndef _DARWIN_C_SOURCE
#    define _DARWIN_C_SOURCE
#  endif
#else
#  ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE
#  endif
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#endif

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <dirent.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/statvfs.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#define Z23_DOCTOR_PATH_MAX 4096
#define Z23_DOCTOR_TEXT_MAX 512
#define Z23_DOCTOR_CC_WORDS 16

enum z23_status {
    Z23_ST_OK = 0,
    Z23_ST_MISSING,
    Z23_ST_TOO_OLD,
    Z23_ST_BROKEN,
    Z23_ST_OPTIONAL
};

enum z23_pkg {
    Z23_PKG_APT,
    Z23_PKG_DNF,
    Z23_PKG_PACMAN,
    Z23_PKG_BREW,
    Z23_PKG_WINGET,
    Z23_PKG_UNKNOWN
};

struct z23_check {
    const char *name;
    const char *json_key;
    enum z23_status status;
    bool required;
    char detail[Z23_DOCTOR_TEXT_MAX];
    char fix[Z23_DOCTOR_TEXT_MAX];
};

static const char *g_root = ".";
static char g_root_buf[Z23_DOCTOR_PATH_MAX];
static char g_cc_raw[Z23_DOCTOR_PATH_MAX];
static enum z23_pkg g_pkg = Z23_PKG_UNKNOWN;

static const char *status_word(enum z23_status s)
{
    switch (s) {
    case Z23_ST_OK:       return "ok";
    case Z23_ST_MISSING:  return "MISSING";
    case Z23_ST_TOO_OLD:  return "TOO OLD";
    case Z23_ST_BROKEN:   return "BROKEN";
    case Z23_ST_OPTIONAL: return "optional";
    }
    return "BROKEN";
}

static const char *platform_name(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

static void set_check(struct z23_check *c, const char *name, const char *jkey,
                      bool required, enum z23_status st,
                      const char *detail, const char *fix)
{
    c->name = name;
    c->json_key = jkey;
    c->required = required;
    c->status = st;
    snprintf(c->detail, sizeof c->detail, "%s", detail ? detail : "");
    snprintf(c->fix, sizeof c->fix, "%s", fix ? fix : "");
}

static bool join2(char *dst, size_t cap, const char *a, const char *b)
{
    size_t na;
    size_t nb;
    if (!dst || cap == 0 || !a || !b)
        return false;
    na = strlen(a);
    nb = strlen(b);
    while (na > 0 && (a[na - 1u] == '/' || a[na - 1u] == '\\'))
        na--;
    if (na + 1u + nb + 1u > cap)
        return false;
    memcpy(dst, a, na);
    dst[na] = '/';
    memcpy(dst + na + 1u, b, nb + 1u);
    return true;
}

static bool path_exists(const char *path)
{
#if defined(_WIN32)
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
    return access(path, F_OK) == 0;
#endif
}

static bool path_is_exec(const char *path)
{
#if defined(_WIN32)
    DWORD attr = GetFileAttributesA(path);
    return attr != INVALID_FILE_ATTRIBUTES
        && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
    return access(path, X_OK) == 0;
#endif
}

static bool get_cwd(char *out, size_t cap)
{
#if defined(_WIN32)
    DWORD n = GetCurrentDirectoryA((DWORD)cap, out);
    return n > 0 && n < (DWORD)cap;
#else
    return getcwd(out, cap) != NULL;
#endif
}

static bool find_prog(const char *name, char *out, size_t cap)
{
    const char *path;
    const char *p;
    char sep;
    if (!name || !name[0] || !out || cap == 0)
        return false;
#if defined(_WIN32)
    sep = ';';
#else
    sep = ':';
#endif
    if (strchr(name, '/') != NULL
#if defined(_WIN32)
        || strchr(name, '\\') != NULL
#endif
        ) {
        if (path_is_exec(name)) {
            snprintf(out, cap, "%s", name);
            return true;
        }
#if defined(_WIN32)
        {
            char exe[Z23_DOCTOR_PATH_MAX];
            snprintf(exe, sizeof exe, "%s.exe", name);
            if (path_is_exec(exe)) {
                snprintf(out, cap, "%s", exe);
                return true;
            }
        }
#endif
        return false;
    }
    path = getenv("PATH");
    if (path == NULL || path[0] == 0)
#if defined(_WIN32)
        path = "C:\\Windows\\System32";
#else
        path = "/usr/bin:/bin:/usr/local/bin";
#endif
    p = path;
    for (;;) {
        const char *cut = strchr(p, sep);
        size_t n = cut ? (size_t)(cut - p) : strlen(p);
        char cand[Z23_DOCTOR_PATH_MAX];
        if (n == 0u)
            snprintf(cand, sizeof cand, "%s", name);
        else if (n + 1u + strlen(name) + 1u > sizeof cand)
            cand[0] = 0;
        else
            snprintf(cand, sizeof cand, "%.*s/%s", (int)n, p, name);
        if (cand[0] && path_is_exec(cand)) {
            snprintf(out, cap, "%s", cand);
            return true;
        }
#if defined(_WIN32)
        if (n > 0u) {
            snprintf(cand, sizeof cand, "%.*s/%s.exe", (int)n, p, name);
            if (path_is_exec(cand)) {
                snprintf(out, cap, "%s", cand);
                return true;
            }
        }
#endif
        if (cut == NULL)
            break;
        p = cut + 1;
    }
    return false;
}

static int split_ws(char *s, char **tok, int max)
{
    int n = 0;
    if (s == NULL || tok == NULL || max <= 0)
        return 0;
    while (*s && n < max) {
        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == 0)
            break;
        tok[n++] = s;
        while (*s && *s != ' ' && *s != '\t')
            s++;
        if (*s) {
            *s = 0;
            s++;
        }
    }
    return n;
}

static void trim_first_line(char *s)
{
    char *nl;
    if (s == NULL)
        return;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    nl = strchr(s, '\n');
    if (nl != NULL)
        *nl = 0;
    nl = strchr(s, '\r');
    if (nl != NULL)
        *nl = 0;
}

#if defined(_WIN32)
static bool cmd_push(char *cmd, size_t cap, size_t *used, const char *arg)
{
    size_t n;
    bool quote;
    size_t need;
    if (cmd == NULL || used == NULL || arg == NULL)
        return false;
    n = strlen(arg);
    quote = strchr(arg, ' ') != NULL || strchr(arg, '\t') != NULL;
    need = n + (quote ? 2u : 0u) + (*used ? 1u : 0u) + 1u;
    if (*used + need > cap)
        return false;
    if (*used)
        cmd[(*used)++] = ' ';
    if (quote)
        cmd[(*used)++] = '"';
    memcpy(cmd + *used, arg, n);
    *used += n;
    if (quote)
        cmd[(*used)++] = '"';
    cmd[*used] = 0;
    return true;
}
#endif

/* Run argv. On failure of the launcher itself return -1 and set
 * *exit_code to 127. Captured stdout+stderr is truncated to cap and the
 * first line is kept. */
static int run_cmd(char **argv, char *out, size_t cap, int *exit_code)
{
    if (exit_code != NULL)
        *exit_code = 127;
    if (out != NULL && cap > 0u)
        out[0] = 0;
    if (argv == NULL || argv[0] == NULL)
        return -1;
#if defined(_WIN32)
    {
        char cmdline[Z23_DOCTOR_PATH_MAX];
        size_t used = 0;
        FILE *fp;
        int i;
        int rc;
        cmdline[0] = 0;
        for (i = 0; argv[i] != NULL; i++) {
            if (!cmd_push(cmdline, sizeof cmdline, &used, argv[i]))
                return -1;
        }
        fp = _popen(cmdline, "r");
        if (fp == NULL)
            return -1;
        if (out != NULL && cap > 1u) {
            if (fgets(out, (int)cap, fp) == NULL)
                out[0] = 0;
            trim_first_line(out);
        } else {
            char sink[256];
            while (fgets(sink, sizeof sink, fp) != NULL) {
            }
        }
        rc = _pclose(fp);
        if (exit_code != NULL)
            *exit_code = rc;
        return 0;
    }
#else
    {
        int fds[2];
        pid_t pid;
        int st = 0;
        if (pipe(fds) != 0)
            return -1;
        pid = fork();
        if (pid < 0) {
            close(fds[0]);
            close(fds[1]);
            return -1;
        }
        if (pid == 0) {
            close(fds[0]);
            if (dup2(fds[1], 1) < 0 || dup2(fds[1], 2) < 0)
                _exit(127);
            close(fds[1]);
            execvp(argv[0], argv);
            _exit(127);
        }
        close(fds[1]);
        if (out != NULL && cap > 0u) {
            size_t n = 0;
            for (;;) {
                ssize_t r;
                if (n + 1u >= cap)
                    break;
                r = read(fds[0], out + n, cap - 1u - n);
                if (r <= 0)
                    break;
                n += (size_t)r;
            }
            out[n] = 0;
            trim_first_line(out);
        }
        close(fds[0]);
        if (waitpid(pid, &st, 0) < 0)
            return -1;
        if (exit_code != NULL) {
            if (WIFEXITED(st))
                *exit_code = WEXITSTATUS(st);
            else
                *exit_code = 127;
        }
        return 0;
    }
#endif
}

static void compiler_id(char **cc_argv, int cc_n, char *out, size_t cap)
{
    char *argv[Z23_DOCTOR_CC_WORDS + 4];
    int i;
    int rc = 127;
    if (cc_n <= 0 || cc_n > Z23_DOCTOR_CC_WORDS) {
        snprintf(out, cap, "%s", g_cc_raw);
        return;
    }
    for (i = 0; i < cc_n; i++)
        argv[i] = cc_argv[i];
    argv[cc_n] = "--version";
    argv[cc_n + 1] = NULL;
    if (run_cmd(argv, out, cap, &rc) != 0 || out[0] == 0)
        snprintf(out, cap, "%.200s", g_cc_raw);
}

static bool probe_std(char **cc_argv, int cc_n, const char *std,
                      const char *src, const char *obj)
{
    char *argv[Z23_DOCTOR_CC_WORDS + 8];
    char flag[32];
    int i;
    int rc = 127;
    if (cc_n <= 0 || cc_n > Z23_DOCTOR_CC_WORDS)
        return false;
    snprintf(flag, sizeof flag, "-std=%s", std);
    for (i = 0; i < cc_n; i++)
        argv[i] = cc_argv[i];
    argv[cc_n] = flag;
    argv[cc_n + 1] = "-c";
    argv[cc_n + 2] = (char *)src;
    argv[cc_n + 3] = "-o";
    argv[cc_n + 4] = (char *)obj;
    argv[cc_n + 5] = NULL;
    if (run_cmd(argv, NULL, 0, &rc) != 0)
        return false;
    return rc == 0;
}

static void temp_pair(char *src, size_t src_cap, char *obj, size_t obj_cap)
{
    const char *tmp = getenv("TMPDIR");
    unsigned long pid;
#if defined(_WIN32)
    char wtmp[MAX_PATH];
    pid = (unsigned long)GetCurrentProcessId();
    if (tmp == NULL || tmp[0] == 0) {
        if (GetTempPathA(sizeof wtmp, wtmp) > 0)
            tmp = wtmp;
        else
            tmp = ".";
    }
#else
    pid = (unsigned long)getpid();
    if (tmp == NULL || tmp[0] == 0)
        tmp = "/tmp";
#endif
    snprintf(src, src_cap, "%s/z23_doctor_%lu.c", tmp, pid);
    snprintf(obj, obj_cap, "%s/z23_doctor_%lu.o", tmp, pid);
}

static void inspect_dir(const char *path, bool *exists, bool *is_dir,
                        bool *has_git, bool *nonempty)
{
    char gitp[Z23_DOCTOR_PATH_MAX];
    *exists = false;
    *is_dir = false;
    *has_git = false;
    *nonempty = false;
    if (path == NULL || path[0] == 0)
        return;
#if defined(_WIN32)
    {
        DWORD attr = GetFileAttributesA(path);
        char glob[Z23_DOCTOR_PATH_MAX + 4];
        WIN32_FIND_DATAA fd;
        HANDLE h;
        if (attr == INVALID_FILE_ATTRIBUTES)
            return;
        *exists = true;
        *is_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (!*is_dir)
            return;
        if (join2(gitp, sizeof gitp, path, ".git"))
            *has_git = GetFileAttributesA(gitp) != INVALID_FILE_ATTRIBUTES;
        snprintf(glob, sizeof glob, "%s\\*", path);
        h = FindFirstFileA(glob, &fd);
        if (h == INVALID_HANDLE_VALUE)
            return;
        do {
            if (strcmp(fd.cFileName, ".") != 0
                && strcmp(fd.cFileName, "..") != 0) {
                *nonempty = true;
                break;
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    {
        struct stat st;
        DIR *d;
        struct dirent *ent;
        if (stat(path, &st) != 0)
            return;
        *exists = true;
        *is_dir = S_ISDIR(st.st_mode) != 0;
        if (!*is_dir)
            return;
        if (join2(gitp, sizeof gitp, path, ".git"))
            *has_git = access(gitp, F_OK) == 0;
        d = opendir(path);
        if (d == NULL)
            return;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") != 0
                && strcmp(ent->d_name, "..") != 0) {
                *nonempty = true;
                break;
            }
        }
        closedir(d);
    }
#endif
}

static void detect_pkg(void)
{
    char found[Z23_DOCTOR_PATH_MAX];
#if defined(_WIN32)
    if (find_prog("pacman", found, sizeof found)) {
        g_pkg = Z23_PKG_PACMAN;
        return;
    }
    g_pkg = Z23_PKG_WINGET;
#elif defined(__APPLE__)
    (void)found;
    g_pkg = Z23_PKG_BREW;
#else
    if (path_is_exec("/usr/bin/apt-get")
        || find_prog("apt-get", found, sizeof found)) {
        g_pkg = Z23_PKG_APT;
        return;
    }
    if (path_is_exec("/usr/bin/dnf")
        || find_prog("dnf", found, sizeof found)) {
        g_pkg = Z23_PKG_DNF;
        return;
    }
    if (path_is_exec("/usr/bin/pacman")
        || find_prog("pacman", found, sizeof found)) {
        g_pkg = Z23_PKG_PACMAN;
        return;
    }
    if (find_prog("brew", found, sizeof found)) {
        g_pkg = Z23_PKG_BREW;
        return;
    }
    g_pkg = Z23_PKG_UNKNOWN;
#endif
}

static void fix_compiler(char *out, size_t cap)
{
    switch (g_pkg) {
    case Z23_PKG_APT:
        snprintf(out, cap, "sudo apt-get install -y gcc-14 && make CC=gcc-14");
        break;
    case Z23_PKG_DNF:
        snprintf(out, cap, "sudo dnf install -y gcc && make CC=gcc");
        break;
    case Z23_PKG_PACMAN:
#if defined(_WIN32)
        snprintf(out, cap,
                 "pacman -S --needed mingw-w64-ucrt-x86_64-toolchain");
#else
        snprintf(out, cap, "sudo pacman -S --needed gcc && make CC=gcc");
#endif
        break;
    case Z23_PKG_BREW:
        snprintf(out, cap, "brew install gcc && make CC=gcc-14");
        break;
    case Z23_PKG_WINGET:
        snprintf(out, cap, "winget install -e --id MSYS2.MSYS2");
        break;
    case Z23_PKG_UNKNOWN:
    default:
        snprintf(out, cap,
                 "install gcc 14 or newer, then make CC=<that-compiler>");
        break;
    }
}

static void fix_git(char *out, size_t cap)
{
    switch (g_pkg) {
    case Z23_PKG_APT:
        snprintf(out, cap, "sudo apt-get install -y git");
        break;
    case Z23_PKG_DNF:
        snprintf(out, cap, "sudo dnf install -y git");
        break;
    case Z23_PKG_PACMAN:
#if defined(_WIN32)
        snprintf(out, cap, "pacman -S --needed git");
#else
        snprintf(out, cap, "sudo pacman -S --needed git");
#endif
        break;
    case Z23_PKG_BREW:
        snprintf(out, cap, "brew install git");
        break;
    case Z23_PKG_WINGET:
        snprintf(out, cap, "winget install -e --id Git.Git");
        break;
    default:
        snprintf(out, cap, "install git and put it on PATH");
        break;
    }
}

static void fix_make(char *out, size_t cap)
{
    switch (g_pkg) {
    case Z23_PKG_APT:
        snprintf(out, cap, "sudo apt-get install -y make");
        break;
    case Z23_PKG_DNF:
        snprintf(out, cap, "sudo dnf install -y make");
        break;
    case Z23_PKG_PACMAN:
#if defined(_WIN32)
        snprintf(out, cap, "pacman -S --needed make");
#else
        snprintf(out, cap, "sudo pacman -S --needed make");
#endif
        break;
    case Z23_PKG_BREW:
        snprintf(out, cap, "brew install make");
        break;
    case Z23_PKG_WINGET:
        snprintf(out, cap,
                 "winget install -e --id MSYS2.MSYS2  (then pacman -S make)");
        break;
    default:
        snprintf(out, cap, "install GNU make and put it on PATH");
        break;
    }
}

static void fix_mingw(char *out, size_t cap)
{
    switch (g_pkg) {
    case Z23_PKG_APT:
        snprintf(out, cap, "sudo apt-get install -y gcc-mingw-w64-x86-64");
        break;
    case Z23_PKG_DNF:
        snprintf(out, cap, "sudo dnf install -y mingw64-gcc");
        break;
    case Z23_PKG_PACMAN:
        snprintf(out, cap, "sudo pacman -S --needed mingw-w64-gcc");
        break;
    case Z23_PKG_BREW:
        snprintf(out, cap, "brew install mingw-w64");
        break;
    default:
        snprintf(out, cap,
                 "install x86_64-w64-mingw32-gcc for Windows syntax coverage");
        break;
    }
}

static void fix_ccache(char *out, size_t cap)
{
    switch (g_pkg) {
    case Z23_PKG_APT:
        snprintf(out, cap, "sudo apt-get install -y ccache");
        break;
    case Z23_PKG_DNF:
        snprintf(out, cap, "sudo dnf install -y ccache");
        break;
    case Z23_PKG_PACMAN:
#if defined(_WIN32)
        snprintf(out, cap, "pacman -S --needed ccache");
#else
        snprintf(out, cap, "sudo pacman -S --needed ccache");
#endif
        break;
    case Z23_PKG_BREW:
        snprintf(out, cap, "brew install ccache");
        break;
    default:
        snprintf(out, cap,
                 "install ccache, or build the in-tree cache with make zcc");
        break;
    }
}

static void json_escape(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', f);
            fputc((int)c, f);
        } else if (c == '\n') {
            fputs("\\n", f);
        } else if (c == '\r') {
            fputs("\\r", f);
        } else if (c == '\t') {
            fputs("\\t", f);
        } else if (c < 32u) {
            fprintf(f, "\\u%04x", (unsigned)c);
        } else {
            fputc((int)c, f);
        }
    }
    fputc('"', f);
}

static void resolve_root(const char *explicit_root)
{
    char cwd[Z23_DOCTOR_PATH_MAX];
    char cur[Z23_DOCTOR_PATH_MAX];
    char probe[Z23_DOCTOR_PATH_MAX];
    if (explicit_root != NULL && explicit_root[0] != 0) {
        snprintf(g_root_buf, sizeof g_root_buf, "%s", explicit_root);
        g_root = g_root_buf;
        return;
    }
    if (!get_cwd(cwd, sizeof cwd)) {
        snprintf(g_root_buf, sizeof g_root_buf, ".");
        g_root = g_root_buf;
        return;
    }
    snprintf(cur, sizeof cur, "%s", cwd);
    for (;;) {
        if (join2(probe, sizeof probe, cur, "tools/dev/z23_doctor.c")
            && path_exists(probe)) {
            snprintf(g_root_buf, sizeof g_root_buf, "%s", cur);
            g_root = g_root_buf;
            return;
        }
        {
            char *slash = strrchr(cur, '/');
#if defined(_WIN32)
            char *bslash = strrchr(cur, '\\');
            if (bslash != NULL && (slash == NULL || bslash > slash))
                slash = bslash;
#endif
            if (slash == NULL)
                break;
            if (slash == cur) {
#if !defined(_WIN32)
                if (cur[1] != 0) {
                    cur[1] = 0;
                    continue;
                }
#endif
                break;
            }
#if defined(_WIN32)
            if (slash == cur + 2 && cur[1] == ':')
                break;
#endif
            *slash = 0;
        }
    }
    snprintf(g_root_buf, sizeof g_root_buf, "%s", cwd);
    g_root = g_root_buf;
}

static void check_compiler(struct z23_check *c)
{
    char cc_copy[Z23_DOCTOR_PATH_MAX];
    char *words[Z23_DOCTOR_CC_WORDS];
    char found[Z23_DOCTOR_PATH_MAX];
    char ident[Z23_DOCTOR_TEXT_MAX];
    char detail[Z23_DOCTOR_TEXT_MAX];
    char fix[Z23_DOCTOR_TEXT_MAX];
    char src[Z23_DOCTOR_PATH_MAX];
    char obj[Z23_DOCTOR_PATH_MAX];
    int n;
    FILE *fp;
    const char *env = getenv("CC");
    snprintf(g_cc_raw, sizeof g_cc_raw, "%s",
             (env != NULL && env[0] != 0) ? env : "cc");
    snprintf(cc_copy, sizeof cc_copy, "%s", g_cc_raw);
    n = split_ws(cc_copy, words, Z23_DOCTOR_CC_WORDS);
    fix_compiler(fix, sizeof fix);
    if (n <= 0) {
        set_check(c, "compiler", "compiler", true, Z23_ST_MISSING,
                  "CC is empty", fix);
        return;
    }
    if (!find_prog(words[0], found, sizeof found)) {
        snprintf(detail, sizeof detail, "'%.80s' is not on PATH", words[0]);
        set_check(c, "compiler", "compiler", true, Z23_ST_MISSING, detail, fix);
        return;
    }
    temp_pair(src, sizeof src, obj, sizeof obj);
    fp = fopen(src, "w");
    if (fp == NULL) {
        snprintf(detail, sizeof detail,
                 "cannot write compiler probe: %s", strerror(errno));
        set_check(c, "compiler", "compiler", true, Z23_ST_BROKEN, detail, fix);
        return;
    }
    fclose(fp);
    compiler_id(words, n, ident, sizeof ident);
    if (probe_std(words, n, "c23", src, obj)) {
        snprintf(detail, sizeof detail, "%.200s accepts -std=c23", ident);
        set_check(c, "compiler", "compiler", true, Z23_ST_OK, detail, "");
    } else if (probe_std(words, n, "c2x", src, obj)) {
        snprintf(detail, sizeof detail,
                 "%.200s accepts -std=c2x but not -std=c23", ident);
        set_check(c, "compiler", "compiler", true, Z23_ST_TOO_OLD, detail, fix);
    } else {
        snprintf(detail, sizeof detail,
                 "%.200s accepts neither -std=c23 nor -std=c2x", ident);
        set_check(c, "compiler", "compiler", true, Z23_ST_BROKEN, detail, fix);
    }
    remove(src);
    remove(obj);
}

static void check_git(struct z23_check *c)
{
    char found[Z23_DOCTOR_PATH_MAX];
    char ver[Z23_DOCTOR_TEXT_MAX];
    char detail[Z23_DOCTOR_TEXT_MAX];
    char fix[Z23_DOCTOR_TEXT_MAX];
    char *argv[3];
    int rc = 127;
    fix_git(fix, sizeof fix);
    if (!find_prog("git", found, sizeof found)) {
        set_check(c, "git", "git", true, Z23_ST_MISSING, "not on PATH", fix);
        return;
    }
    argv[0] = found;
    argv[1] = "--version";
    argv[2] = NULL;
    if (run_cmd(argv, ver, sizeof ver, &rc) != 0 || ver[0] == 0)
        snprintf(ver, sizeof ver, "%.200s", found);
    snprintf(detail, sizeof detail, "%.200s", ver);
    set_check(c, "git", "git", true, Z23_ST_OK, detail, "");
}

static void check_vendor_tor(struct z23_check *c)
{
    char path[Z23_DOCTOR_PATH_MAX];
    bool exists = false;
    bool is_dir = false;
    bool has_git = false;
    bool nonempty = false;
    const char *fix = "git submodule update --init vendor/tor";
    if (!join2(path, sizeof path, g_root, "vendor/tor")) {
        set_check(c, "vendor/tor", "vendor_tor", true, Z23_ST_BROKEN,
                  "path too long", fix);
        return;
    }
    inspect_dir(path, &exists, &is_dir, &has_git, &nonempty);
    if (!exists) {
        set_check(c, "vendor/tor", "vendor_tor", true, Z23_ST_MISSING,
                  "empty (not initialized; the node would link stub Tor)",
                  fix);
        return;
    }
    if (!is_dir) {
        set_check(c, "vendor/tor", "vendor_tor", true, Z23_ST_BROKEN,
                  "exists but is not a directory", fix);
        return;
    }
    if (has_git) {
        set_check(c, "vendor/tor", "vendor_tor", true, Z23_ST_OK,
                  "initialized", "");
        return;
    }
    if (!nonempty) {
        set_check(c, "vendor/tor", "vendor_tor", true, Z23_ST_MISSING,
                  "empty (not initialized; the node would link stub Tor)",
                  fix);
        return;
    }
    /* THE BAD STATE: bytes but no .git. source-identity capture refuses,
     * so every build dies before a single test runs. */
    set_check(c, "vendor/tor", "vendor_tor", true, Z23_ST_BROKEN,
              "nonempty with no .git (exact source capture will refuse)",
              fix);
}

static void check_make_bin(struct z23_check *c)
{
    char found[Z23_DOCTOR_PATH_MAX];
    char ver[Z23_DOCTOR_TEXT_MAX];
    char fix[Z23_DOCTOR_TEXT_MAX];
    char *argv[3];
    int rc = 127;
    fix_make(fix, sizeof fix);
    if (!find_prog("make", found, sizeof found)) {
        set_check(c, "make", "make", true, Z23_ST_MISSING, "not on PATH", fix);
        return;
    }
    argv[0] = found;
    argv[1] = "--version";
    argv[2] = NULL;
    if (run_cmd(argv, ver, sizeof ver, &rc) != 0 || ver[0] == 0)
        snprintf(ver, sizeof ver, "%.200s", found);
    set_check(c, "make", "make", true, Z23_ST_OK, ver, "");
}

static void check_mingw(struct z23_check *c)
{
    char found[Z23_DOCTOR_PATH_MAX];
    char fix[Z23_DOCTOR_TEXT_MAX];
    fix_mingw(fix, sizeof fix);
    if (find_prog("x86_64-w64-mingw32-gcc", found, sizeof found)) {
        set_check(c, "mingw", "mingw", false, Z23_ST_OK, found, "");
        return;
    }
    set_check(c, "mingw", "mingw", false, Z23_ST_OPTIONAL,
              "x86_64-w64-mingw32-gcc not on PATH; Windows syntax coverage skips",
              fix);
}

static void check_ccache(struct z23_check *c)
{
    char found[Z23_DOCTOR_PATH_MAX];
    char fix[Z23_DOCTOR_TEXT_MAX];
    fix_ccache(fix, sizeof fix);
    if (find_prog("ccache", found, sizeof found)) {
        set_check(c, "ccache", "ccache", false, Z23_ST_OK, found, "");
        return;
    }
    set_check(c, "ccache", "ccache", false, Z23_ST_OPTIONAL,
              "not on PATH; builds work without it (slower)", fix);
}

static void check_zcc(struct z23_check *c)
{
    char src[Z23_DOCTOR_PATH_MAX];
    char bin[Z23_DOCTOR_PATH_MAX];
    char found[Z23_DOCTOR_PATH_MAX];
    if (join2(src, sizeof src, g_root, "tools/zcc.c") && path_exists(src)) {
        set_check(c, "zcc", "zcc", false, Z23_ST_OK,
                  "tools/zcc.c present (in-tree compile cache)", "");
        return;
    }
    if (join2(bin, sizeof bin, g_root, "build/bin/zcc") && path_is_exec(bin)) {
        set_check(c, "zcc", "zcc", false, Z23_ST_OK, bin, "");
        return;
    }
    if (find_prog("zcc", found, sizeof found)) {
        set_check(c, "zcc", "zcc", false, Z23_ST_OK, found, "");
        return;
    }
    set_check(c, "zcc", "zcc", false, Z23_ST_OPTIONAL,
              "in-tree compile cache not in this tree; builds work without it",
              "checkout the full tree (tools/zcc.c) or install ccache");
}

static void check_stack(struct z23_check *c)
{
#if defined(_WIN32)
    set_check(c, "stack", "stack", false, Z23_ST_OK,
              "no POSIX ulimit on Windows; PE default applies", "");
#else
    struct rlimit rl;
    char detail[Z23_DOCTOR_TEXT_MAX];
    const char *fix = "ulimit -s unlimited";
    if (getrlimit(RLIMIT_STACK, &rl) != 0) {
        snprintf(detail, sizeof detail,
                 "could not read RLIMIT_STACK: %s", strerror(errno));
        set_check(c, "stack", "stack", false, Z23_ST_OPTIONAL, detail, fix);
        return;
    }
    if (rl.rlim_cur == RLIM_INFINITY) {
        set_check(c, "stack", "stack", false, Z23_ST_OK, "unlimited", "");
        return;
    }
    /* Flagged, not required for exit: `make test-parallel` sets unlimited
     * itself. A developer shell at 8192 KiB is the Linux default and does
     * not stop a build. Direct `test_parallel` without that ulimit SIGSEGVs. */
    snprintf(detail, sizeof detail,
             "%llu KiB (full test suite needs unlimited)",
             (unsigned long long)(rl.rlim_cur / 1024u));
    set_check(c, "stack", "stack", false, Z23_ST_OPTIONAL, detail, fix);
#endif
}

static void check_cpus(struct z23_check *c)
{
    char detail[Z23_DOCTOR_TEXT_MAX];
    long n = 0;
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    n = (long)si.dwNumberOfProcessors;
#else
    n = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    if (n <= 0) {
        set_check(c, "cpus", "cpus", false, Z23_ST_OK, "unknown", "");
        return;
    }
    snprintf(detail, sizeof detail, "%ld logical CPUs", n);
    set_check(c, "cpus", "cpus", false, Z23_ST_OK, detail, "");
}

static void check_disk(struct z23_check *c)
{
    char detail[Z23_DOCTOR_TEXT_MAX];
    uint64_t bytes = 0;
#if defined(_WIN32)
    ULARGE_INTEGER avail;
    if (!GetDiskFreeSpaceExA(g_root, &avail, NULL, NULL)) {
        set_check(c, "disk", "disk", false, Z23_ST_OPTIONAL,
                  "could not measure free disk", "");
        return;
    }
    bytes = (uint64_t)avail.QuadPart;
#else
    struct statvfs fs;
    if (statvfs(g_root, &fs) != 0) {
        snprintf(detail, sizeof detail, "could not measure free disk: %s",
                 strerror(errno));
        set_check(c, "disk", "disk", false, Z23_ST_OPTIONAL, detail, "");
        return;
    }
    bytes = (uint64_t)fs.f_bavail * (uint64_t)fs.f_frsize;
#endif
    if (bytes >= 1024ull * 1024ull * 1024ull) {
        snprintf(detail, sizeof detail, "%.1f GiB free in working tree",
                 (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else {
        snprintf(detail, sizeof detail, "%.1f MiB free in working tree",
                 (double)bytes / (1024.0 * 1024.0));
    }
    set_check(c, "disk", "disk", false, Z23_ST_OK, detail, "");
}

static bool required_ok(const struct z23_check *checks, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        if (checks[i].required && checks[i].status != Z23_ST_OK)
            return false;
    }
    return true;
}

static void print_text(const struct z23_check *checks, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        const struct z23_check *c = &checks[i];
        printf("%-8s  %-12s  %s", status_word(c->status), c->name, c->detail);
        if (c->status != Z23_ST_OK && c->fix[0] != 0)
            printf(" | %s", c->fix);
        printf("\n");
    }
}

static bool compiler_c23_ok(const struct z23_check *c)
{
    return c->status == Z23_ST_OK;
}

static uint64_t disk_bytes_for_json(void)
{
#if defined(_WIN32)
    ULARGE_INTEGER avail;
    if (!GetDiskFreeSpaceExA(g_root, &avail, NULL, NULL))
        return 0;
    return (uint64_t)avail.QuadPart;
#else
    struct statvfs fs;
    if (statvfs(g_root, &fs) != 0)
        return 0;
    return (uint64_t)fs.f_bavail * (uint64_t)fs.f_frsize;
#endif
}

static long cpu_count_for_json(void)
{
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (long)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 0;
#endif
}

static void print_json(const struct z23_check *checks, int n, bool ok)
{
    int i;
    printf("{\n");
    printf("  \"ok\": %s,\n", ok ? "true" : "false");
    printf("  \"platform\": ");
    json_escape(stdout, platform_name());
    printf(",\n");
    printf("  \"root\": ");
    json_escape(stdout, g_root);
    printf(",\n");
    printf("  \"cc\": ");
    json_escape(stdout, g_cc_raw);
    printf(",\n");
    printf("  \"compiler_c23\": %s,\n",
           compiler_c23_ok(&checks[0]) ? "true" : "false");
    printf("  \"cpu_count\": %ld,\n", cpu_count_for_json());
    printf("  \"disk_free_bytes\": %llu",
           (unsigned long long)disk_bytes_for_json());
    for (i = 0; i < n; i++) {
        const struct z23_check *c = &checks[i];
        char st_key[64];
        char det_key[64];
        char fix_key[64];
        printf(",\n");
        snprintf(st_key, sizeof st_key, "%s_status", c->json_key);
        snprintf(det_key, sizeof det_key, "%s", c->json_key);
        snprintf(fix_key, sizeof fix_key, "%s_fix", c->json_key);
        printf("  ");
        json_escape(stdout, st_key);
        printf(": ");
        json_escape(stdout, status_word(c->status));
        printf(",\n");
        printf("  ");
        json_escape(stdout, det_key);
        printf(": ");
        json_escape(stdout, c->detail);
        printf(",\n");
        printf("  ");
        json_escape(stdout, fix_key);
        printf(": ");
        json_escape(stdout, c->fix);
    }
    printf("\n}\n");
}

static void usage(FILE *f)
{
    fprintf(f,
            "usage: z23_doctor [--input=json] [--root=DIR]\n"
            "  Diagnose the C23 build environment without depending on it.\n"
            "  --input=json  emit one flat JSON object\n"
            "  --root=DIR    inspect this tree (default: this checkout)\n");
}

int main(int argc, char **argv)
{
    struct z23_check checks[10];
    const char *root_arg = NULL;
    bool json = false;
    bool ok;
    int i;
    int n;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--input=json") == 0) {
            json = true;
        } else if (strncmp(argv[i], "--root=", 7) == 0) {
            root_arg = argv[i] + 7;
        } else if (strcmp(argv[i], "--help") == 0
                   || strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "z23_doctor: unknown argument: %s\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

    resolve_root(root_arg);
    detect_pkg();

    check_compiler(&checks[0]);
    check_git(&checks[1]);
    check_vendor_tor(&checks[2]);
    check_make_bin(&checks[3]);
    check_mingw(&checks[4]);
    check_ccache(&checks[5]);
    check_zcc(&checks[6]);
    check_stack(&checks[7]);
    check_cpus(&checks[8]);
    check_disk(&checks[9]);
    n = 10;

    ok = required_ok(checks, n);
    if (json)
        print_json(checks, n, ok);
    else
        print_text(checks, n);
    return ok ? 0 : 1;
}
