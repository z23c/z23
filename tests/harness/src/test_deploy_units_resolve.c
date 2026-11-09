/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Deploy-unit resolution. Every systemd unit tracked under platform/deploy/
 * must name only things that still exist: no retired %h/github/z23 checkout,
 * no build/bin target the Makefile does not produce, no untracked repo file,
 * and no z23 / z23-dev subcommand absent from the command catalog. A unit that
 * fails this check starts under systemd and dies at run time, so the failure
 * is reported here, at review time, as unit:line: reason. */

#include "test/test_core.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <dirent.h>
#include <sys/stat.h>
#endif
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

enum {
    DU_TRACKED_CAP = 1 << 20,
    DU_FILE_CAP = 16 << 20,
    DU_LOGICAL_CAP = 4096,
    DU_MAX_TOKENS = 1024,
    DU_MAX_WORDS = 8,
    DU_PATH_CAP = 512,
};

static const char k_du_deploy[] = "platform/deploy/";
static const char k_du_main[] = "%h/development/z23/main/";
/* Matches both %h/github/z23 and $HOME/github/z23 (and $$HOME in a unit). */
static const char k_du_retired[] = "github/z23";
static const char k_du_bin[] = "build/bin/";
static const char k_du_bin_dir[] = "$(BIN_DIR)/";
/* The install targets rewrite the units' live prefix to the checkout. */
static const char k_du_live_sed[] =
    "sed 's|%h/development/z23/main|$(CURDIR)|g'";
static const char k_du_retired_sed[] = "sed 's|%h/github/z23|";

/* Binaries the Makefile does not build, each with the doc that builds it. A
 * unit may name one only while that doc exists and still names the binary. */
struct du_exempt {
    const char *bin;
    const char *doc;
};

static const struct du_exempt k_du_exempt[] = {
    {"zcl-fleet-front", "platform/deploy/fleet-gateway/README.md"},
};

struct du_ctx {
    char *tracked_buf;
    char *makefile;
    size_t units;
    int failures;
};

static void du_fail(struct du_ctx *c, const char *unit, unsigned line,
                    const char *reason, const char *detail)
{
    fprintf(stderr, "%s:%u: %s: %s\n", unit, line, reason, detail);
    c->failures++;
}

static bool du_read_file(const char *path, char **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    bool ok = false;
    long sz = -1;
    char *buf = NULL;
    size_t got = 0;

    if (!f)
        return false;
    if (fseek(f, 0, SEEK_END) == 0)
        sz = ftell(f);
    if (sz >= 0 && sz < DU_FILE_CAP && fseek(f, 0, SEEK_SET) == 0) {
        buf = malloc((size_t)sz + 1);
        if (buf) {
            got = fread(buf, 1, (size_t)sz, f);
            buf[got] = '\0';
            ok = got == (size_t)sz;
        }
    }
    (void)fclose(f);
    if (!ok) {
        free(buf);
        return false;
    }
    *out = buf;
    *len = got;
    return true;
}

#if defined(__linux__)
static bool du_fixture_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    return ok && chmod(path, mode) == 0;
}

static int du_fixture_entries(const char *path, char *unit, size_t cap)
{
    DIR *d = opendir(path);
    if (!d) return -1;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        count++;
        if (strncmp(e->d_name, "z23-citest.", 11) == 0 &&
            strstr(e->d_name, ".service") && strcmp(e->d_name, "z23-citest.service") != 0)
            (void)snprintf(unit, cap, "%s/%s", path, e->d_name);
    }
    if (closedir(d) != 0) return -1;
    return count;
}

static bool du_fixture_tmp_path(const char *path, const char *prefix)
{
    size_t n = strlen(prefix);
    if (strncmp(path, prefix, n) != 0 || strlen(path + n) != 6) return false;
    for (const unsigned char *p = (const unsigned char *)path + n; *p; p++)
        if (!isalnum(*p)) return false;
    return true;
}

/* The fake service never starts a process; remove only the exact mktemp
 * directories named by its captured output and its retained unit. */
static bool du_fixture_retained_cleanup(const char *output, const char *unit,
                                        const char *root)
{
    const char *p = strstr(output, "make install -> ");
    char prefix[512], datadir[512], expected_prefix[600], expected_datadir[600];
    char *body = NULL, discard[256]; size_t n = 0;
    if (snprintf(expected_prefix, sizeof(expected_prefix), "%s/zcl-linger-prefix.", root) >= (int)sizeof(expected_prefix) ||
        snprintf(expected_datadir, sizeof(expected_datadir), "%s/zcl-linger-dd.", root) >= (int)sizeof(expected_datadir)) return false;
    if (!p || sscanf(p, "make install -> %511s", prefix) != 1 ||
        !du_fixture_tmp_path(prefix, expected_prefix) ||
        !du_read_file(unit, &body, &n)) return false;
    const char *d = strstr(body, "-datadir=");
    struct stat prefix_st, datadir_st;
    bool ok = d && sscanf(d, "-datadir=%511s", datadir) == 1 &&
              du_fixture_tmp_path(datadir, expected_datadir) &&
              stat(prefix, &prefix_st) == 0 && S_ISDIR(prefix_st.st_mode) &&
              stat(datadir, &datadir_st) == 0 && S_ISDIR(datadir_st.st_mode);
    if (ok) {
        const char *argv[] = {"/bin/rm", "-rf", "--", prefix, datadir, NULL};
        ok = zcl_spawn_capture(argv, discard, sizeof(discard), 10000) == 0;
    }
    free(body);
    return ok;
}

struct du_linger_fixture {
    char dir[512], bin[600], config[600], user[700], sentinel[800];
    char log[700], pathenv[800], cfgenv[700], logenv[800], tmpenv[600];
};

static bool du_linger_setup(struct du_linger_fixture *f)
{
    char sys[700], make[700], journal[700];
    static const char systemctl_stub[] =
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_LOG\"\n"
        "case \"$2\" in\n"
        "show-environment|daemon-reload) exit 0;;\n"
        "stop) [ \"$FAKE_MODE\" != stopfail ]; exit $?;;\n"
        "show) case \"$*\" in *LoadState*) [ \"$FAKE_MODE\" = loaded ] && echo loaded || echo not-found;; *ActiveState*) echo inactive;; *MainPID*) echo 0;; esac; exit 0;;\n"
        "start) f=\"$XDG_CONFIG_HOME/systemd/user/$3.service\"; d=$(sed -n 's/.*-datadir=\\([^ ]*\\).*/\\1/p' \"$f\"); : > \"$d/.cookie\"; exit 0;;\n"
        "is-active) echo active; exit 0;; esac\nexit 1\n";
    static const char make_stub[] =
        "#!/bin/sh\n[ \"$FAKE_MODE\" = early ] && exit 1\n"
        "for a do case \"$a\" in DESTDIR=*) p=${a#DESTDIR=};; esac; done\n"
        "mkdir -p \"$p/bin\" || exit 1\n"
        "printf '#!/bin/sh\\nexit 0\\n' > \"$p/bin/zclassic23\"\n"
        "printf '#!/bin/sh\\necho 0\\n' > \"$p/bin/zcl-rpc\"\n"
        "chmod 755 \"$p/bin/zclassic23\" \"$p/bin/zcl-rpc\"\n";
    if (!test_mkdtemp(f->dir, sizeof(f->dir), "linger_unit")) return false;
    snprintf(f->bin, sizeof(f->bin), "%s/bin", f->dir);
    snprintf(f->config, sizeof(f->config), "%s/config", f->dir);
    snprintf(f->user, sizeof(f->user), "%s/systemd", f->config);
    bool ok = mkdir(f->bin, 0700) == 0 && mkdir(f->config, 0700) == 0 && mkdir(f->user, 0700) == 0;
    snprintf(f->user, sizeof(f->user), "%s/systemd/user", f->config);
    ok = ok && mkdir(f->user, 0700) == 0;
    snprintf(f->sentinel, sizeof(f->sentinel), "%s/z23-citest.service", f->user);
    snprintf(sys, sizeof(sys), "%s/systemctl", f->bin);
    snprintf(make, sizeof(make), "%s/make", f->bin);
    snprintf(journal, sizeof(journal), "%s/journalctl", f->bin);
    snprintf(f->log, sizeof(f->log), "%s/calls", f->dir);
    ok = ok && du_fixture_write(f->sentinel, "original\n", 0600) &&
         du_fixture_write(sys, systemctl_stub, 0700) && du_fixture_write(make, make_stub, 0700) &&
         du_fixture_write(journal, "#!/bin/sh\nexit 0\n", 0700);
    snprintf(f->pathenv, sizeof(f->pathenv), "PATH=%s:/usr/bin:/bin", f->bin);
    snprintf(f->cfgenv, sizeof(f->cfgenv), "XDG_CONFIG_HOME=%s", f->config);
    snprintf(f->logenv, sizeof(f->logenv), "FAKE_LOG=%s", f->log);
    snprintf(f->tmpenv, sizeof(f->tmpenv), "TMPDIR=%s", f->dir);
    return ok;
}

static bool du_linger_stop_failure(int rc, int entries, const char *output,
                                   const char *calls, const char *unit,
                                   const char *dir)
{
    bool retained = rc == 1 && !strstr(output, "PASSED") &&
                    strstr(output, "unit stop failed; retaining fixture") &&
                    strstr(calls, "--user stop z23-citest.") && entries == 3 && unit[0];
    bool cleaned = unit[0] && du_fixture_retained_cleanup(output, unit, dir);
    return retained && cleaned;
}

static bool du_linger_result(size_t i, int rc, int entries, const char *output,
                             const char *calls, const char *unit, const char *dir)
{
    if (i < 2) return rc == 1 && entries == 1 && !strstr(calls, "--user stop") && !strstr(calls, "--user disable");
    if (i == 2) return rc == 0 && entries == 1 && strstr(output, "PASSED") && strstr(calls, "--user stop z23-citest.");
    return du_linger_stop_failure(rc, entries, output, calls, unit, dir);
}

/* Exercise the actual linger script with a private config and stub commands.
 * Neither stub contacts systemd or starts a node. */
static void du_check_linger_fixture(struct du_ctx *c)
{
    struct du_linger_fixture f;
    bool ok = du_linger_setup(&f);
    const char *modes[] = {"FAKE_MODE=early", "FAKE_MODE=loaded", "FAKE_MODE=success", "FAKE_MODE=stopfail"};
    for (size_t i = 0; ok && i < sizeof(modes) / sizeof(modes[0]); i++) {
        char output[4096];
        ok = du_fixture_write(f.log, "", 0600);
        const char *argv[] = {"/usr/bin/env", f.pathenv, f.cfgenv, f.logenv, f.tmpenv, modes[i],
                              "bash", "tools/scripts/ci_install_linger_gate.sh", NULL};
        int rc = zcl_spawn_capture_merged_observed(argv, output, sizeof(output), 60000, NULL);
        char *contents = NULL, *calls = NULL; size_t n = 0;
        ok = ok && du_read_file(f.sentinel, &contents, &n) && strcmp(contents, "original\n") == 0 &&
             du_read_file(f.log, &calls, &n);
        char unit[1024] = "";
        int entries = du_fixture_entries(f.user, unit, sizeof(unit));
        if (ok) ok = du_linger_result(i, rc, entries, output, calls, unit, f.dir);
        free(contents); free(calls);
    }
    if (!ok) du_fail(c, "ci_install_linger_gate.sh", 0, "unit ownership fixture failed", "");
}
#endif

/* Runs `git ls-files` in the cwd and captures stdout into out. Returns false
 * on any failure, including output that fills the whole buffer (truncated). */
static bool du_capture_git(char *out, size_t cap)
{
#if defined(_WIN32)
    (void)out;
    (void)cap;
    return false;
#else
    int pipefd[2];
    size_t got = 0;
    int status = 0;
    pid_t pid;

    if (pipe(pipefd) != 0)
        return false;
    pid = fork();
    if (pid < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return false;
    }
    if (pid == 0) {
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        execlp("git", "git", "ls-files", (char *)NULL);
        _exit(127);
    }
    (void)close(pipefd[1]);
    while (got < cap - 1) {
        ssize_t r = read(pipefd[0], out + got, cap - 1 - got);

        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    out[got] = '\0';
    (void)close(pipefd[0]);
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return false;
    return got + 1 < cap;
#endif
}

/* `git ls-files` is the tracked-tree source of truth: a file that exists in
 * the worktree but is not tracked does not exist for a deployed unit. */
static bool du_load_tracked(struct du_ctx *c)
{
    c->tracked_buf = malloc(DU_TRACKED_CAP);
    if (!c->tracked_buf)
        return false;
    if (!du_capture_git(c->tracked_buf, DU_TRACKED_CAP))
        return false;
    return c->tracked_buf[0] != '\0';
}

/* Length of the newline-terminated line at p (the whole rest when unterminated). */
static size_t du_line_len(const char *p)
{
    const char *nl = strchr(p, '\n');

    return nl ? (size_t)(nl - p) : strlen(p);
}

/* Scans the captured listing in place, so the tracked tree has no entry cap. */
static bool du_is_tracked(const struct du_ctx *c, const char *rel)
{
    const char *p = c->tracked_buf;
    size_t n = strlen(rel);

    while (*p) {
        size_t len = du_line_len(p);

        if (len == n && memcmp(p, rel, n) == 0)
            return true;
        p += len;
        if (*p == '\n')
            p++;
    }
    return false;
}

static bool du_is_unit(const char *path)
{
    size_t n = strlen(path);

    if (strncmp(path, k_du_deploy, sizeof k_du_deploy - 1) != 0)
        return false;
    return (n > 8 && strcmp(path + n - 8, ".service") == 0) ||
           (n > 6 && strcmp(path + n - 6, ".timer") == 0);
}

static bool du_name_char(char ch)
{
    return isalnum((unsigned char)ch) || ch == '-' || ch == '_' || ch == '.';
}

static bool du_mk_has_at(const char *mk, const char *prefix, const char *name)
{
    size_t nl = strlen(name);
    const char *p = mk;

    while ((p = strstr(p, prefix)) != NULL) {
        const char *q = p + strlen(prefix);

        if (strncmp(q, name, nl) == 0 && !du_name_char(q[nl]))
            return true;
        p = q;
    }
    return false;
}

static bool du_mk_has_bin(const struct du_ctx *c, const char *name)
{
    return du_mk_has_at(c->makefile, k_du_bin_dir, name) ||
           du_mk_has_at(c->makefile, k_du_bin, name);
}

static bool du_leaf_exists(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();

    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return true;
    return false;
}

/* The CLI words join with '.' into a catalog path. The unit is valid when some
 * prefix of the words is a catalog row; the longest such prefix is the leaf
 * the invocation resolves to, and a trailing argument that is not a
 * subcommand is the leaf's own input, not a reason to refuse. */
static bool du_prefix_leaf(const char *const *words, int n)
{
    char path[DU_PATH_CAP];
    size_t len = 0;
    bool found = false;

    for (int q = 0; q < n; q++) {
        int w;

        w = snprintf(path + len, sizeof path - len, "%s%s",
                     q ? "." : "", words[q]);
        if (w < 0 || (size_t)w >= sizeof path - len)
            return false;
        len += (size_t)w;
        if (du_leaf_exists(path))
            found = true;
    }
    return found;
}

/* True when the exception's doc exists and names build/bin/<name>. */
static bool du_doc_names(const char *doc, const char *name)
{
    char needle[DU_PATH_CAP];
    char *text = NULL;
    size_t len = 0;
    bool found = false;
    int w;

    w = snprintf(needle, sizeof needle, "%s%s", k_du_bin, name);
    if (w < 0 || (size_t)w >= sizeof needle)
        return false;
    if (!du_read_file(doc, &text, &len))
        return false;
    found = strstr(text, needle) != NULL;
    free(text);
    return found;
}

static bool du_bin_exempt(const char *name)
{
    for (size_t i = 0; i < sizeof k_du_exempt / sizeof k_du_exempt[0]; i++)
        if (strcmp(name, k_du_exempt[i].bin) == 0)
            return du_doc_names(k_du_exempt[i].doc, name);
    return false;
}

static void du_check_path(struct du_ctx *c, const char *unit, unsigned line,
                          const char *tok)
{
    const char *rel;
    size_t n;
    char name[DU_PATH_CAP];

    if (strncmp(tok, k_du_main, sizeof k_du_main - 1) != 0)
        return;
    rel = tok + sizeof k_du_main - 1;
    if (strncmp(rel, k_du_bin, sizeof k_du_bin - 1) == 0) {
        n = strcspn(rel + sizeof k_du_bin - 1, "/");
        if (n == 0 || n >= sizeof name) {
            du_fail(c, unit, line, "malformed build/bin path", tok);
            return;
        }
        memcpy(name, rel + sizeof k_du_bin - 1, n);
        name[n] = '\0';
        if (!du_mk_has_bin(c, name) && !du_bin_exempt(name))
            du_fail(c, unit, line,
                    "not a Makefile BIN target or documented exception", tok);
        return;
    }
    if (!du_is_tracked(c, rel))
        du_fail(c, unit, line, "untracked repo path", tok);
}

static void du_check_leaf(struct du_ctx *c, const char *unit, unsigned line,
                           char *const *toks, int n, int i)
{
    const char *base = strrchr(toks[i], '/');
    const char *words[DU_MAX_WORDS];
    int nw = 0;

    base = base ? base + 1 : toks[i];
    if (strcmp(base, "z23") != 0 && strcmp(base, "z23-dev") != 0)
        return;
    for (int j = i + 1; j < n && nw < DU_MAX_WORDS && toks[j][0] != '-'; j++)
        words[nw++] = toks[j];
    if (nw == 0)
        return; /* node launch: flags only, no subcommand leaf to resolve */
    if (!du_prefix_leaf(words, nw))
        du_fail(c, unit, line, "no command leaf", toks[i]);
}

/* Drops quote and backslash characters in place, then splits on blanks. */
static int du_tokenize(char *s, char **toks, int max)
{
    char *r = s, *w = s;
    char *p = s;
    int n = 0;

    for (; *r; r++)
        if (*r != '\'' && *r != '"' && *r != '\\')
            *w++ = *r;
    *w = '\0';
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        if (n == max)
            return -1;
        toks[n++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (*p)
            *p++ = '\0';
    }
    return n;
}

static void du_check_logical(struct du_ctx *c, const char *unit,
                             unsigned line, char *text)
{
    char *toks[DU_MAX_TOKENS];
    int n = du_tokenize(text, toks, DU_MAX_TOKENS);

    if (n < 0) {
        du_fail(c, unit, line, "too many tokens in Exec line", text);
        return;
    }
    for (int i = 0; i < n; i++) {
        du_check_path(c, unit, line, toks[i]);
        du_check_leaf(c, unit, line, toks, n, i);
    }
}

static char *du_next_line(char **cur)
{
    char *s = *cur;
    char *nl;

    if (!s || !*s)
        return NULL;
    nl = strchr(s, '\n');
    if (nl) {
        *nl = '\0';
        *cur = nl + 1;
    } else {
        *cur = s + strlen(s);
    }
    return s;
}

/* Returns the value of an Exec*= line with systemd's leading prefix
 * characters (-, @, +, !, :) removed, or NULL for any other line. */
static char *du_exec_value(char *line)
{
    char *p = line;

    if (strncmp(line, "Exec", 4) != 0)
        return NULL;
    p += 4;
    while (isalpha((unsigned char)*p))
        p++;
    if (*p != '=')
        return NULL;
    p++;
    while (*p && strchr("-@+!:", *p))
        p++;
    return p;
}

static bool du_ends_backslash(const char *s)
{
    size_t n = strlen(s);

    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        n--;
    return n > 0 && s[n - 1] == '\\';
}

static bool du_append(char *dst, size_t cap, size_t *len, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap - *len)
        return false;
    memcpy(dst + *len, src, n + 1);
    *len += n;
    return true;
}

/* Joins a backslash-continued Exec value into one logical line. */
static void du_check_exec(struct du_ctx *c, const char *unit, unsigned start,
                          char *value, char **cur, unsigned *lineno)
{
    char logical[DU_LOGICAL_CAP];
    size_t len = 0;
    char *piece = value;

    logical[0] = '\0';
    for (;;) {
        if (!du_append(logical, sizeof logical, &len, piece)) {
            du_fail(c, unit, start, "Exec line too long", "");
            return;
        }
        if (!du_ends_backslash(piece))
            break;
        piece = du_next_line(cur);
        if (!piece)
            break;
        (*lineno)++;
        if (!du_append(logical, sizeof logical, &len, " ")) {
            du_fail(c, unit, start, "Exec line too long", "");
            return;
        }
    }
    du_check_logical(c, unit, start, logical);
}

static void du_check_unit(struct du_ctx *c, const char *unit, char *text)
{
    char *cur = text;
    char *line;
    unsigned lineno = 0;

    while ((line = du_next_line(&cur)) != NULL) {
        char *value;

        lineno++;
        value = du_exec_value(line);
        if (value)
            du_check_exec(c, unit, lineno, value, &cur, &lineno);
    }
}

static bool du_span_has(const char *s, size_t len, const char *needle)
{
    size_t nl = strlen(needle);

    for (size_t i = 0; i + nl <= len; i++)
        if (memcmp(s + i, needle, nl) == 0)
            return true;
    return false;
}

/* Scans every non-comment line of the raw unit text, not just Exec values, so
 * WorkingDirectory, ReadWritePaths and shell strings inside Exec are covered.
 * Reads the buffer without splitting it, so du_check_unit still sees it whole. */
static void du_check_retired(struct du_ctx *c, const char *unit,
                             const char *text)
{
    const char *p = text;
    unsigned lineno = 1;

    while (*p) {
        const char *nl = strchr(p, '\n');
        const char *first = p + strspn(p, " \t");
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        if (*first != '#' && *first != ';' && first < p + len &&
            du_span_has(p, len, k_du_retired))
            du_fail(c, unit, lineno, "retired checkout", k_du_retired);
        if (!nl)
            break;
        p = nl + 1;
        lineno++;
    }
}

static void du_check_file(struct du_ctx *c, const char *unit)
{
    char *text = NULL;
    size_t len = 0;

    if (!du_read_file(unit, &text, &len)) {
        du_fail(c, unit, 0, "unreadable unit file", "");
        return;
    }
    c->units++;
    du_check_retired(c, unit, text);
    du_check_unit(c, unit, text);
    free(text);
}

static void du_check_all(struct du_ctx *c)
{
    const char *p = c->tracked_buf;

    while (*p) {
        size_t len = du_line_len(p);
        char path[DU_PATH_CAP];

        if (len >= sizeof path) {
            du_fail(c, "git ls-files", 0, "tracked path too long", "");
        } else {
            memcpy(path, p, len);
            path[len] = '\0';
            if (du_is_unit(path))
                du_check_file(c, path);
        }
        p += len;
        if (*p == '\n')
            p++;
    }
}

/* The installers must rewrite the prefix the units carry, not a retired one. */
static void du_check_installers(struct du_ctx *c)
{
    if (strstr(c->makefile, k_du_retired_sed) != NULL)
        du_fail(c, "Makefile", 0, "installer sed targets retired checkout",
                k_du_retired);
    if (strstr(c->makefile, k_du_live_sed) == NULL)
        du_fail(c, "Makefile", 0, "installer sed misses unit prefix",
                k_du_main);
}

int test_deploy_units_resolve(void)
{
    static struct du_ctx ctx;
    size_t mk_len = 0;

    if (!du_load_tracked(&ctx)) {
        fprintf(stderr, "deploy_units_resolve: git ls-files unavailable\n");
        free(ctx.tracked_buf);
        return 1;
    }
    if (!du_read_file("Makefile", &ctx.makefile, &mk_len)) {
        fprintf(stderr, "deploy_units_resolve: Makefile unreadable\n");
        free(ctx.tracked_buf);
        return 1;
    }
    du_check_installers(&ctx);
    du_check_all(&ctx);
#if defined(__linux__)
    du_check_linger_fixture(&ctx);
#endif
    if (ctx.units == 0) {
        fprintf(stderr, "deploy_units_resolve: no tracked deploy units\n");
        ctx.failures++;
    }
    if (ctx.failures == 0)
        printf("test_deploy_units_resolve: all passed (%zu units)\n", ctx.units);
    else
        printf("test_deploy_units_resolve: %d FAILED\n", ctx.failures);
    free(ctx.makefile);
    free(ctx.tracked_buf);
    return ctx.failures;
}
