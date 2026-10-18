/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-fx: run one command on one machine, or on all machines, of a
 * maintainer's fleet over SSH.
 *
 *   z23-fx [--config=PATH] [--print-argv] HOST|all|@ROLE 'command'
 *
 * Machines come from ~/.config/z23/fleet.json (see
 * docs/fleet-dev/fleet.example.json). The command is passed to ssh as ONE
 * argument; no local shell ever sees it. A single host inherits stdin and
 * stdout. "all" and "@ROLE" run in parallel and print each machine's output
 * prefixed by "name | ". The exit status is the largest status of any
 * machine; configuration and usage errors exit 2.
 * Names are checked with isalnum in the default C locale; the tool never
 * calls setlocale.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "base/safe_alloc.h"
#include "json/json.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FX_MAX_HOSTS 64
#define FX_MAX_ROLES 8
#define FX_NAME_MAX 32
#define FX_ALIAS_MAX 256
#define FX_CFG_MAX (64 * 1024)
#define FX_CMD_MAX (64 * 1024)
#define FX_OUT_CAP (1024 * 1024)
#define FX_SOCK_PATH_MAX 104
#define FX_ARGV_MAX 20
#define FX_USAGE_EXIT 2

struct fx_host {
    char name[FX_NAME_MAX + 1];
    char ssh[FX_ALIAS_MAX + 1];
    char roles[FX_MAX_ROLES][FX_NAME_MAX + 1];
    size_t nroles;
};

struct fx_cfg {
    struct fx_host host[FX_MAX_HOSTS];
    size_t n;
};

struct fx_argv {
    const char *v[FX_ARGV_MAX];
};

struct fx_job {
    pid_t pid;
    int fd;
    char *buf;
    size_t len;
    bool truncated;
    int rc;
};

static const char *const FX_OPTIONS[] = {
    "BatchMode=yes",        "ConnectTimeout=8",
    "ControlMaster=auto",   "ControlPersist=30m",
    "ServerAliveInterval=15", "LogLevel=ERROR",
};

static void usage(FILE *to)
{
    fputs("usage: z23-fx [--config=PATH] [--print-argv] HOST|all|@ROLE 'command'\n"
          "Runs the command on a machine named in ~/.config/z23/fleet.json.\n"
          "Example file: docs/fleet-dev/fleet.example.json\n", to);
}

static bool token_ok(const char *s, size_t max, const char *extra)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > max || !isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && !strchr(extra, s[i])) return false;
    return true;
}

static bool has_role(const struct fx_host *h, const char *role)
{
    for (size_t i = 0; i < h->nroles; i++)
        if (strcmp(h->roles[i], role) == 0) return true;
    return false;
}

static bool read_file(const char *path, char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    *len = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && fgetc(f) == EOF;
    fclose(f);
    buf[*len] = '\0';
    return ok;
}

static bool copy_str(char *dst, size_t cap, const struct json_value *v)
{
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!s || strlen(s) >= cap) return false;
    memcpy(dst, s, strlen(s) + 1);
    return true;
}

static bool parse_roles(const struct json_value *arr, struct fx_host *h)
{
    if (!arr) return true;
    size_t n = arr->type == JSON_ARR ? json_size(arr) : FX_MAX_ROLES + 1;
    if (n > FX_MAX_ROLES) return false;
    for (size_t i = 0; i < n; i++) {
        if (!copy_str(h->roles[i], sizeof h->roles[i], json_at(arr, i)) ||
            !token_ok(h->roles[i], FX_NAME_MAX, "_-"))
            return false;
        h->nroles++;
    }
    return true;
}

static bool parse_host(const struct json_value *o, struct fx_host *h)
{
    if (!o || o->type != JSON_OBJ) return false;
    if (!copy_str(h->name, sizeof h->name, json_get(o, "name")) ||
        !copy_str(h->ssh, sizeof h->ssh, json_get(o, "ssh")))
        return false;
    if (!token_ok(h->name, FX_NAME_MAX, "_-") || strcmp(h->name, "all") == 0)
        return false;
    if (!token_ok(h->ssh, FX_ALIAS_MAX, "_.@:%+=-")) return false;
    return parse_roles(json_get(o, "roles"), h);
}

static bool name_taken(const struct fx_cfg *c, const char *name)
{
    for (size_t i = 0; i < c->n; i++)
        if (strcmp(c->host[i].name, name) == 0) return true;
    return false;
}

static bool parse_config(const char *raw, size_t len, struct fx_cfg *c,
                         char *err, size_t en)
{
    struct json_value root;
    json_init(&root);
    const struct json_value *hosts = NULL;
    bool ok = json_read(&root, raw, len) && root.type == JSON_OBJ;
    if (ok) hosts = json_get(&root, "hosts");
    ok = ok && hosts && hosts->type == JSON_ARR && json_size(hosts) > 0 &&
         json_size(hosts) <= FX_MAX_HOSTS;
    if (!ok) snprintf(err, en, "expected {\"hosts\":[...]} with 1 to %d hosts",
                      FX_MAX_HOSTS);
    for (size_t i = 0; ok && i < json_size(hosts); i++) {
        struct fx_host *h = &c->host[c->n];
        memset(h, 0, sizeof *h);
        ok = parse_host(json_at(hosts, i), h) && !name_taken(c, h->name);
        if (ok) c->n++;
        else snprintf(err, en, "hosts[%zu] is invalid or repeats a name", i);
    }
    json_free(&root);
    return ok;
}

static bool config_path(char *out, size_t cap, const char *override)
{
    const char *home = getenv("HOME");
    int n;
    if (override) n = snprintf(out, cap, "%s", override);
    else if (home && home[0] == '/')
        n = snprintf(out, cap, "%s/.config/z23/fleet.json", home);
    else return false;
    return n > 0 && (size_t)n < cap;
}

static bool load_config(const char *override, struct fx_cfg *c)
{
    static char raw[FX_CFG_MAX + 1];
    char path[PATH_MAX], err[128];
    size_t len = 0;
    if (!config_path(path, sizeof path, override)) {
        fputs("z23-fx: HOME is not an absolute path; use --config=PATH\n", stderr);
        return false;
    }
    if (!read_file(path, raw, FX_CFG_MAX, &len)) {
        fprintf(stderr, "z23-fx: cannot read %s (missing or larger than %d bytes).\n"
                "Create it from docs/fleet-dev/fleet.example.json.\n",
                path, FX_CFG_MAX);
        return false;
    }
    if (!parse_config(raw, len, c, err, sizeof err)) {
        fprintf(stderr, "z23-fx: %s: %s\n", path, err);
        return false;
    }
    return true;
}

static size_t select_hosts(const struct fx_cfg *c, const char *sel, size_t *idx)
{
    size_t n = 0;
    bool all = strcmp(sel, "all") == 0;
    const char *role = sel[0] == '@' ? sel + 1 : NULL;
    for (size_t i = 0; i < c->n; i++) {
        bool hit = all || (role ? has_role(&c->host[i], role)
                                : strcmp(c->host[i].name, sel) == 0);
        if (hit) idx[n++] = i;
    }
    return n;
}

static bool control_option(char *out, size_t cap)
{
    const char *run = getenv("XDG_RUNTIME_DIR");
    const char *home = getenv("HOME");
    char dir[PATH_MAX];
    int n;
    if (run && run[0] == '/') n = snprintf(dir, sizeof dir, "%s", run);
    else if (home && home[0] == '/') n = snprintf(dir, sizeof dir, "%s/.ssh", home);
    else return false;
    /* ssh expands %C to 40 hex digits; the socket path must fit sun_path. */
    if (n <= 0 || (size_t)n + 1 + strlen("z23-fx-") + 40 >= FX_SOCK_PATH_MAX)
        return false;
    n = snprintf(out, cap, "ControlPath=%s/z23-fx-%%C", dir);
    return n > 0 && (size_t)n < cap;
}

static void build_argv(struct fx_argv *a, const struct fx_host *h,
                       const char *control, const char *cmd)
{
    size_t k = 0;
    a->v[k++] = "ssh";
    for (size_t i = 0; i < sizeof FX_OPTIONS / sizeof FX_OPTIONS[0]; i++) {
        a->v[k++] = "-o";
        a->v[k++] = FX_OPTIONS[i];
    }
    a->v[k++] = "-o";
    a->v[k++] = control;
    a->v[k++] = "--";
    a->v[k++] = h->ssh;
    a->v[k++] = cmd;
    a->v[k] = NULL;
}

static bool print_argv(const struct fx_host *h, const struct fx_argv *a)
{
    struct json_value o, list;
    json_init(&o);
    json_init(&list);
    json_set_object(&o);
    json_set_array(&list);
    bool ok = json_push_kv_str(&o, "host", h->name);
    for (size_t i = 0; ok && a->v[i]; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, a->v[i]);
        ok = json_push_back(&list, &s);
        json_free(&s);
    }
    ok = ok && json_push_kv(&o, "argv", &list);
    size_t n = ok ? json_write(&o, NULL, 0) : 0;
    char *line = n ? zcl_malloc(n + 1, "fx_argv_json") : NULL;
    ok = line && json_write(&o, line, n + 1) == n && puts(line) != EOF;
    free(line);
    json_free(&list);
    json_free(&o);
    return ok;
}

static int status_code(int status)
{
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255;
}

static int run_single(const struct fx_argv *a)
{
    execvp(a->v[0], (char *const *)a->v);
    fprintf(stderr, "z23-fx: cannot run ssh: %s\n", strerror(errno));
    return 127;
}

static bool start_job(struct fx_job *j, const struct fx_argv *a)
{
    int p[2];
    if (pipe(p) != 0) return false;
    j->pid = fork();
    if (j->pid < 0) {
        close(p[0]);
        close(p[1]);
        return false;
    }
    if (j->pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, STDIN_FILENO);
        dup2(p[1], STDOUT_FILENO);
        dup2(p[1], STDERR_FILENO);
        close(p[0]);
        close(p[1]);
        execvp(a->v[0], (char *const *)a->v);
        _exit(127);
    }
    close(p[1]);
    j->fd = p[0];
    return true;
}

static void drain(struct fx_job *j)
{
    char tmp[4096];
    ssize_t n = read(j->fd, tmp, sizeof tmp);
    if (n < 0 && (errno == EINTR || errno == EAGAIN)) return;
    if (n <= 0) {
        close(j->fd);
        j->fd = -1;
        return;
    }
    size_t take = (size_t)n;
    if (j->len + take > FX_OUT_CAP) {
        take = FX_OUT_CAP - j->len;
        j->truncated = true;
    }
    if (take == 0) return;
    char *grown = zcl_realloc(j->buf, j->len + take, "fx_output");
    if (!grown) {
        j->truncated = true;
        return;
    }
    j->buf = grown;
    memcpy(j->buf + j->len, tmp, take);
    j->len += take;
}

static void close_jobs(struct fx_job *jobs, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (jobs[i].fd < 0) continue;
        close(jobs[i].fd);
        jobs[i].fd = -1;
    }
}

/* A poll failure closes every pipe so no child blocks on a full pipe while
 * run_parallel waits for it. */
static void pump(struct fx_job *jobs, size_t n)
{
    for (;;) {
        struct pollfd pf[FX_MAX_HOSTS];
        size_t map[FX_MAX_HOSTS], live = 0;
        for (size_t i = 0; i < n; i++) {
            if (jobs[i].fd < 0) continue;
            pf[live] = (struct pollfd){.fd = jobs[i].fd, .events = POLLIN};
            map[live++] = i;
        }
        if (live == 0) return;
        int ready = poll(pf, live, -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            close_jobs(jobs, n);
            return;
        }
        for (size_t k = 0; k < live; k++)
            if (pf[k].revents) drain(&jobs[map[k]]);
    }
}

static void emit_job(const struct fx_host *h, const struct fx_job *j)
{
    size_t start = 0;
    for (size_t i = 0; i < j->len; i++) {
        if (j->buf[i] != '\n') continue;
        printf("%s | %.*s\n", h->name, (int)(i - start), j->buf + start);
        start = i + 1;
    }
    if (start < j->len)
        printf("%s | %.*s\n", h->name, (int)(j->len - start), j->buf + start);
    if (j->truncated) printf("%s | [output truncated at %d bytes]\n", h->name, FX_OUT_CAP);
    if (j->rc != 0) printf("%s | exit %d\n", h->name, j->rc);
}

static int run_parallel(const struct fx_cfg *c, const size_t *idx, size_t n,
                        const char *control, const char *cmd)
{
    struct fx_job jobs[FX_MAX_HOSTS] = {0};
    int worst = 0;
    for (size_t i = 0; i < n; i++) {
        struct fx_argv a;
        build_argv(&a, &c->host[idx[i]], control, cmd);
        jobs[i].fd = -1;
        jobs[i].rc = start_job(&jobs[i], &a) ? 0 : 255;
    }
    pump(jobs, n);
    for (size_t i = 0; i < n; i++) {
        int status = 0;
        if (jobs[i].pid > 0 && waitpid(jobs[i].pid, &status, 0) > 0)
            jobs[i].rc = status_code(status);
        emit_job(&c->host[idx[i]], &jobs[i]);
        if (jobs[i].rc > worst) worst = jobs[i].rc;
        free(jobs[i].buf);
    }
    fflush(stdout);
    return worst;
}

struct fx_args {
    const char *config;
    const char *selector;
    const char *cmd;
    bool print;
};

static bool parse_args(int ac, char **av, struct fx_args *a)
{
    int i = 1;
    for (; i < ac && av[i][0] == '-'; i++) {
        if (strcmp(av[i], "--print-argv") == 0) a->print = true;
        else if (strncmp(av[i], "--config=", 9) == 0 && av[i][9]) a->config = av[i] + 9;
        else return false;
    }
    if (ac - i != 2) return false;
    a->selector = av[i];
    a->cmd = av[i + 1];
    return a->cmd[0] != '\0' && strlen(a->cmd) <= FX_CMD_MAX;
}

static int print_all(const struct fx_cfg *c, const size_t *idx, size_t n,
                     const char *control, const char *cmd)
{
    for (size_t i = 0; i < n; i++) {
        struct fx_argv a;
        build_argv(&a, &c->host[idx[i]], control, cmd);
        if (!print_argv(&c->host[idx[i]], &a)) return 1;
    }
    return 0;
}

int main(int ac, char **av)
{
    struct fx_args args = {0};
    static struct fx_cfg cfg;
    size_t idx[FX_MAX_HOSTS], n;
    char control[PATH_MAX];
    if (ac == 2 && strcmp(av[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (!parse_args(ac, av, &args)) {
        usage(stderr);
        return FX_USAGE_EXIT;
    }
    if (!load_config(args.config, &cfg)) return FX_USAGE_EXIT;
    n = select_hosts(&cfg, args.selector, idx);
    if (n == 0) {
        fprintf(stderr, "z23-fx: no machine matches '%s' in the fleet config\n",
                args.selector);
        return FX_USAGE_EXIT;
    }
    if (!control_option(control, sizeof control)) {
        fputs("z23-fx: no usable SSH control socket directory; set XDG_RUNTIME_DIR "
              "to a short absolute path\n", stderr);
        return FX_USAGE_EXIT;
    }
    if (args.print) return print_all(&cfg, idx, n, control, args.cmd);
    if (n == 1 && strcmp(args.selector, "all") != 0 && args.selector[0] != '@') {
        struct fx_argv a;
        build_argv(&a, &cfg.host[idx[0]], control, args.cmd);
        return run_single(&a);
    }
    return run_parallel(&cfg, idx, n, control, args.cmd);
}
