/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Run the two-node netdisrupt drill once and append one ledger
 *          line before surfacing its verdict. Skip exits 0. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "netdisrupt_two_node_record.h"
#include "dev_script_dir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct ndr_seen {
    char wall[32];
    char artifact[PATH_MAX];
    char rpc[16];
};

static const char *ndr_env(const char *key, const char *fallback)
{
    const char *value = getenv(key);
    if (value != NULL && value[0] != '\0')
        return value;
    return fallback;
}

static int ndr_wait(pid_t child)
{
    int report = 0;
    pid_t finished = 0;
    while (finished == 0) {
        finished = waitpid(child, &report, 0);
        if (finished < 0 && errno == EINTR)
            finished = 0;
        else if (finished < 0)
            return 125;
    }
    return WIFEXITED(report) ? WEXITSTATUS(report) : 125;
}

static int ndr_digits(const char *text)
{
    size_t i;
    if (text == NULL || text[0] == '\0')
        return 0;
    for (i = 0; text[i] != '\0'; i++) {
        if ((text[i] < '0' || text[i] > '9') && text[i] != '-')
            return 0;
    }
    return 1;
}

static int ndr_escape(const char *in, char *out, size_t cap)
{
    size_t used = 0;
    size_t i;
    if (in == NULL)
        in = "";
    for (i = 0; in[i] != '\0'; i++) {
        char extra = 0;
        char plain = in[i];
        if (plain == '\\' || plain == '"')
            extra = plain;
        else if (plain == '\t')
            extra = 't';
        else if (plain == '\r')
            extra = 'r';
        else if (plain == '\n')
            plain = ' ';
        if (extra != 0) {
            if (used + 2 >= cap)
                return -1;
            out[used++] = '\\';
            out[used++] = extra;
            continue;
        }
        if (used + 1 >= cap)
            return -1;
        out[used++] = plain;
    }
    out[used] = '\0';
    return 0;
}

static void ndr_note_wall(const char *line, char *wall, size_t cap)
{
    const char *prefix = "WALL_CLOCK_SECONDS=";
    size_t n = strlen(prefix);
    size_t i = 0;
    if (strncmp(line, prefix, n) != 0)
        return;
    while (line[n + i] >= '0' && line[n + i] <= '9')
        i++;
    if (i == 0 || line[n + i] != '\0' || i >= cap)
        return;
    memcpy(wall, line + n, i + 1);
}

static void ndr_note_artifact(const char *line, char *artifact, size_t cap)
{
    const char *prefix = "netdisrupt-two-node: artifact=";
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0)
        return;
    if (strlen(line + n) >= cap)
        return;
    memcpy(artifact, line + n, strlen(line + n) + 1);
}

static void ndr_note_rpc(const char *line, char *rpc, size_t cap)
{
    const char *mark = strstr(line, "B{dd=");
    const char *rpc_at;
    size_t i = 0;
    if (mark == NULL)
        return;
    mark += 5;
    while (*mark != '\0' && *mark != ' ')
        mark++;
    if (strncmp(mark, " p2p=", 5) != 0)
        return;
    mark += 5;
    while (*mark >= '0' && *mark <= '9')
        mark++;
    if (strncmp(mark, " rpc=", 5) != 0)
        return;
    rpc_at = mark + 5;
    while (rpc_at[i] >= '0' && rpc_at[i] <= '9')
        i++;
    if (i == 0 || rpc_at[i] != '}' || i >= cap)
        return;
    memcpy(rpc, rpc_at, i);
    rpc[i] = '\0';
}

static void ndr_note(const char *line, struct ndr_seen *seen)
{
    ndr_note_wall(line, seen->wall, sizeof seen->wall);
    ndr_note_artifact(line, seen->artifact, sizeof seen->artifact);
    ndr_note_rpc(line, seen->rpc, sizeof seen->rpc);
}

static int ndr_pump(int fd, struct ndr_seen *seen)
{
    char hold[2048];
    size_t held = 0;
    for (;;) {
        char chunk[1024];
        ssize_t got = read(fd, chunk, sizeof chunk);
        size_t off = 0;
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return -1;
        if (got == 0)
            break;
        if (fwrite(chunk, 1, (size_t)got, stdout) != (size_t)got)
            return -1;
        while (off < (size_t)got) {
            char byte = chunk[off++];
            if (byte == '\n') {
                hold[held] = '\0';
                ndr_note(hold, seen);
                held = 0;
                continue;
            }
            if (held + 1 < sizeof hold)
                hold[held++] = byte;
        }
    }
    if (held > 0) {
        hold[held] = '\0';
        ndr_note(hold, seen);
    }
    fputc('\n', stdout);
    return 0;
}

static int ndr_drill(const char *drill, struct ndr_seen *seen)
{
    int fds[2];
    pid_t pid;
    char *argv[3];
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
        if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0)
            _exit(127);
        if (fds[1] > STDERR_FILENO)
            close(fds[1]);
        if (setenv("LC_ALL", "C", 1) != 0)
            _exit(127);
        argv[0] = "bash";
        argv[1] = (char *)drill;
        argv[2] = NULL;
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    if (ndr_pump(fds[0], seen) != 0) {
        close(fds[0]);
        (void)ndr_wait(pid);
        return -1;
    }
    close(fds[0]);
    return ndr_wait(pid);
}

static void ndr_git_child(int wr, char *const argv[])
{
    int sink = open("/dev/null", O_WRONLY);
    if (dup2(wr, STDOUT_FILENO) < 0)
        _exit(127);
    if (sink >= 0)
        (void)dup2(sink, STDERR_FILENO);
    if (wr > STDERR_FILENO)
        close(wr);
    if (sink > STDERR_FILENO)
        close(sink);
    execvp(argv[0], argv);
    _exit(127);
}

static size_t ndr_collect(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        unsigned char byte = 0;
        ssize_t step = read(fd, &byte, 1);
        if (step == 0)
            break;
        if (step < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (byte == '\n')
            break;
        buf[n++] = (char)byte;
    }
    buf[n] = '\0';
    return n;
}

static void ndr_trim(char *buf)
{
    char *end = buf + strlen(buf);
    while (end > buf && (end[-1] == '\n' || end[-1] == '\r'))
        *--end = '\0';
}

static int ndr_git(const char *repo, char *out, size_t cap)
{
    int fds[2];
    pid_t pid;
    char *argv[] = {"git", "-C", (char *)repo, "rev-parse", "--short", "HEAD", NULL};
    char buf[64];
    size_t n;
    out[0] = '\0';
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
        ndr_git_child(fds[1], argv);
        _exit(127);
    }
    close(fds[1]);
    n = ndr_collect(fds[0], buf, sizeof buf);
    close(fds[0]);
    if (ndr_wait(pid) != 0 || n == 0) {
        if (cap > 7)
            memcpy(out, "unknown", 8);
        return 0;
    }
    ndr_trim(buf);
    n = strlen(buf);
    if (n + 1 > cap)
        return -1;
    memcpy(out, buf, n + 1);
    return 0;
}

static int ndr_mkdir(const char *path)
{
    char copy[PATH_MAX];
    size_t n = strlen(path);
    char *cursor;
    if (n == 0 || n >= sizeof copy)
        return -1;
    memcpy(copy, path, n + 1);
    cursor = copy;
    if (*cursor == '/')
        cursor++;
    while (*cursor != '\0') {
        if (*cursor == '/') {
            *cursor = '\0';
            if (mkdir(copy, 0755) != 0 && errno != EEXIST)
                return -1;
            *cursor = '/';
        }
        cursor++;
    }
    if (mkdir(copy, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int ndr_exec(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return ndr_wait(pid);
}

static int ndr_stamp(char *out, size_t cap)
{
    int fds[2];
    pid_t pid;
    char *argv[] = {"date", "+%s", NULL};
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
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(127);
        if (fds[1] > STDERR_FILENO)
            close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    (void)ndr_collect(fds[0], out, cap);
    close(fds[0]);
    if (ndr_wait(pid) != 0 || !ndr_digits(out)) {
        if (cap > 1)
            memcpy(out, "0", 2);
    }
    return 0;
}

static int ndr_append(const char *file, const char *line)
{
    int fd = open(file, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
    char *argv[] = {
        "flock", "-x", "-w", "30", (char *)file,
        "sh", "-c", "printf '%s\\n' \"$1\" >> \"$2\"",
        "append", (char *)line, (char *)file, NULL
    };
    int rc;
    if (fd < 0)
        return 1;
    close(fd);
    rc = ndr_exec(argv);
    if (rc == 0)
        return 0;
    if (rc < 0)
        return 1;
    return rc == 1 ? 9 : rc;
}

static const char *ndr_verdict(int rc)
{
    if (rc == 0)
        return "pass";
    if (rc == 1)
        return "fail";
    if (rc == 2)
        return "skip";
    if (rc == 3)
        return "seam";
    if (rc == 4)
        return "stalled-named";
    return "error";
}

static int ndr_quote(const char *text, char *out, size_t cap)
{
    char escaped[PATH_MAX * 2];
    int n;
    if (ndr_escape(text, escaped, sizeof escaped) != 0)
        return -1;
    n = snprintf(out, cap, "\"%s\"", escaped);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int ndr_line(const struct ndr_seen *seen, int rc, const char *ts,
                    const char *budget, const char *cut, const char *node,
                    const char *commit, char *out, size_t cap)
{
    char verdict[64];
    char peer[64];
    char node_q[PATH_MAX * 2];
    char commit_q[128];
    char art_q[PATH_MAX * 2];
    const char *wall = ndr_digits(seen->wall) ? seen->wall : "null";
    const char *bud = ndr_digits(budget) ? budget : "null";
    const char *cut_n = ndr_digits(cut) ? cut : "null";
    const char *rpc = seen->rpc[0] != '\0' ? seen->rpc : "0";
    if (ndr_quote(ndr_verdict(rc), verdict, sizeof verdict) != 0)
        return -1;
    if (snprintf(peer, sizeof peer, "127.0.0.1:%s", rpc) >= (int)sizeof peer)
        return -1;
    if (ndr_quote(peer, peer, sizeof peer) != 0)
        return -1;
    if (ndr_quote(node, node_q, sizeof node_q) != 0)
        return -1;
    if (ndr_quote(commit, commit_q, sizeof commit_q) != 0)
        return -1;
    if (ndr_quote(seen->artifact, art_q, sizeof art_q) != 0)
        return -1;
    if (snprintf(out, cap,
                 "{\"ts\":%s,\"verdict\":%s,\"exit_code\":%d,"
                 "\"wall_clock_seconds\":%s,\"budget_seconds\":%s,"
                 "\"cut_seconds\":%s,\"peer\":%s,\"node_bin\":%s,"
                 "\"build_commit\":%s,\"artifact_dir\":%s}",
                 ts, verdict, rc, wall, bud, cut_n, peer, node_q, commit_q,
                 art_q) >= (int)cap)
        return -1;
    return 0;
}

static int ndr_history(const char *history_dir, char *dir, size_t cap)
{
    const char *home;
    const char *env;
    int n;
    if (history_dir != NULL && history_dir[0] != '\0') {
        if (strlen(history_dir) >= cap)
            return -1;
        memcpy(dir, history_dir, strlen(history_dir) + 1);
        return 0;
    }
    env = getenv("ZCL_ND_HISTORY_DIR");
    if (env != NULL && env[0] != '\0') {
        if (strlen(env) >= cap)
            return -1;
        memcpy(dir, env, strlen(env) + 1);
        return 0;
    }
    home = getenv("HOME");
    if (home == NULL || home[0] == '\0')
        home = "/root";
    n = snprintf(dir, cap, "%s/.local/state/zclassic23-netdisrupt-stopwatch", home);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int ndr_fail_append(const char *file, int append_rc)
{
    if (append_rc == 9)
        fprintf(stderr,
                "netdisrupt-two-node-run: FAIL could not acquire append lock on %s within 30s\n",
                file);
    else
        fprintf(stderr,
                "netdisrupt-two-node-run: FAIL could not append to %s (rc=%d)\n",
                file, append_rc);
    return 1;
}

static int ndr_body(const char *repo, const char *drill, const char *history_dir)
{
    struct ndr_seen seen;
    char node_buf[PATH_MAX];
    char hist[PATH_MAX];
    char file[PATH_MAX];
    char commit[64];
    char stamp[32];
    char line[PATH_MAX * 4];
    const char *node;
    const char *cut;
    const char *budget;
    int rc;
    int append_rc;
    memset(&seen, 0, sizeof seen);
    node = ndr_env("ZCL_ND2_NODE_BIN", NULL);
    if (node == NULL) {
        if (snprintf(node_buf, sizeof node_buf, "%s/build/bin/zclassic23", repo) >=
            (int)sizeof node_buf)
            return 1;
        node = node_buf;
    }
    cut = ndr_env("ZCL_ND2_CUT_SECS", "30");
    budget = ndr_env("ZCL_ND2_BUDGET_SECS", "120");
    if (ndr_history(history_dir, hist, sizeof hist) != 0)
        return 1;
    if (snprintf(file, sizeof file, "%s/history.jsonl", hist) >= (int)sizeof file)
        return 1;
    if (ndr_mkdir(hist) != 0)
        return ndr_fail_append(file, 1);
    if (ndr_git(repo, commit, sizeof commit) != 0)
        return 1;
    printf("netdisrupt-two-node-run: bin=%s cut=%ss budget=%ss build_commit=%s\n",
           node, cut, budget, commit);
    rc = ndr_drill(drill, &seen);
    if (rc < 0)
        rc = 127;
    if (ndr_stamp(stamp, sizeof stamp) != 0)
        return ndr_fail_append(file, 1);
    if (ndr_line(&seen, rc, stamp, budget, cut, node, commit, line, sizeof line) != 0)
        return ndr_fail_append(file, 1);
    append_rc = ndr_append(file, line);
    if (append_rc != 0)
        return ndr_fail_append(file, append_rc);
    printf("netdisrupt-two-node-run: appended file=%s verdict=%s rc=%d\n",
           file, ndr_verdict(rc), rc);
    printf("%s\n", line);
    if (rc == 2) {
        printf("netdisrupt-two-node-run: SKIP mapped to clean exit 0 (precondition absent — recorded, not a verdict)\n");
        return 0;
    }
    return rc;
}

static int ndr_paths(const char *repo, const char *drill, char *root, size_t root_cap,
                     char *script, size_t script_cap)
{
    int n;
    if (repo == NULL || repo[0] == '\0') {
        if (zcl_dev_checkout_root(root, root_cap) != 0)
            return -1;
    } else if (strlen(repo) >= root_cap) {
        return -1;
    } else {
        memcpy(root, repo, strlen(repo) + 1);
    }
    if (drill != NULL && drill[0] != '\0') {
        if (strlen(drill) >= script_cap)
            return -1;
        memcpy(script, drill, strlen(drill) + 1);
        return 0;
    }
    n = snprintf(script, script_cap, "%s/tools/scripts/netdisrupt_two_node_drill.sh", root);
    if (n < 0 || (size_t)n >= script_cap)
        return -1;
    return 0;
}
#endif

int zcl_netdisrupt_two_node_record(const char *repo, const char *drill,
                                   const char *history_dir)
{
#if defined(_WIN32)
    (void)repo;
    (void)drill;
    (void)history_dir;
    fprintf(stderr, "netdisrupt-two-node-run: unavailable on Windows\n");
    return 1;
#else
    char root[PATH_MAX];
    char script[PATH_MAX];
    if (ndr_paths(repo, drill, root, sizeof root, script, sizeof script) != 0) {
        fprintf(stderr, "netdisrupt-two-node-run: FAIL could not locate the drill\n");
        return 1;
    }
    return ndr_body(root, script, history_dir);
#endif
}
