/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Emit the lane baseline pin as stable key=value lines.
 *          Reads git, the registered test-group count, the Makefile
 *          lint-gate list, and sha256 of named files. Writes nothing. */

#include "agent_baseline.h"
#include "dev_script_dir.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern char **environ;

static int abl_blank(char c)
{
    return memchr(" \t\n\r\v\f", (unsigned char)c, 6) != NULL;
}

static int abl_ifs(char c)
{
    return c == ' ' || c == '\t' || c == '\n';
}

static int abl_piece(char *dst, size_t cap, const char *root, const char *tail)
{
    int wrote = snprintf(dst, cap, "%s/%s", root, tail);
    if (wrote < 0)
        return -1;
    if ((size_t)wrote >= cap)
        return -1;
    return 0;
}

static int abl_resolve(const char *tool, char *dst, size_t cap)
{
    const char *path = getenv("PATH");
    size_t tool_n = strlen(tool);
    size_t i = 0;
    if (path == NULL || path[0] == '\0')
        path = "/usr/bin:/bin:/usr/local/bin";
    while (path[i] != '\0') {
        size_t start = i;
        size_t dir_n;
        while (path[i] != '\0' && path[i] != ':')
            i++;
        dir_n = i - start;
        if (path[i] == ':')
            i++;
        if (dir_n == 0 || dir_n + 1 + tool_n + 1 > cap)
            continue;
        memcpy(dst, path + start, dir_n);
        dst[dir_n] = '/';
        memcpy(dst + dir_n + 1, tool, tool_n + 1);
        if (access(dst, X_OK) == 0)
            return 0;
    }
    dst[0] = '\0';
    return -1;
}

static int abl_reap(pid_t pid)
{
    int status = 0;
    pid_t got = waitpid(pid, &status, 0);
    while (got < 0 && errno == EINTR)
        got = waitpid(pid, &status, 0);
    if (got != pid)
        return 125;
    if (!WIFEXITED(status))
        return 125;
    return WEXITSTATUS(status);
}

static int abl_begin(char *const argv[], int quiet_err, int *rd, pid_t *pid)
{
    int pipefd[2];
    posix_spawn_file_actions_t act;
    int rc;
    *rd = -1;
    *pid = 0;
    if (pipe(pipefd) != 0)
        return -1;
    rc = posix_spawn_file_actions_init(&act);
    if (rc != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (quiet_err)
        rc = posix_spawn_file_actions_addopen(&act, STDERR_FILENO, "/dev/null",
                                               O_WRONLY, 0);
    if (rc == 0)
        rc = posix_spawn_file_actions_adddup2(&act, pipefd[1], STDOUT_FILENO);
    if (rc == 0)
        rc = posix_spawn_file_actions_addclose(&act, pipefd[0]);
    if (rc == 0)
        rc = posix_spawn_file_actions_addclose(&act, pipefd[1]);
    if (rc == 0)
        rc = posix_spawn(pid, argv[0], &act, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&act);
    close(pipefd[1]);
    if (rc != 0) {
        close(pipefd[0]);
        *pid = 0;
        return -1;
    }
    *rd = pipefd[0];
    return 0;
}

static void abl_take(int rd, char *out, size_t cap)
{
    size_t used = 0;
    char extra[256];
    if (cap == 0)
        return;
    out[0] = '\0';
    for (;;) {
        int room = used + 1 < cap;
        ssize_t n = read(rd, room ? out + used : extra,
                         room ? cap - 1 - used : sizeof extra);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (room) {
            used += (size_t)n;
            out[used] = '\0';
        }
    }
}

static void abl_trim_nl(char *text)
{
    size_t n = strlen(text);
    while (n > 0 && text[n - 1] == '\n') {
        n--;
        text[n] = '\0';
    }
}

static int abl_run(char *const argv[], int quiet_err, char *out, size_t cap)
{
    int rd = -1;
    pid_t pid = 0;
    if (abl_begin(argv, quiet_err, &rd, &pid) != 0)
        return -1;
    abl_take(rd, out, cap);
    close(rd);
    abl_trim_nl(out);
    return abl_reap(pid);
}

static int abl_count_lines(char *const argv[], int *lines)
{
    int rd = -1;
    pid_t pid = 0;
    int saw = 0;
    *lines = 0;
    if (abl_begin(argv, 1, &rd, &pid) != 0)
        return -1;
    for (;;) {
        char buf[512];
        ssize_t n = read(rd, buf, sizeof buf);
        ssize_t i;
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (i = 0; i < n; i++) {
            if (buf[i] == '\n')
                saw++;
        }
    }
    close(rd);
    *lines = saw;
    return abl_reap(pid);
}

static int abl_git(const char *root, char *out, size_t cap, const char *a,
                   const char *b, const char *c)
{
    char git[PATH_MAX];
    char *argv[8];
    int n = 0;
    out[0] = '\0';
    if (abl_resolve("git", git, sizeof git) != 0)
        return -1;
    argv[n++] = git;
    argv[n++] = "-C";
    argv[n++] = (char *)root;
    if (a != NULL)
        argv[n++] = (char *)a;
    if (b != NULL)
        argv[n++] = (char *)b;
    if (c != NULL)
        argv[n++] = (char *)c;
    argv[n] = NULL;
    return abl_run(argv, 1, out, cap);
}

static void abl_or_unknown(const char *root, char *dst, size_t cap,
                           const char *a, const char *b, const char *c)
{
    if (abl_git(root, dst, cap, a, b, c) != 0)
        snprintf(dst, cap, "UNKNOWN");
}

static void abl_nine(const char *src, char *dst, size_t cap)
{
    size_t n = 0;
    if (cap == 0)
        return;
    while (src[n] != '\0' && n < 9 && n + 1 < cap) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

static int abl_dirty_lines(const char *root)
{
    char git[PATH_MAX];
    char *argv[6];
    int lines = 0;
    int rc;
    if (abl_resolve("git", git, sizeof git) != 0)
        return 0;
    argv[0] = git;
    argv[1] = "-C";
    argv[2] = (char *)root;
    argv[3] = "status";
    argv[4] = "--porcelain";
    argv[5] = NULL;
    rc = abl_count_lines(argv, &lines);
    if (rc < 0 || lines < 0)
        return 0;
    return lines;
}

static void abl_identity(const char *root)
{
    char head[160];
    char brief[16];
    char branch[256];
    char base[160];
    char ahead[64];
    int lines;
    abl_or_unknown(root, head, sizeof head, "rev-parse", "HEAD", NULL);
    abl_nine(head, brief, sizeof brief);
    abl_or_unknown(root, branch, sizeof branch, "rev-parse", "--abbrev-ref",
                   "HEAD");
    lines = abl_dirty_lines(root);
    abl_or_unknown(root, base, sizeof base, "merge-base", "HEAD", "main");
    abl_or_unknown(root, ahead, sizeof ahead, "rev-list", "--count",
                   "main..HEAD");
    printf("head_sha=%s\n", head);
    printf("head_short=%s\n", brief);
    printf("branch=%s\n", branch);
    if (lines > 0) {
        printf("tree_dirty=1\n");
        printf("tree_dirty_files=%d\n", lines);
    } else {
        printf("tree_dirty=0\n");
        printf("tree_dirty_files=0\n");
    }
    printf("merge_base_main=%s\n", base);
    printf("commits_ahead_of_main=%s\n", ahead);
}

static int abl_groups(const char *root)
{
    char bin[PATH_MAX];
    char count[64];
    char *argv[3];
    int rc;
    if (abl_piece(bin, sizeof bin, root, "build/bin/test-group-list") != 0 ||
        access(bin, X_OK) != 0) {
        printf("registered_test_groups=UNKNOWN\n");
        return 1;
    }
    argv[0] = bin;
    argv[1] = "--count";
    argv[2] = NULL;
    rc = abl_run(argv, 1, count, sizeof count);
    if (rc != 0) {
        printf("registered_test_groups=UNKNOWN\n");
        return 1;
    }
    printf("registered_test_groups=%s\n", count);
    return 0;
}

static void abl_drop_record_end(char *line)
{
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n') {
        n--;
        line[n] = '\0';
    }
    if (n > 0 && line[n - 1] == '\r')
        line[n - 1] = '\0';
}

static int abl_gate_head(const char *line)
{
    const char *p = line;
    if (strncmp(p, "LINT_GATES", 10) != 0)
        return 0;
    p += 10;
    while (abl_blank(*p))
        p++;
    if (*p == ':')
        p++;
    return *p == '=';
}

static int abl_continued(const char *line)
{
    size_t n = strlen(line);
    while (n > 0 && abl_blank(line[n - 1]))
        n--;
    return n > 0 && line[n - 1] == '\\';
}

static int abl_check_tokens(const char *line)
{
    int found = 0;
    const char *p = line;
    while (*p != '\0') {
        const char *start;
        while (abl_blank(*p))
            p++;
        if (*p == '\0')
            break;
        start = p;
        while (*p != '\0' && !abl_blank(*p))
            p++;
        if ((size_t)(p - start) >= 6 && memcmp(start, "check-", 6) == 0)
            found++;
    }
    return found;
}

static int abl_count_gates(const char *makefile)
{
    FILE *fp = fopen(makefile, "r");
    char line[4096];
    int inside = 0;
    int count = 0;
    if (fp == NULL)
        return -1;
    while (fgets(line, sizeof line, fp) != NULL) {
        abl_drop_record_end(line);
        if (inside == 0 && abl_gate_head(line))
            inside = 1;
        if (inside == 0)
            continue;
        count += abl_check_tokens(line);
        if (!abl_continued(line))
            break;
    }
    fclose(fp);
    return count;
}

static int abl_gates_report(const char *root)
{
    char makefile[PATH_MAX];
    char parsed[16];
    const char *want;
    int n;
    if (abl_piece(makefile, sizeof makefile, root, "Makefile") != 0)
        return 2;
    n = abl_count_gates(makefile);
    if (n < 0)
        return 2;
    snprintf(parsed, sizeof parsed, "%d", n);
    want = getenv("ZCL_BASELINE_LINT_GATES");
    if (want != NULL && want[0] != '\0') {
        printf("lint_gates=%s\n", want);
        if (strcmp(want, parsed) != 0) {
            printf("lint_gates_parse_mismatch=%s\n", parsed);
            return 1;
        }
        return 0;
    }
    printf("lint_gates=%s\n", parsed);
    return 0;
}

static int abl_plain_file(const char *root, const char *file, char *full,
                          size_t cap)
{
    struct stat info;
    if (file[0] == '/') {
        if (snprintf(full, cap, "%s", file) >= (int)cap)
            return 0;
    } else if (abl_piece(full, cap, root, file) != 0) {
        return 0;
    }
    if (stat(full, &info) != 0)
        return 0;
    if (!S_ISREG(info.st_mode))
        return 0;
    return 1;
}

static void abl_first_field(char *line)
{
    char *sp = strchr(line, ' ');
    if (sp != NULL)
        *sp = '\0';
}

static int abl_one_file(const char *root, const char *file, int *tool)
{
    char full[PATH_MAX];
    char raw[PATH_MAX + 96];
    char sum[PATH_MAX];
    char *argv[4];
    int rc;
    *tool = 0;
    if (!abl_plain_file(root, file, full, sizeof full)) {
        printf("sha256.%s=MISSING\n", file);
        return 1;
    }
    if (abl_resolve("sha256sum", sum, sizeof sum) != 0) {
        *tool = 127;
        return 127;
    }
    argv[0] = sum;
    argv[1] = "--";
    argv[2] = full;
    argv[3] = NULL;
    rc = abl_run(argv, 0, raw, sizeof raw);
    if (rc != 0) {
        *tool = rc < 0 ? 127 : rc;
        return *tool;
    }
    abl_first_field(raw);
    printf("sha256.%s=%s\n", file, raw);
    return 0;
}

static int abl_pin_list(const char *root, int n, char **list)
{
    int i;
    int status = 0;
    printf("baseline_file_count=%d\n", n);
    for (i = 0; i < n; i++) {
        int tool = 0;
        int one = abl_one_file(root, list[i], &tool);
        if (tool != 0)
            return tool;
        if (one != 0)
            status = 1;
    }
    return status;
}

static int abl_word_count(const char *text)
{
    int n = 0;
    const char *p = text;
    while (*p != '\0') {
        while (abl_ifs(*p))
            p++;
        if (*p == '\0')
            break;
        n++;
        while (*p != '\0' && !abl_ifs(*p))
            p++;
    }
    return n;
}

static const char *abl_next_word(const char *p, char *dst, size_t cap)
{
    size_t n = 0;
    while (abl_ifs(*p))
        p++;
    while (*p != '\0' && !abl_ifs(*p)) {
        if (n + 1 >= cap)
            return NULL;
        dst[n++] = *p++;
    }
    dst[n] = '\0';
    return p;
}

static int abl_pin_env(const char *root)
{
    const char *env = getenv("BASELINE_FILES");
    const char *p = env != NULL ? env : "";
    int count = abl_word_count(p);
    int status = 0;
    int i;
    printf("baseline_file_count=%d\n", count);
    for (i = 0; i < count; i++) {
        char word[PATH_MAX];
        int tool = 0;
        int one;
        p = abl_next_word(p, word, sizeof word);
        if (p == NULL)
            return 1;
        one = abl_one_file(root, word, &tool);
        if (tool != 0)
            return tool;
        if (one != 0)
            status = 1;
    }
    return status;
}

static int abl_pin_files(const char *root, int argc, char **files)
{
    if (argc > 0)
        return abl_pin_list(root, argc, files);
    return abl_pin_env(root);
}

static int abl_root(const char *repo, char *out, size_t cap)
{
    size_t n;
    if (repo != NULL && repo[0] != '\0') {
        n = strlen(repo);
        if (n + 1 > cap)
            return -1;
        memcpy(out, repo, n + 1);
        return 0;
    }
    return zcl_dev_checkout_root(out, cap);
}
#endif

int zcl_agent_baseline(const char *repo, int argc, char **files)
{
#if defined(_WIN32)
    (void)repo;
    (void)argc;
    (void)files;
    fputs("agent-baseline: unavailable on Windows\n", stdout);
    return 1;
#else
    char root[PATH_MAX];
    int status = 0;
    int gate;
    int pin;
    if (abl_root(repo, root, sizeof root) != 0) {
        fputs("agent-baseline: cannot locate the checkout\n", stderr);
        return 1;
    }
    printf("baseline_schema=zcl.agent_baseline.v1\n");
    printf("repo_root=%s\n", root);
    abl_identity(root);
    status |= abl_groups(root);
    gate = abl_gates_report(root);
    if (gate == 2)
        return 2;
    status |= gate;
    pin = abl_pin_files(root, argc, files);
    if (pin > 1)
        return pin;
    status |= pin;
    return status;
#endif
}
