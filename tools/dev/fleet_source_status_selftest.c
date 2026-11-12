/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Drive fleet_source_status.sh through a private git history.
 *          No network and no operator fleet state. */

#include "fleet_source_status_selftest.h"

#include <stdio.h>
#include <string.h>

static int fss_fail(const char *msg)
{
    if (msg != NULL && msg[0] != '\0')
        fprintf(stderr, "check_fleet_source_status: %s\n", msg);
    fprintf(stderr, "check_fleet_source_status: FAIL\n");
    return 1;
}

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char k_probe[] =
    "#!/bin/bash\n"
    "set -euo pipefail\n"
    ". \"$1\"\n"
    "shift\n"
    "op=$1\n"
    "shift\n"
    "if [ \"$op\" = date ]; then\n"
    "    fleet_source_normalize_commit_date \"$1\"\n"
    "    printf '\\n'\n"
    "    exit 0\n"
    "fi\n"
    "fleet_source_status_audit \"$1\" \"$2\" \"$3\" \"$4\" \"$5\"\n"
    "printf '%s\\n' \\\n"
    "    \"$FLEET_SOURCE_STATUS\" \\\n"
    "    \"$FLEET_SOURCE_COMMIT\" \\\n"
    "    \"$FLEET_SOURCE_KIND\" \\\n"
    "    \"$FLEET_SOURCE_COMMIT_DATE\" \\\n"
    "    \"$FLEET_SOURCE_BEHIND\" \\\n"
    "    \"$FLEET_SOURCE_DETAIL\" \\\n"
    "    \"$FLEET_SOURCE_REQUIRED_FLOOR\"\n";

struct fss_job {
    char tmp[PATH_MAX];
    char repo[PATH_MAX];
    char probe[PATH_MAX];
    char library[PATH_MAX];
    int fail;
};

static int fss_reap(pid_t pid)
{
    int status = 0;
    for (;;) {
        pid_t got = waitpid(pid, &status, 0);
        if (got == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 125;
        if (errno != EINTR)
            return 125;
    }
}

static int fss_take(int fd, char *out, size_t cap)
{
    size_t used = 0;
    if (out == NULL || cap < 2) {
        close(fd);
        return -1;
    }
    out[0] = '\0';
    for (;;) {
        ssize_t n = read(fd, out + used, cap - 1 - used);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        used += (size_t)n;
        out[used] = '\0';
        if (used + 1 >= cap) {
            char dump[64];
            while (read(fd, dump, sizeof dump) > 0)
                ;
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

static void fss_child(char *const argv[], const char *date, int out_fd)
{
    int sink = open("/dev/null", O_RDONLY);
    if (sink >= 0) {
        if (dup2(sink, STDIN_FILENO) < 0)
            _exit(127);
        if (sink > STDERR_FILENO)
            close(sink);
    }
    if (out_fd >= 0) {
        if (dup2(out_fd, STDOUT_FILENO) < 0)
            _exit(127);
        if (out_fd > STDERR_FILENO)
            close(out_fd);
    }
    if (date != NULL && date[0] != '\0') {
        if (setenv("GIT_AUTHOR_DATE", date, 1) != 0)
            _exit(127);
        if (setenv("GIT_COMMITTER_DATE", date, 1) != 0)
            _exit(127);
    }
    execvp(argv[0], argv);
    _exit(127);
}

static int fss_exec(char *const argv[], const char *date, char *out, size_t cap, int *status)
{
    int pipefd[2];
    pid_t pid;
    int capture = out != NULL;
    if (status == NULL)
        return -1;
    pipefd[0] = -1;
    pipefd[1] = -1;
    if (capture && pipe(pipefd) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        if (pipefd[0] >= 0)
            close(pipefd[0]);
        if (pipefd[1] >= 0)
            close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        if (pipefd[0] >= 0)
            close(pipefd[0]);
        fss_child(argv, date, capture ? pipefd[1] : -1);
        _exit(127);
    }
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    if (capture && fss_take(pipefd[0], out, cap) != 0) {
        fss_reap(pid);
        return -1;
    }
    *status = fss_reap(pid);
    return *status == 125 ? -1 : 0;
}

static void fss_trim(char *text)
{
    char *end;
    if (text == NULL)
        return;
    end = text + strlen(text);
    while (end > text && (end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
}

static int fss_git(const char *repo, const char *date, char *const argv[], char *out, size_t cap)
{
    int status = 1;
    (void)repo;
    if (fss_exec(argv, date, out, cap, &status) != 0)
        return -1;
    if (status != 0)
        return -1;
    if (out != NULL)
        fss_trim(out);
    return 0;
}

static int fss_init(const char *repo)
{
    char *init[] = {"git", "-C", (char *)repo, "init", "-q", "-b", "main", NULL};
    char *name[] = {"git", "-C", (char *)repo, "config", "user.name",
                    "fleet-source-test", NULL};
    char *mail[] = {"git", "-C", (char *)repo, "config", "user.email",
                    "fleet-source-test@example.invalid", NULL};
    if (fss_git(repo, NULL, init, NULL, 0) != 0)
        return -1;
    if (fss_git(repo, NULL, name, NULL, 0) != 0)
        return -1;
    return fss_git(repo, NULL, mail, NULL, 0);
}

static int fss_put(const char *repo, const char *name)
{
    char path[PATH_MAX];
    FILE *file;
    int n = snprintf(path, sizeof path, "%s/%s", repo, name);
    if (n < 0 || (size_t)n >= sizeof path)
        return -1;
    file = fopen(path, "w");
    if (file == NULL)
        return -1;
    if (fprintf(file, "%s\n", name) < 0) {
        fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int fss_commit(const char *repo, const char *name, const char *stamp, char *hash, size_t cap)
{
    char *add[] = {"git", "-C", (char *)repo, "add", "--", (char *)name, NULL};
    char *commit[] = {"git", "-C", (char *)repo, "commit", "-q", "-m", (char *)name, NULL};
    char *rev[] = {"git", "-C", (char *)repo, "rev-parse", "HEAD", NULL};
    if (fss_put(repo, name) != 0)
        return -1;
    if (fss_git(repo, NULL, add, NULL, 0) != 0)
        return -1;
    if (fss_git(repo, stamp, commit, NULL, 0) != 0)
        return -1;
    if (fss_git(repo, NULL, rev, hash, cap) != 0)
        return -1;
    return strlen(hash) == 40 ? 0 : -1;
}

static int fss_switch(const char *repo, const char *target, int detach)
{
    char *detached[] = {"git", "-C", (char *)repo, "switch", "-q", "--detach",
                        (char *)target, NULL};
    char *branch[] = {"git", "-C", (char *)repo, "switch", "-q", (char *)target, NULL};
    if (detach)
        return fss_git(repo, NULL, detached, NULL, 0);
    return fss_git(repo, NULL, branch, NULL, 0);
}

static int fss_repeat(char *out, size_t cap, int count, char mark)
{
    int i;
    if ((size_t)count + 1 > cap)
        return -1;
    for (i = 0; i < count; i++)
        out[i] = mark;
    out[count] = '\0';
    return 0;
}

static int fss_row(const char *text, int index, char *out, size_t cap)
{
    const char *p = text;
    int seen = 0;
    if (out == NULL || cap == 0)
        return -1;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t n = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (seen == index) {
            if (n >= cap)
                return -1;
            memcpy(out, p, n);
            out[n] = '\0';
            return 0;
        }
        if (nl == NULL)
            break;
        p = nl + 1;
        seen++;
    }
    return -1;
}

static void fss_expect(struct fss_job *job, const char *label, const char *want, const char *got)
{
    if (want != NULL && got != NULL && strcmp(want, got) == 0) {
        printf("  ok: %s\n", label);
        return;
    }
    fprintf(stderr, "  FAIL: %s expected=%s actual=%s\n",
            label, want != NULL ? want : "", got != NULL ? got : "");
    job->fail = 1;
}

static int fss_probe(struct fss_job *job, char *const argv[], char *out, size_t cap)
{
    return fss_git(job->repo, NULL, argv, out, cap);
}

static int fss_date(struct fss_job *job, const char *label, const char *stamp, const char *want)
{
    char *argv[] = {job->probe, job->library, "date", (char *)stamp, NULL};
    char got[128];
    if (fss_probe(job, argv, got, sizeof got) != 0)
        return -1;
    fss_expect(job, label, want, got);
    return 0;
}

static int fss_audit(struct fss_job *job, const char *head, const char *source,
                     const char *git_sha, const char *floor, char *text, size_t cap)
{
    char *argv[] = {job->probe, job->library, "audit", job->repo, (char *)head,
                    (char *)source, (char *)git_sha, (char *)floor, NULL};
    return fss_probe(job, argv, text, cap);
}

static int fss_got(const char *text, int index, char *out, size_t cap)
{
    if (fss_row(text, index, out, cap) != 0) {
        if (cap > 0)
            out[0] = '\0';
        return -1;
    }
    return 0;
}

static int fss_direct(struct fss_job *job, const char *head, const char *floor)
{
    char text[512];
    char status[64];
    char commit[48];
    char kind[64];
    char date[64];
    char behind[16];
    if (fss_audit(job, head, floor, floor, floor, text, sizeof text) != 0)
        return -1;
    fss_got(text, 0, status, sizeof status);
    fss_got(text, 1, commit, sizeof commit);
    fss_got(text, 2, kind, sizeof kind);
    fss_got(text, 3, date, sizeof date);
    fss_got(text, 4, behind, sizeof behind);
    fss_expect(job, "direct_git_status", "CURRENT", status);
    fss_expect(job, "direct_git_commit", floor, commit);
    fss_expect(job, "direct_source_kind", "legacy_40hex_source", kind);
    fss_expect(job, "direct_git_date", "2026-08-21T02:03:04+00:00", date);
    fss_expect(job, "direct_git_behind", "1", behind);
    return 0;
}

struct fss_want {
    int index;
    const char *label;
    const char *value;
};

static int fss_scene(struct fss_job *job, const char *head, const char *source,
                     const char *git_sha, const char *floor,
                     const struct fss_want *rows, int count)
{
    char text[512];
    int i;
    if (fss_audit(job, head, source, git_sha, floor, text, sizeof text) != 0)
        return -1;
    for (i = 0; i < count; i++) {
        char got[96];
        fss_got(text, rows[i].index, got, sizeof got);
        fss_expect(job, rows[i].label, rows[i].value, got);
    }
    return 0;
}

static int fss_unbound(struct fss_job *job, const char *head, const char *source, const char *floor)
{
    char text[512];
    char status[64];
    char date[64];
    char detail[80];
    if (fss_audit(job, head, source, "", floor, text, sizeof text) != 0)
        return -1;
    fss_got(text, 0, status, sizeof status);
    fss_got(text, 3, date, sizeof date);
    fss_got(text, 5, detail, sizeof detail);
    fss_expect(job, "unbound_runtime_status", "STALE", status);
    fss_expect(job, "unbound_runtime_date", "UNKNOWN", date);
    fss_expect(job, "unbound_runtime_detail", "missing_or_invalid_git_sha", detail);
    return 0;
}

static int fss_missing(struct fss_job *job, const char *head, const char *source, const char *floor)
{
    char missing[48];
    char text[512];
    char status[64];
    char date[64];
    if (fss_repeat(missing, sizeof missing, 40, 'b') != 0)
        return -1;
    if (fss_audit(job, head, source, missing, floor, text, sizeof text) != 0)
        return -1;
    fss_got(text, 0, status, sizeof status);
    fss_got(text, 3, date, sizeof date);
    fss_expect(job, "missing_commit_status", "STALE", status);
    fss_expect(job, "missing_commit_date", "UNKNOWN", date);
    return 0;
}

static int fss_prefloor(struct fss_job *job, const char *head, const char *source,
                        const char *base, const char *floor)
{
    char text[512];
    char status[64];
    char flag[16];
    if (fss_audit(job, head, source, base, floor, text, sizeof text) != 0)
        return -1;
    fss_got(text, 0, status, sizeof status);
    fss_got(text, 6, flag, sizeof flag);
    fss_expect(job, "prefloor_status", "STALE", status);
    fss_expect(job, "prefloor_flag", "yes", flag);
    return 0;
}

static int fss_history(struct fss_job *job, char *base, char *floor, char *head, char *foreign)
{
    if (fss_init(job->repo) != 0)
        return -1;
    if (fss_commit(job->repo, "base", "2026-08-20T01:02:03+00:00", base, 48) != 0)
        return -1;
    if (fss_commit(job->repo, "floor", "2026-08-21T02:03:04+00:00", floor, 48) != 0)
        return -1;
    if (fss_commit(job->repo, "head", "2026-08-22T03:04:05+00:00", head, 48) != 0)
        return -1;
    if (fss_switch(job->repo, base, 1) != 0)
        return -1;
    if (fss_commit(job->repo, "foreign", "2026-08-20T06:07:08+00:00", foreign, 48) != 0)
        return -1;
    return fss_switch(job->repo, "main", 0);
}

static int fss_cases(struct fss_job *job)
{
    char base[48];
    char floor[48];
    char head[48];
    char foreign[48];
    char source[72];
    if (fss_history(job, base, floor, head, foreign) != 0)
        return -1;
    if (fss_date(job, "utc_z_normalized", "2026-08-21T02:03:04Z",
                 "2026-08-21T02:03:04+00:00") != 0)
        return -1;
    if (fss_date(job, "utc_offset_stable", "2026-08-21T02:03:04+00:00",
                 "2026-08-21T02:03:04+00:00") != 0)
        return -1;
    if (fss_repeat(source, sizeof source, 64, 'a') != 0)
        return -1;
    if (fss_direct(job, head, floor) != 0)
        return -1;
    {
        static const struct fss_want bound[] = {
            {0, "bound_runtime_status", "CURRENT"},
            {2, "bound_runtime_kind", "source_id_sha256"},
            {3, "bound_runtime_date", "2026-08-22T03:04:05+00:00"},
        };
        static const struct fss_want foreign_rows[] = {
            {0, "nonancestor_status", "STALE"},
            {3, "nonancestor_date", "2026-08-20T06:07:08+00:00"},
            {5, "nonancestor_detail", "source_commit_not_ancestor_of_observed_main"},
        };
        if (fss_scene(job, head, source, head, head, bound, 3) != 0)
            return -1;
        if (fss_unbound(job, head, source, floor) != 0)
            return -1;
        if (fss_missing(job, head, source, floor) != 0)
            return -1;
        if (fss_scene(job, head, source, foreign, floor, foreign_rows, 3) != 0)
            return -1;
    }
    return fss_prefloor(job, head, source, base, floor);
}

static int fss_workdir(struct fss_job *job)
{
    const char *base = getenv("TMPDIR");
    char templ[PATH_MAX];
    int n;
    if (base == NULL || base[0] == '\0')
        base = "/tmp";
    n = snprintf(templ, sizeof templ, "%s/%s.XXXXXX", base, "z23-fleet-source-status");
    if (n < 0 || (size_t)n >= sizeof templ)
        return -1;
    if (mkdtemp(templ) == NULL)
        return -1;
    memcpy(job->tmp, templ, strlen(templ) + 1);
    n = snprintf(job->repo, sizeof job->repo, "%s/repo", job->tmp);
    if (n < 0 || (size_t)n >= sizeof job->repo)
        return -1;
    if (mkdir(job->repo, 0700) != 0)
        return -1;
    n = snprintf(job->probe, sizeof job->probe, "%s/probe.sh", job->tmp);
    if (n < 0 || (size_t)n >= sizeof job->probe)
        return -1;
    return 0;
}

static int fss_write_probe(const char *path)
{
    FILE *file = fopen(path, "w");
    if (file == NULL)
        return -1;
    if (fputs(k_probe, file) == EOF) {
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0)
        return -1;
    return chmod(path, 0700) == 0 ? 0 : -1;
}

static void fss_wipe(const char *dir)
{
    /* One level of files plus the repo directory. Git writes nested
     * objects, so remove with a recursive walk that stays inside dir. */
    DIR *handle;
    struct dirent *ent;
    if (dir == NULL || dir[0] == '\0')
        return;
    handle = opendir(dir);
    if (handle == NULL)
        return;
    while ((ent = readdir(handle)) != NULL) {
        char path[PATH_MAX];
        struct stat st;
        int n;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        n = snprintf(path, sizeof path, "%s/%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof path)
            continue;
        if (lstat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            fss_wipe(path);
        else
            unlink(path);
    }
    closedir(handle);
    rmdir(dir);
}

static void fss_end(struct fss_job *job)
{
    if (strstr(job->tmp, "z23-fleet-source-status") != NULL)
        fss_wipe(job->tmp);
    job->tmp[0] = '\0';
}

static int fss_run(const char *library)
{
    struct fss_job job;
    mode_t saved;
    int rc;
    memset(&job, 0, sizeof job);
    if (library == NULL || library[0] == '\0' || access(library, R_OK) != 0)
        return fss_fail("library is unreadable");
    if (strlen(library) >= sizeof job.library)
        return fss_fail("library path does not fit");
    memcpy(job.library, library, strlen(library) + 1);
    saved = umask(077);
    rc = fss_workdir(&job);
    if (rc == 0)
        rc = fss_write_probe(job.probe);
    if (rc == 0)
        rc = fss_cases(&job);
    umask(saved);
    fss_end(&job);
    if (rc != 0)
        return fss_fail("git fixture failed");
    if (job.fail)
        return fss_fail(NULL);
    printf("check_fleet_source_status: PASS\n");
    return 0;
}

#endif /* !_WIN32 */

int zcl_fleet_source_status_selftest(const char *library_path)
{
#if defined(_WIN32)
    (void)library_path;
    return fss_fail("unavailable on Windows");
#else
    return fss_run(library_path);
#endif
}
