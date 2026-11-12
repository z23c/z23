/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Refuse stable release publication. --verify checks one archive. */

#define _POSIX_C_SOURCE 200809L

#include "release_containment.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int rc_error(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    return 1;
}

static int rc_usage(const char *argv0)
{
    fprintf(stderr, "ERROR: usage: %s --verify <archive.tar.gz>\n", argv0);
    return 1;
}

static int rc_err_path(const char *prefix, const char *path)
{
    char msg[PATH_MAX + 80];
    int n = snprintf(msg, sizeof msg, "%s%s", prefix, path);
    if (n < 0 || (size_t)n >= sizeof msg)
        return rc_error(prefix);
    return rc_error(msg);
}

static int rc_mismatch(const char *expect, const char *actual)
{
    char msg[256];
    snprintf(msg, sizeof msg, "SHA3-256 mismatch: expected=%s actual=%s",
             expect, actual);
    return rc_error(msg);
}

static int rc_reap(pid_t pid)
{
    int status = 0;
    pid_t got;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got != pid || !WIFEXITED(status))
        return 1;
    return WEXITSTATUS(status);
}

static void rc_slurp(int fd, char *out, size_t cap)
{
    char junk[64];
    ssize_t n;
    if (out == NULL || cap < 2) {
        while (read(fd, junk, sizeof junk) > 0)
            ;
        return;
    }
    do {
        n = read(fd, out, cap - 1);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
        n = 0;
    out[n] = '\0';
    while (read(fd, junk, sizeof junk) > 0)
        ;
}

static int rc_fa_close(posix_spawn_file_actions_t *actions, int fd)
{
    if (fd < 0)
        return 0;
    return posix_spawn_file_actions_addclose(actions, fd);
}

static int rc_fa_begin(posix_spawn_file_actions_t *actions, int out_fd,
                       int err_fd, int close0, int close1, int close2)
{
    if (posix_spawn_file_actions_init(actions) != 0)
        return -1;
    if (posix_spawn_file_actions_adddup2(actions, out_fd, STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(actions, err_fd, STDERR_FILENO) != 0 ||
        rc_fa_close(actions, close0) != 0 ||
        rc_fa_close(actions, close1) != 0 ||
        rc_fa_close(actions, close2) != 0) {
        posix_spawn_file_actions_destroy(actions);
        return -1;
    }
    return 0;
}

static int rc_quiet(char *const argv[])
{
    posix_spawn_file_actions_t actions;
    pid_t pid = 0;
    int sink = open("/dev/null", O_WRONLY);
    int spawned;
    if (sink < 0)
        return -1;
    if (rc_fa_begin(&actions, sink, sink, sink, -1, -1) != 0) {
        close(sink);
        return -1;
    }
    spawned = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(sink);
    if (spawned != 0)
        return -1;
    return rc_reap(pid);
}

static int rc_capture(char *const argv[], char *out, size_t cap)
{
    posix_spawn_file_actions_t actions;
    int fds[2];
    int sink;
    int spawned;
    pid_t pid = 0;
    if (pipe(fds) != 0)
        return -1;
    sink = open("/dev/null", O_WRONLY);
    if (sink < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (rc_fa_begin(&actions, fds[1], sink, fds[0], fds[1], sink) != 0) {
        close(sink);
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    spawned = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(sink);
    close(fds[1]);
    if (spawned != 0) {
        close(fds[0]);
        return -1;
    }
    rc_slurp(fds[0], out, cap);
    close(fds[0]);
    return rc_reap(pid);
}

static int rc_regular(const char *path)
{
    struct stat st;
    if (path == NULL || stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) ? 1 : 0;
}

static int rc_executable(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    return access(path, X_OK) == 0;
}

static int rc_path_hit(const char *dir, size_t n, const char *name)
{
    char buf[PATH_MAX];
    size_t name_n = strlen(name);
    if (n == 0 || n + 1 + name_n + 1 > sizeof buf)
        return 0;
    memcpy(buf, dir, n);
    buf[n] = '/';
    memcpy(buf + n + 1, name, name_n + 1);
    return rc_executable(buf);
}

static int rc_on_path(const char *name)
{
    const char *path = getenv("PATH");
    const char *cursor;
    if (path == NULL || name == NULL || name[0] == '\0' || strchr(name, '/') != NULL)
        return 0;
    cursor = path;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ':');
        size_t n = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        if (rc_path_hit(cursor, n, name))
            return 1;
        if (end == NULL)
            break;
        cursor = end + 1;
    }
    return 0;
}

static int rc_ends(const char *text, const char *suffix)
{
    size_t text_n = strlen(text);
    size_t suffix_n = strlen(suffix);
    if (text_n < suffix_n)
        return 0;
    return memcmp(text + text_n - suffix_n, suffix, suffix_n) == 0;
}

static int rc_join_suffix(const char *base, size_t n, const char *suffix,
                          char *out, size_t cap)
{
    size_t suffix_n = strlen(suffix);
    if (n + suffix_n + 1 > cap)
        return -1;
    memcpy(out, base, n);
    memcpy(out + n, suffix, suffix_n + 1);
    return 0;
}

static int rc_side_paths(const char *archive, char *sha3, size_t sha3_cap,
                         char *sig, size_t sig_cap)
{
    size_t n = strlen(archive);
    if (rc_ends(archive, ".tar.gz"))
        n -= strlen(".tar.gz");
    if (rc_join_suffix(archive, n, ".sha3", sha3, sha3_cap) != 0)
        return -1;
    return rc_join_suffix(sha3, strlen(sha3), ".sig", sig, sig_cap);
}

static const char *rc_ws(const char *text)
{
    while (*text == ' ' || *text == '\t')
        text++;
    return text;
}

static int rc_field_end(char c)
{
    return c == '\0' || c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static const char *rc_take(const char *text, char *out, size_t cap)
{
    size_t n = 0;
    text = rc_ws(text);
    if (text[0] == '\0' || text[0] == '\n' || text[0] == '\r')
        return NULL;
    while (!rc_field_end(text[n]))
        n++;
    if (n + 1 > cap)
        return NULL;
    memcpy(out, text, n);
    out[n] = '\0';
    return text + n;
}

static int rc_skip_field(const char **cursor)
{
    const char *text = rc_ws(*cursor);
    if (text[0] == '\0' || text[0] == '\n' || text[0] == '\r')
        return 0;
    while (!rc_field_end(*text))
        text++;
    *cursor = text;
    return 1;
}

static int rc_exactly_two(const char *line, char *first, size_t cap)
{
    const char *rest = rc_take(line, first, cap);
    if (rest == NULL || rc_skip_field(&rest) == 0)
        return 0;
    rest = rc_ws(rest);
    return rest[0] == '\0' || rest[0] == '\n' || rest[0] == '\r';
}

static int rc_hex64(const char *text)
{
    static const char digits[] = "0123456789abcdefABCDEF";
    size_t i;
    if (text == NULL)
        return 0;
    for (i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c == 0 || strchr(digits, c) == NULL)
            return 0;
    }
    return text[64] == '\0';
}

static int rc_manifest_hex(const char *path, char *out, size_t cap)
{
    FILE *file = fopen(path, "r");
    char line[512];
    char field[80];
    if (file == NULL)
        return -1;
    if (fgets(line, (int)sizeof line, file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);
    if (rc_exactly_two(line, field, sizeof field) == 0 || rc_hex64(field) == 0)
        return -1;
    if (strlen(field) + 1 > cap)
        return -1;
    memcpy(out, field, strlen(field) + 1);
    return 0;
}

static char rc_fold(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (char)(c - 'A' + 'a');
    return c;
}

static int rc_same_hex(const char *left, const char *right)
{
    size_t i = 0;
    if (left == NULL || right == NULL)
        return 0;
    while (left[i] != '\0' && right[i] != '\0') {
        if (rc_fold(left[i]) != rc_fold(right[i]))
            return 0;
        i++;
    }
    return left[i] == '\0' && right[i] == '\0';
}

static int rc_last_token(const char *text, char *out, size_t cap)
{
    const char *start = NULL;
    size_t n = 0;
    const char *cursor = text;
    if (text == NULL)
        return -1;
    while (*cursor != '\0') {
        size_t len = 0;
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' ||
               *cursor == '\r')
            cursor++;
        if (*cursor == '\0')
            break;
        start = cursor;
        while (!rc_field_end(*cursor)) {
            cursor++;
            len++;
        }
        n = len;
    }
    if (start == NULL || n + 1 > cap)
        return -1;
    memcpy(out, start, n);
    out[n] = '\0';
    return 0;
}

static int rc_openssl_digest(const char *archive, char *out, size_t cap)
{
    char raw[512];
    char *argv[5];
    int status;
    argv[0] = "openssl";
    argv[1] = "dgst";
    argv[2] = "-sha3-256";
    argv[3] = (char *)archive;
    argv[4] = NULL;
    raw[0] = '\0';
    status = rc_capture(argv, raw, sizeof raw);
    if (status != 0)
        return status < 0 ? 1 : status;
    if (rc_last_token(raw, out, cap) != 0)
        out[0] = '\0';
    return 0;
}

static int rc_gpg(const char *sig, const char *sha3)
{
    char *argv[5];
    argv[0] = "gpg";
    argv[1] = "--verify";
    argv[2] = (char *)sig;
    argv[3] = (char *)sha3;
    argv[4] = NULL;
    return rc_quiet(argv);
}

static int rc_tar_list(const char *archive)
{
    char *argv[4];
    argv[0] = "tar";
    argv[1] = "-tzf";
    argv[2] = (char *)archive;
    argv[3] = NULL;
    return rc_quiet(argv);
}

static int rc_verify(const char *archive)
{
    char sha3[PATH_MAX];
    char sig[PATH_MAX];
    char expect[80];
    char actual[80];
    int status;
    if (!rc_regular(archive))
        return rc_err_path("archive not found: ", archive);
    if (rc_side_paths(archive, sha3, sizeof sha3, sig, sizeof sig) != 0)
        return rc_error("archive path is too long");
    if (!rc_regular(sha3))
        return rc_err_path("required SHA3 manifest missing: ", sha3);
    if (!rc_regular(sig))
        return rc_err_path("required detached signature missing: ", sig);
    if (!rc_on_path("openssl"))
        return rc_error("openssl is required");
    if (!rc_on_path("gpg"))
        return rc_error("gpg is required");
    if (rc_manifest_hex(sha3, expect, sizeof expect) != 0)
        return rc_err_path("malformed SHA3 manifest: ", sha3);
    status = rc_openssl_digest(archive, actual, sizeof actual);
    if (status != 0)
        return status;
    if (!rc_same_hex(expect, actual))
        return rc_mismatch(expect, actual);
    if (rc_gpg(sig, sha3) != 0)
        return rc_error("GPG signature verification failed");
    if (rc_tar_list(archive) != 0)
        return rc_error("archive structure is invalid");
    fputs("legacy_local_artifact_verification=PASS\n"
          "stable_release_verification=NOT_IMPLEMENTED\n"
          "publishable=false\n",
          stdout);
    return 0;
}
#endif

static int rc_refuse(void)
{
    fputs("REFUSING: stable release build/package/sign/publish is contained.\n",
          stderr);
    fputs("Required first: exact immutable quality evidence, complete canonical security posture,\n",
          stderr);
    fputs("clean parity/soak, two-builder byte identity, SBOM/provenance, signature quorum,\n",
          stderr);
    fputs("offline verification, upgrade, and rollback proof.\n", stderr);
    fputs("Unsigned output is local-development-only; use ordinary build targets for local binaries.\n",
          stderr);
    return 2;
}

int zcl_release_invoke(int argc, char **argv)
{
#if defined(_WIN32)
    (void)argc;
    (void)argv;
    return rc_refuse();
#else
    const char *prog = (argv != NULL && argv[0] != NULL) ? argv[0] : "release";
    if (argc >= 2 && argv != NULL && argv[1] != NULL &&
        strcmp(argv[1], "--verify") == 0) {
        if (argc != 3 || argv[2] == NULL || argv[2][0] == '\0')
            return rc_usage(prog);
        return rc_verify(argv[2]);
    }
    return rc_refuse();
#endif
}
