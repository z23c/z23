/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: enter a filesystem-confined environment before a fixed C23 AI adapter. */

#define _GNU_SOURCE

#include "base/cleanse.h"
#include "platform/os_sandbox.h"
#include "platform/process_compat.h"
#include "sha3/sha3.h"
#include "util/result.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ADAPTER_PACKET_MAX (512u * 1024u)

#ifndef ZCL_BUILD_SOURCE_ID
#define ZCL_BUILD_SOURCE_ID "unknown"
#endif

volatile sig_atomic_t g_shutdown_requested = 0;

static bool adapter_beneath(const char *parent, const char *child)
{
    size_t len = strlen(parent);
    return strncmp(parent, child, len) == 0 && child[len] == '/';
}

static bool adapter_codex_path(char out[PATH_MAX])
{
    struct passwd pwd, *found = NULL;
    char scratch[16384];
    if (getpwuid_r(getuid(), &pwd, scratch, sizeof(scratch), &found) != 0 ||
        !found || !pwd.pw_dir || !pwd.pw_dir[0])
        return false;
    char link[PATH_MAX];
    int n = snprintf(link, sizeof(link), "%s/.local/bin/codex", pwd.pw_dir);
    if (n <= 0 || (size_t)n >= sizeof(link) || !realpath(link, out))
        return false;
    struct stat st;
    return stat(out, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == getuid() && (st.st_mode & 0111u) != 0 &&
           (st.st_mode & 0022u) == 0;
}

static bool adapter_file_sha3(const char *path, char out[65])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    uint8_t buffer[8192];
    bool ok = true;
    while (ok) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) ok = false;
        if (got <= 0) break;
        sha3_256_write(&sha, buffer, (size_t)got);
    }
    uint8_t digest[32];
    if (ok) sha3_256_finalize(&sha, digest);
    if (close(fd) != 0) ok = false;
    static const char hex[] = "0123456789abcdef";
    if (ok) {
        for (size_t i = 0; i < sizeof(digest); i++) {
            out[i * 2u] = hex[digest[i] >> 4u];
            out[i * 2u + 1u] = hex[digest[i] & 15u];
        }
        out[64] = '\0';
    }
    return ok;
}

static bool adapter_mkdir(const char *path)
{
    struct stat st;
    if (mkdir(path, 0700) == 0)
        return true;
    return errno == EEXIST && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == getuid() && (st.st_mode & 0077u) == 0;
}

static void adapter_rule_add(struct os_sandbox_path_rule *rules,
                             size_t *count, const char *path, bool write,
                             bool execute, bool create)
{
    if (access(path, F_OK) != 0)
        return;
    rules[*count] = (struct os_sandbox_path_rule){
        .path = path,
        .allow_read = true,
        .allow_write = write,
        .allow_execute = execute,
        .allow_create = create,
    };
    (*count)++;
}

/* The adapter's process budget. RLIMIT_NPROC is charged across the real uid,
 * not this adapter's subtree, so neither an absolute allowance nor one
 * rebased on a snapshot of the uid's task count is a budget for the adapter:
 * both are (limit − whatever else this account happens to be running), and
 * the snapshot form additionally races every task started between the sample
 * and the adapter's own forks. See platform/os_sandbox.h "process budget".
 *
 * So: install a STATIC absolute backstop (clamped only by the uid's NPROC
 * hard limit, which is host configuration, not host load), and treat "this
 * host has no process table left" as its own refusal with the numbers in it
 * — never as an adapter failure. */
#define ADAPTER_NPROC_BACKSTOP 65536u
#define ADAPTER_NPROC_REQUIRED 128u
static bool adapter_nproc_limit(uint64_t *out)
{
    struct os_sandbox_process_budget budget = os_sandbox_process_budget_live(
        ADAPTER_NPROC_BACKSTOP, ADAPTER_NPROC_REQUIRED);
    if (!budget.admitted) {
        fprintf(stderr,
                "adapter_runner: process-headroom-exhausted "
                "nproc_backstop=%llu uid_tasks=%llu hard=%llu headroom=%llu "
                "required=%llu\n",
                (unsigned long long)budget.ceiling,
                (unsigned long long)budget.uid_tasks,
                (unsigned long long)budget.hard,
                (unsigned long long)budget.headroom,
                (unsigned long long)budget.required);
        return false;
    }
    *out = budget.ceiling;
    return true;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--identity") == 0) {
        printf("{\"schema\":\"zcl.zcode_adapter_runner_identity.v1\","
               "\"source_id\":\"%s\"}\n", ZCL_BUILD_SOURCE_ID);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--binding") == 0) {
        char codex_path[PATH_MAX], digest[65];
        if (!adapter_codex_path(codex_path) ||
            !adapter_file_sha3(codex_path, digest)) {
            fprintf(stderr, "adapter_runner: fixed Codex binding unavailable\n");
            return 69;
        }
        printf("{\"schema\":\"zcl.zcode_adapter_executable_binding.v1\","
               "\"ready\":true,\"artifact_sha3\":\"%s\"}\n", digest);
        return 0;
    }
    bool preflight = argc == 4 && strcmp(argv[1], "--preflight") == 0;
    if ((!preflight && argc != 3) || (preflight && argc != 4)) {
        fprintf(stderr, "adapter_runner: candidate and packet required\n");
        return 64;
    }
    const char *candidate_arg = argv[preflight ? 2 : 1];
    const char *packet_arg = argv[preflight ? 3 : 2];
    char candidate[PATH_MAX], packet[PATH_MAX], codex[PATH_MAX];
    if (!realpath(candidate_arg, candidate) || !realpath(packet_arg, packet) ||
        !adapter_beneath(candidate, packet) ||
        (!preflight && !adapter_codex_path(codex))) {
        fprintf(stderr, "adapter_runner: fixed adapter or paths unavailable\n");
        return 69;
    }
    int packet_fd = open(packet, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat packet_st;
    if (packet_fd < 0 || fstat(packet_fd, &packet_st) != 0 ||
        !S_ISREG(packet_st.st_mode) || packet_st.st_size <= 0 ||
        (uint64_t)packet_st.st_size > ADAPTER_PACKET_MAX) {
        if (packet_fd >= 0) close(packet_fd);
        fprintf(stderr, "adapter_runner: bounded packet refused\n");
        return 65;
    }
    const char *credential_name = "CODEX_API_KEY";
    const char *inherited_key = preflight ? NULL : getenv(credential_name);
    const char *access_token = preflight ? NULL : getenv("CODEX_ACCESS_TOKEN");
    if (!preflight && (!inherited_key || !inherited_key[0]) && access_token &&
        access_token[0]) {
        credential_name = "CODEX_ACCESS_TOKEN";
        inherited_key = access_token;
    }
    if (!preflight &&
        (!inherited_key || !inherited_key[0] ||
         strlen(inherited_key) > 16384u ||
         (getenv("CODEX_API_KEY") && getenv("CODEX_API_KEY")[0] &&
          access_token && access_token[0]))) {
        close(packet_fd);
        fprintf(stderr, "adapter_runner: one supported Codex credential required\n");
        return 69;
    }
    char *api_key = preflight ? NULL : strdup(inherited_key);
    char adapter_home[PATH_MAX], adapter_tmp[PATH_MAX];
    int hn = snprintf(adapter_home, sizeof(adapter_home),
                      "%s/.zcode-adapter-home", candidate);
    int tn = snprintf(adapter_tmp, sizeof(adapter_tmp),
                      "%s/.zcode-adapter-tmp", candidate);
    if ((!preflight && !api_key) || hn <= 0 ||
        (size_t)hn >= sizeof(adapter_home) ||
        tn <= 0 || (size_t)tn >= sizeof(adapter_tmp) ||
        !adapter_mkdir(adapter_home) || !adapter_mkdir(adapter_tmp)) {
        free(api_key); close(packet_fd);
        fprintf(stderr, "adapter_runner: private adapter directories unavailable\n");
        return 73;
    }
    if (platform_clear_environment() != 0 ||
        (!preflight && setenv(credential_name, api_key, 1) != 0) ||
        setenv("HOME", adapter_home, 1) != 0 ||
        setenv("CODEX_HOME", adapter_home, 1) != 0 ||
        setenv("TMPDIR", adapter_tmp, 1) != 0 ||
        setenv("PATH", "/usr/bin:/bin", 1) != 0 ||
        setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt", 1) != 0) {
        if (api_key) memory_cleanse(api_key, strlen(api_key));
        free(api_key); close(packet_fd);
        fprintf(stderr, "adapter_runner: environment scrub failed\n");
        return 70;
    }
    if (api_key) memory_cleanse(api_key, strlen(api_key));
    free(api_key);

    uint64_t nproc_limit = 0;
    if (!adapter_nproc_limit(&nproc_limit)) {
        close(packet_fd);
        fprintf(stderr, "adapter_runner: process-limit baseline unavailable\n");
        return 70;
    }
    struct os_sandbox_rlimits limits = {
        .as_bytes = UINT64_C(4) * 1024u * 1024u * 1024u,
        .cpu_seconds = 300,
        .nproc = nproc_limit,
        .fsize_bytes = 16u * 1024u * 1024u,
        .nofile = 256,
        .core_bytes = 0,
    };
    struct zcl_result limited = os_sandbox_set_rlimits(&limits);
    if (!limited.ok || !os_sandbox_no_new_privs()) {
        close(packet_fd);
        fprintf(stderr, "adapter_runner: resource confinement unavailable\n");
        return 70;
    }
    struct os_sandbox_path_rule rules[20];
    size_t count = 0;
    adapter_rule_add(rules, &count, candidate, true, false, true);
    if (!preflight)
        adapter_rule_add(rules, &count, codex, false, true, false);
    adapter_rule_add(rules, &count, "/usr", false, true, false);
    adapter_rule_add(rules, &count, "/bin", false, true, false);
    adapter_rule_add(rules, &count, "/lib", false, true, false);
    adapter_rule_add(rules, &count, "/lib64", false, true, false);
    adapter_rule_add(rules, &count, "/etc/ssl", false, false, false);
    adapter_rule_add(rules, &count, "/etc/resolv.conf", false, false, false);
    adapter_rule_add(rules, &count, "/etc/hosts", false, false, false);
    adapter_rule_add(rules, &count, "/etc/nsswitch.conf", false, false, false);
    adapter_rule_add(rules, &count, "/etc/passwd", false, false, false);
    adapter_rule_add(rules, &count, "/etc/group", false, false, false);
    adapter_rule_add(rules, &count, "/dev/null", true, false, false);
    adapter_rule_add(rules, &count, "/dev/urandom", false, false, false);
    adapter_rule_add(rules, &count, OS_SANDBOX_PROC_SELF_PATH,
                     false, false, false);
    struct zcl_result confined = os_sandbox_landlock_restrict(rules, count);
    if (!confined.ok) {
        close(packet_fd);
        fprintf(stderr, "adapter_runner: Landlock confinement unavailable\n");
        return 70;
    }
    if (chdir(candidate) != 0 || dup2(packet_fd, STDIN_FILENO) < 0 ||
        (!preflight && dup2(STDOUT_FILENO, STDERR_FILENO) < 0)) {
        close(packet_fd);
        fprintf(stderr, "adapter_runner: confined I/O setup failed\n");
        return 70;
    }
    if (packet_fd > STDERR_FILENO)
        close(packet_fd);
    if (preflight) {
        const char sentinel[] = ".zcode-adapter-preflight";
        int fd = open(sentinel, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                O_NOFOLLOW, 0600);
        bool ok = fd >= 0;
        if (fd >= 0) {
            ok = close(fd) == 0;
            fd = -1;
        }
        if (ok) ok = unlink(sentinel) == 0;
        if (!ok) {
            (void)unlink(sentinel);
            fprintf(stderr, "adapter_runner: sandbox write probe failed\n");
            return 70;
        }
        printf("{\"schema\":\"zcl.zcode_adapter_sandbox_preflight.v1\","
               "\"sandbox_started\":true,"
               "\"model_request_attempted\":false}\n");
        return 0;
    }
    const char *const codex_argv[] = {
        codex, "exec", "--sandbox", "workspace-write", "-C", candidate,
        "--skip-git-repo-check", "--ephemeral", "--ignore-user-config",
        "--ignore-rules", "--color", "never",
        "-c", "shell_environment_policy.inherit=none",
        "-c", "shell_environment_policy.set.PATH=\"/usr/bin:/bin\"",
        "-c", "shell_environment_policy.set.HOME=\".\"",
        "-c", "shell_environment_policy.set.TMPDIR=\".zcode-adapter-tmp\"",
        "-", NULL,
    };
    execv(codex, (char *const *)codex_argv);
    fprintf(stderr, "adapter_runner: fixed codex exec failed\n");
    return 127;
}
