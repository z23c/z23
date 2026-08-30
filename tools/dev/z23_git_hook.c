/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-fast Git admission for exact local development receipts. */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include "dev_proof_receipt.h"
#include "base/hex.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HOOK_LINE_MAX 1024u
#define HOOK_OUTPUT_MAX 8192u

static void clear_git_local_environment(void)
{
    static const char *const names[] = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_DIR",
        "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX",
        "GIT_QUARANTINE_PATH", "GIT_WORK_TREE",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        (void)unsetenv(names[i]);
}

static const char *program_basename(const char *path)
{
    const char *slash = path ? strrchr(path, '/') : NULL;
    return slash ? slash + 1 : (path ? path : "");
}

static bool oid_text(const char *text)
{
    uint8_t oid[ZCL_DEV_PROOF_OID_MAX], len = 0;
    return zcl_dev_proof_oid_decode(text, oid, &len);
}

static bool oid_zero(const char *text)
{
    if (!text || (strlen(text) != 40 && strlen(text) != 64)) return false;
    for (const char *p = text; *p; p++)
        if (*p != '0') return false;
    return true;
}

static bool read_exact(const char *path, uint8_t *out, size_t size)
{
    struct stat st;
    if (!path || !out || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode) || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        st.st_size != (off_t)size)
        return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t offset = 0;
    while (offset < size) {
        ssize_t n = read(fd, out + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            (void)close(fd);
            return false;
        }
        offset += (size_t)n;
    }
    uint8_t extra;
    ssize_t tail = read(fd, &extra, 1);
    return close(fd) == 0 && tail == 0;
}

static int child_capture(const char *const argv[], char *out, size_t out_size)
{
    int pipefd[2];
    if (!argv || !argv[0] || !out || out_size == 0 || pipe(pipefd) != 0)
        return -1;
    pid_t child = fork();
    if (child < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        (void)close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(127);
        if (pipefd[1] > STDERR_FILENO) (void)close(pipefd[1]);
        clear_git_local_environment();
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    (void)close(pipefd[1]);
    size_t used = 0;
    bool truncated = false;
    for (;;) {
        char discard[1024];
        void *target = used + 1 < out_size ? out + used : discard;
        size_t capacity = used + 1 < out_size ? out_size - used - 1
                                               : sizeof(discard);
        ssize_t n = read(pipefd[0], target, capacity);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) truncated = true;
        if (n <= 0) break;
        if (target == discard) truncated = true;
        else used += (size_t)n;
    }
    (void)close(pipefd[0]);
    out[used] = 0;
    int status = 0;
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR) return -1;
    if (truncated || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static bool repo_root(char out[PATH_MAX])
{
    const char *argv[] = {"git", "rev-parse", "--show-toplevel", NULL};
    if (child_capture(argv, out, PATH_MAX) != 0) return false;
    size_t len = strlen(out);
    while (len && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = 0;
    return len > 0 && out[0] == '/';
}

static bool ancestor(const char *base, const char *local)
{
    char output[HOOK_OUTPUT_MAX];
    const char *argv[] = {"git", "merge-base", "--is-ancestor", base,
                          local, NULL};
    return child_capture(argv, output, sizeof(output)) == 0;
}

static int refusal(const char *state, const char *local, const char *base,
                   int64_t eta_ms)
{
    (void)fprintf(stderr,
        "pre-push: REFUSED status=%s eta_ms=%lld local=%s base=%s; "
        "run build/bin/z23-dev dev proof wait --input='"
        "{\"local_commit\":\"%s\",\"remote_base\":\"%s\"}'\n",
        state, (long long)eta_ms, local, base, local, base);
    return 1;
}

static int64_t running_eta(const char *root, const char *local,
                           const char *base)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     "%s/.cache/zcl-dev-proof/%s-%s.running",
                     root, local, base);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode) || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return -1;
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    long long pid = 0, started = 0;
    bool parsed = fscanf(file, "%lld %lld", &pid, &started) == 2;
    (void)fclose(file);
    if (!parsed || pid <= 1 || started <= 0 || kill((pid_t)pid, 0) != 0)
        return -1;
    struct timespec now = {0};
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return -1;
    int64_t elapsed = (int64_t)now.tv_sec - (int64_t)started;
    int64_t eta = 900000 - (elapsed > 0 ? elapsed * 1000 : 0);
    return eta > 0 ? eta : 0;
}

static int admit_pair(const char *root, const char *local, const char *base)
{
    if (!ancestor(base, local)) return refusal("remote-base-not-ancestor",
                                                local, base, 0);
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     "%s/.cache/zcl-dev-proof/receipts/%s-%s.receipt",
                     root, local, base);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return refusal("receipt-path-invalid", local, base, 0);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    struct zcl_dev_acceptance_receipt_v1 receipt;
    char why[128] = {0};
    if (!read_exact(path, wire, sizeof(wire))) {
        int64_t eta = running_eta(root, local, base);
        return refusal(eta >= 0 ? "running" : "receipt-missing",
                       local, base, eta >= 0 ? eta : 0);
    }
    if (!zcl_dev_proof_receipt_parse(wire, sizeof(wire), &receipt) ||
        !zcl_dev_proof_receipt_validate(&receipt, local, base,
                                        why, sizeof(why)))
        return refusal(why[0] ? why : "receipt-invalid", local, base, 0);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        const struct zcl_dev_proof_dimension *dimension =
            &receipt.dimensions[i];
        if (!dimension->selected) continue;
        char root_hex[65], child_path[PATH_MAX];
        zcl_hex_encode(dimension->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES,
                       root_hex);
        n = snprintf(child_path, sizeof(child_path),
                     "%s/.cache/zcl-dev-proof/children/%s.child",
                     root, root_hex);
        uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
        if (n <= 0 || (size_t)n >= sizeof(child_path) ||
            !read_exact(child_path, child, sizeof(child)) ||
            !zcl_dev_proof_child_receipt_validate(
                child, sizeof(child), (enum zcl_dev_proof_dimension_id)i,
                dimension))
            return refusal("child-receipt-missing-or-invalid", local, base, 0);
    }
    return 0;
}

static int pre_push(void)
{
    char root[PATH_MAX];
    if (!repo_root(root)) {
        (void)fprintf(stderr, "pre-push: REFUSED status=repository-unavailable\n");
        return 1;
    }
    char line[HOOK_LINE_MAX];
    bool saw_update = false;
    while (fgets(line, sizeof(line), stdin)) {
        if (!strchr(line, '\n') && !feof(stdin)) {
            (void)fprintf(stderr, "pre-push: REFUSED status=ref-tuple-truncated\n");
            return 1;
        }
        char local_ref[256], local[65], remote_ref[256], base[65], extra;
        int fields = sscanf(line, "%255s %64s %255s %64s %c", local_ref,
                            local, remote_ref, base, &extra);
        if (fields != 4 || !oid_text(local) || !oid_text(base)) {
            (void)fprintf(stderr, "pre-push: REFUSED status=ref-tuple-invalid\n");
            return 1;
        }
        if (strcmp(remote_ref, "refs/heads/main") != 0) {
            (void)fprintf(stderr,
                          "pre-push: REFUSED status=remote-ref-not-main ref=%s\n",
                          remote_ref);
            return 1;
        }
        if (oid_zero(local))
            return refusal("main-deletion-forbidden", local, base, 0);
        if (oid_zero(base))
            return refusal("advertised-base-missing", local, base, 0);
        saw_update = true;
        if (admit_pair(root, local, base) != 0) return 1;
    }
    if (ferror(stdin)) {
        (void)fprintf(stderr, "pre-push: REFUSED status=ref-input-failed\n");
        return 1;
    }
    if (saw_update)
        (void)fprintf(stderr, "pre-push: PASS exact local receipt admitted\n");
    return 0;
}

static int notify_proof(void)
{
    char root[PATH_MAX], binary[PATH_MAX];
    if (!repo_root(root)) return 0;
    int n = snprintf(binary, sizeof(binary), "%s/build/bin/z23-dev", root);
    if (n <= 0 || (size_t)n >= sizeof(binary) || access(binary, X_OK) != 0)
        return 0;
    pid_t child = fork();
    if (child != 0) return 0;
    if (setsid() < 0) _exit(0);
    int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull >= 0) {
        (void)dup2(devnull, STDIN_FILENO);
        (void)dup2(devnull, STDOUT_FILENO);
        (void)dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) (void)close(devnull);
    }
    if (chdir(root) != 0) _exit(0);
    clear_git_local_environment();
    execl(binary, binary, "dev", "proof", "ensure", (char *)NULL);
    _exit(0);
}

static int compare_u64(const void *a, const void *b)
{
    uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;
    return left < right ? -1 : left > right;
}

static uint64_t sample_clock_ns(void)
{
    struct timespec now = {0};
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return 0;
    return (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
}

static int selftest(void)
{
    static const char local[] =
        "1111111111111111111111111111111111111111";
    static const char base[] =
        "2222222222222222222222222222222222222222";
    struct zcl_dev_acceptance_receipt_v1 receipt = {0};
    if (!zcl_dev_proof_oid_decode(local, receipt.local_commit,
                                  &receipt.local_commit_len) ||
        !zcl_dev_proof_oid_decode(base, receipt.remote_base,
                                  &receipt.remote_base_len))
        return 1;
    uint8_t *roots[] = {
        receipt.source_root, receipt.source_cas_root, receipt.mutation_root,
        receipt.changed_set_root, receipt.impact_policy_root,
        receipt.compiler_root, receipt.flags_root, receipt.environment_root,
        receipt.build_graph_root, receipt.child_set_root,
    };
    for (size_t root = 0; root < sizeof(roots) / sizeof(roots[0]); root++)
        for (size_t i = 0; i < ZCL_DEV_PROOF_ROOT_BYTES; i++)
            roots[root][i] = (uint8_t)(root + i + 1u);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        memset(receipt.dimensions[i].receipt_root, (int)i + 1,
               ZCL_DEV_PROOF_ROOT_BYTES);
        receipt.dimensions[i].selected = 1;
        receipt.dimensions[i].reused = 1;
    }
    receipt.policy_version = 1;
    receipt.complete = 1;
    if (!zcl_dev_proof_receipt_child_set_root(
            &receipt, receipt.child_set_root) ||
        !zcl_dev_proof_receipt_seal(&receipt))
        return 1;
    struct zcl_dev_proof_dimension child_dimension =
        receipt.dimensions[ZCL_DEV_PROOF_TEST];
    uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
    if (!zcl_dev_proof_child_receipt_create(ZCL_DEV_PROOF_TEST,
                                             &child_dimension, child) ||
        !zcl_dev_proof_child_receipt_validate(
            child, sizeof(child), ZCL_DEV_PROOF_TEST, &child_dimension))
        return 1;
    child[40] ^= 1u;
    if (zcl_dev_proof_child_receipt_validate(
            child, sizeof(child), ZCL_DEV_PROOF_TEST, &child_dimension))
        return 1;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    if (!zcl_dev_proof_receipt_serialize(&receipt, wire)) return 1;
    char fixture[] = "/tmp/z23-git-hook-receipt.XXXXXX";
    int fixture_fd = mkstemp(fixture);
    if (fixture_fd < 0) return 1;
    size_t written = 0;
    while (written < sizeof(wire)) {
        ssize_t n = write(fixture_fd, wire + written, sizeof(wire) - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            (void)close(fixture_fd);
            (void)unlink(fixture);
            return 1;
        }
        written += (size_t)n;
    }
    if (fsync(fixture_fd) != 0 || close(fixture_fd) != 0) {
        (void)unlink(fixture);
        return 1;
    }
    uint64_t samples[1000];
    char why[128];
    for (size_t i = 0; i < 1000; i++) {
        struct zcl_dev_acceptance_receipt_v1 parsed;
        uint8_t admitted[ZCL_DEV_PROOF_WIRE_BYTES];
        uint64_t start = sample_clock_ns();
        if (!read_exact(fixture, admitted, sizeof(admitted)) ||
            !zcl_dev_proof_receipt_parse(admitted, sizeof(admitted), &parsed) ||
            !zcl_dev_proof_receipt_validate(&parsed, local, base,
                                            why, sizeof(why))) {
            (void)unlink(fixture);
            return 1;
        }
        samples[i] = sample_clock_ns() - start;
    }
    if (unlink(fixture) != 0) return 1;
    qsort(samples, 1000, sizeof(samples[0]), compare_u64);
    struct zcl_dev_acceptance_receipt_v1 tampered = receipt;
    tampered.dimensions[ZCL_DEV_PROOF_TEST].skipped = 1;
    if (zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    tampered = receipt;
    memset(tampered.compiler_root, 0, sizeof(tampered.compiler_root));
    if (!zcl_dev_proof_receipt_seal(&tampered) ||
        zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    tampered = receipt;
    tampered.complete = 0;
    if (!zcl_dev_proof_receipt_seal(&tampered) ||
        zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    tampered = receipt;
    tampered.child_set_root[0] ^= 1u;
    if (!zcl_dev_proof_receipt_seal(&tampered) ||
        zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    if (zcl_dev_proof_receipt_validate(&receipt, local,
          "3333333333333333333333333333333333333333", why, sizeof(why)))
        return 1;
    wire[100] ^= 1u;
    struct zcl_dev_acceptance_receipt_v1 parsed;
    if (!zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed) ||
        zcl_dev_proof_receipt_validate(&parsed, local, base,
                                       why, sizeof(why)))
        return 1;
    (void)printf("git-hook-selftest: PASS checks=1000 p95_us=%llu "
                 "tamper_refused=true incomplete_refused=true "
                 "hollow_refused=true stale_refused=true child_processes=0\n",
                 (unsigned long long)(samples[949] / 1000u));
    return samples[949] < 250000000u ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *mode = program_basename(argv[0]);
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) return selftest();
    if (argc >= 2 && strncmp(argv[1], "--hook=", 7) == 0)
        mode = argv[1] + 7;
    if (strcmp(mode, "pre-push") == 0) return pre_push();
    if (strcmp(mode, "post-commit") == 0 ||
        strcmp(mode, "post-merge") == 0 ||
        strcmp(mode, "post-checkout") == 0)
        return notify_proof();
    (void)fprintf(stderr, "z23-git-hook: unknown hook mode '%s'\n", mode);
    return 2;
}
