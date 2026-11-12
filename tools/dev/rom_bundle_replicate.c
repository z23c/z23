/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Copy a consensus-state bundle and its replay receipt to a second
 *          directory and prove the copy with the SHA3 tool. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "rom_bundle_replicate.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define RBR_PATH 4096
#define RBR_HEX 128

static const char k_usage[] =
    "rom-bundle-replicate: copy a verified consensus-state bundle and its\n"
    "replay receipt to a second directory and prove the copy by SHA3-256.\n"
    "\n"
    "Usage:\n"
    "  rom-bundle-replicate --bundle=PATH --receipt=PATH --dest=DIR\n"
    "      [--binary=PATH] [--sha3-tool=PATH]\n"
    "\n"
    "Exit codes: 0 PASS, 1 digest mismatch, 2 usage or a missing input.\n";

struct rbr_job {
    const char *bundle;
    const char *receipt;
    const char *dest;
    const char *binary;
    const char *sha3;
    char bundle_sha[RBR_HEX];
    char receipt_sha[RBR_HEX];
    char binary_sha[RBR_HEX];
    int have_binary;
};

static int rbr_reap(pid_t child)
{
    int status = 0;
    for (;;) {
        pid_t got = waitpid(child, &status, 0);
        if (got == child && WIFEXITED(status))
            return WEXITSTATUS(status);
        if (got == child)
            return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
        if (errno != EINTR)
            return 125;
    }
}

static int rbr_glue(char *out, size_t cap, const char *left, char mid, const char *right);

static int rbr_drain(int fd)
{
    for (;;) {
        char dump[128];
        ssize_t got = read(fd, dump, sizeof dump);
        if (got == 0)
            return 0;
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return -1;
    }
}

static int rbr_field_byte(int fd, char *out, size_t cap)
{
    size_t n = 0;
    for (;;) {
        unsigned char b = 0;
        ssize_t got = read(fd, &b, 1);
        if (got == 0)
            break;
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return -1;
        if (b == ' ' || b == '\t' || b == '\n' || b == '\r')
            break;
        if (n + 1 >= cap)
            return -1;
        out[n++] = (char)b;
    }
    out[n] = '\0';
    if (rbr_drain(fd) != 0)
        return -1;
    return n == 0 ? -1 : 0;
}

/* Child stdout is a private pipe. Only the first field is kept; the rest of
 * the line, including a path longer than any fixed buffer, is discarded. */
static int rbr_tool_field(char *const argv[], char *out, size_t cap)
{
    int rd;
    int wr;
    pid_t child;
    int field;
    int rc;
    int ends[2];

    if (pipe(ends) != 0)
        return 127;
    rd = ends[0];
    wr = ends[1];
    child = fork();
    if (child == 0) {
        int wired = dup2(wr, STDOUT_FILENO);
        close(rd);
        close(wr);
        if (wired < 0)
            _exit(127);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(wr);
    if (child < 0) {
        close(rd);
        return 127;
    }
    field = rbr_field_byte(rd, out, cap);
    close(rd);
    rc = rbr_reap(child);
    if (rc != 0)
        return rc;
    if (field != 0)
        return 1;
    return 0;
}

static int rbr_status(char *const argv[])
{
    pid_t child = fork();
    if (child < 0)
        return 127;
    if (child == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return rbr_reap(child);
}

static int rbr_digest(const char *tool, const char *file, char *out, size_t cap)
{
    char *argv[] = {(char *)tool, (char *)file, NULL};
    return rbr_tool_field(argv, out, cap);
}

static int rbr_glue(char *out, size_t cap, const char *left, char mid, const char *right)
{
    size_t nl = strlen(left);
    size_t nr = strlen(right);
    if (mid == '\0' || nl + nr + 2 > cap)
        return -1;
    memcpy(out, left, nl);
    out[nl] = mid;
    memcpy(out + nl + 1, right, nr + 1);
    return 0;
}

static const char *rbr_base(const char *path)
{
    const char *slash = strrchr(path, '/');
    if (slash == NULL || slash[1] == '\0')
        return path;
    return slash + 1;
}

static int rbr_nonempty(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (!S_ISREG(st.st_mode))
        return 0;
    return st.st_size > 0;
}

static int rbr_tmp_name(char *out, size_t cap, const char *dest)
{
    char tail[32];
    int n = snprintf(tail, sizeof tail, ".tmp.%ld", (long)getpid());
    if (n < 0)
        return -1;
    if ((size_t)n >= sizeof tail)
        return -1;
    return rbr_glue(out, cap, dest, '.', tail + 1);
}

static int rbr_copy(const char *src, const char *dest)
{
    char tmp[RBR_PATH];
    char *argv[] = {"cp", "--", (char *)src, tmp, NULL};
    int rc;
    if (rbr_tmp_name(tmp, sizeof tmp, dest) != 0)
        return 1;
    rc = rbr_status(argv);
    if (rc != 0) {
        unlink(tmp);
        return rc;
    }
    if (rename(tmp, dest) != 0) {
        unlink(tmp);
        return 1;
    }
    return 0;
}

static int rbr_take_opt(const char *arg, const char *key, const char **slot)
{
    size_t n = strlen(key);
    if (strncmp(arg, key, n) != 0)
        return 0;
    *slot = arg + n;
    return 1;
}

static int rbr_parse(int argc, char **argv, struct rbr_job *job, int *help)
{
    int i;
    memset(job, 0, sizeof *job);
    *help = 0;
    for (i = 0; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            *help = 1;
            return 0;
        }
        if (rbr_take_opt(arg, "--bundle=", &job->bundle))
            continue;
        if (rbr_take_opt(arg, "--receipt=", &job->receipt))
            continue;
        if (rbr_take_opt(arg, "--dest=", &job->dest))
            continue;
        if (rbr_take_opt(arg, "--binary=", &job->binary))
            continue;
        if (rbr_take_opt(arg, "--sha3-tool=", &job->sha3))
            continue;
        fprintf(stderr, "rom-bundle-replicate: unknown option %s\n", arg);
        fputs(k_usage, stderr);
        return 2;
    }
    return 0;
}

static int rbr_need(const struct rbr_job *job)
{
    if (job->bundle == NULL || job->bundle[0] == '\0') {
        fprintf(stderr, "rom-bundle-replicate: --bundle=PATH is required\n");
        return 2;
    }
    if (job->receipt == NULL || job->receipt[0] == '\0') {
        fprintf(stderr, "rom-bundle-replicate: --receipt=PATH is required\n");
        return 2;
    }
    if (job->dest == NULL || job->dest[0] == '\0') {
        fprintf(stderr, "rom-bundle-replicate: --dest=DIR is required\n");
        return 2;
    }
    if (!rbr_nonempty(job->bundle)) {
        fprintf(stderr, "rom-bundle-replicate: bundle not found or empty: %s\n",
                job->bundle);
        return 2;
    }
    if (!rbr_nonempty(job->receipt)) {
        fprintf(stderr, "rom-bundle-replicate: receipt not found or empty: %s\n",
                job->receipt);
        return 2;
    }
    if (job->sha3 == NULL || access(job->sha3, X_OK) != 0) {
        fprintf(stderr,
                "rom-bundle-replicate: %s not built (run: make tools/rom_bundle_sha3)\n",
                job->sha3 == NULL ? "" : job->sha3);
        return 2;
    }
    return 0;
}

static void rbr_plan(const struct rbr_job *job, const char *dest_bundle,
                     const char *dest_receipt, const char *dest_hash)
{
    const char *shown = job->binary;
    printf("======================================================================\n");
    printf("  rom-bundle-replicate plan\n");
    printf("  bundle:  %s\n", job->bundle);
    printf("  receipt: %s\n", job->receipt);
    if (shown != NULL && shown[0] != '\0')
        printf("  binary:  %s\n", shown);
    else
        printf("  binary:  <none — hash step skipped>\n");
    printf("  dest:    %s\n", job->dest);
    printf("  steps:\n");
    printf("    1. sha3 of source bundle + receipt\n");
    printf("    2. cp bundle  -> %s (via temp + atomic rename)\n", dest_bundle);
    printf("       cp receipt -> %s (via temp + atomic rename, canonical name)\n",
           dest_receipt);
    printf("    3. record producing binary SHA3 -> %s\n", dest_hash);
    printf("    4. sha3 of the DEST copies; require exact match to step 1\n");
    printf("======================================================================\n");
}

static int rbr_mkdir_dest(const char *dest)
{
    char *argv[] = {"mkdir", "-p", "--", (char *)dest, NULL};
    return rbr_status(argv);
}

static int rbr_stamp(char *out, size_t cap)
{
    char *argv[] = {"date", "+%s", NULL};
    return rbr_tool_field(argv, out, cap);
}

static int rbr_record(struct rbr_job *job, const char *dest_hash, const char *base)
{
    char tmp[RBR_PATH];
    char when[32];
    FILE *fp;
    int rc = rbr_digest(job->sha3, job->binary, job->binary_sha, sizeof job->binary_sha);
    if (rc != 0)
        return rc;
    if (rbr_stamp(when, sizeof when) != 0)
        return 1;
    if (rbr_tmp_name(tmp, sizeof tmp, dest_hash) != 0)
        return 1;
    fp = fopen(tmp, "w");
    if (fp == NULL) {
        unlink(tmp);
        return 1;
    }
    if (fprintf(fp,
                "# rom-bundle-replicate producing-binary record\n"
                "binary_path: %s\n"
                "binary_sha3: %s\n"
                "bundle: %s\n"
                "bundle_sha3: %s\n"
                "replicated_at_unix: %s\n",
                job->binary, job->binary_sha, base, job->bundle_sha, when) < 0) {
        fclose(fp);
        unlink(tmp);
        return 1;
    }
    if (fclose(fp) != 0) {
        unlink(tmp);
        return 1;
    }
    if (rename(tmp, dest_hash) != 0) {
        unlink(tmp);
        return 1;
    }
    job->have_binary = 1;
    printf("[rom-bundle-replicate] producing binary sha3: %s (%s)\n",
           job->binary_sha, job->binary);
    return 0;
}

static int rbr_verify(const struct rbr_job *job, const char *dest_bundle,
                      const char *dest_receipt)
{
    char got_bundle[RBR_HEX];
    char got_receipt[RBR_HEX];
    int fail = 0;
    int rc = rbr_digest(job->sha3, dest_bundle, got_bundle, sizeof got_bundle);
    if (rc != 0)
        return rc;
    rc = rbr_digest(job->sha3, dest_receipt, got_receipt, sizeof got_receipt);
    if (rc != 0)
        return rc;
    if (strcmp(got_bundle, job->bundle_sha) != 0) {
        fprintf(stderr,
                "FAIL: bundle copy digest mismatch: dest=%s want=%s\n",
                got_bundle, job->bundle_sha);
        fail = 1;
    }
    if (strcmp(got_receipt, job->receipt_sha) != 0) {
        fprintf(stderr,
                "FAIL: receipt copy digest mismatch: dest=%s want=%s\n",
                got_receipt, job->receipt_sha);
        fail = 1;
    }
    if (!fail)
        return 0;
    fprintf(stderr, "FAIL: rom-bundle-replicate — copy not verified, see mismatches above\n");
    return 1;
}

static int rbr_paths(const struct rbr_job *job, char *dest_bundle, char *dest_receipt,
                     char *dest_hash, size_t cap)
{
    if (rbr_glue(dest_bundle, cap, job->dest, '/', rbr_base(job->bundle)) != 0)
        return -1;
    if (rbr_glue(dest_receipt, cap, job->dest, '/', "consensus_state_replay_receipt.v1") != 0)
        return -1;
    if (rbr_glue(dest_hash, cap, job->dest, '/', "producing_binary_sha3.txt") != 0)
        return -1;
    return 0;
}

static int rbr_go(const char *repo, struct rbr_job *job)
{
    char dest_bundle[RBR_PATH];
    char dest_receipt[RBR_PATH];
    char dest_hash[RBR_PATH];
    int rc;
    (void)repo;
    if (rbr_need(job) != 0)
        return 2;
    if (rbr_paths(job, dest_bundle, dest_receipt, dest_hash, RBR_PATH) != 0)
        return 2;
    rbr_plan(job, dest_bundle, dest_receipt, dest_hash);
    if (rbr_mkdir_dest(job->dest) != 0)
        return 1;
    rc = rbr_digest(job->sha3, job->bundle, job->bundle_sha, sizeof job->bundle_sha);
    if (rc != 0)
        return rc;
    rc = rbr_digest(job->sha3, job->receipt, job->receipt_sha, sizeof job->receipt_sha);
    if (rc != 0)
        return rc;
    printf("[rom-bundle-replicate] source bundle  sha3: %s\n", job->bundle_sha);
    printf("[rom-bundle-replicate] source receipt sha3: %s\n", job->receipt_sha);
    rc = rbr_copy(job->bundle, dest_bundle);
    if (rc != 0)
        return rc;
    rc = rbr_copy(job->receipt, dest_receipt);
    if (rc != 0)
        return rc;
    if (job->binary != NULL && job->binary[0] != '\0' && access(job->binary, X_OK) == 0) {
        rc = rbr_record(job, dest_hash, rbr_base(job->bundle));
        if (rc != 0)
            return rc;
    } else {
        fprintf(stderr,
                "[rom-bundle-replicate] NOTE: producing binary not found/executable at '%s'"
                " — skipping the binary-hash record\n",
                job->binary == NULL ? "" : job->binary);
    }
    rc = rbr_verify(job, dest_bundle, dest_receipt);
    if (rc != 0)
        return rc;
    printf("PASS: rom-bundle-replicate — copy verified byte-identical by SHA3-256\n");
    printf("  %s\n", dest_bundle);
    printf("  %s\n", dest_receipt);
    if (job->have_binary)
        printf("  %s\n", dest_hash);
    printf("\n");
    printf("Point a node at this directory to serve it: -rombundlereplicadir=%s\n",
           job->dest);
    return 0;
}

static int rbr_dispatch(const char *repo, int argc, char **argv)
{
    struct rbr_job job;
    int help = 0;
    int rc;
    if (repo == NULL || repo[0] == '\0') {
        fprintf(stderr, "rom-bundle-replicate: repo is required\n");
        return 2;
    }
    rc = rbr_parse(argc, argv, &job, &help);
    if (rc != 0)
        return rc;
    if (help) {
        fputs(k_usage, stdout);
        return 0;
    }
    /* Defaults are stored in rbr_need on the stack of that call. Keep the
     * resolved paths here so they outlive the check. */
    {
        char sha3[RBR_PATH];
        char binary[RBR_PATH];
        int sha3_default = job.sha3 == NULL;
        int binary_default = job.binary == NULL;
        if (sha3_default) {
            if (rbr_glue(sha3, sizeof sha3, repo, '/', "build/bin/rom_bundle_sha3") != 0)
                return 2;
            job.sha3 = sha3;
        }
        if (binary_default) {
            if (rbr_glue(binary, sizeof binary, repo, '/', "build/bin/zclassic23") != 0)
                return 2;
            job.binary = binary;
        }
        return rbr_go(repo, &job);
    }
}

#endif /* !_WIN32 */

int zcl_rom_bundle_replicate(const char *repo, int argc, char **argv)
{
#if defined(_WIN32)
    (void)repo;
    (void)argc;
    (void)argv;
    fprintf(stdout, "rom-bundle-replicate: unavailable on Windows\n");
    return 2;
#else
    return rbr_dispatch(repo, argc, argv);
#endif
}
