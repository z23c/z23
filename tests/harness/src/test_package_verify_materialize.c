/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_package_verify_materialize: descriptor custody and verified bytes in
 * tools/package_verify.c pv_materialize_write_chunks.
 *
 * The defect this pins. On a write error other than EINTR the function freed
 * its chunk and closed the output descriptor, broke out of the loop and then
 * freed the chunk again (double free); its read-failure return closed the
 * descriptor too, while the caller closes it after every call (double close,
 * which can shut a descriptor another thread just reopened). It also wrote
 * the stored chunk bytes without checking them against the manifest hash,
 * and a write(2) that returned 0 for a non-empty remainder spun forever.
 *
 * The rule asserted: the CALLER owns the descriptor for its whole life; the
 * function never closes it. Every stored chunk is verified against the
 * manifest BEFORE any of its bytes are written. The caller removes the whole
 * work tree on a false return (pv_rm_rf in the verifier), so a partial output
 * is never left as if valid; this test pins the byte count written.
 *
 * Seam: the test includes the real implementation (the way
 * tools/package_verify_fix_admit_test.c does) and drives the private
 * function; the write(2) call goes through a ZCL_TESTING function pointer so
 * a zero-byte write can be injected. */

#define _GNU_SOURCE

#include "test/test_core.h"
#if defined(__linux__) || defined(__APPLE__)
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
enum pvm_group_fault { PVM_GROUP_NORMAL, PVM_GROUP_BOTH, PVM_GROUP_PARENT };
static enum pvm_group_fault pvm_group_setup_fault;
static int pvm_setpgid(pid_t pid, pid_t pgid)
{
    if (pvm_group_setup_fault == PVM_GROUP_BOTH) { errno = EPERM; return -1; }
    if (pvm_group_setup_fault == PVM_GROUP_PARENT && pid != 0) { errno = EACCES; return -1; }
    int rc = setpgid(pid, pgid);
    if (pid == 0 && (rc != 0 || getpgrp() != getpid())) {
        dprintf(STDERR_FILENO, "test: child group setup failed rc=%d errno=%d\n", rc, errno); _exit(79);
    }
    return rc;
}
#define setpgid pvm_setpgid
static int pvm_wait_fault;
static unsigned pvm_wait_calls;
static pid_t pvm_wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    ++pvm_wait_calls;
    if (pvm_wait_fault) {
        int error = pvm_wait_fault;
        if (error == EINTR) pvm_wait_fault = 0;
        errno = error;
        return -1;
    }
    return wait4(pid, status, options, usage);
}
#define wait4 pvm_wait4
#endif

#undef _DEFAULT_SOURCE
#define main pv_tool_main
#define g_shutdown_requested pvm_g_shutdown_requested
#define os_sandbox_process_group_census pvm_process_group_census
#include "../../../tools/package_verify.c"
#if defined(__linux__) || defined(__APPLE__)
#undef wait4
#undef setpgid
#endif
#undef os_sandbox_process_group_census
#undef g_shutdown_requested
#undef main

static uint64_t pvm_census_value;
static bool pvm_census_advance;
uint64_t pvm_process_group_census(pid_t pgid)
{
    (void)pgid;
    if (pvm_census_advance && pvm_census_value == 1) {
        pvm_census_value = 2;
        return 1;
    }
    return pvm_census_value;
}

#define PVM_CHECK(name, expr)                                          \
    do {                                                               \
        if (expr) {                                                    \
            printf("  package_verify_materialize: %s... OK\n", (name)); \
        } else {                                                       \
            printf("  package_verify_materialize: %s... FAIL\n", (name)); \
            failures++;                                                \
        }                                                              \
    } while (0)

/* A failed setup step is recorded once and the case returns through its
 * cleanup at once; it never continues on a half-built fixture. */
#define PVM_NEED(name, expr)                                           \
    do {                                                               \
        if (!(expr)) {                                                 \
            printf("  package_verify_materialize: %s... FAIL\n", (name)); \
            failures++;                                                \
            pvm_case_close(&c);                                        \
            return failures;                                           \
        }                                                              \
    } while (0)

#define PVM_TAIL_BYTES 4096u

struct pvm_case {
    char dir[PATH_MAX];
    char out[PATH_MAX + 16];
    struct vcs_package_file file;
    uint8_t *bytes;     /* the whole logical file */
    size_t bytes_len;
};

static bool pvm_write_all_file(const char *path, const uint8_t *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(p, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool pvm_mkdir_p(const char *path)
{
    return pv_mkdir_p(path, 0755);
}

static const char *pvm_hex_of_chunk(const struct pvm_case *c, uint32_t i,
                                    char hex[65])
{
    if (!c || !c->file.chunk_hashes || i >= c->file.chunk_count) return NULL;
    zcl_hex_encode(c->file.chunk_hashes + (size_t)i * 32u, 32, hex);
    return hex;
}

static bool pvm_store_chunk(const struct pvm_case *c, uint32_t i)
{
    char hex[65], sub[PATH_MAX + 64], path[PATH_MAX + 200];
    if (!pvm_hex_of_chunk(c, i, hex)) return false;
    snprintf(sub, sizeof(sub), "%s/cas/sha3/%.2s", c->dir, hex);
    snprintf(path, sizeof(path), "%s/%s", sub, hex);
    const uint8_t *p = c->bytes + (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
    size_t n = i == 0 ? VCS_PACKAGE_CHUNK_BYTES : PVM_TAIL_BYTES;
    return pvm_mkdir_p(sub) && pvm_write_all_file(path, p, n);
}

/* Build a two-chunk file (1 MiB + tail) with both chunks stored in the CAS
 * layout the materializer reads. */
static bool pvm_case_open(struct pvm_case *c, const char *tag)
{
    memset(c, 0, sizeof(*c));
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "pvmat_%s", tag);
    if (!test_mkdtemp(c->dir, sizeof(c->dir), prefix)) return false;
    snprintf(c->out, sizeof(c->out), "%s/out.bin", c->dir);

    c->bytes_len = (size_t)VCS_PACKAGE_CHUNK_BYTES + PVM_TAIL_BYTES;
    c->bytes = zcl_malloc(c->bytes_len, "pvm_bytes");
    if (!c->bytes) return false;
    for (size_t i = 0; i < c->bytes_len; i++)
        c->bytes[i] = (uint8_t)((i * 131u + (i >> 9)) & 0xffu);

    uint8_t hashes[64];
    if (!vcs_package_chunk_hash(c->bytes, VCS_PACKAGE_CHUNK_BYTES, hashes) ||
        !vcs_package_chunk_hash(c->bytes + VCS_PACKAGE_CHUNK_BYTES,
                                PVM_TAIL_BYTES, hashes + 32))
        return false;
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool added = vcs_package_manifest_add(&m, "a.bin", VCS_PACKAGE_MODE_FILE,
                                          c->bytes_len, hashes, 2);
    if (added) {
        c->file.mode = m.files[0].mode;
        c->file.size = m.files[0].size;
        c->file.chunk_count = m.files[0].chunk_count;
        c->file.chunk_hashes = zcl_malloc(64, "pvm_hashes");
        if (c->file.chunk_hashes)
            memcpy(c->file.chunk_hashes, m.files[0].chunk_hashes, 64);
        c->file.path = strdup(m.files[0].path);
    }
    vcs_package_manifest_free(&m);
    if (!added || !c->file.chunk_hashes || !c->file.path) return false;

    return pvm_store_chunk(c, 0) && pvm_store_chunk(c, 1);
}

static void pvm_case_close(struct pvm_case *c)
{
    char cmd_path[PATH_MAX + 8];
    snprintf(cmd_path, sizeof(cmd_path), "%s", c->dir);
    if (c->dir[0]) pv_rm_rf(cmd_path);
    free(c->file.chunk_hashes);
    free(c->file.path);
    free(c->bytes);
}

static bool pvm_chunk_path(const struct pvm_case *c, uint32_t i, char *path,
                           size_t cap)
{
    char hex[65];
    if (!pvm_hex_of_chunk(c, i, hex)) return false;
    int n = snprintf(path, cap, "%s/cas/sha3/%.2s/%s", c->dir, hex, hex);
    return n > 0 && (size_t)n < cap;
}

static bool pvm_fd_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1;
}

static long pvm_file_len(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

/* A write that makes no progress on a non-empty remainder. */
static int pvm_zero_calls;
static ssize_t pvm_write_zero(int fd, const void *buf, size_t n)
{
    (void)fd;
    (void)buf;
    (void)n;
    pvm_zero_calls++;
    return pvm_zero_calls > 1000 ? -1 : 0;
}

/* Seams shared by T1 and the P cases. A double close of an already-closed
 * descriptor returns EBADF without changing the open count, so the count
 * alone cannot see it; the close spy counts calls. */
static int pvm_close_calls;
static int pvm_close_last_fd = -1;
static int pvm_close_spy(int fd)
{
    pvm_close_calls++;
    pvm_close_last_fd = fd;
    return close(fd);
}

/* Writes the first chunk for real, then fails ENOSPC: a short write followed
 * by the error, on a real descriptor, identically on every platform. */
static size_t pvm_written;
static ssize_t pvm_write_enospc_second_chunk(int fd, const void *buf,
                                             size_t n)
{
    if (pvm_written >= VCS_PACKAGE_CHUNK_BYTES) {
        errno = ENOSPC;
        return -1;
    }
    ssize_t w = write(fd, buf, n);
    if (w > 0) pvm_written += (size_t)w;
    return w;
}

static int pvm_open_fds(void)
{
    int n = 0;
    for (int fd = 0; fd < 1024; fd++)
        if (fcntl(fd, F_GETFD) != -1) n++;
    return n;
}

/* T1: ENOSPC injected through the write seam against a real temporary
 * output descriptor (no platform device). */
static int t_write_error_custody(void)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("T1: fixture built", pvm_case_open(&c, "enospc"));
    int fd = open(c.out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    PVM_NEED("T1: output opened", fd >= 0);
    pvm_close_calls = 0;
    pvm_written = 0;
    pv_materialize_close_fn = pvm_close_spy;
    pv_materialize_write_fn = pvm_write_enospc_second_chunk;
    int before = pvm_open_fds();
    bool ok = pv_materialize_write_chunks(fd, &c.file, c.dir);
    int after = pvm_open_fds();
    pv_materialize_write_fn = write;
    pv_materialize_close_fn = close;
    PVM_CHECK("T1: a write error returns false", !ok);
    PVM_CHECK("T1: the function closed nothing", pvm_close_calls == 0);
    PVM_CHECK("T1: no descriptor leaked or closed", before == after);
    PVM_CHECK("T1: the descriptor is still open and the caller's",
              pvm_fd_open(fd));
    PVM_CHECK("T1: the caller's close succeeds exactly once",
              close(fd) == 0);
    PVM_CHECK("T1: the first chunk was written before the error",
              pvm_file_len(c.out) == (long)VCS_PACKAGE_CHUNK_BYTES);
    PVM_CHECK("T1: the caller's cleanup removes the partial output",
              pv_rm_rf(c.dir) && access(c.out, F_OK) != 0);
    pvm_case_close(&c);
    return failures;
}

/* T2: the first chunk file is missing. */
static int t_missing_chunk_custody(void)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("T2: fixture built", pvm_case_open(&c, "missing"));
    char path[PATH_MAX + 200];
    PVM_NEED("T2: chunk path", pvm_chunk_path(&c, 0, path, sizeof(path)));
    PVM_NEED("T2: chunk removed", unlink(path) == 0);
    int fd = open(c.out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    PVM_NEED("T2: output opened", fd >= 0);
    if (fd >= 0) {
        bool ok = pv_materialize_write_chunks(fd, &c.file, c.dir);
        PVM_CHECK("T2: a missing chunk returns false", !ok);
        PVM_CHECK("T2: the descriptor is still open and the caller's",
                  pvm_fd_open(fd));
        PVM_CHECK("T2: the caller's close succeeds exactly once",
                  close(fd) == 0);
        PVM_CHECK("T2: nothing was written", pvm_file_len(c.out) == 0);
    }
    pvm_case_close(&c);
    return failures;
}

/* T3: a stored chunk with one flipped byte never reaches the output. */
static int t_corrupt_chunk_unwritten(void)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("T3: fixture built", pvm_case_open(&c, "corrupt"));
    char path[PATH_MAX + 200];
    PVM_NEED("T3: chunk path", pvm_chunk_path(&c, 1, path, sizeof(path)));
    c.bytes[VCS_PACKAGE_CHUNK_BYTES + 17] ^= 0x01u;
    PVM_NEED("T3: tail chunk corrupted on disk",
              pvm_write_all_file(path, c.bytes + VCS_PACKAGE_CHUNK_BYTES,
                                 PVM_TAIL_BYTES));
    int fd = open(c.out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    PVM_NEED("T3: output opened", fd >= 0);
    if (fd >= 0) {
        bool ok = pv_materialize_write_chunks(fd, &c.file, c.dir);
        PVM_CHECK("T3: a corrupt chunk returns false", !ok);
        PVM_CHECK("T3: no byte of the corrupt chunk was written",
                  pvm_file_len(c.out) == (long)VCS_PACKAGE_CHUNK_BYTES);
        PVM_CHECK("T3: the descriptor is still open and the caller's",
                  pvm_fd_open(fd));
        PVM_CHECK("T3: the caller's close succeeds exactly once",
                  close(fd) == 0);
    }
    /* A corrupt FIRST chunk writes nothing at all. */
    c.bytes[VCS_PACKAGE_CHUNK_BYTES + 17] ^= 0x01u;
    c.bytes[5] ^= 0x80u;
    PVM_NEED("T3: head chunk corrupted on disk",
              pvm_chunk_path(&c, 0, path, sizeof(path)) &&
              pvm_write_all_file(path, c.bytes, VCS_PACKAGE_CHUNK_BYTES));
    fd = open(c.out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    PVM_NEED("T3: head output opened", fd >= 0);
    {
        PVM_CHECK("T3: a corrupt head chunk returns false",
                  !pv_materialize_write_chunks(fd, &c.file, c.dir));
        PVM_CHECK("T3: nothing was written for a corrupt head chunk",
                  pvm_file_len(c.out) == 0);
        PVM_CHECK("T3: head case close succeeds", close(fd) == 0);
    }
    pvm_case_close(&c);
    return failures;
}

/* T4: write(2) returning 0 for a non-empty remainder fails, no spin. */
static int t_zero_write_fails(void)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("T4: fixture built", pvm_case_open(&c, "zero"));
    int fd = open(c.out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    PVM_NEED("T4: output opened", fd >= 0);
    if (fd >= 0) {
        pvm_zero_calls = 0;
        pv_materialize_write_fn = pvm_write_zero;
        bool ok = pv_materialize_write_chunks(fd, &c.file, c.dir);
        pv_materialize_write_fn = write;
        PVM_CHECK("T4: a zero-byte write returns false", !ok);
        PVM_CHECK("T4: it failed at once, without spinning",
                  pvm_zero_calls == 1);
        PVM_CHECK("T4: the descriptor is still the caller's",
                  pvm_fd_open(fd));
        PVM_CHECK("T4: the caller's close succeeds", close(fd) == 0);
    }
    pvm_case_close(&c);
    return failures;
}

/* T5: the success path is byte-identical and closes nothing. */
static int t_success_identical(void)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("T5: fixture built", pvm_case_open(&c, "ok"));
    int fd = open(c.out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    PVM_NEED("T5: output opened", fd >= 0);
    if (fd >= 0) {
        PVM_CHECK("T5: the verified chunks are written",
                  pv_materialize_write_chunks(fd, &c.file, c.dir));
        PVM_CHECK("T5: the descriptor is still open", pvm_fd_open(fd));
        PVM_CHECK("T5: the caller's single close succeeds", close(fd) == 0);
        size_t n = 0;
        uint8_t *got = pv_read_file(c.out, c.bytes_len, &n);
        PVM_CHECK("T5: output equals the concatenated chunks",
                  got && n == c.bytes_len && memcmp(got, c.bytes, n) == 0);
        free(got);
    }
    pvm_case_close(&c);
    return failures;
}

/* ── production boundary: pv_materialize_package ─────────────────────
 * Ceiling: these cases drive pv_materialize_package; the caller's cleanup is
 * invoked by the test, the full verifier caller is not exercised.
 * Cleanup contract (tools/package_verify.c, the call site in the verifier
 * body): pv_materialize_package never removes anything; on false the caller
 * logs and runs pv_rm_rf(work), so no partial tree survives. The P cases
 * assert false + descriptor custody here, then run the same pv_rm_rf(work)
 * the caller runs and assert the output is gone. Descriptor custody is
 * asserted by the open-descriptor count AND by a close seam: a double close
 * of an already-closed descriptor returns EBADF without changing the count,
 * so the count alone cannot see it. */

enum pvm_fault { PVM_NONE, PVM_MISSING, PVM_CORRUPT, PVM_ENOSPC };

/* Build the fixture, inject the fault, drive pv_materialize_package. */
static int pvm_package_case(const char *tag, enum pvm_fault fault)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("P: fixture built", pvm_case_open(&c, tag));
    char src_root[PATH_MAX + 16], dest[PATH_MAX + 32], path[PATH_MAX + 200];
    snprintf(src_root, sizeof(src_root), "%s/work/src", c.dir);
    snprintf(dest, sizeof(dest), "%s/a.bin", src_root);
    PVM_NEED("P: src root", pvm_mkdir_p(src_root));
    if (fault == PVM_MISSING)
        PVM_NEED("P: chunk removed",
                  pvm_chunk_path(&c, 0, path, sizeof(path)) &&
                  unlink(path) == 0);
    if (fault == PVM_CORRUPT) {
        c.bytes[VCS_PACKAGE_CHUNK_BYTES + 3] ^= 0x01u;
        PVM_NEED("P: tail chunk corrupted",
                  pvm_chunk_path(&c, 1, path, sizeof(path)) &&
                  pvm_write_all_file(path, c.bytes + VCS_PACKAGE_CHUNK_BYTES,
                                     PVM_TAIL_BYTES));
    }
    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    if (!vcs_package_manifest_add(&m, "a.bin", VCS_PACKAGE_MODE_FILE,
                                  c.file.size, c.file.chunk_hashes, 2)) {
        printf("  package_verify_materialize: P: manifest built... FAIL\n");
        failures++;
        vcs_package_manifest_free(&m);
        pvm_case_close(&c);
        return failures;
    }
    pvm_close_calls = 0;
    pvm_close_last_fd = -1;
    pvm_written = 0;
    pv_materialize_close_fn = pvm_close_spy;
    if (fault == PVM_ENOSPC)
        pv_materialize_write_fn = pvm_write_enospc_second_chunk;
    int before = pvm_open_fds();
    bool ok = pv_materialize_package(false, &m, c.dir, src_root);
    int after = pvm_open_fds();
    pv_materialize_close_fn = close;
    pv_materialize_write_fn = write;

    PVM_CHECK("P: result matches the fault", ok == (fault == PVM_NONE));
    PVM_CHECK("P: no descriptor leaked", before == after);
    PVM_CHECK("P: the output descriptor was closed exactly once",
              pvm_close_calls == 1 && pvm_close_last_fd >= 0);
    if (fault == PVM_NONE) {
        size_t n = 0;
        uint8_t *got = pv_read_file(dest, c.bytes_len, &n);
        PVM_CHECK("P: output equals the concatenated chunks",
                  got && n == c.bytes_len && memcmp(got, c.bytes, n) == 0);
        free(got);
    } else {
        char work[PATH_MAX + 16];
        snprintf(work, sizeof(work), "%s/work", c.dir);
        PVM_CHECK("P: the caller's pv_rm_rf(work) clears the output",
                  pv_rm_rf(work) && access(dest, F_OK) != 0 &&
                  access(work, F_OK) != 0);
    }
    vcs_package_manifest_free(&m);
    pvm_case_close(&c);
    return failures;
}

static int t_package_boundary(void)
{
    return pvm_package_case("p1", PVM_MISSING) +
           pvm_package_case("p2", PVM_CORRUPT) +
           pvm_package_case("p4", PVM_NONE) +
           pvm_package_case("p3", PVM_ENOSPC);
}

/* T7: a declared size that disagrees with the stored tail length. The
 * manifest entry is structurally valid (two chunks, the tail hash is the SHA3
 * of the real 4096 stored bytes), but the declared size makes the expected
 * tail length 4097. Helper level: the file size field is set directly on the
 * fixture's vcs_package_file; the package level is not covered. */
static int pvm_run_sized(struct pvm_case *c, uint64_t size, bool *ok,
                         int *close_calls)
{
    int fd = open(c->out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    c->file.size = size;
    pvm_close_calls = 0;
    pv_materialize_close_fn = pvm_close_spy;
    *ok = pv_materialize_write_chunks(fd, &c->file, c->dir);
    pv_materialize_close_fn = close;
    *close_calls = pvm_close_calls;
    return fd;
}

static int t_size_disagrees_with_tail(void)
{
    int failures = 0;
    struct pvm_case c;
    PVM_NEED("T7: fixture built", pvm_case_open(&c, "sizemis"));
    bool ok = true;
    int calls = -1;
    int fd = pvm_run_sized(&c, (uint64_t)VCS_PACKAGE_CHUNK_BYTES +
                                   PVM_TAIL_BYTES + 1u, &ok, &calls);
    PVM_NEED("T7: output opened", fd >= 0);
    PVM_CHECK("T7: a declared size 1 over the stored tail returns false", !ok);
    PVM_CHECK("T7: the function closed nothing", calls == 0);
    PVM_CHECK("T7: the descriptor is still the caller's", pvm_fd_open(fd));
    PVM_CHECK("T7: the caller's close succeeds exactly once", close(fd) == 0);
    PVM_CHECK("T7: the head chunk is written and not one tail byte",
              pvm_file_len(c.out) == (long)VCS_PACKAGE_CHUNK_BYTES);
    fd = pvm_run_sized(&c, (uint64_t)VCS_PACKAGE_CHUNK_BYTES +
                               PVM_TAIL_BYTES, &ok, &calls);
    PVM_NEED("T7: control output opened", fd >= 0);
    PVM_CHECK("T7: control: the exact declared size succeeds", ok);
    PVM_CHECK("T7: control: nothing closed by the function", calls == 0);
    PVM_CHECK("T7: control: the caller's close succeeds", close(fd) == 0);
    size_t n = 0;
    uint8_t *got = pv_read_file(c.out, c.bytes_len, &n);
    PVM_CHECK("T7: control: bytes identical",
              got && n == c.bytes_len && memcmp(got, c.bytes, n) == 0);
    free(got);
    pvm_case_close(&c);
    return failures;
}

#if defined(__linux__) || defined(__APPLE__)
static void pvm_census_close(int fds[4])
{
    for (int i = 0; i < 4; ++i) if (fds[i] >= 0) close(fds[i]);
}

static void pvm_census_child(void)
{
    sigset_t signals;
    if (setpgid(0, 0) != 0 || signal(SIGALRM, SIG_DFL) == SIG_ERR ||
        sigemptyset(&signals) != 0 || sigaddset(&signals, SIGALRM) != 0 ||
        sigprocmask(SIG_UNBLOCK, &signals, NULL) != 0) _exit(1);
    alarm(10);
    for (;;) pause();
}

static bool pvm_census_setup(int fds[4], pid_t *pid)
{
    int a[2], b[2];
    for (int i = 0; i < 4; ++i) fds[i] = -1;
    if (pipe(a) != 0) return false;
    fds[0] = a[0]; fds[1] = a[1];
    if (pipe(b) != 0) { pvm_census_close(fds); return false; }
    fds[2] = b[0]; fds[3] = b[1];
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0 || fcntl(fds[2], F_SETFL, O_NONBLOCK) < 0) { pvm_census_close(fds); return false; }
    *pid = fork();
    if (*pid < 0) { pvm_census_close(fds); return false; }
    if (*pid == 0) pvm_census_child();
    if (setpgid(*pid, *pid) != 0 && errno != EACCES) { (void)kill(*pid, SIGKILL); pvm_census_close(fds); return false; }
    if (getpgid(*pid) != *pid) { (void)kill(*pid, SIGKILL); pvm_census_close(fds); return false; }
    close(fds[1]); fds[1] = -1; close(fds[3]); fds[3] = -1;
    return true;
}

static void pvm_census_reap(pid_t pid)
{
    if (pid <= 0) return;
    pid_t probe;
    do { probe = waitpid(pid, NULL, WNOHANG); }
    while (probe < 0 && errno == EINTR);
    if (probe == pid || (probe < 0 && errno == ECHILD)) return;
    if (probe < 0) return;
    (void)kill(-pid, SIGKILL); (void)kill(pid, SIGKILL);
    for (int i = 0; i < 500; ++i) {
        pid_t got = waitpid(pid, NULL, WNOHANG);
        if (got == pid || (got < 0 && errno == ECHILD)) return;
        struct timespec delay = {.tv_nsec = 10000000}; (void)nanosleep(&delay, NULL); /* real-clock: bounded real-child reap; kernel completion has no injected clock */
    }
}

static int t_census_unavailable(void)
{
    int failures = 0, fds[4]; pid_t pid = -1;
    if (!pvm_census_setup(fds, &pid)) { pvm_census_reap(pid); return 1; }
    int out[2] = {fds[0], -1}, err[2] = {fds[2], -1};
    struct pv_run run = {.subtree_budget = 1};
    size_t out_len = 0, err_len = 0;
    int status = 0; bool reaped = false; struct rusage usage = {0};
    pvm_census_value = UINT64_MAX;
    pvm_census_advance = false;
    pv_run_child_wait_loop(pid, out, err, clock_now_monotonic_ns() + 5000000000LL,
                           &run, &out_len, &err_len, &status, &reaped, &usage);
    PVM_CHECK("unavailable census fails sandbox without claiming budget excess",
              reaped && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL && run.sandbox_fail &&
              run.census_unavailable && !run.budget_exceeded && run.subtree_peak == 0 && !run.timed_out &&
              strstr(run.stderr_buf, "process-group census unavailable") != NULL);
    const char *classification = pv_run_process_failure(&run);
    PVM_CHECK("unavailable census is a retryable resource failure",
              classification && strcmp(classification, "process-census-unavailable") == 0 &&
              pv_report_process_failure(&run, "test", false) == PV_EXIT_RESOURCE_WEDGE);
    pvm_census_reap(pid);
    pvm_census_close(fds);
    return failures;
}

static int t_census_budget_control(void)
{
    int failures = 0, fds[4]; pid_t pid = -1;
    if (!pvm_census_setup(fds, &pid)) { pvm_census_reap(pid); return 1; }
    int out[2] = {fds[0], -1}, err[2] = {fds[2], -1};
    struct pv_run run = {.subtree_budget = 1};
    size_t out_len = 0, err_len = 0;
    int status = 0; bool reaped = false; struct rusage usage = {0};
    pvm_census_value = 1; pvm_census_advance = true;
    pv_run_child_wait_loop(pid, out, err, clock_now_monotonic_ns() + 5000000000LL,
                           &run, &out_len, &err_len, &status, &reaped, &usage);
    PVM_CHECK("valid census enforces only an actual budget excess",
              reaped && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL &&
              run.budget_exceeded && !run.sandbox_fail && run.subtree_peak == 2 && !run.timed_out);
    if (!reaped) pvm_census_reap(pid);
    pvm_census_close(fds);
    return failures;
}

static int pvm_wait_fault_case(int fault)
{
    int failures = 0, fds[4]; pid_t pid = -1;
    if (!pvm_census_setup(fds, &pid)) { pvm_census_reap(pid); return 1; }
    int out[2] = {fds[0], -1}, err[2] = {fds[2], -1};
    struct pv_run run = {.subtree_budget = 1};
    size_t out_len = 0, err_len = 0;
    int status = 0; bool reaped = false; struct rusage usage = {0};
    pvm_census_value = UINT64_MAX; pvm_census_advance = false;
    pvm_wait_fault = fault; pvm_wait_calls = 0;
    pv_run_child_wait_loop(pid, out, err, clock_now_monotonic_ns() + 5000000000LL,
                           &run, &out_len, &err_len, &status, &reaped, &usage);
    pvm_wait_fault = 0;
    if (fault == EINTR) {
        PVM_CHECK("interrupted wait retries and reaps actual child",
                  pvm_wait_calls >= 2 && reaped && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    } else {
        PVM_CHECK("permanent wait failure is not reported as reaped",
                  pvm_wait_calls == 1 && !reaped && run.sandbox_fail);
    }
    pvm_census_reap(pid);
    pvm_census_close(fds);
    return failures;
}
#endif

#if defined(__linux__)
/* Exercise the verifier's actual deny-set, not a copy of its policy. */
static bool pvm_arm_alarm(void)
{
    sigset_t alarms;
    if (signal(SIGALRM, SIG_DFL) == SIG_ERR || sigemptyset(&alarms) != 0 ||
        sigaddset(&alarms, SIGALRM) != 0 || sigprocmask(SIG_UNBLOCK, &alarms, NULL) != 0) return false;
    alarm(5); return true;
}
static int pvm_group_fork_exec(void)
{
    if (access("/bin/true", X_OK) != 0) return 73;
    pid_t child = fork();
    if (child < 0) return 74;
    if (child == 0) { if (!pvm_arm_alarm()) _exit(75); execl("/bin/true", "true", (char *)NULL); _exit(76); }
    int status = 0; pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    return got == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 77;
}
static int pvm_group_action(int op, bool confined)
{
    if (confined && (!os_sandbox_no_new_privs() ||
        !os_sandbox_seccomp_deny(g_pv_child_denied, PV_CHILD_DENIED_COUNT, false).ok)) return 70;
    if (op == 0) return setsid() < 0 ? 71 : 0;
    if (op == 1) return setpgid(0, 0) < 0 ? 72 : 0;
    return pvm_group_fork_exec();
}
static int pvm_group_timeout(pid_t child)
{
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) return -104;
    int status = 0;
    for (int i = 0; i < 500; ++i) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child || (got < 0 && errno == ECHILD)) return -102;
        if (got < 0 && errno != EINTR) return -101;
        struct timespec delay = {.tv_nsec = 10000000};
        (void)nanosleep(&delay, NULL); /* real-clock: bounded real-child reap; kernel completion has no injected clock */
    }
    return -105;
}
static int pvm_group_wait(pid_t child)
{
    int status = 0;
    for (int i = 0; i < 700; ++i) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) {
            if (WIFSIGNALED(status)) return -WTERMSIG(status);
            return WIFEXITED(status) ? WEXITSTATUS(status) : -103;
        }
        if (got < 0 && errno != EINTR) return -101;
        struct timespec delay = {.tv_nsec = 10000000};
        (void)nanosleep(&delay, NULL); /* real-clock: bounded real-child reap; kernel completion has no injected clock */
    }
    return pvm_group_timeout(child);
}
static int pvm_group_run(int op, bool confined)
{
    pid_t child = fork(); if (child < 0) return -100;
    if (child == 0) { if (!pvm_arm_alarm()) _exit(78); _exit(pvm_group_action(op, confined)); }
    return pvm_group_wait(child);
}
static int t_package_group_custody(void)
{
    static const char *const labels[] = {"setsid", "setpgid", "fork/exec"};
    int failures = 0;
    for (int op = 0; op < 3; ++op) {
        int control = pvm_group_run(op, false);
        int confined = pvm_group_run(op, true);
        printf("  package group %s control=%d confined=%d\n", labels[op], control, confined);
        PVM_CHECK(labels[op], control == 0 && confined == (op < 2 ? -SIGSYS : 0));
    }
    return failures;
}
#endif


#if defined(__linux__) || defined(__APPLE__)
static bool pvm_group_marker(const char *root, enum pvm_group_fault inject, struct pv_run *run)
{
    char marker[1024];
    int n = snprintf(marker, sizeof(marker), "%s/marker", root);
    if (n <= 0 || (size_t)n >= sizeof(marker)) return false;
    const char *argv[] = {"/bin/sh", "-c", "printf reached > \"$1\"", "fixture", marker, NULL};
    pvm_group_setup_fault = inject;
    *run = pv_run_child(PV_PROCESS_OTHER, argv, root, NULL, false, NULL, 0, NULL, 5000);
    pvm_group_setup_fault = PVM_GROUP_NORMAL;
    bool exists = access(marker, F_OK) == 0;
    if (exists && unlink(marker) != 0) return false;
    return exists;
}
static int t_group_establish_fail_closed(void)
{
    int failures = 0;
    char root[1024];
    if (!test_mkdtemp(root, sizeof(root), "pvm-group-establish")) return 1;
    struct pv_run control = {0}, denied = {0}, raced = {0};
    bool control_marker = pvm_group_marker(root, PVM_GROUP_NORMAL, &control);
    bool denied_marker = pvm_group_marker(root, PVM_GROUP_BOTH, &denied);
    bool raced_marker = pvm_group_marker(root, PVM_GROUP_PARENT, &raced);
    PVM_CHECK("normal process group executes marker payload",
              control_marker && control.launched && control.exited && control.exit_code == 0 && !control.sandbox_fail);
    PVM_CHECK("failed group establishment refuses payload before marker",
              !denied_marker && denied.launched && denied.sandbox_fail);
    PVM_CHECK("parent EACCES permits verified child group",
              raced_marker && raced.launched && raced.exited && raced.exit_code == 0 && !raced.sandbox_fail);
    test_rm_rf(root);
    return failures;
}
#endif


int test_package_verify_materialize(void)
{
    int failures = 0;
    printf("\n=== test_package_verify_materialize ===\n");
    failures += t_package_boundary();
    failures += t_missing_chunk_custody();
    failures += t_corrupt_chunk_unwritten();
    failures += t_zero_write_fails();
    failures += t_success_identical();
    failures += t_write_error_custody();
    failures += t_size_disagrees_with_tail();
#if defined(__linux__)
    failures += t_package_group_custody();
#endif
#if defined(__linux__) || defined(__APPLE__)
    failures += t_group_establish_fail_closed();
    failures += t_census_unavailable();
    failures += t_census_budget_control();
    failures += pvm_wait_fault_case(EINTR);
    failures += pvm_wait_fault_case(EIO);
#endif
    return failures;
}
