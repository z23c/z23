/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "test/test_core.h"
#include "config/state_offer_link_receive.h"
#include "net/rom_seed.h"
#include "crypto/sha3.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#endif

struct fixture { uint8_t *bytes; uint8_t manifest[72]; int mode; unsigned calls[2]; };
static enum sol_read_result fixture_read(void *ctx, enum sol_object_kind kind,
    const uint8_t root[32], uint32_t index, uint8_t *buf, uint32_t cap, uint32_t *len)
{
    struct fixture *f = ctx; (void)root;
    if (kind == SOL_OBJECT_MANIFEST) {
        if (cap < sizeof(f->manifest)) return SOL_READ_BAD_DATA;
        memcpy(buf, f->manifest, sizeof(f->manifest)); *len = sizeof(f->manifest);
        if (f->mode == 1) buf[8] ^= 1;
        return SOL_READ_OK;
    }
    if (index >= 2) return SOL_READ_BAD_DATA;
    f->calls[index]++;
    if (f->mode == 2 && index == 1) return SOL_READ_UNAVAILABLE;
    if (f->mode == 4 && index == 1) return SOL_READ_CANCELLED;
    uint32_t n = index ? 4096u : ROM_SEED_CHUNK_SIZE;
    if (cap < n) return SOL_READ_BAD_DATA;
    memcpy(buf, f->bytes + (size_t)index * ROM_SEED_CHUNK_SIZE, n);
    if (f->mode == 3 && index == 1) buf[0] ^= 1;
    *len = n; return SOL_READ_OK;
}
static bool init_fixture(struct fixture *f, struct rom_fetch_manifest *m)
{
    memset(f, 0, sizeof(*f)); memset(m, 0, sizeof(*m));
    size_t n = ROM_SEED_CHUNK_SIZE + 4096u;
    f->bytes = malloc(n); if (!f->bytes) return false;
    for (size_t i = 0; i < n; ++i) f->bytes[i] = (uint8_t)(i * 17u);
    f->manifest[0] = 1; f->manifest[4] = 2;
    sha3_256(f->bytes, ROM_SEED_CHUNK_SIZE, f->manifest + 8);
    sha3_256(f->bytes + ROM_SEED_CHUNK_SIZE, 4096, f->manifest + 40);
    sha3_256(f->manifest + 8, 64, m->chunk_root);
    sha3_256(f->bytes, n, m->whole_sha3);
    m->used = true; m->size_bytes = n; m->chunk_size = ROM_SEED_CHUNK_SIZE;
    m->num_chunks = 2; m->kind = ROM_ARTIFACT_CONSENSUS_BUNDLE;
    strcpy(m->filename, "fixture.sqlite"); return true;
}
static void cleanup(const char *dir)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/fixture.sqlite", dir); (void)unlink(p);
    snprintf(p, sizeof(p), "%s/fixture.sqlite.part", dir); (void)unlink(p);
    snprintf(p, sizeof(p), "%s/fixture.sqlite.part.journal", dir); (void)unlink(p);
    (void)rmdir(dir);
}
static int receiver_integrity(void)
{
    int failures = 0;
    TEST_CASE("receive rejects corrupt manifest and resumes verified chunks") {
        struct fixture f; struct rom_fetch_manifest m;
        char dir[256], path[512];
        ASSERT(init_fixture(&f, &m)); ASSERT(test_mkdtemp(dir, sizeof(dir), "state_offer_receive"));
        f.mode = 1;
        m.chunk_root[0] ^= 1;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_BAD_DATA);
        m.chunk_root[0] ^= 1;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_BAD_DATA);
        f.mode = 2;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_UNAVAILABLE);
        ASSERT_EQ(f.calls[0], 1u);
        f.mode = 3;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_BAD_DATA);
        ASSERT_EQ(f.calls[0], 1u);
        f.mode = 4;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_CANCELLED);
        f.mode = 0;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_OK);
        ASSERT_EQ(f.calls[0], 1u);
        struct stat st; ASSERT_EQ(stat(path, &st), 0); ASSERT_EQ(st.st_mode & 0777, 0444);
        ASSERT(rom_fetch_verify_file(path, &m));
        unsigned prior = f.calls[0] + f.calls[1];
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_OK);
        ASSERT_EQ(f.calls[0] + f.calls[1], prior);
        m.whole_sha3[0] ^= 1;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_LOCAL_IO);
        free(f.bytes); cleanup(dir);
    } TEST_END
    return failures;
}
static int receiver_truncated(void)
{
    int failures = 0;
    TEST_CASE("receive rejects a truncated resumed partial and fetches it again") {
        struct fixture f; struct rom_fetch_manifest m;
        char dir[256], path[512], part[512];
        ASSERT(init_fixture(&f, &m)); ASSERT(test_mkdtemp(dir, sizeof(dir), "state_offer_receive")); f.mode = 2;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_UNAVAILABLE);
        snprintf(part, sizeof(part), "%s/fixture.sqlite.part", dir);
        ASSERT_EQ(truncate(part, 1), 0); f.mode = 0;
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_OK);
        ASSERT_EQ(f.calls[0], 2u);
        free(f.bytes); cleanup(dir);
    } TEST_END
    return failures;
}
static int receiver_symlink(void)
{
    int failures = 0;
    TEST_CASE("receive refuses a symlink partial") {
        struct fixture f; struct rom_fetch_manifest m;
        char dir[256], path[512], part[512];
        ASSERT(init_fixture(&f, &m)); ASSERT(test_mkdtemp(dir, sizeof(dir), "state_offer_receive"));
        snprintf(part, sizeof(part), "%s/fixture.sqlite.part", dir);
        ASSERT_EQ(symlink("/dev/null", part), 0);
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_LOCAL_IO);
        ASSERT_EQ(f.calls[0], 0u);
        free(f.bytes); cleanup(dir);
    } TEST_END
    return failures;
}
static int receiver_hardlink(void)
{
    int failures = 0;
    TEST_CASE("receive refuses a hardlinked partial") {
        struct fixture f; struct rom_fetch_manifest m;
        char dir[256], path[512], part[512], target[512];
        ASSERT(init_fixture(&f, &m)); ASSERT(test_mkdtemp(dir, sizeof(dir), "state_offer_receive"));
        snprintf(part, sizeof(part), "%s/fixture.sqlite.part", dir);
        snprintf(target, sizeof(target), "%s/target", dir);
        int fd = open(target, O_CREAT | O_EXCL | O_RDWR, 0600); ASSERT(fd >= 0); ASSERT_EQ(close(fd), 0);
        ASSERT_EQ(link(target, part), 0);
        ASSERT_EQ(state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL, path, sizeof(path)), SOL_RECEIVE_LOCAL_IO);
        ASSERT_EQ(f.calls[0], 0u);
        free(f.bytes); (void)unlink(target); cleanup(dir);
    } TEST_END
    return failures;
}
#if !defined(_WIN32)
static bool receiver_crash_progress(uint32_t done, uint32_t total, uint64_t bytes, void *ctx)
{
    int fd = *(int *)ctx;
    if (done != 1 || total != 2 || bytes != ROM_SEED_CHUNK_SIZE) return false;
    if (write(fd, "R", 1) != 1) return false;
    for (;;) pause();
}

static bool receiver_wait_byte(int fd, char *byte)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int rc;
    do { rc = poll(&p, 1, 30000); } while (rc < 0 && errno == EINTR);
    return rc == 1 && (p.revents & POLLIN) && read(fd, byte, 1) == 1;
}

static bool receiver_reap_child(pid_t child, int signal_number, int *status)
{
    if (kill(child, signal_number) != 0 && errno != ESRCH) return false;
    pid_t rc;
    do { rc = waitpid(child, status, 0); } while (rc < 0 && errno == EINTR);
    return rc == child;
}

static void receiver_resume_child(const char *dir, int fd)
{
    struct fixture f; struct rom_fetch_manifest m; char path[512];
    bool ok = init_fixture(&f, &m);
    if (ok) {
        ok = state_offer_link_receive(&m, dir, fixture_read, &f, NULL, NULL,
                                      path, sizeof(path)) == SOL_RECEIVE_OK &&
             f.calls[0] == 0 && f.calls[1] == 1 && rom_fetch_verify_file(path, &m);
        free(f.bytes);
    }
    char result = ok ? 'Y' : 'N';
    if (write(fd, &result, 1) != 1) _exit(1);
    _exit(ok ? 0 : 1);
}

static bool receiver_crash_first(const char *dir, struct fixture *f,
                                 const struct rom_fetch_manifest *m)
{
    int pipefd[2], status = 0; char byte = 0;
    if (pipe(pipefd) != 0) return false;
    pid_t child = fork();
    if (child == 0) {
        close(pipefd[0]); char path[512];
        (void)state_offer_link_receive(m, dir, fixture_read, f, receiver_crash_progress,
                                       &pipefd[1], path, sizeof(path));
        _exit(1);
    }
    close(pipefd[1]);
    bool ok = false;
    if (child > 0) {
        bool reached = receiver_wait_byte(pipefd[0], &byte) && byte == 'R';
        bool reaped = receiver_reap_child(child, SIGKILL, &status);
        ok = reached && reaped && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
    }
    close(pipefd[0]);
    return ok;
}

static bool receiver_crash_resume(const char *dir)
{
    int pipefd[2], status = 0; char byte = 0;
    if (pipe(pipefd) != 0) return false;
    pid_t child = fork();
    if (child == 0) { close(pipefd[0]); receiver_resume_child(dir, pipefd[1]); }
    close(pipefd[1]);
    bool ok = child > 0 && receiver_wait_byte(pipefd[0], &byte) && byte == 'Y';
    close(pipefd[0]);
    if (child > 0) {
        if (!ok) (void)receiver_reap_child(child, SIGKILL, &status);
        else {
            pid_t rc;
            do { rc = waitpid(child, &status, 0); } while (rc < 0 && errno == EINTR);
            ok = rc == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
    }
    return ok;
}

static bool receiver_crash_case(void)
{
    struct fixture f; struct rom_fetch_manifest m; char dir[256];
    if (!init_fixture(&f, &m)) return false;
    if (!test_mkdtemp(dir, sizeof(dir), "state_offer_crash")) { free(f.bytes); return false; }
    bool ok = receiver_crash_first(dir, &f, &m) && receiver_crash_resume(dir);
    free(f.bytes); cleanup(dir); return ok;
}

static int receiver_crash(void)
{
    int failures = 0;
    TEST_CASE("receive resumes after process death at durable chunk boundary") {
        ASSERT(receiver_crash_case());
    } TEST_END
    return failures;
}
#else
static int receiver_crash(void) { return 0; }
#endif
int test_state_offer_link_receive(void)
{
    return receiver_crash() + receiver_integrity() + receiver_truncated() + receiver_symlink() + receiver_hardlink();
}
