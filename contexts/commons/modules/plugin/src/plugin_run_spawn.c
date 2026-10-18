/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: start, ping and stop one confined plugin process. The child is a
 * static image launched with resident_launch_spawn_confined; the descriptors
 * it holds are exactly the ones the manifest grants. */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "plugin_run_internal.h"

#include "platform/time_compat.h"

uint64_t prs_now_ns(void)
{
    return (uint64_t)platform_time_monotonic_us() * UINT64_C(1000);
}

#if defined(__linux__)
#include "base/hex.h"
#include "platform/os_sandbox.h"
#include "platform/positioned_file.h"
#include "platform/rng.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PRS_HIGH_FD 16
#define PRS_PING_READ_MS 200u
#define PRS_STOP_GRACE_MS 300u

#ifdef ZCL_TESTING
static bool g_prs_corrupt_hash;
static unsigned g_prs_verify_count;

unsigned plugin_run_test_verify_count(void)
{
    return g_prs_verify_count;
}

static void (*g_prs_hook)(int point, void *ctx);
static void *g_prs_hook_ctx;

void plugin_run_test_set_hook(void (*fn)(int point, void *ctx), void *ctx)
{
    g_prs_hook = fn;
    g_prs_hook_ctx = ctx;
}

static void prs_hook(int point)
{
    if (g_prs_hook)
        g_prs_hook(point, g_prs_hook_ctx);
}

void plugin_run_test_corrupt_signed_hash(bool on)
{
    g_prs_corrupt_hash = on;
}
#else
#define prs_hook(point) ((void)0)
#endif

static void prs_detail(struct plugin_run *run, const char *what, const char *why)
{
    snprintf(run->info.detail, sizeof(run->info.detail), "%s: %s", what, why);
}

static unsigned prs_cap_bit(const char *name)
{
    for (unsigned i = 0; plugin_capability_name(i); i++)
        if (strcmp(plugin_capability_name(i), name) == 0)
            return 1u << i;
    return 0;
}

/* Capabilities whose descriptors do not exist yet are refused by name. */
static bool prs_caps_supported(struct plugin_run *run)
{
    static const char *const unsupported[] = {
        "net.client", "net.server", "process.spawn", "ui.panel"
    };
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        if (run->capabilities & prs_cap_bit(unsupported[i])) {
            prs_detail(run, "capability not available", unsupported[i]);
            return false;
        }
    }
    return true;
}

/* Read trusted_keys once, with the same no-follow, owner-only rules the
 * verifier applies, and digest those bytes. The same buffer is what a full
 * verification runs under, so what is remembered is exactly what was judged.
 * False when it cannot be read: the caller then verifies in full from the
 * file, remembers nothing, and the verifier reports the real refusal. */
static bool prs_trust_snapshot(const struct plugin_run *run, char **keys, size_t *len,
                               unsigned char digest[32])
{
    char path[PLUGIN_PATH_MAX];
    if (!plugin_join(path, sizeof(path), run->opt.root, "trusted_keys", NULL, NULL) ||
        plugin_trust_load(path, keys, len) != PLUGIN_OK)
        return false;
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)*keys, *len);
    sha3_256_finalize(&c, digest);
    return true;
}

static bool prs_entry_matches(const struct plugin_run *run, const char *generation,
                              const unsigned char digest[32])
{
    return run->verified_generation[0] && strcmp(run->verified_generation, generation) == 0 &&
           memcmp(run->verified_trust, digest, 32) == 0;
}

/* Verify the generation, reusing the one entry that already passed under the
 * same generation id and the same trusted_keys bytes. A reuse still checks the
 * whole directory chain down to the generation, since those are what the full
 * path checks and a permission change there must refuse. The executable is not
 * part of this: prs_accept hashes it on every launch. A failure clears the
 * entry. */
static enum plugin_status prs_verify(struct plugin_run *run, const char *generation,
                                     struct plugin_manifest *m)
{
    unsigned char digest[32];
    char *keys = NULL;
    size_t keys_len = 0;
    bool keyed = prs_trust_snapshot(run, &keys, &keys_len, digest);
    enum plugin_status st;
    prs_hook(PLUGIN_RUN_TEST_AFTER_TRUST);
    if (keyed && prs_entry_matches(run, generation, digest)) {
        st = plugin_check_generation_dirs(run->opt.root, run->opt.name, generation);
        if (st == PLUGIN_OK)
            *m = run->verified_manifest;
        else
            run->verified_generation[0] = '\0';
        free(keys);
        return st;
    }
    run->verified_generation[0] = '\0';
#ifdef ZCL_TESTING
    g_prs_verify_count++;
#endif
    st = keyed ? plugin_verify_generation_manifest_trust(run->opt.root, run->opt.name,
                                                         generation, keys, keys_len, m)
               : plugin_verify_generation_manifest(run->opt.root, run->opt.name,
                                                   generation, m);
    prs_hook(PLUGIN_RUN_TEST_AFTER_VERIFY);
    if (st == PLUGIN_OK && keyed) {
        snprintf(run->verified_generation, sizeof(run->verified_generation), "%s", generation);
        memcpy(run->verified_trust, digest, sizeof(digest));
        run->verified_manifest = *m;
    }
    free(keys);
    return st;
}

enum plugin_run_status prs_resolve(struct plugin_run *run)
{
    char generation[PLUGIN_HEX_SHA3_512 + 1];
    struct plugin_manifest m;
    run->store = plugin_check_dir(run->opt.root);
    if (run->store == PLUGIN_OK)
        run->store = plugin_check_dir(run->plugdir);
    if (run->store == PLUGIN_OK && !plugin_link_generation(run->plugdir, "current", generation))
        run->store = PLUGIN_ERR_NO_GENERATION;
    if (run->store == PLUGIN_OK)
        run->store = prs_verify(run, generation, &m);
    if (run->store == PLUGIN_OK && m.interface_version != 1)
        run->store = PLUGIN_ERR_INTERFACE;
    if (run->store != PLUGIN_OK) {
        prs_detail(run, "plugin store refused", plugin_status_code(run->store));
        return PLUGIN_RUN_ERR_STORE;
    }
    run->capabilities = m.capabilities;
    snprintf(run->exe_sha3, sizeof(run->exe_sha3), "%s", m.exe_sha3);
#ifdef ZCL_TESTING
    if (g_prs_corrupt_hash)
        run->exe_sha3[0] = run->exe_sha3[0] == '0' ? '1' : '0';
#endif
    snprintf(run->info.generation, sizeof(run->info.generation), "%s", generation);
    if (!prs_caps_supported(run))
        return PLUGIN_RUN_ERR_CAPABILITY;
    return plugin_join(run->exe, sizeof(run->exe), run->plugdir, "generations", generation,
                       run->opt.name) &&
           plugin_join(run->data_dir, sizeof(run->data_dir), run->plugdir, "data", NULL, NULL)
               ? PLUGIN_RUN_OK : PLUGIN_RUN_ERR_ARGUMENT;
}

/* Open the executable once and hash that descriptor: SHA3-512 against the
 * signed manifest, SHA3-256 and the positioned-file identity for the launch
 * record resident_launch_prepare re-proves on its own pinned descriptor.
 * A symbolic link or a non-regular file is refused. */
static bool prs_accept(const struct plugin_run *run, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    struct sha3_256_ctx c256;
    struct sha3_512_ctx c512;
    struct stat st;
    unsigned char chunk[4096], d256[32], d512[64];
    char hex[PLUGIN_HEX_SHA3_512 + 1];
    uint64_t offset = 0;
    int64_t got = 1;
    if (lstat(run->exe, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, run->exe) &&
              platform_positioned_file_snapshot(&file, &snap);
    sha3_256_init(&c256);
    sha3_512_init(&c512);
    while (ok && got > 0) {
        got = platform_positioned_file_read(&file, chunk, sizeof(chunk), offset);
        ok = got >= 0;
        if (ok && got > 0) {
            sha3_256_write(&c256, chunk, (size_t)got);
            sha3_512_write(&c512, chunk, (size_t)got);
            offset += (uint64_t)got;
        }
    }
    platform_positioned_file_close(&file);
    if (!ok)
        return false;
    sha3_256_finalize(&c256, d256);
    sha3_512_finalize(&c512, d512);
    zcl_hex_encode(d512, sizeof(d512), hex);
    if (strcmp(hex, run->exe_sha3) != 0)
        return false;
    zcl_hex_encode(d256, sizeof(d256), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

/* Everything the parent opens for one start, released together. */
struct prs_start {
    int log_read, log_write, data_fd, grant_image, grant_data;
    struct os_sandbox_path_rule rules[2];
    struct os_sandbox_profile profile;
    char fds_env[96];
};

static void prs_close(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

static void prs_start_release(struct prs_start *s, bool keep_log_read)
{
    prs_close(&s->log_write);
    prs_close(&s->data_fd);
    prs_close(&s->grant_image);
    prs_close(&s->grant_data);
    if (!keep_log_read)
        prs_close(&s->log_read);
}

/* Grants move above the child's slot range so placement cannot overwrite them. */
static int prs_grant(const char *path)
{
    int fd = os_sandbox_open_grant(path);
    if (fd < 0)
        return -1;
    int high = fcntl(fd, F_DUPFD_CLOEXEC, PRS_HIGH_FD);
    int saved = errno;
    close(fd);
    errno = saved;
    return high;
}

static bool prs_open_data(struct plugin_run *run, struct prs_start *s)
{
    if (!(run->capabilities & (prs_cap_bit("fs.read") | prs_cap_bit("fs.write"))))
        return true;
    if (mkdir(run->data_dir, 0700) != 0 && errno != EEXIST)
        return false;
    if (plugin_check_dir(run->data_dir) != PLUGIN_OK)
        return false;
    s->data_fd = open(run->data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    s->grant_data = prs_grant(run->data_dir);
    return s->data_fd >= 0 && s->grant_data >= 0;
}

static bool prs_open_channels(struct plugin_run *run, struct prs_start *s)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return false;
    s->log_read = pipefd[0];
    s->log_write = pipefd[1];
    if (fcntl(s->log_read, F_SETFL, O_NONBLOCK) != 0)
        return false;
    s->grant_image = prs_grant(run->exe);
    return s->grant_image >= 0 && prs_open_data(run, s);
}

/* Landlock: read and execute the image; read, write and create inside data.dir only
 * when fs.write is granted, read-only for fs.read. */
static size_t prs_build_rules(const struct plugin_run *run, struct prs_start *s)
{
    size_t n = 0;
    s->rules[n++] = (struct os_sandbox_path_rule){
        .path = run->exe, .allow_read = true, .allow_execute = true,
        .has_fd = true, .fd = s->grant_image};
    if (s->grant_data >= 0) {
        bool write = (run->capabilities & prs_cap_bit("fs.write")) != 0;
        s->rules[n++] = (struct os_sandbox_path_rule){
            .path = run->data_dir, .allow_read = true, .allow_write = write,
            .allow_create = write, .has_fd = true, .fd = s->grant_data};
    }
    return n;
}

/* Descriptors in sorted capability order from 3: control, data.dir, log. */
static size_t prs_announce(const struct prs_start *s, char *out, size_t cap,
                           int extra[RESIDENT_LAUNCH_EXTRA_FD_MAX])
{
    size_t n = 0;
    int slot = RESIDENT_LAUNCH_CHILD_FD;
    int len = snprintf(out, cap, "Z23_PLUGIN_FDS=control=%d", slot++);
    if (s->data_fd >= 0) {
        len += snprintf(out + len, cap - (size_t)len, ",data.dir=%d", slot++);
        extra[n++] = s->data_fd;
    }
    snprintf(out + len, cap - (size_t)len, ",log=%d", slot);
    extra[n++] = s->log_write;
    return n;
}

static bool prs_launch(struct plugin_run *run, struct prs_start *s)
{
    struct resident_launch_accepted accepted;
    struct resident_receipt receipt;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    if (!prs_accept(run, &accepted) ||
        !resident_launch_prepare(&run->launch, run->exe, &accepted, error, sizeof(error))) {
        prs_detail(run, "image not accepted", error[0] ? error : "bytes differ from the signed SHA3-512");
        return false;
    }
    size_t n_rules = prs_build_rules(run, s);
    s->profile = os_sandbox_plugin_profile(s->rules, n_rules);
    run->launch.null_stdio = true;
    run->launch.n_extra_fds = prs_announce(s, s->fds_env, sizeof(s->fds_env), run->launch.extra_fds);
    char *argv[] = {run->exe, "--resident", run->launch.nonce, NULL};
    char *envp[] = {s->fds_env, NULL};
    bool ok = resident_launch_spawn_confined(&run->launch, argv, envp, &s->profile,
                                             &receipt, error, sizeof(error)) &&
              run->launch.exec_state == RESIDENT_EXEC_CONFIRMED;
    if (!ok) {
        prs_detail(run, "spawn refused", error[0] ? error : "exec not confirmed");
        if (run->launch.spawned)
            resident_launch_cancel(&run->launch, PRS_STOP_GRACE_MS, error, sizeof(error));
        resident_launch_close(&run->launch);
    }
    return ok;
}

enum plugin_run_status prs_child_start(struct plugin_run *run)
{
    struct prs_start s = {.log_read = -1, .log_write = -1, .data_fd = -1,
                          .grant_image = -1, .grant_data = -1};
    if (!prs_open_channels(run, &s)) {
        prs_detail(run, "descriptor setup failed", strerror(errno));
        prs_start_release(&s, false);
        return PLUGIN_RUN_ERR_SPAWN;
    }
    bool ok = prs_launch(run, &s);
    prs_start_release(&s, ok);
    if (!ok)
        return PLUGIN_RUN_ERR_SPAWN;
    run->log_fd = s.log_read;
    run->log_len = 0;
    snprintf(run->info.detail, sizeof(run->info.detail), "running");
    return PLUGIN_RUN_OK;
}

void prs_child_stop(struct plugin_run *run)
{
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    if (run->launch.spawned)
        resident_launch_cancel(&run->launch, PRS_STOP_GRACE_MS, error, sizeof(error));
    prs_log_drain(run, true);
    resident_launch_close(&run->launch);
    prs_close(&run->log_fd);
    run->info.pid = 0;
    run->ping_pending = false;
}

bool prs_child_reaped(struct plugin_run *run)
{
    int status = 0;
    pid_t got = waitpid((pid_t)run->launch.pid, &status, WNOHANG);
    if (got == 0 || (got < 0 && errno != ECHILD))
        return false;
    run->launch.spawned = false;
    if (got < 0) { /* the status was taken elsewhere or SIGCHLD is ignored */
        run->info.last_exit_code = -1;
        run->info.last_exit_signal = 0;
        snprintf(run->info.detail, sizeof(run->info.detail), "exit status lost (ECHILD)");
    } else {
        run->info.last_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        run->info.last_exit_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        snprintf(run->info.detail, sizeof(run->info.detail), "exited: code %d signal %d",
                 run->info.last_exit_code, run->info.last_exit_signal);
    }
    prs_log_drain(run, true);
    resident_launch_close(&run->launch);
    prs_close(&run->log_fd);
    return true;
}

void prs_ping_send(struct plugin_run *run, uint64_t now)
{
    uint8_t raw[PRS_TOKEN_HEX / 2];
    struct prs_frame frame;
    memset(&frame, 0, sizeof(frame));
    if (!rng_fill(raw, sizeof(raw)))
        return;
    snprintf(frame.magic, sizeof(frame.magic), "%s", PRS_PING_MAGIC);
    zcl_hex_encode(raw, sizeof(raw), frame.value);
    snprintf(run->ping_token, sizeof(run->ping_token), "%s", frame.value);
    run->ping_pending = true;
    run->ping_sent_ns = now;
    (void)send((int)run->launch.ipc_native, &frame, sizeof(frame),
               MSG_DONTWAIT | MSG_NOSIGNAL);
}

/* One reply, accepted only under this launch's nonce and the pending token.
 * An older ping's late answer is consumed and ignored. */
enum prs_ping prs_ping_collect(struct plugin_run *run)
{
    struct pollfd waiter = {.fd = (int)run->launch.ipc_native, .events = POLLIN};
    struct resident_result_header header;
    char payload[PRS_TOKEN_HEX + 1];
    char error[RESIDENT_LAUNCH_ERROR_MAX];
    if (poll(&waiter, 1, 0) <= 0 || !(waiter.revents & POLLIN))
        return PRS_PING_NONE;
    if (!resident_result_read(&run->launch, &header, payload, PRS_TOKEN_HEX,
                              PRS_PING_READ_MS, error, sizeof(error)))
        return errno == ECONNRESET || errno == ETIMEDOUT ? PRS_PING_NONE : PRS_PING_BAD;
    if (header.payload_len != PRS_TOKEN_HEX)
        return PRS_PING_BAD;
    return memcmp(payload, run->ping_token, PRS_TOKEN_HEX) == 0 ? PRS_PING_OK
                                                                : PRS_PING_NONE;
}

static void prs_log_flush(struct plugin_run *run)
{
    if (run->log_len == 0)
        return;
    snprintf(run->info.last_log, sizeof(run->info.last_log), "%.*s", (int)run->log_len,
             run->log_line);
    if (run->opt.log_to_stderr)
        fprintf(stderr, "plugin %s: %.*s\n", run->opt.name, (int)run->log_len, run->log_line);
    run->log_len = 0;
}

static void prs_log_bytes(struct plugin_run *run, const char *bytes, ssize_t n)
{
    for (ssize_t i = 0; i < n; i++) {
        if (bytes[i] == '\n' || run->log_len == sizeof(run->log_line)) {
            prs_log_flush(run);
            if (bytes[i] == '\n')
                continue;
        }
        unsigned char c = (unsigned char)bytes[i];
        run->log_line[run->log_len++] = (c < 0x20 && c != '\t') || c == 0x7f ? '?' : bytes[i];
    }
}

void prs_log_drain(struct plugin_run *run, bool final)
{
    char buf[512];
    ssize_t n;
    while (run->log_fd >= 0 && (n = read(run->log_fd, buf, sizeof(buf))) > 0) {
        run->info.log_bytes += (uint64_t)n;
        prs_log_bytes(run, buf, n);
    }
    if (final)
        prs_log_flush(run);
}
#endif /* __linux__ */
