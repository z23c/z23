/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "sim/postmortem.h"

#if !defined(_WIN32)
#include "postmortem_internal.h"

#include "platform/clock.h"
#include "util/clientversion.h"
#include "util/signal_handler.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(__linux__) && defined(__x86_64__)
#include <ucontext.h>
#endif
#include <unistd.h>
#include <zlib.h>

#define POSTMORTEM_LOG_TAIL_MAX (64u * 1024u)
#define POSTMORTEM_GZ_MEMBER_MAX (4u * 1024u * 1024u)
#define POSTMORTEM_SIGNAL_TAPE_MAX (1024u * 1024u)

static seed_tape_t *g_postmortem_tape = NULL;
static char g_postmortem_dir[512];
static char g_postmortem_signal_log_path[512];
static uint8_t *g_postmortem_signal_tape_buf = NULL;
static size_t g_postmortem_signal_tape_cap = 0;
static int64_t g_postmortem_install_unix = 0;
static volatile sig_atomic_t g_postmortem_in_handler = 0;

static int mkdir_if_needed(const char *path)
{
    if (!path || !*path) return -EINVAL;
    if (mkdir(path, 0755) == 0) return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
        return -ENOTDIR;
    }
    return -errno;
}

static int write_bytes_file(const char *path, const void *buf, size_t len)
{
    if (!path || (!buf && len > 0)) return -EINVAL;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -errno;
    size_t wrote = len ? fwrite(buf, 1, len, fp) : 0;
    int close_rc = fclose(fp);
    if (wrote != len) return -EIO;
    if (close_rc != 0) return -errno;
    return 0;
}

static int copy_proc_status(const char *dst_path)
{
#if defined(__linux__)
    FILE *in = fopen("/proc/self/status", "rb");
    if (!in) return write_bytes_file(dst_path, "", 0);
    uint8_t buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), in);
    fclose(in);
    return write_bytes_file(dst_path, buf, n);
#else
    static const char unavailable[] =
        "unavailable: /proc/self/status is Linux-only\n";
    return write_bytes_file(dst_path, unavailable,
                            sizeof(unavailable) - 1u);
#endif
}

static int copy_log_tail(const char *src_path, const char *dst_path)
{
    if (!src_path || !*src_path)
        return write_bytes_file(dst_path, "", 0);

    FILE *in = fopen(src_path, "rb");
    if (!in) return write_bytes_file(dst_path, "", 0);
    if (fseek(in, 0, SEEK_END) != 0) {
        fclose(in);
        return write_bytes_file(dst_path, "", 0);
    }
    long end = ftell(in);
    if (end < 0) {
        fclose(in);
        return write_bytes_file(dst_path, "", 0);
    }
    long start = end > (long)POSTMORTEM_LOG_TAIL_MAX
        ? end - (long)POSTMORTEM_LOG_TAIL_MAX
        : 0;
    if (fseek(in, start, SEEK_SET) != 0) {
        fclose(in);
        return write_bytes_file(dst_path, "", 0);
    }
    size_t want = (size_t)(end - start);
    uint8_t *buf = NULL;
    if (want > 0) {
        buf = (uint8_t *)zcl_malloc(want, "postmortem.log_tail");
        if (!buf) {
            fclose(in);
            return -ENOMEM;
        }
    }
    size_t got = want ? fread(buf, 1, want, in) : 0;
    fclose(in);
    int rc = write_bytes_file(dst_path, buf, got);
    free(buf);
    return rc;
}

bool postmortem_has_suffix(const char *s, const char *suffix)
{
    if (!s || !suffix) return false;
    size_t sl = strlen(s);
    size_t xl = strlen(suffix);
    return sl >= xl && strcmp(s + sl - xl, suffix) == 0;
}

static bool fatal_signal_handlers_are_default(void)
{
    const int sigs[] = { SIGABRT, SIGSEGV, SIGBUS, SIGFPE };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        struct sigaction old_sa;
        memset(&old_sa, 0, sizeof(old_sa));
        if (sigaction(sigs[i], NULL, &old_sa) != 0)
            return false;
        if (old_sa.sa_handler != SIG_DFL)
            return false;
    }
    return true;
}

int postmortem_remove_tree(const char *path)
{
    if (!path || !*path) return -EINVAL;
    DIR *d = opendir(path);
    if (!d) {
        if (unlink(path) == 0) return 0;
        return -errno;
    }

    int first_err = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[768];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) {
            if (first_err == 0) first_err = -ENAMETOOLONG;
            continue;
        }
        int rc = postmortem_remove_tree(child);
        if (rc != 0 && first_err == 0)
            first_err = rc;
    }
    closedir(d);
    if (rmdir(path) != 0 && first_err == 0)
        first_err = -errno;
    return first_err;
}

static void json_escape_string(const char *in, char *out, size_t out_cap)
{
    if (!out || out_cap == 0) return;
    size_t w = 0;
    if (!in) in = "";
    for (size_t r = 0; in[r] && w + 1 < out_cap; r++) {
        unsigned char c = (unsigned char)in[r];
        if ((c == '"' || c == '\\') && w + 2 < out_cap) {
            out[w++] = '\\';
            out[w++] = (char)c;
        } else if (c == '\n' && w + 2 < out_cap) {
            out[w++] = '\\';
            out[w++] = 'n';
        } else if (c == '\r' && w + 2 < out_cap) {
            out[w++] = '\\';
            out[w++] = 'r';
        } else if (c == '\t' && w + 2 < out_cap) {
            out[w++] = '\\';
            out[w++] = 't';
        } else if (c >= 0x20) {
            out[w++] = (char)c;
        }
    }
    out[w] = '\0';
}

static ssize_t signal_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, p + off, len - off);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return -1;
        off += (size_t)wrote;
    }
    return (ssize_t)off;
}

static size_t signal_cstr_len(const char *s)
{
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int signal_append_cstr(char *dst, size_t cap, size_t *off,
                              const char *s)
{
    if (!dst || !off || !s || *off >= cap) return -1;
    size_t n = signal_cstr_len(s);
    if (n >= cap - *off) return -1;
    memcpy(dst + *off, s, n);
    *off += n;
    dst[*off] = '\0';
    return 0;
}

static int signal_append_u64(char *dst, size_t cap, size_t *off,
                             uint64_t v)
{
    char tmp[32];
    size_t n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v > 0 && n < sizeof(tmp)) {
            tmp[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    }
    if (n >= cap - *off) return -1;
    for (size_t i = 0; i < n; i++)
        dst[(*off)++] = tmp[n - 1u - i];
    dst[*off] = '\0';
    return 0;
}

static int signal_append_hex_u64(char *dst, size_t cap, size_t *off,
                                 uint64_t v)
{
    static const char hex[] = "0123456789abcdef";
    if (signal_append_cstr(dst, cap, off, "0x") != 0) return -1;
    char tmp[16];
    size_t n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v && n < sizeof(tmp)) {
            tmp[n++] = hex[v & 0xfu];
            v >>= 4;
        }
    }
    if (n >= cap - *off) return -1;
    for (size_t i = 0; i < n; i++)
        dst[(*off)++] = tmp[n - 1u - i];
    dst[*off] = '\0';
    return 0;
}

static int signal_append_i64(char *dst, size_t cap, size_t *off,
                             int64_t v)
{
    if (v < 0) {
        if (signal_append_cstr(dst, cap, off, "-") != 0) return -1;
        uint64_t mag = (uint64_t)(-(v + 1)) + 1u;
        return signal_append_u64(dst, cap, off, mag);
    }
    return signal_append_u64(dst, cap, off, (uint64_t)v);
}

static int signal_join_path(char *dst, size_t cap,
                            const char *a, const char *b)
{
    size_t off = 0;
    dst[0] = '\0';
    if (signal_append_cstr(dst, cap, &off, a) != 0) return -1;
    if (signal_append_cstr(dst, cap, &off, "/") != 0) return -1;
    if (signal_append_cstr(dst, cap, &off, b) != 0) return -1;
    return 0;
}

static int signal_write_file(const char *path, const void *buf, size_t len)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return -1;
    int ok = signal_write_all(fd, buf, len) == (ssize_t)len ? 0 : -1;
    if (close(fd) != 0 && ok == 0) ok = -1;
    return ok;
}

static int signal_write_empty_file(const char *path)
{
    return signal_write_file(path, "", 0);
}

#if defined(__linux__)
static int signal_copy_file_limited(const char *src, const char *dst,
                                    size_t max_bytes)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }

    char buf[512];
    size_t copied = 0;
    int ok = 0;
    while (copied < max_bytes) {
        size_t want = max_bytes - copied;
        if (want > sizeof(buf)) want = sizeof(buf);
        ssize_t got = read(in, buf, want);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = -1;
            break;
        }
        if (got == 0)
            break;
        if (signal_write_all(out, buf, (size_t)got) != got) {
            ok = -1;
            break;
        }
        copied += (size_t)got;
    }

    if (close(out) != 0 && ok == 0) ok = -1;
    if (close(in) != 0 && ok == 0) ok = -1;
    return ok;
}
#endif

static int signal_copy_tail_limited(const char *src, const char *dst,
                                    size_t max_bytes)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;

    off_t end = lseek(in, 0, SEEK_END);
    if (end < 0) {
        close(in);
        return -1;
    }
    off_t start = end > (off_t)max_bytes ? end - (off_t)max_bytes : 0;
    if (lseek(in, start, SEEK_SET) < 0) {
        close(in);
        return -1;
    }

    int out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }

    char buf[512];
    size_t copied = 0;
    int ok = 0;
    while (copied < max_bytes) {
        size_t want = max_bytes - copied;
        if (want > sizeof(buf)) want = sizeof(buf);
        ssize_t got = read(in, buf, want);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = -1;
            break;
        }
        if (got == 0)
            break;
        if (signal_write_all(out, buf, (size_t)got) != got) {
            ok = -1;
            break;
        }
        copied += (size_t)got;
    }

    if (close(out) != 0 && ok == 0) ok = -1;
    if (close(in) != 0 && ok == 0) ok = -1;
    return ok;
}

static void derive_signal_log_path(const char *dir)
{
    const char suffix[] = "/postmortems";
    g_postmortem_signal_log_path[0] = '\0';

    if (!dir) return;
    size_t len = strlen(dir);
    size_t suffix_len = sizeof(suffix) - 1u;
    if (len <= suffix_len ||
        strcmp(dir + len - suffix_len, suffix) != 0) {
        return;
    }

    size_t parent_len = len - suffix_len;
    const char log_suffix[] = "/node.log";
    size_t log_suffix_len = sizeof(log_suffix) - 1u;
    if (parent_len + log_suffix_len >= sizeof(g_postmortem_signal_log_path))
        return;

    memcpy(g_postmortem_signal_log_path, dir, parent_len);
    memcpy(g_postmortem_signal_log_path + parent_len,
           log_suffix, log_suffix_len + 1u);
}

static int signal_write_manifest(const char *path, int sig,
                                 int64_t crash_unix, size_t tape_size,
                                 uint64_t rng_count,
                                 uint64_t clock_advance_count,
                                 uint64_t inject_count)
{
    char manifest[768];
    size_t off = 0;
    manifest[0] = '\0';
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           "{\n"
                           "  \"version\": 1,\n"
                           "  \"format\": \"unpacked-cap-v1\",\n"
                           "  \"crash_signal\": ") != 0) return -1;
    if (signal_append_i64(manifest, sizeof(manifest), &off, sig) != 0)
        return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           ",\n"
                           "  \"crash_unix\": ") != 0) return -1;
    if (signal_append_i64(manifest, sizeof(manifest), &off, crash_unix) != 0)
        return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           ",\n"
                           "  \"reason\": \"fatal-signal\",\n"
                           "  \"tape_size_bytes\": ") != 0) return -1;
    if (signal_append_u64(manifest, sizeof(manifest), &off,
                          (uint64_t)tape_size) != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           ",\n"
                           "  \"rng_count\": ") != 0) return -1;
    if (signal_append_u64(manifest, sizeof(manifest), &off,
                          rng_count) != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           ",\n"
                           "  \"clock_advance_count\": ") != 0) return -1;
    if (signal_append_u64(manifest, sizeof(manifest), &off,
                          clock_advance_count) != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           ",\n"
                           "  \"inject_count\": ") != 0) return -1;
    if (signal_append_u64(manifest, sizeof(manifest), &off,
                          inject_count) != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           ",\n"
                           "  \"build_id\": \"") != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           CLIENT_NAME) != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off, "-") != 0)
        return -1;
    if (signal_append_u64(manifest, sizeof(manifest), &off,
                          (uint64_t)CLIENT_VERSION) != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           "\",\n"
                           "  \"git_sha\": \"unknown\"") != 0) return -1;
    if (signal_append_cstr(manifest, sizeof(manifest), &off,
                           "\n}\n") != 0) return -1;
    return signal_write_file(path, manifest, off);
}

static int signal_write_coremarker(const char *path, int64_t crash_unix)
{
    char marker[256];
    size_t off = 0;
    marker[0] = '\0';
    if (signal_append_cstr(marker, sizeof(marker), &off,
                           "postmortem capsule captured at ") != 0)
        return -1;
    if (signal_append_i64(marker, sizeof(marker), &off, crash_unix) != 0)
        return -1;
    if (signal_append_cstr(marker, sizeof(marker), &off,
                           "; match with corefile near this timestamp\n") != 0)
        return -1;
    return signal_write_file(path, marker, off);
}

static int signal_write_registers(const char *path, int sig,
                                  const siginfo_t *info,
                                  const void *ucontext)
{
#if !defined(__linux__) || !defined(__x86_64__) || !defined(REG_RIP)
    (void)ucontext;
#endif
    char regs[1024];
    size_t off = 0;
    regs[0] = '\0';
    if (signal_append_cstr(regs, sizeof(regs), &off, "signal: ") != 0)
        return -1;
    if (signal_append_i64(regs, sizeof(regs), &off, sig) != 0)
        return -1;
    if (signal_append_cstr(regs, sizeof(regs), &off, "\nsi_code: ") != 0)
        return -1;
    if (signal_append_i64(regs, sizeof(regs), &off,
                          info ? (int64_t)info->si_code : 0) != 0)
        return -1;
    if (signal_append_cstr(regs, sizeof(regs), &off, "\nfault_addr: ") != 0)
        return -1;
    if (signal_append_hex_u64(regs, sizeof(regs), &off,
                              info ? (uint64_t)(uintptr_t)info->si_addr
                                   : 0) != 0)
        return -1;

#if defined(__linux__) && defined(__x86_64__) && defined(REG_RIP)
    const ucontext_t *uc = (const ucontext_t *)ucontext;
    if (uc) {
        const greg_t *g = uc->uc_mcontext.gregs;
        const struct {
            const char *name;
            int idx;
        } fields[] = {
            { "rip", REG_RIP },
            { "rsp", REG_RSP },
            { "rbp", REG_RBP },
            { "rax", REG_RAX },
            { "rbx", REG_RBX },
            { "rcx", REG_RCX },
            { "rdx", REG_RDX },
            { "rsi", REG_RSI },
            { "rdi", REG_RDI },
        };
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            if (signal_append_cstr(regs, sizeof(regs), &off, "\n") != 0 ||
                signal_append_cstr(regs, sizeof(regs), &off,
                                   fields[i].name) != 0 ||
                signal_append_cstr(regs, sizeof(regs), &off, ": ") != 0 ||
                signal_append_hex_u64(regs, sizeof(regs), &off,
                                      (uint64_t)g[fields[i].idx]) != 0)
                return -1;
        }
    } else if (signal_append_cstr(regs, sizeof(regs), &off,
                                  "\nregisters: unavailable\n") != 0) {
        return -1;
    }
#else
    if (signal_append_cstr(regs, sizeof(regs), &off,
                           "\nregisters: unavailable\n") != 0)
        return -1;
#endif
    if (off == 0 || regs[off - 1u] != '\n') {
        if (signal_append_cstr(regs, sizeof(regs), &off, "\n") != 0)
            return -1;
    }
    return signal_write_file(path, regs, off);
}

int postmortem_capture_write(const struct postmortem_capture_opts *opts,
                             char *capsule_path_out,
                             size_t capsule_path_cap)
{
    if (!opts || !opts->dir || !*opts->dir || !opts->tape)
        return -EINVAL;

    int rc = mkdir_if_needed(opts->dir);
    if (rc != 0) return rc;

    int64_t ts = opts->crash_unix > 0
        ? opts->crash_unix
        : clock_now_wall_ms() / 1000;
    char name[128];
    snprintf(name, sizeof(name), "%lld-%d.cap",
             (long long)ts, (int)getpid());

    char cap_dir[512];
    int n = snprintf(cap_dir, sizeof(cap_dir), "%s/%s", opts->dir, name);
    if (n < 0 || (size_t)n >= sizeof(cap_dir)) return -ENAMETOOLONG;

    rc = mkdir_if_needed(cap_dir);
    if (rc != 0) return rc;

    char tape_path[576];
    snprintf(tape_path, sizeof(tape_path), "%s/tape.bin", cap_dir);
    size_t tape_need = seed_tape_size_bytes(opts->tape);
    uint8_t *tape_buf = (uint8_t *)zcl_malloc(tape_need, "postmortem.tape");
    if (!tape_buf) return -ENOMEM;
    size_t tape_written = 0;
    rc = seed_tape_save_to_memory(opts->tape, tape_buf, tape_need,
                                  &tape_written);
    if (rc == 0) rc = write_bytes_file(tape_path, tape_buf, tape_written);
    free(tape_buf);
    if (rc != 0) return rc;

    char manifest_path[576];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json",
             cap_dir);
    char reason_json[256];
    json_escape_string(opts->reason, reason_json, sizeof(reason_json));
    char version[64];
    FormatVersion(CLIENT_VERSION, version, sizeof(version));
    char manifest[1024];
    int mn = snprintf(manifest, sizeof(manifest),
        "{\n"
        "  \"version\": 1,\n"
        "  \"format\": \"unpacked-cap-v1\",\n"
        "  \"crash_signal\": %d,\n"
        "  \"crash_unix\": %lld,\n"
        "  \"reason\": \"%s\",\n"
        "  \"tape_size_bytes\": %zu,\n"
        "  \"rng_count\": %llu,\n"
        "  \"clock_advance_count\": %llu,\n"
        "  \"inject_count\": %llu,\n"
        "  \"build_id\": \"%s-%s\",\n"
        "  \"git_sha\": \"unknown\"\n"
        "}\n",
        opts->crash_signal,
        (long long)ts,
        reason_json,
        seed_tape_size_bytes(opts->tape),
        (unsigned long long)seed_tape_rng_count(opts->tape),
        (unsigned long long)seed_tape_clock_advance_count(opts->tape),
        (unsigned long long)seed_tape_inject_count(opts->tape),
        CLIENT_NAME,
        version);
    if (mn < 0 || (size_t)mn >= sizeof(manifest)) return -EOVERFLOW;
    rc = write_bytes_file(manifest_path, manifest, (size_t)mn);
    if (rc != 0) return rc;

    char proc_path[576];
    snprintf(proc_path, sizeof(proc_path), "%s/procstatus.txt", cap_dir);
    rc = copy_proc_status(proc_path);
    if (rc != 0) return rc;

    char log_path[576];
    snprintf(log_path, sizeof(log_path), "%s/log.txt", cap_dir);
    rc = copy_log_tail(opts->log_path, log_path);
    if (rc != 0) return rc;

    char regs_path[576];
    snprintf(regs_path, sizeof(regs_path), "%s/registers.txt", cap_dir);
    rc = write_bytes_file(regs_path,
                          "registers unavailable: non-signal capture\n",
                          strlen("registers unavailable: non-signal capture\n"));
    if (rc != 0) return rc;

    char marker_path[576];
    snprintf(marker_path, sizeof(marker_path), "%s/coremarker.txt", cap_dir);
    char marker[256];
    int marker_n = snprintf(marker, sizeof(marker),
        "postmortem capsule captured at %lld; match with corefile near this timestamp\n",
        (long long)ts);
    if (marker_n < 0 || (size_t)marker_n >= sizeof(marker)) return -EOVERFLOW;
    rc = write_bytes_file(marker_path, marker, (size_t)marker_n);
    if (rc != 0) return rc;

    if (capsule_path_out && capsule_path_cap > 0) {
        int pn = snprintf(capsule_path_out, capsule_path_cap, "%s", cap_dir);
        if (pn < 0 || (size_t)pn >= capsule_path_cap) return -ENAMETOOLONG;
    }
    fprintf(stderr,  // obs-ok:postmortem-capsule-path-diagnostic
            "[postmortem] capsule written: %s\n", cap_dir);
    return 0;
}

static void postmortem_crash_hook(int sig, zcl_signal_info_t *info,
                                  void *ucontext,
                                  void *ctx)
{
    (void)ctx;
    if (g_postmortem_in_handler || !g_postmortem_tape ||
        g_postmortem_dir[0] == '\0' || !g_postmortem_signal_tape_buf ||
        g_postmortem_signal_tape_cap == 0) {
        return;
    }
    g_postmortem_in_handler = 1;

    size_t tape_written = 0;
    uint64_t rng_count = seed_tape_rng_count(g_postmortem_tape);
    uint64_t clock_advance_count =
        seed_tape_clock_advance_count(g_postmortem_tape);
    uint64_t inject_count = seed_tape_inject_count(g_postmortem_tape);
    if (seed_tape_save_to_memory(g_postmortem_tape,
                                 g_postmortem_signal_tape_buf,
                                 g_postmortem_signal_tape_cap,
                                 &tape_written) != 0 ||
        tape_written == 0) {
        g_postmortem_in_handler = 0;
        return;
    }

    int64_t crash_unix = g_postmortem_install_unix > 0
        ? g_postmortem_install_unix
        : 0;
    char name[128];
    size_t off = 0;
    name[0] = '\0';
    if (signal_append_i64(name, sizeof(name), &off, crash_unix) != 0 ||
        signal_append_cstr(name, sizeof(name), &off, "-") != 0 ||
        signal_append_u64(name, sizeof(name), &off,
                          (uint64_t)getpid()) != 0 ||
        signal_append_cstr(name, sizeof(name), &off, ".cap") != 0) {
        g_postmortem_in_handler = 0;
        return;
    }

    char cap_dir[512];
    if (signal_join_path(cap_dir, sizeof(cap_dir),
                         g_postmortem_dir, name) != 0) {
        g_postmortem_in_handler = 0;
        return;
    }

    (void)mkdir(g_postmortem_dir, 0755);
    if (mkdir(cap_dir, 0755) != 0 && errno != EEXIST) {
        g_postmortem_in_handler = 0;
        return;
    }

    char path[576];
    if (signal_join_path(path, sizeof(path), cap_dir, "tape.bin") != 0 ||
        signal_write_file(path, g_postmortem_signal_tape_buf,
                          tape_written) != 0) {
        g_postmortem_in_handler = 0;
        return;
    }
    if (signal_join_path(path, sizeof(path), cap_dir, "manifest.json") == 0)
        (void)signal_write_manifest(path, sig, crash_unix, tape_written,
                                    rng_count, clock_advance_count,
                                    inject_count);
    if (signal_join_path(path, sizeof(path), cap_dir, "procstatus.txt") == 0) {
#if defined(__linux__)
        (void)signal_copy_file_limited("/proc/self/status", path, 8192);
#else
        static const char unavailable[] =
            "unavailable: /proc/self/status is Linux-only\n";
        (void)signal_write_file(path, unavailable,
                                sizeof(unavailable) - 1u);
#endif
    }
    if (signal_join_path(path, sizeof(path), cap_dir, "log.txt") == 0) {
        if (g_postmortem_signal_log_path[0] == '\0' ||
            signal_copy_tail_limited(g_postmortem_signal_log_path, path,
                                     POSTMORTEM_LOG_TAIL_MAX) != 0) {
            (void)signal_write_empty_file(path);
        }
    }
    if (signal_join_path(path, sizeof(path), cap_dir, "registers.txt") == 0)
        (void)signal_write_registers(path, sig, info, ucontext);
    if (signal_join_path(path, sizeof(path), cap_dir, "coremarker.txt") == 0)
        (void)signal_write_coremarker(path, crash_unix);

    g_postmortem_in_handler = 0;
}

int postmortem_install(seed_tape_t *tape, const char *dir)
{
    if (!tape || !dir || !*dir) return -EINVAL;
    if (strlen(dir) >= sizeof(g_postmortem_dir)) return -ENAMETOOLONG;
    int rc = mkdir_if_needed(dir);
    if (rc != 0) return rc;

    if (!g_postmortem_signal_tape_buf) {
        g_postmortem_signal_tape_buf =
            zcl_malloc(POSTMORTEM_SIGNAL_TAPE_MAX,
                       "postmortem.signal_tape");
        if (!g_postmortem_signal_tape_buf)
            return -ENOMEM;
        g_postmortem_signal_tape_cap = POSTMORTEM_SIGNAL_TAPE_MAX;
    }

    snprintf(g_postmortem_dir, sizeof(g_postmortem_dir), "%s", dir);
    derive_signal_log_path(dir);
    g_postmortem_tape = tape;
    g_postmortem_install_unix = clock_now_wall_ms() / 1000;
    g_postmortem_in_handler = 0;
    signal_handler_set_crash_hook(postmortem_crash_hook, NULL);
    if (fatal_signal_handlers_are_default() && signal_handler_install() != 0) {
        postmortem_uninstall();
        return -errno;
    }
    return 0;
}

void postmortem_uninstall(void)
{
    signal_handler_clear_crash_hook();
    g_postmortem_tape = NULL;
    g_postmortem_dir[0] = '\0';
    g_postmortem_signal_log_path[0] = '\0';
    free(g_postmortem_signal_tape_buf);
    g_postmortem_signal_tape_buf = NULL;
    g_postmortem_signal_tape_cap = 0;
    g_postmortem_install_unix = 0;
    g_postmortem_in_handler = 0;
}

seed_tape_t *postmortem_capsule_load_tape(const char *capsule_path)
{
    if (!capsule_path || !*capsule_path) return NULL;
    if (postmortem_has_suffix(capsule_path, ".cap.gz")) {
        uint8_t *buf = NULL;
        size_t size = 0;
        int rc = gz_read_tar_member(capsule_path, "tape.bin", &buf, &size,
                                    POSTMORTEM_GZ_MEMBER_MAX);
        if (rc != 0 || !buf || size == 0) {
            free(buf);
            return NULL;
        }
        seed_tape_t *tape = seed_tape_load_from_memory(buf, size);
        free(buf);
        return tape;
    }

    char tape_path[576];
    int n = snprintf(tape_path, sizeof(tape_path), "%s/tape.bin",
                     capsule_path);
    if (n < 0 || (size_t)n >= sizeof(tape_path)) return NULL;

    FILE *fp = fopen(tape_path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long size_l = ftell(fp);
    if (size_l < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    size_t size = (size_t)size_l;
    if (size == 0) {
        fclose(fp);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)zcl_malloc(size, "postmortem.tape_load");
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t got = fread(buf, 1, size, fp);
    fclose(fp);
    if (got != size) {
        free(buf);
        return NULL;
    }
    seed_tape_t *tape = seed_tape_load_from_memory(buf, size);
    free(buf);
    return tape;
}

bool postmortem_capsule_validate(const char *capsule_path)
{
    if (!capsule_path || !*capsule_path) return false;
    if (postmortem_has_suffix(capsule_path, ".cap.gz")) {
        uint8_t *manifest = NULL;
        size_t manifest_len = 0;
        int rc = gz_read_tar_member(capsule_path, "manifest.json",
                                    &manifest, &manifest_len, 64u * 1024u);
        if (rc != 0 || !manifest || manifest_len == 0) {
            free(manifest);
            return false;
        }
        free(manifest);
        seed_tape_t *t = postmortem_capsule_load_tape(capsule_path);
        if (!t) return false;
        seed_tape_close(t);
        return true;
    }

    char manifest_path[576];
    int n = snprintf(manifest_path, sizeof(manifest_path),
                     "%s/manifest.json", capsule_path);
    if (n < 0 || (size_t)n >= sizeof(manifest_path)) return false;
    struct stat st;
    if (stat(manifest_path, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    seed_tape_t *t = postmortem_capsule_load_tape(capsule_path);
    if (!t) return false;
    seed_tape_close(t);
    return true;
}

int postmortem_capsule_compress(const char *capsule_path,
                                char *compressed_path_out,
                                size_t compressed_path_cap)
{
    if (!capsule_path || !*capsule_path) return -EINVAL;
    if (!postmortem_has_suffix(capsule_path, ".cap")) return -EINVAL;

    struct stat st;
    if (stat(capsule_path, &st) != 0) return -errno;
    if (!S_ISDIR(st.st_mode)) return -ENOTDIR;

    char dst[576];
    int n = snprintf(dst, sizeof(dst), "%s.gz", capsule_path);
    if (n < 0 || (size_t)n >= sizeof(dst)) return -ENAMETOOLONG;

    char tmp[640];
    n = snprintf(tmp, sizeof(tmp), "%s.tmp", dst);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return -ENAMETOOLONG;

    gzFile gz = gzopen(tmp, "wb6");
    if (!gz) return errno ? -errno : -EIO;

    const char *required[] = { "manifest.json", "tape.bin" };
    int rc = 0;
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        char path[640];
        n = snprintf(path, sizeof(path), "%s/%s", capsule_path, required[i]);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            rc = -ENAMETOOLONG;
            break;
        }
        rc = tar_write_file(gz, required[i], path);
        if (rc != 0) break;
    }

    const char *optional[] = {
        "procstatus.txt",
        "log.txt",
        "registers.txt",
        "coremarker.txt",
    };
    for (size_t i = 0; rc == 0 &&
         i < sizeof(optional) / sizeof(optional[0]); i++) {
        char path[640];
        n = snprintf(path, sizeof(path), "%s/%s", capsule_path, optional[i]);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            rc = -ENAMETOOLONG;
            break;
        }
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
            rc = tar_write_file(gz, optional[i], path);
    }

    if (rc == 0) {
        uint8_t zero[TAR_BLOCK_SIZE * 2u] = {0};
        rc = gz_write_all(gz, zero, sizeof(zero));
    }

    int close_rc = gzclose(gz);
    if (rc == 0 && close_rc != Z_OK) rc = -EIO;
    if (rc != 0) {
        unlink(tmp);
        return rc;
    }

    if (rename(tmp, dst) != 0) {
        rc = -errno;
        unlink(tmp);
        return rc;
    }

    rc = postmortem_remove_tree(capsule_path);
    if (rc != 0) return rc;

    if (compressed_path_out && compressed_path_cap > 0) {
        n = snprintf(compressed_path_out, compressed_path_cap, "%s", dst);
        if (n < 0 || (size_t)n >= compressed_path_cap)
            return -ENAMETOOLONG;
    }
    return 0;
}

int postmortem_capsule_compress_unpacked(const char *dir,
                                         size_t *compressed_out)
{
    if (!dir || !*dir || !compressed_out) return -EINVAL;
    *compressed_out = 0;

    DIR *d = opendir(dir);
    if (!d) return errno == ENOENT ? 0 : -errno;

    int first_err = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!postmortem_has_suffix(de->d_name, ".cap")) continue;

        char path[576];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            if (first_err == 0) first_err = -ENAMETOOLONG;
            continue;
        }
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        int rc = postmortem_capsule_compress(path, NULL, 0);
        if (rc == 0) {
            (*compressed_out)++;
        } else if (first_err == 0) {
            first_err = rc;
        }
    }
    closedir(d);
    return first_err;
}

seed_tape_t *postmortem_load(const char *path)
{
    return postmortem_capsule_load_tape(path);
}
#endif /* !defined(_WIN32) */
