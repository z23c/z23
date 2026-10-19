/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared slot naming and path rules (see native_slot_common.h).
 */
#include "command/native_slot_common.h"

#include "crypto/sha256.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

bool slot_name_ok(const char *name)
{
    size_t n = name ? strlen(name) : 0;
    if (n == 0 || n > SLOT_NAME_MAX || name[0] == '-' || name[0] == '.')
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return strstr(name, ".tmp.") == NULL;
}

bool slot_root(char *out, size_t cap)
{
    const char *env = getenv("ZCL_BINARY_SLOTS_DIR");
    const char *home = getenv("HOME");
    int n = -1;
    if (env && env[0])
        n = snprintf(out, cap, "%s", env);
    else if (home && home[0])
        n = snprintf(out, cap, "%s/.local/lib/zclassic23-slots", home);
    return n > 0 && (size_t)n < cap && out[0] == '/';
}

enum slot_path_status slot_paths_resolve(struct slot_paths *out,
                                         const char *name)
{
    int a, b, c;
    if (!slot_root(out->slots, sizeof(out->slots)))
        return SLOT_PATH_NO_ROOT;
    a = snprintf(out->name_dir, sizeof(out->name_dir), "%s/%s", out->slots,
                 name);
    b = snprintf(out->final_path, sizeof(out->final_path), "%s/%s/%s",
                 out->slots, name, SLOT_FILE);
    c = snprintf(out->tmp_path, sizeof(out->tmp_path), "%s/%s.tmp.%ld",
                 out->slots, name, (long)getpid());
    if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof(out->name_dir) ||
        (size_t)b >= sizeof(out->final_path) ||
        (size_t)c >= sizeof(out->tmp_path))
        return SLOT_PATH_TOO_LONG;
    return SLOT_PATH_OK;
}

bool slot_class_ok(const char *service_class)
{
    return service_class && (strcmp(service_class, "tunnel-receiver") == 0 ||
                             strcmp(service_class, "gateway") == 0);
}

bool slot_unit_name(const char *service_class, const char *instance,
                    char *out, size_t cap)
{
    const char *prefix = NULL;
    int n;
    if (!slot_class_ok(service_class) || !slot_name_ok(instance))
        return false;
    prefix = strcmp(service_class, "gateway") == 0 ? "z23-gateway@"
                                                   : "z23-tunnel-receiver@";
    n = snprintf(out, cap, "%s%s.service", prefix, instance);
    return n > 0 && (size_t)n < cap;
}

static bool dir_from_env(const char *env, const char *home_rel,
                         char *out, size_t cap)
{
    const char *home = getenv("HOME");
    int n = -1;
    if (env && env[0])
        n = snprintf(out, cap, "%s", env);
    else if (home && home[0])
        n = snprintf(out, cap, "%s/%s", home, home_rel);
    return n > 0 && (size_t)n < cap && out[0] == '/';
}

bool slot_unit_dir(char *out, size_t cap)
{
    return dir_from_env(getenv("ZCL_SLOT_UNIT_DIR"),
                        ".config/systemd/user", out, cap);
}

bool slot_state_dir(char *out, size_t cap)
{
    return dir_from_env(getenv("ZCL_SLOT_STATE_DIR"),
                        ".local/state/zclassic23/slots",
                        out, cap);
}

long slot_read_file(const char *path, char *buf, size_t cap)
{
    ssize_t got;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || cap == 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    got = read(fd, buf, cap - 1);
    close(fd);
    if (got < 0)
        return -1;
    buf[got] = '\0';
    return (long)got;
}

bool slot_dropin_exec(const char *text, char *bin, size_t bin_cap, char *args,
                      size_t args_cap)
{
    const char *line = text, *found = NULL;
    while (line && *line) {
        if (strncmp(line, "ExecStart=", 10) == 0 && line[10] != '\n' &&
            line[10] != '\0')
            found = line + 10;
        line = strchr(line, '\n');
        if (line)
            line++;
    }
    if (!found)
        return false;
    size_t len = strcspn(found, "\n");
    size_t blen = strcspn(found, " \n");
    if (blen == 0 || blen >= bin_cap)
        return false;
    memcpy(bin, found, blen);
    bin[blen] = '\0';
    const char *rest = found + blen;
    size_t alen = len - blen;
    while (alen > 0 && *rest == ' ') {
        rest++;
        alen--;
    }
    if (alen >= args_cap)
        return false;
    memcpy(args, rest, alen);
    args[alen] = '\0';
    return true;
}

bool slot_name_from_binary(const char *binary, char *out, size_t cap)
{
    const char *end = strrchr(binary, '/');
    const char *start;
    if (!end || end == binary)
        return false;
    start = end;
    while (start > binary && start[-1] != '/')
        start--;
    if ((size_t)(end - start) == 0 || (size_t)(end - start) >= cap)
        return false;
    memcpy(out, start, (size_t)(end - start));
    out[end - start] = '\0';
    return true;
}

#ifndef _WIN32
/* ---- slot digest record -------------------------------------------------- */

static bool slot_child_path(const char *dir, const char *leaf, char *out,
                            size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}

/* The slot directory must be a real directory we own, and neither it nor the
 * slots root above it may be writable by group or others: whoever can write
 * there can swap the binary the digest record vouches for. */
enum slot_dir_state { SLOT_DIR_OK, SLOT_DIR_BAD, SLOT_DIR_WRITABLE };

static enum slot_dir_state slot_dir_state(const char *name_dir)
{
    struct stat sb;
    char root[SLOT_PATH_MAX];
    const char *slash = strrchr(name_dir, '/');
    if (lstat(name_dir, &sb) != 0 || !S_ISDIR(sb.st_mode) ||
        sb.st_uid != geteuid())
        return SLOT_DIR_BAD;
    if ((sb.st_mode & 022) != 0)
        return SLOT_DIR_WRITABLE;
    if (!slash || slash == name_dir ||
        (size_t)(slash - name_dir) >= sizeof(root))
        return SLOT_DIR_BAD;
    memcpy(root, name_dir, (size_t)(slash - name_dir));
    root[slash - name_dir] = '\0';
    if (stat(root, &sb) != 0 || !S_ISDIR(sb.st_mode))
        return SLOT_DIR_BAD;
    return (sb.st_mode & 022) != 0 ? SLOT_DIR_WRITABLE : SLOT_DIR_OK;
}

bool slot_binary_digest(const char *name_dir, uint8_t sha[32])
{
    char path[SLOT_PATH_MAX];
    struct stat sb;
    bool ok;
    if (!slot_child_path(name_dir, SLOT_FILE, path, sizeof(path)))
        return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    ok = fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) &&
         sb.st_uid == geteuid() && slot_fd_digest(fd, sha);
    close(fd);
    return ok;
}

bool slot_fd_digest(int fd, uint8_t sha[32])
{
    struct sha256_ctx ctx;
    uint8_t buf[65536];
    bool ok = true;
    sha256_init(&ctx);
    for (;;) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got < 0) {
            ok = false;
            break;
        }
        if (got == 0)
            break;
        sha256_write(&ctx, buf, (size_t)got);
    }
    if (ok)
        sha256_finalize(&ctx, sha);
    return ok;
}

bool slot_record_write(const char *name_dir, const uint8_t sha[32])
{
    char final_path[SLOT_PATH_MAX], tmp_path[SLOT_PATH_MAX + 16];
    char hex[66];
    if (!slot_child_path(name_dir, SLOT_DIGEST_FILE, final_path,
                         sizeof(final_path)) ||
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", final_path,
                 (long)getpid()) >= (int)sizeof(tmp_path))
        return false;
    for (size_t i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", sha[i]);
    hex[64] = '\n';
    hex[65] = '\0';
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                O_NOFOLLOW, 0644);
    if (fd < 0)
        return false;
    bool ok = write(fd, hex, 65) == 65 && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (!ok || rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return false;
    }
    return true;
}

bool slot_record_hex(const char *name_dir, char hex[65])
{
    char rec_path[SLOT_PATH_MAX], rec[80];
    struct stat sb;
    if (!slot_child_path(name_dir, SLOT_DIGEST_FILE, rec_path,
                         sizeof(rec_path)) ||
        lstat(rec_path, &sb) != 0 || !S_ISREG(sb.st_mode) ||
        sb.st_uid != geteuid())
        return false;
    if (slot_read_file(rec_path, rec, sizeof(rec)) < 64)
        return false;
    memcpy(hex, rec, 64);
    hex[64] = '\0';
    return true;
}

bool slot_exe_matches_hex(const char *exe_path, const char hex[65])
{
    uint8_t sha[32];
    char got[65];
    int fd = open(exe_path, O_RDONLY | O_CLOEXEC);
    bool ok;
    if (fd < 0)
        return false;
    ok = slot_fd_digest(fd, sha);
    close(fd);
    if (!ok)
        return false;
    for (size_t i = 0; i < 32; i++)
        snprintf(got + i * 2, 3, "%02x", sha[i]);
    return memcmp(got, hex, 64) == 0;
}

enum slot_verify slot_verify_installed(const char *name_dir)
{
    uint8_t sha[32];
    char hex[65], rec[65];
    enum slot_dir_state ds = slot_dir_state(name_dir);
    if (ds == SLOT_DIR_WRITABLE)
        return SLOT_VERIFY_WRITABLE;
    if (ds != SLOT_DIR_OK)
        return SLOT_VERIFY_UNSAFE;
    if (!slot_record_hex(name_dir, rec))
        return SLOT_VERIFY_NO_RECORD;
    if (!slot_binary_digest(name_dir, sha))
        return SLOT_VERIFY_UNSAFE;
    for (size_t i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", sha[i]);
    return memcmp(rec, hex, 64) == 0 ? SLOT_VERIFY_OK : SLOT_VERIFY_MISMATCH;
}

#endif /* _WIN32 */
