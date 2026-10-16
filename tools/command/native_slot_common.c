/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared slot naming and path rules (see native_slot_common.h).
 */
#include "command/native_slot_common.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
