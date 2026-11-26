/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.lane.new leaves a lease and the signing settings in a lane.
 *
 * The lease says who made the lane and when it may be reaped (6 h without a
 * touch). It is written to a temporary name and renamed, so a reader never
 * sees half a file, and it is excluded from the lane's git status through
 * the worktree's own info/exclude. Signing is armed per worktree
 * (gpg.format=ssh, user.signingkey=<~/.ssh/id_ed25519.pub path>,
 * commit.gpgsign=true) only when gpg.ssh.allowedsignersfile is set and lists
 * that public key; only the .pub is read, never a private key. Otherwise
 * nothing is set and signing_reason says why. git runs only through
 * zcl_spawn_capture(). */

#include "command/native_dev_lane_lease.h"

#include "platform/time_compat.h"
#include "util/path_util.h"
#include "util/spawn.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define DLL_PATH_CAP 4096
#define DLL_VAL_CAP 1024
#define DLL_BODY_CAP 512
#define DLL_GIT_TIMEOUT_MS 60000

static bool dll_name_char(char c)
{
    return isalnum((unsigned char)c) || (c != '\0' && strchr("._-", c));
}

static bool dll_name_ok(const char *name)
{
    if (!name || !name[0] || strlen(name) > 64)
        return false;
    for (const char *p = name; *p; p++)
        if (!dll_name_char(*p))
            return false;
    return true;
}

/* Owner: $BOARD_AGENT, else $USER, else "unknown"; characters outside
 * [A-Za-z0-9._-] make the name unusable, so it falls back to "unknown". */
static const char *dll_owner(void)
{
    const char *name = getenv("BOARD_AGENT");
    if (!name || !name[0])
        name = getenv("USER");
    return dll_name_ok(name) ? name : "unknown";
}

bool zcl_dev_lane_lease_body(const char *owner, int64_t now, char *out,
                             size_t cap)
{
    int n;
    if (!owner || !owner[0] || !out)
        return false;
    for (const char *p = owner; *p; p++)
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20)
            return false;
    n = snprintf(out, cap,
                 "{\"owner\":\"%s\",\"created\":%lld,\"touched\":%lld,"
                 "\"ttl_seconds\":%d}\n",
                 owner, (long long)now, (long long)now,
                 ZCL_LANE_LEASE_TTL_S);
    return n > 0 && (size_t)n < cap;
}

static bool dll_write_temp(const char *temp, const char *body)
{
    size_t len = strlen(body);
    int fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    bool ok;
    if (fd < 0)
        return false;
    ok = write(fd, body, len) == (ssize_t)len;
#ifndef _WIN32
    ok = ok && fsync(fd) == 0;
#endif
    return close(fd) == 0 && ok;
}

static bool dll_lease_write(const char *lane, char *lease, size_t lease_cap)
{
    char temp[DLL_PATH_CAP], body[DLL_BODY_CAP];
    struct stat st;
    if (!zcl_path_join(lease, lease_cap, lane, ZCL_LANE_LEASE_FILE) ||
        snprintf(temp, sizeof(temp), "%s.tmp", lease) >= (int)sizeof(temp))
        return false;
    if (stat(lease, &st) == 0)
        return true;
    if (!zcl_dev_lane_lease_body(dll_owner(), platform_time_wall_unix(), body,
                                 sizeof(body)) ||
        !dll_write_temp(temp, body) || rename(temp, lease) != 0) {
        (void)unlink(temp);
        return false;
    }
    return true;
}

static int dll_git(const char *dir, const char *const args[], char *out,
                   size_t cap)
{
    const char *argv[12];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    out[0] = '\0';
    return zcl_spawn_capture(argv, out, cap, DLL_GIT_TIMEOUT_MS);
}

/* Value of `key` in root's effective configuration; false when unset. */
static bool dll_cfg_get(const char *root, const char *key, char *val,
                        size_t cap)
{
    const char *args[] = { "config", "--get", key, NULL };
    size_t n;
    if (dll_git(root, args, val, cap) != 0)
        return false;
    n = strlen(val);
    while (n && (val[n - 1] == '\n' || val[n - 1] == '\r'))
        val[--n] = '\0';
    return n > 0;
}

static bool dll_cfg_set(const char *lane, const char *key, const char *val)
{
    const char *args[] = { "config", "--worktree", key, val, NULL };
    char out[256];
    return dll_git(lane, args, out, sizeof(out)) == 0;
}

/* The public key to sign with: $HOME/.ssh/id_ed25519.pub. Fills `pub` with
 * its path and `blob` with the base64 key field; only the .pub is read. */
static bool dll_pub_key(char *pub, size_t pub_cap, char *blob, size_t blob_cap)
{
    const char *home = getenv("HOME");
    char line[DLL_VAL_CAP], kind[64];
    FILE *f;
    bool ok;
    if (!home || home[0] != '/' ||
        !zcl_path_join(pub, pub_cap, home, ".ssh/id_ed25519.pub"))
        return false;
    f = fopen(pub, "r");
    if (!f)
        return false;
    ok = fgets(line, sizeof(line), f) != NULL;
    (void)fclose(f);
    return ok && sscanf(line, "%63s %1000s", kind, blob) == 2 &&
           strlen(blob) < blob_cap && strlen(blob) > 16;
}

/* True when `blob` appears in the allowed-signers file named by the
 * effective gpg.ssh.allowedsignersfile of `root` (a leading ~/ is $HOME). */
static bool dll_allowed_has(const char *root, const char *blob)
{
    char path[DLL_PATH_CAP], val[DLL_VAL_CAP], line[2048];
    const char *home = getenv("HOME");
    bool found = false;
    FILE *f;
    if (!dll_cfg_get(root, "gpg.ssh.allowedsignersfile", val, sizeof(val)))
        return false;
    if (strncmp(val, "~/", 2) == 0 && home)
        (void)snprintf(path, sizeof(path), "%s/%s", home, val + 2);
    else
        (void)snprintf(path, sizeof(path), "%s", val);
    f = fopen(path, "r");
    if (!f)
        return false;
    while (!found && fgets(line, sizeof(line), f))
        found = strstr(line, blob) != NULL;
    (void)fclose(f);
    return found;
}

static bool dll_signing_apply(const char *root, const char *lane,
                              const char *pub)
{
    const char *ext[] = { "config", "extensions.worktreeConfig", "true",
                          NULL };
    char out[256];
    return dll_git(root, ext, out, sizeof(out)) == 0 &&
           dll_cfg_set(lane, "gpg.format", "ssh") &&
           dll_cfg_set(lane, "user.signingkey", pub) &&
           dll_cfg_set(lane, "commit.gpgsign", "true");
}

/* Arm signing in the lane when the repository trusts the user's ed25519
 * key; otherwise set nothing and name the first condition that failed. */
static const char *dll_signing_setup(const char *root, const char *lane)
{
    char pub[DLL_PATH_CAP], blob[DLL_VAL_CAP], val[DLL_VAL_CAP];
    if (!dll_cfg_get(root, "gpg.ssh.allowedsignersfile", val, sizeof(val)))
        return "gpg.ssh.allowedsignersfile is not set";
    if (!dll_pub_key(pub, sizeof(pub), blob, sizeof(blob)))
        return "~/.ssh/id_ed25519.pub is missing or unreadable";
    if (!dll_allowed_has(root, blob))
        return "the public key is not in the allowed signers file";
    if (!dll_signing_apply(root, lane, pub))
        return "git config --worktree failed";
    return NULL;
}

/* Keep the lease out of the lane's `git status` via the worktree's own
 * info/exclude. Best effort: a failure leaves the lease untracked only. */
static void dll_exclude_lease(const char *lane)
{
    const char *args[] = { "rev-parse", "--git-path", "info/exclude", NULL };
    char rel[DLL_PATH_CAP], abs[DLL_PATH_CAP];
    size_t n;
    FILE *f;
    if (dll_git(lane, args, rel, sizeof(rel)) != 0)
        return;
    n = strlen(rel);
    while (n && (rel[n - 1] == '\n' || rel[n - 1] == '\r'))
        rel[--n] = '\0';
    if (!n)
        return;
    if (rel[0] == '/')
        (void)snprintf(abs, sizeof(abs), "%s", rel);
    else if (!zcl_path_join(abs, sizeof(abs), lane, rel))
        return;
    f = fopen(abs, "a");
    if (!f)
        return;
    (void)fputs("/" ZCL_LANE_LEASE_FILE "\n", f);
    (void)fclose(f);
}

bool zcl_dev_lane_lease_setup(const char *root, const char *lane,
                              struct json_value *data)
{
    char lease[DLL_PATH_CAP], lint[DLL_PATH_CAP];
    const char *why;
    bool lint_present;
    struct stat st;
    bool fresh;
    if (!zcl_path_join(lease, sizeof(lease), lane, ZCL_LANE_LEASE_FILE))
        return false;
    fresh = stat(lease, &st) != 0;
    if (!dll_lease_write(lane, lease, sizeof(lease)))
        return false;
    if (fresh)
        dll_exclude_lease(lane);
    why = dll_signing_setup(root, lane);
    lint_present = zcl_path_join(lint, sizeof(lint), lane,
                                 "build/bin/z23-lint") &&
                   stat(lint, &st) == 0 && S_ISREG(st.st_mode);
    (void)json_push_kv_str(data, "lease_path", lease);
    (void)json_push_kv_bool(data, "signing_configured", why == NULL);
    if (why)
        (void)json_push_kv_str(data, "signing_reason", why);
    (void)json_push_kv_bool(data, "precheck_lint_present", lint_present);
    return true;
}
