/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: supervisor run registration and uninstall for the signed plugin store. */

#include "plugin_internal.h"
#include "platform/os_proc.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PS_MANIFEST_SUFFIX ".plugin.json"
#define PS_RUN_FILE "run"
#define PS_LOCK_FILE ".lock"
#define PS_LOCK_QUEUE ".lock.q"

/* NAME/run is one line: "<pid> <start token> <128 hex generation>\n". The
 * token is os_proc_pid_start_token for the pid, so a pid the kernel reused
 * after the supervisor died never counts as the same supervisor. */
enum { PS_RUN_LINE_MAX = 10 + 1 + 20 + 1 + PLUGIN_HEX_SHA3_512 + 1 };

static bool ps_run_path(const char *plugdir, char *path, size_t cap)
{
    return plugin_join(path, cap, plugdir, PS_RUN_FILE, NULL, NULL);
}

/* Split "<pid> <token> <128 hex>\n" in place into its three fields. */
static bool ps_run_split(char *line, char **pid, char **token, char **gen)
{
    char *sp1 = strchr(line, ' ');
    char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
    char *nl = sp2 ? strchr(sp2 + 1, '\n') : NULL;
    if (!sp1 || !sp2 || !nl || nl[1] != '\0' || sp1 == line ||
        sp2 == sp1 + 1 || nl != sp2 + 1 + PLUGIN_HEX_SHA3_512)
        return false;
    *sp1 = '\0';
    *sp2 = '\0';
    *nl = '\0';
    *pid = line;
    *token = sp1 + 1;
    *gen = sp2 + 1;
    return true;
}

/* A decimal u64 above zero and within max, with no trailing bytes. */
static bool ps_run_u64(const char *s, uint64_t max, uint64_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end != '\0' || v == 0 || v > max)
        return false;
    *out = (uint64_t)v;
    return true;
}

static enum plugin_status ps_run_parse(const char *bytes, size_t len,
                                       struct plugin_run_registration *out)
{
    char line[PS_RUN_LINE_MAX + 1];
    if (len < 1 || len > PS_RUN_LINE_MAX || bytes[len - 1] != '\n')
        return PLUGIN_ERR_UNINSTALL_LAYOUT;
    memcpy(line, bytes, len);
    line[len] = '\0';
    char *pid, *token, *gen;
    if (!ps_run_split(line, &pid, &token, &gen) ||
        !plugin_hex_valid(gen, PLUGIN_HEX_SHA3_512))
        return PLUGIN_ERR_UNINSTALL_LAYOUT;
    if (!ps_run_u64(pid, UINT32_MAX, &out->pid) ||
        !ps_run_u64(token, UINT64_MAX, &out->start_token))
        return PLUGIN_ERR_UNINSTALL_LAYOUT;
    memcpy(out->generation, gen, PLUGIN_HEX_SHA3_512 + 1);
    return PLUGIN_OK;
}

/* ENOENT means *found = false; anything unreadable is PLUGIN_ERR_IO and
 * malformed content is PLUGIN_ERR_UNINSTALL_LAYOUT — a NAME/run the store
 * never wrote counts as a foreign entry. */
static enum plugin_status ps_run_read(const char *plugdir,
                                      struct plugin_run_registration *out,
                                      bool *found)
{
    char path[PLUGIN_PATH_MAX];
    if (!ps_run_path(plugdir, path, sizeof(path)))
        return PLUGIN_ERR_ARGUMENT;
    *found = false;
    char *bytes = NULL;
    size_t len = 0;
    if (!plugin_read_file(path, PS_RUN_LINE_MAX + 1,
                          PLUGIN_OPEN_NOFOLLOW | PLUGIN_OPEN_OWNER_ONLY,
                          &bytes, &len)) {
        return errno == ENOENT ? PLUGIN_OK : PLUGIN_ERR_IO;
    }
    enum plugin_status st = ps_run_parse(bytes, len, out);
    free(bytes);
    if (st == PLUGIN_OK)
        *found = true;
    return st;
}

enum ps_run_live { PS_RUN_DEAD = 0, PS_RUN_LIVE, PS_RUN_UNKNOWN };

/* A registration is live only when the pid runs and its start token matches
 * the record now; a reused pid has a different token and counts as dead. */
static enum ps_run_live ps_run_liveness(const struct plugin_run_registration *reg)
{
    switch (os_proc_pid_liveness(reg->pid)) {
    case OS_PROC_LIVENESS_DEAD:
        return PS_RUN_DEAD;
    case OS_PROC_LIVENESS_UNKNOWN:
        return PS_RUN_UNKNOWN;
    default:
        break;
    }
    uint64_t token = 0;
    if (!os_proc_pid_start_token(reg->pid, &token))
        return PS_RUN_UNKNOWN;
    return token == reg->start_token ? PS_RUN_LIVE : PS_RUN_DEAD;
}

/* Gate for mutations that must not touch a live run: OK when nothing is
 * registered or the record is stale, BUSY when it is live, IO when liveness
 * cannot be decided (a malformed record fails earlier, in the read). */
static enum plugin_status ps_run_gate(const char *plugdir)
{
    struct plugin_run_registration reg;
    bool found = false;
    enum plugin_status st = ps_run_read(plugdir, &reg, &found);
    if (st != PLUGIN_OK || !found)
        return st;
    switch (ps_run_liveness(&reg)) {
    case PS_RUN_LIVE:
        return PLUGIN_ERR_BUSY;
    case PS_RUN_UNKNOWN:
        return PLUGIN_ERR_IO;
    default:
        return PLUGIN_OK;
    }
}

enum plugin_status plugin_store_run_register(const char *root, const char *name,
                                             uint64_t pid, uint64_t start_token,
                                             const char *generation)
{
    if (pid == 0 || pid > UINT32_MAX || start_token == 0 || !generation ||
        !plugin_hex_valid(generation, PLUGIN_HEX_SHA3_512))
        return PLUGIN_ERR_ARGUMENT;
    char plugdir[PLUGIN_PATH_MAX];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    struct plugin_lock lock;
    st = plugin_lock_acquire(plugdir, &lock);
    if (st != PLUGIN_OK)
        return st;
    st = ps_run_gate(plugdir);
    if (st == PLUGIN_OK) {
        char line[PS_RUN_LINE_MAX + 1], path[PLUGIN_PATH_MAX];
        int n = snprintf(line, sizeof(line), "%llu %llu %s\n",
                         (unsigned long long)pid,
                         (unsigned long long)start_token, generation);
        if (n <= 0 || (size_t)n > PS_RUN_LINE_MAX ||
            !ps_run_path(plugdir, path, sizeof(path)))
            st = PLUGIN_ERR_ARGUMENT;
        else if (!ps_write_private(path, line, (size_t)n) ||
                 !plugin_fsync_dir(plugdir))
            st = PLUGIN_ERR_IO;
    }
    plugin_lock_release(&lock);
    return st;
}

enum plugin_status plugin_store_run_unregister(const char *root, const char *name,
                                               uint64_t pid)
{
    char plugdir[PLUGIN_PATH_MAX], path[PLUGIN_PATH_MAX];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    struct plugin_lock lock;
    st = plugin_lock_acquire(plugdir, &lock);
    if (st != PLUGIN_OK)
        return st;
    struct plugin_run_registration reg;
    bool found = false;
    st = ps_run_read(plugdir, &reg, &found);
    if (st == PLUGIN_OK && found && reg.pid == pid &&
        ps_run_path(plugdir, path, sizeof(path))) {
        if (unlink(path) != 0 && errno != ENOENT)
            st = PLUGIN_ERR_IO;
        else if (!plugin_fsync_dir(plugdir))
            st = PLUGIN_ERR_IO;
    }
    plugin_lock_release(&lock);
    return st;
}

enum plugin_status plugin_store_run_query(const char *root, const char *name,
                                          struct plugin_run_registration *out,
                                          bool *registered, bool *live)
{
    if (!out || !registered || !live)
        return PLUGIN_ERR_ARGUMENT;
    *registered = false;
    *live = false;
    char plugdir[PLUGIN_PATH_MAX];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    st = ps_run_read(plugdir, out, registered);
    if (st != PLUGIN_OK || !*registered)
        return st;
    switch (ps_run_liveness(out)) {
    case PS_RUN_LIVE:
        *live = true;
        break;
    case PS_RUN_UNKNOWN:
        return PLUGIN_ERR_IO;
    default:
        break;
    }
    return PLUGIN_OK;
}

/* ── uninstall ─────────────────────────────────────────────────────────── */

/* True for one of the three leaves the store writes into a generation
 * directory: NAME, NAME.plugin.json, NAME.plugin.sig. */
static bool ps_uninstall_leaf_ok(const char *name, const char *leaf)
{
    char want[PLUGIN_NAME_MAX + 16];
    if (strcmp(leaf, name) == 0)
        return true;
    snprintf(want, sizeof(want), "%s%s", name, PS_MANIFEST_SUFFIX);
    if (strcmp(leaf, want) == 0)
        return true;
    snprintf(want, sizeof(want), "%s.plugin.sig", name);
    return strcmp(leaf, want) == 0;
}

/* Preflight one generation directory: every entry must be a store-written
 * leaf. Anything else refuses before a byte is removed — uninstall names
 * exact owned files and never deletes a stranger's bytes. */
static enum plugin_status ps_uninstall_check_generation(const char *dir,
                                                        const char *name)
{
    DIR *d = opendir(dir);
    if (!d)
        return errno == ENOENT ? PLUGIN_ERR_NO_GENERATION : PLUGIN_ERR_IO;
    enum plugin_status st = PLUGIN_OK;
    struct dirent *e;
    while (st == PLUGIN_OK && (e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0 &&
            !ps_uninstall_leaf_ok(name, e->d_name))
            st = PLUGIN_ERR_UNINSTALL_LAYOUT;
    closedir(d);
    return st;
}

/* Remove exactly the store-written leaves present, then the directory. The
 * preflight ran first under the same lock, so rmdir meets no leftovers. */
static enum plugin_status ps_uninstall_drop_generation(const char *dir,
                                                       const char *name)
{
    static const char *const suffix[] = { "", PS_MANIFEST_SUFFIX, ".plugin.sig" };
    for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
        char leaf[PLUGIN_NAME_MAX + 16], path[PLUGIN_PATH_MAX];
        snprintf(leaf, sizeof(leaf), "%s%s", name, suffix[i]);
        if (!plugin_join(path, sizeof(path), dir, leaf, NULL, NULL))
            return PLUGIN_ERR_ARGUMENT;
        if (unlink(path) != 0 && errno != ENOENT)
            return PLUGIN_ERR_IO;
    }
    return rmdir(dir) == 0 ? PLUGIN_OK : PLUGIN_ERR_IO;
}

/* The plugin directory may hold only the store's own top-level entries plus
 * the runner's NAME/data directory and the supervisor's NAME/state host-call
 * directory, which uninstall never touches. The .lock file is the mutation
 * lock this call holds — store-owned, unlinked at the end. A NAME/run
 * supervisor registration is admitted by name only; the caller already parsed
 * it and proved the supervisor is gone. */
static enum plugin_status ps_uninstall_check_top(const char *plugdir)
{
    DIR *d = opendir(plugdir);
    if (!d)
        return PLUGIN_ERR_IO;
    enum plugin_status st = PLUGIN_OK;
    struct dirent *e;
    while (st == PLUGIN_OK && (e = readdir(d)) != NULL)
        if (strcmp(e->d_name, "generations") != 0 &&
            strcmp(e->d_name, "current") != 0 &&
            strcmp(e->d_name, "last-good") != 0 &&
            strcmp(e->d_name, "data") != 0 &&
            strcmp(e->d_name, "state") != 0 &&
            strcmp(e->d_name, PS_RUN_FILE) != 0 &&
            strcmp(e->d_name, PS_LOCK_FILE) != 0 &&
            strcmp(e->d_name, PS_LOCK_QUEUE) != 0 &&
            strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            st = PLUGIN_ERR_UNINSTALL_LAYOUT;
    closedir(d);
    return st;
}

/* Preflight every generation: each entry must be a 128-hex directory holding
 * only store-written leaves. A missing generations directory means zero
 * generations — a repeated whole-plugin uninstall is a no-op, not an error. */
static enum plugin_status ps_uninstall_check_generations(const char *gens,
                                                         const char *name)
{
    DIR *d = opendir(gens);
    if (!d)
        return errno == ENOENT ? PLUGIN_OK : PLUGIN_ERR_IO;
    enum plugin_status st = PLUGIN_OK;
    struct dirent *e;
    while (st == PLUGIN_OK && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char dir[PLUGIN_PATH_MAX];
        if (!plugin_hex_valid(e->d_name, PLUGIN_HEX_SHA3_512) ||
            !plugin_join(dir, sizeof(dir), gens, e->d_name, NULL, NULL))
            st = PLUGIN_ERR_UNINSTALL_LAYOUT;
        else
            st = ps_uninstall_check_generation(dir, name);
    }
    closedir(d);
    return st;
}

/* Unlink a current/last-good pointer; absence is not an error. */
static enum plugin_status ps_uninstall_pointer(const char *plugdir,
                                               const char *link, bool *cleared)
{
    char path[PLUGIN_PATH_MAX];
    if (!plugin_join(path, sizeof(path), plugdir, link, NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    *cleared = false;
    if (unlink(path) != 0)
        return errno == ENOENT ? PLUGIN_OK : PLUGIN_ERR_IO;
    *cleared = true;
    return PLUGIN_OK;
}

/* Single generation: never the current or last-good one — the operator
 * switches first, so a running or recoverable plugin never loses the bytes
 * its pointers name. */
static enum plugin_status ps_uninstall_one(const char *plugdir,
                                           const char *name,
                                           const char *generation,
                                           struct plugin_uninstall_report *report)
{
    char pointed[PLUGIN_HEX_SHA3_512 + 1];
    if ((plugin_link_generation(plugdir, "current", pointed) &&
         strcmp(pointed, generation) == 0) ||
        (plugin_link_generation(plugdir, "last-good", pointed) &&
         strcmp(pointed, generation) == 0))
        return PLUGIN_ERR_UNINSTALL_ACTIVE;
    char dir[PLUGIN_PATH_MAX];
    if (!plugin_join(dir, sizeof(dir), plugdir, "generations", generation, NULL))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_uninstall_check_generation(dir, name);
    if (st == PLUGIN_OK)
        st = ps_uninstall_drop_generation(dir, name);
    if (st == PLUGIN_OK)
        report->generations_removed = 1;
    return st;
}

/* Remove every 128-hex generation directory under gens (the preflight
 * admitted only those), then the generations directory itself. A missing
 * generations directory is the idempotent repeat: nothing to remove. */
static enum plugin_status ps_uninstall_sweep(const char *gens,
                                             const char *name,
                                             struct plugin_uninstall_report *report)
{
    DIR *d = opendir(gens);
    if (!d && errno != ENOENT)
        return PLUGIN_ERR_IO;
    enum plugin_status st = PLUGIN_OK;
    struct dirent *e;
    while (d && st == PLUGIN_OK && (e = readdir(d)) != NULL) {
        if (!plugin_hex_valid(e->d_name, PLUGIN_HEX_SHA3_512))
            continue;
        char dir[PLUGIN_PATH_MAX];
        if (!plugin_join(dir, sizeof(dir), gens, e->d_name, NULL, NULL)) {
            st = PLUGIN_ERR_ARGUMENT;
            break;
        }
        st = ps_uninstall_drop_generation(dir, name);
        if (st == PLUGIN_OK)
            report->generations_removed++;
    }
    if (d)
        closedir(d);
    if (st == PLUGIN_OK && rmdir(gens) != 0 && errno != ENOENT)
        st = PLUGIN_ERR_IO;
    return st;
}

/* Whole plugin: preflight everything, then remove every generation, both
 * pointers, the generations directory and the plugin directory. */
static enum plugin_status ps_uninstall_all(const char *plugdir,
                                           const char *name,
                                           struct plugin_uninstall_report *report)
{
    char gens[PLUGIN_PATH_MAX];
    if (!plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL))
        return PLUGIN_ERR_ARGUMENT;
    enum plugin_status st = ps_uninstall_check_top(plugdir);
    if (st == PLUGIN_OK)
        st = ps_uninstall_check_generations(gens, name);
    if (st == PLUGIN_OK)
        st = ps_uninstall_sweep(gens, name, report);
    if (st == PLUGIN_OK)
        st = ps_uninstall_pointer(plugdir, "current", &report->current_cleared);
    if (st == PLUGIN_OK)
        st = ps_uninstall_pointer(plugdir, "last-good",
                                  &report->last_good_cleared);
    /* The stale supervisor registration goes with the pointers; a live one
     * already refused the whole operation with PLUGIN_ERR_BUSY. */
    bool run_cleared;
    if (st == PLUGIN_OK)
        st = ps_uninstall_pointer(plugdir, PS_RUN_FILE, &run_cleared);
    /* The lock file goes last of the store-owned entries; a waiter on the
     * unlinked inode finds every later path gone and refuses cleanly. */
    bool lock_cleared = false, queue_cleared = false;
    if (st == PLUGIN_OK)
        st = ps_uninstall_pointer(plugdir, PS_LOCK_FILE, &lock_cleared);
    if (st == PLUGIN_OK)
        st = ps_uninstall_pointer(plugdir, PS_LOCK_QUEUE, &queue_cleared);
    /* The plugin directory goes only when nothing but store-owned entries
     * remained; a NAME/data or NAME/state directory keeps it and is reported,
     * never removed. */
    if (st == PLUGIN_OK && rmdir(plugdir) != 0) {
        if (errno == ENOTEMPTY || errno == EEXIST)
            report->state_preserved = true;
        else
            st = PLUGIN_ERR_IO;
    }
    return st;
}

enum plugin_status plugin_store_uninstall(const char *root, const char *name,
                                          const char *generation,
                                          struct plugin_uninstall_report *report)
{
    if (!report)
        return PLUGIN_ERR_ARGUMENT;
    memset(report, 0, sizeof(*report));
    if (generation && !plugin_hex_valid(generation, PLUGIN_HEX_SHA3_512))
        return PLUGIN_ERR_ARGUMENT;
    char plugdir[PLUGIN_PATH_MAX];
    enum plugin_status st = ps_plugin_dir(root, name, plugdir, sizeof(plugdir));
    if (st != PLUGIN_OK)
        return st;
    struct plugin_lock lock;
    st = plugin_lock_acquire(plugdir, &lock);
    if (st != PLUGIN_OK)
        return st;
    /* A live registered supervisor keeps every byte: stop the run first. A
     * stale registration is store-owned and removed by the whole-plugin
     * path; a malformed one refuses as a foreign entry in the read. */
    st = ps_run_gate(plugdir);
    if (st == PLUGIN_OK)
        st = generation ? ps_uninstall_one(plugdir, name, generation, report)
                        : ps_uninstall_all(plugdir, name, report);
    plugin_lock_release(&lock);
    return st;
}
