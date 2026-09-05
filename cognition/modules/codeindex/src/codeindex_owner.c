/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Record and read which resident process owns rebuilding one
 * checkout's code index, so a query refuses a stale answer instead of
 * rebuilding it. */

#include "codeindex_priv.h"

#include "base/hex.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

/* One line, fixed shape, written whole by the resident on every heartbeat:
 *
 *   zcl.codeindex_owner.v1 <pid> <heartbeat_unix>
 *
 * Plain text on purpose. Every reader of this marker is on a query's latency
 * path, and a reader that has to open a database to learn whether it may open
 * a database has reintroduced the cost it exists to remove. */
#define CI_OWNER_MAGIC "zcl.codeindex_owner.v1"
#define CI_OWNER_LINE_MAX 128

static _Thread_local struct codeindex_stale_refusal g_last_refusal;

static bool owner_path(const char *root, char *out, size_t cap)
{
    if (!root || !root[0] || !out) return false;
    int n = snprintf(out, cap, "%s/.codeindex/owner.v1", root);
    return n > 0 && (size_t)n < cap;
}

static bool store_path(const char *root, char *out, size_t cap)
{
    if (!root || !root[0] || !out) return false;
    int n = snprintf(out, cap, "%s/.codeindex/index.kv", root);
    return n > 0 && (size_t)n < cap;
}

long long codeindex_generation_age_s(const char *root, long long now_unix)
{
    char path[CI_PATH_MAX];
    struct stat st;
    if (!store_path(root, path, sizeof(path)) || stat(path, &st) != 0)
        return -1;
    long long age = now_unix - (long long)st.st_mtime;
    return age < 0 ? 0 : age;
}

bool codeindex_owner_claim(const char *root, long long pid,
                           long long heartbeat_unix)
{
    char path[CI_PATH_MAX];
    if (!owner_path(root, path, sizeof(path)) || pid <= 0 ||
        heartbeat_unix <= 0)
        LOG_FAIL("codeindex", "invalid owner claim");
    /* Whole-file replace: a reader must never see half a heartbeat. The line
     * is shorter than a page and a single write of it is atomic in practice
     * on every filesystem this runs on; truncate-then-write would not be. */
    char line[CI_OWNER_LINE_MAX];
    int n = snprintf(line, sizeof(line), "%s %lld %lld\n", CI_OWNER_MAGIC, pid,
                     heartbeat_unix);
    if (n <= 0 || (size_t)n >= sizeof(line))
        LOG_FAIL("codeindex", "owner claim does not fit");
    char tmp[CI_PATH_MAX], dir[CI_PATH_MAX];
    int tn = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int dn = snprintf(dir, sizeof(dir), "%s/.codeindex", root);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp) || dn <= 0 ||
        (size_t)dn >= sizeof(dir))
        LOG_FAIL("codeindex", "owner claim path too long");
    /* A checkout can be claimed before it has ever been indexed — that is
     * the ordinary first cycle, and the claim is what stops a reader
     * building the first generation underneath the owner. */
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("codeindex", "create index directory for owner marker");
    FILE *f = fopen(tmp, "wb");
    if (!f) LOG_FAIL("codeindex", "open owner marker for write");
    bool ok = fwrite(line, 1, (size_t)n, f) == (size_t)n;
    ok = fflush(f) == 0 && ok;
    ok = fclose(f) == 0 && ok;
    if (!ok || rename(tmp, path) != 0) {
        (void)remove(tmp);
        LOG_FAIL("codeindex", "publish owner marker");
    }
    return true;
}

bool codeindex_owner_read(const char *root, long long *pid_out,
                          long long *heartbeat_unix_out)
{
    if (pid_out) *pid_out = 0;
    if (heartbeat_unix_out) *heartbeat_unix_out = 0;
    char path[CI_PATH_MAX];
    if (!owner_path(root, path, sizeof(path)))
        return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char line[CI_OWNER_LINE_MAX];
    char *got = fgets(line, (int)sizeof(line), f);
    (void)fclose(f);
    if (!got) return false;
    char magic[32];
    long long pid = 0, beat = 0;
    /* A marker that does not parse is not a claim. It is never repaired here
     * and never treated as an owner: an unreadable claim must read as no
     * claim, or a corrupt byte would refuse every query on the box. */
    if (sscanf(line, "%31s %lld %lld", magic, &pid, &beat) != 3 ||
        strcmp(magic, CI_OWNER_MAGIC) != 0 || pid <= 0 || beat <= 0)
        return false;
    if (pid_out) *pid_out = pid;
    if (heartbeat_unix_out) *heartbeat_unix_out = beat;
    return true;
}

bool codeindex_owner_release(const char *root, long long pid)
{
    long long held = 0;
    if (!codeindex_owner_read(root, &held, NULL))
        return true;                       /* nothing claimed: already free */
    if (held != pid)
        return false;                      /* never drop another's claim */
    char path[CI_PATH_MAX];
    return owner_path(root, path, sizeof(path)) && remove(path) == 0;
}

bool codeindex_owner_is_live(const char *root, long long now_unix)
{
    long long beat = 0;
    if (!codeindex_owner_read(root, NULL, &beat))
        return false;
    long long age = now_unix - beat;
    if (age < 0) age = 0;                  /* clock skew is not a live claim */
    return age <= CODEINDEX_OWNER_HEARTBEAT_MAX_AGE_S;
}

void ci_owner_clear_refusal(void)
{
    memset(&g_last_refusal, 0, sizeof(g_last_refusal));
}

void ci_owner_record_refusal(struct codeindex *ci, const char *root)
{
    memset(&g_last_refusal, 0, sizeof(g_last_refusal));
    long long now = (long long)platform_time_wall_time_t();
    g_last_refusal.recorded = true;
    g_last_refusal.index_age_s = codeindex_generation_age_s(root, now);
    long long pid = 0, beat = 0;
    if (codeindex_owner_read(root, &pid, &beat)) {
        g_last_refusal.owner_present = true;
        g_last_refusal.owner_pid = pid;
        g_last_refusal.owner_heartbeat_unix = beat;
        g_last_refusal.owner_heartbeat_age_s = now - beat < 0 ? 0 : now - beat;
    }
    uint8_t root_sha3[32];
    if (ci && ci->store && codeindex_source_root_sha3(ci, root_sha3))
        zcl_hex_encode(root_sha3, sizeof(root_sha3), g_last_refusal.index_root);
}

bool codeindex_last_stale_refusal(struct codeindex_stale_refusal *out)
{
    if (!out) return false;
    *out = g_last_refusal;
    return g_last_refusal.recorded;
}

long long codeindex_generation_bytes(const char *root)
{
    char dir[CI_PATH_MAX];
    if (!root || !root[0]) return -1;
    int n = snprintf(dir, sizeof(dir), "%s/.codeindex", root);
    if (n <= 0 || (size_t)n >= sizeof(dir)) return -1;
    DIR *d = opendir(dir);
    if (!d) return -1;
    long long total = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char path[CI_PATH_MAX];
        int pn = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (pn > 0 && (size_t)pn < sizeof(path) && stat(path, &st) == 0 &&
            S_ISREG(st.st_mode))
            total += (long long)st.st_size;
    }
    (void)closedir(d);
    return total;
}
