/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_fetch_orphan_sweep.c — the eviction policy for abandoned ROM downloads.
 * Contract, and the exact staleness rule, in
 * config/rom_fetch_orphan_sweep.h; not duplicated here.
 *
 * Consumes net/rom_seed.h's read-only registry to answer "does anything still
 * want this download's target?" and edits nothing under core/. One bounded
 * pass over <datadir>/bundles/, no threads, no network, no state kept between
 * calls. */
#include "config/rom_fetch_orphan_sweep.h"

#include "net/rom_fetch.h"                      /* ROM_FETCH_PART_SUFFIX      */
#include "net/rom_seed.h"                       /* rom_seed_list, ROM_SEED_*  */
#include "platform/time_compat.h"               /* platform_time_wall_time_t  */
#include "util/log_macros.h"
#include "util/safe_alloc.h"                    /* zcl_malloc                 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ROS_SUBSYS "rom_fetch_orphan_sweep"

/* The journal rom_fetch.c writes beside every staging file. */
#define ROS_JOURNAL_SUFFIX ".journal"

/* Longest `<target>.part` basename this sweep will consider. A target is
 * bounded by ROM_SEED_NAME_MAX; the slack covers the suffix and keeps the
 * fixed-size copies below obviously safe. */
#define ROS_NAME_MAX 256u

/* Runaway stop for a pathological directory, mirroring rom_seed's own bounded
 * walk. Not a routine limit: reaching it sets `capped`. */
#define ROS_SCAN_ENTRY_CAP ROM_SEED_SCAN_ENTRY_CAP

_Static_assert(ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS == ROM_SEED_MAX_ARTIFACTS,
               "sweep pair bound must track the ROM registry bound");
_Static_assert(ROS_NAME_MAX > ROM_SEED_NAME_MAX,
               "a .part basename must outrun its target's bound");

/* One candidate: a `<target>.part` that has a journal sibling. */
struct ros_pair {
    char     name[ROS_NAME_MAX]; /* the `.part` basename                     */
    uint64_t bytes;              /* `.part` + journal bytes on disk          */
    int64_t  newest_mtime;       /* the NEWER of the two mtimes (unix)       */
};

uint32_t rom_fetch_orphan_sweep_horizon_sec(void)
{
    const char *env = getenv("ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC");
    if (!env || !env[0])
        return ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT;
    char *end = NULL;
    long v = strtol(env, &end, 10);
    if (end && *end == '\0' && v > 0 && v <= (long)UINT32_MAX)
        return (uint32_t)v;
    LOG_WARN(ROS_SUBSYS,
             "ignoring invalid ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC='%s' — "
             "keeping the %u second horizon (a zero or malformed horizon "
             "would put a live download in reach of the sweep)",
             env, (unsigned)ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT);
    return ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT;
}

/* `<datadir>/bundles` into `out`. False on overflow. */
static bool ros_bundles_dir(const char *datadir, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", datadir, ROM_SEED_BUNDLES_SUBDIR);
    return n > 0 && (size_t)n < cap;
}

/* `<dirpath>/<name>` into `out`. False on overflow. */
static bool ros_join(const char *dirpath, const char *name, const char *suffix,
                     char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s%s", dirpath, name, suffix);
    return n > 0 && (size_t)n < cap;
}

/* Both halves of the pair must be regular files for this to be a pair at all.
 * Fills the summed size and the NEWER mtime — a download that is progressing
 * touches its journal after every chunk, so the newer stamp is the honest
 * "when was this last alive" answer. */
static bool ros_pair_stat(const char *dirpath, const char *part_name,
                          uint64_t *out_bytes, int64_t *out_newest)
{
    char part[PATH_MAX];
    char jrnl[PATH_MAX];
    if (!ros_join(dirpath, part_name, "", part, sizeof(part)) ||
        !ros_join(dirpath, part_name, ROS_JOURNAL_SUFFIX, jrnl, sizeof(jrnl)))
        return false;

    struct stat sp;
    struct stat sj;
    if (stat(part, &sp) != 0 || !S_ISREG(sp.st_mode))
        return false;
    if (stat(jrnl, &sj) != 0 || !S_ISREG(sj.st_mode))
        return false; /* a lone `.part` is not this sweep's shape */

    *out_bytes = (uint64_t)sp.st_size + (uint64_t)sj.st_size;
    *out_newest = (int64_t)sp.st_mtime > (int64_t)sj.st_mtime
                      ? (int64_t)sp.st_mtime
                      : (int64_t)sj.st_mtime;
    return true;
}

/* One bounded, non-recursive pass collecting every `<target>.part` that has a
 * journal sibling. Returns the pair count, or -1 when the directory cannot be
 * read at all. */
static int ros_collect_pairs(const char *dirpath, struct ros_pair *pairs,
                             bool *capped)
{
    DIR *d = opendir(dirpath);
    if (!d)
        return -1;

    static const char SFX[] = ROM_FETCH_PART_SUFFIX;
    const size_t slen = sizeof(SFX) - 1;
    int n = 0;
    uint32_t entries = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (++entries > ROS_SCAN_ENTRY_CAP) {
            *capped = true;
            break;
        }
        const char *nm = ent->d_name;
        size_t len = strlen(nm);
        if (len <= slen || len >= ROS_NAME_MAX)
            continue;
        if (strcmp(nm + len - slen, SFX) != 0)
            continue;
        if ((uint32_t)n >= ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS) {
            *capped = true;
            break;
        }
        uint64_t bytes = 0;
        int64_t newest = 0;
        if (!ros_pair_stat(dirpath, nm, &bytes, &newest))
            continue;
        memcpy(pairs[n].name, nm, len + 1);
        pairs[n].bytes = bytes;
        pairs[n].newest_mtime = newest;
        n++;
    }
    closedir(d);
    return n;
}

/* Bare basename of a registered artifact's filename — the registry stores a
 * bundles/ entry as "bundles/<name>" (rom_seed.h). */
static const char *ros_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Does any registered artifact still claim this `.part`'s target name? */
static bool ros_target_registered(const struct rom_artifact *arts, int narts,
                                  const char *target)
{
    for (int i = 0; i < narts; i++) {
        if (!arts[i].used)
            continue;
        if (strcmp(ros_basename(arts[i].filename), target) == 0)
            return true;
    }
    return false;
}

/* Remove BOTH files of a pair, or neither.
 *
 * The journal goes first on purpose: if that unlink refuses, nothing has
 * changed and the pair is still exactly the resumable state it was. Only an
 * unlink that refuses AFTER the journal is gone can leave a residue, and that
 * residue is the harmless half — a bare `.part` that the next download opens
 * O_TRUNC because there is no journal to resume from. Either failure is
 * counted and logged, never swallowed. */
static bool ros_remove_pair(const char *dirpath, const struct ros_pair *p)
{
    char part[PATH_MAX];
    char jrnl[PATH_MAX];
    if (!ros_join(dirpath, p->name, "", part, sizeof(part)) ||
        !ros_join(dirpath, p->name, ROS_JOURNAL_SUFFIX, jrnl, sizeof(jrnl)))
        return false;

    if (unlink(jrnl) != 0 && errno != ENOENT) {
        LOG_WARN(ROS_SUBSYS, "keeping '%s': its journal could not be removed "
                 "(errno=%d) — a pair is removed whole or not at all",
                 p->name, errno);
        return false;
    }
    if (unlink(part) != 0 && errno != ENOENT) {
        LOG_WARN(ROS_SUBSYS, "'%s': journal removed but the staging file "
                 "could not be (errno=%d) — the leftover file carries no "
                 "resume state and the next download truncates it",
                 p->name, errno);
        return false;
    }
    return true;
}

/* Apply the staleness rule to every collected pair. */
static void ros_apply(const char *dirpath, const struct ros_pair *pairs, int n,
                      const struct rom_artifact *arts, int narts,
                      uint32_t horizon_sec, int64_t now,
                      struct rom_fetch_orphan_sweep_result *r)
{
    const size_t slen = sizeof(ROM_FETCH_PART_SUFFIX) - 1;
    for (int i = 0; i < n; i++) {
        r->pairs_seen++;
        char target[ROS_NAME_MAX];
        size_t tlen = strlen(pairs[i].name) - slen;
        memcpy(target, pairs[i].name, tlen);
        target[tlen] = '\0';

        if (ros_target_registered(arts, narts, target)) {
            r->pairs_kept++;
            LOG_INFO(ROS_SUBSYS, "keeping '%s': '%s' is still a registered "
                     "artifact, so this download still has a target to "
                     "resume toward", pairs[i].name, target);
            continue;
        }
        int64_t age = now - pairs[i].newest_mtime;
        if (age < (int64_t)horizon_sec) {
            r->pairs_kept++;
            LOG_INFO(ROS_SUBSYS, "keeping '%s': last touched %lld s ago, "
                     "inside the %u s horizon — a download this recent may "
                     "still be running", pairs[i].name,
                     (long long)age, (unsigned)horizon_sec);
            continue;
        }
        if (!ros_remove_pair(dirpath, &pairs[i])) {
            r->pairs_failed++;
            continue;
        }
        r->pairs_removed++;
        r->bytes_reclaimed += pairs[i].bytes;
        LOG_INFO(ROS_SUBSYS, "removed '%s' and its journal (%llu bytes): "
                 "no registered artifact named '%s' and idle for %lld s, "
                 "past the %u s horizon", pairs[i].name,
                 (unsigned long long)pairs[i].bytes, target,
                 (long long)age, (unsigned)horizon_sec);
    }
}

bool rom_fetch_orphan_sweep_run(const char *datadir, uint32_t horizon_sec,
                                struct rom_fetch_orphan_sweep_result *out)
{
    struct rom_fetch_orphan_sweep_result local;
    struct rom_fetch_orphan_sweep_result *r = out ? out : &local;
    memset(r, 0, sizeof(*r));

    if (!datadir || !datadir[0])
        return false;

    char dirpath[PATH_MAX];
    if (!ros_bundles_dir(datadir, dirpath, sizeof(dirpath)))
        return false;

    /* A datadir that has never downloaded anything has no bundles/ at all.
     * That is a completed pass with nothing to do, not a failure. */
    struct stat sd;
    if (stat(dirpath, &sd) != 0 || !S_ISDIR(sd.st_mode))
        return true;

    struct ros_pair pairs[ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS];
    memset(pairs, 0, sizeof(pairs));
    int n = ros_collect_pairs(dirpath, pairs, &r->capped);
    if (n < 0) {
        LOG_WARN(ROS_SUBSYS, "skipping the sweep: '%s' could not be read "
                 "(errno=%d)", dirpath, errno);
        return false;
    }
    if (n == 0)
        return true;

    /* The registry table is large (a per-artifact chunk-digest array), so it
     * is only paid for when a candidate actually exists. */
    struct rom_artifact *arts =
        zcl_malloc(sizeof(*arts) * ROM_SEED_MAX_ARTIFACTS, "ros_registry");
    if (!arts) {
        LOG_WARN(ROS_SUBSYS, "skipping the sweep: could not read the artifact "
                 "registry, and a pair is never removed unverified");
        return false;
    }
    int narts = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    if (narts < 0)
        narts = 0;

    ros_apply(dirpath, pairs, n, arts, narts, horizon_sec,
              (int64_t)platform_time_wall_time_t(), r);
    free(arts);

    if (r->pairs_removed > 0)
        LOG_INFO(ROS_SUBSYS, "swept %s: %u orphaned pair(s) removed, %llu "
                 "bytes reclaimed, %u kept", dirpath,
                 (unsigned)r->pairs_removed,
                 (unsigned long long)r->bytes_reclaimed,
                 (unsigned)r->pairs_kept);
    return r->pairs_failed == 0;
}
