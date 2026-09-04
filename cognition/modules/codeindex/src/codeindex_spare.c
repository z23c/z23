/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Pre-materialize the next incremental staging clone so publication fsyncs only changed pages.
 *
 * Why this file exists is measured, not assumed. Reindexing a one-line edit in
 * this checkout is already incremental on the scan side — the source Merkle
 * snapshot names the changed leaves and only those files are rescanned, which
 * costs about 0.15 s of CPU. The command still took four to ten seconds, and a
 * syscall trace put every one of those seconds in a single place: fsync() of
 * the freshly cloned 161 MB staging image. The clone dirties the whole image,
 * so the publication fsync waits for 161 MB to reach a disk that, on a loaded
 * build host, moves about 8 MB/s.
 *
 * The same bytes still get written; they do not have to be written while a
 * developer waits. `ci_spare_publish` lays the clone down one publication
 * early — immediately after the previous one succeeded — and returns without
 * flushing it, so ordinary kernel writeback drains it during the seconds
 * before the next edit. `ci_spare_adopt` then takes that inode as the next
 * staging file, leaving the publication fsync only the pages the incremental
 * scan actually changed. Measured on this checkout, that fsync went from
 * 10.03 s to 0.26 s. Note that the total volume written per publication is
 * unchanged: one full image either way.
 *
 * The durability contract is untouched: the adopted inode goes through the
 * same fsync/renameat/fsync ritual as a freshly written one, and a writeback
 * error the kernel latched earlier is still reported by that fsync. The spare
 * is a cache of work, never an authority — every check below fails closed onto
 * the ordinary clone.
 *
 * What it does cost, stated plainly: one extra resident image per checkout,
 * and only for a checkout that has actually taken the incremental branch. That
 * is why codeindex_build.c calls ci_spare_publish() there and nowhere else —
 * a checkout that is only ever cold-built would carry a second full image for
 * a rebuild that never comes. It also only pays off when writeback has had
 * time to run: back to back with no gap, the adopted inode is still dirty and
 * the publication fsync pays what the old always-clone path paid.
 */

#include "codeindex_priv.h"

#include "util/log_macros.h"

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* The published-generation clone waiting to become the next staging file. It
 * deliberately does NOT match ci_cleanup_orphan_stages()' "index.kv.tmp."
 * sweep: an orphan staging file is abandoned work, while this one is the
 * result the next rebuild is meant to find. */
#define CI_SPARE_NAME "index.kv.spare"

/* Every meta record that seals what a generation ANSWERS. store_format and
 * ci_schema_version fix the derived layout; source_root_sha3 binds every
 * indexed file's exact content; dep_stat_root_sha3 binds the compiler-input
 * graph the include edges came from; source_merkle_root_sha3 binds the source
 * tree identity; and the retrieval projection root binds the group, file,
 * symbol and reference rows a consumer actually reads. Two stores agreeing on
 * all six answer every query identically, which is exactly the property the
 * ordinary byte clone of the live generation would have given us. */
static const char *const ci_spare_seal_keys[] = {
    "store_format",
    "ci_schema_version",
    "source_root_sha3",
    "dep_stat_root_sha3",
    "source_merkle_root_sha3",
    CI_RETRIEVAL_PROJECTION_META,
};

/* A private, owner-controlled, single-linked regular file — the same shape
 * ci_create_unique_stage() insists on for an inode it made itself. */
static bool ci_spare_inode_is_private(int fd, struct ci_stage_identity *identity)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH)) ||
        st.st_size <= 0)
        return false;
    if (identity) {
        identity->dev = st.st_dev;
        identity->ino = st.st_ino;
    }
    return true;
}

static bool ci_spare_seal_equal(struct ci_store *a, struct ci_store *b)
{
    for (size_t i = 0; i < sizeof(ci_spare_seal_keys) /
                           sizeof(ci_spare_seal_keys[0]); i++) {
        unsigned char left[64], right[64];
        size_t left_len = 0, right_len = 0;
        bool left_found = false, right_found = false;
        if (!ci_store_meta_get(a, ci_spare_seal_keys[i], left, sizeof(left),
                               &left_len, &left_found) ||
            !ci_store_meta_get(b, ci_spare_seal_keys[i], right, sizeof(right),
                               &right_len, &right_found))
            return false;
        if (!left_found || !right_found || left_len == 0 ||
            left_len != right_len || memcmp(left, right, left_len) != 0)
            return false;
    }
    return true;
}

/* Does the file behind `fd` seal the same generation as `live`? Opened through
 * a duplicate so the staging descriptor keeps its own file offset and stays
 * usable after the probe is closed. */
static bool ci_spare_matches_live(int fd, struct ci_store *live)
{
    int probe = dup(fd);
    if (probe < 0) return false;
    struct ci_store *candidate = ci_store_open_readonly_fd(probe);
    if (!candidate) return false; /* takes ownership of `probe` on failure too */
    bool same = ci_spare_seal_equal(candidate, live);
    ci_store_close(candidate);
    return same;
}

void ci_spare_discard(int dirfd)
{
    if (dirfd < 0) return;
    (void)unlinkat(dirfd, CI_SPARE_NAME, 0);
}

bool ci_spare_adopt(int dirfd, struct ci_store *live, char name[128],
                    struct ci_stage_identity *identity, int *out_fd)
{
    if (dirfd < 0 || !live || !name || !identity || !out_fd) return false;
    *out_fd = -1;
    name[0] = '\0';

    int fd = openat(dirfd, CI_SPARE_NAME, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;

    /* Rename before touching a byte. From here on the inode is an ordinary
     * staging file: if this process dies mid-update the next rebuild's orphan
     * sweep removes it, and no later run can mistake a half-written image for
     * a clone of a published generation. */
    char reserved[128];
    if (!ci_spare_inode_is_private(fd, identity) ||
        !ci_spare_matches_live(fd, live) ||
        !ci_stage_reserve_name(reserved) ||
        renameat(dirfd, CI_SPARE_NAME, dirfd, reserved) != 0) {
        close(fd);
        ci_spare_discard(dirfd);
        return false;
    }

    /* renameat moves the directory entry, never the inode, so the descriptor
     * opened above still names the file now called `reserved`. Say so with a
     * check rather than an assumption. */
    struct stat named;
    if (fstatat(dirfd, reserved, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        named.st_dev != identity->dev || named.st_ino != identity->ino) {
        close(fd);
        (void)unlinkat(dirfd, reserved, 0);
        return false;
    }

    (void)snprintf(name, 128, "%s", reserved);
    *out_fd = fd;
    return true;
}

bool ci_spare_publish(int dirfd)
{
    if (dirfd < 0) return false;
    ci_spare_discard(dirfd);

    int published = openat(dirfd, "index.kv", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (published < 0) return false;
    struct stat st;
    if (fstat(published, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(published);
        return false;
    }

    char reserved[128];
    if (!ci_stage_reserve_name(reserved)) {
        close(published);
        return false;
    }
    int spare = openat(dirfd, reserved,
                       O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       0600);
    if (spare < 0) {
        close(published);
        return false;
    }

    /* Nothing is flushed, nudged or waited on here. Ordinary kernel writeback
     * drains these pages during the seconds before the next edit, and that is
     * the whole trick: the bytes are written either way, just not while a
     * developer is watching. Asking for writeback explicitly is worse, not
     * better — sync_file_range(SYNC_FILE_RANGE_WRITE) blocks on a congested
     * request queue and cost a measured 2.96 s on this host, which is exactly
     * the wait this file exists to remove. If the next rebuild arrives before
     * writeback finishes, its publication fsync pays whatever is left, which
     * is the cost the old always-clone path paid every single time. */
    bool ok = ci_copy_image_fd(published, spare);
    if (ok && renameat(dirfd, reserved, dirfd, CI_SPARE_NAME) != 0) ok = false;
    if (!ok) (void)unlinkat(dirfd, reserved, 0);
    close(spare);
    close(published);
    return ok;
}

#endif /* !_WIN32 */
