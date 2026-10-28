/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Verify a published codeindex generation from another checkout
 * against this checkout's sealed source identity and install it through the
 * rebuild path's own publication ritual. Fetched bytes are inert until the
 * sealed source_root_sha3 and source_merkle_root_sha3 match a fresh local
 * computation; install is stage-verify-rename, never a move of the image. */

#include "codeindex_priv.h"

#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_fetch.h"
#include "codeindex/codeindex_merkle.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Refusal codes are a stable contract: tests and the reply body match on
 * them. Every refusal names what failed; digests/paths ride in evidence. */
static bool fetch_refuse(struct codeindex_fetch_report *report,
                         const char *code, const char *message,
                         const char *evidence)
{
    (void)snprintf(report->code, sizeof(report->code), "%s", code);
    (void)snprintf(report->message, sizeof(report->message), "%s", message);
    (void)snprintf(report->evidence, sizeof(report->evidence), "%s",
                   evidence ? evidence : "");
    LOG_ERROR("codeindex", "fetch refused: %s: %s%s%s", code, message,
              evidence && evidence[0] ? " — " : "",
              evidence ? evidence : "");
    return false;
}

/* Resolve `--from`: a checkout root (its .codeindex/index.kv), a .codeindex
 * directory, or an index.kv file directly. Ambiguity is impossible: each form
 * has exactly one candidate that exists. */
static bool fetch_resolve_image(const char *from, char out[CI_PATH_MAX],
                                struct codeindex_fetch_report *report)
{
    struct stat st;
    if (lstat(from, &st) != 0)
        return fetch_refuse(report, "FETCH_FROM_MISSING",
                            "the fetch source does not exist", from);
    if (S_ISREG(st.st_mode)) {
        int n = snprintf(out, CI_PATH_MAX, "%s", from);
        if (n <= 0 || n >= CI_PATH_MAX)
            return fetch_refuse(report, "FETCH_FROM_MISSING",
                                "the fetch source path is too long", from);
        return true;
    }
    if (!S_ISDIR(st.st_mode))
        return fetch_refuse(report, "FETCH_FROM_MISSING",
                            "the fetch source is not a checkout root, a "
                            ".codeindex directory, or an index.kv file",
                            from);
    static const char *const suffixes[] = {
        "/.codeindex/index.kv", "/index.kv",
    };
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        int n = snprintf(out, CI_PATH_MAX, "%s%s", from, suffixes[i]);
        if (n <= 0 || n >= CI_PATH_MAX)
            return fetch_refuse(report, "FETCH_FROM_MISSING",
                                "the fetch source path is too long", from);
        struct stat cand;
        if (lstat(out, &cand) == 0 && S_ISREG(cand.st_mode))
            return true;
    }
    return fetch_refuse(report, "FETCH_FROM_MISSING",
                        "no published index.kv under the fetch source", from);
}

/* Open the image with the same owner-controlled capability discipline
 * ci_store_open applies to a canonical generation: the containing directory
 * must be owner-controlled and not group/other-writable; the file must be a
 * private regular inode (nlink 1, ours, no group/other write). */
static bool fetch_image_fd_valid(int fd, const char *image,
                                 struct codeindex_fetch_report *report)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH)) ||
        st.st_size <= 0) {
        close(fd);
        fetch_refuse(report, "FETCH_FROM_PRIVATE",
                     "the image is not a private owner-controlled store",
                     image);
        return false;
    }
    return true;
}

static int fetch_open_image(const char *image,
                            struct codeindex_fetch_report *report)
{
    char dir[CI_PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s", image);
    if (n <= 0 || (size_t)n >= sizeof(dir)) {
        fetch_refuse(report, "FETCH_FROM_MISSING",
                     "the image path is too long", image);
        return -1;
    }
    char *slash = strrchr(dir, '/');
    const char *base;
    if (slash) {
        base = slash + 1;
        if (slash == dir)
            slash[1] = '\0'; /* the directory is "/" itself */
        else
            *slash = '\0';
    } else {
        base = dir; /* a bare basename: the directory is the cwd */
    }
    int dirfd = open(slash ? dir : ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        fetch_refuse(report, "FETCH_FROM_MISSING",
                     "could not open the image's directory", image);
        return -1;
    }
    struct stat dir_st;
    if (fstat(dirfd, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
        dir_st.st_uid != geteuid() ||
        (dir_st.st_mode & (S_IWGRP | S_IWOTH))) {
        close(dirfd);
        fetch_refuse(report, "FETCH_FROM_PRIVATE",
                     "the image's directory is not owner-controlled", image);
        return -1;
    }
    int fd = openat(dirfd, base, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dirfd);
    if (fd < 0) {
        fetch_refuse(report, "FETCH_FROM_MISSING",
                     "could not open the image", image);
        return -1;
    }
    if (!fetch_image_fd_valid(fd, image, report)) return -1;
    return fd;
}

/* This checkout's own source observation: the exact content root (one bounded
 * byte pass), the location-independent Merkle root, and the local depfile
 * roots used to re-stamp freshness after content verification. */
static bool fetch_observe_local(const char *root, uint8_t source_out[32],
                                uint8_t merkle_out[32],
                                uint8_t dep_root_out[32],
                                uint8_t dep_stat_out[32],
                                struct codeindex_fetch_report *report)
{
    uint8_t stat_throwaway[32];
    if (!ci_source_roots_sha3(root, source_out, stat_throwaway))
        return fetch_refuse(report, "FETCH_LOCAL_ROOTS",
                            "could not compute this checkout's exact source "
                            "root", root);
    struct ci_merkle_cost cost = {0};
    struct ci_merkle *merkle = ci_merkle_refresh_reconciled(root, &cost);
    struct ci_merkle_node node;
    bool ok = merkle && ci_merkle_root(merkle, &node);
    if (ok) memcpy(merkle_out, node.digest.bytes, 32);
    ci_merkle_free(merkle);
    if (!ok)
        return fetch_refuse(report, "FETCH_LOCAL_ROOTS",
                            "could not compute this checkout's source Merkle "
                            "root", root);
    if (!ci_deps_scan_roots(root, NULL, NULL, dep_root_out, dep_stat_out))
        return fetch_refuse(report, "FETCH_LOCAL_ROOTS",
                            "could not compute this checkout's depfile roots",
                            root);
    return true;
}

/* Requirement: an existing FRESH local store is never overwritten. Freshness
 * is the rebuild path's own profile (source Merkle + depfile stat roots +
 * format/schema). Missing, unreadable, or damaged stores are rebuild
 * territory: they may be replaced. */
static bool fetch_local_is_fresh(const char *root, bool *fresh)
{
    *fresh = false;
    struct codeindex *existing = codeindex_open_existing(root);
    if (!existing) return true;
    bool stale = true;
    bool checked = codeindex_is_stale(existing, &stale);
    codeindex_close(existing);
    if (!checked) return true;
    *fresh = !stale;
    return true;
}

/* Copy the validated image into the private staging inode. The source is
 * re-statted after the copy: a source that moved mid-copy is refused, so the
 * verified bytes are one consistent generation. */
static bool fetch_write_chunk(int stage_fd, const unsigned char *buf,
                              ssize_t got, off_t offset,
                              struct codeindex_fetch_report *report)
{
    size_t done = 0;
    while (done < (size_t)got) {
        ssize_t put = pwrite(stage_fd, buf + done, (size_t)got - done,
                 offset + (off_t)done);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0)
            return fetch_refuse(report, "FETCH_STAGE",
                                "could not write the staging store", "");
        done += (size_t)put;
    }
    return true;
}

static bool fetch_image_unchanged(int image_fd, const struct stat *before,
                                  struct codeindex_fetch_report *report)
{
    struct stat after;
    if (fstat(image_fd, &after) != 0 || after.st_dev != before->st_dev ||
        after.st_ino != before->st_ino || after.st_size != before->st_size ||
        after.st_mtim.tv_sec != before->st_mtim.tv_sec ||
        after.st_mtim.tv_nsec != before->st_mtim.tv_nsec)
        return fetch_refuse(report, "FETCH_STAGE",
                            "the image changed while it was being copied", "");
    return true;
}

static bool fetch_copy_image(int image_fd, int stage_fd,
                             struct codeindex_fetch_report *report)
{
    enum { COPY_CHUNK_BYTES = 1024 * 1024 };
    struct stat before;
    if (fstat(image_fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size <= 0)
        return fetch_refuse(report, "FETCH_STAGE",
                            "could not inspect the image for copying", "");
    unsigned char *buf = zcl_malloc(COPY_CHUNK_BYTES,
                                    "codeindex_fetch_copy");
    if (!buf)
        return fetch_refuse(report, "FETCH_STAGE",
                            "could not allocate the image copy buffer", "");
    bool ok = true;
    off_t offset = 0;
    while (offset < before.st_size) {
        size_t want = (before.st_size - offset) < (off_t)COPY_CHUNK_BYTES
            ? (size_t)(before.st_size - offset) : COPY_CHUNK_BYTES;
        ssize_t got = pread(image_fd, buf, want, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            ok = fetch_refuse(report, "FETCH_STAGE",
                              "could not read the image for copying", "");
            break;
        }
        if (!fetch_write_chunk(stage_fd, buf, got, offset, report)) {
            ok = false;
            break;
        }
        offset += got;
    }
    free(buf);
    if (!ok) return false;
    if (ftruncate(stage_fd, before.st_size) != 0)
        return fetch_refuse(report, "FETCH_STAGE",
                            "could not size the staging store", "");
    return fetch_image_unchanged(image_fd, &before, report);
}

/* Read one exact-width meta key from the staged image. */
static bool fetch_meta(struct ci_store *image, const char *key, void *buf,
                       size_t cap, size_t *len, bool *found,
                       struct codeindex_fetch_report *report)
{
    if (!ci_store_meta_get(image, key, buf, cap, len, found))
        return fetch_refuse(report, "FETCH_IMAGE",
                            "the staged image's metadata is unreadable", key);
    return true;
}

/* Verify the STAGED copy (the bytes that would be installed): format and
 * schema tags equal this binary's constants, and both sealed source roots
 * equal this checkout's freshly computed values. */
struct fetch_metadata {
    char stored_format[64], stored_schema[64];
    size_t format_len, schema_len;
    bool format_found, schema_found;
    uint8_t image_source[32], image_merkle[32];
    size_t source_len, merkle_len;
    bool source_found, merkle_found;
    char cold_ms_text[24], cold_files_text[24];
    size_t cold_ms_len, cold_files_len;
    bool cold_ms_found, cold_files_found;

};

static bool fetch_verify_tags(struct ci_store *image, struct fetch_metadata *m,
                                struct codeindex_fetch_report *report)
{
    if (!m->format_found || m->format_len != sizeof(CI_STORE_FORMAT) - 1 ||
        memcmp(m->stored_format, CI_STORE_FORMAT, sizeof(CI_STORE_FORMAT) - 1) != 0) {
        char evidence[256];
        (void)snprintf(evidence, sizeof(evidence),
                       "store_format image=%.*s expected=%s",
                       m->format_found ? (int)m->format_len : 0,
                       m->format_found ? m->stored_format : "(absent)",
                       CI_STORE_FORMAT);
        ci_store_close(image);
        return fetch_refuse(report, "FETCH_FORMAT",
                            "the fetched store's format tag differs from this "
                            "binary's", evidence);
    }
    if (!m->schema_found || m->schema_len != sizeof(CI_SCHEMA_VERSION) - 1 ||
        memcmp(m->stored_schema, CI_SCHEMA_VERSION,
               sizeof(CI_SCHEMA_VERSION) - 1) != 0) {
        char evidence[256];
        (void)snprintf(evidence, sizeof(evidence),
                       "ci_schema_version image=%.*s expected=%s",
                       m->schema_found ? (int)m->schema_len : 0,
                       m->schema_found ? m->stored_schema : "(absent)",
                       CI_SCHEMA_VERSION);
        ci_store_close(image);
        return fetch_refuse(report, "FETCH_SCHEMA",
                            "the fetched store's schema version differs from "
                            "this binary's", evidence);
    }

    return true;
}

static bool fetch_verify_roots(struct ci_store *image, struct fetch_metadata *m,
                                const uint8_t local_source[32],
                                const uint8_t local_merkle[32],
                                struct codeindex_fetch_report *report)
{
    char image_hex[65], local_hex[65];
    if (!m->source_found || m->source_len != 32 ||
        memcmp(m->image_source, local_source, 32) != 0) {
        char evidence[256];
        if (m->source_found && m->source_len == 32) {
            zcl_hex_encode(m->image_source, 32, image_hex);
            zcl_hex_encode(local_source, 32, local_hex);
            (void)snprintf(evidence, sizeof(evidence),
                           "source_root_sha3 image=%s local=%s",
                           image_hex, local_hex);
        } else {
            (void)snprintf(evidence, sizeof(evidence),
                           "source_root_sha3 absent or malformed in the image");
        }
        ci_store_close(image);
        return fetch_refuse(report, "FETCH_SOURCE_ROOT",
                            "the fetched index describes a different source "
                            "generation than this checkout", evidence);
    }
    if (!m->merkle_found || m->merkle_len != 32 ||
        memcmp(m->image_merkle, local_merkle, 32) != 0) {
        char evidence[256];
        if (m->merkle_found && m->merkle_len == 32) {
            zcl_hex_encode(m->image_merkle, 32, image_hex);
            zcl_hex_encode(local_merkle, 32, local_hex);
            (void)snprintf(evidence, sizeof(evidence),
                           "source_merkle_root_sha3 image=%s local=%s",
                           image_hex, local_hex);
        } else {
            (void)snprintf(evidence, sizeof(evidence),
                           "source_merkle_root_sha3 absent or malformed in "
                           "the image");
        }
        ci_store_close(image);
        return fetch_refuse(report, "FETCH_MERKLE_ROOT",
                            "the fetched index's source Merkle root differs "
                            "from this checkout's", evidence);
    }

    return true;
}

static void fetch_copy_receipt(struct fetch_metadata *m,
                               struct codeindex_fetch_report *report)
{
    /* The cold-build self-receipt rides along verbatim when present and
     * well-formed; it describes the build that produced these bytes. */
    if (m->cold_ms_found && m->cold_files_found && m->cold_ms_len > 0 &&
        m->cold_files_len > 0) {
        m->cold_ms_text[m->cold_ms_len] = '\0';
        m->cold_files_text[m->cold_files_len] = '\0';
        char *end_ms = NULL, *end_files = NULL;
        long long ms = strtoll(m->cold_ms_text, &end_ms, 10);
        long long files = strtoll(m->cold_files_text, &end_files, 10);
        if (end_ms && *end_ms == '\0' && end_files && *end_files == '\0' &&
            ms >= 0 && files >= 0) {
            report->receipt_present = true;
            report->build_cold_ms = ms;
            report->build_cold_files = files;
        }
    }
}

static bool fetch_verify_staged(int stage_fd, const uint8_t local_source[32],
                                const uint8_t local_merkle[32],
                                struct codeindex_fetch_report *report)
{
    int rofd = dup(stage_fd);
    if (rofd < 0)
        return fetch_refuse(report, "FETCH_STAGE",
                            "could not duplicate the staging descriptor", "");
    struct ci_store *image = ci_store_open_readonly_fd(rofd);
    if (!image)
        return fetch_refuse(report, "FETCH_IMAGE",
                            "the staged image is not a readable codeindex "
                            "store", "");

    struct fetch_metadata m = {0};

    bool readable =
        fetch_meta(image, "store_format", m.stored_format,
                   sizeof(m.stored_format), &m.format_len, &m.format_found, report) &&
        fetch_meta(image, "ci_schema_version", m.stored_schema,
                   sizeof(m.stored_schema), &m.schema_len, &m.schema_found, report) &&
        fetch_meta(image, "source_root_sha3", m.image_source,
                   sizeof(m.image_source), &m.source_len, &m.source_found, report) &&
        fetch_meta(image, "source_merkle_root_sha3", m.image_merkle,
                   sizeof(m.image_merkle), &m.merkle_len, &m.merkle_found, report) &&
        fetch_meta(image, "build_cold_ms", m.cold_ms_text,
                   sizeof(m.cold_ms_text) - 1, &m.cold_ms_len, &m.cold_ms_found,
                   report) &&
        fetch_meta(image, "build_cold_files", m.cold_files_text,
                   sizeof(m.cold_files_text) - 1, &m.cold_files_len,
                   &m.cold_files_found, report);
    if (!readable) {
        ci_store_close(image);
        return false;
    }

    if (!fetch_verify_tags(image, &m, report)) return false;

    if (!fetch_verify_roots(image, &m, local_source, local_merkle, report)) return false;

    fetch_copy_receipt(&m, report);
    ci_store_close(image);
    return true;
}

/* Re-stamp the stat-bound depfile freshness keys to THIS checkout's
 * observation. They describe local build artifacts, not source content; the
 * sealed source roots are untouched. Without this a fresh worktree without
 * build/ would pay a full rebuild on its first open anyway. */
static bool fetch_restamp_deps(int stage_fd, const uint8_t dep_root[32],
                               const uint8_t dep_stat[32],
                               struct codeindex_fetch_report *report)
{
    struct ci_store *staging = ci_store_open_rw_fd(stage_fd);
    if (!staging)
        return fetch_refuse(report, "FETCH_RESTAMP",
                            "could not open the staging store for the local "
                            "freshness stamp", "");
    bool ok = ci_store_meta_set(staging, "dep_root_sha3", dep_root, 32) &&
              ci_store_meta_set(staging, "dep_stat_root_sha3", dep_stat, 32);
    ci_store_close(staging);
    if (!ok)
        return fetch_refuse(report, "FETCH_RESTAMP",
                            "could not re-stamp the staging store's depfile "
                            "freshness keys", "");
    return true;
}

static bool fetch_recheck_source(const char *root, const uint8_t local_merkle[32],
                                 const uint8_t local_dep_stat[32],
                                 struct codeindex_fetch_report *report)
{
    /* The tree must not have moved between verification and publication:
     * the same last-boundary recheck the rebuild path performs. */
    struct ci_merkle_cost final_cost = {0};
    struct ci_merkle *final_merkle = ci_merkle_refresh(root, &final_cost);
    struct ci_merkle_node final_root;
    uint8_t final_dep_stat[32];
    bool final_ok = final_merkle &&
        ci_merkle_root(final_merkle, &final_root) &&
        memcmp(local_merkle, final_root.digest.bytes, 32) == 0 &&
        ci_deps_stat_root_sha3(root, final_dep_stat) &&
        memcmp(local_dep_stat, final_dep_stat, 32) == 0;
    ci_merkle_free(final_merkle);
    if (!final_ok) {
        fetch_refuse(report, "FETCH_PUBLISH",
                     "the source tree changed while the fetched store was "
                     "being verified", root);
        return false;
    }

    return true;
}

static bool fetch_check_stage_identity(int stage_fd, int dirfd, const char *stage_name,
                                       const struct ci_stage_identity *identity,
                                       struct stat *stage_st,
                                       struct codeindex_fetch_report *report)
{
    struct stat stage_name_st;
    if (fstat(stage_fd, stage_st) != 0 || !S_ISREG(stage_st->st_mode) ||
        stage_st->st_nlink != 1 || stage_st->st_dev != identity->dev ||
        stage_st->st_ino != identity->ino ||
        fstatat(dirfd, stage_name, &stage_name_st,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(stage_name_st.st_mode) || stage_name_st.st_nlink != 1 ||
        stage_name_st.st_dev != stage_st->st_dev ||
        stage_name_st.st_ino != stage_st->st_ino) {
        fetch_refuse(report, "FETCH_PUBLISH",
                     "the staging inode's identity changed", "");
        return false;
    }
    return true;
}

static bool fetch_check_published(int dirfd, const struct stat *stage_st,
                                  struct codeindex_fetch_report *report)
{
    struct stat published_st;
    if (fstatat(dirfd, "index.kv", &published_st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(published_st.st_mode) || published_st.st_nlink != 1 ||
        published_st.st_uid != geteuid() ||
        (published_st.st_mode & (S_IWGRP | S_IWOTH)) ||
        published_st.st_dev != stage_st->st_dev ||
        published_st.st_ino != stage_st->st_ino) {
        fetch_refuse(report, "FETCH_PUBLISH",
                     "the published index's inode identity changed", "");
        return false;
    }
    if (fsync(dirfd) != 0 || !ci_remove_legacy_sidecars(dirfd) ||
        fsync(dirfd) != 0) {
        fetch_refuse(report, "FETCH_PUBLISH",
                     "could not make the published index durable", "");
        return false;
    }
    return true;
}

static bool fetch_publish_stage(int stage_fd, int dirfd, char *stage_name,
                                const struct stat *stage_st,
                                struct codeindex_fetch_report *report)
{
    unsigned char journal_versions[2];
    if (pread(stage_fd, journal_versions, sizeof(journal_versions), 18) !=
            (ssize_t)sizeof(journal_versions) ||
        journal_versions[0] != 1 || journal_versions[1] != 1) {
        fetch_refuse(report, "FETCH_IMAGE",
                     "the staged image is not rollback-journal format",
                     "");
        return false;
    }
    if (fsync(stage_fd) != 0) {
        fetch_refuse(report, "FETCH_PUBLISH",
                     "could not fsync the staging store", "");
        return false;
    }
    if (renameat(dirfd, stage_name, dirfd, "index.kv") != 0) {
        fetch_refuse(report, "FETCH_PUBLISH",
                     "the atomic publication rename failed", "");
        return false;
    }
    stage_name[0] = '\0';
    return fetch_check_published(dirfd, stage_st, report);
}

static bool fetch_preflight(const char *root, int image_fd,
                            uint8_t local_source[32], uint8_t local_merkle[32],
                            uint8_t local_dep_root[32], uint8_t local_dep_stat[32],
                            struct codeindex_fetch_report *report)
{
    if (!fetch_observe_local(root, local_source, local_merkle,
                             local_dep_root, local_dep_stat, report)) {
        close(image_fd);
        return false;
    }

    bool fresh = false;
    if (!fetch_local_is_fresh(root, &fresh)) {
        close(image_fd);
        return fetch_refuse(report, "FETCH_LOCAL_ROOTS",
                            "could not evaluate the local store's freshness",
                            root);
    }
    if (fresh) {
        close(image_fd);
        return fetch_refuse(report, "FETCH_FRESH",
                            "the local code index is already fresh for this "
                            "source generation; not overwriting it", root);
    }

    return true;
}

static bool fetch_locked_stage(const char *root, const char *image, int image_fd,
                               int dirfd, char stage_name[128],
                               struct ci_stage_identity *identity, int *stage_fd,
                               const uint8_t local_source[32],
                               const uint8_t local_merkle[32],
                               const uint8_t local_dep_root[32],
                               const uint8_t local_dep_stat[32],
                               struct codeindex_fetch_report *report)
{
    bool fresh = false;
    if (!ci_cleanup_orphan_stages(dirfd)) return false;

    /* A concurrent fetch may have installed while we waited on the lock;
     * re-check under the lock (the freshness pass is snapshot-cached now). */
    if (!fetch_local_is_fresh(root, &fresh)) return false;
    if (fresh) {
        fetch_refuse(report, "FETCH_FRESH",
                     "the local code index became fresh while the rebuild "
                     "lock was held", root);
        return false;
    }

    /* Fetching a store onto itself is always a no-op at best. */
    struct stat local_st, image_st;
    if (fstatat(dirfd, "index.kv", &local_st, AT_SYMLINK_NOFOLLOW) == 0 &&
        fstat(image_fd, &image_st) == 0 &&
        local_st.st_dev == image_st.st_dev &&
        local_st.st_ino == image_st.st_ino) {
        fetch_refuse(report, "FETCH_FROM_SELF",
                     "the fetch source IS this checkout's local store",
                     image);
        return false;
    }

    if (!ci_create_unique_stage(dirfd, stage_name, identity, stage_fd))
        return false;
    if (!fetch_copy_image(image_fd, *stage_fd, report)) return false;
    if (!fetch_verify_staged(*stage_fd, local_source, local_merkle, report))
        return false;
    if (!fetch_restamp_deps(*stage_fd, local_dep_root, local_dep_stat,
                            report))
        return false;
    report->dep_restamped = true;

    if (!fetch_recheck_source(root, local_merkle, local_dep_stat, report)) return false;

    struct stat stage_st;
    if (!fetch_check_stage_identity(*stage_fd, dirfd, stage_name, identity,
                                    &stage_st, report)) return false;

    if (!fetch_publish_stage(*stage_fd, dirfd, stage_name, &stage_st, report)) return false;

    close(*stage_fd);
    *stage_fd = -1;

    return true;
}

static void fetch_report_installed(const char *root,
                                   const uint8_t local_source[32],
                                   const uint8_t local_merkle[32],
                                   struct codeindex_fetch_report *report)
{
    /* Post-install observation: a plain open of the installed store must see
     * it as fresh (no rebuild pending). Reported, not enforced — a store that
     * somehow reads stale here is still exactly what the next open's normal
     * staleness path handles. */
    memcpy(report->source_root_sha3, local_source, 32);
    memcpy(report->source_merkle_root_sha3, local_merkle, 32);
    struct codeindex *post = codeindex_open_existing(root);
    if (post) {
        bool stale = true;
        if (codeindex_is_stale(post, &stale))
            report->adopted = !stale;
        codeindex_close(post);
    }
}

static bool fetch_install_posix(const char *root, const char *from,
                                struct codeindex_fetch_report *report)
{
    if (!report) return false;
    memset(report, 0, sizeof(*report));
    if (!root || !root[0] || !from || !from[0]) {
        if (report)
            fetch_refuse(report, "FETCH_ARGS",
                         "fetch needs a checkout root and a from path", "");
        return false;
    }

    char image[CI_PATH_MAX];
    if (!fetch_resolve_image(from, image, report))
        return false;
    int image_fd = fetch_open_image(image, report);
    if (image_fd < 0)
        return false;

    uint8_t local_source[32], local_merkle[32];
    uint8_t local_dep_root[32], local_dep_stat[32];
    if (!fetch_preflight(root, image_fd, local_source, local_merkle,
                         local_dep_root, local_dep_stat, report)) return false;

    /* ── the publication ritual, exactly the rebuild path's own ── */
    char dir[CI_PATH_MAX];
    int dirfd = -1, lockfd = -1;
    char stage_name[128] = "";
    struct ci_stage_identity identity = {0};
    int stage_fd = -1;
    bool installed = false;

    if (!ci_rebuild_lock_open(root, dir, &dirfd, &lockfd)) {
        close(image_fd);
        return fetch_refuse(report, "FETCH_PUBLISH",
                            "could not take the rebuild lock", root);
    }
    installed = fetch_locked_stage(root, image, image_fd, dirfd, stage_name,
                                   &identity, &stage_fd, local_source, local_merkle,
                                   local_dep_root, local_dep_stat, report);

    if (stage_fd >= 0) close(stage_fd);
    if (stage_name[0]) (void)unlinkat(dirfd, stage_name, 0);
    ci_rebuild_lock_close(dirfd, lockfd);
    close(image_fd);
    if (!installed) {
        if (!report->code[0])
            fetch_refuse(report, "FETCH_PUBLISH",
                         "the publication ritual failed", root);
        return false;
    }

    fetch_report_installed(root, local_source, local_merkle, report);
    return true;
}

#else /* _WIN32 */

static bool fetch_install_unsupported(const char *root, const char *from,
                                      struct codeindex_fetch_report *report)
{
    (void)root;
    (void)from;
    if (report) {
        memset(report, 0, sizeof(*report));
        (void)snprintf(report->code, sizeof(report->code), "%s",
                       "FETCH_UNSUPPORTED");
        (void)snprintf(report->message, sizeof(report->message), "%s",
                       "codeindex fetch is a POSIX descriptor-capability "
                       "install; the native Windows publisher does not expose "
                       "it");
    }
    return false;
}

#endif

/* One public definition above the platform split (check-arm-symbol-single):
 * dispatches to the per-arm static body. */
bool codeindex_fetch_install(const char *root, const char *from,
                             struct codeindex_fetch_report *report)
{
#if defined(_WIN32)
    return fetch_install_unsupported(root, from, report);
#else
    return fetch_install_posix(root, from, report);
#endif
}
