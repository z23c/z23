/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_install_bundle.c — the BOOT WIRINGS around the non-terminal install
 * engine (engine/composition/src/consensus_state_install_runtime.c). Contract in
 * config/consensus_state_install_runtime.h.
 *
 *   1b. Zero-flag cold-boot autodetect of a complete-state bundle under
 *       <datadir>/bundles/<name>.sqlite, installed BEFORE the transparent-only
 *       from-anchor path (which would leave shielded state empty → the
 *       anchor_backfill_gap wedge).
 *   1c. A durable "install-on-next-boot" request, modeled EXACTLY on the proven
 *       boot_auto_refold_* self-respawn pattern: a bounded, fsync-durable
 *       request boot consumes and runs through the same installer, then clears.
 *       This is the entry point the shielded-gap self-heal (Move 2) arms; Move 2
 *       itself is deliberately NOT wired here.
 *
 * Plus boot_select_state_source — the app_init seam composing the three booleans
 * (auto_installed_bundle / consumed_auto_refold / do_from_anchor) that select the
 * boot's state source, kept here so app_init stays a thin caller. A complete
 * install SUPERSEDES the transparent-only from-anchor reset. Fail-closed
 * everywhere; a durable marker prevents re-installing over sovereign state. */

#include "config/flysync_island.h"
#include "config/consensus_state_install_runtime.h"

#include "config/boot_internal.h"
#include "config/boot.h"                       /* app_context, boot_refold_body_span_contiguous,
                                                 * boot_load_verify_snapshot_eligible, active_chain_* */
#include "config/boot_bundle_fetch.h"          /* THE WELD: download-before-autodetect */
#include "config/boot_header_seed_import.h"    /* headers-as-artifact in-process import */
#include "config/boot_consensus_bundle_marker.h"
#include "config/rom_fetch_orphan_sweep.h"      /* once-per-boot stale-partial sweep */
#include "net/checkpoint_header_fetch.h"       /* pre-arm compiled-checkpoint capture */
#include "conditions/no_state_source.h"        /* LOUD no-state-source signage */
#include "jobs/reducer_frontier.h"             /* reducer_frontier_provable_tip_cached */
#include "storage/boot_auto_refold.h"          /* A1: consume the escalator's armed refold */
#include "storage/progress_store.h"            /* progress_store_db */
#include "util/log_macros.h"
#include "util/safe_alloc.h"                   /* zcl_malloc */
#include "validation/chainstate.h"             /* active_chain_height */
#include "validation/main_state.h"

#include "platform/private_file.h"
#include "platform/file_metadata.h"
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>

#if !defined(_WIN32)
static pthread_mutex_t g_ibr_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
static _Atomic uint64_t g_ibr_generation;
#ifdef ZCL_TESTING
static _Atomic int g_ibr_fail_flush;
void boot_install_bundle_test_fail_flush(int which) { atomic_store(&g_ibr_fail_flush, which); }
#endif

/* The durable install-on-next-boot request file (both platform arms). */
static bool ibr_path(const char *datadir, char *out, size_t n)
{
    if (!datadir || !datadir[0]) return false;
    int len = snprintf(out, n, "%s/install_bundle_request", datadir);
    return len >= 0 && (size_t)len < n;
}

#define IBR_PATH_CAP 4096
#define IBR_WIRE_CAP (2 * IBR_PATH_CAP + 512)
struct ibr_request {
    int attempts;
    char bundle[IBR_PATH_CAP];
    bool bound;
    char snapshot_sha3[65], endpoint_height[24], endpoint_hash[65];
    char manifest_root[65], history_path[IBR_PATH_CAP];
};
enum ibr_status { IBR_ABSENT, IBR_INVALID, IBR_LEGACY, IBR_BOUND };
struct ibr_cursor { const char *data; size_t len, pos; };

static bool ibr_line(struct ibr_cursor *c, char *out, size_t cap, bool *ended)
{
    size_t n = 0;
    while (c->pos < c->len && c->data[c->pos] != '\n') {
        unsigned char ch = (unsigned char)c->data[c->pos++];
        if (ch == 0 || n + 1 >= cap) return false;
        out[n++] = (char)ch;
    }
    *ended = c->pos < c->len;
    if (*ended) ++c->pos;
    out[n] = 0;
    return n != 0;
}
static bool ibr_hash(const char *s)
{
    if (strlen(s) != 64) return false;
    for (; *s; ++s)
        if (!(*s >= '0' && *s <= '9') && !(*s >= 'a' && *s <= 'f')) return false;
    return true;
}
static bool ibr_height(const char *s)
{
    if (!*s || (s[0] == '0' && s[1])) return false;
    for (const char *p = s; *p; ++p) if (*p < '0' || *p > '9') return false;
    errno = 0; char *end = NULL;
    unsigned long value = strtoul(s, &end, 10);
    return !errno && *end == 0 && value <= INT32_MAX;
}
static bool ibr_required_line(struct ibr_cursor *c, char *out, size_t cap)
{
    bool ended = false;
    return ibr_line(c, out, cap, &ended) && ended;
}
static bool ibr_hash_line(struct ibr_cursor *c, char out[65])
{
    return ibr_required_line(c, out, 65) && ibr_hash(out);
}
static bool ibr_attempts(const char *number, int *out)
{
    errno = 0; char *end = NULL;
    long value = strtol(number, &end, 10);
    if (errno || *end || end == number || value < INT_MIN || value > INT_MAX) return false;
    if (value < 0 && value != BOOT_INSTALL_BUNDLE_TERMINAL) return false;
    *out = (int)value;
    return true;
}
static enum ibr_status ibr_legacy(struct ibr_cursor *c, struct ibr_request *req)
{
    size_t len = strlen(req->bundle);
    while (len && req->bundle[len - 1] == '\r') req->bundle[--len] = 0;
    return len && c->pos == c->len ? IBR_LEGACY : IBR_INVALID;
}
static bool ibr_decode_bound(struct ibr_cursor *c, struct ibr_request *req, bool nl)
{
    if (!nl || req->bundle[0] != '/' || strchr(req->bundle, '\r')) return false;
    if (!ibr_hash_line(c, req->snapshot_sha3)) return false;
    if (!ibr_required_line(c, req->endpoint_height, sizeof(req->endpoint_height)) || !ibr_height(req->endpoint_height)) return false;
    if (!ibr_hash_line(c, req->endpoint_hash)) return false;
    if (!ibr_hash_line(c, req->manifest_root)) return false;
    if (!ibr_required_line(c, req->history_path, sizeof(req->history_path))) return false;
    return req->history_path[0] == '/' && !strchr(req->history_path, '\r') && c->pos == c->len;
}
static enum ibr_status ibr_decode(const char *wire, size_t size, struct ibr_request *req)
{
    struct ibr_cursor c = { wire, size, 0 };
    char number[32]; bool nl = false;
    if (!ibr_line(&c, number, sizeof(number), &nl) || !nl) return IBR_INVALID;
    bool bound = strcmp(number, "Z23-HISTORY-1") == 0;
    if (bound && (!ibr_line(&c, number, sizeof(number), &nl) || !nl)) return IBR_INVALID;
    if (!ibr_attempts(number, &req->attempts)) return IBR_INVALID;
    if (!ibr_line(&c, req->bundle, sizeof(req->bundle), &nl)) return IBR_INVALID;
    if (!bound) return ibr_legacy(&c, req);
    if (!ibr_decode_bound(&c, req, nl)) return IBR_INVALID;
    req->bound = true;
    return IBR_BOUND;
}
static enum ibr_status ibr_read(const char *path, struct ibr_request *req, int *read_errno)
{
    memset(req, 0, sizeof(*req));
    if (read_errno) *read_errno = 0;
    struct platform_private_file file; platform_private_file_init(&file);
    if (!platform_private_file_open_observation(path, &file)) {
        int error = errno;
        if (platform_file_shape_read(path) == PLATFORM_FILE_SHAPE_MISSING) return IBR_ABSENT;
        if (read_errno) *read_errno = error ? error : EIO;
        return IBR_INVALID;
    }
    char wire[IBR_WIRE_CAP]; uint64_t size = 0, size_after = 0;
    bool ok = platform_private_file_size(&file, &size) && size > 0 && size <= sizeof(wire) &&
        platform_private_file_read_at(&file, wire, (size_t)size, 0) &&
        platform_private_file_size(&file, &size_after) && size == size_after;
    platform_private_file_close(&file);
    if (!ok) { if (read_errno) *read_errno = EIO; return IBR_INVALID; }
    return ibr_decode(wire, (size_t)size, req);
}

bool boot_install_bundle_request_refused(const char *datadir)
{
    char path[512]; struct ibr_request req;
    enum ibr_status status = ibr_path(datadir, path, sizeof(path)) ?
        ibr_read(path, &req, NULL) : IBR_INVALID;
    if (status != IBR_INVALID && status != IBR_BOUND) return false;
    const char *reason = status == IBR_BOUND ?
        "bound install request requires a supported installer" :
        "install request is malformed or unreadable";
#if defined(_WIN32)
    fprintf(stderr, "boot: %s; refusing state-source selection\n", reason);
#else
    LOG_ERROR("boot", "%s; refusing state-source selection", reason);
#endif
    return true;
}


#if defined(_WIN32)

/* Bundle installation and activation remain fail-closed on native Windows
 * until immutable-generation staging and the installer sandbox are qualified.
 * Every exported filesystem mutation returns here before inspecting or
 * changing the install budget, bundle, datadir, or active state. */
char *boot_autodetect_consensus_bundle(const char *datadir)
{
    (void)datadir;
    return NULL;
}

void boot_auto_install_clear_failed_marker(const char *bundle_path)
{
    (void)bundle_path;
}

int boot_install_bundle_request(const char *datadir, const char *bundle_path)
{
    (void)datadir;
    (void)bundle_path;
    return 0;
}

bool boot_install_bundle_pending(const char *datadir)
{
    (void)datadir;
    return false;
}

bool boot_install_bundle_consume(const char *datadir, char *out_path,
                                 size_t out_cap)
{
    (void)datadir;
    if (out_path && out_cap) out_path[0] = '\0';
    return false;
}

void boot_install_bundle_clear(const char *datadir) { (void)datadir; }

bool boot_maybe_auto_install_consensus_bundle(struct node_db *ndb,
                                              struct main_state *ms,
                                              const char *datadir,
                                              bool trust_existing_block_files)
{
    (void)ndb;
    (void)ms;
    (void)datadir;
    (void)trust_existing_block_files;
    return false;
}

size_t boot_post_install_drop_borrowed_have_data(
    struct main_state *ms, const char *datadir, int32_t installed_height,
    bool trust_existing_block_files)
{
    (void)ms;
    (void)datadir;
    (void)installed_height;
    (void)trust_existing_block_files;
    return 0;
}

void boot_post_install_fold_span_check(struct main_state *ms,
                                       int32_t installed_height)
{
    (void)ms;
    (void)installed_height;
}

void boot_select_state_source(struct node_db *ndb, struct main_state *ms,
                              struct app_context *ctx,
                              struct boot_state_source_selection *out)
{
    (void)ndb;
    (void)ms;
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (ctx && boot_install_bundle_request_refused(ctx->datadir)) { out->refused = true; return; }
    /* Explicit operator from-anchor selection is independent of bundle
     * installation and remains available in the native refusal lane. */
    if (ctx) out->do_from_anchor = ctx->refold_from_anchor;
}

#else

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define ICB_SUBSYS "install_consensus_bundle"

/* ── 1b — Autodetect a complete-state bundle under <datadir>/bundles/ ───────── */

/* Parse the height out of a canonical "consensus-state-bundle-<N>.sqlite" name,
 * or -1 for any other *.sqlite name. Lets the freshest-selection sort NUMERICALLY
 * by height rather than lexicographically (which mis-orders un-padded heights,
 * e.g. "...-9.sqlite" > "...-3056758.sqlite"). Pure. */
static long icb_bundle_height(const char *name)
{
    static const char PFX[] = "consensus-state-bundle-";
    static const char SFX[] = ".sqlite";
    size_t pl = sizeof(PFX) - 1, sl = sizeof(SFX) - 1, nl = strlen(name);
    if (nl <= pl + sl || strncmp(name, PFX, pl) != 0 ||
        strcmp(name + nl - sl, SFX) != 0)
        return -1;
    const char *d = name + pl;
    size_t dcount = nl - pl - sl;
    if (dcount == 0 || dcount >= 19)
        return -1;
    long h = 0;
    for (size_t i = 0; i < dcount; i++) {
        if (d[i] < '0' || d[i] > '9')
            return -1;
        h = h * 10 + (d[i] - '0');
    }
    return h;
}

/* Pure ordering predicate for the freshest-selection scan: true iff the
 * candidate (nm, h) replaces the current best (best_name, best_h). */
static bool icb_candidate_beats_best(const char *nm, long h,
                                     const char *best_name, long best_h)
{
    if (best_name[0] == '\0')
        return true;
    if (h != best_h)
        return h > best_h;
    return strcmp(nm, best_name) > 0;
}

/* Scan an open bundles/ directory for the freshest installable *.sqlite name
 * into best_name (best_cap bytes; best_name[0] stays '\0' when none
 * qualifies). */
static void icb_scan_best_bundle(DIR *d, const char *dirpath, char *best_name,
                                 size_t best_cap)
{
    static const char SFX[] = ".sqlite";
    const size_t slen = sizeof(SFX) - 1;
    long best_h = -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *nm = ent->d_name;
        size_t len = strlen(nm);
        if (len <= slen || len >= best_cap)
            continue;
        if (strcmp(nm + len - slen, SFX) != 0)
            continue;
        /* Never-stuck: a prior boot that failed installing THIS bundle wrote a
         * sibling "<name>.failed" marker. Skip such a bundle so a bad /
         * incompatible / contained bundle degrades to normal boot on the next
         * (systemd Restart=always) boot instead of retrying forever — no human
         * needed to delete it. */
        char failp[PATH_MAX];
        int fpn = snprintf(failp, sizeof(failp), "%s/%s.failed", dirpath, nm);
        if (fpn > 0 && (size_t)fpn < sizeof(failp) && access(failp, F_OK) == 0)
            continue;
        /* FRESHEST wins, NUMERICALLY by parsed height (not lexicographically —
         * un-padded heights lex-mis-sort). A canonical bundle (height >= 0)
         * always beats a non-canonical *.sqlite (height -1); among canonical
         * names the higher height wins; ties / two non-canonical names break
         * lexicographically for stable determinism. */
        long h = icb_bundle_height(nm);
        if (icb_candidate_beats_best(nm, h, best_name, best_h)) {
            size_t name_len = strlen(nm);
            if (name_len >= best_cap)
                continue;
            memcpy(best_name, nm, name_len + 1);
            best_h = h;
        }
    }
}

char *boot_autodetect_consensus_bundle(const char *datadir)
{
    if (!datadir || !datadir[0])
        return NULL;

    /* Never re-install over already-sovereign state. */
    if (boot_consensus_bundle_marker_exists(datadir))
        return NULL;

    char dirpath[PATH_MAX];
    int dn = snprintf(dirpath, sizeof(dirpath), "%s/bundles", datadir);
    if (dn < 0 || (size_t)dn >= sizeof(dirpath))
        return NULL;

    DIR *d = opendir(dirpath);
    if (!d)
        return NULL; /* no bundles/ directory → nothing to auto-install */

    char best_name[256] = {0};
    icb_scan_best_bundle(d, dirpath, best_name, sizeof(best_name));
    closedir(d);

    if (best_name[0] == '\0')
        return NULL; /* no installable *.sqlite bundle present */

    char *outp = zcl_malloc(PATH_MAX, "autodetect_consensus_bundle");
    if (!outp)
        return NULL;
    int on = snprintf(outp, PATH_MAX, "%s/%s", dirpath, best_name);
    if (on < 0 || on >= PATH_MAX) {
        free(outp);
        return NULL;
    }
    return outp;
}

/* Write a sibling "<bundle_path>.failed" never-stuck marker (best-effort). */
static void csir_write_failed_marker(const char *bundle_path)
{
    char failp[PATH_MAX];
    int n = snprintf(failp, sizeof(failp), "%s.failed", bundle_path);
    if (n < 0 || (size_t)n >= sizeof(failp))
        return;
    int fd = open(failp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_WARN(ICB_SUBSYS, "could not write never-stuck marker %s: %s", failp,
                 strerror(errno));
        return;
    }
    (void)close(fd);
}

/* Clear a stale "<bundle_path>.failed" marker after the bundle installed
 * successfully: without this, an earlier failed attempt at the same path
 * (e.g. a watchdog-killed boot) permanently excludes the now-GOOD bundle
 * from autodetect on every later scan (boot_autodetect_consensus_bundle
 * skips marked bundles). Best-effort: a remove()
 * failure is loud but non-fatal, the install itself is durable.
 * Contract: config/consensus_state_install_runtime.h. */
void boot_auto_install_clear_failed_marker(const char *bundle_path)
{
    if (!bundle_path || !*bundle_path)
        return;
    char failp[PATH_MAX];
    int n = snprintf(failp, sizeof(failp), "%s.failed", bundle_path);
    if (n < 0 || (size_t)n >= sizeof(failp))
        return;
    if (remove(failp) != 0 && errno != ENOENT)
        LOG_WARN(ICB_SUBSYS, "could not clear stale never-stuck marker %s: %s",
                 failp, strerror(errno));
}

/* ── 1c — Durable "install-on-next-boot" request (mirror of boot_auto_refold_*) */

static bool ibr_flush_file(struct platform_private_file *file)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_ibr_fail_flush) == 1) return false;
#endif
    return platform_private_file_authority_flush(file);
}
static bool ibr_flush_parent(const char *datadir)
{
#ifdef ZCL_TESTING
    if (atomic_load(&g_ibr_fail_flush) == 2) return false;
#endif
    return platform_private_parent_flush(datadir);
}
static bool ibr_write(const char *datadir, const char *path,
                      const struct ibr_request *req, bool fresh)
{
    char temp[PATH_MAX], wire[2 * IBR_PATH_CAP + 512];
    int n = snprintf(temp, sizeof(temp), "%s/.install-request-XXXXXX", datadir);
    int len = req->bound ? snprintf(wire, sizeof(wire), "Z23-HISTORY-1\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n",
        req->attempts, req->bundle, req->snapshot_sha3, req->endpoint_height,
        req->endpoint_hash, req->manifest_root, req->history_path) :
        snprintf(wire, sizeof(wire), "%d\n%s\n", req->attempts, req->bundle);
    if (n < 0 || (size_t)n >= sizeof(temp) || len < 0 || (size_t)len >= sizeof(wire)) return false;
    int fd = mkstemp(temp);
    if (fd < 0) return false;
    if (close(fd) != 0) { (void)unlink(temp); return false; }
    struct platform_private_file file; platform_private_file_init(&file);
    bool exists = false;
    bool ok = platform_private_file_open_locked(temp, &file) &&
        platform_private_file_write_at(&file, wire, (size_t)len, 0) && ibr_flush_file(&file) &&
        (fresh ? platform_private_file_publish_no_clobber(&file, temp, path, &exists) && !exists :
                 platform_private_file_replace(&file, temp, path)) && ibr_flush_parent(datadir);
    platform_private_file_close(&file);
    (void)unlink(temp);
    return ok;
}

static bool ibr_bound_path(const char *s)
{
    return s && s[0] == '/' && !strchr(s, '\n') && !strchr(s, '\r') &&
           strlen(s) < IBR_PATH_CAP;
}
static void ibr_hex(char out[65], const uint8_t bytes[32])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 15];
    }
    out[64] = 0;
}
static bool ibr_bound_from_public(const struct boot_bound_bundle_request *in,
                                  struct ibr_request *out)
{
    if (!in || !out || !ibr_bound_path(in->bundle_path) ||
        !ibr_bound_path(in->private_history_path) || in->endpoint_height < 0) return false;
    memset(out, 0, sizeof(*out));
    out->bound = true;
    memcpy(out->bundle, in->bundle_path, strlen(in->bundle_path) + 1);
    memcpy(out->history_path, in->private_history_path, strlen(in->private_history_path) + 1);
    ibr_hex(out->snapshot_sha3, in->snapshot_sha3);
    ibr_hex(out->endpoint_hash, in->endpoint_hash);
    ibr_hex(out->manifest_root, in->history_manifest_root);
    snprintf(out->endpoint_height, sizeof(out->endpoint_height), "%" PRId32, in->endpoint_height);
    return true;
}
static bool ibr_bound_equal(const struct ibr_request *a, const struct ibr_request *b)
{
    return a->bound && b->bound && !strcmp(a->bundle, b->bundle) &&
        !strcmp(a->snapshot_sha3, b->snapshot_sha3) &&
        !strcmp(a->endpoint_height, b->endpoint_height) &&
        !strcmp(a->endpoint_hash, b->endpoint_hash) &&
        !strcmp(a->manifest_root, b->manifest_root) &&
        !strcmp(a->history_path, b->history_path);
}

static bool ibr_marker_missing(const char *datadir)
{
    char marker[1200];
    int n = snprintf(marker, sizeof(marker), "%s/%s", datadir, BOOT_CONSENSUS_BUNDLE_MARKER_NAME);
    return n >= 0 && (size_t)n < sizeof(marker) &&
           platform_file_shape_read(marker) == PLATFORM_FILE_SHAPE_MISSING;
}

static bool ibr_arm_path(const char *datadir, const char *bundle, char *path, size_t cap)
{
    if (!datadir || !datadir[0] || !bundle || !bundle[0] || strchr(bundle, '\n') || strchr(bundle, '\r')) return false;
    int n = snprintf(path, cap, "%s/install_bundle_request", datadir);
    return n >= 0 && (size_t)n < cap;
}

static enum boot_bundle_arm_result ibr_arm_locked(const char *datadir,
    const char *bundle_path, int *legacy)
{
    char path[512]; struct ibr_request req;
    *legacy = 0;
    if (!ibr_arm_path(datadir, bundle_path, path, sizeof(path))) return BOOT_BUNDLE_ARM_ERROR;
    enum ibr_status status = ibr_read(path, &req, NULL);
    bool have = status == IBR_LEGACY;
    int attempts = req.attempts;
    if (have && attempts == BOOT_INSTALL_BUNDLE_TERMINAL) {
        *legacy = BOOT_INSTALL_BUNDLE_TERMINAL; return BOOT_BUNDLE_ARM_TERMINAL;
    }
    if (have && attempts >= 0) {
        *legacy = attempts > 0 ? attempts : 1; return BOOT_BUNDLE_ARM_EXISTING;
    }
    if (status != IBR_ABSENT) return BOOT_BUNDLE_ARM_ERROR;
    bool fresh = true;
    memset(&req, 0, sizeof(req));
    if (snprintf(req.bundle, sizeof(req.bundle), "%s", bundle_path) >= (int)sizeof(req.bundle)) return BOOT_BUNDLE_ARM_ERROR;
    bool ok = ibr_write(datadir, path, &req, true);
    if (!ok) return BOOT_BUNDLE_ARM_ERROR;
    atomic_fetch_add(&g_ibr_generation, 1);
    *legacy = 1;
    return fresh ? BOOT_BUNDLE_ARM_CREATED : BOOT_BUNDLE_ARM_REPAIRED;
}
static enum boot_bundle_arm_result ibr_arm_platform(const char *datadir,
    const char *bundle_path, int *legacy, uint64_t *created_generation)
{
    pthread_mutex_lock(&g_ibr_lock);
    enum boot_bundle_arm_result r = ibr_arm_locked(datadir, bundle_path, legacy);
    if (created_generation) *created_generation = r == BOOT_BUNDLE_ARM_CREATED ?
        atomic_load(&g_ibr_generation) : 0;
    pthread_mutex_unlock(&g_ibr_lock);
    return r;
}
int boot_install_bundle_request(const char *datadir, const char *bundle_path)
{
    int legacy = 0;
    (void)ibr_arm_platform(datadir, bundle_path, &legacy, NULL);
    return legacy;
}

bool boot_install_bundle_pending(const char *datadir)
{
    if (!datadir)
        return false;
    char path[512];
    if (!ibr_path(datadir, path, sizeof(path))) return false;
    struct ibr_request req;
    enum ibr_status status = ibr_read(path, &req, NULL);
    if (status == IBR_ABSENT) return false;
    if ((status == IBR_LEGACY || status == IBR_BOUND) && req.attempts == BOOT_INSTALL_BUNDLE_TERMINAL)
        return false; /* terminal: present-but-not-pending */
    return true;
}

static bool ibr_consume_locked(const char *datadir, char *out_path,
                                 size_t out_cap)
{
    if (out_path && out_cap)
        out_path[0] = '\0';
    if (!datadir || !out_path || !out_cap)
        return false;

    char path[512];
    if (!ibr_path(datadir, path, sizeof(path))) return false;

    struct ibr_request req;
    if (ibr_read(path, &req, NULL) != IBR_LEGACY) return false;
    int attempts = req.attempts;
    const char *bundle = req.bundle;
    if (attempts == BOOT_INSTALL_BUNDLE_TERMINAL)
        return false; /* budget already spent */

    if (attempts >= BOOT_INSTALL_BUNDLE_MAX) {
        /* Budget exhausted: persist the terminal marker (do NOT delete — a delete
         * would let the next boot re-arm a fresh count and loop) and refuse so the
         * node boots normally + the escalator/operator sees it. */
        req.attempts = BOOT_INSTALL_BUNDLE_TERMINAL;
        (void)ibr_write(datadir, path, &req, false);
        LOG_WARN(ICB_SUBSYS,
                 "install-on-next-boot request for %s exhausted the bounded budget "
                 "(max=%d) — marking TERMINAL, booting normally", bundle,
                 BOOT_INSTALL_BUNDLE_MAX);
        return false;
    }

    if (strlen(bundle) >= out_cap)
        return false; /* caller buffer too small — fail closed */

    /* Count this boot's attempt BEFORE running the install, so a FATAL-exit mid
     * install still burns the budget. */
    req.attempts = attempts + 1;
    if (!ibr_write(datadir, path, &req, false))
        return false;
    snprintf(out_path, out_cap, "%s", bundle);
    return true;
}

bool boot_install_bundle_consume(const char *datadir, char *out_path, size_t out_cap)
{
    pthread_mutex_lock(&g_ibr_lock);
    bool ok = ibr_consume_locked(datadir, out_path, out_cap);
    atomic_fetch_add(&g_ibr_generation, 1);
    pthread_mutex_unlock(&g_ibr_lock);
    return ok;
}

void boot_install_bundle_clear(const char *datadir)
{
    if (!datadir)
        return;
    pthread_mutex_lock(&g_ibr_lock);
    char path[512];
    if (!ibr_path(datadir, path, sizeof(path))) { pthread_mutex_unlock(&g_ibr_lock); return; }
    (void)remove(path);
    atomic_fetch_add(&g_ibr_generation, 1);
    pthread_mutex_unlock(&g_ibr_lock);
}

/* Reuse boot_refold_body_span_contiguous: after a successful install, if the
 * local header chain already extends above the installed height (the Move 2
 * self-heal case on an already-synced node), NAME any body gap in the
 * fold-forward span so the reducer's body-fetch fills it rather than the fold
 * silently stalling. Non-fatal — the install is durable; this only raises the
 * typed blocker refold.body_gap so the stall is never silent. Extracted as its
 * own entry point (contract in consensus_state_install_runtime.h) so the
 * "catch the tail" wiring is directly unit-testable without a full bundle
 * install. */
void boot_post_install_fold_span_check(struct main_state *ms,
                                       int32_t installed_height)
{
    if (!ms || installed_height < 0)
        return;
    int32_t resume_target = (int32_t)active_chain_height(&ms->chain_active);
    if (resume_target <= installed_height)
        return; /* fresh install: no local advance yet — body_fetch resumes at
                  * installed_height+1 and the tail arrives via normal P2P */
    int32_t first_missing = -1;
    if (!boot_refold_body_span_contiguous(ms, installed_height, resume_target,
                                          &first_missing, /*raise_blocker=*/true))
        LOG_WARN(ICB_SUBSYS,
                 "post-install fold span (%d..%d] has a missing body at "
                 "h=%d — named blocker refold.body_gap raised; the "
                 "reducer's body-fetch fills it before the fold advances",
                 installed_height, resume_target, first_missing);
}

/* Post-install borrowed-have-data drop — contract in
 * config/consensus_state_install_runtime.h. The boot after a header-seed
 * import loads <datadir>/block_index.bin VERBATIM through the block-index
 * ladder (the header-only clamp lives only in RAM on the first-boot import
 * path, and the checkpoint_bundle_install_ready arm-and-respawn can pre-empt
 * every shutdown save), so the map can carry the bundle PUBLISHER's HAVE_DATA
 * + (nFile, nDataPos) for bodies this node never wrote, which would storm
 * read_block_pread on absent blk files. Drop each claim whose blk file is absent/unreadable
 * HERE — post-install, before the staged pipeline starts — mirroring the
 * -load-snapshot-at-own-height gate (boot_refold_staged.c), then retract the
 * active-chain tip to the installed height so P2P fills the gap bottom-up. */
size_t boot_post_install_drop_borrowed_have_data(
    struct main_state *ms, const char *datadir, int32_t installed_height,
    bool trust_existing_block_files)
{
    if (!ms || !datadir || installed_height < 0)
        return 0;
    size_t dropped = boot_snapshot_drop_bodiless_have_data_above_seed(
        ms, datadir, (int)installed_height, trust_existing_block_files);
    if (dropped == 0)
        return 0;
    /* Mirror the snapshot path's retraction: with the borrowed span cleared,
     * an active tip left at the top of that span would aim the P2P download
     * window at the gap TOP; the staged fold needs the connectable bottom
     * (installed_height+1) next. Publishes no finalized authority — the
     * staged pipeline re-publishes the served tip as it folds forward. */
    struct block_index *seed_bi =
        active_chain_at(&ms->chain_active, (int)installed_height);
    if (seed_bi && active_chain_move_window_tip(&ms->chain_active, seed_bi)) {
        LOG_INFO(ICB_SUBSYS,
                 "post-install: dropped %zu borrowed have-data claim(s) "
                 "(blocks-less bundle) — retracted the active-chain tip to "
                 "the installed height h=%d so P2P fills the gap bottom-up",
                 dropped, (int)installed_height);
    } else {
        LOG_WARN(ICB_SUBSYS,
                 "post-install: dropped %zu borrowed have-data claim(s) but "
                 "the active-tip retract to h=%d failed (seed slot %s) — "
                 "download may still target the gap top",
                 dropped, (int)installed_height,
                 seed_bi ? "present" : "NULL");
    }
    return dropped;
}

/* ── The 1b + 1c orchestrator ──────────────────────────────────────────────── */

/* (1b) Passive autodetect of a <datadir>/bundles/<name>.sqlite starter bundle.
 * Returns true iff the bundle installed; *installed_height is set then. */
static bool auto_install_detected(struct node_db *ndb, struct main_state *ms,
                                  const char *datadir,
                                  int32_t *installed_height)
{
    bool installed = false;
    char *auto_bundle = boot_autodetect_consensus_bundle(datadir);
    if (auto_bundle) {
        struct consensus_state_install_runtime_result rr;
        struct zcl_result r = boot_install_startup_bundle(
            ndb, ms, auto_bundle, datadir, &rr);
        if (r.ok) {
            installed = true;
            *installed_height = rr.height;
            boot_auto_install_clear_failed_marker(auto_bundle);
            LOG_INFO(ICB_SUBSYS, "autodetected consensus bundle installed %s "
                                 "(H*=%d)", auto_bundle, rr.hstar);
        } else if (rr.state_installed) {
            LOG_ERROR(ICB_SUBSYS,
                      "autodetected bundle %s landed durably but a "
                      "post-install step failed (%s) — retrying on the next "
                      "boot (not marked .failed: the state is on disk)",
                      auto_bundle, rr.reason);
        } else if (rr.owner_gate_refused) {
            /* The canonical-lane owner gate protects existing chain state;
             * it judges the datadir, not the bundle. Leave no .failed
             * marker so a boot with ZCL_DEPLOY_ALLOW_CANONICAL=1 finds the
             * bundle again. */
            LOG_WARN(ICB_SUBSYS,
                     "autodetected bundle %s not installed (NOT marked "
                     ".failed): %s", auto_bundle, rr.reason);
        } else if (rr.retriable_headers_not_ready) {
            /* RETRIABLE WAIT (fresh boot / mid-header-sync): the validated
             * header chain has not yet reached the checkpoint height. The
             * bundle is GOOD — the node has not caught up — so do NOT mark
             * .failed. It is re-detected on the next boot, and the
             * checkpoint_bundle_install_ready condition arms the install the
             * moment the header chain reaches the checkpoint this session. */
            LOG_INFO(ICB_SUBSYS,
                     "autodetected bundle %s deferred (NOT marked .failed): "
                     "%s", auto_bundle, rr.reason);
        } else {
            /* Genuine pre-activate refusal (bad / incompatible / contained
             * bundle): mark .failed so the next boot degrades to normal
             * behavior (never-stuck). */
            csir_write_failed_marker(auto_bundle);
            LOG_ERROR(ICB_SUBSYS,
                      "autodetected bundle %s did not install (marked .failed "
                      "→ normal boot next time): %s", auto_bundle, rr.reason);
        }
        free(auto_bundle);
    }
    return installed;
}

bool boot_maybe_auto_install_consensus_bundle(struct node_db *ndb,
                                              struct main_state *ms,
                                              const char *datadir,
                                              bool trust_existing_block_files)
{
    if (!datadir || !datadir[0])
        return false;

    /* Never re-install over already-sovereign state. */
    if (boot_consensus_bundle_marker_exists(datadir))
        return false;

    bool installed = false;
    int32_t installed_height = -1;

    /* (1c) A durable install-on-next-boot request (the Move 2 self-heal) takes
     * precedence over the passive autodetect. Consume bumps the bounded attempt
     * count so a persistently-failing bundle degrades to a normal boot instead
     * of crash-looping. */
    char req_path[PATH_MAX];
    if (boot_install_bundle_pending(datadir) &&
        boot_install_bundle_consume(datadir, req_path, sizeof(req_path))) {
        struct consensus_state_install_runtime_result rr;
        struct zcl_result r =
            boot_install_startup_bundle(ndb, ms, req_path, datadir, &rr);
        if (r.ok) {
            boot_install_bundle_clear(datadir);
            boot_auto_install_clear_failed_marker(req_path);
            installed = true;
            installed_height = rr.height;
            LOG_INFO(ICB_SUBSYS,
                     "install-on-next-boot request installed %s (H*=%d)", req_path,
                     rr.hstar);
        } else if (rr.state_installed) {
            /* Landed durably but a post-install step failed. Do NOT clear the
             * request or fall through to a wipe: the swapped state is on disk, a
             * retry re-runs activate+invalidation (idempotent), the bounded budget
             * caps retries, and the boot loader's own Sapling/coins gates are the
             * backstop. Never-silent. */
            LOG_ERROR(ICB_SUBSYS,
                      "install-on-next-boot request for %s landed durably but a "
                      "post-install step failed (%s) — retrying under the bounded "
                      "budget on the next boot", req_path, rr.reason);
        } else if (rr.retriable_headers_not_ready) {
            /* Defensive: the retry condition only arms this request once the
             * header chain has reached the checkpoint, and the header chain is
             * durable, so a consume should find headers ready. If it does not
             * (a torn/rewound header index), the bounded consume budget still
             * caps the retries — just log the wait rather than a hard error. */
            LOG_INFO(ICB_SUBSYS,
                     "install-on-next-boot request for %s deferred: %s",
                     req_path, rr.reason);
        } else {
            LOG_ERROR(ICB_SUBSYS,
                      "install-on-next-boot request for %s did not install: %s",
                      req_path, rr.reason);
        }
    }

    if (!installed)
        installed = auto_install_detected(ndb, ms, datadir, &installed_height);

    /* Post-install repair wiring — first drop any borrowed HAVE_DATA claims
     * the verbatim ladder load admitted (boot_post_install_drop_borrowed_
     * have_data), then the "catch the tail" check (see boot_post_install_fold_
     * span_check's contract above / in the header for the full rationale). */
    if (installed) {
        (void)boot_post_install_drop_borrowed_have_data(
            ms, datadir, installed_height, trust_existing_block_files);
        boot_post_install_fold_span_check(ms, installed_height);
    }

    return installed;
}

/* ── LOUD no-state-source signage helpers ──────────────────────────────────── */

/* True iff this datadir has no meaningful chain state yet — a genesis-only (or
 * empty) active-chain window, so the reducer would fold from genesis. Reads the
 * canonical active_chain_height (which consults the durable tip_finalize frontier
 * when the progress store is open), so a WARM reboot of an already-synced node
 * reports its real height and is NOT mistaken for a fresh, sourceless boot. */
static bool nss_no_meaningful_chain_state(struct main_state *ms)
{
    if (!ms)
        return true;
    return active_chain_height(&ms->chain_active) <= 0;
}

/* True iff an installable *.sqlite bundle is still staged (a deferred install is
 * a PENDING state source — checkpoint_bundle_install_ready owns that case). */
static bool nss_bundle_staged(const char *datadir)
{
    char *b = boot_autodetect_consensus_bundle(datadir);
    if (!b)
        return false;
    free(b);
    return true;
}

/* True iff a prior boot marked a staged bundle <name>.sqlite.failed. */
static bool nss_failed_bundle_present(const char *datadir)
{
    char dirpath[PATH_MAX];
    int n = snprintf(dirpath, sizeof(dirpath), "%s/bundles", datadir);
    if (n < 0 || (size_t)n >= sizeof(dirpath))
        return false;
    DIR *d = opendir(dirpath);
    if (!d)
        return false;
    static const char SFX[] = ".failed";
    const size_t slen = sizeof(SFX) - 1;
    bool found = false;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len > slen && strcmp(ent->d_name + len - slen, SFX) == 0) {
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

/* Best-effort classification of WHY no state source landed, from observable
 * datadir state (this distinguishes what the boot seam can see). */
static void nss_classify(struct app_context *ctx,
                         struct no_state_source_facts *out)
{
    memset(out, 0, sizeof(*out));

    if (!boot_bundle_fetch_should_run(ctx->datadir, ctx)) {
        /* Not eligible — opt-out (-nofilesync / ZCL_NO_BUNDLE_FETCH). */
        out->fetch = NO_STATE_SOURCE_FETCH_SKIPPED;
    } else if (boot_bundle_fetch_seed_count(ctx) == 0) {
        /* Eligible, but the seed set assembled to ZERO peers, so the fetch was
         * never ATTEMPTED. boot_bundle_fetch_should_run does not consult the
         * seed set, so without this branch a structurally-off fetch reported
         * `no_seed` — indistinguishable from "seeds were contacted and none
         * served a usable manifest", so a wiring problem does not read as a
         * network/discovery one. */
        out->fetch = NO_STATE_SOURCE_FETCH_SEEDS_EMPTY;
    } else {
        /* Eligible + attempted, but nothing installable landed. A persisted
         * <datadir>/bundles/directory.json means a manifest reached quorum but
         * the bytes did not complete; its absence means no reachable seed served
         * a usable manifest. */
        char hint[PATH_MAX];
        int hn = snprintf(hint, sizeof(hint), "%s/bundles/directory.json",
                          ctx->datadir);
        bool have_hint = hn > 0 && (size_t)hn < sizeof(hint) &&
                         access(hint, F_OK) == 0;
        out->fetch = have_hint ? NO_STATE_SOURCE_FETCH_DOWNLOAD_FAILED
                               : NO_STATE_SOURCE_FETCH_NO_SEED;
    }

    out->bundle = nss_failed_bundle_present(ctx->datadir)
                      ? NO_STATE_SOURCE_BUNDLE_FAILED
                      : NO_STATE_SOURCE_BUNDLE_NONE;
    out->baseline_hstar = reducer_frontier_provable_tip_cached();
}

/* ── The app_init selection seam ───────────────────────────────────────────── */

/* The transparent-only from-anchor predicate: an explicit operator
 * -refold-from-anchor, a consumed escalator refold, or a load-verify boot with
 * an eligible snapshot selects the from-anchor reset — unless a complete
 * install already fired. */
static bool bss_wants_from_anchor(struct node_db *ndb, struct app_context *ctx,
                                  const struct boot_state_source_selection *out)
{
    return !out->auto_installed_bundle &&
           (ctx->refold_from_anchor || out->consumed_auto_refold ||
            (ctx->load_verify_boot &&
             boot_load_verify_snapshot_eligible(ndb, progress_store_db())));
}

/* The LOUD no-state-source predicate: this boot selected NO fast-start state
 * source (no complete install, no consumed refold, no from-anchor cutover),
 * there is no staged/pending bundle and no sovereign marker, AND the datadir
 * has no meaningful chain state. */
static bool bss_no_state_source_condition(
    struct main_state *ms, struct app_context *ctx,
    const struct boot_state_source_selection *out)
{
    return !out->auto_installed_bundle && !out->consumed_auto_refold &&
           !out->do_from_anchor &&
           !boot_consensus_bundle_marker_exists(ctx->datadir) &&
           !boot_install_bundle_pending(ctx->datadir) &&
           !nss_bundle_staged(ctx->datadir) &&
           nss_no_meaningful_chain_state(ms);
}

void boot_select_state_source(struct node_db *ndb, struct main_state *ms,
                              struct app_context *ctx,
                              struct boot_state_source_selection *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctx)
        return;
    if (boot_install_bundle_request_refused(ctx->datadir)) { out->refused = true; return; }

    /* Capture the compiled checkpoint header's Equihash solution as IBD
     * headers fly past. Arming only after the height is already passed (the
     * repair condition's old path) misses the one header a new node needs.
     * Mainnet only: the compiled checkpoint is mainnet. Skip a datadir that
     * already holds sovereign installed state. */
    /* -flysync (config/flysync_island.h) walks only the rung window: no
     * keystone capture, no weld, no header-seed import below the rung. */
    const bool flysync = flysync_island_owns_state_source();
    enum flysync_recovery_result recovery = FLYSYNC_RECOVERY_NOT_APPLICABLE;
    if (!flysync && !ctx->regtest && !ctx->testnet &&
        !boot_consensus_bundle_marker_exists(ctx->datadir))
        checkpoint_header_fetch_arm_compiled();

    /* THE WELD (instant-on linchpin): on a fresh, marker-less datadir with no
     * local *.sqlite bundle, swarm-download the content-verified checkpoint
     * bundle into <datadir>/bundles/ so the autodetect below installs it under
     * the EXISTING fail-closed CHECKPOINT_ROM guards. Default-on for a fresh
     * datadir; opt out with -nofilesync or ZCL_NO_BUNDLE_FETCH=1. Best-effort +
     * fail-open: an absent manifest hint, no reachable seeder, or a failed /
     * byte-mismatched download lands nothing and leaves boot on its unchanged
     * path (P2P IBD / the operator bundle remain the fallback). Downloads bytes
     * only — it NEVER installs; the autodetect + CHECKPOINT_ROM authority is the
     * sole sovereignty gate and is not weakened here. */
    /* Discovery, not trust: arm the peer-discovered seed source FIRST so the
     * weld can reach a seeder with no operator flag at all. It reads back the
     * file_services table — the file-service endpoints peers advertised to
     * this node over the existing zfileaddr message and boot_save_file_service
     * already persisted — and offers them at LOWEST precedence behind every
     * operator-named seed, at each peer's OWN advertised port. An address is
     * all it contributes; the content verification and the CHECKPOINT_ROM
     * install authority below are untouched. Never fails boot; a first-ever
     * boot with an empty table arms nothing and behaves exactly as before. */
    /* Import the swarm-downloaded header-chain seed (block_index.bin) into the
     * header index IN-PROCESS so pindex_best_header climbs to the artifact tip
     * THIS boot — the checkpoint-bundle install below defers on the header chain
     * reaching the checkpoint, and this replaces the serial ~4.7 GB P2P header
     * crawl that otherwise gates it. Verified flat load + header-only clamp; a
     * miss is fail-open (headers still arrive via P2P). No-op unless a fresh
     * node actually downloaded the artifact above. */
    if (!flysync) {
        boot_bundle_fetch_arm_peer_seeds(ndb);
        (void)boot_bundle_fetch_maybe(ctx->datadir, ctx);
        recovery = flysync_island_recover_staged(ctx->datadir, ms);
        if (recovery == FLYSYNC_RECOVERY_NOT_APPLICABLE)
            (void)boot_header_seed_import_maybe(ctx->datadir, ms);
    }

    if (recovery != FLYSYNC_RECOVERY_NOT_APPLICABLE) return;

    /* 1b/1c — a complete-state install (durable request OR autodetected bundle)
     * SUPERSEDES the transparent-only from-anchor reset (which leaves shielded
     * state empty → the anchor_backfill_gap wedge). */
    out->auto_installed_bundle =
        boot_maybe_auto_install_consensus_bundle(ndb, ms, ctx->datadir,
                                                 !ctx->no_legacy_auto_import);

    /* A1 — consume the sticky escalator's armed refold (bumps its bounded,
     * fsync-durable attempt budget) unless a complete install already fired. */
    if (!out->auto_installed_bundle && !ctx->refold_from_anchor &&
        boot_auto_refold_pending(ctx->datadir))
        out->consumed_auto_refold = boot_auto_refold_consume(ctx->datadir);

    out->do_from_anchor = bss_wants_from_anchor(ndb, ctx, out);

    /* LOUD no-state-source signage (conditions/no_state_source.h): if this boot
     * selected NO fast-start state source (no complete install, no consumed
     * refold, no from-anchor cutover), there is no staged/pending bundle and no
     * sovereign marker, AND the datadir has no meaningful chain state, NAME the
     * real problem NOW so a run that would otherwise pin folding an empty genesis
     * datadir surfaces the cause in the first seconds via `dumpstate blocker`,
     * instead of a misleading downstream fold symptom. The node still proceeds
     * with normal from-genesis IBD; the blocker self-clears on H* climb / a
     * source landing (the no_state_source condition's witness). */
    if (bss_no_state_source_condition(ms, ctx, out)) {
        struct no_state_source_facts f;
        nss_classify(ctx, &f);
        no_state_source_raise(&f);
    }

    /* Reclaim the disk abandoned downloads left in <datadir>/bundles/. Runs
     * ONCE per boot and LAST, after every decision above has already had its
     * say: whatever this boot is fetching or installing has just touched its
     * own .part + journal, so the sweep's freshness guard exempts it without
     * needing to know anything about it. Counts only — nothing here can fail
     * a boot (config/rom_fetch_orphan_sweep.h). */
    struct rom_fetch_orphan_sweep_result sweep;
    (void)rom_fetch_orphan_sweep_run(ctx->datadir,
                                     rom_fetch_orphan_sweep_horizon_sec(),
                                     &sweep);
}

#endif /* _WIN32 */

/* One definition for both platform arms: read only the attempts line of the
 * request. Native Windows never writes a request, so it reads false there.
 * It logs nothing (the Windows acceptance build links this file without the
 * log module): *read_errno carries the errno of a request that exists but
 * cannot be opened, 0 otherwise, for the caller to log. */
bool boot_install_bundle_terminal(const char *datadir, int *read_errno)
{
    if (read_errno)
        *read_errno = 0;
    if (!datadir || !datadir[0])
        return false;
    char path[512];
    if (!ibr_path(datadir, path, sizeof(path))) { if (read_errno) *read_errno = ENAMETOOLONG; return false; }
    struct ibr_request req;
    enum ibr_status status = ibr_read(path, &req, read_errno);
    return (status == IBR_LEGACY || status == IBR_BOUND) &&
           req.attempts == BOOT_INSTALL_BUNDLE_TERMINAL;
}

enum boot_bundle_arm_result boot_install_bound_bundle_request(
    const char *datadir, const struct boot_bound_bundle_request *request,
    uint64_t *created_generation)
{
    if (created_generation) *created_generation = 0;
#if defined(_WIN32)
    (void)datadir; (void)request;
    return BOOT_BUNDLE_ARM_ERROR;
#else
    char path[512]; struct ibr_request candidate, current;
    if (!ibr_path(datadir, path, sizeof(path)) || !ibr_bound_from_public(request, &candidate))
        return BOOT_BUNDLE_ARM_ERROR;
    pthread_mutex_lock(&g_ibr_lock);
    enum ibr_status status = ibr_read(path, &current, NULL);
    enum boot_bundle_arm_result result = BOOT_BUNDLE_ARM_ERROR;
    if (!ibr_marker_missing(datadir)) {
        result = BOOT_BUNDLE_ARM_ERROR;
    } else if (status == IBR_BOUND && ibr_bound_equal(&current, &candidate)) {
        result = current.attempts == BOOT_INSTALL_BUNDLE_TERMINAL ?
            BOOT_BUNDLE_ARM_TERMINAL : BOOT_BUNDLE_ARM_EXISTING;
    } else if (status == IBR_ABSENT && ibr_write(datadir, path, &candidate, true)) {
        result = BOOT_BUNDLE_ARM_CREATED;
        uint64_t generation = atomic_fetch_add(&g_ibr_generation, 1) + 1;
        if (created_generation) *created_generation = generation;
    }
    pthread_mutex_unlock(&g_ibr_lock);
    return result;
#endif
}
bool boot_install_bound_bundle_request_matches(
    const char *datadir, const struct boot_bound_bundle_request *request,
    uint64_t *generation)
{
#if defined(_WIN32)
    (void)datadir; (void)request; (void)generation; return false;
#else
    char path[512]; struct ibr_request candidate, current;
    if (!generation || !ibr_path(datadir, path, sizeof(path)) ||
        !ibr_bound_from_public(request, &candidate)) return false;
    pthread_mutex_lock(&g_ibr_lock);
    bool ok = ibr_marker_missing(datadir) &&
        ibr_read(path, &current, NULL) == IBR_BOUND && current.attempts == 0 &&
        ibr_bound_equal(&current, &candidate);
    if (ok) *generation = atomic_load(&g_ibr_generation);
    pthread_mutex_unlock(&g_ibr_lock);
    return ok;
#endif
}
#ifdef ZCL_TESTING
bool boot_install_bound_bundle_test_rewrite(const char *datadir, int attempts)
{
#if defined(_WIN32)
    (void)datadir; (void)attempts; return false;
#else
    char path[512]; struct ibr_request request;
    if (!ibr_path(datadir, path, sizeof(path))) return false;
    pthread_mutex_lock(&g_ibr_lock);
    bool ok = ibr_read(path, &request, NULL) == IBR_BOUND;
    if (ok) {
        request.attempts = attempts;
        ok = ibr_write(datadir, path, &request, false);
        atomic_fetch_add(&g_ibr_generation, 1);
    }
    pthread_mutex_unlock(&g_ibr_lock);
    return ok;
#endif
}
#endif

enum boot_bundle_arm_result boot_install_bundle_request_typed(
    const char *datadir, const char *bundle_path, int *legacy_result, uint64_t *created_generation)
{
    int ignored = 0;
    if (!legacy_result) legacy_result = &ignored;
#if defined(_WIN32)
    (void)datadir; (void)bundle_path; *legacy_result = 0;
    if (created_generation) *created_generation = 0;
    return BOOT_BUNDLE_ARM_ERROR;
#else
    return ibr_arm_platform(datadir, bundle_path, legacy_result, created_generation);
#endif
}
uint64_t boot_install_bundle_request_generation(void)
{
    return atomic_load(&g_ibr_generation);
}
bool boot_install_bundle_request_matches(const char *datadir, const char *bundle_path,
                                         uint64_t *generation)
{
#if defined(_WIN32)
    (void)datadir; (void)bundle_path; (void)generation; return false;
#else
    if (!datadir || !bundle_path || !generation) return false;
    char path[512], marker[1200]; struct ibr_request req;
    int a = snprintf(path, sizeof(path), "%s/install_bundle_request", datadir);
    int b = snprintf(marker, sizeof(marker), "%s/%s", datadir, BOOT_CONSENSUS_BUNDLE_MARKER_NAME);
    if (a < 0 || (size_t)a >= sizeof(path) || b < 0 || (size_t)b >= sizeof(marker)) return false;
    pthread_mutex_lock(&g_ibr_lock);
    bool ok = platform_file_shape_read(marker) == PLATFORM_FILE_SHAPE_MISSING &&
        ibr_read(path, &req, NULL) == IBR_LEGACY && req.attempts == 0 &&
        strcmp(req.bundle, bundle_path) == 0;
    if (ok) *generation = atomic_load(&g_ibr_generation);
    pthread_mutex_unlock(&g_ibr_lock);
    return ok;
#endif
}
