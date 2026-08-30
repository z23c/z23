/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native transactional dev-lane activation engine — the C port of the proven
 * shell transaction in tools/dev/deploy-dev-lane.sh. See dev_activation.h.
 *
 * The whole engine is compiled only under a dev OR test build so the release
 * binary carries none of these symbols (proven by
 * tools/lint/check_release_no_dev_symbols.sh). Process exec (the real
 * systemctl/proc ops) is further confined to ZCL_DEV_BUILD.
 */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "dev_activation.h"
#include "dev_activation_internal.h"

#include "base/hex.h"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#include "crypto/sha256.h"
#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "storage/boot_auto_reindex.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

/* ── small utilities ─────────────────────────────────────────────────── */

bool dev_activation_join(char *out, size_t out_sz, const char *a, const char *b)
{
    int n = snprintf(out, out_sz, "%s/%s", a, b);
    if (n <= 0 || (size_t)n >= out_sz)
        LOG_FAIL("dev-activation", "path join overflow: %s/%s", a, b);
    return true;
}

bool dev_activation_mkdir_p(const char *path)
{
#if defined(_WIN32)
    return platform_private_directory_ensure(path);
#else
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp))
        LOG_FAIL("dev-activation", "mkdir_p bad path length");
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = 0;
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            LOG_FAIL("dev-activation", "mkdir %s: %s", tmp, strerror(errno));
        *p = '/';
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        LOG_FAIL("dev-activation", "mkdir %s: %s", tmp, strerror(errno));
    return true;
#endif
}

void dev_activation_iso_utc_now(char out[32])
{
    time_t t = platform_time_wall_time_t();
    struct tm tmv;
#if defined(_WIN32)
    if (gmtime_s(&tmv, &t) == 0)
#else
    if (gmtime_r(&t, &tmv))
#endif
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    else
        snprintf(out, 32, "1970-01-01T00:00:00Z");
}

/* Escape a string for embedding in a JSON double-quoted value. */
void dev_activation_json_escape(const char *in, char *out, size_t out_sz)
{
    size_t o = 0;
    if (out_sz == 0)
        return;
    for (const char *p = in ? in : ""; *p && o + 2 < out_sz; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '\\' || c == '"') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            if (o + 2 >= out_sz)
                break;
            out[o++] = '\\';
            out[o++] = (c == '\n') ? 'n' : (c == '\r') ? 'r' : 't';
        } else if (c < 0x20) {
            /* drop other control bytes */
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

bool dev_activation_sha256_file(const char *path, char out[65])
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        LOG_FAIL("dev-activation", "sha256 open %s failed", path);
    }
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[65536];
    uint64_t offset = 0;
    bool ok = true;
    while (offset < before.size) {
        size_t want = before.size - offset > sizeof(buf) ? sizeof(buf) :
                      (size_t)(before.size - offset);
        int64_t got = platform_positioned_file_read(&file, buf, want, offset);
        if (got <= 0) { ok = false; break; }
        sha256_write(&ctx, buf, (size_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && platform_positioned_file_snapshot(&file, &after) &&
         before.size == after.size && before.volume == after.volume &&
         before.file_low == after.file_low &&
         before.file_high == after.file_high &&
         before.modified_seconds == after.modified_seconds &&
         before.modified_nanoseconds == after.modified_nanoseconds &&
         before.changed_seconds == after.changed_seconds &&
         before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!ok)
        LOG_FAIL("dev-activation", "sha256 read %s failed", path);
    unsigned char digest[32];
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, 32, out);
    return true;
}

bool dev_activation_canon(const char *in, char *out, size_t out_sz)
{
#if defined(_WIN32)
    if (!in || !((in[0] >= 'A' && in[0] <= 'Z') ||
                 (in[0] >= 'a' && in[0] <= 'z')) ||
        in[1] != ':' || (in[2] != '/' && in[2] != '\\'))
        LOG_FAIL("dev-activation", "canon requires an absolute drive path");
#else
    if (!in || in[0] != '/')
        LOG_FAIL("dev-activation", "canon requires an absolute path");
#endif
    char *stack[256];
    size_t depth = 0;
    char work[PATH_MAX];
    size_t len = strlen(in);
    if (len >= sizeof(work))
        LOG_FAIL("dev-activation", "canon path too long");
    memcpy(work, in, len + 1);
#if defined(_WIN32)
    for (size_t i = 0; i < len; i++)
        if (work[i] == '\\') work[i] = '/';
    char drive = work[0] >= 'a' && work[0] <= 'z'
        ? (char)(work[0] - 'a' + 'A') : work[0];
    char *token_input = work + 3;
#else
    char *token_input = work;
#endif
    for (char *tok = strtok(token_input, "/"); tok; tok = strtok(NULL, "/")) {
        if (strcmp(tok, ".") == 0)
            continue;
        if (strcmp(tok, "..") == 0) {
            if (depth > 0)
                depth--;
            continue;
        }
        if (depth >= 256)
            LOG_FAIL("dev-activation", "canon depth overflow");
        stack[depth++] = tok;
    }
    size_t o = 0;
#if defined(_WIN32)
    int prefix = snprintf(out, out_sz, "%c:/", drive);
    if (prefix != 3) return false;
    o = 2;
#endif
    if (depth == 0) {
#if defined(_WIN32)
        out[3] = 0;
        return true;
#else
        if (out_sz < 2)
            LOG_FAIL("dev-activation", "canon out overflow");
        out[0] = '/';
        out[1] = 0;
        return true;
#endif
    }
    for (size_t i = 0; i < depth; i++) {
        int n = snprintf(out + o, out_sz - o, "/%s", stack[i]);
        if (n <= 0 || (size_t)n >= out_sz - o)
            LOG_FAIL("dev-activation", "canon out overflow");
        o += (size_t)n;
    }
    return true;
}

/* ── generation link helpers ─────────────────────────────────────────── */

static bool dev_valid_generation_id(const char *g)
{
    size_t n = strlen(g);
    const char *hex;
    if (strncmp(g, "gen-", 4) == 0)
        hex = g + 4;
    else if (strncmp(g, "legacy-", 7) == 0)
        hex = g + 7;
    else
        return false;
    if (strchr(g, '/'))
        return false;
    if (n == 0)
        return false;
    for (const char *p = hex; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
            return false;
    return hex[0] != 0;
}

bool dev_activation_json_first_string(const char *blob, const char *key,
                                      char *out, size_t out_sz);

bool dev_activation_read_gen_link(const struct dev_activation_txn *txn,
                                  const char *link, char *out, size_t out_sz)
{
#if defined(_WIN32)
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    uint64_t size = 0;
    char blob[256];
    if (!platform_positioned_file_open(&file, link) ||
        !platform_positioned_file_size(&file, &size) || size == 0 ||
        size >= sizeof(blob) ||
        platform_positioned_file_read(&file, blob, (size_t)size, 0) !=
            (int64_t)size) {
        platform_positioned_file_close(&file);
        return false;
    }
    platform_positioned_file_close(&file);
    blob[size] = 0;
    if (!dev_activation_json_first_string(blob, "generation", out, out_sz) ||
        !dev_valid_generation_id(out))
        return false;
    char full[PATH_MAX];
    int m = snprintf(full, sizeof(full), "%s/%s/zclassic23-dev.exe",
                     txn->gen_root, out);
    struct platform_positioned_file binary;
    platform_positioned_file_init(&binary);
    bool ok = m > 0 && (size_t)m < sizeof(full) &&
              platform_positioned_file_open(&binary, full) &&
              platform_positioned_file_is_executable(&binary);
    platform_positioned_file_close(&binary);
    return ok;
#else
    char target[PATH_MAX];
    ssize_t n = readlink(link, target, sizeof(target) - 1);
    if (n <= 0)
        return false;
    target[n] = 0;
    if (!dev_valid_generation_id(target))
        return false;
    char full[PATH_MAX];
    int m = snprintf(full, sizeof(full), "%s/%s/zclassic23-dev",
                     txn->gen_root, target);
    if (m <= 0 || (size_t)m >= sizeof(full))
        return false;
    if (access(full, X_OK) != 0)
        return false;
    n = snprintf(out, out_sz, "%s", target);
    if (n <= 0 || (size_t)n >= out_sz)
        return false;
    return true;
#endif
}

void dev_activation_refresh_gen_state(struct dev_activation_txn *txn)
{
    if (!dev_activation_read_gen_link(txn, txn->current_link,
                                      txn->current_generation,
                                      sizeof(txn->current_generation)))
        txn->current_generation[0] = 0;
    if (!dev_activation_read_gen_link(txn, txn->last_good_link,
                                      txn->last_good_generation,
                                      sizeof(txn->last_good_generation)))
        txn->last_good_generation[0] = 0;
}

bool dev_activation_link_generation(const struct dev_activation_txn *txn,
                                    const char *name, const char *generation)
{
    if (!dev_valid_generation_id(generation))
        LOG_FAIL("dev-activation", "invalid generation id: %s", generation);
    char bin[PATH_MAX];
    int m = snprintf(bin, sizeof(bin),
#if defined(_WIN32)
                     "%s/%s/zclassic23-dev.exe",
#else
                     "%s/%s/zclassic23-dev",
#endif
                     txn->gen_root, generation);
    if (m <= 0 || (size_t)m >= sizeof(bin))
        LOG_FAIL("dev-activation", "generation bin path overflow");
#if defined(_WIN32)
    struct platform_positioned_file binary;
    platform_positioned_file_init(&binary);
    bool executable = platform_positioned_file_open(&binary, bin) &&
                      platform_positioned_file_is_executable(&binary);
    platform_positioned_file_close(&binary);
    if (!executable)
#else
    if (access(bin, X_OK) != 0)
#endif
        LOG_FAIL("dev-activation", "generation binary not executable: %s", bin);
    char link[PATH_MAX], tmp[PATH_MAX];
    if (!dev_activation_join(link, sizeof(link), txn->gen_root, name))
        return false;
    int n = snprintf(tmp, sizeof(tmp), "%s/.%s.%llu",
                     txn->gen_root, name,
                     (unsigned long long)os_proc_current_pid());
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("dev-activation", "link tmp path overflow");
#if defined(_WIN32)
    char payload[160];
    int pn = snprintf(payload, sizeof(payload),
                      "{\"schema\":\"zcl.dev_generation_selection.v1\","
                      "\"generation\":\"%s\"}\n", generation);
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = pn > 0 && (size_t)pn < sizeof(payload) &&
              platform_private_file_create(tmp, &file) &&
              platform_private_file_write_at(&file, payload, (size_t)pn, 0) &&
              platform_private_file_truncate(&file, (size_t)pn) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(&file, tmp, link);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(tmp);
        LOG_FAIL("dev-activation", "generation manifest replace failed");
    }
#else
    (void)unlink(tmp);
    if (symlink(generation, tmp) != 0)
        LOG_FAIL("dev-activation", "symlink %s: %s", tmp, strerror(errno));
    if (rename(tmp, link) != 0) {
        (void)unlink(tmp);
        LOG_FAIL("dev-activation", "rename %s -> %s: %s", tmp, link,
                 strerror(errno));
    }
#endif
    return true;
}

bool dev_activation_refresh_compat_link(const struct dev_activation_txn *txn)
{
#if defined(_WIN32)
    (void)txn;
    return true; /* the stable controller resolves the current manifest */
#else
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s", txn->compat_bin);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        LOG_FAIL("dev-activation", "compat path overflow");
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        if (!dev_activation_mkdir_p(dir))
            return false;
    }
    char target[PATH_MAX], tmp[PATH_MAX];
    n = snprintf(target, sizeof(target), "%s/zclassic23-dev", txn->current_link);
    if (n <= 0 || (size_t)n >= sizeof(target))
        LOG_FAIL("dev-activation", "compat target overflow");
    n = snprintf(tmp, sizeof(tmp), "%s.next.%ld", txn->compat_bin,
                 (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("dev-activation", "compat tmp overflow");
    (void)unlink(tmp);
    if (symlink(target, tmp) != 0)
        LOG_FAIL("dev-activation", "compat symlink: %s", strerror(errno));
    if (rename(tmp, txn->compat_bin) != 0) {
        (void)unlink(tmp);
        LOG_FAIL("dev-activation", "compat rename: %s", strerror(errno));
    }
    return true;
#endif
}

/* Extract the first "key":"value" string field from a JSON blob into out. */
bool dev_activation_json_first_string(const char *blob, const char *key,
                                  char *out, size_t out_sz)
{
    char needle[96];
    int n = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (n <= 0 || (size_t)n >= sizeof(needle))
        return false;
    const char *p = strstr(blob, needle);
    if (!p)
        return false;
    p = strchr(p + strlen(needle), ':');
    if (!p)
        return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    if (*p != '"')
        return false;
    p++;
    const char *end = strchr(p, '"');
    if (!end)
        return false;
    size_t vlen = (size_t)(end - p);
    if (vlen >= out_sz)
        return false;
    memcpy(out, p, vlen);
    out[vlen] = 0;
    return true;
}

void dev_activation_generation_commit(const struct dev_activation_txn *txn,
                                      const char *generation,
                                      char *out, size_t out_sz)
{
    out[0] = 0;
    char manifest[PATH_MAX];
    int n = snprintf(manifest, sizeof(manifest), "%s/%s/manifest.json",
                     txn->gen_root, generation);
    if (n <= 0 || (size_t)n >= sizeof(manifest))
        return;
    FILE *f = fopen(manifest, "rb");
    if (!f)
        return;
    char buf[4096];
    size_t rn = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[rn] = 0;
    (void)dev_activation_json_first_string(buf, "build_commit", out, out_sz);
}

bool dev_activation_source_id_valid(const char *s)
{
    if (!s || strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    }
    return true;
}

void dev_activation_generation_source_id(
    const struct dev_activation_txn *txn, const char *generation,
    char out[65])
{
    out[0] = 0;
    char manifest[PATH_MAX];
    int n = snprintf(manifest, sizeof(manifest), "%s/%s/manifest.json",
                     txn->gen_root, generation);
    if (n <= 0 || (size_t)n >= sizeof(manifest))
        return;
    FILE *f = fopen(manifest, "rb");
    if (!f)
        return;
    char buf[4096];
    size_t rn = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[rn] = 0;
    if (!dev_activation_json_first_string(buf, "source_id_sha256", out, 65) ||
        !dev_activation_source_id_valid(out))
        out[0] = 0;
}

bool dev_activation_write_build_identity(const struct dev_activation_txn *txn,
                                         const char *generation)
{
    char source_id[65];
    dev_activation_generation_source_id(txn, generation, source_id);
    if (!source_id[0]) {
        fprintf(stderr,
                "[dev-activation] generation %s has no valid source_id_sha256; "
                "not writing runtime identity intent\n",
                generation ? generation : "(null)");
        return false;
    }
#if defined(_WIN32)
    /* The Windows supervisor resolves the exact immutable generation and its
     * source identity directly from the selected-generation manifest. */
    return true;
#else
    char commit[128];
    dev_activation_generation_commit(txn, generation, commit, sizeof(commit));
    if (commit[0] == 0)
        snprintf(commit, sizeof(commit), "unknown");
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", txn->build_id_dropin);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        if (!dev_activation_mkdir_p(dir))
            return false;
    }
    FILE *f = fopen(txn->build_id_dropin, "w");
    if (!f) {
        fprintf(stderr, "[dev-activation] build-identity drop-in open: %s\n",
                strerror(errno));
        return false;
    }
    char esc[256], esc_source_id[80];
    dev_activation_json_escape(commit, esc, sizeof(esc));
    dev_activation_json_escape(source_id, esc_source_id,
                               sizeof(esc_source_id));
    fprintf(f, "[Service]\n");
    fprintf(f, "Environment=\"ZCL_AGENT_EXPECT_SOURCE_ID=%s\"\n",
            esc_source_id);
    /* Compatibility/display metadata only. Runtime freshness decisions bind
     * exclusively to ZCL_AGENT_EXPECT_SOURCE_ID. */
    fprintf(f, "Environment=\"ZCL_AGENT_EXPECT_BUILD_COMMIT=%s\"\n", esc);
    fprintf(f, "Environment=\"ZCL_AGENT_EXPECT_BUILD_SOURCE=deploy-dev\"\n");
    if (fclose(f) != 0) {
        fprintf(stderr, "[dev-activation] build-identity drop-in close: %s\n",
                strerror(errno));
        return false;
    }
    return true;
#endif
}

/* ── confinement + path derivation ───────────────────────────────────── */

static void dev_set_status(struct dev_activation_result *r, const char *act,
                           const char *verify, const char *detail)
{
    if (act)
        snprintf(r->activation_status, sizeof(r->activation_status), "%s", act);
    if (verify)
        snprintf(r->verify_status, sizeof(r->verify_status), "%s", verify);
    if (detail)
        snprintf(r->verify_detail, sizeof(r->verify_detail), "%s", detail);
}

/* True iff canon(path) is at or under canon(root). */
static bool dev_path_under(const char *path, const char *root)
{
    char cp[PATH_MAX], cr[PATH_MAX];
    if (!dev_activation_canon(path, cp, sizeof(cp)) ||
        !dev_activation_canon(root, cr, sizeof(cr)))
        return false;
    size_t rl = strlen(cr);
    if (strncmp(cp, cr, rl) != 0)
        return false;
    return cp[rl] == 0 || cp[rl] == '/';
}

static bool dev_paths_equal(const char *a, const char *b)
{
    char ca[PATH_MAX], cb[PATH_MAX];
    if (!dev_activation_canon(a, ca, sizeof(ca)) ||
        !dev_activation_canon(b, cb, sizeof(cb)))
        return false;
    return strcmp(ca, cb) == 0;
}

/* TOP SEVERITY: refuse to touch anything but the isolated dev lane. */
static bool dev_validate_confinement(struct dev_activation_txn *txn)
{
    const struct dev_activation_request *req = txn->req;
#if defined(_WIN32)
    if (!req->gen_root || strlen(req->gen_root) < 3 || req->gen_root[1] != ':')
#else
    if (!req->gen_root || req->gen_root[0] != '/')
#endif
        LOG_FAIL("dev-activation",
                 "FATAL: generation root must be absolute: %s",
                 req->gen_root ? req->gen_root : "(null)");
    if (strstr(req->gen_root, "/../") || strstr(req->gen_root, "\n") ||
        (strlen(req->gen_root) >= 3 &&
         strcmp(req->gen_root + strlen(req->gen_root) - 3, "/..") == 0))
        LOG_FAIL("dev-activation", "FATAL: unsafe generation root: %s",
                 req->gen_root);

    char dev_dd[PATH_MAX], canonical[PATH_MAX], soak[PATH_MAX], legacy[PATH_MAX];
#if defined(_WIN32)
    if (!dev_activation_join(dev_dd, sizeof(dev_dd), txn->home, "z23/dev") ||
        !dev_activation_join(canonical, sizeof(canonical), txn->home, "z23/canonical") ||
        !dev_activation_join(soak, sizeof(soak), txn->home, "z23/soak") ||
        !dev_activation_join(legacy, sizeof(legacy), txn->home, "z23/legacy"))
#else
    if (!dev_activation_join(dev_dd, sizeof(dev_dd), txn->home, ".zclassic-c23-dev") ||
        !dev_activation_join(canonical, sizeof(canonical), txn->home, ".zclassic-c23") ||
        !dev_activation_join(soak, sizeof(soak), txn->home, ".zclassic-c23-soak") ||
        !dev_activation_join(legacy, sizeof(legacy), txn->home, ".zclassic"))
#endif
        return false;

    if (dev_path_under(req->gen_root, canonical) ||
        dev_path_under(req->gen_root, soak) ||
        dev_path_under(req->gen_root, legacy))
        LOG_FAIL("dev-activation",
                 "FATAL: generation root enters a canonical/soak/legacy datadir: %s",
                 req->gen_root);
    if (!req->unit || strcmp(req->unit, "zcl23-dev.service") != 0)
        LOG_FAIL("dev-activation", "FATAL: refusing non-dev unit: %s",
                 req->unit ? req->unit : "(null)");
    if (!req->datadir || !dev_paths_equal(req->datadir, dev_dd))
        LOG_FAIL("dev-activation", "FATAL: refusing non-dev datadir: %s",
                 req->datadir ? req->datadir : "(null)");
    if (req->rpcport != 18252)
        LOG_FAIL("dev-activation", "FATAL: refusing non-dev RPC port: %d",
                 req->rpcport);
    return true;
}

static bool dev_derive_paths(struct dev_activation_txn *txn)
{
    const struct dev_activation_request *req = txn->req;
    const char *home =
#if defined(_WIN32)
        getenv("LOCALAPPDATA");
#else
        getenv("HOME");
#endif
    if (!home || !home[0])
        LOG_FAIL("dev-activation", "HOME is unset");
    int n = snprintf(txn->home, sizeof(txn->home), "%s", home);
    if (n <= 0 || (size_t)n >= sizeof(txn->home))
        LOG_FAIL("dev-activation", "HOME too long");
    n = snprintf(txn->gen_root, sizeof(txn->gen_root), "%s", req->gen_root);
    if (n <= 0 || (size_t)n >= sizeof(txn->gen_root))
        LOG_FAIL("dev-activation", "gen_root too long");
    if (!dev_activation_join(txn->current_link, sizeof(txn->current_link),
                  txn->gen_root, "current") ||
        !dev_activation_join(txn->last_good_link, sizeof(txn->last_good_link),
                  txn->gen_root, "last-good") ||
        !dev_activation_join(txn->staged_link, sizeof(txn->staged_link),
                  txn->gen_root, "staged") ||
        !dev_activation_join(txn->rejected_dir, sizeof(txn->rejected_dir),
                  txn->gen_root, "rejected") ||
        !dev_activation_join(txn->lock_path, sizeof(txn->lock_path),
                  txn->gen_root, "activation.lock") ||
        !dev_activation_join(txn->inprogress_path, sizeof(txn->inprogress_path),
                  txn->gen_root, "activation.in_progress"))
        return false;
    n = snprintf(txn->compat_bin, sizeof(txn->compat_bin),
                 "%s/.local/bin/zclassic23-dev", txn->home);
    if (n <= 0 || (size_t)n >= sizeof(txn->compat_bin))
        LOG_FAIL("dev-activation", "compat path too long");
    n = snprintf(txn->build_id_dropin, sizeof(txn->build_id_dropin),
                 "%s/.config/systemd/user/zcl23-dev.service.d/90-build-identity.conf",
                 txn->home);
    if (n <= 0 || (size_t)n >= sizeof(txn->build_id_dropin))
        LOG_FAIL("dev-activation", "drop-in path too long");
    n = snprintf(txn->deploy_state, sizeof(txn->deploy_state),
                 "%s/agent-deploy.json", req->datadir);
    if (n <= 0 || (size_t)n >= sizeof(txn->deploy_state))
        LOG_FAIL("dev-activation", "deploy-state path too long");
    return true;
}

/* ── activation lock ─────────────────────────────────────────────────── */

static int dev_acquire_lock(struct dev_activation_txn *txn)
{
    if (!dev_activation_mkdir_p(txn->gen_root) || !dev_activation_mkdir_p(txn->rejected_dir))
        return DEV_ACTIVATION_E_INTERNAL;
    if (!platform_process_lock_try_acquire(&txn->lock, txn->lock_path, true))
        return DEV_ACTIVATION_E_LOCK_BUSY;
    txn->lock_held = true;
    return DEV_ACTIVATION_OK;
}

static void dev_release_lock(struct dev_activation_txn *txn)
{
    if (txn->lock_held)
        platform_process_lock_release(&txn->lock);
    txn->lock_held = false;
}

/* ── pending crash-only auto-reindex guard ───────────────────────────────
 *
 * Port of deploy-dev-lane.sh:guard_pending_auto_reindex(). Runs BEFORE the
 * activation lock is taken (same transaction point as the shell). If boot has
 * armed a pending crash-only auto-reindex request on the dev datadir, a native
 * activation would stop/flip/restart the service and the next boot would
 * consume the marker — silently burning one of the bounded
 * BOOT_AUTO_REINDEX_MAX crash-recovery attempts before RPC is available. We
 * refuse with a distinct code unless ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY=1.
 *
 * Missing, malformed, or TERMINAL (count == -1, operator already paged) markers
 * are NOT pending — they allow the deploy, exactly like the shell. */
static int dev_guard_pending_auto_reindex(struct dev_activation_txn *txn)
{
    struct dev_activation_result *r = txn->result;
    int32_t anchor = 0;
    int count = 0;
    if (!boot_auto_reindex_status(txn->req->datadir, &anchor, &count))
        return DEV_ACTIVATION_OK; /* no marker / malformed => allow */
    if (count == BOOT_AUTO_REINDEX_TERMINAL) {
        fprintf(stderr,
                "[dev-activation] NOTE: terminal auto-reindex marker present "
                "anchor=%d; not a pending rebuild\n", (int)anchor);
        return DEV_ACTIVATION_OK;
    }
    if (count <= 0)
        return DEV_ACTIVATION_OK; /* zero/malformed count => allow */

    const char *force = getenv("ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY");
    if (force && strcmp(force, "1") == 0) {
        txn->recovery_boot = true;
        fprintf(stderr,
                "[dev-activation] WARN: pending crash-only auto-reindex request "
                "anchor=%d count=%d; next boot may rebuild chainstate and "
                "uses the recovery readiness budget\n", (int)anchor, count);
        return DEV_ACTIVATION_OK;
    }

    dev_set_status(r, "refused", "auto_reindex_pending",
                   "pending crash-only auto-reindex request; boot would consume "
                   "the marker and rebuild chainstate before RPC is available");
    snprintf(r->failure_capsule, sizeof(r->failure_capsule),
             "pending auto-reindex anchor=%d count=%d; let recovery finish, or "
             "set ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY=1 to force this deploy",
             (int)anchor, count);
    LOG_RETURN(DEV_ACTIVATION_E_AUTO_REINDEX_PENDING, "dev-activation",
               "BLOCKED: pending crash-only auto-reindex request anchor=%d "
               "count=%d; refusing to start or hot-swap the dev lane (boot would "
               "consume the marker and rebuild chainstate before RPC). Let "
               "recovery finish, clear a proven-stale marker, or set "
               "ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY=1 to force", (int)anchor, count);
}

/* ── crash-recovery in-progress marker ───────────────────────────────────
 *
 * The shell activator arms `trap emergency_rollback EXIT` while
 * ACTIVATION_IN_PROGRESS=1 so an unexpected exit mid-flip restores the previous
 * generation. A native in-process bool cannot survive a crash of this very
 * process, so instead we persist a durable on-disk marker after the service is
 * stopped but BEFORE the `current` link is flipped to the candidate, and clear
 * it on completion OR rollback. The NEXT activation — which necessarily holds the activation
 * flock, so no live run is racing us — detects a leftover marker as a crashed
 * prior transaction and refuses, pointing the operator at `make
 * agent-dev-recover`. We deliberately do NOT auto-roll-back another run's
 * half-finished state. */
#if !defined(_WIN32)
static bool dev_write_all(int fd, const char *bytes, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t written = write(fd, bytes + off, len - off);
        if (written > 0) {
            off += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}
#endif

static bool dev_write_in_progress(struct dev_activation_txn *txn)
{
    char now[32];
    dev_activation_iso_utc_now(now);
    char esc[96];
    dev_activation_json_escape(txn->candidate_generation, esc, sizeof(esc));
    char line[256];
    int n = snprintf(line, sizeof(line),
                     "{\"schema\":\"zcl.dev_activation_in_progress.v1\","
                     "\"pid\":%llu,\"candidate_generation\":\"%s\","
                     "\"started_at_utc\":\"%s\"}\n",
                     (unsigned long long)os_proc_current_pid(), esc, now);
    if (n <= 0 || (size_t)n >= sizeof(line))
        LOG_FAIL("dev-activation", "in-progress marker payload overflow");
    size_t line_len = (size_t)n;

    char tmp[PATH_MAX];
#if defined(_WIN32)
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.%llu", txn->inprogress_path,
                 (unsigned long long)os_proc_current_pid());
#else
    /* mkstemp() below requires the path to END in exactly six X's. A pid
     * suffix makes it fail with EINVAL before it ever touches the disk,
     * so the POSIX arm keeps the template and lets mkstemp pick the
     * unique suffix itself. */
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", txn->inprogress_path);
#endif
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("dev-activation", "in-progress marker temp path overflow");
#if defined(_WIN32)
    struct platform_private_file file;
    platform_private_file_init(&file);
    bool ok = platform_private_file_create(tmp, &file) &&
              platform_private_file_write_at(&file, line, line_len, 0) &&
              platform_private_file_truncate(&file, line_len) &&
              platform_private_file_flush(&file) &&
              platform_private_file_replace(
                  &file, tmp, txn->inprogress_path);
    if (!ok) {
        platform_private_file_close(&file);
        (void)platform_private_file_unlink_missing_ok(tmp);
        return false;
    }
#else
    int fd = mkstemp(tmp);
    if (fd < 0) {
        LOG_WARN("dev-activation", "in-progress marker create %s: %s",
                 tmp, strerror(errno));
        return false;
    }
    bool ok = fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 &&
              fchmod(fd, 0644) == 0 &&
              dev_write_all(fd, line, line_len) &&
              fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp, txn->inprogress_path) != 0)
        ok = false;
    if (!ok) {
        LOG_WARN("dev-activation", "in-progress marker publish %s: %s",
                 txn->inprogress_path, strerror(errno));
        (void)unlink(tmp);
        (void)unlink(txn->inprogress_path);
        return false;
    }

    int dfd = open(txn->gen_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool dir_ok = dfd >= 0;
    if (dir_ok && fsync(dfd) != 0)
        dir_ok = false;
    if (dfd >= 0 && close(dfd) != 0)
        dir_ok = false;
    if (!dir_ok) {
        LOG_WARN("dev-activation", "in-progress marker directory fsync: %s",
                 strerror(errno));
        (void)unlink(txn->inprogress_path);
        return false;
    }
#endif
    txn->activation_in_progress = true;
    return true;
}

void dev_activation_clear_in_progress(const struct dev_activation_txn *txn)
{
    (void)platform_private_file_unlink_missing_ok(txn->inprogress_path);
}

/* With the activation flock held, a surviving in-progress marker can only come
 * from a prior activation that died mid-transaction. Refuse and point at the
 * recovery command; never touch the mixed on-disk state. */
static int dev_check_stale_in_progress(struct dev_activation_txn *txn)
{
    struct platform_positioned_file marker;
    platform_positioned_file_init(&marker);
    if (!platform_positioned_file_open(&marker, txn->inprogress_path))
        return DEV_ACTIVATION_OK; /* no marker => clean */

    char buf[256] = {0};
#if defined(_WIN32)
    uint64_t marker_size = 0;
    if (platform_positioned_file_size(&marker, &marker_size) &&
        marker_size < sizeof(buf))
        (void)platform_positioned_file_read(
            &marker, buf, (size_t)marker_size, 0);
    platform_positioned_file_close(&marker);
#else
    platform_positioned_file_close(&marker);
    FILE *f = fopen(txn->inprogress_path, "r");
    if (f) {
        size_t rn = fread(buf, 1, sizeof(buf) - 1, f);
        buf[rn] = 0;
        fclose(f);
    }
#endif
    char stale_gen[96] = {0};
    (void)dev_activation_json_first_string(buf, "candidate_generation", stale_gen,
                                           sizeof(stale_gen));

    struct dev_activation_result *r = txn->result;
    dev_set_status(r, "refused", "activation_in_progress",
                   "a prior activation crashed mid-transaction; run "
                   "`make agent-dev-recover` to reconcile before retrying");
    snprintf(r->failure_capsule, sizeof(r->failure_capsule),
             "stale in-progress marker%s%s from a dead activation; the lane may "
             "be mixed — run `make agent-dev-recover`",
             stale_gen[0] ? " candidate=" : "", stale_gen);
    (void)dev_activation_write_deploy_state(txn);
    LOG_RETURN(DEV_ACTIVATION_E_STALE_IN_PROGRESS, "dev-activation",
               "REFUSED: stale activation-in-progress marker %s (%s) from a "
               "crashed prior activation; the dev lane may be in a mixed state — "
               "run `make agent-dev-recover` to reconcile. Not auto-rolling back.",
               txn->inprogress_path, buf[0] ? buf : "(empty)");
}

/* ── the activation transaction ──────────────────────────────────────── */

static void dev_mark_failed(struct dev_activation_result *r)
{
    if (strcmp(r->rollback_status, "verified") == 0)
        snprintf(r->activation_status, sizeof(r->activation_status),
                 "rolled_back");
    else
        snprintf(r->activation_status, sizeof(r->activation_status), "failed");
}

/* Perform the stop/flip/start/verify transaction for the already-staged
 * txn->candidate_generation. Assumes lock held, preflight passed. */
static int dev_activate_candidate(struct dev_activation_txn *txn)
{
    struct dev_activation_result *r = txn->result;
    const struct dev_activation_ops *ops = txn->ops;
    char reason[256];

    dev_activation_refresh_gen_state(txn);
    snprintf(txn->previous_generation, sizeof(txn->previous_generation), "%s",
             txn->current_generation);
    if (txn->previous_generation[0] != 0)
        (void)dev_activation_link_generation(txn, "last-good",
                                             txn->previous_generation);

    if (ops->service_prepare && ops->service_prepare(ops->ctx) != 0) {
        dev_set_status(r, "prepare_failed", "activation_failed",
                       "could not install the exact dev unit before activation");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "dev unit preparation failed; generation links and running "
                 "process untouched");
        return DEV_ACTIVATION_E_ACTIVATE;
    }

    if (ops->service_stop(ops->ctx) != 0) {
        dev_set_status(r, "stop_failed", "activation_failed",
                       "could not stop the unit within the bounded stop window");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "candidate stop failed");
        (void)ops->service_start(ops->ctx);
        return DEV_ACTIVATION_E_ACTIVATE;
    }

    /* Arm crash recovery before the first namespace mutation. If durable
     * intent cannot be recorded, restart the untouched prior generation. */
    if (!dev_write_in_progress(txn)) {
        int restart_rc = ops->service_start(ops->ctx);
        dev_set_status(r, "failed", "activation_failed",
                       "could not durably record activation intent");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "activation marker write failed; prior service restart %s",
                 restart_rc == 0 ? "succeeded" : "failed");
        return DEV_ACTIVATION_E_ACTIVATE;
    }

    if (!dev_activation_link_generation(txn, "current",
                                        txn->candidate_generation)) {
        int restart_rc = ops->service_start(ops->ctx);
        txn->activation_in_progress = false;
        dev_activation_clear_in_progress(txn);
        dev_set_status(r, "failed", "activation_failed",
                       "could not flip the current generation symlink");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "current generation flip failed; prior service restart %s",
                 restart_rc == 0 ? "succeeded" : "failed");
        return DEV_ACTIVATION_E_ACTIVATE;
    }
    (void)dev_activation_refresh_compat_link(txn);
    if (!dev_activation_write_build_identity(
            txn, txn->candidate_generation)) {
        snprintf(reason, sizeof(reason),
                 "could not bind candidate source identity intent");
        (void)dev_activation_rollback_previous(txn, reason);
        dev_mark_failed(r);
        dev_set_status(r, NULL, "activation_failed", reason);
        return DEV_ACTIVATION_E_ACTIVATE;
    }
    if (ops->service_daemon_reload(ops->ctx) != 0) {
        snprintf(reason, sizeof(reason), "daemon-reload failed mid-activation");
        dev_activation_quarantine(txn, reason);
        (void)dev_activation_rollback_previous(txn, reason);
        dev_mark_failed(r);
        dev_set_status(r, NULL, "activation_failed", reason);
        return DEV_ACTIVATION_E_ACTIVATE;
    }

    if (ops->service_start(ops->ctx) != 0) {
        snprintf(reason, sizeof(reason), "candidate service start failed");
        dev_activation_quarantine(txn, reason);
        (void)dev_activation_rollback_previous(txn, reason);
        dev_mark_failed(r);
        dev_set_status(r, NULL, "activation_failed", reason);
        return DEV_ACTIVATION_E_ACTIVATE;
    }

    if (!dev_activation_verify_running(txn, txn->candidate_generation)) {
        snprintf(reason, sizeof(reason),
                 "candidate failed bounded readiness or /proc identity");
        dev_activation_quarantine(txn, reason);
        (void)dev_activation_rollback_previous(txn, reason);
        dev_mark_failed(r);
        dev_set_status(r, NULL, "activation_failed", reason);
        return DEV_ACTIVATION_E_ACTIVATE;
    }

    (void)dev_activation_link_generation(txn, "last-good",
                                         txn->candidate_generation);
    (void)platform_private_file_unlink_missing_ok(txn->staged_link);
    txn->activation_in_progress = false;
    dev_activation_clear_in_progress(txn);
    dev_set_status(r, "active", "ready",
                   "exact candidate generation is active and verified");
    snprintf(r->rollback_status, sizeof(r->rollback_status), "not_needed");
    return DEV_ACTIVATION_OK;
}

/* Shared body: with the lock held and paths derived, run stage/preflight/
 * activate. `already_staged` skips staging (activate_generation revert hook). */
static int dev_run_locked(struct dev_activation_txn *txn, bool already_staged)
{
    struct dev_activation_result *r = txn->result;
    const struct dev_activation_ops *ops = txn->ops;

    /* With the flock held, a leftover in-progress marker is a crashed prior
     * run — refuse before touching anything (no stage, no stop/flip). */
    int stale = dev_check_stale_in_progress(txn);
    if (stale != DEV_ACTIVATION_OK)
        return stale;

    /* The plan half binds the exact resident epoch it observed.  Check it
     * only after acquiring the same lock that protects the flip, otherwise a
     * concurrent activation could pass a pre-lock comparison and be lost. */
    if (txn->req->expected_current_generation) {
        dev_activation_refresh_gen_state(txn);
        if (strcmp(txn->current_generation,
                   txn->req->expected_current_generation) != 0) {
            dev_set_status(r, "superseded", "resident_epoch_superseded",
                           "resident generation changed after planning; "
                           "running generation untouched");
            snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                     "resident generation compare-and-swap refused publication");
            (void)dev_activation_write_deploy_state(txn);
            return DEV_ACTIVATION_E_PREFLIGHT;
        }
    }

    if (!already_staged) {
        int st = dev_activation_stage_candidate(txn);
        if (st != DEV_ACTIVATION_OK) {
            dev_set_status(r, "stage_failed", "stage_failed",
                           "candidate staging failed");
            snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                     "candidate staging failed");
            (void)dev_activation_write_deploy_state(txn);
            return st;
        }
    }
    dev_activation_ensure_rollback(txn);

    dev_set_status(r, "preflighting", "preflighting",
                   "candidate staged; running process untouched");
    (void)dev_activation_write_deploy_state(txn);

    char source_id[65];
    dev_activation_generation_source_id(
        txn, txn->candidate_generation, source_id);
    if (!source_id[0] || strcmp(source_id, txn->req->source_identity) != 0) {
        dev_set_status(r, "preflight_failed", "source_identity_mismatch",
                       "generation source_id_sha256 does not match the "
                       "requested source epoch");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "generation source_id_sha256 mismatch");
        (void)dev_activation_write_deploy_state(txn);
        return DEV_ACTIVATION_E_PREFLIGHT;
    }
    if (ops->preflight(ops->ctx, txn->candidate_bin, source_id) != 0) {
        dev_set_status(r, "preflight_failed", "preflight_failed",
                       "candidate preflight failed");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "candidate preflight failed");
        dev_activation_quarantine(txn, "candidate preflight failed");
        (void)dev_activation_write_deploy_state(txn);
        fprintf(stderr, "[dev-activation] REJECTED: preflight failed; "
                        "running process and current generation untouched\n");
        return DEV_ACTIVATION_E_PREFLIGHT;
    }

    if (ops->source_epoch_cas && ops->source_epoch_cas(ops->ctx) != 0) {
        dev_set_status(r, "superseded", "source_epoch_superseded",
                       "source changed after candidate preflight; running generation untouched");
        snprintf(r->failure_capsule, sizeof(r->failure_capsule),
                 "source epoch compare-and-swap refused publication");
        (void)dev_activation_write_deploy_state(txn);
        fprintf(stderr, "[dev-activation] REFUSED: source epoch superseded; "
                        "running process and current generation untouched\n");
        return DEV_ACTIVATION_E_PREFLIGHT;
    }

    if (txn->req->mode == DEV_ACTIVATION_MODE_STAGE_ONLY) {
        (void)dev_activation_link_generation(txn, "staged",
                                             txn->candidate_generation);
        dev_set_status(r, "staged", "staged",
                       "candidate preflight passed; no service stop/restart");
        (void)dev_activation_write_deploy_state(txn);
        return DEV_ACTIVATION_OK;
    }

    int st = dev_activate_candidate(txn);
    (void)dev_activation_write_deploy_state(txn);
    return st;
}

/* ── public entry points ─────────────────────────────────────────────── */

static void dev_result_init(struct dev_activation_result *r)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->activation_status, sizeof(r->activation_status), "preparing");
    snprintf(r->verify_status, sizeof(r->verify_status), "started");
    snprintf(r->rollback_status, sizeof(r->rollback_status), "not_needed");
}

static int dev_prepare(struct dev_activation_txn *txn,
                       const struct dev_activation_request *req,
                       const struct dev_activation_ops *ops,
                       struct dev_activation_result *result,
                       struct dev_activation_ops *default_slot)
{
    memset(txn, 0, sizeof(*txn));
    platform_process_lock_init(&txn->lock);
    txn->req = req;
    txn->result = result;
    if (!result)
        return DEV_ACTIVATION_E_INTERNAL;
    dev_result_init(result);
    if (!req)
        return DEV_ACTIVATION_E_INTERNAL;
    if (!ops) {
#ifdef ZCL_DEV_BUILD
        dev_activation_default_ops(req, default_slot);
        txn->ops = default_slot;
#else
        /* The real (process-exec) default ops live in a ZCL_DEV_BUILD-only TU;
         * a test build must always supply an ops vtable. */
        (void)default_slot;
        return DEV_ACTIVATION_E_INTERNAL;
#endif
    } else {
        txn->ops = ops;
    }
    if (!dev_derive_paths(txn))
        return DEV_ACTIVATION_E_INTERNAL;
    if (!dev_validate_confinement(txn)) {
        dev_set_status(result, "refused", "refused",
                       "confinement check failed: not the isolated dev lane");
        snprintf(result->failure_capsule, sizeof(result->failure_capsule),
                 "confinement refusal");
        return DEV_ACTIVATION_E_CONFINEMENT;
    }
    if (!dev_activation_source_id_valid(req->source_identity)) {
        dev_set_status(result, "refused", "source_identity_invalid",
                       "activation requires an exact lowercase 64-hex "
                       "source_id_sha256");
        snprintf(result->failure_capsule, sizeof(result->failure_capsule),
                 "missing or malformed source_id_sha256");
        return DEV_ACTIVATION_E_STAGE;
    }
    if (!dev_activation_mkdir_p(req->datadir) || !dev_activation_mkdir_p(txn->gen_root) ||
        !dev_activation_mkdir_p(txn->rejected_dir))
        return DEV_ACTIVATION_E_INTERNAL;
    return DEV_ACTIVATION_OK;
}

int dev_activation_run(const struct dev_activation_request *req,
                       const struct dev_activation_ops *ops,
                       struct dev_activation_result *result)
{
    if (!result)
        return DEV_ACTIVATION_E_INTERNAL;
    struct dev_activation_txn txn;
    struct dev_activation_ops default_ops;
    int st = dev_prepare(&txn, req, ops, result, &default_ops);
    if (st != DEV_ACTIVATION_OK) {
        result->status = st;
        return st;
    }
    /* Guard the pending crash-only auto-reindex request BEFORE the lock, at the
     * same transaction point as deploy-dev-lane.sh:guard_pending_auto_reindex. */
    st = dev_guard_pending_auto_reindex(&txn);
    if (st != DEV_ACTIVATION_OK) {
        result->status = st;
        return st;
    }
    st = dev_acquire_lock(&txn);
    if (st != DEV_ACTIVATION_OK) {
        dev_set_status(result, "lock_busy", "lock_busy",
                       "another activation holds the lock");
        result->status = st;
        return st;
    }
    st = dev_run_locked(&txn, false);
    dev_release_lock(&txn);
    result->status = st;
    return st;
}

int dev_activation_activate_generation(const uint8_t gen_sha256[32],
                                       const struct dev_activation_request *req,
                                       const struct dev_activation_ops *ops,
                                       struct dev_activation_result *result)
{
    if (!result)
        return DEV_ACTIVATION_E_INTERNAL;
    struct dev_activation_txn txn;
    struct dev_activation_ops default_ops;
    int st = dev_prepare(&txn, req, ops, result, &default_ops);
    if (st != DEV_ACTIVATION_OK) {
        result->status = st;
        return st;
    }
    /* Same pre-lock auto-reindex guard as dev_activation_run(): the revert hook
     * also stops/flips/restarts the lane, so a pending reindex must block it. */
    st = dev_guard_pending_auto_reindex(&txn);
    if (st != DEV_ACTIVATION_OK) {
        result->status = st;
        return st;
    }
    /* Resolve the already-staged generation by sha — no build, no restage. */
    zcl_hex_encode(gen_sha256, 32, txn.candidate_sha_hex);
    snprintf(result->candidate_sha256, sizeof(result->candidate_sha256), "%s",
             txn.candidate_sha_hex);
    snprintf(txn.candidate_generation, sizeof(txn.candidate_generation),
             "gen-%s", txn.candidate_sha_hex);
    snprintf(result->candidate_generation, sizeof(result->candidate_generation),
             "%s", txn.candidate_generation);
    dev_activation_join(txn.candidate_dir, sizeof(txn.candidate_dir), txn.gen_root,
             txn.candidate_generation);
    int candidate_n = snprintf(txn.candidate_bin, sizeof(txn.candidate_bin),
#if defined(_WIN32)
             "%s/zclassic23-dev.exe", txn.candidate_dir);
#else
             "%s/zclassic23-dev", txn.candidate_dir);
#endif
    if (candidate_n <= 0 ||
        (size_t)candidate_n >= sizeof(txn.candidate_bin)) {
        dev_set_status(result, "stage_failed", "stage_failed",
                       "generation binary path too long");
        result->status = DEV_ACTIVATION_E_STAGE;
        return DEV_ACTIVATION_E_STAGE;
    }

    st = dev_acquire_lock(&txn);
    if (st != DEV_ACTIVATION_OK) {
        dev_set_status(result, "lock_busy", "lock_busy",
                       "another activation holds the lock");
        result->status = st;
        return st;
    }
    char have[65];
#if defined(_WIN32)
    struct platform_positioned_file candidate;
    platform_positioned_file_init(&candidate);
    bool candidate_ok = platform_positioned_file_open(
                            &candidate, txn.candidate_bin) &&
                        platform_positioned_file_is_executable(&candidate);
    platform_positioned_file_close(&candidate);
    if (!candidate_ok ||
#else
    if (access(txn.candidate_bin, X_OK) != 0 ||
#endif
        !dev_activation_sha256_file(txn.candidate_bin, have) ||
        strcmp(have, txn.candidate_sha_hex) != 0) {
        dev_release_lock(&txn);
        dev_set_status(result, "stage_failed", "stage_failed",
                       "requested generation is not staged");
        snprintf(result->failure_capsule, sizeof(result->failure_capsule),
                 "generation %s not staged", txn.candidate_generation);
        (void)dev_activation_write_deploy_state(&txn);
        result->status = DEV_ACTIVATION_E_STAGE;
        return DEV_ACTIVATION_E_STAGE;
    }
    st = dev_run_locked(&txn, true);
    dev_release_lock(&txn);
    result->status = st;
    return st;
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */
