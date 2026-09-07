/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: command-line argument parsing and signer seed handling
 * (slice 1b). See the Usage block at the top of tools/corpus_census.c for
 * the full flag reference; the signer seed holds exactly 32 raw bytes,
 * generated from the kernel CSPRNG on first use and never written under
 * the repo (the census signs every evidence object with it).
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/checked.h"
#include "base/cleanse.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/rng.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static bool parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = (uint64_t)v;
    return true;
}

static bool parse_i64(const char *s, int64_t *out)
{
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno || !end || *end) return false;
    *out = (int64_t)v;
    return true;
}

void usage(FILE *stream)
{
    fprintf(stream,
        "usage: corpus-census --repo <repo root> --def <scopes.def> "
        "--out <dir>\n"
        "       --cutoff-height N --cutoff-mtp N [--signer-seed-file PATH]\n"
        "       [--sequence N] [--predecessor-root HEX64] "
        "[--quality-attested 0|1]\n"
        "       [--install <datadir>] [--previous-report PATH]\n"
        "       [--store-root DIR]   package-store labels in scopes.def "
        "resolve to\n"
        "                            <DIR>/<label>; default "
        "$ZCL_CORPUS_STORE_ROOT else $HOME\n"
        "       (sequence >1 auto-discovers the predecessor root and the\n"
        "       previous report from <out>/report-<seq-1>.json)\n");
}

/* Split one `--key value` or `--key=value` argv token. `*i` advances past
 * a separate value token; the caller's loop variable owns it. */
static bool args_next_token(int argc, char **argv, int *i, char *key,
                            size_t key_sz, char **value)
{
    char *arg = argv[*i];
    if (strncmp(arg, "--", 2) != 0) return false;
    char *eq = strchr(arg, '=');
    if (eq) {
        size_t klen = (size_t)(eq - arg);
        if (klen >= key_sz) return false;
        memcpy(key, arg, klen);
        key[klen] = '\0';
        *value = eq + 1;
        return true;
    }
    if (strlen(arg) >= key_sz) return false;
    strcpy(key, arg);
    if (*i + 1 >= argc) return false;
    *value = argv[++*i];
    return true;
}

static bool args_parse_numeric_flag(struct census_args *args,
                                    const char *key, const char *value)
{
    if (strcmp(key, "--sequence") == 0)
        return parse_u64(value, &args->sequence);
    if (strcmp(key, "--cutoff-height") == 0)
        return parse_u64(value, &args->cutoff_height);
    if (strcmp(key, "--cutoff-mtp") == 0)
        return parse_i64(value, &args->cutoff_mtp);
    if (strcmp(key, "--quality-attested") == 0) {
        uint64_t v = 0;
        if (!parse_u64(value, &v) || v > 1) return false;
        args->quality_attested = v == 1;
        return true;
    }
    if (strcmp(key, "--predecessor-root") == 0) {
        if (strlen(value) != 64 ||
            !zcl_hex_decode_lower(value, args->predecessor, 32))
            return false;
        args->predecessor_given = true;
        return true;
    }
    return false;
}

static bool args_parse_flag(struct census_args *args, const char *key,
                            char *value)
{
    if (strcmp(key, "--repo") == 0) { args->repo = value; return true; }
    if (strcmp(key, "--def") == 0) { args->def = value; return true; }
    if (strcmp(key, "--out") == 0) { args->out = value; return true; }
    if (strcmp(key, "--signer-seed-file") == 0) {
        args->seed_path = value;
        return true;
    }
    if (strcmp(key, "--install") == 0) {
        args->install_datadir = value;
        return true;
    }
    if (strcmp(key, "--previous-report") == 0) {
        args->previous_report = value;
        return true;
    }
    if (strcmp(key, "--store-root") == 0) {
        args->store_root = value;
        return true;
    }
    return args_parse_numeric_flag(args, key, value);
}

/* Package-store label resolution root and the final cross-field checks:
 * never committed anywhere, an operator-local coordinate (which is exactly
 * why it is a flag/env and not a field in scopes.def). */
static bool args_parse_finalize(struct census_args *args)
{
    if (!args->store_root) args->store_root = getenv("ZCL_CORPUS_STORE_ROOT");
    if (!args->store_root) args->store_root = getenv("HOME");
    if (!args->repo || !args->def || !args->out || !args->cutoff_height ||
        args->cutoff_mtp <= 0 || !args->sequence)
        return false;
    bool pred_nonzero =
        args->predecessor_given && zcl_bytes_any_set(args->predecessor, 32);
    /* sequence 1 requires the zero predecessor root; sequence >1 either
     * takes an explicit nonzero root or discovers it from the previous
     * sequence's report in the out dir (main, fail-closed). */
    if (args->sequence == 1 && pred_nonzero) return false;
    if (!shell_safe(args->repo))
        return false;
    return true;
}

bool args_parse(int argc, char **argv, struct census_args *args)
{
    memset(args, 0, sizeof(*args));
    args->sequence = 1;
    for (int i = 1; i < argc; i++) {
        char key[64];
        char *value = NULL;
        if (!args_next_token(argc, argv, &i, key, sizeof(key), &value))
            return false;
        if (!args_parse_flag(args, key, value))
            return false;
    }
    return args_parse_finalize(args);
}

/* ── signer seed ──────────────────────────────────────────────────── */

/* Try reading an existing 32-raw-byte seed file. *loaded stays false (with
 * true returned) when the file is simply absent — the caller generates
 * one; the bool return is false only for a hard I/O or size failure. */
static bool seed_try_load(const char *path, uint8_t seed[32], bool *loaded)
{
    *loaded = false;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT)
            LOG_FAIL(CENSUS_LOG, "open signer seed %s: %s", path,
                     strerror(errno));
        return true;
    }
    struct stat st;
    uint8_t buf[32];
    size_t off = 0;
    bool ok = fstat(fd, &st) == 0 && st.st_size == 32;
    while (ok && off < sizeof(buf)) {
        ssize_t r = read(fd, buf + off, sizeof(buf) - off);
        if (r <= 0) ok = false;
        else off += (size_t)r;
    }
    close(fd);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "signer seed %s must be exactly 32 raw bytes",
                 path);
    memcpy(seed, buf, sizeof(buf));
    memory_cleanse(buf, sizeof(buf));
    *loaded = true;
    return true;
}

/* Resolve the seed path's parent against the repo to enforce the
 * never-under-the-repo boundary before writing anything. */
static bool seed_check_not_under_repo(const char *path, const char *repo_real)
{
    const char *slash = strrchr(path, '/');
    if (!slash)
        LOG_FAIL(CENSUS_LOG, "signer seed path %s has no directory", path);
    size_t dir_len = (size_t)(slash - path);
    char *dir = zcl_malloc(dir_len + 1u, "corpus.seed.dir");
    if (!dir)
        LOG_FAIL(CENSUS_LOG, "seed dir alloc");
    memcpy(dir, path, dir_len);
    dir[dir_len] = '\0';
    char resolved[4096];
    if (realpath(dir, resolved) && repo_real) {
        size_t rlen = strlen(repo_real);
        if (strncmp(resolved, repo_real, rlen) == 0 &&
            (resolved[rlen] == '/' || resolved[rlen] == '\0')) {
            free(dir);
            LOG_FAIL(CENSUS_LOG,
                     "signer seed %s would live under the repo %s", path,
                     repo_real);
        }
    }
    free(dir);
    return true;
}

/* mkdir -p the seed file's parent (single level deep is the default
 * layout; create intermediate components one by one). */
static bool seed_mkdir_parents(const char *path)
{
    char *mutable = dup_str(path, "corpus.seed.path");
    if (!mutable)
        LOG_FAIL(CENSUS_LOG, "seed path dup");
    bool ok = true;
    for (char *p = mutable + 1; ok && *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(mutable, 0700) != 0 && errno != EEXIST) {
                LOG_ERROR(CENSUS_LOG, "mkdir %s: %s", mutable,
                          strerror(errno));
                ok = false;
            }
            *p = '/';
        }
    }
    free(mutable);
    return ok;
}

static bool seed_write_new(const char *path, const uint8_t seed[32])
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        LOG_FAIL(CENSUS_LOG, "create signer seed %s: %s", path,
                 strerror(errno));
    size_t off = 0;
    bool ok = true;
    while (ok && off < 32) {
        ssize_t w = write(fd, seed + off, 32 - off);
        if (w <= 0) ok = false;
        else off += (size_t)w;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "write signer seed %s: %s", path,
                 strerror(errno));
    return true;
}

/* Load exactly 32 RAW seed bytes from `path`, or generate them from the
 * kernel CSPRNG and write the file mode 0600 (parents 0700) when missing.
 * The seed file must never live under the repo. */
bool seed_load_or_create(const char *path, const char *repo_real,
                         uint8_t seed[32], bool *created_out)
{
    *created_out = false;
    bool loaded = false;
    if (!seed_try_load(path, seed, &loaded))
        return false;
    if (loaded) return true;

    if (!seed_check_not_under_repo(path, repo_real))
        return false;
    if (!rng_fill(seed, 32))
        LOG_FAIL(CENSUS_LOG, "kernel CSPRNG refused 32 bytes");
    if (!seed_mkdir_parents(path))
        return false;
    if (!seed_write_new(path, seed))
        return false;
    *created_out = true;
    return true;
}
