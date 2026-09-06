/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-tor-provenance — bind the bundled Tor archives to the bytes that
 * produced them, instead of every readiness check asking only "do four
 * files exist and are they non-empty".
 *
 * Every existing gate (Makefile's TOR_FULL wildcard, tor_archives_ready.sh,
 * ship.sh's preflight) treats vendor/tor/{libtor.a, the three ext archives}
 * as ready the instant they are present and non-empty. None of them notice
 * a stale libtor.a built by a different compiler, a copy from an unrelated
 * vendor/tor commit, or a byte-flipped archive. This tool closes that gap
 * with one small manifest, `<tor tree>/.provenance`:
 *
 *     tor_commit=<40 lowercase hex — git -C vendor/tor rev-parse HEAD>
 *     compiler_id=<tools/dev/build-epoch-key.sh compiler-id output>
 *     configure_args_sha256=<sha256 of the NUL-joined configure_opts array>
 *     archive_sha256=<sha256 of libtor.a> <ed25519 donna> <ed25519 ref10> <keccak-tiny>
 *
 * Modes:
 *   write <tor-dir> <tor_commit> <compiler_id> <configure_args_sha256>
 *       Hash the four archives under <tor-dir> in the fixed order above and
 *       write <tor-dir>/.provenance atomically (temp file + rename).
 *
 *   check <tor-dir> [--tor-commit <hex>] [--compiler-id <id>]
 *       Recompute the archive hashes and compare every recorded field that
 *       was supplied on the command line, plus archive_sha256 always. Prints
 *       one line per checked field: "tor-provenance: <field> ok|MISMATCH ...".
 *       A missing manifest is a MISMATCH, never a pass. Exits 0 only when
 *       every checked field matched.
 *
 *   --selftest
 *       Builds a throwaway fixture (under $TMPDIR, default /tmp — same
 *       convention as every other selftest in this tree), proves write then
 *       check agree, then proves a flipped archive byte and a deleted
 *       manifest both come back MISMATCH. Exits 0 only if all three behave.
 *
 * No malloc/calloc/realloc/free (tools/ is check-malloc's scan scope):
 * every buffer here is fixed-size on the stack, and manifest lines are read
 * with fgets into caller-owned buffers, never getline.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "base/hex.h"
#include "zsha256/zsha256.h"

#define TOR_PROVENANCE_NAME ".provenance"
#define TOR_COMMIT_HEX_LEN 40
#define COMPILER_ID_MAX 512
#define PATH_BUF_MAX 4096
#define LINE_BUF_MAX 1024
#define ARCHIVE_COUNT 4

static const char *const ARCHIVE_RELPATHS[ARCHIVE_COUNT] = {
    "libtor.a",
    "src/ext/ed25519/donna/libed25519_donna.a",
    "src/ext/ed25519/ref10/libed25519_ref10.a",
    "src/ext/keccak-tiny/libkeccak-tiny.a",
};

typedef struct {
    char tor_commit[TOR_COMMIT_HEX_LEN + 1];
    char compiler_id[COMPILER_ID_MAX];
    char configure_args_sha256[ZSHA256_HEX_LEN];
    char archive_sha256[ARCHIVE_COUNT][ZSHA256_HEX_LEN];
    int has_tor_commit;
    int has_compiler_id;
    int has_configure_args_sha256;
    int has_archive_sha256;
} provenance_t;

static void die_usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s write <tor-dir> <tor_commit> <compiler_id> <configure_args_sha256>\n"
        "       %s check <tor-dir> [--tor-commit <hex>] [--compiler-id <id>]\n"
        "       %s --selftest\n",
        prog, prog, prog);
    exit(2);
}

static int is_hex_string(const char *s, size_t want_len)
{
    size_t n = strlen(s);
    if (n != want_len) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int contains_control_or_eq(const char *s)
{
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '\n' || c == '\r' || c == '=' ) return 1;
    }
    return 0;
}

/* Hash one file's bytes with a fixed 64 KiB read buffer — no malloc. */
static int sha256_hex_of_file(const char *path, char out_hex[ZSHA256_HEX_LEN])
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    zsha256_ctx ctx;
    zsha256_init(&ctx);
    static _Thread_local unsigned char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) break;
        zsha256_update(&ctx, buf, (size_t)n);
    }
    close(fd);
    uint8_t digest[ZSHA256_DIGEST_LEN];
    zsha256_final(&ctx, digest);
    /* zsha256_hex hashes fresh input rather than formatting a digest we
     * already have, so format the digest with the canonical codec instead. */
    zcl_hex_encode(digest, ZSHA256_DIGEST_LEN, out_hex);
    return 0;
}

static int join_path(char out[PATH_BUF_MAX], const char *dir, const char *rel)
{
    int n = snprintf(out, PATH_BUF_MAX, "%s/%s", dir, rel);
    return (n > 0 && (size_t)n < PATH_BUF_MAX) ? 0 : -1;
}

static int hash_all_archives(const char *tor_dir,
                              char out[ARCHIVE_COUNT][ZSHA256_HEX_LEN],
                              int *failing_index)
{
    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        char path[PATH_BUF_MAX];
        if (join_path(path, tor_dir, ARCHIVE_RELPATHS[i]) != 0) {
            if (failing_index) *failing_index = i;
            return -1;
        }
        if (sha256_hex_of_file(path, out[i]) != 0) {
            if (failing_index) *failing_index = i;
            return -1;
        }
    }
    return 0;
}

/* ---- write ---------------------------------------------------------- */

static int cmd_write(const char *tor_dir, const char *tor_commit,
                      const char *compiler_id, const char *configure_args_sha256)
{
    if (!is_hex_string(tor_commit, TOR_COMMIT_HEX_LEN)) {
        fprintf(stderr, "tor-provenance: write: tor_commit must be exactly %d lowercase hex chars\n",
                TOR_COMMIT_HEX_LEN);
        return 1;
    }
    if (!is_hex_string(configure_args_sha256, ZSHA256_HEX_LEN - 1)) {
        fprintf(stderr, "tor-provenance: write: configure_args_sha256 must be exactly %d lowercase hex chars\n",
                ZSHA256_HEX_LEN - 1);
        return 1;
    }
    size_t cid_len = strlen(compiler_id);
    if (cid_len == 0 || cid_len >= COMPILER_ID_MAX) {
        fprintf(stderr, "tor-provenance: write: compiler_id is empty or too long\n");
        return 1;
    }
    if (contains_control_or_eq(compiler_id)) {
        fprintf(stderr, "tor-provenance: write: compiler_id must not contain '=', CR, or LF\n");
        return 1;
    }

    char archive_hex[ARCHIVE_COUNT][ZSHA256_HEX_LEN];
    int failing = -1;
    if (hash_all_archives(tor_dir, archive_hex, &failing) != 0) {
        fprintf(stderr, "tor-provenance: write: could not hash archive %s/%s: %s\n",
                tor_dir, ARCHIVE_RELPATHS[failing], strerror(errno));
        return 1;
    }

    char content[LINE_BUF_MAX];
    int n = snprintf(content, sizeof content,
        "tor_commit=%s\n"
        "compiler_id=%s\n"
        "configure_args_sha256=%s\n"
        "archive_sha256=%s %s %s %s\n",
        tor_commit, compiler_id, configure_args_sha256,
        archive_hex[0], archive_hex[1], archive_hex[2], archive_hex[3]);
    if (n <= 0 || (size_t)n >= sizeof content) {
        fprintf(stderr, "tor-provenance: write: manifest content too large\n");
        return 1;
    }

    char manifest_path[PATH_BUF_MAX];
    char tmp_path[PATH_BUF_MAX];
    if (join_path(manifest_path, tor_dir, TOR_PROVENANCE_NAME) != 0) {
        fprintf(stderr, "tor-provenance: write: tor-dir path too long\n");
        return 1;
    }
    int tmp_n = snprintf(tmp_path, sizeof tmp_path, "%s.tmp.%ld",
                          manifest_path, (long)getpid());
    if (tmp_n <= 0 || (size_t)tmp_n >= sizeof tmp_path) {
        fprintf(stderr, "tor-provenance: write: temp path too long\n");
        return 1;
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "tor-provenance: write: could not create %s: %s\n", tmp_path, strerror(errno));
        return 1;
    }
    size_t off = 0;
    size_t len = (size_t)n;
    while (off < len) {
        ssize_t w = write(fd, content + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "tor-provenance: write: write failed: %s\n", strerror(errno));
            close(fd);
            unlink(tmp_path);
            return 1;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        fprintf(stderr, "tor-provenance: write: fsync failed: %s\n", strerror(errno));
        close(fd);
        unlink(tmp_path);
        return 1;
    }
    close(fd);
    if (rename(tmp_path, manifest_path) != 0) {
        fprintf(stderr, "tor-provenance: write: rename failed: %s\n", strerror(errno));
        unlink(tmp_path);
        return 1;
    }
    printf("tor-provenance: wrote %s\n", manifest_path);
    return 0;
}

/* ---- check ------------------------------------------------------------ */

static int parse_manifest(const char *manifest_path, provenance_t *pv)
{
    FILE *f = fopen(manifest_path, "r");
    if (!f) return -1;
    memset(pv, 0, sizeof *pv);
    char line[LINE_BUF_MAX];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;
        if (strcmp(key, "tor_commit") == 0) {
            if (strlen(val) < sizeof pv->tor_commit) {
                snprintf(pv->tor_commit, sizeof pv->tor_commit, "%s", val);
                pv->has_tor_commit = 1;
            }
        } else if (strcmp(key, "compiler_id") == 0) {
            if (strlen(val) < sizeof pv->compiler_id) {
                snprintf(pv->compiler_id, sizeof pv->compiler_id, "%s", val);
                pv->has_compiler_id = 1;
            }
        } else if (strcmp(key, "configure_args_sha256") == 0) {
            if (strlen(val) < sizeof pv->configure_args_sha256) {
                snprintf(pv->configure_args_sha256, sizeof pv->configure_args_sha256, "%s", val);
                pv->has_configure_args_sha256 = 1;
            }
        } else if (strcmp(key, "archive_sha256") == 0) {
            char a0[ZSHA256_HEX_LEN], a1[ZSHA256_HEX_LEN], a2[ZSHA256_HEX_LEN], a3[ZSHA256_HEX_LEN];
            if (sscanf(val, "%64s %64s %64s %64s", a0, a1, a2, a3) == 4) {
                snprintf(pv->archive_sha256[0], ZSHA256_HEX_LEN, "%s", a0);
                snprintf(pv->archive_sha256[1], ZSHA256_HEX_LEN, "%s", a1);
                snprintf(pv->archive_sha256[2], ZSHA256_HEX_LEN, "%s", a2);
                snprintf(pv->archive_sha256[3], ZSHA256_HEX_LEN, "%s", a3);
                pv->has_archive_sha256 = 1;
            }
        }
    }
    fclose(f);
    return 0;
}

static int cmd_check(const char *tor_dir, const char *want_tor_commit, const char *want_compiler_id)
{
    char manifest_path[PATH_BUF_MAX];
    if (join_path(manifest_path, tor_dir, TOR_PROVENANCE_NAME) != 0) {
        fprintf(stderr, "tor-provenance: check: tor-dir path too long\n");
        return 1;
    }

    provenance_t pv;
    if (parse_manifest(manifest_path, &pv) != 0) {
        printf("tor-provenance: manifest MISMATCH %s is missing\n", manifest_path);
        return 1;
    }

    int all_ok = 1;

    /* archive_sha256 is always checked — it is the whole point. */
    if (!pv.has_archive_sha256) {
        printf("tor-provenance: archive_sha256 MISMATCH manifest has no archive_sha256 line\n");
        all_ok = 0;
    } else {
        char actual[ARCHIVE_COUNT][ZSHA256_HEX_LEN];
        int failing = -1;
        if (hash_all_archives(tor_dir, actual, &failing) != 0) {
            printf("tor-provenance: archive_sha256 MISMATCH could not hash %s/%s: %s\n",
                   tor_dir, ARCHIVE_RELPATHS[failing], strerror(errno));
            all_ok = 0;
        } else {
            int mismatch_index = -1;
            for (int i = 0; i < ARCHIVE_COUNT; i++) {
                if (strcmp(actual[i], pv.archive_sha256[i]) != 0) {
                    mismatch_index = i;
                    break;
                }
            }
            if (mismatch_index < 0) {
                printf("tor-provenance: archive_sha256 ok\n");
            } else {
                printf("tor-provenance: archive_sha256 MISMATCH %s recorded=%s actual=%s\n",
                       ARCHIVE_RELPATHS[mismatch_index],
                       pv.archive_sha256[mismatch_index], actual[mismatch_index]);
                all_ok = 0;
            }
        }
    }

    if (want_tor_commit) {
        if (!pv.has_tor_commit) {
            printf("tor-provenance: tor_commit MISMATCH manifest has no tor_commit line\n");
            all_ok = 0;
        } else if (strcmp(pv.tor_commit, want_tor_commit) != 0) {
            printf("tor-provenance: tor_commit MISMATCH recorded=%s actual=%s\n",
                   pv.tor_commit, want_tor_commit);
            all_ok = 0;
        } else {
            printf("tor-provenance: tor_commit ok\n");
        }
    }

    if (want_compiler_id) {
        if (!pv.has_compiler_id) {
            printf("tor-provenance: compiler_id MISMATCH manifest has no compiler_id line\n");
            all_ok = 0;
        } else if (strcmp(pv.compiler_id, want_compiler_id) != 0) {
            printf("tor-provenance: compiler_id MISMATCH recorded=%s actual=%s\n",
                   pv.compiler_id, want_compiler_id);
            all_ok = 0;
        } else {
            printf("tor-provenance: compiler_id ok\n");
        }
    }

    return all_ok ? 0 : 1;
}

/* ---- selftest ----------------------------------------------------------
 * Fixture lives under $TMPDIR (default /tmp, same convention as every other
 * selftest in this tree — see tools/ship.sh, tools/scripts/tor_archives_ready.sh).
 */

static int write_fixture_archive(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t len = strlen(content);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, content + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static int mkdir_p_fixed(const char *path)
{
    /* Fixed, known-shape fixture directories only — no generic recursive
     * mkdir -p needed. Caller passes exact paths one level at a time. */
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int selftest_rmdir_tree(const char *base)
{
    /* The fixture's shape is exactly known (we built it), so we can tear it
     * down without a generic recursive-delete routine or malloc. */
    char path[PATH_BUF_MAX];
    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        join_path(path, base, ARCHIVE_RELPATHS[i]);
        unlink(path);
    }
    join_path(path, base, TOR_PROVENANCE_NAME);
    unlink(path);
    char sub[PATH_BUF_MAX];
    if (join_path(sub, base, "src/ext/ed25519/donna") == 0) rmdir(sub);
    if (join_path(sub, base, "src/ext/ed25519/ref10") == 0) rmdir(sub);
    if (join_path(sub, base, "src/ext/ed25519") == 0) rmdir(sub);
    if (join_path(sub, base, "src/ext/keccak-tiny") == 0) rmdir(sub);
    if (join_path(sub, base, "src/ext") == 0) rmdir(sub);
    if (join_path(sub, base, "src") == 0) rmdir(sub);
    rmdir(base);
    return 0;
}

/* Silence stdout for the wrapped call, capturing nothing — the selftest only
 * cares about exit status of the internal check, not its text. */
static int quiet_check(const char *tor_dir, const char *want_commit, const char *want_cc)
{
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
    int rc = cmd_check(tor_dir, want_commit, want_cc);
    fflush(stdout);
    if (saved >= 0) { dup2(saved, STDOUT_FILENO); close(saved); }
    return rc;
}

static int run_selftest(void)
{
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";

    char base[PATH_BUF_MAX];
    snprintf(base, sizeof base, "%s/z23-tor-provenance-selftest.%ld", tmpdir, (long)getpid());
    selftest_rmdir_tree(base); /* clean any stale run with the same pid, best effort */
    if (mkdir_p_fixed(base) != 0) {
        fprintf(stderr, "tor-provenance: selftest: could not create fixture dir %s: %s\n", base, strerror(errno));
        return 1;
    }
    char d1[PATH_BUF_MAX], d2[PATH_BUF_MAX], d3[PATH_BUF_MAX], d4[PATH_BUF_MAX], d5[PATH_BUF_MAX], d6[PATH_BUF_MAX];
    if (join_path(d1, base, "src") || join_path(d2, base, "src/ext") ||
        join_path(d3, base, "src/ext/ed25519") ||
        join_path(d4, base, "src/ext/ed25519/donna") ||
        join_path(d5, base, "src/ext/ed25519/ref10") ||
        join_path(d6, base, "src/ext/keccak-tiny")) {
        fprintf(stderr, "tor-provenance: selftest: fixture path too long under %s\n", base);
        return 1;
    }
    if (mkdir_p_fixed(d1) || mkdir_p_fixed(d2) || mkdir_p_fixed(d3) ||
        mkdir_p_fixed(d4) || mkdir_p_fixed(d5) || mkdir_p_fixed(d6)) {
        fprintf(stderr, "tor-provenance: selftest: could not create fixture subdirs under %s\n", base);
        return 1;
    }

    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        char path[PATH_BUF_MAX];
        join_path(path, base, ARCHIVE_RELPATHS[i]);
        char content[128];
        snprintf(content, sizeof content, "fixture tor archive bytes %d\n", i);
        if (write_fixture_archive(path, content) != 0) {
            fprintf(stderr, "tor-provenance: selftest: could not write fixture archive %s\n", path);
            return 1;
        }
    }

    const char *fake_commit_ok = "0123456789abcdef0123456789abcdef012345aa"; /* 40 hex chars */
    const char *fake_compiler_id = "selftest-compiler-id";
    /* 64 hex chars: "0123456789abcdef" repeated 4 times. */
    const char *fake_configure_sha =
        "0123456789abcdef" "0123456789abcdef" "0123456789abcdef" "0123456789abcdef";

    int rc = 1;
    if (cmd_write(base, fake_commit_ok, fake_compiler_id, fake_configure_sha) != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — write did not succeed\n");
        goto out;
    }

    if (quiet_check(base, fake_commit_ok, fake_compiler_id) != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — check did not accept a just-written manifest\n");
        goto out;
    }

    /* Flip one byte in one archive: check must now MISMATCH. */
    {
        char path[PATH_BUF_MAX];
        join_path(path, base, ARCHIVE_RELPATHS[1]);
        int fd = open(path, O_RDWR);
        if (fd < 0) {
            fprintf(stderr, "tor-provenance: selftest FAILED — could not reopen %s to corrupt it\n", path);
            goto out;
        }
        char c;
        if (pread(fd, &c, 1, 0) != 1) { close(fd); goto out; }
        c ^= 0x01;
        if (pwrite(fd, &c, 1, 0) != 1) { close(fd); goto out; }
        close(fd);
    }
    if (quiet_check(base, fake_commit_ok, fake_compiler_id) == 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — a flipped archive byte still checked ok\n");
        goto out;
    }

    /* Restore the archive, delete the manifest: check must MISMATCH (missing). */
    {
        char path[PATH_BUF_MAX];
        join_path(path, base, ARCHIVE_RELPATHS[1]);
        char content[128];
        snprintf(content, sizeof content, "fixture tor archive bytes %d\n", 1);
        if (write_fixture_archive(path, content) != 0) goto out;
        char manifest_path[PATH_BUF_MAX];
        join_path(manifest_path, base, TOR_PROVENANCE_NAME);
        unlink(manifest_path);
    }
    if (quiet_check(base, fake_commit_ok, fake_compiler_id) == 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — a missing manifest still checked ok\n");
        goto out;
    }

    printf("tor-provenance: selftest PASS\n");
    rc = 0;
out:
    selftest_rmdir_tree(base);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) die_usage(argv[0]);

    if (strcmp(argv[1], "--selftest") == 0) {
        return run_selftest();
    }

    if (strcmp(argv[1], "write") == 0) {
        if (argc != 6) die_usage(argv[0]);
        return cmd_write(argv[2], argv[3], argv[4], argv[5]);
    }

    if (strcmp(argv[1], "check") == 0) {
        if (argc < 3) die_usage(argv[0]);
        const char *tor_dir = argv[2];
        const char *want_tor_commit = NULL;
        const char *want_compiler_id = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--tor-commit") == 0 && i + 1 < argc) {
                want_tor_commit = argv[++i];
            } else if (strcmp(argv[i], "--compiler-id") == 0 && i + 1 < argc) {
                want_compiler_id = argv[++i];
            } else {
                die_usage(argv[0]);
            }
        }
        return cmd_check(tor_dir, want_tor_commit, want_compiler_id);
    }

    die_usage(argv[0]);
    return 2;
}
