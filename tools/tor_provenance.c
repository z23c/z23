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
 *     compiler_id=<tools/dev/build-epoch-key.sh compiler-bytes-id output:
 *                  "sha256:<compiler binary hash> version:<--version first
 *                  line> triple:<-dumpmachine>" -- bytes-only, deliberately
 *                  NOT the CPATH/LD_LIBRARY_PATH/COMPILER_PATH/CCACHE_*-
 *                  bound `compiler-id` mode used for cached-object epochs
 *                  elsewhere: that form makes the identical compiler yield a
 *                  different id from a systemd unit than from an
 *                  interactive shell. Derived identically by the writer
 *                  (build_tor_full.sh) and every reader
 *                  (tor_archives_ready.sh, check_tor_provenance.sh) via the
 *                  one shared function
 *                  tools/scripts/tor_provenance_lib.sh:zcl_tor_compiler_identity_for_cc.
 *                  A manifest recorded before this scheme existed has a
 *                  compiler_id with no "sha256:" prefix; `check` calls that
 *                  out by name (see below) and `rewrite-compiler-id` updates
 *                  it in place without a rebuild. `check` compares ids with
 *                  tor_compiler_ids_match (tools/tor_compiler_id.h): equal
 *                  binary hash, else equal version text after the driver word.>
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
 *       A missing manifest is a MISMATCH, never a pass, PROVIDED at least one
 *       archive is present -- that is the real producer having run and left
 *       an incomplete record, which some caller must rebuild. When NONE of
 *       the four archives exist at all, that is a stub build (Tor was never
 *       compiled), not a defect: prints "no Tor archives present (stub
 *       build) -- nothing to attest" and exits 0 only when ZCL_TOR=stub is
 *       set in the environment (the same variable tor_archives_ready.sh's
 *       do_ready() reads to decide to link the offline stub); otherwise
 *       exits 1, because a full build was expected and never happened.
 *       Exits 0 only when every checked field matched. On a compiler_id
 *       mismatch against a pre-bytes-based manifest (no "sha256:" prefix
 *       recorded), prints an extra line naming that specifically and
 *       pointing at `rewrite-compiler-id` instead of leaving the reader to
 *       guess why an apparently-correct compiler still MISMATCHes.
 *
 *   rewrite-compiler-id <tor-dir> <new-compiler-id>
 *       Migration only: update JUST the compiler_id field of an existing
 *       manifest in place, keeping its tor_commit and configure_args_sha256.
 *       Refuses (manifest untouched) unless every recorded archive_sha256
 *       still matches the archive bytes on disk -- a rewrite never fixes a
 *       manifest whose archives are themselves suspect; that needs a real
 *       `make tor-full`, not a relabel.
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
#include "platform/file_sync.h"
#include "platform/path_replace.h"
#include "zsha256/zsha256.h"
#include "tor_compiler_id.h"

#if defined(_WIN32)
#include <direct.h>
#else
#define O_BINARY 0
#endif

#define TOR_PROVENANCE_NAME ".provenance"
#define FATAL_HANDLER_POLICY "owner-v1"
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
    int fatal_handler_policy_ok;
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
        "       %s check-legacy-policy-rebuild <tor-dir> <tor_commit> <compiler_id>\n"
        "       %s rewrite-compiler-id <tor-dir> <new-compiler-id>\n"
        "       %s check-compiler-results <positive-status> <negative-status> <positive-log> <negative-log>\n"
        "       %s --selftest\n",
        prog, prog, prog, prog, prog, prog);
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

enum { COMPILER_LOG_MAX = 65536 };

/* Build glue owns process execution. This native helper owns the verdict,
 * including refusal of setup failures and incomplete diagnostic evidence. */
static int compiler_log_read(const char *path, char log[COMPILER_LOG_MAX + 1])
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 1;
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    size_t n = fread(log, 1, COMPILER_LOG_MAX + 1, f);
    int failed = ferror(f);
    if (fclose(f) != 0) failed = 1;
    if (failed) return 1;
    if (n > COMPILER_LOG_MAX) return 2;
    if (memchr(log, '\0', n)) return 3;
    log[n] = '\0';
    return 0;
}

static const char *compiler_results_reason(unsigned positive, unsigned negative,
                                           const char *positive_log,
                                           const char *negative_log)
{
    if (positive != 0) return "positive compile failed";
    if (negative == 0) return "missing-header compile unexpectedly succeeded";
    if (negative >= 126) return "negative compile did not complete normally";
    char log[COMPILER_LOG_MAX + 1];
    int rc = compiler_log_read(positive_log, log);
    if (rc != 0) return "positive compiler log missing, unreadable, oversized, or invalid";
    rc = compiler_log_read(negative_log, log);
    if (rc != 0) return "negative compiler log missing, unreadable, oversized, or invalid";
    if (!strstr(log, "base/hex.h")) return "negative compile did not diagnose base/hex.h";
    return NULL;
}

static int compiler_status_parse(const char *text, unsigned *status)
{
    if (!text[0] || strspn(text, "0123456789") != strlen(text)) return 0;
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end || value > 255) return 0;
    *status = (unsigned)value;
    return 1;
}

static int cmd_check_compiler_results(const char *positive_text,
                                      const char *negative_text,
                                      const char *positive_log,
                                      const char *negative_log)
{
    unsigned positive, negative;
    if (!compiler_status_parse(positive_text, &positive) ||
        !compiler_status_parse(negative_text, &negative)) {
        fprintf(stderr, "tor-provenance: invalid compiler exit status\n");
        return 1;
    }
    const char *why = compiler_results_reason(positive, negative,
                                               positive_log, negative_log);
    if (why) {
        fprintf(stderr, "tor-provenance: compiler check refused: %s (positive=%u, negative=%u; logs %s, %s)\n",
                why, positive, negative, positive_log, negative_log);
        return 1;
    }
    puts("tor-provenance: required includes compile; omitting hex include fails on base/hex.h");
    return 0;
}

/* Hash one file's bytes with a fixed 64 KiB read buffer — no malloc. */
static int sha256_hex_of_file(const char *path, char out_hex[ZSHA256_HEX_LEN])
{
    int fd = open(path, O_RDONLY | O_BINARY);
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

static int validate_write_inputs(const char *tor_commit, const char *compiler_id,
                                 const char *configure_args_sha256)
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
    return 0;
}

/* Only an explicit producer may attest the embedding policy. A configure
 * digest identifies inputs but does not say whether those inputs are safe. */
static int embedded_config_without_backtrace(const char *tor_dir)
{
    char path[PATH_BUF_MAX];
    if (join_path(path, tor_dir, "orconfig.h") != 0)
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[LINE_BUF_MAX];
    int disabled = 0, enabled = 0;
    while (fgets(line, sizeof(line), f)) {
        const char *undefined = strstr(line, "#undef HAVE_BACKTRACE");
        if (undefined && (undefined[21] == ' ' || undefined[21] == '\n' ||
                          undefined[21] == '\r' || undefined[21] == '\0'))
            disabled = 1;
        char directive[32], name[64];
        if (sscanf(line, " #%31s %63s", directive, name) == 2 &&
            strcmp(directive, "define") == 0 &&
            strcmp(name, "HAVE_BACKTRACE") == 0)
            enabled = 1;
    }
    int unreadable = ferror(f);
    fclose(f);
    return disabled && !enabled && !unreadable;
}

static int validate_manifest_build(const char *tor_dir, const char *tor_commit,
                                   const char *compiler_id,
                                   const char *configure_args_sha256,
                                   int attest_configuration)
{
    if (attest_configuration && !embedded_config_without_backtrace(tor_dir)) {
        fprintf(stderr, "tor-provenance: write: generated orconfig.h must disable HAVE_BACKTRACE; rebuild with make tor-full\n");
        return 1;
    }
    if (validate_write_inputs(tor_commit, compiler_id, configure_args_sha256) != 0)
        return 1;
    return 0;
}

static int write_manifest(const char *tor_dir, const char *tor_commit,
                          const char *compiler_id, const char *configure_args_sha256,
                          int attest_configuration)
{
    if (validate_manifest_build(tor_dir, tor_commit, compiler_id,
                                configure_args_sha256, attest_configuration))
        return 1;
    char archive_hex[ARCHIVE_COUNT][ZSHA256_HEX_LEN];
    int failing = -1;
    if (hash_all_archives(tor_dir, archive_hex, &failing) != 0) {
        fprintf(stderr, "tor-provenance: write: could not hash archive %s/%s: %s\n",
                tor_dir, ARCHIVE_RELPATHS[failing], strerror(errno));
        return 1;
    }

    char content[LINE_BUF_MAX];
    int n = snprintf(content, sizeof content,
        "fatal_handler_policy=" FATAL_HANDLER_POLICY "\n"
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

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_BINARY, 0644);
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
    if (platform_file_sync(fd) != 0) {
        fprintf(stderr, "tor-provenance: write: fsync failed: %s\n", strerror(errno));
        close(fd);
        unlink(tmp_path);
        return 1;
    }
    close(fd);
    if (platform_path_replace(tmp_path, manifest_path) != 0) {
        fprintf(stderr, "tor-provenance: write: rename failed: %s\n", strerror(errno));
        unlink(tmp_path);
        return 1;
    }
    printf("tor-provenance: wrote %s\n", manifest_path);
    return 0;
}

static int cmd_write(const char *tor_dir, const char *tor_commit,
                      const char *compiler_id, const char *configure_args_sha256)
{
    return write_manifest(tor_dir, tor_commit, compiler_id,
                          configure_args_sha256, 1);
}

/* ---- check ------------------------------------------------------------ */

static void parse_fatal_policy(provenance_t *pv, const char *val)
{
    /* Duplicate policy lines cannot turn an old/wrong policy valid. */
    if (pv->fatal_handler_policy_ok != 0)
        pv->fatal_handler_policy_ok = -1;
    else
        pv->fatal_handler_policy_ok =
            strcmp(val, FATAL_HANDLER_POLICY) == 0 ? 1 : -1;
}

static void parse_archive_hashes(provenance_t *pv, const char *val)
{
    char a0[ZSHA256_HEX_LEN], a1[ZSHA256_HEX_LEN], a2[ZSHA256_HEX_LEN], a3[ZSHA256_HEX_LEN];
    if (sscanf(val, "%64s %64s %64s %64s", a0, a1, a2, a3) == 4) {
        snprintf(pv->archive_sha256[0], ZSHA256_HEX_LEN, "%s", a0);
        snprintf(pv->archive_sha256[1], ZSHA256_HEX_LEN, "%s", a1);
        snprintf(pv->archive_sha256[2], ZSHA256_HEX_LEN, "%s", a2);
        snprintf(pv->archive_sha256[3], ZSHA256_HEX_LEN, "%s", a3);
        pv->has_archive_sha256 = 1;
    }
}

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
        if (strcmp(key, "fatal_handler_policy") == 0) {
            parse_fatal_policy(pv, val);
        } else if (strcmp(key, "tor_commit") == 0) {

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
            parse_archive_hashes(pv, val);
        }
    }
    fclose(f);
    return 0;
}

/* Each check_*_field helper prints its own "tor-provenance: <field> ok|
 * MISMATCH ..." line(s) and returns 1 when the field checked out, 0 on any
 * mismatch -- split out of cmd_check() so that function's own branch count
 * does not grow every time a field gains one more diagnostic case. */

static int check_archive_sha256_field(const char *tor_dir, const provenance_t *pv)
{
    if (!pv->has_archive_sha256) {
        printf("tor-provenance: archive_sha256 MISMATCH manifest has no archive_sha256 line\n");
        return 0;
    }
    char actual[ARCHIVE_COUNT][ZSHA256_HEX_LEN];
    int failing = -1;
    if (hash_all_archives(tor_dir, actual, &failing) != 0) {
        printf("tor-provenance: archive_sha256 MISMATCH could not hash %s/%s: %s\n",
               tor_dir, ARCHIVE_RELPATHS[failing], strerror(errno));
        return 0;
    }
    int mismatch_index = -1;
    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        if (strcmp(actual[i], pv->archive_sha256[i]) != 0) {
            mismatch_index = i;
            break;
        }
    }
    if (mismatch_index < 0) {
        printf("tor-provenance: archive_sha256 ok\n");
        return 1;
    }
    printf("tor-provenance: archive_sha256 MISMATCH %s recorded=%s actual=%s\n",
           ARCHIVE_RELPATHS[mismatch_index],
           pv->archive_sha256[mismatch_index], actual[mismatch_index]);
    return 0;
}

static int check_tor_commit_field(const provenance_t *pv, const char *want_tor_commit)
{
    if (!pv->has_tor_commit) {
        printf("tor-provenance: tor_commit MISMATCH manifest has no tor_commit line\n");
        return 0;
    }
    if (strcmp(pv->tor_commit, want_tor_commit) != 0) {
        printf("tor-provenance: tor_commit MISMATCH recorded=%s actual=%s\n",
               pv->tor_commit, want_tor_commit);
        return 0;
    }
    printf("tor-provenance: tor_commit ok\n");
    return 1;
}

static int check_compiler_id_field(const provenance_t *pv, const char *want_compiler_id)
{
    if (!pv->has_compiler_id) {
        printf("tor-provenance: compiler_id MISMATCH manifest has no compiler_id line\n");
        return 0;
    }
    if (tor_compiler_ids_match(pv->compiler_id, want_compiler_id)) {
        printf("tor-provenance: compiler_id ok\n");
        return 1;
    }
    printf("tor-provenance: compiler_id MISMATCH recorded=%s actual=%s\n",
           pv->compiler_id, want_compiler_id);
    /* "sha256:" prefixes every bytes-based identity this program writes
     * today (build-epoch-key.sh's compiler-bytes-id mode). A manifest
     * without it predates that scheme -- point the reader at the one-time
     * in-place fix instead of leaving them to guess why an
     * apparently-correct compiler still MISMATCHes. */
    if (strncmp(pv->compiler_id, "sha256:", 7) != 0) {
        printf("tor-provenance: compiler_id MISMATCH manifest predates bytes-based compiler identity: run make tor-full (or `z23-tor-provenance rewrite-compiler-id <tor-dir> <new-compiler-id>` to update in place without rebuilding)\n");
    }
    return 0;
}

/* True when none of the four archives exist (a stub build: Tor was never
 * compiled here, so there is nothing to attest) -- as opposed to "the real
 * producer ran and left no manifest" (a MISMATCH some caller must rebuild).
 * Both look identical to parse_manifest(), so this must run first. */
static int no_archives_present(const char *tor_dir)
{
    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        char apath[PATH_BUF_MAX];
        struct stat ast;
        if (join_path(apath, tor_dir, ARCHIVE_RELPATHS[i]) == 0 &&
            stat(apath, &ast) == 0 && ast.st_size > 0) {
            return 0;
        }
    }
    return 1;
}

static int cmd_check(const char *tor_dir, const char *want_tor_commit, const char *want_compiler_id)
{
    char manifest_path[PATH_BUF_MAX];
    if (join_path(manifest_path, tor_dir, TOR_PROVENANCE_NAME) != 0) {
        fprintf(stderr, "tor-provenance: check: tor-dir path too long\n");
        return 1;
    }

    /* The signal for "stub build, nothing to attest" is the SAME one
     * tools/scripts/tor_archives_ready.sh's do_ready() reads to decide
     * whether to link the offline stub instead of real Tor: the ZCL_TOR
     * environment variable, "stub" vs. the default "full". */
    if (no_archives_present(tor_dir)) {
        const char *zcl_tor = getenv("ZCL_TOR");
        printf("tor-provenance: no Tor archives present (stub build) — nothing to attest\n");
        return (zcl_tor != NULL && strcmp(zcl_tor, "stub") == 0) ? 0 : 1;
    }

    provenance_t pv;
    if (parse_manifest(manifest_path, &pv) != 0) {
        printf("tor-provenance: manifest MISMATCH %s is missing\n", manifest_path);
        return 1;
    }

    int all_ok = 1;
    if (pv.fatal_handler_policy_ok != 1) {
        printf("tor-provenance: fatal_handler_policy MISMATCH missing or unsupported; rebuild with make tor-full\n");
        all_ok = 0;
    }


    /* archive_sha256 is always checked — it is the whole point. */
    if (!check_archive_sha256_field(tor_dir, &pv)) all_ok = 0;

    if (want_tor_commit && !check_tor_commit_field(&pv, want_tor_commit)) all_ok = 0;

    if (want_compiler_id && !check_compiler_id_field(&pv, want_compiler_id)) all_ok = 0;

    return all_ok ? 0 : 1;
}

static unsigned legacy_manifest_field(const char *key)
{
    if (strcmp(key, "tor_commit") == 0) return 1;
    if (strcmp(key, "compiler_id") == 0) return 2;
    if (strcmp(key, "configure_args_sha256") == 0) return 4;
    if (strcmp(key, "archive_sha256") == 0) return 8;
    return 0;
}

/* Only the four legacy keys may authorize migration; explicit policy,
 * unknown keys, duplicates and truncation refuse. Never writes a manifest. */
static int legacy_archive_text(const char *val)
{
    char hashes[ARCHIVE_COUNT][ZSHA256_HEX_LEN], extra;
    if (sscanf(val, "%64s %64s %64s %64s %c", hashes[0], hashes[1],
               hashes[2], hashes[3], &extra) != ARCHIVE_COUNT)
        return 0;
    for (int i = 0; i < ARCHIVE_COUNT; i++)
        if (!is_hex_string(hashes[i], ZSHA256_HEX_LEN - 1)) return 0;
    return 1;
}

/* Byte-aware bounded reader: never let NUL/control bytes hide a record
 * suffix from the text parser. Binary mode also forbids Windows text EOF. */
static int legacy_manifest_line(FILE *f, char *line, size_t cap)
{
    size_t used = 0;
    int byte;
    while ((byte = fgetc(f)) != EOF) {
        if (byte == '\n') {
            line[used] = '\0';
            return 1;
        }
        if ((byte < 32 && byte != '\r') || byte > 126 || used >= cap - 1)
            return -1;
        line[used++] = (char)byte;
    }
    if (ferror(f)) return -1;
    line[used] = '\0';
    return used != 0;
}

static int legacy_manifest_shape(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned seen = 0;
    char line[LINE_BUF_MAX];
    int valid = 1, status = 0;
    while ((status = legacy_manifest_line(f, line, sizeof(line))) > 0) {
        char *eq = strchr(line, '=');
        if (!eq) { valid = 0; break; }
        *eq = '\0';
        unsigned field = legacy_manifest_field(line);
        if (!field || (seen & field)) { valid = 0; break; }
        if (field == 8 && !legacy_archive_text(eq + 1)) { valid = 0; break; }
        seen |= field;
    }
    valid = valid && status == 0 && seen == 15;
    fclose(f);
    return valid;
}

static int cmd_check_legacy_rebuild(const char *dir, const char *pin,
                                   const char *compiler)
{
    char path[PATH_BUF_MAX];
    provenance_t pv;
    if (join_path(path, dir, TOR_PROVENANCE_NAME) != 0 ||
        !legacy_manifest_shape(path) || parse_manifest(path, &pv) != 0)
        return 1;
    if (validate_write_inputs(pv.tor_commit, pv.compiler_id,
                              pv.configure_args_sha256) != 0)
        return 1;
    if (!check_tor_commit_field(&pv, pin) ||
        !check_compiler_id_field(&pv, compiler) ||
        !check_archive_sha256_field(dir, &pv))
        return 1;
    printf("tor-provenance: intact legacy bundle eligible for rebuild only\n");
    return 0;
}

/* ---- rewrite-compiler-id -------------------------------------------
 * Migration for a manifest written under an older compiler-identity scheme
 * (or a manifest whose ambient recording drifted, e.g. the CPATH/PATH-bound
 * `compiler-id` this file used before compiler-bytes-id existed): update
 * ONLY the compiler_id field, in place, from the archives that are already
 * on disk. Refuses (leaves the manifest untouched) unless every recorded
 * archive_sha256 still matches the archive bytes on disk -- if it does not,
 * the archives themselves are suspect and no compiler-identity fix belongs
 * here; the caller needs a real rebuild (`make tor-full`), not a relabel.
 */
static int cmd_rewrite_compiler_id(const char *tor_dir, const char *new_compiler_id)
{
    char manifest_path[PATH_BUF_MAX];
    if (join_path(manifest_path, tor_dir, TOR_PROVENANCE_NAME) != 0) {
        fprintf(stderr, "tor-provenance: rewrite-compiler-id: tor-dir path too long\n");
        return 1;
    }

    provenance_t pv;
    if (parse_manifest(manifest_path, &pv) != 0) {
        fprintf(stderr, "tor-provenance: rewrite-compiler-id: %s is missing or unreadable\n",
                manifest_path);
        return 1;
    }
    /* Identity migration must never bless an old archive with a new policy. */
    if (pv.fatal_handler_policy_ok != 1) {
        fprintf(stderr, "tor-provenance: rewrite-compiler-id: missing or unsupported fatal-handler policy; rebuild with make tor-full\n");
        return 1;
    }
    if (!pv.has_tor_commit || !pv.has_configure_args_sha256 || !pv.has_archive_sha256) {

        fprintf(stderr, "tor-provenance: rewrite-compiler-id: manifest is incomplete; run 'make tor-full' to write a fresh one\n");
        return 1;
    }

    char actual[ARCHIVE_COUNT][ZSHA256_HEX_LEN];
    int failing = -1;
    if (hash_all_archives(tor_dir, actual, &failing) != 0) {
        fprintf(stderr, "tor-provenance: rewrite-compiler-id: could not hash %s/%s: %s\n",
                tor_dir, ARCHIVE_RELPATHS[failing], strerror(errno));
        return 1;
    }
    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        if (strcmp(actual[i], pv.archive_sha256[i]) != 0) {
            fprintf(stderr,
                "tor-provenance: rewrite-compiler-id: refusing -- %s does not match its recorded archive_sha256 (recorded=%s actual=%s); the archives are suspect, run 'make tor-full' to rebuild instead of relabeling\n",
                ARCHIVE_RELPATHS[i], pv.archive_sha256[i], actual[i]);
            return 1;
        }
    }

    /* Existing owner-v1 policy and every archive byte were verified above.
     * Preserve that attestation without requiring copied build headers.
     * This path cannot mint the policy on an old or unsupported manifest. */
    if (write_manifest(tor_dir, pv.tor_commit, new_compiler_id,
                        pv.configure_args_sha256, 0) != 0)
        return 1;
    printf("tor-provenance: rewrite-compiler-id: %s compiler_id updated (tor_commit, configure_args_sha256, and archive_sha256 unchanged)\n",
           manifest_path);
    return 0;
}

/* ---- selftest ----------------------------------------------------------
 * Fixture lives under $TMPDIR (default /tmp, same convention as every other
 * selftest in this tree — see tools/ship.sh, tools/scripts/tor_archives_ready.sh).
 */

static int write_fixture_archive(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
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

static int selftest_compiler_statuses(const char *positive, const char *negative)
{
    static const unsigned refused[][2] = {{1, 1}, {0, 0}, {0, 126}, {0, 127}, {0, 128}};
    if (compiler_results_reason(0, 1, positive, negative) != NULL) return 1;
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i)
        if (compiler_results_reason(refused[i][0], refused[i][1], positive, negative) == NULL)
            return 1;
    unsigned status;
    if (compiler_status_parse("256", &status) || compiler_status_parse("-1", &status) ||
        compiler_status_parse("1tail", &status)) return 1;
    return 0;
}

static int selftest_compiler_logs(const char *positive, const char *negative,
                                 const char *directory)
{
    if (compiler_results_reason(0, 1, directory, negative) == NULL ||
        compiler_results_reason(0, 1, positive, directory) == NULL) return 1;
    if (write_fixture_archive(negative, "unrelated compiler failure\n") != 0 ||
        compiler_results_reason(0, 1, positive, negative) == NULL) return 1;
    char oversized[COMPILER_LOG_MAX + 2];
    memset(oversized, 'x', sizeof(oversized) - 1);
    memcpy(oversized, "base/hex.h", sizeof("base/hex.h") - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    if (write_fixture_archive(negative, oversized) != 0 ||
        compiler_results_reason(0, 1, positive, negative) == NULL) return 1;
    if (unlink(negative) != 0 ||
        compiler_results_reason(0, 1, positive, negative) == NULL) return 1;
    if (unlink(positive) != 0 ||
        compiler_results_reason(0, 1, positive, negative) == NULL) return 1;
    return 0;
}

static int selftest_compiler_results(const char *base)
{
    char positive[PATH_BUF_MAX], negative[PATH_BUF_MAX];
    if (join_path(positive, base, "compiler-positive.log") != 0 ||
        join_path(negative, base, "compiler-negative.log") != 0) return 1;
    int rc = write_fixture_archive(positive, "") ||
             write_fixture_archive(negative, "fatal error: base/hex.h: missing\n") ||
             selftest_compiler_statuses(positive, negative) ||
             selftest_compiler_logs(positive, negative, base);
    unlink(positive);
    unlink(negative);
    if (rc) fprintf(stderr, "tor-provenance: selftest FAILED — compiler evidence judgment\n");
    return rc;
}

static int mkdir_p_fixed(const char *path)
{
    /* Fixed, known-shape fixture directories only — no generic recursive
     * mkdir -p needed. Caller passes exact paths one level at a time. */
#if defined(_WIN32)
    if (_mkdir(path) != 0 && errno != EEXIST) return -1;
#else
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
#endif
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
    join_path(path, base, "orconfig.h");
    unlink(path);
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
#if defined(_WIN32)
    int devnull = open("NUL", O_WRONLY);
#else
    int devnull = open("/dev/null", O_WRONLY);
#endif
    if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
    int rc = cmd_check(tor_dir, want_commit, want_cc);
    fflush(stdout);
    if (saved >= 0) { dup2(saved, STDOUT_FILENO); close(saved); }
    return rc;
}

static int selftest_create_directories(const char *base)
{
    if (mkdir_p_fixed(base) != 0) {
        fprintf(stderr, "tor-provenance: selftest: could not create fixture dir %s: %s\n", base, strerror(errno));
        return 1;
    }
    static const char *const directories[] = {
        "src", "src/ext", "src/ext/ed25519", "src/ext/ed25519/donna",
        "src/ext/ed25519/ref10", "src/ext/keccak-tiny"
    };
    for (size_t i = 0; i < sizeof directories / sizeof directories[0]; ++i) {
        char path[PATH_BUF_MAX];
        if (join_path(path, base, directories[i]) || mkdir_p_fixed(path)) {
            fprintf(stderr, "tor-provenance: selftest: could not create fixture directory %s/%s\n",
                    base, directories[i]);
            return 1;
        }
    }
    return 0;
}

static int selftest_create_archives(const char *base)

{
    char config[PATH_BUF_MAX];
    if (join_path(config, base, "orconfig.h") != 0 ||
        write_fixture_archive(config, "/* #undef HAVE_BACKTRACE */\n") != 0)
        return 1;
    for (int i = 0; i < ARCHIVE_COUNT; i++) {
        char path[PATH_BUF_MAX];
        if (join_path(path, base, ARCHIVE_RELPATHS[i]) != 0) {
            fprintf(stderr, "tor-provenance: selftest: archive path too long under %s\n", base);
            return 1;
        }
        char content[128];
        snprintf(content, sizeof content, "fixture tor archive bytes %d\r\n\x1a tail\n", i);
        if (write_fixture_archive(path, content) != 0) {
            fprintf(stderr, "tor-provenance: selftest: could not write fixture archive %s\n", path);
            return 1;
        }
        char expected[ZSHA256_HEX_LEN], actual[ZSHA256_HEX_LEN];
        zsha256_hex(content, strlen(content), expected);
        if (sha256_hex_of_file(path, actual) != 0 || strcmp(actual, expected) != 0) {
            fprintf(stderr, "tor-provenance: selftest FAILED — archive bytes changed in file I/O\n");
            selftest_rmdir_tree(base);
            return 1;
        }
    }
    return 0;
}

static int selftest_prepare(const char *base)
{
    return selftest_create_directories(base) || selftest_create_archives(base) ||
           selftest_compiler_results(base);
}

/* Old and wrong policy manifests must fail both readiness and identity-only
 * migration, and migration must leave every manifest byte unchanged. */
static int selftest_legacy_mutations(const char *base, const char *path,
                                    const char *legacy, const provenance_t *pv)
{
    static const char *const additions[] = {
        "unknown=value\n", "tor_commit=duplicate\n",
        "fatal_handler_policy=wrong\n", "fatal_handler_policy=owner-v1\n"
    };
    char changed[LINE_BUF_MAX];
    for (size_t i = 0; i < sizeof(additions) / sizeof(additions[0]); i++) {
        int n = snprintf(changed, sizeof(changed), "%s%s", legacy, additions[i]);
        if (n <= 0 || (size_t)n >= sizeof(changed) ||
            write_fixture_archive(path, changed) != 0 ||
            cmd_check_legacy_rebuild(base, pv->tor_commit, pv->compiler_id) == 0)
            return 1;
    }
    return write_fixture_archive(path, legacy) != 0;
}

static int selftest_legacy_integrity(const char *base, const provenance_t *pv)
{
    if (cmd_check_legacy_rebuild(base, "0000000000000000000000000000000000000000",
                                pv->compiler_id) == 0 ||
        cmd_check_legacy_rebuild(base, pv->tor_commit, "wrong-compiler") == 0)
        return 1;
    char path[PATH_BUF_MAX], first;
    if (join_path(path, base, ARCHIVE_RELPATHS[0]) != 0) return 1;
    int fd = open(path, O_RDWR | O_BINARY);
    if (fd < 0) return 1;
    if (read(fd, &first, 1) != 1) { close(fd); return 1; }
    char altered = first ^ 1;
    if (lseek(fd, 0, SEEK_SET) != 0 || write(fd, &altered, 1) != 1) {
        close(fd); return 1;
    }
    int refused = cmd_check_legacy_rebuild(base, pv->tor_commit, pv->compiler_id);
    int restored = lseek(fd, 0, SEEK_SET) == 0 && write(fd, &first, 1) == 1;
    close(fd);
    return !refused || !restored;
}

static int selftest_read_manifest(const char *path, char *text, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    size_t bytes = fread(text, 1, cap - 1, f);
    int bad = ferror(f) || !feof(f);
    fclose(f);
    text[bytes] = '\0';
    return bad;
}

static int selftest_binary_legacy(const char *base, const char *path,
                                 const char *legacy, const provenance_t *pv)
{
    const char *end = strchr(legacy, '\n');
    if (!end) return 1;
    static const char hidden[] = "\0fatal_handler_policy=wrong";
    size_t prefix = (size_t)(end - legacy), suffix = strlen(end);
    FILE *f = fopen(path, "wb");
    if (!f) return 1;
    int written = fwrite(legacy, 1, prefix, f) == prefix &&
                  fwrite(hidden, 1, sizeof(hidden) - 1, f) == sizeof(hidden) - 1 &&
                  fwrite(end, 1, suffix, f) == suffix;
    int closed = fclose(f);
    if (!written || closed != 0) return 1;
    char before[ZSHA256_HEX_LEN], after[ZSHA256_HEX_LEN];
    if (sha256_hex_of_file(path, before) != 0 ||
        cmd_check_legacy_rebuild(base, pv->tor_commit, pv->compiler_id) == 0 ||
        sha256_hex_of_file(path, after) != 0 || strcmp(before, after) != 0)
        return 1;
    return write_fixture_archive(path, legacy) != 0;
}

static int selftest_legacy_case(const char *base, const char *path,
                               const char *legacy, const provenance_t *pv,
                               int wrong)
{
    if ((cmd_check_legacy_rebuild(base, pv->tor_commit, pv->compiler_id) == 0) !=
        (wrong == 0)) return 1;
    if (!wrong && quiet_check(base, NULL, NULL) == 0) return 1;
    if (!wrong && (selftest_legacy_mutations(base, path, legacy, pv) != 0 ||
                   selftest_legacy_integrity(base, pv) != 0)) return 1;
    if (!wrong && selftest_binary_legacy(base, path, legacy, pv) != 0) return 1;
    return 0;
}

static int selftest_fatal_policy(const char *base)
{
    char path[PATH_BUF_MAX], original[LINE_BUF_MAX];
    if (join_path(path, base, TOR_PROVENANCE_NAME) != 0 ||
        selftest_read_manifest(path, original, sizeof(original)) != 0)
        return 1;
    const char *line = "fatal_handler_policy=" FATAL_HANDLER_POLICY "\n";
    size_t policy_bytes = strlen(line);
    if (strncmp(original, line, policy_bytes) != 0)
        return 1;
    provenance_t pv;
    if (parse_manifest(path, &pv) != 0) return 1;
    for (int wrong = 0; wrong < 2; wrong++) {
        char mutant[LINE_BUF_MAX];
        snprintf(mutant, sizeof(mutant), "%s", original);
        if (wrong)
            mutant[strlen("fatal_handler_policy=")] = 'X';
        else
            memmove(mutant, mutant + policy_bytes,
                    strlen(mutant + policy_bytes) + 1);
        char before[ZSHA256_HEX_LEN], after[ZSHA256_HEX_LEN];
        if (write_fixture_archive(path, mutant) != 0 ||
            sha256_hex_of_file(path, before) != 0 ||
            quiet_check(base, NULL, NULL) == 0 ||
            cmd_rewrite_compiler_id(base, "replacement-compiler") == 0 ||
            sha256_hex_of_file(path, after) != 0 || strcmp(before, after) != 0)
            return 1;
        if (selftest_legacy_case(base, path, mutant, &pv, wrong) != 0) return 1;
    }
    return write_fixture_archive(path, original) != 0;
}

static int selftest_replace_manifest(const char *base, const char *commit,
                                      const char *first, const char *second,
                                      const char *configure_sha)
{
    if (cmd_write(base, commit, first, configure_sha) != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — write did not succeed\n");
        return 1;
    }
    if (cmd_write(base, commit, second, configure_sha) != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — could not replace manifest\n");
        return 1;
    }
    if (quiet_check(base, commit, first) == 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — replacement retained old identity\n");
        return 1;
    }
    if (quiet_check(base, commit, second) != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — check did not accept a just-written manifest\n");
        return 1;
    }
    return 0;
}

static int selftest_copied_policy(const char *base, const char *commit,
                                  const char *first, const char *second,
                                  const char *configure_sha)
{
    char config[PATH_BUF_MAX];
    if (join_path(config, base, "orconfig.h") != 0 || unlink(config) != 0 ||
        cmd_write(base, commit, second, configure_sha) == 0 ||
        cmd_rewrite_compiler_id(base, first) != 0 ||
        quiet_check(base, commit, first) != 0 ||
        cmd_rewrite_compiler_id(base, second) != 0 ||
        quiet_check(base, commit, second) != 0 ||
        write_fixture_archive(config, "/* #undef HAVE_BACKTRACE */\n") != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — verified copied policy migration\n");
        return 1;
    }
    return 0;
}

static int selftest_enabled_backtrace(const char *base, const char *commit,
                                      const char *compiler,
                                      const char *configure_sha)
{
    char config[PATH_BUF_MAX];
    if (join_path(config, base, "orconfig.h") != 0 ||
        write_fixture_archive(config, "#define HAVE_BACKTRACE 1\n") != 0 ||
        cmd_write(base, commit, compiler, configure_sha) == 0 ||
        write_fixture_archive(config, "/* #undef HAVE_BACKTRACE */\n") != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — enabled backtrace was attested\n");
        return 1;
    }
    return 0;
}

static int run_selftest(void)
{
    const char *tmpdir = getenv("TMPDIR");
#if defined(_WIN32)
    if (!tmpdir || !*tmpdir) tmpdir = getenv("TEMP");
    if (!tmpdir || !*tmpdir) tmpdir = ".";
#else
    if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
#endif

    char base[PATH_BUF_MAX];
    snprintf(base, sizeof base, "%s/z23-tor-provenance-selftest.%ld", tmpdir, (long)getpid());
    selftest_rmdir_tree(base); /* clean any stale run with the same pid, best effort */
    if (selftest_prepare(base)) {
        selftest_rmdir_tree(base);
        return 1;
    }

    const char *fake_commit_ok = "0123456789abcdef0123456789abcdef012345aa"; /* 40 hex chars */
    const char *first_compiler_id = "cc (selftest) 1.0";
    const char *fake_compiler_id = "cc (selftest) 2.0";
    /* 64 hex chars: "0123456789abcdef" repeated 4 times. */
    const char *fake_configure_sha =
        "0123456789abcdef" "0123456789abcdef" "0123456789abcdef" "0123456789abcdef";

    int rc = 1;
    /* Rebuilding Tor must atomically replace an existing manifest too. */
    if (selftest_replace_manifest(base, fake_commit_ok, first_compiler_id,
                                  fake_compiler_id, fake_configure_sha))
        goto out;

    if (selftest_fatal_policy(base) != 0) {
        fprintf(stderr, "tor-provenance: selftest FAILED — unsafe policy accepted or upgraded\n");
        goto out;
    }

    /* A copied verified bundle may carry no generated build headers.
     * Identity-only migration preserves policy rather than re-attesting it. */
    if (selftest_copied_policy(base, fake_commit_ok, first_compiler_id,
                               fake_compiler_id, fake_configure_sha))
        goto out;
    if (selftest_enabled_backtrace(base, fake_commit_ok, fake_compiler_id,
                                   fake_configure_sha))
        goto out;

    /* Flip one byte in one archive: check must now MISMATCH. */

    {
        char path[PATH_BUF_MAX];
        join_path(path, base, ARCHIVE_RELPATHS[1]);
        int fd = open(path, O_RDWR | O_BINARY);
        if (fd < 0) {
            fprintf(stderr, "tor-provenance: selftest FAILED — could not reopen %s to corrupt it\n", path);
            goto out;
        }
        char c;
        if (read(fd, &c, 1) != 1) { close(fd); goto out; }
        c ^= 0x01;
        if (lseek(fd, 0, SEEK_SET) != 0 || write(fd, &c, 1) != 1) { close(fd); goto out; }
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

/* Parses `check <tor-dir> [--tor-commit <hex>] [--compiler-id <id>]`'s
 * argv tail out of main() so main()'s own branch count stays under the
 * complexity cap regardless of how many flags `check` grows. */
static int run_check_command(const char *prog, int argc, char **argv)
{
    if (argc < 3) die_usage(prog);
    const char *tor_dir = argv[2];
    const char *want_tor_commit = NULL;
    const char *want_compiler_id = NULL;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--tor-commit") == 0 && i + 1 < argc) {
            want_tor_commit = argv[++i];
        } else if (strcmp(argv[i], "--compiler-id") == 0 && i + 1 < argc) {
            want_compiler_id = argv[++i];
        } else {
            die_usage(prog);
        }
    }
    return cmd_check(tor_dir, want_tor_commit, want_compiler_id);
}

int main(int argc, char **argv)
{
    if (argc < 2) die_usage(argv[0]);

    if (strcmp(argv[1], "--selftest") == 0) {
        return run_selftest();
    }

    if (strcmp(argv[1], "check-compiler-results") == 0) {
        if (argc != 6) die_usage(argv[0]);
        return cmd_check_compiler_results(argv[2], argv[3], argv[4], argv[5]);
    }

    if (strcmp(argv[1], "check-legacy-policy-rebuild") == 0) {
        if (argc != 5) die_usage(argv[0]);
        return cmd_check_legacy_rebuild(argv[2], argv[3], argv[4]);
    }

    if (strcmp(argv[1], "write") == 0) {
        if (argc != 6) die_usage(argv[0]);
        return cmd_write(argv[2], argv[3], argv[4], argv[5]);
    }

    if (strcmp(argv[1], "rewrite-compiler-id") == 0) {
        if (argc != 4) die_usage(argv[0]);
        return cmd_rewrite_compiler_id(argv[2], argv[3]);
    }

    if (strcmp(argv[1], "check") == 0) {
        return run_check_command(argv[0], argc, argv);
    }

    die_usage(argv[0]);
    return 2;
}
