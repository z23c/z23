/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Plumbing shared by every check in the `make_lint_gates` self-test group:
 * file read/write/copy, directory walks over .c and .h, and planting and
 * removing the transient fixtures. The fork+exec wrappers that run a gate
 * script live in the sibling lint_gate_exec.c — a group whose closure reaches
 * this file only for the utilities below runs no out-of-closure script, and
 * the testcache exec rail relies on that separation.
 *
 * Nothing here asserts. The checks that do live in the sibling
 * lint_gate_*.c files; see lint_gate_selftests.h for the map. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; on
 * _WIN32 every helper compiles out and the group entry points report a skip. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

/* Per-process scratch path under the (possibly sandboxed) repo root. Names
 * are pid-unique because real-worktree checks run concurrently; everything
 * lands under ./test-tmp/, which check-no-stray-root-files requires. */
int repo_path_pid(char *out, size_t outsz, const char *rel_prefix,
                  const char *suffix)
{
    if (!rel_prefix || !suffix) return -1;
    char rel[256];
    if (snprintf(rel, sizeof(rel), "%s_%ld%s", rel_prefix, (long)getpid(),
                 suffix) >= (int)sizeof(rel))
        return -1;
    return repo_path(out, outsz, rel);
}

/* The pid-unique stdout+stderr sink every gate-script run redirects into. */
int lint_gate_out_path(char *out, size_t outsz)
{
    return repo_path_pid(out, outsz, "test-tmp/zcl_gate_lint", ".out");
}

int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) {
        fprintf(stderr, "copy_file: fopen(%s) failed: %s\n",
                src, strerror(errno));
        return -1;
    }
    FILE *out = fopen(dst, "wb");
    if (!out) {
        fprintf(stderr, "copy_file: fopen(%s) failed: %s\n",
                dst, strerror(errno));
        fclose(in);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fprintf(stderr, "copy_file: fwrite failed: %s\n",
                    strerror(errno));
            fclose(in); fclose(out);
            return -1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

/* Replace the first occurrence of `needle` in `hay` with `repl`, returning a
 * freshly malloc'd buffer (caller frees) or NULL if `needle` is absent or on
 * allocation failure. Test-only string-fixture helper (no production callers,
 * so plain malloc — test/ files are exempt from check-raw-malloc). */
char *str_replace_once(const char *hay, const char *needle,
                              const char *repl)
{
    const char *pos = strstr(hay, needle);
    if (!pos) return NULL;
    size_t pre = (size_t)(pos - hay);
    size_t hay_len = strlen(hay);
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(repl);
    size_t out_len = hay_len - needle_len + repl_len;
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    memcpy(out, hay, pre);
    memcpy(out + pre, repl, repl_len);
    memcpy(out + pre + repl_len, pos + needle_len, hay_len - pre - needle_len);
    out[out_len] = '\0';
    return out;
}

bool has_c_suffix(const char *path)
{
    size_t len = strlen(path);
    return len >= 2 && strcmp(path + len - 2, ".c") == 0;
}

bool has_ch_suffix(const char *path)
{
    size_t len = strlen(path);
    return len >= 2 &&
           (strcmp(path + len - 2, ".c") == 0 ||
            strcmp(path + len - 2, ".h") == 0);
}

int read_entire_file(const char *path, char **out_buf)
{
    *out_buf = NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *buf = calloc((size_t)len + 1, 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *out_buf = buf;
    return 0;
}

size_t count_occurrences(const char *haystack, const char *needle)
{
    size_t step = strlen(needle);
    if (step == 0) return 0;
    size_t n = 0;
    for (const char *p = strstr(haystack, needle); p;
         p = strstr(p + step, needle))
        n++;
    return n;
}

int walk_c_files(const char *dirpath,
                        int (*check_file)(const char *path))
{
    DIR *dir = opendir(dirpath);
    if (!dir) return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name) >=
            (int)sizeof(path)) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            int rc = walk_c_files(path, check_file);
            if (rc != 0) {
                closedir(dir);
                return rc;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode) || !has_c_suffix(path))
            continue;

        int rc = check_file(path);
        if (rc != 0) {
            closedir(dir);
            return rc;
        }
    }

    closedir(dir);
    return 0;
}

int walk_ch_files(const char *dirpath,
                         int (*check_file)(const char *path))
{
    DIR *dir = opendir(dirpath);
    if (!dir) return -1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name) >=
            (int)sizeof(path)) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (stat(path, &st) != 0) {
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            int rc = walk_ch_files(path, check_file);
            if (rc != 0) {
                closedir(dir);
                return rc;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode) || !has_ch_suffix(path))
            continue;

        int rc = check_file(path);
        if (rc != 0) {
            closedir(dir);
            return rc;
        }
    }

    closedir(dir);
    return 0;
}

int write_file(const char *path, const char *contents)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t n = strlen(contents);
    int ok = fwrite(contents, 1, n, fp) == n;
    fclose(fp);
    return ok ? 0 : -1;
}

int plant_oversized_file(const char *rel, int n_lines)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), rel) != 0) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    for (int i = 0; i < n_lines; i++)
        fputs("// fixture line\n", fp);
    fclose(fp);
    return 0;
}

void unlink_rel(const char *rel)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), rel) == 0)
        (void)unlink(path);
}

/* Write a single-function .c fixture whose gate-measured length (closing
 * brace line minus signature line) is exactly `target_len`, optionally
 * tagged `// long-function-ok:<tag>` on the signature line. Mirrors
 * plant_oversized_file's direct-fopen approach (no giant string buffer). */
int plant_long_function_file(const char *rel, const char *func_name,
                                    int target_len, const char *tag)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), rel) != 0) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    if (tag)
        fprintf(fp, "void %s(void) // long-function-ok:%s\n", func_name, tag);
    else
        fprintf(fp, "void %s(void)\n", func_name);
    fprintf(fp, "{\n");
    int body_lines = target_len - 2;
    if (body_lines < 1) body_lines = 1;
    for (int i = 0; i < body_lines; i++)
        fprintf(fp, "    (void)0; /* fixture line %d */\n", i);
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

/* META-GATE: a gate whose scan set is empty must fail loud (exit 2), never
 * report a hollow clean pass (docs/dev/lint-gate-hollowness-audit.md).
 * One gate's check: an empty scan dir via its ZCL_*_SCAN_* override must exit
 * 2; with no override, exit 0. One TEST block per call (the TEST macro's
 * `_test_next` label is function-scoped). Returns 0 on pass, nonzero on
 * failure. */
int meta_gate_empty_scan_trips(const char *script_rel,
                                      const char *env_name,
                                      const char *empty_value)
{
    int failures = 0;
    int trip_rc = run_gate_script_with_env(script_rel, env_name, empty_value);
    int green_rc = run_gate_script(script_rel, NULL);
    TEST("[lint-gate] META: empty/drifted scan trips gate exit 2, real tree passes") {
        /* Empty scan set MUST be exit 2 (fail-LOUD), never 0 (hollow) and
         * never 1 (a violation it could not actually have seen). */
        if (trip_rc != 2) {
            fprintf(stderr,
                    "[lint-gate] %s with empty %s: expected exit 2, got %d "
                    "(hollow gate?)\n", script_rel, env_name, trip_rc);
        }
        ASSERT(trip_rc == 2);
        if (green_rc != 0) {
            fprintf(stderr,
                    "[lint-gate] %s with no override: expected exit 0, got %d\n",
                    script_rel, green_rc);
        }
        ASSERT(green_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

void unlink_lint_fixtures(void)
{
    const char *fixtures[] = {
        FIXTURE_DST_REL,
        NODE_DB_EXEC_FIXTURE_DST_REL,
        COINS_FIXTURE_DST_REL,
        OBS_FIXTURE_DST_REL,
        OBS_OK_FIXTURE_DST_REL,
        RAW_MALLOC_FIXTURE_DST_REL,
        RAW_MALLOC_OK_FIXTURE_DST_REL,
        E1_BUFFER_FIXTURE_DST,
        E1_OVER_LIMIT_FIXTURE_DST,
        E10_SHAPE_FIXTURE_DST,
        E10_SQL_FIXTURE_DST,
        E10_SQL_SERVICE_FIXTURE_DST,
        MODEL_AR_FIXTURE_DST,
        E2_FIXTURE_DST,
        E3_FIXTURE_DST,
        E4_FIXTURE_DST,
        DOMAIN_PURITY_FIXTURE_DST,
        E5_FIXTURE_DST,
        E6_FIXTURE_DST,
        E7_FIXTURE_DST,
        E12_FIXTURE_DST,
        SUPDOM_BAD_WORKER_REL,
        SUPDOM_OK_WORKER_REL,
        CONSENSUS_PARITY_FIXTURE_DST,
        SILENT_BOOL_FIXTURE_DST,
    };

    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        char path[PATH_MAX];
        if (repo_path(path, sizeof(path), fixtures[i]) == 0)
            (void)unlink(path);
    }
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_hlp_unit;

#endif /* ZCL_TESTING */
