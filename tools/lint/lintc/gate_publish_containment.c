/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-stable-publish-contained
 * Single-gate family file: a project-wide textual containment tripwire,
 * not a per-file shrinking-floor ratchet (that shape is this job's
 * sibling file, gate_service_result_convergence.c). Per the standing
 * 2026-09-06 single-gate-file placement ruling already used by
 * gate_framework_shape.c and gate_zclassicd_reach.c (each holds ONE
 * gate, each says so in its own header), this port lands in its own
 * file rather than being folded into either of those or any other.
 *
 * Byte-parity C23 port of tools/scripts/check_stable_publish_containment.sh
 * (Phase-0 containment: no production path may create a network release
 * until immutable quality/release evidence and the signed stable publisher
 * exist). A textual tripwire, not a parser; the actual stable entrypoints
 * (tools/release.sh, the `release:`/`bootstrap-publish:` Makefile targets)
 * are separately asserted hard-contained by known_entrypoints_contained().
 *
 * Scan roots (existence-gated): Makefile Dockerfile Jenkinsfile Justfile
 * Taskfile core engine contexts cognition platform tools .github deploy.
 * File filter (recursive): Makefile, *.mk, *.sh, *.c, *.h, *.yml, *.yaml,
 * *.json, *.toml, Dockerfile*, Jenkinsfile*, Justfile, Taskfile,
 * *.service, *.timer — pruning build/vendor/test-tmp.
 *
 * PATTERN_PUBLISH (a real release/upload primitive) vs. PATTERN_TRANSFER
 * (host-to-host transfer — copying a file to a machine the operator owns
 * is not publishing a release). TRANSFER_EXEMPT_REL (tools/ship.sh) is
 * exempt from PATTERN_TRANSFER only — a line there that also matches
 * PATTERN_PUBLISH still trips.
 *
 * Self-exclusion: the shell excluded its own script text (SELF_REL) — its
 * pattern definitions/--self-test fixtures are full of literal matches.
 * This port's fixtures live in THIS .c file instead, so
 * gate_publish_containment.c joins the shim script on the self-exclusion
 * list (neither is scanned at all), or the gate would trip on its own
 * test fixtures the moment this port lands.
 *
 * Exit codes, preserved rather than collapsed to the runtime's usual
 * UNPROVEN-2 convention: 3 is FATAL (the scan itself could not be
 * trusted); 2 is a clean scan with a live containment violation or a
 * structural known-entrypoints gap; 0 success.
 *
 * ZCL_CONTAINMENT_GREP: the shell let a test point this at a
 * missing/unexecutable path to prove a broken scanner fails CLOSED. This
 * runtime has no external grep to override — the scanner is the linked-in
 * regex engine, always available — so the seam keeps its name but changes
 * meaning: set and non-empty, it must name an executable path or the
 * gate FATALs exit 3 before scanning; unset, no effect.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static const char k_pgc_name[] = "check_stable_publish_containment";

static const char *const k_pgc_self_rel[] = {
    "tools/scripts/check_stable_publish_containment.sh",
    "tools/lint/lintc/gate_publish_containment.c",
};
enum { PGC_N_SELF = (int)(sizeof k_pgc_self_rel / sizeof k_pgc_self_rel[0]) };

static const char k_pgc_transfer_exempt[] = "tools/ship.sh";

static const char *const k_pgc_roots[] = {
    "Makefile", "Dockerfile", "Jenkinsfile", "Justfile", "Taskfile",
    "core", "engine", "contexts", "cognition", "platform", "tools",
    ".github", "deploy",
};
enum { PGC_N_ROOTS = (int)(sizeof k_pgc_roots / sizeof k_pgc_roots[0]) };

static const char k_pgc_pattern_publish[] =
    "gh[[:space:]]+release[[:space:]]+(create|upload)"
    "|\"gh\"[[:space:]]*,[[:space:]]*\"release\"[[:space:]]*,[[:space:]]*"
    "\"(create|upload)\""
    "|gh[[:space:]]+api.*(/releases|uploads\\.github\\.com)"
    "|hub[[:space:]]+release[[:space:]]+(create|edit)"
    "|glab[[:space:]]+release"
    "|git[[:space:]]+push.*(--tags|refs/tags|\\$TAG)"
    "|actions/(create-release|upload-release-asset)"
    "|softprops/action-gh-release"
    "|ncipollo/release-action"
    "|uploads\\.github\\.com/[^[:space:]]*/releases"
    "|aws[[:space:]]+s3[[:space:]]+(cp|sync)"
    "|gsutil[[:space:]]+(cp|rsync)"
    "|python(.*)-m[[:space:]]+twine[[:space:]]+upload"
    "|curl.*(--upload-file|-T[[:space:]]|-X[[:space:]]*(POST|PUT)"
    "|--request[[:space:]]*(POST|PUT)).*(release|upload|artifact|s3|gitlab)";

static const char k_pgc_pattern_transfer[] =
    "scp[[:space:]].+[^[:space:]]:[^[:space:]]"
    "|rsync[[:space:]].+[^[:space:]]:[^[:space:]]";

enum { PGC_LINE = 4096, PGC_PATH = 4096, PGC_MSG = 512 };

struct pgc_list { char **v; size_t n, cap; };

struct pgc_acc {
    const regex_t *combined, *publish;
    struct pgc_list hits;
    int fatal_rc;
    char fatal_msg[PGC_MSG];
};

static regex_t g_pgc_combined, g_pgc_publish;
static int g_pgc_re_ok;

static int pgc_regex_ensure(void)
{
    if (g_pgc_re_ok)
        return 0;
    int cr = reg_fail(&g_pgc_publish,
                      regcomp(&g_pgc_publish, k_pgc_pattern_publish,
                              REG_EXTENDED));
    if (cr)
        return cr;
    static char combined[sizeof k_pgc_pattern_publish
                         + sizeof k_pgc_pattern_transfer + 2];
    if (ovf(snprintf(combined, sizeof combined, "%s|%s",
                     k_pgc_pattern_publish, k_pgc_pattern_transfer),
            sizeof combined)) {
        regfree(&g_pgc_publish);
        return 2;
    }
    cr = reg_fail(&g_pgc_combined, regcomp(&g_pgc_combined, combined,
                                           REG_EXTENDED));
    if (cr) {
        regfree(&g_pgc_publish);
        return cr;
    }
    g_pgc_re_ok = 1;
    return 0;
}

static void pgc_regex_drop(void)
{
    if (!g_pgc_re_ok)
        return;
    drop2(&g_pgc_combined, &g_pgc_publish);
    g_pgc_re_ok = 0;
}

/* The hit list: a heap-owned "path:lineno:body" string per surviving match,
 * mirroring the shell's filtered grep -rEn lines. */
static int pgc_push(struct pgc_list *l, const char *s)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 64;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    char *copy = strdup(s); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    l->v[l->n++] = copy;
    return 0;
}

static void pgc_free(struct pgc_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

/* Sets a->fatal_rc = 3 and formats a->fatal_msg; every FATAL exit path
 * (missing scanner, no scannable roots, an unopenable/unreadable scanned
 * file or directory) shares this one formatter. */
static int pgc_fatal(struct pgc_acc *a, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->fatal_msg, sizeof a->fatal_msg, fmt, ap);
    va_end(ap);
    a->fatal_rc = 3;
    return 3;
}

static int pgc_resolve_scanner(struct pgc_acc *a)
{
    const char *ov = getenv("ZCL_CONTAINMENT_GREP");
    if (ov && ov[0] && access(ov, X_OK) != 0)
        return pgc_fatal(a, "FAIL: stable-publish containment cannot scan "
                         "(grep missing/unexecutable)\n");
    return 0;
}

static int pgc_excluded_dir(const char *name)
{
    return strcmp(name, "build") == 0 || strcmp(name, "vendor") == 0
        || strcmp(name, "test-tmp") == 0;
}

static int pgc_suffix_is(const char *name, size_t nl, const char *suf)
{
    size_t sl = strlen(suf);
    return nl >= sl && strcmp(name + nl - sl, suf) == 0;
}

static int pgc_matches_glob(const char *name)
{
    if (strcmp(name, "Makefile") == 0 || strcmp(name, "Justfile") == 0
        || strcmp(name, "Taskfile") == 0)
        return 1;
    if (strncmp(name, "Dockerfile", 10) == 0
        || strncmp(name, "Jenkinsfile", 11) == 0)
        return 1;
    static const char *const sufs[] = {
        ".mk", ".sh", ".c", ".h", ".yml", ".yaml", ".json", ".toml",
        ".service", ".timer",
    };
    size_t nl = strlen(name);
    for (size_t i = 0; i < sizeof sufs / sizeof sufs[0]; i++)
        if (pgc_suffix_is(name, nl, sufs[i]))
            return 1;
    return 0;
}

static int pgc_is_self(const char *rel)
{
    for (int i = 0; i < PGC_N_SELF; i++)
        if (strcmp(rel, k_pgc_self_rel[i]) == 0)
            return 1;
    return 0;
}

static int pgc_record_hit(struct pgc_acc *a, const char *rel, int lineno,
                          const char *body)
{
    char rec[PGC_LINE + PGC_PATH];
    if (ovf(snprintf(rec, sizeof rec, "%s:%d:%s", rel, lineno, body),
            sizeof rec))
        return 2;
    return pgc_push(&a->hits, rec);
}

static int pgc_scan_line(struct pgc_acc *a, const char *rel, int lineno,
                         char *line)
{
    size_t n = strlen(line);
    if (n > 0 && line[n - 1] == '\n')
        line[n - 1] = '\0';
    if (regexec(a->combined, line, 0, NULL, 0) != 0)
        return 0;
    if (strcmp(rel, k_pgc_transfer_exempt) == 0
        && regexec(a->publish, line, 0, NULL, 0) != 0)
        return 0; /* host-to-host transfer inside the exempt path: drop */
    return pgc_record_hit(a, rel, lineno, line);
}

static int pgc_scan_file(struct pgc_acc *a, const char *full, const char *rel)
{
    if (pgc_is_self(rel))
        return 0;
    FILE *f = fopen(full, "r");
    if (!f)
        return pgc_fatal(a, "FAIL: stable-publish containment scan error "
                         "(native scanner): cannot open %s\n", rel);
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int lineno = 0, rc = 0;
    while (rc == 0 && (nread = getline(&line, &cap, f)) >= 0) {
        lineno++;
        rc = pgc_scan_line(a, rel, lineno, line);
    }
    int ferr = ferror(f);
    free(line);
    fclose(f);
    if (rc)
        return rc;
    if (ferr)
        return pgc_fatal(a, "FAIL: stable-publish containment scan error "
                         "(native scanner): cannot read %s\n", rel);
    return 0;
}

static int pgc_walk_dir(struct pgc_acc *a, const char *dir,
                        const char *reldir);

static int pgc_walk_entry(struct pgc_acc *a, const char *dir,
                          const char *reldir, const char *name)
{
    char full[PGC_PATH], rel[PGC_PATH];
    if (ovf(snprintf(full, sizeof full, "%s/%s", dir, name), sizeof full)
        || ovf(reldir[0]
                   ? snprintf(rel, sizeof rel, "%s/%s", reldir, name)
                   : snprintf(rel, sizeof rel, "%s", name),
               sizeof rel))
        return 2;
    struct stat st;
    if (lstat(full, &st) != 0)
        return 0; /* vanished mid-walk: not an error, matches find's own */
    if (S_ISDIR(st.st_mode))
        return pgc_excluded_dir(name) ? 0 : pgc_walk_dir(a, full, rel);
    if (S_ISREG(st.st_mode) && pgc_matches_glob(name))
        return pgc_scan_file(a, full, rel);
    return 0;
}

static int pgc_walk_dir(struct pgc_acc *a, const char *dir,
                        const char *reldir)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0) {
        if (errno == ENOENT)
            return 0;
        return pgc_fatal(a, "FAIL: stable-publish containment scan error "
                         "(native scanner): cannot read directory %s\n",
                         reldir[0] ? reldir : ".");
    }
    int rc = 0;
    for (int i = 0; i < n; i++) {
        if (rc == 0 && strcmp(names[i]->d_name, ".") != 0
            && strcmp(names[i]->d_name, "..") != 0)
            rc = pgc_walk_entry(a, dir, reldir, names[i]->d_name);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int pgc_scan_roots(struct pgc_acc *a, const char *root)
{
    int rc = pgc_resolve_scanner(a);
    if (rc)
        return rc;
    int nfound = 0;
    for (int i = 0; rc == 0 && i < PGC_N_ROOTS; i++) {
        char full[PGC_PATH];
        if (ovf(snprintf(full, sizeof full, "%s/%s", root, k_pgc_roots[i]),
                sizeof full))
            return 2;
        struct stat st;
        if (lstat(full, &st) != 0)
            continue;
        nfound++;
        rc = S_ISDIR(st.st_mode)
            ? pgc_walk_dir(a, full, k_pgc_roots[i])
            : pgc_scan_file(a, full, k_pgc_roots[i]);
    }
    if (rc)
        return rc;
    if (nfound == 0)
        return pgc_fatal(a, "FAIL: stable-publish containment has no "
                         "scannable roots\n");
    return 0;
}
static int pgc_file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0)
        found = strstr(line, needle) != NULL;
    free(line);
    fclose(f);
    return found;
}

/* Builds root/suffix into path and reports: -1 overflow, 0 absent/not a
 * regular file, 1 present. Shared by the three known-entrypoint checks,
 * each of which is a no-op when its own subject file does not exist. */
static int pgc_stat_exists(const char *root, const char *suffix, char *path,
                           size_t cap)
{
    if (ovf(snprintf(path, cap, "%s/%s", root, suffix), cap))
        return -1;
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode)) ? 1 : 0;
}

static int pgc_check_release_sh(const char *root, FILE *err)
{
    char path[PGC_PATH];
    int e = pgc_stat_exists(root, "tools/release.sh", path, sizeof path);
    if (e <= 0)
        return e < 0 ? 2 : 0;
    if (pgc_file_contains(path,
            "REFUSING: stable release build/package/sign/publish is "
            "contained"))
        return 0;
    fputs("FAIL: tools/release.sh is not hard-contained\n", err);
    return 2;
}

/* Port of the shell's awk state machine: for EVERY line beginning
 * "release:", the line itself must read exactly "release:" and the line
 * right after it exactly "\t@./tools/release.sh". */
static int pgc_release_target_ok(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1; /* no Makefile at all: the caller already gated on that */
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int seen = 0, bad = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (strncmp(line, "release:", 8) != 0)
            continue;
        seen = 1;
        if (strcmp(line, "release:") != 0)
            bad = 1;
        ssize_t n2 = getline(&line, &cap, f);
        if (n2 <= 0) {
            bad = 1;
            break;
        }
        if (n2 > 0 && line[n2 - 1] == '\n')
            line[n2 - 1] = '\0';
        if (strcmp(line, "\t@./tools/release.sh") != 0)
            bad = 1;
    }
    free(line);
    fclose(f);
    return seen && !bad;
}

static int pgc_check_release_target(const char *root, FILE *err)
{
    char path[PGC_PATH];
    int e = pgc_stat_exists(root, "Makefile", path, sizeof path);
    if (e <= 0)
        return e < 0 ? 2 : 0;
    if (!pgc_file_contains(path, "release:"))
        return 0; /* no ^release: line at all: nothing to check */
    if (pgc_release_target_ok(path))
        return 0;
    fputs("FAIL: make release has prerequisites or bypasses contained "
          "release.sh\n", err);
    return 2;
}

/* Port of the shell's awk state machine: SOME recipe line (tab-prefixed)
 * within the bootstrap-publish: target must contain "REFUSING". */
static int pgc_bootstrap_publish_ok(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int seen = 0, in_target = 0, refused = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (strncmp(line, "bootstrap-publish:", 18) == 0) {
            in_target = 1;
            seen = 1;
            continue;
        }
        if (in_target && line[0] == '\t') {
            if (strstr(line, "REFUSING"))
                refused = 1;
        } else if (in_target) {
            in_target = 0;
        }
    }
    free(line);
    fclose(f);
    return seen && refused;
}

static int pgc_check_bootstrap_publish(const char *root, FILE *err)
{
    char path[PGC_PATH];
    int e = pgc_stat_exists(root, "Makefile", path, sizeof path);
    if (e <= 0)
        return e < 0 ? 2 : 0;
    if (!pgc_file_contains(path, "bootstrap-publish:"))
        return 0;
    if (pgc_bootstrap_publish_ok(path))
        return 0;
    fputs("FAIL: bootstrap-publish is not hard-contained\n", err);
    return 2;
}

static int pgc_known_entrypoints(const char *root, FILE *err)
{
    int rc = pgc_check_release_sh(root, err);
    if (rc == 0)
        rc = pgc_check_release_target(root, err);
    if (rc == 0)
        rc = pgc_check_bootstrap_publish(root, err);
    return rc;
}

static int pgc_check_root(const char *root, FILE *out, FILE *err)
{
    (void)out;
    struct pgc_acc a = { .combined = &g_pgc_combined, .publish = &g_pgc_publish };
    int rc = pgc_scan_roots(&a, root);
    if (rc == 3)
        fputs(a.fatal_msg, err);
    else if (rc == 0 && a.hits.n > 0) {
        for (size_t i = 0; i < a.hits.n; i++)
            fprintf(err, "%s\n", a.hits.v[i]);
        fputs("FAIL: network release creation is contained until stable "
              "evidence/signing gates land\n", err);
        rc = 2;
    } else if (rc == 0)
        rc = pgc_known_entrypoints(root, err);
    pgc_free(&a.hits);
    return rc;
}

int check_stable_publish_containment_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = pgc_regex_ensure();
    if (rc == 0) {
        rc = pgc_check_root(".", stdout, stderr);
        if (rc == 0)
            fputs("  OK: known stable entrypoints are hard-contained; no "
                  "known network publication primitive found\n", stdout);
        pgc_regex_drop();
    }
    return rc;
}

/* Runs pgc_check_root(root, ...) with scratch out/err streams the caller
 * never needs to read, and hands back only the exit code. */
static int pgc_run_check(const char *root, int *code)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return die("z23-lint: tmpfile failed\n", "");
    }
    *code = pgc_check_root(root, out, err);
    fclose(out);
    fclose(err);
    return 0;
}

static int pgc_bad_fixture(const char *name, const char *rel,
                           const char *body)
{
    char root[256], path[PGC_PATH];
    if (ovf(snprintf(root, sizeof root, "test-tmp/pgc_bad_%s", name),
            sizeof root))
        return 2;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    int rc = csr_write(path, body);
    int code = 0;
    if (rc == 0)
        rc = pgc_run_check(root, &code);
    if (rc == 0 && code == 0) {
        fprintf(stderr, "FAIL: stable-publish %s fixture did not trip\n",
                name);
        rc = 2;
    }
    (void)rap_rm_rf(root);
    return rc;
}

struct pgc_bad_case { const char *name, *rel, *body; };
static const struct pgc_bad_case k_pgc_bad_cases[] = {
    { "gh-cli", "Makefile", "bad:\n\tgh release create forbidden\n" },
    { "gh-api", "Makefile", "bad:\n\tgh api repos/acme/project/releases\n" },
    { "tag-push", "Makefile", "bad:\n\tgit push origin refs/tags/v1.2.3\n" },
    { "workflow", ".github/workflows/release.yml",
      "uses: softprops/action-gh-release@deadbeef\n" },
    { "service", "deploy/publish.service",
      "ExecStart=scp artifact host:/stable/releases/\n" },
    { "json", "config/release.json",
      "{\"command\":[\"gh\",\"release\",\"upload\",\"v1\",\"artifact\"]}\n" },
    { "toml", "config/release.toml",
      "command = \"aws s3 cp artifact s3://stable/releases/\"\n" },
    { "extensionless", "Dockerfile", "RUN gh release create forbidden\n" },
    { "transfer-elsewhere", "tools/other_deploy.sh",
      "scp artifact host:/stable/releases/\n" },
    { "publish-inside-exempt", NULL, "gh release create v1 artifact\n" },
    { "s3-inside-exempt", NULL,
      "aws s3 cp artifact s3://stable/releases/\n" },
};

static int pgc_selftest_bad_cases(void)
{
    int rc = 0;
    for (size_t i = 0; rc == 0
             && i < sizeof k_pgc_bad_cases / sizeof k_pgc_bad_cases[0]; i++) {
        const struct pgc_bad_case *c = &k_pgc_bad_cases[i];
        rc = pgc_bad_fixture(c->name, c->rel ? c->rel : k_pgc_transfer_exempt,
                             c->body);
    }
    return rc;
}

static int pgc_write_safe_makefile(const char *root)
{
    char path[PGC_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    return csr_write(path, "safe:\n\t@echo local-only\n");
}

static int pgc_selftest_clean_case(void)
{
    static const char root[] = "test-tmp/pgc_clean";
    char path[PGC_PATH];
    int rc = pgc_write_safe_makefile(root);
    if (rc == 0
        && ovf(snprintf(path, sizeof path, "%s/%s", root,
                        k_pgc_transfer_exempt), sizeof path))
        rc = 2;
    if (rc == 0)
        rc = csr_write(path,
                "scp -q \"$CANDIDATE\" \"$REMOTE_HOST:${svc_bin}.incoming\"\n");
    int code = 0;
    if (rc == 0)
        rc = pgc_run_check(root, &code);
    if (rc == 0 && code != 0) {
        fputs("FAIL: stable-publish containment clean fixture failed\n",
              stderr);
        rc = 2;
    }
    (void)rap_rm_rf(root);
    return rc;
}

static int pgc_selftest_scanner_case(void)
{
    static const char root[] = "test-tmp/pgc_clean_scan";
    int rc = pgc_write_safe_makefile(root);
    if (rc == 0
        && setenv("ZCL_CONTAINMENT_GREP", "/definitely/missing/grep", 1) != 0)
        rc = die("z23-lint: setenv failed\n", "");
    int code = 0;
    if (rc == 0)
        rc = pgc_run_check(root, &code);
    if (rc == 0 && code == 0) {
        fputs("FAIL: missing scanner fixture failed open\n", stderr);
        rc = 2;
    }
    if (unsetenv("ZCL_CONTAINMENT_GREP") != 0 && rc == 0)
        rc = die("z23-lint: setenv failed\n", "");
    (void)rap_rm_rf(root);
    return rc;
}

int check_stable_publish_containment_selftest(void)
{
    char root[4096];
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0)
        rc = pgc_regex_ensure();
    if (rc == 0)
        rc = pgc_selftest_bad_cases();
    if (rc == 0)
        rc = pgc_selftest_clean_case();
    if (rc == 0)
        rc = pgc_selftest_scanner_case();
    if (g_pgc_re_ok)
        pgc_regex_drop();
    if (rc != 0) {
        fprintf(stderr, "%s: SELFTEST FAILED\n", k_pgc_name);
        return rc;
    }
    fputs("  OK: independent CLI/tag/workflow/service/JSON/TOML/"
          "extensionless fixtures trip; clean and scanner-failure fixtures "
          "behave\n", stdout);
    return 0;
}
