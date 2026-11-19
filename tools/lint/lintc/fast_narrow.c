/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: decide when a per-file lint gate may scan only the changed-file
 * set. The per-file-deterministic marker rows live in gate_commands.def
 * (LINT_ROW_FILES), compiled in below, next to the command they qualify;
 * the built-in gate->sources table after them extends the same rule to the
 * per-file gates no marker row names yet. The land proof and `make lint`
 * never call this; a narrowed pass is
 * not a whole-tree proof. `z23-lint fast-scan` is a tool, not a gate.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lintc.h"
#include "lint_narrow_hook.h"
#include "precheck_base.h"
#include "run_priv.h"

/* The per-file-deterministic marker rows of gate_commands.def: the run
 * driver narrows exactly these gates, never a gate without a row. */
#define LINT_ROW(name, cmd)
#define LINT_ROW_FILES(name, files) { name, files },
static const struct {
    const char *name;
    const char *files;
} k_fast_file_rows[] = {
#include "gate_commands.def"
};
#undef LINT_ROW
#undef LINT_ROW_FILES

const char *lint_fast_files_decl(const char *gate)
{
    if (!gate)
        return NULL;
    for (size_t i = 0; i < sizeof k_fast_file_rows / sizeof k_fast_file_rows[0]; i++)
        if (strcmp(k_fast_file_rows[i].name, gate) == 0)
            return k_fast_file_rows[i].files;
    return NULL;
}

/* The built-in gate->sources table: the same source-unchanged rule for the
 * per-file gates no LINT_ROW_FILES row marks. */
static const char *const k_fast_nak[] = {
    "tools/lint/lintc/gate_git_scan_a.c",
    NULL
};
static const char *const k_fast_fmd[] = {
    "tools/lint/lintc/gate_fortify_masked_decls.c",
    NULL
};
static const char *const k_fast_crs[] = {
    "tools/lint/lintc/gate_raw_sqlite.c",
    "tools/lint/lintc/gate_raw_sqlite_ctx.c",
    "tools/lint/lintc/gate_raw_sqlite_exec.c",
    "tools/lint/lintc/gate_raw_sqlite_priv.h",
    "tools/lint/lintc/gate_raw_sqlite_selftest.c",
    "tools/lint/lintc/lintc_text.c",
    NULL
};
static const char *const k_fast_wps[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_windows_platform_seam.c",
    "tools/lint/lintc/gate_windows_platform_seam_selftest.c",
    NULL
};
static const char *const k_fast_zcc[] = {
    "tools/lint/lintc/gate_zcc_cache.c",
    "tools/lint/lintc/gate_zcc_cache_apple.c",
    "tools/lint/lintc/gate_zcc_cache_boot.c",
    "tools/lint/lintc/gate_zcc_cache_core.c",
    "tools/lint/lintc/gate_zcc_cache_flight.c",
    "tools/lint/lintc/gate_zcc_cache_root.c",
    "tools/lint/lintc/gate_zcc_cache_selftest.c",
    "tools/lint/lintc/gate_zcc_cache_stage.c",
    "tools/lint/lintc/gate_zcc_cache_tools.c",
    "tools/lint/lintc/gate_zcc_cache_util.c",
    "tools/lint/lintc/lintc_text.c",
    NULL
};
static const char *const k_fast_rma[] = {
    "tools/lint/lintc/gate_raw_malloc.c",
    NULL
};
static const char *const k_fast_mal[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_pattern_small.c",
    "tools/lint/lintc/gate_pattern_guard.c",
    NULL
};
static const char *const k_fast_hfs[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_hotfork_stories.c",
    "tools/dev/hotfork_unity.h",
    "engine/composition/hotfork_capsules.def",
    NULL
};
static const char *const k_fast_bo[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_byte_order_codec_single.c",
    "tools/lint/lintc/gate_byte_order_codec_single_report.c",
    "tools/lint/lintc/gate_byte_order_codec_single_priv.h",
    NULL
};
static const char *const k_fast_zpr[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_zcode_packages.c",
    NULL
};
static const char *const k_fast_db[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_describe_budget.c",
    NULL
};
static const char *const k_fast_hcs[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_hex_codec_single.c",
    "tools/lint/lintc/gate_hex_codec_single_selftest.c",
    NULL
};
static const char *const k_fast_ssr[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_sqlite_step_row.c",
    "tools/lint/lintc/gate_sqlite_step_row_baseline.c",
    "tools/lint/lintc/gate_sqlite_step_row_priv.h",
    "tools/lint/lintc/gate_sqlite_step_row_selftest.c",
    NULL
};
static const char *const k_fast_clk[] = {
    "tools/lint/lintc/gate_tree_walk.c",
    "tools/lint/lintc/gate_tree_walk_priv.h",
    "tools/lint/lintc/gate_tree_walk_selftests.c",
    "tools/lint/lintc/lib.c",
    NULL
};
static const char *const k_fast_cyc[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_function_complexity.c",
    "tools/lint/lintc/gate_function_complexity_priv.h",
    "tools/lint/lintc/gate_function_complexity_selftest.c",
    NULL
};
static const char *const k_fast_hrl[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_hidden_return_under_lock.c",
    "tools/lint/lintc/gate_hidden_return_under_lock_priv.h",
    "tools/lint/lintc/gate_hidden_return_under_lock_selftest.c",
    "tools/lint/lintc/lib.c",
    "tools/lint/lintc/lintc_text.c",
    NULL
};
static const char *const k_fast_lmr[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_log_macro_return_type.c",
    "tools/lint/lintc/gate_log_macro_return_type_priv.h",
    "tools/lint/lintc/gate_log_macro_return_type_selftest.c",
    "tools/lint/lintc/lib.c",
    NULL
};
static const char *const k_fast_pt[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_pattern_small.c",
    "tools/lint/lintc/gate_pattern_guard.c",
    "tools/lint/lintc/lib.c",
    NULL
};
static const char *const k_fast_ntf[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_no_bare_tmp_fixture.c",
    "tools/lint/lintc/lib.c",
    NULL
};
static const char *const k_fast_jvi[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_state_hygiene_fences.c",
    "tools/lint/lintc/lib.c",
    NULL
};
static const char *const k_fast_cph[] = {
    "tools/lint/lintc/lint_narrow_hook.h",
    "tools/lint/lintc/gate_controller_private_headers.c",
    "tools/lint/lintc/gate_controller_private_headers_scan.c",
    "tools/lint/lintc/gate_controller_private_headers_workers.c",
    "tools/lint/lintc/lib.c",
    NULL
};

int lint_fast_should_narrow(int per_file, int set_supplied, int source_matches)
{
    return per_file && set_supplied && source_matches;
}

int lint_examined_print(int n, int floor)
{
    int k;
    if (floor < 0)
        k = printf("examined-files: %d\nscan-floor: whole\n", n);
    else
        k = printf("examined-files: %d\nscan-floor: %d\n", n, floor);
    return k < 0 ? -1 : 0;
}

static int lint_changed_has(const struct lint_changed *c, const char *s)
{
    for (int i = 0; i < c->n; i++) {
        if (strcmp(c->path[i], s) == 0)
            return 1;
    }
    return 0;
}

void lint_changed_free(struct lint_changed *c)
{
    if (!c)
        return;
    for (int i = 0; i < c->n; i++)
        free(c->path[i]);
    free(c->path);
    c->path = NULL;
    c->n = 0;
    c->active = 0;
}

/* Takes ownership of s. Empty and duplicate lines are dropped. */
static int lint_changed_add(struct lint_changed *c, char *s)
{
    char **np;
    if (s[0] == '\0' || lint_changed_has(c, s)) {
        free(s);
        return 0;
    }
    np = realloc(c->path, (size_t)(c->n + 1) * sizeof(*np)); // raw-alloc-ok:lint-runtime
    if (!np) {
        free(s);
        return 2;
    }
    c->path = np;
    c->path[c->n++] = s;
    return 0;
}

static int lint_changed_load(struct lint_changed *c, const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: cannot open changed-file list\n");
        return 2;
    }
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *copy;
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (line[0] == '\0')
            continue;
        /* Git quotes paths this newline format cannot represent literally.
         * Discard even earlier entries: a partial set is not a safe scan. */
        if (line[0] == '"') {
            fprintf(stderr, "z23-lint: quoted changed-file path; using whole-tree scan\n");
            lint_changed_free(c);
            break;
        }
        if (strlen(line) >= 4096) {
            rc = 2;
            break;
        }
        copy = malloc(strlen(line) + 1); // raw-alloc-ok:lint-runtime
        if (!copy) {
            rc = 2;
            break;
        }
        memcpy(copy, line, strlen(line) + 1);
        rc = lint_changed_add(c, copy);
    }
    if (ferror(f))
        rc = 2;
    free(line);
    if (fclose(f) != 0)
        rc = 2;
    return rc;
}

static int lint_changed_take(int *argc, char ***argv, const char **file)
{
    int w = 0;
    *file = NULL;
    for (int i = 0; i < *argc; i++) {
        const char *a = (*argv)[i];
        if (a && strncmp(a, "--changed-files=", 16) == 0) {
            if (*file || a[16] == '\0')
                return 2;
            *file = a + 16;
            continue;
        }
        (*argv)[w++] = (*argv)[i];
    }
    *argc = w;
    return 0;
}

int lint_changed_bind(int *argc, char ***argv, struct lint_changed *out)
{
    const char *file = NULL;
    int rc;
    memset(out, 0, sizeof *out);
    if (!argc || !argv || *argc <= 0)
        return 0;
    rc = lint_changed_take(argc, argv, &file);
    if (rc)
        return rc;
    if (!file)
        return 0;
    out->active = 1;
    rc = lint_changed_load(out, file);
    if (rc)
        lint_changed_free(out);
    return rc;
}

int lint_fast_append_changed(char *cmd, size_t cap, const char *path)
{
    char quoted[8192];
    size_t n;
    int k;
    if (!cmd || !path || !path[0] || sh_single_quote(path, quoted, sizeof quoted))
        return 2;
    n = strlen(cmd);
    if (n >= cap)
        return 2;
    k = snprintf(cmd + n, cap - n, " --changed-files=%s", quoted);
    if (k < 0 || (size_t)k >= cap - n)
        return 2;
    return 0;
}

struct lint_fast_gate {
    const char *name;
    const char *const *sources;
};

static const struct lint_fast_gate k_fast_gates[] = {
    { "check-no-api-keys", k_fast_nak },
    { "check-fortify-masked-decls", k_fast_fmd },
    { "check-raw-sqlite", k_fast_crs },
    { "check-windows-platform-seam", k_fast_wps },
    { "check-zcc-cache", k_fast_zcc },
    { "check-raw-malloc", k_fast_rma },
    { "check-malloc", k_fast_mal },
    { "check-hotfork-stories", k_fast_hfs },
    { "check-byte-order-codec-single", k_fast_bo },
    { "check-zcode-package-registry", k_fast_zpr },
    { "check-describe-budget", k_fast_db },
    { "check-hex-codec-single", k_fast_hcs },
    { "check-sqlite-step-row", k_fast_ssr },
    { "check-no-raw-clock-outside-platform", k_fast_clk },
    { "check-cyclomatic-complexity", k_fast_cyc },
    { "check-hidden-return-under-lock", k_fast_hrl },
    { "check-log-macro-return-type", k_fast_lmr },
    { "check-pthread-create", k_fast_pt },
    { "check-no-bare-tmp-fixture", k_fast_ntf },
    { "check-json-value-init", k_fast_jvi },
    { "check-controller-private-headers", k_fast_cph },
};

static const char *const *lint_fast_sources(const char *name)
{
    for (size_t i = 0; i < sizeof k_fast_gates / sizeof k_fast_gates[0]; i++)
        if (strcmp(name, k_fast_gates[i].name) == 0)
            return k_fast_gates[i].sources;
    return NULL;
}

static int lint_fast_tip(char *tip, size_t cap)
{
    const char *rev[] = {
        "rev-parse", "--verify", "-q", "refs/remotes/origin/main^{commit}", NULL
    };
    int rc = precheck_base_git(NULL, rev, tip, cap);
    return rc == 0 && tip[0] != '\0';
}

/* merge-base(HEAD, origin/main): the one base both the def-marked rows and
 * the built-in gate table narrow against. */
int lint_fast_merge_base(char *sha, size_t cap)
{
    char tip[80];
    const char *mb[] = { "merge-base", "HEAD", tip, NULL };
    int rc;
    if (!sha || cap == 0)
        return 0;
    sha[0] = '\0';
    if (!lint_fast_tip(tip, sizeof tip))
        return 0;
    rc = precheck_base_git(NULL, mb, sha, cap);
    return rc == 0 && sha[0] != '\0';
}

static int lint_fast_diff_quiet(const char *sha, const char *const *files)
{
    const char *args[9];
    int n = 0;
    args[n++] = "diff";
    args[n++] = "--quiet";
    args[n++] = sha;
    args[n++] = "--";
    for (int i = 0; files[i] != NULL && n < 8; i++)
        args[n++] = files[i];
    args[n] = NULL;
    return precheck_base_git(NULL, args, NULL, 0) == 0;
}

enum { LINT_FAST_SOURCE_MAX = 64 };

static int lint_fast_source_list(const char **paths)
{
    int n = 0;
    for (size_t i = 0; i < sizeof k_fast_gates / sizeof k_fast_gates[0]; i++) {
        const char *const *src = k_fast_gates[i].sources;
        for (int j = 0; src[j]; j++) {
            int seen = 0;
            for (int k = 0; k < n; k++)
                if (strcmp(paths[k], src[j]) == 0)
                    seen = 1;
            if (seen)
                continue;
            if (n >= LINT_FAST_SOURCE_MAX)
                return -1;
            paths[n++] = src[j];
        }
    }
    return n;
}

int lint_fast_diff_names(const char *base, char *out, size_t cap)
{
    const char *args[LINT_FAST_SOURCE_MAX + 6];
    if (!base || !base[0] || !out || cap == 0)
        return 0;
    int nsrc = lint_fast_source_list(args + 5);
    if (nsrc <= 0)
        return 0;
    args[0] = "diff";
    args[1] = "--name-only";
    args[2] = "--no-renames";
    args[3] = base;
    args[4] = "--";
    args[5 + nsrc] = NULL;
    out[0] = '\0';
    return precheck_base_git(NULL, args, out, cap) == 0;
}

static int lint_fast_name_has(const char *names, const char *path)
{
    size_t want = strlen(path);
    for (const char *p = names; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n == want && memcmp(p, path, n) == 0)
            return 1;
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

int lint_fast_gate_narrow_names(const char *name, int set_supplied,
                                const char *names)
{
    if (!name || !set_supplied || !names)
        return 0;
    const char *const *src = lint_fast_sources(name);
    if (!src)
        return 0;
    for (int i = 0; src[i]; i++)
        if (lint_fast_name_has(names, src[i]))
            return lint_fast_should_narrow(1, 1, 0);
    return lint_fast_should_narrow(1, 1, 1);
}

int lint_fast_gate_narrow_base(const char *name, int set_supplied,
                               const char *base)
{
    const char *const *src;
    if (!name || !set_supplied || !base || !base[0])
        return 0;
    src = lint_fast_sources(name);
    if (!src)
        return 0;
    return lint_fast_should_narrow(1, 1, lint_fast_diff_quiet(base, src));
}

/* Split the declared space-separated sources into OUT (NULL-terminated) inside
 * BUF. Returns the count, 0 when the row is empty or overflows either. */
static int lint_fast_split_sources(const char *files, char *buf, size_t cap,
                                   const char *out[9])
{
    size_t w = 0;
    int n = 0;
    const char *p = files;
    while (*p) {
        const char *q = p;
        size_t len;
        while (*q && *q != ' ')
            q++;
        len = (size_t)(q - p);
        if (len == 0) {
            p++;
            continue;
        }
        if (w + len + 1 >= cap || n >= 8)
            return 0;
        memcpy(buf + w, p, len);
        buf[w + len] = '\0';
        out[n++] = buf + w;
        w += len + 1;
        p = q;
    }
    out[n] = NULL;
    return n;
}

/* A gate narrows only when its own sources match the merge-base: first a
 * gate_commands.def LINT_ROW_FILES row, else a row of the built-in table.
 * A gate named by neither never narrows. */
int lint_fast_gate_narrow(const char *name, int set_supplied)
{
    char sha[80], buf[512];
    const char *src[9];
    const char *decl;
    if (!name || !set_supplied)
        return 0;
    decl = lint_fast_files_decl(name);
    if (!decl && !lint_fast_sources(name))
        return 0;
    if (!lint_fast_merge_base(sha, sizeof sha))
        return 0;
    if (decl) {
        if (lint_fast_split_sources(decl, buf, sizeof buf, src) == 0)
            return 0;
        return lint_fast_should_narrow(1, 1, lint_fast_diff_quiet(sha, src));
    }
    return lint_fast_gate_narrow_base(name, set_supplied, sha);
}

/* The run driver's --base scope: git's stdout for ARGS appended to FD. */
static int lint_scope_git_to_fd(const char *const *args, int fd)
{
    int st = 0;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (dup2(fd, STDOUT_FILENO) < 0)
            _exit(127);
        execvp("git", (char *const *)args);
        _exit(127);
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
        ;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

int lint_changed_scope_from_base(const char *base, char *out, size_t cap)
{
    const char *diff[] = { "git", "diff", "--name-only", base, NULL };
    static const char *const k_untracked[] = {
        "git", "ls-files", "--others", "--exclude-standard", NULL
    };
    char path[PATH_MAX], cwd[PATH_MAX];
    int fd, rc, n;
    if (!base || !base[0] || lr_mkdir_p("build/scratch") != 0)
        return 2;
    /* Absolute: the scope file is handed to gates and readers that may not
     * share the driver's working directory. */
    if (!getcwd(cwd, sizeof cwd))
        return 2;
    n = snprintf(path, sizeof path, "%s/build/scratch/lint-changed-%ld.txt",
                 cwd, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof path)
        return 2;
    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0)
        return 2;
    rc = lint_scope_git_to_fd(diff, fd);
    if (rc == 0)
        rc = lint_scope_git_to_fd(k_untracked, fd);
    if (close(fd) != 0)
        rc = -1;
    if (rc != 0) {
        (void)unlink(path);
        return 2;
    }
    if (snprintf(out, cap, "%s", path) >= (int)cap)
        return 2;
    return 0;
}



/* ── the shared narrowing hooks (lint_narrow_hook.h) ─────────────────────
 * The per-gate wrappers keep their long-standing symbols; these bodies are
 * the once-duplicated repo-root, path-form, collect and baseline-row
 * filter shapes the gates now share. */

static const char *lint_narrow_form(const struct lint_narrow_gate *g,
                                    const char *path, const char *repo)
{
    return g->path_form ? g->path_form(path, repo) : path;
}

int lint_narrow_ok(const struct lint_changed *ch, const char *baseline,
                   const struct lint_narrow_gate *g)
{
    if (!ch->active)
        return 0;
    char repo_buf[4096];
    const char *repo = repo_buf;
    if (g->repo_resolve) {
        if (g->repo_resolve(ch, repo_buf, &repo) != 0)
            return 0;
    } else if (cic_repo_root(repo_buf, sizeof repo_buf) != 0) {
        return 0;
    }
    const char *wanted = NULL;
    if (baseline) {
        wanted = lint_narrow_form(g, baseline, repo);
        /* cyc's absolute-baseline guard: with no repo root an absolute
         * baseline cannot be compared, so the gate stays whole-tree. */
        if (!repo && wanted[0] == '/')
            return 0;
    }
    for (int i = 0; i < ch->n; i++) {
        const char *path = lint_narrow_form(g, ch->path[i], repo);
        if (g->extra_keep && g->extra_keep(path))
            return 0;
        if (wanted && strcmp(path, wanted) == 0)
            return 0;
    }
    return 1;
}

int lint_narrow_collect(const struct lint_changed *ch, char repo[4096],
                        const struct lint_narrow_gate *g,
                        int (*emit)(void *ctx, const char *path), void *ctx)
{
    if (cic_repo_root(repo, 4096) != 0)
        return 2;
    for (int i = 0; i < ch->n; i++) {
        const char *path = lint_narrow_form(g, ch->path[i], repo);
        size_t len = strlen(path);
        struct stat st;
        if (len < 2 || path[len - 2] != '.' ||
            (path[len - 1] != 'c' && path[len - 1] != 'h'))
            continue;
        if (g->collect_skip && g->collect_skip(ctx, path))
            continue;
        if (g->collect_stat) {
            if (lstat(path, &st) != 0) {
                if (errno == ENOENT)
                    continue;
                fprintf(stderr, "z23-lint: cannot stat %s: %s\n", path,
                        strerror(errno));
                return 2;
            }
            if (!S_ISREG(st.st_mode))
                continue;
        }
        int rc = emit(ctx, path);
        if (rc)
            return rc;
    }
    return 0;
}

int lint_narrow_filter_keys(const char *const *changed, int n,
                            const char *keys[], int nkeys, int key_len,
                            int (*match)(const char *key, const char *path))
{
    char *rows = (char *)keys;
    int as_ptr = key_len == (int)sizeof keys[0];
    int kept = 0;
    for (int i = 0; i < nkeys; i++) {
        const char *key = as_ptr ? keys[i]
                                 : rows + (size_t)i * (size_t)key_len;
        int keep = 0;
        for (int k = 0; k < n && !keep; k++)
            keep = match ? match(key, changed[k]) : strcmp(key, changed[k]) == 0;
        if (!keep)
            continue;
        if (kept != i)
            memmove(rows + (size_t)kept * (size_t)key_len,
                    rows + (size_t)i * (size_t)key_len, (size_t)key_len);
        kept++;
    }
    return kept;
}

const char *lint_narrow_repo_form(const char *path, const char *repo)
{
    if (strncmp(path, "./", 2) == 0)
        path += 2;
    size_t len = strlen(repo);
    if (len && repo[len - 1] == '/')
        len--;
    if (strcmp(path, repo) == 0)
        return ".";
    if (strncmp(path, repo, len) == 0 && path[len] == '/')
        return path + len + 1;
    return path;
}

const char *lint_narrow_repo_form_opt(const char *path, const char *repo)
{
    if (strncmp(path, "./", 2) == 0)
        path += 2;
    if (!repo)
        return path;
    return lint_narrow_repo_form(path, repo);
}

int lint_narrow_repo_opt(const struct lint_changed *ch, char out[4096],
                         const char **repo)
{
    *repo = NULL;
    if (cic_repo_root(out, 4096) == 0) {
        *repo = out;
        return 0;
    }
    for (int i = 0; i < ch->n; i++) {
        const char *path = ch->path[i];
        if (strncmp(path, "./", 2) == 0)
            path += 2;
        if (path[0] == '/')
            return 2;
    }
    return 0;
}

int lint_narrow_under_roots(const char *path, char roots[][RS_PATH],
                            int nroots, const char *repo)
{
    for (int i = 0; i < nroots; i++) {
        const char *root = lint_narrow_repo_form(roots[i], repo);
        if (!root[0] || strcmp(root, ".") == 0)
            return path[0] != '/';
        size_t len = strlen(root);
        while (len > 1 && root[len - 1] == '/')
            len--;
        if (len == 1 && root[0] == '/')
            return 1;
        if (strncmp(path, root, len) == 0 && path[len] == '/')
            return 1;
    }
    return 0;
}

int lint_narrow_roots_prefix(const char *path, const char *const *roots)
{
    for (size_t i = 0; roots[i]; i++) {
        size_t n = strlen(roots[i]);
        if (strncmp(path, roots[i], n) == 0 && path[n] == '/')
            return 1;
    }
    return 0;
}

int lint_narrow_suffix(const char *path, const char *suffix)
{
    size_t n = strlen(path), s = strlen(suffix);
    return n >= s && strcmp(path + n - s, suffix) == 0;
}

int lint_narrow_relevant(const struct lint_changed *ch,
                         int (*relevant)(const char *path))
{
    if (!ch->active)
        return 1;
    for (int i = 0; i < ch->n; i++)
        if (relevant(ch->path[i]))
            return 1;
    return 0;
}

int lint_narrow_env_save(const char *const *names, char *values[], int n)
{
    memset(values, 0, (size_t)n * sizeof values[0]);
    for (int i = 0; names[i] && i < n; i++) {
        const char *value = getenv(names[i]);
        if (value && !(values[i] = strdup(value))) {
            for (int j = 0; j < i; j++)
                free(values[j]);
            return 1;
        }
    }
    return 0;
}

int lint_narrow_env_clear(const char *const *names, int n)
{
    int bad = 0;
    for (int i = 0; names[i] && i < n; i++)
        bad |= unsetenv(names[i]) != 0;
    return bad;
}

int lint_narrow_env_restore(const char *const *names,
                            char *const values[], int n)
{
    int bad = 0;
    for (int i = 0; names[i] && i < n; i++) {
        if (values[i])
            bad |= setenv(names[i], values[i], 1) != 0;
        else
            bad |= unsetenv(names[i]) != 0;
        free(values[i]);
    }
    return bad;
}

int lint_narrow_wait_pid(pid_t pid, const char *what)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        int error = errno;
        char msg[128];
        if (ovf(snprintf(msg, sizeof msg,
                         "z23-lint: %s waitpid failed: %s\n",
                         what, strerror(error)), sizeof msg))
            return 2;
        return die("%s", msg);
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 2;
}
