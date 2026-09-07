/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint family for Program H demoted-store consumer-freeze
 * ratchets (check-no-utxo-projection, check-no-block-index-flat).
 *
 * Two near-identical OBSERVE-style freezes: each greps a fixed identifier
 * set over core/engine/contexts/cognition/platform and diffs the matching
 * .c and .h files against a shrink-only baseline. Shared baseline-diff lives
 * in one helper; the two _run functions only supply pattern, baseline path,
 * and per-gate strings.
 *
 * Placement ruling (2026-09-06): small-pattern/ratchet families are claimed,
 * so this subject lands in its own file. gate_ratchet_ports.c was consulted
 * for the walk_src + baseline-diff idiom and is not reused — it names a
 * different ratchet set, and these two gates freeze demoted representations.
 * Scan floor is the shell's scan-root-existence preflight; no extra
 * gate_require_scanned. The four already-registered ZCL_NO_*_{BASELINE,
 * SCAN_ROOTS} flags are read through env_or (the lint runtime's flag-registry
 * getenv wrapper), matching the shell scripts they replace.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { DSR_MAX = 512, DSR_PATH = RS_PATH };

static const char *const k_dsr_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};
enum { DSR_N_ROOTS = (int)(sizeof k_dsr_roots / sizeof k_dsr_roots[0]),
       DSR_ROOT_CAP = 16, DSR_ROOT_BUF = 1024 };
static const char k_dsr_roots_text[] =
    "core engine contexts cognition platform";

struct dsr_roots {
    char buf[DSR_ROOT_BUF];
    const char *v[DSR_ROOT_CAP];
    int n;
};

struct dsr_set {
    char n[DSR_MAX][DSR_PATH];
    unsigned char seen[DSR_MAX];
    int count;
};

struct dsr_msg {
    const char *gate;
    const char *new_fail;
    const char *guidance;
};

struct dsr_cfg {
    const char *const *needles;
    int n_needles;
    const char *baseline;
    const char *const *roots;
    int n_roots;
    struct dsr_msg msg;
};

struct dsr_acc {
    const struct dsr_cfg *c;
    struct dsr_set *hits;
};

static const char *const k_utxo_needles[] = {
    "utxo_projection_", "EV_UTXO_ADD", "EV_UTXO_SPEND"
};
static const char *const k_blk_needles[] = {
    "save_block_index_flat", "load_block_index_flat",
    "save_block_index_recent", "load_block_index_sqlite",
    "block_tree_db_write_block_index", "boot_dispatch_blocks_table_hydrate"
};

static const struct dsr_cfg k_utxo_cfg = {
    .needles = k_utxo_needles,
    .n_needles = (int)(sizeof k_utxo_needles / sizeof k_utxo_needles[0]),
    .baseline = "tools/scripts/check_no_utxo_projection_baseline.txt",
    .roots = k_dsr_roots,
    .n_roots = DSR_N_ROOTS,
    .msg = {
        .gate = "check_no_utxo_projection",
        .new_fail = "new consumer(s) of the demoted UTXO projection",
        .guidance =
            "The kernel coins store is the one UTXO ledger; do not add users of\n"
            "utxo_projection / EV_UTXO_*. Baselines shrink only.\n",
    },
};

static const struct dsr_cfg k_blk_cfg = {
    .needles = k_blk_needles,
    .n_needles = (int)(sizeof k_blk_needles / sizeof k_blk_needles[0]),
    .baseline = "tools/scripts/check_no_block_index_flat_baseline.txt",
    .roots = k_dsr_roots,
    .n_roots = DSR_N_ROOTS,
    .msg = {
        .gate = "check_no_block_index_flat",
        .new_fail = "new consumer(s) of a demoted header cache",
        .guidance =
            "Do not add new users of the flat/LevelDB/SQLite header caches; feed\n"
            "the event log and read block_index_projection. Baselines shrink only.\n",
    },
};

static int dsr_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int dsr_find(const struct dsr_set *s, const char *path)
{
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->n[i], path) == 0)
            return i;
    }
    return -1;
}

static int dsr_add(struct dsr_set *s, const char *path)
{
    size_t n = strlen(path);
    if (dsr_find(s, path) >= 0)
        return 0;
    if (s->count >= DSR_MAX || n >= DSR_PATH)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(s->n[s->count], path, n + 1);
    s->seen[s->count] = 0;
    s->count++;
    return 0;
}

static int dsr_skip(const char *path)
{
    return strstr(path, "/test/") != NULL
        || strstr(path, "/tests/") != NULL
        || strstr(path, "/include/") != NULL
        || strstr(path, "_test.") != NULL;
}

static int dsr_fatal(FILE *err, const char *gate, const char *why,
                     const char *arg)
{
    if (fprintf(err, "%s: FATAL — %s%s\n", gate, why, arg) < 0)
        return die("z23-lint: write failed\n", "");
    return 2;
}

static int dsr_preflight(const struct dsr_cfg *c, FILE *err)
{
    const char *g = c->msg.gate;
    if (!c->baseline || access(c->baseline, R_OK) != 0)
        return dsr_fatal(err, g, "baseline missing: ",
                         c->baseline ? c->baseline : "");
    if (c->n_roots <= 0)
        return dsr_fatal(err, g, "empty scan-root set", "");
    for (int i = 0; i < c->n_roots; i++) {
        struct stat st;
        if (stat(c->roots[i], &st) != 0 || !S_ISDIR(st.st_mode))
            return dsr_fatal(err, g, "scan root missing: ", c->roots[i]);
    }
    return 0;
}

/* Shell `case "$path" in ''|'#'*)` — no whitespace trim. */
static int dsr_load_base(const struct dsr_cfg *c, FILE *err, struct dsr_set *s)
{
    FILE *f = fopen(c->baseline, "r");
    if (!f)
        return dsr_fatal(err, c->msg.gate, "baseline missing: ", c->baseline);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (dsr_find(s, line) >= 0) {
            rc = dsr_fatal(err, c->msg.gate, "duplicate baseline row: ", line);
            break;
        }
        rc = dsr_add(s, line);
    }
    return fin(f, line, c->baseline, rc);
}

/* Literal substring per alternative: both shell EREs are fixed identifiers
 * with no metacharacters, so strstr is byte-exact with grep -E. */
static int dsr_file_hits(const char *path, const char *const *needles,
                         int n_needles, int *hit)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    *hit = 0;
    while (!*hit && getline(&line, &cap, f) >= 0) {
        for (int i = 0; i < n_needles; i++) {
            if (strstr(line, needles[i]) != NULL) {
                *hit = 1;
                break;
            }
        }
    }
    return fin(f, line, path, 0);
}

static int dsr_on_file(const char *path, void *ctx)
{
    struct dsr_acc *a = ctx;
    int hit = 0;
    if (dsr_skip(path))
        return 0;
    int rc = dsr_file_hits(path, a->c->needles, a->c->n_needles, &hit);
    if (rc || !hit)
        return rc;
    return dsr_add(a->hits, path);
}

static int dsr_classify(struct dsr_set *allowed, const struct dsr_set *hits,
                        struct dsr_set *nw, struct dsr_set *stale)
{
    for (int i = 0; i < hits->count; i++) {
        int k = dsr_find(allowed, hits->n[i]);
        if (k >= 0) {
            allowed->seen[k] = 1;
        } else {
            int rc = dsr_add(nw, hits->n[i]);
            if (rc)
                return rc;
        }
    }
    for (int i = 0; i < allowed->count; i++) {
        if (!allowed->seen[i]) {
            int rc = dsr_add(stale, allowed->n[i]);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int dsr_emit_list(FILE *out, const struct dsr_set *s)
{
    for (int i = 0; i < s->count; i++) {
        if (fprintf(out, "  %s\n", s->n[i]) < 0)
            return die("z23-lint: write failed\n", "");
    }
    return 0;
}

static int dsr_report(FILE *out, const struct dsr_msg *m, int base_n,
                      const struct dsr_set *nw, const struct dsr_set *stale)
{
    if (nw->count == 0 && stale->count == 0) {
        if (fprintf(out,
                    "%s: clean — %d reviewed consumer(s), no new use\n",
                    m->gate, base_n) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (nw->count > 0) {
        if (fprintf(out, "%s: FAIL — %s\n", m->gate, m->new_fail) < 0)
            return die("z23-lint: write failed\n", "");
        int rc = dsr_emit_list(out, nw);
        if (rc)
            return rc;
    }
    if (stale->count > 0) {
        if (fprintf(out,
                    "%s: FAIL — stale baseline row(s) (consumer gone; shrink the baseline)\n",
                    m->gate) < 0)
            return die("z23-lint: write failed\n", "");
        int rc = dsr_emit_list(out, stale);
        if (rc)
            return rc;
    }
    if (fputs(m->guidance, out) == EOF)
        return die("z23-lint: write failed\n", "");
    return 1;
}

static int dsr_diff(const struct dsr_cfg *c, FILE *out, FILE *err)
{
    int rc = dsr_preflight(c, err);
    if (rc)
        return rc;
    struct dsr_set allowed = {0}, hits = {0}, nw = {0}, stale = {0};
    rc = dsr_load_base(c, err, &allowed);
    if (rc)
        return rc;
    struct dsr_acc a = { .c = c, .hits = &hits };
    for (int i = 0; rc == 0 && i < c->n_roots; i++)
        rc = walk_src(c->roots[i], 1, dsr_on_file, &a);
    if (rc)
        return rc;
    qsort(hits.n, (size_t)hits.count, DSR_PATH, dsr_cmp);
    rc = dsr_classify(&allowed, &hits, &nw, &stale);
    if (rc)
        return rc;
    qsort(nw.n, (size_t)nw.count, DSR_PATH, dsr_cmp);
    qsort(stale.n, (size_t)stale.count, DSR_PATH, dsr_cmp);
    return dsr_report(out, &c->msg, allowed.count, &nw, &stale);
}

static int dsr_parse_roots(const char *text, struct dsr_roots *r)
{
    r->n = 0;
    if (ovf(snprintf(r->buf, sizeof r->buf, "%s", text), sizeof r->buf))
        return 2;
    char *p = r->buf;
    while (*p != '\0') {
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;
        if (r->n >= DSR_ROOT_CAP)
            return die("z23-lint: derived buffer overflow\n", "");
        r->v[r->n++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
            p++;
        if (*p != '\0')
            *p++ = '\0';
    }
    return 0;
}

static int dsr_run_cfg(const struct dsr_cfg *proto, const char *baseline,
                       const char *roots_text)
{
    struct dsr_cfg c = *proto;
    struct dsr_roots roots;
    c.baseline = baseline;
    int rc = dsr_parse_roots(roots_text, &roots);
    if (rc)
        return rc;
    c.roots = roots.v;
    c.n_roots = roots.n;
    return dsr_diff(&c, stdout, stderr);
}

int check_no_utxo_projection_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return dsr_run_cfg(&k_utxo_cfg,
                       env_or("ZCL_NO_UTXO_PROJECTION_BASELINE",
                              k_utxo_cfg.baseline),
                       env_or("ZCL_NO_UTXO_PROJECTION_SCAN_ROOTS",
                              k_dsr_roots_text));
}

int check_no_block_index_flat_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return dsr_run_cfg(&k_blk_cfg,
                       env_or("ZCL_NO_BLOCK_INDEX_FLAT_BASELINE",
                              k_blk_cfg.baseline),
                       env_or("ZCL_NO_BLOCK_INDEX_FLAT_SCAN_ROOTS",
                              k_dsr_roots_text));
}

/* ── selftest ──────────────────────────────────────────────────────────── */

static int dsr_st_slurp(FILE *out, FILE *err, char *both, size_t cap)
{
    char bo[8192], be[8192];
    int rc = csr_slurp(out, bo, sizeof bo) | csr_slurp(err, be, sizeof be)
        | ovf(snprintf(both, cap, "%s%s", bo, be), cap);
    fclose(out);
    fclose(err);
    return rc;
}

static int dsr_st_plant(const char *root, const char *base_body,
                        const char *rel, const char *body)
{
    char bp[4096], fp[4096];
    if (ovf(snprintf(bp, sizeof bp, "%s/baseline.txt", root), sizeof bp)
        || csr_write(bp, base_body))
        return 1;
    if (!rel || !body)
        return 0;
    return ovf(snprintf(fp, sizeof fp, "%s/%s", root, rel), sizeof fp)
        || csr_write(fp, body);
}

static int dsr_st_exec(const char *root, const struct dsr_cfg *proto,
                       int *rc_out, char *both, size_t cap)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        if (chdir(cwd) != 0)
            return die("z23-lint: getcwd failed\n", "");
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct dsr_cfg c = *proto;
    c.baseline = "baseline.txt";
    c.roots = k_dsr_roots;
    c.n_roots = DSR_N_ROOTS;
    *rc_out = dsr_diff(&c, out, err);
    int slurp = dsr_st_slurp(out, err, both, cap);
    if (chdir(cwd) != 0)
        return die("z23-lint: getcwd failed\n", "");
    return slurp;
}

static int dsr_st_probe(const char *root, const struct dsr_cfg *proto,
                        const char *base_body, const char *rel,
                        const char *body, int want_rc, const char *needle)
{
    char both[16384];
    int rc = 0;
    if (dsr_st_plant(root, base_body, rel, body))
        return 1;
    if (dsr_st_exec(root, proto, &rc, both, sizeof both))
        return 1;
    if (rel) {
        char fp[4096];
        if (!ovf(snprintf(fp, sizeof fp, "%s/%s", root, rel), sizeof fp))
            (void)unlink(fp);
    }
    if (rc != want_rc || (needle && !strstr(both, needle))) {
        fprintf(stderr,
                "%s selftest: want rc %d needle '%s'; got rc %d:\n%s\n",
                proto->msg.gate, want_rc, needle ? needle : "", rc, both);
        return 1;
    }
    return 0;
}

static int dsr_st_roots(const char *root)
{
    for (int i = 0; i < DSR_N_ROOTS; i++) {
        char p[4096];
        if (ovf(snprintf(p, sizeof p, "%s/%s", root, k_dsr_roots[i]),
                sizeof p)
            || csr_mkdirs(p))
            return 1;
    }
    return 0;
}

static int dsr_st_clean(const char *root, const struct dsr_cfg *proto)
{
    return dsr_st_probe(root, proto, "# comments only\n", NULL, NULL, 0,
                        "clean — 0 reviewed consumer(s), no new use");
}

static int dsr_st_new(const char *root, const struct dsr_cfg *proto,
                      const char *plant)
{
    return dsr_st_probe(root, proto, "# none\n", "engine/src/hit.c", plant, 1,
                        proto->msg.new_fail);
}

static int dsr_st_stale(const char *root, const struct dsr_cfg *proto)
{
    return dsr_st_probe(root, proto, "engine/src/gone.c\n", NULL, NULL, 1,
                        "stale baseline row(s) (consumer gone; shrink the baseline)");
}

static int dsr_st_dup(const char *root, const struct dsr_cfg *proto)
{
    return dsr_st_probe(root, proto, "engine/src/a.c\nengine/src/a.c\n",
                        NULL, NULL, 2, "FATAL — duplicate baseline row: ");
}

static int dsr_st_excl(const char *root, const struct dsr_cfg *proto,
                       const char *plant)
{
    return dsr_st_probe(root, proto, "# none\n", "engine/src/test/skip.c",
                        plant, 0,
                        "clean — 0 reviewed consumer(s), no new use");
}

static int dsr_st_boot(const struct dsr_cfg *proto, const char *plant)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-dsr-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    int bad = dsr_st_roots(root);
    if (!bad)
        bad = dsr_st_clean(root, proto)
            | dsr_st_new(root, proto, plant)
            | dsr_st_stale(root, proto)
            | dsr_st_dup(root, proto)
            | dsr_st_excl(root, proto, plant);
    (void)rap_rm_rf(root);
    return bad;
}

int check_no_utxo_projection_selftest(void)
{
    int rc = dsr_st_boot(&k_utxo_cfg, "int utxo_projection_st;\n");
    if (rc == 2)
        return 2;
    return st_ok(rc != 0, "check_no_utxo_projection selftest: OK\n");
}

int check_no_block_index_flat_selftest(void)
{
    int rc = dsr_st_boot(&k_blk_cfg, "int save_block_index_flat(void);\n");
    if (rc == 2)
        return 2;
    return st_ok(rc != 0, "check_no_block_index_flat selftest: OK\n");
}
