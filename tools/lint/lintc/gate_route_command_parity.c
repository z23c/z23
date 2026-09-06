/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-route-command-parity
 * Single-gate family file. Placement ruling (2026-09-06, Linux side): both
 * small-pattern families are claimed by lintc26 (gate_ratchet_ports.c) and
 * lintc28 (gate_pattern_small.c), so new ports land in their own files; the
 * older in-file routing comments that would have folded this gate into an
 * existing family are overridden by that ruling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* ── check-route-command-parity ────────────────────────────────────────────
 * Byte-parity C23 port of the shell gate tools/lint/
 * check_route_command_parity.sh (at eb95d4c74, "REST route <-> native
 * command parity (OS-B3b)"). Every entry in k_api_resource_routes[]
 * (engine/controllers/src/api_controller_routes.c) carries a command_path
 * naming the native command registry leaf (engine/composition/commands/
 * *.def) that owns the same data/service, or "none:<short-reason>". The gate
 * fails when a non-"none:" path names no real LEAF (a ZCL_COMMAND_BRANCH
 * group node does not count), when a NEW "none:" value is not in
 * tools/lint/route_command_parity_baseline.txt (shrink-only ratchet), or
 * when a baseline line is STALE (no route emits that reason any more).
 *
 * Semantic mapping:
 * - Routes: the awk that joins each multi-line API_ROUTE( call into one
 *   logical line (paren-depth counter, /^#define/ skipped) is
 *   rcp_read_routes; the `grep -oE '"[^"]*"[[:space:]]*\)[[:space:]]*,?
 *   [[:space:]]*$' | tail -1 | sed -E 's/^"(.*)"[^"]*$/\1/'` extraction of
 *   the final string literal is rcp_emit (one $-anchored regexec — only one
 *   match can end at end-of-line, so tail -1 is the identity — then
 *   first-quote/last-quote capture).
 * - Leaves: the per-.def awk (a /^ZCL_COMMAND_/ line arms want_next with
 *   the [A-Z_]+ macro kind; the first following line that begins with
 *   optional whitespace plus a quote yields the path; ZCL_COMMAND_BRANCH is
 *   not a leaf) is rcp_leaf_file / rcp_leaf_dir.
 * - Baseline: hand-rolled, NOT lint_base_load_set — the shell loop skips
 *   empty and ^[[:space:]]*# lines but does NOT trim, counts every stored
 *   line (duplicates included) into the clean-line arithmetic, collapses
 *   duplicates for membership and staleness, drops an unterminated final
 *   line (bash `while read`), and touches the file into existence.
 *   lint_base_load_set trims and strips mid-line comments; lint_base_load
 *   is exact-pin. Neither matches, so the loader stays local.
 *
 * Parity notes / preserved latent defects:
 * - The shell's `sort -u` of leaf paths ran under the ambient locale, but
 *   the sorted blob feeds only a membership set and never reaches output;
 *   the port keeps an insertion-order vector with linear membership.
 * - The shell reported STALE entries in bash associative-array hash order.
 *   The port reports them in baseline file order — byte-identical whenever
 *   zero or one entry is stale; with several stale entries the original's
 *   order was not a stable contract.
 * - A single-line API_ROUTE(...) entry is never printed by the awk (buf is
 *   armed but not flushed at depth 0): followed by another API_ROUTE( line
 *   it is silently DROPPED; followed by anything else the join swallows
 *   that line and the entry usually dies as unparseable. Reproduced
 *   state-for-state.
 * - The "could not parse command_path" FATAL is shadowed by set -e +
 *   pipefail: a final argument that is not a quoted string makes grep exit
 *   1 and the shell dies SILENTLY with exit 1 before the FATAL can print
 *   (see rcp_emit). Only an empty "" final literal reaches the FATAL text.
 *   Both branches are reproduced byte-exactly.
 * - A leaf macro whose path sits on the macro line itself would mislabel
 *   the next quote-led line as its path (BRANCH lines use exactly this to
 *   swallow their continuation). Reproduced.
 * - With zero *.def files the shell fed awk the literal unexpanded glob and
 *   died on awk's exit 2 under set -e; the port instead reaches the
 *   gate_require_scanned floor — same exit 2, different stderr text.
 * - The SIGPIPE hazard the shell comments about (grep -q closing the pipe)
 *   does not exist here: there are no pipes.
 * - A baseline path that exists but is not a regular file fails nonzero in
 *   both, with different messages (shell: bash redirection error, exit 1;
 *   port: read failure, exit 2).
 */

static const char k_rcp_routes[] =
    "engine/controllers/src/api_controller_routes.c";
static const char k_rcp_base[] = "tools/lint/route_command_parity_baseline.txt";
static const char k_rcp_cmd_dir[] = "engine/composition/commands";
static const char k_rcp_name[] = "check_route_command_parity";

struct rcp_list { char **v; size_t n, cap; };
struct rcp_base { struct rcp_list keys; int count; };
struct rcp_verdict {
    struct rcp_list bad, newn, seenn, stale;
    int fail;
};

static int rcp_push(struct rcp_list *l, const char *s, size_t n)
{
    if (l->n == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        char **nv = realloc(l->v, nc * sizeof *nv); // raw-alloc-ok:lint-runtime
        if (!nv)
            return die("z23-lint: out of memory\n", "");
        l->v = nv;
        l->cap = nc;
    }
    char *copy = malloc(n + 1); // raw-alloc-ok:lint-runtime
    if (!copy)
        return die("z23-lint: out of memory\n", "");
    memcpy(copy, s, n);
    copy[n] = '\0';
    l->v[l->n++] = copy;
    return 0;
}

static int rcp_has(const struct rcp_list *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i], s) == 0)
            return 1;
    return 0;
}

static int rcp_add_uniq(struct rcp_list *l, const char *s, size_t n)
{
    char tmp[512];
    if (n >= sizeof tmp)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(tmp, s, n);
    tmp[n] = '\0';
    if (rcp_has(l, tmp))
        return 0;
    return rcp_push(l, s, n);
}

static void rcp_free(struct rcp_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
}

static int rcp_path(char *buf, size_t cap, const char *root, const char *rel)
{
    int k = strcmp(root, ".") == 0
        ? snprintf(buf, cap, "%s", rel)
        : snprintf(buf, cap, "%s/%s", root, rel);
    return ovf(k, cap);
}

/* ── route table parse (the API_ROUTE-joining awk + the tail extraction) ── */

struct rcp_buf { char *s; size_t n, cap; };

static int rcp_buf_grow(struct rcp_buf *b, size_t need)
{
    if (need <= b->cap)
        return 0;
    size_t nc = b->cap ? b->cap * 2 : 256;
    while (nc < need)
        nc *= 2;
    char *ns = realloc(b->s, nc); // raw-alloc-ok:lint-runtime
    if (!ns)
        return die("z23-lint: out of memory\n", "");
    b->s = ns;
    b->cap = nc;
    return 0;
}

/* awk: buf = $0 (reset, even mid-collection) */
static int rcp_buf_set(struct rcp_buf *b, const char *s, size_t n)
{
    if (rcp_buf_grow(b, n + 1))
        return 2;
    memcpy(b->s, s, n);
    b->s[n] = '\0';
    b->n = n;
    return 0;
}

/* awk: buf = buf " " $0 (single-space join) */
static int rcp_buf_cat(struct rcp_buf *b, const char *s, size_t n)
{
    if (rcp_buf_grow(b, b->n + 1 + n + 1))
        return 2;
    b->s[b->n] = ' ';
    memcpy(b->s + b->n + 1, s, n);
    b->n += 1 + n;
    b->s[b->n] = '\0';
    return 0;
}

/* gsub-count of '(' minus gsub-count of ')' — every char, string literals
 * included, exactly like the awk. */
static int rcp_parens(const char *s)
{
    int d = 0;
    for (; *s; s++)
        d += (*s == '(') - (*s == ')');
    return d;
}

/* grep -oE '"[^"]*"[[:space:]]*\)[[:space:]]*,?[[:space:]]*$' | tail -1
 * | sed -E 's/^"(.*)"[^"]*$/\1/' on one joined entry. Latent defect,
 * preserved: the assignment runs under set -e + pipefail, so when grep
 * finds NO match the shell dies silently with exit 1 before the empty-cp
 * FATAL can run — reproduced as a bare return 1. The FATAL (exit 2) is
 * reachable only when the final literal is "" — grep matches, sed captures
 * the empty string, and [ -z "$cp" ] fires. */
static int rcp_emit(const char *entry, regex_t *tail, struct rcp_list *cps,
                    FILE *err)
{
    regmatch_t m;
    if (regexec(tail, entry, 1, &m, 0) != 0)
        return 1;
    const char *s = entry + m.rm_so;
    size_t n = (size_t)(m.rm_eo - m.rm_so), last = n - 1;
    while (last > 0 && s[last] != '"')
        last--;
    if (last == 1) {
        fprintf(err, "%s: FATAL — could not parse command_path from entry:\n"
                "  %s\n", k_rcp_name, entry);
        return 2;
    }
    return rcp_push(cps, s + 1, last - 1);
}

static int rcp_route_line(char *line, struct rcp_buf *buf, int *collecting,
                          int *depth, regex_t *tail, struct rcp_list *cps,
                          FILE *err)
{
    size_t n = strlen(line);
    if (n && line[n - 1] == '\n')
        line[--n] = '\0';
    if (strncmp(line, "#define", 7) == 0)
        return 0;
    if (strstr(line, "API_ROUTE(")) {
        *depth = rcp_parens(line);
        *collecting = 1;
        return rcp_buf_set(buf, line, n);
    }
    if (!*collecting)
        return 0;
    if (rcp_buf_cat(buf, line, n))
        return 2;
    *depth += rcp_parens(line);
    if (*depth > 0)
        return 0;
    *collecting = 0;
    return rcp_emit(buf->s, tail, cps, err);
}

static int rcp_read_routes(const char *path, regex_t *tail,
                           struct rcp_list *cps, FILE *err)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    struct rcp_buf buf = { NULL, 0, 0 };
    int collecting = 0, depth = 0, rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        rc = rcp_route_line(line, &buf, &collecting, &depth, tail, cps, err);
    free(buf.s);
    return fin(f, line, path, rc);
}

/* ── command-leaf scan (the per-.def awk) ────────────────────────────────── */

/* match($0, /^ZCL_COMMAND_[A-Z_]+/) — macro kind is the leading
 * ZCL_COMMAND_ plus the greedy run of [A-Z_]. [A-Z_] is ASCII-only. */
static int rcp_macro_kind(const char *line, char *macro, size_t cap)
{
    size_t i = 12;
    while ((line[i] >= 'A' && line[i] <= 'Z') || line[i] == '_')
        i++;
    if (i >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    memcpy(macro, line, i);
    macro[i] = '\0';
    return 0;
}

/* want_next == 1: if ($0 ~ /^[[:space:]]*"/) — the path is the bytes between
 * the first and second quote; BRANCH never prints. Returns 1 when the line
 * was consumed as the path line (want_next := 0). */
static int rcp_leaf_path_line(const char *line, const char *macro,
                              struct rcp_list *leaves, int *consumed)
{
    const char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (*p != '"')
        return 0;
    *consumed = 1;
    p++;
    const char *e = strchr(p, '"');
    if (strcmp(macro, "ZCL_COMMAND_BRANCH") == 0)
        return 0;
    return rcp_add_uniq(leaves, p, e ? (size_t)(e - p) : strlen(p));
}

static int rcp_leaf_file(const char *path, struct rcp_list *leaves)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    char macro[80] = "";
    int want_next = 0, rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        if (strncmp(line, "ZCL_COMMAND_", 12) == 0) {
            rc = rcp_macro_kind(line, macro, sizeof macro);
            want_next = 1;
            continue;
        }
        int consumed = 0;
        if (want_next)
            rc = rcp_leaf_path_line(line, macro, leaves, &consumed);
        want_next = want_next && !consumed;
    }
    return fin(f, line, path, rc);
}

/* The shell's $CMD_DIR glob for .def files never matches a leading dot. */
static int rcp_leaf_dir(const char *root, struct rcp_list *leaves)
{
    char dir[4096];
    if (rcp_path(dir, sizeof dir, root, k_rcp_cmd_dir))
        return 2;
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        const char *name = names[i]->d_name;
        size_t nl = strlen(name);
        if (name[0] != '.' && nl >= 4
            && memcmp(name + nl - 4, ".def", 4) == 0) {
            char full[4096];
            if (ovf(snprintf(full, sizeof full, "%s/%s", dir, name),
                    sizeof full))
                rc = 2;
            else
                rc = rcp_leaf_file(full, leaves);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

/* ── baseline (the hand-rolled shell set; see the mapping comment) ──────── */

static int rcp_base_line(char *line, ssize_t len, struct rcp_base *b)
{
    if (len <= 0 || line[len - 1] != '\n')
        return 0; /* bash `while read` drops the unterminated final line */
    line[--len] = '\0';
    const char *p = line;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (len == 0 || *p == '#')
        return 0;
    int rc = rcp_add_uniq(&b->keys, line, (size_t)len);
    b->count++;
    return rc;
}

static int rcp_base_load(const char *root, struct rcp_base *b)
{
    char path[4096];
    if (rcp_path(path, sizeof path, root, k_rcp_base))
        return 2;
    struct stat st;
    if (stat(path, &st) != 0) { /* [ -f "$BASELINE" ] || touch "$BASELINE" */
        FILE *t = fopen(path, "w");
        if (!t)
            return die("z23-lint: cannot create %s\n", path);
        if (fclose(t) != 0)
            return die("z23-lint: fclose failed: %s\n", path);
    }
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int rc = 0;
    while (rc == 0 && (len = getline(&line, &cap, f)) >= 0)
        rc = rcp_base_line(line, len, b);
    return fin(f, line, path, rc);
}

/* ── verdict + report ────────────────────────────────────────────────────── */

static int rcp_judge_one(const char *cp, const struct rcp_list *leaves,
                         const struct rcp_base *base, struct rcp_verdict *v)
{
    if (strncmp(cp, "none:", 5) == 0) {
        int rc = rcp_push(&v->seenn, cp, strlen(cp));
        if (rc == 0 && !rcp_has(&base->keys, cp)) {
            v->fail = 1;
            rc = rcp_push(&v->newn, cp, strlen(cp));
        }
        return rc;
    }
    if (!rcp_has(leaves, cp)) {
        v->fail = 1;
        return rcp_push(&v->bad, cp, strlen(cp));
    }
    return 0;
}

static int rcp_stale(const struct rcp_base *base,
                     const struct rcp_list *seenn, struct rcp_list *stale)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < base->keys.n; i++)
        if (!rcp_has(seenn, base->keys.v[i]))
            rc = rcp_push(stale, base->keys.v[i], strlen(base->keys.v[i]));
    return rc;
}

static int rcp_sec(const struct rcp_list *l, FILE *out, const char *head,
                   const char *tail_text)
{
    if (fprintf(out, head, l->n) < 0)
        return die("z23-lint: write failed\n", "");
    for (size_t i = 0; i < l->n; i++)
        if (fprintf(out, "  %s\n", l->v[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return fputs(tail_text, out) < 0 ? die("z23-lint: write failed\n", "")
                                     : 0;
}

static int rcp_report(const struct rcp_verdict *v, int nroutes, int bcount,
                      FILE *out)
{
    if (!v->fail && v->stale.n == 0) {
        if (fprintf(out, "%s: clean — %d route(s), %d mapped to a real leaf,"
                    " %d grandfathered none:\n", k_rcp_name, nroutes,
                    nroutes - bcount, bcount) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    int rc = fputc('\n', out) == EOF;
    if (!rc && v->bad.n)
        rc = rcp_sec(&v->bad, out,
            "check_route_command_parity: %zu command_path(s) do NOT name a "
            "real leaf in engine/composition/commands/*.def:\n",
            "\nFix the route's command_path in engine/controllers/src/"
            "api_controller_routes.c to a real leaf path,\nor (if honestly "
            "unmapped) set it to \"none:<short-reason>\" and add\nthat line "
            "to tools/lint/route_command_parity_baseline.txt.\n");
    if (!rc && v->newn.n)
        rc = rcp_sec(&v->newn, out,
            "check_route_command_parity: %zu NEW none: entry(ies) not in "
            "the baseline:\n",
            "\nAdd each to tools/lint/route_command_parity_baseline.txt "
            "(one per line) if the route genuinely has no\nnative command "
            "leaf yet, or wire the route to a real leaf instead.\n");
    if (!rc && v->stale.n)
        rc = rcp_sec(&v->stale, out,
            "check_route_command_parity: %zu STALE baseline entry(ies) (no "
            "route emits this reason any more):\n",
            "\nA route was deleted or its command_path got mapped to a real "
            "leaf —\ngood. Delete its line from tools/lint/"
            "route_command_parity_baseline.txt so the ratchet reflects the\n"
            "smaller set.\n");
    return rc ? die("z23-lint: write failed\n", "") : 1;
}

/* ── orchestration ───────────────────────────────────────────────────────── */

/* The shell's up-front hollow-gate guards: missing route table or command
 * directory is FATAL exit 2, never a vacuous pass. */
static int rcp_prereq(const char *root, FILE *err)
{
    char path[4096];
    struct stat st;
    if (rcp_path(path, sizeof path, root, k_rcp_routes))
        return 2;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(err, "%s: FATAL — %s not found.\n", k_rcp_name, k_rcp_routes);
        return 2;
    }
    if (rcp_path(path, sizeof path, root, k_rcp_cmd_dir))
        return 2;
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(err, "%s: FATAL — %s not found.\n", k_rcp_name,
                k_rcp_cmd_dir);
        return 2;
    }
    return 0;
}

static void rcp_free_all(struct rcp_list *cps, struct rcp_list *leaves,
                         struct rcp_verdict *v)
{
    rcp_free(cps);
    rcp_free(leaves);
    rcp_free(&v->seenn);
    rcp_free(&v->bad);
    rcp_free(&v->newn);
    rcp_free(&v->stale);
}

static int rcp_scan(const char *root, regex_t *tail, FILE *out, FILE *err)
{
    struct rcp_list cps = { NULL, 0, 0 }, leaves = { NULL, 0, 0 };
    struct rcp_base base = { { NULL, 0, 0 }, 0 };
    struct rcp_verdict v;
    memset(&v, 0, sizeof v);
    char path[4096];
    int rc = rcp_path(path, sizeof path, root, k_rcp_routes);
    if (rc == 0)
        rc = rcp_read_routes(path, tail, &cps, err);
    if (rc == 0)
        rc = gate_require_scanned((int)cps.n, 1, k_rcp_name,
            "k_api_resource_routes[] in engine/controllers/src/"
            "api_controller_routes.c parsed to zero entries — the API_ROUTE("
            " call shape likely changed; update this gate's awk/grep.");
    if (rc == 0)
        rc = rcp_leaf_dir(root, &leaves);
    if (rc == 0)
        rc = gate_require_scanned((int)leaves.n, 1, k_rcp_name,
            "engine/composition/commands/*.def parsed to zero leaf paths — "
            "the ZCL_COMMAND_* macro shape likely changed; update this "
            "gate's awk.");
    if (rc == 0)
        rc = rcp_base_load(root, &base);
    for (size_t i = 0; rc == 0 && i < cps.n; i++)
        rc = rcp_judge_one(cps.v[i], &leaves, &base, &v);
    if (rc == 0)
        rc = rcp_stale(&base, &v.seenn, &v.stale);
    if (rc == 0)
        rc = rcp_report(&v, (int)cps.n, base.count, out);
    rcp_free(&base.keys);
    rcp_free_all(&cps, &leaves, &v);
    return rc;
}

static int rcp_check(const char *root, FILE *out, FILE *err)
{
    int rc = rcp_prereq(root, err);
    if (rc)
        return rc;
    regex_t tail;
    rc = reg_fail(&tail, regcomp(&tail,
        "\"[^\"]*\"[[:space:]]*\\)[[:space:]]*,?[[:space:]]*$",
        REG_EXTENDED));
    if (rc)
        return rc;
    rc = rcp_scan(root, &tail, out, err);
    regfree(&tail);
    return rc;
}

int check_route_command_parity_run(int argc, char **argv)
{
    char cwd[4096];
    const char *root = NULL;
    if (argc > 0 && argv[0][0])
        root = argv[0];
    else if (env_or("GATE_ROOT", "")[0])
        root = getenv("GATE_ROOT");
    else {
        if (!getcwd(cwd, sizeof cwd))
            return die("z23-lint: getcwd failed\n", "");
        root = cwd;
    }
    /* cd "$ROOT" under set -e: a bad root exits nonzero with bash's own
     * message; the port fails closed with exit 2. */
    if (chdir(root) != 0)
        return 2;
    return rcp_check(".", stdout, stderr);
}

/* ── selftest (the shell gate had none; each violation class is planted) ── */

static int rcp_st_tree(const char *root, const char *cp1, const char *cp2)
{
    char p[4096], body[2048];
    int k = snprintf(body, sizeof body,
        "/* selftest fixture route table */\n"
        "#define API_ROUTE(method_, path_, command_path_) \\\n"
        "    { method_, path_, command_path_ }\n"
        "\n"
        "static const int k_api_resource_routes[] = {\n"
        "    API_ROUTE(\"GET\", \"/api/one\",\n"
        "              \"%s\"),\n"
        "    API_ROUTE(\"GET\", \"/api/two\",\n"
        "              \"%s\"),\n"
        "};\n", cp1, cp2);
    if (ovf(k, sizeof body)
        || ovf(snprintf(p, sizeof p, "%s/%s", root, k_rcp_routes), sizeof p)
        || csr_write(p, body))
        return 1;
    k = snprintf(body, sizeof body,
        "/* selftest fixture command registry */\n"
        "\n"
        "ZCL_COMMAND_BRANCH(\"one\", \"root\", \"fixture branch\")\n"
        "\n"
        "ZCL_COMMAND_READY_READ(\n"
        "    \"one.alpha\", \"one\", \"\", \"Alpha fixture leaf\",\n"
        "    \"a longer description\", 0)\n");
    if (ovf(k, sizeof body)
        || ovf(snprintf(p, sizeof p, "%s/engine/composition/commands/"
                        "one.def", root), sizeof p)
        || csr_write(p, body))
        return 1;
    return 0;
}

/* An entry whose final argument is not a string literal: grep finds no
 * quoted tail, and set -e + pipefail kill the shell silently with exit 1
 * before the empty-cp FATAL can print. */
static int rcp_st_unparseable(const char *root)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/%s", root, k_rcp_routes), sizeof p))
        return 1;
    return csr_write(p,
        "/* selftest fixture route table */\n"
        "static const int k_api_resource_routes[] = {\n"
        "    API_ROUTE(\"GET\", \"/api/one\",\n"
        "              \"one.alpha\"),\n"
        "    API_ROUTE(\"GET\", \"/api/broken\",\n"
        "              0),\n"
        "};\n");
}

static int rcp_st_base(const char *root, const char *body)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/%s", root, k_rcp_base), sizeof p))
        return 1;
    if (body)
        return csr_write(p, body);
    (void)unlink(p);
    return 0;
}

/* needle: searched in the merged output; err_needle: must be on the error
 * stream exactly (the route-parse FATAL is stderr-only in the shell). */
static int rcp_st_case2(const char *root, int want_rc, const char *needle,
                        const char *err_needle)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = rcp_check(root, out, err);
    char bo[8192], be[8192], both[16384];
    int src = csr_slurp(out, bo, sizeof bo) | csr_slurp(err, be, sizeof be)
        | ovf(snprintf(both, sizeof both, "%s%s", bo, be), sizeof both);
    fclose(out);
    fclose(err);
    int ok = !src && rc == want_rc && (!needle || strstr(both, needle))
        && (!err_needle || strstr(be, err_needle));
    if (!ok) {
        fprintf(stderr, "check_route_command_parity selftest: want rc %d "
                "needle '%s'; got rc %d and:\n%s\n", want_rc,
                needle ? needle : "(none)", rc, both);
        return 1;
    }
    return 0;
}

static int rcp_st_case(const char *root, int want_rc, const char *needle)
{
    return rcp_st_case2(root, want_rc, needle, NULL);
}

/* Hollow-scan cases (missing route file / empty parse) fail through
 * gate_require_scanned, which writes to process stderr — only the exit
 * code is asserted here. */
static int rcp_st_hollow(const char *root)
{
    char p[4096];
    if (ovf(snprintf(p, sizeof p, "%s/%s", root, k_rcp_routes), sizeof p)
        || csr_write(p, "/* fixture with no API_ROUTE calls at all */\n"
                        "static const int k_api_resource_routes[] = { 0 };\n"))
        return 1;
    int bad = rcp_st_case(root, 2, NULL);
    if (ovf(snprintf(p, sizeof p, "%s/%s", root, k_rcp_routes), sizeof p))
        return 1;
    if (unlink(p) != 0)
        return 1;
    return bad | rcp_st_case(root, 2, "FATAL — engine/controllers/src/"
                                      "api_controller_routes.c not found.");
}

int check_route_command_parity_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-rcp-XXXXXX", td),
            sizeof tmpl))
        return 2;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    int bad = rcp_st_tree(root, "one.alpha", "none:two-no-leaf");
    if (!bad) {
        /* clean: one real leaf + one grandfathered none: */
        bad |= rcp_st_base(root, "# comment line\n\nnone:two-no-leaf\n");
        bad |= rcp_st_case(root, 0, "check_route_command_parity: clean — "
            "2 route(s), 1 mapped to a real leaf, 1 grandfathered none:");
        /* command_path naming no real leaf */
        bad |= rcp_st_tree(root, "one.gone", "none:two-no-leaf");
        bad |= rcp_st_case(root, 1, "1 command_path(s) do NOT name a real "
            "leaf in engine/composition/commands/*.def:\n  one.gone");
        /* a NEW none: value not in the baseline */
        bad |= rcp_st_tree(root, "one.alpha", "none:two-no-leaf");
        bad |= rcp_st_base(root, "# nothing pinned\n");
        bad |= rcp_st_case(root, 1, "1 NEW none: entry(ies) not in the "
            "baseline:\n  none:two-no-leaf");
        /* a baseline line no route emits any more is STALE */
        bad |= rcp_st_base(root, "none:two-no-leaf\nnone:stale-reason\n");
        bad |= rcp_st_case(root, 1, "1 STALE baseline entry(ies) (no route "
            "emits this reason any more):\n  none:stale-reason");
        /* a missing baseline is touched into existence; every none: is NEW */
        bad |= rcp_st_base(root, NULL);
        bad |= rcp_st_case(root, 1, "NEW none: entry(ies)");
        bad |= rcp_st_base(root, "none:two-no-leaf\n");
        /* a non-string final argument dies silently under set -e/pipefail */
        bad |= rcp_st_unparseable(root);
        bad |= rcp_st_case(root, 1, NULL);
        /* an empty "" final literal reaches the shell's empty-cp FATAL,
         * printed to stderr only */
        bad |= rcp_st_tree(root, "one.alpha", "");
        bad |= rcp_st_case2(root, 2, "could not parse command_path from "
            "entry:", "check_route_command_parity: FATAL — could not parse "
            "command_path from entry:\n");
        bad |= rcp_st_tree(root, "one.alpha", "none:two-no-leaf");
        /* hollow scans and a missing route table are FATAL, never a pass */
        bad |= rcp_st_hollow(root);
    }
    (void)rap_rm_rf(root);
    return st_ok(bad, "check_route_command_parity selftest: OK\n");
}
