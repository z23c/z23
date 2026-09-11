/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-describe-budget
 * Single-gate family file. Placement ruling (2026-09-06, Linux side): the
 * small-pattern, ratchet, tree-walk, and git-scan families are claimed or
 * full, so new ports land in their own files; the older in-file routing
 * comments that would have folded this gate into an existing family are
 * overridden by that ruling.
 */

/* ── check-describe-budget ─────────────────────────────────────────────────
 * Byte-parity C23 port of the shell gate tools/lint/
 * check_describe_budget.sh (at 9907c0a14, "discover describe/help documents
 * fit byte budgets"). The shell gate is a DRIVER around a compiled helper:
 * it compiles tools/check_describe_budget.c — a second consumer of the
 * command .def X-macro grammar that calls the REAL
 * zcl_command_registry_describe_json()/menu_json() on every leaf and branch
 * — fresh on every run, then grades the helper's output. That mechanism is
 * the point of the gate (no `make`, no build/ dependency, no second size
 * model, no stale snapshot of the catalog), so the port keeps it exactly:
 * this file re-implements only the driver (prereq check, scan floors,
 * compile-and-run, output framing, --selftest) and still invokes the
 * unchanged helper source with the same flags, include paths, and link
 * units. There is NO built-binary dependency: the helper is compiled from
 * source at gate-run time, as in the shell.
 *
 * DIVERGENCE FROM THE SHELL (deliberate): the shell's LINK_SRCS was a
 * written-down list. The command registry has since split into a family of
 * engine/modules/kernel/src/command_registry*.c translation units that
 * keeps growing under the complexity and file-size ceilings, and every
 * written-down copy of that family has gone stale — the gate then dies on
 * undefined references instead of measuring anything. db_derive_srcs()
 * enumerates the family from the directory (scandir + alphasort + regular
 * file, the same filter db_count_defs() uses) and only the dependencies
 * outside it stay spelled out in k_db_extra_srcs. DB_REG_FLOOR then
 * refuses a scan that found none, the way DEF_FLOOR refuses an empty
 * catalog.
 *
 * Semantic mapping:
 * - The up-front `for required in ...` regular-file check over TOOL_SRC,
 *   BASELINE, and the LINK_SRCS (FATAL, exit 2) is db_prereq, now over the
 *   derived list. Include dirs were never checked; they still are not.
 * - The `"$DEF_DIR"` *.def glob count with DEF_FLOOR=8 is db_count_defs
 *   (scandir; a missing directory yields 0 exactly like the unexpanded
 *   glob) feeding the shared gate_require_scanned, which already prints the
 *   gate_lib.sh text byte-for-byte.
 * - build_tool() is db_compile: ${CC:-cc} inserted RAW (the shell
 *   word-splits it, so "ccache cc" still works), identical flags and
 *   -D set, def_parent first on -I, the nine INCS, -o, TOOL_SRC, LINK_SRCS,
 *   stderr to the log. Compiler diagnostics land in the same log file.
 * - `"$tmp/gate" "$BASELINE" > out.log 2>&1 || rc=$?` is db_run_gate.
 * - The rc!=0 FAIL block (message, blank, 4-space-indented out.log, blank,
 *   trim hint; exit 1) is db_main_fail; the success-path 2-space indent of
 *   out.log on stdout is db_indent_file. Both indent with sed semantics:
 *   every line prefixed, an unterminated final line kept unterminated.
 * - The leaf-count extraction `sed -n 's/^check-describe-budget:
 *   \([0-9]\{1,\}\) leaves render.STAR/\1/p' | head -1` (first match, empty
 *   → 0) with LEAF_FLOOR=200 is db_extract_leaves + gate_require_scanned.
 * - --selftest is db_selftest_body: build the clean helper and prove the
 *   gate passes an unmodified tree (db_st_clean); drop one sibling
 *   command_registry*.c from the derived link and prove the helper then
 *   FAILS to build, so a sibling the walk stops matching cannot go
 *   unnoticed (db_st_missing); copy the .def catalogs,
 *   require the padding anchor to be exactly once in core.def (grep -Fxc →
 *   db_count_anchor), pad it 2000 bytes as an adjacent string literal
 *   (the awk sub → db_pad_core), rebuild against the padded copy, and prove
 *   the gate goes red naming core.wallet.recovery.status (db_st_padded).
 *
 * Baseline: NOT a lint_base_load / lint_base_load_set client. The
 * shrink-only `path  reason` baseline is loaded, enforced, and reported by
 * the compiled helper (tools/check_describe_budget.c), which this port does
 * not reimplement; the driver only checks the file EXISTS (db_prereq).
 * Neither shared helper mode is reachable from here.
 *
 * Parity notes / preserved latent defects:
 * - cc stdout was inherited live by the shell; the port captures it and
 *   replays it after the compile (capture_cmd strips trailing newlines, so
 *   a hypothetical multi-trailing-newline compiler stdout would collapse).
 *   cc writes diagnostics to stderr, so this path is empty in practice.
 * - An unexecutable/crashed helper: the shell records 127/128+sig and takes
 *   the FAIL branch; capture_cmd maps any non-exit to 127 — same branch,
 *   the numeric code never reaches output.
 * - mktemp failure: the shell dies with mktemp's own stderr under set -e
 *   (exit 1); the port fails closed with die() (exit 2). Environment
 *   failure, not a gate verdict.
 * - Selftest `cp` of the catalog's *.def files on an empty/moved catalog
 *   dies with cp's own message under set -e (exit 1); the port returns a
 *   bare 1 (db_copy_defs), and a non-regular *.def entry (cp: omitting
 *   directory) is the same bare 1. cp's diagnostic text is not reproduced.
 * - Selftest grep -Fxc on an unreadable core.def copy prints grep's own
 *   diagnostic and yields "(found )." — the port reproduces the empty
 *   "(found )." but not grep's diagnostic line. Unreachable in practice:
 *   the port just wrote that copy itself.
 * - awk rewrites core.def wholesale (an unterminated final line gains a
 *   newline); db_pad_core does the same.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static const char k_db_name[] = "check_describe_budget";
static const char k_db_tool_src[] = "tools/check_describe_budget.c";
static const char k_db_baseline[] = "tools/lint/describe_budget_baseline.txt";
static const char k_db_def_dir[] = "engine/composition/commands";
static const char k_db_anchor[] =
    "    \"Can this wallet be rebuilt from its words\",";

/* The renderer's link list, kept honest so a missing object is a compile
 * error rather than a silently skipped gate.
 *
 * The registry half is DERIVED, not written down: the complexity and
 * file-size ceilings keep splitting command_registry.c into more sibling
 * TUs (describe, reply, search, validate, execute, path, replace,
 * input_types, devagent_input, input_budget ...), and every hardcoded list
 * of them has gone stale within days — the gate then dies on undefined
 * references, or worse, links an older definition. db_derive_srcs() walks
 * engine/modules/kernel/src for `command_registry*.c` with the same
 * scandir+alphasort+regular-file filter db_count_defs() uses on the .def
 * catalog, so a new sibling joins the link the moment it exists and a
 * deleted one leaves it. Only the dependencies OUTSIDE that family stay
 * spelled out. */
static const char k_db_reg_dir[] = "engine/modules/kernel/src";
static const char k_db_reg_prefix[] = "command_registry";
static const char *const k_db_extra_srcs[] = {
    "platform/modules/json/src/json.c",
    "core/modules/crypto/src/sha256.c",
    "platform/modules/base/src/safe_alloc.c",
    "platform/modules/base/src/log_level.c",
    "platform/modules/platform/src/clock.c",
};

static const char *const k_db_incs[] = {
    "-Iengine/modules/kernel/include",
    "-Iplatform/modules/json/include",
    "-Icore/modules/crypto/include",
    "-Iplatform/modules/base/include",
    "-Iplatform/modules/platform/include",
    "-Iplatform/modules/util/include",
    "-Icontexts/commons/modules/vcs/include",
    "-Iengine/services/include",
    "-Icognition/services/include",
};

/* Floors: refuse to report clean off a catalog that moved or emptied out.
 * DB_REG_FLOOR is the same idea for the derived half: an empty or moved
 * engine/modules/kernel/src would otherwise produce a short link list and
 * a compile error read as a gate verdict. */
enum { DB_DEF_FLOOR = 8, DB_LEAF_FLOOR = 200, DB_REG_FLOOR = 2 };
enum { DB_CMD = 16384, DB_SINK = 65536 };
enum { DB_MAX_SRCS = 64, DB_SRC_PATH = 512 };
#define DB_N_INCS (sizeof k_db_incs / sizeof k_db_incs[0])
#define DB_N_EXTRA (sizeof k_db_extra_srcs / sizeof k_db_extra_srcs[0])

/* The link list for one compile: every derived command_registry*.c first
 * (alphasort order), then k_db_extra_srcs. */
struct db_srcs {
    char path[DB_MAX_SRCS][DB_SRC_PATH];
    size_t n;
    size_t derived;   /* how many of `n` came from the registry directory */
};

/* ── command-string assembly (CC raw, every path shell-quoted) ─────────── */

static int db_cat(char *buf, size_t cap, size_t *n, const char *s)
{
    if (*n >= cap)
        return die("z23-lint: derived buffer overflow\n", "");
    int k = snprintf(buf + *n, cap - *n, "%s", s);
    if (k < 0 || (size_t)k >= cap - *n)
        return die("z23-lint: derived buffer overflow\n", "");
    *n += (size_t)k;
    return 0;
}

static int db_catq(char *buf, size_t cap, size_t *n, const char *arg)
{
    char q[8192];
    int rc = sh_single_quote(arg, q, sizeof q);
    if (rc == 0)
        rc = db_cat(buf, cap, n, q);
    return rc;
}

/* ── small file utilities ──────────────────────────────────────────────── */

/* sed 's/^/<prefix>/' — every line prefixed, an unterminated final line
 * kept unterminated, an empty file emitting nothing. */
static int db_indent_file(const char *path, FILE *out, const char *prefix)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0)
        if (fputs(prefix, out) == EOF
            || fwrite(line, 1, (size_t)n, out) != (size_t)n)
            rc = die("z23-lint: write failed\n", "");
    return fin(f, line, path, rc);
}

static int db_mkdtemp(char *buf, size_t cap, const char *tag)
{
    if (ovf(snprintf(buf, cap, "%s/%s.XXXXXX", env_or("TMPDIR", "/tmp"),
                     tag), cap))
        return 2;
    if (!mkdtemp(buf))
        return die("z23-lint: mkdtemp failed: %s\n", buf);
    return 0;
}

/* The .def glob under "$DEF_DIR" never matches a leading dot; `[ -f ]`
 * follows symlinks. A missing directory yields 0, like the unexpanded
 * glob. */
static int db_count_defs(void)
{
    struct dirent **names = NULL;
    int n = scandir(k_db_def_dir, &names, NULL, alphasort);
    if (n < 0)
        return 0;
    int count = 0;
    for (int i = 0; i < n; i++) {
        const char *nm = names[i]->d_name;
        size_t nl = strlen(nm);
        if (nm[0] != '.' && nl >= 4 && memcmp(nm + nl - 4, ".def", 4) == 0) {
            char full[4096];
            struct stat st;
            int k = snprintf(full, sizeof full, "%s/%s", k_db_def_dir, nm);
            if (k > 0 && (size_t)k < sizeof full && stat(full, &st) == 0
                && S_ISREG(st.st_mode))
                count++;
        }
        free(names[i]);
    }
    free(names);
    return count;
}

/* ── the derived link list ─────────────────────────────────────────────── */

/* `command_registry*.c`, same shape as the .def glob above: no leading dot,
 * the family prefix, the .c suffix. */
static int db_is_reg_src(const char *nm)
{
    size_t nl = strlen(nm);
    size_t pl = sizeof k_db_reg_prefix - 1;
    return nm[0] != '.' && nl > 2 && nl >= pl
        && memcmp(nm, k_db_reg_prefix, pl) == 0
        && memcmp(nm + nl - 2, ".c", 2) == 0;
}

/* Appends "<dir>/<name>" when it is a regular file. A full table, an
 * overlong path, or a non-regular entry is skipped, exactly as the glob
 * plus `[ -f ]` in db_count_defs() skips one. */
static void db_push_src(struct db_srcs *out, const char *dir, const char *nm)
{
    if (out->n >= DB_MAX_SRCS)
        return;
    char *slot = out->path[out->n];
    int k = snprintf(slot, DB_SRC_PATH, "%s/%s", dir, nm);
    struct stat st;
    if (k > 0 && (size_t)k < DB_SRC_PATH && stat(slot, &st) == 0
        && S_ISREG(st.st_mode))
        out->n++;
}

/* Derives the whole link list: every engine/modules/kernel/src/
 * command_registry*.c in alphasort order, then the fixed dependencies.
 * A missing directory yields zero derived entries, which DB_REG_FLOOR
 * then refuses. */
static void db_derive_srcs(struct db_srcs *out)
{
    struct dirent **names = NULL;
    out->n = 0;
    out->derived = 0;
    int n = scandir(k_db_reg_dir, &names, NULL, alphasort);
    for (int i = 0; i < n; i++) {
        if (db_is_reg_src(names[i]->d_name))
            db_push_src(out, k_db_reg_dir, names[i]->d_name);
        free(names[i]);
    }
    free(names);
    out->derived = out->n;
    for (size_t i = 0; i < DB_N_EXTRA && out->n < DB_MAX_SRCS; i++) {
        (void)snprintf(out->path[out->n], DB_SRC_PATH, "%s",
                       k_db_extra_srcs[i]);
        out->n++;
    }
}

/* ── the driver steps ──────────────────────────────────────────────────── */

static int db_prereq(const struct db_srcs *srcs)
{
    for (size_t i = 0; i < srcs->n + 2; i++) {
        const char *req = i == 0 ? k_db_tool_src
                        : i == 1 ? k_db_baseline
                                 : srcs->path[i - 2];
        struct stat st;
        if (stat(req, &st) != 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, "%s: FATAL — missing %s\n", k_db_name, req);
            return 2;
        }
    }
    return 0;
}

/* build_tool(): compile the helper. $1 = output path, $2 = directory
 * holding `commands/`, $3 = the compile log. Returns 0 built, 1 compile
 * failed (diagnostics in the log), 2 internal error. */
static int db_compile(const struct db_srcs *srcs, const char *out,
                      const char *def_parent, const char *log)
{
    char cmd[DB_CMD], sink[DB_SINK], inc[4096];
    size_t n = 0;
    int rc = db_cat(cmd, sizeof cmd, &n, env_or("CC", "cc"));
    rc |= db_cat(cmd, sizeof cmd, &n,
        " -std=c23 -O1 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L"
        " -D_DARWIN_C_SOURCE"
        " -Dst_atim=st_atimespec -Dst_mtim=st_mtimespec"
        " -Dst_ctim=st_ctimespec");
    rc |= ovf(snprintf(inc, sizeof inc, "-I%s", def_parent), sizeof inc);
    rc |= db_cat(cmd, sizeof cmd, &n, " ");
    rc |= db_catq(cmd, sizeof cmd, &n, inc);
    for (size_t i = 0; i < DB_N_INCS; i++) {
        rc |= db_cat(cmd, sizeof cmd, &n, " ");
        rc |= db_catq(cmd, sizeof cmd, &n, k_db_incs[i]);
    }
    rc |= db_cat(cmd, sizeof cmd, &n, " -o ");
    rc |= db_catq(cmd, sizeof cmd, &n, out);
    rc |= db_cat(cmd, sizeof cmd, &n, " ");
    rc |= db_catq(cmd, sizeof cmd, &n, k_db_tool_src);
    for (size_t i = 0; i < srcs->n; i++) {
        rc |= db_cat(cmd, sizeof cmd, &n, " ");
        rc |= db_catq(cmd, sizeof cmd, &n, srcs->path[i]);
    }
    rc |= db_cat(cmd, sizeof cmd, &n, " 2> ");
    rc |= db_catq(cmd, sizeof cmd, &n, log);
    if (rc)
        return 2;
    int code = 0;
    rc = capture_cmd(cmd, sink, sizeof sink, &code);
    if (rc)
        return rc;
    if (sink[0] && fprintf(stdout, "%s\n", sink) < 0)
        return die("z23-lint: write failed\n", "");
    return code == 0 ? 0 : 1;
}

/* `"$gate" "$BASELINE" > "$log" 2>&1 || rc=$?` — the helper's exit code
 * lands in *code; its merged output lands in the log file. */
static int db_run_gate(const char *bin, const char *log, int *code)
{
    char cmd[DB_CMD], sink[256];
    size_t n = 0;
    int rc = db_catq(cmd, sizeof cmd, &n, bin);
    rc |= db_cat(cmd, sizeof cmd, &n, " ");
    rc |= db_catq(cmd, sizeof cmd, &n, k_db_baseline);
    rc |= db_cat(cmd, sizeof cmd, &n, " > ");
    rc |= db_catq(cmd, sizeof cmd, &n, log);
    rc |= db_cat(cmd, sizeof cmd, &n, " 2>&1");
    if (rc)
        return 2;
    return capture_cmd(cmd, sink, sizeof sink, code);
}

/* sed -n 's/^check-describe-budget: \([0-9]\{1,\}\) leaves render[.][*]/\1/p'
 * | head -1 — first matching line's digits; no match leaves 0. */
static int db_extract_leaves(const char *path, long *leaves)
{
    static const char prefix[] = "check-describe-budget: ";
    *leaves = 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (!found && getline(&line, &cap, f) >= 0) {
        if (strncmp(line, prefix, sizeof prefix - 1) != 0)
            continue;
        const char *p = line + sizeof prefix - 1, *q = p;
        while (isdigit((unsigned char)*q))
            q++;
        if (q > p && strncmp(q, " leaves render", 14) == 0) {
            *leaves = strtol(p, NULL, 10);
            found = 1;
        }
    }
    return fin(f, line, path, 0);
}

/* The rc!=0 branch of the main flow: report, indented helper output, trim
 * hint, exit 1. */
static int db_main_fail(const char *log)
{
    if (fputs("FAIL: a leaf's describe document does not fit its byte "
              "budget.\n\n", stderr) == EOF)
        return die("z23-lint: write failed\n", "");
    int rc = db_indent_file(log, stderr, "    ");
    if (rc == 0
        && fputs("\n  Trim the named leaf's `semantics` in "
                 "engine/composition/commands/*.def.\n"
                 "  Do NOT raise ZCL_COMMAND_SPEC_BUDGET.\n",
                 stderr) == EOF)
        rc = die("z23-lint: write failed\n", "");
    return rc ? rc : 1;
}

static int db_main_body(const struct db_srcs *srcs, const char *tmp)
{
    char gate[4096], cc_log[4096], out_log[4096];
    int rc = ovf(snprintf(gate, sizeof gate, "%s/gate", tmp), sizeof gate);
    rc |= ovf(snprintf(cc_log, sizeof cc_log, "%s/cc.log", tmp),
              sizeof cc_log);
    rc |= ovf(snprintf(out_log, sizeof out_log, "%s/out.log", tmp),
              sizeof out_log);
    if (rc == 0)
        rc = db_compile(srcs, gate, "engine/composition", cc_log);
    if (rc == 1) {
        fprintf(stderr, "%s: FATAL — %s does not compile:\n", k_db_name,
                k_db_tool_src);
        (void)db_indent_file(cc_log, stderr, "    ");
        return 2;
    }
    int code = 0;
    long leaves = 0;
    if (rc == 0)
        rc = db_run_gate(gate, out_log, &code);
    if (rc == 0 && code != 0)
        rc = db_main_fail(out_log);
    if (rc == 0)
        rc = db_extract_leaves(out_log, &leaves);
    if (rc == 0)
        rc = gate_require_scanned((int)leaves, DB_LEAF_FLOOR, k_db_name,
            "almost no leaves rendered — the X-macro expansion broke");
    if (rc == 0)
        rc = db_indent_file(out_log, stdout, "  ");
    return rc;
}

int check_describe_budget_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096], tmp[4096];
    struct db_srcs srcs;
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0) {
        db_derive_srcs(&srcs);
        rc = gate_require_scanned((int)srcs.derived, DB_REG_FLOOR, k_db_name,
            "no command_registry*.c under engine/modules/kernel/src — the "
            "command registry moved?");
    }
    if (rc == 0)
        rc = db_prereq(&srcs);
    if (rc == 0)
        rc = gate_require_scanned(db_count_defs(), DB_DEF_FLOOR, k_db_name,
            "no .def catalogs under engine/composition/commands — the "
            "command catalog moved?");
    if (rc == 0)
        rc = db_mkdtemp(tmp, sizeof tmp, "zcl-describe-budget");
    if (rc == 0) {
        rc = db_main_body(&srcs, tmp);
        (void)rap_rm_rf(tmp);
    }
    return rc;
}

/* ── selftest ──────────────────────────────────────────────────────────── */

struct db_st {
    char gate[4096], cc[4096], clean[4096], defs[4096], defparent[4096];
    char gate2[4096], cc2[4096], padded[4096];
    char gate3[4096], cc3[4096];
};

static int db_st_paths(struct db_st *p, const char *tmp)
{
    int rc = ovf(snprintf(p->gate, sizeof p->gate, "%s/gate", tmp),
                 sizeof p->gate);
    rc |= ovf(snprintf(p->cc, sizeof p->cc, "%s/cc.log", tmp), sizeof p->cc);
    rc |= ovf(snprintf(p->clean, sizeof p->clean, "%s/clean.log", tmp),
              sizeof p->clean);
    rc |= ovf(snprintf(p->defs, sizeof p->defs, "%s/defs/commands", tmp),
              sizeof p->defs);
    rc |= ovf(snprintf(p->defparent, sizeof p->defparent, "%s/defs", tmp),
              sizeof p->defparent);
    rc |= ovf(snprintf(p->gate2, sizeof p->gate2, "%s/gate_padded", tmp),
              sizeof p->gate2);
    rc |= ovf(snprintf(p->cc2, sizeof p->cc2, "%s/cc2.log", tmp),
              sizeof p->cc2);
    rc |= ovf(snprintf(p->padded, sizeof p->padded, "%s/padded.log", tmp),
              sizeof p->padded);
    rc |= ovf(snprintf(p->gate3, sizeof p->gate3, "%s/gate_cut", tmp),
              sizeof p->gate3);
    rc |= ovf(snprintf(p->cc3, sizeof p->cc3, "%s/cc3.log", tmp),
              sizeof p->cc3);
    return rc ? 2 : 0;
}

/* The repeated selftest failure shape: one or two message lines on stderr,
 * then the 4-space-indented log, exit 1. */
static int db_st_fail(const char *l1, const char *l2, const char *log)
{
    fputs(l1, stderr);
    if (l2)
        fputs(l2, stderr);
    (void)db_indent_file(log, stderr, "    ");
    return 1;
}

/* Step 1: the unmodified tree must compile and pass. */
static int db_st_clean(const struct db_srcs *srcs, const struct db_st *p)
{
    int rc = db_compile(srcs, p->gate, "engine/composition", p->cc);
    if (rc == 1)
        return db_st_fail("check_describe_budget selftest: FAIL — "
            "tools/check_describe_budget.c does not compile:\n", NULL, p->cc);
    if (rc)
        return rc;
    int code = 0;
    rc = db_run_gate(p->gate, p->clean, &code);
    if (rc)
        return rc;
    if (code != 0)
        return db_st_fail("check_describe_budget selftest: FAIL — the gate "
            "does not pass on\n  an unmodified tree:\n", NULL, p->clean);
    return 0;
}

static int db_copy_one(const char *src, const char *dst)
{
    FILE *in = fopen(src, "r");
    if (!in)
        return die("z23-lint: cannot open %s\n", src);
    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return die("z23-lint: cannot open %s\n", dst);
    }
    char buf[8192];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    fclose(in);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    return rc;
}

/* One glob member of the selftest `cp`: skip non-.def/dot names, fail like
 * cp on a non-regular entry ("omitting directory" → exit 1), else copy. */
static int db_copy_def(const char *nm, const char *dest, int *copied)
{
    size_t nl = strlen(nm);
    if (nm[0] == '.' || nl < 4 || memcmp(nm + nl - 4, ".def", 4) != 0)
        return 0;
    char s[4096], d[4096];
    int rc = ovf(snprintf(s, sizeof s, "%s/%s", k_db_def_dir, nm), sizeof s);
    if (rc == 0)
        rc = ovf(snprintf(d, sizeof d, "%s/%s", dest, nm), sizeof d);
    struct stat st;
    if (rc == 0 && (stat(s, &st) != 0 || !S_ISREG(st.st_mode)))
        rc = 1;
    if (rc == 0)
        rc = db_copy_one(s, d);
    if (rc == 0)
        (*copied)++;
    return rc;
}

/* `mkdir -p` plus `cp` of the catalog's *.def files — the same non-dot
 * .def set. An empty or missing catalog is cp failing under set -e: a bare
 * exit 1. */
static int db_copy_defs(const char *dest)
{
    int rc = csr_mkdirs(dest);
    struct dirent **names = NULL;
    int n = -1;
    if (rc == 0) {
        n = scandir(k_db_def_dir, &names, NULL, alphasort);
        if (n < 0)
            rc = 1;
    }
    int copied = 0;
    for (int i = 0; i < n && rc == 0; i++) {
        rc = db_copy_def(names[i]->d_name, dest, &copied);
        free(names[i]);
    }
    free(names);
    if (rc == 0 && copied == 0)
        rc = 1;
    return rc;
}

/* grep -Fxc "$anchor" — lines exactly equal to the anchor. An unreadable
 * file yields an empty count string in the shell; *open_failed carries that
 * (grep's own diagnostic line is not reproduced — see the header). */
static int db_count_anchor(const char *path, long *count, int *open_failed)
{
    *count = 0;
    *open_failed = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        *open_failed = 1;
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[--n] = '\0';
        if (strcmp(line, k_db_anchor) == 0)
            (*count)++;
    }
    return fin(f, line, path, 0);
}

/* One line of the padding awk: `$0 == anchor { sub(/,$/, " " pad ",", $0) }
 * { print }` — an anchor line loses its trailing comma and gains the quoted
 * 2000-P adjacent literal; every line is printed with a newline. */
static int db_pad_line(char *line, ssize_t n, const char *pad, FILE *out)
{
    if (n > 0 && line[n - 1] == '\n')
        line[--n] = '\0';
    size_t len = strlen(line);
    if (strcmp(line, k_db_anchor) == 0 && len > 0 && line[len - 1] == ',') {
        line[len - 1] = '\0';
        if (fprintf(out, "%s %s,\n", line, pad) < 0)
            return die("z23-lint: write failed\n", "");
        return 0;
    }
    if (fprintf(out, "%s\n", line) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

/* The padding awk, where pad is the 2000-P string in quotes — an adjacent
 * string literal the preprocessor concatenates onto that leaf's summary. */
static int db_pad_core(const char *defs)
{
    char src[4096], dst[4096], pad[2003];
    pad[0] = '"';
    memset(pad + 1, 'P', 2000);
    pad[2001] = '"';
    pad[2002] = '\0';
    int rc = ovf(snprintf(src, sizeof src, "%s/core.def", defs), sizeof src);
    rc |= ovf(snprintf(dst, sizeof dst, "%s/core.def.new", defs),
              sizeof dst);
    if (rc)
        return 2;
    FILE *in = fopen(src, "r");
    if (!in)
        return die("z23-lint: cannot open %s\n", src);
    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return die("z23-lint: cannot open %s\n", dst);
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&line, &cap, in)) >= 0)
        rc = db_pad_line(line, n, pad, out);
    free(line);
    if (rc == 0 && ferror(in))
        rc = die("z23-lint: read failed: %s\n", src);
    fclose(in);
    if (fclose(out) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", dst);
    if (rc == 0 && rename(dst, src) != 0)
        rc = die("z23-lint: rename failed: %s\n", dst);
    return rc;
}

static int db_log_contains(const char *path, const char *needle)
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

/* Step 2: pad one leaf past the budget in a COPY of the catalog and prove
 * the gate goes red on it, naming the padded leaf. */
static int db_st_padded(const struct db_srcs *srcs, const struct db_st *p)
{
    int rc = db_copy_defs(p->defs);
    char core[4096];
    if (rc == 0)
        rc = ovf(snprintf(core, sizeof core, "%s/core.def", p->defs),
                 sizeof core);
    long anch = 0;
    int open_failed = 0;
    if (rc == 0)
        rc = db_count_anchor(core, &anch, &open_failed);
    if (rc)
        return rc;
    if (anch != 1) {
        char num[32] = "";
        if (!open_failed)
            (void)snprintf(num, sizeof num, "%ld", anch);
        fprintf(stderr, "check_describe_budget selftest: FAIL — the padding "
            "anchor is no\n  longer unique in engine/composition/commands/"
            "core.def (found %s). Point the\n  selftest at another leaf's "
            "summary line.\n", num);
        return 1;
    }
    rc = db_pad_core(p->defs);
    if (rc == 0)
        rc = db_compile(srcs, p->gate2, p->defparent, p->cc2);
    if (rc == 1)
        return db_st_fail("check_describe_budget selftest: FAIL — the "
            "padded catalog does\n  not compile, so the fixture proves "
            "nothing:\n", NULL, p->cc2);
    if (rc)
        return rc;
    int code = 0;
    rc = db_run_gate(p->gate2, p->padded, &code);
    if (rc)
        return rc;
    if (code == 0)
        return db_st_fail("check_describe_budget selftest: FAIL — a leaf "
            "padded 2000 bytes\n  past the budget did NOT trip the gate. "
            "The gate is hollow.\n", NULL, p->padded);
    if (!db_log_contains(p->padded,
                         "OVER BUDGET: core.wallet.recovery.status"))
        return db_st_fail("check_describe_budget selftest: FAIL — the "
            "failure did not name\n  the padded leaf:\n", NULL, p->padded);
    return 0;
}

/* The sibling TU step 3 drops. It defines
 * zcl_command_registry_describe_json(), which tools/check_describe_budget.c
 * calls directly, so a link without it cannot resolve. */
static const char k_db_drop_src[] =
    "engine/modules/kernel/src/command_registry_describe.c";

/* Copies `in` into `out` with `drop` removed. Returns 1 when `drop` was
 * there to remove, 0 when it was not. */
static int db_srcs_without(const struct db_srcs *in, const char *drop,
                           struct db_srcs *out)
{
    int found = 0;
    out->n = 0;
    out->derived = 0;
    for (size_t i = 0; i < in->n; i++) {
        if (strcmp(in->path[i], drop) == 0) {
            found = 1;
            continue;
        }
        (void)snprintf(out->path[out->n], DB_SRC_PATH, "%s", in->path[i]);
        out->n++;
        if (i < in->derived)
            out->derived++;
    }
    return found;
}

/* Step 3: the derived link list must be load-bearing. Drop ONE sibling
 * command_registry*.c and require the helper to fail to build. Without
 * this, a sibling the scandir walk stopped matching — renamed out of the
 * family, moved to another directory — would silently leave the gate
 * measuring a document rendered by whatever definitions still linked. */
static int db_st_missing(const struct db_srcs *srcs, const struct db_st *p)
{
    struct db_srcs cut;
    if (!db_srcs_without(srcs, k_db_drop_src, &cut)) {
        fprintf(stderr, "check_describe_budget selftest: FAIL — %s is no "
            "longer in\n  the derived link list. Point the selftest at "
            "another command_registry*.c\n  the helper needs.\n",
            k_db_drop_src);
        return 1;
    }
    int rc = db_compile(&cut, p->gate3, "engine/composition", p->cc3);
    if (rc == 0)
        return db_st_fail("check_describe_budget selftest: FAIL — the helper "
            "still builds with\n  a sibling command_registry*.c dropped from "
            "the link, so the derived list\n  proves nothing:\n", NULL,
            p->cc3);
    return rc == 1 ? 0 : rc;
}

static int db_selftest_body(const struct db_srcs *srcs, const char *tmp)
{
    struct db_st p;
    int rc = db_st_paths(&p, tmp);
    if (rc == 0)
        rc = db_st_clean(srcs, &p);
    if (rc == 0)
        rc = db_st_padded(srcs, &p);
    if (rc == 0)
        rc = db_st_missing(srcs, &p);
    if (rc == 0)
        fputs("check_describe_budget selftest: PASS — clean tree passes; "
              "a leaf padded past ZCL_COMMAND_SPEC_BUDGET fails and is "
              "named; a dropped sibling command_registry*.c breaks the "
              "link\n", stdout);
    return rc;
}

int check_describe_budget_selftest(void)
{
    char root[4096], tmp[4096];
    struct db_srcs srcs;
    int rc = cic_repo_root(root, sizeof root);
    if (rc == 0 && chdir(root) != 0)
        rc = 2;
    if (rc == 0) {
        db_derive_srcs(&srcs);
        rc = gate_require_scanned((int)srcs.derived, DB_REG_FLOOR, k_db_name,
            "no command_registry*.c under engine/modules/kernel/src — the "
            "command registry moved?");
    }
    if (rc == 0)
        rc = db_mkdtemp(tmp, sizeof tmp, "zcl-describe-budget-selftest");
    if (rc == 0) {
        rc = db_selftest_body(&srcs, tmp);
        (void)rap_rm_rf(tmp);
    }
    return rc;
}
