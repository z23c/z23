/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Cold-proof preflight engine: parse the dep table, grade each row,
 *          and find fix rules in the Makefile text without running make. */

#include "land_preflight.h"

#include "proof_dependencies.h"

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LP_PATH_MAX 1024
#define LP_LINE_MAX 4096
#define LP_DEF_MAX 65536
#define LP_MAX_ROWS 64
#define LP_TOKEN_MAX 512

static void lp_trim(char *s)
{
    size_t n = strlen(s);
    size_t b = 0;
    while (s[b] == ' ' || s[b] == '\t' || s[b] == '\n' || s[b] == '\r')
        b++;
    memmove(s, s + b, n - b + 1);
    n -= b;
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n'
                     || s[n - 1] == '\r'))
        s[--n] = '\0';
}

struct lp_dep {
    char path[LP_TOKEN_MAX];
    bool consumed;  /* at least one consumer (proof, land or lane) needs it */
    bool optional;  /* the table tolerates absence */
    enum zcl_dep_host host;
};

static bool lp_path_join(char *dst, size_t cap, const char *root,
                         const char *leaf)
{
    int n = snprintf(dst, cap, "%s/%s", root, leaf);
    return n >= 0 && n < (int)cap;
}

/* True when the artifact exists AND the proof could actually read it. The
 * 2026-11-19 queue burned two cold proofs on a mode-0 fixture source, so
 * presence alone is not enough: an unreadable artifact is reported MISSING
 * with the reason named. */
/* The Windows CRT has no lstat; stat is the same answer there for a presence
 * check. This tool builds standalone, so it takes no platform seam. */
static int lp_probe(const char *path, struct stat *st)
{
#if defined(_WIN32)
    return stat(path, st);
#else
    return lstat(path, st);
#endif
}

static bool lp_artifact_present(const char *path, const char **why)
{
    struct stat st;
    if (lp_probe(path, &st) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            *why = "absent";
            return false;
        }
        *why = strerror(errno);
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        struct dirent *ent;
        bool empty = true;
        if (!dir) {
            *why = strerror(errno);
            return false;
        }
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") != 0
                && strcmp(ent->d_name, "..") != 0) {
                empty = false;
                break;
            }
        }
        (void)closedir(dir);
        if (empty) {
            *why = "empty directory";
            return false;
        }
        return true;
    }
    if (access(path, R_OK) != 0) {
        *why = "present but not readable";
        return false;
    }
    return true;
}

/* The fix taxonomy mirrors dev_proof.c's dp_generation_dependency_missing:
 * one command per class, named as the exact make goal a reader can run. */
static void lp_fix_for(const char *dep, char *fix, size_t cap)
{
    static const char hotswap[] =
        "make build/hotswap/zcl_rollback_fixture_a.so"
        " build/hotswap/zcl_rollback_fixture_b.so";
    static const char fixtures[] =
        "make build/fixtures/rlc_child_v1"
        " build/fixtures/rlc_child_broken"
        " build/fixtures/otlp_startup_probe";
    if (strncmp(dep, "vendor/", 7) == 0)
        snprintf(fix, cap, "make vendor");
    else if (strncmp(dep, "build/hotswap/", 14) == 0)
        snprintf(fix, cap, "%s", hotswap);
    else if (strncmp(dep, "build/fixtures/", 15) == 0)
        snprintf(fix, cap, "%s", fixtures);
    else if (strncmp(dep, "build/bin/", 10) == 0)
        snprintf(fix, cap, "make %.500s", dep);
    else
        snprintf(fix, cap, "make install-hooks");
}

/* Resolve one Makefile variable name against the parsed layout. The two
 * full-path tools are composed here: $(LINTC_TOOL) is $(BIN_DIR)/z23-lint
 * (Makefile:7286) and $(CAPABILITY_INVENTORY_TOOL) is $(BIN_DIR)/
 * gen_capability_inventory$(ZCL_HOST_EXEEXT) (Makefile:868) — their rule
 * lines use the bare variable as the whole target. */
static const char *lp_var_value(const char *name, const char *build_dir,
                                const char *bin_dir, const char *exeext)
{
    static char lintc[LP_TOKEN_MAX], inv[LP_TOKEN_MAX];
    if (strcmp(name, "BUILD_DIR") == 0)
        return build_dir;
    if (strcmp(name, "BIN_DIR") == 0)
        return bin_dir;
    if (strcmp(name, "ZCL_HOST_EXEEXT") == 0)
        return exeext;
    if (strcmp(name, "LINTC_TOOL") == 0) {
        snprintf(lintc, sizeof lintc, "%s/z23-lint", bin_dir);
        return lintc;
    }
    if (strcmp(name, "CAPABILITY_INVENTORY_TOOL") == 0) {
        snprintf(inv, sizeof inv, "%s/gen_capability_inventory%s", bin_dir,
                 exeext);
        return inv;
    }
    return NULL;
}

/* Replace every "$(VAR)" whose name lp_var_value resolves with the parsed
 * value, twice, because BIN_DIR's own value references BUILD_DIR. */
static void lp_expand_vars(char *tok, size_t cap, const char *build_dir,
                           const char *bin_dir, const char *exeext)
{
    for (int pass = 0; pass < 2; pass++) {
        char out[LP_LINE_MAX];
        size_t o = 0;
        for (size_t i = 0; tok[i] != '\0' && o + 1 < sizeof out; ) {
            if (tok[i] != '$' || tok[i + 1] != '(') {
                out[o++] = tok[i++];
                continue;
            }
            const char *body = &tok[i + 2];
            const char *close = strchr(body, ')');
            if (!close || (size_t)(close - body) >= LP_TOKEN_MAX) {
                out[o++] = tok[i++];
                continue;
            }
            char name[LP_TOKEN_MAX];
            size_t n = (size_t)(close - body);
            memcpy(name, body, n);
            name[n] = '\0';
            const char *val = lp_var_value(name, build_dir, bin_dir, exeext);
            if (!val) {
                out[o++] = tok[i++];
                continue;
            }
            for (size_t k = 0; val[k] != '\0' && o + 1 < sizeof out; k++)
                out[o++] = val[k];
            i += n + 3;
        }
        out[o] = '\0';
        size_t cl = o < cap ? o : cap - 1;
        memcpy(tok, out, cl);
        tok[cl] = '\0';
    }
}

/* A '%' in a rule target matches any string (GNU make pattern rule). */
static bool lp_pattern_match(const char *pat, const char *target)
{
    const char *star = strchr(pat, '%');
    size_t pre = star ? (size_t)(star - pat) : strlen(pat);
    if (!star)
        return strcmp(pat, target) == 0;
    size_t suf = strlen(star + 1);
    size_t len = strlen(target);
    return len >= pre + suf
        && strncmp(pat, target, pre) == 0
        && strcmp(star + 1, target + len - suf) == 0;
}

static bool lp_is_directive(const char *line)
{
    static const char *const words[] = {
        "ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include",
        "-include", "sinclude", "define", "endef", "export", "unexport",
        "override", "undefine", "load",
    };
    for (size_t i = 0; i < sizeof words / sizeof words[0]; i++) {
        size_t n = strlen(words[i]);
        if (strncmp(line, words[i], n) == 0
            && (line[n] == '\0' || line[n] == ' ' || line[n] == '\t'))
            return true;
    }
    return false;
}

/* Rule lines start at column zero, hold a ':' before any '=', and are not
 * directives, comments, variable assignments or .PHONY-style specials. */
static bool lp_rule_line(const char *line)
{
    if (line[0] == '\0' || line[0] == ' ' || line[0] == '\t')
        return false;
    if (line[0] == '#' || line[0] == '.')
        return false;
    if (lp_is_directive(line))
        return false;
    const char *colon = strchr(line, ':');
    if (!colon)
        return false;
    if (colon[1] == '=')
        return false;
    const char *eq = strchr(line, '=');
    return !eq || eq > colon;
}

static bool lp_is_space(char c)
{
    return c == ' ' || c == '\t';
}

static bool lp_is_eol(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool lp_assign_value(const char *line, const char *name, char *val,
                            size_t cap)
{
    size_t n = strlen(name);
    if (strncmp(line, name, n) != 0)
        return false;
    const char *p = line + n;
    while (lp_is_space(*p))
        p++;
    if (*p != '=')
        return false;
    p++;
    if (*p == '=')
        return false;  /* leave := / ?= alone: this tool needs the plain form */
    while (lp_is_space(*p))
        p++;
    size_t len = strlen(p);
    while (len > 0 && lp_is_eol(p[len - 1]))
        len--;
    if (len == 0 || len >= cap || strchr(p, '$') != NULL)
        return false;  /* nested-variable values are not this tool's input */
    memcpy(val, p, len);
    val[len] = '\0';
    return true;
}

/* Scan the makefile once to learn BUILD_DIR/BIN_DIR, then again looking for
 * a rule whose (variable-expanded) target matches `target` exactly or as a
 * '%' pattern. Text only: make is never run. */
static bool lp_rule_reachable(const char *makefile, const char *target,
                              const char *exeext)
{
    char build_dir[LP_TOKEN_MAX] = "build";
    char bin_dir[LP_LINE_MAX] = "build/bin";
    FILE *f = fopen(makefile, "r");
    if (!f)
        return false;
    char line[LP_LINE_MAX];
    while (fgets(line, sizeof line, f) != NULL) {
        if (!lp_assign_value(line, "BUILD_DIR", build_dir,
                             sizeof build_dir))
            (void)lp_assign_value(line, "BIN_DIR", bin_dir, sizeof bin_dir);
    }
    bool found = false;
    rewind(f);
    while (!found && fgets(line, sizeof line, f) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (!lp_rule_line(line))
            continue;
        char *colon = strchr(line, ':');
        *colon = '\0';
        char tok[LP_LINE_MAX];
        char save[LP_LINE_MAX];
        snprintf(save, sizeof save, "%s", line);
        char *word = strtok(save, " \t");
        while (word != NULL && !found) {
            snprintf(tok, sizeof tok, "%s", word);
            lp_expand_vars(tok, sizeof tok, build_dir, bin_dir, exeext);
            found = lp_pattern_match(tok, target);
            word = strtok(NULL, " \t");
        }
    }
    (void)fclose(f);
    return found;
}

/* Every make goal named in the fix must have a text-visible rule — all of
 * them, not any: one unreachable goal in a multi-goal fix means the fix
 * command itself would fail halfway. */
static bool lp_fix_buildable(const char *makefile, const char *fix,
                             const char *exeext)
{
    char buf[LP_LINE_MAX];
    snprintf(buf, sizeof buf, "%s", fix);
    char *save = buf;
    char *word = strtok(save, " ");
    bool all_rules = true;
    bool any_goal = false;
    while (word != NULL) {
        if (strcmp(word, "make") == 0) {
            word = strtok(NULL, " ");
            continue;
        }
        any_goal = true;
        if (!lp_rule_reachable(makefile, word, exeext))
            all_rules = false;
        word = strtok(NULL, " ");
    }
    return any_goal && all_rules;
}

enum lp_state { LP_CODE, LP_BLOCK, LP_LINE };

/* Consume one character inside a comment: block text is dropped (a newline
 * becomes one separator space), a line comment ends at the newline, and the
 * block closer emits the separator. */
static void lp_skip_comment(char **rp, char **wp, enum lp_state *state)
{
    char *r = *rp;
    char *w = *wp;
    if (*state == LP_BLOCK && r[0] == '*' && r[1] == '/') {
        *state = LP_CODE;
        *w++ = ' ';
        *rp = r + 2;
    } else if (*state == LP_LINE && (r[0] == '\n' || r[0] == '\r')) {
        *state = LP_CODE;
        *w++ = *r;
        *rp = r + 1;
    } else {
        if (r[0] == '\n')
            *w++ = ' ';
        *rp = r + 1;
    }
    *wp = w;
}

/* Remove block (slash-star) and // comment text in place. String literals in
 * the table hold paths with no comment openers, so a flat scan is exact. */
static void lp_strip_comments(char *buf)
{
    char *r = buf;
    char *w = buf;
    enum lp_state state = LP_CODE;
    while (*r != '\0') {
        if (state != LP_CODE) {
            lp_skip_comment(&r, &w, &state);
            continue;
        }
        if (r[0] == '/' && r[1] == '*') {
            state = LP_BLOCK;
            r += 2;
            continue;
        }
        if (r[0] == '/' && r[1] == '/') {
            state = LP_LINE;
            r += 2;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static bool lp_token_is(const char *field, const char *token)
{
    return strstr(field, token) != NULL;
}

static enum zcl_dep_host lp_row_host(const char *field);

/* Split the ZCL_DEP(...) argument text into its five comma fields, stopping
 * at the call's own closing paren. Returns the field count. */
static int lp_split_fields(const char *call,
                           char fields[5][LP_TOKEN_MAX])
{
    int nf = 0;
    int depth = 0;
    size_t o = 0;
    memset(fields, 0, 5 * LP_TOKEN_MAX);
    for (const char *p = call; *p != '\0'; p++) {
        if (*p == '(') {
            depth++;
            continue;
        }
        if (*p == ')') {
            if (depth <= 1)
                break;  /* the call's own closing paren */
            depth--;
            continue;
        }
        if (*p == ',' && depth == 1) {
            if (++nf >= 5)
                break;
            o = 0;
            continue;
        }
        if (o + 1 < LP_TOKEN_MAX)
            fields[nf][o++] = *p;
    }
    for (int i = 0; i < nf; i++)
        lp_trim(fields[i]);
    return nf;
}

/* Map the consumers field to "at least one consumer needs this row". */
static bool lp_row_consumed(const char *field)
{
    return lp_token_is(field, "ZCL_DEP_PROOF")
        || lp_token_is(field, "ZCL_DEP_LAND")
        || lp_token_is(field, "ZCL_DEP_LANE")
        || lp_token_is(field, "ZCL_DEP_ALL")
        || lp_token_is(field, "ZCL_DEP_PL");
}

/* Fill one row from the comma fields inside a ZCL_DEP(...) call: consumers,
 * host, optional flag, acquire. Textual: the table is data, not code. */
static bool lp_parse_row(const char *call, struct lp_dep *row, FILE *err)
{
    char fields[5][LP_TOKEN_MAX];
    int nf = lp_split_fields(call, fields);
    if (nf < 4) {
        fprintf(err, "land-preflight: row has %d of 5 fields: %.120s\n",
                nf + 1, call);
        return false;
    }
    const char *q1 = strchr(fields[0], '"');
    const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
    if (!q1 || !q2) {
        fprintf(err, "land-preflight: row path is not quoted: %.120s\n",
                call);
        return false;
    }
    size_t n = (size_t)(q2 - q1 - 1);
    if (n == 0 || n >= sizeof row->path) {
        fprintf(err, "land-preflight: row path empty or oversized\n");
        return false;
    }
    memcpy(row->path, q1 + 1, n);
    row->path[n] = '\0';
    row->consumed = lp_row_consumed(fields[1]);
    row->optional = fields[3][0] != '\0' && fields[3][0] != '0';
    row->host = lp_row_host(fields[2]);
    return true;
}

static enum zcl_dep_host lp_row_host(const char *field)
{
    if (lp_token_is(field, "ZCL_DEP_HOST_LINUX"))
        return ZCL_DEP_HOST_LINUX;
    if (lp_token_is(field, "ZCL_DEP_HOST_POSIX"))
        return ZCL_DEP_HOST_POSIX;
    return ZCL_DEP_HOST_ANY;
}

/* Find every "ZCL_DEP(" call in the stripped table text and parse it. */
static int lp_parse_def(char *buf, struct lp_dep *rows, size_t max,
                        size_t *count, FILE *err)
{
    lp_strip_comments(buf);
    size_t n = 0;
    const char *p = buf;
    while (p != NULL && (p = strstr(p, "ZCL_DEP(")) != NULL) {
        if (p > buf && (p[-1] == '_' || (p[-1] >= '0' && p[-1] <= '9'))) {
            /* part of a longer identifier, not the row macro */
            p += strlen("ZCL_DEP");
            continue;
        }
        if (n >= max) {
            fprintf(err, "land-preflight: dep table exceeds %zu rows\n",
                    max);
            return -1;
        }
        p += strlen("ZCL_DEP");
        if (!lp_parse_row(p, &rows[n], err))
            return -1;
        if (rows[n].consumed)
            n++;
        p = strchr(p, ')');
    }
    if (n == 0) {
        fprintf(err, "land-preflight: no consumable ZCL_DEP rows in table\n");
        return -1;
    }
    *count = n;
    return 0;
}

/* One graded row. Returns true when the row is MISSING (absent, optional
 * does not cover it, and no make rule can build it). */
static bool lp_print_row(FILE *out, const struct lp_dep *row, bool present,
                         const char *why, const char *makefile,
                         const char *exeext)
{
    char fix[LP_LINE_MAX];
    lp_fix_for(row->path, fix, sizeof fix);
    if (present) {
        fprintf(out, "OK       %s\n", row->path);
        return false;
    }
    if (row->optional && strcmp(why, "absent") == 0) {
        fprintf(out, "OPTIONAL %s absent (table marks it optional)\n",
                row->path);
        return false;
    }
    if (lp_fix_buildable(makefile, fix, exeext)) {
        fprintf(out, "OK       %s (%s; buildable: %s)\n", row->path, why,
                fix);
        return false;
    }
    fprintf(out, "MISSING  %s (%s, no reachable make rule); fix: %s\n",
            row->path, why, fix);
    return true;
}

/* Resolve the effective root/table/makefile paths into def[] and mk[]. */
static int lp_resolve_paths(const struct zcl_land_preflight_opts *opts,
                            char *def, size_t def_cap, char *mk, size_t mk_cap,
                            const char **root_out, FILE *err)
{
    struct zcl_land_preflight_opts defaults;
    if (!opts) {
        defaults = (struct zcl_land_preflight_opts){0};
        opts = &defaults;
    }
    const char *root = opts->root ? opts->root : ".";
    *root_out = root;
    if (!lp_path_join(def, def_cap, root,
                      opts->def_path ? opts->def_path
                                     : "tools/dev/proof_dependencies.def")
        || !lp_path_join(mk, mk_cap, root,
                         opts->makefile ? opts->makefile : "Makefile")) {
        fprintf(err, "land-preflight: root path too long\n");
        return -1;
    }
    return 0;
}

/* Slurp the dep table into buf. Returns the byte count, or negative. */
static long lp_read_def(const char *def, char *buf, size_t cap, FILE *err)
{
    FILE *f = fopen(def, "r");
    if (!f) {
        fprintf(err, "land-preflight: cannot open dep table %s: %s\n", def,
                strerror(errno));
        return -1;
    }
    size_t got = fread(buf, 1, cap - 1, f);
    bool bad = ferror(f) || got == 0;
    (void)fclose(f);
    if (bad) {
        fprintf(err, "land-preflight: cannot read dep table %s\n", def);
        return -1;
    }
    buf[got] = '\0';
    return (long)got;
}

/* Grade one applicable row against the tree. Returns true when MISSING. */
static bool lp_grade_row(FILE *out, const char *root, const char *mk,
                         const struct lp_dep *row)
{
    char full[LP_PATH_MAX];
    if (!lp_path_join(full, sizeof full, root, row->path))
        return lp_print_row(out, row, false, "path too long", mk, "");
    const char *why = "absent";
    bool present = lp_artifact_present(full, &why);
    return lp_print_row(out, row, present, why, mk, "");
}

int zcl_land_preflight_run(const struct zcl_land_preflight_opts *opts,
                           FILE *out, FILE *err)
{
    char def[LP_PATH_MAX];
    char mk[LP_PATH_MAX];
    const char *root = ".";
    if (lp_resolve_paths(opts, def, sizeof def, mk, sizeof mk, &root, err)
        != 0)
        return -1;
    static char buf[LP_DEF_MAX];
    if (lp_read_def(def, buf, sizeof buf, err) < 0)
        return -1;
    struct lp_dep rows[LP_MAX_ROWS];
    size_t count = 0;
    if (lp_parse_def(buf, rows, LP_MAX_ROWS, &count, err) != 0)
        return -1;
    size_t skipped = 0;
    size_t missing = 0;
    for (size_t i = 0; i < count; i++) {
        if (!zcl_dep_host_applies(rows[i].host)) {
            skipped++;
            continue;
        }
        if (lp_grade_row(out, root, mk, &rows[i]))
            missing++;
    }
    fprintf(out, "land-preflight: %zu checked, %zu missing, %zu skipped"
                 " (not applicable on this host)\n", count - skipped,
            missing, skipped);
    return missing > 0 ? 1 : 0;
}
