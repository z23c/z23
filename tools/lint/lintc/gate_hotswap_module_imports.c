/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_hotswap_module_imports — a hot-swap module may import
 * only what engine/composition/hotswap_module_imports.def allows; the
 * allowlist itself may carry no forbidden capability class, over a closed
 * class vocabulary; built .so artifacts are read with nm and every
 * undefined symbol must be declared. Ported from
 * tools/lint/check_hotswap_module_imports.sh (deleted). Selftest:
 * gate_hotswap_module_imports_selftest.c.
 *
 * Exit: 0 clean (or UNOBSERVED artifact leg), 1 forbidden import or
 * malformed allowlist row, 2 when the gate could not look.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_hotswap_module_imports_priv.h"

static const char k_gate[] = "check_hotswap_module_imports";
static const char k_def[] = "engine/composition/hotswap_module_imports.def";
static const char k_capfile[] = "engine/composition/capability_symbols.def";
static const char k_classfile[] = "engine/composition/capability_classes.def";
static const char k_so_dir[] = "build/hotswap";
static const char k_valid_groups[] =
    " TOOLCHAIN LIBC JSON LOG NODE_COMMAND NODE_STATUS NODE_DB NODE_UTIL"
    " NODE_HOTSWAP NODE_APP ";
static const char k_forbidden_caps[] =
    " CAP_NETWORK CAP_PROCESS CAP_DYNLOAD CAP_PRIVILEGE CAP_WALLET ";
static const char k_permitted_caps[] =
    " CAP_HARMLESS CAP_FS_READ CAP_FS_WRITE CAP_CLOCK CAP_RANDOM ";
static const char k_scratch_tail[] =
    "/.local/state/zclassic23/scratch/lane-imports";

struct hmi_pair {
    char sym[HMI_SYM];
    char cls[HMI_GRP];
};

struct hmi_ctx {
    FILE *out, *err;
    const char *def, *capfile, *so_dir;
    int sandbox;
    struct hmi_pair allow[HMI_ROWS];
    int allow_n, class_vocab_n, scanned_so, fail;
    struct hmi_pair caps[HMI_CAPROWS];
    int caps_n, caps_expect;
    char caplines[HMI_CAP_LINES][HMI_LINE];
    int capline_n;
    char seen[HMI_SEEN][HMI_SYM];
    int seen_n;
    char bad_rows[8192];
};

void hmi_canonical(const char *raw, int darwin, char *out, size_t cap)
{
    const char *p = raw;
    if (darwin && p[0] == '_')
        p++;
    if (strcmp(p, "dyld_stub_binder") == 0)
        p = "";
    snprintf(out, cap, "%s", p);
}

int hmi_spawn_argv(char *const argv[], int merge_err, char *out, size_t cap,
                   size_t *olen, int *code)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        if (merge_err)
            dup2(fds[1], STDERR_FILENO);
        else {
            int nul = open("/dev/null", O_WRONLY);
            if (nul >= 0)
                dup2(nul, STDERR_FILENO);
        }
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = read(fds[0], out + n, cap - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    out[n] = '\0';
    int overflow = 0;
    if (n + 1 >= cap) {
        char extra;
        overflow = read(fds[0], &extra, 1) > 0;
    }
    close(fds[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    *code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    if (olen)
        *olen = n;
    return overflow ? -2 : 0;
}

static void hmi_bad(struct hmi_ctx *c, const char *msg)
{
    fprintf(c->err, "%s: FAIL — %s\n", k_gate, msg);
    c->fail = 1;
}

static void hmi_note(struct hmi_ctx *c, const char *msg)
{
    fprintf(c->out, "  %s\n", msg);
}

static int hmi_marker_ok(void)
{
    const char *m = getenv("ZCL_HOTSWAP_IMPORTS_SELFTEST");
    return m && strcmp(m, k_gate) == 0;
}

static int hmi_scratch_path(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return -1;
    return ovf(snprintf(out, cap, "%s%s", home, k_scratch_tail), cap) ? -1 : 0;
}

/* Reads one text file line by line into lines[][HMI_LINE]. 0 ok, 2 fatal. */
static int hmi_slurp_lines(const char *path, char lines[][HMI_LINE], int *n,
                           int max)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 2;
    char buf[HMI_LINE];
    while (fgets(buf, sizeof buf, f)) {
        size_t len = strlen(buf);
        if (len + 1 >= sizeof buf && (len == 0 || buf[len - 1] != '\n')) {
            fprintf(stderr, "%s: line of %s exceeds %d bytes\n", k_gate, path,
                    HMI_LINE);
            fclose(f);
            return 2;
        }
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        if (*n >= max) {
            fprintf(stderr, "%s: %s exceeds %d lines\n", k_gate, path, max);
            fclose(f);
            return 2;
        }
        snprintf(lines[*n], HMI_LINE, "%s", buf);
        (*n)++;
    }
    fclose(f);
    return 0;
}

static int hmi_group_ok(const char *grp)
{
    char tok[HMI_GRP + 3];
    if (ovf(snprintf(tok, sizeof tok, " %s ", grp), sizeof tok))
        return 0;
    return strstr(k_valid_groups, tok) != NULL;
}

static int hmi_allow_has(const struct hmi_ctx *c, const char *sym)
{
    for (int i = 0; i < c->allow_n; i++)
        if (strcmp(c->allow[i].sym, sym) == 0)
            return 1;
    return 0;
}

static const char *hmi_cap_class(const struct hmi_ctx *c, const char *sym)
{
    for (int i = 0; i < c->caps_n; i++)
        if (strcmp(c->caps[i].sym, sym) == 0)
            return c->caps[i].cls;
    return NULL;
}

static void hmi_seen_add(struct hmi_ctx *c, const char *sym)
{
    if (strlen(sym) >= HMI_SYM)
        return;
    for (int i = 0; i < c->seen_n; i++)
        if (strcmp(c->seen[i], sym) == 0)
            return;
    if (c->seen_n < HMI_SEEN)
        snprintf(c->seen[c->seen_n++], HMI_SYM, "%s", sym);
}

static int hmi_seen_has(const struct hmi_ctx *c, const char *sym)
{
    for (int i = 0; i < c->seen_n; i++)
        if (strcmp(c->seen[i], sym) == 0)
            return 1;
    return 0;
}

/* Parses one row of the exact shape
 * ws* HOTSWAP_MODULE_IMPORT("sym" ws* , ws* "grp" ) — 1 on a match. */
static const char *hmi_skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

/* Copies the non-empty text up to the next '"' (below cap) into out and
 * returns the closing quote, or NULL. */
static const char *hmi_quoted(const char *p, char *out, size_t cap)
{
    const char *q = strchr(p, '"');
    if (!q || q == p || (size_t)(q - p) >= cap)
        return NULL;
    memcpy(out, p, (size_t)(q - p));
    out[q - p] = '\0';
    return q;
}

static int hmi_parse_import_row(const char *line, char *sym, char *grp)
{
    const char *p = hmi_skip_ws(line);
    if (strncmp(p, "HOTSWAP_MODULE_IMPORT(\"", 23) != 0)
        return 0;
    const char *q = hmi_quoted(p + 23, sym, HMI_SYM);
    if (!q)
        return 0;
    p = hmi_skip_ws(q + 1);
    if (*p != ',')
        return 0;
    p = hmi_skip_ws(p + 1);
    if (*p != '"')
        return 0;
    q = hmi_quoted(p + 1, grp, HMI_GRP);
    return q && q[1] == ')';
}

/* Leg 1: the contract file itself. 0 ok, 1 rows flagged (fail set), 2 fatal. */
static int hmi_load_allowlist(struct hmi_ctx *c)
{
    if (access(c->def, F_OK) != 0) {
        fprintf(c->err,
                "%s: FATAL — allowlist %s does not exist. The import contract cannot be checked against a file that is not there; refusing to report clean.\n",
                k_gate, c->def);
        return 2;
    }
    if (hmi_slurp_lines(c->def, c->caplines, &c->capline_n, HMI_CAP_LINES))
        return 2;
    char dupes[2048] = "";
    int matched = 0;
    for (int i = 0; i < c->capline_n; i++) {
        char sym[HMI_SYM], grp[HMI_GRP];
        if (!hmi_parse_import_row(c->caplines[i], sym, grp))
            continue;
        matched++;
        if (!grp[0]) {
            char msg[512];
            snprintf(msg, sizeof msg, "unparseable allowlist row in %s: %s",
                     c->def, c->caplines[i]);
            hmi_bad(c, msg);
        } else if (!hmi_group_ok(grp)) {
            char msg[640];
            snprintf(msg, sizeof msg,
                     "allowlist row for '%s' carries group '%s', which is not one of the declared groups (%s). A row nobody classified is an unreviewed widening.",
                     sym, grp, k_valid_groups);
            hmi_bad(c, msg);
        } else if (hmi_allow_has(c, sym)) {
            if (strlen(dupes) + strlen(sym) + 2 < sizeof dupes) {
                strcat(dupes, " ");
                strcat(dupes, sym);
            }
        } else if (c->allow_n < HMI_ROWS) {
            snprintf(c->allow[c->allow_n].sym, HMI_SYM, "%s", sym);
            snprintf(c->allow[c->allow_n].cls, HMI_GRP, "%s", grp);
            c->allow_n++;
        }
    }
    c->capline_n = 0;
    if (matched == 0) {
        fprintf(c->err,
                "%s: FATAL — %s parsed to ZERO HOTSWAP_MODULE_IMPORT rows.\n"
                "  Either the file was gutted or its row shape changed and this\n"
                "  parser no longer matches it. An empty parse is not an empty\n"
                "  contract; it is an unreadable one.\n", k_gate, c->def);
        return 2;
    }
    if (dupes[0]) {
        char msg[2304];
        snprintf(msg, sizeof msg, "duplicate symbol row(s) in %s:%s", c->def,
                 dupes);
        hmi_bad(c, msg);
    }
    if (c->allow_n < HMI_IMPORT_FLOOR) {
        fprintf(c->err,
                "%s: FATAL — allowlist holds %d row(s), below the floor of %d.\n"
                "  %s was derived from the real undefined-symbol union of every\n"
                "  built module; a drop this far means it was gutted or the parser\n"
                "  stopped matching. Refusing to judge modules against it.\n",
                k_gate, c->allow_n, HMI_IMPORT_FLOOR, c->def);
        return 2;
    }
    if (c->fail)
        return 1;
    char msg[HMI_LINE];
    snprintf(msg, sizeof msg,
             "contract  : OK — %d allowlisted import(s) in %s, all classified, no duplicates",
             c->allow_n, c->def);
    hmi_note(c, msg);
    return 0;
}

static int hmi_is_cap_open(const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    return strncmp(p, "ZCL_CAPABILITY_SYMBOL(", 22) == 0;
}

static int hmi_first_cap(const char *line, char *out)
{
    const char *p = strstr(line, "CAP_");
    if (!p)
        return 0;
    const char *q = p + 4;
    while ((*q >= 'A' && *q <= 'Z') || *q == '_')
        q++;
    if (q == p + 4 || (size_t)(q - p) >= HMI_GRP)
        return 0;
    memcpy(out, p, (size_t)(q - p));
    out[q - p] = '\0';
    return 1;
}

/* Continuation-line lookup: walks forward from row i until the next row
 * opener or EOF, taking the first CAP_ token found. */
static int hmi_lookahead_cap(const struct hmi_ctx *c, int i, char *cls)
{
    for (int j = i + 1; j < c->capline_n; j++) {
        if (hmi_is_cap_open(c->caplines[j]))
            break;
        if (hmi_first_cap(c->caplines[j], cls))
            return 1;
    }
    return 0;
}

static int hmi_first_quoted(const char *line, char *out)
{
    const char *p = strchr(line, '"');
    if (!p)
        return 0;
    const char *q = strchr(p + 1, '"');
    if (!q || q == p + 1 || (size_t)(q - p - 1) >= HMI_SYM)
        return 0;
    memcpy(out, p + 1, (size_t)(q - p - 1));
    out[q - p - 1] = '\0';
    return 1;
}

/* Parses the capability table, including class-on-continuation-line rows.
 * 0 ok, 2 fatal. */
static int hmi_load_caps(struct hmi_ctx *c)
{
    c->caps_n = 0;
    c->caps_expect = 0;
    c->capline_n = 0;
    if (access(c->capfile, F_OK) != 0) {
        fprintf(c->err,
                "%s: FATAL — capability table %s does not exist. The allowlist cannot be crossed against reach classes for a file that is not there; refusing to report clean.\n",
                k_gate, c->capfile);
        return 2;
    }
    if (hmi_slurp_lines(c->capfile, c->caplines, &c->capline_n, HMI_CAP_LINES))
        return 2;
    int parsed = 0;
    char unparsed[4096] = "";
    for (int i = 0; i < c->capline_n; i++) {
        if (!hmi_is_cap_open(c->caplines[i]))
            continue;
        c->caps_expect++;
        char sym[HMI_SYM] = "", cls[HMI_GRP] = "";
        (void)hmi_first_quoted(c->caplines[i], sym);
        if (!hmi_first_cap(c->caplines[i], cls))
            (void)hmi_lookahead_cap(c, i, cls);
        if (!sym[0] || !cls[0]) {
            char row[600];
            snprintf(row, sizeof row, "\n    line %d: %.400s", i + 1,
                     c->caplines[i]);
            if (strlen(unparsed) + strlen(row) + 1 < sizeof unparsed)
                strcat(unparsed, row);
        } else if (c->caps_n < HMI_CAPROWS) {
            snprintf(c->caps[c->caps_n].sym, HMI_SYM, "%s", sym);
            snprintf(c->caps[c->caps_n].cls, HMI_GRP, "%s", cls);
            c->caps_n++;
            parsed++;
        }
    }
    c->capline_n = 0;
    if (c->caps_expect == 0) {
        fprintf(c->err,
                "%s: FATAL — %s parsed to ZERO ZCL_CAPABILITY_SYMBOL rows.\n"
                "  Either the file was gutted or its row shape changed and this\n"
                "  parser no longer matches it. Refusing to cross the import\n"
                "  allowlist against a capability table that read as empty.\n",
                k_gate, c->capfile);
        return 2;
    }
    if (unparsed[0]) {
        fprintf(c->err,
                "%s: FATAL — %s holds ZCL_CAPABILITY_SYMBOL row(s) this gate could not assign a class to:%s\n"
                "  A row it cannot parse is a row it cannot judge; refusing to cross the\n"
                "  import allowlist against an incompletely-read capability table.\n",
                k_gate, c->capfile, unparsed);
        return 2;
    }
    if (parsed != c->caps_expect) {
        fprintf(c->err,
                "%s: FATAL — parsed %d ZCL_CAPABILITY_SYMBOL row(s) but %s holds %d; refusing to report a crossing off a partial parse.\n",
                k_gate, parsed, c->capfile, c->caps_expect);
        return 2;
    }
    return 0;
}

static int hmi_cap_tok_ok(const char *tok)
{
    char f[HMI_GRP + 3], p[HMI_GRP + 3];
    if (ovf(snprintf(f, sizeof f, " %s ", tok), sizeof f) ||
        ovf(snprintf(p, sizeof p, " %s ", tok), sizeof p))
        return 0;
    return strstr(k_forbidden_caps, f) != NULL ||
           strstr(k_permitted_caps, p) != NULL;
}

/* Resolves the class table path (selftest-only override, scratch-bound).
 * 0 ok, 2 fatal. */
static int hmi_classfile_resolve(struct hmi_ctx *c, const char **classfile)
{
    *classfile = k_classfile;
    const char *ov = getenv("ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE");
    char scratch[HMI_PATH];
    if (hmi_scratch_path(scratch, sizeof scratch))
        return 2;
    if (ov && ov[0]) {
        if (!hmi_marker_ok()) {
            fprintf(c->err,
                    "%s: FATAL — ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE is set outside --selftest\n",
                    k_gate);
            return 2;
        }
        size_t n = strlen(scratch);
        if (strncmp(ov, scratch, n) != 0 || ov[n] != '/') {
            fprintf(c->err,
                    "%s: FATAL — ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE must live under %s\n",
                    k_gate, scratch);
            return 2;
        }
        *classfile = ov;
    }
    if (access(*classfile, F_OK) != 0) {
        fprintf(c->err,
                "%s: FATAL — %s is missing; the class vocabulary cannot be checked.\n",
                k_gate, *classfile);
        return 2;
    }
    return 0;
}

/* Extracts "CAP_<NAME>" from a ZCL_CAPABILITY_CLASS row: 1 parsed, 0 not a
 * row, -1 buffer overflow. */
static int hmi_class_token(const char *line, char *tok, size_t cap)
{
    const char *p = hmi_skip_ws(line);
    if (strncmp(p, "ZCL_CAPABILITY_CLASS(", 21) != 0)
        return 0;
    p = hmi_skip_ws(p + 21);
    const char *q = p;
    while ((*q >= 'A' && *q <= 'Z') || *q == '_')
        q++;
    if (q == p || (size_t)(q - p) >= HMI_GRP)
        return 0;
    char name[HMI_GRP];
    memcpy(name, p, (size_t)(q - p));
    name[q - p] = '\0';
    return ovf(snprintf(tok, cap, "CAP_%s", name), cap) ? -1 : 1;
}

/* Leg 1c: every declared class must be verdicted in this file. 0/2. */
static int hmi_class_vocab(struct hmi_ctx *c)
{
    const char *classfile;
    if (hmi_classfile_resolve(c, &classfile))
        return 2;
    static char lines[HMI_CAP_LINES][HMI_LINE];
    int nlines = 0;
    if (hmi_slurp_lines(classfile, lines, &nlines, HMI_CAP_LINES))
        return 2;
    int n = 0;
    for (int i = 0; i < nlines; i++) {
        char tok[HMI_GRP + 8];
        int t = hmi_class_token(lines[i], tok, sizeof tok);
        if (t < 0)
            return 2;
        if (t == 0)
            continue;
        n++;
        if (!hmi_cap_tok_ok(tok)) {
            fprintf(c->err,
                    "%s: FATAL — %s declares %s, which this gate classifies neither way.\n"
                    "  A hot-swap module's import allowlist is checked against a CLOSED vocabulary.\n"
                    "  A class this file does not name is a class permitted by omission.\n"
                    "  Decide, in tools/lint/lintc/gate_hotswap_module_imports.c:\n"
                    "    - can a hot-swapped module hold %s?  add it to PERMITTED_CAP_CLASSES\n"
                    "    - can it not?                          add it to FORBIDDEN_CAP_CLASSES\n",
                    k_gate, classfile, tok, tok);
            return 2;
        }
    }
    if (n < HMI_CLASS_VOCAB_FLOOR) {
        fprintf(c->err,
                "%s: FATAL — parsed only %d class(es) from %s (floor %d).\n"
                "  Refusing to judge the allowlist against a vocabulary that did not load.\n",
                k_gate, n, classfile, HMI_CLASS_VOCAB_FLOOR);
        return 2;
    }
    c->class_vocab_n = n;
    return 0;
}

static int hmi_count_cls(const struct hmi_ctx *c, const char *cls)
{
    int n = 0;
    for (int i = 0; i < c->allow_n; i++) {
        const char *rc = hmi_cap_class(c, c->allow[i].sym);
        if (rc && strcmp(rc, cls) == 0)
            n++;
    }
    return n;
}

/* Leg 1b: cross the allowlist against the capability table. 0/1/2. */
static int hmi_crossing(struct hmi_ctx *c)
{
    if (hmi_load_caps(c))
        return 2;
    int resolved = 0;
    char forbidden_rows[4096] = "";
    for (int i = 0; i < c->allow_n; i++) {
        const char *cls = hmi_cap_class(c, c->allow[i].sym);
        if (!cls)
            continue;
        resolved++;
        char f[HMI_GRP + 3];
        if (ovf(snprintf(f, sizeof f, " %s ", cls), sizeof f))
            return 2;
        if (strstr(k_forbidden_caps, f)) {
            char row[HMI_SYM + HMI_GRP + 32];
            snprintf(row, sizeof row, "\n    %s  carries %s", c->allow[i].sym,
                     cls);
            if (strlen(forbidden_rows) + strlen(row) + 1 < sizeof forbidden_rows)
                strcat(forbidden_rows, row);
        }
    }
    if (resolved < HMI_CAPABILITY_CROSS_FLOOR) {
        fprintf(c->err,
                "%s: FATAL — only %d of %d allowlisted import(s) resolved to a class in %s, below the coverage floor of %d.\n"
                "  A crossing that resolves almost nothing prints the same result as a\n"
                "  crossing whose parser matched nothing. Refusing to report either the\n"
                "  presence or the absence of a forbidden capability off a scan this thin\n"
                "  — the crossing could not be meaningfully performed.\n",
                k_gate, resolved, c->allow_n, c->capfile,
                HMI_CAPABILITY_CROSS_FLOOR);
        return 2;
    }
    if (forbidden_rows[0]) {
        char msg[4600];
        snprintf(msg, sizeof msg,
                 "allowlisted import(s) in %s carry a FORBIDDEN capability class:%s",
                 c->def, forbidden_rows);
        hmi_bad(c, msg);
        fprintf(c->err,
                "\n"
                "  %s is the closed set of what a hot-swap module may import from the\n"
                "  resident node. A symbol that reaches the network, spawns a process,\n"
                "  loads code, changes privilege, or touches the wallet does not belong\n"
                "  in a module's interface at all — the allowlist row itself is the\n"
                "  widening, whether or not any module currently imports it.\n"
                "\n"
                "  Remove the row from %s. The call belongs in the resident node behind\n"
                "  an existing NODE_COMMAND door, not imported into the module; if the\n"
                "  honest answer is that the module needs it, that door is designed and\n"
                "  reviewed then, not pre-opened here.\n", c->def, c->def);
        return 1;
    }
    char msg[HMI_LINE];
    snprintf(msg, sizeof msg,
             "crossing  : OK — %d/%d allowlisted import(s) resolved to a capability class in %s (harmless=%d fs_read=%d fs_write=%d clock=%d random=%d) over a %d-class closed vocabulary; zero forbidden (network/process/dynload/privilege/wallet)",
             resolved, c->allow_n, c->capfile,
             hmi_count_cls(c, "CAP_HARMLESS"), hmi_count_cls(c, "CAP_FS_READ"),
             hmi_count_cls(c, "CAP_FS_WRITE"), hmi_count_cls(c, "CAP_CLOCK"),
             hmi_count_cls(c, "CAP_RANDOM"), c->class_vocab_n);
    hmi_note(c, msg);
    return 0;
}

/* Collects the sorted regular *.so paths of dir. 0 ok, 3 missing dir,
 * 2 overflow/error. */
static int hmi_list_sos(const char *dir, char out[][HMI_PATH], int *n, int max,
                        FILE *err)
{
    DIR *d = opendir(dir);
    if (!d)
        return 3;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".so") != 0)
            continue;
        char full[HMI_PATH];
        if (ovf(snprintf(full, sizeof full, "%s/%s", dir, e->d_name),
                sizeof full)) {
            closedir(d);
            return 2;
        }
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (*n >= max) {
            fprintf(err, "%s: module list of %s exceeds %d\n", k_gate, dir,
                    max);
            closedir(d);
            return 2;
        }
        int i = *n;
        while (i > 0 && strcmp(out[i - 1], full) > 0) {
            snprintf(out[i], HMI_PATH, "%s", out[i - 1]);
            i--;
        }
        snprintf(out[i], HMI_PATH, "%s", full);
        (*n)++;
    }
    closedir(d);
    return 0;
}

static int hmi_host_darwin(void)
{
    struct utsname u;
    return uname(&u) == 0 && strcmp(u.sysname, "Darwin") == 0;
}

static void hmi_nm_fail(struct hmi_ctx *c, const char *mod, int code,
                        const char *nm_out)
{
    char msg[640];
    snprintf(msg, sizeof msg,
             "cannot read dynamic symbols of %.200s (nm exit %d): %.200s", mod,
             code, nm_out);
    hmi_bad(c, msg);
}

/* One nm output line: trailing field is the symbol, '@version' stripped. */
static void hmi_scan_nm_line(struct hmi_ctx *c, char *line, const char *mod,
                             int darwin)
{
    if (!line[0])
        return;
    char *sp = line + strlen(line);
    while (sp > line && sp[-1] != ' ' && sp[-1] != '\t')
        sp--;
    char *at = strchr(sp, '@');
    if (at)
        *at = '\0';
    if (!sp[0])
        return;
    char probe[HMI_SYM];
    hmi_canonical(sp, darwin, probe, sizeof probe);
    hmi_seen_add(c, sp);
    if (probe[0])
        hmi_seen_add(c, probe);
    if (probe[0] && !hmi_allow_has(c, sp) && !hmi_allow_has(c, probe)) {
        char row[512];
        snprintf(row, sizeof row, "\n    %.200s  imports  %.200s", mod, sp);
        if (strlen(c->bad_rows) + strlen(row) + 1 < sizeof c->bad_rows)
            strcat(c->bad_rows, row);
    }
}

static void hmi_scan_nm_buf(struct hmi_ctx *c, char *buf, size_t olen,
                            const char *mod)
{
    int darwin = hmi_host_darwin();
    char *p = buf;
    char *end = buf + olen;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        if (nl)
            *nl = '\0';
        hmi_scan_nm_line(c, p, mod, darwin);
        if (!nl)
            break;
        p = nl + 1;
    }
}

/* Runs one nm argv. 0 ran (see *code), 2 fatal (no nm, or output cut off). */
static int hmi_run_nm(struct hmi_ctx *c, char *const argv[], int merge_err,
                      char *buf, size_t *olen, int *code, const char *mod)
{
    *olen = 0;
    *code = 0;
    int r = hmi_spawn_argv(argv, merge_err, buf, HMI_TXT, olen, code);
    if (r == -2) {
        fprintf(c->err,
                "%s: FATAL — nm output for %s exceeds %d bytes; refusing to judge a truncated symbol set\n",
                k_gate, mod, HMI_TXT - 1);
        return 2;
    }
    if (r != 0 || *code == 127) {
        fprintf(c->err,
                "%s: FATAL — nm(1) is not on PATH; the undefined-symbol set cannot be read\n",
                k_gate);
        return 2;
    }
    return 0;
}

/* Reads one module's undefined dynamic symbols. 0 read, 1 flagged bad,
 * 2 fatal (could not look). */
static int hmi_nm_module(struct hmi_ctx *c, const char *path, const char *mod)
{
    static char buf[HMI_TXT];
    char *argv1[5] = {(char *)"nm", (char *)"-D", (char *)"--undefined-only",
                      (char *)path, NULL};
    char *argv2[4] = {(char *)"nm", (char *)"-u", (char *)path, NULL};
    size_t olen = 0;
    int code = 0;
    int rc = hmi_run_nm(c, argv1, 0, buf, &olen, &code, mod);
    if (rc == 0 && code != 0)
        rc = hmi_run_nm(c, argv2, 1, buf, &olen, &code, mod);
    if (rc)
        return rc;
    if (code != 0) {
        hmi_nm_fail(c, mod, code, buf);
        return 1;
    }
    c->scanned_so++;
    hmi_scan_nm_buf(c, buf, olen, mod);
    return 0;
}

/* Leg 2. 0 clean, 1 violation, 2 fatal, 3 UNOBSERVED. */
static int hmi_scan_modules(struct hmi_ctx *c)
{
    static char sos[HMI_SOS][HMI_PATH];
    int nsos = 0;
    int rc = hmi_list_sos(c->so_dir, sos, &nsos, HMI_SOS, c->err);
    if (rc == 3) {
        if (c->sandbox) {
            fprintf(c->err,
                    "%s: FATAL — sandbox module dir %s does not exist\n",
                    k_gate, c->so_dir);
            return 2;
        }
        return 3;
    }
    if (rc)
        return 2;
    if (nsos == 0) {
        fprintf(c->err,
                "%s: FATAL — %s exists but contains no *.so module.\n"
                "  A module directory that is present and empty is a producer that\n"
                "  ran and emitted nothing, or an artifact name this gate no longer\n"
                "  matches. Either way the import contract would be 'proven' against\n"
                "  zero artifacts. Refusing.\n", k_gate, c->so_dir);
        return 2;
    }
    for (int i = 0; i < nsos; i++) {
        const char *slash = strrchr(sos[i], '/');
        rc = hmi_nm_module(c, sos[i], slash ? slash + 1 : sos[i]);
        if (rc)
            return rc;
    }
    if (c->scanned_so == 0) {
        fprintf(c->err,
                "%s: FATAL — found %d module file(s) but read the symbols of none of them\n",
                k_gate, nsos);
        return 2;
    }
    if (c->bad_rows[0]) {
        char msg[8300];
        snprintf(msg, sizeof msg,
                 "module(s) import symbol(s) that are NOT on the declared contract:%s",
                 c->bad_rows);
        hmi_bad(c, msg);
        fprintf(c->err,
                "\n"
                "  A hot-swap module runs inside the live node. Its UNDEFINED symbol set\n"
                "  is its whole reach into the resident image, so an import that nobody\n"
                "  declared is reach that nobody reviewed.\n"
                "\n"
                "  If the new call is legitimate: add a row to %s under the group that\n"
                "  explains WHY it is allowed, and say in the commit message which door\n"
                "  you opened and why the leaf behind it still cannot misreport or mutate\n"
                "  anything a reader trusts.\n"
                "  If the honest answer is that it can: do not import it. Move the call\n"
                "  into the resident and reach it through an existing NODE_COMMAND door.\n",
                c->def);
        return 1;
    }
    return 0;
}

static void hmi_report_unused(struct hmi_ctx *c)
{
    int unused = 0;
    for (int i = 0; i < c->allow_n; i++)
        if (!hmi_seen_has(c, c->allow[i].sym))
            unused++;
    if (unused > 0) {
        char msg[512];
        snprintf(msg, sizeof msg,
                 "unused    : %d allowlisted import(s) are not taken by any built module (dead ceiling; safe to trim, not a violation)",
                 unused);
        hmi_note(c, msg);
    }
}

/* Resolves one selftest-only override env var with the shell refusals. */
static int hmi_take_override(struct hmi_ctx *c, const char *var,
                             const char *setmsg, const char *what,
                             const char *scratch, const char **out)
{
    const char *v = getenv(var);
    if (!v || !v[0])
        return 0;
    if (!hmi_marker_ok()) {
        fprintf(c->err, "%s\n", setmsg);
        return 2;
    }
    size_t n = strlen(scratch);
    if (strncmp(v, scratch, n) != 0 || v[n] != '/') {
        fprintf(c->err, "%s: FATAL — %s must live under %s, got: %s\n", k_gate,
                what, scratch, v);
        return 2;
    }
    *out = v;
    return 0;
}

static int hmi_resolve_env(struct hmi_ctx *c)
{
    char scratch[HMI_PATH], msg[HMI_PATH + 160];
    if (hmi_scratch_path(scratch, sizeof scratch)) {
        fprintf(c->err, "%s: FATAL — HOME unset; cannot resolve scratch\n",
                k_gate);
        return 2;
    }
    const char *v = getenv("ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR");
    if (v && v[0]) {
        snprintf(msg, sizeof msg,
                 "%s: FATAL — ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR is set outside --selftest; refusing to scan anywhere but %s",
                 k_gate, k_so_dir);
        if (hmi_take_override(c, "ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR", msg,
                              "sandbox dir", scratch, &c->so_dir))
            return 2;
        c->sandbox = 1;
        fprintf(c->out, "%s: SANDBOX module dir (selftest only): %s\n", k_gate,
                c->so_dir);
    }
    v = getenv("ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE");
    if (v && v[0]) {
        snprintf(msg, sizeof msg,
                 "%s: FATAL — ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE is set outside --selftest; refusing to read anywhere but %s",
                 k_gate, k_def);
        if (hmi_take_override(c, "ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE", msg,
                              "allowlist override", scratch, &c->def))
            return 2;
        fprintf(c->out, "%s: SANDBOX allowlist file (selftest only): %s\n",
                k_gate, c->def);
    }
    v = getenv("ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE");
    if (v && v[0]) {
        snprintf(msg, sizeof msg,
                 "%s: FATAL — ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE is set outside --selftest; refusing to read anywhere but %s",
                 k_gate, k_capfile);
        if (hmi_take_override(c, "ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE", msg,
                              "capability table override", scratch,
                              &c->capfile))
            return 2;
        fprintf(c->out, "%s: SANDBOX capability table (selftest only): %s\n",
                k_gate, c->capfile);
    }
    return 0;
}

int hmi_run_core(FILE *out, FILE *err)
{
    static struct hmi_ctx c;
    memset(&c, 0, sizeof c);
    c.out = out;
    c.err = err;
    c.def = k_def;
    c.capfile = k_capfile;
    c.so_dir = k_so_dir;
    if (hmi_resolve_env(&c))
        return 2;
    int rc = hmi_load_allowlist(&c);
    if (rc == 2)
        return 2;
    if (hmi_class_vocab(&c))
        return 2;
    if (hmi_crossing(&c) == 2)
        return 2;
    int contract_fail = c.fail;
    int art = hmi_scan_modules(&c);
    if (art == 2)
        return 2;
    if (contract_fail) {
        fprintf(err,
                "%s: the import contract file is malformed; module imports were not judged against it.\n",
                k_gate);
        return 1;
    }
    if (art == 3) {
        char msg[HMI_LINE];
        fprintf(c.out,
                "%s: UNOBSERVED (artifact leg) — %s does not exist, so no module .so was examined.\n",
                k_gate, c.so_dir);
        hmi_note(&c, "This is NOT a clean bill of health for any module. Nothing was built,");
        hmi_note(&c, "so nothing was judged. The contract leg above DID run and did prove");
        snprintf(msg, sizeof msg,
                 "%s is well-formed and holds %d classified rows.", c.def,
                 c.allow_n);
        hmi_note(&c, msg);
        hmi_note(&c, "Build modules (make hotswap ...) and re-run to exercise the artifact leg.");
        fprintf(c.out, "%s: contract OK, artifacts UNOBSERVED\n", k_gate);
        return 0;
    }
    if (art != 0 || c.fail)
        return 1;
    hmi_report_unused(&c);
    char msg[HMI_LINE];
    snprintf(msg, sizeof msg,
             "artifacts : OK — %d module .so in %s, every undefined symbol declared",
             c.scanned_so, c.so_dir);
    hmi_note(&c, msg);
    fprintf(c.out,
            "%s: OK — %d module(s) checked against %d declared imports in %s; no undeclared reach into the node\n",
            k_gate, c.scanned_so, c.allow_n, c.def);
    return 0;
}

int check_hotswap_module_imports_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return hmi_run_core(stdout, stderr);
}
