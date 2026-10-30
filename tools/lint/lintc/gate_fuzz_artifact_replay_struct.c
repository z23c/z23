/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: check_fuzz_artifact_replay, structural half. Derives the
 * corpus<->binary map from the Makefile, loads ARTIFACT_VERDICTS.txt,
 * enumerates artifacts (git when it resolves to THIS tree, find otherwise)
 * and runs the cheap always-on checks. Ported from the same-named half of
 * tools/lint/check_fuzz_artifact_replay.sh (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_fuzz_artifact_replay_priv.h"

static const char k_fars_mkrule[] = "$(BIN_DIR)/fuzz_";
static const char *const k_fars_artifact[] = {
    "crash", "timeout", "oom", "leak", "slow-unit", "minimized-from"
};
static const char *const k_fars_nearmiss[] = {
    "crash", "crashes", "timeout", "timeouts", "oom", "ooms", "leak", "leaks",
    "slow-unit", "slow_unit", "slowunit", "minimized-from", "minimized_from",
    "minimized", "hang", "hangs", "repro", "abort", "assert"
};

/* Runs argv with fork+execvp (never a shell), capturing stdout into out.
 * quiet_err redirects the child's stderr to /dev/null. Returns 0 with the
 * child's exit status in *code; 2 on truncation; -1 on spawn failure. */
int far_spawn_cap(char *const argv[], int quiet_err, char *out, size_t cap,
                  size_t *len, int *code)
{
    int pfd[2];
    size_t got = 0;
    if (pipe(pfd) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        close(pfd[1]);
        if (quiet_err) {
            int nd = open("/dev/null", O_WRONLY);
            if (nd >= 0)
                dup2(nd, STDERR_FILENO);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);
    for (;;) {
        if (got >= cap)
            break;
        ssize_t n = read(pfd[0], out + got, cap - got);
        if (n < 0) {
            close(pfd[0]);
            return -1;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    close(pfd[0]);
    if (got >= cap) {
        int st2;
        waitpid(pid, &st2, 0);
        return 2;
    }
    out[got] = '\0';
    *len = got;
    int st;
    waitpid(pid, &st, 0);
    *code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
    return 0;
}

struct fars_kind_ctx { struct far_ctx *c; int rc; };

static int fars_kind_line(void *v, const char *line, size_t len)
{
    struct fars_kind_ctx *k = v;
    struct far_ctx *c = k->c;
    char buf[FAR_REASON];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof buf) {
        fprintf(c->err, "%s: Makefile line exceeds %d\n", k_far_gate,
                FAR_REASON);
        k->rc = 2;
        return 2;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';
    size_t off = strlen(k_fars_mkrule);
    if (strncmp(buf, k_fars_mkrule, off) != 0)
        return 0;
    size_t e = off;
    while (buf[e] && (islower((unsigned char)buf[e]) || buf[e] == '_' ||
                      isdigit((unsigned char)buf[e])))
        e++;
    if (e == off || buf[e] != ':')
        return 0;
    buf[e] = '\0';
    const char *kind = buf + off;
    if (far_kind_has(c, kind))
        return 0;
    if (c->n_kinds >= FAR_KINDS) {
        fprintf(c->err, "%s: fuzz kinds exceed %d\n", k_far_gate, FAR_KINDS);
        k->rc = 2;
        return 2;
    }
    if (strlen(kind) >= FAR_KIND) {
        fprintf(c->err, "%s: fuzz kind name too long: %s\n", k_far_gate, kind);
        k->rc = 2;
        return 2;
    }
    snprintf(c->kinds[c->n_kinds], FAR_KIND, "%s", kind);
    c->n_kinds++;
    return 0;
}

int far_load_kinds(struct far_ctx *c)
{
    struct fars_kind_ctx k;
    k.c = c;
    k.rc = 0;
    int rc = lc_each_line("Makefile", fars_kind_line, &k, 1);
    if (rc || k.rc)
        return 2;
    return far_floor(c, c->n_kinds, 5,
                     "no $(BIN_DIR)/fuzz_<kind> rules found in the Makefile — "
                     "did the rule spelling change?");
}

struct fars_led_ctx { struct far_ctx *c; int rc; };

static void fars_trim(char *s)
{
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i]))
        i++;
    if (i)
        memmove(s, s + i, n - i + 1);
}

/* Reads up to three whitespace tokens like `read -r f v d _rest`. */
static void fars_tok3(char *line, char *f, char *v, char *d)
{
    char *p = line;
    size_t i = 0;
    const char *dst[3];
    size_t cap[3];
    dst[0] = f; cap[0] = FAR_NAME;
    dst[1] = v; cap[1] = FAR_VERD;
    dst[2] = d; cap[2] = FAR_DATE;
    f[0] = v[0] = d[0] = '\0';
    while (i < 3) {
        while (*p && isspace((unsigned char)*p))
            p++;
        if (!*p)
            return;
        char *st = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        size_t n = (size_t)(p - st);
        if (n >= cap[i])
            n = cap[i] - 1;
        memcpy((void *)dst[i], st, n);
        ((char *)dst[i])[n] = '\0';
        i++;
    }
}

static int fars_led_line(void *v, const char *line, size_t len)
{
    struct fars_led_ctx *lc = v;
    struct far_ctx *c = lc->c;
    char raw[FAR_REASON], lpart[FAR_REASON], reason[FAR_REASON];
    char f[FAR_NAME], vd[FAR_VERD], d[FAR_DATE];
    size_t n = len;
    if (n > 0 && line[n - 1] == '\n')
        n--;
    if (n >= sizeof raw) {
        fprintf(c->err, "%s: ledger line exceeds %d\n", k_far_gate, FAR_REASON);
        lc->rc = 2;
        return 2;
    }
    memcpy(raw, line, n);
    raw[n] = '\0';
    char *hash = strchr(raw, '#');
    if (hash) {
        snprintf(lpart, sizeof lpart, "%s", raw);
        lpart[hash - raw] = '\0';
        snprintf(reason, sizeof reason, "%s", hash + 1);
    } else {
        snprintf(lpart, sizeof lpart, "%s", raw);
        reason[0] = '\0';
    }
    fars_trim(lpart);
    if (!lpart[0])
        return 0;
    size_t r = 0;
    while (reason[r] == ' ' || reason[r] == '\t')
        r++;
    memmove(reason, reason + r, strlen(reason) - r + 1);
    fars_tok3(lpart, f, vd, d);
    if (c->n_ledger >= FAR_LEDGER) {
        fprintf(c->err, "%s: ledger entries exceed %d\n", k_far_gate,
                FAR_LEDGER);
        lc->rc = 2;
        return 2;
    }
    if (far_ledger_find(c, f) >= 0)
        far_report(c, "%s: duplicate entry for '%s' — one line per artifact",
                   k_far_ledger, f);
    struct far_ledger_ent *e = &c->ledger[c->n_ledger];
    snprintf(e->file, FAR_NAME, "%s", f);
    snprintf(e->verdict, FAR_VERD, "%s", vd);
    snprintf(e->date, FAR_DATE, "%s", d);
    snprintf(e->reason, FAR_REASON, "%s", reason);
    e->seen = 0;
    c->n_ledger++;
    return 0;
}

int far_load_ledger(struct far_ctx *c)
{
    struct stat sb;
    struct fars_led_ctx lc;
    int rc;
    if (stat(k_far_ledger, &sb) != 0) {
        fprintf(c->err, "%s: FATAL — %s is missing.\n", k_far_gate,
                k_far_ledger);
        fputs("  Every saved fuzz artifact needs a written verdict. Without "
              "the\n", c->err);
        fputs("  ledger this gate cannot tell a triaged finding from an "
              "unread one,\n", c->err);
        fputs("  and reporting 'clean' off that is the exact hole it exists "
              "to close.\n", c->err);
        return 2;
    }
    lc.c = c;
    lc.rc = 0;
    rc = lc_each_line(k_far_ledger, fars_led_line, &lc, 1);
    if (rc || lc.rc)
        return 2;
    return 0;
}

/* Returns 1 when rel is already recorded as an artifact or near miss. */
static int fars_known(const struct far_ctx *c, const char *rel)
{
    for (int i = 0; i < c->n_artifacts; i++)
        if (!strcmp(c->artifacts[i], rel))
            return 1;
    for (int i = 0; i < c->n_nearmiss; i++)
        if (!strcmp(c->nearmiss[i], rel))
            return 1;
    return 0;
}

/* Records rel when base starts with an artifact kind: 0 no, 1 added, 2 error. */
static int fars_add_artifact(struct far_ctx *c, const char *rel,
                             const char *base, int origin)
{
    for (size_t i = 0; i < sizeof k_fars_artifact / sizeof k_fars_artifact[0];
         i++) {
        size_t kl = strlen(k_fars_artifact[i]);
        if (strncmp(base, k_fars_artifact[i], kl) || base[kl] != '-')
            continue;
        if (c->n_artifacts >= FAR_ARTIFACTS) {
            fprintf(c->err, "%s: artifacts exceed %d\n", k_far_gate,
                    FAR_ARTIFACTS);
            return 2;
        }
        snprintf(c->artifacts[c->n_artifacts], FAR_NAME, "%s", rel);
        snprintf(c->kind_of[c->n_artifacts], FAR_KIND, "%s",
                 k_fars_artifact[i]);
        c->untracked_of[c->n_artifacts] = (unsigned char)origin;
        c->n_artifacts++;
        return 1;
    }
    return 0;
}

/* Records rel when the lowercased base looks like a mistyped artifact name. */
static int fars_add_nearmiss(struct far_ctx *c, const char *rel,
                             const char *base)
{
    char lc[FAR_NAME];
    snprintf(lc, sizeof lc, "%s", base);
    for (size_t i = 0; lc[i]; i++)
        lc[i] = (char)tolower((unsigned char)lc[i]);
    for (size_t i = 0; i < sizeof k_fars_nearmiss / sizeof k_fars_nearmiss[0];
         i++) {
        size_t wl = strlen(k_fars_nearmiss[i]);
        if (strncmp(lc, k_fars_nearmiss[i], wl) ||
            (lc[wl] != '-' && lc[wl] != '_'))
            continue;
        if (c->n_nearmiss >= FAR_NEARMISS) {
            fprintf(c->err, "%s: near-miss names exceed %d\n", k_far_gate,
                    FAR_NEARMISS);
            return 2;
        }
        snprintf(c->nearmiss[c->n_nearmiss], FAR_NAME, "%s", rel);
        c->n_nearmiss++;
        return 1;
    }
    return 0;
}

/* Classify one repo-relative path. origin: 1 = untracked. */
static int fars_consider(struct far_ctx *c, const char *p, int origin)
{
    size_t pre = strlen(k_far_seed_root) + 1;
    const char *base, *rel;
    int rc;
    if (strncmp(p, k_far_seed_root, pre - 1) != 0 || p[pre - 1] != '/')
        return 0;
    rel = p + pre;
    if (!strchr(rel, '/') || fars_known(c, rel))
        return 0;
    base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    rc = fars_add_artifact(c, rel, base, origin);
    if (rc)
        return rc == 2 ? 2 : 0;
    rc = fars_add_nearmiss(c, rel, base);
    return rc == 2 ? 2 : 0;
}

static char fars_cap[1u << 20];

/* Feeds every NUL-delimited token of buf to fars_consider. */
static int fars_feed(struct far_ctx *c, char *buf, size_t len, int origin)
{
    size_t st = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && buf[i] != '\0')
            continue;
        if (i > st) {
            buf[i] = '\0';
            int rc = fars_consider(c, buf + st, origin);
            if (rc)
                return rc;
        }
        st = i + 1;
    }
    return 0;
}

static int fars_git_pass(struct far_ctx *c, int others)
{
    char *av[8];
    int ai = 0, code;
    size_t len = 0;
    int rc;
    av[ai++] = (char *)"git";
    av[ai++] = (char *)"ls-files";
    av[ai++] = (char *)"-z";
    if (others) {
        av[ai++] = (char *)"--others";
        av[ai++] = (char *)"--exclude-standard";
    }
    av[ai++] = (char *)k_far_seed_root;
    av[ai] = NULL;
    rc = far_spawn_cap(av, 1, fars_cap, sizeof fars_cap, &len, &code);
    if (rc != 0)
        return 2;
    return fars_feed(c, fars_cap, len, others);
}

static int fars_git_here(struct far_ctx *c)
{
    char *av[4];
    size_t len = 0;
    int code;
    av[0] = (char *)"git";
    av[1] = (char *)"rev-parse";
    av[2] = (char *)"--show-toplevel";
    av[3] = NULL;
    if (far_spawn_cap(av, 1, fars_cap, sizeof fars_cap, &len, &code) != 0)
        return 0;
    while (len && fars_cap[len - 1] == '\n')
        fars_cap[--len] = '\0';
    return len && !strcmp(fars_cap, c->root);
}

/* find "$SEED_ROOT" -mindepth 2 -maxdepth 2 -type f, enumerated by hand. */
static int fars_find_pass(struct far_ctx *c)
{
    DIR *d = opendir(k_far_seed_root);
    struct dirent *de;
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL) {
        char cdir[FAR_PATH];
        DIR *cd;
        struct dirent *ce;
        struct stat sb;
        if (de->d_name[0] == '.')
            continue;
        if (ovf(snprintf(cdir, sizeof cdir, "%s/%s", k_far_seed_root,
                         de->d_name), sizeof cdir)) {
            closedir(d);
            return 2;
        }
        cd = opendir(cdir);
        if (!cd)
            continue;
        while ((ce = readdir(cd)) != NULL) {
            char p[FAR_PATH];
            if (ce->d_name[0] == '.')
                continue;
            if (ovf(snprintf(p, sizeof p, "%s/%s", cdir, ce->d_name),
                     sizeof p)) {
                closedir(cd);
                closedir(d);
                return 2;
            }
            if (stat(p, &sb) == 0 && S_ISREG(sb.st_mode))
                if (fars_consider(c, p, 0) == 2) {
                    closedir(cd);
                    closedir(d);
                    return 2;
                }
        }
        closedir(cd);
    }
    closedir(d);
    return 0;
}

int far_enumerate(struct far_ctx *c)
{
    int rc;
    if (fars_git_here(c)) {
        rc = fars_git_pass(c, 0);
        if (!rc)
            rc = fars_git_pass(c, 1);
    } else {
        fprintf(c->out, "[%s] no git here — enumerating with find; every "
                        "artifact is still\n", k_far_gate);
        fprintf(c->out, "[%s] replayed and still needs a verdict, but the "
                        "tracked vs\n", k_far_gate);
        fprintf(c->out, "[%s] uncommitted distinction is NOT being checked "
                        "on this run.\n", k_far_gate);
        rc = fars_find_pass(c);
    }
    if (rc)
        return 2;
    return far_floor(c, c->n_artifacts, 20,
                     "git ls-files found almost no saved artifacts under "
                     "tests/harness/fuzz_seeds — wrong cwd, or the corpus "
                     "moved?");
}

static int fars_valid_date(const char *d)
{
    if (strlen(d) != 10)
        return 0;
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7)
            continue;
        if (!isdigit((unsigned char)d[i]))
            return 0;
    }
    return d[4] == '-' && d[7] == '-';
}

static void fars_repro_notes(struct far_ctx *c, const char *rel,
                             const char *corpus, int tmo)
{
    far_note(c, "Reproduce it:  ASAN_OPTIONS=detect_leaks=0:symbolize=0 \\");
    far_note(c, "  timeout -k 5 %d %s/fuzz_%s -timeout=%d \\", tmo + 10,
             c->bin_dir, corpus, tmo);
    far_note(c, "  -runs=1 -artifact_prefix=/tmp/ %s/%s", k_far_seed_root,
             rel);
}

static void fars_check_fields(struct far_ctx *c, const char *rel,
                              const char *v, const char *d, const char *r)
{
    if (!fars_valid_date(d))
        far_report(c, "%s: '%s' has no valid YYYY-MM-DD date (got '%s')",
                   k_far_ledger, rel, d);
    if (!r[0]) {
        far_report(c, "%s: '%s' has no reason — say what you decided and why",
                   k_far_ledger, rel);
    } else if (!strcmp(v, "accepted") && strlen(r) < 30) {
        far_report(c, "%s: '%s' is 'accepted' with a %zu-char reason "
                      "(need >= 30)", k_far_ledger, rel, strlen(r));
        far_note(c, "'accepted' is the ONLY verdict that lets a reproducing "
                    "artifact");
        far_note(c, "pass a build. It costs a real sentence. A bug you have "
                    "not");
        far_note(c, "fixed is 'open', not 'accepted'.");
    }
}

static void fars_check_regression(struct far_ctx *c, const char *rel,
                                  const char *kind, const char *corpus,
                                  const char *r)
{
    if (far_regression_sufficient(kind, r))
        return;
    far_report(c, "%s: '%s' (%s) closed 'regression-seed' on non-reproduction "
                  "alone", k_far_ledger, rel, kind);
    far_note(c, "reason: %s", r);
    far_note(c, "A %s finding needs a named fix ('fixed by <commit>') or an",
             kind);
    far_note(c, "explicit pattern-init replay recorded in the reason "
                "('pattern-init:");
    far_note(c, "clean (Nx)') before it can close. 'it replayed clean' by "
                "itself is");
    far_note(c, "not exoneration — a freshly-mapped stack reads as zero, so "
                "one");
    far_note(c, "clean run proves nothing about a stale-stack bug. Rebuild "
                "under");
    far_note(c, "  make BUILD_DIR=build/fuzz-patterninit \\");
    far_note(c, "    ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern "
                "fuzz_%s", corpus);
    far_note(c, "and replay against that binary too, then record what it "
                "did.");
}

static void fars_check_verdict(struct far_ctx *c, const char *rel,
                               const struct far_ledger_ent *e,
                               const char *corpus)
{
    const char *v = e->verdict;
    if (!strcmp(v, "regression-seed") || !strcmp(v, "open") ||
        !strcmp(v, "accepted"))
        return;
    if (!strcmp(v, "unaudited")) {
        far_report(c, "%s/%s [UNAUDITED — auto-filed on %s, nobody has "
                      "triaged it]", k_far_seed_root, rel,
                   e->date[0] ? e->date : "?");
        fars_repro_notes(c, rel, corpus, c->replay_timeout);
        far_note(c, "Then replace its line in %s with a real", k_far_ledger);
        far_note(c, "verdict: regression-seed (it is clean), open (it is a "
                    "bug you");
        far_note(c, "have not fixed), or accepted (it is genuinely not a "
                    "bug, +why).");
    } else if (!strcmp(v, "unreplayable")) {
        far_report(c, "%s/%s [UNREPLAYABLE — filed %s, promoter could not "
                      "get a verdict]", k_far_seed_root, rel,
                   e->date[0] ? e->date : "?");
        far_note(c, "%s", e->reason);
        far_note(c, "Build the missing binary (stock: 'make fuzz_%s'; "
                    "pattern-init:", corpus);
        far_note(c, "  'make BUILD_DIR=build/fuzz-patterninit "
                    "ZCL_FUZZ_EXTRA_CFLAGS=-ftrivial-auto-var-init=pattern "
                    "fuzz_%s')", corpus);
        far_note(c, "then re-run promote_fuzz_artifacts.sh or replay it by "
                    "hand and write a real verdict.");
    } else {
        far_report(c, "%s: '%s' has unknown verdict '%s' (want "
                      "regression-seed | open | accepted)", k_far_ledger, rel,
                   v);
    }
}

static int fars_check_artifact(struct far_ctx *c, int i)
{
    const char *rel = c->artifacts[i];
    char corpus[FAR_KIND];
    const char *sl = strchr(rel, '/');
    size_t cl = sl ? (size_t)(sl - rel) : strlen(rel);
    struct stat sb;
    char path[FAR_PATH];
    int li;
    if (cl >= sizeof corpus)
        cl = sizeof corpus - 1;
    memcpy(corpus, rel, cl);
    corpus[cl] = '\0';
    li = far_ledger_find(c, rel);
    if (li >= 0)
        c->ledger[li].seen = 1;
    if (c->untracked_of[i]) {
        far_report(c, "%s/%s [UNCOMMITTED — a saved repro sitting in the "
                      "corpus, untracked]", k_far_seed_root, rel);
        far_note(c, "A finding nobody committed is a finding nobody reads. "
                    "Either");
        far_note(c, "'git add' it and record a verdict in %s,", k_far_ledger);
        far_note(c, "or delete it if it was local debris.");
    }
    if (ovf(snprintf(path, sizeof path, "%s/%s", k_far_seed_root, rel),
             sizeof path))
        return 2;
    if (stat(path, &sb) != 0) {
        far_report(c, "%s/%s [MISSING FROM DISK — git tracks it, the file is "
                      "not there]", k_far_seed_root, rel);
        far_note(c, "A deleted artifact is not a triaged one. Restore it");
        far_note(c, "('git checkout -- %s/%s'), or 'git rm' it AND delete",
                 k_far_seed_root, rel);
        far_note(c, "its line from %s so the record", k_far_ledger);
        far_note(c, "says the finding left the corpus on purpose.");
        return 0;
    }
    if (!far_kind_has(c, corpus)) {
        far_report(c, "%s/%s [no fuzz binary: the Makefile has no "
                      "$(BIN_DIR)/fuzz_%s rule]", k_far_seed_root, rel,
                   corpus);
        far_note(c, "An artifact nothing can replay is an artifact nobody "
                    "will read.");
        return 0;
    }
    if (li < 0 || !c->ledger[li].verdict[0]) {
        char today[FAR_DATE];
        far_today_utc(today, sizeof today);
        far_report(c, "%s/%s [UNTRIAGED — no verdict recorded]",
                   k_far_seed_root, rel);
        fars_repro_notes(c, rel, corpus, c->replay_timeout);
        far_note(c, "Then add one line to %s:", k_far_ledger);
        far_note(c, "  %s  <regression-seed|open|accepted>  %s  # why", rel,
                 today);
        return 0;
    }
    fars_check_verdict(c, rel, &c->ledger[li], corpus);
    fars_check_fields(c, rel, c->ledger[li].verdict, c->ledger[li].date,
                      c->ledger[li].reason);
    if (!strcmp(c->ledger[li].verdict, "regression-seed") &&
        c->ledger[li].reason[0])
        fars_check_regression(c, rel, c->kind_of[i], corpus,
                              c->ledger[li].reason);
    return 0;
}

static void fars_nearmiss_reports(struct far_ctx *c)
{
    for (int i = 0; i < c->n_nearmiss; i++) {
        far_report(c, "%s/%s [NOT A LIBFUZZER ARTIFACT NAME — nothing will "
                      "ever replay it]", k_far_seed_root, c->nearmiss[i]);
        far_note(c, "This reads as a saved finding but does not match any "
                    "prefix");
        far_note(c, "libFuzzer writes, so the gate would file it as a "
                    "hand-authored seed");
        far_note(c, "and never demand a verdict for it.");
        far_note(c, "Rename it to one of: crash- timeout- oom- leak- "
                    "slow-unit- minimized-from-");
        far_note(c, "(hyphen, lowercase, then the hash), then add its "
                    "verdict line to");
        far_note(c, "%s. If it really is a hand-written", k_far_ledger);
        far_note(c, "seed, give it a name that does not start with a finding "
                    "word.");
    }
}

static void fars_orphans(struct far_ctx *c)
{
    for (int i = 0; i < c->n_ledger; i++)
        if (!c->ledger[i].seen)
            far_report(c, "%s: line for '%s' but no such tracked artifact — "
                          "delete the line or restore the file", k_far_ledger,
                       c->ledger[i].file);
}

static int fars_corpus_dirs(struct far_ctx *c)
{
    char names[FAR_KINDS * 4][FAR_KIND];
    char *ptr[FAR_KINDS * 4];
    int n = 0;
    DIR *d = opendir(k_far_seed_root);
    struct dirent *de;
    for (int i = 0; i < c->n_kinds; i++) {
        char p[FAR_PATH];
        struct stat sb;
        if (ovf(snprintf(p, sizeof p, "%s/%s", k_far_seed_root, c->kinds[i]),
                 sizeof p))
            return 2;
        if (stat(p, &sb) != 0 || !S_ISDIR(sb.st_mode))
            far_report(c, "%s/%s/ missing — $(BIN_DIR)/fuzz_%s exists but "
                          "has no corpus dir", k_far_seed_root, c->kinds[i],
                       c->kinds[i]);
    }
    if (!d)
        return 0;
    while ((de = readdir(d)) != NULL && n < FAR_KINDS * 4) {
        char p[FAR_PATH];
        struct stat sb;
        if (de->d_name[0] == '.')
            continue;
        if (ovf(snprintf(p, sizeof p, "%s/%s", k_far_seed_root, de->d_name),
                 sizeof p)) {
            closedir(d);
            return 2;
        }
        if (stat(p, &sb) == 0 && S_ISDIR(sb.st_mode)) {
            if (strlen(de->d_name) >= FAR_KIND) {
                closedir(d);
                return 2;
            }
            snprintf(names[n], FAR_KIND, "%s", de->d_name);
            ptr[n] = names[n];
            n++;
        }
    }
    closedir(d);
    qsort(ptr, (size_t)n, sizeof ptr[0], lintc_strcmp_ptr);
    for (int i = 0; i < n; i++)
        if (!far_kind_has(c, ptr[i]))
            far_report(c, "%s/%s/ has no fuzz binary — add a "
                          "$(BIN_DIR)/fuzz_%s rule or remove the corpus",
                       k_far_seed_root, ptr[i], ptr[i]);
    return 0;
}

int far_structural(struct far_ctx *c)
{
    int rc;
    fars_nearmiss_reports(c);
    for (int i = 0; i < c->n_artifacts; i++) {
        rc = fars_check_artifact(c, i);
        if (rc)
            return rc;
    }
    fars_orphans(c);
    return fars_corpus_dirs(c);
}
