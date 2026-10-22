/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — no new shell script (check-no-new-bash). Z23 tools are
 * C23, and a new tool is a nested `z23` command, not a script. A tracked file
 * is a shell file when its name ends in `.sh` or `.bash`, or its first line is
 * a shebang that names sh, bash, dash or ksh (`#!/bin/sh`, `#!/usr/bin/env
 * bash`, with or without flags). vendor/ and contexts/commons/corpus/ are not
 * scanned.
 *
 * Every shell file must be listed in tools/lint/bash_allowlist.txt (one
 * repo-relative path per line, LC_ALL=C sorted, '#' comments allowed). A shell
 * file that is not listed FAILS as NEW. A listed path that is no longer
 * tracked, no longer exists or no longer is a shell file FAILS as STALE: delete
 * the line. An unsorted list FAILS. The list is hand-edited and can only
 * shrink; the gate never adds a row.
 *
 * SIZE: the summed line count of every shell file above may not exceed the one
 * integer in tools/lint/bash_line_budget.txt. A missing or garbled budget FAILS
 * closed. Shell that shrinks passes with a slack note. `--tighten-baseline`
 * lowers the budget to the current sum and deletes list rows whose file no
 * longer exists; it refuses (and writes nothing) when the sum is above the
 * budget, so the budget never rises.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

static const char k_nb_list[] = "tools/lint/bash_allowlist.txt";
static const char k_nb_budget[] = "tools/lint/bash_line_budget.txt";

static int nb_is_name(const char *tok, const char *want_name)
{
    const char *slash = strrchr(tok, '/');
    return strcmp(slash ? slash + 1 : tok, want_name) == 0;
}

/* The interpreter names that make a file a shell file. */
static int nb_name_is_shell(const char *tok)
{
    return nb_is_name(tok, "bash") || nb_is_name(tok, "sh")
        || nb_is_name(tok, "dash") || nb_is_name(tok, "ksh");
}

/* A word that names a shell once surrounding quotes are dropped. */
static int nb_word_is_shell(const char *w)
{
    char buf[256];
    while (*w == '"' || *w == '\'')
        w++;
    size_t n = strlen(w);
    while (n > 0 && (w[n - 1] == '"' || w[n - 1] == '\''))
        n--;
    if (n == 0 || n >= sizeof buf)
        return 0;
    memcpy(buf, w, n);
    buf[n] = '\0';
    return nb_name_is_shell(buf);
}

/* An env option whose value is the next word. */
static int nb_env_takes_arg(const char *opt)
{
    return strcmp(opt, "-u") == 0 || strcmp(opt, "-C") == 0
        || strcmp(opt, "--unset") == 0 || strcmp(opt, "--chdir") == 0;
}

/* After env: skip options (and the value of -u/-C), NAME=value words and
 * the word after a bare -S; -SSTRING names its command directly. */
static int nb_env_command_is_shell(char *save)
{
    char *tok;
    while ((tok = strtok_r(NULL, " \t\r\n", &save)) != NULL) {
        if (nb_env_takes_arg(tok)) {
            (void)strtok_r(NULL, " \t\r\n", &save);
            continue;
        }
        if (strncmp(tok, "-S", 2) == 0 && tok[2] != '\0')
            return nb_word_is_shell(tok + 2);
        if (tok[0] == '-' || strchr(tok, '='))
            continue;
        return nb_word_is_shell(tok);
    }
    return 0;
}

/* `line` is the first line. The interpreter is the first word, or the
 * command word after env. */
static int nb_shebang_is_shell(char *line)
{
    if (line[0] != '#' || line[1] != '!')
        return 0;
    char *save = NULL;
    char *tok = strtok_r(line + 2, " \t\r\n", &save);
    if (!tok)
        return 0;
    if (nb_name_is_shell(tok))
        return 1;
    return nb_is_name(tok, "env") && nb_env_command_is_shell(save);
}

static int nb_has_suffix(const char *path, const char *suffix)
{
    size_t n = strlen(path), k = strlen(suffix);
    return n > k && strcmp(path + n - k, suffix) == 0;
}

/* 1 when `path` is under a tree the gate does not scan, else 0. */
static int nb_excluded(const char *path)
{
    return strncmp(path, "vendor/", 7) == 0
        || strncmp(path, "contexts/commons/corpus/", 24) == 0;
}

/* 1 when `path` is a regular file that is a shell file, else 0. */
static int nb_is_shell(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    if (nb_has_suffix(path, ".sh") || nb_has_suffix(path, ".bash"))
        return 1;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[512];
    int shell = 0;
    if (fgets(line, sizeof line, f))
        shell = nb_shebang_is_shell(line);
    fclose(f);
    return shell;
}

static int nb_on_path(const char *path, void *ctx)
{
    if (nb_excluded(path))
        return 0;
    return nb_is_shell(path) ? bln_add(ctx, path) : 0;
}

/* Appends without dropping repeats, so a duplicated line stays visible. */
static int nb_push(struct bln_set *s, const char *text)
{
    size_t n = strlen(text);
    if (s->count >= BLN_MAX || n >= BLN_ROW)
        return die("z23-lint: baseline-set overflow\n", "");
    memcpy(s->n[s->count++], text, n + 1);
    return 0;
}

/* Loads the list as written: '#' starts a comment, blank lines are skipped. */
static int nb_load(struct bln_set *s, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0) {
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        size_t n = strlen(p);
        while (n > 0 && strchr(" \t\r\n", p[n - 1]))
            p[--n] = '\0';
        if (n)
            rc = nb_push(s, p);
    }
    return fin(f, line, path, rc);
}

/* Strictly ascending order proves sorted and duplicate-free. */
static int nb_list_sorted(FILE *err, const struct bln_set *list)
{
    int bad = 0;
    for (int i = 1; i < list->count; i++) {
        int order = strcmp(list->n[i - 1], list->n[i]);
        if (order < 0)
            continue;
        if (order == 0)
            fprintf(err, "check-no-new-bash: %s lists \"%.80s\" more than "
                         "once; delete the repeated line\n",
                    k_nb_list, list->n[i]);
        else
            fprintf(err, "check-no-new-bash: %s is unsorted near \"%.80s\"; "
                         "keep one path per line, sorted with LC_ALL=C sort\n",
                    k_nb_list, list->n[i]);
        bad = 1;
    }
    return bad;
}

/* Prints the paths of `a` that are absent from `b`; returns how many. */
static int nb_only_in(FILE *err, const struct bln_set *a,
                      const struct bln_set *b, const char *hdr)
{
    int n = 0;
    for (int i = 0; i < a->count; i++) {
        if (bln_has(b, a->n[i]))
            continue;
        if (n++ == 0)
            fputs(hdr, err);
        fprintf(err, "  %s\n", a->n[i]);
    }
    return n;
}

/* Returns 1 when the found set and the list disagree, or the list is
 * unsorted; every disagreement is named. */
static int nb_compare(FILE *err, const struct bln_set *list,
                      const struct bln_set *found)
{
    int bad = nb_list_sorted(err, list);
    bad |= nb_only_in(err, found, list,
                      "check-no-new-bash: NEW shell file(s) not on the list.\n"
                      "Do not add a shell script. Write it in C23 and add a "
                      "nested `z23` command instead:\n") > 0;
    bad |= nb_only_in(err, list, found,
                      "check-no-new-bash: STALE list entries: the file is "
                      "gone or no longer is a shell file.\n"
                      "Delete these lines from tools/lint/bash_allowlist.txt:\n") > 0;
    return bad;
}

/* ── size budget ──────────────────────────────────────────────────────── */

enum { NB_TOP = 10, NB_NUM = 32 };
static const long long k_nb_max_budget = INT_MAX;

struct nb_row { long long lines; char path[BLN_ROW]; };
struct nb_size { long long total; int top_n; struct nb_row top[NB_TOP]; };

/* Copies the path on one list line (text before '#', trimmed) into `out`.
 * Returns 1 when the line names a path, 0 for a blank, comment or too-long line. */
static int nb_row_path(const char *line, char *out, size_t cap)
{
    const char *hash = strchr(line, '#');
    size_t n = hash ? (size_t)(hash - line) : strlen(line);
    size_t s = 0;
    while (n > 0 && strchr(" \t\r\n", line[n - 1]))
        n--;
    while (s < n && (line[s] == ' ' || line[s] == '\t'))
        s++;
    n -= s;
    if (n == 0 || n >= cap)
        return 0;
    memcpy(out, line + s, n);
    out[n] = '\0';
    return 1;
}

/* 0 when `text` is a plain decimal count within the budget ceiling. */
static int nb_count_text(const char *text, long long *out)
{
    if (text[0] < '0' || text[0] > '9')
        return 1;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(text, &end, 10);
    if (errno != 0 || *end != '\0' || v > k_nb_max_budget)
        return 1;
    *out = v;
    return 0;
}

static int nb_budget_bad(FILE *err, const char *path, const char *why)
{
    fprintf(err, "check-no-new-bash: budget %s %s; it must hold one integer "
                 "line, a count of shell lines. Restore it, or run "
                 "`z23-lint check-no-new-bash --tighten-baseline`\n", path, why);
    return 1;
}

/* Reads the one count line; '#' lines are comments. 0 on success. */
static int nb_read_budget(FILE *err, const char *path, long long *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return nb_budget_bad(err, path, "is missing");
    char *line = NULL, num[NB_NUM] = "", text[NB_NUM];
    size_t cap = 0;
    int data = 0;
    while (getline(&line, &cap, f) >= 0)
        if (nb_row_path(line, text, sizeof text) && data++ == 0)
            (void)snprintf(num, sizeof num, "%s", text);
    int rc = fin(f, line, path, 0);
    if (rc != 0)
        return rc;
    if (data == 0)
        return nb_budget_bad(err, path, "holds no count");
    if (data > 1)
        return nb_budget_bad(err, path, "holds more than one line");
    if (nb_count_text(num, out) != 0)
        return nb_budget_bad(err, path, "does not hold a count");
    return 0;
}

/* Lines in `path`: newline-terminated lines plus an unterminated last one. */
static int nb_line_count(const char *path, long long *out)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("check-no-new-bash: cannot read %s\n", path);
    char buf[4096];
    long long n = 0;
    int last = '\n';
    size_t got;
    while ((got = fread(buf, 1, sizeof buf, f)) > 0) {
        for (size_t i = 0; i < got; i++)
            n += buf[i] == '\n';
        last = buf[got - 1];
    }
    int rc = fin(f, NULL, path, 0);
    if (rc != 0)
        return rc;
    *out = n + (last != '\n');
    return 0;
}

/* Keeps the NB_TOP largest files, biggest first. */
static void nb_top_add(struct nb_size *s, const char *path, long long lines)
{
    if (s->top_n == NB_TOP && lines <= s->top[NB_TOP - 1].lines)
        return;
    int i = s->top_n < NB_TOP ? s->top_n++ : NB_TOP - 1;
    for (; i > 0 && s->top[i - 1].lines < lines; i--)
        s->top[i] = s->top[i - 1];
    s->top[i].lines = lines;
    snprintf(s->top[i].path, sizeof s->top[i].path, "%s", path);
}

/* Sums the line count of every shell file in `found`. 0 on success. */
static int nb_size_scan(const struct bln_set *found, struct nb_size *s)
{
    for (int i = 0; i < found->count; i++) {
        long long lines = 0;
        if (nb_line_count(found->n[i], &lines) != 0)
            return 1;
        if (lines > LLONG_MAX - s->total)
            return die("check-no-new-bash: shell line total overflows\n", "");
        s->total += lines;
        nb_top_add(s, found->n[i], lines);
    }
    return 0;
}

/* Passes with a slack note when the sum fits; over budget FAILS and names the
 * sum, the budget and the largest shell files. Returns 1 on failure. */
static int nb_budget_verdict(FILE *out, FILE *err, const struct nb_size *s,
                             long long budget)
{
    if (s->total <= budget) {
        fprintf(out, "check-no-new-bash: shell lines %lld of budget %lld, "
                     "slack %lld (lower it with --tighten-baseline)\n",
                s->total, budget, budget - s->total);
        return 0;
    }
    fprintf(err, "check-no-new-bash: shell lines %lld exceed the budget %lld "
                 "in %s by %lld. Port or delete shell; the budget never "
                 "rises. Ten largest shell files:\n",
            s->total, budget, k_nb_budget, s->total - budget);
    for (int i = 0; i < s->top_n; i++)
        fprintf(err, "  %8lld  %s\n", s->top[i].lines, s->top[i].path);
    return 1;
}

/* Opens `path` for reading and its sibling `tmp` for writing. 0 on success. */
static int nb_open_rewrite(const char *path, FILE **in, FILE **out, char *tmp,
                           size_t cap)
{
    *in = NULL;
    *out = NULL;
    if (ovf(snprintf(tmp, cap, "%s.tmp", path), cap))
        return die("check-no-new-bash: path overflow\n", "");
    *in = fopen(path, "r");
    *out = *in ? fopen(tmp, "w") : NULL;
    if (*out)
        return 0;
    if (*in)
        (void)fclose(*in);
    return die("check-no-new-bash: cannot rewrite %s\n", path);
}

/* Closes both files. `tmp` replaces `path` by rename only when `rc` is 0 and
 * the copy closed cleanly; otherwise `tmp` is removed. Returns the final rc. */
static int nb_close_rewrite(FILE *in, FILE *out, char *line, const char *path,
                            const char *tmp, int rc)
{
    rc = fin(in, line, path, rc);
    if (fclose(out) != 0 && rc == 0)
        rc = 2;
    if (rc == 0 && rename(tmp, path) != 0)
        rc = die("check-no-new-bash: cannot replace %s\n", path);
    if (rc != 0)
        (void)remove(tmp);
    return rc;
}

/* Rewrites `path` with its first count line replaced by `value`. 0 on success. */
static int nb_write_budget(const char *path, long long value)
{
    char tmp[4096], text[NB_NUM], *line = NULL;
    FILE *in = NULL, *out = NULL;
    size_t cap = 0;
    int rc = nb_open_rewrite(path, &in, &out, tmp, sizeof tmp);
    if (rc != 0)
        return rc;
    int done = 0, ok = 1;
    while (ok && getline(&line, &cap, in) >= 0) {
        if (!done && nb_row_path(line, text, sizeof text)) {
            done = 1;
            ok = fprintf(out, "%lld\n", value) >= 0;
        } else {
            ok = fputs(line, out) >= 0;
        }
    }
    return nb_close_rewrite(in, out, line, path, tmp, ok && done ? 0 : 2);
}

/* 1 when root/row exists (an overflowing row is kept). */
static int nb_row_exists(const char *root, const char *row)
{
    char full[4096];
    struct stat st;
    if (ovf(snprintf(full, sizeof full, "%s/%s", root, row), sizeof full))
        return 1;
    return stat(full, &st) == 0;
}

/* Deletes list rows whose file is gone; every other line is kept verbatim.
 * Stores the number of deleted rows in *dropped. 0 on success. */
static int nb_prune_list(const char *root, const char *list_path, int *dropped)
{
    char tmp[4096], row[BLN_ROW], *line = NULL;
    FILE *in = NULL, *out = NULL;
    size_t cap = 0;
    int rc = nb_open_rewrite(list_path, &in, &out, tmp, sizeof tmp);
    if (rc != 0)
        return rc;
    int ok = 1;
    *dropped = 0;
    while (ok && getline(&line, &cap, in) >= 0) {
        if (nb_row_path(line, row, sizeof row) && !nb_row_exists(root, row))
            (*dropped)++;
        else
            ok = fputs(line, out) >= 0;
    }
    return nb_close_rewrite(in, out, line, list_path, tmp, ok ? 0 : 2);
}

/* Lowers the budget to the current sum and prunes stale list rows. Refuses,
 * and writes nothing, when the sum is above the budget. Returns 1 on refusal
 * or failure. */
static int nb_tighten(FILE *out, FILE *err, const char *root,
                      const char *budget_path, const char *list_path,
                      const struct nb_size *s, long long budget)
{
    if (s->total > budget) {
        fprintf(err, "check-no-new-bash: refusing to raise the budget: shell "
                     "lines %lld exceed %lld. Port or delete shell instead.\n",
                s->total, budget);
        return 1;
    }
    if (s->total < budget && nb_write_budget(budget_path, s->total) != 0)
        return 1;
    int dropped = 0;
    if (nb_prune_list(root, list_path, &dropped) != 0)
        return 1;
    fprintf(out, "check-no-new-bash: budget %lld -> %lld; pruned %d stale "
                 "row(s) from %s\n", budget, s->total, dropped, list_path);
    return 0;
}

int check_no_new_bash_run(int argc, char **argv)
{
    int tighten = argc == 1 && strcmp(argv[0], "--tighten-baseline") == 0;
    if (argc > 0 && !tighten)
        return die("check-no-new-bash: takes no arguments or "
                   "--tighten-baseline; the list is hand-edited and only "
                   "shrinks%s\n", "");
    static struct bln_set list, found;
    int rc = nb_load(&list, k_nb_list);
    if (rc == 0 && list.count == 0)
        return die("check-no-new-bash: %s is missing or empty\n", k_nb_list);
    if (rc == 0)
        rc = each_zpath(k_ls_all, nb_on_path, &found);
    if (rc != 0)
        return rc;
    long long budget = 0;
    if (nb_read_budget(stderr, k_nb_budget, &budget) != 0)
        return 1;
    struct nb_size size = { 0 };
    if (nb_size_scan(&found, &size) != 0)
        return 1;
    if (tighten)
        return nb_tighten(stdout, stderr, ".", k_nb_budget, k_nb_list, &size,
                          budget);
    int bad = nb_compare(stderr, &list, &found);
    bad |= nb_budget_verdict(stdout, stderr, &size, budget);
    if (bad) {
        fputs("check-no-new-bash: FAIL\n", stderr);
        return 1;
    }
    printf("check-no-new-bash: clean — %d shell file(s), all on the shrinking "
           "list\n", found.count);
    return 0;
}

/* ── selftest ─────────────────────────────────────────────────────────── */

static int nb_fixture(const char *dir, const char *name, const char *text,
                      int expect)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, name), sizeof path)
        || csr_write(path, text))
        return 1;
    if (nb_is_shell(path) == expect)
        return 0;
    fprintf(stderr, "check-no-new-bash selftest: %s expected %s\n", name,
            expect ? "shell" : "not shell");
    return 1;
}

static int nb_detect_selftest(const char *dir)
{
    return nb_fixture(dir, "a", "#!/bin/bash\necho\n", 1)
         | nb_fixture(dir, "b", "#!/usr/bin/env bash\n", 1)
         | nb_fixture(dir, "c", "#!/bin/bash -eu\n", 1)
         | nb_fixture(dir, "d", "#!/usr/bin/env -S bash -e\n", 1)
         | nb_fixture(dir, "k", "#!/usr/bin/env -u HOME bash\n", 1)
         | nb_fixture(dir, "l", "#!/usr/bin/env -C /srv bash\n", 1)
         | nb_fixture(dir, "m", "#!/usr/bin/env -Sbash -e\n", 1)
         | nb_fixture(dir, "n", "#!/usr/bin/env -S\"bash -e\"\n", 1)
         | nb_fixture(dir, "o", "#!/usr/bin/env -u bash sh\n", 1)
         | nb_fixture(dir, "e.bash", "echo\n", 1)
         | nb_fixture(dir, "f", "#!/bin/sh\necho\n", 1)
         | nb_fixture(dir, "g", "#!/usr/bin/env sh\n", 1)
         | nb_fixture(dir, "q", "#!/bin/dash\n", 1)
         | nb_fixture(dir, "r", "#!/usr/bin/env ksh\n", 1)
         | nb_fixture(dir, "p.sh", "echo\n", 1)
         | nb_fixture(dir, "h.txt", "echo bash\n", 0)
         | nb_fixture(dir, "i", "# #!/bin/bash\n", 0)
         | nb_fixture(dir, "t", "#!/bin/zsh\n", 0)
         | nb_fixture(dir, "j.c", "#!/bin/bashful\n", 0);
}

static int nb_expect(const char *tag, const struct bln_set *list,
                     const struct bln_set *found, int want_bad)
{
    FILE *sink = tmpfile();
    if (!sink)
        return 1;
    int bad = nb_compare(sink, list, found);
    fclose(sink);
    if (bad == want_bad)
        return 0;
    fprintf(stderr, "check-no-new-bash selftest: %s\n", tag);
    return 1;
}

static int nb_compare_selftest(void)
{
    static struct bln_set list, same, added, gone, reversed, dup;
    int rc = bln_add(&list, "a.sh") | bln_add(&list, "b.sh");
    rc |= bln_add(&same, "a.sh") | bln_add(&same, "b.sh");
    rc |= bln_add(&added, "a.sh") | bln_add(&added, "b.sh")
        | bln_add(&added, "c.sh");
    rc |= bln_add(&gone, "a.sh");
    rc |= bln_add(&reversed, "b.sh") | bln_add(&reversed, "a.sh");
    rc |= nb_push(&dup, "a.sh") | nb_push(&dup, "a.sh") | nb_push(&dup, "b.sh");
    if (rc)
        return 1;
    return nb_expect("exact list must pass", &list, &same, 0)
         | nb_expect("new shell file must fail", &list, &added, 1)
         | nb_expect("stale entry must fail", &list, &gone, 1)
         | nb_expect("unsorted list must fail", &reversed, &same, 1)
         | nb_expect("duplicate entry must fail", &dup, &same, 1);
}

static int nb_exclude_expect(const char *path, int want)
{
    if (nb_excluded(path) == want)
        return 0;
    fprintf(stderr, "check-no-new-bash selftest: %s excluded != %d\n", path,
            want);
    return 1;
}

static int nb_exclude_selftest(void)
{
    return nb_exclude_expect("vendor/x.sh", 1)
         | nb_exclude_expect("contexts/commons/corpus/y.sh", 1)
         | nb_exclude_expect("tools/x.sh", 0)
         | nb_exclude_expect("vendor.sh", 0);
}

static int nb_join(char *out, size_t cap, const char *dir, const char *name)
{
    return ovf(snprintf(out, cap, "%s/%s", dir, name), cap);
}

static int nb_sink_has(FILE *sink, const char *needle)
{
    char buf[2048];
    rewind(sink);
    size_t n = fread(buf, 1, sizeof buf - 1, sink);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static int nb_file_has(const char *path, const char *needle)
{
    char buf[4096] = "";
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    (void)fclose(f);
    return strstr(buf, needle) != NULL;
}

static int nb_rc_expect(const char *tag, int got, int want)
{
    if (got == want)
        return 0;
    fprintf(stderr, "check-no-new-bash selftest: %s (got %d, want %d)\n", tag,
            got, want);
    return 1;
}

static int nb_text_expect(const char *tag, int ok)
{
    if (ok)
        return 0;
    fprintf(stderr, "check-no-new-bash selftest: %s\n", tag);
    return 1;
}

/* Growth over the budget fails and names the largest files; a shrink passes
 * with the slack note. */
static int nb_verdict_selftest(void)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            (void)fclose(out);
        if (err)
            (void)fclose(err);
        return 1;
    }
    struct nb_size big = { 0 }, small = { 0 };
    big.total = 150;
    big.top_n = 1;
    big.top[0].lines = 150;
    (void)snprintf(big.top[0].path, sizeof big.top[0].path, "%s", "big.sh");
    small.total = 40;
    int bad = nb_rc_expect("growth over budget must fail",
                           nb_budget_verdict(out, err, &big, 100), 1);
    bad |= nb_text_expect("growth must print the sum and the budget",
                          nb_sink_has(err, "exceed the budget 100"));
    bad |= nb_text_expect("growth must name the largest file",
                          nb_sink_has(err, "big.sh"));
    bad |= nb_rc_expect("shrink under budget must pass",
                        nb_budget_verdict(out, err, &small, 100), 0);
    bad |= nb_text_expect("shrink must print the slack note",
                          nb_sink_has(out, "slack 60"));
    (void)fclose(out);
    (void)fclose(err);
    return bad;
}

/* Tighten lowers the budget to the sum and prunes rows whose file is gone. */
static int nb_tighten_lower_case(const char *dir, const char *budget,
                                 const char *list)
{
    char keep[4096];
    if (nb_join(keep, sizeof keep, dir, "keep.sh") || csr_write(keep, "x\n")
        || csr_write(budget, "100\n")
        || csr_write(list, "# header\nkeep.sh\ngone.sh\n"))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            (void)fclose(out);
        if (err)
            (void)fclose(err);
        return 1;
    }
    struct nb_size s = { 0 };
    s.total = 40;
    int bad = nb_rc_expect("tighten lowers must succeed",
                           nb_tighten(out, err, dir, budget, list, &s, 100),
                           0);
    long long v = -1;
    bad |= nb_rc_expect("tighten lowers the budget file", nb_read_budget(err,
                        budget, &v), 0) | nb_text_expect("tighten budget is 40",
                        v == 40);
    bad |= nb_text_expect("tighten keeps the header and live rows",
                          nb_file_has(list, "# header")
                          && nb_file_has(list, "keep.sh"));
    bad |= nb_text_expect("tighten deletes the row of a missing file",
                          !nb_file_has(list, "gone.sh"));
    (void)fclose(out);
    (void)fclose(err);
    return bad;
}

/* Tighten never raises: over the budget it refuses and writes nothing. */
static int nb_tighten_raise_case(const char *dir, const char *budget,
                                 const char *list)
{
    if (csr_write(budget, "40\n")
        || csr_write(list, "keep.sh\ngone.sh\n"))
        return 1;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            (void)fclose(out);
        if (err)
            (void)fclose(err);
        return 1;
    }
    struct nb_size s = { 0 };
    s.total = 90;
    int bad = nb_rc_expect("tighten must refuse to raise",
                           nb_tighten(out, err, dir, budget, list, &s, 40), 1);
    long long v = -1;
    bad |= nb_rc_expect("refused tighten leaves the budget", nb_read_budget(
                        err, budget, &v), 0) | nb_text_expect(
                        "refused tighten keeps 40", v == 40);
    bad |= nb_text_expect("refused tighten writes no list change",
                          nb_file_has(list, "gone.sh"));
    (void)fclose(out);
    (void)fclose(err);
    return bad;
}

static int nb_tighten_selftest(const char *dir)
{
    char budget[4096], list[4096];
    if (nb_join(budget, sizeof budget, dir, "budget.txt")
        || nb_join(list, sizeof list, dir, "list.txt"))
        return 1;
    return nb_tighten_lower_case(dir, budget, list)
         | nb_tighten_raise_case(dir, budget, list);
}

/* A missing, empty, garbled, negative or two-line budget fails closed; a
 * comment and a blank line around one count are allowed. */
static int nb_read_selftest(const char *dir)
{
    static const char *const bad_text[] = {
        "", "12x\n", "abc\n", "-5\n", "1\n2\n", "# only a comment\n"
    };
    char path[4096];
    FILE *err = tmpfile();
    if (!err || nb_join(path, sizeof path, dir, "read.txt"))
        return 1;
    int bad = 0;
    for (size_t i = 0; i < sizeof bad_text / sizeof bad_text[0]; i++) {
        long long v = 0;
        if (csr_write(path, bad_text[i]))
            bad = 1;
        else
            bad |= nb_rc_expect("garbled budget must fail closed",
                                nb_read_budget(err, path, &v), 1);
    }
    long long v = 0;
    bad |= nb_rc_expect("missing budget must fail closed",
                        nb_read_budget(err, "/nonexistent/budget", &v), 1);
    if (csr_write(path, "# header\n\n 123  # count\n"))
        bad = 1;
    else
        bad |= nb_rc_expect("valid budget must read", nb_read_budget(err, path,
                            &v), 0) | nb_text_expect("valid budget is 123",
                            v == 123);
    (void)fclose(err);
    return bad;
}

static int nb_budget_selftest(const char *dir)
{
    return nb_verdict_selftest() | nb_tighten_selftest(dir)
         | nb_read_selftest(dir);
}

int check_no_new_bash_selftest(void)
{
    char dir[4096];
    if (ovf(snprintf(dir, sizeof dir, "%s/z23-nb-XXXXXX",
                     env_or("TMPDIR", "test-tmp")), sizeof dir))
        return die("z23-lint: selftest path overflow\n", "");
    if (csr_mkdirs(env_or("TMPDIR", "test-tmp")) || !mkdtemp(dir))
        return die("z23-lint: mkdtemp failed\n", "");
    int bad = nb_detect_selftest(dir) | nb_compare_selftest()
            | nb_exclude_selftest() | nb_budget_selftest(dir);
    rap_rm_rf(dir);
    return st_ok(bad, "check_no_new_bash selftest: OK\n");
}
