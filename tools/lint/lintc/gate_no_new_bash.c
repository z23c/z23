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
 * shrink; this gate never writes it.
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

static const char k_nb_list[] = "tools/lint/bash_allowlist.txt";

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

int check_no_new_bash_run(int argc, char **argv)
{
    (void)argv;
    if (argc > 0)
        return die("check-no-new-bash: takes no arguments; the list is "
                   "hand-edited and only shrinks%s\n", "");
    static struct bln_set list, found;
    int rc = nb_load(&list, k_nb_list);
    if (rc == 0 && list.count == 0)
        return die("check-no-new-bash: %s is missing or empty\n", k_nb_list);
    if (rc == 0)
        rc = each_zpath(k_ls_all, nb_on_path, &found);
    if (rc != 0)
        return rc;
    if (nb_compare(stderr, &list, &found)) {
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

int check_no_new_bash_selftest(void)
{
    char dir[4096];
    if (ovf(snprintf(dir, sizeof dir, "%s/z23-nb-XXXXXX",
                     env_or("TMPDIR", "test-tmp")), sizeof dir))
        return die("z23-lint: selftest path overflow\n", "");
    if (csr_mkdirs(env_or("TMPDIR", "test-tmp")) || !mkdtemp(dir))
        return die("z23-lint: mkdtemp failed\n", "");
    int bad = nb_detect_selftest(dir) | nb_compare_selftest()
            | nb_exclude_selftest();
    rap_rm_rf(dir);
    return st_ok(bad, "check_no_new_bash selftest: OK\n");
}
