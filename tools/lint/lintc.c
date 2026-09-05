/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-lint — C23 replacements for tools/lint shell gates.
 * Invoke: z23-lint <gate-name> [--selftest] | z23-lint --list
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char k_ls_all[] = "git ls-files -z";
static const char k_ls_refs[] =
    "git ls-files -z -- AGENTS.md CLAUDE.md README.md Makefile "
    "config app core domain lib ports adapters packages src tools docs";
static const char *const k_exclude[] = {
    "tools/lint/check_no_python.sh",
    "tests/harness/src/test_mnemonic.c",
    "tests/harness/src/test_domain_wallet_mnemonic.c",
    "contexts/commons/packages/zu256/tests/vectors.h",
};

struct acc { regex_t *re; FILE *out; int hits; };

static int die(const char *msg, const char *arg)
{
    fprintf(stderr, msg, arg);
    return 2;
}

static int compile_ref(regex_t *re)
{
    char pat[256];
    /* Pieces so this translation unit does not itself match the live pattern. */
    int n = snprintf(pat, sizeof pat, "%s%s%s%s%s%s",
                     "(^|[|;&[:space:]])(python", "3|python",
                     "2)([[:space:]]|$)|[[:space:]]python[[:space:]]+-|command -v python",
                     "3|#!/usr/bin/env pytho", "n|#!/usr/bin/pytho", "n");
    if (n < 0 || (size_t)n >= sizeof pat)
        return die("z23-lint: pattern buffer overflow\n", "");
    int err = regcomp(re, pat, REG_EXTENDED);
    if (err != 0) {
        char msg[128];
        (void)regerror(err, re, msg, sizeof msg);
        return die("z23-lint: regcomp failed: %s\n", msg);
    }
    return 0;
}

static int each_zpath(const char *cmd, int (*fn)(const char *, void *), void *ctx)
{
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        return die("z23-lint: popen failed (%s)\n", cmd);
    char *buf = NULL;
    size_t cap = 0;
    int rc = 0;
    ssize_t n;
    while ((n = getdelim(&buf, &cap, '\0', pipe)) >= 0) {
        if (n <= 0 || buf[0] == '\0')
            continue;
        rc = fn(buf, ctx);
        if (rc != 0)
            break;
    }
    if (rc == 0 && ferror(pipe))
        rc = die("z23-lint: read failed (%s)\n", cmd);
    free(buf);
    int st = pclose(pipe);
    if (rc != 0)
        return rc;
    return st != 0 ? die("z23-lint: command failed (%s)\n", cmd) : 0;
}

static int note(struct acc *a, const char *fmt, const char *path, int lineno,
                const char *line)
{
    a->hits++;
    int n = (lineno >= 0) ? fprintf(a->out, fmt, path, lineno, line)
                          : fprintf(a->out, fmt, path);
    return n < 0 ? die("z23-lint: write failed\n", "") : 0;
}

static int on_py_path(const char *path, void *ctx)
{
    size_t n = strlen(path);
    if (!((n >= 3 && memcmp(path + n - 3, ".py", 3) == 0)
          || strncmp(path, "__pycache__/", 12) == 0
          || strstr(path, "/__pycache__/") != NULL))
        return 0;
    return note(ctx, "%s\n", path, -1, NULL);
}

static int on_ref_file(const char *path, void *ctx)
{
    struct acc *a = ctx;
    for (size_t i = 0; i < sizeof k_exclude / sizeof k_exclude[0]; i++) {
        if (strcmp(path, k_exclude[i]) == 0)
            return 0;
    }
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        /* getline may return a buffer containing NULs; a NUL never terminates
         * a line early. Scan the NUL-free prefix with regexec (bytes after
         * the first NUL are skipped as binary). */
        if (regexec(a->re, line, 0, NULL, 0) != 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        rc = note(a, "%s:%d:%s\n", path, lineno, line);
        if (rc != 0)
            break;
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int replay(FILE *out)
{
    if (fseek(out, 0, SEEK_SET) != 0)
        return die("z23-lint: fseek failed\n", "");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, out)) >= 0) {
        if (fwrite(line, 1, (size_t)n, stderr) != (size_t)n) {
            free(line);
            return die("z23-lint: write failed\n", "");
        }
    }
    int err = ferror(out);
    free(line);
    return err ? die("z23-lint: read failed\n", "") : 0;
}

static int check_no_python_run(void)
{
    regex_t re;
    int cr = compile_ref(&re);
    if (cr != 0)
        return cr;
    FILE *out = tmpfile();
    if (!out) {
        regfree(&re);
        return die("z23-lint: tmpfile failed\n", "");
    }
    struct acc a = { .re = &re, .out = out, .hits = 0 };
    int rc = each_zpath(k_ls_all, on_py_path, &a);
    if (rc == 0)
        rc = each_zpath(k_ls_refs, on_ref_file, &a);
    if (rc == 0 && a.hits) {
        fputs("check_no_python: FAIL — Z23 must have no Python dependency\n",
              stderr);
        rc = replay(out);
        if (rc == 0)
            rc = 1;
    } else if (rc == 0) {
        fputs("check_no_python: clean — no Python source, shebang, or runtime path\n",
              stdout);
    }
    fclose(out);
    regfree(&re);
    return rc;
}

static int want(const regex_t *re, const char *s, int w)
{
    if ((regexec(re, s, 0, NULL, 0) == 0) != w) {
        fprintf(stderr, "check_no_python selftest: want %d: %s\n", w, s);
        return 1;
    }
    return 0;
}

static int check_no_python_selftest(void)
{
    regex_t re;
    int cr = compile_ref(&re);
    if (cr != 0)
        return cr;
    char p1[64], p2[64], p3[64];
    if (snprintf(p1, sizeof p1, "python%s", "3 -c \"print(1)\"") >= (int)sizeof p1
        || snprintf(p2, sizeof p2, "#!" "/usr/bin/env pytho" "n%s", "3")
               >= (int)sizeof p2
        || snprintf(p3, sizeof p3, "command -v python%s", "3") >= (int)sizeof p3) {
        regfree(&re);
        return die("z23-lint: selftest buffer overflow\n", "");
    }
    int bad = want(&re, "cc -std=c23 main.c", 0)
            | want(&re, "Never use Python.", 0)
            | want(&re, "No python (banned), no jq", 0)
            | want(&re, p1, 1) | want(&re, p2, 1) | want(&re, p3, 1);
    regfree(&re);
    if (bad)
        return 1;
    fputs("check_no_python selftest: OK\n", stdout);
    return 0;
}

struct mal_acc { regex_t *hit; regex_t *excl; int hits; };

static void drop2(regex_t *a, regex_t *b) { regfree(a); regfree(b); }

static int compile_mal(regex_t *hit, regex_t *excl, const char *nm, const char *xtra)
{
    char hp[64], ep[160], msg[128];
    int n = snprintf(hp, sizeof hp, "[^_]%s[[:space:]]*\\(", nm);
    if (n < 0 || (size_t)n >= sizeof hp)
        return die("z23-lint: pattern buffer overflow\n", "");
    n = snprintf(ep, sizeof ep, "zcl_%s%s|raw-alloc-ok|safe_alloc|\".*%s|LOG_|fprintf",
                 nm, xtra, nm);
    if (n < 0 || (size_t)n >= sizeof ep)
        return die("z23-lint: pattern buffer overflow\n", "");
    int err = regcomp(hit, hp, REG_EXTENDED);
    if (err != 0) {
        (void)regerror(err, hit, msg, sizeof msg);
        return die("z23-lint: regcomp failed: %s\n", msg);
    }
    err = regcomp(excl, ep, REG_EXTENDED);
    if (err != 0) {
        (void)regerror(err, excl, msg, sizeof msg);
        regfree(hit);
        return die("z23-lint: regcomp failed: %s\n", msg);
    }
    return 0;
}

static int scan_mal(const char *path, struct mal_acc *a)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", path);
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int lineno = 0, rc = 0;
    while ((n = getline(&line, &cap, f)) >= 0) {
        lineno++;
        /* getline may return a buffer containing NULs; a NUL never terminates
         * a line early. Scan the NUL-free prefix with regexec (bytes after
         * the first NUL are skipped as binary). */
        if (regexec(a->hit, line, 0, NULL, 0) != 0
            || regexec(a->excl, line, 0, NULL, 0) == 0)
            continue;
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (fprintf(stdout, "%s:%d:%s\n", path, lineno, line) < 0) {
            rc = die("z23-lint: write failed\n", "");
            break;
        }
        a->hits++;
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    free(line);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int walk_mal(const char *dir, struct mal_acc *a)
{
    struct dirent **names = NULL;
    int n = scandir(dir, &names, NULL, alphasort);
    if (n < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = names[i]->d_name;
        if (rc == 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            char path[4096];
            struct stat st;
            size_t nl = strlen(name);
            int k = snprintf(path, sizeof path, "%s/%s", dir, name);
            if (k < 0 || (size_t)k >= sizeof path)
                rc = die("z23-lint: path too long: %s\n", dir);
            else if (lstat(path, &st) != 0)
                rc = die("z23-lint: cannot stat %s\n", path);
            else if (S_ISDIR(st.st_mode))
                rc = walk_mal(path, a);
            else if (S_ISREG(st.st_mode) && nl >= 2 && name[nl - 2] == '.'
                     && (name[nl - 1] == 'c' || name[nl - 1] == 'h'))
                rc = scan_mal(path, a);
        }
        free(names[i]);
    }
    free(names);
    return rc;
}

static int mal_pass(const char *nm, const char *xtra)
{
    regex_t hit, excl;
    int cr = compile_mal(&hit, &excl, nm, xtra);
    if (cr != 0)
        return cr;
    struct mal_acc a = { .hit = &hit, .excl = &excl, .hits = 0 };
    int rc = walk_mal("app", &a);
    if (rc == 0)
        rc = walk_mal("tools", &a);
    if (rc == 0 && a.hits) {
        printf("FAIL: bare %s in app/tools code (use zcl_%s or mark // raw-alloc-ok)\n",
               nm, nm);
        rc = 1;
    }
    drop2(&hit, &excl);
    return rc;
}

static int check_malloc_run(void)
{
    int rc = mal_pass("malloc", "|zcl_calloc|zcl_realloc");
    if (rc == 0)
        rc = mal_pass("calloc", "");
    if (rc == 0)
        rc = mal_pass("realloc", "");
    if (rc == 0)
        fputs("  OK: no raw allocations\n", stdout);
    return rc;
}

static int mal_want(const regex_t *hit, const regex_t *excl, const char *s, int w)
{
    int got = (regexec(hit, s, 0, NULL, 0) == 0)
           && (regexec(excl, s, 0, NULL, 0) != 0);
    if (got != w) {
        fprintf(stderr, "check_malloc selftest: want %d: %s\n", w, s);
        return 1;
    }
    return 0;
}

static int check_malloc_selftest(void)
{
    regex_t mh, me, ch, ce, rh, re;
    int cr = compile_mal(&mh, &me, "malloc", "|zcl_calloc|zcl_realloc");
    if (cr != 0)
        return cr;
    if ((cr = compile_mal(&ch, &ce, "calloc", "")) != 0) {
        drop2(&mh, &me);
        return cr;
    }
    if ((cr = compile_mal(&rh, &re, "realloc", "")) != 0) {
        drop2(&mh, &me);
        drop2(&ch, &ce);
        return cr;
    }
    int bad = mal_want(&mh, &me, "p = malloc(n);", 1)
            | mal_want(&mh, &me, "p = zcl_malloc(n);", 0)
            | mal_want(&mh, &me, "p = malloc(n); // raw-alloc-ok", 0)
            | mal_want(&mh, &me, "p = my_malloc(n);", 0)
            | mal_want(&mh, &me, "fprintf(stderr, \"malloc(\")", 0)
            | mal_want(&ch, &ce, "LOG_INFO(\"calloc(\")", 0)
            | mal_want(&rh, &re, "q = realloc(q, n);", 1)
            | mal_want(&ch, &ce, "r = calloc(1, n);", 1);
    drop2(&mh, &me);
    drop2(&ch, &ce);
    drop2(&rh, &re);
    if (bad)
        return 1;
    fputs("check_malloc selftest: OK\n", stdout);
    return 0;
}

struct lint_gate {
    const char *name;
    int (*run)(void);
    int (*selftest)(void);
};

static const struct lint_gate k_gates[] = {
    { "check-no-python", check_no_python_run, check_no_python_selftest },
    { "check-malloc", check_malloc_run, check_malloc_selftest },
};

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++)
            printf("%s\n", k_gates[i].name);
        return 0;
    }
    if (argc < 2)
        return die("z23-lint: usage: z23-lint <gate-name> [--selftest] | --list\n", "");
    const struct lint_gate *g = NULL;
    for (size_t i = 0; i < sizeof k_gates / sizeof k_gates[0]; i++) {
        if (strcmp(argv[1], k_gates[i].name) == 0)
            g = &k_gates[i];
    }
    if (!g)
        return die("z23-lint: unknown gate: %s\n", argv[1]);
    if (argc >= 3 && strcmp(argv[2], "--selftest") == 0)
        return g->selftest();
    if (argc >= 3)
        return die("z23-lint: unexpected argument: %s\n", argv[2]);
    return g->run();
}
